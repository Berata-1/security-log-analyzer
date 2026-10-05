#!/usr/bin/env python3
"""
Log Analyzer TUI
Apache/Nginx, Syslog/Auth.log, Windows Event Log, Özel Regex
"""
import pyodbc
import re
import sys
import csv
import gzip
import json
import io

from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional

def get_db_connection():
    return pyodbc.connect(
        r"DRIVER={ODBC Driver 18 for SQL Server};"
        r"SERVER=localhost\MSSQLSERVER01;"
        r"DATABASE=SecurityDB;"
        r"Trusted_Connection=yes;"
        r"TrustServerCertificate=yes;"
    )

def save_security_log(source_ip, event_type, severity, description):
    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT TOP 1 LogID
            FROM dbo.SecurityLogs
            WHERE SourceIP = ?
              AND EventType = ?
              AND EventTime >= DATEADD(MINUTE, -10, GETDATE())
            ORDER BY EventTime DESC
        """, source_ip, event_type)

        existing_log = cursor.fetchone()

        if existing_log:
            return

        cursor.execute("""
            INSERT INTO dbo.SecurityLogs
            (SourceIP, EventType, Severity, EventTime, Description)
            OUTPUT INSERTED.LogID
            VALUES (?, ?, ?, GETDATE(), ?)
        """, source_ip, event_type, severity, description)

        log_id = cursor.fetchone()[0]

        # High seviyeli olaylarda otomatik incident oluştur
        if severity == "High":
            cursor.execute("""
                INSERT INTO dbo.Incidents
                (LogID, IncidentName, Status, AssignedTo, CreatedAt)
                VALUES (?, ?, ?, ?, GETDATE())
            """,
                log_id,
                f"{event_type} Investigation",
                "Open",
                "Berat"
            )

        conn.commit()

    except Exception as e:
        with open("sql_error.txt", "a", encoding="utf-8") as f:
            f.write(str(e) + "\n")

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
# ── Veri Yapıları ──────────────────────────────────────────────────────────────

@dataclass
class LogEntry:
    raw: str
    timestamp: Optional[datetime] = None
    ip: str = ""
    method: str = ""
    path: str = ""
    status: int = 0
    size: int = 0
    user: str = ""
    message: str = ""
    level: str = "INFO"
    source: str = ""

    @property
    def is_error(self) -> bool:
        return self.status >= 500 or self.level in ("ERROR", "CRIT", "ALERT", "EMERG")

    @property
    def is_warning(self) -> bool:
        return self.level == "WARNING" or (400 <= self.status < 500)


@dataclass
class Stats:
    total: int = 0
    errors: int = 0
    warnings: int = 0
    top_ips: Counter = field(default_factory=Counter)
    status_codes: Counter = field(default_factory=Counter)
    top_paths: Counter = field(default_factory=Counter)
    methods: Counter = field(default_factory=Counter)
    hourly: Counter = field(default_factory=Counter)
    failed_logins: Counter = field(default_factory=Counter)
    brute_force_ips: list = field(default_factory=list)
    format_name: str = "Bilinmiyor"


# ── Parser: Apache / Nginx ─────────────────────────────────────────────────────

_APACHE_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)?\s*(?P<path>[^"]*?)?\s*(?:HTTP/[0-9.]+)?"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
)
_APACHE_TIME = "%d/%b/%Y:%H:%M:%S %z"


def _parse_apache(line: str) -> Optional[LogEntry]:
    m = _APACHE_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("time"), _APACHE_TIME)
    except (ValueError, TypeError):
        ts = None
    status = int(m.group("status"))
    size_s = m.group("size")
    size = int(size_s) if size_s.isdigit() else 0
    level = "ERROR" if status >= 500 else ("WARNING" if status >= 400 else "INFO")
    return LogEntry(
        raw=line.rstrip(),
        timestamp=ts,
        ip=m.group("ip"),
        method=(m.group("method") or "").upper(),
        path=m.group("path") or "",
        status=status,
        size=size,
        level=level,
    )


# ── Parser: Syslog / Auth.log ─────────────────────────────────────────────────

_SYSLOG_RE = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
    r'(?P<host>\S+)\s+(?P<proc>[^\[:]+?)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<msg>.*)'
)
_AUTH_FAIL_RE = re.compile(
    r'Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.a-fA-F:.]+)'
)
_AUTH_OK_RE = re.compile(
    r'Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.a-fA-F:.]+)'
)


def _parse_syslog(line: str) -> Optional[LogEntry]:
    m = _SYSLOG_RE.match(line)
    if not m:
        return None
    msg = m.group("msg")
    msg_l = msg.lower()
    level = "INFO"
    if any(w in msg_l for w in ("error", "failed", "failure", "crit", "fatal")):
        level = "ERROR"
    elif any(w in msg_l for w in ("warn", "warning", "notice")):
        level = "WARNING"

    ip, user = "", ""
    if (fm := _AUTH_FAIL_RE.search(msg)):
        ip, user = fm.group("ip"), fm.group("user")
        level = "ERROR"
    elif (am := _AUTH_OK_RE.search(msg)):
        ip, user = am.group("ip"), am.group("user")

    year = datetime.now().year
    try:
        ts = datetime.strptime(
            f"{year} {m.group('month')} {m.group('day').zfill(2)} {m.group('time')}",
            "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        ts = None

    return LogEntry(
        raw=line.rstrip(),
        timestamp=ts,
        ip=ip,
        user=user,
        message=msg,
        level=level,
        source=m.group("proc").strip(),
    )


# ── Parser: Windows Event Log (CSV export) ────────────────────────────────────

_WIN_LEVEL = {"Information": "INFO", "Warning": "WARNING",
              "Error": "ERROR", "Critical": "CRIT", "Verbose": "DEBUG"}


def _parse_windows_csv(content: str) -> list[LogEntry]:
    entries = []
    try:
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            ts = None
            for key in ("TimeCreated", "Date and Time", "Time"):
                raw_ts = row.get(key, "").strip()
                if raw_ts:
                    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                                "%m/%d/%Y %I:%M:%S %p", "%Y-%m-%d %H:%M:%S"):
                        try:
                            ts = datetime.strptime(raw_ts[:26], fmt)
                            break
                        except ValueError:
                            continue
                    if ts:
                        break
            raw_level = row.get("Level", row.get("LevelDisplayName", "Information")).strip()
            level = _WIN_LEVEL.get(raw_level, "INFO")
            msg = row.get("Message", row.get("Description", "")).strip()[:300]
            source = row.get("Source", row.get("MachineName", "")).strip()
            entries.append(LogEntry(
                raw=str(row)[:200],
                timestamp=ts,
                message=msg,
                level=level,
                source=source,
            ))
    except Exception:
        pass
    return entries


# ── Parser: Windows Event Log (XML export) ────────────────────────────────────

def _parse_windows_xml(content: str) -> list[LogEntry]:
    entries = []
    try:
        import xml.etree.ElementTree as ET
        clean = re.sub(r'\s+xmlns(?::\w+)?="[^"]*"', "", content)
        for m in re.finditer(r'<Event>(.*?)</Event>', clean, re.DOTALL):
            try:
                root = ET.fromstring(f"<Event>{m.group(1)}</Event>")
            except ET.ParseError:
                continue
            ts = None
            tc = root.find(".//TimeCreated")
            if tc is not None:
                st = tc.get("SystemTime", "")
                for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
                    try:
                        ts = datetime.strptime(st[:26], fmt)
                        break
                    except ValueError:
                        continue
            lv = root.find(".//Level")
            level_map = {"1": "CRIT", "2": "ERROR", "3": "WARNING", "4": "INFO", "5": "DEBUG"}
            level = level_map.get((lv.text or "4").strip() if lv is not None else "4", "INFO")
            parts = [d.text for d in root.findall(".//Data") if d.text]
            entries.append(LogEntry(
                raw=m.group(0)[:200],
                timestamp=ts,
                message=" | ".join(parts)[:300],
                level=level,
            ))
    except Exception:
        pass
    return entries


# ── Format Tespiti ─────────────────────────────────────────────────────────────

def _detect(lines: list[str]) -> str:
    sample = "".join(lines[:30])
    if _APACHE_RE.search(sample):
        return "apache"
    if _SYSLOG_RE.search(sample):
        return "syslog"
    if any(k in sample for k in ("TimeCreated", "LevelDisplayName", "Date and Time")):
        return "windows_csv"
    if "<Event>" in sample or "<EventID>" in sample:
        return "windows_xml"
    return "custom"


def parse_file(path: Path, custom_pattern: str = "") -> tuple[list[LogEntry], str]:
    try:
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        return [], f"Okuma hatası: {e}"

    fmt = _detect(lines)
    entries: list[LogEntry] = []

    if fmt == "apache":
        for l in lines:
            e = _parse_apache(l)
            if e:
                entries.append(e)
    elif fmt == "syslog":
        for l in lines:
            e = _parse_syslog(l)
            if e:
                entries.append(e)
    elif fmt == "windows_csv":
        entries = _parse_windows_csv("".join(lines))
    elif fmt == "windows_xml":
        entries = _parse_windows_xml("".join(lines))
    elif custom_pattern:
        try:
            pat = re.compile(custom_pattern)
            for l in lines:
                m = pat.search(l)
                if m:
                    e = LogEntry(raw=l.rstrip(), message=l.rstrip())
                    for k, v in m.groupdict().items():
                        if hasattr(e, k) and v:
                            try:
                                setattr(e, k, type(getattr(e, k))(v))
                            except (TypeError, ValueError):
                                setattr(e, k, v)
                    entries.append(e)
        except re.error:
            pass
    else:
        for l in lines:
            if l.strip():
                entries.append(LogEntry(raw=l.rstrip(), message=l.rstrip()))

    return entries, fmt


# ── Analiz ─────────────────────────────────────────────────────────────────────

def analyze(entries: list[LogEntry]) -> Stats:
    s = Stats(total=len(entries))
    fail_times: dict[str, list[datetime]] = defaultdict(list)

    for e in entries:
        if e.is_error:
            s.errors += 1
        elif e.is_warning:
            s.warnings += 1
        if e.ip:
            s.top_ips[e.ip] += 1
        if e.status:
            s.status_codes[e.status] += 1
        if e.path:
            s.top_paths[e.path] += 1
        if e.method:
            s.methods[e.method] += 1
        if e.timestamp:
            s.hourly[e.timestamp.hour] += 1
        # Başarısız giriş tespiti
        raw_l = e.raw.lower()
        is_fail = (
            e.status in (401, 403)
            or "failed password" in raw_l
            or "authentication failure" in raw_l
            or "invalid user" in raw_l
        )
        if is_fail and e.ip:
            s.failed_logins[e.ip] += 1
            if e.timestamp:
                fail_times[e.ip].append(e.timestamp)

    # Brute-force: aynı IP'den 1 saat içinde 10+ başarısız deneme
    for ip, times in fail_times.items():
        if len(times) < 10:
            continue
        for i in range(len(times) - 9):
            window = sorted(times)[i:i + 10]
            if (window[-1] - window[0]).total_seconds() <= 3600:
                
                s.brute_force_ips.append(ip)
                print(f"[DEBUG] Brute force bulundu: {ip}")

                save_security_log(
                    ip,
                    "Brute Force",
                    "High",
                    f"Brute Force Detected from {ip}"
                )
                break

    s.brute_force_ips = list(set(s.brute_force_ips))
    return s


# ── Dışa Aktarma ──────────────────────────────────────────────────────────────

def export_json(entries: list[LogEntry], path: Path) -> None:
    data = []
    for e in entries:
        data.append({
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "ip": e.ip,
            "method": e.method,
            "path": e.path,
            "status": e.status,
            "level": e.level,
            "user": e.user,
            "message": e.message,
            "source": e.source,
        })
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def export_csv(entries: list[LogEntry], path: Path) -> None:
    fields = ["timestamp", "ip", "method", "path", "status", "level", "user", "message", "source"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for e in entries:
            w.writerow({
                "timestamp": e.timestamp.isoformat() if e.timestamp else "",
                "ip": e.ip, "method": e.method, "path": e.path,
                "status": e.status, "level": e.level,
                "user": e.user, "message": e.message, "source": e.source,
            })


# ── TUI ───────────────────────────────────────────────────────────────────────

try:
    from textual.app import App, ComposeResult
    from textual.widgets import (
        Header, Footer, DataTable, Static, Label, Input,
        RichLog, TabbedContent, TabPane, ListView, ListItem, Button,
    )
    from textual.containers import Horizontal, Vertical, ScrollableContainer
    from textual.binding import Binding
    from textual import on, work
    from textual.screen import ModalScreen
    from rich.text import Text
    from rich.panel import Panel
    from rich.table import Table
    from rich.bar import Bar
    _TUI_OK = True
except ImportError:
    _TUI_OK = False


if _TUI_OK:

    class ExportModal(ModalScreen):
        """Dışa aktarma ekranı."""

        def compose(self) -> ComposeResult:
            with Vertical(id="export-dialog"):
                yield Label("Dışa Aktar", id="export-title")
                yield Input(placeholder="Dosya yolu (örn: cikti.json)", id="export-path")
                with Horizontal(id="export-buttons"):
                    yield Button("JSON", id="btn-json", variant="primary")
                    yield Button("CSV",  id="btn-csv",  variant="success")
                    yield Button("İptal", id="btn-cancel", variant="error")

        @on(Button.Pressed, "#btn-cancel")
        def cancel(self) -> None:
            self.dismiss(None)

        @on(Button.Pressed, "#btn-json")
        def do_json(self) -> None:
            path = self.query_one("#export-path", Input).value.strip() or "cikti.json"
            self.dismiss(("json", path))

        @on(Button.Pressed, "#btn-csv")
        def do_csv(self) -> None:
            path = self.query_one("#export-path", Input).value.strip() or "cikti.csv"
            self.dismiss(("csv", path))


    class FilterModal(ModalScreen):
        """Filtre ekranı."""

        def compose(self) -> ComposeResult:
            with Vertical(id="filter-dialog"):
                yield Label("Filtrele", id="filter-title")
                yield Input(placeholder="IP adresi", id="f-ip")
                yield Input(placeholder="Min. HTTP durum (örn: 400)", id="f-status")
                yield Input(placeholder="Kelime / path", id="f-keyword")
                with Horizontal(id="filter-buttons"):
                    yield Button("Uygula", id="btn-apply", variant="primary")
                    yield Button("Temizle", id="btn-clear", variant="warning")
                    yield Button("İptal",  id="btn-fcancel", variant="error")

        @on(Button.Pressed, "#btn-fcancel")
        def cancel(self) -> None:
            self.dismiss(None)

        @on(Button.Pressed, "#btn-apply")
        def apply(self) -> None:
            ip = self.query_one("#f-ip", Input).value.strip()
            status = self.query_one("#f-status", Input).value.strip()
            keyword = self.query_one("#f-keyword", Input).value.strip()
            self.dismiss({"ip": ip, "status": status, "keyword": keyword})

        @on(Button.Pressed, "#btn-clear")
        def clear(self) -> None:
            self.dismiss({"ip": "", "status": "", "keyword": ""})


    class LogAnalyzerApp(App):
        """Log Analyzer TUI Uygulaması."""

        CSS = """
        Screen {
            background: $surface;
        }
        #main-layout {
            height: 1fr;
        }
        #sidebar {
            width: 26;
            border: solid $primary;
            padding: 0 1;
        }
        #sidebar-title {
            text-style: bold;
            color: $accent;
            padding: 1 0 0 0;
        }
        #file-list {
            height: 1fr;
        }
        #content {
            width: 1fr;
            border: solid $primary;
        }
        #stats-grid {
            layout: grid;
            grid-size: 2;
            grid-gutter: 1;
            padding: 1;
            height: auto;
        }
        .stat-card {
            border: round $accent;
            padding: 0 1;
            height: 5;
        }
        .stat-num {
            text-style: bold;
            color: $accent;
        }
        .card-error { border: round $error; }
        .card-warning { border: round $warning; }
        .card-ok { border: round $success; }
        #log-table { height: 1fr; }
        #search-bar {
            dock: top;
            height: 3;
            padding: 0 1;
        }
        #status-bar {
            color: $text-muted;
            height: 1;
            padding: 0 1;
        }
        #security-panel { padding: 1; }
        #export-dialog, #filter-dialog {
            width: 50;
            height: auto;
            border: round $accent;
            background: $surface;
            padding: 1 2;
            margin: 4 8;
        }
        #export-title, #filter-title {
            text-style: bold;
            color: $accent;
            margin-bottom: 1;
        }
        #export-buttons, #filter-buttons {
            height: 3;
            margin-top: 1;
        }
        Button { margin: 0 1; }
        Input { margin-bottom: 1; }
        #chart-panel { padding: 1; }
        """

        BINDINGS = [
            Binding("a", "add_file", "Dosya Ekle"),
            Binding("f", "filter", "Filtrele"),
            Binding("e", "export", "Dışa Aktar"),
            Binding("r", "reload", "Yenile"),
            Binding("q", "quit", "Çıkış"),
        ]

        def __init__(self, initial_file: str = ""):
            super().__init__()
            self.loaded_files: dict[str, tuple[list[LogEntry], Stats]] = {}
            self.active_file: str = ""
            self._filter: dict = {}
            self._initial_file = initial_file

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Horizontal(id="main-layout"):
                with Vertical(id="sidebar"):
                    yield Label("DOSYALAR", id="sidebar-title")
                    yield ListView(id="file-list")
                    yield Button("+ Ekle [A]", id="btn-add", variant="primary")
                with Vertical(id="content"):
                    with TabbedContent(id="tabs"):
                        with TabPane("Özet", id="tab-ozet"):
                            yield ScrollableContainer(
                                Static(id="stats-display"),
                                id="stats-scroll"
                            )
                        with TabPane("Loglar", id="tab-logs"):
                            yield Input(placeholder="Ara... (IP, path, mesaj)", id="search-bar")
                            yield DataTable(id="log-table", cursor_type="row")
                            yield Label("", id="status-bar")
                        with TabPane("Güvenlik", id="tab-sec"):
                            yield ScrollableContainer(
                                Static(id="security-panel"),
                                id="sec-scroll"
                            )
                        with TabPane("İstatistikler", id="tab-stats"):
                            yield ScrollableContainer(
                                Static(id="chart-panel"),
                                id="chart-scroll"
                            )
            yield Footer()

        def on_mount(self) -> None:
            table = self.query_one("#log-table", DataTable)
            table.add_columns("Zaman", "IP", "Yöntem", "Path / Mesaj", "Durum", "Seviye")
            if self._initial_file:
                self._load(Path(self._initial_file))

        @on(Button.Pressed, "#btn-add")
        def action_add_file(self) -> None:
            self.app.push_screen(_PathInput(), self._on_path)

        def _on_path(self, path_str: str | None) -> None:
            if path_str:
                self._load(Path(path_str.strip()))

        @work(thread=True)
        def _load(self, path: Path) -> None:
            if not path.exists():
                self.notify(f"Dosya bulunamadı: {path}", severity="error")
                return
            self.notify(f"Yükleniyor: {path.name}...")
            entries, fmt = parse_file(path)
            stats = analyze(entries)
            stats.format_name = fmt
            key = str(path)
            self.loaded_files[key] = (entries, stats)
            self.call_from_thread(self._after_load, key, path.name)

        def _after_load(self, key: str, name: str) -> None:
            lv = self.query_one("#file-list", ListView)
            lv.append(ListItem(Label(f"📄 {name}"), id=f"file-{len(self.loaded_files)}"))
            self.active_file = key
            self.notify(f"{name} yüklendi.", severity="information")
            self._refresh_all()

        def on_list_view_selected(self, event: ListView.Selected) -> None:
            idx = list(self.loaded_files.keys())
            item_idx = int(str(event.item.id).split("-")[1]) - 1
            if 0 <= item_idx < len(idx):
                self.active_file = idx[item_idx]
                self._refresh_all()

        def _refresh_all(self) -> None:
            if not self.active_file or self.active_file not in self.loaded_files:
                return
            entries, stats = self.loaded_files[self.active_file]
            self._render_stats(stats)
            self._render_logs(entries)
            self._render_security(entries, stats)
            self._render_charts(stats)

        # ── Özet ──────────────────────────────────────────────────────────────

        def _render_stats(self, s: Stats) -> None:
            from rich.console import Console
            from rich.columns import Columns

            ok_count = s.total - s.errors - s.warnings
            ok_pct = ok_count * 100 // s.total if s.total else 0
            err_pct = s.errors * 100 // s.total if s.total else 0

            top_ips = Table("IP", "İstek", "Başarısız Giriş", box=None, padding=(0, 1))
            for ip, cnt in s.top_ips.most_common(10):
                fail = s.failed_logins.get(ip, 0)
                bf = " [bold red]⚠ BRUTE FORCE[/]" if ip in s.brute_force_ips else ""
                top_ips.add_row(ip, str(cnt), f"{fail}{bf}")

            status_t = Table("Kod", "Açıklama", "Sayı", box=None, padding=(0, 1))
            code_labels = {
                200: "OK", 201: "Created", 204: "No Content",
                301: "Moved", 302: "Found", 304: "Not Modified",
                400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
                404: "Not Found", 405: "Method Not Allowed",
                500: "Internal Error", 502: "Bad Gateway", 503: "Unavailable",
            }
            for code, cnt in sorted(s.status_codes.items()):
                lbl = code_labels.get(code, "")
                color = "green" if code < 400 else ("yellow" if code < 500 else "red")
                status_t.add_row(
                    Text(str(code), style=color),
                    Text(lbl, style=color),
                    Text(str(cnt), style=color),
                )

            top_paths = Table("Path", "İstek", box=None, padding=(0, 1))
            for path, cnt in s.top_paths.most_common(10):
                top_paths.add_row(path[:60], str(cnt))

            lines = [
                f"[bold cyan]Format     :[/] {s.format_name}",
                f"[bold]Toplam Satır:[/] {s.total:,}",
                f"[bold green]Başarılı   :[/] {ok_count:,}  ({ok_pct}%)",
                f"[bold yellow]Uyarı      :[/] {s.warnings:,}",
                f"[bold red]Hata        :[/] {s.errors:,}  ({err_pct}%)",
                f"[bold red]Brute-Force :[/] {len(s.brute_force_ips)} IP",
                "",
                "[bold underline]Top 10 IP[/]",
            ]

            output = "\n".join(lines)
            panel_content = (
                output + "\n"
                + self._table_to_str(top_ips) + "\n\n"
                + "[bold underline]HTTP Durum Kodları[/]\n"
                + self._table_to_str(status_t) + "\n\n"
                + "[bold underline]Top 10 Path[/]\n"
                + self._table_to_str(top_paths)
            )
            self.query_one("#stats-display", Static).update(panel_content)

        def _table_to_str(self, table: "Table") -> str:
            from io import StringIO
            from rich.console import Console
            buf = StringIO()
            c = Console(file=buf, width=80, highlight=False)
            c.print(table)
            return buf.getvalue()

        # ── Loglar ────────────────────────────────────────────────────────────

        def _render_logs(self, entries: list[LogEntry], keyword: str = "") -> None:
            table = self.query_one("#log-table", DataTable)
            table.clear()
            filt = self._filter
            shown = 0
            for e in entries:
                if filt.get("ip") and filt["ip"] not in e.ip:
                    continue
                if filt.get("status"):
                    try:
                        if e.status < int(filt["status"]):
                            continue
                    except ValueError:
                        pass
                kw = filt.get("keyword", "") or keyword
                if kw and kw.lower() not in e.raw.lower():
                    continue

                ts = e.timestamp.strftime("%m-%d %H:%M:%S") if e.timestamp else "-"
                path_msg = (e.path or e.message)[:55]
                status_s = str(e.status) if e.status else "-"

                color = "white"
                if e.level in ("ERROR", "CRIT"):
                    color = "red"
                elif e.level == "WARNING":
                    color = "yellow"
                elif e.status and e.status < 400:
                    color = "green"

                table.add_row(
                    Text(ts, style=color),
                    Text(e.ip or "-", style=color),
                    Text(e.method or "-", style=color),
                    Text(path_msg, style=color),
                    Text(status_s, style=color),
                    Text(e.level, style=color),
                )
                shown += 1

            self.query_one("#status-bar", Label).update(
                f"{shown:,} satır gösteriliyor ({len(entries):,} toplam)"
            )

        @on(Input.Changed, "#search-bar")
        def on_search(self, event: Input.Changed) -> None:
            if self.active_file and self.active_file in self.loaded_files:
                entries, _ = self.loaded_files[self.active_file]
                self._render_logs(entries, keyword=event.value)

        # ── Güvenlik ──────────────────────────────────────────────────────────

        def _render_security(self, entries: list[LogEntry], s: Stats) -> None:
            lines = ["[bold underline red]Güvenlik Raporu[/]\n"]

            if s.brute_force_ips:
                lines.append(f"[bold red]⚠  Brute-Force Tespit Edildi ({len(s.brute_force_ips)} IP)[/]")
                for ip in s.brute_force_ips:
                    lines.append(f"   • {ip}  ({s.failed_logins.get(ip, 0)} başarısız deneme)")
                lines.append("")
            else:
                lines.append("[green]✓  Brute-force saldırısı tespit edilmedi.[/]\n")

            if s.failed_logins:
                lines.append("[bold yellow]Başarısız Giriş Denemeleri (Top 15)[/]")
                fail_t = Table("IP", "Deneme", box=None, padding=(0, 1))
                for ip, cnt in s.failed_logins.most_common(15):
                    style = "red" if ip in s.brute_force_ips else "yellow"
                    fail_t.add_row(Text(ip, style=style), Text(str(cnt), style=style))
                lines.append(self._table_to_str(fail_t))

            # 404 bombaları
            not_found_ips: Counter = Counter()
            for e in entries:
                if e.status == 404 and e.ip:
                    not_found_ips[e.ip] += 1
            suspect_404 = [(ip, cnt) for ip, cnt in not_found_ips.items() if cnt > 20]
            if suspect_404:
                lines.append("\n[bold yellow]Şüpheli 404 Taraması (>20 istek)[/]")
                for ip, cnt in sorted(suspect_404, key=lambda x: -x[1])[:10]:
                    lines.append(f"   • {ip}  →  {cnt} × 404")

            self.query_one("#security-panel", Static).update("\n".join(lines))

        # ── İstatistikler ─────────────────────────────────────────────────────

        def _render_charts(self, s: Stats) -> None:
            lines = ["[bold underline]Saatlik Dağılım[/]\n"]
            if s.hourly:
                max_val = max(s.hourly.values()) or 1
                for hour in range(24):
                    cnt = s.hourly.get(hour, 0)
                    bar_len = int(cnt / max_val * 40)
                    bar = "█" * bar_len
                    lines.append(f"  {hour:02d}:00  {bar:<40} {cnt:>6,}")
            lines.append("")
            if s.methods:
                lines.append("[bold underline]HTTP Yöntem Dağılımı[/]\n")
                max_m = max(s.methods.values()) or 1
                for method, cnt in s.methods.most_common():
                    bar_len = int(cnt / max_m * 30)
                    lines.append(f"  {method:<8} {'█' * bar_len:<30} {cnt:>6,}")
            lines.append("")
            if s.status_codes:
                lines.append("[bold underline]Durum Kodu Dağılımı[/]\n")
                max_sc = max(s.status_codes.values()) or 1
                for code in sorted(s.status_codes):
                    cnt = s.status_codes[code]
                    bar_len = int(cnt / max_sc * 30)
                    color = "green" if code < 400 else ("yellow" if code < 500 else "red")
                    bar = f"[{color}]{'█' * bar_len}[/]"
                    lines.append(f"  {code}  {bar:<40} {cnt:>6,}")

            self.query_one("#chart-panel", Static).update("\n".join(lines))

        # ── Eylemler ──────────────────────────────────────────────────────────

        def action_filter(self) -> None:
            self.push_screen(FilterModal(), self._apply_filter)

        def _apply_filter(self, result: dict | None) -> None:
            if result is not None:
                self._filter = result
                if self.active_file and self.active_file in self.loaded_files:
                    entries, _ = self.loaded_files[self.active_file]
                    self._render_logs(entries)

        def action_export(self) -> None:
            if not self.active_file:
                self.notify("Önce bir dosya yükleyin.", severity="warning")
                return
            self.push_screen(ExportModal(), self._do_export)

        def _do_export(self, result: tuple | None) -> None:
            if result and self.active_file in self.loaded_files:
                fmt, path_str = result
                entries, _ = self.loaded_files[self.active_file]
                out = Path(path_str)
                try:
                    if fmt == "json":
                        export_json(entries, out)
                    else:
                        export_csv(entries, out)
                    self.notify(f"Dışa aktarıldı: {out}", severity="information")
                except Exception as e:
                    self.notify(f"Hata: {e}", severity="error")

        def action_reload(self) -> None:
            if self.active_file:
                self._load(Path(self.active_file))


    class _PathInput(ModalScreen):
        """Dosya yolu giriş ekranı."""

        def compose(self) -> ComposeResult:
            with Vertical(id="filter-dialog"):
                yield Label("Dosya Yolu", id="filter-title")
                yield Input(placeholder="örn: /var/log/auth.log", id="path-input")
                with Horizontal(id="filter-buttons"):
                    yield Button("Yükle", id="btn-load", variant="primary")
                    yield Button("İptal", id="btn-pcancel", variant="error")

        @on(Button.Pressed, "#btn-pcancel")
        def cancel(self) -> None:
            self.dismiss(None)

        @on(Button.Pressed, "#btn-load")
        def load(self) -> None:
            val = self.query_one("#path-input", Input).value.strip()
            self.dismiss(val or None)

        @on(Input.Submitted, "#path-input")
        def submitted(self, event: Input.Submitted) -> None:
            self.dismiss(event.value.strip() or None)


# ── CLI Giriş Noktası ─────────────────────────────────────────────────────────

def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(
        description="Log Analyzer — Apache, Nginx, Syslog, Auth.log, Windows Event Log"
    )
    ap.add_argument("dosya", nargs="?", help="Analiz edilecek log dosyası")
    ap.add_argument("--pattern", metavar="REGEX", help="Özel regex deseni (named groups)")
    ap.add_argument("--export-json", metavar="ÇIKTI", help="JSON olarak dışa aktar (TUI olmadan)")
    ap.add_argument("--export-csv",  metavar="ÇIKTI", help="CSV olarak dışa aktar (TUI olmadan)")
    args = ap.parse_args()

    # TUI olmayan mod: doğrudan analiz + dışa aktarma
    if args.dosya and (args.export_json or args.export_csv):
        entries, fmt = parse_file(Path(args.dosya), args.pattern or "")
        s = analyze(entries)
        print(f"\n  Format     : {fmt}")
        print(f"  Toplam     : {s.total:,}")
        print(f"  Hata       : {s.errors:,}")
        print(f"  Uyarı      : {s.warnings:,}")
        print(f"  Brute-force: {len(s.brute_force_ips)} IP")
        if args.export_json:
            export_json(entries, Path(args.export_json))
            print(f"  JSON → {args.export_json}")
        if args.export_csv:
            export_csv(entries, Path(args.export_csv))
            print(f"  CSV  → {args.export_csv}")
        return

    if not _TUI_OK:
        print("[HATA] Textual kütüphanesi bulunamadı.")
        print("Kurmak için: pip install textual")
        sys.exit(1)

    app = LogAnalyzerApp(initial_file=args.dosya or "")
    app.run()


if __name__ == "__main__":
    main()