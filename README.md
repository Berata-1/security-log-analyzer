# Security Log Analyzer

Python ve Microsoft SQL Server kullanılarak geliştirilmiş terminal tabanlı güvenlik log analiz ve incident yönetim sistemi.

Uygulama; Apache/Nginx, Syslog/Auth.log ve Windows Event Log gibi log kaynaklarını analiz edebilir, şüpheli aktiviteleri tespit edebilir ve tespit edilen güvenlik olaylarını SQL Server veritabanına kaydedebilir.

## Features

- Apache / Nginx log analizi
- Syslog / Auth.log analizi
- Windows Event Log desteği
- Brute-force saldırı tespiti
- Başarısız giriş denemelerinin analizi
- Şüpheli IP tespiti
- HTTP durum kodu analizi
- Log filtreleme ve arama
- JSON ve CSV dışa aktarma
- SQL Server entegrasyonu
- Güvenlik olaylarının otomatik kaydedilmesi
- Aynı olayın tekrar kaydedilmesini engelleyen duplicate kontrolü
- High severity olaylarda otomatik incident oluşturma
- Incident durum ve sorumlu bilgisi
- Terminal tabanlı Textual kullanıcı arayüzü

## Technologies

- Python
- Microsoft SQL Server
- pyodbc
- Textual
- Rich
- SQL

## Project Flow

```text
Log File
   |
   v
Log Analyzer
   |
   v
Security Detection
   |
   v
Brute Force Detection
   |
   v
SecurityLogs
   |
   v
Automatic Incident Creation
   |
   v
Incidents
```

## Database Structure

### SecurityLogs

Güvenlik olaylarını saklar.

- LogID
- SourceIP
- EventType
- Severity
- EventTime
- Description

### Incidents

Tespit edilen önemli güvenlik olayları için oluşturulan vakaları saklar.

- IncidentID
- LogID
- IncidentName
- Status
- AssignedTo
- CreatedAt

`Incidents.LogID`, `SecurityLogs.LogID` alanına Foreign Key ile bağlıdır.

## Installation

Bağımlılıkları yükleyin:

```bash
pip install -r requirements.txt
```

Microsoft SQL Server üzerinde:

```text
setup.sql
```

dosyasını çalıştırarak gerekli veritabanı ve tabloları oluşturun.

## SQL Server Configuration

Varsayılan bağlantı yapılandırması:

```text
Server: localhost\MSSQLSERVER01
Database: SecurityDB
Authentication: Windows Authentication
ODBC Driver: ODBC Driver 18 for SQL Server
```

Farklı bir SQL Server instance kullanıyorsanız `log_analyzer.py` içerisindeki bağlantı ayarlarını değiştirin.

## Run

```bash
python log_analyzer.py
```

Uygulama açıldıktan sonra analiz edilecek log dosyası eklenebilir.

## Brute Force Test

Repository içerisindeki:

```text
sample_bruteforce.log
```

dosyası uygulamaya yüklenerek brute-force tespit sistemi test edilebilir.

Bir IP adresinden belirlenen zaman aralığında çok sayıda başarısız kimlik doğrulama denemesi tespit edildiğinde sistem bunu **Brute Force** olayı olarak işaretler.

High severity olay SQL Server üzerindeki `SecurityLogs` tablosuna kaydedilir ve otomatik olarak `Incidents` tablosunda yeni bir vaka oluşturulur.

## Example Incident

```text
Source IP:      192.168.1.202
Event Type:     Brute Force
Severity:       High
Incident Name:  Brute Force Investigation
Status:         Open
Assigned To:    Berat
```

## Purpose

Bu proje, log analizi, güvenlik olaylarının tespiti, veritabanı entegrasyonu ve temel incident management süreçlerini tek bir uygulamada birleştirmek amacıyla geliştirilmiştir.

## License

This project is licensed under the MIT License.
