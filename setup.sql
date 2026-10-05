CREATE DATABASE SecurityDB;
GO

USE SecurityDB;
GO

CREATE TABLE dbo.SecurityLogs (
    LogID INT IDENTITY(1,1) PRIMARY KEY,
    SourceIP VARCHAR(45) NOT NULL,
    EventType VARCHAR(100) NOT NULL,
    Severity VARCHAR(20) NOT NULL,
    EventTime DATETIME NOT NULL DEFAULT GETDATE(),
    Description VARCHAR(500)
);
GO

CREATE TABLE dbo.Incidents (
    IncidentID INT IDENTITY(1,1) PRIMARY KEY,
    LogID INT NOT NULL,
    IncidentName VARCHAR(150) NOT NULL,
    Status VARCHAR(50) NOT NULL,
    AssignedTo VARCHAR(100),
    CreatedAt DATETIME NOT NULL DEFAULT GETDATE(),

    CONSTRAINT FK_Incidents_SecurityLogs
        FOREIGN KEY (LogID)
        REFERENCES dbo.SecurityLogs(LogID)
);
GO
