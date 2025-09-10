# SPSWakeUP Installation Guide

This document provides instructions for installing and configuring the **SPSWakeUP** PowerShell script in environments without internet access. It is intended for SharePoint On-Premises administrators who need to warm up site collections automatically.

## 📦 Prerequisites

- SharePoint Server (2016 or later)
- Administrator privileges on the server
- PowerShell 5.1 or later
- Valid credentials for task scheduler setup

## 📁 Files Required

Ensure the following files are available locally:

- `SPSWakeUP.ps1` (main script)
- Any dependencies or modules used by the script (if applicable)

## 🛠 Installation Steps

### 1. Copy Files to Server

Place `SPSWakeUP.ps1` in a local folder on the SharePoint server, e.g., `E:\SCRIPT\`.

### 2. Run Script with Install Action

Open PowerShell as Administrator and execute:

```powershell
E:\SCRIPT\SPSWakeUP.ps1 -Action Install -InstallAccount (Get-Credential)
```

This will:

- Validate credentials
- Add a scheduled task to run daily at 6:00 AM
- Configure read access for the warm-up account

### 3. Verify Scheduled Task

Check Task Scheduler under the `SharePoint` folder for a task named `SPSWakeUP`.

## 🔄 Uninstalling

To remove the scheduled task:

```powershell
E:\SCRIPT\SPSWakeUP.ps1 -Action Uninstall
```

## 🔍 Admin Sites Only Mode

To warm up only the Central Administration site:

```powershell
E:\SCRIPT\SPSWakeUP.ps1 -Action AdminSitesOnly
```

## 📝 Logging and Transcript

To enable PowerShell transcript logging:

```powershell
E:\SCRIPT\SPSWakeUP.ps1 -Transcript:$True
```

Log files will be saved in the script directory.

## 📚 Additional Notes

- The script automatically disables proxy settings during execution and restores them afterward.
- It supports multi-threaded web requests for efficient warm-up.
- HOSTS file entries are backed up and cleaned automatically.

## 📄 License

MIT License

## 👤 Authors

- Jean-Cyril Drouhin (luigilink)
- Des Finkenzeller (Nutsoft)

For more details, refer to the embedded comments in `SPSWakeUP.ps1`.
