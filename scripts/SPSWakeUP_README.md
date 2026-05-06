# SPSWakeUP Installation Guide

This document provides instructions for installing and configuring the **SPSWakeUP** PowerShell script in environments without internet access. It is intended for SharePoint On-Premises administrators who need to warm up site collections automatically.

## 📦 Prerequisites

- SharePoint Server (2016 or later)
- Administrator privileges on the server
- PowerShell 5.1 (required)
- PowerShell 7.x (optional, recommended for faster web request warm-up)
- Valid credentials for task scheduler setup

PowerShell 7.x installation source (official Microsoft docs):

- [Install PowerShell on Windows](https://learn.microsoft.com/en-us/powershell/scripting/install/install-powershell-on-windows)

## 📁 Files Required

Ensure the following files are available locally:

- `SPSWakeUP.ps1` (main script/orchestrator)
- `SPSWakeUp-pwsh.ps1` (PowerShell 7 worker for warm-up web requests)

`SPSWakeUP.ps1` will use `SPSWakeUp-pwsh.ps1` when `pwsh` is available.
If PowerShell 7.x is not installed, it automatically falls back to the PowerShell 5.1 warm-up flow.

## 🛠 Installation Steps

### 1. Copy Files to Server

Place both scripts in the same local folder on the SharePoint server, for example `E:\SCRIPT\`:

- `SPSWakeUP.ps1`
- `SPSWakeUp-pwsh.ps1`

### 2. Run Script with Install Action

Open PowerShell as Administrator and execute:

```powershell
E:\SCRIPT\SPSWakeUP.ps1 -Action Install -InstallAccount (Get-Credential)
```

This will:

- Validate credentials
- Add a scheduled task to run daily at 6:00 AM
- Configure read access for the warm-up account

At runtime:

- If `pwsh` is installed, warm-up requests run via `SPSWakeUp-pwsh.ps1`.
- If `pwsh` is not found, warm-up requests run directly in the PowerShell 5.1 fallback path.

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
- In PowerShell 7 mode, warm-up requests run through the dedicated worker script for better parallel request handling.
- In PowerShell 5.1 mode, the script still runs using the built-in fallback warm-up flow.
- HOSTS file entries are backed up and cleaned automatically.

## 📄 License

MIT License

## 👤 Authors

- Jean-Cyril Drouhin (luigilink)
- Des Finkenzeller (Nutsoft)

For more details, refer to the embedded comments in `SPSWakeUP.ps1`.
