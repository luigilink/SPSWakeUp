# SPSWakeUp - Wake Up Your SharePoint

SPSWakeUp is a PowerShell script tool to warm up all site collections in your SharePoint environment.

Current architecture uses two scripts:

- `SPSWakeUP.ps1`: main entrypoint (orchestrator), SharePoint URL collection, install/uninstall, and PowerShell 5.1 compatibility flow.
- `SPSWakeUp-pwsh.ps1`: PowerShell 7.x worker for warm-up web requests.

When PowerShell 7.x is available, the main script delegates warm-up to `SPSWakeUp-pwsh.ps1`.
If PowerShell 7.x is not installed, the main script automatically falls back to the PowerShell 5.1 warm-up flow.

## Key Features

- **Multiple authentication providers** => Works with Integrated windows and Forms Based Authentication
- **Multi-Threading** for better performance => Execution time can be divide per 4 (depends of CPU Number)
- Better performance with **output-cache** for Publishing Site
- **HSNC** Host Named Site Collection
- Disable Loop Back Check
- **Automatic Installation** in Task Scheduler

Use web requests to warm up pages and related assets, log script results in log files, and configure prerequisites for reliable warm-up.

This current version supports FBA and Windows Authentication (Claims, NTLM and Kerberos).

For details on installation, features, and parameters, explore the links below:

> [!IMPORTANT]
> Install and run SPSWakeUp on SharePoint Web Front End (WFE) servers only.
> Do not install or run SPSWakeUp on servers with the Search MinRole.

- [Getting Started](./Getting-Started)
- [Features](./Features)
- [Usage](./Usage)

> [!IMPORTANT]
> For previous version of SPSWakeUp like 3.x, explore the links below:
>
> - [Getting Started](./Getting-Started-Archive)
> - [Usage](./Usage-Archive)
