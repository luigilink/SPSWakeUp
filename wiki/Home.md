# SPSWakeUp - Wake Up Your SharePoint

SPSWakeUp is a PowerShell script tool to warm up all site collection in your SharePoint environment.

## Key Features

- **Multiple authentication providers** => Works with Integrated windows and Forms Based Authentication
- **Multi-Threading** for better performance => Execution time can be divide per 4 (depends of CPU Number)
- Better performance with **output-cache** for Publishing Site
- **HSNC** Host Named Site Collection
- Disable Loop Back Check
- **Automatic Installation** in Task Scheduler

Use WebRequest from System.Net.HttpWebRequest to download JS, CSS and Pictures files, Log script results in log file, Configure automatically prerequisites for a best warm-up.

This current version supports FBA and Windows Authentication (Claims, NTLM and Kerberos).

For details on installation, features, and parameters, explore the links below:

- [Getting Started](./Getting-Started)
- [Features](./Features)
- [Usage](./Usage)

> [!IMPORTANT]
> For previous version of SPSWakeUp like 3.x, explore the links below:
>
> - [Getting Started](./Getting-Started-Archive)
> - [Usage](./Usage-Archive)
