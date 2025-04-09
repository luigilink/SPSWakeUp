# Usage Guide (for previous version of SPSWakeUp like 3.x)

## Overview

`SPSWakeUp.ps1` is a PowerShell script designed to wake up SharePoint sites by sending HTTP requests to their URLs. This ensures that the sites are preloaded into memory, reducing the initial load time for users.

## Prerequisites

- PowerShell 5.1 or later.
- Necessary permissions to access the SharePoint sites.
- Ensure the script is placed in a directory accessible by the user.

## Parameters

The script supports the following parameters:

| Parameter         | Description                                                                                                                                                 |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-Install`        | (Optional) Use the switch Install parameter if you want to add the warmup script in taskscheduler. InstallAccount parameter need to be set.                 |
| `-InstallAccount` | (Optional) Need parameter InstallAccount whent you use the switch Install parameter.                                                                        |
| `-Uninstall`      | (Optional) Use the switch Uninstall parameter if you want to remove the warmup script from taskscheduler.                                                   |
| `-AllSites`       | (Optional) Use the boolean AllSites parameter if you want to warmup the SPWebs of each site collection and only warmup the root web of the site collection. |
| `-AdminSites`     | (Optional) Use the boolean AdminSites parameter if you want to warmup the Central Administration Site collection.                                           |
| `-Transcript`     | (Optional) Use the boolean Transcript parameter if you want to start Transcrit PowerShell Feature.                                                          |

## Examples

### Example 1: Wake up central admin site

```powershell
.\SPSWakeUp.ps1 -AdminSites:$True
```

### Example 2: Wake up all sites

```powershell
.\SPSWakeUp.ps1 -AllSites:$True
```

### Example 3: Install script in Task Scheduler

```powershell
.\SPSWakeUp.ps1 -Install -InstallAccount (Get-Credential)
```

### Example 4: Uninstall script in Task Scheduler

```powershell
.\SPSWakeUp.ps1 -Uninstall
```

### Example 5: Enable Transcript

```powershell
.\SPSWakeUp.ps1 -Transcript:$True
```

## Logging

The script logs the status of each request, including success or failure, and saves it to the specified log file or the default location.

## Error Handling

- If a site URL is unreachable, the script will log the error and continue with the next URL.
- Ensure the provided credentials have access to the specified SharePoint sites.

## Notes

- Use HTTPS URLs for secure communication.
- Test the script in a non-production environment before deploying it widely.

## Support

For issues or questions, please contact the script maintainer or refer to the project documentation.
