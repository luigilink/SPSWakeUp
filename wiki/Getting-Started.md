# Getting Started

## Prerequisites

- PowerShell 5.0 or later
- PowerShell 7.x (optional, recommended for warm-up worker script)
- Administrative privileges on the SharePoint Server

## Installation

### Download the latest release

[Download the release from Github](https://github.com/luigilink/SPSWakeUp/releases/latest) and unzip to a directory on your SharePoint Server.

Ensure these files are present in the same folder:

- `SPSWakeUP.ps1`
- `SPSWakeUp-pwsh.ps1`

[Download the release from PSGallery](https://www.powershellgallery.com/packages/SPSWakeUP) Alternatively, you can install the script directly from the PowerShell Gallery by running:

```powershell
Install-Script -Name SPSWakeUP -Verbose
Install-Script -Name SPSWakeUp-pwsh -Verbose
```

`SPSWakeUP.ps1` remains the main entrypoint. If `pwsh` is available, it delegates warm-up requests to `SPSWakeUp-pwsh.ps1`; otherwise it uses a PowerShell 5.1 fallback flow.

### Install the script in TaskScheduler

Run the script with the following command:

```powershell
.\SPSWakeUp.ps1 -Action Install -InstallAccount (Get-Credential)
```

## Next Step

For the next steps, go to the [Usage](./Usage) page.

## Change log

A full list of changes in each version can be found in the [change log](https://github.com/luigilink/SPSWakeUp/blob/main/CHANGELOG.md).
