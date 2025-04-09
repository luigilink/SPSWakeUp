# Getting Started (for previous version of SPSWakeUp like 3.x)

## Prerequisites

- PowerShell 5.0 or later
- Administrative privileges on the SharePoint Server

## Installation

### Download the latest release

[Download the release from Github](https://github.com/luigilink/SPSWakeUp/releases/latest) and unzip to a directory on your SharePoint Server.

[Download the release from PSGallery](https://www.powershellgallery.com/packages/SPSWakeUP) Alternatively, you can install the script directly from the PowerShell Gallery by running:

```powershell
Install-Script -Name SPSWakeUP -Verbose
```

### Install the script in TaskScheduler

Run the script with the following command:

```powershell
.\SPSWakeUp.ps1 -Install -InstallAccount (Get-Credential)
```

## Next Step

For the next steps, go to the [Usage](./Usage-Archive) page.

## Change log

A full list of changes in each version can be found in the [change log](https://github.com/luigilink/SPSWakeUp/blob/main/CHANGELOG.md).
