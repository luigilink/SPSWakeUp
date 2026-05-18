# SPSWakeUp - Wake Up Your SharePoint

![Latest release date](https://img.shields.io/github/release-date/luigilink/spswakeup.svg?style=flat)
![Total downloads](https://img.shields.io/github/downloads/luigilink/spswakeup/total.svg?style=flat)  
![Issues opened](https://img.shields.io/github/issues/luigilink/spswakeup.svg?style=flat)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](code_of_conduct.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Description

SPSWakeUp is a PowerShell script tool to warm up all site collection in your SharePoint environment.

It's compatible with all supported versions for SharePoint OnPremises (2016 to Subscription Edition).

[Download the latest release, Click here!](https://github.com/luigilink/spswakeup/releases/latest)

## Requirements

## Deployment Guidance (Server Role)

- Install and run SPSWakeUp on SharePoint Web Front End (WFE) servers.
- Do not install or run SPSWakeUp on servers using the Search MinRole.

### Windows Management Framework 5.0

Required because this module now implements class-based resources.
Class-based resources can only work on computers with Windows
Management Framework 5.0 or above.
The preferred version is PowerShell 5.1 or higher, which ships with Windows 10 or Windows Server 2016.

### PowerShell 7.x (Optional)

PowerShell 7.x is optional but recommended to run the PS7 warm-up worker script (`SPSWakeUp-pwsh.ps1`) for improved web request execution.

Installation source (official Microsoft docs):

- [Install PowerShell on Windows](https://learn.microsoft.com/en-us/powershell/scripting/install/install-powershell-on-windows)

This is discussed further on the [SPSWakeUp Wiki Getting-Started](https://github.com/luigilink/SPSWakeUp/wiki/Getting-Started)

## Script Architecture

SPSWakeUp now uses a 2-script model:

- `scripts/SPSWakeUP.ps1`: main entrypoint, orchestration, SharePoint URL collection, and PowerShell 5.1 compatibility path.
- `scripts/SPSWakeUp-pwsh.ps1`: PowerShell 7.x worker used for `Invoke-WebRequest` warm-up operations.

When `pwsh` (PowerShell 7.x) is available, `SPSWakeUP.ps1` delegates the warm-up phase to `SPSWakeUp-pwsh.ps1`.
If PowerShell 7.x is not installed, `SPSWakeUP.ps1` automatically falls back to the PowerShell 5.1 warm-up flow.

## PowerShell Gallery

If you install scripts from PowerShell Gallery, install both scripts so PS7 mode is available:

```powershell
Install-Script -Name SPSWakeUP -Scope CurrentUser
Install-Script -Name SPSWakeUp-pwsh -Scope CurrentUser
```

If only `SPSWakeUP` is installed, the script can still run using the PowerShell 5.1 fallback path.

## Documentation

For detailed usage, configuration, and getting started information, visit the [SPSWakeUp Wiki](https://github.com/luigilink/SPSWakeUp/wiki)

## Changelog

A full list of changes in each version can be found in the [change log](CHANGELOG.md)
