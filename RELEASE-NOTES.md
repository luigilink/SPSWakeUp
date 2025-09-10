# SPSWakeUp - Release Notes

## [4.1.0] - 2025-09-10

### Added

SPSWakeUP.ps1:

- Add new function:

  - Set-SPSProxySettings | Backup, Disable and Restore IE Proxy Settings ([issue #26](https://github.com/luigilink/SPSWakeUp/issues/26)).

Add README.md file for Installation guide in package release ([issue #25](https://github.com/luigilink/SPSWakeUp/issues/25)).

### Changed

SPSWakeUP.ps1:

- Use $PSScriptRoot instead of $MyInvocation.MyCommand.Definition
- Use [System.Diagnostics.FileVersionInfo]::GetVersionInfo instead of Get-Command
- Use Exit instead of Break
- Remove UseBasicParsing param in Invoke-WebRequest CmdLet ([issue #27](https://github.com/luigilink/SPSWakeUp/issues/27)).

## Changelog

A full list of changes in each version can be found in the [change log](CHANGELOG.md)
