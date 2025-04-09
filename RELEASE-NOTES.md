# SPSWakeUp - Release Notes

## [4.0.0] - 2025-04-09

### Added

Wiki Documentation in repository - Add:

- wiki\Getting-Started-Archive.md
- wiki\Usage-Archive.md

### Changed

Wiki Documentation in repository - Update with new parameters:

- wiki\Getting-Started.md
- wiki\Usage.md

SPSWakeUP.ps1:

- BREAKING CHANGE - Add new parameter Action
- Add new function:

  - Add-SPSWakeUpEvent | Logs events to the Windows Event Viewer under a custom log named SPSWakeUp.
  - Get-SPSInstalledProductVersion | Retrieves the version of the installed SharePoint product by checking the Microsoft.SharePoint.dll file.
  - Install-SPSWakeUP | Installs the SPSWakeUp script by creating a scheduled task and configuring necessary permissions for the specified user.
  - Invoke-SPSWebRequest | Sends HTTP requests to SharePoint URLs in a multi-threaded manner to warm up the sites.
  - Invoke-SPSAdminSites | Sends HTTP requests to SharePoint Admin URLs to warms up SharePoint Central Administration site Pages.

- BREAKING CHANGE - Remove function:

  - Write-LogException
  - Add-PSSharePoint

- BREAKING CHANGE - Rename function:

  - Add-SPSTask => Add-SPSSheduledTask
  - Remove-SPSTask => Remove-SPSSheduledTask

## Changelog

A full list of changes in each version can be found in the [change log](CHANGELOG.md)
