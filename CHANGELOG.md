# Change log for SPSWakeUp

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.6.0] - 2022-10-27

### Added

- Add integration.yml file
- Add RELEASE.md file

### Changed

- README.md
  - Add SharePoint Server Subscription Edition support
  - Remove SharePoint 2010 support
  - Update minimum PowerShell version supported

## [2.5.1] - 2022-10-14

### Removed

- SPSWakeUP.ps1
  - Remove duplicate entries before writing in HOSTS File

## [2.5.0] - 2021-07-21

### Changed

- SPSWakeUP.ps1
  - Check if Web Application Url contains One of SPServer and remove it from HOSTS

## [2.4.0] - 2020-02-20

### Added

- SPSWakeUP.ps1
    - Add Uninstall and OnlyRootWeb parameters
    - Add Remove-SPSTask function
    - Add reporting: Memory Usage for each worker process

### Changed

- SPSWakeUP.ps1
  - Update Get-SPSSitesUrl function with Service Application Urls and SPWeb urls

### Removed

- SPSWakeUP.ps1
  - Remove functions: Get-SPSWebRequest, Add-IETrustedSite and Clear-IECache
- README.md
  - Remove Internet Explorer information

## [2.3.1] - 2020-02-20

### Changed

- SPSWakeUP.ps1
  - Fix issue "You cannot call a method on a null-valued expression" when InstallAccount variable is null

## [2.3.0] - 2019-11-27

### Changed

- README.md
  - Add SharePoint 2019 support
- SPSWakeUP.ps1
  - Remove sitemaster-[GUID] urls in Get-SPSSitesUrl and Get-SPSHSNCUrl functions
  - For SharePoint 2016 or higher, check if local server has Search MinRole
  - Check if HOSTS File already contains Urls of All Web Applications or HSNC
  - Security Fix: Change UserName and Password parameters by InstallAccount parameter

### Removed

- Remove Modules folder

## [2.2.1] - 2019-11-27

### Changed

- README.md
  - Latest release date, Total downloads and Issues opened
- SPSWakeUP.ps1
  - Add Try-Catch exception in Get-SPSThrottleLimit function
  - Fix issue on Get-SPSThrottleLimit when CimInstance returns an array

### [2.2.0] - 2018-03-07

### Changed

- SPSWakeUP.ps1
  - Support of Form Based Authentication (XML element removed from SPSWakeUP.xml)
  - Update description of script
- Readme.md
  - Add Download link for latest release

### Added

- Add SPSWakeUp.psd1 file to replace xml file
- SPSWakeUP.ps1
  - Add Write-VerboseMessage function
  - Add UserName and Password parameter for installation process
  - Update ps1 for the input file psd1
  - Update parameter of script
- Improved code styling by following PowerShell guidelines:
  - Changing alias to its full content
  - Function Names Must Use Approved Verbs
  - Using Named Parameters Instead of Positional Parameters
  - Rename logfolder by scriptRootPath
  - Remove variable not used

### Removed

- SPSWakeUP.ps1
  - Remove all global variables
  - Remove Get-SPSUserPassword function
  - Remove mailLogContent variable
  - Rename Add-LogContent function to Write-LogContent
- Remove SPSWakeUP.xml file
- Remove Internet Explorer warmup in ps1 and psd1 files

### [2.1.4] - 2016-10-14

### Changed

- SPSWakeUP.ps1
  - Fix Exception log
  - Update function Get-SPSWebAppUrl: Check if url contains computername
  - Check if hostEntries variable is not null before change HOST system file
  - Improved code styling by following PowerShell guidelines

### Removed

- SPSWakeUP.xml
  - Delete CustomUrls and ExcludeUrls XML Elements
  - Delete FBA.ServiceAccount XML Element

### [2.1.3] - 2016-10-13

### Added

- SPSWakeUP.ps1
  - Add functions: Get-SPWebServicesUrl, Backup-HostsFile, Restore-HostsFile and Clear-HostsFileCopy
  - Add variables for HOSTS and Backup Hosts file with today's date: hostsFile and hostsFileCopy
  - Improved code styling by following PowerShell guidelines

### [2.1.2] - 2016-10-12

### Added

- SPSWakeUP.ps1
  - Add psVersion variable that contains the actual PowerShell version
  - Add function Get-SPSVersion
  - Check support between PSVersion and SharePoint Server 2010
  - Improved code styling by following PowerShell guidelines

### [2.1.1] - 2016-10-11

### Added

- Initial public release of SPSWakeUp on Github
- SPSWakeUP.ps1
  - All Supported version of SharePoint (2010, 2013 and 2016)
  - Automatic Installation in Task Scheduler
  - Multi-Threading for better performance
  - Output-Cache for Publishing Sites
  - Works with FBA if Windows authentication is enabled on the same web application
  - Use Internet Explorer to download JS, CSS and Pictures files
  - All site collection (HSNC include) for all web applications are included in warm-up
  - Disable IE ESC, Disable LoopBackCheck : *Secure *or Less Secure
  - Add Web application Urls in HOSTS file and in Internet Options Security,
  - Add User Account in User Policy for Each Web Application,
  - Clear Cache Internet Explorer.
  - Logging: Log script results in log file, Cleaning log files after 30 days by default.
- SPSWakeUP.xml
  - Email notifications : SMTP settings
  - Add or/and remove urls from warm-up
  - Central Administration can be include or exclude