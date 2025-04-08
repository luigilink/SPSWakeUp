# Change log for SPSWakeUp

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

Wiki Documentation in repository - Add:
wiki\Home.md
wiki\Getting-Started.md
wiki\Usage.md
.github\workflows\wiki.yml

### Changed

- SPSWakeUP.ps1:
  - Add PSScriptInfo for PSGallery
  - Remove spwakeup.com url or update with github project url

## [3.0.2] - 2024-12-16

### Changed

- CONTRIBUTING.md add new line top respect mardown file best practices
- SPSWakeUP.ps1:
  - Update NOTES
  - Review Indentation

## [3.0.1] - 2024-10-10

### Added

- README.md
  - Add code_of_conduct.md badge
- Add CODE_OF_CONDUCT.md file
- Add Issue Templates files:
  - 1_bug_report.yml
  - 2_feature_request.yml
  - 3_documentation_request.yml
  - 4_improvement_request.yml
  - config.yml

### Changed

- Rename folder Scripts to scripts

### Fixed

- Increase major version to 3.x.x as suggested by DennisL68 in ([issue #17](https://github.com/luigilink/SPSWakeUp/issues/17))

## [2.7.2] - 2023-06-15

### Changed

- SPSWakeUP.ps1
  - BREAKING CHANGE: Remove Add-HostsEntry function
  - Using the CmdLet Add-Content for update HOSTS file

## [2.7.1] - 2023-05-10

### Changed

- SPSWakeUP.ps1
  - Add ErrorAction parameter for SPWeb CmdLet
- release.yml
  - Use softprops/action-gh-release@v1 action for release step
  - Add github.ref for release name
  - Remove actions/upload-artifact@v3

### Added

- Add RELEASE-NOTES.md file

## [2.7.0] - 2023-05-08

### Changed

- README.md
  - BREAKING CHANGE: Windows Management Framework 5.0 is required
  - Remove SharePoint Server 2013 from supported versions
- Remove azure-pipelines.yml and SPSWakeUp.psd1 files
- SPSWakeUP.ps1
  - BREAKING CHANGE: Remove InputFile and OnlyRootWeb switch parameters and update examples
  - Add Transcript boolean parameter and update examples
  - BREAKING CHANGE: Remove logging functions and logging variables
  - Replace Write-LogContent function with Write-Output CmdLet
  - BREAKING CHANGE: Remove functions :
    - Add-RASharePoint, Add-SystemWeb, Disable-IEESC, Disable-IEFirstRun,
    - Backup-HostsFile, Restore-HostsFile, Add-SPSSitesUrl, Get-SPSHSNCUrl
  - Update Disable-LoopbackCheck, Add-HostsEntry, Get-SPSSitesUrl and Get-SPSWebAppUrl functions
  - Remove unnecessary comments
  - Add Get-SPSAdminUrl function to improve central admin urls warmup

## [2.6.1] - 2023-01-18

### Changed

- SPSWakeUp.ps1
  - Replaced if-elseif-else logic with pseudo ternary operator to get throttle value.

## [2.6.0] - 2022-10-27

### Added

- Add release.yml file

### Changed

- SPSWakeUP.ps1
  - Update SPSWakeUp Version
- README.md
  - Add SharePoint Server Subscription Edition support
  - Remove SharePoint 2010 support
  - Update minimum PowerShell version supported

## [2.5.1] - 2022-10-14

### Changed

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
  - Disable IE ESC, Disable LoopBackCheck : _Secure_ or _Less Secure_,
  - Add Web application Urls in HOSTS file and in Internet Options Security,
  - Add User Account in User Policy for Each Web Application,
  - Clear Cache Internet Explorer.
  - Logging: Log script results in log file, Cleaning log files after 30 days by default.
- SPSWakeUP.xml
  - Email notifications : SMTP settings
  - Add or/and remove urls from warm-up
  - Central Administration can be include or exclude
