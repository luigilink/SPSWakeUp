# Change log for SPSWakeUp

## 2.2.1

* Add Try-Catch exception in Get-SPSThrottleLimit function
* Fix issue on Get-SPSThrottleLimit when CimInstance returns an array
* Update README.md file with Latest release date, Total downloads and Issues opened

### 2.2.0

* Support of Form Based Authentication (XML element removed from SPSWakeUP.xml)
* Update description of script
* Remove all global variables
* Remove Get-SPSUserPassword function
* Remove mailLogContent variable
* Rename Add-LogContent function to Write-LogContent
* Update Readme.md
* Add functions:
  * Write-VerboseMessage
* Improved code styling by following PowerShell guidelines:
  * Changing alias to its full content
  * Function Names Must Use Approved Verbs
  * Using Named Parameters Instead of Positional Parameters
  * Rename logfolder by scriptRootPath
  * Remove variable not used
* Add SPSWakeUp.psd1 file to replace xml file
* Update ps1 for the input file psd1
* Add UserName and Password parameter for installation process
* Remove SPSWakeUP.xml file
* Remove Internet Explorer warmup in ps1 and psd1 files
* Update parameter of script

### 2.1.4

* Change SPSWakeUP.xml file:
  * Delete CustomUrls and ExcludeUrls XML Elements
  * Delete FBA.ServiceAccount XML Element
* Fix Exception log
* Update function Get-SPSWebAppUrl: Check if url contains computername
* Check if hostEntries variable is not null before change HOST system file
* Improved code styling by following PowerShell guidelines

### 2.1.3

* Add functions:
  * Get-SPWebServicesUrl
  * Backup-HostsFile
  * Restore-HostsFile
  * Clear-HostsFileCopy
* Add variables for HOSTS and Backup Hosts file with today's date
  * hostsFile
  * hostsFileCopy
* Improved code styling by following PowerShell guidelines

### 2.1.2

* Add psVersion variable that contains the actual PowerShell version
* Add function Get-SPSVersion
* Check support between PSVersion and SharePoint Server 2010
* Improved code styling by following PowerShell guidelines

### 2.1.1

* Initial public release of SPSWakeUp on Github
