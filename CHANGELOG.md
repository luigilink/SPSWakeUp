# Change log for SPSWakeUp

### Unreleased

* Support of Form Based Authentication (XML element removed from SPSWakeUP.xml)

### 2.1.4

* Change SPSWakeUP.xml file:
 - Delete CustomUrls and ExcludeUrls XML Elements
 - Delete FBA.ServiceAccount XML Element
* Fix Exception log
* Update function Get-SPSWebAppUrl: Check if url contains computername
* Check if hostEntries variable is not null before change HOST system file
* Improved code styling by following PowerShell guidelines

### 2.1.3

* Add functions:
 - Get-SPWebServicesUrl
 - Backup-HostsFile
 - Restore-HostsFile
 - Clear-HostsFileCopy
* Add variables for HOSTS and Backup Hosts file with today's date
 - hostsFile
 - hostsFileCopy
* Improved code styling by following PowerShell guidelines

### 2.1.2

* Add psVersion variable that contains the actual PowerShell version
* Add function Get-SPSVersion
* Check support between PSVersion and SharePoint Server 2010
* Improved code styling by following PowerShell guidelines

### 2.1.1

* Initial public release of SPSWakeUp on Github
