## Description
SPSWakeUp is a PowerShell script tool to warm up all site collection in your SharePoint environment. It's compatible with all supported versions for SharePoint (2010, 2013 and 2016).

## Features

* **Multiple authentication providers** => Works with Integrated windows and Forms Based Authentication
* **Multi-Threading** for better performance => Execution time can be divide per 4 (depends of CPU Number)
* Better performance with **output-cache** for Publishing Site
* **HSNC** Host Named Site Collection
* Disable Loop Back Check - Secure Mode (backconnectionhostnames)
* **Automatic Installation** in Task Scheduler

Use Internet Explorer to download JS, CSS and Pictures files, Log script results in rtf file, Email nofications, Configure automatically prerequisites for a best warm-up, possibility to add or remove custom url, etc ... 
This current version supports FBA and Windows Authentication (Claims, NTLM and Kerberos).
For more details of available features [Click here!](https://github.com/luigilink/spswakeup/wiki/Features)

## Requirements 

The minimum PowerShell version required is 2.0, which ships in Windows Server 2008 R2 (or higher versions).
The preferred version is PowerShell 5.0 or higher, which ships with Windows 10 or Windows Server 2016. 

## Changelog

A full list of changes in each version can be found in the [change log](CHANGELOG.md)
