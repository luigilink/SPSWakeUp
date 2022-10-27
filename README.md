# SPSWakeUp - Wake Up Your SharePoint

[https://spwakeup.com - Official WebSite](https://spwakeup.com)

![Latest release date](https://img.shields.io/github/release-date/luigilink/spswakeup.svg?style=flat)
![Total downloads](https://img.shields.io/github/downloads/luigilink/spswakeup/total.svg?style=flat)  
![Issues opened](https://img.shields.io/github/issues/luigilink/spswakeup.svg?style=flat)

## Description

SPSWakeUp is a PowerShell script tool to warm up all site collection in your SharePoint environment.

It's compatible with all supported versions for SharePoint OnPremises (2013 to Subscription Edition).

[Download the latest release, Click here!](https://github.com/luigilink/spswakeup/releases/latest)

## Features

* **Multiple authentication providers** => Works with Integrated windows and Forms Based Authentication
* **Multi-Threading** for better performance => Execution time can be divide per 4 (depends of CPU Number)
* Better performance with **output-cache** for Publishing Site
* **HSNC** Host Named Site Collection
* Disable Loop Back Check - Secure Mode (backconnectionhostnames)
* **Automatic Installation** in Task Scheduler

Use WebRequest from System.Net.HttpWebRequest to download JS, CSS and Pictures files, Log script results in log file, Email nofications, Configure automatically prerequisites for a best warm-up.

This current version supports FBA and Windows Authentication (Claims, NTLM and Kerberos).

For more details of available features [Click here!](https://github.com/luigilink/spswakeup/wiki/Features)

## Requirements

The minimum PowerShell version required is 4.0, which ships in Windows Server 2012 R2 (or higher versions).
The preferred version is PowerShell 5.1 or higher, which ships with Windows 10 or Windows Server 2016.

## Changelog

A full list of changes in each version can be found in the [change log](CHANGELOG.md)
