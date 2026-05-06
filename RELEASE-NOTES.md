# SPSWakeUp - Release Notes

## [4.1.3] - 2026-05-06

### Added

Implement Pester tests for script functionality, resource management, and security practices:

- .github/workflows/pester.yml
- tests/SPSWakeUP.Tests.ps1
- tests/README.md

### Fixed

SPSWakeUP.ps1:

- Fix variable name inconsistency in Invoke-SPSWebRequest — $webApp was assigned but $webapp (different case) was used when constructing the webSession authentication URL, causing the URL to be built from a null reference.

- The term 'Clear-SPSLog' is not recognized as the name of a cmdlet ([issue #34](https://github.com/luigilink/SPSWakeUp/issues/34)).
- Fix function name typo: Disable-IEFirsRun → Disable-IEFirstRun.
- Fix undefined variable bug in Get-SPSSitesUrl by removing unused $AllSites check.
- Fix inconsistent output methods by replacing Write-Host with Write-Output in Set-SPSProxySetting function.
- Fix bug in Remove-SPSSheduledTask where a caught exception left $TaskFolder unassigned, causing a second unhandled error on the next statement — added early return in the catch block.
- Fix Get-SPSInstalledProductVersion returning .FileVersion string instead of the FileVersionInfo object — callers use .ProductMajorPart and .ProductBuildPart which are FileVersionInfo properties, not string properties. Returning a string caused both to resolve as $null, and $null -le 12999 evaluates to $true in PowerShell (null coerces to 0), so the SharePoint 2013 PSSnapin branch was always taken regardless of the installed version. Updated [OutputType] to [System.Diagnostics.FileVersionInfo].

### Changed

SPSWakeUP.ps1:

- Add COM object cleanup with ReleaseComObject in Add-SPSSheduledTask and Remove-SPSSheduledTask functions to prevent memory leaks.
- Add Remove-Variable for sensitive data (passwords, credentials) to reduce security exposure in memory.
- Add runspace job cleanup with Pipe.Dispose() in Invoke-SPSWebRequest to prevent memory leaks in multi-threading operations.
- Add module import check before Import-Module SharePointServer to prevent unnecessary re-imports.
- Improve resource management with proper cleanup in finally blocks and early exit scenarios.
- Cache $webapp.GetResponseUri('Default').AbsoluteUri result into $responseUri in Get-SPSWebAppUrl to avoid redundant method calls per loop iteration.
- Replace -Include with -Filter parameter in Get-ChildItem call in Clear-SPSLog for filesystem-level filtering and better performance.
- Replace -Include with -Filter parameter in Get-ChildItem call in Clear-HostsFileCopy and remove intermediate $extension variable.
- Replace single-use $Now intermediate variable with inline (Get-Date).AddDays(-$days) in Clear-SPSLog.
- Remove redundant $null -ne $file null guard inside foreach loop in Clear-SPSLog — Get-ChildItem never emits null items.
- Replace $Jobs and $Results array accumulation (@() + +=) with [System.Collections.Generic.List[object]]::new() and .Add() in Invoke-SPSWebRequest to avoid O(n²) array copy overhead on large URL sets.
- Remove $Host.UI.RawUI.WindowTitle assignment from initialization section.
- Remove unused Get-SPSVersion function.
- Add [CmdletBinding(SupportsShouldProcess)] and $PSCmdlet.ShouldProcess() guards to Remove-SPSSheduledTask and Set-SPSProxySetting to satisfy PSUseShouldProcessForStateChangingFunctions and enable -WhatIf/-Confirm support.
- Rename Invoke-SPSAdminSites → Invoke-SPSAdminSite, Invoke-SPSAllSites → Invoke-SPSAllSite, Set-SPSProxySettings → Set-SPSProxySetting to comply with PSUseSingularNouns convention.

Update release.yml to clarify workflow purpose

## Changelog

A full list of changes in each version can be found in the [change log](CHANGELOG.md)
