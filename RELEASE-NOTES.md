# SPSWakeUp - Release Notes

## [5.0.0] - 2026-09-01

### Removed

- **BREAKING:** Drop support for SharePoint Server 2016 and 2019 (both reached end of support on 14 July 2026). SPSWakeUp now targets **SharePoint Server Subscription Edition** only ([#49](https://github.com/luigilink/SPSWakeUp/issues/49)).
- Remove the deprecated `Microsoft.SharePoint.PowerShell` PSSnapin load path and the associated product-version detection.
- Remove the now-unused `Get-SPSInstalledProductVersion` helper.

### Changed

- Load the `SharePointServer` module only, guarded by an explicit availability check that throws a clear error when the module is missing.
- Simplify the Search MinRole guard that was gated on `buildversion.major -ge 16` (always true on Subscription Edition).
- Bump script version metadata and in-script version variables to `5.0.0`.

### Migration

- Users still running SharePoint Server 2016 or 2019 must stay on the previous release [v4.2.4](https://github.com/luigilink/SPSWakeUp/releases/tag/v4.2.4), which retains the legacy PSSnapin path.

## Changelog

A full list of changes in each version can be found in the [change log](CHANGELOG.md)
