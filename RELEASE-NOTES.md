# SPSWakeUp - Release Notes

## [4.2.4] - 2026-08-17

### Fixed

- Fix warm-up failing in **SSL offloading** architectures where the Web Front End listens in HTTP only (no 443 binding) while the Default zone public URL is HTTPS. SPSWakeUp now selects the local warm-up scheme from the zone's real IIS bindings (`ServerBindings` / `SecureBindings`) instead of the offloaded public URL ([#46](https://github.com/luigilink/SPSWakeUp/issues/46)).

### Added

- Add `Get-SPSPreferredUrl` helper that chooses the warm-up protocol/host from the zone IIS bindings: HTTP when an HTTP ServerBinding exists (covers SSL offloading), HTTPS otherwise. Backward compatible for farms with a real 443 binding.

### Changed

- Refactor `Get-SPSWebAppUrl` and `Get-SPSSitesUrl` (and the Default-zone authentication URL) to build warm-up URLs through `Get-SPSPreferredUrl`.
- Bump script version metadata and in-script version variables to `4.2.4`.

## Changelog

A full list of changes in each version can be found in the [change log](CHANGELOG.md)
