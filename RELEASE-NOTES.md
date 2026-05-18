# SPSWakeUp - Release Notes

## [4.2.2] - 2026-05-18

### Changed

SPSWakeUP.ps1 / SPSWakeUp-pwsh.ps1:

- Bump script version metadata and in-script version variables to `4.2.2`.

### Fixed

SPSWakeUP.ps1:

- Fix scheduled task action argument construction in `Install-SPSWakeUP` by quoting the `-File` script path, so installations work when the script path contains spaces.

### Tests

- Add regression test in `tests/SPSWakeUP.Tests.ps1` to assert scheduled task `ActionArguments` uses a quoted script path for `-File`.

### Documentation

- Update `README.md` and wiki pages (`Home.md`, `Features.md`, `Getting-Started.md`, `Usage.md`) to specify deployment guidance: run/install on Web Front End (WFE) servers and do not run/install on Search MinRole servers.

## Changelog

A full list of changes in each version can be found in the [change log](CHANGELOG.md)
