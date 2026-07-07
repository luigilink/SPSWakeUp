# SPSWakeUp - Release Notes

## [4.2.3] - 2026-07-07

### Changed

- Bump `actions/checkout` to `v7` across all workflows (`release.yml`, `pester.yml`, `wiki.yml`), replacing the previous `v4`/`v3` pins that relied on the deprecated Node.js runtime ([#42](https://github.com/luigilink/SPSWakeUp/issues/42)).
- Bump `actions/upload-artifact` to `v7` and `softprops/action-gh-release` to `v3` in the CI workflows ([#42](https://github.com/luigilink/SPSWakeUp/issues/42)).
- `release.yml`: build the release ZIP from the **contents** of `scripts/` instead of the folder itself, so `SPSWakeUP.ps1`, `SPSWakeUp-pwsh.ps1` and `SPSWakeUP_README.md` are extracted at the archive root ([#42](https://github.com/luigilink/SPSWakeUp/issues/42)).

SPSWakeUP.ps1 / SPSWakeUp-pwsh.ps1:

- Bump script version metadata and in-script version variables to `4.2.3`.

## Changelog

A full list of changes in each version can be found in the [change log](CHANGELOG.md)
