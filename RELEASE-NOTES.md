# SPSWakeUp - Release Notes

## [4.0.1] - 2025-07-03

### Changed

SPSWakeUP.ps1:

- Add Try-Catch exception in Invoke-SPSWebRequest function
- Remove $TaskTrigger1.Repetition.Duration and $TaskTrigger1.Repetition.Interval

ISSUE_TEMPLATE:

- Add missing versions in 1_bug_report.yml file

### Fixed

SPSWakeUP.ps1:

- Resolve Error 503 Server Unavailable during Invoke-WebRequest with topology.svc
  ([issue #20](https://github.com/luigilink/SPSWakeUp/issues/20)).
- Resolve No Central Admin Service Instance running on server
  ([issue #22](https://github.com/luigilink/SPSWakeUp/issues/22)).

## Changelog

A full list of changes in each version can be found in the [change log](CHANGELOG.md)
