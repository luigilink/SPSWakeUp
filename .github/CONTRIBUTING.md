# SPSWakeUp - Contributing

Thanks for your interest in improving SPSWakeUp! Contributions of all kinds are welcome:
bug reports, feature requests, documentation, and pull requests.

## Before you start

- Search the [existing issues](https://github.com/luigilink/SPSWakeUp/issues) to avoid duplicates.
- For questions and ideas, open a [discussion](https://github.com/luigilink/SPSWakeUp/discussions).
- Read the [wiki](https://github.com/luigilink/SPSWakeUp/wiki) for usage, configuration, and the
  [Release Process](https://github.com/luigilink/SPSWakeUp/wiki/Release-Process).

## Reporting bugs and requesting features

Use the [issue templates](https://github.com/luigilink/SPSWakeUp/issues/new/choose) (bug report,
feature request, documentation request, improvement request) and fill in as much detail as possible.

## Pull requests

1. Fork the repository and create a topic branch from `main`.
2. Keep changes focused and commits atomic; reference the issue being resolved (e.g. `Closes #123`).
3. Add or update the relevant Pester tests under `tests/` and make sure they pass locally:

   ```powershell
   Invoke-Pester -Path .\tests
   Invoke-ScriptAnalyzer -Path .\src -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
   ```

4. Add an entry to `CHANGELOG.md` describing what changed and how it affects users.
5. Update the wiki pages under `wiki/` when behaviour, parameters, or configuration change.
6. Open the pull request and complete the checklist in the PR template.

## Coding conventions

- Target Windows PowerShell 5.1+ and follow the existing SPS* toolkit style.
- Shared logic lives in the `SPSWakeUp.Common` module (one function per file under `Public/` or
  `Private/`); the entry script `src/SPSWakeUp.ps1` orchestrates the run.
- The module `ModuleVersion` in `SPSWakeUp.Common.psd1` is the single source of truth for the version.
