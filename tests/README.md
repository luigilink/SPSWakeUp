# SPSWakeUp Tests

This directory contains Pester tests for the SPSWakeUp PowerShell script.

## Prerequisites

- PowerShell 5.1 or later
- Pester 5.x or later

Install Pester if not already installed:

```powershell
Install-Module -Name Pester -Force -SkipPublisherCheck
```

## Running Tests

### Run All Tests

```powershell
Invoke-Pester -Path .\tests\
```

### Run Specific Test File

```powershell
Invoke-Pester -Path .\tests\SPSWakeUP.Tests.ps1
```

### Run with Code Coverage

```powershell
$config = New-PesterConfiguration
$config.CodeCoverage.Enabled = $true
$config.CodeCoverage.Path = '.\scripts\SPSWakeUP.ps1'
$config.Run.Path = '.\tests\'
Invoke-Pester -Configuration $config
```

### Run in CI/CD (with output)

```powershell
Invoke-Pester -Path .\tests\ -Output Detailed
```

## Test Structure

The test suite covers:

### 1. **Script Structure**
- File existence and PowerShell syntax validation
- Verification that all required functions are defined

### 2. **Unit Tests**
- `Get-SPSThrottleLimit`: CPU detection logic
- `Clear-SPSLog`: Log file cleanup
- `Add-SPSHostEntry`: URL parsing
- `Get-SPSSitesUrl`: Site collection retrieval
- `Set-SPSProxySettings`: Proxy configuration management

### 3. **Resource Management**
- COM object cleanup with ReleaseComObject
- Password variable removal
- Runspace pool and job cleanup

### 4. **Error Handling**
- Try-Catch-Finally block verification
- Event logging validation

### 5. **Security Best Practices**
- Credential handling
- Administrator privilege checks
- Sensitive data cleanup

### 6. **Code Quality**
- Function naming conventions
- Output method consistency
- Module import optimization

## Test Coverage Goals

- **Unit Tests**: Test individual functions in isolation
- **Integration Tests**: Test function interactions (requires SharePoint environment)
- **Resource Management**: Verify proper cleanup of system resources
- **Security**: Ensure sensitive data is properly handled
- **Error Handling**: Validate error scenarios are properly handled

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Test SPSWakeUp
on: [push, pull_request]
jobs:
  test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install Pester
        shell: pwsh
        run: Install-Module -Name Pester -Force -SkipPublisherCheck
      - name: Run Tests
        shell: pwsh
        run: Invoke-Pester -Path .\tests\ -Output Detailed -PassThru
```

## Notes

- Tests use mocked SharePoint cmdlets to avoid SharePoint dependencies
- Some tests validate code patterns in the script file directly
- Integration tests requiring actual SharePoint environment should be run separately

## Contributing

When adding new features to SPSWakeUP.ps1:

1. Add corresponding unit tests
2. Ensure all existing tests pass
3. Aim for >80% code coverage
4. Document any SharePoint dependencies in test descriptions
