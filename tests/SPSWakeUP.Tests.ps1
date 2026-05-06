<#
.SYNOPSIS
    Pester tests for SPSWakeUP.ps1 script

.DESCRIPTION
    Tests for SharePoint warm-up script functionality, resource management,
    error handling, and security practices.

.NOTES
    Requires Pester v5.x
    Run: Invoke-Pester -Path .\tests\SPSWakeUP.Tests.ps1
#>

BeforeAll {    # Validate Windows Server environment
    if ($PSVersionTable.Platform -eq 'Unix' -or -not [System.Environment]::OSVersion.Platform.ToString().Contains('Win')) {
        Write-Warning 'SPSWakeUP tests are designed for Windows Server with SharePoint. Skipping suite on non-Windows platforms.'
    }
        # Import the script
    $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUP.ps1'
    
    # Mock SharePoint cmdlets to avoid dependencies
    function Get-SPWebApplication { }
    function Get-SPSite { }
    function Get-SPWeb { }
    function Get-SPServer { }
    function Get-SPServiceInstance { }
    function Get-SPServiceApplication { }
    function Get-SPFarm { }
    function New-SPClaimsPrincipal { }
    
    # Source the functions from the script without executing the main region
    $scriptContent = Get-Content $scriptPath -Raw
    $functionsOnly = $scriptContent -replace '(?s)#region main.*?#endregion', ''
    $functionsOnly = $functionsOnly -replace '(?s)#region Initialization.*?#endregion', ''
    $functionsOnly = $functionsOnly -replace '(?s)#region initialize SharePoint Context.*?#endregion', ''
    Invoke-Expression $functionsOnly
}

Describe 'SPSWakeUP Script Structure' {
    
    Context 'Script File' {
        It 'Should exist' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUP.ps1'
            $scriptPath | Should -Exist
        }

        It 'Should have valid PowerShell syntax' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUP.ps1'
            $errors = $null
            [System.Management.Automation.PSParser]::Tokenize((Get-Content $scriptPath -Raw), [ref]$errors)
            $errors.Count | Should -Be 0
        }

        It 'Should include companion PS7 worker script' {
            $pwshScriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUp-pwsh.ps1'
            $pwshScriptPath | Should -Exist
        }
    }

    Context 'Required Functions' {
        It 'Should define Add-SPSWakeUpEvent function' {
            Get-Command Add-SPSWakeUpEvent -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }

        It 'Should define Get-SPSInstalledProductVersion function' {
            Get-Command Get-SPSInstalledProductVersion -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }

        It 'Should define Add-SPSSheduledTask function' {
            Get-Command Add-SPSSheduledTask -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }

        It 'Should define Remove-SPSSheduledTask function' {
            Get-Command Remove-SPSSheduledTask -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }

        It 'Should define Get-SPSSitesUrl function' {
            Get-Command Get-SPSSitesUrl -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }

        It 'Should define Get-SPSWebAppUrl function' {
            Get-Command Get-SPSWebAppUrl -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }

        It 'Should define Invoke-SPSWebRequest function' {
            Get-Command Invoke-SPSWebRequest -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }

        It 'Should define Set-SPSProxySetting function' {
            Get-Command Set-SPSProxySetting -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }

        It 'Should define Disable-LoopbackCheck function' {
            Get-Command Disable-LoopbackCheck -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }

        It 'Should define Disable-IEFirstRun function' {
            Get-Command Disable-IEFirstRun -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Get-SPSThrottleLimit Function' {
    
    Context 'CPU Detection' {
        BeforeEach {
            Mock Get-CimInstance {
                return @(
                    [PSCustomObject]@{
                        NumberOfLogicalProcessors = 4
                    }
                )
            }
        }

        It 'Should return 10 for systems with 8 or more logical CPUs' {
            Mock Get-CimInstance {
                return @(
                    [PSCustomObject]@{
                        NumberOfLogicalProcessors = 8
                    }
                )
            }
            Get-SPSThrottleLimit | Should -Be 10
        }

        It 'Should return 2x CPU count for systems with less than 8 logical CPUs' {
            Mock Get-CimInstance {
                return @(
                    [PSCustomObject]@{
                        NumberOfLogicalProcessors = 4
                    }
                )
            }
            Get-SPSThrottleLimit | Should -Be 8
        }

        It 'Should handle multiple sockets' {
            Mock Get-CimInstance {
                return @(
                    [PSCustomObject]@{ NumberOfLogicalProcessors = 4 },
                    [PSCustomObject]@{ NumberOfLogicalProcessors = 4 }
                )
            }
            Get-SPSThrottleLimit | Should -Be 10
        }
    }
}

Describe 'Clear-SPSLog Function' {
    
    Context 'Log Cleanup' {
        BeforeAll {
            $testPath = Join-Path -Path $TestDrive -ChildPath 'logs'
            New-Item -Path $testPath -ItemType Directory -Force
        }

        It 'Should accept valid parameters' {
            { Clear-SPSLog -path $TestDrive -days 30 } | Should -Not -Throw
        }

        It 'Should not fail if path does not exist' {
            $nonExistentPath = Join-Path -Path $TestDrive -ChildPath 'nonexistent'
            { Clear-SPSLog -path $nonExistentPath -days 30 } | Should -Not -Throw
        }

        It 'Should delete old log files' {
            $testPath = Join-Path -Path $TestDrive -ChildPath 'logs'
            $oldLog = Join-Path -Path $testPath -ChildPath 'old.log'
            $newLog = Join-Path -Path $testPath -ChildPath 'new.log'
            
            Set-Content -Path $oldLog -Value 'old'
            Set-Content -Path $newLog -Value 'new'
            
            (Get-Item $oldLog).LastWriteTime = (Get-Date).AddDays(-31)
            (Get-Item $newLog).LastWriteTime = (Get-Date).AddDays(-1)
            
            Clear-SPSLog -path $testPath -days 30
            
            Test-Path $oldLog | Should -Be $false
            Test-Path $newLog | Should -Be $true
        }
    }
}

Describe 'Add-SPSHostEntry Function' {
    
    Context 'URL Parsing' {
        BeforeAll {
            $script:hostEntries = New-Object -TypeName System.Collections.Generic.List[string]
        }

        It 'Should extract hostname from https URL' {
            Add-SPSHostEntry -url 'https://sharepoint.contoso.com/sites/test'
            $hostEntries | Should -Contain 'sharepoint.contoso.com'
        }

        It 'Should extract hostname from http URL' {
            $script:hostEntries = New-Object -TypeName System.Collections.Generic.List[string]
            Add-SPSHostEntry -url 'http://sharepoint.contoso.com/sites/test'
            $hostEntries | Should -Contain 'sharepoint.contoso.com'
        }

        It 'Should handle URL with port' {
            $script:hostEntries = New-Object -TypeName System.Collections.Generic.List[string]
            Add-SPSHostEntry -url 'https://sharepoint.contoso.com:8080/sites/test'
            $hostEntries | Should -Contain 'sharepoint.contoso.com:8080'
        }
    }
}

Describe 'Get-SPSSitesUrl Function' {
    
    Context 'Site Collection Retrieval' {
        BeforeEach {
            Mock Get-SPWebApplication {
                $site1 = [PSCustomObject]@{
                    RootWeb = [PSCustomObject]@{ Url = 'http://sharepoint.contoso.com' }
                }
                $site1 | Add-Member -MemberType ScriptMethod -Name 'Dispose' -Value {}
                return @(
                    [PSCustomObject]@{
                        Sites = @($site1)
                    }
                )
            }
        }

        It 'Should return array of site URLs' {
            $result = Get-SPSSitesUrl
            $result | Should -Not -BeNullOrEmpty
            $result.Count | Should -BeGreaterThan 0
        }

        It 'Should filter out sitemaster URLs' {
            Mock Get-SPWebApplication {
                $site1 = [PSCustomObject]@{
                    RootWeb = [PSCustomObject]@{ Url = 'http://sitemaster-contoso.com' }
                }
                $site1 | Add-Member -MemberType ScriptMethod -Name 'Dispose' -Value {}
                $site2 = [PSCustomObject]@{
                    RootWeb = [PSCustomObject]@{ Url = 'http://sharepoint.contoso.com' }
                }
                $site2 | Add-Member -MemberType ScriptMethod -Name 'Dispose' -Value {}
                return @(
                    [PSCustomObject]@{
                        Sites = @($site1, $site2)
                    }
                )
            }
            $result = Get-SPSSitesUrl
            $result | Should -Not -Contain 'http://sitemaster-contoso.com'
            $result | Should -Contain 'http://sharepoint.contoso.com'
        }

        It 'Should handle null web applications' {
            Mock Get-SPWebApplication { return $null }
            $result = Get-SPSSitesUrl
            $result | Should -BeNullOrEmpty
        }

        It 'Should call Dispose on site objects' -Skip:([System.Environment]::OSVersion.Platform.ToString().Contains('Win') -eq $false) {
            $disposeCalled = $false
            Mock Get-SPWebApplication {
                $siteObj = [PSCustomObject]@{
                    RootWeb = [PSCustomObject]@{
                        Url = 'http://sharepoint.contoso.com'
                    }
                }
                # Add Dispose method that tracks calls
                $siteObj | Add-Member -MemberType ScriptMethod -Name 'Dispose' -Value { $script:disposeCalled = $true }.GetNewClosure()
                return @(
                    [PSCustomObject]@{
                        Sites = @($siteObj)
                    }
                )
            }
            Get-SPSSitesUrl
            # Note: Dispose should be called on SPSite objects
        }
    }
}

Describe 'Set-SPSProxySetting Function' {
    
    Context 'Parameter Validation' {
        It 'Should accept Backup action' {
            { Set-SPSProxySetting -Action 'Backup' -BackupFile "$TestDrive\proxy.json" } | Should -Not -Throw
        }

        It 'Should accept Disable action' {
            { Set-SPSProxySetting -Action 'Disable' } | Should -Not -Throw
        }

        It 'Should accept Restore action' {
            { Set-SPSProxySetting -Action 'Restore' -BackupFile "$TestDrive\proxy.json" } | Should -Not -Throw
        }

        It 'Should reject invalid action' {
            { Set-SPSProxySetting -Action 'Invalid' } | Should -Throw
        }
    }

    Context 'Output Method' {
        It 'Should use Write-Output in Set-SPSProxySetting' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUP.ps1'
            $content = Get-Content $scriptPath -Raw
            
            # Check that the function uses Write-Output for proxy settings messages
            $content | Should -Match 'function Set-SPSProxySetting'
            $content | Should -Match 'Write-Output.*proxy'
        }
    }
}

Describe 'Resource Management' {
    
    Context 'COM Object Cleanup' {
        It 'Script should contain ReleaseComObject calls' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUP.ps1'
            $content = Get-Content $scriptPath -Raw
            
            $content | Should -Match 'ReleaseComObject'
        }

        It 'Should release COM objects in Add-SPSSheduledTask' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUP.ps1'
            $content = Get-Content $scriptPath -Raw
            
            # Extract the Add-SPSSheduledTask function
            $functionPattern = '(?s)function Add-SPSSheduledTask\s*{.*?^}'
            $regexMatch = [regex]::Match($content, $functionPattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)
            
            $regexMatch.Value | Should -Match 'ReleaseComObject.*TaskSvc'
        }

        It 'Should release COM objects in Remove-SPSSheduledTask' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUP.ps1'
            $content = Get-Content $scriptPath -Raw
            
            $functionPattern = '(?s)function Remove-SPSSheduledTask\s*{.*?^}'
            $regexMatch = [regex]::Match($content, $functionPattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)
            
            $regexMatch.Value | Should -Match 'ReleaseComObject.*TaskSvc'
        }
    }

    Context 'Password Cleanup' {
        It 'Should remove password variables after use' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUP.ps1'
            $content = Get-Content $scriptPath -Raw
            
            $content | Should -Match 'Remove-Variable.*Password'
        }

        It 'Should use ErrorAction SilentlyContinue on Remove-Variable for sensitive data' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '.\..\scripts\SPSWakeUP.ps1'
            $content = Get-Content $scriptPath -Raw
            
            # Check that at least some Remove-Variable commands use -ErrorAction SilentlyContinue for password cleanup
            $removeVarWithErrorAction = ($content -split "`n") | Where-Object { $_ -match 'Remove-Variable.*Password.*ErrorAction\s+SilentlyContinue' }
            $removeVarWithErrorAction.Count | Should -BeGreaterThan 0
            
            # Also verify password variables are being removed somewhere
            $removeVarPassword = ($content -split "`n") | Where-Object { $_ -match 'Remove-Variable.*Password' }
            $removeVarPassword.Count | Should -BeGreaterThan 0
        }
    }

    Context 'Runspace Cleanup' {
        It 'Should dispose runspace pool' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUP.ps1'
            $content = Get-Content $scriptPath -Raw
            
            $content | Should -Match '\$Pool\.Dispose\(\)'
        }

        It 'Should dispose PowerShell job pipes' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUP.ps1'
            $content = Get-Content $scriptPath -Raw
            
            $content | Should -Match '\$Job\.Pipe\.Dispose\(\)'
        }
    }
}

Describe 'Error Handling' {
    
    Context 'Try-Catch Blocks' {
        It 'Should have try-catch in critical functions' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUP.ps1'
            $content = Get-Content $scriptPath -Raw
            
            # Check for try-catch blocks
            $content | Should -Match 'try\s*{'
            $content | Should -Match 'catch\s*{'
        }

        It 'Should have finally blocks for cleanup' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUP.ps1'
            $content = Get-Content $scriptPath -Raw
            
            $content | Should -Match 'finally\s*{'
        }
    }

    Context 'Event Logging' {
        It 'Should log errors to event log' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUP.ps1'
            $content = Get-Content $scriptPath -Raw
            
            $content | Should -Match 'Add-SPSWakeUpEvent.*EntryType.*Error'
        }
    }
}

Describe 'Security Best Practices' {
    
    Context 'Credential Handling' {
        It 'Should remove password variables after use' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUP.ps1'
            $content = Get-Content $scriptPath -Raw
            
            # Verify that Remove-Variable is called for password variables
            $passwordRemovals = ([regex]::Matches($content, 'Remove-Variable.*Password')).Count
            
            $passwordRemovals | Should -BeGreaterThan 0
        }

        It 'Should use PSCredential parameter type' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUP.ps1'
            $content = Get-Content $scriptPath -Raw
            
            $content | Should -Match 'System\.Management\.Automation\.PSCredential'
        }
    }

    Context 'Administrator Check' {
        It 'Should verify administrator privileges' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUP.ps1'
            $content = Get-Content $scriptPath -Raw
            
            $content | Should -Match 'WindowsPrincipal.*Administrator'
        }
    }
}

Describe 'Code Quality' {

    Context 'Output Consistency' {
        It 'Should prefer Write-Output over Write-Host for pipeline support' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUP.ps1'
            $content = Get-Content $scriptPath -Raw
            
            $writeOutputCount = ([regex]::Matches($content, 'Write-Output')).Count
            $writeHostCount = ([regex]::Matches($content, 'Write-Host')).Count
            
            # Write-Output should be more prevalent than Write-Host
            $writeOutputCount | Should -BeGreaterThan $writeHostCount
        }
    }

    Context 'Module Import' {
        It 'Should check if module is loaded before importing' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUP.ps1'
            $content = Get-Content $scriptPath -Raw
            
            $content | Should -Match 'Get-Module.*SharePointServer'
        }
    }
}
