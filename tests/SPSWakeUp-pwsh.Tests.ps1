<#
.SYNOPSIS
    Pester tests for SPSWakeUp-pwsh.ps1 script

.DESCRIPTION
    Tests for the PowerShell 7 worker script that performs warm-up requests
    using JSON input produced by SPSWakeUP.ps1.

.NOTES
    Requires Pester v5.x
    Run: Invoke-Pester -Path .\tests\SPSWakeUp-pwsh.Tests.ps1
#>

BeforeAll {
    $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUp-pwsh.ps1'

    # Source functions without executing initialization/main blocks.
    $scriptContent = Get-Content $scriptPath -Raw
    $functionsOnly = $scriptContent -replace '(?s)#region main.*?#endregion', ''
    $functionsOnly = $functionsOnly -replace '(?s)#region Initialization.*?#endregion', ''
    Invoke-Expression $functionsOnly
}

Describe 'SPSWakeUp-pwsh Script Structure' {

    Context 'Script File' {
        It 'Should exist' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUp-pwsh.ps1'
            $scriptPath | Should -Exist
        }

        It 'Should have valid PowerShell syntax' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUp-pwsh.ps1'
            $errors = $null
            [System.Management.Automation.PSParser]::Tokenize((Get-Content $scriptPath -Raw), [ref]$errors)
            $errors.Count | Should -Be 0
        }

        It 'Should require PowerShell 7 or later' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUp-pwsh.ps1'
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match '#Requires\s+-Version\s+7\.0'
        }
    }

    Context 'Required Functions' {
        It 'Should define Set-SPSProxySetting function' {
            Get-Command Set-SPSProxySetting -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }

        It 'Should define Invoke-SPSWebRequestParallel function' {
            Get-Command Invoke-SPSWebRequestParallel -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }

        It 'Should define Invoke-SPSAdminWarmUp function' {
            Get-Command Invoke-SPSAdminWarmUp -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'SPSWakeUp-pwsh Runtime Behavior' {

    Context 'Parallel and HTTP settings' {
        It 'Should use ForEach-Object -Parallel for warm-up' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUp-pwsh.ps1'
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'ForEach-Object\s+-ThrottleLimit\s+\$ThrottleLimit\s+-Parallel'
        }

        It 'Should use SkipCertificateCheck in web requests' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUp-pwsh.ps1'
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'SkipCertificateCheck'
        }

        It 'Should use AllowUnencryptedAuthentication for default credentials over HTTP' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUp-pwsh.ps1'
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'AllowUnencryptedAuthentication'
        }
    }

    Context 'Reporting' {
        It 'Should include PowerShell version in summary output' {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUp-pwsh.ps1'
            $content = Get-Content $scriptPath -Raw
            $content | Should -Match 'PowerShell Version\s*:\s*\$\(\$PSVersionTable\.PSVersion\)'
        }
    }
}

Describe 'Version Consistency' {
    It 'Should keep PSScriptInfo version aligned between orchestrator and pwsh worker' {
        $mainPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUP.ps1'
        $pwshPath = Join-Path -Path $PSScriptRoot -ChildPath '..\scripts\SPSWakeUp-pwsh.ps1'

        $mainContent = Get-Content $mainPath -Raw
        $pwshContent = Get-Content $pwshPath -Raw

        $mainVersion = [regex]::Match($mainContent, '\.VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)').Groups[1].Value
        $pwshVersion = [regex]::Match($pwshContent, '\.VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)').Groups[1].Value

        $mainVersion | Should -Not -BeNullOrEmpty
        $pwshVersion | Should -Not -BeNullOrEmpty
        $pwshVersion | Should -Be $mainVersion
    }
}