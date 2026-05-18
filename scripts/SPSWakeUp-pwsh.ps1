#Requires -Version 7.0
<#PSScriptInfo
    .VERSION 4.2.2

    .GUID 3cd095b3-7b4e-5a2f-ad8e-4f6a2b9c1d5e

    .AUTHOR luigilink (Jean-Cyril DROUHIN)

    .COPYRIGHT

    .TAGS
    script powershell sharepoint warmup

    .LICENSEURI
    https://github.com/luigilink/SPSWakeUp/blob/main/LICENSE

    .PROJECTURI
    https://github.com/luigilink/SPSWakeUp

    .ICONURI

    .EXTERNALMODULEDEPENDENCIES

    .REQUIREDSCRIPTS

    .EXTERNALSCRIPTDEPENDENCIES

    .RELEASENOTES

    .PRIVATEDATA
#>

<#
    .SYNOPSIS
    SPSWakeUP PS7 runner script (PowerShell 7.x only)

    .DESCRIPTION
    Reads the URL JSON file produced by SPSWakeUP.ps1 and warms up all
    SharePoint site collections using parallel Invoke-WebRequest calls
    (ForEach-Object -Parallel, available in PowerShell 7+).
    The script will exit immediately if the JSON file does not exist.

    .PARAMETER InputJsonPath
    Full path to the JSON file written by SPSWakeUP.ps1.
    Defaults to SPSWakeUp_urls.json in the script folder.

    .PARAMETER Action
    Default        : Warm up admin pages + all site collections
    AdminSitesOnly : Warm up central administration pages only

    .PARAMETER Transcript
    Set to $true to enable transcript logging.

    .EXAMPLE
    pwsh -File SPSWakeUp-pwsh.ps1
    pwsh -File SPSWakeUp-pwsh.ps1 -Action AdminSitesOnly
    pwsh -File SPSWakeUp-pwsh.ps1 -InputJsonPath C:\Temp\urls.json

    .NOTES
    FileName:   SPSWakeUp-pwsh.ps1
    Authors:    luigilink (Jean-Cyril DROUHIN)

    Date:       May 06, 2026
    Version:    4.2.2
    Licence:    MIT License

    .LINK
    https://spjc.fr/
    https://github.com/luigilink/spswakeup
#>
param
(
    [Parameter(Position = 1)]
    [System.String]
    $InputJsonPath,

    [Parameter(Position = 2)]
    [ValidateSet('Default', 'AdminSitesOnly', IgnoreCase = $true)]
    [System.String]
    $Action = 'Default',

    [Parameter(Position = 3)]
    [System.Boolean]
    $Transcript = $false
)

#region Initialization
$spsWakeupVersion = '4.2.2'
$currentUser = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name

Clear-Host

if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Throw 'Administrator rights are required. Please re-run this script as an Administrator.'
}

if ([string]::IsNullOrEmpty($InputJsonPath)) {
    $InputJsonPath = Join-Path -Path $PSScriptRoot -ChildPath 'SPSWakeUp_urls.json'
}

# Exit immediately if the JSON file does not exist
if (-not (Test-Path -Path $InputJsonPath)) {
    Write-Warning "JSON file not found: $InputJsonPath"
    Write-Warning 'Run SPSWakeUP.ps1 first to generate the URL data file.'
    Exit 1
}

if ($Transcript) {
    $pathLogFile = Join-Path -Path $PSScriptRoot -ChildPath ('SPSWakeUP-pwsh_' + (Get-Date -Format yyyy-MM-dd_H-mm) + '.log')
    Start-Transcript -Path $pathLogFile -IncludeInvocationHeader
}
#endregion

#region functions
function Add-SPSWakeUpEvent {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Message,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Source,

        [Parameter()]
        [ValidateSet('Error', 'Information', 'FailureAudit', 'SuccessAudit', 'Warning')]
        [System.String]
        $EntryType = 'Information',

        [Parameter()]
        [System.UInt32]
        $EventID = 1
    )

    $LogName = 'SPSWakeUp'

    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
            if (-not [System.Diagnostics.EventLog]::Exists($LogName)) {
                [System.Diagnostics.EventLog]::CreateEventSource($Source, $LogName)
            }
            else {
                [System.Diagnostics.EventLog]::CreateEventSource($Source, $LogName)
            }
        }
        $headerMessage = @"
SPSWakeUp Script Version: $spsWakeupVersion
User: $currentUser
ComputerName: $($env:COMPUTERNAME)
--------------------------------------------------------------
$Message
"@
        $entryTypeEnum = [System.Diagnostics.EventLogEntryType]::$EntryType
        [System.Diagnostics.EventLog]::WriteEntry($Source, $headerMessage, $entryTypeEnum, $EventID)
    }
    catch {
        Write-Warning "Could not write to Windows Event Log (Source: $Source): $_"
    }
}

function Disable-LoopbackCheck {
    $lsaPath = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    $lsaPathValue = Get-ItemProperty -Path $lsaPath
    if (-not ($lsaPathValue.DisableLoopbackCheck -eq '1')) {
        Write-Output 'Disabling Loopback Check...'
        New-ItemProperty -Path $lsaPath -Name 'DisableLoopbackCheck' -Value '1' -PropertyType dword -Force | Out-Null
    }
    else {
        Write-Output 'Loopback Check already Disabled - skipping.'
    }
}

function Disable-IEFirstRun {
    $iefirstrunPath = 'HKCU:\Software\Microsoft\Internet Explorer\Main'
    if (Test-Path $iefirstrunPath) {
        $iefirstrunPathValue = Get-ItemProperty -Path $iefirstrunPath
        if (-not ($iefirstrunPathValue.DisableFirstRunCustomize -eq '1')) {
            Write-Output 'Disabling IE First Run...'
            New-ItemProperty -Path $iefirstrunPath -Name 'DisableFirstRunCustomize' -Value '1' -PropertyType dword -Force | Out-Null
        }
        else {
            Write-Output 'IE First Run already Disabled - skipping.'
        }
    }
}

function Clear-HostsFileCopy {
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $hostsFilePath,

        [Parameter()]
        [System.UInt32]
        $numberFiles = 10
    )

    $hostsFolderPath = Split-Path $hostsFilePath
    if (Test-Path $hostsFolderPath) {
        $copyFiles = Get-ChildItem -Path $hostsFolderPath -Filter '*.copy' | Sort-Object -Descending -Property Name | Select-Object -Skip $numberFiles
        if ($copyFiles) {
            Write-Output '--------------------------------------------------------------'
            Write-Output "Cleaning backup HOSTS files in $hostsFolderPath ..."
            foreach ($copyFile in $copyFiles) {
                if ($null -ne $copyFile) {
                    Write-Output "   * Deleting File $copyFile ..."
                    Remove-Item $copyFile.FullName | Out-Null
                }
            }
        }
    }
}

function Set-SPSProxySetting {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet('Backup', 'Disable', 'Restore', IgnoreCase = $true)]
        [System.String]
        $Action,

        [Parameter(Position = 1)]
        [System.String]
        $BackupFile = "$PSScriptRoot\SPSWakeUP_proxy_backup.json"
    )

    $regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

    switch ($Action) {
        'Backup' {
            if ($PSCmdlet.ShouldProcess($BackupFile, 'Back up proxy settings')) {
                try {
                    $proxySettings = Get-ItemProperty -Path $regPath |
                        Select-Object AutoConfigURL, ProxyEnable, ProxyServer, ProxyOverride
                    $proxySettings | ConvertTo-Json | Out-File -FilePath $BackupFile -Encoding UTF8
                    Write-Output "Proxy settings backed up to $BackupFile"
                }
                catch {
                    Write-Error "An error occurred while saving proxy settings. File: $BackupFile. Exception: $($_.Exception.Message)"
                }
            }
        }
        'Disable' {
            if ($PSCmdlet.ShouldProcess('Proxy settings', 'Disable')) {
                try {
                    $itemProperties = @('AutoConfigURL', 'ProxyServer', 'ProxyOverride')
                    Set-ItemProperty -Path $regPath -Name ProxyEnable -Value 0
                    foreach ($itemProperty in $itemProperties) {
                        if (Get-ItemProperty -Path $regPath -Name $itemProperty -ErrorAction SilentlyContinue) {
                            Remove-ItemProperty -Path $regPath -Name $itemProperty -ErrorAction SilentlyContinue
                        }
                    }
                    Write-Output 'All proxy settings disabled.'
                }
                catch {
                    Write-Error "An error occurred while disabling proxy settings. Exception: $($_.Exception.Message)"
                }
            }
        }
        'Restore' {
            if (Test-Path $BackupFile) {
                if ($PSCmdlet.ShouldProcess($BackupFile, 'Restore proxy settings')) {
                    try {
                        $proxySettings = Get-Content $BackupFile | ConvertFrom-Json
                        Set-ItemProperty -Path $regPath -Name ProxyEnable -Value $proxySettings.ProxyEnable
                        if ($proxySettings.ProxyServer) {
                            Set-ItemProperty -Path $regPath -Name ProxyServer -Value $proxySettings.ProxyServer
                        }
                        else {
                            Remove-ItemProperty -Path $regPath -Name ProxyServer -ErrorAction SilentlyContinue
                        }
                        if ($proxySettings.AutoConfigURL) {
                            Set-ItemProperty -Path $regPath -Name AutoConfigURL -Value $proxySettings.AutoConfigURL
                        }
                        else {
                            Remove-ItemProperty -Path $regPath -Name AutoConfigURL -ErrorAction SilentlyContinue
                        }
                        if ($proxySettings.ProxyOverride) {
                            Set-ItemProperty -Path $regPath -Name ProxyOverride -Value $proxySettings.ProxyOverride
                        }
                        else {
                            Remove-ItemProperty -Path $regPath -Name ProxyOverride -ErrorAction SilentlyContinue
                        }
                        Write-Output "Proxy settings restored from $BackupFile"
                    }
                    catch {
                        Write-Error "An error occurred while restoring proxy settings. File: $BackupFile. Exception: $($_.Exception.Message)"
                    }
                }
            }
            else {
                Write-Output "Backup file not found at $BackupFile"
            }
        }
    }
}

function Invoke-SPSWebRequestParallel {
    <#
    .SYNOPSIS
    Warms up a list of URLs in parallel using ForEach-Object -Parallel (PS 7+).
    #>
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String[]]
        $Urls,

        [Parameter(Mandatory = $true)]
        [int]
        $ThrottleLimit,

        [Parameter()]
        $WebSession
    )

    $psUserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome

    $results = $Urls | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
        $Uri       = $_
        $sess      = $using:WebSession
        $agent     = $using:psUserAgent

        $timeExec  = '0.00'
        $status    = 'Not started'

        try {
            $startProcess = Get-Date
            $params = @{
                Uri             = $Uri
                TimeoutSec      = 90
                UserAgent       = $agent
                SkipCertificateCheck = $true
                UseBasicParsing = $true
            }
            if ($null -ne $sess) {
                $params['WebSession'] = $sess
            }
            else {
                $params['UseDefaultCredentials'] = $true
                $params['AllowUnencryptedAuthentication'] = $true
            }
            $webResponse = Invoke-WebRequest @params
            $timeExec = '{0:N2}' -f (((Get-Date) - $startProcess).TotalSeconds)
            $status   = "$([int]$webResponse.StatusCode) - $($webResponse.StatusDescription)"
        }
        catch {
            $status = $_.Exception.Message
        }

        [PSCustomObject]@{
            Url       = $Uri
            'Time(s)' = $timeExec
            Status    = $status
        }
    }

    return $results
}

function Invoke-SPSAdminWarmUp {
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String[]]
        $AdminUrls
    )

    Write-Output '--------------------------------------------------------------'
    Write-Output 'Opening All Central Admin Urls with Invoke-WebRequest, Please Wait...'

    $psUserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome

    foreach ($spADMUrl in $AdminUrls) {
        try {
            $startInvoke = Get-Date
            $argsInvokeWebReq = @{
                Uri                            = $spADMUrl
                UseDefaultCredentials          = $true
                AllowUnencryptedAuthentication = $true
                TimeoutSec                     = 90
                UserAgent                      = $psUserAgent
                SkipCertificateCheck           = $true
                UseBasicParsing                = $true
            }
            $webResponse = Invoke-WebRequest @argsInvokeWebReq
            $TimeExec = '{0:N2}' -f (((Get-Date) - $startInvoke).TotalSeconds)
            Write-Output '-----------------------------------'
            Write-Output "| Url    : $spADMUrl"
            Write-Output "| Time   : $TimeExec"
            Write-Output "| Status : $($webResponse.StatusCode) - $($webResponse.StatusDescription)"
        }
        catch {
            $catchMessage = @"
An error occurred with Invoke-WebRequest CMDLet
Url: $($spADMUrl)
Exception: $($_.Exception.Message)
"@
            Write-Error -Message $catchMessage
            Add-SPSWakeUpEvent -Message $catchMessage -Source 'Invoke-SPSAdminWarmUp' -EntryType 'Error'
        }
    }
}

function Get-SPSAuthWebSession {
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $AuthUrl,

        [Parameter(Mandatory = $true)]
        $UserAgent
    )

    $argsInvokeWebReq = @{
        Uri                            = $AuthUrl
        SessionVariable                = 'webSession'
        UseDefaultCredentials          = $true
        AllowUnencryptedAuthentication = $true
        TimeoutSec                     = 90
        UserAgent                      = $UserAgent
        SkipCertificateCheck           = $true
        UseBasicParsing                = $true
    }
    Invoke-WebRequest @argsInvokeWebReq | Out-Null

    return $webSession
}
#endregion

#region main
Write-Output '======================================================'
Write-Output "SPSWakeUp-WarmUp v$spsWakeupVersion - SharePoint warm-up"
Write-Output "Action     : $Action"
Write-Output "Input JSON : $InputJsonPath"
Write-Output '======================================================'

# Read and validate JSON
try {
    $jsonData = Get-Content -Path $InputJsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Write-Output "JSON generated at : $($jsonData.GeneratedAt)"
    Write-Output "JSON action       : $($jsonData.Action)"
}
catch {
    Write-Error "Failed to read JSON file: $InputJsonPath. Exception: $($_.Exception.Message)"
    Exit 1
}

# Backup and disable proxy settings
Set-SPSProxySetting -Action 'Backup' -BackupFile "$PSScriptRoot\SPSWakeUP_proxy_backup.json"
Set-SPSProxySetting -Action 'Disable'

# Disable LoopBack Check and IE First Run
Disable-LoopbackCheck
Disable-IEFirstRun

switch ($Action) {
    'AdminSitesOnly' {
        $adminUrls = @($jsonData.AdminUrls | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

        if ($adminUrls.Count -eq 0) {
            Write-Warning 'No Admin URLs found in JSON file. Exiting.'
            Exit 1
        }

        Invoke-SPSAdminWarmUp -AdminUrls $adminUrls
    }

    Default {
        $hostsFile     = "$env:windir\System32\drivers\etc\HOSTS"
        $hostsFileCopy = $hostsFile + '.' + (Get-Date -UFormat '%y%m%d%H%M%S').ToString() + '.copy'

        $adminUrls   = @($jsonData.AdminUrls | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $siteUrls    = @($jsonData.SiteUrls  | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $hostEntries = @($jsonData.HostEntries | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
        $authUrl     = $jsonData.AuthUrl
        $throttle    = if ($jsonData.ThrottleLimit -gt 0) { [int]$jsonData.ThrottleLimit } else { 4 }

        # Update HOSTS file for web apps / HNSCs
        if ($hostEntries.Count -gt 0) {
            $hostIPV4Addr      = '127.0.0.1'
            $hostFileNeedsBackup = $true

            Write-Output '--------------------------------------------------------------'
            Write-Output 'Adding Web Application / HSNC entries to HOSTS file ...'

            foreach ($hostEntry in $hostEntries) {
                $hostEntryIsPresent = Select-String -Path $hostsFile -Pattern ([regex]::Escape($hostEntry)) -Quiet
                if (-not $hostEntryIsPresent) {
                    if ($hostFileNeedsBackup) {
                        Write-Verbose "Backing up $hostsFile to: $hostsFileCopy"
                        Copy-Item -Path $hostsFile -Destination $hostsFileCopy -Force
                        $hostFileNeedsBackup = $false
                    }
                    if ($hostEntry.Contains(':')) {
                        Write-Warning "$hostEntry cannot be added to HOSTS file - only standard port (80/443) web applications are supported."
                    }
                    else {
                        Write-Output "Adding $hostEntry to HOSTS file"
                        Add-Content -Path $hostsFile -Value "$hostIPV4Addr `t $hostEntry"
                    }
                }
            }
        }

        # Warm up Central Admin
        if ($adminUrls.Count -gt 0) {
            Invoke-SPSAdminWarmUp -AdminUrls $adminUrls
        }
        else {
            Write-Warning 'No Admin URLs in JSON - skipping Central Admin warm-up.'
        }

        # Warm up all site collections
        if ($siteUrls.Count -gt 0) {
            Write-Output '--------------------------------------------------------------'
            Write-Output "Opening $($siteUrls.Count) site collection URL(s) with Invoke-WebRequest (ThrottleLimit: $throttle), Please Wait..."

            # Establish a web session via the authentication URL
            $webSession  = $null
            $psUserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome

            if (-not [string]::IsNullOrWhiteSpace($authUrl)) {
                try {
                    Write-Output "Getting web session from: $authUrl"
                    $webSession = Get-SPSAuthWebSession -AuthUrl $authUrl -UserAgent $psUserAgent
                }
                catch {
                    Write-Warning "Could not establish web session from auth URL: $_"
                    $webSession = $null
                }
            }

            $DateStarted = Get-Date
            $invokeResults = Invoke-SPSWebRequestParallel -Urls $siteUrls -ThrottleLimit $throttle -WebSession $webSession

            foreach ($result in $invokeResults) {
                if ($null -ne $result.Url) {
                    Write-Output '-----------------------------------'
                    Write-Output "| Url    : $($result.Url)"
                    Write-Output "| Time   : $($result.'Time(s)') seconds"
                    Write-Output "| Status : $($result.Status)"
                }
            }

            $DateEnded    = Get-Date
            $totalUrls    = $siteUrls.Count
            $totalDuration = ($DateEnded - $DateStarted).TotalSeconds

            $outputMessage = @"
-------------------------------------
| SPSWakeUp Script - WarmUp complete
| PowerShell Version : $($PSVersionTable.PSVersion)
| Started on  : $DateStarted
| Completed on: $DateEnded
| Warmed up $totalUrls URL(s) in $totalDuration seconds
--------------------------------------------------------------
| REPORTING: Memory Usage for each worker process (W3WP.EXE)
| Process Creation Date | Memory | Application Pool Name
--------------------------------------------------------------
"@
            $w3wpProcess = Get-CimInstance Win32_Process -Filter "name = 'w3wp.exe'" |
                Select-Object WorkingSetSize, CommandLine, CreationDate |
                Sort-Object CommandLine

            foreach ($w3wpProc in $w3wpProcess) {
                $w3wpProcCmdLine = $w3wpProc.CommandLine.Replace('c:\windows\system32\inetsrv\w3wp.exe -ap "', '')
                $pos         = $w3wpProcCmdLine.IndexOf('"')
                $appPoolName = $w3wpProcCmdLine.Substring(0, $pos)
                $memMB       = [Math]::Round($w3wpProc.WorkingSetSize / 1MB)
                $outputMessage += ("`r`n" + "| $($w3wpProc.CreationDate) | $memMB MB | $appPoolName")
            }

            Write-Output $outputMessage
            Add-SPSWakeUpEvent -Message $outputMessage -Source 'Invoke-SPSAllSite' -EntryType 'Information'
        }
        else {
            Write-Warning 'No site collection URLs found in JSON - skipping site warm-up.'
            Add-SPSWakeUpEvent -Message 'SPSWakeUp-WarmUp: No site URLs found in JSON file.' -Source 'Invoke-SPSAllSite' -EntryType 'Warning'
        }

        # Clean up old HOSTS backup copies
        Clear-HostsFileCopy -hostsFilePath $hostsFile
    }
}

# Restore proxy settings
Set-SPSProxySetting -Action 'Restore' -BackupFile "$PSScriptRoot\SPSWakeUP_proxy_backup.json"

if ($Transcript) {
    Stop-Transcript
}

Exit 0
#endregion
