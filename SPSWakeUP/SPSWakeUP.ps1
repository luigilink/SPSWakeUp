<#
    .SYNOPSIS
    SPSWakeUP script for SharePoint OnPremises

    .DESCRIPTION
    SPSWakeUp is a PowerShell script tool to warm up all site collection in your SharePoint environment.
    It's compatible with all supported versions for SharePoint (2016 to Subscription Edition).
    Use WebRequest object in multi-thread to download JS, CSS and Pictures files,
    Log script results in log file,
    Configure automatically prerequisites for a best warm-up,

    .PARAMETER Install
    Use the switch Install parameter if you want to add the warmup script in taskscheduler
    InstallAccount parameter need to be set
    PS D:\> E:\SCRIPT\SPSWakeUP.ps1 -Install -InstallAccount (Get-Credential)

    .PARAMETER InstallAccount
    Need parameter InstallAccount whent you use the switch Install parameter
    PS D:\> E:\SCRIPT\SPSWakeUP.ps1 -Install -InstallAccount (Get-Credential)

    .PARAMETER Uninstall
    Use the switch Uninstall parameter if you want to remove the warmup script from taskscheduler
    PS D:\> E:\SCRIPT\SPSWakeUP.ps1 -Uninstall

    .PARAMETER AllSites
    Use the boolean AllSites parameter if you want to warmup the SPWebs of each site collection
    and only warmup the root web of the site collection.
    PS D:\> E:\SCRIPT\SPSWakeUP.ps1 -AllSites:$True

    .PARAMETER AdminSites
    Use the boolean AdminSites parameter if you want to warmup the Central Administration Site collection
    PS D:\> E:\SCRIPT\SPSWakeUP.ps1 -AdminSites:$True

    .PARAMETER Transcript
    Use the boolean Transcript parameter if you want to start Transcrit PowerShell Feature.
    PS D:\> E:\SCRIPT\SPSWakeUP.ps1 -Transcript:$True

    .EXAMPLE
    SPSWakeUP.ps1 -Install -InstallAccount (Get-Credential)
    SPSWakeUP.ps1 -Uninstall
    SPSWakeUP.ps1 -AllSites:$True
    SPSWakeUP.ps1 -AdminSites:$True
    SPSWakeUP.ps1 -Transcript:$True

    .NOTES
    FileName:	SPSWakeUP.ps1
    Authors:	luigilink (Jean-Cyril DROUHIN)
                Nutsoft (Des Finkenzeller)
    Date:		December 16, 2024
    Version:	4.0.0
    Licence:	MIT License

    .LINK
    https://spwakeup.com/
    https://github.com/luigilink/spswakeup
#>
param
(
    [Parameter(Position = 1)]
    [switch]
    $Install,

    [Parameter(Position = 2)]
    [System.Management.Automation.PSCredential]
    $InstallAccount,

    [Parameter(Position = 3)]
    [switch]
    $Uninstall,

    [Parameter(Position = 4)]
    [System.Boolean]
    $AllSites = $true,

    [Parameter(Position = 5)]
    [System.Boolean]
    $AdminSites = $true,

    [Parameter(Position = 6)]
    [System.Boolean]
    $Transcript = $false
)

#region Initialization
# Clear the host console
Clear-Host

# Set the window title
$Host.UI.RawUI.WindowTitle = "SPSWakeUP script running on $env:COMPUTERNAME"

# Define the path to the helper module
$scriptRootPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$script:HelperModulePath = Join-Path -Path $scriptRootPath -ChildPath 'Modules'

# Import the helper module
Import-Module -Name (Join-Path -Path (Join-Path -Path $script:HelperModulePath -ChildPath 'SPSWakeUP.Util') -ChildPath 'SPSWakeUP.Util.psm1') -Force

# Ensure the script is running with administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Throw "Administrator rights are required. Please re-run this script as an Administrator."
}

# Define variable
$spsWakeupVersion = '4.0.0'
$currentUser = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name
$scriptRootPath = Split-Path -parent $MyInvocation.MyCommand.Definition
$hostEntries = New-Object -TypeName System.Collections.Generic.List[string]
$hostsFile = "$env:windir\System32\drivers\etc\HOSTS"
$hostsFileCopy = $hostsFile + '.' + (Get-Date -UFormat "%y%m%d%H%M%S").ToString() + '.copy'

# Start Transcript parameter is equal to True
if ($Transcript) {
    $pathLogFile = Join-Path -Path $scriptRootPath -ChildPath ('SPSWakeUP_script_' + (Get-Date -Format yyyy-MM-dd_H-mm) + '.log')
    Start-Transcript -Path $pathLogFile -IncludeInvocationHeader
}

# Check UserName and Password if Install parameter is used
if ($Install) {
    if ($null -eq $InstallAccount) {
        Write-Warning -Message ('SPSWakeUp: Install parameter is set. Please set also InstallAccount ' + `
                "parameter. `nSee https://spwakeup.com for details.")
        Break
    }
    else {
        $UserName = $InstallAccount.UserName
        $Password = $InstallAccount.GetNetworkCredential().Password
        $currentDomain = 'LDAP://' + ([ADSI]'').distinguishedName
        Write-Output "Checking Account `"$UserName`" ..."
        $dom = New-Object System.DirectoryServices.DirectoryEntry($currentDomain, $UserName, $Password)
        if ($null -eq $dom.Path) {
            Write-Warning -Message "Password Invalid for user:`"$UserName`""
            Break
        }
    }
}

#region Main
# ===================================================================================
#
# SPSWakeUP Script - MAIN Region
#
# ===================================================================================
$DateStarted = Get-date
$psVersion = ($host).Version.ToString()
$spsVersion = Get-SPSVersion
if ($PSVersionTable.PSVersion -gt [Version]'2.0' -and $spsVersion -lt 15) {
    powershell -Version 2 -File $MyInvocation.MyCommand.Definition
    exit
}

Write-Output '-------------------------------------'
Write-Output "| Automated Script - SPSWakeUp v$spsWakeupVersion"
Write-Output "| Started on : $DateStarted by $currentUser"
Write-Output "| PowerShell Version: $psVersion"
Write-Output "| SharePoint Version: $spsVersion"
Write-Output '-------------------------------------'

if ($Uninstall) {
    # Remove SPSWakeup script from scheduled Task
    Remove-SPSTask
}
elseif ($Install) {
    # Add SPSWakeup script in a new scheduled Task
    Add-SPSTask -Path $scriptRootPath

    # 1. Load SharePoint Powershell Snapin or Import-Module
    try {
        $installedVersion = Get-SPSInstalledProductVersion
        if ($installedVersion.ProductMajorPart -eq 15 -or $installedVersion.ProductBuildPart -le 12999) {
            if ($null -eq (Get-PSSnapin -Name Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue)) {
                Add-PSSnapin Microsoft.SharePoint.PowerShell
            }
        }
        else {
            Import-Module SharePointServer -Verbose:$false -WarningAction SilentlyContinue
        }
    }
    catch {
        # Handle errors during retrieval of Installed Product Version
        Write-Error -Message @"
Failed to get installed Product Version for $($env:COMPUTERNAME)
Exception: $_
"@
    }

    # Get All Web Applications Urls
    Write-Output '--------------------------------------------------------------'
    Write-Output 'Get URLs of All Web Applications ...'
    $getSPWebApps = Get-SPSWebAppUrl

    # Add read access for Warmup User account in User Policies settings
    Add-SPSUserPolicy -Urls $getSPWebApps -UserName $UserName
}
else {
    Write-Output "Setting power management plan to `"High Performance`"..."
    Start-Process -FilePath "$env:SystemRoot\system32\powercfg.exe" `
        -ArgumentList '/s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' `
        -NoNewWindow

    # Load SharePoint Powershell Snapin, Assembly and System.Web
    Add-PSSharePoint

    # From SharePoint 2016, check if MinRole equal to Search
    $currentSPServer = Get-SPServer | Where-Object -FilterScript { $_.Address -eq $env:COMPUTERNAME }
    if ($null -ne $currentSPServer -and (Get-SPFarm).buildversion.major -ge 16) {
        if ($currentSPServer.Role -eq 'Search') {
            Write-Warning -Message 'You run this script on server with Search MinRole'
            Write-Output 'Search MinRole is not supported in SPSWakeUp'
            Break
        }
    }

    # Invoke-WebRequest on Central Admin if AdminSites parameter equal to True
    if ($AdminSites) {
        $spCASvcInstance = $currentSPServer.ServiceInstances | Where-Object -FilterScript { $_.TypeName -eq 'Central Administration' }
        if ($spCASvcInstance.Status -eq 'Online') {
            Write-Output '--------------------------------------------------------------'
            Write-Output 'Opening All Central Admin Urls with Invoke-WebRequest, Please Wait...'
            $getSPADMSites = Get-SPSAdminUrl
            foreach ($spADMUrl in $getSPADMSites) {
                try {
                    $startInvoke = Get-Date
                    $webResponse = Invoke-WebRequest -Uri $spADMUrl -UseDefaultCredentials -TimeoutSec 90 -UseBasicParsing
                    $TimeExec = '{0:N2}' -f (((Get-Date) - $startInvoke).TotalSeconds)
                    Write-Output '-----------------------------------'
                    Write-Output "| Url    : $spADMUrl"
                    Write-Output "| Time   : $TimeExec"
                    Write-Output "| Status : $($webResponse.StatusCode) - $($webResponse.StatusDescription)"
                }
                catch {
                    Write-LogException -Message $_
                }
            }
        }
        else {
            Write-Warning -Message "No Central Admin Service Instance running on $env:COMPUTERNAME"
        }
    }

    # Get All Web Applications Urls, Host Named Site Collection and Site Collections
    Write-Output '--------------------------------------------------------------'
    Write-Output 'Get URLs of All Web Applications ...'
    $getSPWebApps = Get-SPSWebAppUrl

    Write-Output '--------------------------------------------------------------'
    Write-Output 'Get URLs of All Site Collection ...'
    $getSPSites = Get-SPSSitesUrl
    if ($null -ne $getSPWebApps -and $null -ne $getSPSites) {
        if ($hostEntries) {
            # Disable LoopBack Check
            Disable-LoopbackCheck
            # Remove Duplicate Entries
            $hostEntries = $hostEntries | Get-Unique
            # Initialize variables
            $hostFileNeedsBackup = $true
            $hostIPV4Addr = '127.0.0.1'
            # Make backup copy of the Hosts file with today's date Add Web Application and Host Named Site Collection Urls in HOSTS system File
            Write-Output '--------------------------------------------------------------'
            Write-Output 'Add Urls of All Web Applications or HSNC in HOSTS File ...'
            foreach ($hostEntry in $hostEntries) {
                $hostEntryIsPresent = Select-String -Path $hostsFile -Pattern $hostEntry
                if ($null -eq $hostEntryIsPresent) {
                    if ($hostFileNeedsBackup) {
                        Write-Verbose -Message "Backing up $hostsFile file to: $hostsFileCopy"
                        Copy-Item -Path $hostsFile -Destination $hostsFileCopy -Force
                        $hostFileNeedsBackup = $false
                    }
                    # Remove http or https information to keep only HostName or FQDN
                    if ($hostEntry.Contains(':')) {
                        Write-Warning -Message "$hostEntry cannot be added in HOSTS File, only web applications with 80 or 443 port are added."
                    }
                    else {
                        Write-Output "Adding $($hostEntry) in HOSTS file"
                        Add-Content -Path $hostsFile -value "$hostIPV4Addr `t $hostEntry"
                    }
                }
            }
        }
        # Request Url with Invoke-WebRequest CmdLet for All Urls
        Write-Output '--------------------------------------------------------------'
        Write-Output 'Opening All sites Urls with Invoke-WebRequest, Please Wait...'
        $InvokeResults = Invoke-SPSWebRequest -Urls $getSPSites -throttleLimit (Get-SPSThrottleLimit)
        # Show the results
        foreach ($InvokeResult in $InvokeResults) {
            if ($null -ne $InvokeResult.Url) {
                Write-Output '-----------------------------------'
                Write-Output "| Url    : $($InvokeResult.Url)"
                Write-Output "| Time   : $($InvokeResult.'Time(s)') seconds"
                Write-Output "| Status : $($InvokeResult.Status)"
            }
        }
    }

    $DateEnded = Get-Date
    $totalUrls = $getSPSites.Count
    $totalDuration = ($DateEnded - $DateStarted).TotalSeconds

    Write-Output '-------------------------------------'
    Write-Output '| Automated Script - SPSWakeUp'
    Write-Output "| Started on : $DateStarted"
    Write-Output "| Completed on : $DateEnded"
    Write-Output "| SPSWakeUp waked up $totalUrls urls in $totalDuration seconds"
    Write-Output '--------------------------------------------------------------'
    Write-Output '| REPORTING: Memory Usage for each worker process (W3WP.EXE)'
    Write-Output '| Process Creation Date | Memory | Application Pool Name'
    Write-Output '--------------------------------------------------------------'

    $w3wpProcess = Get-CimInstance Win32_Process -Filter "name = 'w3wp.exe'" | Select-Object WorkingSetSize, CommandLine, CreationDate | Sort-Object CommandLine
    foreach ($w3wpProc in $w3wpProcess) {
        $w3wpProcCmdLine = $w3wpProc.CommandLine.Replace('c:\windows\system32\inetsrv\w3wp.exe -ap "', '')
        $pos = $w3wpProcCmdLine.IndexOf('"')
        $appPoolName = $w3wpProcCmdLine.Substring(0, $pos)
        $w3wpMemoryUsage = [Math]::Round($w3wpProc.WorkingSetSize / 1MB)
        Write-Output "| $($w3wpProc.CreationDate) | $($w3wpMemoryUsage) MB | $($appPoolName)"
    }
    Write-Output '--------------------------------------------------------------'

    Trap { Continue }

    # Clean the copy files of system HOSTS folder
    Clear-HostsFileCopy -hostsFilePath $hostsFile
    # Clean the folder of log files
    Clear-SPSLog -path $scriptRootPath
    # Stop Transcript parameter is equal to True
    if ($Transcript) {
        Stop-Transcript
    }
}
Exit
#endregion
