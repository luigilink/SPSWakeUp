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
    Date:		May 08, 2023
    Version:	2.7.1
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

Clear-Host
$Host.UI.RawUI.WindowTitle = "WarmUP script running on $env:COMPUTERNAME"

# Define variable
$spsWakeupVersion = '2.7.1'
$currentUser      = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name
$scriptRootPath   = Split-Path -parent $MyInvocation.MyCommand.Definition
$hostEntries      = New-Object -TypeName System.Collections.Generic.List[string]
$hostsFile        = "$env:windir\System32\drivers\etc\HOSTS"
$hostsFileCopy    = $hostsFile + '.' + (Get-Date -UFormat "%y%m%d%H%M%S").ToString() + '.copy'

# Start Transcript parameter is equal to True
if ($Transcript) {
    $pathLogFile  = Join-Path -Path $scriptRootPath -ChildPath ('SPSWakeUP_script_' + (Get-Date -Format yyyy-MM-dd_H-mm) + '.log')
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
        $UserName      = $InstallAccount.UserName
        $Password      = $InstallAccount.GetNetworkCredential().Password
        $currentDomain = 'LDAP://' + ([ADSI]'').distinguishedName
        Write-Output "Checking Account `"$UserName`" ..."
        $dom = New-Object System.DirectoryServices.DirectoryEntry($currentDomain, $UserName, $Password)
        if ($null -eq $dom.Path) {
            Write-Warning -Message "Password Invalid for user:`"$UserName`""
            Break
        }
    }
}

#region logging and trap exception
# ===================================================================================
# Func: Write-LogException
# Desc: write Exception in powershell session and in error file
# ===================================================================================
function Write-LogException
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([String])]
    param
    (
        [Parameter(Mandatory=$true)]
        $Message
    )

    $pathErrLog = Join-Path -Path $scriptRootPath -ChildPath (((Get-Date).Ticks.ToString()) + '_errlog.xml')
    Write-Warning -Message $Message.Exception.Message
    Export-Clixml -Path $pathErrLog -InputObject $Message -Depth 3
}
# ===================================================================================
# Func: Clear-SPSLog
# Desc: Clean Log Files
# ===================================================================================
function Clear-SPSLog
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $path,

        [Parameter()]
        [System.UInt32]
        $days = 30
    )

    if (Test-Path $path) {
        # Get the current date
        $Now = Get-Date
        # Definie the extension of log files
        $Extension = '*.log'
        # Define LastWriteTime parameter based on $days
        $LastWrite = $Now.AddDays(-$days)
        # Get files based on lastwrite filter and specified folder
        $files = Get-Childitem -Path "$path\*.*" -Include $Extension | Where-Object -FilterScript {
            $_.LastWriteTime -le "$LastWrite"
        }

        if ($files) {
            Write-Output '--------------------------------------------------------------'
            Write-Output "Cleaning log files in $path ..."
            foreach ($file in $files) {
                if ($null -ne $file) {
                    Write-Output "Deleting file $file ..."
                    Remove-Item $file.FullName | Out-Null
                }
            }
        }
    }
}
#endregion

#region Installation in Task Scheduler
# ===================================================================================
# Func: Add-SPSTask
# Desc: Add SPSWakeUP Task in Task Scheduler
# ===================================================================================
function Add-SPSTask
{
    param
    (
        [Parameter(Mandatory=$true)]
        [System.String]
        $Path
    )

    $TrigSubscription =
@"
<QueryList><Query Id="0" Path="System"><Select Path="System">*[System[Provider[@Name='Microsoft-Windows-IIS-IISReset'] and EventID=3201]]</Select></Query></QueryList>
"@
    $TaskDate = Get-Date -Format yyyy-MM-dd
    $TaskName = 'SPSWakeUP'
    $Hostname = $Env:computername

    # Connect to the local TaskScheduler Service
    $TaskSvc = New-Object -ComObject ('Schedule.service')
    $TaskSvc.Connect($Hostname)
    $TaskFolder = $TaskSvc.GetFolder('\')
    $TaskSPSWKP = $TaskFolder.GetTasks(0) | Where-Object -FilterScript {
        $_.Name -eq $TaskName
    }
    $TaskCmd = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $TaskCmdArg =
@"
-Command Start-Process "$PSHOME\powershell.exe" -Verb RunAs -ArgumentList "'-ExecutionPolicy Bypass ""$path\SPSWakeUP.ps1""'"
"@

    if ($TaskSPSWKP) {
        Write-Warning -Message 'Shedule Task already exists - skipping.'
    }
    else {
        Write-Output '--------------------------------------------------------------'
        Write-Output 'Adding SPSWakeUP script in Task Scheduler Service ...'

        # Get Credentials for Task Schedule
        $TaskAuthor = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name
        $TaskUser = $UserName
        $TaskUserPwd = $Password

        # Add a New Task Schedule
        $TaskSchd = $TaskSvc.NewTask(0)
        $TaskSchd.RegistrationInfo.Description = 'SPSWakeUp Task - Start at 6:00 daily'
        $TaskSchd.RegistrationInfo.Author = $TaskAuthor
        $TaskSchd.Principal.RunLevel = 1

        # Task Schedule - Modify Settings Section
        $TaskSettings = $TaskSchd.Settings
        $TaskSettings.AllowDemandStart = $true
        $TaskSettings.Enabled = $true
        $TaskSettings.Hidden = $false
        $TaskSettings.StartWhenAvailable = $true

        # Task Schedule - Trigger Section
        $TaskTriggers = $TaskSchd.Triggers

        # Add Trigger Type 2 OnSchedule Daily Start at 6:00 AM
        $TaskTrigger1 = $TaskTriggers.Create(2)
        $TaskTrigger1.StartBoundary = $TaskDate + 'T06:00:00'
        $TaskTrigger1.DaysInterval = 1
        $TaskTrigger1.Repetition.Duration = 'PT12H'
        $TaskTrigger1.Repetition.Interval = 'PT1H'
        $TaskTrigger1.Enabled = $true

        # Add Trigger Type 8 At StartUp Delay 10M
        $TaskTrigger2 = $TaskTriggers.Create(8)
        $TaskTrigger2.Delay = 'PT10M'
        $TaskTrigger2.Enabled = $true

        # Add Trigger Type 0 OnEvent IISReset
        $TaskTrigger3 = $TaskTriggers.Create(0)
        $TaskTrigger3.Delay = 'PT20S'
        $TaskTrigger3.Subscription = $TrigSubscription
        $TaskTrigger3.Enabled = $true

        $TaskAction = $TaskSchd.Actions.Create(0)
        $TaskAction.Path = $TaskCmd
        $TaskAction.Arguments = $TaskCmdArg
        try {
            $TaskFolder.RegisterTaskDefinition( $TaskName, $TaskSchd, 6, $TaskUser , $TaskUserPwd , 1)
            Write-Output 'Successfully added SPSWakeUP script in Task Scheduler Service'
        }
        catch {
            Write-LogException -Message $_
        }
    }
}
# ===================================================================================
# Func: Remove-SPSTask
# Desc: Remove SPSWakeUP Task from Task Scheduler
# ===================================================================================
function Remove-SPSTask
{
    $TaskName = 'SPSWakeUP'
    $Hostname = $Env:computername

    # Connect to the local TaskScheduler Service
    $TaskSvc = New-Object -ComObject ('Schedule.service')
    $TaskSvc.Connect($Hostname)
    $TaskFolder = $TaskSvc.GetFolder('\')
    $TaskSPSWKP = $TaskFolder.GetTasks(0) | Where-Object -FilterScript {
        $_.Name -eq $TaskName
    }
    if ($null -eq $TaskSPSWKP) {
        Write-Warning -Message 'Shedule Task already removed - skipping.'
    }
    else {
        Write-Output '--------------------------------------------------------------'
        Write-Output 'Removing SPSWakeUP script in Task Scheduler Service ...'
        try {
            $TaskFolder.DeleteTask($TaskName, $null)
            Write-Output 'Successfully removed SPSWakeUP script from Task Scheduler Service'
        }
        catch {
            Write-LogException -Message $_
        }
    }
}
#endregion

#region Load SharePoint Powershell Snapin for SharePoint Server
# ===================================================================================
# Name: 		Add-PSSharePoint
# Description:	Load SharePoint Powershell Snapin
# ===================================================================================
function Add-PSSharePoint
{
    if ($null -eq (Get-PSSnapin | Where-Object -FilterScript { $_.Name -eq 'Microsoft.SharePoint.PowerShell' })) {
        Write-Output '--------------------------------------------------------------'
        Write-Output 'Loading SharePoint Powershell Snapin ...'
        Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction Stop | Out-Null
        Write-Output '--------------------------------------------------------------'
    }
}
# ===================================================================================
# Name: 		Get-SPSThrottleLimit
# Description:	Get Number Of Throttle Limit
# ===================================================================================
function Get-SPSThrottleLimit
{
    # Get Number Of Throttle Limit
    process {
        try {
            $cimInstanceProc   = @(Get-CimInstance -ClassName Win32_Processor)
            $cimInstanceSocket = $cimInstanceProc.count
            $numLogicalCpu     = $cimInstanceProc[0].NumberOfLogicalProcessors * $cimInstanceSocket
            $NumThrottle       = @{ $true = 10; $false = 2 * $numLogicalCpu }[$numLogicalCpu -ge 8]
            return $NumThrottle
        }
        catch {
            Write-Warning -Message $_
        }
    }
}
#endregion

#region get all site collections and all web applications
# ===================================================================================
# Name: 		Get-SPSVersion
# Description:	PowerShell script to display SharePoint products from the registry.
# ===================================================================================
function Get-SPSVersion
{
    process {
        try {
            # location in registry to get info about installed software
            $regLoc = Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall
            # Get SharePoint Products and language packs
            $programs = $regLoc |  Where-Object -FilterScript {
                $_.PsPath -like '*\Office*'
            } | ForEach-Object -Process { Get-ItemProperty $_.PsPath }
            # output the info about Products and Language Packs
            $spsVersion = $programs | Where-Object -FilterScript {
                $_.DisplayName -like '*SharePoint Server*'
            }
            # Return SharePoint version
            $spsVersion.DisplayVersion
        }
        catch {
            Write-Warning -Message $_
        }
    }
}
# ===================================================================================
# Name: 		Add-SPSHostEntry
# Description:	Add Web Application and HSNC Urls in hostEntries Variable
# ===================================================================================
function Add-SPSHostEntry
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $url
    )

    $url = $url -replace 'https://',''
    $url = $url -replace 'http://',''
    $hostNameEntry = $url.split('/')[0]
    [void]$hostEntries.Add($hostNameEntry)
}
# ===================================================================================
# Name: 		Get-SPSAdminUrl
# Description:	Get All Url of Central Admin
# ===================================================================================
function Get-SPSAdminUrl
{
    try {
        # Initialize ArrayList Object
        $tbCASitesURL = New-Object -TypeName System.Collections.ArrayList
        # Get Central Administration Url and add it in ArrayList Object
        $webAppADM = Get-SPWebApplication -IncludeCentralAdministration | Where-Object -FilterScript {
            $_.IsAdministrationWebApplication
        }
        [void]$tbCASitesURL.Add("$($webAppADM.Url)")
        # List of the most useful administration pages and Quick launch top links
        $urlsAdmin = @('Lists/HealthReports/AllItems.aspx',`
                       '_admin/FarmServers.aspx',`
                       '_admin/Server.aspx',`
                       '_admin/WebApplicationList.aspx',`
                       '_admin/ServiceApplications.aspx',`
                       'applications.aspx',`
                       'systemsettings.aspx',`
                       'monitoring.aspx',`
                       'backups.aspx',`
                       'security.aspx',`
                       'upgradeandmigration.aspx',`
                       'apps.aspx',`
                       'generalapplicationsettings.aspx')
        foreach($urlAdmin in $urlsAdmin) {
            [void]$tbCASitesURL.Add("$($webAppADM.Url)$($urlAdmin)")
        }
        # Get Service Application Urls and then in ArrayList Object
        $sa = Get-SPServiceApplication
        $linkUrls = $sa | ForEach-Object {$_.ManageLink.Url} | Select-Object -Unique
        foreach ($linkUrl in $linkUrls) {
            $siteADMSA = $linkUrl.TrimStart('/')
            [void]$tbCASitesURL.Add("$($webAppADM.Url)$($siteADMSA)")
        }
        return $tbCASitesURL
    }
    catch {
        Write-LogException -Message $_
    }
}
# ===================================================================================
# Name: 		Get-SPSSitesUrl
# Description:	Get All Site Collections Url
# ===================================================================================
function Get-SPSSitesUrl
{
    try {
        # Initialize ArrayList Object
        $tbSitesURL = New-Object -TypeName System.Collections.ArrayList
        # Get Url of all site collection
        $webApps = Get-SPWebApplication -ErrorAction SilentlyContinue
        if ($null -ne $webApps) {
            foreach ($webApp in $webApps) {
                $sites = $webApp.sites
                foreach ($site in $sites) {
                    if ($AllSites) {
                        $webs = (Get-SPWeb -Site $site -Limit ALL -ErrorAction SilentlyContinue)
                        if ($null -ne $webs) {
                            foreach ($web in $webs) {
                                if ($web.Url -notmatch 'sitemaster-') {
                                    [void]$tbSitesURL.Add("$($web.Url)")
                                }
                            }
                        }
                    }
                    else {
                        if ($site.RootWeb.Url -notmatch 'sitemaster-') {
                            [void]$tbSitesURL.Add("$($site.RootWeb.Url)")
                        }
                    }
                    $site.Dispose()
                }
            }
        }
        # Add Topology.svc in ArrayList Object
        [void]$tbSitesURL.Add('http://localhost:32843/Topology/topology.svc')
        return $tbSitesURL
    }
    catch {
        Write-LogException -Message $_
    }
}
# ===================================================================================
# Name: 		Get-SPSWebAppUrl
# Description:	Get All Web Applications and Host Named Site Collection Url
# ===================================================================================
function Get-SPSWebAppUrl
{
    try {
        # Initialize ArrayList Object
        $webAppURL = New-Object -TypeName System.Collections.ArrayList
        # Get SPwebApplication Object
        $webApps = Get-SPWebApplication -ErrorAction SilentlyContinue
        if ($null -ne $webApps) {
            foreach ($webapp in $webApps) {
                [void]$webAppURL.Add($webapp.GetResponseUri('Default').AbsoluteUri)
                $spSrvIsInUri = Get-SPServer | Where-Object -FilterScript {
                    $webapp.GetResponseUri('Default').AbsoluteUri -match $_.Name
                }
                if ($null -eq $spSrvIsInUri) {
                    Add-SPSHostEntry -Url $webapp.GetResponseUri('Default').AbsoluteUri
                }
            }
            $sites = $webApps | ForEach-Object -Process {
                $_.sites
            }
            $HSNCs = $sites | Where-Object -FilterScript {
                $_.HostHeaderIsSiteName -eq $true
            }
            foreach ($HSNC in $HSNCs) {
                if ($HSNC.Url -notmatch 'sitemaster-') {
                    [void]$webAppURL.Add($HSNC.Url)
                    Add-SPSHostEntry -Url $HSNC.Url
                }
                $HSNC.Dispose()
            }
        }
        return $webAppURL
    }
    catch {
        Write-Warning -Message $_
    }
}
#endregion

#region Invoke webRequest
# ===================================================================================
# Name: 		Invoke-SPSWebRequest
# Description:	Multi-Threading Request Url with System.Net.WebClient Object
# ===================================================================================
function Invoke-SPSWebRequest
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $Urls,

        [Parameter(Mandatory=$true)]
        $throttleLimit
    )

    $ScriptBlock =
    {
        param
        (
            [Parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [System.String]
            $Uri,

            [Parameter()]
            $Useragent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome,

            [Parameter()]
            $SessionWeb
        )

        Process {
            try {
                $startProcess = Get-Date
                if ($null -ne $sessionWeb) {
                    $webResponse = Invoke-WebRequest -Uri $uri `
                                                     -WebSession $sessionWeb `
                                                     -TimeoutSec 90 `
                                                     -UserAgent $useragent `
                                                     -UseBasicParsing
                }
                else {
                    $webResponse = Invoke-WebRequest -Uri $uri `
                                                     -UseDefaultCredentials `
                                                     -TimeoutSec 90 `
                                                     -UserAgent $useragent `
                                                     -UseBasicParsing
                }
                $timeExec = '{0:N2}' -f (((Get-Date) - $startProcess).TotalSeconds)
                $Response = "$([System.int32]$webResponse.StatusCode) - $($webResponse.StatusDescription)"
            }
            catch {
                $Response = $_.Exception.Message
            }
            finally {
                if ($webResponse) {
                    $webResponse.Close()
                    Remove-Variable webResponse
                }
            }
            $RunResult = New-Object PSObject
            $RunResult | Add-Member -MemberType NoteProperty -Name Url -Value $uri
            $RunResult | Add-Member -MemberType NoteProperty -Name 'Time(s)' -Value $TimeExec
            $RunResult | Add-Member -MemberType NoteProperty -Name Status -Value $Response
            $RunResult
        }
    }

    try {
        # Initialize variables and runpsace for Multi-Threading Request
        $psUserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
        $Jobs        = @()
        $iss         = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
        $Pool        = [runspacefactory]::CreateRunspacePool(1, $throttleLimit, $iss, $Host)
        $Pool.Open()

        # Initialize WebSession from First SPWebApplication object
        $webApp     = Get-SpWebApplication | Select-Object -first 1
        $authentUrl = ("$($webapp.GetResponseUri('Default').AbsoluteUri)" + '_windows/default.aspx?ReturnUrl=/_layouts/15/Authenticate.aspx?Source=%2f')
        Write-Output "Getting webSession by opening $($authentUrl) with Invoke-WebRequest"
        Invoke-WebRequest -Uri $authentUrl `
                          -SessionVariable webSession `
                          -UseDefaultCredentials `
                          -UseBasicParsing `
                          -TimeoutSec 90 `
                          -UserAgent $psUserAgent
        foreach ($Url in $Urls) {
            $Job = [powershell]::Create().AddScript($ScriptBlock).AddParameter('Uri', $Url).AddParameter('UserAgent', $psUserAgent).AddParameter('SessionWeb', $webSession)
            $Job.RunspacePool = $Pool
            $Jobs += New-Object PSObject -Property @{
                Url    = $Url
                Pipe   = $Job
                Result = $Job.BeginInvoke()
            }
        }

        While ($Jobs.Result.IsCompleted -contains $false) {
            Start-Sleep -S 1
        }

        $Results = @()
        foreach ($Job in $Jobs) {
            $Results += $Job.Pipe.EndInvoke($Job.Result)
        }

    }
    catch {
        Write-Output 'An error occurred invoking multi-threading function'
        Write-LogException -Message $_
    }

    Finally {
        $Pool.Dispose()
    }
    $Results
}
#endregion

#region Configuration and permission
# ===================================================================================
# Func: Disable-LoopbackCheck
# Desc: This setting usually kicks out a 401 error when you try to navigate to sites
#       that resolve to a loopback address e.g.  127.0.0.1
# ===================================================================================
function Disable-LoopbackCheck {
    $lsaPath      = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    $lsaPathValue = Get-ItemProperty -path $lsaPath
    if (-not ($lsaPathValue.DisableLoopbackCheck -eq '1')) {
        Write-Output 'Disabling Loopback Check...'
        New-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\Lsa -Name 'DisableLoopbackCheck' -value '1' -PropertyType dword -Force | Out-Null
    }
    else {
        Write-Output 'Loopback Check already Disabled - skipping.'
    }
}
# ====================================================================================
# Func: Clear-HostsFileCopy
# Desc: Clear previous HOSTS File copy
# ====================================================================================
function Clear-HostsFileCopy
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $hostsFilePath,

        [Parameter()]
        [System.UInt32]
        $numberFiles = 10
    )

    $hostsFolderPath = Split-Path $hostsFilePath
    if (Test-Path $hostsFolderPath) {
        # Definie the extension of log files
        $extension = '*.copy'

        # Get files with .copy extension, sort them by name, from most recent to oldest and skip the first numberFiles variable
        $copyFiles = Get-ChildItem -Path "$hostsFolderPath\*.*" -Include $extension | Sort-Object -Descending -Property Name | Select-Object -Skip $numberFiles
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
# ====================================================================================
# Func: Add-HostsEntry
# Desc: This writes URLs to the server's local hosts file and points them to the server itself
# ====================================================================================
function Add-HostsEntry
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $hostNameList
    )

    if ($null -ne $hostNameList) {
        $hostsContentFile =  New-Object System.Collections.Generic.List[string]
        $hostIPV4Addr     = '127.0.0.1'
        $hostsContentFile.Add("
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host
")
        $hostsContentFile.Add("127.0.0.1 `t crl.microsoft.com")
        foreach ($hostname in $hostNameList) {
            # Remove http or https information to keep only HostName or FQDN
            if ($hostname.Contains(':')) {
                Write-Warning -Message "$hostname cannot be added in HOSTS File, only web applications with 80 or 443 port are added."
            }
            else {
                $hostsContentFile.Add("$hostIPV4Addr `t $hostname")
            }
        }
        # Save the HOSTS system File
        Out-File $hostsfile -InputObject $hostsContentFile
    }
}
# ===================================================================================
# Func: Add-SPSUserPolicy
# Desc: Applies Read Access to the specified accounts for a web application
# ===================================================================================
function Add-SPSUserPolicy
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Urls,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $UserName
    )

    Write-Output '--------------------------------------------------------------'
    Write-Output "Add Read Access to $UserName for All Web Applications ..."
    foreach ($url in $Urls) {
        try {
            $webapp = [Microsoft.SharePoint.Administration.SPWebApplication]::Lookup("$url")
            $displayName = 'SPSWakeUP Account'

            # If the web app is not Central Administration
            if ($webapp.IsAdministrationWebApplication -eq $false) {
                # If the web app is using Claims auth, change the user accounts to the proper syntax
                if ($webapp.UseClaimsAuthentication -eq $true) {
                    $user = (New-SPClaimsPrincipal -identity $UserName -identitytype 1).ToEncodedString()
                }
                else {
                    $user = $UserName
                }
                Write-Output "Checking Read access for $user account to $url..."
                [Microsoft.SharePoint.Administration.SPPolicyCollection]$policies = $webapp.Policies
                $policyExist = $policies | Where-Object -FilterScript {
                    $_.Displayname -eq 'SPSWakeUP Account'
                }

                if (-not ($policyExist)) {
                    Write-Output "Applying Read access for $user account to $url..."
                    [Microsoft.SharePoint.Administration.SPPolicy]$policy = $policies.Add($user, $displayName)
                    $policyRole = $webApp.PolicyRoles.GetSpecialRole([Microsoft.SharePoint.Administration.SPPolicyRoleType]::FullRead)
                    if ($null -ne $policyRole) {
                        $policy.PolicyRoleBindings.Add($policyRole)
                    }
                    $webapp.Update()
                    Write-Output "Done Applying Read access for `"$user`" account to `"$url`""
                }
            }
        }
        catch {
            Write-LogException -Message $_
        }
    }
}
#endregion

#region Main
# ===================================================================================
#
# SPSWakeUP Script - MAIN Region
#
# ===================================================================================
$DateStarted = Get-date
$psVersion = ($host).Version.ToString()
$spsVersion = Get-SPSVersion
if ($PSVersionTable.PSVersion -gt [Version]'2.0' -and $spsVersion -lt 15)
{
  powershell -Version 2 -File $MyInvocation.MyCommand.Definition
  exit
}

Write-Output '-------------------------------------'
Write-Output "| Automated Script - SPSWakeUp v$spsWakeupVersion"
Write-Output "| Started on : $DateStarted by $currentUser"
Write-Output "| PowerShell Version: $psVersion"
Write-Output "| SharePoint Version: $spsVersion"
Write-Output '-------------------------------------'

# Check Permission Level
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Warning -Message 'You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!'
    Break
}
else {
    if ($Uninstall) {
        # Remove SPSWakeup script from scheduled Task
        Remove-SPSTask
    }
    elseif ($Install) {
        # Add SPSWakeup script in a new scheduled Task
        Add-SPSTask -Path $scriptRootPath

        # Load SharePoint Powershell Snapin
        Add-PSSharePoint

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
                        $TimeExec = '{0:N2}' -f  (((Get-Date) - $startInvoke).TotalSeconds)
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
                # Remove Duplicate Entries
                $hostEntries = $hostEntries | Get-Unique

                # Disable LoopBack Check
                Disable-LoopbackCheck

                # Make backup copy of the Hosts file with today's date Add Web Application and Host Named Site Collection Urls in HOSTS system File
                Write-Output '--------------------------------------------------------------'
                Write-Output 'Add Urls of All Web Applications or HSNC in HOSTS File ...'

                foreach ($hostEntry in $hostEntries) {
                    $hostEntryIsPresent = Select-String -Path $hostsFile -Pattern $hostEntry
                    if ($null -eq $hostEntryIsPresent) { $hostFileNeedsUpdate = $true }
                }
                if ($hostFileNeedsUpdate) {
                    Write-Verbose -Message "Backing up $hostsFile file to: $hostsFileCopy"
                    Copy-Item -Path $hostsFile -Destination $hostsFileCopy -Force
                    Add-HostsEntry -hostNameList $hostEntries
                }
                else {
                    Write-Verbose -Message 'HOSTS File already contains Urls of All Web Applications or HSNC- skipping.'
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
            $pathLogFile = Join-Path -Path $scriptRootPath -ChildPath ('SPSWakeUP_script_' + (Get-Date -Format yyyy-MM-dd_H-mm) + '.log')
            Stop-Transcript
        }
    }
    Exit
}
#endregion
