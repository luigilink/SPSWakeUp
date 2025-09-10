﻿<#PSScriptInfo
    .VERSION 4.0.1

    .GUID 1fc873b1-5854-46cb-8632-29cee879bb55

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
    SPSWakeUP script for SharePoint OnPremises

    .DESCRIPTION
    SPSWakeUp is a PowerShell script tool to warm up all site collection in your SharePoint environment.
    It's compatible with all supported versions for SharePoint (2016 to Subscription Edition).
    Use WebRequest object in multi-thread to download JS, CSS and Pictures files.
    Log script results in log file, Configure automatically prerequisites for a best warm-up.

    .PARAMETER Action
    Use the Action parameter equal to Install if you want to add the warmup script in taskscheduler
    InstallAccount parameter need to be set
    PS D:\> E:\SCRIPT\SPSWakeUP.ps1 -Action Install -InstallAccount (Get-Credential)

    Use the Action parameter equal to Uninstall if you want to remove the warmup script from taskscheduler
    PS D:\> E:\SCRIPT\SPSWakeUP.ps1 -Action Uninstall

    Use the Action parameter equal to AdminSitesOnly if you want to warmup the Central Administration Site collection
    PS D:\> E:\SCRIPT\SPSWakeUP.ps1 -Action AdminSitesOnly

    .PARAMETER InstallAccount
    Need parameter InstallAccount whent you use the Action parameter equal to Install
    PS D:\> E:\SCRIPT\SPSWakeUP.ps1 -Install -InstallAccount (Get-Credential)

    .PARAMETER Transcript
    Use the boolean Transcript parameter if you want to start Transcrit PowerShell Feature.
    PS D:\> E:\SCRIPT\SPSWakeUP.ps1 -Transcript:$True

    .EXAMPLE
    SPSWakeUP.ps1 -Action Install -InstallAccount (Get-Credential)
    SPSWakeUP.ps1 -Action Uninstall
    SPSWakeUP.ps1 -Action AdminSitesOnly
    SPSWakeUP.ps1 -Transcript:$True

    .NOTES
    FileName:	SPSWakeUP.ps1
    Authors:	luigilink (Jean-Cyril DROUHIN)
                Nutsoft (Des Finkenzeller)
    Date:		July 03, 2025
    Version:	4.0.1
    Licence:	MIT License

    .LINK
    https://spjc.fr/
    https://github.com/luigilink/spswakeup
#>
param
(
    [Parameter(Position = 1)]
    [validateSet('Install', 'Uninstall', 'Default', 'AdminSitesOnly', IgnoreCase = $true)]
    [System.String]
    $Action = 'Default',

    [Parameter(Position = 2)]
    [System.Management.Automation.PSCredential]
    $InstallAccount,

    [Parameter(Position = 3)]
    [System.Boolean]
    $Transcript = $false
)

#region Initialization
# Define variables
$spsWakeupVersion = '4.0.1'
$currentUser = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name

# Clear the host console
Clear-Host

# Set the window title
$Host.UI.RawUI.WindowTitle = "SPSWakeUP script running on $env:COMPUTERNAME"

# Ensure the script is running with administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Throw "Administrator rights are required. Please re-run this script as an Administrator."
}

# Setting power management plan to High Performance"
Start-Process -FilePath "$env:SystemRoot\system32\powercfg.exe" -ArgumentList '/s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' -NoNewWindow

# Start Transcript parameter is equal to True
if ($Transcript) {
    # Initialize the log file full path
    $pathLogFile = Join-Path -Path $PSScriptRoot -ChildPath ('SPSWakeUP_script_' + (Get-Date -Format yyyy-MM-dd_H-mm) + '.log')
    # Clean the folder of log files
    Clear-SPSLog -path $PSScriptRoot
    # Start Transcript with the log file
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

    if ([System.Diagnostics.EventLog]::SourceExists($Source)) {
        $sourceLogName = [System.Diagnostics.EventLog]::LogNameFromSourceName($Source, ".")
        if ($LogName -ne $sourceLogName) {
            Write-Verbose -Message "[ERROR] Specified source {$Source} already exists on log {$sourceLogName}"
            return
        }
    }
    else {
        if ([System.Diagnostics.EventLog]::Exists($LogName) -eq $false) {
            #Create event log
            $null = New-EventLog -LogName $LogName -Source $Source
        }
        else {
            [System.Diagnostics.EventLog]::CreateEventSource($Source, $LogName)
        }
    }

    try {
        $headerMessage = @"
SPSWakeUp Script Version: $spsWakeupVersion
User: $currentUser
ComputerName: $($env:COMPUTERNAME)
--------------------------------------------------------------
"@
        Write-EventLog -LogName $LogName -Source $Source -EventId $EventID -Message ($headerMessage + "`r`n" + $Message) -EntryType $EntryType
    }
    catch {
        Write-Error -Message @"
SPSWakeUp Script Version: $spsWakeupVersion
An error occurred while adding Event Log in Source: $Source
User: $currentUser
ComputerName: $($env:COMPUTERNAME)
Exception: $_
"@
    }
}
function Get-SPSInstalledProductVersion {
    [OutputType([System.Version])]
    param ()

    $pathToSearch = 'C:\Program Files\Common Files\microsoft shared\Web Server Extensions\*\ISAPI\Microsoft.SharePoint.dll'
    $fullPath = Get-Item $pathToSearch -ErrorAction SilentlyContinue | Sort-Object { $_.Directory } -Descending | Select-Object -First 1
    if ($null -eq $fullPath) {
        Write-Error -Message 'SharePoint path {C:\Program Files\Common Files\microsoft shared\Web Server Extensions} does not exist'
    }
    else {
        return ([System.Diagnostics.FileVersionInfo]::GetVersionInfo($fullPath.FullName)).FileVersion
    }
}
function Add-SPSSheduledTask {
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $ExecuteAsCredential, # Credentials for Task Schedule

        [Parameter(Mandatory = $true)]
        [System.String]
        $ActionArguments, # Arguments for the task action

        [Parameter()]
        [System.String]
        $TaskName = 'SPSWakeUP', # Name of the scheduled task to be added

        [Parameter()]
        [System.String]
        $TaskPath = 'SharePoint' # Path of the task folder
    )

    # Initialize variables
    $TaskDate = Get-Date -Format yyyy-MM-dd # Current date in yyyy-MM-dd format
    $TaskCmd = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' # Path to PowerShell executable
    $UserName = $ExecuteAsCredential.UserName
    $Password = $ExecuteAsCredential.GetNetworkCredential().Password

    # Connect to the local TaskScheduler Service
    $TaskSvc = New-Object -ComObject ('Schedule.service')
    $TaskSvc.Connect($env:COMPUTERNAME)

    # Check if the folder exists, if not, create it
    try {
        $TaskFolder = $TaskSvc.GetFolder($TaskPath) # Attempt to get the task folder
    }
    catch {
        Write-Output "Task folder '$TaskPath' does not exist. Creating folder..."
        $RootFolder = $TaskSvc.GetFolder('\') # Get the root folder
        $RootFolder.CreateFolder($TaskPath) # Create the missing task folder
        $TaskFolder = $TaskSvc.GetFolder($TaskPath) # Get the newly created folder
        Write-Output "Successfully created task folder '$TaskPath'"
    }

    # Retrieve the scheduled task
    $getScheduledTask = $TaskFolder.GetTasks(0) | Where-Object -FilterScript {
        $_.Name -eq $TaskName
    }

    if ($getScheduledTask) {
        Write-Warning -Message 'Scheduled Task already exists - skipping.' # Task already exists
    }
    else {
        Write-Output '--------------------------------------------------------------'
        Write-Output "Adding '$TaskName' script in Task Scheduler Service ..."

        # Get credentials for Task Schedule
        $TaskAuthor = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name # Author of the task
        $TaskUser = $UserName # Username for task registration
        $TaskUserPwd = $Password # Password for task registration

        # Add a new Task Schedule
        $TaskSchd = $TaskSvc.NewTask(0)
        $TaskSchd.RegistrationInfo.Description = "$($TaskName) Task - Start at 6:00 daily" # Task description
        $TaskSchd.RegistrationInfo.Author = $TaskAuthor # Task author
        $TaskSchd.Principal.RunLevel = 1 # Task run level (1 = Highest)

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
        $TaskTrigger1.Enabled = $true

        # Add Trigger Type 8 At StartUp Delay 10M
        $TaskTrigger2 = $TaskTriggers.Create(8)
        $TaskTrigger2.Delay = 'PT10M'
        $TaskTrigger2.Enabled = $true

        # Add Trigger Type 0 OnEvent IISReset
        $TrigSubscription =
        @"
<QueryList><Query Id="0" Path="System"><Select Path="System">*[System[Provider[@Name='Microsoft-Windows-IIS-IISReset'] and EventID=3201]]</Select></Query></QueryList>
"@
        $TaskTrigger3 = $TaskTriggers.Create(0)
        $TaskTrigger3.Delay = 'PT20S'
        $TaskTrigger3.Subscription = $TrigSubscription
        $TaskTrigger3.Enabled = $true

        # Define the task action
        $TaskAction = $TaskSchd.Actions.Create(0) # 0 = Executable action
        $TaskAction.Path = $TaskCmd # Path to the executable
        $TaskAction.Arguments = $ActionArguments # Arguments for the executable

        try {
            # Register the task
            $TaskFolder.RegisterTaskDefinition($TaskName, $TaskSchd, 6, $TaskUser, $TaskUserPwd, 1)
            Write-Output "Successfully added '$TaskName' script in Task Scheduler Service"
            Add-SPSWakeUpEvent -Message "Successfully added '$TaskName' script in Task Scheduler Service" -Source 'Add-SPSSheduledTask' -EntryType 'Information'
        }
        catch {
            $catchMessage = @"
An error occurred while adding the script in scheduled task: $($TaskName)
ActionArguments: $($ActionArguments)
Exception: $($_.Exception.Message)
"@
            Write-Error -Message $catchMessage # Handle any errors during task registration
            Add-SPSWakeUpEvent -Message $catchMessage -Source 'Add-SPSSheduledTask' -EntryType 'Error'
        }
    }
}
function Remove-SPSSheduledTask {
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $TaskName, # Name of the scheduled task to be removed

        [Parameter()]
        [System.String]
        $TaskPath = 'SharePoint' # Path of the task folder
    )

    # Connect to the local TaskScheduler Service
    $TaskSvc = New-Object -ComObject ('Schedule.service')
    $TaskSvc.Connect($env:COMPUTERNAME)

    # Check if the folder exists
    try {
        $TaskFolder = $TaskSvc.GetFolder($TaskPath) # Attempt to get the task folder
    }
    catch {
        Write-Output "Task folder '$TaskPath' does not exist."
    }

    # Retrieve the scheduled task
    $getScheduledTask = $TaskFolder.GetTasks(0) | Where-Object -FilterScript {
        $_.Name -eq $TaskName
    }

    if ($null -eq $getScheduledTask) {
        Write-Warning -Message 'Scheduled Task already removed - skipping.' # Task not found
    }
    else {
        Write-Output '--------------------------------------------------------------'
        Write-Output "Removing $($TaskName) script in Task Scheduler Service ..."
        try {
            $TaskFolder.DeleteTask($TaskName, $null) # Remove the task
            Write-Output "Successfully removed $($TaskName) script from Task Scheduler Service"
            Add-SPSWakeUpEvent -Message "Successfully removed '$TaskName' script from Task Scheduler Service" -Source 'Remove-SPSSheduledTask' -EntryType 'Information'
        }
        catch {
            $catchMessage = @"
An error occurred while removing the script in scheduled task: $($TaskName)
Exception: $($_.Exception.Message)
"@
            Write-Error -Message $catchMessage # Handle any errors during task removal
            Add-SPSWakeUpEvent -Message $catchMessage -Source 'Remove-SPSSheduledTask' -EntryType 'Error'
        }
    }
}
function Get-SPSVersion {
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
function Install-SPSWakeUP {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [Parameter(Position = 2)]
        [System.Management.Automation.PSCredential]
        $InstallAccount
    )

    # Initialize variables
    $ActionArguments = "-ExecutionPolicy Bypass -File $Path"
    $UserName = $InstallAccount.UserName
    $Password = $InstallAccount.GetNetworkCredential().Password
    $currentDomain = 'LDAP://' + ([ADSI]'').distinguishedName
    Write-Output "Checking Account `"$UserName`" ..."
    $dom = New-Object System.DirectoryServices.DirectoryEntry($currentDomain, $UserName, $Password)
    if ($null -eq $dom.Path) {
        Write-Warning -Message "Password Invalid for user:`"$UserName`""
        Add-SPSWakeUpEvent -Message "Password Invalid for user:`"$UserName`"" -Source 'SPSWakeUP' -EntryType 'Error'
        Exit
    }
    else {
        Write-Output "Account `"$UserName`" is valid. Adding SPSWakeUp script in Task Scheduler Service ..."
        # 1. Add SPSWakeup script in a new scheduled Task
        Add-SPSSheduledTask -ExecuteAsCredential $InstallAccount -ActionArguments $ActionArguments

        # 2. Get All Web Applications Urls
        $getSPWebApps = Get-SPSWebAppUrl

        # 3. Add read access for Warmup User account in User Policies settings
        if ($null -ne $getSPWebApps) {
            Add-SPSUserPolicy -Urls $getSPWebApps -UserName $UserName
        }
    }
}
function Clear-SPSLog {
    param
    (
        [Parameter(Mandatory = $true)]
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
function Get-SPSThrottleLimit {
    # Get Number Of Throttle Limit
    process {
        try {
            $cimInstanceProc = @(Get-CimInstance -ClassName Win32_Processor)
            $cimInstanceSocket = $cimInstanceProc.count
            $numLogicalCpu = $cimInstanceProc[0].NumberOfLogicalProcessors * $cimInstanceSocket
            $NumThrottle = @{ $true = 10; $false = 2 * $numLogicalCpu }[$numLogicalCpu -ge 8]
            return $NumThrottle
        }
        catch {
            Write-Warning -Message $_
        }
    }
}
function Add-SPSHostEntry {
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $url
    )

    $url = $url -replace 'https://', ''
    $url = $url -replace 'http://', ''
    $hostNameEntry = $url.split('/')[0]
    [void]$hostEntries.Add($hostNameEntry)
}
function Get-SPSAdminUrl {
    try {
        # Initialize ArrayList Object
        $tbCASitesURL = New-Object -TypeName System.Collections.ArrayList
        # Get Central Administration Url and add it in ArrayList Object
        $webAppADM = Get-SPWebApplication -IncludeCentralAdministration | Where-Object -FilterScript {
            $_.IsAdministrationWebApplication
        }
        [void]$tbCASitesURL.Add("$($webAppADM.Url)")
        # List of the most useful administration pages and Quick launch top links
        $urlsAdmin = @('Lists/HealthReports/AllItems.aspx', `
                '_admin/FarmServers.aspx', `
                '_admin/Server.aspx', `
                '_admin/WebApplicationList.aspx', `
                '_admin/ServiceApplications.aspx', `
                'applications.aspx', `
                'systemsettings.aspx', `
                'monitoring.aspx', `
                'backups.aspx', `
                'security.aspx', `
                'upgradeandmigration.aspx', `
                'apps.aspx', `
                'generalapplicationsettings.aspx')
        foreach ($urlAdmin in $urlsAdmin) {
            [void]$tbCASitesURL.Add("$($webAppADM.Url)$($urlAdmin)")
        }
        # Get Service Application Urls and then in ArrayList Object
        $sa = Get-SPServiceApplication
        $linkUrls = $sa | ForEach-Object { $_.ManageLink.Url } | Select-Object -Unique
        foreach ($linkUrl in $linkUrls) {
            $siteADMSA = $linkUrl.TrimStart('/')
            [void]$tbCASitesURL.Add("$($webAppADM.Url)$($siteADMSA)")
        }
        return $tbCASitesURL
    }
    catch {
        Write-Warning -Message $_
    }
}
function Get-SPSSitesUrl {
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
        return $tbSitesURL
    }
    catch {
        Write-Warning -Message $_
    }
}
function Get-SPSWebAppUrl {
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
        else {
            $webAppURL = $null
        }
        return $webAppURL
    }
    catch {
        Write-Warning -Message $_
    }
}
function Invoke-SPSWebRequest {
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $Urls,

        [Parameter(Mandatory = $true)]
        $throttleLimit
    )

    $ScriptBlock =
    {
        param
        (
            [Parameter(Mandatory = $true)]
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
                if ($null -ne $SessionWeb) {
                    $webResponse = Invoke-WebRequest -Uri $Uri `
                        -WebSession $SessionWeb `
                        -TimeoutSec 90 `
                        -UserAgent $Useragent
                }
                else {
                    $webResponse = Invoke-WebRequest -Uri $Uri `
                        -UseDefaultCredentials `
                        -TimeoutSec 90 `
                        -UserAgent $Useragent
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
            $RunResult | Add-Member -MemberType NoteProperty -Name Url -Value $Uri
            $RunResult | Add-Member -MemberType NoteProperty -Name 'Time(s)' -Value $TimeExec
            $RunResult | Add-Member -MemberType NoteProperty -Name Status -Value $Response
            $RunResult
        }
    }

    try {
        # Initialize variables and runpsace for Multi-Threading Request
        $psUserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
        $Jobs = @()
        $iss = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
        $Pool = [runspacefactory]::CreateRunspacePool(1, $throttleLimit, $iss, $Host)
        $Pool.Open()
    }
    catch {
        $catchMessage = @"
An error occurred invoking CreateRunspacePool Method
Exception: $($_.Exception.Message)
"@
        Write-Error -Message $catchMessage # Handle any errors during task removal
        Add-SPSWakeUpEvent -Message $catchMessage -Source 'CreateRunspacePool' -EntryType 'Error'
    }
    try {
        # Initialize WebSession from First SPWebApplication object
        $webApp = Get-SpWebApplication | Select-Object -first 1
        $authentUrl = ("$($webapp.GetResponseUri('Default').AbsoluteUri)" + '_windows/default.aspx?ReturnUrl=/_layouts/15/Authenticate.aspx?Source=%2f')
        Write-Output "Getting webSession by opening $($authentUrl) with Invoke-WebRequest"
        Invoke-WebRequest -Uri $authentUrl `
            -SessionVariable webSession `
            -UseDefaultCredentials `
            -TimeoutSec 90 `
            -UserAgent $psUserAgent
    }
    catch {
        $catchMessage = @"
An error occurred invoking Invoke-WebRequest Function
Exception: $($_.Exception.Message)
"@
        Write-Error -Message $catchMessage # Handle any errors during task removal
        Add-SPSWakeUpEvent -Message $catchMessage -Source 'Invoke-WebRequest' -EntryType 'Error'
    }
    foreach ($Url in $Urls) {
        try {
            if (-not([string]::IsNullOrEmpty($Url))) {
                $Job = [powershell]::Create().AddScript($ScriptBlock).AddParameter('Uri', $Url).AddParameter('UserAgent', $psUserAgent).AddParameter('SessionWeb', $webSession)
                $Job.RunspacePool = $Pool
                $Jobs += New-Object PSObject -Property @{
                    Url    = $Url
                    Pipe   = $Job
                    Result = $Job.BeginInvoke()
                }
            }
        }
        catch {
            $catchMessage = @"
An error occurred invoking Create Method for Url: $($Url)
Exception: $($_.Exception.Message)
"@
            Write-Error -Message $catchMessage # Handle any errors during task removal
            Add-SPSWakeUpEvent -Message $catchMessage -Source 'Invoke-SPSWebRequest' -EntryType 'Error'
        }

    }

    While ($Jobs.Result.IsCompleted -contains $false) {
        Start-Sleep -S 1
    }

    $Results = @()
    foreach ($Job in $Jobs) {
        try {
            $Results += $Job.Pipe.EndInvoke($Job.Result)
        }
        catch {
            $catchMessage = @"
An error occurred invoking Job Pipe EndInvoke Method for Url: $($Job.Url)
Exception: $($_.Exception.Message)
"@
            Write-Error -Message $catchMessage # Handle any errors during task removal
            Add-SPSWakeUpEvent -Message $catchMessage -Source 'Invoke-SPSWebRequest' -EntryType 'Error'
        }
    }
    $Pool.Dispose()
    $Results
}
function Invoke-SPSAdminSites {
    $serviceInstance = Get-SPServiceInstance -Server $env:COMPUTERNAME
    if ($null -eq $serviceInstance) {
        $domain = (Get-CimInstance -ClassName Win32_ComputerSystem).Domain
        $fqdn = "$($env:COMPUTERNAME).$domain"
        $serviceInstance = Get-SPServiceInstance -Server $fqdn
    }

    if ($null -ne $serviceInstance) {
        $serviceInstance = $serviceInstance | Where-Object -FilterScript {
            $_.GetType().Name -eq "SPWebServiceInstance" -and
            $_.Name -eq "WSS_Administration"
        }
    }

    if ($null -ne $serviceInstance) {
        Write-Output 'Opening All Central Admin Urls with Invoke-WebRequest, Please Wait...'
        $getSPADMSites = Get-SPSAdminUrl
        foreach ($spADMUrl in $getSPADMSites) {
            try {
                $startInvoke = Get-Date
                $argsInvokeWebReq = @{
                    Uri                   = $spADMUrl
                    UseDefaultCredentials = $true
                    TimeoutSec            = 90
                    UserAgent             = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
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
                Add-SPSWakeUpEvent -Message $catchMessage -Source 'Invoke-SPSAdminSites' -EntryType 'Error'
            }
        }
    }
    else {
        Write-Warning -Message "No Central Admin Service Instance running on $env:COMPUTERNAME"
        Add-SPSWakeUpEvent -Message "No Central Admin Service Instance running on $env:COMPUTERNAME" -Source 'Invoke-SPSAdminSites' -EntryType 'Warning'
    }
}
function Invoke-SPSAllSites {
    # Initialize variables
    $DateStarted = Get-Date
    $hostEntries = New-Object -TypeName System.Collections.Generic.List[string]
    $hostsFile = "$env:windir\System32\drivers\etc\HOSTS"
    $hostsFileCopy = $hostsFile + '.' + (Get-Date -UFormat "%y%m%d%H%M%S").ToString() + '.copy'
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
        $DateEnded = Get-Date
        $totalUrls = $getSPSites.Count
        $totalDuration = ($DateEnded - $DateStarted).TotalSeconds

        $outputMessage = @"
-------------------------------------
| SPSWakeUp Script - Invoke-SPSAllSites
| Started on : $DateStarted
| Completed on : $DateEnded
| SPSWakeUp waked up $totalUrls urls in $totalDuration seconds
--------------------------------------------------------------
| REPORTING: Memory Usage for each worker process (W3WP.EXE)
| Process Creation Date | Memory | Application Pool Name
--------------------------------------------------------------
"@

        $w3wpProcess = Get-CimInstance Win32_Process -Filter "name = 'w3wp.exe'" | Select-Object WorkingSetSize, CommandLine, CreationDate | Sort-Object CommandLine
        foreach ($w3wpProc in $w3wpProcess) {
            $w3wpProcCmdLine = $w3wpProc.CommandLine.Replace('c:\windows\system32\inetsrv\w3wp.exe -ap "', '')
            $pos = $w3wpProcCmdLine.IndexOf('"')
            $appPoolName = $w3wpProcCmdLine.Substring(0, $pos)
            $w3wpMemoryUsage = [Math]::Round($w3wpProc.WorkingSetSize / 1MB)
            $outputMessage += ("`r`n" + "| $($w3wpProc.CreationDate) | $($w3wpMemoryUsage) MB | $($appPoolName)")
        }
        Write-Output $outputMessage
        Add-SPSWakeUpEvent -Message $outputMessage -Source 'Invoke-SPSAllSites'-EntryType Information

        # Clean the copy files of system HOSTS folder
        Clear-HostsFileCopy -hostsFilePath $hostsFile
    }
}
function Disable-LoopbackCheck {
    $lsaPath = 'HKLM:\System\CurrentControlSet\Control\Lsa'
    $lsaPathValue = Get-ItemProperty -path $lsaPath
    if (-not ($lsaPathValue.DisableLoopbackCheck -eq '1')) {
        Write-Output 'Disabling Loopback Check...'
        New-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\Lsa -Name 'DisableLoopbackCheck' -value '1' -PropertyType dword -Force | Out-Null
    }
    else {
        Write-Output 'Loopback Check already Disabled - skipping.'
    }
}
function Clear-HostsFileCopy {
    Param
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
function Add-SPSUserPolicy {
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $Urls,

        [Parameter(Mandatory = $true)]
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
            $catchMessage = @"
An error occurred while adding SPWebApp Policy for UserName: $UserName
Url: $($url)
Exception: $($_.Exception.Message)
"@
            Write-Error -Message $catchMessage
            Add-SPSWakeUpEvent -Message $catchMessage -Source 'SPSWakeUP' -EntryType 'Error'
        }
    }
}
function Set-SPSProxySettings {
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
            try {
                $proxySettings = Get-ItemProperty -Path $regPath |
                Select-Object AutoConfigURL, ProxyEnable, ProxyServer, ProxyOverride

                $proxySettings | ConvertTo-Json | Out-File -FilePath $BackupFile -Encoding UTF8
                Write-Output "Proxy settings backed up to $BackupFile"
            }
            catch {
                $catchMessage = @"
An error occurred while saving proxy settings
File : $BackupFile
Exception: $($_.Exception.Message)
"@
                Write-Error -Message $catchMessage
            }
        }
        'Disable' {
            try {
                $itemProperties = @('AutoConfigURL', 'ProxyServer', 'ProxyOverride')
                Set-ItemProperty -Path $regPath -Name ProxyEnable -Value 0
                foreach ($itemProperty in $itemProperties) {
                    if (Get-ItemProperty -Path $regPath -Name $itemProperty -ErrorAction SilentlyContinue) {
                        Remove-ItemProperty -Path $regPath -Name $itemProperty -ErrorAction SilentlyContinue
                    }
                }
                Write-Host 'All proxy settings disabled.'
            }
            catch {
                $catchMessage = @"
An error occurred while disabling proxy settings
Exception: $($_.Exception.Message)
"@
                Write-Error -Message $catchMessage
            }
        }
        'Restore' {
            if (Test-Path $BackupFile) {
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
                    Write-Host "Proxy settings restored from $BackupFile"
                }
                catch {
                    $catchMessage = @"
An error occurred while restoring proxy settings
File : $BackupFile
Exception: $($_.Exception.Message)
"@
                    Write-Error -Message $catchMessage
                }
            }
            else {
                Write-Host "Backup file not found at $BackupFile"
            }
        }
    }
}
#endregion

#region initialize SharePoint Context
# Load SharePoint Powershell Snapin or Import-Module
try {
    $installedVersion = Get-SPSInstalledProductVersion
    if ($installedVersion.ProductMajorPart -eq 15 -or $installedVersion.ProductBuildPart -le 12999) {
        if ($null -eq (Get-PSSnapin -Name Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue)) {
            Add-PSSnapin Microsoft.SharePoint.PowerShell
        }
    }
    else {
        Import-Module SharePointServer -Verbose:$false -WarningAction SilentlyContinue -DisableNameChecking
    }
}
catch {
    # Handle errors during retrieval of Installed Product Version
    $catchMessage = @"
Failed to get installed Product Version for $($env:COMPUTERNAME)
Exception: $($_.Exception.Message)
"@
    Write-Error -Message $catchMessage
    Add-SPSWakeUpEvent -Message $catchMessage -Source 'Initialize Module' -EntryType 'Error'
}
# From SharePoint 2016, check if MinRole equal to Search
try {
    $currentSPServer = Get-SPServer | Where-Object -FilterScript { $_.Address -eq $env:COMPUTERNAME }
    if ($null -ne $currentSPServer -and (Get-SPFarm).buildversion.major -ge 16) {
        if ($currentSPServer.Role -eq 'Search') {
            Write-Warning -Message 'You run this script on server with Search MinRole'
            Add-SPSWakeUpEvent -Message 'Search MinRole is not supported in SPSWakeUp' -Source 'Server MinRole' -EntryType 'Warning'
            Exit
        }
    }
}
catch {
    Write-Error -Message @"
An error occurred while checking the SharePoint Server Role
Exception: $($_.Exception.Message)
"@
}
#endregion

#region main
switch ($Action) {
    'Uninstall' {
        # Remove SPSWakeup script from scheduled Task
        Remove-SPSSheduledTask -TaskName 'SPSWakeUP'
    }
    'Install' {
        if ($null -eq $InstallAccount) {
            Write-Warning -Message ('SPSWakeUp: Install parameter is set. Please set also InstallAccount ' + `
                    "parameter. `nSee https://github.com/luigilink/SPSWakeUp/wiki for details.")
            Exit
        }
        else {
            # Initialize variables
            $scriptFullPath = Join-Path -Path $PSScriptRoot -ChildPath 'SPSWakeUP.ps1'
            # Add SPSWakeup script in a new scheduled Task
            Install-SPSWakeUP -Path $scriptFullPath -InstallAccount $InstallAccount
        }
    }
    'AdminSitesOnly' {
        # Backup current Proxy Settings and Disable them
        Set-SPSProxySettings -Action 'Backup' -BackupFile "$PSScriptRoot\SPSWakeUP_proxy_backup.json"
        Set-SPSProxySettings -Action 'Disable'

        # Invoke-WebRequest on Central Admin if Action parameter equal to AdminSitesOnly
        Invoke-SPSAdminSites

        # Restore Proxy Settings
        Set-SPSProxySettings -Action 'Restore' -BackupFile "$PSScriptRoot\SPSWakeUP_proxy_backup.json"
    }
    Default {
        # Backup current Proxy Settings and Disable them
        Set-SPSProxySettings -Action 'Backup' -BackupFile "$PSScriptRoot\SPSWakeUP_proxy_backup.json"
        Set-SPSProxySettings -Action 'Disable'

        # Invoke-WebRequest on Central Admin if Action parameter equal to Default
        Invoke-SPSAdminSites

        # Invoke-WebRequest on All Web Applications Urls, Host Named Site Collection and Site Collections
        Invoke-SPSAllSites

        # Restore Proxy Settings
        Set-SPSProxySettings -Action 'Restore' -BackupFile "$PSScriptRoot\SPSWakeUP_proxy_backup.json"
    }
}

# Stop Transcript parameter is equal to True
if ($Transcript) {
    Stop-Transcript
}
Exit
#endregion
