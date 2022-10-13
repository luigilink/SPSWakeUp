<#
    .SYNOPSIS
    SPSWakeUP script for SharePoint OnPremises

    .DESCRIPTION
    SPSWakeUp is a PowerShell script tool to warm up all site collection in your SharePoint environment.
    It's compatible with all supported versions for SharePoint (2010 to 2019).
    Use WebRequest object in multi-thread to download JS, CSS and Pictures files,
    Log script results in log file,
    Email nofications,
    Configure automatically prerequisites for a best warm-up,

    .PARAMETER InputFile
    Need parameter input file, example:
    PS D:\> E:\SCRIPT\SPSWakeUP.ps1 -InputFile 'E:\SCRIPT\SPSWakeUP.psd1'

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

    .PARAMETER OnlyRootWeb
    Use the switch OnlyRootWeb parameter if you don't want to warmup the SPWebs of each site collection
    and only warmup the root web of the site collection.
    PS D:\> E:\SCRIPT\SPSWakeUP.ps1 -OnlyRootWeb

    .EXAMPLE
    SPSWakeUP.ps1 -InputFile 'E:\SCRIPT\SPSWakeUP.psd1'
    SPSWakeUP.ps1 -Install -InstallAccount (Get-Credential)
    SPSWakeUP.ps1 -Uninstall
    SPSWakeUP.ps1 -OnlyRootWeb

    .NOTES
    FileName:	SPSWakeUP.ps1
    Author:		luigilink (Jean-Cyril DROUHIN)
    Date:		July 16, 2021
    Version:	2.5.0
    Licence:	MIT License

    .LINK
    https://spwakeup.com/
    https://github.com/luigilink/spswakeup
#>
param
(
    [Parameter(Position = 0)]
    [System.String]
    $InputFile,

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
    [switch]
    $OnlyRootWeb
)

Clear-Host
$Host.UI.RawUI.WindowTitle = "WarmUP script running on $env:COMPUTERNAME"

# Define variable
$spsWakeupVersion = '2.5.1'
$currentUser = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name
$scriptRootPath = Split-Path -parent $MyInvocation.MyCommand.Definition

$pathLogFile = Join-Path -Path $scriptRootPath -ChildPath ('SPSWakeUP_script_' + (Get-Date -Format yyyy-MM-dd_H-mm) + '.log')
$logFileContent =  New-Object -TypeName System.Collections.Generic.List[string]

$hostEntries =  New-Object -TypeName System.Collections.Generic.List[string]
$hostsFile = "$env:windir\System32\drivers\etc\HOSTS"
$hostsFileCopy = $hostsFile + '.' + (Get-Date -UFormat "%y%m%d%H%M%S").ToString() + '.copy'

# Get the content of the SPSWakeUP.xml file
if (-not($InputFile))
{
    $InputFile = Join-Path -Path $scriptRootPath -ChildPath 'SPSWakeUP.psd1'
}
if (Test-Path -Path $InputFile)
{
    $dataConfig = Import-LocalizedData -BaseDirectory $scriptRootPath -FileName 'SPSWakeUP.psd1'
}

#Check UserName and Password if Install parameter is used
if ($Install)
{
    if ($null -eq $InstallAccount)
    {
        Write-Warning -Message ('SPSWakeUp: Install parameter is set. Please set also InstallAccount ' + `
                                "parameter. `nSee https://spwakeup.com for details.")
        Break
    }
    else
    {
        $UserName = $InstallAccount.UserName
        $Password = $InstallAccount.GetNetworkCredential().Password

        $currentDomain = 'LDAP://' + ([ADSI]'').distinguishedName
        Write-Output "Checking Account `"$UserName`" ..."
        $dom = New-Object System.DirectoryServices.DirectoryEntry($currentDomain,$UserName,$Password)
        if ($null -eq $dom.Path)
        {
            Write-Warning -Message "Password Invalid for user:`"$UserName`""
            Break
        }
    }
}

# ====================================================================================
# INTERNAL FUNCTIONS
# ====================================================================================
#region logging and trap exception
<#
    .SYNOPSIS
    Displays a standardized verbose message.

    .PARAMETER Message
    String containing the key of the localized verbose message.
#>
function Write-VerboseMessage
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([String])]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [System.String]
        $Message
    )

    Write-Verbose -Message ((Get-Date -format yyyy-MM-dd_HH-mm-ss) + ": $Message");
}
# ===================================================================================
# Func: Write-LogException
# Desc: write Exception in powershell session and in error file
# ===================================================================================
<#
    .SYNOPSIS
    Write Exception in powershell session and in error file

    .PARAMETER Message
    Object containing the exception of a try/catch sequence.
#>
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

    Write-Warning -Message $Message.Exception.Message
    $pathErrLog = Join-Path -Path $scriptRootPath -ChildPath (((Get-Date).Ticks.ToString()) + '_errlog.xml')
    Export-Clixml -Path $pathErrLog -InputObject $Message -Depth 3
    Write-LogContent -Message 'For more informations, see errlog.xml file:'
    Write-LogContent -Message $pathErrLog
}
# ===================================================================================
# Func: Save-LogFile
# Desc: Save the log file in current folder
# ===================================================================================
function Save-LogFile
{
    param
    (
        [Parameter(Mandatory=$true)]
        [System.String]
        $Path
    )

    $pathLogFile = New-Object -TypeName System.IO.StreamWriter($Path)
    foreach ($logFileC in $logFileContent)
    {
        $pathLogFile.WriteLine($logFileC)
    }

    $pathLogFile.Close()
}
# ===================================================================================
# Func: Write-LogContent
# Desc: Add Content in log file and write-output in console
# ===================================================================================
function Write-LogContent
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([String])]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [System.String]
        $Message
    )

    Write-Output $Message

    $logFileContent.Add($Message)
}
# ===================================================================================
# Func: Send-SPSLog
# Desc: Send Email with log file in attachment
# ===================================================================================
function Send-SPSLog
{
    param
    (
        [Parameter(Mandatory=$true)]
        $MailAttachment,

        [Parameter(Mandatory=$true)]
        $MailBody
    )

    if ($dataConfig.Settings.EmailNotification.Enable)
    {
        $mailAddress = $dataConfig.Settings.EmailNotification.EmailAddress
        $smtpServer = $dataConfig.Settings.EmailNotification.SMTPServer
        $mailSubject = "Automated Script - SPSWakeUP Urls - $env:COMPUTERNAME"

        Write-LogContent -Message '--------------------------------------------------------------'
        Write-LogContent -Message "Sending Email with Log file to $mailAddress ..."
        try
        {
            Send-MailMessage -To $mailAddress -From $mailAddress -Subject $mailSubject -Body $MailBody -BodyAsHtml -SmtpServer $smtpServer -Attachments $MailAttachment -ea stop
            Write-LogContent -Message "Email sent successfully to $mailAddress"
        }
        catch
        {
            Write-LogException -Message $_
        }
    }
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
        [System.String]$path
    )

    if (Test-Path $path)
    {
        # Days of logs that will be remaining after log cleanup.
        $days = $dataConfig.Settings.CleanLogsDays

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

        if ($files)
        {
            Write-LogContent -Message '--------------------------------------------------------------'
            Write-LogContent -Message "Cleaning log files in $path ..."
            foreach ($file in $files)
            {
                if ($null -ne $file)
                {
                    Write-LogContent -Message "Deleting file $file ..."
                    Remove-Item $file.FullName | out-null
                }
                else
                {
                    Write-LogContent -Message 'No more log files to delete'
                    Write-LogContent -Message '--------------------------------------------------------------'
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
    $inputFileFullPath = (Get-Item $InputFile).FullName;
    $TaskCmdArg =
@"
-Command Start-Process "$PSHOME\powershell.exe" -Verb RunAs -ArgumentList "'-ExecutionPolicy Bypass ""$path\SPSWakeUP.ps1 -inputFile $inputFileFullPath""'"
"@

    if ($TaskSPSWKP)
    {
        Write-Warning -Message 'Shedule Task already exists - skipping.'
    }
    else
    {
        Write-LogContent -Message '--------------------------------------------------------------'
        Write-LogContent -Message 'Adding SPSWakeUP script in Task Scheduler Service ...'

        # Get Credentials for Task Schedule
        $TaskAuthor = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name
        $TaskUser =  $UserName
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
        try
        {
            $TaskFolder.RegisterTaskDefinition( $TaskName, $TaskSchd, 6, $TaskUser , $TaskUserPwd , 1)
            Write-LogContent -Message 'Successfully added SPSWakeUP script in Task Scheduler Service'
        }
        catch
        {
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

    if ($null -eq $TaskSPSWKP)
    {
        Write-Warning -Message 'Shedule Task already removed - skipping.'
    }
    else
    {
        Write-LogContent -Message '--------------------------------------------------------------'
        Write-LogContent -Message 'Removing SPSWakeUP script in Task Scheduler Service ...'

        try
        {
            $TaskFolder.DeleteTask($TaskName,$null)
            Write-LogContent -Message 'Successfully removed SPSWakeUP script from Task Scheduler Service'
        }
        catch
        {
            Write-LogException -Message $_
        }
    }
}
#endregion

#region Load SharePoint Powershell Snapin for SharePoint 2010, 2013 & 2016
# ===================================================================================
# Name: 		Add-PSSharePoint
# Description:	Load SharePoint Powershell Snapin
# ===================================================================================
function Add-PSSharePoint
{
    if ($null -eq (Get-PsSnapin | Where-Object -FilterScript {$_.Name -eq 'Microsoft.SharePoint.PowerShell'}))
    {
        Write-LogContent -Message '--------------------------------------------------------------'
        Write-LogContent -Message 'Loading SharePoint Powershell Snapin ...'
        Add-PsSnapin Microsoft.SharePoint.PowerShell -ErrorAction Stop | Out-Null
        Write-LogContent -Message '--------------------------------------------------------------'
    }
}
# ===================================================================================
# Name: 		Add-RASharePoint
# Description:	Load SharePoint Assembly for SharePoint 2007, 2010, 2013 & 2016
# ===================================================================================
function Add-RASharePoint
{
    Write-LogContent -Message '--------------------------------------------------------------'
    Write-LogContent -Message 'Loading Microsoft.SharePoint Assembly ...'
    [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SharePoint') | Out-Null
    Write-LogContent -Message '--------------------------------------------------------------'
}
# ===================================================================================
# Name: 		Add-SystemWeb
# Description:	Load System.Web with Reflection Assembly
# ===================================================================================
function Add-SystemWeb
{

    Write-LogContent -Message '--------------------------------------------------------------'
    Write-LogContent -Message 'Loading System.Web ...'
    [System.Reflection.Assembly]::LoadWithPartialName('system.web') | Out-Null
    Write-LogContent -Message '--------------------------------------------------------------'

}
# ===================================================================================
# Name: 		Get-SPSThrottleLimit
# Description:	Get Number Of Throttle Limit
# ===================================================================================
function Get-SPSThrottleLimit
{
    [int]$NumThrottle = 8

    # Get Number Of Throttle Limit
    try
    {
        $cimInstanceProc = @(Get-CimInstance -ClassName Win32_Processor)
        $cimInstanceSocket = $cimInstanceProc.count
        $numLogicalCpu = $cimInstanceProc[0].NumberOfLogicalProcessors * $cimInstanceSocket

        if ($numLogicalCpu -le 2)
        {
            $NumThrottle = 2 * $numLogicalCpu
        }
        elseif ($numLogicalCpu -ge 8)
        {
            $NumThrottle = 10
        }
        else
        {
            $NumThrottle = 2 * $numLogicalCpu
        }
    }
    catch
    {
        Write-Warning -Message $_
    }

    return $NumThrottle
}
#endregion

#region get all site collections and all web applications
# ===================================================================================
# Name: 		Get-SPSVersion
# Description:	PowerShell script to display SharePoint products from the registry.
# ===================================================================================
function Get-SPSVersion
{
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
# ===================================================================================
# Name: 		Add-SPSSitesUrl
# Description:	Add Site Collection Url and FBA settings in PSObject
# ===================================================================================
function Add-SPSSitesUrl
{
    param
    (
        [Parameter(Mandatory=$true)]
        [System.String]
        $Url,

        [Parameter(Mandatory=$false)]
        [bool]
        $Fba = $false,

        [Parameter(Mandatory=$false)]
        [bool]
        $Win = $true
    )

    $pso = New-Object PSObject
    $pso | Add-Member -Name Url -MemberType NoteProperty -Value $Url
    $pso | Add-Member -Name FBA -MemberType NoteProperty -Value $Fba
    $pso | Add-Member -Name Win -MemberType NoteProperty -Value $Win
    $pso
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
        $url
    )

    $url = $url -replace 'https://',''
    $url = $url -replace 'http://',''
    $hostNameEntry = $url.split('/')[0]
    [void]$hostEntries.Add($hostNameEntry)
}
# ===================================================================================
# Name: 		Get-SPSSitesUrl
# Description:	Get All Site Collections Url
# ===================================================================================
function Get-SPSSitesUrl
{
    [CmdletBinding()]
    [OutputType([System.Collections.ArrayList])]

    $tbSitesURL = New-Object -TypeName System.Collections.ArrayList
    $defaultUrlZone = [Microsoft.SharePoint.Administration.SPUrlZone]::Default
    [bool]$fbaSParameter = $false
    [bool]$winParameter = $true

    try
    {
        $topologySvcUrl = 'http://localhost:32843/Topology/topology.svc'
        [void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $topologySvcUrl))

        # Get url of CentralAdmin if include in input xml file
        if ($dataConfig.Settings.IncludeCentralAdmin -eq $true)
        {
            $webAppADM = Get-SPWebApplication -IncludeCentralAdministration | Where-Object -FilterScript {
                $_.IsAdministrationWebApplication
            }
            $siteADM = $webAppADM.Url
            # Most useful administration pages
            [void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $siteADM))
            [void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $siteADM'Lists/HealthReports/AllItems.aspx'))
            [void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $siteADM'_admin/FarmServers.aspx'))
            [void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $siteADM'_admin/Server.aspx'))
            [void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $siteADM'_admin/WebApplicationList.aspx'))
            [void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $siteADM'_admin/ServiceApplications.aspx'))

            # Quick launch top links
            [void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $siteADM'applications.aspx'))
            [void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $siteADM'systemsettings.aspx'))
            [void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $siteADM'monitoring.aspx'))
            [void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $siteADM'backups.aspx'))
            [void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $siteADM'security.aspx'))
            [void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $siteADM'upgradeandmigration.aspx'))
            [void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $siteADM'apps.aspx'))
            [void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $siteADM'generalapplicationsettings.aspx'))

            # Get Service Application Urls
            $sa = Get-SPServiceApplication
            $linkUrls = $sa | ForEach-Object {$_.ManageLink.Url} | Select-Object -Unique
            foreach ($linkUrl in $linkUrls)
            {
                $siteADMSA = $linkUrl.TrimStart('/')
                [void]$tbSitesURL.Add((Add-SPSSitesUrl -Url "$siteADM$siteADMSA"))
            }
        }

        # Get Url of all site collection
        #$WebSrv = [microsoft.sharepoint.administration.spwebservice]::ContentService
        $webApps = Get-SPWebApplication

        foreach ($webApp in $webApps)
        {
            $iisSettings = $webApp.GetIisSettingsWithFallback($defaultUrlZone)
            $getClaimProviderForms = $iisSettings.ClaimsAuthenticationProviders | Where-Object -FilterScript {
                $_.ClaimProviderName -eq 'Forms'
            }
            $getClaimProviderWindows = $iisSettings.ClaimsAuthenticationProviders | Where-Object -FilterScript {
                $_.ClaimProviderName -eq 'AD'
            }

            if ($getClaimProviderForms)
            {
                $fbaSParameter = $true
            }
            else
            {
                $fbaSParameter=$false
            }

            if ($getClaimProviderWindows)
            {
                $winParameter = $true
            }
            else
            {
                $winParameter=$false
            }

            $sites = $webApp.sites
            foreach ($site in $sites)
            {
                if ($OnlyRootWeb)
                {
                    if (($fbaSParameter -eq $true) -and ($winParameter -eq $true))
                    {
                        $siteUrl = $site.RootWeb.Url + '/_windows/default.aspx?ReturnUrl=/_layouts/15/Authenticate.aspx?Source=%2f'
                    }
                    else
                    {
                        $siteUrl = $site.RootWeb.Url
                    }
                    if ($siteUrl -notmatch 'sitemaster-')
                    {
                        [void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $siteUrl -FBA $fbaSParameter -Win $winParameter))
                    }
                }
                else
                {
                    $webs = (Get-SPWeb -Site $site -Limit ALL)
                    foreach ($web in $webs)
                    {
                        if (($fbaSParameter -eq $true) -and ($winParameter -eq $true))
                        {
                            $webUrl = $web.Url + '/_windows/default.aspx?ReturnUrl=/_layouts/15/Authenticate.aspx?Source=%2f'
                        }
                        else
                        {
                            $webUrl = $web.Url
                        }
                        if ($webUrl -notmatch 'sitemaster-')
                        {
                            [void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $webUrl -FBA $fbaSParameter -Win $winParameter))
                        }
                    }
                }
                $site.Dispose()
            }

        }
    }
    catch
    {
        Write-LogException -Message $_
    }

    $tbSitesURL
}
# ===================================================================================
# Name: 		Get-SPSHSNCUrl
# Description:	Get All Host Named Site Collection Url
# ===================================================================================
function Get-SPSHSNCUrl
{
    [CmdletBinding()]
    [OutputType([System.Collections.ArrayList])]

    $hsncURL = New-Object System.Collections.ArrayList
    $webApps = Get-SPWebApplication

    $sites = $webApps | ForEach-Object -Process {
        $_.sites
    }
    $HSNCs = $sites | Where-Object -FilterScript {
        $_.HostHeaderIsSiteName -eq $true
    }

    foreach ($HSNC in $HSNCs)
    {
        if ($HSNC.Url -notmatch 'sitemaster-')
        {
            [void]$hsncURL.Add($HSNC.Url)
            Add-SPSHostEntry -Url $HSNC.Url
        }
        $HSNC.Dispose()
    }

    $hsncURL
}
# ===================================================================================
# Name: 		Get-SPSWebAppUrl
# Description:	Get All Web Applications Url
# ===================================================================================
function Get-SPSWebAppUrl
{
    [CmdletBinding()]
    [OutputType([System.Collections.ArrayList])]

    $webAppURL = New-Object -TypeName System.Collections.ArrayList
    $webApps = Get-SPWebApplication

    foreach ($webapp in $webApps)
    {
        [void]$webAppURL.Add($webapp.GetResponseUri('Default').AbsoluteUri)
        $spSrvIsInUri = Get-SPServer | Where-Object -FilterScript {
            $webapp.GetResponseUri('Default').AbsoluteUri -match $_.Name
        }
        if ($null -eq $spSrvIsInUri)
        {
            Add-SPSHostEntry -Url $webapp.GetResponseUri('Default').AbsoluteUri
        }
    }

    $webAppURL
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
        $Urls,

        [Parameter(Mandatory=$true)]
        $throttleLimit
    )

    # Get UserAgent from current OS
    if ([string]::IsNullOrEmpty($userAgent))
    {
        $userAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::InternetExplorer
    }

    $iss = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
    $Pool = [runspacefactory]::CreateRunspacePool(1, $throttleLimit, $iss, $Host)
    $Pool.Open()

    $ScriptBlock =
    {
        param
        (
            [Parameter(Mandatory=$true)]$url,
            [Parameter(Mandatory=$false)]$useragent
        )

        Process
        {
            function Get-GenericWebRequest()
            {
                param
                (
                    [Parameter(Mandatory=$true)]$URL,
                    [Parameter(Mandatory=$false)]$AllowAutoRedirect = $true
                )
                Process
                {
                    $GenericWebRequest = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create($URL)
                    $GenericWebRequest.UseDefaultCredentials = $true
                    $GenericWebRequest.Method = 'GET'
                    $GenericWebRequest.UserAgent = $useragent
                    $GenericWebRequest.Accept = 'text/html'
                    $GenericWebRequest.Timeout = 80000
                    $GenericWebRequest.AllowAutoRedirect = $AllowAutoRedirect
                    if (((Get-Host).Version.Major) -gt 2){$GenericWebRequest.ServerCertificateValidationCallback = { $true }}
                    $GenericWebRequest
                }
            }

            $TimeStart = Get-Date;
            $fedAuthwebrequest = Get-GenericWebRequest -URL $url -AllowAutoRedirect $false;

            try
            {
                # Get the response of $WebRequestObject
                $fedAuthwebresponse = [System.Net.HttpWebResponse] $fedAuthwebrequest.GetResponse()
                $fedAuthCookie = $fedAuthwebresponse.Headers['Set-Cookie'];

                $httpwebrequest = Get-GenericWebRequest -URL $Url -AllowAutoRedirect $true;
                $httpwebrequest.Headers.Add('Cookie', "$fedAuthCookie");

                $ResponseObject = [System.Net.HttpWebResponse] $httpwebrequest.GetResponse()
                $TimeStop = Get-Date
                $TimeExec = ($TimeStop - $TimeStart).TotalSeconds
                $TimeExec = '{0:N2}' -f $TimeExec
                $Response = "$([System.int32]$ResponseObject.StatusCode) - $($ResponseObject.StatusCode)"

            }
            catch [Net.WebException]
            {
                $Response = $_.Exception.Message
            }
            finally
            {
                if ($ResponseObject)
                {
                    $ResponseObject.Close()
                    Remove-Variable ResponseObject
                }
            }
            $RunResult = New-Object PSObject
            $RunResult | Add-Member -MemberType NoteProperty -Name Url -Value $url
            $RunResult | Add-Member -MemberType NoteProperty -Name 'Time(s)' -Value $TimeExec
            $RunResult | Add-Member -MemberType NoteProperty -Name Status -Value $Response

            $RunResult
        }
    }

    try
    {

       $Jobs = @()
       foreach ($Url in $Urls)
       {
            $Job = [powershell]::Create().AddScript($ScriptBlock).AddParameter('URL',$Url.Url).AddParameter('UserAgent',$userAgent)
            $Job.RunspacePool = $Pool
            $Jobs += New-Object PSObject -Property @{
                Url = $Url.Url
                Pipe = $Job
                Result = $Job.BeginInvoke()
            }
       }

        While ($Jobs.Result.IsCompleted -contains $false)
        {
            if ($i -lt 100)
            {
                $i = $i+1
            }

           Write-Progress -Activity 'Opening All sites Urls with Web Request' -Status 'Please Wait...' -Percentcomplete ($i)
           Start-Sleep -S 1
        }

        $Results = @()
        foreach ($Job in $Jobs)
        {
            $Results += $Job.Pipe.EndInvoke($Job.Result)
        }

    }
    catch
    {
        Write-LogContent -Message 'An error occurred invoking multi-threading function'
        Write-LogException -Message $_
    }

    Finally
    {
        $Pool.Dispose()
    }
    $Results
}
#endregion

#region Configuration and permission
# ===================================================================================
# Func: Disable-LoopbackCheck
# Desc: Disable Loopback Check
# ===================================================================================
function Disable-LoopbackCheck
{
    param
    (
        [Parameter(Mandatory=$true)]$hostNameList
    )

    # Disable the Loopback Check on stand alone demo servers.
    # This setting usually kicks out a 401 error when you try to navigate to sites that resolve to a loopback address e.g.  127.0.0.1
    if ($dataConfig.Settings.DisableLoopbackCheck -eq $true)
    {

        $lsaPath = 'HKLM:\System\CurrentControlSet\Control\Lsa'
        $lsaPathValue = Get-ItemProperty -path $lsaPath
        if (-not ($lsaPathValue.DisableLoopbackCheck -eq '1'))
        {
            Write-LogContent -Message 'Disabling Loopback Check...'
            New-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name 'DisableLoopbackCheck' -value '1' -PropertyType dword -Force | Out-Null
        }
        else
        {
            Write-LogContent -Message 'Loopback Check already Disabled - skipping.'
        }
    }
    else
    {
        $lsaPath = 'HKLM:\System\CurrentControlSet\Control\Lsa'
        $paramPath = 'HKLM:System\CurrentControlSet\Services\LanmanServer\Parameters'
        $mvaPath = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
        $lsaPathValue = Get-ItemProperty -path $lsaPath
        $paramPathValue = Get-ItemProperty -path $paramPath

        if ($lsaPathValue.DisableLoopbackCheck -eq '1')
        {
            Write-LogContent -Message 'Disabling Loopback Check - Back to default value ...'
            New-ItemProperty $lsaPath -Name 'DisableLoopbackCheck' -value '0' -PropertyType dword -Force | Out-Null
        }

        if (-not($paramPathValue.DisableStrictNameChecking -eq '1'))
        {
            Write-LogContent -Message 'Disabling Strict Name Checking ...'
            New-ItemProperty $paramPath -Name 'DisableStrictNameChecking' -value '1' -PropertyType dword -Force | Out-Null
        }

        $BackCoName = Get-ItemProperty -Path $mvaPath -Name BackConnectionHostNames -ea SilentlyContinue
        if (!($BackCoName))
        {
            New-ItemProperty $mvaPath -Name 'BackConnectionHostNames' -PropertyType multistring -Force | Out-Null
        }
        foreach ($hostName in $hostNameList)
        {
            if (!($BackCoName.BackConnectionHostNames -like "*$hostName*"))
            {
                Write-LogContent -Message "Add $hostName in BackConnectionHostNames regedit key ..."
                $BackCoNameNew = $BackCoName.BackConnectionHostNames + "$hostName"
                New-ItemProperty $mvaPath -Name 'BackConnectionHostNames' -Value $BackCoNameNew -PropertyType multistring -Force | Out-Null
            }
        }
    }
}
# ====================================================================================
# Func: Backup-HostsFile
# Desc: Backup HOSTS File System
# ====================================================================================
function Backup-HostsFile
{
    Param
    (
        [Parameter(Mandatory=$true)]$hostsFilePath,
        [Parameter(Mandatory=$true)]$hostsBackupPath
    )

    if ($dataConfig.Settings.AddURLsToHOSTS.Enable -eq $true)
    {
        Write-LogContent -Message "Backing up $hostsFilePath file to:"
        Write-LogContent -Message "$hostsBackupPath"
        Copy-Item $hostsFilePath -Destination $hostsBackupPath -Force
    }
}
# ====================================================================================
# Func: Restore-HostsFile
# Desc: Restore previous HOSTS File System
# ====================================================================================
function Restore-HostsFile
{
    Param
    (
        [Parameter(Mandatory=$true)]$hostsFilePath,
        [Parameter(Mandatory=$true)]$hostsBackupPath
    )
    if ($dataConfig.Settings.AddURLsToHOSTS.Enable -eq $true -AND $dataConfig.Settings.AddURLsToHOSTS.KeepOriginal -eq $true)
    {
        Write-LogContent -Message "Restoring $hostsBackupPath file to:"
        Write-LogContent -Message "$hostsFilePath"
        Copy-Item $hostsBackupPath -Destination $hostsFilePath -Force
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
        [Parameter(Mandatory=$true)]$hostsFilePath
    )

    $hostsFolderPath = Split-Path $hostsFilePath
    if (Test-Path $hostsFolderPath)
    {
        # Number of files that will be remaining after backup cleanup.
        $numberFiles = $dataConfig.Settings.AddURLsToHOSTS.Retention
        # Definie the extension of log files
        $extension = '*.copy'

        # Get files with .copy extension, sort them by name, from most recent to oldest and skip the first numberFiles variable
        $copyFiles = Get-Childitem -Path "$hostsFolderPath\*.*" -Include $extension | Sort-Object -Descending -Property Name | Select-Object -Skip $numberFiles

        if ($copyFiles)
        {
            Write-LogContent -Message '--------------------------------------------------------------'
            Write-LogContent -Message "Cleaning backup HOSTS files in $hostsFolderPath ..."
            foreach ($copyFile in $copyFiles)
            {
                if ($null -ne $copyFile)
                {
                    Write-LogContent -Message "   * Deleting File $copyFile ..."
                    Remove-Item $copyFile.FullName | out-null
                }
                Else
                {
                    Write-LogContent -Message 'No more backup HOSTS files to delete '
                    Write-LogContent -Message '--------------------------------------------------------------'
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
        [Parameter(Mandatory=$true)]$hostNameList
    )

    if ($dataConfig.Settings.AddURLsToHOSTS.Enable -eq $true -and $hostNameList)
    {
        $hostsContentFile =  New-Object System.Collections.Generic.List[string]
        # Check if the IPv4Address configured in XML Input file is reachable
        $hostIPV4Addr = $dataConfig.Settings.AddURLsToHOSTS.IPv4Address
        Write-LogContent -Message "Testing connection (via Ping) to `"$hostIPV4Addr`"..."
        $canConnect = Test-Connection $hostIPV4Addr -Count 1 -Quiet
        if ($canConnect)
        {
            Write-LogContent -Message "IPv4Address $hostIPV4Addr will be used in HOSTS File during WarmUP ..."
        }
        else
        {
            Write-LogContent -Message '   * IPv4Address not valid in Input XML File, 127.0.0.1 will be used in HOSTS File'
            $hostIPV4Addr = '127.0.0.1'
        }

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

        if ($dataConfig.Settings.AddURLsToHOSTS.ListRevocationUrl -eq $true){$hostsContentFile.Add("127.0.0.1 `t crl.microsoft.com")}
        ForEach ($hostname in $hostNameList)
        {
            # Remove http or https information to keep only HostName or FQDN
            if ($hostname.Contains(':'))
            {
                Write-LogContent -Message "$hostname cannot be added in HOSTS File, only web applications with 80 or 443 port are added."
            }
            Else
            {
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

    Write-LogContent -Message '--------------------------------------------------------------'
    Write-LogContent -Message "Add Read Access to $UserName for All Web Applications ..."
    foreach ($url in $Urls)
    {
        try
        {
            $webapp = [Microsoft.SharePoint.Administration.SPWebApplication]::Lookup("$url")
            $displayName = 'SPSWakeUP Account'

            # If the web app is not Central Administration
            if ($webapp.IsAdministrationWebApplication -eq $false)
            {
                # If the web app is using Claims auth, change the user accounts to the proper syntax
                if ($webapp.UseClaimsAuthentication -eq $true)
                {
                    $user = (New-SPClaimsPrincipal -identity $UserName -identitytype 1).ToEncodedString()
                }
                else
                {
                    $user = $UserName
                }
                Write-LogContent -Message "Checking Read access for $user account to $url..."
                [Microsoft.SharePoint.Administration.SPPolicyCollection]$policies = $webapp.Policies
                $policyExist = $policies | Where-Object -FilterScript {
                    $_.Displayname -eq 'SPSWakeUP Account'
                }

                if (-not ($policyExist))
                {
                    Write-LogContent -Message "Applying Read access for $user account to $url..."
                    [Microsoft.SharePoint.Administration.SPPolicy]$policy = $policies.Add($user, $displayName)
                    $policyRole = $webApp.PolicyRoles.GetSpecialRole([Microsoft.SharePoint.Administration.SPPolicyRoleType]::FullRead)
                    if ($null -ne $policyRole)
                    {
                        $policy.PolicyRoleBindings.Add($policyRole)
                    }
                    $webapp.Update()
                    Write-LogContent -Message "Done Applying Read access for `"$user`" account to `"$url`""
                }
            }
        }
        catch
        {
            Write-LogException -Message $_
        }
    }
}
#endregion

#region Internet Explorer Configuration
# ===================================================================================
# Name: 		Disable-IEESC
# Description:	Disable Internet Explorer Enhanced Security Configuration for administrators
# ===================================================================================
function Disable-IEESC
{
    if ($dataConfig.Configuration.Settings.DisableIEESC -eq $true)
    {
        Write-LogContent -Message '--------------------------------------------------------------'
        try
        {
            $AdminKey = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}'
            $AdminKeyValue = Get-ItemProperty -Path $AdminKey
            if (-not ($AdminKeyValue.IsInstalled -eq '0'))
            {
                Write-LogContent -Message 'Disabling Internet Explorer Enhanced Security Configuration ...'
                Set-ItemProperty -Path $AdminKey -Name 'IsInstalled' -Value 0
            }
            else
            {
                Write-LogContent -Message 'Internet Explorer ESC already Disabled - skipping.'
            }
        }
        catch
        {
            Write-LogContent -Message 'Failed to Disable Internet Explorer Enhanced Security Configuration'
        }
    }
}

# ===================================================================================
# Func: Disable-IEFirstRun
# Desc: Disable First Run for Internet Explorer
# ===================================================================================
function Disable-IEFirstRun
{
    Write-LogContent -Message '--------------------------------------------------------------'
    $lsaPath = 'HKCU:\Software\Microsoft\Internet Explorer\Main'
    $lsaPathValue = Get-ItemProperty -path $lsaPath

    if (-not ($lsaPathValue.DisableFirstRunCustomize -eq '1'))
    {
        Write-LogContent -Message 'Disabling Internet Explorer First Run ...'
        New-ItemProperty -Path $lsaPath -Name DisableFirstRunCustomize -value '1' -PropertyType dword -Force | Out-Null
    }
    else
    {
        Write-LogContent -Message 'Internet Explorer First Run already Disabled - skipping.'
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

Write-LogContent -Message '-------------------------------------'
Write-LogContent -Message "| Automated Script - SPSWakeUp v$spsWakeupVersion"
Write-LogContent -Message "| Started on : $DateStarted by $currentUser"
Write-LogContent -Message "| PowerShell Version: $psVersion"
Write-LogContent -Message "| SharePoint Version: $spsVersion"
Write-LogContent -Message '-------------------------------------'

# Check Permission Level
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))
{
    Write-Warning -Message 'You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!'
    Break
}
else
{
    if ($Uninstall)
    {
        # Remove SPSWakeup script from scheduled Task
        Remove-SPSTask
    }
    elseif ($Install)
    {
        # Add SPSWakeup script in a new scheduled Task
        Add-SPSTask -Path $scriptRootPath

        # Disable Internet Explorer Enhanced Security Configuration and First Run
        Disable-IEESC
        Disable-IEFirstRun

        # Load SharePoint Powershell Snapin
        Add-PSSharePoint

        # Get All Web Applications Urls
        Write-LogContent -Message '--------------------------------------------------------------'
        Write-LogContent -Message 'Get URLs of All Web Applications ...'
        $getSPWebApps = Get-SPSWebAppUrl

        # Add read access for Warmup User account in User Policies settings
        Add-SPSUserPolicy -Urls $getSPWebApps -UserName $UserName
    }
    else
    {
        Write-LogContent -Message "Setting power management plan to `"High Performance`"..."
        Start-Process -FilePath "$env:SystemRoot\system32\powercfg.exe" `
                      -ArgumentList '/s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' `
                      -NoNewWindow

        # Load SharePoint Powershell Snapin, Assembly and System.Web
        Add-RASharePoint
        Add-PSSharePoint
        Add-SystemWeb

        # From SharePoint 2016, check if MinRole equal to Search
        $currentSPServer = Get-SPServer | Where-Object -FilterScript {$_.Address -eq $env:COMPUTERNAME}
        if ($null -ne $currentSPServer -and (Get-SPFarm).buildversion.major -ge 16)
        {
            if ($currentSPServer.Role -eq 'Search')
            {
                Write-Warning -Message 'You run this script on server with Search MinRole'
                Write-LogContent -Message 'Search MinRole is not supported in SPSWakeUp'
                Break
            }
        }

        # Get All Web Applications Urls, Host Named Site Collection and Site Collections
        Write-LogContent -Message '--------------------------------------------------------------'
        Write-LogContent -Message 'Get URLs of All Web Applications ...'
        $getSPWebApps = Get-SPSWebAppUrl

        Write-LogContent -Message '--------------------------------------------------------------'
        Write-LogContent -Message 'Get URLs of All Host Named Site Collection ...'
        $getSPSiteColN = Get-SPSHSNCUrl

        Write-LogContent -Message '--------------------------------------------------------------'
        Write-LogContent -Message 'Get URLs of All Site Collection ...'
        $getSPSites = Get-SPSSitesUrl
        if ($null -ne $getSPWebApps -and $null -ne $getSPSites)
        {
            if ($hostEntries)
            {
                # Remove Duplicate Entries
                $hostEntries = $hostEntries | Get-Unique
                
                # Disable LoopBack Check
                Write-LogContent -Message '--------------------------------------------------------------'
                Write-LogContent -Message 'Add Urls of All Web Applications or HSNC in BackConnectionHostNames regedit key ...'
                Disable-LoopbackCheck -hostNameList $hostEntries

                # Make backup copy of the Hosts file with today's date Add Web Application and Host Named Site Collection Urls in HOSTS system File
                Write-LogContent -Message '--------------------------------------------------------------'
                Write-LogContent -Message 'Add Urls of All Web Applications or HSNC in HOSTS File ...'

                foreach ($hostEntry in $hostEntries)
                {
                    $hostEntryIsPresent = Select-String -Path $hostsFile -Pattern $hostEntry
                    if ($null -eq $hostEntryIsPresent)
                    {
                        $hostFileNeedsUpdate = $true
                    }
                }
                if ($hostFileNeedsUpdate)
                {
                    Backup-HostsFile -hostsFilePath $hostsFile -hostsBackupPath $hostsFileCopy
                    Add-HostsEntry -hostNameList $hostEntries
                }
                else
                {
                    Write-LogContent -Message 'HOSTS File already contains Urls of All Web Applications or HSNC- skipping.'
                }
            }

            # Request Url with System.Net.WebClient Object for All Site Collections Urls
            Write-LogContent -Message '--------------------------------------------------------------'
            Write-LogContent -Message 'Opening All sites Urls with Web Request Object, Please Wait...'
            $InvokeResults = Invoke-SPSWebRequest -Urls $getSPSites -throttleLimit (Get-SPSThrottleLimit)

            # Show the results
            foreach ($InvokeResult in $InvokeResults)
            {
                $resultUrl = $InvokeResult.Url
                $resultTime = $InvokeResult.'Time(s)'
                $resultStatus = $InvokeResult.Status
                Write-LogContent -Message '-----------------------------------'
                Write-LogContent -Message "| Url    : $resultUrl"
                Write-LogContent -Message "| Time   : $resultTime seconds"
                Write-LogContent -Message "| Status : $resultStatus"
            }
        }

        # Clean the folder of log files
        Clear-SPSLog -path $scriptRootPath

        $DateEnded = Get-date
        $totalUrls = $getSPSites.Count
        $totalDuration = ($DateEnded - $DateStarted).TotalSeconds

        Write-LogContent -Message '-------------------------------------'
        Write-LogContent -Message '| Automated Script - SPSWakeUp'
        Write-LogContent -Message "| Started on : $DateStarted"
        Write-LogContent -Message "| Completed on : $DateEnded"
        Write-LogContent -Message "| SPSWakeUp waked up $totalUrls urls in $totalDuration seconds"
        Write-LogContent -Message '--------------------------------------------------------------'
        Write-LogContent -Message '| REPORTING: Memory Usage for each worker process (W3WP.EXE)'
        Write-LogContent -Message '| Process Creation Date | Memory | Application Pool Name'
        Write-LogContent -Message '--------------------------------------------------------------'

        $w3wpProcess = Get-CimInstance Win32_Process -Filter "name = 'w3wp.exe'" | Select-Object WorkingSetSize, CommandLine, CreationDate | Sort-Object CommandLine
        foreach($w3wpProc in $w3wpProcess)
        {
            $w3wpProcCmdLine = $w3wpProc.CommandLine.Replace('c:\windows\system32\inetsrv\w3wp.exe -ap "','')
            $pos = $w3wpProcCmdLine.IndexOf('"')
            $appPoolName = $w3wpProcCmdLine.Substring(0,$pos)
            $w3wpMemoryUsage = [Math]::Round($w3wpProc.WorkingSetSize / 1MB)
            Write-LogContent -Message "| $($w3wpProc.CreationDate) | $($w3wpMemoryUsage) MB | $($appPoolName)"
        }
        Write-LogContent -Message '--------------------------------------------------------------'

        Trap {Continue}

        # Restore backup copy of the Hosts file with today's date
        Restore-HostsFile -hostsFilePath $hostsFile -hostsBackupPath $hostsFileCopy

        # Clean the copy files of system HOSTS folder
        Clear-HostsFileCopy -hostsFilePath $hostsFile

        Save-LogFile $pathLogFile

        # Send Email with log file in attachment - For settings see XML input file
        $mailLogContent = "Automated Script - SPSWakeUP - Started on: $DateStarted <br>"
        $mailLogContent += "SharePoint Server : $env:COMPUTERNAME<br>"
        Send-SPSLog -MailAttachment $pathLogFile -MailBody $mailLogContent
    }

    Exit
}
#endregion
