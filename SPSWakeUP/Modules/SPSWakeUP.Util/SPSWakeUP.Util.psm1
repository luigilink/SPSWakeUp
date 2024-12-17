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
    Write-EventLog -LogName $LogName -Source $Source -EventId $EventID -Message $Message -EntryType $EntryType
  }
  catch {
    Write-Verbose -Message $_
  }
}
function Get-SPSInstalledProductVersion {
  [OutputType([System.Version])]
  param ()

  $pathToSearch = 'C:\Program Files\Common Files\microsoft shared\Web Server Extensions\*\ISAPI\Microsoft.SharePoint.dll'
  $fullPath = Get-Item $pathToSearch -ErrorAction SilentlyContinue | Sort-Object { $_.Directory } -Descending | Select-Object -First 1
  if ($null -eq $fullPath) {
    throw 'SharePoint path {C:\Program Files\Common Files\microsoft shared\Web Server Extensions} does not exist'
  }
  else {
    return (Get-Command $fullPath).FileVersionInfo
  }
}
function Write-LogException {
  [CmdletBinding()]
  [Alias()]
  [OutputType([String])]
  param
  (
    [Parameter(Mandatory = $true)]
    $Message
  )

  $pathErrLog = Join-Path -Path $scriptRootPath -ChildPath (((Get-Date).Ticks.ToString()) + '_errlog.xml')
  Write-Warning -Message $Message.Exception.Message
  Export-Clixml -Path $pathErrLog -InputObject $Message -Depth 3
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
function Add-SPSTask {
  param
  (
    [Parameter(Mandatory = $true)]
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
function Remove-SPSTask {
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
function Add-PSSharePoint {
  if ($null -eq (Get-PSSnapin | Where-Object -FilterScript { $_.Name -eq 'Microsoft.SharePoint.PowerShell' })) {
    Write-Output '--------------------------------------------------------------'
    Write-Output 'Loading SharePoint Powershell Snapin ...'
    Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction Stop | Out-Null
    Write-Output '--------------------------------------------------------------'
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
    Write-LogException -Message $_
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
    # Add Topology.svc in ArrayList Object
    [void]$tbSitesURL.Add('http://localhost:32843/Topology/topology.svc')
    return $tbSitesURL
  }
  catch {
    Write-LogException -Message $_
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
    $Jobs = @()
    $iss = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
    $Pool = [runspacefactory]::CreateRunspacePool(1, $throttleLimit, $iss, $Host)
    $Pool.Open()

    # Initialize WebSession from First SPWebApplication object
    $webApp = Get-SpWebApplication | Select-Object -first 1
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
      Write-LogException -Message $_
    }
  }
}
