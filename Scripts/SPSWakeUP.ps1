<#
.SYNOPSIS  
    WarmUP script for SharePoint 2010, 2013 & 2016
.DESCRIPTION  
	SPSWakeUp is a PowerShell script tool to warm up all site collection in your SharePoint environment.
	It's compatible with all supported versions for SharePoint (2007, 2010 and 2013).
	Use Internet Explorer to download JS, CSS and Pictures files, 
	Log script results in rtf file, 
	Email nofications, 
	Configure automatically prerequisites for a best warm-up, 
	Possibility to add or remove custom url
.PARAMETER InputFile
	Need parameter input file, example: 
	PS D:\> E:\SCRIPT\SPSWakeUP.ps1 "E:\SCRIPT\SPSWakeUP.xml"
.EXAMPLE
	SPSWakeUP.ps1 "E:\SCRIPT\SPSWakeUP.xml"
.NOTES  
	FileName:	SPSWarmUP.ps1
	Author:		Jean-Cyril DROUHIN
	Date:		October 14, 2016
	Version:	2.1.4
	Licence:	MS-PL
.LINK
	https://github.com/luigilink/spswakeup
#>	
param 
(
    [Parameter(Mandatory=$false)]
	[string]
	$InputFile,
	
    [Parameter(Mandatory=$false)]
	[switch]
	$Install
)
Clear-Host
$Host.UI.RawUI.WindowTitle = " -- WarmUP script -- $env:COMPUTERNAME --"
$spsWakeupVersion = "2.1.4"

# Logging PowerShell script in log file 
$logfolder = Split-Path -parent $MyInvocation.MyCommand.Definition
$logTime = Get-Date -Format yyyy-MM-dd_H-mm
$logFile = $logfolder+"\WarmUP_script_$logTime.log"
$currentuser = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name

#Get the content of the SPSWakeUP.xml file
if (!$InputFile)
{
	$InputFile = $logfolder+"\SPSWakeUP.xml"
}
if (Test-Path $InputFile)
{
	[xml]$xmlinput = (Get-Content $InputFile -ReadCount 0)
}

#Define Global Variable
New-variable -Name logFileContent -scope "Global" -force
New-variable -Name MailContent -scope "Global" -force
New-Variable -Name hostEntries -scope "Global" -Force
$logFileContent =  New-Object System.Collections.Generic.List[string]

# Define variable for HOSTS and Backup Hosts file with today's date
$hostEntries =  New-Object System.Collections.Generic.List[string]
$hostsFile = "$env:windir\System32\drivers\etc\HOSTS"
$hostsFileCopy = $hostsFile + '.' + (Get-Date -UFormat "%y%m%d%H%M%S").ToString() + '.copy'

# ====================================================================================
# INTERNAL FUNCTIONS
# ====================================================================================

#region logging and trap exception
# ===================================================================================
# Func: Write-LogException
# Desc: write Exception in powershell session and in error file
# ===================================================================================
Function Write-LogException
{
	param
	(
		[Parameter(Mandatory=$true)]
		$ErrLog
	)
	Add-LogContent "Yellow" "$($ErrLog.Exception.Message)" -noNewLine
	$pathErrLog = Join-Path -Path $logfolder -ChildPath (((Get-Date).Ticks.ToString())+"_errlog.xml")
	$ErrLog | Export-Clixml -Path $pathErrLog -Depth 3
    Add-LogContent "Yellow" " For more informations, see errlog.xml file:"
    Add-LogContent "Yellow" "$pathErrLog"
}
# ===================================================================================
# Func: Save-LogFile
# Desc: Save logFile in current folder
# ===================================================================================
Function Save-LogFile
{
	param 
	(
		[Parameter(Mandatory=$true)]
		[string]
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
# Func: Add-LogContent
# Desc: Add Content in log file
# ===================================================================================
Function Add-LogContent
{
	param
	(
		[Parameter(Mandatory=$true)]
		[string]
		$logColor,

		[Parameter(Mandatory=$true)]
		[string]
		$logText,

		[Parameter(Mandatory=$false)]
		[switch]
		$noNewLine
	)
	if ($noNewLine)
	{
		Write-Host -ForegroundColor $logColor "$logText" -NoNewline
	}
	else
	{
		Write-Host -ForegroundColor $logColor "$logText"
	}

	$logFileContent.Add($logText)
	$global:MailContent += $logText
}
# ===================================================================================
# Func: Send-SPSLog
# Desc: Send Email with log file in attachment
# ===================================================================================
Function Send-SPSLog
{
	param 
	(
		[Parameter(Mandatory=$true)]
		$MailAttachment,

		[Parameter(Mandatory=$true)]
		$MailBody
	)
	
	if ($xmlinput.Configuration.EmailNotification.Enable -eq $true)
	{
		$mailAddress = $xmlinput.Configuration.EmailNotification.EmailAddress
		$smtpServer = $xmlinput.Configuration.EmailNotification.SMTPServer
		$mailSubject = "Automated Script - WarmUp Urls - $env:COMPUTERNAME"

		Add-LogContent "White" "--------------------------------------------------------------"
		Add-LogContent "White" " - Sending Email with Log file to $mailAddress ..."
		try
		{
			Send-MailMessage -To $mailAddress -From $mailAddress -Subject $mailSubject -Body $MailBody -BodyAsHtml -SmtpServer $smtpServer -Attachments $MailAttachment -ea stop
			Add-LogContent "Green" " - Email sent successfully to $mailAddress"
		}
		catch 
		{
			Write-LogException -ErrLog "$_"
		}
	}
}
# ===================================================================================
# Func: Clear-SPSLog
# Desc: Clean Log Files
# ===================================================================================
Function Clear-SPSLog
{
	param 
	(
		[Parameter(Mandatory=$true)]
		[string]$path
	)
	
	if ($xmlinput.Configuration.Settings.CleanLogs.Enable -eq $true)
	{
		if (Test-Path $path)
		{
			# Days of logs that will be remaining after log cleanup. 
			$days = $xmlinput.Configuration.Settings.CleanLogs.Days
			
			# Get the current date
			$Now = Get-Date
			
			# Definie the extension of log files
			$Extension = "*.log"
			
			# Define LastWriteTime parameter based on $days
			$LastWrite = $Now.AddDays(-$days)
			
			# Get files based on lastwrite filter and specified folder
			$Files = Get-Childitem -Path "$path\*.*" -Include $Extension | Where {$_.LastWriteTime -le "$LastWrite"}
			
			if ($Files)
			{
				Add-LogContent "White" "--------------------------------------------------------------"
				Add-LogContent "White" " - Cleaning log files in $path ..."
				foreach ($File in $Files) 
				{
					if ($File -ne $NULL)
					{
						Add-LogContent "Yellow" " * Deleting File $File ..."
						Remove-Item $File.FullName | out-null
					}
					else
					{
						Add-LogContent "White" " - No more log files to delete "
						Add-LogContent "White" "--------------------------------------------------------------"
					}
				}
			}
		}
	}
	else
	{
		Add-LogContent "White" "--------------------------------------------------------------" 
		Add-LogContent "Yellow" " Clean of logs is disabled in XML input file. "
		Add-LogContent "White" "--------------------------------------------------------------"	
	}
}
#endregion

#region Installation in Task Scheduler
# ===================================================================================
# Func: Get-SPSUserPassword
# Desc: Get Password from Service Account
# ===================================================================================
Function Get-SPSUserPassword
{
	param 
	(
		[Parameter(Mandatory=$true)]
		[string]
		$user
	)
	[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
	$password = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the password of $user", "User Account Information", "")
	try
	{
		if (($password -ne "") -and ($user -ne ""))
		{
			$currentDomain = "LDAP://" + ([ADSI]"").distinguishedName
			Add-LogContent "White" " - Account `"$user`" ..." -noNewLine
			$dom = New-Object System.DirectoryServices.DirectoryEntry($currentDomain,$user,$password)
			if ($dom.Path -eq $null)
			{
				Write-Host -BackgroundColor Red -ForegroundColor Black "Invalid!"
			}
			else{Write-Host -ForegroundColor Black -BackgroundColor Green "Verified."}
		}
	}
	catch
	{
		Add-LogContent "Yellow" "An error occurred checking password for `"$user`""
		Write-LogException $_	
	}

	$password
}
# ===================================================================================
# Func: Add-SPSTask
# Desc: Add SPSWakeUP Task in Task Scheduler
# ===================================================================================
Function Add-SPSTask
{
	param 
	(
		[Parameter(Mandatory=$true)]
		[string]
		$Path
	)

	if (($xmlinput.Configuration.Install.Enable -eq "true") -OR ($Install))
	{        
		$TrigSubscription =
@"
<QueryList><Query Id="0" Path="System"><Select Path="System">*[System[Provider[@Name='Microsoft-Windows-IIS-IISReset'] and EventID=3201]]</Select></Query></QueryList>
"@
		$TaskDate = Get-Date -Format yyyy-MM-dd
		$TaskName = "SPSWakeUP"
		$Hostname = $Env:computername

		# Connect to the local TaskScheduler Service
		$TaskSvc = New-Object -ComObject ("Schedule.service")
		$TaskSvc.Connect($Hostname)
		$TaskFolder = $TaskSvc.GetFolder("\")
		$TaskSPSWKP = $TaskFolder.GetTasks(0) | Where {$_.Name -eq $TaskName}
		$TaskCmd = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
		$inputFileFullPath = (Get-Item $InputFile).FullName;
		$TaskCmdArg = 
@"
-Command Start-Process "$PSHOME\powershell.exe" -Verb RunAs -ArgumentList "'-ExecutionPolicy Bypass ""$path\SPSWakeUP.ps1 -inputFile $inputFileFullPath""'"
"@

		if ($TaskSPSWKP)
		{
			Add-LogContent "Yellow" "   * Shedule Task already exists - skipping."
		}
		else
		{
			Add-LogContent "White" "--------------------------------------------------------------"
			Add-LogContent "White" " - Adding SPSWakeUP script in Task Scheduler Service ..."

			# Get Credentials for Task Schedule
			$TaskAuthor = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name
			$TaskUser =  $xmlinput.Configuration.Install.ServiceAccount.UserName
			#$TaskUserPwd = Get-SPSUserPassword $TaskUser
			$TaskUserPwd = $xmlinput.Configuration.Install.ServiceAccount.Password

			# Add a New Task Schedule
			$TaskSchd = $TaskSvc.NewTask(0)
			$TaskSchd.RegistrationInfo.Description = "SPSWakeUp Task - Start at 6:00 daily"
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
			$TaskTrigger1.StartBoundary = $TaskDate + "T06:00:00"
			$TaskTrigger1.DaysInterval = 1
			if ($xmlinput.Configuration.Install.Repetition.Enable -eq $true)
			{
				$TaskTrigger1.Repetition.Duration = $xmlinput.Configuration.Install.Repetition.Duration
				$TaskTrigger1.Repetition.Interval = $xmlinput.Configuration.Install.Repetition.Interval
			}
			$TaskTrigger1.Enabled = $true

			# Add Trigger Type 8 At StartUp Delay 10M
			$TaskTrigger2 = $TaskTriggers.Create(8)
			$TaskTrigger2.Delay = "PT10M"
			$TaskTrigger2.Enabled = $true

			# Add Trigger Type 0 OnEvent IISReset
			$TaskTrigger3 = $TaskTriggers.Create(0)
			$TaskTrigger3.Delay = "PT20S"
			$TaskTrigger3.Subscription = $TrigSubscription
			$TaskTrigger3.Enabled = $true

			$TaskAction = $TaskSchd.Actions.Create(0)
			$TaskAction.Path = $TaskCmd
			$TaskAction.Arguments = $TaskCmdArg
			try
			{
				$TaskFolder.RegisterTaskDefinition( $TaskName, $TaskSchd, 6, $TaskUser , $TaskUserPwd , 1)
				Add-LogContent "Green" "   * Successfully added SPSWakeUP script in Task Scheduler Service"
			}
			catch
			{
				Add-LogContent "Yellow" "An error occurred adding Scheduled Task for `"$TaskUser`""
				Write-LogException $_			    
			}
		}
	}
}
#endregion

#region Load SharePoint Powershell Snapin for SharePoint 2010, 2013 & 2016
# ===================================================================================
# Name: 		Add-PSSharePoint
# Description:	Load SharePoint Powershell Snapin
# ===================================================================================
Function Add-PSSharePoint
{
	if ((Get-PsSnapin | Where {$_.Name -eq "Microsoft.SharePoint.PowerShell"})-eq $null)
	{
		Add-LogContent "White" "--------------------------------------------------------------"
		Add-LogContent "Cyan" " - Loading SharePoint Powershell Snapin..."
		Add-PsSnapin Microsoft.SharePoint.PowerShell -ErrorAction Stop | Out-Null
		Add-LogContent "White" "--------------------------------------------------------------"
	}
}
# ===================================================================================
# Name: 		Add-RASharePoint
# Description:	Load SharePoint Assembly for SharePoint 2007, 2010, 2013 & 2016
# ===================================================================================
Function Add-RASharePoint
{
	Add-LogContent "White" "--------------------------------------------------------------"
	Add-LogContent "Cyan" " - Loading Microsoft.SharePoint Assembly..."
	[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SharePoint") | Out-Null
	Add-LogContent "White" "--------------------------------------------------------------"
}
# ===================================================================================
# Name: 		Add-SystemWeb
# Description:	Load System.Web with Reflection Assembly
# ===================================================================================
Function Add-SystemWeb
{
	if ($xmlinput.Configuration.Settings.UseIEforWarmUp -eq $false)
	{
		Add-LogContent "White" "--------------------------------------------------------------"
		Add-LogContent "Cyan" " - Loading System.Web ..."
		[System.Reflection.Assembly]::LoadWithPartialName("system.web") | Out-Null
		Add-LogContent "White" "--------------------------------------------------------------"
	}
}
# ===================================================================================
# Name: 		Get-SPSThrottleLimit
# Description:	Get Number Of Throttle Limit
# ===================================================================================
Function Get-SPSThrottleLimit
{
	Begin
	{
		Add-LogContent "White" "--------------------------------------------------------------"
		Add-LogContent "White" " - Get Number Of Throttle Limit (from NumberOfLogicalProcessors)"
		[int]$NumThrottle = 8 
	}
	
	Process
	{
		# Get Number Of Throttle Limit 
		$NCpu = (Get-WmiObject Win32_Processor | measure -Property NumberOfLogicalProcessors -Sum).Sum
		if ($NCpu -le 2)
		{
			$NumThrottle = 2*$NCpu
		}
		elseif ($NCpu -ge 8)
		{
			$NumThrottle = 10
		}
		else 
		{
			$NumThrottle = 2*$NCpu
		}
		Add-LogContent "White" " * Number Of Throttle Limit will be $NumThrottle"
	}
	End
	{	
		$NumThrottle
	}
}
#endregion

#region get all site collections and all web applications
# ===================================================================================
# Name: 		Get-SPSVersion
# Description:	PowerShell script to display SharePoint products from the registry.
# ===================================================================================
Function Get-SPSVersion
{
    # location in registry to get info about installed software
    $regLoc = Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall

    # Get SharePoint Products and language packs
    $programs = $regLoc |  Where-Object -FilterScript {
        $_.PsPath -like "*\Office*" 
    } | ForEach-Object -Process { Get-ItemProperty $_.PsPath } 

    # output the info about Products and Language Packs
    $spsVersion = $programs | Where-Object -FilterScript {
        $_.DisplayName -like "*SharePoint Server*"
    }

    # Return SharePoint version
    $spsVersion.DisplayVersion
}
# ===================================================================================
# Name: 		Add-SPSSitesUrl
# Description:	Add Site Collection Url and FBA settings in PSObject
# ===================================================================================
Function Add-SPSSitesUrl
{
	param 
	(
		[Parameter(Mandatory=$true)]
		[string]
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
Function Add-SPSHostEntry
{
	param
	(
		[Parameter(Mandatory=$true)]
		$url
	)

    $url = $url -replace "https://",""
    $url = $url -replace "http://",""
    $hostNameEntry = $url.split('/')[0] 
    [void]$hostEntries.Add($hostNameEntry)
}
# ===================================================================================
# Name: 		Get-SPWebServicesUrl
# Description:	Get All Web Services *.svc used by SharePoint
# ===================================================================================
Function Get-SPWebServicesUrl
{
    if ($xmlinput.Configuration.Settings.WarmupWebSvc -eq $true)
	{
		# Import module WebAdministration
		Import-Module WebAdministration
				
		# Add SharePoint Web Services (.svc) in warmup	
		$iisSPWebServices = Get-ChildItem 'IIS:\Sites\SharePoint Web Services' -recurse | where {$_.Name -like "*svc"}
		if ($iisSPWebServices)
		{
			foreach ($iisSPWebService in $iisSPWebServices)
			{
				$iisSPWebServiceUrl = Get-WebURL $iisSPWebService.PSPath
						
				[void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $iisSPWebServiceUrl.ResponseUri.AbsoluteUri.ToString()))
			}
		}
		Add-LogContent "White" "   * SharePoint Web services included in WarmUp Urls"
	}
}
# ===================================================================================
# Name: 		Get-SPSSitesUrl
# Description:	Get All Site Collections Url
# ===================================================================================
Function Get-SPSSitesUrl
{
	Begin
	{
		Add-LogContent "White" "--------------------------------------------------------------"
		Add-LogContent "White" " - Get URLs of All Site Collection ... Please waiting"
		# Variable Declaration
		$tbSitesURL = New-Object System.Collections.ArrayList
		$defaultUrlZone = [Microsoft.SharePoint.Administration.SPUrlZone]::Default
		[bool]$fbaSParameter = $false
		[bool]$winParameter = $true
		$NumSites = 0
	}
	
	Process
	{
		try
		{
            $topologySvcUrl = "http://localhost:32843/Topology/topology.svc"
            [void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $topologySvcUrl))
            Add-LogContent "White" "   * SharePoint Web service Topology.svc included in WarmUp Urls"
			
			# Get url of CentralAdmin if include in input xml file
			if ($xmlinput.Configuration.Settings.IncludeCentralAdmin -eq $true)
			{
				$webAppADM = Get-SPWebApplication -IncludeCentralAdministration | Where-Object -FilterScript {
					$_.IsAdministrationWebApplication
				}
				$siteADM = $webAppADM.Url
				[void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $siteADM))
				[void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $siteADM"Lists/HealthReports/AllItems.aspx"))
				[void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $siteADM"_admin/FarmServers.aspx"))
				[void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $siteADM"_admin/Server.aspx"))
				[void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $siteADM"_admin/WebApplicationList.aspx"))
				[void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $siteADM"_admin/ServiceApplications.aspx"))
				Add-LogContent "White" "   * Central Administration included in WarmUp Urls"
			}
			else
			{
				Add-LogContent "White" "   * Central Administration excluded from WarmUp Urls"
			}
		
			# Get Url of all site collection
            #$WebSrv = [microsoft.sharepoint.administration.spwebservice]::ContentService
			$webApps = Get-SPWebApplication
		
			foreach ($webApp in $webApps)
			{
				$iisSettings = $webApp.GetIisSettingsWithFallback($defaultUrlZone)
				$getClaimProviderForms = $iisSettings.ClaimsAuthenticationProviders | Where-Object -FilterScript {
					$_.ClaimProviderName -eq "Forms"
				}
				$getClaimProviderWindows = $iisSettings.ClaimsAuthenticationProviders | Where-Object -FilterScript {
					$_.ClaimProviderName -eq "AD"
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
					if (($fbaSParameter -eq $true) -and ($winParameter -eq $true))
					{
						$siteUrl = $site.Url + "/_windows/default.aspx?ReturnUrl=/_layouts/15/Authenticate.aspx?Source=%2f"
					}
					else
					{
						$siteUrl = $site.Url
					}
					[void]$tbSitesURL.Add((Add-SPSSitesUrl -Url $siteUrl -FBA $fbaSParameter -Win $winParameter))
					$site.Dispose()
					$NumSites++
				}

			}
			Add-LogContent "White" "   * $NumSites site collection will be waking up ..."
		}
		catch
		{
			Add-LogContent "Yellow" "An error occurred getting all site collections"
			Write-LogException $_		
		}
	}
	
	End
	{
		$tbSitesURL
	}
}
# ===================================================================================
# Name: 		Get-SPSHSNCUrl
# Description:	Get All Host Named Site Collection Url
# ===================================================================================
Function Get-SPSHSNCUrl
{
	Add-LogContent "White" "--------------------------------------------------------------"
	Add-LogContent "White" " - Get URLs of All Host Named Site Collection ..."
	# Variable Declaration
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
		[void]$hsncURL.Add($HSNC.Url)
		Add-SPSHostEntry -Url $HSNC.Url
		$HSNC.Dispose()
	}

	$hsncURL
}
# ===================================================================================
# Name: 		Get-SPSWebAppUrl
# Description:	Get All Web Applications Url
# ===================================================================================
Function Get-SPSWebAppUrl
{
	Add-LogContent "White" "--------------------------------------------------------------"
	Add-LogContent "White" " - Get URLs of All Web Applications ..."
	$webAppURL = New-Object System.Collections.ArrayList
	
	#$WebSrv = [microsoft.sharepoint.administration.spwebservice]::ContentService
	$webApps = Get-SPWebApplication

	foreach ($webapp in $webApps)
	{
		[void]$webAppURL.Add($webapp.GetResponseUri("Default").AbsoluteUri)
		if (-not($webapp.GetResponseUri("Default").AbsoluteUri -match $env:COMPUTERNAME))
		{
			Add-SPSHostEntry -Url $webapp.GetResponseUri("Default").AbsoluteUri
		}
	}		

	$webAppURL
}
#endregion

#region Invoke webRequest and IEwebRequest
# ===================================================================================
# Name: 		Get-SPSWebRequest
# Description:	Request Url with System.Net.WebClient Object
# ===================================================================================
Function Get-SPSWebRequest
{
	param
	(
		[Parameter(Mandatory=$true)]
		[System.String]
		$Url
	)
	
	$TimeStart = Get-Date
	$WebRequestObject = [System.Net.HttpWebRequest] [System.Net.WebRequest]::Create($Url)
	$WebRequestObject.UseDefaultCredentials = $true
	$WebRequestObject.Method = "GET"
	$WebRequestObject.Accept = "text/html"
	$WebRequestObject.Timeout = 80000

	Add-LogContent "White" " - Web Request for url: $url"
	$global:MailContent += " - Web Request for url: $url"
	try
	{
		# Get the response of $WebRequestObject
		$ResponseObject = [System.Net.HttpWebResponse] $WebRequestObject.GetResponse()
		$TimeStop = Get-Date
		$TimeExec = ($TimeStop - $TimeStart).TotalSeconds
		'{0,-30} : {1,10:#,##0.00} s' -f '   WebSite successfully loaded in', $TimeExec
		#Add-LogContent "Green" "   * WebSite successfully loaded in $TimeExec s"
		$global:MailContent += "<br><font color=green>WebSite successfully loaded in $TimeExec s</font><br>"
	}
	catch [Net.WebException]
	{
		Write-LogException $_
	}
	finally 
	{
		# Issue 1451 - https://spswakeup.codeplex.com/workitem/1451
		# Thanks to Pupasini - Closing the HttpWebResponse object		
		if ($ResponseObject) 
		{
			$ResponseObject.Close()
			Remove-Variable ResponseObject
		}
	}

}
# ===================================================================================
# Name: 		Invoke-SPSWebRequest
# Description:	Multi-Threading Request Url with System.Net.WebClient Object
# ===================================================================================
Function Invoke-SPSWebRequest
{
	param
	(
		[Parameter(Mandatory=$true)]
		$Urls,

		[Parameter(Mandatory=$true)]
		$throttleLimit
	)
	
	# Get UserAgent from XML input file if no exist get UserAgent from current OS
	$userAgent = $xmlinput.Configuration.Settings.UserAgent
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
			Function Get-GenericWebRequest()
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
					$GenericWebRequest.Method = "GET"
					$GenericWebRequest.UserAgent = $useragent
					$GenericWebRequest.Accept = "text/html"
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
				$fedAuthCookie = $fedAuthwebresponse.Headers["Set-Cookie"];

				$httpwebrequest = Get-GenericWebRequest -URL $Url -AllowAutoRedirect $true;
				$httpwebrequest.Headers.Add("Cookie", "$fedAuthCookie");
			
				$ResponseObject = [System.Net.HttpWebResponse] $httpwebrequest.GetResponse()
				$TimeStop = Get-Date
				$TimeExec = ($TimeStop - $TimeStart).TotalSeconds
				$TimeExec = "{0:N2}" -f $TimeExec
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
			$Job = [powershell]::Create().AddScript($ScriptBlock).AddParameter("URL",$Url.Url).AddParameter("UserAgent",$userAgent)
			$Job.RunspacePool = $Pool
			$Jobs += New-Object PSObject -Property @{
				Url = $Url.Url
				Pipe = $Job
				Result = $Job.BeginInvoke()
			}
	   }

		Write-Host " - Please Wait.." -NoNewline

		While ($Jobs.Result.IsCompleted -contains $false)
		{
		   Write-Host "." -NoNewline
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
		Add-LogContent "Yellow" "An error occurred invoking multi-threading function"
		Write-LogException $_
	}
	
	Finally
	{
		$Pool.Dispose()
	}
	$Results
}
# ===================================================================================
# Name: 		Get-IEWebRequest
# Description:	Open Url in Internet Explorer Window
# ===================================================================================
Function Get-IEWebRequest
{
	param
	(
		[Parameter(Mandatory=$true)]$urls
	)
	# Run Internet Explorer
	$global:ie = New-Object -com "InternetExplorer.Application"
	$global:ie.Navigate("about:blank")
	$global:ie.visible = $true
	$global:ieproc = (Get-Process -Name iexplore) | Where-Object {$_.MainWindowHandle -eq $global:ie.HWND}
	
	foreach ($url in $urls)
	{
		Add-LogContent "White" " - Internet Explorer - Browsing $url"
		$global:MailContent += "- Browsing $url"
		$TimeOut = 90
		$Wait = 0
		try
		{
			$global:ie.Navigate($url)
			While ($ie.busy -like "True" -Or $Wait -gt $TimeOut)
			{
				Start-Sleep -s 1
				$Wait++
			}
			Add-LogContent "Green" "   * WebSite successfully loaded in $Wait s"
			$global:MailContent += "<br><font color=green>WebSite successfully loaded in $Wait s</font><br>"
		}
		catch
		{
			$pid = $global:ieproc.id
			Add-LogContent "Red" "  IE not responding.  Closing process ID $pid"
			$global:ie.Quit()
			$global:ieproc | Stop-Process -Force
			$global:ie = New-Object -com "InternetExplorer.Application"
			$global:ie.Navigate("about:blank")
			$global:ie.visible = $true
			$global:ieproc = (Get-Process -Name iexplore)| Where-Object {$_.MainWindowHandle -eq $global:ie.HWND}
		}
	}
	# Quit Internet Explorer
	if ($global:ie)
	{
		Add-LogContent "White" "--------------------------------------------------------------"
		Add-LogContent "White" " - Closing Internet Explorer ..."
		$global:ie.Quit()
	}
}
# ===================================================================================
# Name: 		Invoke-IEWebRequest
# Description:	Multi-Threading Request Url in Internet Explorer Window
# ===================================================================================
Function Invoke-IEWebRequest
{
	param
	(
		[Parameter(Mandatory=$true)]$Urls,
		[Parameter(Mandatory=$true)]$throttleLimit
	)
	
	$iss = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
	$Pool = [runspacefactory]::CreateRunspacePool(1, $throttleLimit, $iss, $Host)
	$Pool.Open()
		
	$ScriptBlock = 
	{
		$RunResult
	}

	$Jobs = @()

	$Urls | Where {
		
		$url = $_.Url
		
		# Run Internet Explorer
		$ie = New-Object -com "InternetExplorer.Application"
		$ie.Navigate("about:blank")
		$ie.visible = $true
		$ieproc = (Get-Process -Name iexplore)| Where {$_.MainWindowHandle -eq $ie.HWND}
		
		$TimeOut = 90
		$Wait = 0
		try
		{
			$ie.Navigate($url)
			While ($ie.busy -like "True" -Or $Wait -gt $TimeOut)
			{
				Start-Sleep -s 1
				$Wait++
			}
			$Response = "OK"
		}
		catch
		{
			$pid = $ieproc.id
			$Response = "IE not responding.  Closing process ID $pid"
			$ie.Quit()
			$ieproc | Stop-Process -Force
			$ie = New-Object -com "InternetExplorer.Application"
			$ie.Navigate("about:blank")
			$ie.visible = $true
			$ieproc = (Get-Process -Name iexplore)| where {$_.MainWindowHandle -eq $ie.HWND}
		}
		finally
		{
			$ie.Quit()
			#$ieproc | Stop-Process -Force 
		}

		$RunResult = New-Object PSObject
		$RunResult | Add-Member -MemberType NoteProperty -Name Url -Value $url
		$RunResult | Add-Member -MemberType NoteProperty -Name 'Time(s)' -Value $Wait
		$RunResult | Add-Member -MemberType NoteProperty -Name Status -Value $Response

	}

	Write-Host " - Please Wait.." -NoNewline

	While ($Jobs.Result.IsCompleted -contains $false)
	{
	   Write-Host "." -NoNewline
	   Start-Sleep -s 1
	} 

	$Results = @()
	foreach ($Job in $Jobs)
	{   
		$Results += $Job.Pipe.EndInvoke($Job.Result)
	}
 
	$Pool.Dispose()
	$Results
}
#endregion

#region Configuration and permission
# ===================================================================================
# Func: Disable-LoopbackCheck
# Desc: Disable Loopback Check
# ===================================================================================
Function Disable-LoopbackCheck
{
	param
	(
		[Parameter(Mandatory=$true)]$hostNameList
	)
	
	# Disable the Loopback Check on stand alone demo servers.
	# This setting usually kicks out a 401 error when you try to navigate to sites that resolve to a loopback address e.g.  127.0.0.1
	if ($xmlinput.Configuration.Settings.DisableLoopbackCheck -eq "true")
	{
		
		$lsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
		$lsaPathValue = Get-ItemProperty -path $lsaPath
		if (-not ($lsaPathValue.DisableLoopbackCheck -eq "1"))
		{
			Add-LogContent "White" " - Disabling Loopback Check..."
			New-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name "DisableLoopbackCheck" -value "1" -PropertyType dword -Force | Out-Null
		}
		else
		{
			Add-LogContent "White" " - Loopback Check already Disabled - skipping."
		}
	}
	ElseIf($xmlinput.Configuration.Settings.DisableLoopbackCheck -eq "secure")
	{
		$lsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
		$paramPath = "HKLM:System\CurrentControlSet\Services\LanmanServer\Parameters"
		$mvaPath = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"
		$lsaPathValue = Get-ItemProperty -path $lsaPath
		$paramPathValue = Get-ItemProperty -path $paramPath

		if ($lsaPathValue.DisableLoopbackCheck -eq "1")
		{
			Add-LogContent "White" " - Disabling Loopback Check - Back to default value ..."
			New-ItemProperty $lsaPath -Name "DisableLoopbackCheck" -value "0" -PropertyType dword -Force | Out-Null
		}

		if (-not($paramPathValue.DisableStrictNameChecking -eq "1"))
		{
			Add-LogContent "White" " - Disabling Strict Name Checking ..."
			New-ItemProperty $paramPath -Name "DisableStrictNameChecking" -value "1" -PropertyType dword -Force | Out-Null
		}

		$BackCoName = Get-ItemProperty -Path $mvaPath -Name BackConnectionHostNames -ea SilentlyContinue
		if (!($BackCoName))
		{
			New-ItemProperty $mvaPath -Name "BackConnectionHostNames" -PropertyType multistring -Force | Out-Null
		}
		foreach ($hostName in $hostNameList)
		{	
			if (!($BackCoName.BackConnectionHostNames -like "*$hostName*"))
			{
				Add-LogContent "White" " - Add $hostName in BackConnectionHostNames regedit key ..."
				$BackCoNameNew = $BackCoName.BackConnectionHostNames + "$hostName"
				New-ItemProperty $mvaPath -Name "BackConnectionHostNames" -Value $BackCoNameNew -PropertyType multistring -Force | Out-Null
			}
		}
	}
}
# ====================================================================================
# Func: Backup-HostsFile
# Desc: Backup HOSTS File System
# ====================================================================================
Function Backup-HostsFile
{
	Param
	(
		[Parameter(Mandatory=$true)]$hostsFilePath,
		[Parameter(Mandatory=$true)]$hostsBackupPath
	)
	
	if ($xmlinput.Configuration.Settings.AddURLsToHOSTS.Enable -eq "true")
	{
		Add-LogContent "White" "   * Backing up $hostsFilePath file to:"
		Add-LogContent "White" "   * $hostsBackupPath"
		Copy-Item $hostsFilePath -Destination $hostsBackupPath -Force
	}
}
# ====================================================================================
# Func: Restore-HostsFile
# Desc: Restore previous HOSTS File System
# ====================================================================================
Function Restore-HostsFile
{
	Param
	(
		[Parameter(Mandatory=$true)]$hostsFilePath,
		[Parameter(Mandatory=$true)]$hostsBackupPath
	)
	if ($xmlinput.Configuration.Settings.AddURLsToHOSTS.Enable -eq "true" -AND $xmlinput.Configuration.Settings.AddURLsToHOSTS.KeepOriginal -eq "true")
	{
		Add-LogContent "White" "   * Restoring $hostsBackupPath file to:"
		Add-LogContent "White" "   * $hostsFilePath"
		Copy-Item $hostsBackupPath -Destination $hostsFilePath -Force
	}
}
# ====================================================================================
# Func: Clear-HostsFileCopy
# Desc: Clear previous HOSTS File copy
# ====================================================================================
Function Clear-HostsFileCopy
{
	Param
	(
		[Parameter(Mandatory=$true)]$hostsFilePath
	)
	
	$hostsFolderPath = Split-Path $hostsFilePath
	if (Test-Path $hostsFolderPath)
	{
		# Number of files that will be remaining after backup cleanup. 
		$numberFiles = $xmlinput.Configuration.Settings.AddURLsToHOSTS.Retention	
		# Definie the extension of log files
		$extension = "*.copy"
		
		# Get files with .copy extension, sort them by name, from most recent to oldest and skip the first numberFiles variable
		$copyFiles = Get-Childitem -Path "$hostsFolderPath\*.*" -Include $extension | Sort-Object -Descending -Property Name | Select-Object -Skip $numberFiles
		
		if ($copyFiles)
		{
			Add-LogContent "White" "--------------------------------------------------------------"
			Add-LogContent "White" " - Cleaning backup HOSTS files in $hostsFolderPath ..."
			foreach ($copyFile in $copyFiles) 
			{
				if ($copyFile -ne $NULL)
				{
					Add-LogContent "Yellow" "   * Deleting File $copyFile ..."
					Remove-Item $copyFile.FullName | out-null
				}
				Else
				{
					Add-LogContent "White" " - No more backup HOSTS files to delete "
					Add-LogContent "White" "--------------------------------------------------------------"
				}
			}
		}
	}
}
# ====================================================================================
# Func: Add-HostsEntry
# Desc: This writes URLs to the server's local hosts file and points them to the server itself
# ====================================================================================
Function Add-HostsEntry
{
	param
	(
		[Parameter(Mandatory=$true)]$hostNameList
	)

	if ($xmlinput.Configuration.Settings.AddURLsToHOSTS.Enable -eq "true" -and $hostNameList)
	{
		$hostsContentFile =  New-Object System.Collections.Generic.List[string]
		# Check if the IPv4Address configured in XML Input file is reachable
		$hostIPV4Addr = $xmlinput.Configuration.Settings.AddURLsToHOSTS.IPv4Address
		Add-LogContent "White" "   * Testing connection (via Ping) to `"$hostIPV4Addr`"..."
		$canConnect = Test-Connection $hostIPV4Addr -Count 1 -Quiet
		if ($canConnect) {Add-LogContent "White" "   * IPv4Address $hostIPV4Addr will be used in HOSTS File during WarmUP ..."}
		if (!$canConnect)
		{
			Add-LogContent "Yellow" "   * IPv4Address not valid in Input XML File, 127.0.0.1 will be used in HOSTS File"
			$hostIPV4Addr = "127.0.0.1"
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

		if ($xmlinput.Configuration.Settings.AddURLsToHOSTS.ListRevocationUrl -eq "true"){$hostsContentFile.Add("127.0.0.1 `t crl.microsoft.com")}		
		ForEach ($hostname in $hostNameList)
		{
			# Remove http or https information to keep only HostName or FQDN		
			if ($hostname.Contains(":"))
			{
				Add-LogContent "White" "   * $hostname cannot be added in HOSTS File, only web applications with 80 or 443 port are added."
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
Function Add-SPSUserPolicy
{
	param
	(	
		[Parameter(Mandatory=$true)]$urls
		
	)
	$userName = $xmlinput.Configuration.Install.ServiceAccount.Username
	Add-LogContent "White" "--------------------------------------------------------------"
	Add-LogContent "White" " - Add Read Access to $user for All Web Applications ..."
	foreach ($url in $urls)
	{
		try
		{
			$webapp = [Microsoft.SharePoint.Administration.SPWebApplication]::Lookup("$url")
			#$user = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name
			
			$displayName = "WarmUp Account"
			
			# If the web app is not Central Administration 
			if ($webapp.IsAdministrationWebApplication -eq $false)
			{
				# If the web app is using Claims auth, change the user accounts to the proper syntax
				if ($webapp.UseClaimsAuthentication -eq $true)
				{
					#$user = 'i:0#.w|'+$userName
					$user = (New-SPClaimsPrincipal -identity $userName -identitytype 1).ToEncodedString()  
				}
				else{$user = $userName}
				Add-LogContent "White" " - Applying Read access for $user account to $url..."
				[Microsoft.SharePoint.Administration.SPPolicyCollection]$policies = $webapp.Policies
				$PolicyExist = $policies | where {$_.Displayname -eq "WarmUp Account"}
				
				if ($PolicyExist)
				{
					Add-LogContent "Yellow" "   * Read access for WarmUp Account already exists - skipping."
				}
				else
				{
					[Microsoft.SharePoint.Administration.SPPolicy]$policy = $policies.Add($user, $displayName)
					$policyRole = $webApp.PolicyRoles.GetSpecialRole([Microsoft.SharePoint.Administration.SPPolicyRoleType]::FullRead)
					if ($policyRole -ne $null)
					{
						$policy.PolicyRoleBindings.Add($policyRole)
					}
					$webapp.Update()
					Add-LogContent "White" "   * Done Applying Read access for `"$user`" account to `"$url`""
				}
			}
		}
		catch
		{
			Add-LogContent "Yellow" "An error occurred applying Read access for `"$user`" account to `"$url`""
			Write-LogException $_
		}
	}
}
#endregion

#region Internet Explorer Configuration
# ===================================================================================
# Name: 		Add-IETrustedSite
# Description:	Add Url in Security Option - Intranet Zone
# ===================================================================================
Function Add-IETrustedSite
{
	param
	(
		[Parameter(Mandatory=$true)]$urls
	)

	Add-LogContent "White" "--------------------------------------------------------------"
	Add-LogContent "White" " - Add URLs of All Web Applications in Internet Settings/Security ..."
	foreach ($url in $urls)
	{
		# Remove http or https information to keep only HostName or FQDN
		$url = $url -replace "https://",""
		$url = $url -replace "http://",""
		$urlDomain = $url -replace "/",""

		if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$urlDomain"))
		{
			Add-LogContent "White" " - Adding *.$urlDomain to local Intranet security zone..."
			New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains" -Name $urlDomain -ItemType Leaf -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$urlDomain" -Name '*' -value "1" -PropertyType dword -Force | Out-Null
		}
		else
		{
			Add-LogContent "White" " - $urlDomain already added to local Intranet security zone - skipping."
		}

		if (-not (Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\$urlDomain"))
		{
			Add-LogContent "White" " - Adding *.$urlDomain to local Intranet security zone (IE ESC) ..."
			New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains" -Name $urlDomain -ItemType Leaf -Force | Out-Null
			New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\$urlDomain" -Name '*' -value "1" -PropertyType dword -Force | Out-Null
		}
		else
		{
			Add-LogContent "White" " - $urlDomain already added to local Intranet security zone (IE ESC) - skipping."
		}
	}
}
# ===================================================================================
# Name: 		Clear-IECache
# Description:	Clear Internet Explorer's cache
# ===================================================================================
Function Clear-IECache
{
	$RunDll32 = "$env:windir\System32\rundll32.exe"
	if (Test-Path -Path $RunDll32)
	{
		try
		{
			Add-LogContent "White" " - Cleaning Cache IE with runDll32.exe ..."
			Start-Process -FilePath $RunDll32 -ArgumentList "InetCpl.cpl,ClearMyTracksByProcess 8" -NoNewWindow -Wait -ErrorAction Stop
		}
		catch
		{
			Write-Warning "An error occurred attempting to clear internet explorer temporary files."
		}
	}
	else
	{
		Add-LogContent "White" " - Clear Cache IE - The rundll32 is not present in $env:windir\System32 folder"
	}
}
# ===================================================================================
# Name: 		Disable-IEESC
# Description:	Disable Internet Explorer Enhanced Security Configuration for administrators
# ===================================================================================
Function Disable-IEESC
{
	if ($xmlinput.Configuration.Settings.DisableIEESC -eq $true)
	{
		Add-LogContent "White" "--------------------------------------------------------------"
		try
		{			
			$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
			$AdminKeyValue = Get-ItemProperty -Path $AdminKey
			if (-not ($AdminKeyValue.IsInstalled -eq "0"))
			{
				Add-LogContent "White" " - Disabling Internet Explorer Enhanced Security Configuration ..."
				Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
			}
			else
			{
				Add-LogContent "White" " - Internet Explorer ESC already Disabled - skipping."
			}
		}
		catch 
		{
			Add-LogContent "Yellow" "Failed to Disable Internet Explorer Enhanced Security Configuration"
		}
	}
}

# ===================================================================================
# Func: Disable-IEFirstRun
# Desc: Disable First Run for Internet Explorer
# ===================================================================================
Function Disable-IEFirstRun
{
	Add-LogContent "White" "--------------------------------------------------------------"
	$lsaPath = "HKCU:\Software\Microsoft\Internet Explorer\Main"
	$lsaPathValue = Get-ItemProperty -path $lsaPath
	if (-not ($lsaPathValue.DisableFirstRunCustomize -eq "1"))
	{
		Add-LogContent "White" " - Disabling Internet Explorer First Run ..."
		New-ItemProperty "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -value "1" -PropertyType dword -Force | Out-Null
	}
	else
	{
		Add-LogContent "White" " - Internet Explorer First Run already Disabled - skipping."
	}
}
#endregion

#region Main
# ===================================================================================
#
# WarmUp Script - MAIN Region
#
# ===================================================================================
$DateStarted = Get-date
$psVersion = ($host).Version.ToString()
$spsVersion = Get-SPSVersion
if ($PSVersionTable.PSVersion -gt [Version]"2.0" -and $spsVersion -lt 15)
{
  powershell -Version 2 -File $MyInvocation.MyCommand.Definition
  exit
}

Add-LogContent "Green" "-------------------------------------"
Add-LogContent "Green" "| Automated Script - SPSWakeUp v$spsWakeupVersion |"
Add-LogContent "Green" "| Started on : $DateStarted by $currentuser|"
Add-LogContent "Green" "| PowerShell Version: $psVersion |"
Add-LogContent "Green" "| SharePoint Version: $spsVersion |"
Add-LogContent "Green" "-------------------------------------"
$global:MailContent = "Automated Script - WarmUp Urls - Started on: $DateStarted <br>"
$global:MailContent += "SharePoint Server : $env:COMPUTERNAME<br>"

# Check Permission Level
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
	Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
	Break
} 
else 
{
	# Add SPSWakeup script in a new scheduled Task
	Add-SPSTask -Path $logfolder

	# Load SharePoint Powershell Snapin, Assembly and System.Web
	Add-RASharePoint
	Add-PSSharePoint
	Add-SystemWeb

	# Get Number Of Throttle Limit 
	[int]$NumThrottle = Get-SPSThrottleLimit

	# Get All Web Applications Urls, Host Named Site Collection and Site Collections
	$getSPWebApps = Get-SPSWebAppUrl
	$getSPSiteColN = Get-SPSHSNCUrl
	$getSPSites = Get-SPSSitesUrl

	if ($null -ne $getSPWebApps -and $null -ne $getSPSites)
	{
		if ($hostEntries)
        {
            # Disable LoopBack Check
		    Add-LogContent "White" "--------------------------------------------------------------"
		    Add-LogContent "White" " - Add Urls of All Web Applications or HSNC in BackConnectionHostNames regedit key ..."
		    Disable-LoopbackCheck -hostNameList $hostEntries

	        # Make backup copy of the Hosts file with today's date Add Web Application and Host Named Site Collection Urls in HOSTS system File
	        Add-LogContent "White" "--------------------------------------------------------------"
	        Add-LogContent "White" " - Add Urls of All Web Applications or HSNC in HOSTS File ..."
	        Backup-HostsFile -hostsFilePath $hostsFile -hostsBackupPath $hostsFileCopy
            Add-HostsEntry -hostNameList $hostEntries
		}

		# Add read access for Warmup User account in User Policies settings
		Add-SPSUserPolicy -urls $getSPWebApps
		
		if ($xmlinput.Configuration.Settings.UseIEforWarmUp -eq $true)
		{
			# Disable Internet Explorer Enhanced Security Configuration and First Run
			Disable-IEESC
			Disable-IEFirstRun
			
			# Add Web Application Url in Intranet Security Options for Internet Explorer
			Add-IETrustedSite $getSPWebApps
			if ($null -ne $getSPSiteColN)
			{
				Add-IETrustedSite $getSPSiteColN
			}			

			# Remove Internet Explorer Temporary Files with RunDll32.exe
			Clear-IECache
			
			# Request Url with Internet Explorer for All Site Collections Urls
			Add-LogContent "White" "--------------------------------------------------------------"
			Add-LogContent "White" " - Opening All sites Urls with Internet Explorer ..."
			$global:MailContent += "<br>Opening All sites Urls with Internet Explorer ... <br>"
			$InvokeResults = Invoke-IEWebRequest -Urls $getSPSites -throttleLimit $NumThrottle
		}
		else
		{
			# Request Url with System.Net.WebClient Object for All Site Collections Urls
			Add-LogContent "White" "--------------------------------------------------------------"
			Add-LogContent "White" " - UseIEforWarmUp is set to False - Opening All sites Urls with Web Request ..."
			$global:MailContent += "<br>Opening All sites Urls with Web Request Object, see log files for more details<br>"
			$InvokeResults = Invoke-SPSWebRequest -Urls $getSPSites -throttleLimit $NumThrottle
		}
		# Show the results
        Add-LogContent "White" "WarmUP Results:"
		foreach ($InvokeResult in $InvokeResults)
		{
			$resultUrl = $InvokeResult.Url
			$resultTime = $InvokeResult.'Time(s)'
			$resultStatus = $InvokeResult.Status
			Add-LogContent "White" " -----------------------------------"
			Add-LogContent "White" " | Url    : $resultUrl"
			Add-LogContent "White" " | Time   : $resultTime seconds"
            if ($resultStatus -match "200")
            {
                Add-LogContent "White" " | Status : " -noNewLine
                Add-LogContent "Green" "$resultStatus"
            }
			else
            {
                Add-LogContent "White" " | Status : $resultStatus"
            }
		}
	}
	
	# Clean the folder of log files 
	Clear-SPSLog -path $logfolder
	
	$DateEnded = Get-date
	Add-LogContent "Green" "-----------------------------------"
	Add-LogContent "Green" "| Automated Script - SPSWakeUp |"
	Add-LogContent "Green" "| Started on : $DateStarted |"
	Add-LogContent "Green" "| Completed on : $DateEnded |"
	Add-LogContent "Green" "-----------------------------------"
	$global:MailContent += "<br>"
	$global:MailContent += "Automated Script - WarmUp Urls - Completed on: $DateEnded"

	Trap {Continue}
	
	# Restore backup copy of the Hosts file with today's date
	Restore-HostsFile -hostsFilePath $hostsFile -hostsBackupPath $hostsFileCopy
	
	# Clean the copy files of system HOSTS folder
	Clear-HostsFileCopy -hostsFilePath $hostsFile
	
	Save-LogFile $logFile
	
	# Send Email with log file in attachment - For settings see XML input file
	Send-SPSLog -MailAttachment $logFile -MailBody $global:MailContent
	
	Exit
}
#endregion