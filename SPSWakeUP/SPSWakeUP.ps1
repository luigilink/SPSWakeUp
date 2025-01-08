<#
    .SYNOPSIS
    SPSWakeUP script for SharePoint OnPremises

    .DESCRIPTION
    SPSWakeUp is a PowerShell script tool to warm up all site collection in your SharePoint environment.
    It's compatible with all supported versions for SharePoint (2016 to Subscription Edition).
    Use WebRequest object in multi-thread to download JS, CSS and Pictures files,
    Log script results in log file,
    Configure automatically prerequisites for a best warm-up,

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
# Clear the host console
Clear-Host

# Set the window title
$Host.UI.RawUI.WindowTitle = "SPSWakeUP script running on $env:COMPUTERNAME"

# Define the path to the helper module
$scriptRootPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$script:HelperModulePath = Join-Path -Path $scriptRootPath -ChildPath 'Modules'

# Import the helper module
Import-Module -Name (Join-Path -Path $script:HelperModulePath -ChildPath 'SPSWakeUP.Util.psm1') -Force -DisableNameChecking

# Start Transcript parameter is equal to True
if ($Transcript) {
    $pathLogFile = Join-Path -Path $scriptRootPath -ChildPath ('SPSWakeUP_script_' + (Get-Date -Format yyyy-MM-dd_H-mm) + '.log')
    # Clean the folder of log files
    Clear-SPSLog -path $scriptRootPath
    # Start Transcript with the log file
    Start-Transcript -Path $pathLogFile -IncludeInvocationHeader
}

switch ($Action) {
    'Uninstall' {
        # Remove SPSWakeup script from scheduled Task
        Remove-SPSSheduledTask -TaskName 'SPSWakeUP'
    }
    'Install' {
        if ($null -eq $InstallAccount) {
            Write-Warning -Message ('SPSWakeUp: Install parameter is set. Please set also InstallAccount ' + `
                    "parameter. `nSee https://spwakeup.com for details.")
            Break
        }
        else {
            # Initialize variables
            $scriptFullPath = Join-Path -Path $scriptRootPath -ChildPath 'SPSWakeUP.ps1'
            # Add SPSWakeup script in a new scheduled Task
            Install-SPSWakeUP -Path $scriptFullPath -InstallAccount $InstallAccount
        }
    }
    'AdminSitesOnly' {
        # Invoke-WebRequest on Central Admin if Action parameter equal to AdminSitesOnly
        Invoke-SPSAdminSites
    }
    Default {
        # Invoke-WebRequest on Central Admin if Action parameter equal to Default
        Invoke-SPSAdminSites

        # Invoke-WebRequest on All Web Applications Urls, Host Named Site Collection and Site Collections
        Invoke-SPSAllSites
    }
}

# Stop Transcript parameter is equal to True
if ($Transcript) {
    Stop-Transcript
}
Exit
#endregion
