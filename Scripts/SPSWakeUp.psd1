<#
    .DESCRIPTION  
    SPSWakeUP Configuration file for SharePoint 2010, 2013 & 2016

    .NOTES  
    FileName:	SPSWakeUP.psd1
    Author:		luigilink (Jean-Cyril DROUHIN)
    Date:		March 07, 2018
    Version:	2.2.0
    Licence:	MIT License
    
    .LINK
    https://spwakeup.com/
    https://github.com/luigilink/spswakeup
#>
@{
    Settings =
    @{
		#Disables network loopback checks. This prevents the OS blocking access to your server under names other than its actual host name
		#Set to $false for BackConnectionHostNames or $true for standard DisableLoopbackCheck (less secure)
		DisableLoopbackCheck = $true
		#Add URL of Web Application in HOSTS system file, you can keep the original file and configure retention file backup (number of files)
        AddURLsToHOSTS =
        @{
            Enable              = $true 
            IPv4Address         = '127.0.0.1' 
            KeepOriginal        = $false 
            Retention           = '10' 
            ListRevocationUrl   = $true
        } 
		#Include Central Administration Url in WarmUp
		IncludeCentralAdmin     = $true
        #Number of Days for keeping Logs Files
        CleanLogsDays           = 30
        #This EmailNotification section configure settings for mail notifications
        EmailNotification =
        @{
            Enable          = $false
            SMTPServer      = 'smtp.contoso.com'
            EmailAddress    = 'ADM-SharePoint@contoso.com'
        }
    }
}
