## Readable values for enumerations http://blogs.technet.com/b/jamesone/archive/2009/01/27/managing-windows-update-with-powershell.aspx
<#
	$AutoUpdateNotificationLevels= @{0="Not configured"; 1="Disabled" ; 2="Notify before download"; 
                                 3="Notify before installation"; 4="Scheduled installation"}

	$AutoUpdateDays=@{0="Every Day"; 1="Every Sunday"; 2="Every Monday"; 3="Every Tuesday"; 4="Every Wednesday";
                  5="Every Thursday"; 6="Every Friday"; 7="EverySaturday"}
#>

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	Param
	(
		[parameter(Mandatory = $true)]		
		[System.Boolean]
		$Enabled
	)

    (New-Object -com "Microsoft.Update.AutoUpdate").Settings
}

function Set-TargetResource
{
	[CmdletBinding()]
	Param
	(
		[parameter(Mandatory = $true)]		
		[System.Boolean]
		$Enabled
	)
    
	$Settings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
	Write-Verbose "Current Windows Update Settings:- $Settings"
    if($Enabled)
    {
        if($Settings.NotificationLevel -ne 4)
		{
			Write-Verbose "Setting Update to 'Scheduled Update'"
			$Settings.NotificationLevel = 4
			$Settings.Save
		}
    }
    else
    {
	    if($Settings.NotificationLevel -ne 0)
		{
			Write-Verbose "Setting Update to 'Not configured'"
			$Settings.NotificationLevel = 0
			$Settings.Save
		}
    }
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]		
		[System.Boolean]
		$Enabled
	)

	$Settings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
	Write-Verbose "Windows Update Settings:- $($Settings.NotificationLevel)"
	if($Enabled)
    {
        $Settings.NotificationLevel -eq 4
    }
    else
    {
	    $Settings.NotificationLevel -ne 4
    }
}

Export-ModuleMember -Function *-TargetResource


