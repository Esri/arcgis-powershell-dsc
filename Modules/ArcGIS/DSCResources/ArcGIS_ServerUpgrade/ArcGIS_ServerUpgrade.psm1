$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.Server.psm1'))

<#
    .SYNOPSIS
        Resource to aid post upgrade completion workflows. This resource upgrades the server site once server installer has completed the upgrade.
    .PARAMETER ServerHostName
        HostName of the machine that is being Upgraded
    .PARAMETER ServerType
        Server type
    .PARAMETER Version
        Version to which the Server is being upgraded to
#>

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$ServerHostName,

        [parameter(Mandatory = $true)]
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer","DataPipelinesServer","VelocityServer")]
        [System.String]
        $ServerType
	)
    
    $returnValue = @{
		ServerHostName = $ServerHostName
        ServerType = $ServerType
	}

	$returnValue
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
        [System.String]
        $ServerHostName,

        [parameter(Mandatory = $true)]
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer","DataPipelinesServer","VelocityServer")]
        [System.String]
        $ServerType,
    
        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $EnableUpgradeSiteDebug = $False

	)
    
    $result = Test-Install -Name $ServerType -Version $Version
    if(-not($result)) {
        throw "ArcGIS Server not upgraded to required Version $Version"
    }

    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    $Referer = "https://localhost"
    $ServerBaseURL = Get-ArcGISComponentBaseUrl -ComponentName $ServerType -FQDN $FQDN
    Write-Verbose "Server Type:- $ServerType , Fully Qualified Domain Name :- $FQDN"
    Write-Verbose "Waiting for Server '$($ServerBaseURL)'"
    if($ServerType -ieq "Server"){
        Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName "ServerAdmin" -Verbose
        Invoke-GISServerUpgrade -URL $ServerBaseURL -EnableUpgradeSiteDebug $EnableUpgradeSiteDebug -Version $Version -Referer $Referer -Verbose
    }else{
        Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName $ServerType -Verbose
        Invoke-ServerUpgrade -URL $ServerBaseURL -Referer $Referer -Verbose
    }
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
        [System.String]
        $ServerHostName,

        [parameter(Mandatory = $true)]
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer","DataPipelinesServer","VelocityServer")]
        [System.String]
        $ServerType,

        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $EnableUpgradeSiteDebug = $False
    )
    
    $result = Test-Install -Name $ServerType -Version $Version
    if(-not($result)) {
        throw "ArcGIS Server not upgraded to required Version $Version"
    }

    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    $Referer = "https://localhost"
    $ServerBaseURL = Get-ArcGISComponentBaseUrl -ComponentName $ServerType -FQDN $FQDN
    if($ServerType -ieq "Server"){
        Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName "ServerAdmin" -MaxWaitTimeInSeconds 300 -SleepTimeInSeconds 15 -Verbose
        $result = Test-GISServerUpgrade -URL $ServerBaseURL -Referer $Referer -Version $Version -Verbose
    }else{
        Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName $ServerType -MaxWaitTimeInSeconds 300 -SleepTimeInSeconds 15 -Verbose
        $result = Test-ServerUpgrade -URL $ServerBaseURL -Referer $Referer -Verbose
    }
    
    $result
}

Export-ModuleMember -Function *-TargetResource
