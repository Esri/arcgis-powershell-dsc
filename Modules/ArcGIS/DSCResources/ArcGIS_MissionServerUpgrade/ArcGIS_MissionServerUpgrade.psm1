$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

<#
    .SYNOPSIS
        Resource to aid post upgrade completion workflows. This resource upgrades the Mission Server Site once Server Installer has completed the upgrade.
    .PARAMETER ServerHostName
        HostName of the Machine that is being Upgraded
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
		$ServerHostName
	)
    
    $returnValue = @{
		ServerHostName = $ServerHostName
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
        [System.String]
        $Version

	)
    
    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    Write-Verbose "Fully Qualified Domain Name :- $FQDN"

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	Write-Verbose "Waiting for Mission Server 'https://$($FQDN):20443/arcgis/admin'"
    Wait-ForUrl "https://$($FQDN):20443/arcgis/admin" -HttpMethod 'GET'

    $Referer = "http://localhost"
    $ServerSiteURL = "https://$($FQDN):20443"
    [string]$ServerUpgradeUrl = $ServerSiteURL.TrimEnd('/') + "/arcgis/admin/upgrade"
    $ResponseStatus = Invoke-ArcGISWebRequest -Url $ServerUpgradeUrl -HttpFormParameters @{f = 'json'} -Referer $Referer -Verbose -HttpMethod 'GET'
    if($ResponseStatus.isUpgrade -ieq $true ){
        Write-Verbose "Making request to $ServerUpgradeUrl to Upgrade the site"
        $Response = Invoke-ArcGISWebRequest -Url $ServerUpgradeUrl -HttpFormParameters @{ f = 'json' } -Referer $Referer -Verbose
        if($Response.status -ieq "success"){
            Write-Verbose 'Mission Server Upgrade Successful'
        }else{
            throw "An Error occurred. Request Response - $Response"
        }
    }else{
        Write-Verbose 'Mission Server is already upgraded'
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
        [System.String]
        $Version
    )
    
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null

    $result = Test-Install -Name "MissionServer" -Version $Version
    
    if($result) {
        $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
        $Referer = "http://localhost"
        $ServerUpgradeUrl = "https://$($FQDN):20443/arcgis/admin/upgrade"
        $ResponseStatus = Invoke-ArcGISWebRequest -Url $ServerUpgradeUrl -HttpFormParameters @{f = 'json'} -Referer $Referer -Verbose -HttpMethod 'GET'
        if($ResponseStatus.isUpgrade -ieq $true ){
            $result = $false
        }else{
            $result = $true
        }
    }else{
        throw "ArcGIS Mission Server not upgraded to required Version"
    }
    
    $result   
}

Export-ModuleMember -Function *-TargetResource
