$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

<#
    .SYNOPSIS
        Resource to aid post upgrade completion workflows. This resource upgrades the Video Server Site once Server Installer has completed the upgrade.
    .PARAMETER Ensure
        Take the values Present or Absent. 
        - "Present" ensure Upgrade the Server Site once Video Server Installer is completed
        - "Absent" - (Not Implemented).
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
		[ValidateSet("Present","Absent")]
		[System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [System.String]
        $ServerHostName,
    
        [parameter(Mandatory = $true)]
        [System.String]
        $Version

	)
    
    #$MachineFQDN = Get-FQDN $env:COMPUTERNAME    
    Write-Verbose "Fully Qualified Domain Name :- $ServerHostName"

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	Write-Verbose "Waiting for Video Server 'https://$($ServerHostName):21443/arcgis/admin'"
    Wait-ForUrl "https://$($ServerHostName):21443/arcgis/admin" -HttpMethod 'GET'

    if($Ensure -ieq 'Present') {        
        $Referer = "http://localhost"
        $ServerSiteURL = "https://$($ServerHostName):21443"
        [string]$ServerUpgradeUrl = $ServerSiteURL.TrimEnd('/') + "/arcgis/admin/upgrade"
        $ResponseStatus = Invoke-ArcGISWebRequest -Url $ServerUpgradeUrl -HttpFormParameters @{f = 'json'} -Referer $Referer -Verbose -HttpMethod 'GET'
        if($ResponseStatus.isUpgrade -ieq $true ){
            Write-Verbose "Making request to $ServerUpgradeUrl to Upgrade the site"
            $Response = Invoke-ArcGISWebRequest -Url $ServerUpgradeUrl -HttpFormParameters @{ f = 'json' } -Referer $Referer -Verbose
            if($Response.status -ieq "success"){
                Write-Verbose 'Video Server Upgrade Successful'
            }else{
                throw "An Error occurred. Request Response - $Response"
            }
        }else{
            Write-Verbose 'Video Server is already upgraded'
        }
    }
    elseif($Ensure -ieq 'Absent') {
       Write-Verbose "Do Nothing"
    }
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[ValidateSet("Present","Absent")]
		[System.String]
        $Ensure,
        
        [parameter(Mandatory = $true)]
        [System.String]
        $ServerHostName,

        [parameter(Mandatory = $true)]
        [System.String]
        $Version
    )
    
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null

    $result = Test-Install -Name "VideoServer" -Version $Version
    
    $Referer = "http://localhost"
    $ServerUpgradeUrl = "https://$($ServerHostName):21443/arcgis/admin/upgrade"
    $ResponseStatus = Invoke-ArcGISWebRequest -Url $ServerUpgradeUrl -HttpFormParameters @{f = 'json'} -Referer $Referer -Verbose -HttpMethod 'GET'
    
    if($result) {
        if($ResponseStatus.isUpgrade -ieq $true ){
            $result = $false
        }else{
            $result = $true
        }
    }else{
        throw "ArcGIS Video Server not upgraded to required Version"
    }
    
    if($Ensure -ieq 'Present') {
	       $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}

Export-ModuleMember -Function *-TargetResource
