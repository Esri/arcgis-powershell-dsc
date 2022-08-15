$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
        $PortalEndPoint,
            
		[System.Management.Automation.PSCredential]
        $PortalAdministrator,
        
        [parameter(Mandatory = $true)]
        [System.String]
        $StandbyMachine,

        [parameter(Mandatory = $true)]
        [System.String]
        $Version
	)

    $null
}

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
	param
	(
        [parameter(Mandatory = $true)]
		[System.String]
        $PortalEndPoint,
            
		[System.Management.Automation.PSCredential]
        $PortalAdministrator,
        
        [parameter(Mandatory = $true)]
        [System.String]
        $StandbyMachine,

        [parameter(Mandatory = $true)]
        [System.String]
        $Version
    )
    
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    
	$result = $false

	$result = Test-Install -Name "Portal" -Version $Version
    
    if(-not($result)){
		$Referer = 'http://localhost'
		$token = Get-PortalToken -PortalHostName $PortalEndPoint -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
    
		$Machines = Invoke-ArcGISWebRequest -Url ("https://$($PortalEndPoint):7443/arcgis/portaladmin/machines") -HttpFormParameters @{ f = 'json'; token = $token.token; } -Referer $Referer -HttpMethod 'GET'
		$StandbyFlag = $false
		$StandbyMachineHostName = Get-FQDN $StandbyMachine
		ForEach($m in $Machines.machines){
			if($StandbyMachineHostName -ieq $m.machineName){
				$StandbyFlag = $true
				break;
			}
		}

		$result = -not($StandbyFlag)
	}

	$result
	
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
        [parameter(Mandatory = $true)]
		[System.String]
        $PortalEndPoint,
            
		[System.Management.Automation.PSCredential]
        $PortalAdministrator,
        
        [parameter(Mandatory = $true)]
        [System.String]
        $StandbyMachine,

        [parameter(Mandatory = $true)]
        [System.String]
        $Version
	)


    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null

    $Referer = 'http://localhost'
    $token = Get-PortalToken -PortalHostName $PortalEndPoint -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
        
    Write-Verbose "Unregistering $StandbyMachine Portal"
    $StandbyMachineHostName = Get-FQDN $StandbyMachine
    $StandbyMachineName = ""
    $Machines = Invoke-ArcGISWebRequest -Url ("https://$($PortalEndPoint):7443/arcgis/portaladmin/machines") -HttpFormParameters @{ f = 'json'; token = $token.token; } -Referer $Referer -HttpMethod 'GET'
    ForEach($m in $Machines.machines){
        if($StandbyMachineHostName -ieq $m.machineName){
            $StandbyMachineName = $m.machineName
            break
        }
    }

    $FormParameters = @{ f = 'json'; token =  $token.token; machineName = $StandbyMachineName }
    try{
        $Response = Invoke-ArcGISWebRequest -Url "https://$($PortalEndPoint):7443/arcgis/portaladmin/machines/unregister" -HttpFormParameters $FormParameters -Referer $Referer -TimeOutSec 120
    }catch{
        $Machines = Invoke-ArcGISWebRequest -Url ("https://$($PortalEndPoint):7443/arcgis/portaladmin/machines") -HttpFormParameters @{ f = 'json'; token = $token.token; } -Referer $Referer -HttpMethod 'GET'
        $StandbyFlag = $false
        ForEach($m in $Machines.machines){
            if($StandbyMachineHostName -ieq $m.machineName){
                $StandbyFlag = $true
                break;
            }
        }    
    }

    if($null -ne $Response){
        Write-Verbose (ConvertTo-Json -Depth 5 $Response)
    }
    
    if(($Response.status -ieq "success") -or -not($StandbyFlag)){
        Write-Verbose "Sleeping for 3 Minutes. Portal will restart!"
        Start-Sleep -Seconds 180
    }else{
        throw "Unable to Unregister Portal! Please run the configuration again!"
    }
}

Export-ModuleMember -Function *-TargetResource
