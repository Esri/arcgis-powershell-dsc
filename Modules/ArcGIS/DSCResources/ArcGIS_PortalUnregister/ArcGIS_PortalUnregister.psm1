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
        $PrimarySiteAdmin,
        
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
        $PrimarySiteAdmin,
        
        [parameter(Mandatory = $true)]
        [System.String]
        $StandbyMachine,

        [parameter(Mandatory = $true)]
        [System.String]
        $Version
    )
	
	$result = $false

	$result = Test-Install -Name "Portal" -Version $Version
    
    if(-not($result)){
		$Referer = 'http://localhost'
		$token = Get-PortalToken -PortalHostName $PortalEndPoint -SiteName 'arcgis' -UserName $PrimarySiteAdmin.UserName  `
			-Password $PrimarySiteAdmin.GetNetworkCredential().Password -Referer $Referer
    
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
        $PrimarySiteAdmin,
        
        [parameter(Mandatory = $true)]
        [System.String]
        $StandbyMachine,

        [parameter(Mandatory = $true)]
        [System.String]
        $Version
	)

    $Referer = 'http://localhost'
    $token = Get-PortalToken -PortalHostName $PortalEndPoint -SiteName 'arcgis' -UserName $PrimarySiteAdmin.UserName  `
        -Password $PrimarySiteAdmin.GetNetworkCredential().Password -Referer $Referer
        
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

    if($Response -ne $null){
        Write-Verbose (ConvertTo-Json -Depth 5 $Response)
    }
    
    if(($Response.status -ieq "success") -or -not($StandbyFlag)){
        Write-Verbose "Sleeping for 3 Minutes. Portal will restart!"
        Start-Sleep -Seconds 180
    }else{
        throw "Unable to Unregister Portal! Please run the configuration again!"
    }
}

function Test-Install{
    [CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [parameter(Mandatory = $true)]
		[System.String]
		$Name,

		[parameter(Mandatory = $true)]
		[System.String]
		$Version
    )
    
    $result = $false
    
    $ProdId = Get-ComponentCode -ComponentName $Name -Version $Version
    if(-not($ProdId.StartsWith('{'))){
        $ProdId = '{' + $ProdId
    }
    if(-not($ProdId.EndsWith('}'))){
        $ProdId = $ProdId + '}'
    }

    $PathToCheck = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$($ProdId)"
    Write-Verbose "Testing Presence for Component '$Name' with Path $PathToCheck"
    if (Test-Path $PathToCheck -ErrorAction Ignore){
        $result = $true
    }
    if(-not($result)){
        $PathToCheck = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$($ProdId)"
        Write-Verbose "Testing Presence for Component '$Name' with Path $PathToCheck"
        if (Test-Path $PathToCheck -ErrorAction Ignore){
            $result = $true
        }
    }

    $result
}

Export-ModuleMember -Function *-TargetResource