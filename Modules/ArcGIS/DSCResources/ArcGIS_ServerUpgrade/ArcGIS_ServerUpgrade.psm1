<#
    .SYNOPSIS
        Resource to aid post upgrade completion workflows. This resource upgrades the Server Site once Server Installer has completed the upgrade.
    .PARAMETER Ensure
        Take the values Present or Absent. 
        - "Present" ensure Upgrade the Server Site once Server Installer is completed
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
	
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

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
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    #$MachineFQDN = Get-FQDN $env:COMPUTERNAME    
    Write-Verbose "Fully Qualified Domain Name :- $ServerHostName"

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	Write-Verbose "Waiting for Server 'http://$($ServerHostName):6080/arcgis/admin'"
    Wait-ForUrl "http://$($ServerHostName):6080/arcgis/admin" -HttpMethod 'GET'

    if($Ensure -ieq 'Present') {        
        $Referer = "http://localhost"
        $ServerSiteURL = "https://$($ServerHostName):6443"
        [string]$ServerUpgradeUrl = $ServerSiteURL.TrimEnd('/') + "/arcgis/admin/upgrade"
        $Response = Invoke-ArcGISWebRequest -Url $ServerUpgradeUrl -HttpFormParameters @{f = 'json';runAsync='true'} -Referer $Referer -LogResponse
                    
        Write-Verbose "Making request to $ServerUpgradeUrl to Upgrade the site"
        if($Response.upgradeStatus -ieq 'IN_PROGRESS') {
            Write-Verbose "Upgrade in Progress"
			$ServerReady = $false
			$Attempts = 0

            while(-not($ServerReady) -and ($Attempts -lt 60)){
                $ResponseStatus = Invoke-ArcGISWebRequest -Url $ServerUpgradeUrl -HttpFormParameters @{f = 'json'} -Referer $Referer -LogResponse -HttpMethod 'GET'
                if(($ResponseStatus.upgradeStatus -ne 'IN_PROGRESS') -and ($ResponseStatus.code -ieq '404') -and ($ResponseStatus.status -ieq 'error')){
                    Write-Verbose "Server Upgrade is likely done!"
                    $Info = Invoke-ArcGISWebRequest -Url ($ServerSiteURL.TrimEnd('/') + "/arcgis/rest/info") -HttpFormParameters @{f = 'json';} -Referer $Referer -LogResponse
                    $currentversion = $Info.currentVersion 
                    if($currentversion -ieq "10.51"){
                        $currentversion = "10.5.1"
                    }elseif($currentversion -ieq "10.61"){
                        $currentversion = "10.6.1"
                    }
                    
                    if(($Version.Split('.').Length -gt 1) -and ($Version.Split('.')[1] -eq $currentversion.Split('.')[1])){
                        if($Version.Split('.').Length -eq 3){
                            if($Version.Split('.')[2] -eq $currentversion.Split('.')[2]){
                                Write-Verbose 'Server Upgrade Successfull'
                                $ServerReady = $true
                                break
                            }
                        }else{
                            Write-Verbose 'Server Upgrade Successfull'
                            $ServerReady = $true
                            break
                        }
                    }
                }elseif(($ResponseStatus.status -ieq "error") -and ($ResponseStatus.code -ieq '500')){
					throw $ResponseStatus.messages
					break
				}
				Write-Verbose "Response received:- $(ConvertTo-Json -Depth 5 -Compress $ResponseStatus)"  
				Start-Sleep -Seconds 30
				$Attempts = $Attempts + 1
            }
        }else{
			throw "Error:- $(ConvertTo-Json -Depth 5 -Compress $Response)"  
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
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false
    $result = Check-ServerVersion -Version $Version
    
    $Referer = "http://localhost"
    $ServerUpgradeUrl = "https://$($ServerHostName):6443/arcgis/admin/upgrade"
    $ResponseStatus = Invoke-ArcGISWebRequest -Url $ServerUpgradeUrl -HttpFormParameters @{f = 'json'} -Referer $Referer -LogResponse -HttpMethod 'GET'
    
    if($result) {
        if($ResponseStatus.upgradeStatus -ieq "UPGRADE_REQUIRED" -or $ResponseStatus.upgradeStatus -ieq "LAST_ATTEMPT_FAILED" -or $ResponseStatus.upgradeStatus -ieq "IN_PROGRESS"){
            $result = $false
        }else{
            $result = $true
        }
    }else{
        throw "ArcGIS Server not upgraded to required Version"
    }
    
    
    if($Ensure -ieq 'Present') {
	       $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}

function Check-ServerVersion(){
    [CmdletBinding()]
    [OutputType([System.Boolean])]
	param(
        [string]$Version
    )

    $result = $false

    $ProdId = Get-ComponentCode -ComponentName "Server" -Version $Version
    if(-not($ProdId.StartsWith('{'))){
        $ProdId = '{' + $ProdId
    }
    if(-not($ProdId.EndsWith('}'))){
        $ProdId = $ProdId + '}'
    }
    $PathToCheck = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$($ProdId)"
    Write-Verbose "Testing Presence for Component 'Server' with Path $PathToCheck"
    if (Test-Path $PathToCheck -ErrorAction Ignore){
        $result = $true
    }
    if(-not($result)){
        $PathToCheck = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$($ProdId)"
        Write-Verbose "Testing Presence for Component 'Server' with Path $PathToCheck"
        if (Test-Path $PathToCheck -ErrorAction Ignore){
            $result = $true
        }
    }
    
    $result

}

Export-ModuleMember -Function *-TargetResource