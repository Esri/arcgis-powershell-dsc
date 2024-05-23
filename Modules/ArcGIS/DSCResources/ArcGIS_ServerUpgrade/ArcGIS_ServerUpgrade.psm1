$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

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
    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    Write-Verbose "Fully Qualified Domain Name :- $FQDN"

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	Write-Verbose "Waiting for Server 'https://$($FQDN):6443/arcgis/admin'"
    Wait-ForUrl "https://$($FQDN):6443/arcgis/admin" -HttpMethod 'GET'

    if($Ensure -ieq 'Present') {

        $ServiceName = 'ArcGIS Server'
        $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
        $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir  

        $RestartRequired = $false
        $configuredHostName = Get-ConfiguredHostName -InstallDir $InstallDir
        if($configuredHostName -ine $FQDN){
            Write-Verbose "Configured Host Name '$configuredHostName' is not equal to '$($FQDN)'. Setting it"
            if(Set-ConfiguredHostName -InstallDir $InstallDir -HostName $FQDN) { 
				# Need to restart the service to pick up the hostname 
                $RestartRequired = $true 
            }
        }

        if(Test-Install -Name "Server" -Version $Version){
            Write-Verbose "Installed Version of ArcGIS Server is $Version"
        }else{
            throw "ArcGIS Server not upgraded to required Version $Version"
        }

        if(Get-NodeAgentAmazonElementsPresent -InstallDir $InstallDir) {
            Write-Verbose "Removing EC2 Listener from NodeAgent xml file"
            if(Remove-NodeAgentAmazonElements -InstallDir $InstallDir) {
                 # Need to restart the service to pick up the EC2
                 $RestartRequired = $true
             }  
        }

        if($RestartRequired) {
			Restart-ArcGISService -ServiceName $ServiceName -Verbose

			Write-Verbose "Waiting for Server 'https://$($FQDN):6443/arcgis/admin' to initialize"
            Wait-ForUrl "https://$($FQDN):6443/arcgis/admin" -HttpMethod 'GET' -Verbose
            Start-Sleep -Seconds 30
        }


        $Referer = "http://localhost"
        $ServerSiteURL = "https://$($FQDN):6443"
        [string]$ServerUpgradeUrl = $ServerSiteURL.TrimEnd('/') + "/arcgis/admin/upgrade"
        
        Write-Verbose "Making request to $ServerUpgradeUrl to Upgrade the site"
        $Response = Invoke-ArcGISWebRequest -Url $ServerUpgradeUrl -HttpFormParameters @{f = 'json';runAsync='true'} -Referer $Referer -Verbose
                    
        if($Response.upgradeStatus -ieq 'IN_PROGRESS' -or ($Response.status -ieq "error" -and $Response.code -ieq 403 -and ($Response.messages -imatch "Upgrade in progress."))) {
            Write-Verbose "Upgrade in Progress"
			$ServerReady = $false
			$Attempts = 0

            while(-not($ServerReady) -and ($Attempts -lt 120)){
                $ResponseStatus = Invoke-ArcGISWebRequest -Url $ServerUpgradeUrl -HttpFormParameters @{f = 'json'} -Referer $Referer -Verbose -HttpMethod 'GET'
                if(($ResponseStatus.upgradeStatus -ne 'IN_PROGRESS') -and ($ResponseStatus.code -ieq '404') -and ($ResponseStatus.status -ieq 'error')){
                    if(Test-ServerUpgradeStatus -ServerSiteURL $ServerSiteURL -Referer $Referer -Version $Version -Verbose){
                        $ServerReady = $True
                        break
                    }
                }elseif(($ResponseStatus.status -ieq "error") -and ($ResponseStatus.code -ieq '500')){
					throw $ResponseStatus.messages
					break
				}elseif($ResponseStatus.upgradeStatus -ieq "LAST_ATTEMPT_FAILED"){
                    throw $ResponseStatus.messages
					break
                }
				Write-Verbose "Response received:- $(ConvertTo-Json -Depth 5 -Compress -InputObject $ResponseStatus)"  
				Start-Sleep -Seconds 30
				$Attempts = $Attempts + 1
            }

            if($Attempts -eq 120 -and -not($ServerReady)){
                throw "Upgrade Failed. Server not ready after 60 minutes."
            }
        }else{
			throw "Error:- $(ConvertTo-Json -Depth 5 -Compress -InputObject $Response)"  
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

    $result = Test-Install -Name "Server" -Version $Version
    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    $Referer = "http://localhost"
    $ServerUpgradeUrl = "https://$($FQDN):6443/arcgis/admin/upgrade"
    
    Wait-ForUrl -Url "https://$($FQDN):6443/arcgis/admin" -MaxWaitTimeInSeconds 300 -SleepTimeInSeconds 15 -HttpMethod 'GET' -Verbose

    $Referer = "http://localhost"
    $ServerSiteURL = "https://$($FQDN):6443"
    $ServerUpgradeUrl = "$($ServerSiteURL)/arcgis/admin/upgrade"
    $ResponseStatus = Invoke-ArcGISWebRequest -Url $ServerUpgradeUrl -HttpFormParameters @{f = 'json'} -Referer $Referer -Verbose -HttpMethod 'GET'

    if($result) {
        if($ResponseStatus.upgradeStatus -ieq "UPGRADE_REQUIRED" -or $ResponseStatus.upgradeStatus -ieq "LAST_ATTEMPT_FAILED" -or $ResponseStatus.upgradeStatus -ieq "IN_PROGRESS"){
            $result = $false
        }else{
            if(($ResponseStatus.code -ieq '404') -and ($ResponseStatus.status -ieq 'error')){
                $result = Test-ServerUpgradeStatus -ServerSiteURL $ServerSiteURL -Referer $Referer -Version $Version -Verbose
            } else {
                Write-Verbose "Error Code - $($ResponseStatus.code), Error Messages - $($ResponseStatus.messages)"
                $result = $false
            }
        }
    }else{
        throw "ArcGIS Server not upgraded to required Version $Version"
    }
    
    
    if($Ensure -ieq 'Present') {
	       $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}

function Test-ServerUpgradeStatus
{
    [CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
        [System.String]
        $ServerSiteURL,

        [parameter(Mandatory = $true)]
        [System.String]
        $Referer,

        [parameter(Mandatory = $true)]
        [System.String]
        $Version

    )

    Write-Verbose "Server Upgrade is likely done!"
    $Info = Invoke-ArcGISWebRequest -Url ($ServerSiteURL.TrimEnd('/') + "/arcgis/rest/info") -HttpFormParameters @{f = 'json';} -Referer $Referer -Verbose
    $currentversion = "$($Info.currentVersion)"
    Write-Verbose "Current Version Installed - $currentversion"
    if($currentversion -ieq "10.51"){
        $currentversion = "10.5.1"
    }elseif($currentversion -ieq "10.61"){
        $currentversion = "10.6.1"
    }elseif($currentversion -ieq "10.71"){
        $currentversion = "10.7.1"
    }elseif($currentversion -ieq "10.81"){
        $currentversion = "10.8.1"
    }elseif($currentversion -ieq "10.91"){
        $currentversion = "10.9.1"
    }

    if(($Version.Split('.').Length -gt 1) -and ($Version.Split('.')[1] -eq $currentversion.Split('.')[1])){
        if($Version.Split('.').Length -eq 3){
            if($Version.Split('.')[2] -eq $currentversion.Split('.')[2]){
                Write-Verbose 'Server Upgrade Successful'
                return $True
            }
        }else{
            Write-Verbose 'Server Upgrade Successful'
            return $True
        }
    }
    return $False
}

Export-ModuleMember -Function *-TargetResource
