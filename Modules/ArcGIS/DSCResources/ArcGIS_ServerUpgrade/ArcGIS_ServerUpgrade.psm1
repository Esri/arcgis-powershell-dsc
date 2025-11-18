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
		[parameter(Mandatory = $true)]
        [System.String]
        $ServerHostName,
    
        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $EnableUpgradeSiteDebug = $False
	)

    $VersionArray = $Version.Split('.')

    #$MachineFQDN = Get-FQDN $env:COMPUTERNAME    
    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    Write-Verbose "Fully Qualified Domain Name :- $FQDN"

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	Write-Verbose "Waiting for Server 'https://$($FQDN):6443/arcgis/admin'"
    Wait-ForUrl "https://$($FQDN):6443/arcgis/admin" -HttpMethod 'GET'

    if(Test-Install -Name "Server" -Version $Version){
        Write-Verbose "Installed Version of ArcGIS Server is $Version"
    }else{
        throw "ArcGIS Server not upgraded to required Version $Version"
    }

    $Referer = "http://localhost"
    $ServerSiteURL = "https://$($FQDN):6443"
    
    [string]$ServerLocalUrl = $ServerSiteURL.TrimEnd('/') + "/arcgis/admin/local"
    Write-Verbose "Making request to $ServerLocalUrl before upgrading the site"
    Invoke-ArcGISWebRequest -Url $ServerLocalUrl -HttpFormParameters @{f = 'json'} -Referer $Referer -Verbose
    
    [string]$ServerUpgradeUrl = $ServerSiteURL.TrimEnd('/') + "/arcgis/admin/upgrade"
    Write-Verbose "Making request to $ServerUpgradeUrl to Upgrade the site"
    $UpgradeParameters = @{f = 'json'; runAsync='true'}
    if($VersionArray[0] -gt 10 -and $EnableUpgradeSiteDebug){
        $UpgradeParameters.Add("enableDebug", 'true')
    }

    $Response = Invoke-ArcGISWebRequest -Url $ServerUpgradeUrl -HttpFormParameters $UpgradeParameters -Referer $Referer -Verbose
                
    if($Response.upgradeStatus -ieq 'IN_PROGRESS' -or ($Response.status -ieq "error" -and $Response.code -ieq 403 -and ($Response.messages -imatch "Upgrade in progress."))) {
        Write-Verbose "Upgrade in Progress"
        $ServerReady = $false
        $Attempts = 0

        [int]$TotalElapsedTimeInSeconds = 0
        $MaxWaitTimeInSeconds = 3600 * 4 # 4 hours
        while((-not($ServerReady)) -and ($TotalElapsedTimeInSeconds -lt $MaxWaitTimeInSeconds)) {
            $ResponseStatus = Invoke-ArcGISWebRequest -Url $ServerUpgradeUrl -HttpFormParameters $UpgradeParameters -Referer $Referer -Verbose -HttpMethod 'GET'
            
            Write-Verbose "Response received:- $(ConvertTo-Json -Depth 5 -Compress -InputObject $ResponseStatus)"
            if(($ResponseStatus.upgradeStatus -ine 'IN_PROGRESS') -and (($VersionArray[0] -gt 11) -or ($VersionArray[0] -ieq 11 -and $VersionArray[1] -gt 3))){
                foreach($Stage in $Stages){
                    Write-Verbose "$($Stage.name) : $($Stage.state)"
                }
            }

            if($ResponseStatus.upgradeStatus -ieq 'Success' -or $ResponseStatus.upgradeStatus -ieq 'Success with warnings'  -or (($ResponseStatus.upgradeStatus -ne 'IN_PROGRESS') -and ($ResponseStatus.code -ieq '404') -and ($ResponseStatus.status -ieq 'error'))){
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

            Start-Sleep -Seconds 5
            $Attempts = $Attempts + 1
        }
        
        if(-not($ServerReady)){
            throw "Upgrade Failed. Server not ready after 4 hours."
        }
    }else{
        throw "Error:- $(ConvertTo-Json -Depth 5 -Compress -InputObject $Response)"  
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
        $Version,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $EnableUpgradeSiteDebug = $False        
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

    $result    
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

    $VersionArray = $Version.Split('.')
    $CurrentVersionArray = $currentversion.Split('.')
    if($currentversion.Split('.').Length -eq 1){
        $CurrentVersionArray = @($currentversion, "0")
    }

    if(($VersionArray.Length -gt 1) -and ($VersionArray[1] -eq $CurrentVersionArray[1])){
        if($VersionArray.Length -eq 3){
            if($VersionArray[2] -eq $CurrentVersionArray[2]){
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
