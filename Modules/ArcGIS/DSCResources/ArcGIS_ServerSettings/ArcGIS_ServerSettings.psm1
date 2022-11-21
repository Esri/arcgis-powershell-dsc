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
        [parameter(Mandatory = $false)]
		[System.String]
        $ServerContext,
        
        [parameter(Mandatory = $true)]
		[System.String]
		$ServerHostName,

		[parameter(Mandatory = $false)]
		[System.String]
		$ExternalDNSName,

	    [System.String]
		$ServerEndPoint,

		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

		[System.Boolean]
        $DisableServiceDirectory,

        [System.String]
        $SharedKey
	)

	$null
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$ServerHostName,

		[parameter(Mandatory = $false)]
		[System.String]
		$ExternalDNSName,

        [parameter(Mandatory = $false)]
		[System.String]
        $ServerContext,

		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

		[System.Boolean]
        $DisableServiceDirectory,

        [System.String]
        $SharedKey
    )
    
	[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	$ServerFQDN = Get-FQDN $ServerHostName
	$ServerHttpsUrl = "https://$($ServerFQDN):6443" 
    $Referer = $ServerHttpsUrl
	
	Write-Verbose "Getting Server Token for user '$($SiteAdministrator.UserName)' from '$ServerHttpsUrl'"

	$serverToken = Get-ServerToken -ServerEndPoint $ServerHttpsUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer
    if(-not($serverToken.token)) {
        Write-Verbose "Get Server Token Response:- $serverToken"
        throw "Unable to retrieve Server Token for '$($SiteAdministrator.UserName)'"
    }
	Write-Verbose "Connected to Server successfully and retrieved token for '$($SiteAdministrator.UserName)'"

	if ($ExternalDNSName){
		$serverSysProps = Get-ServerSystemProperties -ServerHostName $ServerFQDN -Token $serverToken.token -Referer $Referer	
		if($serverSysProps) {
			Write-Verbose "System Properties:- $(ConvertTo-Json $serverSysProps -Depth 3 -Compress)"
		}else {
			Write-Verbose "System Properties is NULL"
		}
		$ExpectedServerWebContextUrl = "https://$($ExternalDNSName)/$($ServerContext)"	
		if($serverSysProps.WebContextURL -ieq $ExpectedServerWebContextUrl) {
			Write-Verbose "Server System Properties > WebContextUrl is correctly set to '$($ExpectedServerWebContextUrl)'"
		}else{
			Write-Verbose "Server System Properties > WebContextUrl is NOT correctly set to '$($ExpectedServerWebContextUrl)'"
			if(-not($serverSysProps.WebContextURL)) {
				Add-Member -InputObject $serverSysProps -MemberType NoteProperty -Name 'WebContextURL' -Value $ExpectedServerWebContextUrl
			}else{
				$serverSysProps.WebContextURL = $ExpectedServerWebContextUrl
			}	
			Write-Verbose "Updating Server System Properties to set WebContextUrl to $ExpectedServerWebContextUrl"
			Set-ServerSystemProperties -ServerHostName $ServerFQDN -Token $serverToken.token -Referer $Referer -Properties $serverSysProps
			Write-Verbose "Updated Server System Properties to set WebContextUrl to $ExpectedServerWebContextUrl"
		}
	}

	Write-Verbose "Waiting for Url 'https://$($ServerFQDN):6443/arcgis/rest/info/healthCheck' to respond"
	Wait-ForUrl -Url "https://$($ServerFQDN):6443/arcgis/rest/info/healthCheck?f=json" -SleepTimeInSeconds 10 -MaxWaitTimeInSeconds 150 -HttpMethod 'GET' -Verbose

	Write-Verbose "Get Service Directory Setting"
	$servicesdirectory = Get-AdminSettings -ServerUrl $ServerHttpsUrl -SettingUrl "arcgis/admin/system/handlers/rest/servicesdirectory" -Token $serverToken.token -Referer $Referer
	if($servicesdirectory.enabled -eq "true") {
		$dirStatus = "enabled"
	} else {
		$dirStatus = "disabled"
	}
	Write-Verbose "Current Service Directory Setting:- $dirStatus"
	if($servicesdirectory.enabled -eq $DisableServiceDirectory) {
		Write-Verbose "Updating Service Directory Setting"
		$servicesdirectory.enabled = (!$DisableServiceDirectory)
		$servicesdirectory = ConvertTo-Json $servicesdirectory
		Set-AdminSettings -ServerUrl $ServerHttpsUrl -SettingUrl "arcgis/admin/system/handlers/rest/servicesdirectory/edit" -Token $serverToken.token -Properties $servicesdirectory -Referer $Referer
	}
	
	if($SharedKey){
		Write-Verbose "Get Token Setting"
		$TokenSettings = Get-AdminSettings -ServerUrl $ServerHttpsUrl -SettingUrl "arcgis/admin/security/tokens" -Token $serverToken.token -Referer $Referer
		if($TokenSettings.properties.sharedKey -ine $SharedKey) {
			Write-Verbose "Updating shared key"
			$TokenSettings.properties.sharedKey = $SharedKey
			$TokenSettings = ConvertTo-Json $TokenSettings
			Set-TokenSettings -ServerUrl $ServerHttpsUrl -SettingUrl "arcgis/admin/security/tokens/update" -Token $serverToken.token -Properties $TokenSettings -Referer $Referer
		}
	}

    
    Write-Verbose "Waiting for Url 'https://$($ServerFQDN):6443/arcgis/rest/info/healthCheck' to respond"
	Wait-ForUrl -Url "https://$($ServerFQDN):6443/arcgis/rest/info/healthCheck?f=json" -SleepTimeInSeconds 10 -MaxWaitTimeInSeconds 150 -HttpMethod 'GET' -Verbose
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [parameter(Mandatory = $false)]
		[System.String]
        $ServerContext,
        
        [parameter(Mandatory = $true)]
		[System.String]
		$ServerHostName,

		[parameter(Mandatory = $false)]
		[System.String]
		$ExternalDNSName,

		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

		[System.Boolean]
        $DisableServiceDirectory,

        [System.String]
        $SharedKey
    )

	[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	$ServerFQDN = Get-FQDN $ServerHostName
    $ServerHttpsUrl = "https://$($ServerFQDN):6443" 
    $Referer = $ServerHttpsUrl	
    Write-Verbose "Getting Server Token for user '$($SiteAdministrator.UserName)' from 'https://$($ServerFQDN):6443'"

    $serverToken = Get-ServerToken -ServerEndPoint $ServerHttpsUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer
    if(-not($serverToken.token)) {
        Write-Verbose "Get Server Token Response:- $serverToken"
        throw "Unable to retrieve Server Token for '$($SiteAdministrator.UserName)'"
    }
    Write-Verbose "Connected to Server successfully and retrieved token for '$($SiteAdministrator.UserName)'"
	$result = $true
	
	if($result){
		$serverSysProps = Get-ServerSystemProperties -ServerHostName $ServerFQDN -Token $serverToken.token -Referer $Referer	
		if($serverSysProps) {
			Write-Verbose "System Properties:- $(ConvertTo-Json $serverSysProps -Depth 3 -Compress)"
		}else {
			Write-Verbose "System Properties is NULL"
		}
		if($ExternalDNSName){
			$ExpectedServerWebContextUrl = "https://$($ExternalDNSName)/$($ServerContext)"	
			if($serverSysProps.WebContextURL -ieq $ExpectedServerWebContextUrl) {
				Write-Verbose "Server System Properties > WebContextUrl is correctly set to '$($ExpectedServerWebContextUrl)'"
			}else{
				$result = $false
				Write-Verbose "Server System Properties > WebContextUrl is NOT correctly set to '$($ExpectedServerWebContextUrl)'"
			}
		}
	}

	if($result) {
        Write-Verbose "Get Service Directory Setting"
        $servicesdirectory = Get-AdminSettings -ServerUrl $ServerHttpsUrl -SettingUrl "arcgis/admin/system/handlers/rest/servicesdirectory" -Token $serverToken.token -Referer $Referer
        if($servicesdirectory.enabled -eq "true") {
            $dirStatus = "enabled"
        } else {
            $dirStatus = "disabled"
        }
        Write-Verbose "Current Service Directory Setting:- $dirStatus"
        if($servicesdirectory.enabled -eq $DisableServiceDirectory) {
            $result = $false
        }
    }

	if($result -and $SharedKey) {
        Write-Verbose "Get Token Setting"
        $TokenSettings = Get-AdminSettings -ServerUrl $ServerHttpsUrl -SettingUrl "arcgis/admin/security/tokens" -Token $serverToken.token -Referer $Referer
        if($TokenSettings.properties.sharedKey -ine $SharedKey) {
            $result = $false
        }
    }

	$result    
}

function Get-ServerSystemProperties
{
    [CmdletBinding()]
    param(        
        [System.String]
		$ServerHostName, 

        [System.String]
		$Token, 

        [System.String]
		$Referer
    )
    
    Invoke-ArcGISWebRequest -Url ("https://$($ServerHostName):6443/arcgis/admin/system/properties/") -HttpMethod 'Get' -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer 
}

function Set-ServerSystemProperties
{
    [CmdletBinding()]
    param(
        
        [System.String]
		$ServerHostName, 

        [System.String]
		$Token, 

        [System.String]
		$Referer,

        $Properties
    )
    
    try {
        Invoke-ArcGISWebRequest -Url("https://$($ServerHostName):6443/arcgis/admin/system/properties/update/") -HttpFormParameters @{ f = 'json'; token = $Token; properties = (ConvertTo-Json $Properties -Depth 4) } -Referer $Referer -TimeOutSec 180
    }catch {
        Write-Verbose "[WARNING] Request to Set-ServerSystemProperties returned error:- $_"
    }
}

function Get-AdminSettings
{
    [CmdletBinding()]
    Param
    (
        [System.String]
        $ServerUrl,
        
        [System.String]
        $SettingUrl,
        
        [System.String]
        $Token, 

        [System.String]
		$Referer
    )
    $RequestParams = @{ f= 'json'; token = $Token; }
    $RequestUrl  = $ServerUrl.TrimEnd("/") + "/" + $SettingUrl.TrimStart("/")
    $Response = Invoke-ArcGISWebRequest -Url $RequestUrl -HttpFormParameters $RequestParams -Referer $Referer
    Confirm-ResponseStatus $Response
    $Response
}

function Set-AdminSettings
{
    [CmdletBinding()]
    Param
    (
        [System.String]
        $ServerUrl,

        [System.String]
        $SettingUrl,
        
        [System.String]
        $Token,
        
        [System.String]
        $Properties, 

        [System.String]
		$Referer
    )
    $RequestUrl  = $ServerUrl.TrimEnd("/") + "/" + $SettingUrl.TrimStart("/")
    $COProperties = $Properties | ConvertFrom-Json
    $RequestParams = @{ f= 'json'; token = $Token; }
    $COProperties.psobject.properties | ForEach-Object { $RequestParams[$_.Name] = $_.Value }
    $Response = Invoke-ArcGISWebRequest -Url $RequestUrl -HttpFormParameters $RequestParams -Referer $Referer 
    Write-Verbose $Response
    Confirm-ResponseStatus $Response
    $Response
}

function Set-TokenSettings {
    [CmdletBinding()]
    Param (
        [System.String]
        $ServerUrl,

        [System.String]
        $SettingUrl,
        
        [System.String]
        $Token,
        
        [System.String]
        $Properties, 

        [System.String]
		$Referer
    )

    $RequestUrl = $ServerUrl.TrimEnd("/") + "/" + $SettingUrl.TrimStart("/")
    $RequestParams = @{ f = 'json'; token = $Token; tokenManagerConfig = $Properties }
    $Response = Invoke-ArcGISWebRequest -Url $RequestUrl -HttpFormParameters $RequestParams -Referer $Referer
    Confirm-ResponseStatus $Response
    Write-Verbose $Response
    $Response
}

Export-ModuleMember -Function *-TargetResource
