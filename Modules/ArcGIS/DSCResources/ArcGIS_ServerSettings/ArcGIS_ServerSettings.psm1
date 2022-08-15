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
        $EnableSSL,

		[System.Boolean]
        $EnableHTTP
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
        $EnableSSL,

		[System.Boolean]
        $EnableHTTP
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

	# Get the current security configuration
	$UpdateSecurityConfig = $False
	Write-Verbose 'Getting security config for site'
	$secConfig = Get-SecurityConfig -ServerHostName $ServerFQDN -Token $serverToken.token -Referer $Referer
	if($EnableSSL -ine $secConfig.sslEnabled){
		Write-Verbose "Enabled SSL matches doesn't match the expected state $EnableSSL"
		$UpdateSecurityConfig = $True
	}else{
		Write-Verbose "Enabled SSL matches the expected state $EnableSSL"
	}

	if($EnableHTTP -ine $secConfig.httpEnabled){
		Write-Verbose "Http Enabled doesn't match the expected state $EnableHTTP"
		$UpdateSecurityConfig = $True
	}else{
		Write-Verbose "Http Enabled matches the expected state $EnableHTTP"
	}

	if($UpdateSecurityConfig){
		Update-SecurityConfig -ServerHostName $ServerFQDN -Token $serverToken.token -SecurityConfig $secConfig `
									-Referer $Referer -EnableHTTP $EnableHTTP -EnableSSL $EnableSSL -Verbose
		# Changes will cause the web server to restart.
		Write-Verbose "Waiting 30 seconds before checking"
		Start-Sleep -Seconds 30
		Write-Verbose "Waiting for Url 'https://$($ServerFQDN):6443/arcgis/admin' to respond"
		Wait-ForUrl -Url "https://$($ServerFQDN):6443/arcgis/admin/" -SleepTimeInSeconds 15 -MaxWaitTimeInSeconds 90 
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
        $EnableSSL,

		[System.Boolean]
        $EnableHTTP
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

	$secConfig = Get-SecurityConfig -ServerHostName $ServerFQDN -Token $serverToken.token -Referer $Referer
	if($result){
		Write-Verbose "Enabled SSL Current state- $($secConfig.sslEnabled)"
		if($EnableSSL -ine $secConfig.sslEnabled){
			Write-Verbose "Enabled SSL doesn't match the expected state $EnableSSL"
			$result = $false
		}else{
			Write-Verbose "Enabled SSL matches the expected state $EnableSSL"
		}
	}
	
	if($result){
		Write-Verbose "Enabled Http Current state- $($secConfig.httpEnabled)"
		if($EnableHTTP -ine $secConfig.httpEnabled){
			Write-Verbose "Http Enabled doesn't match the expected state $EnableHTTP"
			$result = $false
		}else{
			Write-Verbose "Http Enabled matches the expected state $EnableHTTP"
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

function Update-SecurityConfig
{
    [CmdletBinding()]
    param(
		[System.String]
		$ServerHostName,

        [System.String]
        $Token, 

        [System.String]
        $Referer,

        $SecurityConfig,

		[System.Boolean]
        $EnableSSL,

		[System.Boolean]
        $EnableHTTP
    ) 

    if(-not($SecurityConfig)) {
        throw "Security Config parameter is not provided"
    }

	$Protocol = "HTTP_AND_HTTPS"
	if($EnableSSL -and $EnableHTTP){
		$Protocol = "HTTP_AND_HTTPS"
	}elseif($EnableSSL -and -not($EnableHTTP)){
		$Protocol = "HTTPS"
	}elseif($EnableHTTP -and -not($EnableSSL)){
		$Protocol = "HTTP"
	}

    $UpdateSecurityConfigUrl  = "https://$($ServerHostName):6443/arcgis/admin/security/config/update"
    $props = @{ 
				f= 'json'; 
				token = $Token; 
				Protocol = $Protocol; 
				authenticationTier = $SecurityConfig.authenticationTier; 
				allowDirectAccess = $SecurityConfig.allowDirectAccess;  
				cipherSuites = $SecurityConfig.cipherSuites 
			}
    Invoke-ArcGISWebRequest -Url $UpdateSecurityConfigUrl -HttpFormParameters $props -Referer $Referer -TimeOutSec 300
}

function Get-SecurityConfig 
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

    $GetSecurityConfigUrl  = "https://$($ServerHostName):6443/arcgis/admin/security/config/"
    Write-Verbose "Url:- $GetSecurityConfigUrl"
    Invoke-ArcGISWebRequest -Url $GetSecurityConfigUrl -HttpFormParameters @{ f= 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET' -TimeOutSec 30
}


Export-ModuleMember -Function *-TargetResource
