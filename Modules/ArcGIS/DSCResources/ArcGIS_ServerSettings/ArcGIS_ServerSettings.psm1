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
	param(
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

		[parameter(Mandatory = $false)]
		[System.string]                 
		$HttpProxyHost,

		[parameter(Mandatory = $false)]
		[AllowNull()]
        [Nullable[System.UInt32]]                
		$HttpProxyPort,

		[parameter(Mandatory = $false)]
		[System.Management.Automation.PSCredential]           
		$HttpProxyCredential,

		[parameter(Mandatory = $false)]
		[System.string]                 
		$HttpsProxyHost,

		[parameter(Mandatory = $false)]
		[AllowNull()]
        [Nullable[System.UInt32]]              
		$HttpsProxyPort,

		[parameter(Mandatory = $false)]
		[System.Management.Automation.PSCredential]           
		$HttpsProxyCredential,

		[parameter(Mandatory = $false)]
		[System.string]                 
		$NonProxyHosts,

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
	$UpdateSystemProperties = $false

	$serverToken = Get-ServerToken -ServerEndPoint $ServerHttpsUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer
    if(-not($serverToken.token)) {
        Write-Verbose "Get Server Token Response:- $serverToken"
        throw "Unable to retrieve Server Token for '$($SiteAdministrator.UserName)'"
    }
	Write-Verbose "Connected to Server successfully and retrieved token for '$($SiteAdministrator.UserName)'"

	$serverSysProps = Get-ServerSystemProperties -ServerHostName $ServerFQDN -Token $serverToken.token -Referer $Referer
	if($serverSysProps) {
		Write-Verbose "System Properties:- $(ConvertTo-Json $serverSysProps -Depth 3 -Compress)"
	}else {
		Write-Verbose "System Properties is NULL"
	}
	# checking forward proxy settings
	if ($HttpProxyHost) {
		if(-not($serverSysProps.HttpProxyHost)) {
			Add-Member -InputObject $serverSysProps -MemberType NoteProperty -Name 'httpProxyHost' -Value $HttpProxyHost
		}else{
			$serverSysProps.HttpProxyHost = $HttpProxyHost
		}
		$UpdateSystemProperties = $true
	}
	elseif ($serverSysProps.HttpProxyHost) {
        # JSON removed it, so clear it
        $serverSysProps.PSObject.Properties.Remove('httpProxyHost')
        $UpdateSystemProperties = $true
    }
	if ($HttpProxyPort) {
		if(-not($serverSysProps.HttpProxyPort)) {
			Add-Member -InputObject $serverSysProps -MemberType NoteProperty -Name 'httpProxyPort' -Value $HttpProxyPort
		}else{
			$serverSysProps.HttpProxyPort = $HttpProxyPort
		}
		$UpdateSystemProperties = $true
	}
	elseif ($serverSysProps.HttpProxyPort) {
        $serverSysProps.PSObject.Properties.Remove('httpProxyPort')
        $UpdateSystemProperties = $true
    }
	if ($HttpProxyCredential) {
		if(-not($serverSysProps.HttpProxyUser)) {
			Add-Member -InputObject $serverSysProps -MemberType NoteProperty -Name 'httpProxyUser' -Value $HttpProxyCredential.UserName
		}else{
			$serverSysProps.HttpProxyUser = $HttpProxyCredential.UserName
		}
		if(-not($serverSysProps.HttpProxyPassword)) {
			Add-Member -InputObject $serverSysProps -MemberType NoteProperty -Name 'httpProxyPassword' -Value $HttpProxyCredential.GetNetworkCredential().Password
		}else{
			$serverSysProps.HttpProxyPassword = $HttpProxyCredential.GetNetworkCredential().Password
		}

		if(-not($serverSysProps.IsHttpProxyPasswordEncrypted)) {
			Add-Member -InputObject $serverSysProps -MemberType NoteProperty -Name 'isHttpProxyPasswordEncrypted' -Value $false
		}else{
			$serverSysProps.IsHttpProxyPasswordEncrypted = $false
		}

		$UpdateSystemProperties = $true
	}
	elseif ($serverSysProps.HttpProxyUser -or $serverSysProps.HttpProxyPassword) {
        $serverSysProps.PSObject.Properties.Remove('httpProxyUser')
        $serverSysProps.PSObject.Properties.Remove('httpProxyPassword')

		$serverSysProps.PSObject.Properties.Remove('isHttpProxyPasswordEncrypted')
        $UpdateSystemProperties = $true
    }
	# Forward proxy HTTPS Proxy: set or clear
	if ($HttpsProxyHost) {
		if(-not($serverSysProps.HttpsProxyHost)) {
			Add-Member -InputObject $serverSysProps -MemberType NoteProperty -Name 'httpsProxyHost' -Value $HttpsProxyHost
		}else{
			$serverSysProps.HttpsProxyHost = $HttpsProxyHost
		}
		$UpdateSystemProperties = $true
	}
	elseif ($serverSysProps.HttpsProxyHost) {
        # JSON removed it, so clear it
        $serverSysProps.PSObject.Properties.Remove('httpsProxyHost')
        $UpdateSystemProperties = $true
    }
	if ($HttpsProxyPort) {
		if(-not($serverSysProps.HttpsProxyPort)) {
			Add-Member -InputObject $serverSysProps -MemberType NoteProperty -Name 'httpsProxyPort' -Value $HttpsProxyPort
		}else{
			$serverSysProps.HttpsProxyPort = $HttpsProxyPort
		}
		$UpdateSystemProperties = $true
	}
	elseif ($serverSysProps.HttpsProxyPort) {
        $serverSysProps.PSObject.Properties.Remove('httpsProxyPort')
        $UpdateSystemProperties = $true
    }
	if ($HttpsProxyCredential) {
		if(-not($serverSysProps.HttpsProxyUser)) {
			Add-Member -InputObject $serverSysProps -MemberType NoteProperty -Name 'httpsProxyUser' -Value $HttpsProxyCredential.UserName
		}else{
			$serverSysProps.HttpsProxyUser = $HttpsProxyCredential.UserName
		}
		if(-not($serverSysProps.HttpsProxyPassword)) {
			Add-Member -InputObject $serverSysProps -MemberType NoteProperty -Name 'httpsProxyPassword' -Value $HttpsProxyCredential.GetNetworkCredential().Password
		}else{
			$serverSysProps.HttpsProxyPassword = $HttpsProxyCredential.GetNetworkCredential().Password
		}
		if(-not($serverSysProps.IsHttpsProxyPasswordEncrypted  )) {
			Add-Member -InputObject $serverSysProps -MemberType NoteProperty -Name 'isHttpsProxyPasswordEncrypted' -Value $false
		}else{
			$serverSysProps.IsHttpsProxyPasswordEncrypted  = $false
		}
		$UpdateSystemProperties = $true
	}
	elseif ($serverSysProps.HttpsProxyUser -or $serverSysProps.HttpsProxyPassword) {
        $serverSysProps.PSObject.Properties.Remove('httpsProxyUser')
        $serverSysProps.PSObject.Properties.Remove('httpsProxyPassword')

		$serverSysProps.PSObject.Properties.Remove('isHttpsProxyPasswordEncrypted')
        $UpdateSystemProperties = $true
    }

	if ($NonProxyHosts) {
		if(-not($serverSysProps.NonProxyHosts)) {
			Add-Member -InputObject $serverSysProps -MemberType NoteProperty -Name 'nonProxyHosts' -Value $NonProxyHosts
		}else{
			$serverSysProps.NonProxyHosts = $NonProxyHosts
		}
		$UpdateSystemProperties = $true
	}
	elseif ($serverSysProps.NonProxyHosts) {
        $serverSysProps.PSObject.Properties.Remove('nonProxyHosts')
        $UpdateSystemProperties = $true
    }

	if ($ExternalDNSName){
		$ExpectedServerWebContextUrl = "https://$($ExternalDNSName)/$($ServerContext)"	
		if($serverSysProps.WebContextURL -ieq $ExpectedServerWebContextUrl) {
			Write-Verbose "Server System Properties > WebContextUrl is correctly set to '$($ExpectedServerWebContextUrl)'"
		}else{
			$UpdateSystemProperties = $true
			Write-Verbose "Server System Properties > WebContextUrl is NOT correctly set to '$($ExpectedServerWebContextUrl)'"
			if(-not($serverSysProps.WebContextURL)) {
				Add-Member -InputObject $serverSysProps -MemberType NoteProperty -Name 'WebContextURL' -Value $ExpectedServerWebContextUrl
			}else{
				$serverSysProps.WebContextURL = $ExpectedServerWebContextUrl
			}
		}
	}

	if($UpdateSystemProperties ){	
		Write-Verbose "Updating Server System Properties"
		Set-ServerSystemProperties -ServerHostName $ServerFQDN -Token $serverToken.token -Referer $Referer -Properties $serverSysProps
		Write-Verbose "Updated Server System Properties"
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
		Write-Verbose "Get Token and Shared Key Setting"
		$TokenSettings = Get-AdminSettings -ServerUrl $ServerHttpsUrl -SettingUrl "arcgis/admin/security/tokens" -Token $serverToken.token -Referer $Referer	
		if($TokenSettings.properties.sharedKey -ine $SharedKey){
			Write-Verbose "Shared Key is not set as expected. Updating shared key."	
			$TokenSettings.properties.sharedKey = $SharedKey
			$TokenSettings = ConvertTo-Json $TokenSettings
			Set-TokenSettings -ServerUrl $ServerHttpsUrl -SettingUrl "arcgis/admin/security/tokens/update" -Token $serverToken.token -Properties $TokenSettings -Referer $Referer
		}else{
			Write-Verbose "Shared Key is set as expected"
		}
	}
    
    Write-Verbose "Waiting for Url 'https://$($ServerFQDN):6443/arcgis/rest/info/healthCheck' to respond"
	Wait-ForUrl -Url "https://$($ServerFQDN):6443/arcgis/rest/info/healthCheck?f=json" -SleepTimeInSeconds 10 -MaxWaitTimeInSeconds 150 -HttpMethod 'GET' -Verbose
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param(
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

		[parameter(Mandatory = $false)]
		[System.string]                 
		$HttpProxyHost,

		[parameter(Mandatory = $false)]
		[AllowNull()]
        [Nullable[System.UInt32]]                    
		$HttpProxyPort,

		[parameter(Mandatory = $false)]
		[System.Management.Automation.PSCredential]           
		$HttpProxyCredential,

		[parameter(Mandatory = $false)]
		[System.string]                 
		$HttpsProxyHost,

		[parameter(Mandatory = $false)]
		[AllowNull()]
        [Nullable[System.UInt32]]               
		$HttpsProxyPort,

		[parameter(Mandatory = $false)]
		[System.Management.Automation.PSCredential]           
		$HttpsProxyCredential,

		[parameter(Mandatory = $false)]
		[System.string]                 
		$NonProxyHosts,

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
		Write-Verbose "Get Token and Shared Key Setting"
        $TokenSettings = Get-AdminSettings -ServerUrl $ServerHttpsUrl -SettingUrl "arcgis/admin/security/tokens" -Token $serverToken.token -Referer $Referer
		if($TokenSettings.properties.sharedKey -ine $SharedKey){
			Write-Verbose "Shared Key is not set as expected"
			$result = $false
		}else{
			Write-Verbose "Shared Key is set as expected"
		}
    }
	$ProtocolSettings = @(
        [PSCustomObject]@{ Prefix = 'Http';  CredentialParam = 'HttpProxyCredential'  },
        [PSCustomObject]@{ Prefix = 'Https'; CredentialParam = 'HttpsProxyCredential' }
    )

	foreach ($Protocol in $ProtocolSettings) {
        $Prefix                 = $Protocol.Prefix
        $ProxyHostParamName     = "${Prefix}ProxyHost"
        $ProxyPortParamName     = "${Prefix}ProxyPort"
        $ProxyCredentialParam   = $Protocol.CredentialParam

        # Grab the parameter values by name
        $ProxyHostValue         = Get-Variable -Name $ProxyHostParamName       -ValueOnly
        $ProxyPortValue         = Get-Variable -Name $ProxyPortParamName       -ValueOnly
        $ProxyCredentialValue   = Get-Variable -Name $ProxyCredentialParam     -ValueOnly

        # Grab the server’s current system properties
        $ServerProxyHost        = $ServerSysProps."${Prefix}ProxyHost"
        $ServerProxyPort        = $ServerSysProps."${Prefix}ProxyPort"
        $ServerProxyUser        = $ServerSysProps."${Prefix}ProxyUser"
        $ServerProxyPassword    = $ServerSysProps."${Prefix}ProxyPassword"

        # If user supplied any proxy info, compare them
        if ($ProxyHostValue -or $ProxyPortValue -or $ProxyCredentialValue) {
            if ($ProxyHostValue -and $ServerProxyHost -ne $ProxyHostValue) {
                Write-Verbose "$Prefix ProxyHost mismatch (`"$ServerProxyHost`" vs `"$ProxyHostValue`")"
                $result = $false
            }
            if ($ProxyPortValue -and $ServerProxyPort -ne $ProxyPortValue) {
                Write-Verbose "$Prefix ProxyPort mismatch (`"$ServerProxyPort`" vs `"$ProxyPortValue`")"
                $result = $false
            }
            if ($ProxyCredentialValue) {
                $UserName = $ProxyCredentialValue.UserName
                $Password = $ProxyCredentialValue.GetNetworkCredential().Password

                if ($ServerProxyUser -ne $UserName) {
                    Write-Verbose "$Prefix ProxyUser mismatch (`"$ServerProxyUser`" vs `"$UserName`")"
                    $result = $false
                }
                if ($ServerProxyPassword -ne $Password) {
                    Write-Verbose "$Prefix ProxyPassword mismatch"
                    $result = $false
                }
            }
        }
        # Otherwise, if nothing in JSON but server has a value => mismatch
        elseif ($ServerProxyHost -or $ServerProxyPort -or $ServerProxyUser -or $ServerProxyPassword) {
            Write-Verbose "$Prefix proxy present on server but absent in JSON"
            $result = $false
        }

        if (-not $result) { break }
    }

    # NonProxyHosts
    if ($result) {
        if ($NonProxyHosts) {
            if ($ServerSysProps.NonProxyHosts -ne $NonProxyHosts) {
                Write-Verbose "NonProxyHosts mismatch (`"$($ServerSysProps.NonProxyHosts)`" vs `"$NonProxyHosts`")"
                $result = $false
            }
        }
        elseif ($ServerSysProps.NonProxyHosts) {
            Write-Verbose "NonProxyHosts present on server but absent in JSON"
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
