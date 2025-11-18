$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

<#
    .SYNOPSIS
        Makes a request to the installed Mission Server to set the Web Context & Web Socket URL  
    .PARAMETER ServerHostName
        Optional Host Name or IP of the Machine on which the Mission Server has been installed and is to be configured.
    .PARAMETER WebContextURL
        External Enpoint when using a reverse proxy server and the URL to your site does not end with the default string /arcgis (all lowercase). 
    .PARAMETER WebSocketContextURL
        External WebSocket Enpoint when using a reverse proxy server and the URL to your site does not end with the default string /arcgis (all lowercase). 
    .PARAMETER SiteAdministrator
        A MSFT_Credential Object - Primary Site Administrator
#>
function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
    (
        [parameter(Mandatory = $false)]    
        [System.String]
        $ServerHostName,

        [parameter(Mandatory = $true)]
        [System.String]
        $WebContextURL, 

        [parameter(Mandatory = $false)]
        [System.String]
        $WebSocketContextUrl,   
        
        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator,
        
		[System.Boolean]
        $DisableServiceDirectory
    )
    
    $null
}

function Set-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param(	
        [parameter(Mandatory = $false)]    
        [System.String]
        $ServerHostName,

        [parameter(Mandatory = $true)]
        [System.String]
        $WebContextURL,    

        [parameter(Mandatory = $false)]
        [System.String]
        $WebSocketContextUrl,
        
        [parameter(Mandatory = $true)]
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
        $DisableServiceDirectory
	)
    
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null

    if($VerbosePreference -ine 'SilentlyContinue') 
    {        
        Write-Verbose ("Site Administrator UserName:- " + $SiteAdministrator.UserName) 
    }

    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    Write-Verbose "Fully Qualified Domain Name :- $FQDN"
    $Referer = 'http://localhost'
    $ServerUrl = "https://$($FQDN):20443"
    $ServiceName = Get-ArcGISServiceName -ComponentName 'MissionServer'
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir  
    
	Write-Verbose "Waiting for Server 'https://$($FQDN):20443/arcgis/admin' to initialize"
    Wait-ForUrl "https://$($FQDN):20443/arcgis/admin" -HttpMethod 'GET'
    #Write-Verbose 'Get Server Token'   
    $token = Get-ServerToken -ServerEndPoint "https://$($FQDN):20443" -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer
 
    $AdminSettingsModified = $False
    $systemProperties = Get-AdminSettings -ServerUrl $ServerUrl -SettingUrl "arcgis/admin/system/properties" -Token $token.token
    if($WebContextURL -and (-not($systemProperties.WebContextURL) -or $systemProperties.WebContextURL -ine $WebContextURL)){
        Write-Verbose "Web Context URL '$($systemProperties.WebContextURL)' doesn't match expected value '$WebContextURL'"
        if(-not($systemProperties.WebContextURL)){
            Add-Member -InputObject $systemProperties -MemberType NoteProperty -Name "WebContextURL" -Value $WebContextURL
        }else{
            $systemProperties.WebContextURL = $WebContextURL
        }
        $AdminSettingsModified = $True
    }
    if($WebSocketContextUrl -and (-not($systemProperties.WebSocketContextURL) -or $systemProperties.WebSocketContextURL -ine $WebSocketContextUrl)){
        Write-Verbose "Web Socket Context URL '$($systemProperties.WebSocketContextURL)' doesn't match expected value '$WebSocketContextUrl'"
        if(-not($systemProperties.WebSocketContextURL)){
            Add-Member -InputObject $systemProperties -MemberType NoteProperty -Name "WebSocketContextURL" -Value $WebSocketContextUrl
        }else{
            $systemProperties.WebSocketContextURL = $WebSocketContextUrl
        }
        $AdminSettingsModified = $True
    }

    if($systemProperties.disableServicesDirectory -ine $DisableServiceDirectory){
        if(Get-Member -InputObject $systemProperties -name "disableServicesDirectory" -Membertype NoteProperty){
            $systemProperties.disableServicesDirectory = $DisableServiceDirectory
        }else{
            Add-Member -InputObject $systemProperties -MemberType NoteProperty -Name "disableServicesDirectory" -Value $DisableServiceDirectory
        }
    
        $AdminSettingsModified = $True
    }

    # checking forward proxy settings
	if ($HttpProxyHost) {
		if(-not($systemProperties.HttpProxyHost)) {
			Add-Member -InputObject $systemProperties -MemberType NoteProperty -Name 'httpProxyHost' -Value $HttpProxyHost
		}else{
			$systemProperties.HttpProxyHost = $HttpProxyHost
		}
		$AdminSettingsModified = $true
	}
	elseif ($systemProperties.HttpProxyHost) {
        # JSON removed it, so clear it
        $systemProperties.PSObject.Properties.Remove('httpProxyHost')
        $AdminSettingsModified = $true
    }
	if ($HttpProxyPort) {
		if(-not($systemProperties.HttpProxyPort)) {
			Add-Member -InputObject $systemProperties -MemberType NoteProperty -Name 'httpProxyPort' -Value $HttpProxyPort
		}else{
			$systemProperties.HttpProxyPort = $HttpProxyPort
		}
		$AdminSettingsModified = $true
	}
	elseif ($systemProperties.HttpProxyPort) {
        $systemProperties.PSObject.Properties.Remove('httpProxyPort')
        $AdminSettingsModified = $true
    }
	if ($HttpProxyCredential) {
		if(-not($systemProperties.HttpProxyUser)) {
			Add-Member -InputObject $systemProperties -MemberType NoteProperty -Name 'httpProxyUser' -Value $HttpProxyCredential.UserName
		}else{
			$systemProperties.HttpProxyUser = $HttpProxyCredential.UserName
		}
		if(-not($systemProperties.HttpProxyPassword)) {
			Add-Member -InputObject $systemProperties -MemberType NoteProperty -Name 'httpProxyPassword' -Value $HttpProxyCredential.GetNetworkCredential().Password
		}else{
			$systemProperties.HttpProxyPassword = $HttpProxyCredential.GetNetworkCredential().Password
		}
		$AdminSettingsModified = $true
	}
	elseif ($systemProperties.HttpProxyUser -or $systemProperties.HttpProxyPassword) {
        $systemProperties.PSObject.Properties.Remove('httpProxyUser')
        $systemProperties.PSObject.Properties.Remove('httpProxyPassword')
        $AdminSettingsModified = $true
    }
	# Forward proxy HTTPS Proxy: set or clear
	if ($HttpsProxyHost) {
		if(-not($systemProperties.HttpsProxyHost)) {
			Add-Member -InputObject $systemProperties -MemberType NoteProperty -Name 'httpsProxyHost' -Value $HttpsProxyHost
		}else{
			$systemProperties.HttpsProxyHost = $HttpsProxyHost
		}
		$AdminSettingsModified = $true
	}
	elseif ($systemProperties.HttpsProxyHost) {
        # JSON removed it, so clear it
        $systemProperties.PSObject.Properties.Remove('httpsProxyHost')
        $AdminSettingsModified = $true
    }
	if ($HttpsProxyPort) {
		if(-not($systemProperties.HttpsProxyPort)) {
			Add-Member -InputObject $systemProperties -MemberType NoteProperty -Name 'httpsProxyPort' -Value $HttpsProxyPort
		}else{
			$systemProperties.HttpsProxyPort = $HttpsProxyPort
		}
		$AdminSettingsModified = $true
	}
	elseif ($systemProperties.HttpsProxyPort) {
        $systemProperties.PSObject.Properties.Remove('httpsProxyPort')
        $AdminSettingsModified = $true
    }
	if ($HttpsProxyCredential) {
		if(-not($systemProperties.HttpsProxyUser)) {
			Add-Member -InputObject $systemProperties -MemberType NoteProperty -Name 'httpsProxyUser' -Value $HttpsProxyCredential.UserName
		}else{
			$systemProperties.HttpsProxyUser = $HttpsProxyCredential.UserName
		}
		if(-not($systemProperties.HttpsProxyPassword)) {
			Add-Member -InputObject $systemProperties -MemberType NoteProperty -Name 'httpsProxyPassword' -Value $HttpsProxyCredential.GetNetworkCredential().Password
		}else{
			$systemProperties.HttpsProxyPassword = $HttpsProxyCredential.GetNetworkCredential().Password
		}
		$AdminSettingsModified = $true
	}
	elseif ($systemProperties.HttpsProxyUser -or $systemProperties.HttpsProxyPassword) {
        $systemProperties.PSObject.Properties.Remove('httpsProxyUser')
        $systemProperties.PSObject.Properties.Remove('httpsProxyPassword')
        $AdminSettingsModified = $true
    }

	if ($NonProxyHosts) {
		if(-not($systemProperties.NonProxyHosts)) {
			Add-Member -InputObject $systemProperties -MemberType NoteProperty -Name 'nonProxyHosts' -Value $NonProxyHosts
		}else{
			$systemProperties.NonProxyHosts = $NonProxyHosts
		}
		$AdminSettingsModified = $true
	}
	elseif ($systemProperties.NonProxyHosts) {
        $systemProperties.PSObject.Properties.Remove('nonProxyHosts')
        $AdminSettingsModified = $true
    }

    if($AdminSettingsModified){
        Set-AdminSettings -ServerUrl $ServerUrl -SettingUrl "arcgis/admin/system/properties/update" -Token $token.token -Properties $systemProperties

        $MaxWaitTimeInSeconds = 120
        $SleepTimeInSeconds = 10
        $TotalElapsedTimeInSeconds = 0
        Write-Verbose "Waiting for up to $($MaxWaitTimeInSeconds) seconds for mission server to restart"
        while(-not($Done) -and ($TotalElapsedTimeInSeconds -lt $MaxWaitTimeInSeconds)){
            try{
                # if available sleep and try again.
                Wait-ForUrl "$($ServerUrl)/arcgis/rest/info/healthcheck/?f=json" -MaxWaitTimeInSeconds 10 -HttpMethod 'GET' -ThrowErrors
                Write-Verbose "Mission web server is still available. Trying again in $($SleepTimeInSeconds) seconds"
                Start-Sleep -Seconds $SleepTimeInSeconds
                $TotalElapsedTimeInSeconds += $SleepTimeInSeconds
            }catch{
                # if error and most likely mission server has become unavailable then exit loop
                Write-Verbose "Mission server is likely restarting as result of update of system properties:- $($_)"
                $Done = $true
            }
        }
        
        Write-Verbose "Waiting up to 6 minutes for mission server healtcheck endpoint '$($ServerUrl)/arcgis/rest/info/healthcheck' to come back up"
        Wait-ForUrl "$($ServerUrl)/arcgis/rest/info/healthcheck/?f=json" -MaxWaitTimeInSeconds 360 -HttpMethod 'GET' -Verbose
        Write-Verbose "Finished waiting for mission server healtcheck endpoint '$($ServerUrl)/arcgis/rest/info/healthcheck' to come back up"
    }    
}

function Test-TargetResource
{
    [CmdletBinding()]
	[OutputType([System.Boolean])]
	param(   
        [parameter(Mandatory = $false)]    
        [System.String]
        $ServerHostName,
        
        [parameter(Mandatory = $true)]
        [System.String]
        $WebContextURL,

        [parameter(Mandatory = $false)]
        [System.String]
        $WebSocketContextUrl,
        
        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator,

        [parameter(Mandatory = $false)]
        [System.String]                
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
        $DisableServiceDirectory
    )

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    Write-Verbose "Fully Qualified Domain Name :- $FQDN" 
    $Referer = 'http://localhost'
    $ServerUrl = "https://$($FQDN):20443"
    Write-Verbose "Checking for site on '$ServerUrl'"
    Wait-ForUrl -Url $ServerUrl -SleepTimeInSeconds 5 -HttpMethod 'GET'
    $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer 
    $result = ($null -ne $token.token)
    if($result){
        Write-Verbose "Site Exists. Was able to retrieve token for PSA"
    }else{
        throw "Unable to detect if Site Exists. Was NOT able to retrieve token for PSA"
    }
   
    $result = $true
    $systemProperties = Get-AdminSettings -ServerUrl $ServerUrl -SettingUrl "arcgis/admin/system/properties/" -Token $token.token
    if($result){
        if($WebContextURL){
            if(-not($systemProperties.WebContextURL) -or $systemProperties.WebContextURL -ine $WebContextURL){
                Write-Verbose "Web Context URL '$($systemProperties.WebContextURL)' doesn't match expected value '$WebContextURL'"
                $result = $false
            }
        }
        
        if($result -and $WebSocketContextUrl){
            if(-not($systemProperties.WebSocketContextURL) -or $systemProperties.WebSocketContextURL -ine $WebContextURL){
                Write-Verbose "Web Socket Context URL '$($systemProperties.WebSocketContextURL)' doesn't match expected value '$WebSocketContextUrl'"
                $result = $false
            }
        }
    }

    if($result -and $systemProperties.disableServicesDirectory -ine $DisableServiceDirectory){
        Write-Verbose "DisableServicesDirectory for Mission Server doesn't match expected value '$DisableServiceDirectory'"
        $result = $false
    }
    #--- begin proxy test block ---
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
        $ServerProxyHost        = $systemProperties."${Prefix}ProxyHost"
        $ServerProxyPort        = $systemProperties."${Prefix}ProxyPort"
        $ServerProxyUser        = $systemProperties."${Prefix}ProxyUser"
        $ServerProxyPassword    = $systemProperties."${Prefix}ProxyPassword"

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
            if ($systemProperties.NonProxyHosts -ne $NonProxyHosts) {
                Write-Verbose "NonProxyHosts mismatch (`"$($systemProperties.NonProxyHosts)`" vs `"$NonProxyHosts`")"
                $result = $false
            }
        }
        elseif ($systemProperties.NonProxyHosts) {
            Write-Verbose "NonProxyHosts present on server but absent in JSON"
            $result = $false
        }
    }

    $result
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
        $Token
    )
    $RequestParams = @{ f= 'json'; token = $Token; }
    $RequestUrl  = $ServerUrl.TrimEnd("/") + "/" + $SettingUrl.TrimStart("/")
    $Response = Invoke-ArcGISWebRequest -Url $RequestUrl -HttpFormParameters $RequestParams
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
        
        $Properties
    )
    $RequestUrl  = $ServerUrl.TrimEnd("/") + "/" + $SettingUrl.TrimStart("/")
    $RequestParams = @{ f= 'json'; token = $Token; properties = ( $Properties | ConvertTo-Json -Depth 5 -Compress ) }
    $Response = Invoke-ArcGISWebRequest -Url $RequestUrl -HttpFormParameters $RequestParams
    if($response.status -ieq "success"){
        Write-Verbose "Admin Settings Update Successfully"
    }else{
        Write-Verbose "[WARNING]: Code:- $($response.error.code), Error:- $($response.error.message)" 
    }
}


Export-ModuleMember -Function *-TargetResource
