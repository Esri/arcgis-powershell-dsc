$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.Server.psm1'))

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
    (
        [parameter(Mandatory = $true)]    
        [System.String]
        $ServerHostName,

        [parameter(Mandatory = $true)]    
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer","DataPipelinesServer","VelocityServer")]
        [System.String]
        $ServerType
    )
    
    return @{}
}

function Set-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param(	
        [parameter(Mandatory = $true)]    
        [System.String]
        $ServerHostName,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator,

        [parameter(Mandatory = $true)]
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer","DataPipelinesServer","VelocityServer")]
        [System.String]
        $ServerType, 

        [parameter(Mandatory = $false)]
        [System.String]
        $WebContextURL,    

        [parameter(Mandatory = $false)]
        [System.String]
        $WebSocketContextUrl,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $DisableDockerHealthCheck,
        
        [parameter(Mandatory = $false)]
        [System.Boolean]
        $DisableServiceDirectory,

        [parameter(Mandatory = $false)]
		[System.String]
		$SharedKey,

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
        [System.String]                 
        $HttpsProxyHost,

        [parameter(Mandatory = $false)]
        [AllowNull()]
        [Nullable[System.UInt32]]                
        $HttpsProxyPort,

        [parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]           
        $HttpsProxyCredential,

        [parameter(Mandatory = $false)]
        [System.String]                 
        $NonProxyHosts,

        [parameter(Mandatory = $false)]
        [System.String]                 
        $VideoServerLivestreamGatewayHostname,

        [parameter(Mandatory = $false)]
        [System.String]                 
        $VideoServerLiveStreamPorts
	)
    

    if($VerbosePreference -ine 'SilentlyContinue') 
    {        
        Write-Verbose ("Site Administrator UserName:- " + $SiteAdministrator.UserName) 
    }

    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    Write-Verbose "Server Type:- $ServerType , Fully Qualified Domain Name :- $FQDN"
    
    $ServerBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName $ServerType -FQDN $FQDN
	Write-Verbose "Waiting for Server '$ServerBaseUrl'"
    Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName $ServerType -Verbose
    $Referer = "https://localhost"
    
	$token = Get-ServerToken -URL $ServerBaseUrl -Credential $SiteAdministrator -Referer $Referer
 
    $AdminSettingsModified = $False
    $systemProperties = Get-SystemProperties -URL $ServerBaseUrl -Token $token.token -Referer $Referer
    if($WebContextURL -and (-not($systemProperties.WebContextURL) -or $systemProperties.WebContextURL -ine $WebContextURL)){
        Write-Verbose "Web Context URL '$($systemProperties.WebContextURL)' doesn't match expected value '$WebContextURL'"
        if(-not($systemProperties.WebContextURL)){
            Add-Member -InputObject $systemProperties -MemberType NoteProperty -Name "WebContextURL" -Value $WebContextURL
        }else{
            $systemProperties.WebContextURL = $WebContextURL
        }
        $AdminSettingsModified = $True
    }
    
    if($ServerType -ieq "MissionServer" -and $WebSocketContextUrl -and (-not($systemProperties.WebSocketContextURL) -or $systemProperties.WebSocketContextURL -ine $WebSocketContextUrl)){
        Write-Verbose "Web Socket Context URL '$($systemProperties.WebSocketContextURL)' doesn't match expected value '$WebSocketContextUrl'"
        if(-not($systemProperties.WebSocketContextURL)){
            Add-Member -InputObject $systemProperties -MemberType NoteProperty -Name "WebSocketContextURL" -Value $WebSocketContextUrl
        }else{
            $systemProperties.WebSocketContextURL = $WebSocketContextUrl
        }
        $AdminSettingsModified = $True
    }

    if($ServerType -ine "Server"){
        if($systemProperties.disableServicesDirectory -ine $DisableServiceDirectory){
            if(Get-Member -InputObject $systemProperties -name "disableServicesDirectory" -Membertype NoteProperty){
                $systemProperties.disableServicesDirectory = $DisableServiceDirectory
            }else{
                Add-Member -InputObject $systemProperties -MemberType NoteProperty -Name "disableServicesDirectory" -Value $DisableServiceDirectory
            }
        
            $AdminSettingsModified = $True
        }
    }

    if($ServerType -ieq "NotebookServer" -and $systemProperties.disableDockerHealthCheck -ine $DisableDockerHealthCheck){
        if(Get-Member -InputObject $systemProperties -name "disableDockerHealthCheck" -Membertype NoteProperty){
            $systemProperties.disableDockerHealthCheck = $DisableDockerHealthCheck
        }else{
            Add-Member -InputObject $systemProperties -MemberType NoteProperty -Name "disableDockerHealthCheck" -Value $DisableDockerHealthCheck
        }
        $AdminSettingsModified = $True
    }

    if($ServerType -ieq "VideoServer"){
        if($VideoServerLivestreamGatewayHostname -and (-not($systemProperties.LivestreamGatewayHostname) -or $systemProperties.LivestreamGatewayHostname -ine $VideoServerLivestreamGatewayHostname)){
            Write-Verbose "Video Server Live stream gateway host name '$($systemProperties.LivestreamGatewayHostname)' doesn't match expected value '$VideoServerLivestreamGatewayHostname'"
            if(-not($systemProperties.LivestreamGatewayHostname)){
                Add-Member -InputObject $systemProperties -MemberType NoteProperty -Name "LivestreamGatewayHostname" -Value $VideoServerLivestreamGatewayHostname
            }else{
                $systemProperties.LivestreamGatewayHostname = $VideoServerLivestreamGatewayHostname
            }
            $AdminSettingsModified = $True
        }

        if($VideoServerLiveStreamPorts){
            if(Test-VideoServerLiveStreamPortsNeedsUpdates -URL $ServerBaseUrl -Token $token.token -Referer $Referer -Ports $VideoServerLiveStreamPorts -Verbose){
                Write-Verbose "Video Server live stream ports do not match expected values"
                Set-UpdateVideoServerLivestreamPorts -URL $ServerBaseUrl -Token $token.token -Referer $Referer -Ports $VideoServerLiveStreamPorts -Verbose
                Write-Verbose "Video Server live stream ports updated."
            }
        }
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
        Set-SystemProperties -URL $ServerBaseUrl -Token $token.token -Properties $systemProperties -Referer $Referer

        Write-Verbose "Admin system settings updated."

        Wait-ForArcGISComponentRestart -BaseURL $ServerBaseUrl -ComponentName $ServerType -Verbose
    }
    
    if($ServerType -ieq "Server"){
        Update-ServiceDirectorySettings -URL $ServerBaseUrl -Token $token.token -Referer $Referer -DisableServiceDirectory $DisableServiceDirectory -Verbose

        Update-SecurityTokenSharedKey -URL $ServerBaseUrl -Token $token.token -Referer $Referer -SharedKey $SharedKey
    }
}

function Test-TargetResource
{
    [CmdletBinding()]
	[OutputType([System.Boolean])]
	param(   
        [parameter(Mandatory = $true)]    
        [System.String]
        $ServerHostName,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator,

        [parameter(Mandatory = $true)]
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer","DataPipelinesServer","VelocityServer")]
        [System.String]
        $ServerType, 

        [parameter(Mandatory = $false)]
        [System.String]
        $WebContextURL,    

        [parameter(Mandatory = $false)]
        [System.String]
        $WebSocketContextUrl,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $DisableDockerHealthCheck,
        
        [parameter(Mandatory = $false)]
        [System.Boolean]
        $DisableServiceDirectory,

        [parameter(Mandatory = $false)]
		[System.String]
		$SharedKey,

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

        [parameter(Mandatory = $false)]
        [System.String]                 
        $VideoServerLivestreamGatewayHostname,

        [parameter(Mandatory = $false)]
        [System.String]                 
        $VideoServerLiveStreamPorts
    )

    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    Write-Verbose "Server Type:- $ServerType , Fully Qualified Domain Name :- $FQDN"
    $ServerBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName $ServerType -FQDN $FQDN

	Write-Verbose "Waiting for Server '$ServerBaseUrl' to initialize"
    Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName $ServerType -Verbose
    $Referer = 'https://localhost'
    
    $token = Get-ServerToken -URL $ServerBaseUrl -Credential $SiteAdministrator -Referer $Referer
    $result = ($null -ne $token.token)
    if($result){
        Write-Verbose "Site Exists. Was able to retrieve token for PSA"
    }else{
        throw "Unable to detect if site exists. Unable to retrieve token for PSA"
    }
   
    $result = $true
    $SystemProperties = Get-SystemProperties -URL $ServerBaseUrl -Token $token.token -Referer $Referer
    if($result -and $WebContextURL){    
        if(-not($systemProperties.WebContextURL) -or $systemProperties.WebContextURL -ine $WebContextURL){
            Write-Verbose "Web Context URL '$($systemProperties.WebContextURL)' doesn't match expected value '$WebContextURL'"
            $result = $false
        }
    }
    
    # Only for Mission Server
    if($ServerType -ieq "MissionServer" -and $result -and $WebSocketContextUrl){
        if(-not($systemProperties.WebSocketContextURL) -or $systemProperties.WebSocketContextURL -ine $WebContextURL){
            Write-Verbose "Web Socket Context URL '$($systemProperties.WebSocketContextURL)' doesn't match expected value '$WebSocketContextUrl'"
            $result = $false
        }
    }

    if($result){
        if($ServerType -ieq "Server"){
            $ServiceDirectoryProperties = Get-ServiceDirectorySettings -URL $ServerBaseUrl -Token $token.token -Referer $Referer -Verbose
            Write-Verbose "Service Directory enabled:- $($ServiceDirectoryProperties.enabled)"
            if([System.Convert]::ToBoolean($ServiceDirectoryProperties.enabled) -ine -not($DisableServiceDirectory)) {
                $result = $false
            }
        }else{
            if($systemProperties.disableServicesDirectory -ine $DisableServiceDirectory){
                $result = $false
            }
        }

        if(-not($result)){
            Write-Verbose "DisableServicesDirectory for '$($ServerType)' doesn't match expected value '$DisableServiceDirectory'"
        }
    }

    if($result -and ($ServerType -ieq "Server") -and $SharedKey) {
		Write-Verbose "Get Token and Shared Key setting"
		$CurrentSharedKey = Get-SecurityTokenSharedKey -URL $ServerBaseUrl -Token $token.token -Referer $Referer
        if($CurrentSharedKey.properties.sharedKey -ine $SharedKey){
			Write-Verbose "Shared Key is not set as expected"
			$result = $false
		}else{
			Write-Verbose "Shared Key is set as expected"
		}
    }

    # Only for Notebook Server
    if($result -and ($ServerType -ieq "NotebookServer") -and $systemProperties.DisableDockerHealthCheck -ine $DisableDockerHealthCheck){
        Write-Verbose "DisableDockerHealthCheck setting for Notebook Server doesn't match expected value '$DisableDockerHealthCheck'"
        $result = $false
    }

    if($result -and $ServerType -ieq "VideoServer"){
        if($VideoServerLivestreamGatewayHostname -and (-not($systemProperties.LivestreamGatewayHostname) -or $systemProperties.LivestreamGatewayHostname -ine $VideoServerLivestreamGatewayHostname)){
            Write-Verbose "Video Server Live stream gateway host name '$($systemProperties.LivestreamGatewayHostname)' doesn't match expected value '$VideoServerLivestreamGatewayHostname'"
            $result = $false
        }
        
        if($result -and $VideoServerLiveStreamPorts){
            if(Test-VideoServerLiveStreamPortsNeedsUpdates -URL $ServerBaseUrl -Token $token.token -Referer $Referer -Ports $VideoServerLiveStreamPorts -Verbose){
                Write-Verbose "Video Server live stream ports do not match expected values"
                $result = $false
            }
        }
    }

    if ($result) {
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


Export-ModuleMember -Function *-TargetResource