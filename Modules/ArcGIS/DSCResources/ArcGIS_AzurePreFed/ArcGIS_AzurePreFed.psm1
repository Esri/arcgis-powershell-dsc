function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
        [parameter(Mandatory = $true)]
		[System.String]
		$PortalContext,

		[parameter(Mandatory = $true)]
		[System.String]
        $ServerContext,
        
        [parameter(Mandatory = $true)]
		[System.String]
		$ServerHostName,

		[parameter(Mandatory = $true)]
		[System.String]
		$ExternalDNSName,

	    [parameter(Mandatory = $true)]
		[System.String]
		$PortalHostName,

		[System.String]
		$ServerEndPoint,

		[System.String]
		$PortalEndPoint,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

		[System.Management.Automation.PSCredential]
		$PortalAdministrator
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

	$null
}


function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
        [parameter(Mandatory = $true)]
		[System.String]
		$PortalContext,

		[parameter(Mandatory = $true)]
		[System.String]
        $ServerContext,
        
        [parameter(Mandatory = $true)]
		[System.String]
		$ServerHostName,

		[parameter(Mandatory = $true)]
		[System.String]
		$ExternalDNSName,

	    [parameter(Mandatory = $true)]
		[System.String]
		$PortalHostName,

		[System.String]
		$ServerEndPoint,

		[System.String]
		$PortalEndPoint,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

		[System.Management.Automation.PSCredential]
		$PortalAdministrator
    )
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

	[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	$ServerFQDN = Get-FQDN $ServerHostName
    $Referer = "https://$($ExternalDNSName)/$($ServerContext)"
    Write-Verbose "Getting Server Token for user '$($SiteAdministrator.UserName)' from 'https://$($ServerFQDN):6443'"

    $serverToken = Get-ServerToken -ServerEndPoint "https://$($ServerFQDN):6443" -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer
    if(-not($serverToken.token)) {
        Write-Verbose "Get Server Token Response:- $serverToken"
        throw "Unable to retrieve Server Token for '$($SiteAdministrator.UserName)'"
    }
    Write-Verbose "Connected to Server successfully and retrieved token for '$($SiteAdministrator.UserName)'"
    if(-not($ServerEndPoint -as [ipaddress])) {
		$ServerEndPoint = Get-FQDN $ServerEndPoint
	}
    Set-WAWCServerProperties -ServerHostName $ServerHostName -ServerContext $ServerContext -ExternalDNSName $ExternalDNSName -ServerEndPoint $ServerEndPoint `
                                -Token $serverToken.token -Referer $Referer -Verbose
    
    $PortalFQDN = Get-FQDN $PortalHostName
    Write-Verbose "Getting Portal Token for user '$($PortalAdministrator.UserName)' from 'https://$($PortalFQDN):7443'"

    $PortalToken = Get-PortalToken -PortalHostName $PortalFQDN -Port 7443 -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
    if(-not($PortalToken.token)) {
        throw "Unable to retrieve Portal Token for '$($PortalAdministrator.UserName)'"
    }else {
		Write-Verbose "Retrieved Portal Token"
	}
    Write-Verbose "Connected to Portal successfully and retrieved token for '$($PortalAdministrator.UserName)'"

	if(-not($PortalEndPoint -as [ipaddress])) {
		$PortalEndPoint = Get-FQDN $PortalEndPoint
    }
    
    Set-WCPPWAPortalProperties -PortalHostName $PortalFQDN -ExternalDNSName $ExternalDNSName -PortalEndPoint $PortalEndPoint -PortalContext $PortalContext `
                                -Token $PortalToken.token -Referer $Referer -Verbose
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [parameter(Mandatory = $true)]
		[System.String]
		$PortalContext,

		[parameter(Mandatory = $true)]
		[System.String]
		$ServerContext,

        [parameter(Mandatory = $true)]
		[System.String]
		$ServerHostName,

		[parameter(Mandatory = $true)]
		[System.String]
		$ExternalDNSName,

	    [parameter(Mandatory = $true)]
		[System.String]
		$PortalHostName,

		[System.String]
		$ServerEndPoint,

		[System.String]
		$PortalEndPoint,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

		[System.Management.Automation.PSCredential]
		$PortalAdministrator
    )
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

	[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	$ServerFQDN = Get-FQDN $ServerHostName
    $ServerHttpsUrl = "https://$($ServerFQDN):6443" 
    $Referer = $ServerHttpsUrl	
    Write-Verbose "Getting Server Token for user '$($SiteAdministrator.UserName)' from 'https://$($ServerFQDN):6443'"

    $serverToken = Get-ServerToken -ServerEndPoint "https://$($ServerFQDN):6443" -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer
    if(-not($serverToken.token)) {
        Write-Verbose "Get Server Token Response:- $serverToken"
        throw "Unable to retrieve Server Token for '$($SiteAdministrator.UserName)'"
    }
    Write-Verbose "Connected to Server successfully and retrieved token for '$($SiteAdministrator.UserName)'"
    if(-not($ServerEndPoint -as [ipaddress])) {
		$ServerEndPoint = Get-FQDN $ServerEndPoint
	}
    
    $result = Test-WAWCServerProperties -ServerHostName $ServerHostName -ServerContext $ServerContext -ExternalDNSName $ExternalDNSName `
                                        -ServerEndPoint $ServerEndPoint -Token $serverToken.token -Referer $Referer -Verbose

    if($result) {
        $PortalFQDN = Get-FQDN $PortalHostName
        Write-Verbose "Getting Portal Token for user '$($PortalAdministrator.UserName)' from 'https://$($PortalFQDN):7443'"

        $PortalToken = Get-PortalToken -PortalHostName $PortalFQDN -Port 7443 -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
        if(-not($PortalToken.token)) {
            throw "Unable to retrieve Portal Token for '$($PortalAdministrator.UserName)'"
        }else {
            Write-Verbose "Retrieved Portal Token"
        }
        Write-Verbose "Connected to Portal successfully and retrieved token for '$($PortalAdministrator.UserName)'"

        if(-not($PortalEndPoint -as [ipaddress])) {
            $PortalEndPoint = Get-FQDN $PortalEndPoint
        }

        $result = Test-WCPPWAPortalProperties -PortalHostName $PortalHostName -ExternalDNSName $ExternalDNSName -PortalEndPoint $PortalEndPoint `
                                                -PortalContext $PortalContext -Token $PortalToken.token -Referer $Referer -Verbose
    }

    if($Ensure -ieq 'Present') {
	    $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}

function Get-SecurityConfig 
{
    [CmdletBinding()]
    param(
        [System.String]
		$ServerURL, 

        [System.String]
		$SiteName, 

        [System.String]
		$Token, 

        [System.String]
		$Referer
    ) 

    $GetSecurityConfigUrl  = $ServerURL.TrimEnd("/") + "/$SiteName/admin/security/config/"
	Invoke-ArcGISWebRequest -Url $GetSecurityConfigUrl -HttpFormParameters  @{ f= 'json'; token = $Token } -Referer $Referer -TimeoutSec 30    
}

function Get-PortalAdminRoot
{
    [CmdletBinding()]
    param(
      [System.String]
	  $PortalHostName,

      [System.String]
	  $SiteName, 
      
	  [System.String]
	  $Token, 

      [System.String]
	  $Referer
    )

    $PortalAdminRootUrl = "https://$($PortalHostName):7443/$SiteName/portaladmin/"
	Invoke-ArcGISWebRequest -Url $PortalAdminRootUrl -HttpFormParameters  @{ f= 'json'; token = $Token } -Referer $Referer -TimeoutSec 30 -HttpMethod 'GET'    
}

function Update-SecurityConfigForServer
{
    [CmdletBinding()]
    param(
        [System.String]
		$ServerLocalHttpsEndpoint, 

        [System.String]
		$PortalSiteName, 

        [System.String]
		$ServerSiteName, 

        [System.String]
		$ServerUrl,

        [System.String]
		$PortalUrl, 

        [System.String]
		$PrivatePortalUrl,  

        [System.String]
		$PortalSecretKey,

        [System.String]
		$ServerId,  

        [System.String]
		$ServerSpecificToken, 

        [System.String]
		$Referer, 

        [System.String]
		$ServerToken, 

        [System.Int32]
		$MaxAttempts = 5
	) 

    $portalProperties = @{
        portalUrl= $PortalUrl
  		privatePortalUrl= $PrivatePortalUrl
  		portalSecretKey= $PortalSecretKey
  		portalMode= 'ARCGIS_PORTAL_FEDERATION'
        serverId = $ServerId
        serverUrl = $ServerUrl
        token = $ServerSpecificToken
        referer = $Referer
   }

    Write-Verbose "Portal Props:- serverUrl:- $($portalProperties.serverUrl) portalUrl:- $($portalProperties.portalUrl) privatePortalUrl:- $($portalProperties.privatePortalUrl)"
    
    $securityConfig = @{
        authenticationTier = 'ARCGIS_PORTAL'
        portalProperties = $portalProperties
    }
        
    $WebParams = @{ securityConfig = ConvertTo-Json $securityConfig -Depth 5 -Compress                   
                    token = $ServerToken
                    f = 'json'
                  } 
    
    $UpdateConfigUrl = "$ServerLocalHttpsEndpoint/$ServerSiteName/admin/security/config/update" 	

    $Done = $false
    $NumAttempts = 1
    while(-not($Done) -and ($NumAttempts -lt $MaxAttempts)) {
        try {
            Write-Verbose "Update Security Config"
			if($NumAttempts -gt 1) {
				Write-Verbose "Attempt $NumAttempts"
			}
			$response = Invoke-ArcGISWebRequest -Url $UpdateConfigUrl -HttpFormParameters $WebParams -Referer $Referer  
            if($response) {
                Write-Verbose $response
            }
            $Done = $true
        }
        catch {
            if($NumAttempts -ge $MaxAttempts){
                throw $_
            }
            Write-Verbose "[WARNING] Update Security Config Attempt $NumAttempts failed $($_). Retrying after 60 seconds"
            Start-Sleep -Seconds 30 # Try again after 60 seconds
        }
        $NumAttempts++
    }    
    if(-not($Done) -and $response){
        # Throw an exception if we were not able to update config
        Check-ResponseStatus $response -Url $UpdateConfigUrl
    }
}

function Register-ServerOnPortal
{
    [CmdletBinding()]
    param(
        [System.String]
		$PortalHttpsUrl, 

        [System.String]
		$SiteName, 

        [System.String]
		$Token, 

        [System.String]
		$Referer,

        [System.String]
		$ServerUrl, 

        [System.String]
		$ServerSiteAdminUrl, 

        [System.Boolean]
		$IsHosted
	)

    [Uri]$ServerUri = [System.String]$ServerUrl
    $WebParams = @{ name = $ServerUri.Host
                    url = $ServerUrl                    
                    adminUrl = $ServerSiteAdminUrl
                    isHosted = $IsHosted.ToString().ToLowerInvariant()
                    serverType = 'ArcGIS'
                    token = $Token
                    f = 'json'
                  }    
    
    $RegisterServerUrl = $PortalHttpsUrl.TrimEnd('/') + "/$SiteName/sharing/rest/portals/self/servers/register"  
	Invoke-ArcGISWebRequest -Url $RegisterServerUrl -HttpFormParameters $WebParams -Referer $Referer         
}

function Get-PortalId 
{
    [CmdletBinding()]
    param(
		[System.String]
		$PortalHttpsUrl, 

		[System.String]
		$SiteName, 

		[System.String]
		$Token, 

		[System.String]
		$Referer
    )

    $PortalSelfCall = $PortalHttpsUrl.TrimEnd('/') + "/$SiteName/sharing/portals/self"  
	Invoke-ArcGISWebRequest -Url $PortalSelfCall -HttpFormParameters @{ token = $Token; f = 'json' } -Referer $Referer             
}

function UnRegister-Server 
{
    [CmdletBinding()]
    param(
        [System.String]
		$PortalHttpsUrl, 

		[System.String]
		$SiteName, 

		[System.String]
		$Token, 

		[System.String]
		$Referer, 

        [System.String]
		$ServerId
	)

    $WebParams = @{ token = $Token
                    f = 'json'
                  } 
    
    $PortalSelfResponse = Get-PortalId -PortalHttpsUrl $PortalHttpsUrl -SiteName $SiteName -Token $Token -Referer $Referer
    $PortalId = $PortalSelfResponse.id
    if(!$PortalId) {
        throw "Unable to retrieve portal id for portal at '$PortalHttpsUrl'"
    }

    $UnRegisterServerUrl = $PortalHttpsUrl.TrimEnd('/') + "/$SiteName/sharing/portals/$PortalId/servers/$ServerId/unregister" 
	Invoke-ArcGISWebRequest -Url $UnRegisterServerUrl -HttpFormParameters @{ token = $Token; f = 'json' } -Referer $Referer           
}

function Get-ServerScopedToken 
{
    [CmdletBinding()]
    param(
            [System.String]
			$PortalHttpsUrl, 

			[System.String]
			$SiteName, 

			[System.String]
			$Token, 

			[System.String]
			$Referer, 

            [System.String]
			$ServerUrl
    )

    $WebParams = @{ serverURL = $ServerUrl                   
                    token = $Token
                    f = 'json'                    
                  } 
    
    $RegisterServerUrl = $PortalHttpsUrl.TrimEnd('/') + "/$SiteName/sharing/rest/generateToken"  
	Invoke-ArcGISWebRequest -Url $RegisterServerUrl -HttpFormParameters $WebParams -Referer $Referer           
}


function Get-ServiceProperties
{
    [CmdletBinding()]
    param(
        [System.String]
		$ServerURL, 

        [System.String]
		$SiteName, 

        [System.String]
		$Token, 

        [System.String]
		$Referer, 

        [System.String]
		$ServicePath
    )

    $GetServicePropsUrl  = $ServerURL.TrimEnd("/") + "/$SiteName/admin/services/$ServicePath"
	Invoke-ArcGISWebRequest -Url $GetServicePropsUrl -HttpFormParameters @{ token = $Token; f = 'json' } -Referer $Referer   
}


function Import-ServicesIntoPortal
{    
    [CmdletBinding()]
    param(
        [System.String]
		$ServerURL, 

        [System.String]
		$SiteName, 

        [System.String]
		$Token, 

        [System.String]
		$Referer, 

        [System.Int32]
		$MaxAttempts = 3
    )

    $FederateUrl  = $ServerURL.TrimEnd("/") + "/$SiteName/admin/services/federate"
	
                
   [bool]$Done = $false
   [int]$NumAttempts = 1
   while(-not($Done)) 
   {
        [bool]$failed = $false
        Write-Verbose "Import Services Attempt $NumAttempts"
        try 
        {
             Invoke-ArcGISWebRequest -Url $FederateUrl -HttpFormParameters @{ token = $Token; f = 'json' } -Referer $Referer  
        }
        catch
        {
            $failed = $true
        }
        if($failed -or $response.error){ 
            if($NumAttempts -ge $MaxAttempts) {
                throw "Import Services Failed after multiple attempts. $($response.error)"
            }else{
                Write-Verbose "Attempt [$NumAttempts] Failed. Retrying after 30 seconds"
                Start-Sleep -Seconds 30
            } 
        }else {
            $Done = $true
        }         
        $NumAttempts++
   }
   $response
}

Export-ModuleMember -Function *-TargetResource