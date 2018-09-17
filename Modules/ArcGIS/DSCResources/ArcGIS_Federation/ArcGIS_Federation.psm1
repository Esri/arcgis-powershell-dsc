<#
    .SYNOPSIS
        Federates a Server with an existing Portal.
    .PARAMETER Ensure
        Indicates if the federation or unfedration of a GIS Server with a portal will take place. Take the values Present or Absent. 
        - "Present" ensures that of GIS Server is federated with a portal, if not so, federation takes place.
        - "Absent" ensures that GIS Server is not federated with a portal.
    .PARAMETER PortalHostName
        Host Name of the Portal on which request to federate is made
    .PARAMETER PortalPort
        Port of the Portal on which request to federate is made
    .PARAMETER PortalContext
        Context of the Portal on which request to federate is made
    .PARAMETER ServiceUrlHostName
        Host Name of the Server on which request to federate is made
    .PARAMETER ServiceUrlPort
        Port of the Server on which request to federate is made
    .PARAMETER ServiceUrlContext
         Context of the Server on which request to federate is made
    .PARAMETER ServerSiteAdminUrlHostName
        Host Name of the Server URL on which the Server Admin is to be accessed
    .PARAMETER ServerSiteAdminUrlPort
        Port of the Server URL on which the Server Admin is to be accessed
    .PARAMETER ServerSiteAdminUrlContext
        Context of the Server URL on which the Server Admin is to be accessed
    .PARAMETER RemoteSiteAdministrator
        A MSFT_Credential Object - Initial Administrator Account
    .PARAMETER SiteAdministrator
        A MSFT_Credential Object - Primary Site Administrator
    .PARAMETER ServerFunctions
        Server Function of the Federate server - (GeoAnalytics, RasterAnalytics) - Add more 
    .PARAMETER ServerRole
        Role of the Federate server - (HOSTING_SERVER, FEDERATED_SERVER)
#>

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$PortalHostName,

        [parameter(Mandatory = $true)]
		[System.String]
        $ServiceUrlHostName
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

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
        $PortalHostName,
        
        [parameter(Mandatory = $false)]
		[System.String]
		$PortalPort = 7443,

        [parameter(Mandatory = $false)]
		[System.String]
        $PortalContext='arcgis',

        [parameter(Mandatory = $true)]
		[System.String]
        $ServiceUrlHostName,
        
        [parameter(Mandatory = $false)]
		[System.String]
		$ServiceUrlPort = 443,

        [parameter(Mandatory = $false)]
		[System.String]
        $ServiceUrlContext='arcgis',

        [parameter(Mandatory = $true)]
		[System.String]
        $ServerSiteAdminUrlHostName,
        
        [parameter(Mandatory = $false)]
		[System.String]
		$ServerSiteAdminUrlPort = 6443,

        [parameter(Mandatory = $false)]
		[System.String]
        $ServerSiteAdminUrlContext='arcgis',

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$RemoteSiteAdministrator,

		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

        [parameter(Mandatory = $false)]
		[System.String] 
        $ServerFunctions = '',

        [parameter(Mandatory = $false)]
		[System.String] 
        $ServerRole
	)
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    $ServiceUrl = "https://$($ServiceUrlHostName):$($ServiceUrlPort)/$ServiceUrlContext"
    if($ServiceUrlPort -eq 443){
        "https://$($ServiceUrlHostName)/$ServiceUrlContext" 
    }
    $ServerSiteAdminUrl = "https://$($ServerSiteAdminUrlHostName):$($ServerSiteAdminUrlPort)/$ServerSiteAdminUrlContext"            
	if($ServerSiteAdminUrlPort -eq 443){
        $ServerSiteAdminUrl = "https://$($ServerSiteAdminUrlHostName)/$ServerSiteAdminUrlContext"  
    }
    $ServerHostName = $ServerSiteAdminUrlHostName
    $ServerContext = $ServerSiteAdminUrlContext

	[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null	    
    Write-Verbose "Get Portal Token from Deployment '$PortalHostName'"
    $Referer = "https://$($PortalHostName)/$PortalContext"
    $waitForToken = $true
    $waitForTokenCounter = 0 
    while ($waitForToken -and $waitForTokenCounter -lt 25) {
        $waitForTokenCounter++
        try{
            $token = Get-PortalToken -PortalHostName $PortalHostName -Port $PortalPort -SiteName $PortalContext -Credential $RemoteSiteAdministrator -Referer $Referer
        } catch {
            Write-Verbose "Error getting Token for Federation ! Waiting for 1 Minutes to try again"
            Start-Sleep -Seconds 60
        }
        if($token.token) {    
            $waitForToken = $false
        }
    }
    if(-not($token.token)) {
        throw "Unable to retrieve Portal Token for '$($RemoteSiteAdministrator.UserName)' from Deployment '$PortalHostName'"
    }

    Write-Verbose "Site Admin Url:- $ServerSiteAdminUrl Service Url:- $ServiceUrl"

    $result = $false
    $fedServers = Get-FederatedServers -PortalHostName $PortalHostName -SiteName $PortalContext -Port $PortalPort -Token $token.token -Referer $Referer    
	$fedServer = $fedServers.servers | Where-Object { $_.url -ieq $ServiceUrl -and $_.adminUrl -ieq $ServerSiteAdminUrl }
    if($fedServer) {
        Write-Verbose "Federated Server with Admin URL $ServerSiteAdminUrl already exists"
        $result = $true
    }else {
        Write-Verbose "Federated Server with Admin URL $ServerSiteAdminUrl does not exist"
    }

    if($result) {
        $oauthApp = Get-OAuthApplication -PortalHostName $PortalHostName -SiteName $PortalContext -Token $token.token -Port $PortalPort -Referer $Referer 
        Write-Verbose "Current list of redirect Uris:- $($oauthApp.redirect_uris)"
        $DesiredDomainForRedirect = "https://$($ServerHostName)"
        if(-not($oauthApp.redirect_uris -icontains $DesiredDomainForRedirect)){
            Write-Verbose "Redirect Uri for $DesiredDomainForRedirect does not exist"
            $result = $false
        }else {
            Write-Verbose "Redirect Uri for $DesiredDomainForRedirect exists as required"
        }        
    }    

    if($result -and ($ServerFunctions -or $ServerRole)) {
        Write-Verbose "Get Server Functions Configuration for https://$($ServerHostName)"
        $serverToken = Get-ServerToken -ServerEndPoint "https://$($ServerHostName):$($ServerSiteAdminUrlPort)" -ServerSiteName $ServerContext -Credential $SiteAdministrator -Referer $Referer
        $securityConfig = Invoke-ArcGISWebRequest -Url "$ServerSiteAdminUrl/admin/security/config" -HttpFormParameters @{ f= 'json'; token = $serverToken.token } -Referer $Referer -HttpMethod 'GET' 
        $serverId = $securityConfig.portalProperties.serverId  
        
        if($securityConfig.serverRole -ine $ServerRole) {
            Write-Verbose "Server Role '$($securityConfig.serverRole)' does not match desired value '$ServerRole'"
            $result = $false
        }else {
            Write-Verbose "Server Role '$($securityConfig.serverRole)' matches desired value '$ServerRole'"
        }
        
        if($result -and $ServerFunctions){
            if($securityConfig.serverFunction -ine $ServerFunctions) {
                Write-Verbose "Server Function '$($securityConfig.serverFunction)' does not match desired value '$ServerFunctions'"
                $result = $false
            }else {
                Write-Verbose "Server Function '$($securityConfig.serverFunction)' matches desired value '$ServerFunctions'"
            }
        }else{
            if($result -and $securityConfig.serverFunction){
                Write-Verbose "Server Function '$($securityConfig.serverFunction)' does not match desired value '$ServerFunctions'"
                $result = $false
            }else{
                Write-Verbose "Server Function '$($securityConfig.serverFunction)' matches desired value '$ServerFunctions'"
            }
        }

        if($result) {
            Write-Verbose "Server Function for federated server with id '$($fedServer.id)' :- $($fedServer.serverRole)"
            if($fedServer.serverRole -ine $ServerRole) {
                Write-Verbose "Server ServerRole for Federated Server with id '$($fedServer.id)' does not match desired value '$ServerRole'"
                $result = $false
            }
            else {
                Write-Verbose "Server ServerRole for Federated Server with id '$($fedServer.id)' matches desired value '$ServerRole'"
            }
            
            Write-Verbose "Server Function for federated server with id '$($fedServer.id)' :- $($fedServer.serverFunction)"
            if($fedServer.serverFunction -ine $ServerFunctions) {
                Write-Verbose "Server Functions for Federated Server with id '$($fedServer.id)' does not match desired value '$ServerFunctions'"
                $result = $false
            }
            else {
                Write-Verbose "Server Functions for Federated Server with id '$($fedServer.id)' matches desired value '$ServerFunctions'"
            }
        }
    }    

    if($Ensure -ieq 'Present') {
	       $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }    
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
        [parameter(Mandatory = $true)]
		[System.String]
        $PortalHostName,
        
        [parameter(Mandatory = $false)]
		[System.Int32]
		$PortalPort = 7443,

        [parameter(Mandatory = $false)]
		[System.String]
        $PortalContext='arcgis',

        [parameter(Mandatory = $true)]
		[System.String]
        $ServiceUrlHostName,
        
        [parameter(Mandatory = $false)]
		[System.Int32]
		$ServiceUrlPort = 443,

        [parameter(Mandatory = $false)]
		[System.String]
        $ServiceUrlContext='arcgis',

        [parameter(Mandatory = $true)]
		[System.String]
        $ServerSiteAdminUrlHostName,
        
        [parameter(Mandatory = $false)]
		[System.Int32]
		$ServerSiteAdminUrlPort = 6443,

        [parameter(Mandatory = $false)]
		[System.String]
        $ServerSiteAdminUrlContext='arcgis',
        
        [ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$RemoteSiteAdministrator,

		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

        [parameter(Mandatory = $false)]
		[System.String] 
        $ServerFunctions = '',

        [parameter(Mandatory = $false)]
		[System.String] 
        $ServerRole
    )

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null	 
    
    $ServiceUrl = "https://$($ServiceUrlHostName):$($ServiceUrlPort)/$ServiceUrlContext"
    if($ServiceUrlPort -eq 443){
        $ServiceUrl = "https://$($ServiceUrlHostName)/$ServiceUrlContext" 
    }
    $ServerSiteAdminUrl = "https://$($ServerSiteAdminUrlHostName):$($ServerSiteAdminUrlPort)/$ServerSiteAdminUrlContext"  
    if($ServerSiteAdminUrlPort -eq 443){
        $ServerSiteAdminUrl = "https://$($ServerSiteAdminUrlHostName)/$ServerSiteAdminUrlContext"  
    }
    $ServerHostName = $ServerSiteAdminUrlHostName
    $ServerContext = $ServerSiteAdminUrlContext

    Write-Verbose "Get Portal Token from Deployment '$PortalHostName'"
    $Referer = "https://$($PortalHostName):$($PortalPort)/$PortalContext"
    $waitForToken = $true
    $waitForTokenCounter = 0 
    while ($waitForToken -and $waitForTokenCounter -lt 25) {
        $waitForTokenCounter++
        try{
            $token = Get-PortalToken -PortalHostName $PortalHostName -Port $PortalPort -SiteName $PortalContext -Credential $RemoteSiteAdministrator -Referer $Referer
        } catch {
            Write-Verbose "Error getting Token for Federation ! Waiting for 1 Minutes to try again"
            Start-Sleep -Seconds 60
        }
        if($token.token) {    
            $waitForToken = $false
        }
    }
    if(-not($token.token)) {
        throw "Unable to retrieve Portal Token for '$($RemoteSiteAdministrator.UserName)' from Deployment '$PortalHostName'"
    }

    Write-Verbose "Site Admin Url:- $ServerSiteAdminUrl Service Url:- $ServiceUrl"

    if($Ensure -eq "Present"){        
        $fedServers = Get-FederatedServers -PortalHostName $PortalHostName -SiteName $PortalContext -Port $PortalPort -Token $token.token -Referer $Referer    
        $fedServer = $fedServers.servers | Where-Object { $_.url -ieq $ServiceUrl -and $_.adminUrl -ieq $ServerSiteAdminUrl }
        if(-not($fedServer)) {        
            Write-Verbose "Federated Server with Admin URL $ServerSiteAdminUrl does not exist"
            Federate-Server -PortalHostName $PortalHostName -SiteName $PortalContext -Port $PortalPort -PortalToken $token.token -Referer $Referer `
                            -ServerServiceUrl $ServiceUrl -ServerAdminUrl $ServerSiteAdminUrl -ServerAdminCredential $SiteAdministrator
        }else {
            Write-Verbose "Federated Server with Admin URL $ServerSiteAdminUrl already exists"
        }

        $oauthApp = Get-OAuthApplication -PortalHostName $PortalHostName -SiteName $PortalContext -Token $token.token -Port $PortalPort -Referer $Referer 
        $DesiredDomainForRedirect = "https://$($ServerHostName)"
        Write-Verbose "Current list of redirect Uris:- $($oauthApp.redirect_uris)"
        if(-not($oauthApp.redirect_uris -icontains $DesiredDomainForRedirect)){
            Write-Verbose "Redirect Uri for $DesiredDomainForRedirect does not exist. Adding it"
            $oauthApp.redirect_uris += $DesiredDomainForRedirect
            Write-Verbose "Updated list of redirect Uris:- $($oauthApp.redirect_uris)"
            Update-OAuthApplication -PortalHostName $PortalHostName -SiteName $PortalContext -Token $token.token -Port $PortalPort -Referer $Referer -AppObject $oauthApp 
        
        }else {
            Write-Verbose "Redirect Uri for $DesiredDomainForRedirect exists as required"
        }        

        if($ServerFunctions -or $ServerRole) {
            $ServerFunctionOrig = $ServerFunctions
            $ServerRoleOrig = $ServerRole

            Write-Verbose "Get Server Functions Configuration for https://$($ServerHostName)"
            $serverToken = Get-ServerToken -ServerEndPoint "https://$($ServerHostName):$($ServerSiteAdminUrlPort)" -ServerSiteName $ServerContext -Credential $SiteAdministrator -Referer $Referer
            $securityConfig = Invoke-ArcGISWebRequest -Url "$ServerSiteAdminUrl/admin/security/config" -HttpFormParameters @{ f= 'json'; token = $serverToken.token } -Referer $Referer -HttpMethod 'GET' 
            $ServerFunctionFlag = $false
            if($securityConfig.serverFunction -ine $ServerFunctions) {
                Write-Verbose "Server Function '$($securityConfig.serverFunctions)' does not match desired value '$ServerFunctions'"
                $ServerFunctionFlag = $true
                if(-not($ServerFunctions)){
                    $ServerFunctions = $securityConfig.serverFunction
                }
            }else {
                Write-Verbose "Server Function '$($securityConfig.serverFunction)' matches desired value '$ServerFunctions'"
            }

            $ServerRoleFlag = $false
            if($securityConfig.serverRole -ine $ServerRole) {
                Write-Verbose "Server Role '$($securityConfig.serverRole)' does not match desired value '$ServerRole'"
                $ServerRoleFlag = $true
                if(-not($ServerRole)){
                    $ServerRole = $securityConfig.serverRole
                }
            }else {
                Write-Verbose "Server Role '$($securityConfig.serverRole)' matches desired value '$ServerRole'"
                
            }
            
            if($ServerRoleFlag -or $ServerFunctionFlag){
                Write-Verbose "Updating Server Role and Function"
                try {
                    Write-Verbose "Making a request to $ServerSiteAdminUrl/admin/security/config/changeServerRole"
                    Invoke-ArcGISWebRequest -Url "$ServerSiteAdminUrl/admin/security/config/changeServerRole" -HttpFormParameters @{ serverRole = $ServerRole; serverFunction = $ServerFunctions; f= 'json'; token = $token.token } -Referer $Referer -HttpMethod 'POST' -LogResponse -TimeOutSec 150
                    Write-Verbose "Updated Server Role to '$($ServerRole)' and Function to '$($ServerFunctions)'"
                }
                catch{
                    Write-Verbose "[WARNING]:- Update operation did not succeed. Error:- $_"
                }
            }
            
            $ServerFunctions = $ServerFunctionOrig 
            $ServerRole = $ServerRoleOrig  

            if(-not($fedServer)) {  
                $fedServers = Get-FederatedServers -PortalHostName $PortalHostName -SiteName $PortalContext -Port $PortalPort -Token $token.token -Referer $Referer    
                $fedServer = $fedServers.servers | Where-Object { $_.url -ieq $ServiceUrl -and $_.adminUrl -ieq $ServerSiteAdminUrl }  
            }
            
            if($fedServer) {
                Write-Verbose "Server Function for federated server with id '$($fedServer.id)' :- $($fedServer.serverFunction)"
                Write-Verbose "Server Role for federated server with id '$($fedServer.id)' :- $($fedServer.serverRole)"
                $ServerFunctionFlag = $False
                if($fedServer.serverFunction -ine $ServerFunctions) {
                    Write-Verbose "Server Functions for Federated Server with id '$($fedServer.id)' does not match desired value '$ServerFunctions'"
                    $ServerFunctionFlag = $true     
                    if(-not($ServerFunctions)){
                        $ServerFunctions = $fedServer.serverFunction
                    } 
                }
                else {
                    Write-Verbose "Server Functions for Federated Server with id '$($fedServer.id)' matches desired value '$ServerFunctions'"
                }

                $ServerRoleFlag = $False
                if($fedServer.serverRole -ine $ServerRole) {
                    Write-Verbose "Server Role for Federated Server with id '$($fedServer.id)' does not match desired value '$ServerRole'"
                    $ServerRoleFlag = $true 
                    if(-not($ServerRole)){
                        $ServerRole = $fedServer.serverRole
                    }
                }else{
                    Write-Verbose "Server Role for Federated Server with id '$($fedServer.id)' matches desired value '$ServerRole'"
                }
                
                
                if($ServerRoleFlag -or $ServerFunctionFlag){
                    Write-Verbose "Updating Portal"
                    try{
                        $response = Update-FederatedServer -PortalHostName $PortalHostName -SiteName $PortalContext -Port $PortalPort -Token $token.token -Referer $Referer `
                                                    -ServerId $fedServer.id -ServerRole $ServerRole -ServerFunction $ServerFunctions
                        if($response.error) {
                            Write-Verbose "[WARNING]:- Update operation did not succeed. Error:- $($response.error.message)"
                        }elseif($response.status -ieq "success"){
                            Write-Verbose "Server Role for Federated Server with id '$($fedServer.id)' was updated to '$ServerRole'"
                        }
                    }catch{
                        Write-Verbose "The error $($_.Exception)"
                    }
                }
                
            }
           
        }
    }elseif($Ensure -eq 'Absent') {
        $PortalFQDN = Get-FQDN $PortalHostName
        $ServerFQDN = Get-FQDN $ServerHostName
        $ServerHttpsUrl = "https://$($ServerFQDN):$($ServerSiteAdminUrlPort)/"
        
        $fedServers = Get-FederatedServers -PortalHostName $PortalHostName -SiteName $PortalContext -Port $PortalPort -Token $token.token -Referer $Referer    
        $fedServer = $fedServers.servers | Where-Object { $_.url -ieq $ServiceUrl -and $_.adminUrl -ieq $ServerSiteAdminUrl }
        if($fedServer) {
            Write-Verbose "Server with Admin URL $ServerSiteAdminUrl already exists"
            try {
                $resp = UnFederate-Server -PortalHostName $PortalFQDN -SiteName $PortalContext -Port $PortalPort -ServerID $fedServer.id -Token $token.token -Referer $Referer
                if($resp.error) {			
                    Write-Verbose "[ERROR]:- UnFederation returned error. Error:- $($resp.error)"
                }else {
                    Write-Verbose 'UnFederation succeeded'
                    Write-Verbose 'Retrieve Current Security Config:'
                    $serverToken = Get-ServerToken -ServerEndPoint "https://$($ServerHostName)" -ServerSiteName $ServerContext -Credential $SiteAdministrator -Referer $Referer
                    $CurrentSecurityConfig = Get-SecurityConfig -ServerURL $ServerHttpsUrl -SiteName $ServerContext -Token $serverToken.token -Referer $Referer
                    Write-Verbose "Current Security Config:- $($CurrentSecurityConfig.authenticationTier)"
                    if('ARCGIS_PORTAL' -ieq $CurrentSecurityConfig.authenticationTier){
                        try{
                            Update-SecurityConfigForServer -ServerLocalHttpsEndpoint $ServerHttpsUrl -ServerContext $ServerContext -Referer $Referer -ServerToken $serverToken.token
                            Write-Verbose "Config Update succeeded"
                        }catch{
                            Write-Verbose "Error during Config Update. Error:- $_"
                        }
                    }
                }
            }catch { 
                Write-Verbose "Error during unfederate operation. Error:- $_"
            }
            Write-Verbose "Unfederate Operation causes a web server restart. Waiting for portaladmin endpoint to come back up"
            Wait-ForUrl -Url "https://$($PortalEndPoint):$($PortalPort)/$($PortalContext)/portaladmin/" -MaxWaitTimeInSeconds 180 -HttpMethod 'GET'
        }else{
            Write-Verbose "Federated Server with Admin URL $ServerSiteAdminUrl doesn't exists"
        }   
    }
}

function Federate-Server
{
    [CmdletBinding()]
    param(
        [System.String]
		$PortalHostName = 'localhost', 

        [System.String]
		$SiteName = 'arcgis',

        [System.String]
		$ServerServiceUrl, 

        [System.String]
		$ServerAdminUrl, 

        [System.Management.Automation.PSCredential]
		$ServerAdminCredential, 

        [System.String]
		$PortalToken, 

        [System.String]
		$Referer,

        [Parameter(Mandatory=$false)]
        [System.Int32]
		$Port = 7443
    )
		
    $FederationUrl = "https://$($PortalHostName):$Port/$SiteName/portaladmin/federation/servers/federate" 
    Write-Verbose "Federation EndPoint:- $FederationUrl"
    Write-Verbose "Referer:- $Referer"
    Write-Verbose "Federation Parameters:- url:- $ServerServiceUrl adminUrl = $ServerAdminUrl"
    Invoke-ArcGISWebRequest -Url $FederationUrl -Verbose -HttpFormParameters @{ f='json'; url = $ServerServiceUrl; adminUrl = $ServerAdminUrl; username = $ServerAdminCredential.UserName; password = $ServerAdminCredential.GetNetworkCredential().Password; token = $PortalToken } -Referer $Referer -LogResponse -TimeOutSec 90
}

function UnFederate-Server
{
    [CmdletBinding()]
    param(
        [System.String]
		$PortalHostName = 'localhost', 

        [System.String]
		$SiteName = 'arcgis',

        [System.String]
		$ServerID, 

        [System.String]
		$Token, 

        [System.String]
        $Referer,
        
        [System.Int32]
        $Port = 7443
    )

    $UnFederationUrl = "https://$($PortalHostName):$($Port)/$SiteName/portaladmin/federation/servers/$($ServerID)/unfederate"
    Write-Verbose "UnFederate the server with ID $($ServerID) using admin URL $UnFederationUrl"
    Invoke-ArcGISWebRequest -Url $UnFederationUrl -HttpFormParameters @{ f='json'; token = $Token } -Referer $Referer -LogResponse -TimeOutSec 90
}

function Get-FederatedServers
{
    [CmdletBinding()]
    param(        
        [System.String]
		$PortalHostName = 'localhost', 

        [System.String]
		$SiteName = 'arcgis', 

        [System.String]
		$Token, 

        [System.String]
		$Referer = 'http://localhost',

        [Parameter(Mandatory=$false)]
        [System.Int32]
		$Port = 7443
    )
    
    Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):$Port/$($SiteName)" + '/portaladmin/federation/servers/') -HttpMethod 'GET' -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer 
}

function Get-OAuthApplication
{
    [CmdletBinding()]
    param(        
        [System.String]
		$PortalHostName = 'localhost', 

        [System.String]
		$SiteName = 'arcgis', 

        [System.String]
		$Token, 

        [System.String]
		$Referer = 'http://localhost',

        [Parameter(Mandatory=$false)]
        [System.Int32]
		$Port = 7443,

        [Parameter(Mandatory=$false)]
        [System.String]
		$AppId = 'arcgisonline'
    )
    
    Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):$Port/$($SiteName)" + "/sharing/oauth2/apps/$($AppId)") -HttpMethod 'GET' -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer 
}

function Update-OAuthApplication
{
    [CmdletBinding()]
    param(        
        [System.String]
		$PortalHostName = 'localhost', 

        [System.String]
		$SiteName = 'arcgis', 

        [System.String]
		$Token, 

        [System.String]
		$Referer = 'http://localhost',

        [Parameter(Mandatory=$false)]
        [System.Int32]
		$Port = 7443,

        [Parameter(Mandatory=$false)]
        [System.String]
		$AppId = 'arcgisonline',

        [Parameter(Mandatory=$true)]
        $AppObject 
    )
    
    $redirect_uris = ConvertTo-Json $AppObject.redirect_uris -Depth 1    
    Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):$Port/$($SiteName)" + "/sharing/oauth2/apps/$($AppId)/update") -HttpMethod 'POST' -HttpFormParameters @{ f = 'json'; token = $Token; redirect_uris = $redirect_uris } -Referer $Referer -LogResponse
}

function Update-FederatedServer
{
    [CmdletBinding()]
    param(        
        [System.String]
		$PortalHostName = 'localhost', 

        [System.String]
		$SiteName = 'arcgis', 

        [System.String]
		$Token, 

        [System.String]
		$Referer = 'http://localhost',

        [Parameter(Mandatory=$true)]
        [System.String]
		$ServerId, 

        [Parameter(Mandatory=$false)]
        [System.String]
		$ServerRole, 

        [Parameter(Mandatory=$false)]
        [System.String]
		$ServerFunction, 

        [Parameter(Mandatory=$false)]
        [System.Int32]
		$Port = 7443
    )
    
    
    try{
    $response = Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):$Port/$($SiteName)/portaladmin/federation/servers/$($ServerId)/update") -HttpMethod 'POST' -HttpFormParameters @{ f = 'json'; token = $Token; serverRole = $ServerRole; serverFunction = $ServerFunction } -Referer $Referer -LogResponse 
    }catch{
        Write-Verbose "The Error --- $($_.ErrorDet)"
    }
    if($response){
        $response
    }else{
        @{status = @("success")}
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

function Update-SecurityConfigForServer
{
    [CmdletBinding()]
    param(
        [System.String]
		$ServerLocalHttpsEndpoint, 

        [System.String]
		$ServerContext, 

        [System.String]
		$Referer, 

        [System.String]
		$ServerToken, 

        [System.Int32]
		$MaxAttempts = 5
	) 
    
    $securityConfig = @{
        authenticationTier = 'GIS_SERVER'
    }
        
    $WebParams = @{ securityConfig = ConvertTo-Json $securityConfig -Depth 5 -Compress                   
                    token = $ServerToken
                    f = 'json'
                  } 
    
    $UpdateConfigUrl = "$ServerLocalHttpsEndpoint/$ServerContext/admin/security/config/update" 	

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

Export-ModuleMember -Function *-TargetResource