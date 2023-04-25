$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

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
        Role of the Federate server - (HOSTING_SERVER, FEDERATED_SERVER, FEDERATED_SERVER_WITH_RESTRICTED_PUBLISHING)
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

    $ServiceUrl = "https://$($ServiceUrlHostName):$($ServiceUrlPort)/$ServiceUrlContext"
    if($ServiceUrlPort -eq 443){
        $ServiceUrl = "https://$($ServiceUrlHostName)/$ServiceUrlContext" 
    }
    $ServerSiteAdminUrl = "https://$($ServerSiteAdminUrlHostName):$($ServerSiteAdminUrlPort)/$ServerSiteAdminUrlContext"            
	if($ServerSiteAdminUrlPort -eq 443){
        $ServerSiteAdminUrl = "https://$($ServerSiteAdminUrlHostName)/$ServerSiteAdminUrlContext"  
    }
    $ServerHostName = $ServerSiteAdminUrlHostName
    $PortalFQDN = Get-FQDN $PortalHostName

	[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    Write-Verbose "Get Portal Token from Deployment '$PortalFQDN'"
    $Referer = "https://$($PortalFQDN):$($PortalPort)/$PortalContext"
    $waitForToken = $true
    $waitForTokenCounter = 0 
    while ($waitForToken -and $waitForTokenCounter -lt 25) {
        $waitForTokenCounter++
        try{
            $token = Get-PortalToken -PortalHostName $PortalFQDN -Port $PortalPort -SiteName $PortalContext -Credential $RemoteSiteAdministrator -Referer $Referer
        } catch {
            Write-Verbose "Error getting Token for Federation ! Waiting for 1 Minutes to try again"
            Start-Sleep -Seconds 60
        }
        if($token.token) {    
            $waitForToken = $false
        }
    }
    if(-not($token.token)) {
        throw "Unable to retrieve Portal Token for '$($RemoteSiteAdministrator.UserName)' from Deployment '$PortalFQDN'"
    }

    Write-Verbose "Site Admin Url:- $ServerSiteAdminUrl Service Url:- $ServiceUrl"

    $result = $false
    $fedServers = Get-FederatedServers -PortalHostName $PortalFQDN -SiteName $PortalContext -Port $PortalPort -Token $token.token -Referer $Referer    
	$fedServer = $fedServers.servers | Where-Object { $_.url -ieq $ServiceUrl -and $_.adminUrl -ieq $ServerSiteAdminUrl }
    if($fedServer) {
        Write-Verbose "Federated Server with Admin URL $ServerSiteAdminUrl already exists"
        $result = $true
    }else {
        Write-Verbose "Federated Server with Admin URL $ServerSiteAdminUrl does not exist"
    }

    if($ServerRole -ieq "HOSTING_SERVER"){
        if($result) {
            $servers = Get-RegisteredServersForPortal -PortalHostName $PortalFQDN -SiteName $PortalContext -Port $PortalPort -Token $token.token -Referer $Referer 
            $server = $servers.servers | Where-Object { $_.isHosted -eq $true }
            if(-not($server)) {
                $result = $false
                Write-Verbose "No hosted Server has been detected"
            }else {
                $result = ($server -and ($server.url -ieq $ServiceUrl))
                if(-not($result)) {
                    Write-Verbose "The URL of the hosted server'$($server.url)' does not match expected '$ServiceUrl'"
                }
            }
        }
    }

    if($result) {
        $oauthApp = Get-OAuthApplication -PortalHostName $PortalFQDN -SiteName $PortalContext -Token $token.token -Port $PortalPort -Referer $Referer 
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
        Write-Verbose "Server Function for federated server with id '$($fedServer.id)' :- $($fedServer.serverRole)"
        if($fedServer.serverRole -ine $ServerRole) {
            Write-Verbose "Server ServerRole for Federated Server with id '$($fedServer.id)' does not match desired value '$ServerRole'"
            $result = $false
        }
        else {
            Write-Verbose "Server ServerRole for Federated Server with id '$($fedServer.id)' matches desired value '$ServerRole'"
        }
        
        Write-Verbose "Server Function for federated server with id '$($fedServer.id)' :- $($fedServer.serverFunction)"
        # We will only allow adding server functions and not deleting them. 
        # This is to support any roles that might have been added by user after federation.
        $ServerFunctionFlag = $false
        $ExpectedServerFunctionsArray = @()
        $ServerFunctionsArray = $ServerFunctions.Split(',')
        
        $ExistingServerFunctionArray = ($fedServer.serverFunction).Split(',')
        foreach($sf in $ExistingServerFunctionArray){
            if($sf -ine "GeneralPurposeServer"){
                $ExpectedServerFunctionsArray += $sf
            }else{
                $ServerFunctionFlag = $true
            }
        }
        
        $ServerFunctionsArray = $ServerFunctions.Split(',')
        foreach($sf in $ServerFunctionsArray){
            if($sf -ine "GeneralPurposeServer"){
                if($ExpectedServerFunctionsArray -icontains $sf){
                    # Nothing to add already exists in updated array.
                }else{
                    $ExpectedServerFunctionsArray += $sf
                    $ServerFunctionFlag = $true
                }
            }else{
                #It is okay not to add it.
            }
        }

        $serverFunctionsCompare = Compare-Object -ReferenceObject $ExpectedServerFunctionsArray -DifferenceObject $ExistingServerFunctionArray -PassThru
        if($serverFunctionsCompare.Count -gt 0) {
            if(-not($ServerFunctions)){
                $ServerFunctions = $fedServer.serverFunction
            }
            Write-Verbose "Server Functions for Federated Server with id '$($fedServer.id)' does not contain desired value '$ServerFunctions'"
            $ServerFunctionFlag = $true
        }
        else {
            Write-Verbose "Server Functions for Federated Server with id '$($fedServer.id)' contains the desired value '$ServerFunctions'"
        }
        if($ServerFunctionFlag){
            $result = $False
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

    $PortalFQDN = Get-FQDN $PortalHostName

    Write-Verbose "Get Portal Token from Deployment '$PortalFQDN'"
    $Referer = "https://$($PortalFQDN):$($PortalPort)/$PortalContext"
    $waitForToken = $true
    $waitForTokenCounter = 0 
    while ($waitForToken -and $waitForTokenCounter -lt 25) {
        $waitForTokenCounter++
        try{
            $token = Get-PortalToken -PortalHostName $PortalFQDN -Port $PortalPort -SiteName $PortalContext -Credential $RemoteSiteAdministrator -Referer $Referer
        } catch {
            Write-Verbose "Error getting Token for Federation ! Waiting for 1 Minutes to try again"
            Start-Sleep -Seconds 60
        }
        if($token.token) {    
            $waitForToken = $false
        }
    }
    if(-not($token.token)) {
        throw "Unable to retrieve Portal Token for '$($RemoteSiteAdministrator.UserName)' from Deployment '$PortalFQDN'"
    }

    Write-Verbose "Site Admin Url:- $ServerSiteAdminUrl Service Url:- $ServiceUrl"

    if($Ensure -eq "Present"){        
        $fedServers = Get-FederatedServers -PortalHostName $PortalFQDN -SiteName $PortalContext -Port $PortalPort -Token $token.token -Referer $Referer    
        $fedServer = $fedServers.servers | Where-Object { $_.url -ieq $ServiceUrl -and $_.adminUrl -ieq $ServerSiteAdminUrl }
        if($ServerRole -ieq "HOSTING_SERVER"){
            if(-not($fedServer) -or ($fedServer.serverRole -ine 'HOSTING_SERVER')){
                Write-Verbose "Could not find a federated server that is the hosting server and whose URL matches expected values"
                $existingFedServer = $fedServers.servers | Where-Object { $_.adminUrl -ieq $ServerSiteAdminUrl }
                if($existingFedServer) {
                    Write-Verbose "Server with Admin URL $ServerSiteAdminUrl already exists"
                    if($existingFedServer.url -ine $ServiceUrl) {
                        Write-Verbose "Server with admin URL $ServerSiteAdminUrl already exits, but its public URL '$($existingFedServer.url)' does match expected '$ServiceUrl'"					
                        try {
                            $resp = Invoke-UnFederateServer -PortalHostName $PortalFQDN -SiteName $PortalContext -Port $PortalPort -ServerID $existingFedServer.id -Token $token.token -Referer $Referer
                            if($resp.error) {			
                                Write-Verbose "[ERROR]:- UnFederation returned error. Error:- $($resp.error)"
                            }else {
                                Write-Verbose 'UnFederation succeeded'
                            }
                        } catch {
                            Write-Verbose "Error during unfederate operation. Error:- $_"
                        }
                        Write-Verbose "Unfederate Operation causes a web server restart. Waiting for portaladmin endpoint to come back up"
                        Wait-ForUrl -Url "https://$($PortalFQDN):$($PortalPort)/$($PortalContext)/portaladmin/" -MaxWaitTimeInSeconds 180 -HttpMethod 'GET'
                    }
                }
            }
        }
 
        if(-not($fedServer)) {
            Write-Verbose "Federated Server with Admin URL $ServerSiteAdminUrl does not exist"
            [bool]$Done = $false
            [int]$NumAttempts = 1
            [int]$MaxAttempts = 3
            while(-not($Done)) {
                Write-Verbose "Federation of Server Attempt $NumAttempts"
                [bool]$failed = $false
                $ErrorMessage = ""
                try {
                    $resp = Invoke-FederateServer -PortalHostName $PortalFQDN -SiteName $PortalContext -Port $PortalPort -PortalToken $token.token -Referer $Referer `
                            -ServerServiceUrl $ServiceUrl -ServerAdminUrl $ServerSiteAdminUrl -ServerAdminCredential $SiteAdministrator
                    if($resp.error){
                        $failed = $true
                        $ErrorMessage = $resp.error
                    }
                }
                catch
                {
                    $failed = $true
                    $ErrorMessage =  $_
                }

                if($failed) {
                    if($NumAttempts -ge $MaxAttempts) {
                        throw "[ERROR]:- Federation Failed after multiple attempts. Error:- $ErrorMessage"                        
                    }else{
                        Write-Verbose "[ERROR]:- Federation returned error. Error:- $ErrorMessage"
                        Write-Verbose "Attempt [$NumAttempts] Failed. Retrying after 30 seconds!"
                        Start-Sleep -Seconds 30
                    }
                } else {
                    Write-Verbose 'Federation succeeded. Now updating server role and function.'
                    $Done = $true
                }
                $NumAttempts++
            }
        } else {
            Write-Verbose "Federated Server with Admin URL $ServerSiteAdminUrl already exists"
        }

        if($ServerRole -ine "HOSTING_SERVER"){
            $oauthApp = Get-OAuthApplication -PortalHostName $PortalFQDN -SiteName $PortalContext -Token $token.token -Port $PortalPort -Referer $Referer 
            $DesiredDomainForRedirect = "https://$($ServerHostName)"
            Write-Verbose "Current list of redirect Uris:- $($oauthApp.redirect_uris)"
            if(-not($oauthApp.redirect_uris -icontains $DesiredDomainForRedirect)){
                Write-Verbose "Redirect Uri for $DesiredDomainForRedirect does not exist. Adding it"
                $oauthApp.redirect_uris += $DesiredDomainForRedirect
                Write-Verbose "Updated list of redirect Uris:- $($oauthApp.redirect_uris)"
                Update-OAuthApplication -PortalHostName $PortalFQDN -SiteName $PortalContext -Token $token.token -Port $PortalPort -Referer $Referer -AppObject $oauthApp 
            }else {
                Write-Verbose "Redirect Uri for $DesiredDomainForRedirect exists as required"
            }        
        }

        if($ServerRole){
            $fedServers = Get-FederatedServers -PortalHostName $PortalFQDN -SiteName $PortalContext -Port $PortalPort -Token $token.token -Referer $Referer    
            $fedServer = $fedServers.servers | Where-Object { $_.url -ieq $ServiceUrl -and $_.adminUrl -ieq $ServerSiteAdminUrl }
            if($fedServer) {
                Write-Verbose "Server Role for federated server with id '$($fedServer.id)' :- $($fedServer.serverRole)"
                $ServerRoleFlag = $False
                if($fedServer.serverRole -ine $ServerRole) {
                    if(-not($ServerRole)){
                        $ServerRole = $fedServer.serverRole
                    }
                    Write-Verbose "Server Role for Federated Server with id '$($fedServer.id)' does not match desired value '$ServerRole'"
                    $ServerRoleFlag = $true
                }else{
                    Write-Verbose "Server Role for Federated Server with id '$($fedServer.id)' matches desired value '$ServerRole'"
                }

                if($ServerRoleFlag){
                    Write-Verbose "Updating Server Role in Portal"
                    try{
                        $response = Update-FederatedServer -PortalHostName $PortalFQDN -SiteName $PortalContext -Port $PortalPort -Token $token.token -Referer $Referer `
                                                    -ServerId $fedServer.id -ServerRole $ServerRole -ServerFunction $fedServer.serverFunction
                        if($response.error) {
                            throw "[WARNING]:- Update operation did not succeed. Error:- $($response.error)"
                        }elseif($response.status -ieq "success"){
                            Write-Verbose "Server Role for Federated Server with id '$($fedServer.id)' was updated to '$ServerRole'"
                        }
                    }catch{
                        throw $_
                    }
                }
            }
        }

        if($ServerFunctions) {
            $fedServers = Get-FederatedServers -PortalHostName $PortalFQDN -SiteName $PortalContext -Port $PortalPort -Token $token.token -Referer $Referer    
            $fedServer = $fedServers.servers | Where-Object { $_.url -ieq $ServiceUrl -and $_.adminUrl -ieq $ServerSiteAdminUrl }
            if($fedServer) {
                Write-Verbose "Server Function for federated server with id '$($fedServer.id)' :- $($fedServer.serverFunction)"
                
                # We will only allow adding server functions and not deleting them. 
                # This is to support any roles that might have been added by user after federation.
                $ServerFunctionFlag = $false
                $ExpectedServerFunctionsArray = @()
                $ServerFunctionsArray = $ServerFunctions.Split(',')
                
                $ExistingServerFunctionArray = ($fedServer.serverFunction).Split(',')
                foreach($sf in $ExistingServerFunctionArray){
                    if($sf -ine "GeneralPurposeServer"){
                        $ExpectedServerFunctionsArray += $sf
                    }else{
                        #Will Remove General Purpose Server if it exists
                        $ServerFunctionFlag = $true
                    }
                }
                
                foreach($sf in $ServerFunctionsArray){
                    if($sf -ine "GeneralPurposeServer"){
                        if($ExpectedServerFunctionsArray -icontains $sf){
                            # Nothing to add already exists in updated array.
                        }else{
                            $ExpectedServerFunctionsArray += $sf
                            $ServerFunctionFlag = $true
                        }
                    }else{
                        #We will not add General Purpose Server.
                    }
                }

                $serverFunctionsCompare = Compare-Object -ReferenceObject $ExpectedServerFunctionsArray -DifferenceObject $ExistingServerFunctionArray -PassThru
                if($serverFunctionsCompare.Count -gt 0) {
                    if(-not($ServerFunctions)){
                        $ServerFunctions = $fedServer.serverFunction
                    }
                    Write-Verbose "Server Functions for Federated Server with id '$($fedServer.id)' does not match desired value '$ServerFunctions'"
                    $ServerFunctionFlag = $true
                } else {
                    Write-Verbose "Server Functions for Federated Server with id '$($fedServer.id)' has the desired value '$ServerFunctions'"
                }

                if($ServerFunctionFlag){
                    Write-Verbose "Updating Server functions in Portal"
                    try{
                        $response = Update-FederatedServer -PortalHostName $PortalFQDN -SiteName $PortalContext -Port $PortalPort -Token $token.token -Referer $Referer `
                                                    -ServerId $fedServer.id -ServerRole $fedServer.serverRole -ServerFunction $ServerFunctions
                        if($response.error) {
                            throw "[WARNING]:- Update operation did not succeed. Error:- $($response.error)"
                        }elseif($response.status -ieq "success"){
                            Write-Verbose "Server Role for Federated Server with id '$($fedServer.id)' was updated to '$ServerRole'"
                        }
                    }catch{
                        throw $_
                    }
                }
            }
        }
    }elseif($Ensure -eq 'Absent') {
        $ServerHttpsUrl = "https://$($ServerHostName):$($ServerSiteAdminUrlPort)/"
        
        $fedServers = Get-FederatedServers -PortalHostName $PortalFQDN -SiteName $PortalContext -Port $PortalPort -Token $token.token -Referer $Referer    
        $fedServer = $fedServers.servers | Where-Object { $_.url -ieq $ServiceUrl -and $_.adminUrl -ieq $ServerSiteAdminUrl }
        if($fedServer) {
            Write-Verbose "Server with Admin URL $ServerSiteAdminUrl already exists"
            try {
                $resp = Invoke-UnFederateServer -PortalHostName $PortalFQDN -SiteName $PortalContext -Port $PortalPort -ServerID $fedServer.id -Token $token.token -Referer $Referer
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
            Wait-ForUrl -Url "https://$($PortalFQDN):$($PortalPort)/$($PortalContext)/portaladmin/" -MaxWaitTimeInSeconds 180 -HttpMethod 'GET'
        }else{
            Write-Verbose "Federated Server with Admin URL $ServerSiteAdminUrl doesn't exists"
        }   
    }
}

function Invoke-FederateServer
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
    Invoke-ArcGISWebRequest -Url $FederationUrl -Verbose -HttpFormParameters @{ f='json'; url = $ServerServiceUrl; adminUrl = $ServerAdminUrl; username = $ServerAdminCredential.UserName; password = $ServerAdminCredential.GetNetworkCredential().Password; token = $PortalToken } -Referer $Referer -TimeOutSec 300
}

function Invoke-UnFederateServer
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
    Invoke-ArcGISWebRequest -Url $UnFederationUrl -HttpFormParameters @{ f='json'; token = $Token } -Referer $Referer -Verbose -TimeOutSec 90
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

function Get-RegisteredServersForPortal 
{
    param(
        [System.String]
		$PortalHostName, 

        [System.String]
        $SiteName, 
        
        [Parameter(Mandatory=$false)]
        [System.Int32]
		$Port = 7443,

        [System.String]
		$Token, 

        [System.String]
		$Referer
    )
    
    $GetServersUrl = "https://$($PortalHostName):$Port/$SiteName/sharing/rest/portals/self/servers/" 
	Invoke-ArcGISWebRequest -Url $GetServersUrl -HttpFormParameters @{ token = $Token; f = 'json' } -Referer $Referer       
}

function Update-ServerAdminUrlForPortal
{
    param(
        [System.String]
        $PortalHostName,
        
        [System.String]
        $SiteName,

        [System.Int32]
        $PortalPort,

        [System.String]
		$Token, 

        [System.String]
        $Referer,
        
        [System.String]
        $ServerAdminUrl,

        $FederatedServer
    )

    Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):$PortalPort/$($SiteName)" + "/sharing/rest/portals/0123456789ABCDEF/servers/$($FederatedServer.id)/update") -HttpMethod 'POST' -HttpFormParameters @{ f = 'json'; token = $Token; name =  $ServerAdminUrl; url = $FederatedServer.url; adminUrl = $ServerAdminUrl; isHosted = $FederatedServer.isHosted; serverType = $FederatedServer.serverType; } -Referer $Referer -Verbose
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
    Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):$Port/$($SiteName)" + "/sharing/oauth2/apps/$($AppId)/update") -HttpMethod 'POST' -HttpFormParameters @{ f = 'json'; token = $Token; redirect_uris = $redirect_uris } -Referer $Referer -Verbose
}

function Update-FederatedServer
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
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
        $UpdateUrl = "https://$($PortalHostName):$Port/$($SiteName)" + "/portaladmin/federation/servers/"+$ServerId+"/update"
        $response = Invoke-ArcGISWebRequest -Url $UpdateUrl -HttpMethod 'POST' -HttpFormParameters @{ f = 'json'; token = $Token; serverRole = $ServerRole; serverFunction = $ServerFunction } -Referer $Referer -TimeOutSec 300 -Verbose 
        Write-Verbose ($response | ConvertTo-Json -Depth 5 -Compress)
        $response
    }catch{
        Write-Verbose "[WARNING] Error - $($_)"
        @{ error = $_ }
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
        Confirm-ResponseStatus $response -Url $UpdateConfigUrl
    }
}

Export-ModuleMember -Function *-TargetResource
