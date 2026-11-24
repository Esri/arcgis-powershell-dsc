$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.Portal.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.Server.psm1'))

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
    .PARAMETER PortalSiteAdministrator
        A MSFT_Credential Object - Initial Administrator Account
    .PARAMETER SiteAdministrator
        A MSFT_Credential Object - Primary Site Administrator
    .PARAMETER ServerFunctions
        Server Function of the federated server (for example, RasterAnalytics)
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

    @{}
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
		$PortalSiteAdministrator,

		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

        [parameter(Mandatory = $false)]
		[System.String] 
        $ServerFunctions = '',

        [parameter(Mandatory = $false)]
		[System.String] 
        $ServerRole
	)

    $ServiceURL = Get-ArcGISComponentBaseUrl -FQDN $ServiceUrlHostName -ComponentName "Server" -Port $ServiceUrlPort -Context $ServiceUrlContext
    $ServerFQDN = Get-FQDN $ServerSiteAdminUrlHostName
    $ServerSiteAdminUrl = Get-ArcGISComponentBaseUrl -FQDN $ServerFQDN -ComponentName "Server" -Context $ServerSiteAdminUrlContext -Port $ServerSiteAdminUrlPort

    $PortalFQDN = Get-FQDN $PortalHostName
    Write-Verbose "Get Portal Token from Deployment '$PortalFQDN'"
    $PortalBaseUrl = Get-ArcGISComponentBaseUrl -FQDN $PortalFQDN -ComponentName "Portal" -Port $PortalPort -Context $PortalContext
    $Referer = $PortalBaseURL

    $token = Get-PortalToken -URL $PortalBaseURL -Credential $PortalSiteAdministrator -Referer $Referer -MaxAttempts 30 -Verbose
    if(-not($token.token)) {
        throw "Unable to retrieve Portal Token for '$($PortalSiteAdministrator.UserName)' from Deployment '$PortalFQDN'"
    }

    Write-Verbose "Site Admin Url:- $ServerSiteAdminUrl Service Url:- $ServiceUrl"

    $result = $false
    $fedServers = Get-FederatedServers -URL $PortalBaseURL -Token $token.token -Referer $Referer    
	$fedServer = $fedServers.servers | Where-Object { $_.url -ieq $ServiceUrl -and $_.adminUrl -ieq $ServerSiteAdminUrl }
    if($fedServer) {
        Write-Verbose "Federated Server with Admin URL $ServerSiteAdminUrl already exists"
        $result = $true
    }else {
        Write-Verbose "Federated Server with Admin URL $ServerSiteAdminUrl does not exist"
    }

    if($result -and $Ensure -ieq 'Absent'){
        $result = $true
    }else{
        if($ServerRole -ieq "HOSTING_SERVER"){
            if($result) {
                $servers = Get-RegisteredServersForPortal -URL $PortalBaseURL -Token $token.token -Referer $Referer 
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
            $oauthApp = Get-OAuthApplication -URL $PortalBaseURL -Token $token.token -Referer $Referer 
            Write-Verbose "Current list of redirect Uris:- $($oauthApp.redirect_uris)"
            $DesiredDomainForRedirect = "https://$($ServerFQDN)"
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
		$PortalSiteAdministrator,

		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

        [parameter(Mandatory = $false)]
		[System.String] 
        $ServerFunctions = '',

        [parameter(Mandatory = $false)]
		[System.String] 
        $ServerRole
    )

    
    $ServiceURL = Get-ArcGISComponentBaseUrl -FQDN $ServiceUrlHostName -ComponentName "Server" -Port $ServiceUrlPort -Context $ServiceUrlContext
    $ServerFQDN = Get-FQDN $ServerSiteAdminUrlHostName
    $ServerSiteAdminUrl = Get-ArcGISComponentBaseUrl -FQDN $ServerFQDN -ComponentName "Server" -Context $ServerSiteAdminUrlContext -Port $ServerSiteAdminUrlPort

    
    $PortalFQDN = Get-FQDN $PortalHostName
    Write-Verbose "Get Portal Token from Deployment '$PortalFQDN'"

    $PortalBaseUrl = Get-ArcGISComponentBaseUrl -FQDN $PortalFQDN -ComponentName "Portal" -Port $PortalPort -Context $PortalContext
    $Referer = $PortalBaseURL
    
    $token = Get-PortalToken -URL $PortalBaseURL -Credential $PortalSiteAdministrator -Referer $Referer -MaxAttempts 30 -Verbose
    if(-not($token.token)) {
        throw "Unable to retrieve Portal Token for '$($PortalSiteAdministrator.UserName)' from Deployment '$PortalFQDN'"
    }

    Write-Verbose "Site Admin Url:- $ServerSiteAdminUrl Service Url:- $ServiceUrl"

    if($Ensure -eq "Present"){        
        $fedServers = Get-FederatedServers -URL $PortalBaseURL -Token $token.token -Referer $Referer    
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
                            $resp = Invoke-UnFederateServer -URL $PortalBaseURL -ServerID $existingFedServer.id -Token $token.token -Referer $Referer
                            if($resp.error) {			
                                Write-Verbose "[ERROR]:- UnFederation returned error. Error:- $($resp.error)"
                            }else {
                                Write-Verbose 'UnFederation succeeded'
                            }
                        } catch {
                            Write-Verbose "Error during unfederate operation. Error:- $_"
                        }
                        Write-Verbose "Unfederate Operation causes a web server restart. Waiting for portaladmin endpoint to come back up"
                        Wait-ForArcGISComponentRestart -BaseURL $PortalBaseURL -ComponentName "Portal" -RestartComponentName "PortalSharing" -MaxRestartWaitTimeInSeconds 300 -MaxStartupWaitTimeInSeconds 180 -Verbose
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
                [bool]$AlreadyFederated = $false
                $ErrorMessage = ""
                try {
                    $resp = Invoke-FederateServer -URL $PortalBaseURL -PortalToken $token.token -Referer $Referer `
                            -ServerServiceUrl $ServiceUrl -ServerAdminUrl $ServerSiteAdminUrl -ServerAdminCredential $SiteAdministrator
                    if($resp.error){
                        $failed = $true
                        $ErrorMessage = $resp.error
                        $AlreadyFederated = ($resp.error.message -imatch '\balready (?:a )?federated\b')
                    }
                }
                catch
                {
                    $failed = $true
                    $ErrorMessage =  $_
                    $AlreadyFederated = ($_.Exception.Message -imatch '\balready (?:a )?federated\b')
                }

                if($failed) {
                    Write-Verbose "[ERROR]:- Federation returned error. Error:- $ErrorMessage"
                    if($NumAttempts -lt $MaxAttempts -and -not($AlreadyFederated)) {
                        Write-Verbose "Attempt [$NumAttempts] Failed. Waiting 30 seconds before checking federation state."
                        Start-Sleep -Seconds 30
                    }

                    try {
                        $fedServers = Get-FederatedServers -URL $PortalBaseURL -Token $token.token -Referer $Referer -ErrorAction Stop
                        if($fedServers.error) {
                            throw ($fedServers.error | ConvertTo-Json -Compress -Depth 10)
                        }
                        $fedServer = $fedServers.servers | Where-Object { $_.url -ieq $ServiceUrl -and $_.adminUrl -ieq $ServerSiteAdminUrl }
                    } catch {
                        throw "Unable to verify federation state after a failed request. Federation error:- $ErrorMessage. Verification error:- $_"
                    }

                    if($fedServer) {
                        Write-Verbose "Federation is confirmed in Portal despite the failed request."
                        $failed = $false
                    }elseif($AlreadyFederated) {
                        $RegisteredServerUrls = @($fedServers.servers | ForEach-Object { "id='$($_.id)', url='$($_.url)', adminUrl='$($_.adminUrl)'" }) -join '; '
                        if(-not($RegisteredServerUrls)) {
                            $RegisteredServerUrls = '(none)'
                        }
                        throw "ArcGIS Server reports that it is already federated, but Portal '$PortalBaseURL' has no server matching service URL '$ServiceUrl' and admin URL '$ServerSiteAdminUrl'. Registered servers: $RegisteredServerUrls. Check the configured URLs and the Server security/config portalProperties before retrying. Federation error:- $ErrorMessage"
                    }
                }

                if($failed) {
                    if($NumAttempts -ge $MaxAttempts) {
                        throw "[ERROR]:- Federation Failed after multiple attempts. Error:- $ErrorMessage"                        
                    }else{
                        Write-Verbose "Federation is not registered in Portal. Retrying."
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
            $oauthApp = Get-OAuthApplication -URL $PortalBaseURL -Token $token.token -Referer $Referer 
            $DesiredDomainForRedirect = "https://$($ServerFQDN)"
            Write-Verbose "Current list of redirect Uris:- $($oauthApp.redirect_uris)"
            if(-not($oauthApp.redirect_uris -icontains $DesiredDomainForRedirect)){
                Write-Verbose "Redirect Uri for $DesiredDomainForRedirect does not exist. Adding it"
                $oauthApp.redirect_uris += $DesiredDomainForRedirect
                Write-Verbose "Updated list of redirect Uris:- $($oauthApp.redirect_uris)"
                Update-OAuthApplication -URL $PortalBaseURL -Token $token.token -Referer $Referer -AppObject $oauthApp 
            }else {
                Write-Verbose "Redirect Uri for $DesiredDomainForRedirect exists as required"
            }        
        }

        if($ServerRole){
            $fedServers = Get-FederatedServers -URL $PortalBaseURL -Token $token.token -Referer $Referer    
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
                        $response = Update-FederatedServer -URL $PortalBaseURL -Token $token.token -Referer $Referer `
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
            $fedServers = Get-FederatedServers -URL $PortalBaseURL -Token $token.token -Referer $Referer    
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
                        $response = Update-FederatedServer -URL $PortalBaseURL -Token $token.token -Referer $Referer `
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
        
        $fedServers = Get-FederatedServers -URL $PortalBaseURL -Token $token.token -Referer $Referer    
        $fedServer = $fedServers.servers | Where-Object { $_.url -ieq $ServiceUrl -and $_.adminUrl -ieq $ServerSiteAdminUrl }
        if($fedServer) {
            Write-Verbose "Server with Admin URL $ServerSiteAdminUrl already exists"
            try {
                $resp = Invoke-UnFederateServer -URL $PortalBaseURL -ServerID $fedServer.id -Token $token.token -Referer $Referer
                if($resp.error) {			
                    Write-Verbose "[ERROR]:- UnFederation returned error. Error:- $($resp.error)"
                }else {
                    Write-Verbose 'UnFederation succeeded'
                    if($null -ne $SiteAdministrator){
                        Write-Verbose 'Retrieve Current Security Config:'
                        $serverToken = Get-ServerToken -URL $ServerSiteAdminUrl -Credential $SiteAdministrator -Referer $Referer 

                        $CurrentSecurityConfig = Get-SecurityConfig -URL $ServerSiteAdminUrl -Token $serverToken.token -Referer $Referer
                        Write-Verbose "Current Security Config:- $($CurrentSecurityConfig.authenticationTier)"
                        if('ARCGIS_PORTAL' -ieq $CurrentSecurityConfig.authenticationTier){
                            try{
                                Update-SecurityConfig -URL $ServerSiteAdminUrl -Token $serverToken.token -Referer $Referer -Properties $CurrentSecurityConfig -AuthenticationTier 'GIS_SERVER'
                                Write-Verbose "Config Update succeeded"
                            }catch{
                                Write-Verbose "Error during Config Update. Error:- $_"
                            }
                        }
                    }

                    if($ServerRole -ine "HOSTING_SERVER"){
                        $oauthApp = Get-OAuthApplication -URL $PortalBaseURL -Token $token.token -Referer $Referer 
                        $DesiredDomainForRedirect = "https://$($ServerFQDN)"
                        Write-Verbose "Current list of redirect Uris:- $($oauthApp.redirect_uris)"
                        if($oauthApp.redirect_uris -icontains $DesiredDomainForRedirect){
                            Write-Verbose "Redirect Uri for $DesiredDomainForRedirect exists. Removing it"
                            $updatedRedirectUris = @()
                            foreach($uri in $oauthApp.redirect_uris){
                                if($uri -ine $DesiredDomainForRedirect){
                                    $updatedRedirectUris += $uri
                                }
                            }
                            $oauthApp.redirect_uris += $updatedRedirectUris
                            Write-Verbose "Updated list of redirect Uris:- $($oauthApp.redirect_uris)"
                            Update-OAuthApplication -URL $PortalBaseURL -Token $token.token -Referer $Referer -AppObject $oauthApp 
                        }else {
                            Write-Verbose "Redirect Uri for $DesiredDomainForRedirect doesn't exists as required"
                        }        
                    }
                }
            }catch { 
                Write-Verbose "Error during unfederate operation. Error:- $_"
            }
            Write-Verbose "Unfederate Operation causes a web server restart. Waiting for portaladmin endpoint to come back up"
            Wait-ForArcGISComponentRestart -BaseURL $PortalBaseURL -ComponentName "Portal" -RestartComponentName "PortalSharing" -MaxRestartWaitTimeInSeconds 300 -MaxStartupWaitTimeInSeconds 180 -Verbose
        }else{
            Write-Verbose "Federated Server with Admin URL $ServerSiteAdminUrl doesn't exists"
        }   
    }
}

Export-ModuleMember -Function *-TargetResource
