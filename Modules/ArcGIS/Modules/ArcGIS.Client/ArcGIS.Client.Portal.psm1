$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

function Get-PortalAdminUrlForPath{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $Path
    )
    return $URL.TrimEnd('/') + "/portaladmin" + $Path
}

function Get-PortalSharingApiUrlForPath{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $Path,

        [switch]
        $NoRest
    )

    $PrimaryRelativePath = "/sharing/rest"
    if($NoRest){
        $PrimaryRelativePath = "/sharing"
    }

    return $URL.TrimEnd('/') + $PrimaryRelativePath + $Path
}

function ConvertTo-PortalCertificateAliases
{
    [CmdletBinding()]
    param(
        $Certificates
    )

    # Portal versions can return certificate aliases as strings or objects. Normalize both
    # representations so idempotency checks do not attempt duplicate imports.
    @($Certificates | ForEach-Object {
        if($_ -is [System.String]){
            $_
        }elseif($_.alias){
            $_.alias
        }elseif($_.name){
            $_.name
        }
    })
}


function Get-PortalToken 
{
    [CmdletBinding()]
    param(
		[Parameter(Mandatory=$true)]		
        [System.String]
		$URL, 

		[parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$Credential,

		[Parameter(Mandatory=$true)]
        [System.String]
		$Referer,

        [System.Int32]
        $MaxAttempts = 10,

        [System.String]
		$Client,

        [System.Int32]
		$Expiration = -1
    )
    $url = Get-PortalSharingApiUrlForPath -URL $URL -Path ("/generateToken")
    $token = $null
    $Done = $false
	$NumAttempts = 0
    $Params = @{ 
                username = $Credential.UserName
                password = $Credential.GetNetworkCredential().Password
                referer = $Referer
                f = 'json' 
            }
    if($Client){
        $Params["client"] = $Client
    }
    if($Expiration -gt 0){
        $Params["expiration"] = $Expiration
    }
    
	while(-not($Done) -and ($NumAttempts -lt $MaxAttempts)) {
        $NumAttempts = $NumAttempts + 1
		try {
            $token = Invoke-ArcGISWebRequest -Url $url -HttpFormParameters $Params -Referer $Referer
            if($null -eq $token){
                 throw "Unable to get token. Response is null."
            }
            if($token.error){
                throw "Unable to get token - $($token.error.message). (Error response: $($token.error))"
            }
            if($token.token){
                Write-Verbose "Token retrieved successfully."
                $Done = $true
            }
		} catch {
            $token = $null
			Write-Verbose "[WARNING]:- $($url) failed to return a token on attempt $($NumAttempts). $($_)."
            if($NumAttempts -lt $MaxAttempts){
                Write-Verbose "Retrying to get token after 15 seconds."
                Start-Sleep -Seconds 15
            }
		}
    }
    $token
}

function Invoke-FederateServer
{
    [CmdletBinding()]
    param(
        [System.String]
		$URL, 

        [System.String]
		$ServerServiceUrl, 

        [System.String]
		$ServerAdminUrl, 

        [System.Management.Automation.PSCredential]
		$ServerAdminCredential, 

        [System.String]
		$PortalToken, 

        [System.String]
		$Referer
    )

    $FederationUrl = Get-PortalAdminUrlForPath -URL $URL -Path "/federation/servers/federate" 
    Write-Verbose "Federation EndPoint:- $FederationUrl"
    Write-Verbose "Referer:- $Referer"
    Write-Verbose "Federation Parameters:- url:- $ServerServiceUrl adminUrl = $ServerAdminUrl"
    $RequestParams = @{ 
                        f='json'
                        url = $ServerServiceUrl
                        adminUrl = $ServerAdminUrl
                        username = $ServerAdminCredential.UserName
                        password = $ServerAdminCredential.GetNetworkCredential().Password 
                        token = $PortalToken 
                    }

    Invoke-ArcGISWebRequest -Url $FederationUrl -Verbose -HttpFormParameters $RequestParams -Referer $Referer -TimeOutSec 300
}


function Invoke-UnFederateServer
{
    [CmdletBinding()]
    param(
        [System.String]
		$URL, 

        [System.String]
		$ServerID, 

        [System.String]
		$Token, 

        [System.String]
        $Referer
    )

    $UnFederationUrl = Get-PortalAdminUrlForPath -URL $URL -Path "/federation/servers/$($ServerID)/unfederate"
    Write-Verbose "UnFederate the server with ID $($ServerID) using admin URL $UnFederationUrl"
    Invoke-ArcGISWebRequest -Url $UnFederationUrl -HttpFormParameters @{ f='json'; token = $Token } -Referer $Referer -Verbose -TimeOutSec 90
}

function Get-FederatedServers
{
    [CmdletBinding()]
    param(        
        [System.String]
		$URL, 

        [System.String]
		$Token, 

        [System.String]
		$Referer = 'https://localhost'
    )
    
    $GetFederatedServerPortalAdminURL = Get-PortalAdminUrlForPath -URL $URL -Path '/federation/servers/'
    $response = Invoke-ArcGISWebRequest -Url $GetFederatedServerPortalAdminURL -HttpMethod 'GET' -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer
    if($null -eq $response) {
        throw "Unable to retrieve federated servers from '$GetFederatedServerPortalAdminURL': response is null."
    }
    if($response.error) {
        throw "Unable to retrieve federated servers from '$GetFederatedServerPortalAdminURL': $($response.error | ConvertTo-Json -Compress -Depth 10)"
    }
    if($null -eq $response.servers) {
        throw "Unable to retrieve federated servers from '$GetFederatedServerPortalAdminURL': response does not contain a server list."
    }
    $response
}

function Get-RegisteredServersForPortal 
{
    param(
        [System.String]
		$URL, 

        [System.String]
		$Token, 

        [System.String]
		$Referer
    )
    
    $GetServersUrl = Get-PortalSharingApiUrlForPath -URL $URL -Path "/portals/self/servers/" 
	Invoke-ArcGISWebRequest -Url $GetServersUrl -HttpFormParameters @{ token = $Token; f = 'json' } -Referer $Referer       
}

function Update-ServerAdminUrlForPortal
{
    param(
        [System.String]
		$URL, 

        [System.String]
		$Token, 

        [System.String]
        $Referer,
        
        [System.String]
        $ServerAdminUrl,

        $FederatedServer
    )

    $UpdateURL = (Get-PortalSharingApiUrlForPath -URL $URL -Path "/portals/0123456789ABCDEF/servers/$($FederatedServer.id)/update")
    Invoke-ArcGISWebRequest -Url $UpdateURL -HttpMethod 'POST' -HttpFormParameters @{ f = 'json'; token = $Token; name =  $ServerAdminUrl; url = $FederatedServer.url; adminUrl = $ServerAdminUrl; isHosted = $FederatedServer.isHosted; serverType = $FederatedServer.serverType; } -Referer $Referer -Verbose
} 

function Get-OAuthApplication
{
    [CmdletBinding()]
    param(        
        [System.String]
		$URL, 

        [System.String]
		$Token, 

        [System.String]
		$Referer = 'https://localhost',

        [Parameter(Mandatory=$false)]
        [System.String]
		$AppId = 'arcgisonline'
    )

    $GetOAuthAppsUrl = Get-PortalSharingApiUrlForPath -URL $URL -Path "/oauth2/apps/$($AppId)" -NoRest
    Invoke-ArcGISWebRequest -Url $GetOAuthAppsUrl -HttpMethod 'GET' -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer 
}



function Update-OAuthApplication
{
    [CmdletBinding()]
    param(        
        [System.String]
		$URL,  

        [System.String]
		$Token, 

        [System.String]
		$Referer = 'https://localhost',

        [Parameter(Mandatory=$false)]
        [System.String]
		$AppId = 'arcgisonline',

        [Parameter(Mandatory=$true)]
        $AppObject 
    )
    $OAuthAppsUpdate = Get-PortalSharingApiUrlForPath -URL $URL -Path "/oauth2/apps/$($AppId)/update" -NoRest
    $redirect_uris = ConvertTo-Json $AppObject.redirect_uris -Depth 1    
    Invoke-ArcGISWebRequest -Url $OAuthAppsUpdate -HttpMethod 'POST' -HttpFormParameters @{ f = 'json'; token = $Token; redirect_uris = $redirect_uris } -Referer $Referer -Verbose
}

function Update-FederatedServer
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(      
        [System.String]
		$URL,

        [System.String]
		$Token, 

        [System.String]
		$Referer = 'https://localhost',

        [Parameter(Mandatory=$true)]
        [System.String]
		$ServerId, 

        [Parameter(Mandatory=$false)]
        [System.String]
		$ServerRole, 

        [Parameter(Mandatory=$false)]
        [System.String]
		$ServerFunction
    )
    
    try{
        $UpdateUrl = Get-PortalAdminUrlForPath -URL $URL -Path ("/federation/servers/"+$ServerId+"/update")
        Invoke-ArcGISWebRequest -Url $UpdateUrl -HttpMethod 'POST' -HttpFormParameters @{ f = 'json'; token = $Token; serverRole = $ServerRole; serverFunction = $ServerFunction } -Referer $Referer -TimeOutSec 300
    }catch{
        Write-Verbose "[WARNING] Error - $($_)"
        @{ error = $_ }
    }
}

function Get-LogSettings
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

		[System.String]
        $Token,

        [System.String]
        $Referer = 'https://localhost'
    )   
    $GetLogSettingURL = Get-PortalAdminUrlForPath -URL $URL -Path "/logs/settings"
    Invoke-ArcGISWebRequest -Url $GetLogSettingURL -HttpFormParameters @{ f = 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET'
}

function Update-PortalLogSettings {
    [CmdletBinding()]
    param(
		[System.String]
        $URL,

		[System.String]
        $Token,

        [System.String]
        $Referer = 'https://localhost',

        $LogSettings
    )   
    
    $EditLogSettingURL = Get-PortalAdminUrlForPath -URL $URL -Path "/logs/settings/edit"
    $FormParameters = @{ f = 'json'; token = $Token; logDir = $LogSettings.logDir; logLevel = $LogSettings.logLevel; maxErrorReportsCount = $LogSettings.maxErrorReportsCount; maxLogFileAge = $LogSettings.maxLogFileAge; usageMeteringEnabled = $LogSettings.usageMeteringEnabled }
    Invoke-ArcGISWebRequest -Url $EditLogSettingURL -HttpFormParameters $FormParameters -Referer $Referer -HttpMethod 'POST'
}

function Test-LicensePopulated
{
    [CmdletBinding()]
    param(
		[System.String]
        $URL,

		[System.String]
        $Token,

        [System.String]
        $Referer = 'https://localhost'
    )
    
    $LicenseCheckURL = Get-PortalAdminUrlForPath -URL $URL
    $populateLicenseCheck = Invoke-ArcGISWebRequest -Url $LicenseCheckURL -HttpMethod "GET" -HttpFormParameters @{f = 'json'; token = $Token} -Referer $Referer -Verbose 
    return $populateLicenseCheck.isLicensePopulated
}

function Invoke-PopulateLicense
{
    [CmdletBinding()]
    param(
		[System.String]
        $URL,

		[System.String]
        $Token,

        [System.String]
        $Referer = 'https://localhost'
    )

    Write-Verbose 'Populating Licenses'
    [string]$populateLicenseUrl = Get-PortalAdminUrlForPath -URL $URL -Path "/license/populateLicense"
    $populateLicenseResponse = Invoke-ArcGISWebRequest -Url $populateLicenseUrl -HttpMethod "POST" -HttpFormParameters @{f = 'json'; token = $Token} -Referer $Referer -TimeOutSec 3000 -Verbose 
    if ($populateLicenseResponse.error -and $populateLicenseResponse.error.message) {
        Write-Verbose "Error from Populate Licenses:- $($populateLicenseResponse.error.message)"
        throw $populateLicenseResponse.error.message
    }
}

function Test-PortalSiteCreated
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

		[System.String]
        $Referer = 'https://localhost'
    )

    $result = $false
    try{
        Test-ArcGISComponentHealth -BaseURL $URL -ComponentName "PortalSharing" -Verbose
        $PortalAdminURL = Get-PortalAdminUrlForPath -URL $URL
        $SiteCreatedCheckResponse = Invoke-ArcGISWebRequest -Url $PortalAdminURL -HttpFormParameters @{ referer = $Referer; f = 'json' } -Referer $Referer -HttpMethod "GET"
        if($SiteCreatedCheckResponse.error.code -eq 499){
            Write-Verbose "Portal Site is already created."
            $result = $true
        }else{
            # Get
            if($SiteCreatedCheckResponse.status -ieq "error"){
                if((Get-UICulture).DisplayName -imatch "English"){
                    if($SiteCreatedCheckResponse.messages -icontains "The portal site has not been initialized. Please create a new site and try again."){
                        $result = $false
                    }else{
                        throw "$(ConvertTo-JSON $SiteCreatedCheckResponse -Compress)"
                    }
                }else{
                    # Skip match for non-english languages
                    $result = $false
                }
            }else{
                throw "Unknown response - $(ConvertTo-JSON $SiteCreatedCheckResponse -Compress)"
            }
        }
    }catch{
        $errMsg = "[ERROR] Unable to detect portal site. $_"
        Write-Verbose  $errMsg
        throw $errMsg
    }

    return $result
}

function Invoke-EnsurePortalSiteHealthy
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

		[System.Management.Automation.PSCredential]
		$PortalAdministrator,

        [System.String]
        $Referer = 'https://localhost'
    )

    $Attempts = 0
    $PortalReady = $False
    $SharingAPIURL = Get-PortalSharingApiUrlForPath -URL $URL -Path "/info" 
    while(-not($PortalReady) -and ($Attempts -lt 2)) {
        
        Write-Verbose "Making request to Sharing API Url - $SharingAPIURL" 
        try {
            Invoke-ArcGISWebRequest -Url $SharingAPIURL -HttpFormParameters @{ referer = $Referer; f = 'json' } -Referer $Referer -Verbose -HttpMethod "GET"
            Write-Verbose "Sharing API rest endpoint is available."
            $PortalReady = $true
        }catch {
            Write-Verbose "Sharing API rest endpoint is not available. Error:- $_. Restarting Portal."
            Restart-ArcGISService -ComponentName 'Portal' -Verbose
            Test-ArcGISComponentHealth -BaseURL $URL -ComponentName "Portal" -MaxWaitTimeInSeconds 600 -Verbose
            $Attempts = $Attempts + 1
        }        
    }
    if(-not($PortalReady)){
        throw "Portal Site is not healthy. Please check your portal site deployment."
    }
}


<#
    .SYNOPSIS
        Resource to Configure a Portal site.
    .PARAMETER Ensure
        Ensure makes sure that a Portal site is configured and joined to site if specified. Take the values Present or Absent. 
        - "Present" ensures that portal is configured, if not.
        - "Absent" ensures that existing portal site is deleted(Not Implemented).
    .PARAMETER PortalHostName
        Host Name of the Machine on which the Portal has been installed and is to be configured.
    .PARAMETER PortalAdministrator
         A MSFT_Credential Object - Initial Administrator Account
    .PARAMETER AdminEmail
        Additional User Details - Email of the Administrator.
    .PARAMETER AdminFullName
        Additional User Details - Full Name of the Administrator.
    .PARAMETER AdminDescription
        Additional User Details - Description for the Administrator.
    .PARAMETER AdminSecurityQuestionCredential.Username
        Additional User Details - Security Questions Index
        0 - What city were you born in?
        1 - What was your high school mascot?
        2 - What is your mother's maiden name?
        3 - What was the make of your first car?
        4 - What high school did you go to?
        5 - What is the last name of your best friend?
        6 - What is the middle name of your youngest sibling?
        7 - What is the name of the street on which you grew up?
        8 - What is the name of your favorite fictional character?
        9 - What is the name of your favorite pet?
        10 - What is the name of your favorite restaurant?
        11 - What is the title of your favorite book?
        12 - What is your dream job?
        13 - Where did you go on your first date?
    .PARAMETER AdminSecurityQuestionCredential.Password
        Additional User Details - Answer to the Security Question
    .PARAMETER Join
        Boolean to indicate if the machine being installed is a Secondary portal and is being joined with an existing portal
    .PARAMETER EnableDebugLogging
        Enables Debug Mode 
    .PARAMETER LogLevel
        Decides what level of Logging has to take place at Tomcat level
    .PARAMETER IsHAPortal
        Boolean to Indicate if the Portal install is a High Availability setup - i.e two portals are joined.
    .PARAMETER PeerMachineHostName
        HostName of the Primary Portal Machine
    .PARAMETER ContentDirectoryLocation
        Content Directory Location for the Portal - Can be a location file path or a Network File Share
    .PARAMETER ADServiceUser
        Service User to connect the Portal-UserStore to an Active Directory
    .PARAMETER EnableAutomaticAccountCreation
        Enables the automaticAccountCreation on Portal
    .PARAMETER EnableEmailSettings
        Enable Email Settings on Portal
    .PARAMETER EmailSettingsSMTPServerAddress
        Email Settings SMTP server host on Portal
    .PARAMETER EmailSettingsFrom
        Email Settings SMTP Email From on Portal
    .PARAMETER EmailSettingsLabel
        Email Settings SMTP Email From Label on Portal
    .PARAMETER EmailSettingsAuthenticationRequired
        Email Settings SMTP Server Authentication Requirement Flag on Portal
    .PARAMETER EmailSettingsCredential
        Email Settings SMTP Server Host Authentication Credentials on Portal
    .PARAMETER EmailSettingsSMTPPort
        Email Settings SMTP Server Host Port on Portal
    .PARAMETER EmailSettingsEncryptionMethod
        Email Settings SMTP Server Encryption Method on Portal
    .PARAMETER EnableCreateSiteDebug
        Enable debug during create site operation
#>
function Invoke-CreatePortalSite{
    [CmdletBinding()]
    param(
        [System.String]
        $Version,

        [System.String]
        $URL, 

        [System.Management.Automation.PSCredential]
        $Credential, 

        [System.String]
        $FullName, 

        [System.String]
        $Email,

        [System.String]
        $Description,

        [System.String]
        $ContentDirectoryLocation,

        [System.String]
		$LicenseFilePath = $null,
        
		[System.String]
        $UserLicenseTypeId = $null,
        
        [System.Management.Automation.PSCredential]
        $AdminSecurityQuestionCredential,

        [System.String]
        [ValidateSet("None","Azure","AWS")]
        $CloudProvider = "None",

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("AccessKey","IAMRole", "None")]
        $AWSAuthenticationType = "None",

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSRegion,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSS3ContentBucketName,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AWSAccessKeyCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("AccessKey","ServicePrincipal","UserAssignedIdentity", "SASToken", "None")]
        $AzureAuthenticationType = "None",

        [parameter(Mandatory = $false)]
        [System.String]
        $AzureContentBlobContainerName,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureServicePrincipalCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureServicePrincipalTenantId,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureServicePrincipalAuthorityHost,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureUserAssignedIdentityClientId,
        
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureStorageAccountCredential,

        [System.Boolean]
        $EnableCreateSiteDebug = $false
    )

    $contentStore = @{}
    if($CloudProvider -ine "None"){
        if($CloudProvider -ieq "Azure"){
            $AccountName = $AzureStorageAccountCredential.UserName
            $EndpointSuffix = ''
            $Pos = $AzureStorageAccountCredential.UserName.IndexOf('.blob.')
            if($Pos -gt -1) {
                $AccountName = $AzureStorageAccountCredential.UserName.Substring(0, $Pos)
                $EndpointSuffix = $AzureStorageAccountCredential.UserName.Substring($Pos + 6) # Remove the hostname and .blob. suffix to get the storage endpoint suffix
            }
            
            $ConnectionString = @{
                accountName = $AccountName
                accountEndpoint = "blob.$($EndpointSuffix)"
            }

            if($AzureAuthenticationType -ieq "AccessKey"){
                $ConnectionString["accountKey"] = $AzureStorageAccountCredential.GetNetworkCredential().Password
                $ConnectionString["credentialType"] = "accessKey"
            }elseif($AzureAuthenticationType -ieq "UserAssignedIdentity"){
                $ConnectionString["managedIdentityClientId"] = $AzureUserAssignedIdentityClientId
                $ConnectionString["credentialType"] = "userAssignedIdentity"
            }elseif($AzureAuthenticationType -ieq "SASToken"){
                $ConnectionString["sasToken"] = $AzureStorageAccountCredential.GetNetworkCredential().Password
                $ConnectionString["credentialType"] = "sasToken"
            }elseif($AzureAuthenticationType -ieq "ServicePrincipal"){
                $ConnectionString["credentialType"] = "servicePrincipal"
                $ConnectionString["tenantId"] = $AzureServicePrincipalTenantId
                $ConnectionString["clientId"] = $AzureServicePrincipalCredential.UserName
                $ConnectionString["clientSecret"] = $AzureServicePrincipalCredential.GetNetworkCredential().Password
                if(-not([string]::IsNullOrEmpty($AzureServicePrincipalAuthorityHost))){
                    $ConnectionString["authorityHost"] = $AzureServicePrincipalAuthorityHost
                }
            }

            Write-Verbose "Using Content Store on Azure Cloud Storage"
            $contentStore = @{ 
                type = 'cloudStore'
                provider = 'Azure'
                connectionString = $ConnectionString
                objectStore = "https://$($AccountName).blob.$($EndpointSuffix)/$($AzureContentBlobContainerName)"
            }
        }elseif($CloudProvider -ieq "AWS"){

            Write-Verbose "Using Content Store in AWS S3 Storage $($AWSS3ContentBucketName)"
            $AWSConnectionString = @{
                region = $AWSRegion
            }

            if($AWSAuthenticationType -ieq "AccessKey"){
                $AWSConnectionString["credentialType"] = "accessKey"
                $AWSConnectionString["accessKeyId"] = $AWSAccessKeyCredential.UserName
                $AWSConnectionString["secretAccessKey"] = $AWSAccessKeyCredential.GetNetworkCredential().Password
            }else{
                $AWSConnectionString["credentialType"] = "IAMRole"
            }
            
            $contentStore = @{ 
                type = 'cloudStore'
                provider = 'Amazon'
                connectionString = $AWSConnectionString
                objectStore = $AWSS3ContentBucketName
            }

        }
    }else{
        Write-Verbose "Using Content Store on File System at location $ContentDirectoryLocation"
        $contentStore = @{
            type = 'fileStore'
            provider = 'FileSystem'
            connectionString = $ContentDirectoryLocation
        }
    }
    
    $CreateNewSiteUrl = Get-PortalAdminUrlForPath -URL $URL -Path "/createNewSite"
    $WebParams = @{ 
                    username = $Credential.UserName
                    password = $Credential.GetNetworkCredential().Password
                    fullname = $FullName
                    email = $Email
                    description = $Description
                    securityQuestionIdx = $AdminSecurityQuestionCredential.UserName
                    securityQuestionAns = $AdminSecurityQuestionCredential.GetNetworkCredential().Password
                    contentStore = ConvertTo-Json -Depth 5 $contentStore
                    f = 'json'
                }
    
    if(([version]$Version -ge "11.3") -and $EnableCreateSiteDebug){
        Write-Verbose "Enable Debug during create site operation"
        $WebParams["enableDebug"] = $EnableCreateSiteDebug
    }
    
    Write-Verbose "Making request to $CreateNewSiteUrl to create the site"
    $Response = $null
    if($LicenseFilePath){
        try{
            if($UserLicenseTypeId){
                $WebParams["userLicenseTypeId"] = $UserLicenseTypeId
            }
        
            $Response = Invoke-UploadFile -url $CreateNewSiteUrl -filePath $LicenseFilePath -fileContentType 'application/json' -fileParameterName 'file' `
                                 -Referer 'https://localhost' -formParams $WebParams -Verbose
            $Response = $Response | ConvertFrom-Json
        }catch{
            throw "Create portal site request failed. $_"
        }
    }else{
        $Response = Invoke-ArcGISWebRequest -Url $CreateNewSiteUrl -HttpFormParameters $WebParams -Referer 'https://localhost' -TimeOutSec 5400 -Verbose 
    }

    Write-Verbose "Response received from create site $( $Response | ConvertTo-Json -Depth 10 )"  
    if ($Response.error -and $Response.error.message) {
        throw $Response.error.message
    }
    if ($null -ne $Response.recheckAfterSeconds) {
        Wait-RecheckAfterSeconds -Seconds $Response.recheckAfterSeconds -Multiplier 2 -Verbose
    }
    
    Write-Verbose "Waiting for portal to start."
    try {
        $token = Get-PortalToken -URL $URL -Credential $Credential -Referer $URL -MaxAttempts 40
        if($token.token){
            Write-Verbose "Portal Site create successful. Was able to retrieve token from Portal."
        }
    } catch {
        Write-Verbose $_
    }
}

function Join-PortalSite {    
    [CmdletBinding()]
    param(
        [System.String]
        $URL, 

        [System.Management.Automation.PSCredential]
        $Credential, 

        [System.String]
        $PrimaryMachineHostName
    )
    
    $PrimaryPortalBaseURL = Get-ArcGISComponentBaseUrl -FQDN $PrimaryMachineHostName -ComponentName "Portal"
    Test-ArcGISComponentHealth -BaseURL $PrimaryPortalBaseURL -ComponentName "Portal" -MaxWaitTimeInSeconds 600 -SleepTimeInSeconds 30 -RequestTimeoutInSeconds 90 -Verbose

    [string]$JoinSiteUrl = Get-PortalAdminUrlForPath -URL $URL -Path "/joinSite"
    $WebParams = @{
                    username = $Credential.UserName
                    password = $Credential.GetNetworkCredential().Password
                    machineAdminUrl = $PrimaryPortalBaseURL.Replace('/arcgis', '')
                    f = 'json'
                  }

    Write-Verbose "Making request to $JoinSiteUrl"
    $Response = Invoke-ArcGISWebRequest -Url $JoinSiteUrl -HttpFormParameters $WebParams -TimeOutSec 1000 -Verbose 
    
	if ($Response) {
		Write-Verbose "Response received:- $(ConvertTo-Json -Depth 5 -Compress -InputObject $Response)"  
	}
    if ($Response.error -and $Response.error.message) {
		Write-Verbose "Error from Join Site:- $($Response.error.message)"

		Restart-ArcGISService -ComponentName 'Portal' -Verbose

		Write-Verbose "Wait for portal sharing endpoint for 10 minutes"
        Test-ArcGISComponentHealth -BaseURL $URL -ComponentName "PortalSharing" `
                                    -MaxWaitTimeInSeconds 600 -Verbose
		Write-Verbose "Finished waiting for portal sharing endpoint."

		Write-Verbose "Check primary with second round of health checks"
        Test-ArcGISComponentHealth -BaseURL $PrimaryPortalBaseURL -ComponentName "Portal" `
                                    -MaxWaitTimeInSeconds 600 -SleepTimeInSeconds 30 `
                                    -RequestTimeoutInSeconds 90 -Verbose

        Write-Verbose "Waiting 5 mins before retrying to join site."
		Start-Sleep -Seconds 300
		Write-Verbose "Making second attempt request to $JoinSiteUrl"
		$Response = Invoke-ArcGISWebRequest -Url $JoinSiteUrl -HttpFormParameters $WebParams -Referer 'https://localhost' -TimeOutSec 1000 -Verbose 
		if ($Response) {
			Write-Verbose "Response received on second attempt:- $(ConvertTo-Json -Depth 5 -Compress -InputObject $Response)"  
        } else {
			Write-Verbose "Response from Join Site was null"
		}

		if ($Response.error -and $Response.error.message) {
			Write-Verbose "Error from Join Site second attempt:- $($Response.error.message)"
			throw $Response.error.message
		}
    }

    if ($null -ne $Response.recheckAfterSeconds) {
        Wait-RecheckAfterSeconds -Seconds $Response.recheckAfterSeconds -Multiplier 6 -Verbose
    }

    Write-Verbose "Waiting for portal to start."
    try {
        $token = Get-PortalToken -URL $URL -Credential $Credential -Referer $URL -MaxAttempts 40
        if($token.token){
            Write-Verbose "Portal Site create successful. Was able to retrieve token from Portal."
        }
    } catch {
        Write-Verbose $_
    }
}


function Get-SSLCertificatesForPortal
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $WebServerCertificateAlias,

        [System.String]
        $Token,

        [System.String]
        $Referer,

        [System.String]
        $MachineName,

        [System.Boolean]
        $ThrowOnResponseError = $false
    )

	try {
        $GetCertURL = Get-PortalAdminUrlForPath -URL $URL -Path "/machines/$MachineName/sslCertificates"
        if($WebServerCertificateAlias){ $GetCertURL = $GetCertURL + "/$($WebServerCertificateAlias)" }
	    $response = Invoke-ArcGISWebRequest -Url $GetCertURL -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer -HttpMethod 'GET' -TimeOutSec 120
        if($ThrowOnResponseError){
            Confirm-ResponseStatus $response -Url $GetCertURL
        }
        $response
	}
	catch {
        if($ThrowOnResponseError){
            throw
        }
		Write-Verbose "[WARNING]:- Error running Get-SSLCertificatesForPortal:- $_"
	}
}

function Invoke-DeletePortalCertificate{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $WebServerCertificateAlias,

        [System.String]
        $Token,

        [System.String]
        $Referer,

        [System.String]
        $MachineName
    )
    try {
        $URL = Get-PortalAdminUrlForPath -URL $URL -Path "/machines/$MachineName/sslCertificates/$($WebServerCertificateAlias)/delete" 
        Invoke-ArcGISWebRequest -Url $URL -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer -HttpMethod 'POST' -TimeOutSec 120
    }catch{
        Write-Verbose "[WARNING]:- Error running Invoke-DeletePortalCertificate. Error:- $_"
    }
}

function Import-ExistingCertificate
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $CertAlias, 

        [System.Management.Automation.PSCredential]
        $CertificatePassword, 

        [System.String]
        $CertificateFilePath,

        [System.String]
        $MachineName,

        [System.String]
        $Version,

        [System.Boolean]
        $ImportCertificateChain = $true,

        # Opt in only when the caller can verify the imported alias and thumbprint. Retrying an
        # upload after a dropped response is unsafe because the first request may have committed.
        [System.Boolean]
        $ThrowOnResponseError = $false
    )
    $ImportCertUrl = Get-PortalAdminUrlForPath -URL $URL -Path "/machines/$MachineName/sslCertificates/importExistingServerCertificate" 
    $props = @{ f= 'json'; token = $Token; alias = $CertAlias; password = $CertificatePassword.GetNetworkCredential().Password  }
    # Version greater than equal to 11.3
    if  ([Version]$Version -ge 11.3) {
        $props["importCertificateChain"] = $ImportCertificateChain
    }
    $res = Invoke-UploadFile -url $ImportCertUrl -filePath $CertificateFilePath -fileContentType 'application/x-pkcs12' -formParams $props -Referer $Referer -fileParameterName 'file' -ThrowOnResponseError $ThrowOnResponseError
    if($res) {
        $response = $res | ConvertFrom-Json
        Confirm-ResponseStatus $response -Url $ImportCertUrl
    } else {
        Write-Verbose "[WARNING] Response from $ImportCertUrl was null"
    }
}

function Import-RootOrIntermediateCertificate
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $CertAlias, 

        [System.String]
        $CertificateFilePath,

        [System.String]
        $MachineName,

        [System.Boolean]
        $ImportCertificateChain = $true, # TODO fix

        [System.Boolean]
        $ThrowOnResponseError = $false
    )

    $ImportCertUrl =  Get-PortalAdminUrlForPath -URL $URL -Path "/machines/$MachineName/sslCertificates/importRootOrIntermediate" 
    $props = @{ f= 'json'; token = $Token; alias = $CertAlias; norestart = $true }
    try{
        $res = Invoke-UploadFile -url $ImportCertUrl -filePath $CertificateFilePath -fileContentType 'application/x-pkcs12' `
                                -formParams $props -Referer $Referer -fileParameterName 'file' `
                                -ThrowOnResponseError $ThrowOnResponseError
        if($res) {
            $response = $res | ConvertFrom-Json
            Confirm-ResponseStatus $response -Url $ImportCertUrl
        } else {
            throw "[WARNING] Response from $ImportCertUrl was null"
        }
    }catch{
	    if($ThrowOnResponseError){
	        throw
	    }
	    Write-Verbose "Error in Import-RootOrIntermediateCertificate :- $_"
    }
}

function Update-PortalSSLCertAliasOrHSTSSetting
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $CertAlias,

        [System.String]
        $MachineName,

        [System.Boolean]
        $HSTSEnabled
    )

    $SSLCertsObject = Get-SSLCertificatesForPortal -URL $URL -Token $Token -Referer $Referer -MachineName $MachineName

    $sslProtocols = if($null -eq $SSLCertsObject.sslProtocols) {"TLSv1.2,TLSv1.1,TLSv1"}else{$SSLCertsObject.sslProtocols}
    $cipherSuites = if($null -eq $SSLCertsObject.cipherSuites){ "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,TLS_DHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,TLS_DHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA" }else{ $SSLCertsObject.cipherSuites }
    $WebParams = @{ 
        f = 'json'
        token = $Token
        sslProtocols = $sslProtocols
        cipherSuites = $cipherSuites
    }

    if(-not([string]::IsNullOrEmpty($CertAlias))){
        $WebParams["HSTSEnabled"] = "$($SSLCertsObject.HSTSEnabled)"
        $WebParams["webServerCertificateAlias"] = $CertAlias
    }else{
        $WebParams["webServerCertificateAlias"] = $SSLCertsObject.webServerCertificateAlias
        $WebParams["HSTSEnabled"] = "$($HSTSEnabled)".ToLower();
    }
    $UpdateCertURL = Get-PortalAdminUrlForPath -URL $URL -Path "/machines/$MachineName/sslCertificates/update" 
    Invoke-ArcGISWebRequest -Url $UpdateCertURL -HttpFormParameters $WebParams -Referer $Referer -Verbose
}

function Get-PortalRootAndIntermdiateCertificatesToUpdate
{
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $True)]
        [System.String]
        $URL,

        [parameter(Mandatory = $True)]
        [System.String]
        $Token,

        [System.String]
        $Referer,

        [System.String]
        $MachineName, 

        [System.String]
        $SslRootOrIntermediate
    )

    $ExpectedCerts = ($SslRootOrIntermediate | ConvertFrom-Json)
    $Certs = Get-SSLCertificatesForPortal -URL $URL -Token $Token -Referer $Referer -MachineName $MachineName -ErrorAction SilentlyContinue
    $MissingCerts = @()
    foreach ($Cert in $ExpectedCerts){
        $CertificateAliases = ConvertTo-PortalCertificateAliases -Certificates $Certs.sslCertificates
        if ($CertificateAliases -icontains $Cert.Alias){
            Write-Verbose "Test RootOrIntermediate $($Cert.Alias) is in List of SSL-Certificates. Validating if thumbprint matches the existing certificate"
            $RootOrIntermediateCertForMachine = Get-SSLCertificatesForPortal -URL $URL -Token $Token -Referer $Referer -WebServerCertificateAlias $Cert.Alias -MachineName $MachineName
            Write-Verbose "Existing Cert Issuer $($RootOrIntermediateCertForMachine.Issuer) and Thumbprint $($RootOrIntermediateCertForMachine.sha1Fingerprint)"
            $NewCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $Cert.Path
            Write-Verbose "Issuer and Thumprint for the supplied certificate is $($NewCert.Issuer) and $($NewCert.Thumbprint) respectively."
            if($RootOrIntermediateCertForMachine.sha1Fingerprint -ine $NewCert.Thumbprint){
                Write-Verbose "Thumbprints for Certificate with Alias $($Cert.Alias) doesn't match that of existing cetificate."
                $Cert | Add-Member -NotePropertyName "Present" -NotePropertyValue $true
                $MissingCerts += ($Cert)
            }else{
                Write-Verbose "Thumbprints for Certificate with Alias $($Cert.Alias) match that of existing cetificate."
            }
        }else{
            Write-Verbose "Test RootOrIntermediate $($Cert.Alias) is NOT in List of SSL-Certificates"
            ($Cert | Add-Member -NotePropertyName "Present" -NotePropertyValue $False)
            $MissingCerts += ($Cert)
        }
    }

    return $MissingCerts
}

<#
    .SYNOPSIS
        Reconciles an indeterminate Portal root or intermediate certificate import.

    .DESCRIPTION
        Portal is asked not to restart for these imports, but upload responses can still be lost or
        returned as null. This helper verifies the durable postcondition instead of retrying: the
        requested alias must exist and contain the expected thumbprint. When credentials are supplied,
        a fresh token is obtained before verification.

        Root and intermediate certificates are trust entries, so endpoint-certificate validation does
        not apply to them.
#>
function Wait-ForPortalRootOrIntermediateCertificateState
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $Token,

        [System.Management.Automation.PSCredential]
        $Credential,

        [System.String]
        $Referer,

        [System.String]
        $MachineName,

        [System.String]
        $CertificateAlias,

        [System.String]
        $ExpectedThumbprint,

        $OperationError
    )

    try {
        Test-ArcGISComponentHealth -BaseURL $URL -ComponentName "Portal" `
                                    -MaxWaitTimeInSeconds 180 -SleepTimeInSeconds 5 -ThrowErrors $true -Verbose
        Test-ArcGISComponentHealth -BaseURL $URL -ComponentName "PortalSharing" `
                                    -MaxWaitTimeInSeconds 180 -SleepTimeInSeconds 5 -ThrowErrors $true -Verbose

        $verificationToken = $Token
        if($null -ne $Credential){
            $refreshedToken = Get-PortalToken -URL $URL -Credential $Credential -Referer $Referer
            if(-not($refreshedToken.token)){
                throw "Unable to retrieve a portal token after importing certificate '$CertificateAlias'."
            }
            $verificationToken = $refreshedToken.token
        }

        $certificate = Get-SSLCertificatesForPortal -URL $URL -Token $verificationToken -Referer $Referer `
                            -WebServerCertificateAlias $CertificateAlias.ToLower() -MachineName $MachineName
        if($null -eq $certificate -or $certificate.sha1Fingerprint -ine $ExpectedThumbprint){
            throw "Root or intermediate certificate '$CertificateAlias' does not have expected thumbprint '$ExpectedThumbprint'."
        }

        return $verificationToken
    }
    catch {
        if($null -ne $OperationError){
            throw "The root or intermediate certificate import response failed and the expected state could not be verified. Operation error: $OperationError Reconciliation error: $_"
        }
        throw
    }
}

function Set-PortalRootAndIntermdiateCertificates{
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $True)]
        [System.String]
        $URL,

        [parameter(Mandatory = $True)]
        [System.String]
        $Token,

        [System.String]
        $Referer,

        [System.String]
        $MachineName, 

        [System.Management.Automation.PSCredential]
        $Credential,

        [System.String]
        $SslRootOrIntermediate
    )

    $RestartRequired = $False
    $MissingCerts = Get-PortalRootAndIntermdiateCertificatesToUpdate -URL $URL `
                                                -Token $Token -Referer $Referer -MachineName $MachineName `
                                                -SslRootOrIntermediate $SslRootOrIntermediate -Verbose

    if(@($MissingCerts).Count -gt 0){
        $RestartRequired = $True
        foreach ($Cert in $MissingCerts){
            if($Cert.Present){
                Write-Verbose "Thumbprints for certificate with alias $($Cert.Alias) doesn't match that of existing cetificate. Deleting existing certificate"
                $res = Invoke-DeletePortalCertificate -URL $URL -Token $Token -Referer $Referer -MachineName $MachineName -WebServerCertificateAlias $Cert.Alias.ToLower()
                Write-Verbose "Existing certificate delete successful - $($res | ConvertTo-Json)"
            }

            $expectedCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $Cert.Path
            $importError = $null
            try{
                Import-RootOrIntermediateCertificate -URL $URL -Token $Token -Referer $Referer -MachineName $MachineName `
                                                    -CertAlias $Cert.Alias.ToLower() -CertificateFilePath $Cert.Path `
                                                    -ThrowOnResponseError $true
            }catch{
                # Do not retry an indeterminate upload; verify whether Portal committed it.
                $importError = $_
            }

            $Token = Wait-ForPortalRootOrIntermediateCertificateState -URL $URL -Token $Token -Credential $Credential `
                            -Referer $Referer -MachineName $MachineName -CertificateAlias $Cert.Alias `
                            -ExpectedThumbprint $expectedCertificate.Thumbprint -OperationError $importError -Verbose
            Write-Verbose "Import of RootOrIntermediate Certificate with Alias $($Cert.Alias) verified successfully."
        }
    }
    
    if($RestartRequired){
        Write-Verbose "Portal root and intermediate certificates were updated. Restart required."
    }

    return $RestartRequired
}

function Unregister-PortalSiteMachine{
    param(
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $MachineFQDN
    )

    $MachineUnregisterURL = Get-PortalAdminUrlForPath -URL $URL -Path "/machines/unregister"
    $MachineInSiteFlag = $False
    $FormParameters = @{ f = 'json'; token = $Token; machineName = $MachineFQDN }
    try{
        $Response = Invoke-ArcGISWebRequest -Url $MachineUnregisterURL -HttpFormParameters $FormParameters -Referer $Referer -TimeOutSec 120
    }catch{
        $MachineInSiteFlag = Test-MachineInPortalSite -URL $URL -Token $Token -Referer $Referer -MachineFQDN $MachineFQDN
    }
    if($null -ne $Response){
        Write-Verbose (ConvertTo-Json -Depth 5 $Response)
    }

    if(($Response.status -ieq "success") -or -not($MachineInSiteFlag)){
        Wait-ForArcGISComponentRestart -BaseURL $URL -ComponentName "Portal" -RestartComponentName "PortalSharing" -MaxRestartWaitTimeInSeconds 180 -MaxStartupWaitTimeInSeconds 180 -Verbose
    }else{
        throw "Unable to Unregister Portal! Please run the configuration again!"
    }
}

function Test-MachineInPortalSite {
    param(
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $MachineFQDN
    )

    $Machines = Get-MachinesInPortalSite -URL $URL -Token $Token -Referer $Referer
    return (($Machines | Where-Object { $_.machineName -ieq $MachineFQDN } | Measure-Object).Count -gt 0 )
}

function Get-MachinesInPortalSite
{
    param(
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer
    )

    $GetMachinesURL = Get-PortalAdminUrlForPath -URL $URL -Path "/machines" 
    $machinesResponse = Invoke-ArcGISWebRequest -Url $GetMachinesURL -HttpFormParameters @{ f = 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET'
    return $machinesResponse.machines
}

function Test-PortalAdminHealth{
    param(
        [System.String]
        $URL, 

        [System.String]
        $Referer,

        [System.Int32]
        $MaxAttempts = 1
    )

    $result = $false
    $PortalAdminHealthCheckURL = Get-PortalAdminUrlForPath -URL $URL -Path "/healthCheck"
    while(-not($result) -and ($Attempts -lt $MaxAttempts)) {
        Write-Verbose "Making request to health check URL '$PortalAdminHealthCheckURL'" 
        try {
            $Response = Invoke-ArcGISWebRequest -Url $PortalAdminHealthCheckURL -TimeOutSec 90 -HttpFormParameters @{ f = 'json' } -Referer $Referer -Verbose -HttpMethod 'GET'
            if ($Response.status){
                if($Response.status -ieq "success"){
                    Write-Verbose "Health check succeeded"
                    $result = $true
                }elseif ($Response.status -ieq "error") { 
                    throw [string]::Format("ERROR: {0}",($Response.messages -join " "))
                }else{
                    throw "Unknown Error"
                }
            }else{
                $jsresponse = ConvertTo-Json $Response -Compress -Depth 5
                Write-Verbose "[WARNING] Portal health check response - $jsresponse "
                if ($Response.error) { 
                    $errMsgs = if($Response.error.messages){ ($Response.error.messages -join ' ') }else{ $Response.error.message }
                    throw "ERROR: $errMsgs"
                }else{
                    throw "Unknown Error"
                }
            }
        } catch {
            Write-Verbose "Health check did not succeed. Error:- $_"
            Start-Sleep -Seconds 30
            $Attempts = $Attempts + 1
        }
    }
    return $result
}


function Get-PortalSystemProperties {
    [CmdletBinding()]
    param(        
        [System.String]
		$URL, 

        [System.String]
		$Token, 

        [System.String]
		$Referer = 'https://localhost'
    )
    
    $GetSystemPropertiesURL = (Get-PortalAdminUrlForPath -URL $URL -Path "/system/properties/")
    Invoke-ArcGISWebRequest -Url $GetSystemPropertiesURL -HttpMethod 'GET' -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer 
}

function Set-PortalSystemProperties {
    [CmdletBinding()]
    param(
        
        [System.String]
		$URL, 

        [System.String]
		$Token, 

        [System.String]
		$Referer = 'https://localhost',

        $Properties
    )
    
    $UpdateSystemPropertiesURL = (Get-PortalAdminUrlForPath -URL $URL -Path "/system/properties/update/")
    try {
        Invoke-ArcGISWebRequest -Url $UpdateSystemPropertiesURL `
                            -HttpFormParameters @{ f = 'json'; token = $Token; properties = (ConvertTo-Json $Properties -Depth 5) } `
                            -Referer $Referer -TimeOutSec 360
    }
    catch {
        Write-Verbose "[WARNING] Request to Set-PortalSystemProperties returned error:- $_"
    }
}

function Get-PortalSecurityConfig {
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'https://localhost'
    )   

    $GetSecurityPropertiesURL = (Get-PortalAdminUrlForPath -URL $URL -Path "/security/config")
    Invoke-ArcGISWebRequest -Url $GetSecurityPropertiesURL `
                        -HttpFormParameters @{ f = 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET'
}

function Set-PortalSecurityConfig {
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'https://localhost',

        [System.String]
        $SecurityParameters
    )   

    $UpdateSecurityPropertiesURL = (Get-PortalAdminUrlForPath -URL $URL -Path "/security/config/update")
    $params = @{ f = 'json'; token = $Token; securityConfig = $SecurityParameters;}
    $resp = Invoke-ArcGISWebRequest -Url $UpdateSecurityPropertiesURL `
                        -HttpFormParameters $params -Referer $Referer -TimeOutSec 100 -Verbose
    if($resp.error -and $resp.error.message){
        throw "[Error] - Set-PortalSecurityConfig Response:- $($resp.error.message)"
    }
}

function Set-PortalUserStoreConfig {
    [CmdletBinding()]
    param(
        [System.String]
        $URL,
        
        [System.String]
        $Token, 

        [System.String]
        $Referer = 'https://localhost',

        [System.Management.Automation.PSCredential]
        $ADServiceUser
    )

    $userStoreConfig = '{
        "type": "WINDOWS",
        "properties": {
            "userPassword": "' + $($ADServiceUser.GetNetworkCredential().Password) +'",
            "isPasswordEncrypted": "false",
            "user": "' + $($ADServiceUser.UserName.Replace("\","\\")) +'",
            "userFullnameAttribute": "cn",
            "userEmailAttribute": "mail",
            "userGivenNameAttribute": "givenName",
            "userSurnameAttribute": "sn",
            "caseSensitive": "false"
        }
    }'

    $UpdateIdentityStoreURL = Get-PortalAdminUrlForPath -URL $URL -Path "/security/config/updateIdentityStore"
    $response = Invoke-ArcGISWebRequest -Url $UpdateIdentityStoreURL `
                                -HttpFormParameters @{ f = 'json'; token = $Token; userStoreConfig = $userStoreConfig; } `
                                -Referer $Referer -TimeOutSec 300 -Verbose
    if ($response.error) {
        throw "Error in Set-PortalUserStoreConfig:- $($response.error)"
    } else {
        Write-Verbose "Response received from Portal Set UserStoreconfig:- $response"
    }
}

function Get-PortalUserDefaults{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,
        
        [System.String]
        $Token, 

        [System.String]
        $Referer = 'https://localhost'
    )
    
    Invoke-ArcGISWebRequest -Url (Get-PortalSharingApiUrlForPath -URL $URL -Path "/portals/self/userDefaultSettings") `
                        -HttpFormParameters @{ f = 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET'
}

function Set-PortalUserDefaults{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'https://localhost',

        $UserDefaultsParameters
    )

	$params = @{ 
                f = 'json'; 
                token = $Token;
                role = $UserDefaultsParameters.role;
                userLicenseType = $UserDefaultsParameters.userLicenseType;
                groups = $UserDefaultsParameters.groups;
                userType = $UserDefaultsParameters.userType;
                apps = $UserDefaultsParameters.apps;
                appBundles = $UserDefaultsParameters.appBundles;
            }
    
    $resp = Invoke-ArcGISWebRequest -Url (Get-PortalSharingApiUrlForPath -URL $URL -Path "/portals/self/setUserDefaultSettings") -HttpFormParameters $params -Referer $Referer -Verbose
    if($resp.error -and $resp.error.message){
        throw "[Error] - Set-PortalUserDefaults Response:- $($resp.error.message)"
    }
}

function Get-PortalSelfDescription {
    [CmdletBinding()]
    param(        
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer = 'https://localhost'
    )
    
    Invoke-ArcGISWebRequest -Url (Get-PortalSharingApiUrlForPath -URL $URL -Path "/portals/self/") `
                        -HttpMethod 'GET' -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer 
}

function Set-PortalSelfDescription 
{
    [CmdletBinding()]
    param(
        
        [System.String]
        $URL,

        [System.String]
        $Token, 

        [System.String]
        $Referer = 'https://localhost',

        $Properties
    )
    
    try {
        $Properties += @{ token = $Token; f = 'json' }
        Invoke-ArcGISWebRequest -Url (Get-PortalSharingApiUrlForPath -URL $URL -Path "/portals/self/update/") `
                            -HttpFormParameters $Properties -Referer $Referer -TimeOutSec 360
    }
    catch {
        Write-Verbose "[WARNING] Request to Set-PortalSelfDescription returned error:- $_"
    }
}

function Get-PortalEmailSettings
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'https://localhost'
    ) 
    
    $GetEmailSettingsURL = Get-PortalAdminUrlForPath -URL $URL -Path "/system/emailSettings"
    $resp = Invoke-ArcGISWebRequest -Url $GetEmailSettingsURL `
                        -HttpFormParameters @{ f = 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET'
						
    if($resp.status -and $resp.status -ieq "error"){
        throw "[Error] - Get-PortalEmailSettings Response:- $($resp.messages)"
    }
	
	$resp 
}

function Update-PortalEmailSettings
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'https://localhost',

        [System.String]
        $SMTPServerAddress,

        [System.String]
        $From,

        [System.String]
        $Label,

        [System.Boolean]
        $AuthenticationRequired = $False,

        [System.Management.Automation.PSCredential]
        $Credential,
        
        [System.Int32]
        $SMTPPort = 25,
         
        [System.String]
        $EncryptionMethod
    )

    $emailSettingObject = @{
        smtpServer = $SMTPServerAddress;
        fromEmailAddress = $From;
        fromEmailAddressLabel = $Label;
        authRequired = if($AuthenticationRequired){ "yes" }else{ "no" };
        smtpPort = $SMTPPort;
        encryptionMethod = $EncryptionMethod;
		f = 'json'; 
		token = $Token;
    }

    if($AuthenticationRequired){
        $emailSettingObject.Add("username",$Credential.UserName)
        $emailSettingObject.Add("password",$Credential.GetNetworkCredential().Password)
    }

    $UpdateEmailSettingsURL = Get-PortalAdminUrlForPath -URL $URL -Path "/system/emailSettings/update"
    $resp = Invoke-ArcGISWebRequest -Url $UpdateEmailSettingsURL `
                        -HttpFormParameters $emailSettingObject -Referer $Referer -Verbose
    if($resp.error -and $resp.error.message){
        throw "[Error] - Update-PortalEmailSettings Response:- $($resp.error.message)"
    }else{
        if($resp.status -and $resp.status -ieq "success"){
            if ($null -ne $resp.recheckAfterSeconds) {
                Wait-RecheckAfterSeconds -Seconds $resp.recheckAfterSeconds -Multiplier 2 -Verbose
            }
            Write-Verbose "Update-PortalEmailSettings successful."
        }
    }
}

function Remove-PortalEmailSettings
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'https://localhost'
    )  
    
    $RemoveEmailSettingsURL = Get-PortalAdminUrlForPath -URL $URL -Path "/system/emailSettings/delete"
    $resp = Invoke-ArcGISWebRequest -Url $RemoveEmailSettingsURL `
                        -HttpFormParameters @{ f = 'json'; token = $Token; } -Referer $Referer -Verbose
    if($resp.error -and $resp.error.message){
        throw "[Error] - Remove-PortalEmailSettings Response:- $($resp.error.message)"
    }
}

function Invoke-UpgradeReindex
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL, 
        
        [System.String]
		$Token, 

        [System.String]
		$Referer = 'https://localhost'
        
    )

    [string]$ReindexSiteUrl = Get-PortalAdminUrlForPath -URL $URL -Path "/system/indexer/reindex"

    $WebParams = @{ 
                    mode = 'FULL_MODE'
                    f = 'json'
                    token = $Token
                  }

    Write-Verbose "Making request to $ReindexSiteUrl to create the site"
    $Response = Invoke-ArcGISWebRequest -Url $ReindexSiteUrl -HttpFormParameters $WebParams -Referer $Referer -TimeOutSec 3000 -Verbose 
    $ResponseJSON = (ConvertTo-JSON $Response -Depth 5 -Compress )
    Write-Verbose "Response received from Reindex site $ResponseJSON"  
    if($Response.error -and $Response.error.message) {
        throw $Response.error.message
    }
    if($Response.status -ieq 'success') {
        Write-Verbose "Reindexing Successful"
    }
}

function Get-LivingAtlasStatus
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [System.String]
        $URL,
        
        [System.String]
        $Token,

        [System.String]
        $Referer = 'https://localhost'
    )
    
    $LAStatusURL =  Get-PortalSharingApiUrlForPath -URL $URL -Path "/search"
    $resp = Invoke-ArcGISWebRequest -Url $LAStatusURL -HttpFormParameters @{ f = 'json'; token = $Token; q = "owner:esri_livingatlas" } -Referer $Referer
    if($resp.total -gt 0){
        Write-Verbose "Living Atlas content found."
        $true
    }else{
        Write-Verbose "Living Atlas content not found."
        $false
    }
}

function Get-LivingAtlasGroupIds
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [System.String]
        $URL,
        
        [System.String]
        $Token,

        [System.String]
        $Referer = 'https://localhost'
    )
    $result = @()
    $LAGroupIdsURL = Get-PortalSharingApiUrlForPath -URL $URL -Path "/community/groups"
    $resp = Invoke-ArcGISWebRequest -Url $LAGroupIdsURL -HttpFormParameters @{ f = 'json'; token = $Token; q = "owner:esri_livingatlas" } -Referer $Referer
    if($resp.total -gt 0){
        foreach($group in $resp.results){
            $result += $group.id
        }
    }
    $result
}

function Invoke-UpgradeLivingAtlas
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'https://localhost'
    )

    $LivingAtlasGroupIds = Get-LivingAtlasGroupIds -URL $URL -Referer $Referer -Token $Token
    foreach($groupId in $LivingAtlasGroupIds){
        $done = $False
        $attempts = 0
        while(-not($done)){
            $LAUpgradeURL =  Get-PortalAdminUrlForPath -URL $URL -Path "/system/content/livingatlas/upgrade"
            try{
				$resp = Invoke-ArcGISWebRequest -Url $LAUpgradeURL -HttpFormParameters @{ f = 'json'; token = $Token; groupId = $groupId } -Referer $Referer -Verbose
				if($resp.status -eq "success"){
					Write-Verbose "Upgraded Living Atlas Content For GroupId - $groupId"
                    $done = $True
				}
			}catch{         
                if($attempts -eq 3){
                    Write-Verbose "Unable to Living Atlas Content For GroupId - $groupId"
                }
            }
			if($attempts -eq 3){
                $done = $True
            }
			$attempts++
        }
    }
}

function Test-IfLivingAtlasUpgraded
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'https://localhost'
    )
    $result = $False
    $LivingAtlasGroupIds = Get-LivingAtlasGroupIds -URL $URL -Referer $Referer -Token $Token
    foreach($groupId in $LivingAtlasGroupIds){
        $done = $False
        $attempts = 0
        while(-not($done)){
            $LAUpgradeStatusCheckURL =  Get-PortalAdminUrlForPath -URL $URL -Path "/system/content/livingatlas/status"
            try{
				$resp = Invoke-ArcGISWebRequest -Url $LAUpgradeStatusCheckURL -HttpFormParameters @{ f = 'json'; token = $Token; groupId = $groupId } -Referer $Referer -Verbose
                if($resp.upgraded -eq $True -or $resp.upgraded -ieq 'true'){
                    $result = $True
                }else{
                    $result = $False
                }
                $done = $True
			}catch{
				if($attempts -eq 3){
					Write-Verbose "Unable to Living Atlas Content For GroupId - $groupId - Please Follow manual steps specified in the documentation"
					$done = $True
                    $result = $False
				}
			}
            if($attempts -eq 3){
                $done = $True
            }
			$attempts++
        }
        if($result -ieq $False){
            break
        }
    }
    $Result
}

function Test-PostUpgrade
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'https://localhost'
    )

    $PortalAdminURL = Get-PortalAdminUrlForPath -URL $URL
    $Response = Invoke-ArcGISWebRequest -Url $PortalAdminURL -HttpFormParameters @{ token = $Token; f = 'json' } -Referer $Referer -Verbose -HttpMethod "GET"
    return -not($Response.isPostUpgrade)
}

function Invoke-PostUpgrade
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'https://localhost'
    )

    Write-Verbose "Invoking Post Upgrade step"
    [string]$postUpgradeUrl =  Get-PortalAdminUrlForPath -URL $URL -Path "/postUpgrade"
    $postUpgradeResponse = Invoke-ArcGISWebRequest -Url $postUpgradeUrl -HttpFormParameters @{f = 'json'; token = $Token} -Referer $Referer -TimeOutSec 3000 -Verbose
    try{
        if($postUpgradeResponse.status -ieq "success" -or $postUpgradeResponse.status -ieq "success with warnings"){
            Write-Verbose "Post Upgrade Step Successful"
            if($postUpgradeResponse.status -ieq 'success with warnings'){
                Write-Verbose "[WARNING]:- $(ConvertTo-Json $postUpgradeResponse -Compress -Depth 5)"
            }

            if($postUpgradeResponse.recheckAfterSeconds){
                Wait-RecheckAfterSeconds -Seconds $postUpgradeResponse.recheckAfterSeconds -Multiplier 3 -Verbose
            }
        }else{
            $ResponseJSON = (ConvertTo-Json $postUpgradeResponse -Compress -Depth 5)
            throw "Post upgrade step failed. Response - $($ResponseJSON)"
        }
    }catch{
        throw  "[ERROR]:- $_"
    }
}

function Test-PortalUpgrade
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $Referer = 'https://localhost'
    )

    $result = $False

    $PortalAdminURL =  Get-PortalAdminUrlForPath -URL $URL
    try{
        $TestPortalResponse = Invoke-ArcGISWebRequest -Url $PortalAdminURL -HttpFormParameters @{ f = 'json' } -Referer $Referer -Verbose -HttpMethod 'GET'
        if($TestPortalResponse.status -ieq "error" -and $TestPortalResponse.isUpgrade -ieq $true -and $TestPortalResponse.messages[0] -ieq "The portal site has not been upgraded. Please upgrade the site and try again."){
            $result = $false
        }else{
            if(($null -ne $TestPortalResponse.error) -and $TestPortalResponse.error.message -ieq 'Token Required.'){
                Write-Verbose "Portal site is already upgraded."
                $result = $true
            }else{
                $jsresponse = ConvertTo-Json $TestPortalResponse -Compress -Depth 5
                throw "Unknown error. Response - $($jsresponse)"
            }
        }
    }catch{
        $result = $false
        Write-Verbose "[WARNING]:- $_"
    }
    return $result
}

function Invoke-UpgradePortal{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $Referer = 'https://localhost',

        [System.String]
        $Version,

        [System.Boolean]
        $EnableUpgradeSiteDebug,

        [System.String]
        $LicenseFilePath
    )

    Write-Verbose "Invoking portal site upgrade."
    [string]$UpgradeUrl = Get-PortalAdminUrlForPath -URL $URL -Path "/upgrade"

    $WebParams = @{ 
        isBackupRequired = $true
        isRollbackRequired = $true
        f = 'json'
    }

    if([version]$Version -ge "11.0"){
        $WebParams["async"] = $true
        if(([version]$Version -ge "11.2") -and $EnableUpgradeSiteDebug){
            Write-Verbose "Enabling Debug for Upgrade Site"
            $WebParams["enableDebug"] = $true
        }
    } 

    $UpgradeResponse = $null
    if($LicenseFilePath){ 
        $UpgradeResponse = Invoke-UploadFile -url $UpgradeUrl -filePath $LicenseFilePath -fileContentType 'application/json' -fileParameterName 'file' `
                            -Referer $Referer -formParams $WebParams -Verbose 
        $UpgradeResponse = ConvertFrom-JSON $UpgradeResponse
    } else {
        $UpgradeResponse = Invoke-ArcGISWebRequest -Url $UpgradeUrl -HttpFormParameters $WebParams -Referer $Referer -TimeOutSec 86400 -Verbose 
    }

    if($UpgradeResponse){
        if([version]$Version -ge "11.0"){
            if($UpgradeResponse.status -ieq "in progress"){
                Write-Verbose "Upgrade in Progress"
                $PortalReady = $false
                while(-not($PortalReady)){
                    $UpgradeResponse = Invoke-ArcGISWebRequest -Url $UpgradeUrl -HttpFormParameters @{f = 'json'} -Referer $Referer -Verbose -HttpMethod 'GET'
                    if($UpgradeResponse.status -ieq "in progress"){
                        Write-Verbose "Response received:- Upgrade in progress"  
                        Start-Sleep -Seconds 20
                        $Attempts = $Attempts + 1
                    }else{
                        Write-Verbose "Response received:- $($UpgradeResponse.status)"
                        break
                    }
                }
            }
        }

        if($UpgradeResponse.status -ieq 'success' -or $UpgradeResponse.status -ieq 'success with warnings') {
            Write-Verbose "Upgrade Successful"
            if($UpgradeResponse.status -ieq 'success with warnings'){
                Write-Verbose "[WARNING]:- $(ConvertTo-Json $UpgradeResponse -Compress -Depth 5)"
            }

            if($null -ne $UpgradeResponse.recheckAfterSeconds) 
            {
                Wait-RecheckAfterSeconds -Seconds $UpgradeResponse.recheckAfterSeconds -Multiplier 2 -Verbose
            }
            
            Test-PortalAdminHealth -URL $URL -MaxAttempts 10 -Referer $Referer -Verbose
        }else{
            throw  "[ERROR]:- $(ConvertTo-Json $UpgradeResponse -Compress -Depth 5)"
        }
    }else{
        throw "[ERROR]:- Upgrade failed. Null response returned."
    }
}

function Unregister-PortalWebAdaptor
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $WebAdaptorURL,

        [System.String]
        $Referer = 'https://localhost',

        [System.String]
        $Token
    )

    $WASystemUrl = Get-PortalAdminUrlForPath -URL $URL -Path "/system/webadaptors"
    $WebAdaptors = Invoke-ArcGISWebRequest -HttpMethod "GET" -Url $WASystemUrl -HttpFormParameters @{ token = $Token; f = 'json' } -Referer $Referer

    $WebAdaptors.webAdaptors | ForEach-Object {
        if($_.webAdaptorURL -ieq  $WebAdaptorUrl) {
            Write-Verbose "Webadaptor with URL $($_.webAdaptorURL) exists. Unregistering the web adaptor"
            Invoke-ArcGISWebRequest -Url ("$($WASystemUrl)/$($_.id)/unregister") -HttpFormParameters  @{ f = 'json'; token = $Token } -Referer $Referer -TimeOutSec 300    
        }
    }
}

Export-ModuleMember -Function *