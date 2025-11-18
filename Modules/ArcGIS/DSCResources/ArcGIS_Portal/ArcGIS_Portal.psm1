$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

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

function Invoke-CreatePortalSite {    
    [CmdletBinding()]
    param(
        [System.String]
        $Version,

        [System.String]
        $PortalHostNameFQDN, 

        [System.String]
        $PortalSiteName, 

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
    
    $CreateNewSiteUrl = "https://$($PortalHostNameFQDN):7443/$PortalSiteName/portaladmin/createNewSite"
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
    
    $VersionArray = $Version.Split('.')
    if(($VersionArray[0] -gt 11 -or ($VersionArray[0] -eq 11 -and $VersionArray[1] -ge 3 )) -and $EnableCreateSiteDebug){
        Write-Verbose "Enable Debug during create site operation"
        $WebParams["enableDebug"] = $EnableCreateSiteDebug
    }
    
    #$HttpRequestBody = ConvertTo-HttpBody -props $WebParams
    Write-Verbose "Making request to $CreateNewSiteUrl to create the site"
    $Response = $null
    if($LicenseFilePath){
        if($UserLicenseTypeId){
            $WebParams.userLicenseTypeId = $UserLicenseTypeId
        }
        $Response = Invoke-UploadFile -url $CreateNewSiteUrl -filePath $LicenseFilePath -fileContentType 'application/json' -fileParameterName 'file' `
                                 -Referer 'http://localhost' -formParams $WebParams -Verbose

        $Response = $Response | ConvertFrom-Json
    }else{
        $Response = Invoke-ArcGISWebRequest -Url $CreateNewSiteUrl -HttpFormParameters $WebParams -Referer 'http://localhost' -TimeOutSec 5400 -Verbose 
    }

    Write-Verbose "Response received from create site $( $Response | ConvertTo-Json -Depth 10 )"  
    if ($Response.error -and $Response.error.message) {
        throw $Response.error.message
    }
    if ($null -ne $Response.recheckAfterSeconds) {
        Write-Verbose "Sleeping for $($Response.recheckAfterSeconds * 2) seconds"
        Start-Sleep -Seconds ($Response.recheckAfterSeconds * 2)
    }
    
    Write-Verbose "Waiting for portal to start."
    try {
        $token = Get-PortalToken -PortalHostName $PortalHostNameFQDN -SiteName $PortalSiteName -Credential $Credential -Referer "https://$($PortalHostNameFQDN):7443" -MaxAttempts 40
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
        $PortalHostNameFQDN, 

        [System.Management.Automation.PSCredential]
        $Credential, 

        [System.String]
        $PeerMachineHostName
    )

    $PrimaryReady = $false
    $Attempts = 0
    while(-not($PrimaryReady) -and ($Attempts -lt 5)) {
        $HealthCheckUrl = "https://$($PeerMachineHostName):7443/arcgis/portaladmin/healthCheck/?f=json"
        Write-Verbose "Making request to health check URL '$HealthCheckUrl'" 
        try {
            $Response = Invoke-ArcGISWebRequest -Url $HealthCheckUrl -TimeoutSec 90 -HttpFormParameters @{ f = 'json' } -Referer $Referer -Verbose -HttpMethod 'GET'
            if ($Response.status){
                if($Response.status -ieq "success"){
                    Write-Verbose "Health check succeeded"
                    $PrimaryReady = $true
                }elseif ($Response.status -ieq "error") { 
                    throw [string]::Format("ERROR: {0}",($Response.messages -join " "))
                }else{
                    throw "Unknow Error"
                }
            }elseif ($Response.error) { 
                throw [string]::Format("ERROR: {0}",($Response.messages -join " "))
                throw "ERROR: $($Response.error.messages)"
            }else{
                throw "Unknow Error"
            }
        }catch {
            Write-Verbose "Health check did not suceed. Error:- $_"
            Start-Sleep -Seconds 30
            $Attempts = $Attempts + 1
        }        
    }

    $peerMachineAdminUrl = "https://$($PeerMachineHostName):7443"
    [string]$JoinSiteUrl = "https://$($PortalHostNameFQDN):7443/arcgis/portaladmin/joinSite"
    $WebParams = @{
                    username = $Credential.UserName
                    password = $Credential.GetNetworkCredential().Password
                    machineAdminUrl = $peerMachineAdminUrl
                    f = 'json'
                  }

    #$HttpRequestBody = ConvertTo-HttpBody -props $WebParams
	Write-Verbose "Making request to $JoinSiteUrl"
    $Response = Invoke-ArcGISWebRequest -Url $JoinSiteUrl -HttpFormParameters $WebParams -Referer 'http://localhost' -TimeOutSec 1000 -Verbose 
    #$Response = Invoke-RestMethod -Method Post -Uri $JoinSiteUrl -Body $HttpRequestBody -TimeoutSec 1000
	if ($Response) {
		Write-Verbose "Response received:- $(ConvertTo-Json -Depth 5 -Compress -InputObject $Response)"  
	}
    if ($Response.error -and $Response.error.message) {
		Write-Verbose "Error from Join Site:- $($Response.error.message)"

		$ServiceName = Get-ArcGISServiceName -ComponentName 'Portal'
		Restart-ArcGISService -ServiceName $ServiceName -Verbose

		Write-Verbose "Wait for endpoint 'https://$($PortalHostNameFQDN):7443/arcgis/portaladmin/' to initialize"
        Wait-ForUrl "https://$($PortalHostNameFQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET' -MaxWaitTimeInSeconds 600 -Verbose
		Write-Verbose "Finished Waiting for endpoint 'https://$($PortalHostNameFQDN):7443/arcgis/portaladmin/' to initialize. Sleeping for 5 minutes"

		Write-Verbose "Check primary with second round of health checks"
		$PrimaryReady = $false
		$Attempts = 0
		while(-not($PrimaryReady) -and ($Attempts -lt 5)) {
			$HealthCheckUrl = "https://$($PeerMachineHostName):7443/arcgis/portaladmin/healthCheck/?f=json"
			Write-Verbose "Making request to health check URL '$HealthCheckUrl'" 
			try {
				$Response = Invoke-ArcGISWebRequest -Url $HealthCheckUrl -TimeoutSec 90 -HttpFormParameters @{ f = 'json' } -Referer $Referer -Verbose -HttpMethod 'GET'
                if ($Response.status){
                    if($Response.status -ieq "success"){
                        Write-Verbose "Health check succeeded"
                        $PrimaryReady = $true
                    }elseif ($Response.status -ieq "error") { 
                        throw [string]::Format("ERROR: {0}",($Response.messages -join " "))
                    }else{
                        throw "Unknow Error"
                    }
                }elseif ($Response.error) { 
                    throw [string]::Format("ERROR: {0}",($Response.messages -join " "))
                    throw "ERROR: $($Response.error.messages)"
                }else{
                    throw "Unknow Error"
                }
			}catch {
				Write-Verbose "Health check did not suceed. Error:- $_"
				Start-Sleep -Seconds 30
				$Attempts = $Attempts + 1
			}        
		}

		Start-Sleep -Seconds 300
		Write-Verbose "Making second attempt request to $JoinSiteUrl"
		$Response = Invoke-ArcGISWebRequest -Url $JoinSiteUrl -HttpFormParameters $WebParams -Referer 'http://localhost' -TimeOutSec 1000 -Verbose 
   
		if ($Response) {
			Write-Verbose "Response received on second attempt:- $(ConvertTo-Json -Depth 5 -Compress -InputObject $Response)"  
        }
        else {
			Write-Verbose "Response from Join Site was null"
		}

		if ($Response.error -and $Response.error.message) {
			Write-Verbose "Error from Join Site second attempt:- $($Response.error.message)"
			throw $Response.error.message
		}
    }

    if ($null -ne $Response.recheckAfterSeconds) {
        Write-Verbose "Sleeping for $($Response.recheckAfterSeconds*6) seconds"
        Start-Sleep -Seconds ($Response.recheckAfterSeconds * 6)
    }

    Write-Verbose "Waiting for portal to start."
    try {
        $token = Get-PortalToken -PortalHostName $PortalHostNameFQDN -SiteName 'arcgis' -Credential $Credential -Referer "https://$($PortalHostNameFQDN):7443/" -MaxAttempts 40
    } catch {
        Write-Verbose $_
    }
}

function Get-TargetResource {
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
        [parameter(Mandatory = $True)]    
        [System.String]
        $Version,

		[parameter(Mandatory = $true)]
        [System.String]
        $PortalHostName
	)

	$null
}

function Set-TargetResource {
	[CmdletBinding()]
	param
	(
        [parameter(Mandatory = $True)]    
        [System.String]
        $Version,

		[parameter(Mandatory = $True)]
        [System.String]
        $PortalHostName,

		[ValidateSet("Present", "Absent")]
		[System.String]
        $Ensure,
        
        [parameter(Mandatory = $false)]
		[System.String]
		$LicenseFilePath = $null,
        
        [parameter(Mandatory = $false)]
		[System.String]
        $UserLicenseTypeId = $null,

		[System.Management.Automation.PSCredential]
		$PortalAdministrator,

		[System.String]
		$AdminEmail,

        [System.String]
		$AdminFullName,

        [System.String]
		$AdminDescription,

		[System.Management.Automation.PSCredential]
		$AdminSecurityQuestionCredential,

        [System.Boolean]
		$Join,

        [System.Boolean]
		$EnableDebugLogging = $False,

        [System.String]
		$LogLevel = 'WARNING',

        [System.Boolean]
        $IsHAPortal,

        [System.String]
		$PeerMachineHostName,

        [System.String]
        $ContentDirectoryLocation,

        [parameter(Mandatory = $True)]    
        [System.String]
        [ValidateSet("None","Azure","AWS")]
        $CloudProvider = "None",

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("AccessKey","IAMRole", "None")]
        $AWSAuthenticationType = "None",

        [parameter(Mandatory = $false)]
        [System.String]
        $AWSS3ContentBucketName,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSRegion,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AWSAccessKeyCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("AccessKey","ServicePrincipal","UserAssignedIdentity", "SASToken", "None")]
        $AzureAuthenticationType = "None",

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureStorageAccountCredential,

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
        [System.Boolean]
        $EnableCreateSiteDebug
    )
    
    if ($VerbosePreference -ne 'SilentlyContinue') {        
        Write-Verbose ("PortalAdmin UserName:- " + $PortalAdministrator.UserName) 
        #Write-Verbose ("PortalAdmin Password:- " + $PortalAdministrator.GetNetworkCredential().Password) 
    }

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $FQDN = if($PortalHostName){ Get-FQDN $PortalHostName }else{ Get-FQDN $env:COMPUTERNAME } 
    $ServiceName = Get-ArcGISServiceName -ComponentName 'Portal'
    $VersionArray = $Version.Split('.')
    $EnableHAPortalDebugLogging = if($IsHAPortal -and ($VersionArray[0] -eq 10 -and $VersionArray[1] -lt 8)){ $True }else{ $False }

	if ($EnableHAPortalDebugLogging -or $EnableDebugLogging) {
        if($EnableHAPortalDebugLogging){
            # Initially set log level to debug to allow Join Site to succeed
            Write-Verbose "Setup is Portal HA. Enable debug logging to troubleshoot JoinSite Failures"        
        }
        
        if (-not(Invoke-TestSetLoggingLevel -EnableDebugLogging $True -Verbose)) {
            $RestartRequired = $true
        }
    } else {
        if(-not($IsHAPortal)){
            Write-Verbose "Setup is Single machine Portal"
        }
        if (-not(Invoke-TestSetLoggingLevel -EnableDebugLogging $False -Verbose)) {
            $RestartRequired = $true
        }
    }

    if ($RestartRequired) {
        Restart-ArcGISService -ServiceName $ServiceName -Verbose
		Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin" -HttpMethod 'GET' -MaxWaitTimeInSeconds 600 -Verbose
    }    

    Write-Verbose "Portal at https://$($FQDN):7443"
    if ($Ensure -ieq 'Present') {
        Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin" -HttpMethod 'GET' -Verbose
        $Referer = 'http://localhost'
        $RestartRequired = $false
        
        $SiteCreatedCheckResponse = Invoke-ArcGISWebRequest -Url "https://$($FQDN):7443/arcgis/portaladmin" -HttpFormParameters @{ referer = $Referer; f = 'json' } -Referer $Referer -Verbose -HttpMethod "GET"
        if($SiteCreatedCheckResponse.error.message -ieq "Token Required." -and $SiteCreatedCheckResponse.error.code -eq 499){
            Write-Verbose "Portal Site is already created. Now checking if portal site is healthy."
            $Attempts = 0
            $PortalReady = $False
            while(-not($PortalReady) -and ($Attempts -lt 2)) {
                $SharingAPIURL = "https://$($FQDN):7443/arcgis/sharing/rest/info" 
                Write-Verbose "Making request to Sharing API Url - $SharingAPIURL" 
                try {
                    Invoke-ArcGISWebRequest -Url $SharingAPIURL -HttpFormParameters @{ referer = $Referer; f = 'json' } -Referer $Referer -Verbose -HttpMethod "GET"
                    Write-Verbose "Sharing API rest endpoint is available."
                    $PortalReady = $true
                }catch {
                    Write-Verbose "Sharing API rest endpoint is not available. Error:- $_. Restarting Portal."
                    Restart-ArcGISService -ServiceName $ServiceName -Verbose
                    Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin" -HttpMethod 'GET' -MaxWaitTimeInSeconds 600 -Verbose
                    $Attempts = $Attempts + 1
                }        
            }
            if(-not($PortalReady)){
                throw "Portal Site is not healthy. Please check your portal site deployment."
            }
        } else {
            if($SiteCreatedCheckResponse.status -ieq "error"){
                if($SiteCreatedCheckResponse.messages -icontains "The portal site has not been initialized. Please create a new site and try again."){
                    if($Join) {
                        $PeerMachineFQDN = Get-FQDN $PeerMachineHostName
                        Write-Verbose "Joining machine to portal site at peer $PeerMachineFQDN"   
                        Join-PortalSite -PortalHostNameFQDN $FQDN -Credential $PortalAdministrator -PeerMachineHostName $PeerMachineFQDN
                        Write-Verbose "Joined machine to portal site at peer $PeerMachineFQDN"   
                    } else {
                        Write-Verbose "Creating Portal Site" 
                        $PortalArguments = @{
                            Version = $Version
                            PortalHostNameFQDN = $FQDN
                            PortalSiteName = 'arcgis'
                            Credential = $PortalAdministrator
                            FullName = $AdminFullName
                            Email = $AdminEmail
                            Description = $AdminDescription
                            AdminSecurityQuestionCredential = $AdminSecurityQuestionCredential
                            LicenseFilePath = $LicenseFilePath
                            UserLicenseTypeId = $UserLicenseTypeId
                            EnableCreateSiteDebug = $EnableCreateSiteDebug
                        }

                        if($CloudProvider -ieq "None"){
                            $PortalArguments["ContentDirectoryLocation"] = $ContentDirectoryLocation
                        }else{
                            $PortalArguments["CloudProvider"] = $CloudProvider
                            if($CloudProvider -ieq "Azure"){
                                $PortalArguments["AzureAuthenticationType"] = $AzureAuthenticationType
                                $PortalArguments["AzureContentBlobContainerName"] = $AzureContentBlobContainerName
                                $PortalArguments["AzureStorageAccountCredential"] = $AzureStorageAccountCredential

                                if($AzureAuthenticationType -ieq "ServicePrincipal"){
                                    $PortalArguments["AzureServicePrincipalCredential"] = $AzureServicePrincipalCredential
                                    $PortalArguments["AzureServicePrincipalTenantId"] = $AzureServicePrincipalTenantId
                                    $PortalArguments["AzureServicePrincipalAuthorityHost"] = $AzureServicePrincipalAuthorityHost
                                }elseif($AzureAuthenticationType -ieq "UserAssignedIdentity"){
                                    $PortalArguments["AzureUserAssignedIdentityClientId"] = $AzureUserAssignedIdentityClientId
                                }
                            }elseif($CloudProvider -ieq "AWS"){
                                $PortalArguments["AWSAuthenticationType"] = $AWSAuthenticationType
                                $PortalArguments["AWSS3ContentBucketName"] = $AWSS3ContentBucketName
                                $PortalArguments["AWSRegion"] = $AWSRegion
                                if($AWSAuthenticationType -ieq "AccessKey"){
                                    $PortalArguments["AWSAccessKeyCredential"] = $AWSAccessKeyCredential
                                }
                            }
                        }

                        Invoke-CreatePortalSite @PortalArguments -Verbose
                        
                        Write-Verbose 'Created Portal Site'
                    }
                }else{
                    throw "[Error] - Response:- $(ConvertTo-JSON $SiteCreatedCheckResponse -Compress)"
                }
            }
        }

        Write-Verbose "Waiting for 'https://$($FQDN):7443/arcgis/portaladmin/healthCheck?f=json'"
        Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/healthCheck?f=json" -HttpMethod 'GET' -Verbose
        Write-Verbose "Finished Waiting for 'https://$($FQDN):7443/arcgis/portaladmin/healthCheck?f=json'"

        $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
        Write-Verbose "Portal Site created. Successfully retrieved token for $($PortalAdministrator.UserName)"

        #Populating Licenses
        if(-not($Join) -and $LicenseFilePath){
            $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer -Verbose
            $populateLicenseCheck =  Invoke-ArcGISWebRequest -Url "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod "GET" -HttpFormParameters @{f = 'json'; token = $token.token} -Referer $Referer -Verbose 
            if(-not($populateLicenseCheck.isLicensePopulated)){
                Write-Verbose 'Populating Licenses'
                [string]$populateLicenseUrl = "https://$($FQDN):7443/arcgis/portaladmin/license/populateLicense"
                $populateLicenseResponse = Invoke-ArcGISWebRequest -Url $populateLicenseUrl -HttpMethod "POST" -HttpFormParameters @{f = 'json'; token = $token.token} -Referer $Referer -TimeOutSec 3000 -Verbose 
                if ($populateLicenseResponse.error -and $populateLicenseResponse.error.message) {
                    Write-Verbose "Error from Populate Licenses:- $($populateLicenseResponse.error.message)"
                    throw $populateLicenseResponse.error.message
                }
            }
        }

        $DesiredLogLevel = $LogLevel
        if($VersionArray[0] -eq 10 -and $VersionArray[1] -lt 8){       
            if ($IsHAPortal) {
                if (-not($Join)) {
                    # On Primary machine
                    # Initially set log level to debug to allow Join Site to succeed
                    Write-Verbose "Setup is Portal HA. On Primary Machine, enable debug logging to troubleshoot Join Site Failures"
                    $DesiredLogLevel = 'Debug'
                }
                else {
                    Write-Verbose "Setup is Portal HA. On secondary machine set portal log level to user defined value"
                }
            }
            else {
                Write-Verbose "Setup is Single machine Portal. Use desired log level '$DesiredLogLevel' as specified by user"
            }
        }
        
        $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
        $LogSettings = Get-PortalLogSettings -PortalHostName $FQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer 
		if ($LogSettings -and $LogSettings.logLevel) {
			$CurrentLogLevel = $LogSettings.logLevel
			if ($CurrentLogLevel -ne $DesiredLogLevel) {
				Write-Verbose "Portal CurrentLogLevel '$CurrentLogLevel' does not match desired value of '$DesiredLogLevel'. Updating it"
				$LogSettings.logLevel = $DesiredLogLevel
				Set-PortalLogSettings -PortalHostName $FQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer -LogSettings $LogSettings
            }
            else {
				Write-Verbose "Portal CurrentLogLevel '$CurrentLogLevel' matches desired value of '$DesiredLogLevel'"
			}
        }
        else {
			Write-Verbose "[WARNING] Unable to retrieve current log settings from portal admin"
		}

		if($IsHAPortal -and ($Join -and ($VersionArray[0] -eq 10 -and $VersionArray[1] -lt 8))) {	
            # On the secondary Portal machine, 
            # Finally set log level to user defined
            if(Set-LoggingLevel -EnableDebugLogging $EnableDebugLogging) {
                Restart-ArcGISService -ServiceName $ServiceName -Verbose
                Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/healthCheck/?f=json" -HttpMethod 'GET' -MaxWaitTimeInSeconds 600 -Verbose
            }
        }
    }
    elseif ($Ensure -ieq 'Absent') {
        Write-Warning 'Site Delete not implemented'
    }
}

function Test-TargetResource {
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [parameter(Mandatory = $True)]    
        [System.String]
        $Version,

		[parameter(Mandatory = $True)]
        [System.String]
        $PortalHostName,
        
        [ValidateSet("Present", "Absent")]
		[System.String]
        $Ensure,
        
        [parameter(Mandatory = $false)]
		[System.String]
		$LicenseFilePath = $null,
        
        [parameter(Mandatory = $false)]
		[System.String]
        $UserLicenseTypeId = $null,

		[System.Management.Automation.PSCredential]
		$PortalAdministrator,

		[System.String]
		$AdminEmail,

        [System.String]
		$AdminFullName,

        [System.String]
		$AdminDescription,

        [System.Management.Automation.PSCredential]
		$AdminSecurityQuestionCredential,

        [System.Boolean]
		$Join,

        [System.Boolean]
		$EnableDebugLogging = $False, 

        [System.String]
		$LogLevel = 'WARNING',

        [System.Boolean]
        $IsHAPortal,

        [System.String]
		$PeerMachineHostName,

        [System.String]
        $ContentDirectoryLocation,

        [parameter(Mandatory = $True)]    
        [System.String]
        [ValidateSet("None","Azure","AWS")]
        $CloudProvider = "None",

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("AccessKey","IAMRole", "None")]
        $AWSAuthenticationType = "None",

        [parameter(Mandatory = $false)]
        [System.String]
        $AWSS3ContentBucketName,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSRegion,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AWSAccessKeyCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("AccessKey","ServicePrincipal","UserAssignedIdentity", "SASToken", "None")]
        $AzureAuthenticationType = "None",

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureStorageAccountCredential,

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
        [System.Boolean]
        $EnableCreateSiteDebug
	)

    
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $FQDN = if($PortalHostName){ Get-FQDN $PortalHostName }else{ Get-FQDN $env:COMPUTERNAME }
    $result = $false

    $result = Invoke-TestSetLoggingLevel -EnableDebugLogging $EnableDebugLogging -TestOnly $true -Verbose
    
    if ($result) {
        try{
            $Referer = 'http://localhost'
            Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET' -Verbose   
            $SiteCreatedCheckResponse = Invoke-ArcGISWebRequest -Url "https://$($FQDN):7443/arcgis/portaladmin" -HttpFormParameters @{ referer = $Referer; f = 'json' } -Referer $Referer -Verbose -HttpMethod "GET"
            if($SiteCreatedCheckResponse.error.message -ieq "Token Required." -and $SiteCreatedCheckResponse.error.code -eq 499){
                Write-Verbose "Portal Site is already created."
                try {
                    $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
                    if (-not($token.token)) {
                        Write-Verbose "Unable to retrive token from portal site"   
                        $result = $false
                    } else {
                        Write-Verbose "Portal Site already created. Successfully retrieved token for $($PortalAdministrator.UserName)"
                    }
                } catch {
                    Write-Verbose "Unable to retrive token from portal site - $_" 
                    $result = $false
                }
            }else{
                if($SiteCreatedCheckResponse.status -ieq "error"){
                    Write-Verbose "Unable to detect portal site - $(ConvertTo-JSON $SiteCreatedCheckResponse -Compress)"
                    $result = $false
                }
            }
        }catch{
            Write-Verbose "Unable to detect portal site - $_)"
            $result = $false
        }
    }

    if($result -and -not($Join) -and $LicenseFilePath){
        Write-Verbose "Checking if portal licenses are populated"
        Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET' -Verbose
        $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
        $populateLicenseCheck = Invoke-ArcGISWebRequest -Url "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod "GET" -HttpFormParameters @{f = 'json'; token = $token.token} -Referer $Referer -Verbose 
        $result = $populateLicenseCheck.isLicensePopulated
        if($result){
            Write-Verbose "Portal Licenses are populated"
        }else{
            Write-Verbose "Portal Licenses are not populated. Will be populated."
        }
    }

    if ($result) {        
        Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET' -Verbose
        $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer     
        
        $LogSettings = Get-PortalLogSettings -PortalHostName $FQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer
        $CurrentLogLevel = $LogSettings.logLevel
        if ($CurrentLogLevel -ne $LogLevel) {
            Write-Verbose "Portal CurrentLogLevel '$CurrentLogLevel' does not match desired value of '$LogLevel'"
            $result = $false
        }
        else {
            Write-Verbose "Portal CurrentLogLevel '$CurrentLogLevel' matches desired value of '$LogLevel'"
        }
    }

    if ($Ensure -ieq 'Present') {
	       $result   
    } elseif ($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}

function Invoke-TestSetLoggingLevel {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [System.Boolean]
        $EnableDebugLogging,

        [System.Boolean]
        $TestOnly = $false
    )

    $ExpectedLogLevelFound = $True
    $ServiceName = Get-ArcGISServiceName -ComponentName 'Portal'
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir  
    $PropertiesFile = Join-Path $InstallDir 'framework\runtime\tomcat\conf\logging.properties'
    @('org.apache.catalina.core.ContainerBase.[Catalina].[localhost].level', '1catalina.org.apache.juli.FileHandler.level', '2localhost.org.apache.juli.FileHandler.level', '3portal.org.apache.juli.FileHandler.level', 'java.util.logging.ConsoleHandler.level') | ForEach-Object {
        $PropertyName = $_
        $DesiredLoggingLevel = $null
        if ($EnableDebugLogging) {
            $DesiredLoggingLevel = 'ALL' 
        }
        else { 
            # Default values for the levels
            if ($PropertyName -eq '3portal.org.apache.juli.FileHandler.level') {
                $DesiredLoggingLevel = 'INFO' 
            }
            elseif ($PropertyName -eq 'java.util.logging.ConsoleHandler.level') {
                $DesiredLoggingLevel = 'FINE'
            }
            else {
                $DesiredLoggingLevel = 'SEVERE'
            }
        }          
            
        $CurrentLoggingLevel = Get-PropertyFromPropertiesFile -PropertiesFilePath $PropertiesFile -PropertyName $PropertyName
        if ($CurrentLoggingLevel -ne $DesiredLoggingLevel) {
            if($TestOnly){
                Write-Verbose "Portal Tomcat CurrentLoggingLevel '$CurrentLoggingLevel' does not match desired value of '$DesiredLoggingLevel' for property '$PropertyName'"
                $ExpectedLogLevelFound = $false
            }else{
                Write-Verbose "Portal Tomcat CurrentLoggingLevel '$CurrentLoggingLevel' does not match desired value of '$DesiredLoggingLevel'. Updating it"
                if (Confirm-PropertyInPropertiesFile -PropertiesFilePath $PropertiesFile -PropertyName $PropertyName -PropertyValue $DesiredLoggingLevel) {
                    Write-Verbose "Portal Tomcat logging level '$PropertyName' changed. Restart needed"
                    $ExpectedLogLevelFound = $false 
                }
            }
        }
        else {
            Write-Verbose "Portal Tomcat CurrentLoggingLevel '$CurrentLoggingLevel' matches desired value of '$DesiredLoggingLevel' for property '$PropertyName'"
        }
    }
    $ExpectedLogLevelFound
}

function Get-PortalLogSettings {
    [CmdletBinding()]
    param(
        [System.String]
        $PortalHostName = 'localhost',

        [System.String]
        $SiteName = 'arcgis',

        [System.Int32]
        $Port = 7443,

		[System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost'
    )   

    Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):$($Port)/$SiteName/portaladmin/logs/settings") -HttpFormParameters @{ f = 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET'
}

function Set-PortalLogSettings {
    [CmdletBinding()]
    param(
		[System.String]
        $PortalHostName = 'localhost',

        [System.String]
        $SiteName = 'arcgis',

        [System.Int32]
        $Port = 7443,

		[System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost',

        $LogSettings
    )   
        
    $FormParameters = @{ f = 'json'; token = $Token; logDir = $LogSettings.logDir; logLevel = $LogSettings.logLevel; maxErrorReportsCount = $LogSettings.maxErrorReportsCount; maxLogFileAge = $LogSettings.maxLogFileAge; usageMeteringEnabled = $LogSettings.usageMeteringEnabled }
    Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):$($Port)/$SiteName/portaladmin/logs/settings/edit") -HttpFormParameters $FormParameters -Referer $Referer -HttpMethod 'POST'
}

Export-ModuleMember -Function *-TargetResource
