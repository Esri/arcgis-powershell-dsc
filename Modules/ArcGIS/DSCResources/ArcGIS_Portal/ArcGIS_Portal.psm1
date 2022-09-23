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
    .PARAMETER AdminSecurityQuestionIndex
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
    .PARAMETER AdminSecurityAnswer
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
    .PARAMETER DisableServiceDirectory
        Disable the Services Directory on Portal
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
#>

function Invoke-CreatePortalSite {    
    [CmdletBinding()]
    param(
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
        $SecurityQuestionAnswer, 
        
        [System.String]
        $ContentDirectoryLocation,
        
        [System.String]
        $ContentDirectoryCloudConnectionString,
        
        [System.String]
        $ContentDirectoryCloudContainerName,
        
        [System.Int32]
        $SecurityQuestionIdx = 1, 
        
        [System.String]
        $Description,

		[System.String]
		$LicenseFilePath = $null,
        
		[System.String]
        $UserLicenseTypeId = $null
    )

    if ($ContentDirectoryCloudConnectionString -and $ContentDirectoryCloudConnectionString.Length -gt 0) {
        $Splits = $ContentDirectoryCloudConnectionString.Split(';')
        
        if($ContentDirectoryCloudConnectionString.IndexOf('AccountName=') -gt -1){
            $StorageEndpointSuffix = $null
            $StorageAccessKey = $null
            $StorageAccountName = $null
            $Splits | ForEach-Object {
                if(-not([string]::IsNullOrEmpty($_))){
                    $Pos = $_.IndexOf('=')
                    $Key = $_.Substring(0, $Pos)
                    $Value = $_.Substring($Pos + 1)
                    if ($Key -ieq 'AccountName') {             
                        $StorageAccountName = $Value
                    }
                    elseif ($Key -ieq 'EndpointSuffix') {
                        $StorageEndpointSuffix = $Value
                    }
                    elseif ($Key -ieq 'AccountKey') {
                        $StorageAccessKey = $Value
                    }
                }
            }
    
            $objectStoreLocation = "https://$($StorageAccountName).blob.$($StorageEndpointSuffix)/$ContentDirectoryCloudContainerName"
            Write-Verbose "Using Content Store on Azure Cloud Storage $objectStoreLocation"
            $contentStore = @{ 
                type = 'cloudStore'
                provider = 'Azure'
                connectionString = @{
                    accountName = $StorageAccountName
                    accountKey = $StorageAccessKey
                    accountEndpoint = 'blob.' + $StorageEndpointSuffix
                    credentialType = 'accessKey'
                }
                objectStore = $objectStoreLocation
            }
        
        } else {
            $AWSRegionName = $null
            $AWSAccessKeyId = $null
            $AWSSecretKey = $null
            $AWSS3BucketName = $null
            $Splits | ForEach-Object { 
                if(-not([string]::IsNullOrEmpty($_))){
                    $Pos = $_.IndexOf('=')
                    $Key = $_.Substring(0, $Pos)
                    $Value = $_.Substring($Pos + 1)
                    if ($Key -ieq 'REGION') {                 
                        $AWSRegionName = $Value
                    }
                    elseif ($Key -ieq 'ACCESS_KEY_ID') {
                        $AWSAccessKeyId = $Value 
                    }
                    elseif ($Key -ieq 'SECRET_KEY') {
                        $AWSSecretKey = $Value
                    }
                    elseif ($Key -ieq 'NAMESPACE') {
                        $AWSS3BucketName = $Value
                    }
                }
            }

            Write-Verbose "Using Content Store in AWS S3 Storage $AWSS3BucketName"
            $AWSConnectionString = @{}
            if($null -ne $AWSAccessKeyId -and $null -ne $AWSSecretKey){
                $AWSConnectionString = @{
                    region = $AWSRegionName
                    credentialType = "accessKey"
                    accessKeyId = $AWSAccessKeyId
                    secretAccessKey = $AWSSecretKey
                }
            }else{
                $AWSConnectionString = @{
                    region = $AWSRegionName
                    credentialType = "IAMRole"
                }
            }

            $contentStore = @{ 
                type = 'cloudStore'
                provider = 'Amazon'
                connectionString = $AWSConnectionString
                objectStore = $AWSS3BucketName
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
                    securityQuestionIdx = $SecurityQuestionIdx
                    securityQuestionAns = $SecurityQuestionAnswer
                    contentStore = ConvertTo-Json -Depth 5 $contentStore
                    f = 'json'
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

		$ServiceName = 'Portal for ArcGIS'
		Restart-ArcGISService -ServiceName $ServiceName -Verbose

		Write-Verbose "Wait for endpoint 'https://$($PortalHostNameFQDN):7443/arcgis/portaladmin/' to initialize"
        Wait-ForUrl "https://$($PortalHostNameFQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET' -Verbose
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

		[System.Byte]
		$AdminSecurityQuestionIndex,

		[System.String]
		$AdminSecurityAnswer,

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

        [System.String]
        $ContentDirectoryCloudConnectionString,

        [System.String]
        $ContentDirectoryCloudContainerName
    )
    
    if ($VerbosePreference -ne 'SilentlyContinue') {        
        Write-Verbose ("PortalAdmin UserName:- " + $PortalAdministrator.UserName) 
        #Write-Verbose ("PortalAdmin Password:- " + $PortalAdministrator.GetNetworkCredential().Password) 
    }

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $FQDN = if($PortalHostName){ Get-FQDN $PortalHostName }else{ Get-FQDN $env:COMPUTERNAME } 

    $ServiceName = 'Portal for ArcGIS'
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir  
    
    $VersionArray = $Version.Split('.')

    $RestartRequired = $false
    $hostname = Get-ConfiguredHostName -InstallDir $InstallDir
    if ($hostname -ieq $FQDN) {
        Write-Verbose "Configured hostname '$hostname' matches expected value '$FQDN'"        
    }
    else {
        Write-Verbose "Configured hostname '$hostname' does not match expected value '$FQDN'. Setting it"
        if (Set-ConfiguredHostName -InstallDir $InstallDir -HostName $FQDN) { 
            # Need to restart the service to pick up the hostname 
			Write-Verbose "hostname.properties file was modified. Need to restart the '$ServiceName' service to pick up changes"
            $RestartRequired = $true 
        }
    }

    if(Get-NodeAgentAmazonElementsPresent -InstallDir $InstallDir) {
        Write-Verbose "Removing EC2 Listener from NodeAgent xml file"
        if(Remove-NodeAgentAmazonElements -InstallDir $InstallDir) {
             # Need to restart the service to pick up the EC2
             $RestartRequired = $true
         }  
    }

    $InstallDir = Join-Path $InstallDir 'framework\runtime\ds' 

    if ((Test-Path -Path $InstallDir)) {    
        $expectedHostIdentifierType = if($FQDN -as [ipaddress]){ 'ip' }else{ 'hostname' }
        $hostidentifier = Get-ConfiguredHostIdentifier -InstallDir $InstallDir
        $hostidentifierType = Get-ConfiguredHostIdentifierType -InstallDir $InstallDir
        if (($hostidentifier -ieq $FQDN) -and ($hostidentifierType -ieq $expectedHostIdentifierType)) {        
            Write-Verbose "In Portal DataStore Configured host identifier '$hostidentifier' matches expected value '$FQDN' and host identifier type '$hostidentifierType' matches expected value '$expectedHostIdentifierType'"        
        }
        else {
            Write-Verbose "In Portal DataStore Configured host identifier '$hostidentifier' does not match expected value '$FQDN' or host identifier type '$hostidentifierType' does not match expected value '$expectedHostIdentifierType'. Setting it"
            if (Set-ConfiguredHostIdentifier -InstallDir $InstallDir -HostIdentifier $FQDN -HostIdentifierType $expectedHostIdentifierType) { 
                # Need to restart the service to pick up the hostidentifier 
                Write-Verbose "In Portal DataStore Hostidentifier.properties file was modified. Need to restart the '$ServiceName' service to pick up changes"
                $RestartRequired = $true 
            }
        }
    }

    $EnableHAPortalDebugLogging = if($IsHAPortal -and ($VersionArray[0] -eq 10 -and $VersionArray[1] -lt 8)){ $True }else{ $False }

	if ($EnableHAPortalDebugLogging -or $EnableDebugLogging) {
        if($EnableHAPortalDebugLogging){
            # Initially set log level to debug to allow Join Site to succeed
            Write-Verbose "Setup is Portal HA. Enable debug logging to troubleshoot JoinSite Failures"        
        }
        
        if (Set-LoggingLevel -EnableDebugLogging $true) {
            $RestartRequired = $true
        }
    } else {
        if(-not($IsHAPortal)){
            Write-Verbose "Setup is Single machine Portal"
        }
        if (Set-LoggingLevel -EnableDebugLogging $false) {
            $RestartRequired = $true
        }
    }

    if ($RestartRequired) {
        Restart-ArcGISService -ServiceName $ServiceName -Verbose
		Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin" -HttpMethod 'GET' -Verbose
    }    

    Write-Verbose "Portal at https://$($FQDN):7443"
    if ($Ensure -ieq 'Present') {
        Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin" -HttpMethod 'GET' -Verbose
        $Referer = 'http://localhost'
        $RestartRequired = $false
        $MessageNotCreated = @("The portal site has not been initialized. Please create a new site and try again.","Le site du portail na pas Ã©tÃ© initialisÃ©. CrÃ©ez un nouveau site et rÃ©essayez.")
        
        $SiteCreatedCheckResponse = Invoke-ArcGISWebRequest -Url "https://$($FQDN):7443/arcgis/portaladmin" -HttpFormParameters @{ referer = $Referer; f = 'json' } -Referer $Referer -Verbose -HttpMethod "GET"
        if($SiteCreatedCheckResponse.error.message -ieq "Token Required." -and $SiteCreatedCheckResponse.error.code -eq 499){
            Write-Verbose "Portal Site already is already created. Now checking if portal site is healthy."
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
                    Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin" -HttpMethod 'GET' -Verbose
                    $Attempts = $Attempts + 1
                }        
            }
            if(-not($PortalReady)){
                throw "Portal Site is not healthy. Please check your portal site deployment."
            }
        } else {
            if($SiteCreatedCheckResponse.status -ieq "error"){
                if($SiteCreatedCheckResponse.messages -in $MessageNotCreated){
                    if($Join) {
                        $PeerMachineFQDN = Get-FQDN $PeerMachineHostName
                        Write-Verbose "Joining machine to portal site at peer $PeerMachineFQDN"   
                        Join-PortalSite -PortalHostNameFQDN $FQDN -Credential $PortalAdministrator -PeerMachineHostName $PeerMachineFQDN
                        Write-Verbose "Joined machine to portal site at peer $PeerMachineFQDN"   
                    } else {
                        Write-Verbose "Creating Portal Site" 
                        Invoke-CreatePortalSite -PortalHostNameFQDN $FQDN -PortalSiteName 'arcgis' -Credential $PortalAdministrator `
                                            -FullName $PortalAdministrator.UserName -ContentDirectoryLocation $ContentDirectoryLocation `
                                            -Email $AdminEmail -SecurityQuestionIdx $AdminSecurityQuestionIndex -SecurityQuestionAnswer $AdminSecurityAnswer `
                                            -Description 'Portal Administrator' -ContentDirectoryCloudConnectionString $ContentDirectoryCloudConnectionString `
                                            -ContentDirectoryCloudContainerName $ContentDirectoryCloudContainerName -LicenseFilePath $LicenseFilePath -UserLicenseTypeId $UserLicenseTypeId
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
                Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/healthCheck/?f=json" -HttpMethod 'GET' -Verbose
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

		[System.Byte]
		$AdminSecurityQuestionIndex,

		[System.String]
		$AdminSecurityAnswer,

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

        [System.String]
        $ContentDirectoryCloudConnectionString,

        [System.String]
        $ContentDirectoryCloudContainerName
	)

    
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $FQDN = if($PortalHostName){ Get-FQDN $PortalHostName }else{ Get-FQDN $env:COMPUTERNAME }
    $result = $false

    $ServiceName = 'Portal for ArcGIS'
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir  

    $hostname = Get-ConfiguredHostName -InstallDir $InstallDir
    if ($hostname -ieq $FQDN) {
        Write-Verbose "Configured hostname '$hostname' matches expected value '$FQDN'"
        $result = $true
    }
    else {
        Write-Verbose "Configured hostname '$hostname' does not match expected value '$FQDN'"
        $result = $false
    }

    if($result) {
        if(Get-NodeAgentAmazonElementsPresent -InstallDir $InstallDir) {
            Write-Verbose "Amazon Elements present in NodeAgentExt.xml. Will be removed in Set Method"
            $result = $false
        }         
    }

    if ($result) {
        
        $InstallDir = Join-Path $InstallDir 'framework\runtime\ds' 

        $expectedHostIdentifierType = if($FQDN -as [ipaddress]){ 'ip' }else{ 'hostname' }
        $hostidentifier = Get-ConfiguredHostIdentifier -InstallDir $InstallDir
		$hostidentifierType = Get-ConfiguredHostIdentifierType -InstallDir $InstallDir
		if (($hostidentifier -ieq $FQDN) -and ($hostidentifierType -ieq $expectedHostIdentifierType)) {        
            Write-Verbose "In Portal DataStore Configured host identifier '$hostidentifier' matches expected value '$FQDN' and host identifier type '$hostidentifierType' matches expected value '$expectedHostIdentifierType'"        
        }
        else {
			Write-Verbose "In Portal DataStore Configured host identifier '$hostidentifier' does not match expected value '$FQDN' or host identifier type '$hostidentifierType' does not match expected value '$expectedHostIdentifierType'. Setting it"
			$result = $false
        }
    }

    if ($result) {
        $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir  
        $PropertiesFile = Join-Path $InstallDir 'framework\runtime\tomcat\conf\logging.properties'
        @('org.apache.catalina.core.ContainerBase.[Catalina].[localhost].level', '1catalina.org.apache.juli.FileHandler.level', '2localhost.org.apache.juli.FileHandler.level', '3portal.org.apache.juli.FileHandler.level', 'java.util.logging.ConsoleHandler.level') | ForEach-Object {
            if ($result) {
                $PropertyName = $_
                Write-Verbose "Property Name :- $PropertyName"
                $DesiredLoggingLevel = $null
                if ($EnableDebugLogging -or $IsHAPortal) {
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
                    Write-Verbose "Portal Tomcat CurrentLoggingLevel '$CurrentLoggingLevel' does not match desired value of '$DesiredLoggingLevel'"
                    $result = $false
                }
                else {
                    Write-Verbose "Portal Tomcat CurrentLoggingLevel '$CurrentLoggingLevel' matches desired value of '$DesiredLoggingLevel'"
                }
            }
        }        
    }
    if ($result) {
        try{
            $Referer = 'http://localhost'
            Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET' -Verbose   
            $SiteCreatedCheckResponse = Invoke-ArcGISWebRequest -Url "https://$($FQDN):7443/arcgis/portaladmin" -HttpFormParameters @{ referer = $Referer; f = 'json' } -Referer $Referer -Verbose -HttpMethod "GET"
            if($SiteCreatedCheckResponse.error.message -ieq "Token Required." -and $SiteCreatedCheckResponse.error.code -eq 499){
                Write-Verbose "Portal Site already is already created."
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

function Set-LoggingLevel {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [System.Boolean]
        $EnableDebugLogging
    )

    $ServiceRestartRequired = $false
    $ServiceName = 'Portal for ArcGIS'
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
            Write-Verbose "Portal Tomcat CurrentLoggingLevel '$CurrentLoggingLevel' does not match desired value of '$DesiredLoggingLevel'. Updating it"
            if (Confirm-PropertyInPropertiesFile -PropertiesFilePath $PropertiesFile -PropertyName $PropertyName -PropertyValue $DesiredLoggingLevel) {
                Write-Verbose "Portal Tomcat logging level '$PropertyName' changed. Restart needed"
                $ServiceRestartRequired = $true 
            }
        }
        else {
            Write-Verbose "Portal Tomcat CurrentLoggingLevel '$CurrentLoggingLevel' matches desired value of '$DesiredLoggingLevel' for property '$PropertyName'"
        }
    }
    $ServiceRestartRequired
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
