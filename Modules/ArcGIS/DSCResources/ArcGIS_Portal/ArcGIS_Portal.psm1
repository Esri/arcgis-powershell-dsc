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

    [string]$CreateNewSiteUrl = "https://$($PortalHostNameFQDN):7443/$PortalSiteName/portaladmin/createNewSite"
    
    if ($ContentDirectoryCloudConnectionString -and $ContentDirectoryCloudConnectionString.Length -gt 0) {
        
        $Splits = $ContentDirectoryCloudConnectionString.Split(';')
        $StorageEndpointSuffix = $null
        $StorageAccessKey = $null
        $StorageAccountName = $null
        $Splits | ForEach-Object { 
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
    }
    else {        
        Write-Verbose "Using Content Store on File System at location $ContentDirectoryLocation"
        $contentStore = @{
            type = 'fileStore'
            provider = 'FileSystem'
            connectionString = $ContentDirectoryLocation
        }
    }
        
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

    Write-Verbose "Response received from create site $( $Response |ConvertTo-Json -Depth 10 )"  
    if ($Response.error -and $Response.error.message) {
        throw $Response.error.message
    }
    if ($null -ne $Response.recheckAfterSeconds) {
        Write-Verbose "Sleeping for $($Response.recheckAfterSeconds * 2) seconds"
        Start-Sleep -Seconds ($Response.recheckAfterSeconds * 2)
    }
    
    Write-Verbose "Waiting for portal to start."
    try {
        $token = Get-PortalToken -PortalHostName $PortalHostNameFQDN -SiteName $PortalSiteName  -Credential $Credential -Referer "https://$($PortalHostNameFQDN):7443" -MaxAttempts 40
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
		Restart-PortalService -ServiceName $ServiceName

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
		[parameter(Mandatory = $true)]
        [System.String]
        $PortalHostName
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

	$null
}

function Set-TargetResource {
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
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
        $ContentDirectoryCloudContainerName,

        [System.Management.Automation.PSCredential]
        $ADServiceUser,

        [System.Boolean]
        $EnableAutomaticAccountCreation,

        [System.String]
        $DefaultRoleForUser,

        [System.String]
        $DefaultUserLicenseTypeIdForUser,

        [System.Boolean]
        $DisableServiceDirectory,

        [System.Boolean]
        $EnableEmailSettings,

        [System.String]
        $EmailSettingsSMTPServerAddress,

        [System.String]
        $EmailSettingsFrom,

        [System.String]
        $EmailSettingsLabel,

        [System.Boolean]
        $EmailSettingsAuthenticationRequired = $False,

        [System.Management.Automation.PSCredential]
        $EmailSettingsCredential,

        [System.Int32]
        $EmailSettingsSMTPPort = 25,

        [ValidateSet("SSL", "TLS", "NONE")]
        [System.String]
        $EmailSettingsEncryptionMethod = "NONE"
    )
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    if ($VerbosePreference -ne 'SilentlyContinue') {        
        Write-Verbose ("PortalAdmin UserName:- " + $PortalAdministrator.UserName) 
        #Write-Verbose ("PortalAdmin Password:- " + $PortalAdministrator.GetNetworkCredential().Password) 
    }

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $FQDN = if($PortalHostName){ Get-FQDN $PortalHostName }else{ Get-FQDN $env:COMPUTERNAME } 

    $ServiceName = 'Portal for ArcGIS'
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir  
    
    [string]$RealVersion = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\ESRI\Portal for ArcGIS').RealVersion
    Write-Verbose "Version of Portal is $RealVersion"
    $PortalMajorVersion = $RealVersion.Split('.')[1]

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

    $EnableHAPortalDebugLogging = if($IsHAPortal -and ($PortalMajorVersion -lt 8)){ $True }else{ $False }

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
		Restart-PortalService -ServiceName $ServiceName -Verbose
        Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin" -HttpMethod 'GET' -Verbose
    }    

    Write-Verbose "Portal at https://$($FQDN):7443"
    if ($Ensure -ieq 'Present') {
        Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin" -HttpMethod 'GET' -Verbose
        $Referer = 'http://localhost'
        $RestartRequired = $false
        
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
                    Restart-PortalService -ServiceName $ServiceName -Verbose
                    Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin" -HttpMethod 'GET' -Verbose
                    $Attempts = $Attempts + 1
                }        
            }
            if(-not($PortalReady)){
                throw "Portal Site is not healthy. Please check your portal site deployment."
            }
        } else {
            if($SiteCreatedCheckResponse.status -ieq "error"){
                if($SiteCreatedCheckResponse.messages -icontains "The portal site has not been initialized. Please create a new site and try again."){
                    if($Join -and -not($RealVersion -ieq '10.3')) {
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
        if($PortalMajorVersion -lt 8){       
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

		if($IsHAPortal -and ($Join -and ($PortalMajorVersion -lt 8))) {	
            # On the secondary Portal machine, 
            # Finally set log level to user defined
            if(Set-LoggingLevel -EnableDebugLogging $EnableDebugLogging) {
                Restart-PortalService -ServiceName $ServiceName -Verbose
                Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/healthCheck/?f=json" -HttpMethod 'GET' -Verbose
            }
        }
		        
		if(-not($Join)){
            Write-Verbose "Waiting for 'https://$($FQDN):7443/arcgis/portaladmin/' to intialize"
            Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET' -Verbose
            
            Write-Verbose "Getting Portal Token for user '$($PortalAdministrator.UserName)' from 'https://$($FQDN):7443'"
            $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
            if (-not($token.token)) {
                throw "Unable to retrieve Portal Token for '$($PortalAdministrator.UserName)'"
            }
            Write-Verbose "Connected to Portal successfully and retrieved token for $($PortalAdministrator.UserName)"
            Write-Verbose "Checking If Portal on HTTPS_Only"
            $PortalSelf = Get-PortalSelfDescription -PortalHostName $FQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer
            if(-not($PortalSelf.allSSL))
            {
                Write-Verbose "Setting Portal to HTTPS_Only"
                $PortalSelfResponse = Set-PortalSelfDescription -PortalHostName $FQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer -Properties @{ allSSL = 'true' }
                Write-Verbose $PortalSelfResponse
            }

            if ($ADServiceUser.UserName) 
            {
                Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET'
                $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer 'http://localhost'

                $securityConfig = Get-PortalSecurityConfig -PortalHostName $FQDN -Token $token.token
                if ($($securityConfig.userStoreConfig.type) -ne 'WINDOWS') 
                {
                    Write-Verbose "UserStore Config Type is set to :-$($securityConfig.userStoreConfig.type). Changing to Active Directory"
                    Set-PortalUserStoreConfig -PortalHostName $FQDN -Token $token.token -ADServiceUser $ADServiceUser
                } else {
                    Write-Verbose "UserStore Config Type is set to :-$($securityConfig.userStoreConfig.type). No Action required"
                }
            }
            
            
            Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET'
            if(-not($token)){
                $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer 'http://localhost'
            }

            if(-not($securityConfig)){
                $securityConfig = Get-PortalSecurityConfig -PortalHostName $FQDN -Token $token.token
            }

            $SecurityPropertiesModifiedCheck = $False
            if(-not([string]::IsNullOrEmpty($DefaultRoleForUser)) -or -not([string]::IsNullOrEmpty($DefaultUserLicenseTypeIdForUser))){
                if($RealVersion.Split('.')[1] -lt 8){
                    if(-not([string]::IsNullOrEmpty($DefaultRoleForUser))){
                        Write-Verbose "Current Default Role for User Setting:- $($securityConfig.defaultRoleForUser)" 
                        if ($securityConfig.defaultRoleForUser -ne $DefaultRoleForUser) {
                            $securityConfig.defaultRoleForUser = $DefaultRoleForUser
                            $SecurityPropertiesModifiedCheck = $True
                        }else{
                            Write-Verbose "Default Role for User already set to $DefaultRoleForUser"
                        }
                    }
                    
                    if(-not([string]::IsNullOrEmpty($DefaultUserLicenseTypeIdForUser))){
                        Write-Verbose "Current Default User Type Setting:- $($securityConfig.defaultUserTypeIdForUser)" 
                        if ($securityConfig.defaultUserTypeIdForUser -ne $DefaultUserLicenseTypeIdForUser) {
                            $securityConfig.defaultUserTypeIdForUser = $DefaultUserLicenseTypeIdForUser
                            $SecurityPropertiesModifiedCheck = $True
                        }else{
                            Write-Verbose "Default User Type already set to $DefaultUserLicenseTypeIdForUser"
                        }
                    }
                }else{
                    $UserDefaultsModified = $False
                    
					$userDefaults = (Get-PortalUserDefaults -PortalHostName $FQDN -Token $token.token -Verbose)
					
                    if(-not([string]::IsNullOrEmpty($DefaultRoleForUser)) ){
                        Write-Verbose "Current Default Role for User Setting:- $($userDefaults.role)" 
                        if ($userDefaults.role -ne $DefaultRoleForUser) {
                            Write-Verbose "Current Default Role for User does not match. Updating it."
                            if("role" -in $userDefaults.PSobject.Properties.Name){
                                $userDefaults.role = $DefaultRoleForUser
                            }else{
                                Add-Member -InputObject $userDefaults -NotePropertyName 'role' -NotePropertyValue $DefaultRoleForUser
                            }
                            $UserDefaultsModified = $True
                        }else{
                            Write-Verbose "Default Role for User already set to $DefaultRoleForUser"
                        }
                    }

                    if(-not([string]::IsNullOrEmpty($DefaultUserLicenseTypeIdForUser))){
                        Write-Verbose "Current Default User Type Setting:- $($userDefaults.userLicenseType)" 
                        if ($userDefaults.userLicenseType -ne $DefaultUserLicenseTypeIdForUser) {
                            Write-Verbose "Current Default User Type does not match. Updating it."
                            if("userLicenseType" -in $userDefaults.PSobject.Properties.Name){
                                $userDefaults.userLicenseType = $DefaultUserLicenseTypeIdForUser
                            }else{
                                Add-Member -InputObject $userDefaults -NotePropertyName 'userLicenseType' -NotePropertyValue $DefaultUserLicenseTypeIdForUser
                            }
                            $UserDefaultsModified = $True
                        }else{
                            Write-Verbose "Default User Type already set to $DefaultUserLicenseTypeIdForUser"
                        }
                    }

                    if($UserDefaultsModified){
						Write-Verbose "Updating Portal User Defaults"
						Set-PortalUserDefaults -PortalHostName $FQDN -Token $token.token -UserDefaultsParameters $userDefaults
                    }
                }
            }   
                
            $EnableAutoAccountCreationStatus = if ($securityConfig.enableAutomaticAccountCreation -ne $True) { 'disabled' } else { 'enabled' }
            Write-Verbose "Current Automatic Account Creation Setting:- $EnableAutoAccountCreationStatus" 
            if ($securityConfig.enableAutomaticAccountCreation -ne $EnableAutomaticAccountCreation) {
                $securityConfig.enableAutomaticAccountCreation = $EnableAutomaticAccountCreation
                $SecurityPropertiesModifiedCheck = $True
            }else{
                Write-Verbose "Automatic Account Creation already $EnableAutoAccountCreationStatus"
            }
            
            $dirStatus = if ($securityConfig.disableServicesDirectory -ne $True) { 'enabled' } else { 'disabled' }
            Write-Verbose "Current Service Directory Setting:- $dirStatus"
            if ($securityConfig.disableServicesDirectory -ne $DisableServiceDirectory) {
                $securityConfig.disableServicesDirectory = $DisableServiceDirectory
                $SecurityPropertiesModifiedCheck = $True
            } else {
                Write-Verbose "Service directory already $dirStatus"
            }
        
            if($SecurityPropertiesModifiedCheck){
                Write-Verbose "Updating portal security configuration"
                Set-PortalSecurityConfig -PortalHostName $FQDN -Token $token.token -SecurityParameters (ConvertTo-Json $securityConfig -Depth 10) -Verbose
            }

            if($RealVersion.Split('.')[1] -gt 8 -or ($RealVersion.Split('.')[1] -eq 8 -and $RealVersion.Split('.')[2] -eq 1)){
            $UpdateEmailSettingsFlag = $False
                try{
                    $PortalEmailSettings = Get-PortalEmailSettings -PortalHostName $FQDN -Token $token.token -Referer $Referer
                    if(-not($EnableEmailSettings)){
                        Write-Verbose "Deleting Portal Email Settings"
                        Delete-PortalEmailSettings -PortalHostName $FQDN -Token $token.token -Referer $Referer -Verbose
                    }else{
                        if(-not($PortalEmailSettings.smtpHost -ieq $EmailSettingsSMTPServerAddress -and $PortalEmailSettings.smtpPort -ieq $EmailSettingsSMTPPort -and $PortalEmailSettings.mailFrom -ieq $EmailSettingsFrom -and $PortalEmailSettings.mailFromLabel -ieq $EmailSettingsLabel -and $PortalEmailSettings.encryptionMethod -ieq $EmailSettingsEncryptionMethod -and $PortalEmailSettings.authRequired -ieq $EmailSettingsAuthenticationRequired -and (($EmailSettingsAuthenticationRequired -ieq $False) -or ($EmailSettingsAuthenticationRequired -ieq $True -and  $PortalEmailSettings.smtpUser -ieq $EmailSettingsCredential.UserName -and $PortalEmailSettings.smtpPass -ieq $EmailSettingsCredential.GetNetworkCredential().Password)))){
                            $UpdateEmailSettingsFlag = $True
                        }else{
                            Write-Verbose "Portal Email settings configured correctly."
                        }
                    }
                }catch{
                    if($EnableEmailSettings){
                        $UpdateEmailSettingsFlag = $True
                    }else{
                        Write-Verbose "Portal Email settings configured correctly."
                    }
                }

                if($UpdateEmailSettingsFlag){
                    Write-Verbose "Updating Portal Email Settings"
                    Update-PortalEmailSettings -SMTPServerAddress $EmailSettingsSMTPServerAddress -From $EmailSettingsFrom -Label $EmailSettingsLabel -AuthenticationRequired $EmailSettingsAuthenticationRequired -Credential $EmailSettingsCredential -SMTPPort $EmailSettingsSMTPPort -EncryptionMethod $EmailSettingsEncryptionMethod -Token $token.token -Verbose
                }
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
		[parameter(Mandatory = $true)]
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
        $ContentDirectoryCloudContainerName,

        [System.Management.Automation.PSCredential]
        $ADServiceUser,

        [System.Boolean]
        $EnableAutomaticAccountCreation,

        [System.String]
        $DefaultRoleForUser,

        [System.String]
        $DefaultUserLicenseTypeIdForUser,

        [System.Boolean]
        $DisableServiceDirectory,

        [System.Boolean]
        $EnableEmailSettings,

        [System.String]
        $EmailSettingsSMTPServerAddress,

        [System.String]
        $EmailSettingsFrom,

        [System.String]
        $EmailSettingsLabel,

        [System.Boolean]
        $EmailSettingsAuthenticationRequired = $False,

        [System.Management.Automation.PSCredential]
        $EmailSettingsCredential,

        [System.Int32]
        $EmailSettingsSMTPPort = 25,

        [ValidateSet("SSL", "TLS", "NONE")]
        [System.String]
        $EmailSettingsEncryptionMethod = "NONE"
	)


    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false
    
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $FQDN = if($PortalHostName){ Get-FQDN $PortalHostName }else{ Get-FQDN $env:COMPUTERNAME }
    $result = $false

    [string]$RealVersion = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\ESRI\Portal for ArcGIS').RealVersion
    Write-Verbose "Version of Portal is $RealVersion"

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

    if ($result){
        try {
            Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET' -Verbose
            $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer     

            Write-Verbose "Checking If Portal on HTTPS_Only" #Need to check this condition
            $PortalSelf = Get-PortalSelfDescription -PortalHostName $FQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer
            $result = $PortalSelf.allSSL
        }
        catch {
            Write-Verbose "[WARNING]:- Exception:- $($_)"   
            $result = $false
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

    if($result -and -not($Join)){
        $Referer = 'http://localhost'
        Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET'
        if (-not($token)){
            $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer 'http://localhost'
        }
        if (-not($securityConfig)){
            $securityConfig = Get-PortalSecurityConfig -PortalHostName $FQDN -Token $token.token
        }
    
        if ($ADServiceUser.UserName) {
            if ($($securityConfig.userStoreConfig.type) -ne 'WINDOWS') {
                Write-Verbose "UserStore Config Type is set to :-$($securityConfig.userStoreConfig.type)"
                $result = $false
            } else {
                Write-Verbose "UserStore Config Type is set to :-$($securityConfig.userStoreConfig.type). No Action required"
            }
        }
        
        if ($result) {
            $dirStatus = if ($securityConfig.disableServicesDirectory -ne "true") { 'enabled' } else { 'disabled' }
            Write-Verbose "Current Service Directory Setting:- $dirStatus"
            if ($securityConfig.disableServicesDirectory -ne $DisableServiceDirectory) {
                Write-Verbose "Service directory setting does not match. Updating it."
                $result = $false
            }  
        }

        if ($result) {
            $EnableAutoAccountCreationStatus = if ($securityConfig.enableAutomaticAccountCreation -ne "true") { "disabled" } else { 'enabled' }
            Write-Verbose "Current Automatic Account Creation Setting:- $EnableAutoAccountCreationStatus" 
            if ($securityConfig.enableAutomaticAccountCreation -ne $EnableAutomaticAccountCreation) {
                Write-Verbose "EnableAutomaticAccountCreation setting doesn't match, Updating it."
                $result = $false
            }
        }

        if($RealVersion.Split('.')[1] -lt 8){
            if ($result -and -not([string]::IsNullOrEmpty($DefaultRoleForUser))) {
                Write-Verbose "Current Default Role for User Setting:- $($securityConfig.defaultRoleForUser)"
                if ($securityConfig.defaultRoleForUser -ne $DefaultRoleForUser) {
                    Write-Verbose "Current Default Role for User does not match. Updating it."
                    $result = $false
                }
            }

            if ($result -and -not([string]::IsNullOrEmpty($DefaultUserLicenseTypeIdForUser))) {
                Write-Verbose "Current Default User Type Setting:- $($securityConfig.defaultUserTypeIdForUser)"
                if ($securityConfig.defaultUserTypeIdForUser -ne $DefaultUserLicenseTypeIdForUser) {
                    Write-Verbose "Current Default User Type does not match. Updating it."
                    $result = $false
                }
            }
        }else{
            $userDefaults = Get-PortalUserDefaults -PortalHostName $FQDN -Token $token.token
            if ($result -and -not([string]::IsNullOrEmpty($DefaultRoleForUser))) {
                Write-Verbose "Current Default Role for User Setting:- $($userDefaults.role)" 
                if ($userDefaults.role -ne $DefaultRoleForUser) {
                    Write-Verbose "Current Default Role for User does not match. Updating it."
                    $result = $false
                }
            }
    
            if ($result -and -not([string]::IsNullOrEmpty($DefaultUserLicenseTypeIdForUser))) {
                Write-Verbose "Current Default User Type Setting:- $($userDefaults.userLicenseType)" 
                if ($userDefaults.userLicenseType -ne $DefaultUserLicenseTypeIdForUser) {
                    Write-Verbose "Current Default User Type does not match. Updating it."
                    $result = $false
                }
            }
        }

        if($result -and ($RealVersion.Split('.')[1] -gt 8 -or ($RealVersion.Split('.')[1] -eq 8 -and $RealVersion.Split('.')[2] -eq 1))){
            Write-Verbose "Checking Portal Email settings."
            try{
                $PortalEmailSettings = Get-PortalEmailSettings -PortalHostName $FQDN -Token $token.token -Referer $Referer
                if(-not($EnableEmailSettings) -or ($EnableEmailSettings -eq $True -and -not($PortalEmailSettings.smtpHost -ieq $EmailSettingsSMTPServerAddress -and $PortalEmailSettings.smtpPort -ieq $EmailSettingsSMTPPort -and $PortalEmailSettings.mailFrom -ieq $EmailSettingsFrom -and $PortalEmailSettings.mailFromLabel -ieq $EmailSettingsLabel -and $PortalEmailSettings.encryptionMethod -ieq $EmailSettingsEncryptionMethod -and $PortalEmailSettings.authRequired -ieq $EmailSettingsAuthenticationRequired -and (($EmailSettingsAuthenticationRequired -ieq $False) -or ($EmailSettingsAuthenticationRequired -ieq $True -and  $PortalEmailSettings.smtpUser -ieq $EmailSettingsCredential.UserName -and $PortalEmailSettings.smtpPass -ieq $EmailSettingsCredential.GetNetworkCredential().Password))))){
                    $result = $false
                }else{
                    Write-Verbose "Portal Email settings configured correctly."
                }
            }catch{
                if($EnableEmailSettings){
                    $result = $false
                }else{
                    Write-Verbose "Portal Email settings configured correctly."
                }
            }
        }
    }


    if ($Ensure -ieq 'Present') {
	       $result   
    } elseif ($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}

function Restart-PortalService {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory=$false)]    
        [System.String]
        $ServiceName = 'Portal for ArcGIS'
    )

    try {
        Write-Verbose "Restarting Service $ServiceName"
        Stop-Service -Name $ServiceName -Force -ErrorAction Ignore
        Write-Verbose 'Stopping the service' 
        Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Stopped'
        Write-Verbose 'Stopped the service'
    }
    catch {
        Write-Verbose "[WARNING] Stopping Service $_"
    }

    try {
        Write-Verbose 'Starting the service'
        Start-Service -Name $ServiceName -ErrorAction Ignore
        Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Running'
        Write-Verbose "Restarted Service '$ServiceName'"
    }
    catch {
        Write-Verbose "[WARNING] Starting Service $_"
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

function Get-PortalSecurityConfig {
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

    Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):$($Port)/$SiteName/portaladmin/security/config") `
                        -HttpFormParameters @{ f = 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET'
}

function Set-PortalSecurityConfig {
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

        [System.String]
        $SecurityParameters
    )   

    $params = @{ f = 'json'; token = $Token; securityConfig = $SecurityParameters;}
    
    $resp = Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):$($Port)/$SiteName/portaladmin/security/config/update") `
                        -HttpFormParameters $params -Referer $Referer -Verbose
    if($resp.error -and $resp.error.message){
        throw "[Error] - Set-PortalSecurityConfig Response:- $($resp.error.message)"
    }
}

function Set-PortalUserStoreConfig {
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
            "caseSensitive": "false"
        }
    }'

    $response = Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):$($Port)/$SiteName/portaladmin/security/config/updateIdentityStore") -HttpFormParameters @{ f = 'json'; token = $Token; userStoreConfig = $userStoreConfig; } -Referer $Referer -TimeOutSec 300 -Verbose
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
    
    Invoke-ArcGISWebRequest -Url "https://$($PortalHostName):$($Port)/$SiteName/sharing/rest/portals/self/userDefaultSettings" -HttpFormParameters @{ f = 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET'
}

function Set-PortalUserDefaults{
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
    
    $resp = Invoke-ArcGISWebRequest -Url "https://$($PortalHostName):$($Port)/$SiteName/sharing/rest/portals/self/setUserDefaultSettings" -HttpFormParameters $params -Referer $Referer -Verbose
    if($resp.error -and $resp.error.message){
        throw "[Error] - Set-PortalUserDefaults Response:- $($resp.error.message)"
    }
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

function Get-PortalSelfDescription {
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
    
    Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):$($Port)/$($SiteName)" + '/sharing/rest/portals/self/') -HttpMethod 'GET' -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer 
}

function Set-PortalSelfDescription 
{
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

        $Properties
    )
    
    try {
        $Properties += @{ token = $Token; f = 'json' }

        Invoke-ArcGISWebRequest -Url("https://$($PortalHostName):$($Port)/$($SiteName)" + '/sharing/rest/portals/self/update/') -HttpFormParameters $Properties -Referer $Referer -TimeOutSec 360
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
    
    $resp = Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):$($Port)/$SiteName/portaladmin/system/emailSettings") `
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
        $PortalHostName = 'localhost',

        [System.String]
        $SiteName = 'arcgis',

        [System.Int32]
        $Port = 7443,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost',

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

    $resp = Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):$($Port)/$SiteName/portaladmin/system/emailSettings/update") `
                        -HttpFormParameters $emailSettingObject -Referer $Referer -Verbose
    if($resp.error -and $resp.error.message){
        throw "[Error] - Update-PortalEmailSettings Response:- $($resp.error.message)"
    }else{
        if($resp.status -and $resp.status -ieq "success"){
            if ($null -ne $resp.recheckAfterSeconds) {
                Write-Verbose "Sleeping for $($resp.recheckAfterSeconds*2) seconds"
                Start-Sleep -Seconds ($resp.recheckAfterSeconds * 2)
            }
            Write-Verbose "Update-PortalEmailSettings successful."
        }
    }
}

function Delete-PortalEmailSettings
{
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
    
    $resp = Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):$($Port)/$SiteName/portaladmin/system/emailSettings/delete") `
                        -HttpFormParameters @{ f = 'json'; token = $Token; } -Referer $Referer -Verbose
    if($resp.error -and $resp.error.message){
        throw "[Error] - Delete-PortalEmailSettings Response:- $($resp.error.message)"
    }
}

function Get-NodeAgentAmazonElementsPresent
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [System.String]
        $InstallDir       
    )

    $Enabled = $false
    $File = Join-Path $InstallDir 'framework\etc\NodeAgentExt.xml'
    if(Test-Path $File){
        [xml]$xml = Get-Content $File
        if((($xml.NodeAgent.Observers.Observer | Where-Object { $_.platform -ieq 'amazon'}).Length -gt 0) -or `
                ($xml.NodeAgent.Observers.Observer.platform -ieq 'amazon') -or `
                (($xml.NodeAgent.Plugins.Plugin | Where-Object { $_.platform -ieq 'amazon'}).Length -gt 0) -or `
                ($xml.NodeAgent.Plugins.Plugin.platform -ieq 'amazon'))
        {
            Write-Verbose "Amazon elements exist in $File"
            $Enabled = $true
        }
    }

    $Enabled
}

function Remove-NodeAgentAmazonElements
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [System.String]
        $InstallDir  
    )

    $Changed = $false
    $File = Join-Path $InstallDir 'framework\etc\NodeAgentExt.xml'
    if(Test-Path $File){
        [xml]$xml = Get-Content $File
        if($xml.NodeAgent.Observers.Observer.platform -ieq 'amazon')
        {
            $xml.NodeAgent.Observers.RemoveChild($xml.NodeAgent.Observers.Observer)
            Write-Verbose "Amazon Observer exists in $File. Removing it"
            $Changed = $true
        }
        if($xml.NodeAgent.Plugins.Plugin.platform -ieq 'amazon')
        {
            $xml.NodeAgent.Plugins.RemoveChild($xml.NodeAgent.Plugins.Plugin)
            Write-Verbose "Amazon plugin exists in $File. Removing it"
            $Changed = $true
        }
        if($Changed) {
            $xml.Save($File)
        }
    }

    $Changed
}

Export-ModuleMember -Function *-TargetResource