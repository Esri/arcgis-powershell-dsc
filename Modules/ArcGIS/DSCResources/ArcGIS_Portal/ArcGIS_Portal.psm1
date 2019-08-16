<#
    .SYNOPSIS
        Resource to Configure a Portal site.
    .PARAMETER Ensure
        Ensure makes sure that a Portal site is configured and joined to site if specified. Take the values Present or Absent. 
        - "Present" ensures that portal is configured, if not.
        - "Absent" ensures that existing portal site is deleted(Not Implemented).
    .PARAMETER PortalEndPoint
        Endpoint to be used for the private portal url, specifically when using an Internal load balancer.
    .PARAMETER PortalHostName
        Host Name of the Machine on which the Portal has been installed and is to be configured.
    .PARAMETER PortalContext
        Context of the Portal in case a LB or WebAdaptor is installed - Default is 'portal'
    .PARAMETER ExternalDNSName
        Enternal Endpoint of Portal in case a LB or WebAdaptor is installed - Needs for dummy Web Adaptor and WebContext URL to registered for the portal
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
    .PARAMETER UpgradeReindex
        Need to Run Reindex of PostgresSQL Database that ships with the portal when a upgrade takes place.
    .PARAMETER ADServiceUser
        Service User to connect the Portal-UserStore to an Active Directory
    .PARAMETER EnableAutomaticAccountCreation
        Enables the automaticAccountCreation on Portal
    .PARAMETER DisableServiceDirectory
        Disable the Services Directory on Portal
#>

function Create-PortalSite {    
    [CmdletBinding()]
    param(
        [System.String]
        $PortalHttpsUrl, 

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
        $UserLicenseType = $null
    )

    [string]$CreateNewSiteUrl = $PortalHttpsUrl.TrimEnd('/') + "/$PortalSiteName/portaladmin/createNewSite"
    
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
    
    #[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} #ignore self-signed certificates
	#[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    #$HttpRequestBody = To-HttpBody -props $WebParams
    Write-Verbose "Making request to $CreateNewSiteUrl to create the site"
    $Response = $null
    if($LicenseFilePath){
        if($UserLicenseType){
            $LicenseObject = Get-Content -Raw -Path $LicenseFilePath | ConvertFrom-Json
            $UserLicenseTypeId = ($LicenseObject.MyEsri.definitions.userTypes | Where-Object { ($_.name -eq 'Creator')} | Select-Object -First 1).id
            $WebParams.userLicenseTypeId = $UserLicenseTypeId
        }
        $Response = Upload-File -url $CreateNewSiteUrl -filePath $LicenseFilePath -fileContentType 'application/json' -fileParameterName 'file' `
                                 -Referer 'http://localhost' -formParams $WebParams -Verbose

        $Response = $Response | ConvertFrom-Json
    }else{
        $Response = Invoke-ArcGISWebRequest -Url $CreateNewSiteUrl -HttpFormParameters $WebParams -Referer 'http://localhost' -TimeOutSec 5400 -LogResponse 
    }

    Write-Verbose "Response received from create site $Response "  
    if ($Response.error -and $Response.error.message) {
        throw $Response.error.message
    }
    if ($Response.recheckAfterSeconds -ne $null) {
        Write-Verbose "Sleeping for $($Response.recheckAfterSeconds*2) seconds"
        Start-Sleep -Seconds ($Response.recheckAfterSeconds * 2)
    }
    Wait-ForPortalToStart -PortalHttpsUrl $PortalHttpsUrl -PortalSiteName $PortalSiteName -PortalAdminCredential $Credential -Referer $PortalHttpsUrl
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
        $HealthCheckUrl = "https://$($PeerMachineHostName):7443/arcgis/portaladmin/healthcheck/?f=json"
        Write-Verbose "Making request to health check URL '$HealthCheckUrl'" 
        try {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} #ignore self-signed certificates
			[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
            Invoke-ArcGISWebRequest -Url $HealthCheckUrl -TimeoutSec 90 -LogResponse -HttpFormParameters @{ f='json' } -Referer 'http://localhost' -HttpMethod 'POST'
            Write-Verbose "Health check succeeded"
            $PrimaryReady = $true
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

    #[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} #ignore self-signed certificates
    #$HttpRequestBody = To-HttpBody -props $WebParams
	Write-Verbose "Making request to $JoinSiteUrl"
    $Response = Invoke-ArcGISWebRequest -Url $JoinSiteUrl -HttpFormParameters $WebParams -Referer 'http://localhost' -TimeOutSec 1000 -LogResponse 
    #$Response = Invoke-RestMethod -Method Post -Uri $JoinSiteUrl -Body $HttpRequestBody -TimeoutSec 1000
	if ($Response) {
		Write-Verbose "Response received:- $(ConvertTo-Json -Depth 5 -Compress $Response)"  
	}
    if ($Response.error -and $Response.error.message) {
		Write-Verbose "Error from Join Site:- $($Response.error.message)"

		$ServiceName = 'Portal for ArcGIS'
		Restart-PortalService -ServiceName $ServiceName

		Write-Verbose "Wait for endpoint 'https://$($PortalHostNameFQDN):7443/arcgis/portaladmin/' to initialize"
        Wait-ForUrl "https://$($PortalHostNameFQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET' -LogFailures
		Write-Verbose "Finished Waiting for endpoint 'https://$($PortalHostNameFQDN):7443/arcgis/portaladmin/' to initialize. Sleeping for 5 minutes"

		Write-Verbose "Check primary with second round of health checks"
		$PrimaryReady = $false
		$Attempts = 0
		while(-not($PrimaryReady) -and ($Attempts -lt 5)) {
			$HealthCheckUrl = "https://$($PeerMachineHostName):7443/arcgis/portaladmin/healthcheck/?f=json"
			Write-Verbose "Making request to health check URL '$HealthCheckUrl'" 
			try {
				[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} #ignore self-signed certificates
				[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
				Invoke-ArcGISWebRequest -Url $HealthCheckUrl -TimeoutSec 90 -LogResponse -HttpFormParameters @{ f='json' } -Referer 'http://localhost' -HttpMethod 'POST'
				Write-Verbose "Health check succeeded"
				$PrimaryReady = $true
			}catch {
				Write-Verbose "Health check did not suceed. Error:- $_"
				Start-Sleep -Seconds 30
				$Attempts = $Attempts + 1
			}        
		}

		Start-Sleep -Seconds 300
		Write-Verbose "Making second attempt request to $JoinSiteUrl"
		$Response = Invoke-ArcGISWebRequest -Url $JoinSiteUrl -HttpFormParameters $WebParams -Referer 'http://localhost' -TimeOutSec 1000 -LogResponse 
   
		if ($Response) {
			Write-Verbose "Response received on second attempt:- $(ConvertTo-Json -Depth 5 -Compress $Response)"  
        }
        else {
			Write-Verbose "Response from Join Site was null"
		}

		if ($Response.error -and $Response.error.message) {
			Write-Verbose "Error from Join Site second attempt:- $($Response.error.message)"
			throw $Response.error.message
		}
    }

    if ($Response.recheckAfterSeconds -ne $null) {
        Write-Verbose "Sleeping for $($Response.recheckAfterSeconds*2) seconds"
        Start-Sleep -Seconds ($Response.recheckAfterSeconds * 2)
    }
    Wait-ForPortalToStart -PortalHttpsUrl "https://$($PortalHostNameFQDN):7443/" -PortalSiteName "arcgis" -PortalAdminCredential $Credential -Referer "https://$($PortalHostNameFQDN):7443/"
}

function Wait-ForPortalToStart {
    [CmdletBinding()]
    param(
        [System.String]
        $PortalHttpsUrl, 

        [System.String]
        $PortalSiteName, 

        [System.Management.Automation.PSCredential]
        $PortalAdminCredential, 

        [string]
        $Referer,

        [System.Int32]
        $MaxAttempts = 40,

        [System.Int32]
        $SleepTimeInSeconds = 15
    )

    ##
    ## Wait for the Portal Admin to start back up
    ##
    [string]$CheckPortalAdminUrl = $PortalHttpsUrl.TrimEnd('/') + "/$PortalSiteName/sharing/rest/generateToken"  
    $WebParams = @{ 
                    username = $PortalAdminCredential.UserName
                    password = $PortalAdminCredential.GetNetworkCredential().Password                 
                    client = 'requestip'
                    f = 'json'
                  }
    $HttpBody = To-HttpBody $WebParams
    [bool]$Done = $false
    [int]$NumOfAttempts = 0
    Write-Verbose "Check sharing API Url:- $CheckPortalAdminUrl"
    $Headers = @{'Content-type' = 'application/x-www-form-urlencoded'
                  'Content-Length' = $HttpBody.Length
                  'Accept' = 'text/plain'     
                  'Referer' = $Referer             
                }
    while (($Done -eq $false) -and ($NumOfAttempts -lt $MaxAttempts)) {
        if ($NumOfAttempts -gt 1) {
            Write-Verbose "Attempt # $NumOfAttempts"            
        }
        
        $response = $null
        Try {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
			[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
            $response = Invoke-RestMethod -Method Post -Uri $CheckPortalAdminUrl -Headers $Headers -Body $HttpBody -TimeoutSec 30 # -MaximumRedirection 1
			if ($response.token) {
                Write-Verbose "Portal returned a token successfully"   
            }
        }
        Catch {
            if ($_.length) {
                Write-Verbose "[WARNING]:- Exception:- $($_)"    
            } 
        }

        if (($response -ne $null) -and ($response.token -ne $null) -and ($response.token.Length -gt 0)) {    
            $Done = $true                
        }
        else {
            if ($NumOfAttempts -gt 1) {
                Write-Verbose "Sleeping for $SleepTimeInSeconds seconds"
            }
            Start-Sleep -Seconds $SleepTimeInSeconds
            $NumOfAttempts++
        }
    }
}

function Test-PortalSiteCreated
{  
    [CmdletBinding()]
    param(
        [string]
        $PortalHttpsUrl, 
        
        [string]
        $PortalSiteName, 
        
        [System.Management.Automation.PSCredential]
        $PortalAdminCredential
    )
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} # Allow self-signed certificates
	[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    $params = @{ f = 'json' }    
    $resp = $null
    Try {        
        $resp = Invoke-RestMethod -Uri $PortalHttpsUrl.TrimEnd('/') + "/$PortalSiteName/portaladmin?f=json" 
    }
    Catch {   
    }
    $DoesSiteExist = $false
    if ($resp.error -ne $null) {
        $DoesSiteExist = $true
    }
    return $DoesSiteExist
}

function Get-TargetResource {
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
        [System.String]
        $PortalEndPoint
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
        $PortalEndPoint,

        [parameter(Mandatory = $false)]
        [System.String]
        $PortalHostName,

        [System.String]
        $PortalContext = 'portal',

		[parameter(Mandatory = $true)]
		[System.String]
		$ExternalDNSName,

		[ValidateSet("Present", "Absent")]
		[System.String]
        $Ensure,
        
        [parameter(Mandatory = $false)]
		[System.String]
		$LicenseFilePath = $null,
        
        [parameter(Mandatory = $false)]
		[System.String]
        $UserLicenseType = $null,

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

        [System.Boolean]
        $UpgradeReindex,

        [System.String]
        $ContentDirectoryCloudConnectionString,

        [System.String]
        $ContentDirectoryCloudContainerName,

        [System.Management.Automation.PSCredential]
        $ADServiceUser,

        [System.Boolean]
        $EnableAutomaticAccountCreation,

        [System.Boolean]
        $DisableServiceDirectory
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

    $InstallDir = Join-Path $InstallDir 'framework\runtime\ds' 

    if ((Test-Path -Path $InstallDir)) {    
        $expectedHostIdentifierType = 'hostname'
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

	if ($IsHAPortal -or $EnableDebugLogging) {
        if($IsHAPortal){
            # Initially set log level to debug to allow Join Site to succeed
            Write-Verbose "Setup is Portal HA. Enable debug logging to troubleshoot JoinSite Failures"        
        }
        
        if (Set-LoggingLevel -EnableDebugLogging $true) {
            $RestartRequired = $true
        }
    }    
    else {
        if(-not($IsHAPortal)){
            Write-Verbose "Setup is Single machine Portal"
        }
        if (Set-LoggingLevel -EnableDebugLogging $false) {
            $RestartRequired = $true
        }
    }

    if ($RestartRequired) {             
		Restart-PortalService -ServiceName $ServiceName
        Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin" -HttpMethod 'GET' 
    }    

    Write-Verbose "Portal at https://$($FQDN):7443"
    if ($Ensure -ieq 'Present') {
        Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin" -HttpMethod 'GET'
        $Referer = 'http://localhost'
        [string]$RealVersion = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\ESRI\Portal for ArcGIS').RealVersion
        Write-Verbose "Version of Portal is $RealVersion"
        $RestartRequired = $false
        try {
            $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
        }
        catch {
            Write-Verbose $_
        }
	    if (-not($token.token)) {
            if ($Join -and (-not($RealVersion -ieq '10.3'))) {
                $PeerMachineFQDN = Get-FQDN $PeerMachineHostName
                Write-Verbose "Joining Site with Peer $PeerMachineFQDN"   
                Join-PortalSite -PortalHostNameFQDN $FQDN -Credential $PortalAdministrator -PeerMachineHostName $PeerMachineFQDN
                Write-Verbose 'Joined Site'
            }
            else {
                Write-Verbose "Creating Site" 
                Create-PortalSite -PortalHttpsUrl "https://$($FQDN):7443" -PortalSiteName 'arcgis' -Credential $PortalAdministrator `
                                    -FullName $PortalAdministrator.UserName -ContentDirectoryLocation $ContentDirectoryLocation `
                                    -Email $AdminEmail -SecurityQuestionIdx $AdminSecurityQuestionIndex -SecurityQuestionAnswer $AdminSecurityAnswer `
                                    -Description 'Portal Administrator' -ContentDirectoryCloudConnectionString $ContentDirectoryCloudConnectionString `
                                    -ContentDirectoryCloudContainerName $ContentDirectoryCloudContainerName -LicenseFilePath $LicenseFilePath -UserLicenseType $UserLicenseType
                Write-Verbose 'Created Site'
                if($LicenseFilePath){
                    Write-Verbose 'Populating Licenses'
                    [string]$populateLicenseUrl = "https://$($FQDN):7443/arcgis/portaladmin/license/populateLicense"
                    $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
                    $populateLicenseResponse = Invoke-ArcGISWebRequest -Url $populateLicenseUrl -HttpMethod "POST" -HttpFormParameters @{f = 'json'; token = $token.token} -Referer $Referer -TimeOutSec 3000 -LogResponse 
                    if ($populateLicenseResponse.error -and $populateLicenseResponse.error.message) {
                        Write-Verbose "Error from Populate Licenses:- $($populateLicenseResponse.error.message)"
                        throw $populateLicenseResponse.error.message
                    }
                }   

                if ($UpgradeReindex) {
                    Write-Verbose "Reindexing Portal"
                    $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
                    if (-not($token.token)) {
                        throw "Unable to retrieve Portal Token for '$($PortalAdministrator.UserName)'"
                    }
                    Write-Verbose "Connected to Portal successfully and retrieved token for '$($PortalAdministrator.UserName)'"
                    Upgrade-Reindex -PortalHttpsUrl "https://$($FQDN):7443" -PortalSiteName 'arcgis' -Referer $Referer -Token $token.token
                    
                    Write-Verbose "Post Upgrade Step"
                    $RealVersionArray = $RealVersion.Split(".")
                    if ($RealVersionArray[1] -gt 5) {
                        [string]$postUpgradeUrl = "https://$($FQDN):7443/arcgis/portaladmin/postUpgrade"
                        $postUpgradeResponse = Invoke-ArcGISWebRequest -Url $postUpgradeUrl -HttpFormParameters @{f = 'json'; token = $token.token} -Referer $Referer -TimeOutSec 3000 -LogResponse 
                        if ($postUpgradeResponse.status -ieq "success") {
                            Write-Verbose "Post Upgrade Step Successful"
                        }
                    }
                }
            }
			Write-Verbose "Waiting for 'https://$($FQDN):7443/arcgis/portaladmin/' to intialize"
			Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET' -LogFailures
			Write-Verbose "Finished Waiting for 'https://$($FQDN):7443/arcgis/portaladmin/' to intialize"

			$token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
			Write-Verbose "Portal Site created. Successfully retrieved token for $($PortalAdministrator.UserName)"
        }
        else {
            Write-Verbose "Portal Site already created. Successfully retrieved token for $($PortalAdministrator.UserName)"
        }  


        $DesiredLogLevel = $LogLevel
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

		if($IsHAPortal) 
        {	
            if($Join) 
            {
                # On the secondary Portal machine, 
                # Finally set log level to user defined
                if(Set-LoggingLevel -EnableDebugLogging $EnableDebugLogging) {
                    Restart-PortalService -ServiceName $ServiceName
                    Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET' 
                }
            }
        }
		        
		if ($ExternalDNSName -and $PortalEndPoint -and -not($Join) <#-and $PortalContext#>) {
			Write-Verbose "Waiting for 'https://$($FQDN):7443/arcgis/portaladmin/' to intialize"
			Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET' -LogFailures
            
			Write-Verbose "Getting Portal Token for user '$($PortalAdministrator.UserName)' from 'https://$($FQDN):7443'"
			$token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
			if (-not($token.token)) {
				throw "Unable to retrieve Portal Token for '$($PortalAdministrator.UserName)'"
			}
			Write-Verbose "Connected to Portal successfully and retrieved token for $($PortalAdministrator.UserName)"
            

            Set-WCPPWAPortalProperties -PortalHostName $FQDN -ExternalDNSName $ExternalDNSName -PortalEndPoint $PortalEndPoint -PortalContext $PortalContext `
                                    -Token $token.token -IsCallingResourcePortal -Referer $Referer -Verbose

            Write-Verbose "Retrieve token to verify that portal has come back up"
            $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
            if (-not($token.token)) {
                Write-Verbose "[WARNING] Unable to retrieve token after configuration"
            }
            else {
                Write-Verbose "Portal Site configuration complete. Successfully retrieved token for $($PortalAdministrator.UserName)"
            }

            Write-Verbose "Checking If Portal on HTTPS_Only"
            $PortalSelf = Get-PortalSelfDescription -PortalHostName $FQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer
            if(-not($PortalSelf.allSSL))
            {
                Write-Verbose "Setting Portal to HTTPS_Only"
                $PortalSelfResponse = Set-PortalSelfDescription -PortalHostName $FQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer -Properties @{allSSL = 'true' }
                Write-Verbose $PortalSelfResponse
            }
        }

        if(-not($Join)){
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
            if ($null -ine $EnableAutomaticAccountCreation)
            {
                Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET'
                if (-not ($token))
                {
                    $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer 'http://localhost'
                }
                if (-not ($securityConfig))
                {
                    $securityConfig = Get-PortalSecurityConfig -PortalHostName $FQDN -Token $token.token
                }
                $EnableAutoAccountCreationStatus = if ($securityConfig.enableAutomaticAccountCreation -ne "true") { "disabled" } else { 'enabled' }
                Write-Verbose "Current Automatic Account Creation Setting:- $EnableAutoAccountCreationStatus" 

                if ($securityConfig.enableAutomaticAccountCreation -ne $EnableAutomaticAccountCreation) {
                    $securityConfig.enableAutomaticAccountCreation = $EnableAutomaticAccountCreation
                    Set-PortalSecurityConfig -PortalHostName $FQDN -Token $token.token -SecurityParameters (ConvertTo-Json $securityConfig)
                }else{
                    Write-Verbose "Automatic Account Creation already $EnableAutoAccountCreationStatus"
                }
            }
            if ($null -ine $DisableServiceDirectory) {
                Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET'
                if (-not ($token)) {
                    $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer 'http://localhost'
                }
                
                if (-not ($securityConfig)) {
                    $securityConfig = Get-PortalSecurityConfig -PortalHostName $FQDN -Token $token.token
                }
                
                $dirStatus = if ($securityConfig.disableServicesDirectory -ne "true") { 'enabled' } else { 'disabled' }
                Write-Verbose "Current Service Directory Setting:- $dirStatus"
                
                if ($securityConfig.disableServicesDirectory -ne $DisableServiceDirectory) {
                    $securityConfig.disableServicesDirectory = $DisableServiceDirectory
                    Set-PortalSecurityConfig -PortalHostName $FQDN -Token $token.token -SecurityParameters (ConvertTo-Json $securityConfig)
                } else {
                    Write-Verbose "Service directory already $dirStatus"
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
        $PortalEndPoint,

        [parameter(Mandatory = $false)]
        [System.String]
        $PortalHostName,
        
        [System.String]
        $PortalContext = 'portal',

		[parameter(Mandatory = $true)]
		[System.String]
		$ExternalDNSName,

		[ValidateSet("Present", "Absent")]
		[System.String]
        $Ensure,
        
        [parameter(Mandatory = $false)]
		[System.String]
		$LicenseFilePath = $null,
        
        [parameter(Mandatory = $false)]
		[System.String]
        $UserLicenseType = $null,

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

        [System.Boolean]
        $UpgradeReindex,

        [System.String]
        $ContentDirectoryCloudConnectionString,

        [System.String]
        $ContentDirectoryCloudContainerName,

        [System.Management.Automation.PSCredential]
        $ADServiceUser,

        [System.Boolean]
        $EnableAutomaticAccountCreation,

        [System.Boolean]
        $DisableServiceDirectory
	)


    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false
    
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

    if ($result) {
        
        $InstallDir = Join-Path $InstallDir 'framework\runtime\ds' 

        $expectedHostIdentifierType = 'hostname'
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

    $Referer = 'http://localhost'   
    if ($result -and -not($Join)) {
        try {
			Wait-ForUrl "https://$($FQDN):7443/arcgis/sharing/rest/generateToken"
            Write-Verbose "Attempt to retrieve token for administrator from host $FQDN"
            $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
            $result = $token.token
            if ($result -and $ExternalDNSName) {
                $result = Test-WCPPWAPortalProperties -PortalHostName $FQDN -ExternalDNSName $ExternalDNSName -PortalEndPoint $PortalEndPoint `
                            -PortalContext $PortalContext -Token $token.token -IsCallingResourcePortal -Referer $Referer -Verbose
                
                if ($result) {
                    Write-Verbose "Checking If Portal on HTTPS_Only"
                    $PortalSelf = Get-PortalSelfDescription -PortalHostName $FQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer
                    $result = $PortalSelf.allSSL
                }				
			}
        }
        catch {
            Write-Verbose "[WARNING]:- Exception:- $($_)"   
            $result = $false
        }
    }    

    if ($result) {        
        $Referer = 'http://localhost'

        Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'POST'
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

    if($result){
        $Referer = 'http://localhost'
        Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET'
        if (-not ($token)){
            $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer 'http://localhost'
        }
        if (-not ($securityConfig)){
            $securityConfig = Get-PortalSecurityConfig -PortalHostName $FQDN -Token $token.token
        }
    
        if ($ADServiceUser.UserName) 
        {
            if ($($securityConfig.userStoreConfig.type) -ne 'WINDOWS') {
                Write-Verbose "UserStore Config Type is set to :-$($securityConfig.userStoreConfig.type)"
                $result = $false
            } else {
                Write-Verbose "UserStore Config Type is set to :-$($securityConfig.userStoreConfig.type). No Action required"
            }
        }

        if ($result -and ($null -ine $EnableAutomaticAccountCreation))
        {
            $EnableAutoAccountCreationStatus = if ($securityConfig.enableAutomaticAccountCreation -ne "true") { "disabled" } else { 'enabled' }
            Write-Verbose "Current Automatic Account Creation Setting:- $EnableAutoAccountCreationStatus" 

            if ($securityConfig.enableAutomaticAccountCreation -ne $EnableAutomaticAccountCreation) {
                Write-Verbose "EnableAutomaticAccountCreation setting doesn't match, Updating it."
                $result = $false
            }
        }

        if ($result -and ($null -ine $DisableServiceDirectory)) {
            
            $dirStatus = if ($securityConfig.disableServicesDirectory -ne "true") { 'enabled' } else { 'disabled' }
            Write-Verbose "Current Service Directory Setting:- $dirStatus"  
            
            if ($securityConfig.disableServicesDirectory -ne $DisableServiceDirectory) {
                Write-Verbose "Service directory setting does not match. Updating it."
                $result = $false
            }  
        }
    }

    if ($Ensure -ieq 'Present') {
	       $result   
    }
    elseif ($Ensure -ieq 'Absent') {        
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
            if (Ensure-PropertyInPropertiesFile -PropertiesFilePath $PropertiesFile -PropertyName $PropertyName -PropertyValue $DesiredLoggingLevel) {
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
                        -HttpFormParameters $params -Referer $Referer
    Write-Verbose "Set-PortalSecurityConfig Response:- $($resp.error) $resp"
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

    $response = Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):$($Port)/$SiteName/portaladmin/security/config/updateIdentityStore") -HttpFormParameters @{ f = 'json'; token = $Token; userStoreConfig = $userStoreConfig; } -Referer $Referer -TimeOutSec 300 -LogResponse
    if ($response.error) {
        throw "Error in Set-PortalUserStoreConfig:- $($response.error)"
    } else {
        Write-Verbose "Response received from Portal Set UserStoreconfig:- $response"
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

function Set-PortalSelfDescription {
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

function Upgrade-Reindex() {

    [CmdletBinding()]
    param(
        [System.String]
        $PortalHttpsUrl, 
        
        [System.String]
        $PortalSiteName = 'arcgis', 

        [System.String]
        $Token, 

        [System.String]
        $Referer = 'http://localhost'
        
    )

    [string]$ReindexSiteUrl = $PortalHttpsUrl.TrimEnd('/') + "/$PortalSiteName/portaladmin/system/indexer/reindex"

    $WebParams = @{ 
        mode = 'FULL_MODE'
        f = 'json'
        token = $Token
    }

    Write-Verbose "Making request to $ReindexSiteUrl to create the site"
    $Response = Invoke-ArcGISWebRequest -Url $ReindexSiteUrl -HttpFormParameters $WebParams -Referer $Referer -TimeOutSec 3000 -LogResponse 
    Write-Verbose "Response received from Reindex site $Response "  
    if ($Response.error -and $Response.error.message) {
        throw $Response.error.message
    }
    if ($Response.status -ieq 'success') {
        Write-Verbose "Reindexing Successful"
    }
}

Export-ModuleMember -Function *-TargetResource