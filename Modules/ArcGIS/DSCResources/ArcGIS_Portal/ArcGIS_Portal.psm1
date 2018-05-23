<#
    .SYNOPSIS
        Resource to Configure a Portal site.
    .PARAMETER Ensure
        Ensure makes sure that a Portal site is configured and joined to site if specified. Take the values Present or Absent. 
        - "Present" ensures that portal is configured, if not.
        - "Absent" ensures that existing portal site is deleted(Not Implemented).
    .PARAMETER PortalEndPoint
        Host Name of the Machine on which the Portal has been installed and is to be configured.
    .PARAMETER PortalContext
        Context of the Portal in case a LB or WebAdaptor is installed - Default is 'portal'
    .PARAMETER ExternalDNSName
        Enternal Endpoint of Portal in case a LB or WebAdaptor is installed - Needs for dummy Web Adaptor and WebContext URL to registered for the portal
    .PARAMETER PortalAdministrator
         A MSFT_Credential Object - Primary Site Adminstrator
    .PARAMETER AdminEMail
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
#>

function Create-PortalSite {    
    [CmdletBinding()]
    param(
        [string]$PortalHttpsUrl, 
        [string]$PortalSiteName, 
        [System.Management.Automation.PSCredential]$Credential, 
        [string]$FullName, 
        [string]$EMail, 
        [string]$SecurityQuestionAnswer, 
        [string]$ContentDirectoryLocation,
        [string]$ContentDirectoryCloudConnectionString,
        [string]$ContentDirectoryCloudContainerName,
        [int]$SecurityQuestionIdx = 1, 
        [string]$Description
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
    #$HttpRequestBody = To-HttpBody -props $WebParams
    Write-Verbose "Making request to $CreateNewSiteUrl to create the site"
    #$Response = Invoke-RestMethod -Method Post -Uri $CreateNewSiteUrl -Body $HttpRequestBody -TimeoutSec 2000
    $Response = Invoke-ArcGISWebRequest -Url $CreateNewSiteUrl -HttpFormParameters $WebParams -Referer 'http://localhost' -TimeOutSec 2000 -LogResponse
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
        [string]$PortalEndPoint, 
        [System.Management.Automation.PSCredential]$Credential, 
        [string]$PeerMachineHostName
    )

    $peerMachineAdminUrl = "https://$($PeerMachineHostName):7443"
    $MachineFQDN = Get-FQDN $PortalEndPoint
    [string]$JoinSiteUrl = "https://$($MachineFQDN):7443/arcgis/portaladmin/joinSite"
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
		
        Write-Verbose "Wait for endpoint 'https://$($MachineFQDN):7443/arcgis/portaladmin/' to initialize"
        Wait-ForUrl "https://$($MachineFQDN):7443/arcgis/portaladmin/" -HttpMethod 'POST'
        Write-Verbose "Finished Waiting for endpoint 'https://$($MachineFQDN):7443/arcgis/portaladmin/' to initialize. Sleeping for 5 minutes"

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
    Wait-ForPortalToStart -PortalHttpsUrl "https://$($MachineFQDN):7443/" -PortalSiteName "arcgis" -PortalAdminCredential $Credential -Referer "https://$($MachineFQDN):7443/"
}

function Wait-ForPortalToStart {
    [CmdletBinding()]
    param(
        [string]$PortalHttpsUrl, 
        [string]$PortalSiteName, 
        [System.Management.Automation.PSCredential]$PortalAdminCredential, 
        [string]$Referer,
        [int]$MaxAttempts = 40,
        [int]$SleepTimeInSeconds = 15
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

function Test-PortalSiteCreated([string]$PortalHttpsUrl, [string]$PortalSiteName, [System.Management.Automation.PSCredential]$PortalAdminCredential) {    
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} # Allow self-signed certificates
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
            
        [System.String]
        $PortalContext = 'portal',

        [parameter(Mandatory = $true)]
        [System.String]
        $ExternalDNSName,

        [ValidateSet("Present", "Absent")]
        [System.String]
        $Ensure,

        [System.Management.Automation.PSCredential]
        $PortalAdministrator,

        [System.String]
        $AdminEMail,

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
        $EnableAutomaticAccountCreation
    )

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    if ($VerbosePreference -ne 'SilentlyContinue') {        
        Write-Verbose ("PortalAdmin UserName:- " + $PortalAdministrator.UserName) 
        #Write-Verbose ("PortalAdmin Password:- " + $PortalAdministrator.GetNetworkCredential().Password) 
    }

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $FQDN = Get-FQDN $PortalEndPoint 

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
                Join-PortalSite -PortalEndPoint $PortalEndPoint -Credential $PortalAdministrator -PeerMachineHostName $PeerMachineFQDN
                Write-Verbose 'Joined Site'
            }
            else {
                Write-Verbose "Creating Site" 
                Create-PortalSite -PortalHttpsUrl "https://$($FQDN):7443" -PortalSiteName 'arcgis' -Credential $PortalAdministrator `
                    -FullName $PortalAdministrator.UserName -ContentDirectoryLocation $ContentDirectoryLocation `
                    -EMail $AdminEMail -SecurityQuestionIdx $AdminSecurityQuestionIndex -SecurityQuestionAnswer $AdminSecurityAnswer `
                    -Description 'Portal Administrator' -ContentDirectoryCloudConnectionString $ContentDirectoryCloudConnectionString `
                    -ContentDirectoryCloudContainerName $ContentDirectoryCloudContainerName
                Write-Verbose 'Created Site'
                if ($UpgradeReindex) {
                    Write-Verbose "Reindexing Portal"
                    $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
                    if (-not($token.token)) {
                        throw "Unable to retrieve Portal Token for '$PortalAdminUserName'"
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

        if ($ExternalDNSName -and $PortalEndPoint -and -not($Join) <#-and $PortalContext#>) {
            Write-Verbose "Waiting for 'https://$($FQDN):7443/arcgis/portaladmin/' to intialize"
            Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET' -LogFailures

            if (-not($PortalEndPoint -as [ipaddress])) {
                $PortalEndPoint = Get-FQDN $PortalEndPoint
            }

            $PortalHttpsUrl = "https://$($FQDN):7443" # "https://$($ExternalDNSName)"
            $PortalAdminUserName = $PortalAdministrator.UserName
            $PortalAdminPassword = $PortalAdministrator.GetNetworkCredential().Password 
			
            if (-not($token)) {
                Write-Verbose "Getting Portal Token for user '$PortalAdminUserName' from '$PortalHttpsUrl'"
                $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
                if (-not($token.token)) {
                    throw "Unable to retrieve Portal Token for '$PortalAdminUserName'"
                }
                Write-Verbose "Connected to Portal successfully and retrieved token for '$PortalAdminUserName'"
            }
    
            $sysProps = Get-PortalSystemProperties -PortalHostName $FQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer
            if (-not($sysProps)) {
                $sysProps = @{ }
            }
            $ExpectedWebContextUrl = "https://$($ExternalDNSName)/$($PortalContext)"
            $ExpectedPrivatePortalUrl = "https://$($PortalEndPoint):7443/arcgis" # "https://$($ExternalDNSName)/$($PortalContext)" 
            if (($sysProps.WebContextURL -ine $ExpectedWebContextUrl) -or ($sysProps.privatePortalURL -ine $ExpectedPrivatePortalUrl)) {
				
                Write-Verbose "One of the system properties for WebContextURL '$($sysProps.WebContextURL)' or privatePortalURL '$($sysProps.privatePortalURL)' does not match expected values"
                if ($sysProps.WebContextURL -ine $ExpectedWebContextUrl) {
                    Write-Verbose "Portal System Properties > WebContextUrl is NOT correctly set to '$($ExpectedWebContextUrl)'"
                    if (-not($sysProps.WebContextURL)) {
                        Add-Member -InputObject $sysProps -MemberType NoteProperty -Name 'WebContextURL' -Value $ExpectedWebContextUrl
                    }
                    else {
                        $sysProps.WebContextURL = $ExpectedWebContextUrl
                    }			
                }
                else {
                    Write-Verbose "Portal System Properties > WebContextUrl is correctly set to '$($sysProps.WebContextURL)'"
                }

                if ($sysProps.privatePortalURL -ine $ExpectedPrivatePortalUrl) {
                    Write-Verbose "Portal System Properties > privatePortalURL is NOT correctly set to '$($ExpectedPrivatePortalUrl)'"
                    if (-not($sysProps.privatePortalURL)) {
                        Add-Member -InputObject $sysProps -MemberType NoteProperty -Name 'privatePortalURL' -Value $ExpectedPrivatePortalUrl
                    }
                    else {
                        $sysProps.privatePortalURL = $ExpectedPrivatePortalUrl
                    }			
                }
                else {
                    Write-Verbose "Portal System Properties > privatePortalURL is correctly set to '$($sysProps.privatePortalURL)'"
                }

                Write-Verbose "Updating Portal System Properties to set WebContextUrl to $ExpectedWebContextUrl and privatePortalURl to $ExpectedPrivatePortalUrl"
                try {
                    Wait-ForUrl -Url "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET'
                    Set-PortalSystemProperties -PortalHostName $FQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer -Properties $sysProps
                } catch {
                    Write-Verbose "Error setting Portal System Properties :- $_"
                    Write-Verbose "Request: Set-PortalSystemProperties -PortalHostName $FQDN -SiteName 'arcgis' -Token $($token.token) -Referer $Referer -Properties $sysProps"
                }
                Write-Verbose "Waiting 5 minutes for web server to apply changes before polling for endpoint being available" 
                Start-Sleep -Seconds 300 # Add a 5 minute wait to allow the web server to go down
                Write-Verbose "Updated Portal System Properties. Waiting for portaladmin endpoint 'https://$($FQDN):7443/arcgis/portaladmin/' to come back up"
                Wait-ForUrl -Url "https://$($FQDN):7443/arcgis/portaladmin/" -MaxWaitTimeInSeconds 300 -HttpMethod 'GET' -LogFailures
                Write-Verbose "Finished waiting for portaladmin endpoint 'https://$($FQDN):7443/arcgis/portaladmin/' to come back up"
            }

            $WebAdaptorUrl = "https://$($ExternalDNSName)/$($PortalContext)"
            $WebAdaptorsForPortal = Get-WebAdaptorsForPortal -PortalHostName $FQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer
            Write-Verbose "Current number of WebAdaptors on Portal:- $($WebAdaptorsForPortal.webAdaptors.Length)"
            $AlreadyExists = $false
            $WebAdaptorsForPortal.webAdaptors | Where-Object { $_.httpPort -eq 80 -and $_.httpsPort -eq 443 } | ForEach-Object {
                if ($_.webAdaptorURL -ine $WebAdaptorUrl) {
                    Write-Verbose "Unregister Web Adaptor with Url $WebAdaptorUrl"
                    UnRegister-WebAdaptorForPortal -PortalHostName $FQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer -WebAdaptorId $_.id             
                }
                else {
                    Write-Verbose "Webadaptor with require properties URL $($_.webAdaptorURL) and Name $($_.machineName) already exists"
                    $AlreadyExists = $true
                }
            }

            if (-not($AlreadyExists)) {        
                #Register the ExternalDNSName and PortalEndPoint as a web adaptor for Portal
                Write-Verbose "Registering the ExternalDNSName Endpoint with Url $WebAdaptorUrl and MachineName $PortalEndPoint as a Web Adaptor for Portal"
                try{
                    Wait-ForUrl -Url "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET'
                    Register-WebAdaptorForPortal -PortalHostName $FQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer -WebAdaptorUrl $WebAdaptorUrl -MachineName $ExternalDNSName -HttpPort 80 -HttpsPort 443
                } catch {
                    Write-Verbose "Error registering Webadaptor for Portal :- $_"    
                    Write-Verbose "Request: Register-WebAdaptorForPortal -PortalHostName $FQDN -SiteName 'arcgis' -Token $($token.token) -Referer $Referer -WebAdaptorUrl $WebAdaptorUrl -MachineName $ExternalDNSName -HttpPort 80 -HttpsPort 443"
                }
                Write-Verbose "Waiting 3 minutes for web server to apply changes before polling for endpoint being available"
                Start-Sleep -Seconds 180 # Add a 3 minute wait to allow the web server to go down
                Write-Verbose "Updated Web Adaptors which causes a web server restart. Waiting for portaladmin endpoint 'https://$($FQDN):7443/arcgis/portaladmin/' to come back up"
                Wait-ForUrl -Url "https://$($FQDN):7443/arcgis/portaladmin/" -MaxWaitTimeInSeconds 300 -HttpMethod 'GET' -LogFailures
                Write-Verbose "Finished waiting for portaladmin endpoint 'https://$($FQDN):7443/arcgis/portaladmin/' to come back up"
            }

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
            if ($EnableAutomaticAccountCreation)
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
                if ($securityConfig.enableAutomaticAccountCreation -ne "true")
                {
                    Write-Verbose "EnableAutomaticAccountCreation is set to false, enable it"
                    $securityConfig.enableAutomaticAccountCreation = "true"
                    Set-PortalSecurityConfig -PortalHostName $FQDN -Token $token.token -SecurityParameters (ConvertTo-Json $securityConfig)
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
        
        [System.String]
        $PortalContext = 'portal',

        [parameter(Mandatory = $true)]
        [System.String]
        $ExternalDNSName,

        [ValidateSet("Present", "Absent")]
        [System.String]
        $Ensure,

        [System.Management.Automation.PSCredential]
        $PortalAdministrator,

        [System.String]
        $AdminEMail,

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
        $EnableAutomaticAccountCreation
    )

 
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false
   
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $FQDN = Get-FQDN $PortalEndPoint    
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
            $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
            $result = $token.token
            if ($result -and $ExternalDNSName) {
                # Check if web context URL is set correctly							
                $sysProps = Get-PortalSystemProperties -PortalHostName $FQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer
                $ExpectedWebContextUrl = "https://$($ExternalDNSName)/$($PortalContext)"	
                if ($sysProps.WebContextURL -ieq $ExpectedWebContextUrl) {
                    Write-Verbose "Portal System Properties > WebContextUrl is correctly set to '$($ExpectedWebContextUrl)'"
                }
                else {
                    $result = $false
                    Write-Verbose "Portal System Properties > WebContextUrl is NOT correctly set to '$($ExpectedWebContextUrl)'"
                }

                if ($result -and $PortalEndPoint) {
                    if (-not($PortalEndPoint -as [ipaddress])) {
                        $PortalEndPoint = Get-FQDN $PortalEndPoint
                    }
                    # Check if private portal URL is set correctly
                    $ExpectedPrivatePortalUrl = "https://$($PortalEndPoint):7443/arcgis" # "https://$($ExternalDNSName)/$($SiteName)"
                    if ($sysProps.privatePortalURL -ieq $ExpectedPrivatePortalUrl) {						
                        Write-Verbose "Portal System Properties > privatePortalURL is correctly set to '$($ExpectedPrivatePortalUrl)'"
                    }
                    else {
                        $result = $false
                        Write-Verbose "Portal System Properties > privatePortalURL is NOT correctly set to '$($ExpectedPrivatePortalUrl)'"
                    }
                }
				
                if ($result) {
                    $ExpectedUrl = "https://$ExternalDNSName/$PortalContext"
                    $webadaptorConfigs = Get-WebAdaptorsForPortal -PortalHostName $FQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer
                    $result = $false
                    $webadaptorConfigs.webAdaptors | Where-Object { $_.httpPort -eq 80 -and $_.httpsPort -eq 443 } | ForEach-Object {
                        if ($_.webAdaptorURL -ieq $ExpectedUrl) {
                            Write-Verbose "WebAdaptor URL $($_.webAdaptorURL) matches $ExpectedUrl"
                            $result = $True
                        }
                    }
                }

                if ($result) {
                    Write-Verbose "Checking If Portal on HTTPS_Only"
                    $PortalSelf = Get-PortalSelfDescription -PortalHostName $FQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer
                    $result = $PortalSelf.allSSL
                }
            }
        }
        catch {
            Write-Verbose "Error:- $_"
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

    if ($result -and ($ADServiceUser.UserName)) 
    {
        $Referer = 'http://localhost'
        
        Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET'
        $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer

        $securityConfig = Get-PortalSecurityConfig -PortalHostName $FQDN -Token $token.token
        if ($($securityConfig.userStoreConfig.type) -ne 'WINDOWS') 
        {
            Write-Verbose "UserStore Config Type is set to :-$($securityConfig.userStoreConfig.type)"
            $result = $false
        } else {
            Write-Verbose "UserStore Config Type is set to :-$($securityConfig.userStoreConfig.type). No Action required"
        }
    }

    if ($result -and ($EnableAutomaticAccountCreation))
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
        if ($securityConfig.enableAutomaticAccountCreation -ne "true")
        {
            Write-Verbose "EnableAutomaticAccountCreation is set to false, it should be enabled"
            $result = $false
        } else {
            Write-Verbose "EnableAutomaticAccountCreation is already set to true"
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

function Get-WebAdaptorsForPortal {
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

    Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):$($Port)/$($SiteName)" + "/portaladmin/system/webadaptors") -HttpFormParameters @{ token = $Token; f = 'json' } -Referer $Referer -HttpMethod 'GET'
}

function Register-WebAdaptorForPortal {
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
        $WebAdaptorUrl, 

        [System.String]
        $MachineName, 

        [System.Int32]
        $HttpPort = 80, 

        [System.Int32]
        $HttpsPort = 443
    )
    [System.String]$RegisterWebAdaptorsUrl = ("https://$($PortalHostName):$($Port)/$($SiteName)" + "/portaladmin/system/webadaptors/register")
    Write-Verbose "Register Web Adaptor URL:- $RegisterWebAdaptorsUrl"
    $WebParams = @{ token = $Token
        f = 'json'
        webAdaptorURL = $WebAdaptorUrl
        machineName = $MachineName
        httpPort = $HttpPort.ToString()
        httpsPort = $HttpsPort.ToString()
    }
    try {
        Invoke-ArcGISWebRequest -Url $RegisterWebAdaptorsUrl -HttpFormParameters $WebParams -Referer $Referer -TimeoutSec 180 -ErrorAction Ignore
    }
    catch {
        Write-Verbose "[WARNING] Register-WebAdaptorForPortal returned an error. Error:- $_"
    }
}

function UnRegister-WebAdaptorForPortal {
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
        $WebAdaptorId
    )
	    
    Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):$($Port)/$($SiteName)" + "/portaladmin/system/webadaptors/$WebAdaptorId/unregister") -HttpFormParameters  @{ f = 'json'; token = $Token } -Referer $Referer -TimeoutSec 300      
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

function Get-PortalSystemProperties {
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
    
    Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):$($Port)/$($SiteName)" + '/portaladmin/system/properties/') -HttpMethod 'GET' -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer 
}

function Set-PortalSystemProperties {
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
        Invoke-ArcGISWebRequest -Url("https://$($PortalHostName):$($Port)/$($SiteName)" + '/portaladmin/system/properties/update/') -HttpFormParameters @{ f = 'json'; token = $Token; properties = (ConvertTo-Json $Properties -Depth 4) } -Referer $Referer -TimeOutSec 360
    }
    catch {
        Write-Verbose "[WARNING] Request to Set-PortalSystemProperties returned error:- $_"
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
