$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.Server.psm1'))
<#
    .SYNOPSIS
        Creates a SelfSigned Certificate or Installs a SSL Certificated Provided and Configures it with Server
    .PARAMETER ServerHostName
        Optional Host Name or IP of the Machine on which the Server has been installed and is to be configured.
    .PARAMETER ServerType
        Site Name or Default Context of Server
    .PARAMETER SiteAdministrator
        A MSFT_Credential Object - Primary Site Administrator.
    .PARAMETER WebServerCertificateAlias
        WebServerCertificateAlias with which the Certificate will be associated.
    .PARAMETER CertificateFileLocation
        Certificate Path from where to fetch the certificate to be installed.
    .PARAMETER CertificatePassword
        Sercret Certificate Password or Key.
    .PARAMETER SslRootOrIntermediate
        Takes a JSON string list of all the root or intermediate certificates to import
    .PARAMETER EnableHTTPSOnly
        Enable only HTTPs protocol
    .PARAMETER EnableHSTS
        Enable HTTP Strict Transport Security (HSTS)
#>

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
        [parameter(Mandatory = $True)]
        [System.String]
        $ServerHostName
	)

	@{}
}

<#
    .SYNOPSIS
        Reconciles an ArcGIS Server certificate operation after its web server may have restarted.

    .DESCRIPTION
        Certificate imports and web-server alias updates can close their HTTP connection after
        committing the change but before returning a response. This function treats that transport
        failure as an indeterminate outcome rather than retrying the mutation. It waits for Server
        to recover, obtains a fresh token, and verifies the expected alias and thumbprint through
        the Server Administrator API. After health recovery, read-only verification is polled
        because the certificate entry may not yet be available even when the listener is healthy.

        When RequireActiveAlias is true, it also waits until a TLS handshake presents the expected
        certificate and confirms that webServerCertificateAlias references the requested alias.
        The supplied OperationError is ignored only when all requested postconditions are observed.

    .PARAMETER RequireActiveAlias
        Also verifies that the alias is active and that the HTTPS endpoint presents its certificate.
        Import-only operations leave this false because an imported certificate is not served until
        a later alias update.

    .PARAMETER OperationError
        Transport error captured from the mutation request. It is retained for diagnostics and is
        included in the final failure if reconciliation cannot prove that the operation succeeded.

    .PARAMETER MaxWaitTimeInSeconds
        Maximum wait for each endpoint, health, and certificate-state verification phase.
        In-flight administrative requests can extend the elapsed time beyond this window.

    .PARAMETER SleepTimeInSeconds
        Interval between read-only certificate-state verification attempts.
#>
function Wait-ForServerCertificateState
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerBaseUrl,

        [System.String]
        $ServerType,

        [System.Management.Automation.PSCredential]
        $SiteAdministrator,

        [System.String]
        $Referer,

        [System.String]
        $MachineName,

        [System.String]
        $CertificateAlias,

        [System.String]
        $ExpectedThumbprint,

        [System.Boolean]
        $RequireActiveAlias = $false,

        $OperationError,

        [ValidateRange(1, 2147483647)]
        [System.Int32]
        $MaxWaitTimeInSeconds = 300,

        [ValidateRange(1, 2147483647)]
        [System.Int32]
        $SleepTimeInSeconds = 5
    )

    try {
        # Give an asynchronously scheduled restart time to begin. Without this grace period, an
        # immediate health request can succeed against the old listener and create a false positive.
        Start-Sleep -Seconds 5
        if($RequireActiveAlias){
            # Velocity exposes a different public health surface, but the purpose is the same:
            # complete a TLS handshake against the component's restarted HTTPS listener.
            $CertificateProbeUrl = if($ServerType -ieq 'VelocityServer'){
                "$($ServerBaseUrl)/rest/info?f=json"
            }else{
                "$($ServerBaseUrl)/rest/info/healthcheck?f=json"
            }
            Wait-ForArcGISEndpointCertificate -Url $CertificateProbeUrl `
                                                -ExpectedThumbprint $ExpectedThumbprint `
                                                -MaxWaitTimeInSeconds $MaxWaitTimeInSeconds `
                                                -SleepTimeInSeconds $SleepTimeInSeconds -Verbose
        }

        Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName $ServerType `
                                    -MaxWaitTimeInSeconds $MaxWaitTimeInSeconds `
                                    -SleepTimeInSeconds $SleepTimeInSeconds -ThrowErrors $true -Verbose

        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            while($true){
                try {
                    $refreshedToken = Get-ServerToken -URL $ServerBaseUrl -Credential $SiteAdministrator -Referer $Referer
                    if(-not($refreshedToken.token)){
                        throw "Unable to retrieve a server token after the certificate operation."
                    }

                    $certificate = Get-SSLCertificateForMachine -URL $ServerBaseUrl -Token $refreshedToken.token `
                                        -Referer $Referer -MachineName $MachineName -SSLCertName $CertificateAlias.ToLower() `
                                        -ThrowOnResponseError $true -ServerType $ServerType -Verbose
                    if($null -eq $certificate){
                        throw "Certificate '$CertificateAlias' was not returned by Server. Expected thumbprint '$ExpectedThumbprint'."
                    }
                    if($certificate.Thumbprint -ine $ExpectedThumbprint){
                        throw "Certificate '$CertificateAlias' has thumbprint '$($certificate.Thumbprint)', but expected '$ExpectedThumbprint'."
                    }

                    if($RequireActiveAlias){
                        $machineProperties = Get-MachineProperties -URL $ServerBaseUrl -Token $refreshedToken.token `
                                            -Referer $Referer -MachineName $MachineName
                        if($machineProperties.webServerCertificateAlias -ine $CertificateAlias){
                            throw "Certificate '$CertificateAlias' is not the active web server certificate."
                        }
                    }

                    return $refreshedToken
                }
                catch {
                    $remainingSeconds = $MaxWaitTimeInSeconds - $stopwatch.Elapsed.TotalSeconds
                    if($remainingSeconds -le 0){
                        throw "Timed out verifying certificate '$CertificateAlias' after Server recovery. Last verification error: $_"
                    }
                    Write-Verbose "Certificate '$CertificateAlias' is not ready after Server recovery. Retrying verification: $_"
                    Start-Sleep -Milliseconds ([int]([Math]::Min($SleepTimeInSeconds, $remainingSeconds) * 1000))
                }
            }
        }
        finally {
            $stopwatch.Stop()
        }
    }
    catch {
        # Surface both failures when the mutation response was lost and its postcondition is absent.
        # If reconciliation succeeds, the original transport error was only a lost acknowledgement.
        if($null -ne $OperationError){
            throw "The certificate operation response failed and the expected state could not be verified. Operation error: $OperationError Reconciliation error: $_"
        }
        throw
    }
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
        [parameter(Mandatory = $true)]
        [System.String]
        $ServerHostName,

        [System.String]
        $ServerType,

		[System.Management.Automation.PSCredential]
		$SiteAdministrator,
		
		[System.String]
		$WebServerCertificateAlias,

        [System.String]
		$CertificateFileLocation,

		[System.Management.Automation.PSCredential]
		$CertificatePassword,
        
        [System.String]
        $SslRootOrIntermediate,

        [System.Boolean]
        $EnableHTTPSOnly,

        [System.Boolean]
        $EnableHSTS,

        [System.String]
        $Version,

        [System.Boolean]
        $ImportCertificateChain = $true,

        [System.Boolean]
        $ForceImportCertificate = $false
	)

    if($WebServerCertificateAlias){
        $WebServerCertificateAlias = $WebServerCertificateAlias.ToLowerInvariant()
    }

    if($CertificateFileLocation -and -not(Test-Path $CertificateFileLocation)){
        throw "Certificate File '$CertificateFileLocation' is not found or inaccessible"
    }
    
    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    
    $ServerBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName $ServerType -FQDN $FQDN
    $Referer = $ServerBaseUrl
	Write-Verbose "Waiting for Server '$($ServerBaseUrl)' to initialize"
    Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName $ServerType
                      
    $token = Get-ServerToken -URL $ServerBaseUrl -Credential $SiteAdministrator -Referer $Referer
    if(-not($token.token)){
        throw "Unable to retrieve token for Site Administrator"
    }

    $MachineName = $FQDN
    $RestartRequired = $False
    if($null -ne $SslRootOrIntermediate){ #RootOrIntermediateCertificate
        $RestartRequired = Set-ServerRootAndIntermdiateCertificates -URL $ServerBaseUrl -ServerType $ServerType `
                                                -Token $token.token -Referer $Referer -MachineName $MachineName `
                                                -Credential $SiteAdministrator -SslRootOrIntermediate $SslRootOrIntermediate -Verbose
        if($RestartRequired){
            # The setter preserves its Boolean contract, so refresh the caller's token explicitly
            # before continuing with security and web-server certificate operations.
            $token = Get-ServerToken -URL $ServerBaseUrl -Credential $SiteAdministrator -Referer $Referer
            if(-not($token.token)){
                throw "Unable to retrieve token after importing Server root or intermediate certificates."
            }
        }
    }

    # Get the current security configuration only for GIS Servers
    if(Test-IfGISServer -ServerType $ServerType){
        $UpdateSecurityConfig = $False
        Write-Verbose 'Getting security config for site'
        $secConfig = Get-SecurityConfig -URL $ServerBaseUrl -Token $token.token -Referer $Referer
        
        if($EnableHTTPSOnly){
            if($secConfig.sslEnabled -and -not($secConfig.httpEnabled)){
                Write-Verbose "Https Only is enabled. No update required"
            }else{
                Write-Verbose "Https Only is disabled. Update required"
                $UpdateSecurityConfig = $True
            }
        }else{
            if($EnableHSTS){
                throw "Error: Enable HSTS porperty requires http protocol set to only HTTPS."
            }

            if(-not($secConfig.sslEnabled -and -not($secConfig.httpEnabled))){
                Write-Verbose "Https Only is disabled. No update required"
            }else{
                Write-Verbose "Https Only is enabled. Update required"
                $UpdateSecurityConfig = $True
            }
        }

        if(-not($UpdateSecurityConfig)){
            if($secConfig.HSTSEnabled -ine $EnableHSTS){
                Write-Verbose "Enable HSTS doesn't match the expected state $EnableHSTS"
                $UpdateSecurityConfig = $True
            }else{
                Write-Verbose "Enable HSTS matches the expected state $EnableHSTS"
            }
        }

        if($UpdateSecurityConfig){
            Update-SecurityConfig -URL $ServerBaseUrl -Token $token.token -Referer $Referer `
                                    -Properties $secConfig -EnableHTTPSOnly $EnableHTTPSOnly `
                                    -EnableHSTS $EnableHSTS -MaxAttempts 1 -Verbose
            
            Wait-ForArcGISComponentRestart -BaseURL $ServerBaseUrl -ComponentName $ServerType -MaxStartupWaitTimeInSeconds 150 -StartupSleepTimeInSeconds 15 -Verbose
        }
    }
    
    Test-MachineExists -URL $ServerBaseUrl -Token $token.token -Referer $Referer -MachineName $MachineName

    if($CertificateFileLocation){
        if(-not(Test-Path $CertificateFileLocation)){
            throw "Certificate File '$CertificateFileLocation' is not found"
        }
        if($WebServerCertificateAlias -as [ipaddress]) {
			Write-Verbose "Adding Host mapping for $WebServerCertificateAlias"
			Add-HostMapping -hostname $WebServerCertificateAlias -ipaddress $WebServerCertificateAlias        
		}

        $suppliedCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $suppliedCertificate.Import($CertificateFileLocation,$CertificatePassword.GetNetworkCredential().Password,'DefaultKeySet')
        $NewCertIssuer = $suppliedCertificate.Issuer
        $NewCertThumbprint = $suppliedCertificate.Thumbprint
        Write-Verbose "Issuer for the supplied certificate is $NewCertIssuer"
        Write-Verbose "Thumbprint for the supplied certificate is $NewCertThumbprint"

        $DeleteTempCert = $False
        $ImportCert = $False
        $UpdateWebAlias = $False
        $CertForMachine = Get-SSLCertificateForMachine -URL $ServerBaseUrl -Token $token.token -Referer $Referer -MachineName $MachineName -SSLCertName $WebServerCertificateAlias.ToLower() -ServerType $ServerType
        if($null -ne $CertForMachine){ # Certificate with CName Found
            $ExistingCertIssuer = $CertForMachine.Issuer    
            $ExistingCertThumbprint = $CertForMachine.Thumbprint
            Write-Verbose "Existing Cert Issuer $ExistingCertIssuer with Thumbprint $ExistingCertThumbprint"
            $machineDetails = Get-MachineProperties -URL $ServerBaseUrl -Token $token.token -Referer $Referer -MachineName $MachineName
            if($ExistingCertThumbprint -ine $NewCertThumbprint -or $ForceImportCertificate){ #Certificate Thumbprint doesn't match
                if($WebServerCertificateAlias -ieq $machineDetails.webServerCertificateAlias -or $ForceImportCertificate){
                    $DeleteTempCert = $True
                    #Upload Temp Cert
                    Write-Verbose "Force import certificate is: $ForceImportCertificate"
                    Write-Verbose "Importing Supplied Certificate with Alias $($WebServerCertificateAlias)-temp"
                    # Never retry this POST after a connection drop. The certificate may already be
                    # committed, so capture the error and let reconciliation determine the outcome.
                    $importError = $null
                    try {
                        Import-ExistingCertificate -URL $ServerBaseUrl -Token $token.token -Referer $Referer `
                            -MachineName $MachineName -CertAlias "$($WebServerCertificateAlias)-temp" -CertificatePassword $CertificatePassword `
                            -CertificateFilePath $CertificateFileLocation -ServerType $ServerType -ImportCertificateChain $ImportCertificateChain `
                            -Version $Version -ThrowOnResponseError $true
                    }
                    catch {
                        $importError = $_
                    }
                    $token = Wait-ForServerCertificateState -ServerBaseUrl $ServerBaseUrl -ServerType $ServerType `
                                -SiteAdministrator $SiteAdministrator -Referer $Referer -MachineName $MachineName `
                                -CertificateAlias "$($WebServerCertificateAlias)-temp" -ExpectedThumbprint $NewCertThumbprint `
                                -OperationError $importError -Verbose

                    $RestartRequired = $False
                    #Update Web Alias to Temp Cert
                    Write-Verbose "Updating to temp SSL Certificate for machine [$MachineName]"
                    # Alias updates can restart the web server before returning their response.
                    # Verify both the endpoint certificate and persisted alias before deleting the old cert.
                    $updateError = $null
                    try {
                        Update-MachineProperties -URL $ServerBaseUrl `
                                -Token          $token.token `
                                -Referer        $Referer `
                                -MachineName    $MachineName `
                                -WebServerCertificateAlias "$($WebServerCertificateAlias)-temp" -MaxAttempts 1 -Verbose
                        
                        # Restart the ArcGIS Server service after updating the machine properties
                        Restart-ArcGISService -ComponentName "Server" -Verbose
                    }
                    catch {
                        $updateError = $_
                    }
                    $token = Wait-ForServerCertificateState -ServerBaseUrl $ServerBaseUrl -ServerType $ServerType `
                                -SiteAdministrator $SiteAdministrator -Referer $Referer -MachineName $MachineName `
                                -CertificateAlias "$($WebServerCertificateAlias)-temp" -ExpectedThumbprint $NewCertThumbprint `
                                -RequireActiveAlias $true -OperationError $updateError -Verbose
                }

                #Delete Certificate
                Write-Verbose "Certificate with alias $WebServerCertificateAlias already exists for machine $MachineName. Deleting it"
                try {
                    $res = Invoke-DeleteSSLCertForMachine -URL $ServerBaseUrl -Token $token.token -Referer $Referer -MachineName $MachineName -SSLCertName $WebServerCertificateAlias.ToLower()
                    Write-Verbose "Delete Certificate Operation result - $($res | ConvertTo-Json)"
                }
                catch {
                    Write-Verbose "[WARNING] Error deleting SSL Cert with alias $WebServerCertificateAlias. Error:- $_"
                }
                $ImportCert = $True #Upload New Cert
                $UpdateWebAlias = $True #Update Web Alias
            }else{ # Thumbprint matches
                if($WebServerCertificateAlias -ine $machineDetails.webServerCertificateAlias){
                    Write-Verbose "Certificate with alias $WebServerCertificateAlias already exists for machine $MachineName, but web server certificate alias $($machineDetails.webServerCertificateAlias) doesn't match."
                    $UpdateWebAlias = $True #Update Web Alias
                } else { #Everything Matches
                    Write-Verbose "Certificate with alias $WebServerCertificateAlias already exists for machine $MachineName and matches all the requirements."
                }
            }
        }else{ #Certificate with CName/Alias not found
            $ImportCert = $True #Upload New Cert
            $UpdateWebAlias = $True #Update Web Alias
        }

        if($ImportCert){
            Write-Verbose "Waiting for Server '$ServerBaseUrl'"
            Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName $ServerType -SleepTimeInSeconds 15 -MaxWaitTimeInSeconds 150

            # Import the Supplied Certificate  
            Write-Verbose "Importing Supplied Certificate with Alias $WebServerCertificateAlias"
            # A dropped response is reconciled by alias and thumbprint; the upload is not repeated.
            $importError = $null
            try {
                Import-ExistingCertificate -URL $ServerBaseUrl -Token $token.token -Referer $Referer `
                        -MachineName $MachineName -CertAlias $WebServerCertificateAlias -CertificatePassword $CertificatePassword `
                        -CertificateFilePath $CertificateFileLocation -ServerType $ServerType -ImportCertificateChain $ImportCertificateChain `
                        -Version $Version -ThrowOnResponseError $true
            }
            catch {
                $importError = $_
            }
            $token = Wait-ForServerCertificateState -ServerBaseUrl $ServerBaseUrl -ServerType $ServerType `
                        -SiteAdministrator $SiteAdministrator -Referer $Referer -MachineName $MachineName `
                        -CertificateAlias $WebServerCertificateAlias -ExpectedThumbprint $NewCertThumbprint `
                        -OperationError $importError -Verbose
        }

        if($UpdateWebAlias){
            $RestartRequired = $False
            Write-Verbose "Updating SSL Certificate for machine [$MachineName]"
            # The endpoint certificate is the authoritative signal that the asynchronous restart
            # completed and clients are receiving the intended certificate.
            $updateError = $null
            try {
                Update-MachineProperties -URL            $ServerBaseUrl `
                                        -Token          $token.token `
                                        -Referer        $Referer `
                                        -MachineName    $MachineName `
                                        -WebServerCertificateAlias $WebServerCertificateAlias -MaxAttempts 1 -Verbose

                # Restart the ArcGIS Server service
                # after updating the machine properties before checking the health of the server
                Restart-ArcGISService -ComponentName "Server" -Verbose
            }
            catch {
                $updateError = $_
            }
            $token = Wait-ForServerCertificateState -ServerBaseUrl $ServerBaseUrl -ServerType $ServerType `
                        -SiteAdministrator $SiteAdministrator -Referer $Referer -MachineName $MachineName `
                        -CertificateAlias $WebServerCertificateAlias -ExpectedThumbprint $NewCertThumbprint `
                        -RequireActiveAlias $true -OperationError $updateError -Verbose

            # Restart Geoevent
            if(Test-IfGISServer -ServerType $ServerType){ #TODO - This will cause issues in Azure, where we have Geoevent and WFM running.
                ### If the SSL Certificate is changed. Restart the GeoEvent Service so that it will pick up the new certificate 
                $GeoEventServiceName = 'ArcGISGeoEvent' 
                $GeoEventService = Get-Service -Name $GeoEventServiceName -ErrorAction Ignore
                if($GeoEventService -and $GeoEventService.Status -ieq 'Running') {
                    $GeoEventServerHttpsUrl = Get-ArcGISComponentBaseUrl -ComponentName "GeoEventServer" -Context "geoevent"
                    Restart-ArcGISService -ServiceName $GeoEventServiceName -Verbose
                    Write-Verbose "Waiting for Url '$($GeoEventServerHttpsUrl)/rest' to respond"
                    Test-ArcGISComponentHealth -BaseURL $GeoEventServerHttpsUrl -ComponentName "GeoEvent" -SleepTimeInSeconds 20 -MaxWaitTimeInSeconds 150 -Verbose
                    Write-Verbose "Restarted Service $GeoEventServiceName"
                }
            }
        }
        
        # Only clean up a temporary certificate uploaded during this invocation.
        if($DeleteTempCert){
            $TempCertificateAlias = "$($WebServerCertificateAlias)-temp"
            try {
                Write-Verbose "Deleting Temp Certificate with alias $TempCertificateAlias"
                $res = Invoke-DeleteSSLCertForMachine -URL $ServerBaseUrl -Token $token.token -Referer $Referer -MachineName $MachineName -SSLCertName $TempCertificateAlias.ToLower()
                Write-Verbose "Delete Temp Certificate Operation result - $($res | ConvertTo-Json)"
            }
            catch {
                Write-Verbose "[WARNING] Error deleting Temp SSL Cert with alias $TempCertificateAlias. Error:- $_"
            }
        }
    }else{
        Write-Verbose "CertificateFileLocation not specified. Skipping web server certificate configuration"
    }

    if($RestartRequired)
    {
        Write-Verbose "Restart required."
        if($ServerType -ieq 'VelocityServer'){
            $WindowsServicesToCheck = Get-VelocityServerServiceNames
            foreach($VelocityServiceName in $WindowsServicesToCheck){
                Restart-ArcGISService -ServiceName $VelocityServiceName -Verbose
            }
        }else{
            Restart-ArcGISService -ComponentName $ServerType -Verbose
        }
        Write-Verbose "Waiting 30 seconds before checking for initialization"
        Start-Sleep -Seconds 30

        Write-Verbose "Waiting for Server '$ServerBaseUrl'"
        Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName $ServerType -SleepTimeInSeconds 10 -MaxWaitTimeInSeconds 60
    }
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [parameter(Mandatory = $True)]
        [System.String]
        $ServerHostName,
        
        [System.String]
        $ServerType,

		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

        [System.String]
		$WebServerCertificateAlias,

		[System.String]
		$CertificateFileLocation,

		[System.Management.Automation.PSCredential]
		$CertificatePassword,
        
        [System.String]
        $SslRootOrIntermediate,

        [System.Boolean]
        $EnableHTTPSOnly,

        [System.Boolean]
        $EnableHSTS,

        [System.String]
        $Version,

        [System.Boolean]
        $ImportCertificateChain = $true,

        [System.Boolean]
        $ForceImportCertificate = $false
	)

    if($CertificateFileLocation -and -not(Test-Path $CertificateFileLocation)){
        throw "Certificate File '$CertificateFileLocation' is not found or inaccessible"
    }

    $result = $True

    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }

    $ServerBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName $ServerType -FQDN $FQDN
    $Referer = $ServerBaseUrl
	Write-Verbose "Waiting for Server '$($ServerBaseUrl)'"
    Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName $ServerType

    $Referer = $ServerBaseUrl
    $token = Get-ServerToken -URL $ServerBaseUrl -Credential $SiteAdministrator -Referer $Referer
    if(-not($token.token)){
        throw "Unable to retrieve token for Site Administrator"
    }

    # Only for GIS Server
    if(Test-IfGISServer -ServerType $ServerType){
        $secConfig = Get-SecurityConfig -URL $ServerBaseUrl -Token $token.token -Referer $Referer
        if($result){
            if($EnableHTTPSOnly){
                if($secConfig.sslEnabled -and -not($secConfig.httpEnabled)){
                    Write-Verbose "Https Only is enabled. No update required"
                }else{
                    Write-Verbose "Https Only is disabled. Update required"
                    $result = $false
                }
            }else{
                if($EnableHSTS){
                    throw "Error: Enable HSTS porperty requires http protocol set to only HTTPS."
                }
        
                if(-not($secConfig.sslEnabled -and -not($secConfig.httpEnabled))){
                    Write-Verbose "Https Only is disabled. No update required"
                }else{
                    Write-Verbose "Https Only is enabled. Update required."
                    $result = $false
                }
            }
        
            if($result){
                if($secConfig.HSTSEnabled -ine $EnableHSTS){
                    Write-Verbose "Enable HSTS doesn't match the expected state $EnableHSTS"
                    $result = $false
                }else{
                    Write-Verbose "Enable HSTS matches the expected state $EnableHSTS"
                }
            }
        }
    }

    $MachineName = $FQDN
    Test-MachineExists -URL $ServerBaseUrl -Token $token.token -Referer $Referer -MachineName $MachineName

    if($result){
        if($CertificateFileLocation){
            if(-not(Test-Path $CertificateFileLocation)){
                throw "Certificate File '$CertificateFileLocation' is not found"
            }
            
            $CertForMachine = Get-SSLCertificateForMachine -URL $ServerBaseUrl -Token $token.token -Referer $Referer -MachineName $MachineName -SSLCertName $WebServerCertificateAlias.ToLower() -ServerType $ServerType -Verbose
            if($null -ne $CertForMachine){ # Certificate with Alias Found
                $NewCertIssuer = $null
                $NewCertThumbprint = $null
                if($CertificateFileLocation -and ($null -ne $CertificatePassword)) {
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                    $cert.Import($CertificateFileLocation,$CertificatePassword.GetNetworkCredential().Password,'DefaultKeySet')
                    $NewCertIssuer = $cert.Issuer
                    $NewCertThumbprint = $cert.Thumbprint
                    Write-Verbose "Issuer for the supplied certificate is $NewCertIssuer"
                    Write-Verbose "Thumbprint for the supplied certificate is $NewCertThumbprint"
                }
                $ExistingCertIssuer = $CertForMachine.Issuer    
                $ExistingCertThumbprint = $CertForMachine.Thumbprint
                Write-Verbose "Existing Cert Issuer $ExistingCertIssuer and Thumbprint $ExistingCertThumbprint"

                # Compare thumbprints and alias
                if($ExistingCertThumbprint -ine $NewCertThumbprint){ #Certificate Thumbprint doesn't match
                    Write-Verbose "Thumbprints for Certificate with Alias $WebServerCertificateAlias doesn't match that of existing cetificate."
                    $result = $False
                }else{ # Thumbprint matches
                    $machineDetails = Get-MachineProperties -URL $ServerBaseUrl -Token $token.token -Referer $Referer -MachineName $MachineName
                    if($WebServerCertificateAlias -ine $machineDetails.webServerCertificateAlias){
                        Write-Verbose "Certificate with alias $WebServerCertificateAlias already exists for machine $MachineName, but web server certificate alias $($machineDetails.webServerCertificateAlias) doesn't match."
                        $result = $False
                    } else { #Everything Matches
                        Write-Verbose "Certificate with alias $WebServerCertificateAlias already exists for machine $MachineName and matches all the requirements."
                    }
                }
            }else{ #Certificate with CName/Alias not found
                Write-Verbose "Certificate with Alias $WebServerCertificateAlias not found for machine $MachineName"
                $result = $False
            }
        }
    }
    
    if($result -and $null -ne $SslRootOrIntermediate){
        $MissingCerts = Get-ServerRootAndIntermdiateCertificatesToUpdate -URL $ServerBaseUrl -ServerType $ServerType `
                                                -Token $token.token -Referer $Referer -MachineName $MachineName `
                                                -SslRootOrIntermediate $SslRootOrIntermediate -Verbose
        $result = (@($MissingCerts).Count -eq 0)
        if(-not($result)){
            Write-Verbose "One or more root and intermediate certificate needs an update."
        }
    }

    if ($Version -and ([version]$Version -ge [version]"11.3") `
        -and (Test-IfGISServer -ServerType $ServerType) `
        -and ($ForceImportCertificate)) {
        $result = $false
        Write-Verbose "Force import certificate is True"
    }

	Write-Verbose "Returning $result from Test-TargetResource"
    $result
}

Export-ModuleMember -Function *-TargetResource