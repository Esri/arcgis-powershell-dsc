$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.Portal.psm1'))

<#
    .SYNOPSIS
        Creates a SelfSigned Certificate or Installs a SSL Certificated Provided and Configures it with Portal.
    .PARAMETER PortalHostName
        Portal Endpoint with which the Certificate will be associated.
    .PARAMETER SiteAdministrator
        A MSFT_Credential Object - Primary Site Administrator.
    .PARAMETER CertificateFileLocation
        Certificate Path from where to fetch the certificate to be installed.
    .PARAMETER CertificatePassword
        Sercret Certificate Password or Key.
    .PARAMETER WebServerCertificateAlias
        CName/Alias with which the Certificate will be associated.
	.PARAMETER SslRootOrIntermediate
        List of RootOrIntermediate Certificates
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
        $Version,

		[parameter(Mandatory = $true)]
        [System.String]
		$PortalHostName
	)

	@{}
}

<#
    .SYNOPSIS
        Reconciles a Portal certificate operation after its web server may have restarted.

    .DESCRIPTION
        Portal certificate imports and alias updates can commit successfully and then close the
        connection while restarting the embedded web server. Retrying such a mutation can conflict
        with the alias created by the first request. This function instead waits for Portal Admin
        and Sharing to recover, then polls read-only verification of the alias and thumbprint
        with fresh tokens because the certificate entry may lag behind listener recovery.

        For alias updates it additionally verifies the certificate presented by the HTTPS endpoint
        and the persisted webServerCertificateAlias setting. A captured OperationError is considered
        a lost acknowledgement only when all requested postconditions are satisfied.

    .PARAMETER RequireActiveAlias
        Also verifies the endpoint certificate and active Portal web-server alias. Import-only calls
        leave this false because importing does not make a certificate active.

    .PARAMETER OperationError
        Original mutation transport error, retained so a failed reconciliation reports both causes.

    .PARAMETER MaxWaitTimeInSeconds
        Maximum wait for each endpoint, health, and certificate-state verification phase.
        In-flight administrative requests can extend the elapsed time beyond this window.

    .PARAMETER SleepTimeInSeconds
        Interval between read-only certificate-state verification attempts.
#>
function Wait-ForPortalCertificateState
{
    [CmdletBinding()]
    param(
        [System.String]
        $PortalBaseURL,

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
        $MaxWaitTimeInSeconds = 360,

        [ValidateRange(1, 2147483647)]
        [System.Int32]
        $SleepTimeInSeconds = 5
    )

    try {
        # Allow an asynchronously scheduled restart to begin before accepting health responses.
        Start-Sleep -Seconds 5
        if($RequireActiveAlias){
            # Health alone can return from the previous listener. The TLS certificate proves that
            # the restarted listener has loaded the requested key material.
            Wait-ForArcGISEndpointCertificate -Url "$($PortalBaseURL)/portaladmin/healthCheck?f=json" `
                                                -ExpectedThumbprint $ExpectedThumbprint `
                                                -MaxWaitTimeInSeconds $MaxWaitTimeInSeconds `
                                                -SleepTimeInSeconds $SleepTimeInSeconds -Verbose
        }

        Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "Portal" `
                                    -MaxWaitTimeInSeconds $MaxWaitTimeInSeconds `
                                    -SleepTimeInSeconds $SleepTimeInSeconds -ThrowErrors $true -Verbose
        Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "PortalSharing" `
                                    -MaxWaitTimeInSeconds $MaxWaitTimeInSeconds `
                                    -SleepTimeInSeconds $SleepTimeInSeconds -ThrowErrors $true -Verbose

        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            while($true){
                try {
                    $refreshedToken = Get-PortalToken -URL $PortalBaseURL -Credential $SiteAdministrator -Referer $Referer
                    if(-not($refreshedToken.token)){
                        throw "Unable to retrieve a portal token after the certificate operation."
                    }

                    $certificate = Get-SSLCertificatesForPortal -URL $PortalBaseURL -Token $refreshedToken.token `
                                        -Referer $Referer -WebServerCertificateAlias $CertificateAlias.ToLower() `
                                        -MachineName $MachineName -ThrowOnResponseError $true
                    if($null -eq $certificate){
                        throw "Certificate '$CertificateAlias' was not returned by Portal. Expected thumbprint '$ExpectedThumbprint'."
                    }
                    if($certificate.sha1Fingerprint -ine $ExpectedThumbprint){
                        throw "Certificate '$CertificateAlias' has thumbprint '$($certificate.sha1Fingerprint)', but expected '$ExpectedThumbprint'."
                    }

                    if($RequireActiveAlias){
                        $certificateSettings = Get-SSLCertificatesForPortal -URL $PortalBaseURL -Token $refreshedToken.token `
                                                -Referer $Referer -MachineName $MachineName -ThrowOnResponseError $true
                        if($certificateSettings.webServerCertificateAlias -ine $CertificateAlias){
                            throw "Certificate '$CertificateAlias' is not the active web server certificate."
                        }
                    }

                    return $refreshedToken
                }
                catch {
                    $remainingSeconds = $MaxWaitTimeInSeconds - $stopwatch.Elapsed.TotalSeconds
                    if($remainingSeconds -le 0){
                        throw "Timed out verifying certificate '$CertificateAlias' after Portal recovery. Last verification error: $_"
                    }
                    Write-Verbose "Certificate '$CertificateAlias' is not ready after Portal recovery. Retrying verification: $_"
                    Start-Sleep -Milliseconds ([int]([Math]::Min($SleepTimeInSeconds, $remainingSeconds) * 1000))
                }
            }
        }
        finally {
            $stopwatch.Stop()
        }
    }
    catch {
        # Preserve the original mutation failure when the expected state cannot be proven.
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
        [parameter(Mandatory = $True)]    
        [System.String]
        $Version,

        [parameter(Mandatory = $true)]
        [System.String]
		$PortalHostName,

		[System.Management.Automation.PSCredential]
		$SiteAdministrator,
		
		[System.String]
		$CertificateFileLocation,

		[System.Management.Automation.PSCredential]
		$CertificatePassword,

        [System.String]
		$WebServerCertificateAlias,

        [System.String]
        $SslRootOrIntermediate,

        [System.Boolean]
        $EnableHSTS,

        [System.Boolean]
        $ImportCertificateChain = $true,

        [System.Boolean]
        $ForceImportCertificate = $false
	)

	
    $FQDN = if($PortalHostName) { Get-FQDN $PortalHostName} else { Get-FQDN $env:COMPUTERNAME }
    $PortalBaseURL = Get-ArcGISComponentBaseUrl -FQDN $FQDN -ComponentName "Portal"
    $Referer = $PortalBaseURL
    try{
        Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "Portal" -ThrowErrors $true -Verbose
        Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "PortalSharing" -ThrowErrors $true -Verbose

        $token = Get-PortalToken -URL $PortalBaseURL -Credential $SiteAdministrator -Referer $Referer 
    }catch{
        throw "[WARNING] Unable to get token:- $_"
    }
    if(-not($token.token)){
        throw "Unable to retrieve Portal Token for '$($SiteAdministrator.UserName)'"
    }else{
        Write-Verbose "Retrieved Portal Token"
    }

    $RestartRequired = $False
	# test and set RootOrIntermediateCertificate
    if($null -ne $SslRootOrIntermediate){
        $RestartRequired = Set-PortalRootAndIntermdiateCertificates -URL $PortalBaseURL `
                                                -Token $token.token -Referer $Referer -MachineName $FQDN `
                                                -Credential $SiteAdministrator -SslRootOrIntermediate $SslRootOrIntermediate -Verbose
        if($RestartRequired){
            # Keep the setter's existing Boolean return value while ensuring later Portal TLS
            # operations use authentication obtained after the trust-store update.
            $token = Get-PortalToken -URL $PortalBaseURL -Credential $SiteAdministrator -Referer $Referer
            if(-not($token.token)){
                throw "Unable to retrieve token after importing Portal root or intermediate certificates."
            }
        }
    }

    if($CertificateFileLocation) 
	{
        if($WebServerCertificateAlias -and $WebServerCertificateAlias -as [ipaddress]) {
            Write-Verbose "Adding Host mapping for $WebServerCertificateAlias"
            Add-HostMapping -hostname $WebServerCertificateAlias -ipaddress $WebServerCertificateAlias        
        }

        if((Test-Path $CertificateFileLocation))
        {
            $suppliedCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $suppliedCertificate.Import($CertificateFileLocation, $CertificatePassword.GetNetworkCredential().Password, 'DefaultKeySet')
            $NewCertThumbprint = $suppliedCertificate.Thumbprint
            Write-Verbose "Thumbprint for the supplied certificate is $NewCertThumbprint"

            try{
                $Certs = Get-SSLCertificatesForPortal -URL $PortalBaseURL -Token $token.token -Referer $Referer -MachineName $FQDN 
            }catch{
                throw "[WARNING] Unable to get SSL-CertificatesForPortal:- $_"
            }
            Write-Verbose "Current Alias for SSL Certificate:- '$($Certs.webServerCertificateAlias)' Certificates:- '$($Certs.sslCertificates -join ',')'"

            $ImportExistingCertFlag = $False
            $DeleteTempCert = $False
            $CertificateAliases = ConvertTo-PortalCertificateAliases -Certificates $Certs.sslCertificates
            if(-not($CertificateAliases -icontains $WebServerCertificateAlias)){
                Write-Verbose "Importing SSL Certificate with alias $WebServerCertificateAlias"
                $ImportExistingCertFlag = $True
            }else{
                Write-Verbose "SSL Certificate with alias $WebServerCertificateAlias already exists"
                $CertForMachine = Get-SSLCertificatesForPortal -URL $PortalBaseURL -Token $token.token -Referer $Referer -WebServerCertificateAlias $WebServerCertificateAlias.ToLower() -MachineName $FQDN 
                Write-Verbose "Examine certificate from $CertificateFileLocation"
                if($CertForMachine.sha1Fingerprint -ine $NewCertThumbprint -or $ForceImportCertificate){
                    $ImportExistingCertFlag = $True
                    Write-Verbose "Force import certificate is: $ForceImportCertificate"
                    Write-Verbose "Importing exsting certificate with alias $($WebServerCertificateAlias)-temp"
                    try{
                        # Capture a lost response without retrying the upload. Reconciliation below
                        # determines whether Portal committed the temporary certificate.
                        $importError = $null
                        try {
                            Import-ExistingCertificate -URL $PortalBaseURL -Token $token.token `
                                                        -Referer $Referer -CertAlias "$($WebServerCertificateAlias)-temp" -CertificateFilePath $CertificateFileLocation `
                                                        -CertificatePassword $CertificatePassword -MachineName $FQDN `
                                                        -Version $Version -ImportCertificateChain $ImportCertificateChain -ThrowOnResponseError $true
                        }
                        catch {
                            $importError = $_
                        }
                        $token = Wait-ForPortalCertificateState -PortalBaseURL $PortalBaseURL -SiteAdministrator $SiteAdministrator `
                                    -Referer $Referer -MachineName $FQDN -CertificateAlias "$($WebServerCertificateAlias)-temp" `
                                    -ExpectedThumbprint $NewCertThumbprint -OperationError $importError -Verbose
                        $DeleteTempCert = $True
                    }catch{
                        throw "[WARNING] Error Import-ExistingCertificate:- $_"
                    }

                    try{
                        $RestartRequired = $False
                        # Switching to the temporary alias protects the currently named certificate
                        # while it is replaced. Do not delete the old alias until activation is proven.
                        $updateError = $null
                        try {
                            Update-PortalSSLCertAliasOrHSTSSetting -URL $PortalBaseURL -Token $token.token `
                                                -Referer $Referer -CertAlias "$($WebServerCertificateAlias)-temp" `
                                                -MachineName $FQDN -Verbose
                        }
                        catch {
                            $updateError = $_
                        }
                        $token = Wait-ForPortalCertificateState -PortalBaseURL $PortalBaseURL -SiteAdministrator $SiteAdministrator `
                                    -Referer $Referer -MachineName $FQDN -CertificateAlias "$($WebServerCertificateAlias)-temp" `
                                    -ExpectedThumbprint $NewCertThumbprint -RequireActiveAlias $true `
                                    -OperationError $updateError -Verbose
                    }catch{
                        throw "[WARNING] Unable to Update-PortalSSLCertificate:- $_"
                    }
                    try{
                        Write-Verbose "Deleting Portal Certificate with alias $WebServerCertificateAlias"
                        Invoke-DeletePortalCertificate -URL $PortalBaseURL -Token $token.token -Referer $Referer -WebServerCertificateAlias $WebServerCertificateAlias -MachineName $FQDN
                    }catch{
                        throw "[WARNING] Unable to Invoke-DeletePortalCertificate:- $_"
                    }
                }
            }

            if($ImportExistingCertFlag){
                Write-Verbose "Importing exsting certificate with alias $WebServerCertificateAlias"
                try{
                    # Import responses can be lost during restart; verify the resulting alias and
                    # thumbprint instead of submitting the mutation a second time.
                    $importError = $null
                    try {
                        Import-ExistingCertificate -URL $PortalBaseURL -Token $token.token `
                            -Referer $Referer -CertAlias $WebServerCertificateAlias `
                            -CertificateFilePath $CertificateFileLocation -CertificatePassword $CertificatePassword `
                            -MachineName $FQDN -Version $Version `
                            -ImportCertificateChain $ImportCertificateChain -ThrowOnResponseError $true
                    }
                    catch {
                        $importError = $_
                    }
                    $token = Wait-ForPortalCertificateState -PortalBaseURL $PortalBaseURL -SiteAdministrator $SiteAdministrator `
                                -Referer $Referer -MachineName $FQDN -CertificateAlias $WebServerCertificateAlias `
                                -ExpectedThumbprint $NewCertThumbprint -OperationError $importError -Verbose
                }catch{
                    throw "[WARNING] Error Import-ExistingCertificate:- $_"
                }
            }
            
            $Certs = Get-SSLCertificatesForPortal -URL $PortalBaseURL -Token $token.token -Referer $Referer -MachineName $FQDN
            if(($Certs.webServerCertificateAlias -ine $WebServerCertificateAlias) -or $ForceImportCertificate) {
                $RestartRequired = $False
                Write-Verbose "Updating Alias to use $WebServerCertificateAlias"
                try{
                    # Activation is complete only when both Portal configuration and the TLS endpoint
                    # expose the requested certificate.
                    $updateError = $null
                    try {
                        Update-PortalSSLCertAliasOrHSTSSetting -URL $PortalBaseURL -Token $token.token  `
                                                            -Referer $Referer -CertAlias $WebServerCertificateAlias `
                                                            -MachineName $FQDN -Verbose
                    }
                    catch {
                        $updateError = $_
                    }
                    $token = Wait-ForPortalCertificateState -PortalBaseURL $PortalBaseURL -SiteAdministrator $SiteAdministrator `
                                -Referer $Referer -MachineName $FQDN -CertificateAlias $WebServerCertificateAlias `
                                -ExpectedThumbprint $NewCertThumbprint -RequireActiveAlias $true `
                                -OperationError $updateError -Verbose

                }catch{
                    throw "[WARNING] Unable to update certificate. $_"
                }
            }else{
                Write-Verbose "SSL Certificate alias $WebServerCertificateAlias is the current one"
            }

            # Only clean up a temporary certificate uploaded during this invocation.
            if($DeleteTempCert){
                $TempCertificateAlias = "$($WebServerCertificateAlias)-temp"
                Write-Verbose "Deleting Temp Certificate with alias $TempCertificateAlias"
                Invoke-DeletePortalCertificate -URL $PortalBaseURL -Token $token.token -Referer $Referer `
                                                -WebServerCertificateAlias $TempCertificateAlias -MachineName $FQDN
            }
            
            Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "Portal" -ThrowErrors $true -Verbose
            Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "PortalSharing" -ThrowErrors $true -Verbose
        }else{
            throw "[ERROR] CertificateFileLocation '$CertificateFileLocation' is not acccesible"
	    }
    }else{
        Write-Verbose "CertificateFileLocation not specified. Skipping web server certificate configuration"
	}

    $PortalMachineCertSettings = Get-SSLCertificatesForPortal -URL $PortalBaseURL -Token $token.token -Referer $Referer -MachineName $FQDN -ErrorAction SilentlyContinue
    if($PortalMachineCertSettings.HSTSEnabled -ine $EnableHSTS){
        $RestartRequired = $False
        Write-Verbose "Enabled HSTS doesn't match the expected state $EnableHSTS"
        Update-PortalSSLCertAliasOrHSTSSetting -URL $PortalBaseURL -Token $token.token -Referer $Referer -MachineName $FQDN -HSTSEnabled $EnableHSTS -Verbose
        Wait-ForArcGISComponentRestart -BaseURL $PortalBaseURL -ComponentName "Portal" -RestartComponentName "PortalSharing" -MaxRestartWaitTimeInSeconds 300 -MaxStartupWaitTimeInSeconds 150 -Verbose
        Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "PortalSharing" -Verbose
    }else{
        Write-Verbose "Enabled HSTS matches the expected state $EnableHSTS"
    }

    if($RestartRequired){
        Write-Verbose "Restarting Portal for ArcGIS."
        Restart-ArcGISService -ComponentName "Portal" -Verbose
        Write-Verbose "Waiting 30 seconds before checking for initialization"
        Start-Sleep -Seconds 30
        Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "Portal" -Verbose
        Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "PortalSharing" -Verbose
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
        $Version,

        [parameter(Mandatory = $true)]
        [System.String]
		$PortalHostName,

		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

		[System.String]
		$CertificateFileLocation,

		[System.Management.Automation.PSCredential]
		$CertificatePassword,

        [System.String]
		$WebServerCertificateAlias,

        [System.String]
        $SslRootOrIntermediate,

        [System.Boolean]
        $EnableHSTS,

        [System.Boolean]
        $ImportCertificateChain = $true,

        [System.Boolean]
        $ForceImportCertificate = $false
	)

    $result = $True
    $FQDN = if($PortalHostName) { Get-FQDN $PortalHostName } else { Get-FQDN $env:COMPUTERNAME }
    $PortalBaseURL = Get-ArcGISComponentBaseUrl -FQDN $FQDN -ComponentName "Portal"
    $Referer = $PortalBaseURL

    Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "Portal" -Verbose
    Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "PortalSharing" -Verbose
    
    $token = $null
    try{ 
        $token = Get-PortalToken -URL $PortalBaseURL -Credential $SiteAdministrator -Referer $Referer -MaxAttempts 30
    } catch {
        Write-Verbose "[WARNING] Unable to get token:- $_."
    }
	if(-not($token.token)) {
		throw "Unable to retrieve Portal Token for '$($SiteAdministrator.UserName)'"
	}else {
        Write-Verbose "Retrieved Portal Token"
    }

    if($WebServerCertificateAlias){
        Write-Verbose "Retrieve SSL Certificate for Portal from $FQDN and checking for Alias $WebServerCertificateAlias"
        $Certs = $null
        try{
            $Certs = Get-SSLCertificatesForPortal -URL $PortalBaseURL -Token $token.token -Referer $Referer -MachineName $FQDN
            Write-Verbose "Number of certificates:- $($Certs.sslCertificates.Length) Certificates:- '$($Certs.sslCertificates -join ',')' Current Alias :- '$($Certs.webServerCertificateAlias)'"   
        }catch{
            Write-Verbose "Error in Get-SSLCertificatesForPortal:- $_"
            throw $_
        }

        $CertificateAliases = ConvertTo-PortalCertificateAliases -Certificates $Certs.sslCertificates
        if(($null -ne $Certs) -and ($CertificateAliases -iContains $WebServerCertificateAlias) -and ($Certs.webServerCertificateAlias -ieq $WebServerCertificateAlias)){
            Write-Verbose "Certificate $($Certs.webServerCertificateAlias) matches expected alias of '$WebServerCertificateAlias'"
            $CertForMachine = Get-SSLCertificatesForPortal -URL $PortalBaseURL -Token $token.token -Referer $Referer -WebServerCertificateAlias $WebServerCertificateAlias -MachineName $FQDN
            if($CertificateFileLocation -and ($null -ne $CertificatePassword)) {
                Write-Verbose "Examine certificate from $CertificateFileLocation"
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $cert.Import($CertificateFileLocation, $CertificatePassword.GetNetworkCredential().Password, 'DefaultKeySet')
                $NewCertThumbprint = $cert.Thumbprint
                Write-Verbose "Thumbprint for the supplied certificate is $NewCertThumbprint"
                if($CertForMachine.sha1Fingerprint -ine $NewCertThumbprint){
                    Write-Verbose "Thumbprint for the supplied certificate doesn't match the existing one"
                    $result = $false
                }else{
                    Write-Verbose "Thumbprint for the supplied certificate matches the existing one"
                    $result = $True
                }
            }
        }
        else {
            Write-Verbose "Certificate $($Certs.webServerCertificateAlias) does not match expected alias of '$WebServerCertificateAlias'"
            $result = $False
        }
    }

    if($result -and $null -ne $SslRootOrIntermediate){
        $MissingCerts = Get-PortalRootAndIntermdiateCertificatesToUpdate -URL $PortalBaseURL `
                                                -Token $token.token -Referer $Referer -MachineName $FQDN `
                                                -SslRootOrIntermediate $SslRootOrIntermediate -Verbose
        $result = (@($MissingCerts).Count -eq 0)
        if(-not($result)){
            Write-Verbose "One or more root and intermediate certificate needs an update."
        }
    }

    if ($result){
        $PortalMachineCertSettings = Get-SSLCertificatesForPortal -URL $PortalBaseURL -Token $token.token -Referer $Referer -MachineName $FQDN -ErrorAction SilentlyContinue
        if($PortalMachineCertSettings.HSTSEnabled -ine $EnableHSTS){
            Write-Verbose "Enabled HSTS doesn't match the expected state $EnableHSTS"
            $result = $false
        }else{
            Write-Verbose "Enabled HSTS matches the expected state $EnableHSTS"
        }
    }

    if ($ForceImportCertificate) {
        $result = $False
        Write-Verbose "Force import certificate is True"
    }

    $result
}

Export-ModuleMember -Function *-TargetResource