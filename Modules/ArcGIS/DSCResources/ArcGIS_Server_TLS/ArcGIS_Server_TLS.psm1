<#
    .SYNOPSIS
        Creates a SelfSigned Certificate or Installs a SSL Certificated Provided and Configures it with Server
    .PARAMETER Ensure
        Take the values Present or Absent. 
        - "Present" ensures the certificate is installed and configured with the Server.
        - "Absent" ensures the certificate configured with the Server is uninstalled and deleted(Not Implemented).
    .PARAMETER SiteName
        Site Name or Default Context of Server
    .PARAMETER SiteAdministrator
        A MSFT_Credential Object - Primary Site Adminstrator.
    .PARAMETER CertificateFileLocation
        Certificate Path from where to fetch the certificate to be installed.
    .PARAMETER CertificatePassword
        Sercret Certificate Password or Key.
    .PARAMETER CName
        CName with which the Certificate will be associated.
    .PARAMETER PortalEndPoint
        #Not sure - Adds a Host Mapping of Portal Machine and associates it with the certificate being Installed.
	.PARAMETER RegisterWebAdaptorForCName
        #Not Sure - Registers a Web Adaptor for the Given CName so it is accessible from this endpoint.
    .PARAMETER EnableSSL
        #Not Sure - Boolean to indicate to whether to enable SSL on Server Site
    .PARAMETER ImportOnly
        #Not Sure - Boolean to indicate to if the Certificate is be created or Imported
#>
        
function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$SiteName
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

	$null # TODO
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$SiteName,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

		[System.Management.Automation.PSCredential]
		$SiteAdministrator,
		
		[System.String]
		$CertificateFileLocation,

		[System.String]
		$CertificatePassword,

        [System.String]
		$CName,

		[System.String]
		$PortalEndPoint,

        [System.Boolean]
        $RegisterWebAdaptorForCName,

        [System.Boolean]
        $EnableSSL,

        [System.Boolean]
        $ImportOnly,

        [System.String]
        $SslRootOrIntermediate
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    if($CertificateFileLocation -and -not(Test-Path $CertificateFileLocation)){
        throw "Certificate File '$CertificateFileLocation' is not found or inaccessible"
    }
        
    $ServiceName = 'ArcGIS Server'
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir  

    $RestartRequired = $false
    if(-not(Test-HardenedSSLOnArcGISServerJVM -InstallDir $InstallDir)){
        Write-Verbose 'Hardening SSL on ArcGIS Server JVM'
        Set-HardenedSSLOnArcGISServerJVM -InstallDir $InstallDir

		$RestartRequired = $true
    }

	$FQDN = Get-FQDN $env:COMPUTERNAME
    $ServerUrl = "http://$($FQDN):6080"
    $ServerHttpsUrl = "https://localhost:6443"   
    Wait-ForUrl -Url "$($ServerUrl)/$SiteName/admin/" 
    $Referer = $ServerUrl
                           
    $token = Get-ServerToken -ServerEndPoint $ServerURL -ServerSiteName $SiteName -Credential $SiteAdministrator -Referer $Referer
    
    if($EnableSSL) 
    {
        # Get the current security configuration
        Write-Verbose 'Getting security config for site'
        $secConfig = Get-SecurityConfig -ServerURL $ServerURL -SiteName $SiteName -Token $token.token -Referer $Referer    

	    if(-not($secConfig.sslEnabled)) 
	    {
		    # Enable HTTPS on the securty config
		    Write-Verbose 'Enabling HTTPS on security config for site'
		    $enableResponse = EnableHTTPS-OnSecurityConfig -ServerURL $ServerURL -SiteName $SiteName -Token $token.token -SecurityConfig $secConfig -Referer $Referer
		  
		    # Changing the protocol will cause the web server to restart.
		    Write-Verbose "Waiting for Url '$ServerHttpsUrl/$SiteName/admin' to respond"
		    Wait-ForUrl -Url "$ServerHttpsUrl/$SiteName/admin/" -SleepTimeInSeconds 15 -MaxWaitTimeInSeconds 90 
	    }
    }

    if($CName) 
    {	
		if($PortalEndPoint -and ($PortalEndPoint -as [ipaddress])) {
			Write-Verbose "Adding Host mapping for $PortalEndPoint"
			Add-HostMapping -hostname $PortalEndPoint -ipaddress $PortalEndPoint        
		}
		elseif($CName -as [ipaddress]) {
			Write-Verbose "Adding Host mapping for $CName"
			Add-HostMapping -hostname $CName -ipaddress $CName        
		}
        
        # Get the machine name in the site
        $MachineName = $FQDN
        $allMachines = Get-Machines -ServerURL $ServerURL -SiteName $SiteName -Token $token.token -Referer $Referer
        if(-not($allMachines.machines | Where-Object { $_.machineName -ieq $MachineName })) {
            $MachineName = $env:COMPUTERNAME
            if(-not($allMachines.machines | Where-Object { $_.machineName -ieq $MachineName })){
                throw "Not able to find machine in site with either hostname $MachineName or fully qualified domain name $FQDN"
            }
        }
        # Get the machine details
	    Write-Verbose "Get Machine details for [$MachineName]"      
		$machine = Get-MachineDetails -ServerURL $ServerURL -SiteName $SiteName -Token $token.token -MachineName $MachineName -Referer $Referer

        $NewCertIssuer = $null
        if($CertificateFileLocation -and $CertificatePassword) {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $cert.Import($CertificateFileLocation,$CertificatePassword,'DefaultKeySet')
            $NewCertIssuer = $cert.Issuer
            Write-Verbose "Issuer for the supplied certificate is $NewCertIssuer"
        }
        
        $CertForMachine = Get-SSLCertificateForMachine -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer -MachineName $MachineName -SSLCertName $CName
        $ExistingCertIssuer = $CertForMachine.Issuer    
        Write-Verbose "Existing Cert Issuer $ExistingCertIssuer"  
        if(($ExistingCertIssuer -eq $null) -or ($NewCertIssuer -and ($ExistingCertIssuer -ine $NewCertIssuer))) 
        {            
            if($CertForMachine) 
            {
                Write-Verbose "Certificate with CName $CName already exists for machine $MachineName. Deleting it"
                try {
                    Delete-SSLCertForMachine -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer -MachineName $MachineName -SSLCertName $CName
                }
                catch {
                    Write-Verbose "[WARNING] Error deleting SSL Cert with CName $CName. Error:- $_"
                }
            }else{
                Write-Verbose "Certificate for CName $CName not found"
            }

		    if($CertificateFileLocation -and $CertificatePassword) {

			    # Import the Supplied Certificate  
			    Write-Verbose "Importing Supplied Cerficate with Alias $CName"
                Import-ExistingCertificate -ServerUrl $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer `
				    -MachineName $MachineName -CertAlias $CName -CertificatePassword $CertificatePassword `
				    -CertificateFilePath $CertificateFileLocation   
           				
		    }else {

                # Generate a Self signed cert 
                Write-Verbose 'Generating SelfSignedCertificate'
                Generate-SelfSignedCertificate -ServerURL $ServerURL -SiteName $SiteName -Token $token.token -MachineName $MachineName `
                                               -CertAlias $CName -CertCommonName $CName -CertOrganization $CName -Referer $Referer
		    }

            if($ImportOnly) {
                Write-Verbose "Import Only Scenario. No need to update certificate alias for Machine"                
            }else {
                # Update the SSL Cert for machine
                Write-Verbose "Updating SSL Certificate for machine [$MachineName]"
                $machine.webServerCertificateAlias = $CName
                Update-SSLCertificate -ServerURL $ServerURL -SiteName $SiteName -Token $token.token -MachineName $MachineName -MachineProperties $machine -Referer $Referer
            }
        }

        # Adding an SSL Certificate will cause the web server to restart. Wait for it to come back
		Write-Verbose "Waiting for Url '$ServerHttpsUrl/$SiteName/admin' to respond"
		Wait-ForUrl -Url "$ServerHttpsUrl/$SiteName/admin" -SleepTimeInSeconds 15 -MaxWaitTimeInSeconds 120 -HttpMethod 'GET'

        if(-not($ImportOnly)) {
            Write-Verbose "Desired CName:- $CName Check if machine is using this"
            $machineDetails = Get-MachineDetails -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer -MachineName $MachineName
            Write-Verbose "WebCertificateAlias :- $($machineDetails.webServerCertificateAlias)"
            if($CName -ine $machineDetails.webServerCertificateAlias) 
            {
                $machineDetails.webServerCertificateAlias = $CName
                Write-Verbose "Updating SSL Certificate to have Desired CName:- $CName"
                Update-SSLCertificate -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -MachineName $MachineName -Referer $Referer -MachineProperties $machineDetails 

                # Updating an SSL Certificate will cause the web server to restart.
		        Write-Verbose "Waiting for Url '$ServerURL/$SiteName/admin' to respond"
		        Wait-ForUrl -Url "$ServerHttpsUrl/$SiteName/admin" -SleepTimeInSeconds 20 -MaxWaitTimeInSeconds 150 -HttpMethod 'GET'
            }
        }else {
            Write-Verbose "Import Only Scenario. No need to update certificate alias for Machine"                
        }

		$GeoEventServiceName = 'ArcGISGeoEvent' 
		$GeoEventService = Get-Service -Name $GeoEventServiceName -ErrorAction Ignore
		if($GeoEventService.Status -ieq 'Running') {
			###
			### If the SSL Certificate is changed. Restart the GeoEvent Service so that it will pick up the new certificate 
			###
			try {			    
				Write-Verbose "Restarting Service $GeoEventServiceName"
				Stop-Service -Name $GeoEventServiceName -Force -ErrorAction Ignore
				Write-Verbose 'Stopping the service' 
				Wait-ForServiceToReachDesiredState -ServiceName $GeoEventServiceName -DesiredState 'Stopped'	
				Write-Verbose 'Stopped the service'		    
			}catch {
				Write-Verbose "[WARNING] While Stopping Service $_"
			}
			try {				
				Write-Verbose 'Starting the service'
				Start-Service -Name $GeoEventServiceName -ErrorAction Ignore       
				Wait-ForServiceToReachDesiredState -ServiceName $GeoEventServiceName -DesiredState 'Running'
				Write-Verbose "Restarted Service $GeoEventServiceName"
			}catch {
				Write-Verbose "[WARNING] While Starting Service $_"
			}
		}

        if($RegisterWebAdaptorForCName) 
        {
            $WebAdaptorsForServer = Get-WebAdaptorsConfigForServer -ServerUrl $ServerUrl -SiteName $SiteName `
                                                                -Token $token.token -Referer $Referer 
            $WebAdaptorUrl = "http://$($CName)/$SiteName"
            $WebAdaptorForHttpPort = $WebAdaptorsForServer.webAdaptors | Where-Object { ($_.httpPort -eq 80 -and $_.httpsPort -eq 443) } | ForEach-Object {
                if($_ -and $_.id -and ($_.webAdaptorURL -ine $WebAdaptorUrl)) {
                    Write-Verbose "Unregistering the current web adaptor with id $($_.id) for (http port 80, https port 443) that does not match $WebAdaptorUrl"
                    UnRegister-WebAdaptorForServer -ServerUrl $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer -WebAdaptorId $_.id
                }
            }   

            $WebAdaptorsForServer = Get-WebAdaptorsConfigForServer -ServerUrl $ServerUrl -SiteName $SiteName `
                                                                -Token $token.token -Referer $Referer
            $ExistingWebAdaptor = $WebAdaptorsForServer.webAdaptors | Where-Object { $_.machineName -ieq $CName -and $_.webAdaptorURL -ieq $WebAdaptorUrl }

            if(-not($ExistingWebAdaptor)) {
                #Register the CName as a (dummy) web adaptor for server
                Write-Verbose "Registering the CName '$CName' as a Web Adaptor with Url 'https://$($CName)/$SiteName'"
                Register-WebAdaptorForServer -ServerUrl $ServerURL -Token $token.token -Referer $Referer -SiteName $SiteName `
                                                -WebAdaptorUrl $WebAdaptorUrl  -MachineName $CName -HttpPort 80 -HttpsPort 443

                $WebAdaptorsForServer = Get-WebAdaptorsConfigForServer -ServerUrl $ServerURL -SiteName $SiteName `
                                                                    -Token $token.token -Referer $Referer
                $VerifyWebAdaptor = $WebAdaptorsForServer.webAdaptors | Where-Object { $_.machineName -ieq $CName }
                if(-not($VerifyWebAdaptor)) {
                    throw "Unable to verify the web adaptor that was just registered for $($CName)"
                }
            } else {
                Write-Verbose "Web Adaptor with CName '$CName' and Url '$WebAdaptorUrl' already exists" 
            }   

        }else {
            Write-Verbose "Not needed to register web adaptor"
        }
    }

    #RootOrIntermediateCertificate
    $certNames = Get-AllSSLCertificateCNamesForMachine -ServerHostName $FQDN -SiteName $SiteName -Token $token.token -Referer $Referer -MachineName $MachineName 
    foreach ($key in ($SslRootOrIntermediate | ConvertFrom-Json)){
        if ($certNames.certificates -icontains $key.Alias){
            Write-Verbose "Set RootOrIntermediate $($key.Alias) is in List of SSL-Certificates no Action Required"
        }else{
            Write-Verbose "Set RootOrIntermediate $($key.Alias) is NOT in List of SSL-Certificates Import-RootOrIntermediate"
            try{
                Import-RootOrIntermediateCertificate -ServerHostName $FQDN -SiteName $SiteName -Token $token.token -Referer $Referer -MachineName $MachineName -CertAlias $key.Alias -CertificateFilePath $key.Path
            }catch{
                Write-Verbose "Error in Import-RootOrIntermediateCertificate :- $_"
            }
        }
    }

    if($RestartRequired)
    {
        Write-Verbose "Restarting Service $ServiceName"
		Stop-Service -Name $ServiceName  -Force		
		Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Stopped'		
		Start-Service -Name $ServiceName         
		Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Running'
		Write-Verbose "Restarted Service $ServiceName"
    }    
    
    Write-Verbose "Waiting for Url '$ServerURL/$SiteName/admin' to respond"
	Wait-ForUrl -Url "$ServerURL/$SiteName/admin" -SleepTimeInSeconds 10 -MaxWaitTimeInSeconds 60 -HttpMethod 'GET'

    Write-Verbose 'Verifying that security config for site can be retrieved'
    $config = Get-SecurityConfig -ServerURL $ServerURL -SiteName $SiteName -Token $token.token -Referer $Referer 
    Write-Verbose "SSLEnabled:- $($config.sslEnabled)"    
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$SiteName,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

		[System.String]
		$CertificateFileLocation,

		[System.String]
		$CertificatePassword,

        [System.String]
		$CName,

		[System.String]
		$PortalEndPoint,

        [System.Boolean]
        $RegisterWebAdaptorForCName,

        [System.Boolean]
        $EnableSSL,

        [System.Boolean]
        $ImportOnly,

        [System.String]
        $SslRootOrIntermediate
	)   
   
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    if($CertificateFileLocation -and -not(Test-Path $CertificateFileLocation)){
        throw "Certificate File '$CertificateFileLocation' is not found or inaccessible"
    }

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $result = $false
       
    $FQDN = Get-FQDN $env:COMPUTERNAME
    $ServerUrl = "http://$($FQDN):6080"    
        
    Wait-ForUrl -Url "$($ServerUrl)/$SiteName/admin/" -MaxWaitTimeInSeconds 60 -HttpMethod 'GET'

    $Referer = $ServerUrl
    $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName $SiteName -Credential $SiteAdministrator -Referer $Referer 
    if(-not($token.token)){
        throw "Unable to retrieve token for Site Administrator"
    }
     
     
    if($EnableSSL) {   
        $secConfig = Get-SecurityConfig -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer    
        $result = ($secConfig -and $secConfig.sslEnabled)
        Write-Verbose "SSL Enabled:- $result"
    }

    $CertWithCNameExists = $false

    if($result -or (-not($EnableSSL)))
    {
        # SSL is enabled
        # Check the CName and issues on the SSL Certificate
        Write-Verbose "Checking Issuer and CName on Certificate"        
        $NewCertIssuer = $null
        if($CertificateFileLocation -and $CertificatePassword) {
			Write-Verbose "Examine certificate from $CertificateFileLocation"
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $cert.Import($CertificateFileLocation, $CertificatePassword, 'DefaultKeySet')
            $NewCertIssuer = $cert.Issuer
            Write-Verbose "Issuer for the supplied certificate is $NewCertIssuer"
        }
        
        $certNames = Get-AllSSLCertificateCNamesForMachine -ServerHostName $FQDN -SiteName $SiteName -Token $token.token -Referer $Referer -MachineName $FQDN 
        if($ImportOnly) 
        {
            Write-Verbose "Import Only Scenario. Check if Certificate exists"
            if($certNames.certificates -icontains $CName) {
                Write-Verbose "Certificate with $CName already exists for Machine $FQDN"
                $CertWithCNameExists = $true
            }else{
                Write-Verbose "Certificate with $CName not found for Machine $FQDN"
            }
        }
        else 
        {
            $CertForMachine = Get-SSLCertificateForMachine -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer -MachineName $FQDN -SSLCertName $CName
            $ExistingCertIssuer = $CertForMachine.Issuer  
            Write-Verbose "Existing Cert Issuer $ExistingCertIssuer"  
            if($CertForMachine -eq $null){
                Write-Verbose "Cert on machine is null"
            }
            if($NewCertIssuer -and ($ExistingCertIssuer -ine $NewCertIssuer)){
                Write-Verbose "New Cert does not match existing cert"
                Write-Verbose "Existing:- $ExistingCertIssuer New:- $NewCertIssuer"            
            }
            if(($CertForMachine -eq $null) -or ($NewCertIssuer -and ($ExistingCertIssuer -ine $NewCertIssuer))) {
                Write-Verbose "Certificate with CName $CName not found on machine '$FQDN' or the Issuer $($CertForMachine.Issuer) is different on the ArcGIS Server" 
            }
            else {
                Write-Verbose "Certificate with CName $CName and required issuer $ExistingCertIssuer already exists on machine $FQDN on the ArcGIS Server"
                if($CName){
                    Write-Verbose "Desired CName:- $CName. Checking if machine is using this"
                    $machineDetails = Get-MachineDetails -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer -MachineName $FQDN
                    if($CName -ieq $machineDetails.webServerCertificateAlias) {
                        Write-Verbose "WebServerCertificateAlias '$($machineDetails.webServerCertificateAlias)' matches Desired CName of '$CName'"
                        $CertWithCNameExists = $true
						$result = $true
                    }else {
                        Write-Verbose "WebServerCertificateAlias '$($machineDetails.webServerCertificateAlias)' does not match Desired CName of '$CName'"
                    }
                }
            }
        }
    }

	if(-not($CertWithCNameExists)) { 
		Write-Verbose "Certificate with CName does not exist as expected"
		$result = $false 
	}else {
		Write-Verbose "Certificate with CName exists as expected"
		$result = $true
	}

    if($result) {
        Write-Verbose "Checking if JVM has SSL Configuration Hardened"
        $ServiceName = 'ArcGIS Server'
        $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
        $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir  

        $IsHardened = Test-HardenedSSLOnArcGISServerJVM -InstallDir $InstallDir
		if(-not($IsHardened)) { 
			Write-Verbose 'JVM is not hardened for SSL'
			$result = $false 
		}
    }

    if($result -and $CName -and $RegisterWebAdaptorForCName) {
        Write-Verbose "Checking Web Adaptors"
        $WebAdaptorsForServer = Get-WebAdaptorsConfigForServer -ServerUrl $ServerUrl -SiteName $SiteName `
                                                                -Token $token.token -Referer $Referer 
        $ExistingWebAdaptor = $WebAdaptorsForServer.webAdaptors | Where-Object { $_.machineName -ieq $CName }
        if(-not($ExistingWebAdaptor)) {
			Write-Verbose "Web  Adaptor not found with CName $CName"
            $result = $false
        }
    }       
    
    if ($result) { # test for RootOrIntermediate Certificate-List
        $testRootorIntermediate = $true
        foreach ($key in ($SslRootOrIntermediate | ConvertFrom-Json)){
            if ($certNames.certificates -icontains $key.Alias){
                Write-Verbose "Test RootOrIntermediate $($key.Alias) is in List of SSL-Certificates"
            }else{
                $testRootorIntermediate = $false 
                Write-Verbose "Test RootOrIntermediate $($key.Alias) is NOT in List of SSL-Certificates"
                break;
            }
        }
        $result = $testRootorIntermediate
    }

	Write-Verbose "Returning $result from Test-TargetResource"
    if($Ensure -ieq 'Present') {
	       $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}

function Test-HardenedSSLOnArcGISServerJVM
{
    [CmdletBinding()]
    param(
        [string]
        $InstallDir
    )

    $hardened = $false
    $PropsFile = Join-Path $InstallDir 'framework\runtime\jre\lib\security\java.security'
    if(Test-Path $PropsFile){
        Get-Content $PropsFile| ForEach-Object {    
            if($_.StartsWith('jdk.tls.disabledAlgorithms=')){
                $splits = $_.ToString().Split('=')
                $trimmed = $splits[$splits.Length-1].Replace(' ','').Split(',')                
                if(($trimmed -icontains 'SSLV3') -and ($trimmed -icontains 'RC4') -and ($trimmed -icontains 'RC4')) {
                    Write-Verbose "ArcGIS Server JVM has all the neccessary TLS algorithms disabled"
                    $hardened = $true
                }
            }
        }
    }
    $hardened
}

function Set-HardenedSSLOnArcGISServerJVM
{
    [CmdletBinding()]
    param(
        [string]
        $InstallDir
    )

    $hardened = $false
    $PropsFile = Join-Path $InstallDir 'framework\runtime\jre\lib\security\java.security'
    if(Test-Path $PropsFile){
        $Text = @()
        $Changed = $false
        Get-Content $PropsFile| ForEach-Object {    
            if($_.ToString().StartsWith('jdk.tls.disabledAlgorithms=')){
                Write-Verbose "Updating $_ to 'jdk.tls.disabledAlgorithms=SSLv3, DHE, RC4'"
                $Text += 'jdk.tls.disabledAlgorithms=SSLv3, DHE, RC4'    
                $Changed = $true
            }
            else {
                $Text += $_
            }
        }
        if($Changed){
            Set-Content -Path $PropsFile -Value $Text
        }
    }
}

function EnableHTTPS-OnSecurityConfig 
{
    [CmdletBinding()]
    param(
        [string]$ServerURL, 
        [string]$SiteName, 
        [string]$Token, 
        [string]$Referer, 
        $SecurityConfig
    ) 

    if(-not($SecurityConfig)) {
        throw "Security Config parameter is not provided"
    }
    $UpdateSecurityConfigUrl  = $ServerURL.TrimEnd("/") + "/$SiteName/admin/security/config/update"
    $props = @{ f= 'json'; token = $Token; Protocol = 'HTTP_AND_HTTPS'; authenticationTier = $SecurityConfig.authenticationTier; allowDirectAccess = $SecurityConfig.allowDirectAccess }
    $cmdBody = To-HttpBody $props   
    $headers = @{'Content-type'='application/x-www-form-urlencoded'
                'Content-Length' = $cmdBody.Length
                'Accept' = 'text/plain'
                'Referer' = $Referer
                }

    $res = $null
    $res = Invoke-WebRequest -Uri $UpdateSecurityConfigUrl -Body $cmdBody -Method POST -Headers $headers -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing -TimeoutSec 300 
    if($res -and $res.Content) {
        Write-Verbose $res.Content
        $response = $res.Content | ConvertFrom-Json        
        Check-ResponseStatus $response -Url $UpdateSecurityConfigUrl
        $response
    }
}

function Delete-SSLCertForMachine
{
    [CmdletBinding()]
    param(
        [string]$ServerURL, 
        [string]$SiteName, 
        [string]$Token, 
        [string]$Referer, 
        [string]$MachineName, 
        [string]$SSLCertName
    )
     
    $DeleteSSlCertUrl  = $ServerURL.TrimEnd("/") + "/$SiteName/admin/machines/$MachineName/sslcertificates/$SSLCertName/delete"
    $props = @{ f= 'json'; token = $Token; }
    $cmdBody = To-HttpBody $props   
    $headers = @{'Content-type'='application/x-www-form-urlencoded'
                'Content-Length' = $cmdBody.Length
                'Accept' = 'text/plain'
                'Referer' = $Referer
                }

    $res = Invoke-WebRequest -Uri $DeleteSSlCertUrl -Body $cmdBody -Method POST -Headers $headers -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing 
    $response = $res.Content | ConvertFrom-Json
    Check-ResponseStatus $response 
    $response    
}

function Generate-SelfSignedCertificate
{
  [CmdletBinding()]
  param([string]$ServerURL, 
        [string]$SiteName, 
        [string]$Token, 
        [string]$Referer, 
        [string]$MachineName,
        [string]$CertAlias, 
        [string]$CertCommonName, 
        [string]$CertOrganization, 
        [string]$ValidityInDays = 1825
  )

  $GenerateSelfSignedCertUrl  = $ServerURL.TrimEnd("/") + "/$SiteName/admin/machines/$MachineName/sslcertificates/generate"
  $props = @{ f= 'json'; token = $Token; alias = $CertAlias; commonName = $CertCommonName; organization = $CertOrganization; validity = $ValidityInDays }
  $cmdBody = To-HttpBody $props    
  $headers = @{'Content-type'='application/x-www-form-urlencoded'
               'Content-Length' = $cmdBody.Length
               'Accept' = 'text/plain'
               'Referer' = $Referer
                }

  $res = Invoke-WebRequest -Uri $GenerateSelfSignedCertUrl -Body $cmdBody -Method POST -Headers $headers -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing -TimeoutSec 150
  $response = $res.Content | ConvertFrom-Json
  Check-ResponseStatus $response  -Url $GenerateSelfSignedCertUrl
  $response
}

function Import-ExistingCertificate
{
    [CmdletBinding()]
    param(
    [string]$ServerUrl, 
    [string]$SiteName, 
    [string]$Token, 
    [string]$Referer, 
    [string]$MachineName, 
    [string]$CertAlias, 
    [string]$CertificatePassword, 
    [string]$CertificateFilePath
    )

    $ImportCACertUrl  = $ServerURL.TrimEnd("/") + "/$SiteName/admin/machines/$MachineName/sslcertificates/importExistingServerCertificate"
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} # Allow self-signed certificates
    [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    $props = @{ f= 'json'; token = $Token; alias = $CertAlias; certPassword = $CertificatePassword  }    
    $res = Upload-File -url $ImportCACertUrl -filePath $CertificateFilePath -fileContentType 'application/x-pkcs12' -formParams $props -Referer $Referer -fileParameterName 'certFile'    
    if($res -and $res.Content) {
        $response = $res | ConvertFrom-Json
        Check-ResponseStatus $response -Url $ImportCACertUrl
    } else {
        Write-Verbose "[WARNING] Response from $ImportCACertUrl was null"
    }
}

function Import-RootOrIntermediateCertificate
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerHostName = 'localhost', 

        [System.String]
        $SiteName = 'arcgis', 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [string]
        $MachineName,

        [System.String]
        $CertAlias, 

        [System.String]
        $CertificateFilePath
    )

    $ImportCertUrl  = "https://$($ServerHostName):6443/$SiteName/admin/machines/$MachineName/sslcertificates/importRootOrIntermediate"
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} # Allow self-signed certificates
    [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    $props = @{ f= 'json'; token = $Token; alias = $CertAlias; } 
    $res = Upload-File -url $ImportCertUrl -filePath $CertificateFilePath -fileContentType 'application/x-pkcs12' -formParams $props -Referer $Referer -fileParameterName 'rootCACertificate'    
    if($res -and $res.Content) {
        $response = $res | ConvertFrom-Json
        Check-ResponseStatus $response -Url $ImportCACertUrl
    } else {
        Write-Verbose "[WARNING] Response from $ImportCertUrl was null"
    }
}


function Get-SecurityConfig 
{
    [CmdletBinding()]
    param(
        [string]$ServerURL, 
        [string]$SiteName, 
        [string]$Token, 
        [string]$Referer
    ) 

    $GetSecurityConfigUrl  = $ServerURL.TrimEnd("/") + "/$SiteName/admin/security/config/"
    $props = @{ f= 'json'; token = $Token; }
    $cmdBody = To-HttpBody $props   
    $headers = @{'Content-type'='application/x-www-form-urlencoded'
                'Content-Length' = $cmdBody.Length
                'Accept' = 'text/plain'
                'Referer' = $Referer
                }
    
    Write-Verbose "Url:- $GetSecurityConfigUrl"
    $res = $null
    try {
       $res =Invoke-WebRequest -Uri $GetSecurityConfigUrl -Body $cmdBody -Method POST -Headers $headers -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing -TimeoutSec 30 -ErrorAction Ignore
       if($res -and $res.Content) {        
            #Write-Verbose "Response:- $($res.Content)"
            $response = $res.Content | ConvertFrom-Json
            Check-ResponseStatus $response -Url $GetSecurityConfigUrl
            $response 
        }else {
            Write-Verbose "[WARNING] Response from $GetSecurityConfigUrl was null"
        }
    }
    catch{
        Write-Verbose "[EXCEPTION] ArcGIS_Server_TLS Get-SecurityConfig Error:- $_"
        $null
    }    
}

function Update-SSLCertificate 
{
    [CmdletBinding()]
    param(
        [string]$ServerURL, 
        [string]$SiteName, 
        [string]$Token, 
        [string]$MachineName, 
        [string]$Referer, 
        $MachineProperties,
        [int]$MaxAttempts = 5,
        [int]$SleepTimeInSecondsBetweenAttempts = 30
    )

    $UpdateSSLCertUrl  = $ServerURL.TrimEnd("/") + "/$SiteName/admin/machines/$MachineName/edit"
        
    $MachineProperties.psobject.properties | foreach -begin {$h=@{}} -process {$h."$($_.Name)" = $_.Value} -end {$h} # convert PSCustomObject to hashtable
    $h.JMXPort = $MachineProperties.ports.JMXPort
    $h.OpenEJBPort = $MachineProperties.ports.OpenEJBPort
    $h.NamingPort = $MachineProperties.ports.NamingPort
    $h.DerbyPort = $MachineProperties.ports.DerbyPort
    $h.ports = $null    
    $h.f = 'json'
    $h.token = $Token
    $cmdBody = To-HttpBody $h   
    $headers = @{'Content-type'='application/x-www-form-urlencoded'
                'Content-Length' = $cmdBody.Length
                'Accept' = 'text/plain'
                'Referer' = $Referer}
    
    [bool]$Done = $false
    [int]$Attempt = 1
    while(-not($Done) -and $Attempt -le $MaxAttempts) 
    {
        $AttemptStr = ''
        if($Attempt -gt 1) {
            $AttemptStr = "Attempt # $Attempt"              
        }
        Write-Verbose "Update SSLCert Name $AttemptStr"
        try {    
            $res = Invoke-WebRequest -Uri $UpdateSSLCertUrl -Body $cmdBody -Method POST -Headers $headers -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing -TimeoutSec 150 -ErrorAction Ignore
            if($res -and $res.Content) {   
                          
                #Write-Verbose $res.Content  
                $response = $res.Content | ConvertFrom-Json
                if(($response.status -ieq 'error') -and $response.messages){
                    Write-Verbose "[WARNING]:- $($response.messages -join ',')"
                }else {
                    Check-ResponseStatus $response -Url $UpdateSSLCertUrl 
                    $Done = $true
                }
                 
            }else {
                Write-Verbose "Response from $UpdateSSLCertUrl is null"
                Start-Sleep -Seconds $SleepTimeInSecondsBetweenAttempts
                $Done = $true
            }
        }
        catch
        {                
            if($Attempt -ge $MaxAttempts) {
                Write-Verbose "[WARNING] Update failed after $MaxAttempts. Last Response:- $($_)"
                #throw "Update failed after $MaxAttempts. Error:- $($_)"
            }
            Start-Sleep -Seconds $SleepTimeInSecondsBetweenAttempts
        }   
        $Attempt++
    }
    $response
}

function Get-Machines 
{
    [CmdletBinding()]
    param(
        [string]$ServerURL, 
        [string]$SiteName, 
        [string]$Token, 
        [string]$Referer
    )
    $GetMachinesUrl  = $ServerURL.TrimEnd("/") + "/$SiteName/admin/machines/"
    $props = @{ f= 'json'; token = $Token  }
    $cmdBody = To-HttpBody $props
    $headers = @{'Content-type'='application/x-www-form-urlencoded'
                'Content-Length' = $cmdBody.Length
                'Accept' = 'text/plain'
                'Referer' = $Referer
                }

    $res = Invoke-WebRequest -Uri $GetMachinesUrl -Body $cmdBody -Method POST -Headers $headers -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing -TimeoutSec 150
    $response = $res.Content | ConvertFrom-Json
    Check-ResponseStatus $response     
    $response
}

function Get-MachineDetails 
{
    [CmdletBinding()]
    param(
        [string]$ServerURL, 
        [string]$SiteName, 
        [string]$Token, 
        [string]$Referer, 
        [string]$MachineName
    )
       
    $props = @{ f= 'json'; token = $Token; }
    $cmdBody = To-HttpBody $props   
    $headers = @{'Content-type'='application/x-www-form-urlencoded'
                'Content-Length' = $cmdBody.Length
                'Accept' = 'text/plain'
                'Referer' = $Referer
                }

    $GetMachineDetailsUrl  = $ServerURL.TrimEnd("/") + "/$SiteName/admin/machines/$MachineName/"
    $res = Invoke-WebRequest -Uri $GetMachineDetailsUrl -Body $cmdBody -Method POST -Headers $headers -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing -TimeoutSec 150
    $response = $res.Content | ConvertFrom-Json
    Check-ResponseStatus $response -Url $GetMachineDetailsUrl
    $response
}

function Register-WebAdaptorForServer     
{
    [CmdletBinding()]
    param(
        [string]$ServerUrl, 
        [string]$SiteName, 
        [string]$Token, 
        [string]$Referer, 
        [string]$WebAdaptorUrl, 
        [string]$MachineName, 
        [int]$HttpPort = 80, 
        [int]$HttpsPort = 443
    )

    [string]$RegisterWebAdaptorsUrl = $ServerUrl.TrimEnd('/') + "/$SiteName/admin/system/webadaptors/register"  
    $WebParams = @{ token = $Token
                    f = 'json'
                    webAdaptorURL = $WebAdaptorUrl
                    machineName = $MachineName
                    httpPort = $HttpPort.ToString()
                    httpsPort = $HttpsPort.ToString()
                    isAdminEnabled = 'true'
                  }
    
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} # Allow self-signed certificates
    [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    $HttpBody = To-HttpBody $WebParams
    
    $Headers = @{'Content-type'='application/x-www-form-urlencoded'
                  'Content-Length' = $HttpBody.Length
                  'Accept' = 'text/plain'     
                  'Referer' = $Referer             
                }
    $res = Invoke-WebRequest -Method Post -Uri $RegisterWebAdaptorsUrl -Headers $Headers -Body $HttpBody -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing -TimeoutSec 300 
    #Write-Verbose $res.Content    
    $response = $res.Content | ConvertFrom-Json
    Check-ResponseStatus $response -Url $RegisterWebAdaptorsUrl
    $response        
}

function UnRegister-WebAdaptorForServer     
{
    [CmdletBinding()]
    param(
        [string]$ServerUrl, 
        [string]$SiteName, 
        [string]$Token, 
        [string]$Referer, 
        [string]$WebAdaptorId
    )

    [string]$UnRegisterWebAdaptorsUrl = $ServerUrl.TrimEnd('/') + "/$SiteName/admin/system/webadaptors/$WebAdaptorId/unregister"  
    $WebParams = @{ token = $Token
                    f = 'json'                    
                  }
    
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} # Allow self-signed certificates
    [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    $HttpBody = To-HttpBody $WebParams
    
    $Headers = @{'Content-type'='application/x-www-form-urlencoded'
                  'Content-Length' = $HttpBody.Length
                  'Accept' = 'text/plain'     
                  'Referer' = $Referer             
                }
    $res = Invoke-WebRequest -Method Post -Uri $UnRegisterWebAdaptorsUrl -Headers $Headers -Body $HttpBody -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing -TimeoutSec 300 
    Write-Verbose $res.Content    
    $response = $res.Content | ConvertFrom-Json
    Check-ResponseStatus $response -Url $UnRegisterWebAdaptorsUrl
    $response        
}

function Get-WebAdaptorsConfigForServer
{
    [CmdletBinding()]
    param(
        [string]$ServerUrl, 
        [string]$SiteName, 
        [string]$Token, 
        [string]$Referer
    )

    [string]$GetWebAdaptorsUrl = $ServerUrl.TrimEnd('/') + "/$SiteName/admin/system/webadaptors"  
    $WebParams = @{ token = $Token
                    f = 'json'
                  }
    
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} # Allow self-signed certificates
    [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    $HttpBody = To-HttpBody $WebParams
    
    $Headers = @{'Content-type'='application/x-www-form-urlencoded'
                  'Content-Length' = $HttpBody.Length
                  'Accept' = 'text/plain'     
                  'Referer' = $Referer             
                }
    $res = Invoke-WebRequest -Method Post -Uri $GetWebAdaptorsUrl -Headers $Headers -Body $HttpBody -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing -TimeoutSec 30     
    $response = $res.Content | ConvertFrom-Json
    Check-ResponseStatus $response -Url $GetWebAdaptorsUrl
    $response        
}

function Get-AllSSLCertificateCNamesForMachine 
{
    [CmdletBinding()]
    param(
        [string]$ServerHostName = 'localhost', 
        [string]$SiteName = 'arcgis', 
        [string]$Token, 
        [string]$Referer, 
        [string]$MachineName
    )

    Invoke-ArcGISWebRequest -Url "http://$($ServerHostName):6080/$SiteName/admin/machines/$MachineName/sslcertificates/" -HttpFormParameters @{ f= 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET' 
}

function Get-SSLCertificateForMachine 
{
    [CmdletBinding()]
    param(
        [string]$ServerURL, 
        [string]$SiteName, 
        [string]$Token, 
        [string]$Referer, 
        [string]$MachineName, 
        [string]$SSLCertName
    )
    $CertUrl  = $ServerURL.TrimEnd("/") + "/$SiteName/admin/machines/$MachineName/sslcertificates/$SSLCertName"
    $props = @{ f= 'json'; token = $Token; }
    $cmdBody = To-HttpBody $props   
    $headers = @{'Content-type'='application/x-www-form-urlencoded'
                'Content-Length' = $cmdBody.Length
                'Accept' = 'text/plain'
                'Referer' = $Referer
                }

    try 
    {
        $res = Invoke-WebRequest -Uri $CertUrl -Body $cmdBody -Method POST -Headers $headers -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing 
       ### Response is not valid JSON. Hence use Regex
        #Write-Verbose "Response $($res.Content)"
       if(-not($res.Content)){
            Write-Verbose "[WARNING] Response from $CertUrl is NULL"
            $null
        }else {
           if($res.Content.IndexOf('error') -gt -1){
                $json = $res.Content | ConvertFrom-Json
				$errMsgs = ($json.messages -join ', ')
				if($errMsgs -and ($errMsgs.IndexOf('Could not find resource or operation') -lt 0)) {
					Write-Verbose "[WARNING] Response from $CertUrl is $errMsgs"
				}
                $null 
            }else {
                $IssuerValue = $null
                $Issuer = [regex]::matches($res.Content, '"[Ii]ssuer":[ ]?\"([A-Za-z =,\.0-9\-]+)\"')
                $Issuer.Groups | %{ 
                    if($_.Value -and $_.Value.Length -gt 0){
                        $Pos = $_.Value.ToLower().IndexOf('"issuer"')
                        if($Pos -gt -1) {
                            $Str = $_.Value.Substring($Pos + '"Issuer"'.Length)
                            $Pos = $Str.IndexOf('"')
                            if($Pos -gt -1) {
                                $Str = $Str.Substring($Pos + 1)
                            }
                            $IssuerValue = $Str.TrimEnd('"')
                        }
                    }
                }
                Write-Verbose "Issuer Value:- $IssuerValue"
                $CN = if($IssuerValue) { ($IssuerValue.Split(',') | ConvertFrom-StringData).CN } else { $null }                 
                Write-Verbose "CN:- $CN"
                @{
                    Issuer = $IssuerValue
                    CName = $CN
                }
           }
       }
    }
    catch{
      # If no cert exists, an error is returned
      Write-Verbose "[WARNING] Error checking $CertUrl Error:- $_"
      $null
    }
}

Export-ModuleMember -Function *-TargetResource

