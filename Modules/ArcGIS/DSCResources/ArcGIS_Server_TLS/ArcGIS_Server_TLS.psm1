<#
    .SYNOPSIS
        Creates a SelfSigned Certificate or Installs a SSL Certificated Provided and Configures it with Server
    .PARAMETER Ensure
        Take the values Present or Absent. 
        - "Present" ensures the certificate is installed and configured with the Server.
        - "Absent" ensures the certificate configured with the Server is uninstalled and deleted(Not Implemented).
    .PARAMETER SiteName
        Site Name or Default Context of Server
    .PARAMETER ServerRole
        Site Name or Default Context of Server
    .PARAMETER SiteAdministrator
        A MSFT_Credential Object - Primary Site Administrator.
    .PARAMETER CertificateFileLocation
        Certificate Path from where to fetch the certificate to be installed.
    .PARAMETER CertificatePassword
        Sercret Certificate Password or Key.
    .PARAMETER CName
        CName with which the Certificate will be associated.
    .PARAMETER PortalEndPoint
        #Not sure - Adds a Host Mapping of Portal Machine and associates it with the certificate being Installed.
	.PARAMETER EnableSSL
        #Not Sure - Boolean to indicate to whether to enable SSL on Server Site
    .PARAMETER ImportOnly
        #Not Sure - Boolean to indicate to if the Certificate is be created or Imported
    .PARAMETER SslRootOrIntermediate
        Takes a JSON string list of all the root or intermediate certificates to import
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

		[System.Management.Automation.PSCredential]
		$CertificatePassword,

        [System.String]
		$CName,

		[System.String]
        $PortalEndPoint,
        
        [System.Boolean]
        $EnableSSL,

        [System.Boolean]
        $ImportOnly,

        [System.String]
        $SslRootOrIntermediate,
        
        [System.String]
        $ServerType
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    if($CertificateFileLocation -and -not(Test-Path $CertificateFileLocation)){
        throw "Certificate File '$CertificateFileLocation' is not found or inaccessible"
    }
    
    $ServiceName = if($ServerType -ieq "NotebookServer"){ 'ArcGIS Notebook Server' }else{'ArcGIS Server'}
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir  

    $RestartRequired = $false
    
	$FQDN = Get-FQDN $env:COMPUTERNAME
    $SitePort = if($ServerType -ieq "NotebookServer"){ 11443 }else{ 6443 }
    $ServerUrl = "https://$($FQDN):$($SitePort)"

    Wait-ForUrl -Url "$($ServerUrl)/$SiteName/admin/" 
    $Referer = $ServerUrl
                      
    $token = Get-ServerToken -ServerEndPoint $ServerURL -ServerSiteName $SiteName -Credential $SiteAdministrator -Referer $Referer
    if(-not($token.token)){
        throw "Unable to retrieve token for Site Administrator"
    }

    $Info = Invoke-ArcGISWebRequest -Url ($ServerUrl.TrimEnd('/') + "/arcgis/rest/info") -HttpFormParameters @{f = 'json';} -Referer $Referer -Verbose -HttpMethod 'GET'
    $ServerMinorVersion = "$($Info.fullVersion)".Split('.')[1]
    
    if($EnableSSL -and -not($ServerType -ieq "NotebookServer"))
    {
        # Get the current security configuration
        Write-Verbose 'Getting security config for site'
        $secConfig = Get-SecurityConfig -ServerURL $ServerURL -SiteName $SiteName -Token $token.token -Referer $Referer    

	    if(-not($secConfig.sslEnabled)) 
	    {
		    # Enable HTTPS on the securty config
		    Write-Verbose 'Enabling HTTPS on security config for site'
		    $enableResponse = Invoke-EnableHTTPSOnSecurityConfig -ServerURL $ServerURL -SiteName $SiteName -Token $token.token -SecurityConfig $secConfig -Referer $Referer
		  
		    # Changing the protocol will cause the web server to restart.
		    Write-Verbose "Waiting for Url '$ServerUrl/$SiteName/admin' to respond"
		    Wait-ForUrl -Url "$ServerUrl/$SiteName/admin/" -SleepTimeInSeconds 15 -MaxWaitTimeInSeconds 90 
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
        $NewCertThumbprint = $null
        if($CertificateFileLocation -and ($null -ne $CertificatePassword)) {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $cert.Import($CertificateFileLocation,$CertificatePassword.GetNetworkCredential().Password,'DefaultKeySet')
            $NewCertIssuer = $cert.Issuer
            $NewCertThumbprint = $cert.Thumbprint
            Write-Verbose "Issuer for the supplied certificate is $NewCertIssuer"
            Write-Verbose "Thumbprint for the supplied certificate is $NewCertThumbprint"
        }
        
        $CertForMachine = Get-SSLCertificateForMachine -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer -MachineName $MachineName -SSLCertName $CName.ToLower() -Version $ServerMinorVersion
        $ExistingCertIssuer = $CertForMachine.Issuer    
        $ExistingCertThumprint = $CertForMachine.Thumprint
        Write-Verbose "Existing Cert Issuer $ExistingCertIssuer"  
        
        if((($ServerMinorVersion -ge 6) -and ( ($null -eq $ExistingCertThumprint) -or  ($NewCertThumbprint -and ($ExistingCertThumprint -ine $NewCertThumbprint)))) -or 
                (($ServerMinorVersion -lt 6) -and (($null -eq $ExistingCertIssuer) -or ($NewCertIssuer -and ($ExistingCertIssuer -ine $NewCertIssuer))))){
            if($CertForMachine) 
            {
                Write-Verbose "Certificate with CName $CName already exists for machine $MachineName. Deleting it"
                try {
                    $res = Invoke-DeleteSSLCertForMachine -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer -MachineName $MachineName -SSLCertName $CName.ToLower()
                    Write-Verbose "Delete Certificate Operation result - $($res | ConvertTo-Json)"
                }
                catch {
                    Write-Verbose "[WARNING] Error deleting SSL Cert with CName $CName. Error:- $_"
                }
            }else{
                Write-Verbose "Certificate for CName $CName not found"
            }

		    if($CertificateFileLocation -and ($null -ne $CertificatePassword)) {

			    # Import the Supplied Certificate  
			    Write-Verbose "Importing Supplied Certificate with Alias $CName"
                Import-ExistingCertificate -ServerUrl $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer `
				    -MachineName $MachineName -CertAlias $CName -CertificatePassword $CertificatePassword `
                    -CertificateFilePath $CertificateFileLocation -ServerType $ServerType
                    
		    }else {

                # Generate a Self signed cert 
                Write-Verbose 'Generating SelfSignedCertificate'
                Invoke-GenerateSelfSignedCertificate -ServerURL $ServerURL -SiteName $SiteName -Token $token.token -MachineName $MachineName `
                                               -CertAlias $CName -CertCommonName $CName -CertOrganization $CName -Referer $Referer
		    }

            if($ImportOnly) {
                Write-Verbose "Import Only Scenario. No need to update certificate alias for Machine"                
            }else {
                # Update the SSL Cert for machine
                Write-Verbose "Updating SSL Certificate for machine [$MachineName]"
                $machine.webServerCertificateAlias = $CName
                Update-SSLCertificate -ServerURL $ServerURL -SiteName $SiteName -Token $token.token -MachineName $MachineName -MachineProperties $machine -Referer $Referer -Version $ServerMinorVersion
                Start-Sleep -Seconds 30
            }
        }
        

        # Adding an SSL Certificate will cause the web server to restart. Wait for it to come back
		Write-Verbose "Waiting for Url '$ServerUrl/$SiteName/admin' to respond"
		Wait-ForUrl -Url "$ServerUrl/$SiteName/admin" -SleepTimeInSeconds 15 -MaxWaitTimeInSeconds 150 -HttpMethod 'GET' -Verbose

        if(-not($ImportOnly)) {
            Write-Verbose "Desired CName:- $CName Check if machine is using this"
            $machineDetails = Get-MachineDetails -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer -MachineName $MachineName
            Write-Verbose "WebCertificateAlias :- $($machineDetails.webServerCertificateAlias)"
            if($CName -ine $machineDetails.webServerCertificateAlias) 
            {
                $machineDetails.webServerCertificateAlias = $CName
                Write-Verbose "Updating SSL Certificate to have Desired CName:- $CName"
                Update-SSLCertificate -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -MachineName $MachineName -Referer $Referer -MachineProperties $machineDetails -Version $ServerMinorVersion
                Start-Sleep -Seconds 30

                # Updating an SSL Certificate will cause the web server to restart.
		        Write-Verbose "Waiting for Url '$ServerURL/$SiteName/admin' to respond"
		        Wait-ForUrl -Url "$ServerUrl/$SiteName/admin" -SleepTimeInSeconds 15 -MaxWaitTimeInSeconds 150 -HttpMethod 'GET' -Verbose
            }
        }else {
            Write-Verbose "Import Only Scenario. No need to update certificate alias for Machine"                
        }

		$GeoEventServiceName = 'ArcGISGeoEvent' 
		$GeoEventService = Get-Service -Name $GeoEventServiceName -ErrorAction Ignore
		if($GeoEventService.Status -ieq 'Running') {
            $GeoEventServerHttpsUrl = "https://localhost:6143"
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
                Wait-ForUrl -Url "$GeoEventServerHttpsUrl/geoevent/rest" -SleepTimeInSeconds 20 -MaxWaitTimeInSeconds 150 -HttpMethod 'GET' -Verbose
				Write-Verbose "Restarted Service $GeoEventServiceName"
			}catch {
				Write-Verbose "[WARNING] While Starting Service $_"
			}
		}
    }

    #RootOrIntermediateCertificate
    $certNames = Get-AllSSLCertificateCNamesForMachine -ServerUrl $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer -MachineName $FQDN 
    foreach ($key in ($SslRootOrIntermediate | ConvertFrom-Json)){
        if ($certNames.certificates -icontains $key.Alias){
            Write-Verbose "Set RootOrIntermediate $($key.Alias) is in List of SSL-Certificates no Action Required"
        }else{
            Write-Verbose "Set RootOrIntermediate $($key.Alias) is NOT in List of SSL-Certificates Import-RootOrIntermediate"
            try{
                Import-RootOrIntermediateCertificate -ServerUrl $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer -MachineName $MachineName -CertAlias $key.Alias -CertificateFilePath $key.Path
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

    if(-not($ServerType -ieq "NotebookServer")){
        Write-Verbose 'Verifying that security config for site can be retrieved'
        $config = Get-SecurityConfig -ServerURL $ServerURL -SiteName $SiteName -Token $token.token -Referer $Referer 
        Write-Verbose "SSLEnabled:- $($config.sslEnabled)"    
    }
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

		[System.Management.Automation.PSCredential]
		$CertificatePassword,

        [System.String]
		$CName,

		[System.String]
		$PortalEndPoint,

        [System.Boolean]
        $EnableSSL,

        [System.Boolean]
        $ImportOnly,

        [System.String]
        $SslRootOrIntermediate,
        
        [System.String]
        $ServerType
	)   
   
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    if($CertificateFileLocation -and -not(Test-Path $CertificateFileLocation)){
        throw "Certificate File '$CertificateFileLocation' is not found or inaccessible"
    }

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $result = $false
       
    $FQDN = Get-FQDN $env:COMPUTERNAME
    $SitePort = if($ServerType -ieq "NotebookServer"){ 11443 }else{ 6443 }
    $ServerUrl = "https://$($FQDN):$($SitePort)"
        
    Wait-ForUrl -Url "$($ServerUrl)/$SiteName/admin/" -MaxWaitTimeInSeconds 60 -HttpMethod 'GET'

    $Referer = $ServerUrl
    $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName $SiteName -Credential $SiteAdministrator -Referer $Referer 
    if(-not($token.token)){
        throw "Unable to retrieve token for Site Administrator"
    }
     
    $Info = Invoke-ArcGISWebRequest -Url ($ServerUrl.TrimEnd('/') + "/arcgis/rest/info") -HttpFormParameters @{f = 'json';} -Referer $Referer -Verbose -HttpMethod 'GET'
    $ServerMinorVersion = "$($Info.fullVersion)".Split('.')[1]
    Write-Verbose $ServerMinorVersion

    if($EnableSSL -and -not($ServerType -ieq "NotebookServer")){
        $secConfig = Get-SecurityConfig -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer    
        $result = ($secConfig -and $secConfig.sslEnabled)
        Write-Verbose "SSL Enabled:- $result"
    }

    $CertWithCNameExists = $false

    if($result -or (-not($EnableSSL -and -not($ServerType -ieq "NotebookServer"))))
    {
        # SSL is enabled
        # Check the CName and issues on the SSL Certificate
        Write-Verbose "Checking Issuer and CName on Certificate"        
        $NewCertIssuer = $null
        $NewCertThumbprint = $null
        if($CertificateFileLocation -and($null -ne $CertificatePassword)) {
			Write-Verbose "Examine certificate from $CertificateFileLocation"
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $cert.Import($CertificateFileLocation, $CertificatePassword.GetNetworkCredential().Password, 'DefaultKeySet')
            $NewCertIssuer = $cert.Issuer
            $NewCertThumbprint = $cert.Thumbprint
            Write-Verbose "Issuer for the supplied certificate is $NewCertIssuer"
            Write-Verbose "Thumbprint for the supplied certificate is $NewCertThumbprint"
        }
        
        $certNames = Get-AllSSLCertificateCNamesForMachine -ServerUrl $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer -MachineName $FQDN
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
            $CertForMachine = Get-SSLCertificateForMachine -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer -MachineName $FQDN -SSLCertName $CName.ToLower() -Version $ServerMinorVersion -Verbose
            if($null -eq $CertForMachine){
                Write-Verbose "Certificate with CName $CName not found on machine '$FQDN'"
                $result = $false
            }else{
                if($ServerMinorVersion -ge 6){
                    $ExistingCertThumprint = $CertForMachine.Thumbprint
                    Write-Verbose "Existing Cert Thumprint $ExistingCertThumprint"  
                    if($NewCertThumbprint -and ($ExistingCertThumprint -ine $NewCertThumbprint)){
                        Write-Verbose "New Cert does not match existing cert"
                        Write-Verbose "Existing:- $ExistingCertThumprint New:- $NewCertThumbprint"       
                        $result = $false     
                    }else{
                        $CheckForCName = $True
                    }
                }else{
                    $ExistingCertIssuer = $CertForMachine.Issuer  
                    Write-Verbose "Existing Cert Issuer $ExistingCertIssuer"  
                    if($NewCertIssuer -and ($ExistingCertIssuer -ine $NewCertIssuer)){
                        Write-Verbose "New Cert does not match existing cert"
                        Write-Verbose "Existing:- $ExistingCertIssuer New:- $NewCertIssuer"       
                        $result = $false     
                    }else{
                        $CheckForCName = $True
                    }
                }
            }
        }
    }
   
    if($CheckForCName -and $CName){
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

	if(-not($CertWithCNameExists)) { 
		Write-Verbose "Certificate with CName does not exist as expected"
		$result = $false 
	}else {
		Write-Verbose "Certificate with CName exists as expected"
		$result = $true
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

function Invoke-EnableHTTPSOnSecurityConfig
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerURL, 

        [System.String]
        $SiteName, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        $SecurityConfig
    ) 

    if(-not($SecurityConfig)) {
        throw "Security Config parameter is not provided"
    }

    $UpdateSecurityConfigUrl  = $ServerURL.TrimEnd("/") + "/$SiteName/admin/security/config/update"
    $props = @{ f= 'json'; token = $Token; Protocol = 'HTTP_AND_HTTPS'; authenticationTier = $SecurityConfig.authenticationTier; allowDirectAccess = $SecurityConfig.allowDirectAccess;  cipherSuites = $SecurityConfig.cipherSuites }
    Invoke-ArcGISWebRequest -Url $UpdateSecurityConfigUrl -HttpFormParameters $props -Referer $Referer -TimeOutSec 300
}

function Invoke-DeleteSSLCertForMachine
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerURL, 

        [System.String]
        $SiteName, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $MachineName, 

        [System.String]
        $SSLCertName
    )
     
    $DeleteSSlCertUrl  = $ServerURL.TrimEnd("/") + "/$SiteName/admin/machines/$MachineName/sslCertificates/$SSLCertName/delete"
    Invoke-ArcGISWebRequest -Url $DeleteSSlCertUrl -HttpFormParameters @{ f= 'json'; token = $Token; } -Referer $Referer -HttpMethod 'POST' -TimeoutSec 150
}

function Invoke-GenerateSelfSignedCertificate
{
    [CmdletBinding()]
    param([string]$ServerURL, 
        [System.String]
        $SiteName, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $MachineName,

        [System.String]
        $CertAlias, 

        [System.String]
        $CertCommonName, 

        [System.String]
        $CertOrganization, 

        [System.String]
        $ValidityInDays = 1825

    )

    $GenerateSelfSignedCertUrl  = $ServerURL.TrimEnd("/") + "/$SiteName/admin/machines/$MachineName/sslCertificates/generate"
    $props = @{ f= 'json'; token = $Token; alias = $CertAlias; commonName = $CertCommonName; organization = $CertOrganization; validity = $ValidityInDays } 
    Invoke-ArcGISWebRequest -Url $GenerateSelfSignedCertUrl -HttpFormParameters $props -Referer $Referer -TimeOutSec 150
}

function Import-ExistingCertificate
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerUrl, 
        
        [System.String]
        $SiteName, 
        
        [System.String]
        $Token, 
        
        [System.String]
        $Referer, 
        
        [System.String]
        $MachineName, 
        
        [System.String]
        $CertAlias, 
        
        [System.Management.Automation.PSCredential]
        $CertificatePassword, 
        
        [System.String]
        $CertificateFilePath,
        
        [System.String]
        $ServerType
    )

    $ImportCACertUrl  = $ServerURL.TrimEnd("/") + "/$SiteName/admin/machines/$MachineName/sslCertificates/importExistingServerCertificate"
    $props = @{ f= 'json';  alias = $CertAlias; certPassword = $CertificatePassword.GetNetworkCredential().Password  }    

    $Header = @{}
    if($ServerType -ne "NotebookServer"){
        $props["token"] = $Token;
    }else{
        $Header["X-Esri-Authorization"] = "Bearer $Token"
    }

    $res = Invoke-UploadFile -url $ImportCACertUrl -filePath $CertificateFilePath -fileContentType 'application/x-pkcs12' -formParams $props -Referer $Referer -fileParameterName 'certFile' -httpHeaders $Header -Verbose 
    if($res -and $res.Content) {
        $response = $res | ConvertFrom-Json
        Confirm-ResponseStatus $response -Url $ImportCACertUrl
    } else {
        Write-Verbose "[WARNING] Response from $ImportCACertUrl was $res"
    }
}

function Import-RootOrIntermediateCertificate
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerUrl,

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
    
    $ImportCertUrl  = $ServerURL.TrimEnd("/") + "/$SiteName/admin/machines/$MachineName/sslCertificates/importRootOrIntermediate"
    $props = @{ f= 'json'; token = $Token; alias = $CertAlias; } 
    $res = Invoke-UploadFile -url $ImportCertUrl -filePath $CertificateFilePath -fileContentType 'application/x-pkcs12' -formParams $props -Referer $Referer -fileParameterName 'rootCACertificate'    
    if($res -and $res.Content) {
        $response = $res | ConvertFrom-Json
        Confirm-ResponseStatus $response -Url $ImportCACertUrl
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
    Write-Verbose "Url:- $GetSecurityConfigUrl"
    Invoke-ArcGISWebRequest -Url $GetSecurityConfigUrl -HttpFormParameters @{ f= 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET' -TimeOutSec 30
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
        [int]$SleepTimeInSecondsBetweenAttempts = 30,
        [System.Int32] $Version
    )

    $UpdateSSLCertUrl  = $ServerURL.TrimEnd("/") + "/$SiteName/admin/machines/$MachineName/edit"
    $MachineProperties.psobject.properties | Foreach-Object -begin {$h=@{}} -process {$h."$($_.Name)" = $_.Value} -end {$h} # convert PSCustomObject to hashtable
    if($Version -lt 7){
        $h.JMXPort = $MachineProperties.ports.JMXPort
        $h.OpenEJBPort = $MachineProperties.ports.OpenEJBPort
        $h.NamingPort = $MachineProperties.ports.NamingPort
        $h.DerbyPort = $MachineProperties.ports.DerbyPort
    }
    $h.ports = $null    
    $h.f = 'json'
    $h.token = $Token
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
            $response = Invoke-ArcGISWebRequest -Url $UpdateSSLCertUrl -HttpFormParameters $h -Referer $Referer -TimeOutSec 150
            if($response.status -ieq 'success'){
                Write-Verbose "Update Web Server SSL Certificate Successful! Server will Restart now."
                $Done = $true
            }else{
                if(($response.status -ieq 'error') -and $response.messages){
                    Write-Verbose "[WARNING]:- $($response.messages -join ',')"
                    Start-Sleep -Seconds $SleepTimeInSecondsBetweenAttempts
                }
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
        [string]$SiteName = 'arcgis', 
        [string]$Token, 
        [string]$Referer
    )
    $GetMachinesUrl  = $ServerURL.TrimEnd("/") + "/$SiteName/admin/machines/"
    Invoke-ArcGISWebRequest -Url $GetMachinesUrl -HttpFormParameters @{ f= 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET' -TimeoutSec 150
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
    $GetMachineDetailsUrl  = $ServerURL.TrimEnd("/") + "/$SiteName/admin/machines/$MachineName/"
    Invoke-ArcGISWebRequest -Url $GetMachineDetailsUrl -HttpFormParameters @{ f= 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET' -TimeoutSec 150
}

function Get-AllSSLCertificateCNamesForMachine 
{
    [CmdletBinding()]
    param(
        [string]$ServerURL, 
        [string]$SiteName = 'arcgis', 
        [string]$Token, 
        [string]$Referer, 
        [string]$MachineName
    )
    $certURL = $ServerURL.TrimEnd("/") + "/$SiteName/admin/machines/$MachineName/sslCertificates/"
    Invoke-ArcGISWebRequest -Url $certURL -HttpFormParameters @{ f= 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET' 
}

function Get-SSLCertificateForMachine 
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [string]$ServerURL, 
        [string]$SiteName, 
        [string]$Token, 
        [string]$Referer, 
        [string]$MachineName, 
        [string]$SSLCertName,
        [System.Int32] $Version
    )
    $CertUrl  = $ServerURL.TrimEnd("/") + "/$SiteName/admin/machines/$MachineName/sslCertificates/$SSLCertName"
    try{
        if($Version -ge 6){
            $json = Invoke-ArcGISWebRequest -Url $CertUrl -HttpFormParameters @{ f= 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET'  
            if($json.error){
                $errMsgs = ($json.error.messages -join ', ')
                Write-Verbose "[WARNING] Response from $CertUrl is $errMsgs"
                $null
            }elseif($json.status -and $json.status -ieq "error"){
                $errMsgs = ($json.messages -join ', ')
                Write-Verbose "[WARNING] Response from $CertUrl is $errMsgs"
                $null
            }else{
                $issuer = $json.issuer
                $CN = if($issuer) { ($issuer.Split(',') | ConvertFrom-StringData).CN } else { $null }
                @{
                     Issuer = $issuer
                     CName = $CN
                     Thumbprint = $json.sha1Fingerprint
                }
            }
        }else{
            $props = @{ f= 'json'; token = $Token; }
            $cmdBody = ConvertTo-HttpBody $props   
            $headers = @{'Content-type'='application/x-www-form-urlencoded'
                        'Content-Length' = $cmdBody.Length
                        'Accept' = 'text/plain'
                        'Referer' = $Referer
                        }
            #Can't use ArcGIS WebRequest Method as the output might not be a JSON
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
                    $Issuer.Groups | ForEach-Object{ 
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
                        Thumbprint = $null
                    }
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

