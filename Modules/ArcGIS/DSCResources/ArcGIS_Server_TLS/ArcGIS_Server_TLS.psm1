$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

<#
    .SYNOPSIS
        Creates a SelfSigned Certificate or Installs a SSL Certificated Provided and Configures it with Server
    .PARAMETER ServerHostName
        Optional Host Name or IP of the Machine on which the Server has been installed and is to be configured.
    .PARAMETER ServerRole
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

	$null # TODO
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
        $EnableHSTS
	)

    if($CertificateFileLocation -and -not(Test-Path $CertificateFileLocation)){
        throw "Certificate File '$CertificateFileLocation' is not found or inaccessible"
    }
    
    $ServiceName = "ArcGIS Server"
    $SitePort = 6443
    if($ServerType -ieq "NotebookServer"){
        $ServiceName = "ArcGIS Notebook Server"
        $SitePort = 11443
    }elseif($ServerType -ieq "MissionServer"){
        $ServiceName = "ArcGIS Mission Server"
        $SitePort = 20443
    }
    
    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
	$ServerUrl = "https://$($FQDN):$($SitePort)"
    
    Wait-ForUrl -Url "$($ServerUrl)/arcgis/admin/" 
    Wait-ForUrl -Url "$($ServerUrl)/arcgis/rest/info/healthCheck?f=json" -HttpMethod 'GET'
    $Referer = $ServerUrl
                      
    $token = Get-ServerToken -ServerEndPoint $ServerURL -Credential $SiteAdministrator -Referer $Referer
    if(-not($token.token)){
        throw "Unable to retrieve token for Site Administrator"
    }

    # Get the current security configuration
    if($ServerType -ine "NotebookServer" -or $ServerType -ine "MissionServer"){
        $UpdateSecurityConfig = $False
        Write-Verbose 'Getting security config for site'
        $secConfig = Get-SecurityConfig -ServerURL $ServerURL -Token $token.token -Referer $Referer
        
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
            Update-SecurityConfig -ServerURL $ServerURL -Token $token.token -SecurityConfig $secConfig `
                                        -Referer $Referer -EnableHTTPSOnly $EnableHTTPSOnly -EnableHSTS $EnableHSTS -Verbose
            # Changes will cause the web server to restart.
            Write-Verbose "Waiting 30 seconds before checking"
            Start-Sleep -Seconds 30

            Write-Verbose "Waiting for Url '$($ServerUrl)/arcgis/admin' to respond"
            Wait-ForUrl -Url "$($ServerUrl)/arcgis/admin/" -SleepTimeInSeconds 15 -MaxWaitTimeInSeconds 90 
            Wait-ForUrl -Url "$($ServerUrl)/arcgis/rest/info/healthCheck?f=json" -HttpMethod 'GET'
        }
    }

    $MachineName = $FQDN
    $AllMachines = Get-Machines -ServerURL $ServerURL -Token $token.token -Referer $Referer
    if(-not($AllMachines.machines | Where-Object { $_.machineName -ieq $MachineName })) {
        $MachineName = $env:COMPUTERNAME
        if(-not($AllMachines.machines | Where-Object { $_.machineName -ieq $MachineName })){
            throw "Not able to find machine in site with either hostname $MachineName or fully qualified domain name $FQDN"
        }
    }

    if($CertificateFileLocation){
        if(-not(Test-Path $CertificateFileLocation)){
            throw "Certificate File '$CertificateFileLocation' is not found"
        }
        if($WebServerCertificateAlias -as [ipaddress]) {
			Write-Verbose "Adding Host mapping for $WebServerCertificateAlias"
			Add-HostMapping -hostname $WebServerCertificateAlias -ipaddress $WebServerCertificateAlias        
		}
        
        $DeleteTempCert = $False
        $ImportCert = $False
        $UpdateWebAlias = $False
        $CertForMachine = Get-SSLCertificateForMachine -ServerURL $ServerUrl -Token $token.token -Referer $Referer -MachineName $MachineName -SSLCertName $WebServerCertificateAlias.ToLower()
        if($null -ne $CertForMachine){ # Certificate with CName Found
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
            Write-Verbose "Existing Cert Issuer $ExistingCertIssuer with Thumbprint $ExistingCertThumbprint"
            $machineDetails = Get-MachineDetails -ServerURL $ServerUrl -Token $token.token -Referer $Referer -MachineName $MachineName
            if($ExistingCertThumbprint -ine $NewCertThumbprint){ #Certificate Thumbprint doesn't match
                if($WebServerCertificateAlias -ieq $machineDetails.webServerCertificateAlias){
                    $DeleteTempCert = $True
                    #Upload Temp Cert
                    Write-Verbose "Importing Supplied Certificate with Alias $($WebServerCertificateAlias)-temp"
                    Import-ExistingCertificate -ServerUrl $ServerUrl -Token $token.token -Referer $Referer `
                        -MachineName $MachineName -CertAlias "$($WebServerCertificateAlias)-temp" -CertificatePassword $CertificatePassword `
                        -CertificateFilePath $CertificateFileLocation -ServerType $ServerType

                    #Update Web Alias to Temp Cert
                    Write-Verbose "Updating to temp SSL Certificate for machine [$MachineName]"
                    $machine = Get-MachineDetails -ServerURL $ServerUrl -Token $token.token -Referer $Referer -MachineName $MachineName
                    $machine.webServerCertificateAlias = "$($WebServerCertificateAlias)-temp"
                    Update-SSLCertificate -ServerURL $ServerURL -Token $token.token -MachineName $MachineName -MachineProperties $machine -Referer $Referer
                    Start-Sleep -Seconds 30
                    Write-Verbose "Waiting for Url '$ServerUrl/arcgis/admin' to respond"
                    Wait-ForUrl -Url "$ServerUrl/arcgis/admin" -SleepTimeInSeconds 15 -MaxWaitTimeInSeconds 150 -HttpMethod 'GET' -Verbose
                    Wait-ForUrl -Url "$($ServerUrl)/arcgis/rest/info/healthCheck?f=json" -HttpMethod 'GET'
                }

                #Delete Certificate
                Write-Verbose "Certificate with alias $WebServerCertificateAlias already exists for machine $MachineName. Deleting it"
                try {
                    $res = Invoke-DeleteSSLCertForMachine -ServerURL $ServerUrl -Token $token.token -Referer $Referer -MachineName $MachineName -SSLCertName $WebServerCertificateAlias.ToLower()
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
            Wait-ForUrl -Url "$ServerUrl/arcgis/admin" -SleepTimeInSeconds 15 -MaxWaitTimeInSeconds 150 -HttpMethod 'GET' -Verbose
            Wait-ForUrl -Url "$($ServerUrl)/arcgis/rest/info/healthCheck?f=json" -HttpMethod 'GET'

            # Import the Supplied Certificate  
            Write-Verbose "Importing Supplied Certificate with Alias $WebServerCertificateAlias"
            Import-ExistingCertificate -ServerUrl $ServerUrl -Token $token.token -Referer $Referer `
                    -MachineName $MachineName -CertAlias $WebServerCertificateAlias -CertificatePassword $CertificatePassword `
                    -CertificateFilePath $CertificateFileLocation -ServerType $ServerType
        }

        if($UpdateWebAlias){
            $machine = Get-MachineDetails -ServerURL $ServerURL -Token $token.token -MachineName $MachineName -Referer $Referer
            # Update the SSL Cert for machine
            Write-Verbose "Updating SSL Certificate for machine [$MachineName]"
            $machine.webServerCertificateAlias = $WebServerCertificateAlias
            Update-SSLCertificate -ServerURL $ServerURL -Token $token.token -MachineName $MachineName -MachineProperties $machine -Referer $Referer
            Start-Sleep -Seconds 30
            Write-Verbose "Waiting for Url '$ServerUrl/arcgis/admin' to respond"
            Wait-ForUrl -Url "$ServerUrl/arcgis/admin" -SleepTimeInSeconds 15 -MaxWaitTimeInSeconds 150 -HttpMethod 'GET' -Verbose
            Wait-ForUrl -Url "$($ServerUrl)/arcgis/rest/info/healthCheck?f=json" -HttpMethod 'GET'

            # Restart Geoevent
            if($ServerType -ine "NotebookServer" -or $ServerType -ine "MissionServer"){ #TODO - This will cause issues in Azure, where we have Geoevent and WFM running.
                ### If the SSL Certificate is changed. Restart the GeoEvent Service so that it will pick up the new certificate 
                $GeoEventServiceName = 'ArcGISGeoEvent' 
                $GeoEventService = Get-Service -Name $GeoEventServiceName -ErrorAction Ignore
                if($GeoEventService.Status -ieq 'Running') {
                    $GeoEventServerHttpsUrl = "https://localhost:6143"
                    Restart-ArcGISService -ServiceName $GeoEventServiceName -Verbose
                    Write-Verbose "Waiting for Url '$GeoEventServerHttpsUrl/geoevent/rest' to respond"
                    Wait-ForUrl -Url "$GeoEventServerHttpsUrl/geoevent/rest" -SleepTimeInSeconds 20 -MaxWaitTimeInSeconds 150 -HttpMethod 'GET' -Verbose
                    Write-Verbose "Restarted Service $GeoEventServiceName"
                }
            }
        }
        
        if($DeleteTempCert){ #Delete Temp Cert
            try {
                Write-Verbose "Deleting Temp Certificate with alias $($WebServerCertificateAlias)-temp"
                $res = Invoke-DeleteSSLCertForMachine -ServerURL $ServerUrl -Token $token.token -Referer $Referer -MachineName $MachineName -SSLCertName "$($WebServerCertificateAlias)-temp".ToLower()
                Write-Verbose "Delete Temp Certificate Operation result - $($res | ConvertTo-Json)"
            }
            catch {
                Write-Verbose "[WARNING] Error deleting Temp SSL Cert with alias $($WebServerCertificateAlias)-temp. Error:- $_"
            }
        }
    }else{
        Write-Verbose "CertificateFileLocation not specified. Skipping web server certificate configuration"
    }

    if($null -ne $SslRootOrIntermediate){ #RootOrIntermediateCertificate
        $RestartRequired = $false
        $Certs = Get-AllSSLCertificateForMachine -ServerUrl $ServerUrl -Token $token.token -Referer $Referer -MachineName $MachineName 
        foreach ($key in ($SslRootOrIntermediate | ConvertFrom-Json)){
            $UploadRootOrIntermediateCertificate = $False
            if ($Certs.certificates -icontains $key.Alias){
                Write-Verbose "RootOrIntermediate $($key.Alias) is in List of SSL-Certificates."
                $RootOrIntermediateCertForMachine = Get-SSLCertificateForMachine -ServerURL $ServerUrl -Token $token.token -Referer $Referer -MachineName $MachineName -SSLCertName $key.Alias -Verbose
                Write-Verbose "Existing Cert Issuer $($RootOrIntermediateCertForMachine.Issuer) and Thumbprint $($RootOrIntermediateCertForMachine.Thumbprint)"
                $NewCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $key.Path
                Write-Verbose "Issuer and Thumprint for the supplied certificate is $($NewCert.Issuer) and $($NewCert.Thumbprint) respectively."
                if($RootOrIntermediateCertForMachine.Thumbprint -ine $NewCert.Thumbprint){
                    Write-Verbose "Thumbprints for Certificate with Alias $($key.Alias) doesn't match that of existing cetificate. Deleting existing certificate and uploading a new one"
                    $UploadRootOrIntermediateCertificate = $True
                    $res = Invoke-DeleteSSLCertForMachine -ServerURL $ServerUrl -Token $token.token -Referer $Referer -MachineName $MachineName -SSLCertName $key.Alias
                    Write-Verbose "Delete existing Certificate Operation result - $($res | ConvertTo-Json)"
                }else{
                    Write-Verbose "Thumbprints for Certificate with Alias $($key.Alias) match that of existing cetificate."
                }
            }else{
                Write-Verbose "RootOrIntermediate $($key.Alias) is NOT in List of SSL-Certificates Import-RootOrIntermediate"
                $UploadRootOrIntermediateCertificate = $True
            }

            if($UploadRootOrIntermediateCertificate){
                try{
                    Import-RootOrIntermediateCertificate -ServerUrl $ServerUrl -Token $token.token -Referer $Referer -MachineName $MachineName -CertAlias $key.Alias -CertificateFilePath $key.Path
                    if(-not($RestartRequired)){
                        $RestartRequired = $True
                    }
                }catch{
                    Write-Verbose "Error in Import-RootOrIntermediateCertificate :- $_"
                }
            }
        }

        if($RestartRequired)
        {
            Write-Verbose "Server Root and intermediate certificates were updated. Restarting Server."
            Restart-ArcGISService -ServiceName $ServiceName -Verbose
            Write-Verbose "Waiting 30 seconds before checking for intitialization"
            Start-Sleep -Seconds 30
            Write-Verbose "Waiting for Url '$ServerURL/arcgis/admin' to respond"
            Wait-ForUrl -Url "$ServerURL/arcgis/admin" -SleepTimeInSeconds 10 -MaxWaitTimeInSeconds 60 -HttpMethod 'GET'
            Wait-ForUrl -Url "$($ServerUrl)/arcgis/rest/info/healthCheck?f=json" -HttpMethod 'GET'
        }
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
        $EnableHSTS
	)

    if($CertificateFileLocation -and -not(Test-Path $CertificateFileLocation)){
        throw "Certificate File '$CertificateFileLocation' is not found or inaccessible"
    }

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $result = $True
       
    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    $SitePort = 6443
    if($ServerType -ieq "NotebookServer"){
        $SitePort = 11443
    }elseif($ServerType -ieq "MissionServer"){
        $SitePort = 20443
    }
    $ServerUrl = "https://$($FQDN):$($SitePort)"
        
    Wait-ForUrl -Url "$($ServerUrl)/arcgis/admin/" -MaxWaitTimeInSeconds 60 -HttpMethod 'GET'
    Wait-ForUrl -Url "$($ServerUrl)/arcgis/rest/info/healthCheck?f=json" -HttpMethod 'GET'

    $Referer = $ServerUrl
    $token = Get-ServerToken -ServerEndPoint $ServerUrl -Credential $SiteAdministrator -Referer $Referer 
    if(-not($token.token)){
        throw "Unable to retrieve token for Site Administrator"
    }

    if($ServerType -ine "NotebookServer" -or $ServerType -ine "MissionServer"){
        $secConfig = Get-SecurityConfig -ServerURL $ServerURL -Token $token.token -Referer $Referer
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
    $AllMachines = Get-Machines -ServerURL $ServerURL -Token $token.token -Referer $Referer
    if(-not($AllMachines.machines | Where-Object { $_.machineName -ieq $MachineName })) {
        $MachineName = $env:COMPUTERNAME
        if(-not($AllMachines.machines | Where-Object { $_.machineName -ieq $MachineName })){
            throw "Not able to find machine in site with either hostname $MachineName or fully qualified domain name $FQDN"
        }
    }

    if($CertificateFileLocation){
        if(-not(Test-Path $CertificateFileLocation)){
            throw "Certificate File '$CertificateFileLocation' is not found"
        }
        
        $CertForMachine = Get-SSLCertificateForMachine -ServerURL $ServerUrl -Token $token.token -Referer $Referer -MachineName $MachineName -SSLCertName $WebServerCertificateAlias.ToLower() -Verbose
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
            $machineDetails = Get-MachineDetails -ServerURL $ServerUrl -Token $token.token -Referer $Referer -MachineName $MachineName
            if($ExistingCertThumbprint -ine $NewCertThumbprint){ #Certificate Thumbprint doesn't match
                Write-Verbose "Thumbprints for Certificate with Alias $WebServerCertificateAlias doesn't match that of existing cetificate."
                if($WebServerCertificateAlias -ieq $machineDetails.webServerCertificateAlias){
                    Write-Verbose "Certificate with alias $WebServerCertificateAlias matches the WebServerCertificateAlias."
                }
                $result = $False

            }else{ # Thumbprint matches
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

    if($result -and $null -ne $SslRootOrIntermediate){ #Check RootOrIntermediateCertificate
        $Certs = Get-AllSSLCertificateForMachine -ServerUrl $ServerUrl -Token $token.token -Referer $Referer -MachineName $MachineName 
        foreach ($key in ($SslRootOrIntermediate | ConvertFrom-Json)){
            if ($Certs.certificates -icontains $key.Alias){
                Write-Verbose "RootOrIntermediate $($key.Alias) is in List of SSL-Certificates. Validating if thumbprint matches the existing certificate"
                $RootOrIntermediateCertForMachine = Get-SSLCertificateForMachine -ServerURL $ServerUrl -Token $token.token -Referer $Referer -MachineName $MachineName -SSLCertName $key.Alias -Verbose
                Write-Verbose "Existing Cert Issuer $($RootOrIntermediateCertForMachine.Issuer) and Thumbprint $($RootOrIntermediateCertForMachine.Thumbprint)"
                $NewCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $key.Path
                Write-Verbose "Issuer and Thumprint for the supplied certificate is $($NewCert.Issuer) and $($NewCert.Thumbprint) respectively."
                if($RootOrIntermediateCertForMachine.Thumbprint -ine $NewCert.Thumbprint){
                    Write-Verbose "Thumbprints for Certificate with Alias $($key.Alias) doesn't match that of existing cetificate."
                    $result = $False
                }else{
                    Write-Verbose "Thumbprints for Certificate with Alias $($key.Alias) match that of existing cetificate."
                }
            }else{
                Write-Verbose "RootOrIntermediate $($key.Alias) is NOT in List of SSL-Certificates"
                $result = $False
            }
        }
    }

	Write-Verbose "Returning $result from Test-TargetResource"
    $result
}

function Invoke-DeleteSSLCertForMachine
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerURL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $MachineName, 

        [System.String]
        $SSLCertName
    )
     
    $DeleteSSlCertUrl  = $ServerURL.TrimEnd("/") + "/arcgis/admin/machines/$MachineName/sslCertificates/$SSLCertName/delete"
    Invoke-ArcGISWebRequest -Url $DeleteSSlCertUrl -HttpFormParameters @{ f= 'json'; token = $Token; } -Referer $Referer -HttpMethod 'POST' -TimeoutSec 150
}

function Invoke-GenerateSelfSignedCertificate
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerURL,

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

    $GenerateSelfSignedCertUrl  = $ServerURL.TrimEnd("/") + "/arcgis/admin/machines/$MachineName/sslCertificates/generate"
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

    $ImportCACertUrl  = $ServerURL.TrimEnd("/") + "/arcgis/admin/machines/$MachineName/sslCertificates/importExistingServerCertificate"
    $props = @{ f= 'json';  alias = $CertAlias; certPassword = $CertificatePassword.GetNetworkCredential().Password  }    

    $Header = @{}
    if(-not($ServerType -ieq "NotebookServer" -or $ServerType -ieq "MissionServer")){
        $props["token"] = $Token;
    }else{
        $Header["X-Esri-Authorization"] = "Bearer $Token"
    }

    $res = Invoke-UploadFile -url $ImportCACertUrl -filePath $CertificateFilePath -fileContentType 'application/x-pkcs12' -formParams $props -Referer $Referer -fileParameterName 'certFile' -httpHeaders $Header -Verbose 
    if($res) {
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
    
    $ImportCertUrl  = $ServerURL.TrimEnd("/") + "/arcgis/admin/machines/$MachineName/sslCertificates/importRootOrIntermediate"
    $props = @{ f= 'json'; token = $Token; alias = $CertAlias; } 
    $res = Invoke-UploadFile -url $ImportCertUrl -filePath $CertificateFilePath -fileContentType 'application/x-pkcs12' -formParams $props -Referer $Referer -fileParameterName 'rootCACertificate'    
    if($res) {
        $response = $res | ConvertFrom-Json
        Confirm-ResponseStatus $response -Url $ImportCACertUrl
    } else {
        Write-Verbose "[WARNING] Response from $ImportCertUrl was null"
    }
}

function Update-SSLCertificate 
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerURL, 
        
        [System.String]
        $Token, 
        
        [System.String]
        $MachineName,

        [System.String]
        $Referer, 
        
        $MachineProperties,
        
        [System.Int32]
        $MaxAttempts = 5,

        [System.Int32]
        $SleepTimeInSecondsBetweenAttempts = 30
    )

    $Info = Invoke-ArcGISWebRequest -Url ($ServerUrl.TrimEnd('/') + "/arcgis/rest/info") -HttpFormParameters @{f = 'json';} -Referer $Referer -Verbose -HttpMethod 'GET'
    $VersionArray = "$($Info.fullVersion)".Split('.')
    $VersionIsLessThan107 = ($VersionArray[0] -eq 10 -and $VersionArray[1] -lt 7)


    $UpdateSSLCertUrl  = $ServerURL.TrimEnd("/") + "/arcgis/admin/machines/$MachineName/edit"
    $MachineProperties.psobject.properties | Foreach-Object -begin {$h=@{}} -process {$h."$($_.Name)" = $_.Value} -end {$h} # convert PSCustomObject to hashtable
    if($VersionIsLessThan107){
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
        [System.String]
        $ServerURL, 
        
        [System.String]
        $Token, 
        
        [System.String]
        $Referer
    )
    $GetMachinesUrl  = $ServerURL.TrimEnd("/") + "/arcgis/admin/machines/"
    Invoke-ArcGISWebRequest -Url $GetMachinesUrl -HttpFormParameters @{ f= 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET' -TimeoutSec 150
}

function Get-MachineDetails 
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerURL, 
        
        [System.String]
        $Token, 
        
        [System.String]
        $Referer, 
        
        [System.String]
        $MachineName
    )
    $GetMachineDetailsUrl  = $ServerURL.TrimEnd("/") + "/arcgis/admin/machines/$MachineName/"
    Invoke-ArcGISWebRequest -Url $GetMachineDetailsUrl -HttpFormParameters @{ f= 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET' -TimeoutSec 150
}

function Get-AllSSLCertificateForMachine 
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerURL, 
        
        [System.String]
        $Token, 
        
        [System.String]
        $Referer, 
        
        [System.String]
        $MachineName
    )
    $certURL = $ServerURL.TrimEnd("/") + "/arcgis/admin/machines/$MachineName/sslCertificates/"
    Invoke-ArcGISWebRequest -Url $certURL -HttpFormParameters @{ f= 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET' 
}

function Get-SSLCertificateForMachine
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [System.String]
        $ServerURL, 
        
        [System.String]
        $Token, 
        
        [System.String]
        $Referer, 
        
        [System.String]
        $MachineName, 
        
        [System.String]
        $SSLCertName
    )
    $CertUrl  = $ServerURL.TrimEnd("/") + "/arcgis/admin/machines/$MachineName/sslCertificates/$SSLCertName"
    try{
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
            $thumbprint = $json.sha1Fingerprint
            @{
                    Issuer = $issuer
                    Thumbprint = $thumbprint
            }
        }
    }
    catch{
        # If no cert exists, an error is returned
        Write-Verbose "[WARNING] Error checking $CertUrl Error:- $_"
        $null
    }
}
function Update-SecurityConfig
{
    [CmdletBinding()]
    param(
		[System.String]
        $ServerURL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer,

        $SecurityConfig,

        [System.Boolean]
        $EnableHTTPSOnly,
        
        [System.Boolean]
        $EnableHSTS
    ) 

    if(-not($SecurityConfig)) {
        throw "Security Config parameter is not provided"
    }

    $UpdateSecurityConfigUrl  = $ServerURL.TrimEnd("/") + "/arcgis/admin/security/config/update"
    $props = @{
        f= 'json';
        token = $Token;
        httpsProtocols = if($null -eq $SecurityConfig.httpsProtocols) {"TLSv1.2,TLSv1.1,TLSv1"}else{$SecurityConfig.httpsProtocols};
        cipherSuites = $SecurityConfig.cipherSuites;
        Protocol = if($EnableHTTPSOnly){ "HTTPS" }else{ "HTTP_AND_HTTPS" };
        authenticationTier = $SecurityConfig.authenticationTier;
        HSTSEnabled = "$EnableHSTS";
        portalProperties = (ConvertTo-Json $SecurityConfig.portalProperties -Compress);
        allowedAdminAccessIPs= if($null -eq $SecurityConfig.allowedAdminAccessIPs) { "" }else{$SecurityConfig.allowedAdminAccessIPs};
        allowDirectAccess= $SecurityConfig.allowDirectAccess ;
        allowInternetCORSEnabled= $SecurityConfig.allowInternetCORSAccess;
        virtualDirsSecurityEnabled = $SecurityConfig.virtualDirsSecurityEnabled;
    }
    Invoke-ArcGISWebRequest -Url $UpdateSecurityConfigUrl -HttpFormParameters $props -Referer $Referer -TimeOutSec 300 -Verbose
}

function Get-SecurityConfig 
{
    [CmdletBinding()]
    param(
		[System.String]
        $ServerURL,
        
        [System.String]
        $Token, 
        
        [System.String]
        $Referer
    ) 

    $GetSecurityConfigUrl  = $ServerURL.TrimEnd("/") + "/arcgis/admin/security/config/"
    Write-Verbose "Url:- $GetSecurityConfigUrl"
    Invoke-ArcGISWebRequest -Url $GetSecurityConfigUrl -HttpFormParameters @{ f= 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET' -TimeOutSec 30
}


Export-ModuleMember -Function *-TargetResource

