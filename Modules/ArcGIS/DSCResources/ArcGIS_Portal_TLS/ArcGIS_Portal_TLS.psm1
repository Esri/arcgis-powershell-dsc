$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

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
		[parameter(Mandatory = $true)]
        [System.String]
		$PortalHostName
	)

	$null 
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
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
        $EnableHSTS
	)

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	
    $VersionGreaterThan1071 = $true
    $FQDN = if($PortalHostName) { Get-FQDN $PortalHostName} else { Get-FQDN $env:COMPUTERNAME }
    $PortalUrl = "https://$($FQDN):7443"  
    $Referer = $PortalUrl
    try{
        Wait-ForUrl "$PortalURL/arcgis/portaladmin/healthCheck/?f=json" -Verbose
        Wait-ForUrl "$PortalURL/arcgis/sharing/rest/generateToken" -Verbose
        $token = Get-PortalToken -PortalHostName $FQDN -Credential $SiteAdministrator -Referer $Referer 
    }catch{
        throw "[WARNING] Unable to get token:- $_"
    }
    if(-not($token.token)){
        throw "Unable to retrieve Portal Token for '$($PortalAdministrator.UserName)'"
    }else{
        Write-Verbose "Retrieved Portal Token"
    }
    $Info = Invoke-ArcGISWebRequest -Url "$($PortalUrl)/arcgis/portaladmin/" -HttpFormParameters @{ f = 'json'; token = $token.token; } -Referer $Referer -Verbose -HttpMethod 'GET'
    $VersionArray = "$($Info.version)".Split('.')
    [System.Boolean]$VersionGreaterThan1071 = ($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 7))

    if($CertificateFileLocation) 
	{
        if($WebServerCertificateAlias -and $WebServerCertificateAlias -as [ipaddress]) {
            Write-Verbose "Adding Host mapping for $WebServerCertificateAlias"
            Add-HostMapping -hostname $WebServerCertificateAlias -ipaddress $WebServerCertificateAlias        
        }

        if((Test-Path $CertificateFileLocation))
        {
            try{
                $Certs = Get-SSLCertificatesForPortal -PortalURL $PortalURL -Token $token.token -Referer $Referer -MachineName $FQDN -VersionGreaterThan1071 $VersionGreaterThan1071 
            }catch{
                throw "[WARNING] Unable to get SSL-CertificatesForPortal:- $_"
            }
            Write-Verbose "Current Alias for SSL Certificate:- '$($Certs.webServerCertificateAlias)' Certificates:- '$($Certs.sslCertificates -join ',')'"

            $ImportExistingCertFlag = $False
            $DeleteTempCert = $False
            if(-not($Certs.sslCertificates -icontains $WebServerCertificateAlias)){
                Write-Verbose "Importing SSL Certificate with alias $WebServerCertificateAlias"
                $ImportExistingCertFlag = $True
            }else{
                Write-Verbose "SSL Certificate with alias $WebServerCertificateAlias already exists"
                $CertForMachine = Get-SSLCertificatesForPortal -PortalURL $PortalURL -Token $token.token -Referer $Referer -WebServerCertificateAlias $WebServerCertificateAlias.ToLower() -MachineName $FQDN -VersionGreaterThan1071 $VersionGreaterThan1071 
                Write-Verbose "Examine certificate from $CertificateFileLocation"
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $cert.Import($CertificateFileLocation, $CertificatePassword.GetNetworkCredential().Password, 'DefaultKeySet')
                $NewCertThumbprint = $cert.Thumbprint
                Write-Verbose "Thumbprint for the supplied certificate is $NewCertThumbprint"
                if($CertForMachine.sha1Fingerprint -ine $NewCertThumbprint){
                    $ImportExistingCertFlag = $True
                    Write-Verbose "Importing exsting certificate with alias $($WebServerCertificateAlias)-temp"
                    try{
                        Import-ExistingCertificate -PortalURL $PortalURL -Token $token.token `
                                                    -Referer $Referer -CertAlias "$($WebServerCertificateAlias)-temp" -CertificateFilePath $CertificateFileLocation `
                                                    -CertificatePassword $CertificatePassword -MachineName $FQDN -VersionGreaterThan1071 $VersionGreaterThan1071
                        $DeleteTempCert = $True
                    }catch{
                        throw "[WARNING] Error Import-ExistingCertificate:- $_"
                    }

                    try{
                        Update-PortalSSLCertificate -PortalURL $PortalURL -Token $token.token -Referer $Referer -CertAlias "$($WebServerCertificateAlias)-temp" -MachineName $FQDN -VersionGreaterThan1071 $VersionGreaterThan1071 -Verbose
                        Write-Verbose "Updating to a temp SSL Certificate causes the web server to restart asynchronously. Waiting 60 seconds before checking for intitialization"
                        Start-Sleep -Seconds 60
                        Wait-ForUrl "$PortalURL/arcgis/portaladmin/healthCheck/?f=json" -Verbose
                        Wait-ForUrl "$PortalURL/arcgis/sharing/rest/generateToken" -Verbose
                    }catch{
                        throw "[WARNING] Unable to Update-PortalSSLCertificate:- $_"
                    }
                    try{
                        Write-Verbose "Deleting Portal Certificate with alias $WebServerCertificateAlias"
                        Invoke-DeletePortalCertificate -PortalURL $PortalURL -Token $token.token -Referer $Referer -WebServerCertificateAlias $WebServerCertificateAlias -MachineName $FQDN -VersionGreaterThan1071 $VersionGreaterThan1071
                    }catch{
                        throw "[WARNING] Unable to Invoke-DeletePortalCertificate:- $_"
                    }
                }
            }

            if($ImportExistingCertFlag){
                Write-Verbose "Importing exsting certificate with alias $WebServerCertificateAlias"
                try{
                    Import-ExistingCertificate -PortalURL $PortalURL -Token $token.token `
                        -Referer $Referer -CertAlias $WebServerCertificateAlias -CertificateFilePath $CertificateFileLocation -CertificatePassword $CertificatePassword -MachineName $FQDN -VersionGreaterThan1071 $VersionGreaterThan1071 
                }catch{
                    throw "[WARNING] Error Import-ExistingCertificate:- $_"
                }
            }
            
            $Certs = Get-SSLCertificatesForPortal -PortalURL $PortalURL -Token $token.token -Referer $Referer -MachineName $FQDN -VersionGreaterThan1071 $VersionGreaterThan1071
            if(($Certs.webServerCertificateAlias -ine $WebServerCertificateAlias) -or $ImportExistingCertFlag) {
                Write-Verbose "Updating Alias to use $WebServerCertificateAlias"
                try{
                    Update-PortalSSLCertificate -PortalURL $PortalURL -Token $token.token -Referer $Referer -CertAlias $WebServerCertificateAlias -MachineName $FQDN -VersionGreaterThan1071 $VersionGreaterThan1071 -Verbose
                    Write-Verbose "Updating an SSL Certificate causes the web server to restart asynchronously. Waiting 60 seconds before checking for intitialization"
                    Start-Sleep -Seconds 60
                    Wait-ForUrl "$PortalURL/arcgis/portaladmin/healthCheck/?f=json" -Verbose
                    Wait-ForUrl "$PortalURL/arcgis/sharing/rest/generateToken" -Verbose

                    if($DeleteTempCert){
                        Write-Verbose "Deleting Temp Certificate with alias $($WebServerCertificateAlias)-temp"
                        Invoke-DeletePortalCertificate -PortalURL $PortalURL -Token $token.token -Referer $Referer -WebServerCertificateAlias "$($WebServerCertificateAlias)-temp" -MachineName $FQDN -VersionGreaterThan1071 $VersionGreaterThan1071 
                    }
                }catch{
                    throw "[WARNING] Unable to Update-PortalSSLCertificate:- $_"
                }
            }else{
                Write-Verbose "SSL Certificate alias $WebServerCertificateAlias is the current one"
            }     
            
            Wait-ForUrl "$PortalURL/arcgis/portaladmin/healthCheck/?f=json" -Verbose
            Wait-ForUrl "$PortalURL/arcgis/sharing/rest/generateToken" -Verbose
        }else{
            throw "[ERROR] - CertificateFileLocation '$CertificateFileLocation' is not acccesible"
	    }
    }else{
        Write-Verbose "CertificateFileLocation not specified. Skipping web server certificate configuration"
	}

	# test and set RootOrIntermediateCertificate
    if($null -ne $SslRootOrIntermediate){
        $Certs = Get-SSLCertificatesForPortal -PortalURL $PortalURL -Token $token.token -Referer $Referer -MachineName $FQDN -VersionGreaterThan1071 $VersionGreaterThan1071 -ErrorAction SilentlyContinue
        $RestartRequired = $False
        foreach ($key in ($SslRootOrIntermediate | ConvertFrom-Json)){
            $UploadRootOrIntermediateCertificate = $False
            if ($Certs.sslCertificates -icontains $key.Alias){
                Write-Verbose "Set RootOrIntermediate $($key.Alias) is in List of SSL-Certificates no Action Required"
                $RootOrIntermediateCertForMachine = Get-SSLCertificatesForPortal -PortalURL $PortalURL -Token $token.token -Referer $Referer -WebServerCertificateAlias $key.Alias -VersionGreaterThan1071 $VersionGreaterThan1071 -MachineName $FQDN
                Write-Verbose "Existing Cert Issuer $($RootOrIntermediateCertForMachine.Issuer) and Thumbprint $($RootOrIntermediateCertForMachine.sha1Fingerprint)"
                $NewCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $key.Path
                Write-Verbose "Issuer and Thumprint for the supplied certificate is $($NewCert.Issuer) and $($NewCert.Thumbprint) respectively."
                if($RootOrIntermediateCertForMachine.sha1Fingerprint -ine $NewCert.Thumbprint){
                    Write-Verbose "Thumbprints for Certificate with Alias $($key.Alias) doesn't match that of existing cetificate. Deleting existing certificate and uploading a new one"
                    $UploadRootOrIntermediateCertificate = $True
                    Invoke-DeletePortalCertificate -PortalURL $PortalURL -Token $token.token -Referer $Referer -WebServerCertificateAlias $key.Alias -MachineName $FQDN -VersionGreaterThan1071 $VersionGreaterThan1071
                }else{
                    Write-Verbose "Thumbprints for Certificate with Alias $($key.Alias) match that of existing cetificate."
                }
            }else{
                Write-Verbose "Set RootOrIntermediate $($key.Alias) is NOT in List of SSL-Certificates Import-RootOrIntermediate"
                $UploadRootOrIntermediateCertificate = $True
            }
            if($UploadRootOrIntermediateCertificate){
                try{
                    Import-RootOrIntermediateCertificate -PortalURL $PortalURL -Token $token.token -Referer $Referer -CertAlias $key.Alias -CertificateFilePath $key.Path -MachineName $FQDN -VersionGreaterThan1071 $VersionGreaterThan1071
                    if(-not($RestartRequired)){
                        $RestartRequired = $True
                    }
                }catch{
                    Write-Verbose "Error in Import-RootOrIntermediateCertificate :- $_"
                }
            }
        }
        if($RestartRequired){
            Write-Verbose "Portal Root and intermediate certificates were updated. Restarting Portal."
            Restart-ArcGISService -ServiceName 'Portal for ArcGIS' -Verbose
            Write-Verbose "Waiting 30 seconds before checking for intitialization"
            Start-Sleep -Seconds 30
            Wait-ForUrl "$PortalURL/arcgis/portaladmin/healthCheck/?f=json" -Verbose
            Wait-ForUrl "$PortalURL/arcgis/sharing/rest/generateToken" -Verbose
        }
    }

    $PortalMachineCertSettings = Get-SSLCertificatesForPortal -PortalURL $PortalURL -Token $token.token -Referer $Referer -MachineName $FQDN -VersionGreaterThan1071 $VersionGreaterThan1071 -ErrorAction SilentlyContinue
    if($PortalMachineCertSettings.HSTSEnabled -ine $EnableHSTS){
        Write-Verbose "Enabled HSTS doesn't match the expected state $EnableHSTS"
        Update-HSTSSetting -PortalURL $PortalURL -Token $token.token -Referer $Referer  -MachineName $FQDN -VersionGreaterThan1071 $VersionGreaterThan1071 -HSTSEnabled $EnableHSTS -Verbose
        Write-Verbose "Waiting 30 seconds as changing hsts setting will cause the web server to restart."
        Start-Sleep -Seconds 30
        Wait-ForUrl "$PortalURL/arcgis/portaladmin/healthCheck/?f=json" -Verbose
        Wait-ForUrl "$PortalURL/arcgis/sharing/rest/generateToken" -Verbose
    }else{
        Write-Verbose "Enabled HSTS matches the expected state $EnableHSTS"
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
        $EnableHSTS
	)

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $result = $True
    $FQDN = if($PortalHostName) { Get-FQDN $PortalHostName } else { Get-FQDN $env:COMPUTERNAME }
    $PortalURL = "https://$($FQDN):7443" 
    $Referer = $PortalURL
    $token = $null
    Wait-ForUrl "$PortalURL/arcgis/portaladmin/healthCheck/?f=json" -Verbose
    Wait-ForUrl "$PortalURL/arcgis/sharing/rest/generateToken" -Verbose
    try{ 
        $token = Get-PortalToken -PortalHostName $FQDN -Credential $SiteAdministrator -Referer $Referer -MaxAttempts 30
    } catch {
        Write-Verbose "[WARNING] Unable to get token:- $_."
    }
	if(-not($token.token)) {
		throw "Unable to retrieve Portal Token for '$($SiteAdministrator.UserName)'"
	}else {
        Write-Verbose "Retrieved Portal Token"
    }

    $Info = Invoke-ArcGISWebRequest -Url "$($PortalURL)/arcgis/portaladmin/" -HttpFormParameters @{f = 'json'; token = $token.token; } -Referer $Referer -HttpMethod 'GET'
    $VersionArray = "$($Info.version)".Split('.')
    [System.Boolean]$VersionGreaterThan1071 = ($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 7))

    if($WebServerCertificateAlias){
        Write-Verbose "Retrieve SSL Certificate for Portal from $FQDN and checking for Alias $WebServerCertificateAlias"
        $Certs = $null
        try{
            $Certs = Get-SSLCertificatesForPortal -PortalURL $PortalURL -Token $token.token -Referer $Referer -MachineName $FQDN -VersionGreaterThan1071 $VersionGreaterThan1071
            Write-Verbose "Number of certificates:- $($Certs.sslCertificates.Length) Certificates:- '$($Certs.sslCertificates -join ',')' Current Alias :- '$($Certs.webServerCertificateAlias)'"   
        }catch{
            Write-Verbose "Error in Get-SSLCertificatesForPortal:- $_"
            throw $_
        }

        if(($null -ne $Certs) -and ($Certs.sslCertificates -iContains $WebServerCertificateAlias) -and ($Certs.webServerCertificateAlias -ieq $WebServerCertificateAlias)){
            Write-Verbose "Certificate $($Certs.webServerCertificateAlias) matches expected alias of '$WebServerCertificateAlias'"
            $CertForMachine = Get-SSLCertificatesForPortal -PortalURL $PortalURL -Token $token.token -Referer $Referer -WebServerCertificateAlias $WebServerCertificateAlias -VersionGreaterThan1071 $VersionGreaterThan1071 -MachineName $FQDN
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

    if ($result -and -not([string]::IsNullOrEmpty($SslRootOrIntermediate))) { 
        $Certs = Get-SSLCertificatesForPortal -PortalURL $PortalURL -Token $token.token -Referer $Referer -MachineName $FQDN -VersionGreaterThan1071 $VersionGreaterThan1071 -ErrorAction SilentlyContinue
        foreach ($key in ($SslRootOrIntermediate | ConvertFrom-Json)){
            if ($Certs.sslCertificates -icontains $key.Alias){
                Write-Verbose "Test RootOrIntermediate $($key.Alias) is in List of SSL-Certificates. Validating if thumbprint matches the existing certificate"
                $RootOrIntermediateCertForMachine = Get-SSLCertificatesForPortal -PortalURL $PortalURL -Token $token.token -Referer $Referer -WebServerCertificateAlias $key.Alias -VersionGreaterThan1071 $VersionGreaterThan1071 -MachineName $FQDN
                Write-Verbose "Existing Cert Issuer $($RootOrIntermediateCertForMachine.Issuer) and Thumbprint $($RootOrIntermediateCertForMachine.sha1Fingerprint)"
                $NewCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $key.Path
                Write-Verbose "Issuer and Thumprint for the supplied certificate is $($NewCert.Issuer) and $($NewCert.Thumbprint) respectively."
                if($RootOrIntermediateCertForMachine.sha1Fingerprint -ine $NewCert.Thumbprint){
                    Write-Verbose "Thumbprints for Certificate with Alias $($key.Alias) doesn't match that of existing cetificate."
                    $result = $False
                    break
                }else{
                    Write-Verbose "Thumbprints for Certificate with Alias $($key.Alias) match that of existing cetificate."
                }
            }else{
                $result = $False
                Write-Verbose "Test RootOrIntermediate $($key.Alias) is NOT in List of SSL-Certificates"
                break
            }
        }
    }

    if ($result){
        $PortalMachineCertSettings = Get-SSLCertificatesForPortal -PortalURL $PortalURL -Token $token.token -Referer $Referer -MachineName $FQDN -VersionGreaterThan1071 $VersionGreaterThan1071 -ErrorAction SilentlyContinue
        if($PortalMachineCertSettings.HSTSEnabled -ine $EnableHSTS){
            Write-Verbose "Enabled HSTS doesn't match the expected state $EnableHSTS"
            $result = $false
        }else{
            Write-Verbose "Enabled HSTS matches the expected state $EnableHSTS"
        }
    }

    $result
}

function Get-SSLCertificatesForPortal
{
    [CmdletBinding()]
    param(
        [System.String]
        $PortalURL,

        [System.String]
        $WebServerCertificateAlias,

        [System.String]
        $Token,

        [System.String]
        $Referer,

        [System.String]
        $MachineName,

        [System.Boolean]
        $VersionGreaterThan1071 
    )

	try {
        $URL = if($VersionGreaterThan1071){ $PortalURL.TrimEnd("/") + "/arcgis/portaladmin/machines/$MachineName/sslCertificates" } else { $PortalURL.TrimEnd("/") + "/arcgis/portaladmin/security/sslCertificates" }
        if($WebServerCertificateAlias){ $URL = $URL + "/$($WebServerCertificateAlias)" }
	    Invoke-ArcGISWebRequest -Url $URL -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer -HttpMethod 'GET' -TimeOutSec 120
	}
	catch {
		Write-Verbose "[WARNING]:- Get-SSLCertificatesForPortal encountered an error during execution. Error:- $_"
	}
}

function Invoke-DeletePortalCertificate{
    [CmdletBinding()]
    param(
        [System.String]
        $PortalURL,

        [System.String]
        $WebServerCertificateAlias,

        [System.String]
        $Token,

        [System.String]
        $Referer,

        [System.String]
        $MachineName,

        [System.Boolean]
        $VersionGreaterThan1071
    )
    try {
        $URL = if($VersionGreaterThan1071){ $PortalURL.TrimEnd("/") + "/arcgis/portaladmin/machines/$MachineName/sslCertificates/$($WebServerCertificateAlias)/delete" }else{ $PortalURL.TrimEnd("/") + "/arcgis/portaladmin/security/sslCertificates/$($WebServerCertificateAlias)/delete" }
        Invoke-ArcGISWebRequest -Url $URL -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer -HttpMethod 'POST' -TimeOutSec 120
    }catch{
        Write-Verbose "[WARNING]:- Invoke-DeletePortalCertificate encountered an error during execution. Error:- $_"
    }
}

function Import-ExistingCertificate
{
    [CmdletBinding()]
    param(
        [System.String]
        $PortalURL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $CertAlias, 

        [System.Management.Automation.PSCredential]
        $CertificatePassword, 

        [System.String]
        $CertificateFilePath,

        [System.String]
        $MachineName,

        [System.Boolean]
        $VersionGreaterThan1071
    )
    $ImportCertUrl = if($VersionGreaterThan1071){ $PortalURL.TrimEnd("/") + "/arcgis/portaladmin/machines/$MachineName/sslCertificates/importExistingServerCertificate" }else{ $PortalURL.TrimEnd("/") + "/arcgis/portaladmin/security/sslCertificates/importExistingServerCertificate" }
    
    $props = @{ f= 'json'; token = $Token; alias = $CertAlias; password = $CertificatePassword.GetNetworkCredential().Password  }    
    $res = Invoke-UploadFile -url $ImportCertUrl -filePath $CertificateFilePath -fileContentType 'application/x-pkcs12' -formParams $props -Referer $Referer -fileParameterName 'file'    
    if($res) {
        $response = $res | ConvertFrom-Json
        Confirm-ResponseStatus $response -Url $ImportCertUrl
    } else {
        Write-Verbose "[WARNING] Response from $ImportCertUrl was null"
    }
}

function Import-RootOrIntermediateCertificate
{
    [CmdletBinding()]
    param(
        [System.String]
        $PortalURL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $CertAlias, 

        [System.String]
        $CertificateFilePath,

        [System.String]
        $MachineName,

        [System.Boolean]
        $VersionGreaterThan1071
    )

    $ImportCertUrl = if($VersionGreaterThan1071){ $PortalURL.TrimEnd("/") + "/arcgis/portaladmin/machines/$MachineName/sslCertificates/importRootOrIntermediate" }else{ $PortalURL.TrimEnd("/") + "/arcgis/portaladmin/security/sslCertificates/importRootOrIntermediate" }
    $props = @{ f= 'json'; token = $Token; alias = $CertAlias; norestart = $true }
    $res = Invoke-UploadFile -url $ImportCertUrl -filePath $CertificateFilePath -fileContentType 'application/x-pkcs12' -formParams $props -Referer $Referer -fileParameterName 'file'    
    if($res) {
        $response = $res | ConvertFrom-Json
        Confirm-ResponseStatus $response -Url $ImportCertUrl
    } else {
        Write-Verbose "[WARNING] Response from $ImportCertUrl was null"
    }
}

function Update-HSTSSetting
{
    [CmdletBinding()]
    param(
        [System.String]
        $PortalURL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $MachineName,

        [System.Boolean]
        $VersionGreaterThan1071,

        [System.Boolean]
        $HSTSEnabled
    )

    $URL = if($VersionGreaterThan1071){ $PortalURL.TrimEnd("/") + "/arcgis/portaladmin/machines/$MachineName/sslCertificates/update" }else{ $PortalURL.TrimEnd("/") + "/arcgis/portaladmin/security/sslCertificates/update" }

    $SSLCertsObject = Get-SSLCertificatesForPortal -PortalURL $PortalURL -Token $Token -Referer $Referer -MachineName $MachineName -VersionGreaterThan1071 $VersionGreaterThan1071
    
    $sslProtocols = if($null -eq $SSLCertsObject.cipherSuites) { "TLSv1.2,TLSv1.1,TLSv1" }else{ $SSLCertsObject.sslProtocols }
    $cipherSuites = if($null -eq $SSLCertsObject.cipherSuites){ "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,TLS_DHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,TLS_DHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA" }else{ $SSLCertsObject.cipherSuites }
    $WebParams = @{ f = 'json'; token = $Token; webServerCertificateAlias = $SSLCertsObject.webServerCertificateAlias; sslProtocols = $sslProtocols ; cipherSuites = $cipherSuites; HSTSEnabled = "$HSTSEnabled";}
    
    Invoke-ArcGISWebRequest -Url $URL -HttpFormParameters $WebParams -Referer $Referer
}

function Update-PortalSSLCertificate
{
    [CmdletBinding()]
    param(
        [System.String]
        $PortalURL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $CertAlias,

        [System.String]
        $MachineName,

        [System.Boolean]
        $VersionGreaterThan1071
    )

    $URL = if($VersionGreaterThan1071){ $PortalURL.TrimEnd("/") + "/arcgis/portaladmin/machines/$MachineName/sslCertificates/update" }else{ $PortalURL.TrimEnd("/") + "/arcgis/portaladmin/security/sslCertificates/update" }

    $SSLCertsObject = Get-SSLCertificatesForPortal -PortalURL $PortalURL -Token $Token -Referer $Referer -MachineName $MachineName -VersionGreaterThan1071 $VersionGreaterThan1071

    $sslProtocols = if($null -eq $SSLCertsObject.sslProtocols) {"TLSv1.2,TLSv1.1,TLSv1"}else{$SSLCertsObject.sslProtocols}
    $cipherSuites = if($null -eq $SSLCertsObject.cipherSuites){ "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,TLS_DHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,TLS_DHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA" }else{ $SSLCertsObject.cipherSuites }
    $WebParams = @{ f = 'json'; token = $Token; webServerCertificateAlias = $CertAlias; sslProtocols = $sslProtocols ; cipherSuites = $cipherSuites;}
    if($VersionGreaterThan1071){ 
        $WebParams.HSTSEnabled = "$($SSLCertsObject.HSTSEnabled)"; 
    }
   
    Invoke-ArcGISWebRequest -Url $URL -HttpFormParameters $WebParams -Referer $Referer
}

Export-ModuleMember -Function *-TargetResource
