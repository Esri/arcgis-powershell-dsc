<#
    .SYNOPSIS
        Creates a SelfSigned Certificate or Installs a SSL Certificated Provided and Configures it with Portal.
    .PARAMETER Ensure
        Ensure makes sure that a Portal site is configured and joined to site if specified. Take the values Present or Absent. 
        - "Present" ensures the certificate is installed and configured with the portal.
        - "Absent" ensures the certificate configured with the portal is uninstalled and deleted(Not Implemented).
    .PARAMETER SiteName
        Site Name or Default Context of Portal
    .PARAMETER SiteAdministrator
        A MSFT_Credential Object - Primary Site Administrator.
    .PARAMETER CertificateFileLocation
        Certificate Path from where to fetch the certificate to be installed.
    .PARAMETER CertificatePassword
        Sercret Certificate Password or Key.
    .PARAMETER CName
        CName with which the Certificate will be associated.
    .PARAMETER PortalEndPoint
        Portal Endpoint with which the Certificate will be associated.
	.PARAMETER ServerEndPoint
        Not sure - Adds a Host Mapping of Server Machine and associates it with the certificate being Installed.
    .PARAMETER SslRootOrIntermediate
        List of RootOrIntermediate Certificates
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

	$null 
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

		[System.String]
		$ServerEndPoint,

        [System.String]
        $SslRootOrIntermediate
	)

	Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null

	if($ServerEndPoint -and ($ServerEndPoint -as [ipaddress])) {
		Write-Verbose "Adding Host mapping for $ServerEndPoint"
		Add-HostMapping -hostname $ServerEndPoint -ipaddress $ServerEndPoint        
	}
	elseif($CName -as [ipaddress]) {
		Write-Verbose "Adding Host mapping for $CName"
		Add-HostMapping -hostname $CName -ipaddress $CName        
	}

    if($CertificateFileLocation -and (Test-Path $CertificateFileLocation)) 
	{
		$result = $false
        $FQDN = if($PortalEndPoint) { Get-FQDN $PortalEndPoint} else { Get-FQDN $env:COMPUTERNAME }
	    $PortalUrl = "https://$($FQDN):7443"  
        $PortalAdminUrl = "$($PortalUrl)/$SiteName/portaladmin/"
		$Referer = $PortalUrl
		try{
			Wait-ForUrl "https://$($FQDN):7443/$SiteName/sharing/rest/generateToken"
			$token = Get-PortalToken -PortalHostName $FQDN -SiteName $SiteName -Credential $SiteAdministrator -Referer $Referer 
		}catch{
			throw "[WARNING] Unable to get token:- $_"
		}
		if(-not($token.token)){
			throw "Unable to retrieve Portal Token for '$($PortalAdministrator.UserName)'"
		}else{
            Write-Verbose "Retrieved Portal Token"
        }
        $Info = Invoke-ArcGISWebRequest -Url $PortalAdminUrl -HttpFormParameters @{ f = 'json'; token = $token.token; } -Referer $Referer -Verbose -HttpMethod 'GET'
        $Version = "$($Info.version)".Split('.')[1]

        try{
            $Certs = Get-SSLCertificatesForPortal -PortalURL $PortalURL -SiteName $SiteName -Token $token.token -Referer $Referer -MachineName $FQDN -Version $Version 
        }catch{
            throw "[WARNING] Unable to get SSL-CertificatesForPortal:- $_"
        }
		Write-Verbose "Current Alias for SSL Certificate:- '$($Certs.webServerCertificateAlias)' Certificates:- '$($Certs.sslCertificates -join ',')'"

        $ImportExistingCertFlag = $False
        $DeleteTempCert = $False
        if(-not($Certs.sslCertificates -icontains $CName)){
            Write-Verbose "Importing SSL Certificate with alias $CName"
			$ImportExistingCertFlag = $True
        }else{
            Write-Verbose "SSL Certificate with alias $CName already exists"
            $CertForMachine = Get-SSLCertificatesForPortal -PortalURL $PortalURL -SiteName $SiteName -Token $token.token -Referer $Referer -CName $CName.ToLower() -MachineName $FQDN -Version $Version 
            Write-Verbose "Examine certificate from $CertificateFileLocation"
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $cert.Import($CertificateFileLocation, $CertificatePassword.GetNetworkCredential().Password, 'DefaultKeySet')
            $NewCertThumbprint = $cert.Thumbprint
            Write-Verbose "Thumbprint for the supplied certificate is $NewCertThumbprint"
            if($CertForMachine.sha1Fingerprint -ine $NewCertThumbprint){
                $ImportExistingCertFlag = $True
                Write-Verbose "Importing exsting certificate with alias $($CName)-temp"
                try{
                    Import-ExistingCertificate -PortalURL $PortalURL -SiteName $SiteName -Token $token.token `
                                                -Referer $Referer -CertAlias "$($CName)-temp" -CertificateFilePath $CertificateFileLocation `
                                                -CertificatePassword $CertificatePassword -MachineName $FQDN -Version $Version
                    $DeleteTempCert = $True
                }catch{
                    throw "[WARNING] Error Import-ExistingCertificate:- $_"
                }

                try{
                    Update-PortalSSLCertificate -PortalURL $PortalURL -SiteName $SiteName -Token $token.token -Referer $Referer -CertAlias "$($CName)-temp" -MachineName $FQDN -Version $Version -Verbose
                    Write-Verbose "Updating to a temp SSL Certificate causes the web server to restart asynchronously. Waiting 180 seconds before checking for intitialization"
                    Start-Sleep -Seconds 180
                    Wait-ForUrl -Url $PortalAdminUrl
                }catch{
                    throw "[WARNING] Unable to Update-PortalSSLCertificate:- $_"
                }
                try{
                    Write-Verbose "Deleting Portal Certificate with alias $CName"
                    Invoke-DeletePortalCertificate -PortalURL $PortalURL -SiteName $SiteName -Token $token.token -Referer $Referer -CName $CName -MachineName $FQDN -Version $Version
                }catch{
                    throw "[WARNING] Unable to Invoke-DeletePortalCertificate:- $_"
                }
            }
        }

        if($ImportExistingCertFlag){
			Write-Verbose "Importing exsting certificate with alias $CName"
			try{
				Import-ExistingCertificate -PortalURL $PortalURL -SiteName $SiteName -Token $token.token `
					-Referer $Referer -CertAlias $CName -CertificateFilePath $CertificateFileLocation -CertificatePassword $CertificatePassword -MachineName $FQDN -Version $Version
			}catch{
				throw "[WARNING] Error Import-ExistingCertificate:- $_"
			}
        }
        
        $Certs = Get-SSLCertificatesForPortal -PortalURL $PortalURL -SiteName $SiteName -Token $token.token -Referer $Referer -MachineName $FQDN -Version $Version
		if(($Certs.webServerCertificateAlias -ine $CName) -or $ImportExistingCertFlag) {
			Write-Verbose "Updating Alias to use $CName"
			try{
                Update-PortalSSLCertificate -PortalURL $PortalURL -SiteName $SiteName -Token $token.token -Referer $Referer -CertAlias $CName -MachineName $FQDN -Version $Version -Verbose
                Write-Verbose "Updating an SSL Certificate causes the web server to restart asynchronously. Waiting 180 seconds before checking for intitialization"
                Start-Sleep -Seconds 180
                Wait-ForUrl -Url $PortalAdminUrl
                if($DeleteTempCert){
                    Write-Verbose "Deleting Temp Certificate with alias $($CName)-temp"
                    Invoke-DeletePortalCertificate -PortalURL $PortalURL -SiteName $SiteName -Token $token.token -Referer $Referer -CName "$($CName)-temp" -MachineName $FQDN -Version $Version
                }
			}catch{
				throw "[WARNING] Unable to Update-PortalSSLCertificate:- $_"
            }
		}else{
			Write-Verbose "SSL Certificate alias $CName is the current one"
		}     
		
        Write-Verbose "Waiting for '$PortalAdminUrl' to initialize"
		Wait-ForUrl -Url $PortalAdminUrl

		try{
            Write-Verbose 'Verifying that SSL Certificates config for site can be retrieved'
            $Certs = Get-SSLCertificatesForPortal -PortalURL $PortalURL -SiteName $SiteName -Token $token.token -Referer $Referer -MachineName $FQDN -Version $Version -ErrorAction SilentlyContinue
            if($CName -ine $Certs.webServerCertificateAlias) {
				Write-Verbose "Unable to retrive current alias to verify. Restarting Portal Service"
				Restart-PortalService -ServiceName 'Portal for ArcGIS'
				Start-Sleep -Seconds 120
				Write-Verbose "Waiting for '$PortalAdminUrl' to initialize after waiting 150 seconds"
				Wait-ForUrl -Url $PortalAdminUrl
				Write-Verbose "Finished Waiting for '$PortalAdminUrl' to initialize"
			}
		}catch{
			Write-Verbose "[WARNING] Unable to get SSL-CertificatesForPortal:- $_"
		}
    }else{
        Write-Verbose "CertificateFileLocation not specified or '$CertificateFileLocation' not accessible"
        Write-Warning "CertificateFileLocation not specified or '$CertificateFileLocation' not accessible"
	}

	# test and set RootOrIntermediateCertificate
    $Certs = Get-SSLCertificatesForPortal -PortalURL $PortalURL -SiteName $SiteName -Token $token.token -Referer $Referer -MachineName $FQDN -Version $Version -ErrorAction 
    foreach ($key in ($SslRootOrIntermediate | ConvertFrom-Json)){
        if ($Certs.sslCertificates -icontains $key.Alias){
            Write-Verbose "Set RootOrIntermediate $($key.Alias) is in List of SSL-Certificates no Action Required"
        }else{
            Write-Verbose "Set RootOrIntermediate $($key.Alias) is NOT in List of SSL-Certificates Import-RootOrIntermediate"
            try{
                Import-RootOrIntermediateCertificate -PortalURL $PortalURL -SiteName $SiteName -Token $token.token -Referer $Referer -CertAlias $key.Alias -CertificateFilePath $key.Path -MachineName $FQDN -Version $Version
            }catch{
                Write-Verbose "Error in Import-RootOrIntermediateCertificate :- $_"
            }
        }
    }
}

function Restart-PortalService
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [System.String]
        $ServiceName = 'Portal for ArcGIS'
    )

    try 
    {
		Write-Verbose "Restarting Service $ServiceName"
		Stop-Service -Name $ServiceName -Force -ErrorAction Ignore
		Write-Verbose 'Stopping the service' 
		Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Stopped'
		Write-Verbose 'Stopped the service'
	}catch {
        Write-Verbose "[WARNING] Stopping Service $_"
    }

	try {
		Write-Verbose 'Starting the service'
		Start-Service -Name $ServiceName -ErrorAction Ignore        
		Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Running'
		Write-Verbose "Restarted Service '$ServiceName'"
	}catch {
        Write-Verbose "[WARNING] Starting Service $_"
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

		[System.String]
		$ServerEndPoint,

        [System.String]
        $SslRootOrIntermediate
	)   
   
	Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $result = $false
    $FQDN = if($PortalEndPoint) { Get-FQDN $PortalEndPoint } else { Get-FQDN $env:COMPUTERNAME }
    $PortalURL = "https://$($FQDN):7443" 
    $PortalAdminUrl = "$($PortalURL)/$SiteName/portaladmin/"
	#Write-Verbose "Waiting for portal at 'https://$($FQDN):7443/$($SiteName)/sharing/rest/' to initialize" 
	#Wait-ForUrl -Url "https://$($FQDN):7443/$($SiteName)/sharing/rest/" -MaxWaitTimeInSeconds 180 -HttpMethod 'GET' -Verbose -MaximumRedirection -1
	$Referer = $PortalURL
    $token = $null
    Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/healthCheck/?f=json" -Verbose
    Wait-ForUrl "https://$($FQDN):7443/arcgis/sharing/rest/generateToken" -Verbose
    try{ 
        $token = Get-PortalToken -PortalHostName $FQDN -SiteName $SiteName -Credential $SiteAdministrator -Referer $Referer -MaxAttempts 30
    } catch {
        Write-Verbose "[WARNING] Unable to get token:- $_. Restarting portal service and retrying to get the token."
        Restart-PortalService -ServiceName 'Portal for ArcGIS'
        Start-Sleep -Seconds 150
        Write-Verbose "Waiting for '$PortalAdminUrl' to initialize after waiting 150 seconds"
        Wait-ForUrl -Url $PortalAdminUrl -Verbose
        Write-Verbose "Finished Waiting for '$PortalAdminUrl' to initialize"
        $token = Get-PortalToken -PortalHostName $FQDN -SiteName $SiteName  -Credential $SiteAdministrator -Referer $Referer -MaxAttempts 30
    }
	if(-not($token.token)) {
		throw "Unable to retrieve Portal Token for '$($SiteAdministrator.UserName)'"
	}else {
        Write-Verbose "Retrieved Portal Token"
    }

    $Info = Invoke-ArcGISWebRequest -Url $PortalAdminUrl -HttpFormParameters @{f = 'json'; token = $token.token; } -Referer $Referer -HttpMethod 'GET'
    $Version = "$($Info.version)".Split('.')[1]

	Write-Verbose "Retrieve SSL Certificate for Portal from $FQDN and checking for Alias $CNAME"
	try{
		$Certs = Get-SSLCertificatesForPortal -PortalURL $PortalURL -SiteName $Sitename -Token $token.token -Referer $Referer -MachineName $FQDN -Version $Version
		Write-Verbose "Number of certificates:- $($Certs.sslCertificates.Length) Certificates:- '$($Certs.sslCertificates -join ',')' Current Alias :- '$($Certs.webServerCertificateAlias)'"
        $result = ($Certs.sslCertificates -icontains $CName) -and ($Certs.webServerCertificateAlias -ieq $CName) 
        
	}catch{
		Write-Verbose "Error in Get-SSLCertificatesForPortal :- $_"
		$result = $false
	}

    if($result){
        Write-Verbose "Certificate $($Certs.webServerCertificateAlias) matches expected alias of '$CNAME'"
        $CertForMachine = Get-SSLCertificatesForPortal -PortalURL $PortalURL -SiteName $SiteName -Token $token.token -Referer $Referer -CName $CName -Version $Version -MachineName $FQDN
        if($CertificateFileLocation -and ($null -ne $CertificatePassword)) {
            Write-Verbose "Examine certificate from $CertificateFileLocation"
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $cert.Import($CertificateFileLocation, $CertificatePassword.GetNetworkCredential().Password, 'DefaultKeySet')
            $NewCertThumbprint = $cert.Thumbprint
            Write-Verbose "Thumbprint for the supplied certificate is $NewCertThumbprint"
            if($CertForMachine.sha1Fingerprint -ine $NewCertThumbprint){
                $result = $false
            }
        }
    }
    else {
        Write-Verbose "Certificate $($Certs.webServerCertificateAlias) does not match expected alias of '$CNAME'"
    }

    if ($result) { # test for RootOrIntermediate Certificate-List
        $testRootorIntermediate = $true
        foreach ($key in ($SslRootOrIntermediate | ConvertFrom-Json)){
            if ($Certs.sslCertificates -icontains $key.Alias){
                Write-Verbose "Test RootOrIntermediate $($key.Alias) is in List of SSL-Certificates"
            }else{
                $testRootorIntermediate = $false
                Write-Verbose "Test RootOrIntermediate $($key.Alias) is NOT in List of SSL-Certificates"
                break;
            }
        }
        $result = $testRootorIntermediate
    }

    if($Ensure -ieq 'Present'){           
           $result
    }elseif($Ensure -ieq 'Absent'){        
        (-not($result))
    }
}

function Get-SSLCertificatesForPortal
{
    param(
        [System.String]
        $PortalURL,

        [System.String]
        $CName,

        [System.String]
        $SiteName = 'arcgis',

        [System.String]
        $Token,

        [System.String]
        $Referer,

        [System.String]
        $MachineName,

        [System.String]
        $Version
    )

	try {
        $URL = if($Version -ge 8){ $PortalURL.TrimEnd("/") + "/$($SiteName)/portaladmin/machines/$MachineName/sslCertificates" } else { $PortalURL.TrimEnd("/") + "/$($SiteName)/portaladmin/security/sslCertificates" }
        if($CName){ $URL = $URL + "/$($CName)" }
	    Invoke-ArcGISWebRequest -Url $URL -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer -HttpMethod 'GET' -TimeOutSec 120
	}
	catch {
		Write-Verbose "[WARNING]:- Get-SSLCertificatesForPortal encountered an error during execution. Error:- $_"
	}
}

function Invoke-DeletePortalCertificate{
    param(
        [System.String]
        $PortalURL,

        [System.String]
        $CName,

        [System.String]
        $SiteName = 'arcgis',

        [System.String]
        $Token,

        [System.String]
        $Referer,

        [System.String]
        $MachineName,

        [System.String]
        $Version
    )
    try {
        $URL = if($Version -ge 8){ $PortalURL.TrimEnd("/") + "/$($SiteName)/portaladmin/machines/$MachineName/sslCertificates/$($CName)/delete" }else{ $PortalURL.TrimEnd("/") + "/$($SiteName)/portaladmin/security/sslCertificates/$($CName)/delete" }
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
        $SiteName = 'arcgis', 

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

        [System.String]
        $Version
    )
    $ImportCertUrl = if($Version -ge 8){ $PortalURL.TrimEnd("/") + "/$($SiteName)/portaladmin/machines/$MachineName/sslCertificates/importExistingServerCertificate" }else{ $PortalURL.TrimEnd("/") + "/$($SiteName)/portaladmin/security/sslCertificates/importExistingServerCertificate" }
    
    $props = @{ f= 'json'; token = $Token; alias = $CertAlias; password = $CertificatePassword.GetNetworkCredential().Password  }    
    $res = Invoke-UploadFile -url $ImportCertUrl -filePath $CertificateFilePath -fileContentType 'application/x-pkcs12' -formParams $props -Referer $Referer -fileParameterName 'file'    
    if($res -and $res.Content) {
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
        $SiteName = 'arcgis', 

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

        [System.String]
        $Version
    )

    $ImportCertUrl = if($Version -ge 8){ $PortalURL.TrimEnd("/") + "/$($SiteName)/portaladmin/machines/$MachineName/sslCertificates/importRootOrIntermediate" }else{ $PortalURL.TrimEnd("/") + "/$($SiteName)/portaladmin/security/sslCertificates/importRootOrIntermediate" }
    $props = @{ f= 'json'; token = $Token; alias = $CertAlias; norestart = $true  } # norestart requires ArcGIS Server 10.6 or higher
    $res = Invoke-UploadFile -url $ImportCertUrl -filePath $CertificateFilePath -fileContentType 'application/x-pkcs12' -formParams $props -Referer $Referer -fileParameterName 'file'    
    if($res -and $res.Content) {
        $response = $res | ConvertFrom-Json
        Confirm-ResponseStatus $response -Url $ImportCertUrl
    } else {
        Write-Verbose "[WARNING] Response from $ImportCertUrl was null"
    }
}

function Update-PortalSSLCertificate
{
    [CmdletBinding()]
    param(
        [System.String]
        $PortalURL, 

        [System.String]
        $SiteName = 'arcgis', 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $CertAlias,

        [System.String]
        $MachineName,

        [System.String]
        $Version
    )

    $URL = if($Version -ge 8){ $PortalURL.TrimEnd("/") + "/$($SiteName)/portaladmin/machines/$MachineName/sslCertificates/update" }else{ $PortalURL.TrimEnd("/") + "/$($SiteName)/portaladmin/security/sslCertificates/update" }

    $SSLCertsObject = Get-SSLCertificatesForPortal -PortalURL $PortalURL -SiteName $Sitename -Token $Token -Referer $Referer -MachineName $MachineName -Version $Version

    $sslProtocols = if($null -eq $SSLCertsObject.cipherSuites) {"TLSv1.2,TLSv1.1,TLSv1"}else{$SSLCertsObject.sslProtocols}
    $cipherSuites = if($null -eq $SSLCertsObject.cipherSuites){ "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,TLS_DHE_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,TLS_DHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA" }else{ $SSLCertsObject.cipherSuites }
    $WebParams = @{ f = 'json'; token = $Token; webServerCertificateAlias = $CertAlias; sslProtocols = $sslProtocols ; cipherSuites = $cipherSuites;}
    if($Version -ge 8){ $WebParams.HSTSEnabled = $False; }
   
    Invoke-ArcGISWebRequest -Url $URL -HttpFormParameters $WebParams -Referer $Referer
}

Export-ModuleMember -Function *-TargetResource