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
        Imports a SSL certificate from remote machine to local machines root store.
    .PARAMETER Ensure
        Take the values Present or Absent. 
        - "Present" ensures the certificate is Imported from remote machine to local machines root store.
        - "Absent" ensures the certificate is removed from local machines root store.
    .PARAMETER HostName
        Host Name of the Remote Machine whose SSL Certificate needs to be imported into the trusted local store.
    .PARAMETER ApplicationPath
        Application Path from where the certificate is to imported.
    .PARAMETER StoreLocation
        Location of the Store where the SSL Certificate will be imported
    .PARAMETER StoreName
        Store Name in the Store Location where the SSL Certificate will be imported
    .PARAMETER SiteAdministrator
        Credential to the Access the link to import Certificates into Trusted Store.
    .PARAMETER HttpsPort
        Port to which this certificate will be binded
#>

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
        [ValidateSet("Present","Absent")]
		[System.String]
        $Ensure,
        
        [parameter(Mandatory = $true)]
		[System.String]
		$HostName,

        [parameter(Mandatory = $true)]
		[System.String]
		$ApplicationPath,

        [parameter(Mandatory = $true)]
		[System.String]
		$StoreLocation = 'LocalMachine',

        [parameter(Mandatory = $true)]
		[System.String]
		$StoreName = 'Root',

        [parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
		$SiteAdministrator,

        [parameter(Mandatory = $true)]
		[uint32]
		$HttpsPort,
        
        [parameter(Mandatory = $false)]
        [System.String]
        $ServerType
    )

	@{}
}


function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [parameter(Mandatory = $true)]
		[System.String]
		$HostName,

        [ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [parameter(Mandatory = $true)]
		[System.String]
		$ApplicationPath,

        [parameter(Mandatory = $true)]
		[System.String]
		$StoreLocation = 'LocalMachine',

        [parameter(Mandatory = $true)]
		[System.String]
		$StoreName = 'Root',

        [parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
		$SiteAdministrator,

        [parameter(Mandatory = $true)]
		[uint32]
		$HttpsPort,
        
        [parameter(Mandatory = $false)]
        [System.String]
        $ServerType
	)

    $FQDN = Get-FQDN $HostName  
    $AppPath = $ApplicationPath.TrimStart('/')
    $Url =  "https://$($FQDN):$($HttpsPort)/$AppPath"
    Write-Verbose "Test Certificate existence from '$Url' in $StoreLocation and $StoreName"
    $result = Test-CertificateInTrustedCertificateStore -Url $Url -StoreLocation $StoreLocation -StoreName $StoreName
    if($Ensure -ieq 'Present') {
	    $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
        [parameter(Mandatory = $true)]
		[System.String]
		$HostName,

        [ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [parameter(Mandatory = $true)]
		[System.String]
		$ApplicationPath,

        [parameter(Mandatory = $true)]
		[System.String]
		$StoreLocation = 'LocalMachine',

        [parameter(Mandatory = $true)]
		[System.String]
		$StoreName = 'Root',

        [parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
		$SiteAdministrator,

        [parameter(Mandatory = $true)]
		[uint32]
        $HttpsPort,
        
        [parameter(Mandatory = $false)]
        [System.String]
        $ServerType
    )

    if($Ensure -ieq 'Present') 
    {
        $FQDN = Get-FQDN $HostName  
        $AppPath = $ApplicationPath.TrimStart('/')
        $Url =  "https://$($FQDN):$($HttpsPort)/$AppPath"
        Write-Verbose "Certificate import from '$Url' into $StoreLocation and $StoreName"     
        if(-not(Test-CertificateInTrustedCertificateStore -Url $Url -StoreLocation $StoreLocation -StoreName $StoreName)) {
            Write-Verbose "Import certificate from $Url"
            Import-CertFromServerIntoTrustedCertificateStore -Url $Url -StoreLocation $StoreLocation -StoreName $StoreName -SiteAdministrator $SiteAdministrator -ServerType $ServerType
        }
    }else {
        Write-Verbose "Ensure ='Absent' not implemented"
    }
}

function Test-CertificateInTrustedCertificateStore
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
	param(
		[parameter(Mandatory = $true)]
		[System.String]
		$Url,

        [parameter(Mandatory = $false)]
		[System.String]
		$StoreLocation = 'LocalMachine',

        [parameter(Mandatory = $false)]
		[System.String]
		$StoreName = 'Root'
	)
    
    try {
        Write-Verbose "Connecting to $Url to retrieve SSL certificate"
        $certificateState = Get-ArcGISEndpointCertificate -Url $Url
    }
    catch {
        Write-Verbose "Unable to retrieve an SSL certificate from '$Url'. Error: $_"
        return $false
    }

    $cert = $certificateState.Certificate
    try {
        if($certificateState.Errors -eq [System.Net.Security.SslPolicyErrors]::None){
            return $true
        }

        $certificateExists = Test-Path "Cert:\$StoreLocation\$StoreName\$($cert.Thumbprint)"
        if($certificateExists){
            Write-Verbose "Certificate '$($cert.Thumbprint)' already exists in $StoreName store in $StoreLocation"
        }else{
            Write-Verbose "Certificate '$($cert.Thumbprint)' does not exist in $StoreName store in $StoreLocation"
        }
        return $certificateExists
    }
    finally {
        $cert.Dispose()
    }
}

function Import-CertFromServerIntoTrustedCertificateStore
{
	[CmdletBinding()]
	param(
		[parameter(Mandatory = $true)]
		[System.String]
		$Url,

        [parameter(Mandatory = $false)]
		[System.String]
		$StoreLocation = 'LocalMachine',

        [parameter(Mandatory = $false)]
		[System.String]
		$StoreName = 'Root',

        [parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator,
        
        [System.String]
        $ServerType
	)
    
    try {
        Write-Verbose "Connecting to $Url to retrieve SSL certificate"
        $certificateState = Get-ArcGISEndpointCertificate -Url $Url
    }
    catch {
        throw "Unable to retrieve an SSL certificate from '$Url'. Error: $_"
    }

    [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert = $certificateState.Certificate
    try {
        if($SiteAdministrator) {
            $FQDN = Get-FQDN $env:COMPUTERNAME
            $ServerBaseURL = Get-ArcGISComponentBaseUrl -FQDN $FQDN -ComponentName $ServerType
            $Referer = $ServerBaseURL
            $token = Get-ServerToken -URL $ServerBaseURL -Credential $SiteAdministrator -Referer $Referer
            $CertOnDiskPath = Join-Path $env:TEMP "$($cert.Thumbprint).cer"
            try {
                Set-Content -Path $CertOnDiskPath -Value ($cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)) -Encoding Byte -Force

                $Issuer = $null
                foreach($split in ($cert.Subject -split ',')) {
                    $SubSplit = $split -split '='
                    $SubSplitKey = ($SubSplit | Select-Object -First 1).Trim()
                    if($SubSplitKey -ieq 'CN'){
                        $Issuer = ($SubSplit | Select-Object -Last 1).Trim()
                        break
                    }
                }

                $ub = New-Object System.UriBuilder -ArgumentList $Url
                $Alias = "$($ub.Host)-$($ub.Port)"
                Write-Verbose "Thumbprint of certificate is $($cert.Thumbprint). Issuer is $Issuer. Alias being used is $Alias."

                $certNames = Get-AllSSLCertificateForMachine -URL $ServerBaseURL -Token $token.token -Referer $Referer -MachineName $FQDN
                $certificateAliases = @($certNames.certificates | ForEach-Object {
                    if($_ -is [System.String]){ $_ } elseif($_.alias){ $_.alias } elseif($_.name){ $_.name }
                })
                if($certificateAliases -icontains $Alias) {
                    Write-Verbose "Certificate with alias $Alias already exists for Machine $FQDN"
                }else{
                    Write-Verbose "Certificate with alias $Alias not found for Machine $FQDN"
                    $importError = $null
                    try {
                        Import-RootOrIntermediateCertificate -URL $ServerBaseURL -Token $token.token -Referer $Referer `
                            -MachineName $FQDN -CertAlias $Alias -CertificateFilePath $CertOnDiskPath `
                            -CertificateFileName "$($cert.Thumbprint).cer" -ServerType $ServerType `
                            -ThrowOnResponseError $true
                    }
                    catch {
                        $importError = $_
                    }

                    $null = Wait-ForServerRootOrIntermediateCertificateState -URL $ServerBaseURL `
                                    -ServerType $ServerType -Token $token.token -Credential $SiteAdministrator `
                                    -Referer $Referer -MachineName $FQDN -CertificateAlias $Alias `
                                    -ExpectedThumbprint $cert.Thumbprint -OperationError $importError -Verbose
                }
            }
            finally {
                if(Test-Path $CertOnDiskPath -ErrorAction Ignore) {
                    Remove-Item $CertOnDiskPath -Force -ErrorAction Ignore
                }
            }
        }else {
            Write-Verbose "Not importing SSL Certificate into ArcGIS Server"
        }

        if($certificateState.Errors -ne [System.Net.Security.SslPolicyErrors]::None) {
            if(-not(Test-Path "Cert:\$StoreLocation\$StoreName\$($cert.Thumbprint)")) {
                Write-Verbose "Importing Certificate '$($cert.Thumbprint)' to $StoreName store in $StoreLocation"
                $certStore = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store $StoreName, $StoreLocation
                try {
                    $certStore.Open("MaxAllowed")
                    $certStore.Add($cert)
                }
                finally {
                    $certStore.Close()
                }
                Write-Verbose "Imported Certificate to $StoreName store in $StoreLocation"
            }else {
                Write-Verbose "Certificate '$($cert.Thumbprint)' already exists in $StoreName store in $StoreLocation"
            }
        }
    }
    finally {
        $cert.Dispose()
    }
}

Export-ModuleMember -Function *-TargetResource

