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

        [parameter(Mandatory = $true)]
		[uint32]
		$HttpsPort
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

	$null
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

        [parameter(Mandatory = $true)]
		[uint32]
		$HttpsPort
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null	 
    $AppPath = $ApplicationPath.TrimStart('/')
    $Url =  "https://$($HostName):$($HttpsPort)/$AppPath"
    Write-Verbose "Test Certificate existence from '$Url' in $StoreLocation and $StoreName"
    $result = Is-CertificateInTrustedCertificateStore -Url $Url -StoreLocation $StoreLocation -StoreName $StoreName
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

        [parameter(Mandatory = $true)]
		[uint32]
		$HttpsPort
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    if($Ensure -ieq 'Present') 
    {
	    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null	   
        $AppPath = $ApplicationPath.TrimStart('/')
        $Url =  "https://$($HostName):$($HttpsPort)/$AppPath"
        Write-Verbose "Certificate import from '$Url' into $StoreLocation and $StoreName"     
        if(-not(Is-CertificateInTrustedCertificateStore -Url $Url -StoreLocation $StoreLocation -StoreName $StoreName)) {
            Write-Verbose "Import certificate from $Url"
            Import-CertFromServerIntoTrustedCertificateStore -Url $Url -StoreLocation $StoreLocation -StoreName $StoreName 
        }

    }else {
        Write-Verbose "Ensure ='Absent' not implemented"
    }
}

function Is-CertificateInTrustedCertificateStore
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
		$StoreName = 'Root'
	)
    
    $global:certCheck = $false
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert = $args[1]
        [System.Net.Security.SslPolicyErrors]$errors = $args[3]
        if($errors -ne [System.Net.Security.SslPolicyErrors]::None) {
            
            if(-not(Test-Path "Cert:\$StoreLocation\$StoreName\$($cert.Thumbprint)")) {
                Write-Verbose "Certificate '$($cert.Thumbprint)' does not exist in $StoreName store in $StoreLocation"
            }else {
                $global:certCheck = $true
                Write-Verbose "Certificate '$($cert.Thumbprint)' already exists in $StoreName store in $StoreLocation"
            }
        }else{
            $global:certCheck = $true
        }
    }

    try
    {
        Write-Verbose "Connecting to $Url to retrieve SSL certificate"
        [System.Net.HttpWebRequest]$request = [System.Net.WebRequest]::Create($Url)
        [System.Net.HttpWebResponse]$response = $request.GetResponse()
        $respStream = $response.GetResponseStream()
        Write-Verbose "Successfully connected to $Url"
    }
    catch{
        Write-Verbose "Connecting to $Url. Expected Error:- $_"
    }
    finally 
    {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    }   
	$global:certCheck
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
		$StoreName = 'Root'
	)
    
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert = $args[1]
        [System.Net.Security.SslPolicyErrors]$errors = $args[3]    

        $CertOnDiskPath = Join-Path $env:TEMP "$($cert.Thumbprint).cer"
        Set-Content -Path $CertOnDiskPath -Value ($cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)) -Encoding Byte -Force
            
        $Subject = $cert.Subject            
        $Splits = $Subject -split ','
        foreach($split in $Splits) {
            $SubSplit = $split -split '='
            $SubSplitKey = $SubSplit | Select-Object -First 1
            $SubSplitValue = $SubSplit | Select-Object -Last 1
            if($SubSplit -ieq 'CN'){
                $Issuer = $SubSplitValue
                $break
            }
        }
            
        $ub = New-Object System.UriBuilder -ArgumentList $Url
        $Alias = "$($ub.Host)-$($ub.Port)"
        Write-Verbose "Thumbprint of certificate is $($cert.Thumbprint). Issue is $($Issuer). Alias being used is $($Alias)."
        if(Test-Path $CertOnDiskPath -ErrorAction Ignore) {
            Remove-Item $CertOnDiskPath -Force -ErrorAction Ignore
        }
        if(-not(Test-Path "Cert:\$StoreLocation\$StoreName\$($cert.Thumbprint)")) {
            Write-Verbose "Importing Certificate '$($cert.Thumbprint)' to $StoreName store in $StoreLocation"
            $certStore = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store $StoreName, $StoreLocation
            $certStore.Open("MaxAllowed")
            $certStore.Add($cert)
            $certStore.Close()            
            Write-Verbose "Imported Certificate to $StoreName store in $StoreLocation"
        }else {
            Write-Verbose "Certificate '$($cert.Thumbprint)' already exists in $StoreName store in $StoreLocation"
        }
    }

    try
    {
        Write-Verbose "Connecting to $Url to retrieve SSL certificate"
        [System.Net.HttpWebRequest]$request = [System.Net.WebRequest]::Create($Url)
        [System.Net.HttpWebResponse]$response = $request.GetResponse()
        $respStream = $response.GetResponseStream()
        Write-Verbose "Successfully connected to $Url"
    }
    catch{
        Write-Verbose "Connecting to $Url. Expected Error:- $_"
    }
    finally 
    {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    }
}

Export-ModuleMember -Function *-TargetResource

