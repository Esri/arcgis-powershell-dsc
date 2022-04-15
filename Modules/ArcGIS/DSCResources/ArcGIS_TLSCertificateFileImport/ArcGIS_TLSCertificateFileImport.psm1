
<#
    .SYNOPSIS
        Imports a SSL certificate to specified store location on local machines.
    .PARAMETER Ensure
        Take the values Present or Absent. 
        - "Present" ensures the certificate is imported local machines specified store location.
        - "Absent" not implemented.
    .PARAMETER CertificatePath
        Certificate Path from where to fetch the certificate to be installed.
    .PARAMETER StoreLocation
        Location of the Store where the SSL Certificate will be imported
    .PARAMETER StoreName
        Store Name in the Store Location where the SSL Certificate will be imported
    .PARAMETER CertificatePassword
        Credential to the Access the link to import Certificates into Trusted Store.
    
#>

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
        [parameter(Mandatory = $true)]
		[System.String]
		$CertificatePath,

        [parameter(Mandatory = $true)]
		[System.String]
		$StoreLocation = 'LocalMachine',

        [parameter(Mandatory = $true)]
		[System.String]
		$StoreName = 'Root',

        [parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
		$CertificatePassword
	)

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
		$CertificatePath,

        [ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [parameter(Mandatory = $true)]
		[System.String]
		$StoreLocation = 'LocalMachine',

        [parameter(Mandatory = $true)]
		[System.String]
		$StoreName = 'Root',

        [parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
		$CertificatePassword
	)

	
    $result = $false
    if($CertificatePassword -and (Test-Path $CertificatePath)) 
    {
        $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $CertificatePath, $CertificatePassword.GetNetworkCredential().Password
        $Thumbprint = $Cert.Thumbprint
        if(-not(Test-Path "Cert:\$StoreLocation\$StoreName\$($Thumbprint)")) {
            Write-Verbose "Certificate with thumprint '$Thumbprint' does not exist. Import certificate from $CertificatePath in Store:- $StoreName into StoreLocation:- $StoreLocatio"            
        }else {
            Write-Verbose "Certificate with thumprint '$Thumbprint' already exists in Store:- $StoreName in StoreLocation:- $StoreLocation"
            $result = $true
        }
    }    
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
		$CertificatePath,

        [ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [parameter(Mandatory = $true)]
		[System.String]
		$StoreLocation = 'LocalMachine',

        [parameter(Mandatory = $true)]
		[System.String]
		$StoreName = 'Root',

        [parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
		$CertificatePassword
	)

    if($CertificatePassword -and (Test-Path $CertificatePath)) 
    {
        $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $CertificatePath, $CertificatePassword.GetNetworkCredential().Password
        $Thumbprint = $Cert.Thumbprint
        if($Ensure -ieq 'Present') 
        {	   
            if(-not(Test-Path "Cert:\$StoreLocation\$StoreName\$($Thumbprint)")) {
                Write-Verbose "Certificate with thumprint '$Thumbprint' does not exist. Import certificate from $CertificatePath to store:- $StoreName in store location:- $StoreLocation"

                $CertStore = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store $StoreName, $StoreLocation
                $CertStore.Open("MaxAllowed")
                $CertStore.Add($Cert)
                $CertStore.Close()            
                Write-Verbose "Imported Certificate with thumprint '$Thumbprint' to store:- $StoreName in store location:- $StoreLocation" 

            }else {
               Write-Verbose "Certificate with thumprint '$Thumbprint' already exists in Store:- $StoreName in StoreLocation:- $StoreLocation"
            }
        }else {        
            Write-Verbose "Ensure ='Absent' not implemented"
        }
    }
}

Export-ModuleMember -Function *-TargetResource

