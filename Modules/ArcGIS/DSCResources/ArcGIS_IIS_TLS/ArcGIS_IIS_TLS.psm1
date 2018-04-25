<#
    .SYNOPSIS
        Check for an SSL Certificate. If not present Installs and Configures the SSL Certificate. If certifcate not provided, creates a self signed certificate and configures it.
    .PARAMETER Ensure
        Indicates to make sure a SSL Certificate is Installed and Configured on the Machine. Take the values Present or Absent. 
        - "Present" ensures that a SSL Certificate is Installed if provided and Configured on the Machine, if not already done. 
        - "Absent" ensures that a SSL Certificate is uninstalled, if present and configured - Not Implemented.
    .PARAMETER WebSiteName
        Name of the website with which the SSL Certificate needs to be Binded with.
    .PARAMETER ExternalDNSName
        Name of the ExternalDNSName with which the SSL Certificates needs to be Binded with.
    .PARAMETER CertificateFileLocation
        A Path to a Physical Location or Network Share Address for the SSL Certificate File.
    .PARAMETER CertificatePassword
        Secret key or password for the SSL Certificate.
#>

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$WebSiteName,

        [parameter(Mandatory = $true)]
		[System.String]
		$ExternalDNSName
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
		$WebSiteName,

        [parameter(Mandatory = $true)]
        [System.String]
		$ExternalDNSName,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,
		
        [System.String]
        $CertificateFileLocation,

        [System.String]
        $CertificatePassword
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

	$CurrVerbosePreference = $VerbosePreference # Save current preference
	$VerbosePreference = 'SilentlyContinue' # quieten it to ignore verbose output from Importing WebAdmin (bug in Powershell for this module) 
	Import-Module WebAdministration | Out-Null
	$VerbosePreference = $CurrVerbosePreference # reset it back to previous preference

    Ensure-WebBindingForHTTPS -WebSiteName $WebSiteName

    $CertToInstall = $null
    if($CertificateFileLocation -and $CertificatePassword -and (Test-Path $CertificateFileLocation)){
        Write-Verbose "Importing Certificate from $CertificateFileLocation"
        $CertToInstall = Import-PfxCertificateFromFile -CertificatePath $CertificateFileLocation -pfxPassword $CertificatePassword
        Write-Verbose "Installing CA Issued Certificate $($CertToInstall) for DnsName $ExternalDNSName"       
        Install-SSLCertificateIntoIIS -DnsName $ExternalDNSName -CertificateToInstall $CertToInstall 
    }
    else {
        Write-Verbose "Installing Self-Signed Certificate for DnsName $ExternalDNSName"
        Install-SSLCertificateIntoIIS -DnsName $ExternalDNSName 
    }    
		
	<#
	Write-Verbose 'Hardening SSL on web server'
    $reboot = $false
    $reboot = Harden-SSLOnMachine
    Write-Verbose 'Hardened SSL on web server'
    If ($reboot) 
    {
	    Write-Verbose 'Rebooting now..'                    
	    #$global:DSCMachineStatus = 1
    }	
	#>
}


function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$WebSiteName,

        [parameter(Mandatory = $true)]
        [System.String]
		$ExternalDNSName,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,
		
        [System.String]
        $CertificateFileLocation,

        [System.String]
        $CertificatePassword
	)
 
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

	$result = $false
    $Port = 443
    
    if($CertificateFileLocation -and $CertificatePassword -and (Test-Path $CertificateFileLocation)){
        $pfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 
        if($CertificatePassword -and $CertificatePassword.Length -gt 0) {
            $pfx.Import($CertificateFileLocation,$CertificatePassword,'DefaultKeySet') 
        }
        else {
            $pfx.Import($CertificateFileLocation)
        }
        $CertRootStore = "LocalMachine"
        $CertStore = "My"
        $CertPath = "Cert:\$CertRootStore\$CertStore\$($pfx.Thumbprint)"
        if(Test-Path $CertPath)  {
            Write-Verbose "Certificate found in $CertPath"
            $result = $true
        }
        if($result){
            $result = $false
            $CurrVerbosePreference = $VerbosePreference # Save current preference
            $VerbosePreference = 'SilentlyContinue' # quieten it to ignore verbose output from Importing WebAdmin (bug in Powershell for this module) 
            Import-Module WebAdministration | Out-Null
            $VerbosePreference = $CurrVerbosePreference # reset it back to previous preference
            $binding = Get-WebBinding -Protocol https -Port $Port
            if($binding)
            {
                Write-Verbose "IIS has a web binding at Port $Port. Checking for the Certificate"
                $IISCertPath = "IIS:\SslBindings\0.0.0.0!$Port"
                if(Test-Path $IISCertPath) {
                    if ($binding.certificateHash -ieq $pfx.Thumbprint) {
                        $result = $true
                    }
                }
            }
        }
    }else{
        # Self Signed option
        $CurrVerbosePreference = $VerbosePreference # Save current preference
		$VerbosePreference = 'SilentlyContinue' # quieten it to ignore verbose output from Importing WebAdmin (bug in Powershell for this module) 
		Import-Module WebAdministration | Out-Null
		$VerbosePreference = $CurrVerbosePreference # reset it back to previous preference
        if(Get-WebBinding -Protocol https -Port $Port)
        {
            Write-Verbose "IIS has a web binding at Port $Port. Checking for the Certificate"
            $IISCertPath = "IIS:\SslBindings\0.0.0.0!$Port"
            if(Test-Path $IISCertPath) {                
                $result = $true
            }
        }
    }  

    if($Ensure -ieq 'Present') {
        $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}



function Set-CryptoSetting {
   param (
		$keyindex,
		$value,
		$valuedata,
		$valuetype,
		$restart
   )
     
    $regKey = $regkeys[$keyindex]
 
	# Check for existence of registry key, and create if it does not exist
	if (!(Test-Path -Path $regkeys[$keyindex])) {
		Write-Verbose "Creating key: $regKey$nl"
		New-Item $regkeys[$keyindex] | Out-Null
	}
 
	# Get data of registry value, or null if it does not exist
	$val = (Get-ItemProperty -Path $regkeys[$keyindex] -Name $value -ErrorAction SilentlyContinue).$value
 
	if ($val -eq $null) {
		# Value does not exist - create and set to desired value
		Write-Verbose "Value $regKey\$value does not exist, creating...$nl"
		New-ItemProperty -Path $regkeys[$keyindex] -Name $value -Value $valuedata -PropertyType $valuetype | Out-Null
		$restart = $True
	} else {
		# Value does exist - if not equal to desired value, change it
		if ($val -ne $valuedata) {
		  Write-Verbose "Value $regKey\$value not correct, setting it$nl"
		  Set-ItemProperty -Path $regkeys[$keyindex] -Name $value -Value $valuedata
		  $restart = $True
		}
		else
		{
			Write-Verbose "Value $regKey\$value already set correctly$nl"
		}
	}
	return $restart
}
 
# Special function that can handle keys that have a forward slash in them. Powershell changes the forward slash
# to a backslash in any function that takes a path.
function Set-CryptoKey {
   param (
	  $parent,
	  $childkey,
	  $value,
	  $valuedata,
	  $valuetype,
	  $restart
	)
 
	$child = $parent.OpenSubKey($childkey, $true);
 
	if ($child -eq $null) {
		# Need to create child key
		$child = $parent.CreateSubKey($childkey);
	}
 
	# Get data of registry value, or null if it does not exist
	$val = $child.GetValue($value);
 
	if ($val -eq $null) {
		# Value does not exist - create and set to desired value
		Write-Verbose "Value $child\$value does not exist, creating...$nl"
		$child.SetValue($value, $valuedata, $valuetype);
		$restart = $True
	} else {
		# Value does exist - if not equal to desired value, change it
		if ($val -ne $valuedata) {
			Write-Verbose "Value $child\$value not correct, setting it$nl"
			$child.SetValue($value, $valuedata, $valuetype);
			$restart = $True
		}
		else
		{
			Write-Verbose "Value $child\$value already set correctly$nl"
		}
	}
 
	return $restart
}

function Harden-SSLOnMachine()
{
    #$nl = [Environment]::NewLine
    $regkeys = @(
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server",
    "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
    )
 
    # Cipher order as per Mozilla: https://wiki.mozilla.org/Security/Server_Side_TLS (Intermediate set - as mapped to Windows names)
    $cipherorder = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256,"
    $cipherorder += "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384,"
    $cipherorder += "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521,"
    $cipherorder += "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521,"
    #$cipherorder += "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,"
    $cipherorder += "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521,"
    $cipherorder += "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384,"
    $cipherorder += "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521,"
    #$cipherorder += "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,"
    $cipherorder += "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521,"
    $cipherorder += "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521,"
    #$cipherorder += "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,"
    $cipherorder += "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256,"
    $cipherorder += "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384,"
    $cipherorder += "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521,"
    $cipherorder += "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521,"
    #$cipherorder += "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,"
    $cipherorder += "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521,"
    $cipherorder += "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521,"
    #$cipherorder += "TLS_RSA_WITH_AES_128_CBC_SHA256,"
    #$cipherorder += "TLS_RSA_WITH_AES_128_CBC_SHA,"
    #$cipherorder += "TLS_RSA_WITH_AES_256_CBC_SHA256,"
    #$cipherorder += "TLS_RSA_WITH_AES_256_CBC_SHA"
 
    
    # If any settings are changed, this will change to $True 
    $reboot = $false
    
    # Check for existence of parent registry keys (SSL 2.0 and SSL 3.0), and create if they do not exist
    For ($i = 9; $i -le 12; $i = $i + 3) {
	    If (!(Test-Path -Path $regkeys[$i])) {
		    New-Item $regkeys[$i] | Out-Null
	    }
    }

    # Ensure SSL 2.0 disabled for client
    $reboot = Set-CryptoSetting 10 DisabledByDefault 1 DWord $reboot
 
    # Ensure SSL 2.0 disabled for server
    $reboot = Set-CryptoSetting 11 Enabled 0 DWord $reboot
 
    # Ensure SSL 3.0 disabled for client
    $reboot = Set-CryptoSetting 13 DisabledByDefault 1 DWord $reboot
 
    # Ensure SSL 3.0 disabled for server
    $reboot = Set-CryptoSetting 14 Enabled 0 DWord $reboot
 
    # Set cipher priority
    $reboot = Set-CryptoSetting 15 Functions $cipherorder String $reboot
 
    # We have to do something special with these keys if they contain a forward-slash since
    # Powershell converts the forward slash to a backslash and it screws up the creation of the key!
    #
    # Just create these parent level keys first
    $cipherskey = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers",$true)
    If ($cipherskey -eq $null) {
	    $cipherskey = (get-item HKLM:\).CreateSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers")
    }
 
    $hasheskey = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes",$true)
    If ($hasheskey -eq $null) {
	    $hasheskey = (get-item HKLM:\).CreateSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes")
    }
 
    # Then add sub keys using a different function
    # Disable RC4, DES, EXPORT, eNULL, aNULL, PSK and aECDH
    $reboot = Set-CryptoKey $cipherskey "RC4 128/128" Enabled 0 DWord $reboot
    $reboot = Set-CryptoKey $cipherskey "Triple DES 168" Enabled 0 DWord $reboot
    $reboot = Set-CryptoKey $cipherskey "RC2 128/128" Enabled 0 DWord $reboot
    $reboot = Set-CryptoKey $cipherskey "RC4 64/128" Enabled 0 DWord $reboot
    $reboot = Set-CryptoKey $cipherskey "RC4 56/128" Enabled 0 DWord $reboot
    $reboot = Set-CryptoKey $cipherskey "RC2 56/128" Enabled 0 DWord $reboot
    $reboot = Set-CryptoKey $cipherskey "DES 56" Enabled 0 DWord $reboot  # It's not clear whether the key is DES 56 or DES 56/56
    $reboot = Set-CryptoKey $cipherskey "DES 56/56" Enabled 0 DWord $reboot
    $reboot = Set-CryptoKey $cipherskey "RC4 40/128" Enabled 0 DWord $reboot
    $reboot = Set-CryptoKey $cipherskey "RC2 40/128" Enabled 0 DWord $reboot
 
    # Disable MD5, enable SHA (which should be by default)
    $reboot = Set-CryptoKey $hasheskey "MD5" Enabled 0 DWord $reboot
    $reboot = Set-CryptoKey $hasheskey "SHA" Enabled 0xFFFFFFFF DWord $reboot
 
    $cipherskey.Close();
    $hasheskey.Close();
 
    $reboot
}

function Get-CommonNameSplits([string]$SubjectName)
{
    if(-not($SubjectName)){
        return $SubjectName
    }
    [string[]]$Splits = $SubjectName.Split(',', [StringSplitOptions]::RemoveEmptyEntries)
    foreach($Split in $Splits)
    {
        [string[]]$SubSplits = $Split.Split('=',[StringSplitOptions]::RemoveEmptyEntries)
        if($SubSplits -and ($SubSplits.Length -gt 1) -and ('CN' -ieq $SubSplits[0])){
            [string[]]$InnerSplits = $SubSplits[1].Split('.',[StringSplitOptions]::RemoveEmptyEntries)  
            return $InnerSplits
        }
    }
    return $null
}


function Install-SSLCertificateIntoIIS([string]$DnsName, [int]$Port = 443, [System.Security.Cryptography.X509Certificates.X509Certificate2]$CertificateToInstall = $null)
{
	<#
    ###
    ### Ensure binding exists
    ###
    Write-Verbose "Install-SSLCertificateIntoIIS"     
    $binding = Get-WebBinding -Protocol https -Port $Port    
    if($binding -eq $null) 
    {        
        Write-Verbose 'Setting up SSL Binding with self signed certificate'
        Write-Verbose "Creating Binding on Port $Port for https"
        New-WebBinding -Name "Default Web Site" -IP "*" -Port $Port -Protocol https
        Write-Verbose "Finished Creating Binding on Port $Port for https"
    } 
	#>   
        
    ###
    ### Ensure certificate (if not create one)
    ###
    if($CertificateToInstall -eq $null) {
        Write-Verbose "Creating New-SelfSignedCertificate for DNS:- $DnsName"
        if((Get-Command -Name 'New-SelfSignedCertificate' -ErrorAction Ignore) -ne $null) {
            Write-Verbose 'Creating using New-SelfSignedCertificate'
            $Cert = New-SelfSignedCertificate -DnsName $DnsName -CertStoreLocation cert:\LocalMachine\My 
            Write-Verbose 'Finished Creating using New-SelfSignedCertificate'
        }
        else {
            Write-Verbose 'Creating using Create-SelfSignedCertificate'
            $Cert = Create-SelfSignedCertificate -subject $DnsName
            Write-Verbose 'Finished Creating using Create-SelfSignedCertificate'
        }
    }
    else {
        Write-Verbose "Installing existing certificate with Thumbprint $($CertificateToInstall.Thumbprint)"

        $AllCerts = Get-ChildItem cert:\LocalMachine\My 
        foreach($ACert in $AllCerts){
            if($CertificateToInstall.Thumbprint -ieq $ACert.Thumbprint) 
            {
                $Cert = $ACert
            }
        }
        
        #Search based on Name as a fallback - Backward compatibility
        if(-not($Cert)) 
        {
            $SubjectName = $CertificateToInstall.SubjectName.Name
            if(-not($SubjectName)){
                $SubjectName = $CertificateToInstall.Subject
            }
            Write-Verbose "Installing existing certificate with SubjectName $($SubjectName)"
            $SubjectNameSplits = Get-CommonNameSplits $SubjectName
            if($SubjectNameSplits -eq $null) { throw "Unable to split $SubjectName" }        
            $AllCerts = Get-ChildItem cert:\LocalMachine\My 
            foreach($ACert in $AllCerts){
                $SubjectForCert = $ACert.Subject
                if($SubjectForCert -and $SubjectForCert.Length -gt 0) {
                    $CertSubjectNameSplits = Get-CommonNameSplits $SubjectForCert
                    if($CertSubjectNameSplits -and ($SubjectNameSplits.Length -eq $CertSubjectNameSplits.Length)) {
                        $MisMatch = $false   
                        [int]$count = $SubjectNameSplits.Length
                        for($m = 0; $m -lt $count; $m++){
                            if($SubjectNameSplits[$m] -ine $CertSubjectNameSplits[$m] -and $SubjectNameSplits[$m] -ine '*') {
                                $MisMatch = $true
                                break
                            }
                        }            
                        if($MisMatch -eq $false) {
                            $Cert = $ACert
                            break
                        } 
                    }
                }
            }
        }

        if(-not($Cert)) 
        {
            $Cert = Get-ChildItem cert:\LocalMachine\My | Where-Object { $_.Thumbprint -ieq $CertificateToInstall.Thumbprint } | Select-Object -First 1 
            if($Cert -eq $null){
                throw "Unable to find certificate with SubjectName = $SubjectName in 'cert:\LocalMachine\My'"
            }               
        }              
    }
    
    $InstallPath = "IIS:\SslBindings\0.0.0.0!$Port"
    if(Test-Path $InstallPath) {
        Write-Verbose "Removing existing certificate at $InstallPath"
        Remove-Item -Path $InstallPath -Force
    }
    Write-Verbose "Installing Certificate with thumbprint $($Cert.Thumbprint) and subject $($Cert.Subject) into IIS Binding for Port $Port"
    New-Item  $InstallPath -Value $Cert
    Write-Verbose 'Finished Installing Certificate'
}
 
function Create-SelfSignedCertificate([string]$subject)
{

$lifeTimeDays = 365*5
$keySize = 2048

$useSHA256 = $true
# The default SHA1 algorithm is more compatible but less secure then SHA256

# The following area includes the enumerations used with the interfaces
$AlternativeNameType = @{
XCN_CERT_ALT_NAME_UNKNOWN = 0
XCN_CERT_ALT_NAME_OTHER_NAME = 1
XCN_CERT_ALT_NAME_RFC822_NAME = 2
XCN_CERT_ALT_NAME_DNS_NAME = 3
XCN_CERT_ALT_NAME_DIRECTORY_NAME = 5
XCN_CERT_ALT_NAME_URL = 7
XCN_CERT_ALT_NAME_IP_ADDRESS = 8
XCN_CERT_ALT_NAME_REGISTERED_ID = 9
XCN_CERT_ALT_NAME_GUID = 10
XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME = 11
}

$ObjectIdGroupId = @{
XCN_CRYPT_ANY_GROUP_ID = 0
XCN_CRYPT_HASH_ALG_OID_GROUP_ID = 1
XCN_CRYPT_ENCRYPT_ALG_OID_GROUP_ID = 2
XCN_CRYPT_PUBKEY_ALG_OID_GROUP_ID = 3
XCN_CRYPT_SIGN_ALG_OID_GROUP_ID = 4
XCN_CRYPT_RDN_ATTR_OID_GROUP_ID = 5
XCN_CRYPT_EXT_OR_ATTR_OID_GROUP_ID = 6
XCN_CRYPT_ENHKEY_USAGE_OID_GROUP_ID = 7
XCN_CRYPT_POLICY_OID_GROUP_ID = 8
XCN_CRYPT_TEMPLATE_OID_GROUP_ID = 9
XCN_CRYPT_LAST_OID_GROUP_ID = 9
XCN_CRYPT_FIRST_ALG_OID_GROUP_ID = 1
XCN_CRYPT_LAST_ALG_OID_GROUP_ID = 4
XCN_CRYPT_OID_DISABLE_SEARCH_DS_FLAG = 0x80000000
XCN_CRYPT_KEY_LENGTH_MASK = 0xffff0000
}

$X509KeySpec = @{
XCN_AT_NONE = 0 # The intended use is not identified.
# This value should be used if the provider is a
# Cryptography API: Next Generation (CNG) key storage provider (KSP).
XCN_AT_KEYEXCHANGE = 1 # The key can be used for encryption or key exchange.
XCN_AT_SIGNATURE = 2 # The key can be used for signing.
}

$X509PrivateKeyExportFlags = @{
XCN_NCRYPT_ALLOW_EXPORT_NONE = 0
XCN_NCRYPT_ALLOW_EXPORT_FLAG = 0x1
XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG = 0x2
XCN_NCRYPT_ALLOW_ARCHIVING_FLAG = 0x4
XCN_NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG = 0x8
}

$X509PrivateKeyUsageFlags = @{
XCN_NCRYPT_ALLOW_USAGES_NONE = 0
XCN_NCRYPT_ALLOW_DECRYPT_FLAG = 0x1
XCN_NCRYPT_ALLOW_SIGNING_FLAG = 0x2
XCN_NCRYPT_ALLOW_KEY_AGREEMENT_FLAG = 0x4
XCN_NCRYPT_ALLOW_ALL_USAGES = 0xffffff
}

$X509CertificateEnrollmentContext = @{
ContextUser = 0x1
ContextMachine = 0x2
ContextAdministratorForceMachine = 0x3
}

$X509KeyUsageFlags = @{
DIGITAL_SIGNATURE = 0x80 # Used with a Digital Signature Algorithm (DSA)
# to support services other than nonrepudiation,
# certificate signing, or revocation list signing.
KEY_ENCIPHERMENT = 0x20 # Used for key transport.
DATA_ENCIPHERMENT = 0x10 # Used to encrypt user data other than cryptographic keys.
}

$EncodingType = @{
XCN_CRYPT_STRING_BASE64HEADER = 0
XCN_CRYPT_STRING_BASE64 = 0x1
XCN_CRYPT_STRING_BINARY = 0x2
XCN_CRYPT_STRING_BASE64REQUESTHEADER = 0x3
XCN_CRYPT_STRING_HEX = 0x4
XCN_CRYPT_STRING_HEXASCII = 0x5
XCN_CRYPT_STRING_BASE64_ANY = 0x6
XCN_CRYPT_STRING_ANY = 0x7
XCN_CRYPT_STRING_HEX_ANY = 0x8
XCN_CRYPT_STRING_BASE64X509CRLHEADER = 0x9
XCN_CRYPT_STRING_HEXADDR = 0xa
XCN_CRYPT_STRING_HEXASCIIADDR = 0xb
XCN_CRYPT_STRING_HEXRAW = 0xc
XCN_CRYPT_STRING_NOCRLF = 0x40000000
XCN_CRYPT_STRING_NOCR = 0x80000000
}

$InstallResponseRestrictionFlags = @{
AllowNone = 0x00000000
AllowNoOutstandingRequest = 0x00000001
AllowUntrustedCertificate = 0x00000002
AllowUntrustedRoot = 0x00000004
}

$X500NameFlags = @{
XCN_CERT_NAME_STR_NONE = 0
XCN_CERT_SIMPLE_NAME_STR = 1
XCN_CERT_OID_NAME_STR = 2
XCN_CERT_X500_NAME_STR = 3
XCN_CERT_XML_NAME_STR = 4
XCN_CERT_NAME_STR_SEMICOLON_FLAG = 0x40000000
XCN_CERT_NAME_STR_NO_PLUS_FLAG = 0x20000000
XCN_CERT_NAME_STR_NO_QUOTING_FLAG = 0x10000000
XCN_CERT_NAME_STR_CRLF_FLAG = 0x8000000
XCN_CERT_NAME_STR_COMMA_FLAG = 0x4000000
XCN_CERT_NAME_STR_REVERSE_FLAG = 0x2000000
XCN_CERT_NAME_STR_FORWARD_FLAG = 0x1000000
XCN_CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG = 0x10000
XCN_CERT_NAME_STR_ENABLE_T61_UNICODE_FLAG = 0x20000
XCN_CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG = 0x40000
XCN_CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG = 0x80000
XCN_CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG = 0x100000
}

$ObjectIdPublicKeyFlags = @{
XCN_CRYPT_OID_INFO_PUBKEY_ANY = 0
XCN_CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG = 0x80000000
XCN_CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG = 0x40000000
}

$AlgorithmFlags = @{
AlgorithmFlagsNone = 0
AlgorithmFlagsWrap = 0x1
}

# Only the following RDNs are supported in the subject name
# IX500DistinguishedName Interface
# http://msdn.microsoft.com/en-us/library/aa377051%28v=VS.85%29.aspx
# C, CN, E, EMAIL, DC, G, GivenName, I, L, O, OU, S, ST, STREET, SN, T, TITLE

# Note we build the subject as CN=subject
$subjectName = "CN=" + $subject
$objSubjectDN = New-Object -ComObject X509Enrollment.CX500DistinguishedName
$objSubjectDN.Encode($subjectName, $X500NameFlags.XCN_CERT_NAME_STR_NONE)

# Build a private key
$objKey = New-Object -ComObject X509Enrollment.CX509PrivateKey
$objKey.ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
$objKey.KeySpec = $X509KeySpec.XCN_AT_KEYEXCHANGE
$objKey.KeyUsage = $X509PrivateKeyUsageFlags.XCN_NCRYPT_ALLOW_ALL_USAGES
$objKey.Length = $keySize
$objKey.MachineContext = $TRUE
$objKey.ExportPolicy = $X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG
$objKey.Create()

# Add the Server Authentication EKU OID
$objServerAuthenticationOid = New-Object -ComObject X509Enrollment.CObjectId
$strServerAuthenticationOid = "1.3.6.1.5.5.7.3.1"
$objServerAuthenticationOid.InitializeFromValue($strServerAuthenticationOid)

$objEkuoids = New-Object -ComObject X509Enrollment.CObjectIds
$objEkuoids.add($objServerAuthenticationOid)
$objEkuext = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage
$objEkuext.InitializeEncode($objEkuoids)

# Set the Key Usage to Key Encipherment and Digital Signature
$keyUsageExt = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
$keyUsageExt.InitializeEncode($X509KeyUsageFlags.KEY_ENCIPHERMENT -bor `
$X509KeyUsageFlags.DIGITAL_SIGNATURE )

$strTemplateName = "" # We don't use a certificate template
$cert = New-Object -ComObject X509Enrollment.CX509CertificateRequestCertificate
# Notice we use $X509CertificateEnrollmentContext.ContextMachine
$cert.InitializeFromPrivateKey($X509CertificateEnrollmentContext.ContextMachine, `
   $objKey, `
   $strTemplateName)
$cert.X509Extensions.Add($keyUsageExt)
$cert.Subject = $objSubjectDN
$cert.Issuer = $cert.Subject

if ($useSHA256)
{
  # Set the hash algorithm to sha256 instead of the default sha1
  $hashAlgorithmObject = New-Object -ComObject X509Enrollment.CObjectId
  $hashAlgorithmObject.InitializeFromAlgorithmName( `
  $ObjectIdGroupId.XCN_CRYPT_HASH_ALG_OID_GROUP_ID, `
  $ObjectIdPublicKeyFlags.XCN_CRYPT_OID_INFO_PUBKEY_ANY, `
  $AlgorithmFlags.AlgorithmFlagsNone, "SHA256")
  $cert.HashAlgorithm = $hashAlgorithmObject
}

# We subtract one day from the start time to avoid timezone or other 
#   time issues where cert is not yet valid
$SubtractDays = New-Object System.TimeSpan 1, 0, 0, 0, 0
$curdate = get-date
$cert.NotBefore = $curdate.Subtract($SubtractDays)
$cert.NotAfter = $cert.NotBefore.AddDays($lifeTimeDays)
$cert.X509Extensions.Add($objEkuext)
$cert.Encode()

# Now we create the cert from the request we have built up and 
#   install it into the certificate store
$enrollment = New-Object -ComObject X509Enrollment.CX509Enrollment
$enrollment.InitializeFromRequest($cert)
$certdata = $enrollment.CreateRequest($EncodingType.XCN_CRYPT_STRING_BASE64HEADER)
$strPassword = ""
$enrollment.InstallResponse($InstallResponseRestrictionFlags.AllowUntrustedCertificate, `
  $certdata, $EncodingType.XCN_CRYPT_STRING_BASE64HEADER, $strPassword)

  Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -ieq "CN=$subject" } | Select-Object -First 1
}

function Import-PfxCertificateFromFile([string]$CertificatePath,[string]$CertRootStore = "LocalMachine",[string]$CertStore = "My", [string]$pfxPassword = $null)
{
    $pfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 
    if($pfxPassword -and $pfxPassword.Length -gt 0) {
        $pfx.Import($CertificatePath,$pfxPassword,"Exportable,PersistKeySet") 
    }
    else {
        $pfx.Import($CertificatePath)
    }
    $CertPath = "Cert:\$CertRootStore\$CertStore\$($pfx.Thumbprint)"    
    if(Test-Path $CertPath)  {        
        Remove-Item $CertPath -Force
    }
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($CertStore,$CertRootStore)
    $store.Open("MaxAllowed")
    $store.Add($pfx)
    $store.Close()
    $pfx
}

function Ensure-WebBindingForHTTPS
{
    [CmdletBinding()]	
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$WebSiteName,

        [parameter(Mandatory = $false)]
		[System.Int32]
		$Port = 443
    )
    ###
    ### Ensure binding exists
    ###      
    $binding = Get-WebBinding -Protocol https -Port $Port    
    if($binding -eq $null) 
    {        
        Write-Verbose 'Setting up SSL Binding with self signed certificate'
        Write-Verbose "Creating Binding on Port $Port for https"
        New-WebBinding -Name $WebSiteName -IP "*" -Port $Port -Protocol https
        Write-Verbose "Finished Creating Binding on Port $Port for https"
    }   
}
Export-ModuleMember -Function *-TargetResource

