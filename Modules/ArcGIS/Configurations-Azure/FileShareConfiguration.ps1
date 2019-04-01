Configuration FileShareConfiguration
{
	param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServiceCredential

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServiceCredentialIsDomainAccount = 'false'

        ,[Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $SiteAdministratorCredential

		,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $MachineAdministratorCredential

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $PortalEndpoint

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServerEndpoint

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $SelfSignedSSLCertificatePassword

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $PortalMachineNames

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServerMachineNames

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $ExternalDNSHostName

        ,[Parameter(Mandatory=$false)]
        [System.Int32]
        $OSDiskSize = 0

         ,[Parameter(Mandatory=$false)]
        [System.String]
        $EnableDataDisk

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $FileShareName = 'fileshare'

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $GitOpenSSL32BitInstaller = 'https://github.com/git-for-windows/git/releases/download/v2.21.0.windows.1/Git-2.21.0-32-bit.exe'

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $DebugMode
    )

    Import-DscResource -Name MSFT_xDisk
    Import-DscResource -Name MSFT_xSmbShare
    Import-DscResource -Name ArcGIS_Disk

    $FileShareHostName = $env:ComputerName
    $FolderName = $ExternalDNSHostName.Substring(0, $ExternalDNSHostName.IndexOf('.')).ToLower()
    $FileShareLocalPath = (Join-Path $env:SystemDrive $FileShareName)
    $CertsFolder = Join-Path $FileShareLocalPath 'Certs'
    if(-not(Test-Path $CertsFolder)){
        New-Item -Path $CertsFolder -ItemType directory -ErrorAction Stop
    }
    $IsDebugMode = $DebugMode -ieq 'true'
    $IsServiceCredentialDomainAccount = $ServiceCredentialIsDomainAccount -ieq 'true'

    function Create-SelfSignedCertificateWithSANs
    {
        param(
            [string]
            $CertificateFilePath,

            [string]
            $CertificatePassword,

            [string]
            $Endpoint,

            $Nodes
        )
        $DnsNames = @($Endpoint)
        if($Nodes) {
            $Nodes | ForEach-Object { $DnsNames += Get-FQDN $_ }
        }
        Write-Verbose "Generating a self signed certificate with the DNS names $($DnsNames -join ',') for the Endpoint $($EndPoint)"
        if([Environment]::OSVersion.Version.Major -ge 10) {
            $Cert = New-SelfSignedCertificate -DnsName @($DnsNames) -CertStoreLocation Cert:\LocalMachine\My -NotBefore ([System.DateTime]::UtcNow).AddDays(-5) -NotAfter ([System.DateTime]::UtcNow).AddYears(5)
        }else {
            $Cert = New-SelfSignedCertificate -DnsName @($DnsNames) -CertStoreLocation Cert:\LocalMachine\My
        }
        Write-Verbose "Saving (exporting) file to $CertificateFilePath"
        Export-PfxCertificate -Force -Password (ConvertTo-SecureString -AsPlainText $CertificatePassword -Force) -FilePath $CertificateFilePath -Cert "Cert:\LocalMachine\My\$($Cert.Thumbprint)"
        Remove-Item "Cert:\LocalMachine\My\$($Cert.Thumbprint)" -Force -ErrorAction Ignore
        Write-Verbose "Saved cert with thumbprint $($Cert.Thumbprint) file to $CertificateFilePath"
    }

    function Add-IPAddressSANToSelfSignedCertificate{
        param(
            [string]
            $CertificateFolder,

            [string]
            $CertificateName,

            [string]
            $CertificatePassword,

            [string]
            $Endpoint,

            $Nodes
        )

        $OutputCertFilePath = Join-Path $CertificateFolder "$($CertificateName).pfx"
        $OutputCertPemFilePath = Join-Path $CertificateFolder "$($CertificateName).pem"
        $openssl = Join-Path ${env:ProgramFiles(x86)} "Git\usr\bin\openssl.exe"

        $certConfigString = '[req]
distinguished_name  = req_distinguished_name
x509_extensions     = v3_req
prompt              = no

[req_distinguished_name]
CN          = [CN]

[v3_req]
keyUsage           = keyEncipherment, dataEncipherment
extendedKeyUsage   = serverAuth
subjectAltName     = @alt_names

[alt_names]
[ALTNAMES]'

        $NewCertConfigString = $certConfigString.replace('[CN]',$Endpoint)

        $altNames = [System.Text.StringBuilder]::new()
        if($Nodes) {
            $i = 1
            $Nodes | ForEach-Object {
                $DnsNames = Get-FQDN $_
                [void]$altNames.AppendLine( "DNS.$i  = $DnsNames" )
                $i++
            }
            [void]$altNames.AppendLine( "DNS.$i  = $Endpoint" )
        }
        [void]$altNames.AppendLine( "IP.1  = $Endpoint" )

        $NewCertConfigString = $NewCertConfigString.replace('[ALTNAMES]',$altNames.ToString())
        $ConfigFilePath = Join-Path $CertificateFolder "$($CertificateName)-config.txt"

        $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
        [System.IO.File]::WriteAllLines($ConfigFilePath, $NewCertConfigString, $Utf8NoBomEncoding)
        Start-Process $openssl -ArgumentList "pkcs12 -in $OutputCertFilePath -out $OutputCertPemFilePath -nodes -password pass:$CertificatePassword" -NoNewWindow -Wait -Verbose
        Start-Process $openssl -ArgumentList "req -x509 -nodes -days 3650 -newkey rsa:4096 -keyout $OutputCertPemFilePath -out $OutputCertPemFilePath -config $ConfigFilePath" -NoNewWindow -Wait -Verbose 
        Start-Process $openssl -ArgumentList "pkcs12 -export -in $OutputCertPemFilePath -out $OutputCertFilePath -name $CertificateName -passout pass:$CertificatePassword" -NoNewWindow -Wait -Verbose
        Remove-Item $ConfigFilePath
    }

    $TempFolder = Join-Path ([System.IO.Path]::GetTempPath()) "git-openssl"
    if(Test-Path $TempFolder)
    {
        Remove-Item -Path $TempFolder -Recurse 
    }
    if(-not(Test-Path $TempFolder))
    {
        New-Item $TempFolder -ItemType directory            
    }
    $ExeFile = Join-Path $TempFolder 'git.exe'

    (New-Object System.Net.WebClient).Downloadfile($GitOpenSSL32BitInstaller, $ExeFile)
    Start-Process $ExeFile -ArgumentList "/VERYSILENT /NORESTART /NOCANCEL /SP- /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS /COMPONENTS=""icons,ext\reg\shellhere,assoc,assoc_sh""" -NoNewWindow -Wait
    
    if($PortalEndpoint -and $SelfSignedSSLCertificatePassword -and $PortalMachineNames -and ($SelfSignedSSLCertificatePassword.GetNetworkCredential().Password -ine 'Placeholder')) {
        $PortalOutputCertFilePath = Join-Path $CertsFolder 'SSLCertificateForPortal.pfx'
        if(-not(Test-Path $PortalOutputCertFilePath)) {
            Create-SelfSignedCertificateWithSANs -CertificateFilePath $PortalOutputCertFilePath -CertificatePassword $SelfSignedSSLCertificatePassword.GetNetworkCredential().Password -Endpoint $PortalEndpoint -Nodes ($PortalMachineNames -split ',')
            Add-IPAddressSANToSelfSignedCertificate -CertificateName 'SSLCertificateForPortal' -CertificateFolder $CertsFolder -CertificatePassword $SelfSignedSSLCertificatePassword.GetNetworkCredential().Password -Endpoint $PortalEndpoint -Nodes ($PortalMachineNames -split ',')
        }
    }
    if($ServerEndpoint -and $SelfSignedSSLCertificatePassword -and $ServerMachineNames -and ($SelfSignedSSLCertificatePassword.GetNetworkCredential().Password -ine 'Placeholder')) {
        $ServerOutputCertFilePath = Join-Path $CertsFolder 'SSLCertificateForServer.pfx'
        if(-not(Test-Path $ServerOutputCertFilePath)) {
            Create-SelfSignedCertificateWithSANs -CertificateFilePath $ServerOutputCertFilePath -CertificatePassword $SelfSignedSSLCertificatePassword.GetNetworkCredential().Password -Endpoint $ServerEndpoint -Nodes ($ServerMachineNames -split ',')
            Add-IPAddressSANToSelfSignedCertificate -CertificateName 'SSLCertificateForServer' -CertificateFolder $CertsFolder -CertificatePassword $SelfSignedSSLCertificatePassword.GetNetworkCredential().Password -Endpoint $ServerEndpoint -Nodes ($ServerMachineNames -split ',')
        }
    }

    Remove-Item -Path $TempFolder -Recurse

	Node localhost
	{
        if($OSDiskSize -gt 0)
        {
            ArcGIS_Disk OSDiskSize
            {
                DriveLetter = ($env:SystemDrive -replace ":" )
                SizeInGB    = $OSDiskSize
            }
        }

        if($EnableDataDisk -ieq 'true')
        {
            xDisk DataDisk
            {
                DiskNumber  =  2
                DriveLetter = 'F'
            }
        }
        if(-Not($IsServiceCredentialDomainAccount)){
            User ArcGIS_RunAsAccount
            {
                UserName       = $ServiceCredential.UserName
                Password       = $ServiceCredential
                FullName       = 'ArcGIS Service Account'
                Ensure         = 'Present'
                PasswordChangeRequired = $false
                PasswordNeverExpires = $true
            }
        }

        File FileShareLocationPath
		{
			Type						= 'Directory'
			DestinationPath				= $FileShareLocalPath
			Ensure						= 'Present'
			Force						= $true
		}

        File ContentDirectoryLocationPath
		{
			Type						= 'Directory'
			DestinationPath				= (Join-Path $FileShareLocalPath "$FolderName/portal/content")
			Ensure						= 'Present'
			Force						= $true
		}

        $DataStoreBackupsLocalPath = (Join-Path $FileShareLocalPath "$FolderName/datastore/dbbackups")
        File DataStoreBackupsLocationPath
		{
			Type						= 'Directory'
			DestinationPath				= $DataStoreBackupsLocalPath
			Ensure						= 'Present'
			Force						= $true
		}

		$Accounts = @('NT AUTHORITY\SYSTEM')
		if($ServiceCredential) { $Accounts += $ServiceCredential.GetNetworkCredential().UserName }
		if($MachineAdministratorCredential -and ($MachineAdministratorCredential.GetNetworkCredential().UserName -ine 'Placeholder') -and ($MachineAdministratorCredential.GetNetworkCredential().UserName -ine $ServiceCredential.GetNetworkCredential().UserName)) { $Accounts += $MachineAdministratorCredential.GetNetworkCredential().UserName }
        xSmbShare FileShare
		{
			Ensure						= 'Present'
			Name						= $FileShareName
			Path						= $FileShareLocalPath
			FullAccess					= $Accounts
            DependsOn					= if(-Not($IsServiceCredentialDomainAccount)){ @('[User]ArcGIS_RunAsAccount','[File]FileShareLocationPath')}else{ @('[File]FileShareLocationPath')}
		}
	}
}