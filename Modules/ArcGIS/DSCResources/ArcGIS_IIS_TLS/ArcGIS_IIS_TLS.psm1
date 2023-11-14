$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

<#
    .SYNOPSIS
        Check for an SSL Certificate. If not present Installs and Configures the SSL Certificate. If certifcate not provided, creates a self signed certificate and configures it.
    .PARAMETER Ensure
        Indicates to make sure a SSL Certificate is Installed and Configured on the Machine. Take the values Present or Absent. 
        - "Present" ensures that a SSL Certificate is Installed if provided and Configured on the Machine, if not already done. 
        - "Absent" ensures that a SSL Certificate is uninstalled, if present and configured - Not Implemented.
    .PARAMETER WebSiteId
        Id of the website with which the SSL Certificate needs to be Binded with.
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
		[System.Int32]
		$WebSiteId,

        [parameter(Mandatory = $true)]
		[System.String]
		$ExternalDNSName
	)
    
    $null
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
        [parameter(Mandatory = $true)]
		[System.Int32]
		$WebSiteId,

        [parameter(Mandatory = $true)]
        [System.String]
		$ExternalDNSName,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,
		
        [System.String]
        $CertificateFileLocation,

        [System.Management.Automation.PSCredential]
        $CertificatePassword
	)

    

	$CurrVerbosePreference = $VerbosePreference # Save current preference
	$VerbosePreference = 'SilentlyContinue' # quieten it to ignore verbose output from Importing WebAdmin (bug in Powershell for this module) 
	Import-Module WebAdministration | Out-Null
	$VerbosePreference = $CurrVerbosePreference # reset it back to previous preference

    Invoke-EnsureWebBindingForHTTPS -WebSiteId $WebSiteId

    $CertToInstall = $null
    if($CertificateFileLocation -and ($null -ne $CertificatePassword) -and (Test-Path $CertificateFileLocation)){
        Write-Verbose "Importing Certificate from $CertificateFileLocation"
        $CertToInstall = Import-PfxCertificateFromFile -CertificatePath $CertificateFileLocation -pfxPassword $CertificatePassword
        Write-Verbose "Installing CA Issued Certificate $($CertToInstall) for DnsName $ExternalDNSName"       
        Install-SSLCertificateIntoIIS -DnsName $ExternalDNSName -CertificateToInstall $CertToInstall
    }
    else {
        Write-Verbose "Installing Self-Signed Certificate for DnsName $ExternalDNSName"
        Install-SSLCertificateIntoIIS -DnsName $ExternalDNSName 
    }
}


function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.Int32]
		$WebSiteId,

        [parameter(Mandatory = $true)]
        [System.String]
		$ExternalDNSName,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,
		
        [System.String]
        $CertificateFileLocation,

        [System.Management.Automation.PSCredential]
        $CertificatePassword
	)

	$result = $false
    $Port = 443
    
    if($CertificateFileLocation -and ($null -ne $CertificatePassword) -and (Test-Path $CertificateFileLocation)){
        $pfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 
        if($null -ne $CertificatePassword) {
            $pfx.Import($CertificateFileLocation,$CertificatePassword.GetNetworkCredential().Password,'DefaultKeySet') 
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


function Get-CommonNameSplits
{
    [CmdletBinding()]
	param
	(
        [System.String]
        $SubjectName
    )

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


function Install-SSLCertificateIntoIIS
{
    [CmdletBinding()]
	param
	(
        [System.String]
        $DnsName,

        [System.Int32]
        $Port = 443,

        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $CertificateToInstall = $null
    )

	<#
    ###
    ### Ensure binding exists
    ###
    Write-Verbose "Install-SSLCertificateIntoIIS"     
    $binding = Get-WebBinding -Protocol https -Port $Port    
    if($null -eq $binding) 
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
    if($null -eq $CertificateToInstall) {
        Write-Verbose "Creating New-SelfSignedCertificate for DNS:- $DnsName"
        if($null -ne (Get-Command -Name 'New-SelfSignedCertificate' -ErrorAction Ignore)) {
            Write-Verbose 'Creating using New-SelfSignedCertificate'
            $Cert = New-SelfSignedCertificate -DnsName $DnsName -CertStoreLocation cert:\LocalMachine\My 
            Write-Verbose 'Finished Creating using New-SelfSignedCertificate'
        }
        else {
            throw "New-SelfSignedCertificate isn't available on the machine. Please create provide a certificate and try again."
        }
    }
    else {
        $SubjectName = $CertificateToInstall.SubjectName.Name
        if(-not($SubjectName)){
            $SubjectName = $CertificateToInstall.Subject
        }

        Write-Verbose "Installing existing certificate with SubjectName = $SubjectName and Thumbprint $($CertificateToInstall.Thumbprint)"

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
            Write-Verbose "Installing existing certificate with SubjectName $($SubjectName)"
            $SubjectNameSplits = Get-CommonNameSplits $SubjectName
            if($null -eq $SubjectNameSplits) { throw "Unable to split $SubjectName" }        
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
            if($null -eq $Cert){
                throw "Unable to find certificate with SubjectName = $SubjectName and Thumbprint $($CertificateToInstall.Thumbprint) in 'cert:\LocalMachine\My'"
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
 
function Import-PfxCertificateFromFile
{
    [CmdletBinding()]
	param
	(
        [System.String]
        $CertificatePath,

        [System.String]
        $CertRootStore = "LocalMachine",

        [System.String]
        $CertStore = "My",

        [System.Management.Automation.PSCredential]
        $pfxPassword = $null
    )

    $pfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 
    if($null -ne $pfxPassword) {
        $pfx.Import($CertificatePath,$pfxPassword.GetNetworkCredential().Password,"Exportable,PersistKeySet") 
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

function Invoke-EnsureWebBindingForHTTPS
{
    [CmdletBinding()]	
	param
	(
		[parameter(Mandatory = $true)]
		[System.Int32]
		$WebSiteId,

        [parameter(Mandatory = $false)]
		[System.Int32]
		$Port = 443
    )
    ###
    ### Ensure binding exists
    ###      
    $binding = Get-WebBinding -Protocol https -Port $Port    
    if($null -eq $binding) 
    {      
        Write-Verbose 'Setting up SSL Binding with self signed certificate'
        Write-Verbose "Creating Binding on Port $Port for https"
        $WebSiteName = (Get-Website | Where-Object {$_.ID -eq $WebSiteId}).Name
        New-WebBinding -Name $WebSiteName -IP "*" -Port $Port -Protocol https
        Write-Verbose "Finished Creating Binding on Port $Port for https"
    }   
}

Export-ModuleMember -Function *-TargetResource