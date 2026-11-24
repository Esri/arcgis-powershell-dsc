$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.Portal.psm1'))

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
        [parameter(Mandatory = $true)]
        [System.String]
        $PortalHostName,

        [parameter(Mandatory = $true)]
		[System.String]
		$PortalAdministrator,
        
        [parameter(Mandatory = $false)]
		[System.String]
        $LicenseFilePath = $null,
        
        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $ImportExternalPublicCertAsRoot = $False,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $EnableUpgradeSiteDebug = $False
	)

    @{}
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
        [parameter(Mandatory = $true)]
        [System.String]
        $PortalHostName,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
        $PortalAdministrator,
        
        [parameter(Mandatory = $false)]
		[System.String]
        $LicenseFilePath = $null,
        
        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $ImportExternalPublicCertAsRoot = $False,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $EnableUpgradeSiteDebug = $False
	)

    $FQDN = Get-FQDN $PortalHostName
    $PortalBaseURL = Get-ArcGISComponentBaseUrl -FQDN $FQDN -ComponentName "Portal"
    $Referer = "https://localhost"

    $result = Test-PortalUpgrade -Url $PortalBaseURL -Referer $Referer -Verbose
    if(-not($result)){
       Invoke-UpgradePortal -Url $PortalBaseURL -Referer $Referer -Version $Version `
                            -EnableUpgradeSiteDebug $EnableUpgradeSiteDebug `
                            -LicenseFilePath $LicenseFilePath -Verbose
    }

    Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "Portal" -Verbose
    Test-PortalAdminHealth -URL $PortalBaseURL -MaxAttempts 10 -Referer $Referer -Verbose
    Test-PortalTokenRetrieved -URL $PortalBaseURL -PortalAdministrator $PortalAdministrator `
                                -Referer $Referer -Verbose -MaxAttempts 20

    $token = Get-PortalToken -URL $PortalBaseURL -Credential $PortalAdministrator -Referer $Referer -Verbose
    if(Test-PostUpgrade -URL $PortalBaseURL -Token $token.token -Referer $Referer -Verbose) {
        Write-Verbose "Post upgrade step successful"
    } else {
        if($LicenseFilePath){
            $token = Get-PortalToken -Url $PortalBaseURL -Credential $PortalAdministrator -Referer $Referer
            Invoke-PopulateLicense -URL $PortalBaseURL -Token $token.token -Referer $Referer -Verbose 
        }

        Test-PortalTokenRetrieved -URL $PortalBaseURL -PortalAdministrator $PortalAdministrator -Referer $Referer -Verbose

        Invoke-PostUpgrade -URL $PortalBaseURL -Token $token.token -Referer $Referer -Verbose

        Test-PortalTokenRetrieved -URL $PortalBaseURL -PortalAdministrator $PortalAdministrator -Referer $Referer -Verbose
    }
   
    if(Get-LivingAtlasStatus -URL $PortalBaseURL -Referer $Referer -Token $token.token){
        Write-Verbose "Upgrading Living Atlas content"
        if(Test-IfLivingAtlasUpgraded -URL $PortalBaseURL -Referer $Referer -Token $token.token){
            Write-Verbose "Living Atlas content is already upgraded."
        }else{
            Write-Verbose "Upgrading Living Atlas content."
            Invoke-UpgradeLivingAtlas -URL $PortalBaseURL -Referer $Referer -Token $token.token
        }
    }

    if($ImportExternalPublicCertAsRoot){
        try{
            $token = Get-PortalToken -URL $PortalBaseURL -Credential $PortalAdministrator -Referer $Referer -Verbose
            $sysProps = Get-PortalSystemProperties -URL $PortalBaseURL -Token $token.token -Referer $Referer
            Write-Verbose "Portal System Properties WebContextUrl is set to '$($sysProps.WebContextURL)'"
            
            $webRequest = [Net.WebRequest]::Create("$($sysProps.WebContextURL)/portaladmin/healthCheck?f=json")
            $response = $null
            try {
                try { $response = $webRequest.GetResponse() } catch {}
                $cert = $webRequest.ServicePoint.Certificate
                if($null -eq $cert){
                    throw "Unable to retrieve the App Gateway certificate from '$($sysProps.WebContextURL)'."
                }
                $bytes = $cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            }
            finally {
                if($null -ne $response){
                    $response.Dispose()
                }
            }
            $ExternalCertAlias = "AppGW-ExternalDNSCerCert"
            $CertOnDiskPath = Join-Path $env:TEMP "$($ExternalCertAlias).cer"
            Set-Content -value $bytes -encoding byte -path $CertOnDiskPath

            $Machines = Get-MachinesInPortalSite -URL $PortalBaseURL -Token $token.token -Referer $Referer
            foreach($m in $Machines){
                $MachineName = $m.machineName
                $Certs = Get-SSLCertificatesForPortal -URL $PortalBaseURL -Token $token.token -Referer $Referer -MachineName $MachineName
                $CertificateAliases = ConvertTo-PortalCertificateAliases -Certificates $Certs.sslCertificates
                if($CertificateAliases -icontains $ExternalCertAlias) {
                    Write-Verbose "Public key of External Certificate used by App Gateway already imported as a root certificate."
                } else {
                    Write-Verbose "Importing Public key of External Certificate used by App Gateway as a root certificate."
                    $importError = $null
                    try {
                        Import-RootOrIntermediateCertificate -URL $PortalBaseURL -CertAlias $ExternalCertAlias `
                            -CertificateFilePath $CertOnDiskPath -MachineName $MachineName -Token $token.token `
                            -Referer $Referer -ThrowOnResponseError $true -Verbose
                    }
                    catch {
                        # The upload may have committed even when its HTTP response was lost.
                        $importError = $_
                    }

                    $tokenValue = Wait-ForPortalRootOrIntermediateCertificateState -URL $PortalBaseURL `
                                    -Token $token.token -Credential $PortalAdministrator -Referer $Referer `
                                    -MachineName $MachineName -CertificateAlias $ExternalCertAlias `
                                    -ExpectedThumbprint $cert.GetCertHashString() -OperationError $importError -Verbose
                    $token = @{ token = $tokenValue }
                }
            }
        }catch{
            Write-Verbose "[WARNING] Unable to import public key of External Certificate used by App Gateway as a root certificate. $_"
        }
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
        
        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$PortalAdministrator,
        
        [parameter(Mandatory = $false)]
		[System.String]
		$LicenseFilePath = $null,
        
        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $ImportExternalPublicCertAsRoot = $False,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $EnableUpgradeSiteDebug = $False
	)

    $FQDN = Get-FQDN $PortalHostName
    $PortalBaseURL = Get-ArcGISComponentBaseUrl -FQDN $FQDN -ComponentName "Portal"
    $Referer = "https://localhost"
    $result = $false
    Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "Portal" -MaxWaitTimeInSeconds 600 -SleepTimeInSeconds 15 -Verbose

    $result = Test-PortalUpgrade -Url $PortalBaseURL -Referer $Referer -Verbose
    if($result){
        $result = Test-PortalAdminHealth -URL $PortalBaseURL -Referer $Referer -Verbose
    }

    if($result){
        $token = Get-PortalToken -URL $PortalBaseURL -Credential $PortalAdministrator -Referer $Referer -Verbose
        $result = Test-PostUpgrade -URL $PortalBaseURL -Token $token.token -Referer $Referer -Verbose
        if(-not($result)) {
            Write-Verbose "Post upgrade step pending."
        }
    }

    if($result){
        try {
            $token = Get-PortalToken -URL $PortalBaseURL -Credential $PortalAdministrator -Referer $Referer -Verbose
            if(Get-LivingAtlasStatus -URL $PortalBaseURL -Referer $Referer -Token $token.token){
                Write-Verbose "Checking if Living Atlas Content needs to be upgraded"
                if(Test-IfLivingAtlasUpgraded -URL $PortalBaseURL -Referer $Referer -Token $token.token){
                    Write-Verbose "Living Atlas content already upgraded."
                }else{
                    Write-Verbose "Living Atlas content needs upgradation."
                    $result = $false
                }
            }
        } catch {
            Write-Verbose $_
            $result = $false
        }
    }
    $result 
}

function Test-PortalTokenRetrieved
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $Referer = 'https://localhost',

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$PortalAdministrator,

        [System.Int32]
        $MaxAttempts = 40
    )

    Write-Verbose "Waiting for portal to start."
    try {
        $token = Get-PortalToken -Url $URL -Credential $PortalAdministrator -Referer $Referer -MaxAttempts $MaxAttempts -Verbose
        if(-not($token.token)) {
            throw "Unable to retrieve Portal Token for '$($PortalAdministrator.UserName)'"
        }
        Write-Verbose "Portal token retrieved for '$($PortalAdministrator.UserName)'"
    } catch {
        Write-Verbose $_
    }
}

Export-ModuleMember -Function *-TargetResource