Configuration ArcGISPortalTLSSettings
{
    param(
        [Parameter(Mandatory=$True)]
        [System.String]
        $Version,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $PortalAdministratorCredential,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $EnableHSTS = $False
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 5.1.2 -Name ArcGIS_Portal_TLS

    Node $AllNodes.NodeName
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        $ImportCertChainValue = $true  # default to true
        $ForceImportCertificate = $false
        if ([version]$Version -ge [version]"11.3") {
            if ($Node.SSLCertificate -and $Node.SSLCertificate.ImportCertificateChain -ne $null) {
                $ImportCertChainValue = $Node.SSLCertificate.ImportCertificateChain
            }
            if ($Node.SSLCertificate -and $Node.SSLCertificate.ForceImport -ne $null) {
                $ForceImportCertificate = $Node.SSLCertificate.ForceImport
            }
        }

        ArcGIS_Portal_TLS ArcGIS_Portal_TLS
        {
            Version                     = $Version
            PortalHostName              = $Node.NodeName
            SiteAdministrator           = $PortalAdministratorCredential
            WebServerCertificateAlias   = if($Node.SSLCertificate){$Node.SSLCertificate.CName}else{$null}
            CertificateFileLocation     = if($Node.SSLCertificate){$Node.SSLCertificate.Path}else{$null}
            CertificatePassword         = if($Node.SSLCertificate){$Node.SSLCertificate.Password}else{$null}
            SslRootOrIntermediate       = if($Node.SslRootOrIntermediate){$Node.SslRootOrIntermediate}else{$null}
            EnableHSTS                  = $EnableHSTS
            ImportCertificateChain      = $ImportCertChainValue
            ForceImportCertificate      = $ForceImportCertificate
        }        
    }   
}
