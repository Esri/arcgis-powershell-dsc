Configuration ArcGISServerMachineAndTLSSettings
{
    param(
        [Parameter(Mandatory=$true)]
        [System.String]
        $Version,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServerPrimarySiteAdminCredential,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Server','NotebookServer','MissionServer','VideoServer','DataPipelinesServer','VelocityServer')]
        [System.String]
        $ServerType = 'Server',

        [Parameter(Mandatory=$false)]
        [System.Int32]
        $SocMaximumHeapSize = 0,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $EnableHTTPSOnly = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $EnableHSTS = $false
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 5.2.0 -Name ArcGIS_ServerMachineSettings, ArcGIS_Server_TLS

    Node $AllNodes.NodeName
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }

        $DependsOn = @()
        if($ServerType -ieq 'Server' -and $SocMaximumHeapSize -gt 0){
            ArcGIS_ServerMachineSettings ServerSettings
            {
                ServerHostName = $Node.NodeName
                SiteAdministrator = $ServerPrimarySiteAdminCredential
                SocMaximumHeapSize = $SocMaximumHeapSize
            }
            $DependsOn += '[ArcGIS_ServerMachineSettings]ServerSettings'
        }

        $ImportCertChainValue = $true
        $ForceImportCertificate = $false
        if([version]$Version -ge '11.3'){
            if($Node.SSLCertificate -and $null -ne $Node.SSLCertificate.ImportCertificateChain){
                $ImportCertChainValue = $Node.SSLCertificate.ImportCertificateChain
            }
            if($Node.SSLCertificate -and $null -ne $Node.SSLCertificate.ForceImport){
                $ForceImportCertificate = $Node.SSLCertificate.ForceImport
            }
        }

        ArcGIS_Server_TLS "$($ServerType)_TLS_$($Node.NodeName)"
        {
            ServerHostName = $Node.NodeName
            SiteAdministrator = $ServerPrimarySiteAdminCredential
            WebServerCertificateAlias = if($Node.SSLCertificate){$Node.SSLCertificate.CName}else{$null}
            CertificateFileLocation = if($Node.SSLCertificate){$Node.SSLCertificate.Path}else{$null}
            CertificatePassword = if($Node.SSLCertificate){$Node.SSLCertificate.Password}else{$null}
            SslRootOrIntermediate = if($Node.SslRootOrIntermediate){$Node.SslRootOrIntermediate}else{$null}
            EnableHTTPSOnly = $EnableHTTPSOnly
            EnableHSTS = $EnableHSTS
            ServerType = $ServerType
            Version = $Version
            ImportCertificateChain = $ImportCertChainValue
            ForceImportCertificate = $ForceImportCertificate
            DependsOn = $DependsOn
        }
    }
}