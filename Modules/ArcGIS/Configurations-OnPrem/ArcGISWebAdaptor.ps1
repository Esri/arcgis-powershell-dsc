Configuration ArcGISWebAdaptor
{
    param(
        [System.Management.Automation.PSCredential]
        $ServerPrimarySiteAdminCredential,

        [System.Management.Automation.PSCredential]
        $PortalAdministratorCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $PrimaryServerMachine,

        [Parameter(Mandatory=$False)]
        [System.String]
        $PrimaryPortalMachine,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ServerRole,

        [System.Int32]
		$WebSiteId = 1,

        [Parameter(Mandatory=$False)]
        [System.String]
        $OverrideHTTPSBinding = $True
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.0.2
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_IIS_TLS
    Import-DscResource -Name ArcGIS_WebAdaptor

    Node $AllNodes.NodeName
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        $MachineFQDN = Get-FQDN $Node.NodeName

        $Depends = @()

        ArcGIS_xFirewall "WebAdaptorFirewallRules$($Node.NodeName)"
        {
            Name                  = "IIS-ARR" 
            DisplayName           = "IIS-ARR" 
            DisplayGroup          = "IIS-ARR" 
            Ensure                = 'Present'  
            Access                = "Allow" 
            State                 = "Enabled" 
            Profile               = "Public"
            LocalPort             = ("80", "443")                         
            Protocol              = "TCP" 
        }
        $Depends += "[ArcGIS_xFirewall]WebAdaptorFirewallRules$($Node.NodeName)"

        Service "StartW3SVC$($Node.NodeName)"
        {
            Name = 'W3SVC'
            StartupType = 'Automatic'
            Ensure = 'Present'
            State = 'Running'
            DependsOn = $Depends
        }
        $Depends += "[Service]StartW3SVC$($Node.NodeName)"

        if($OverrideHTTPSBinding){
            if($Node.SSLCertificate){
                ArcGIS_IIS_TLS "WebAdaptorCertificateInstall$($Node.NodeName)"
                {
                    WebSiteId               = $WebSiteId
                    ExternalDNSName         = $Node.SSLCertificate.CName
                    Ensure                  = 'Present'
                    CertificateFileLocation = $Node.SSLCertificate.Path
                    CertificatePassword     = $Node.SSLCertificate.Password
                    DependsOn               = $Depends
                }
            }else{
                ArcGIS_IIS_TLS "WebAdaptorCertificateInstall$($Node.NodeName)"
                {
                    WebSiteId       = $WebSiteId
                    ExternalDNSName = $MachineFQDN 
                    Ensure          = 'Present'
                    DependsOn       = $Depends
                }
            }
            $Depends += "[ArcGIS_IIS_TLS]WebAdaptorCertificateInstall$($Node.NodeName)"
        }

        if($Node.IsServerWebAdaptorEnabled -and $PrimaryServerMachine){
            ArcGIS_WebAdaptor "ConfigureServerWebAdaptor$($Node.NodeName)"
            {
                Ensure              = "Present"
                Component           = if($ServerRole -ieq "NotebookServer"){ 'NotebookServer' }elseif($ServerRole -ieq "MissionServer"){ 'MissionServer' }else{ 'Server' }
                HostName            = if($Node.SSLCertificate){ $Node.SSLCertificate.CName }else{ $MachineFQDN } 
                ComponentHostName   = (Get-FQDN $PrimaryServerMachine)
                Context             = $Node.ServerContext
                OverwriteFlag       = $False
                SiteAdministrator   = $ServerPrimarySiteAdminCredential
                AdminAccessEnabled  = if($ServerRole -ieq "NotebookServer" -or $ServerRole -ieq "MissionServer"){ $true }else{ if($Node.AdminAccessEnabled) { $true } else { $false } }
                DependsOn           = $Depends
            }
            $Depends += "[ArcGIS_WebAdaptor]ConfigureServerWebAdaptor$($Node.NodeName)"
        }

        if($Node.IsPortalWebAdaptorEnabled -and $PrimaryPortalMachine){
            ArcGIS_WebAdaptor "ConfigurePortalWebAdaptor$($Node.NodeName)"
            {
                Ensure              = "Present"
                Component           = 'Portal'
                HostName            = if($Node.SSLCertificate){ $Node.SSLCertificate.CName }else{ $MachineFQDN }  
                ComponentHostName   = (Get-FQDN $PrimaryPortalMachine)
                Context             = $Node.PortalContext
                OverwriteFlag       = $False
                SiteAdministrator   = $PortalAdministratorCredential
                DependsOn           = $Depends
            }
        }
    }
}
