Configuration ArcGISWebAdaptorJava
{
    param(
        [ValidateNotNullorEmpty()]
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
		$WebSiteId = 1
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.1.1"}
    Import-DscResource -Name ArcGIS_xFirewall
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
            Name                  = "WebServer-RV" 
            DisplayName           = "WebServer-RV" 
            DisplayGroup          = "WebServer-RV" 
            Ensure                = 'Present'  
            Access                = "Allow" 
            State                 = "Enabled" 
            Profile               = "Public"
            LocalPort             = ("80", "443")                         
            Protocol              = "TCP" 
        }
        $Depends += "[ArcGIS_xFirewall]WebAdaptorFirewallRules$($Node.NodeName)"

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