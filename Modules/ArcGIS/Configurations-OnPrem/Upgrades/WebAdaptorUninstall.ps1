Configuration WebAdaptorUninstall{
    param(
        [System.String]
        $Version,
        
        [System.String]
        $Context,
        
        [ValidateSet("ServerWebAdaptor","PortalWebAdaptor")]
        [System.String]
        $WebAdaptorRole,

        [System.Int32]
        $WebSiteId
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.1.1"}
    Import-DscResource -Name ArcGIS_Install

    Node $AllNodes.NodeName {
        
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }

        ArcGIS_Install WebAdaptorUninstall
        { 
            Name = $WebAdaptorRole
            Version = $Version
            WebAdaptorContext = $Context
            Arguments = "WEBSITE_ID=$($WebSiteId)"
            Ensure = "Absent"
        }
    }
}