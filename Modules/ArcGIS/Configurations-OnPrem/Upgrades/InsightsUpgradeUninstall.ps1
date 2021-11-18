Configuration InsightsUpgradeUninstall{
    param(
        [System.String]
        $Version
    )
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.3.0"}
    Import-DscResource -Name ArcGIS_Install
    
    Node $AllNodes.NodeName
    {   
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        ArcGIS_Install InsightsUninstall
        {
            Name = "Insights"
            Version = $Version
            Ensure = "Absent"
        }
    }
}