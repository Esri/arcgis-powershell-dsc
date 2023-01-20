Configuration InsightsUpgradeUninstall{
    param(
        [System.String]
        $Version
    )
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.0.2
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
