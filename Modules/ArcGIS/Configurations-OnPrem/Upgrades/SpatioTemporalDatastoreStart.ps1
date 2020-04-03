Configuration SpatioTemporalDatastoreStart{
    param(
        [System.Management.Automation.PSCredential]
        $ServerPrimarySiteAdminCredential,

        [System.String]
        $ServerMachineName
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.0.1"} 
    Import-DscResource -Name ArcGIS_BDSUpgradePost

    Node $AllNodes.NodeName {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        $ServerMachineHostName = (Get-FQDN $ServerMachineName)
        
        ArcGIS_BDSUpgradePost SpatioTemporalDatastoreStart{
            ServerHostName = $ServerMachineHostName
            SiteAdministrator = $ServerPrimarySiteAdminCredential
            Ensure = 'Present'
        }
    }
}