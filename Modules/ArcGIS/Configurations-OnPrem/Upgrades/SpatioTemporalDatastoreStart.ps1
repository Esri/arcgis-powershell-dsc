Configuration SpatioTemporalDatastoreStart{
    param(
        [System.Management.Automation.PSCredential]
        $SiteAdministratorCredential,

        [System.String]
        $ServerMachineName
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.0.0"} 
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
            SiteAdministrator = $SiteAdministratorCredential
            Ensure = 'Present'
        }
    }
}