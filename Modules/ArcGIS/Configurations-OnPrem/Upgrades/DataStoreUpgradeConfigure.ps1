Configuration DataStoreUpgradeConfigure{
    param(
        [System.String]
        $Version,

        [System.Management.Automation.PSCredential]
        $ServerPrimarySiteAdminCredential,

        [System.String]
        $ServerMachineName,

        [System.String]
        $ContentDirectoryLocation,

        [System.String]
        $InstallDir
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.0.2 
    Import-DscResource -Name ArcGIS_DataStoreUpgrade
    
    Node $AllNodes.NodeName {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        ArcGIS_DataStoreUpgrade DataStoreConfigUpgrade
        {
            ServerHostName = $ServerMachineName
            Ensure = 'Present'
            SiteAdministrator = $ServerPrimarySiteAdminCredential
            ContentDirectory = $ContentDirectoryLocation
            InstallDir = $InstallDir
        }
    }
}
