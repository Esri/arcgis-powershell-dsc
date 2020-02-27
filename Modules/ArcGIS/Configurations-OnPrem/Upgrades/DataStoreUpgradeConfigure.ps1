Configuration DataStoreUpgradeConfigure{
    param(
        [System.String]
        $Version,

        [System.Management.Automation.PSCredential]
        $SiteAdministratorCredential,

        [System.String]
        $ServerMachineName,

        [System.String]
        $ContentDirectoryLocation,

        [System.String]
        $InstallDir
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.0.0"} 
    Import-DscResource -Name ArcGIS_DataStoreUpgrade
    
    Node $AllNodes.NodeName {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        $ServerHostName = (Get-FQDN $ServerMachineName)

        ArcGIS_DataStoreUpgrade DataStoreConfigUpgrade
        {
            ServerHostName = $ServerHostName
            Ensure = 'Present'
            SiteAdministrator = $SiteAdministratorCredential
            ContentDirectory = $ContentDirectoryLocation
            InstallDir = $InstallDir
        }
    }
}