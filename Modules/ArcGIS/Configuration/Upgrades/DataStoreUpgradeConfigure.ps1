Configuration DataStoreUpgradeConfigure{
    param(
        [System.Management.Automation.PSCredential]
        $PrimarySiteAdmin,

        [System.String]
        $ServerMachineName,

        [System.String]
        $ContentDirectoryLocation,

        [System.String]
        $InstallDir
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName ArcGIS 
    Import-DscResource -Name ArcGIS_Install
    Import-DscResource -Name ArcGIS_DataStoreUpgrade
    
    Node $AllNodes.NodeName {
        $ServerHostName = [System.Net.DNS]::GetHostByName($ServerMachineName).HostName

        ArcGIS_DataStoreUpgrade DataStoreConfigUpgrade
        {
            ServerHostName = $ServerHostName
            Ensure = 'Present'
            SiteAdministrator = $PrimarySiteAdmin
            ContentDirectory = $ContentDirectoryLocation
            InstallDir = $InstallDir
        }
    }
}