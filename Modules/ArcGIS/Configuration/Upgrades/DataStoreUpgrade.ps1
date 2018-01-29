Configuration DataStoreUpgrade{
    param(
        [System.String]
        $Version,

        [System.Management.Automation.PSCredential]
        $ServiceAccount,

        [System.Management.Automation.PSCredential]
        $PrimarySiteAdmin,

        [System.String]
        $InstallerPath,

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
        $NodeName = $Node.NodeName
        #ArcGIS Data Store 10.3 or 10.3.1, you must manually provide this account full control to your ArcGIS Data Store content directory 
        ArcGIS_Install DataStoreUpgrade
        { 
            Name = "DataStore"
            Version = $Version
            Path = $InstallerPath
            Arguments = "/qb USER_NAME=$($ServiceAccount.UserName) PASSWORD=$($ServiceAccount.GetNetworkCredential().Password)";
            Ensure = "Present"
        }
        
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