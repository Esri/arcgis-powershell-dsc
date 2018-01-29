Configuration DataStoreUpgradeInstall{
    param(
        [System.String]
        $Version,

        [System.Management.Automation.PSCredential]
        $ServiceAccount,

        [System.String]
        $InstallerPath,
        
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
        
        # Fix for BDS Not Upgrading Bug - Setup needs to run as local account system
        # But in that case it cannot access (C:\Windows\System32\config\systemprofile\AppData\Local)

        ArcGIS_WindowsService ArcGIS_DataStore_Service_Stop
        {
            Name = 'ArcGIS Data Store'
            Credential = $ServiceAccount
            StartupType = 'Manual'
            State = 'Stopped'
            DependsOn = @('[ArcGIS_Install]DataStoreUpgrade')
        }

        File CreateUpgradeFile
        {
          Ensure          = "Present"
          DestinationPath = "$($InstallDir)\etc\upgrade.txt"
          Contents        = ""
          Type            = "File"
          DependsOn = @('[ArcGIS_WindowsService]ArcGIS_DataStore_Service_Stop')
        }  

        ArcGIS_WindowsService ArcGIS_DataStore_Service_Start
        {
            Name = 'ArcGIS Data Store'
            Credential = $ServiceAccount
            StartupType = 'Automatic'
            State = 'Running'
            DependsOn = @('[File]CreateUpgradeFile')
        }
    }
}