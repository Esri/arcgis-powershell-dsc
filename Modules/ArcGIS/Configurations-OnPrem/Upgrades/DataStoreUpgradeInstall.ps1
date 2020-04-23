Configuration DataStoreUpgradeInstall{
    param(
        [System.String]
        $Version,

        [System.Management.Automation.PSCredential]
        $ServiceAccount,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsServiceAccountDomainAccount = $False,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsServiceAccountMSA = $False,
        
        [System.String]
        $InstallerPath,
        
        [System.String]
        $InstallDir
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.0.2"} 
    Import-DscResource -Name ArcGIS_Install
    Import-DscResource -Name ArcGIS_DataStoreUpgrade
    Import-DscResource -Name ArcGIS_xFirewall
    
    Node $AllNodes.NodeName {

        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        $VersionArray = $Version.Split(".")
        $MajorVersion = $VersionArray[1]
        $MinorVersion = $VersionArray[2]

        #$NodeName = $Node.NodeName
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
        if(($MajorVersion -lt 8) -and -not(($MajorVersion -eq 7) -and ($MinorVersion -eq 1))){
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

        if($MajorVersion -gt 7 -and $Node.HasMultiMachineTileCache){
            ArcGIS_xFirewall MultiMachine_TileCache_DataStore_FirewallRules
            {
                Name                  = "ArcGISMultiMachineTileCacheDataStore" 
                DisplayName           = "ArcGIS Multi Machine Tile Cache Data Store" 
                DisplayGroup          = "ArcGIS Tile Cache Data Store" 
                Ensure                = 'Present' 
                Access                = "Allow" 
                State                 = "Enabled" 
                Profile               = ("Domain","Private","Public")
                LocalPort             = ("29079")                        
                Protocol              = "TCP" 
            }
            
            ArcGIS_xFirewall TileCache_FirewallRules_OutBound
            {
                Name                  = "ArcGISTileCacheDataStore-Out" 
                DisplayName           = "ArcGIS TileCache Data Store Out" 
                DisplayGroup          = "ArcGIS TileCache Data Store" 
                Ensure                = 'Present'
                Access                = "Allow" 
                State                 = "Enabled" 
                Profile               = ("Domain","Private","Public")
                LocalPort             = ("29079")       
                Direction             = "Outbound"                        
                Protocol              = "TCP" 
            } 
        }
    }
}