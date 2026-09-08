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

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $InstallerIsSelfExtracting = $True,

        [System.String]
        $PatchesDir,

        [System.Array]
        $PatchInstallOrder,
        
        [System.String]
        $InstallDir,

        [System.Boolean]
        $DownloadPatches = $False,

        [System.Boolean]
        $SkipPatchInstalls = $False,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $EnableMSILogging = $false
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 5.1.2 -Name ArcGIS_Install, ArcGIS_InstallPatch, ArcGIS_xFirewall
    
    Node $AllNodes.NodeName {

        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        $Depends = @()
        #$NodeName = $Node.NodeName
        
        ArcGIS_Install DataStoreUpgrade
        { 
            Name = "DataStore"
            Version = $Version
            Path = $InstallerPath
            Extract = $InstallerIsSelfExtracting
            Arguments = "/qn ACCEPTEULA=YES"
            ServiceCredential = $ServiceAccount
            ServiceCredentialIsDomainAccount =  $IsServiceAccountDomainAccount
            ServiceCredentialIsMSA = $IsServiceAccountMSA
            EnableMSILogging = $EnableMSILogging
            Ensure = "Present"
        }
        $Depends += '[ArcGIS_Install]DataStoreUpgrade'

        if ($PatchesDir -and -not($SkipPatchInstalls)) {
            ArcGIS_InstallPatch DatastoreInstallPatch
            {
                Name = "DataStore"
                Version = $Version
                DownloadPatches = $DownloadPatches
                PatchesDir = $PatchesDir
                PatchInstallOrder = $PatchInstallOrder
                Ensure = "Present"
            }
            $Depends += "[ArcGIS_InstallPatch]DatastoreInstallPatch"
        }

        Service ArcGIS_DataStore_Service_Start
        {
            Name = 'ArcGIS Data Store'
            StartupType = "Automatic"
            State = "Running"
            DependsOn = $Depends
        }

        if($Node.HasMultiMachineTileCache){
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
    
    
        if($Node.HasRelationalStore){
            if([version]$Version -ge "11.0"){
                ArcGIS_xFirewall Queue_DataStore_FirewallRules
                {
                    Name                  = "ArcGISQueueDataStore-Out" 
                    DisplayName           = "ArcGIS Queue Data Store Out" 
                    DisplayGroup          = "ArcGIS Data Store" 
                    Ensure                = 'Present'  
                    Access                = "Allow" 
                    State                 = "Enabled" 
                    Profile               = ("Domain","Private","Public")
                    LocalPort             = ("45671","45672")                      
                    Protocol              = "TCP" 
                }
            }

            if([version]$Version -ge "11.5"){
                ArcGIS_xFirewall MemoryCache_DataStore_FirewallRules
                {
                    Name                  = "ArcGISMemoryCacheDataStore" 
                    DisplayName           = "ArcGIS Memory Cache Data Store" 
                    DisplayGroup          = "ArcGIS Data Store" 
                    Ensure                = 'Present'  
                    Access                = "Allow" 
                    State                 = "Enabled" 
                    Profile               = ("Domain","Private","Public")
                    LocalPort             = ("9820","9840","9850")
                    Protocol              = "TCP" 
                } 
            }
        }

        if($Node.HasObjectStore){
            $ObjectStoreServerPorts = @("29878", "29879")
            if([version]$Version -ge "11.5"){
                $ObjectStoreServerPorts = @("29879", "19879")
            }

            ArcGIS_xFirewall ObjectDataStore_FirewallRules
            {
                Name                  = "ArcGISObjectDataStore" 
                DisplayName           = "ArcGIS Object Data Store" 
                DisplayGroup          = "ArcGIS Object Data Store" 
                Ensure                = 'Present'
                Access                = "Allow" 
                State                 = "Enabled" 
                Profile               = ("Domain","Private","Public")
                LocalPort             = $ObjectStoreServerPorts                      
                Protocol              = "TCP" 
            }

            if($Node.HasMultiMachineObjectStore){
                $ObjectStorePorts = @("9820", "9830", "9840", "9880", "29874", "29876", "29882","29875","29877","29883","29860-29863","29858","29859")
                if([version]$Version -ge "11.5"){
                    $ObjectStorePorts = @("29860-29863","19864","29858","29859","28981","29895","9856", "9857", "9872", "9886", "9894")
                }

                ArcGIS_xFirewall ObjectDataStore_MultiMachine_FirewallRules
                {
                    Name                  = "ArcGISObjectMultiMachineDataStore" 
                    DisplayName           = "ArcGIS Object Multi Machine Data Store" 
                    DisplayGroup          = "ArcGIS Object Multi Machine Data Store" 
                    Ensure                = 'Present'
                    Access                = "Allow" 
                    State                 = "Enabled" 
                    Profile               = ("Domain","Private","Public")
                    LocalPort             = $ObjectStorePorts
                    Protocol              = "TCP" 
                }
            }
        }
    }
}
