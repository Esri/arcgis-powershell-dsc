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
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.5.0 -Name ArcGIS_Install, ArcGIS_InstallPatch, ArcGIS_xFirewall
    
    Node $AllNodes.NodeName {

        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        $VersionArray = $Version.Split(".")
        $Depends = @()
        #$NodeName = $Node.NodeName
        #ArcGIS Data Store 10.3 or 10.3.1, you must manually provide this account full control to your ArcGIS Data Store content directory 
        ArcGIS_Install DataStoreUpgrade
        { 
            Name = "DataStore"
            Version = $Version
            Path = $InstallerPath
            Extract = $InstallerIsSelfExtracting
            Arguments = if($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -or $VersionArray[1] -gt 8)){ "/qn ACCEPTEULA=YES"}else{ "/qn" }
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

        if(($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -or $VersionArray[1] -gt 7)) -and $Node.HasMultiMachineTileCache){
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

    if(($VersionArray[0] -gt 11 -or ($VersionArray[0] -eq 11 -or $VersionArray[1] -ge 5)) -and $Node.HasRelationalStore){
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
