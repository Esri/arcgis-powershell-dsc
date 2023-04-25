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

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $EnableMSILogging = $false
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.1.0 
    Import-DscResource -Name ArcGIS_Install
    Import-DscResource -Name ArcGIS_InstallPatch
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

        if ($PatchesDir) {
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

        # Fix for BDS Not Upgrading Bug - Setup needs to run as local account system
        # But in that case it cannot access (C:\Windows\System32\config\systemprofile\AppData\Local)
        if(($VersionArray[0] -eq 10 -and $VersionArray[1] -lt 8) -and -not($Version -eq "10.7.1"))
        {
            Script CreateUpgradeFile
            {
                GetScript = {
                    $null
                }
                SetScript = {
                    $ChangeObject = @{StartMode="Manual";}
                    $DataStoreServiceStop = Get-CimInstance Win32_Service -filter "name='ArcGIS Data Store'" 
                    $DataStoreStopServiceChangeModeReturnValue = ($DataStoreServiceStop | Invoke-CimMethod -Name Change -Arguments $ChangeObject).ReturnValue
                    if($DataStoreStopServiceChangeModeReturnValue -eq 0){
                        $DataStoreServiceStopReturnValue = $DataStoreServiceStop | Invoke-CimMethod -Name StopService
                        if($DataStoreServiceStopReturnValue -eq 0){
                            Write-Verbose "Service Stop Operation successful."
                            if (!(Test-Path "$($using:InstallDir)\etc\upgrade.txt"))
                            {
                                New-Item -path "$($using:InstallDir)\etc\" -name "upgrade.txt" -type "file" -value ""
                                Write-Verbose "Created new file "
                            }
                            $DataStoreServiceStart = Get-CimInstance Win32_Service -filter "name='ArcGIS Data Store'" 
                            $DataStoreStartServiceChangeModeReturnValue = ($DataStoreServiceStart | Invoke-CimMethod -Name Change -Arguments $ChangeObject).ReturnValue
                            if( $DataStoreStartServiceChangeModeReturnValue -eq 0){
                                $DataStoreServiceStartReturnValue = $DataStoreServiceStart | Invoke-CimMethod -Name StartService
                                if($DataStoreServiceStartReturnValue -eq 0){
                                    Write-Verbose "Service Start Operation successful."
                                }else{
                                    throw "Service ArcGIS Data Store failed to start. Return value - $DataStoreServiceStartReturnValue"
                                }
                            }else{
                                throw "Service ArcGIS Data Store Mode Change Failed. Return value - $DataStoreStartServiceChangeModeReturnValue"
                            }
                        }else{
                            throw "Service ArcGIS Data Store failed to stop. Return value - $DataStoreServiceStopReturnValue"    
                        }
                    }else{
                        throw "Service ArcGIS Data Store Mode Change Failed. Return value - $DataStoreStopServiceChangeModeReturnValue"
                    }
                }
                TestScript = {
                    $False
                }
                DependsOn = $Depends
            }
            $Depends += '[Script]CreateUpgradeFile'
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
}
