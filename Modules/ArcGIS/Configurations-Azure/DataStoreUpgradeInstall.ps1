Configuration DataStoreUpgradeInstall{
    param(
        [Parameter(Mandatory=$false)]
        [System.String]
        $Version = "12.1",

        [System.Management.Automation.PSCredential]
        $ServiceCredential,

        [System.Boolean]
        $ServiceCredentialIsDomainAccount,

		[System.Management.Automation.PSCredential]
        $FileshareMachineCredential,

        [System.String]
        $UpgradeVMName,

        [System.Boolean]
        $HasRelationalDataStore = $false,

        [Parameter(Mandatory=$false)]
        [System.String]
        $UpgradeFailurePatchName,

        [Parameter(Mandatory=$True)]
        [System.Management.Automation.PSCredential]
        $DeploymentArtifactCredentials,
        
		[Parameter(Mandatory=$false)]
        [System.Boolean]
        $DebugMode
    )
    
	Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_Install
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_AzureSetupsManager
    Import-DscResource -Name ArcGIS_WindowsService
    Import-DscResource -Name ArcGIS_InstallPatch
    Import-DscResource -Name ArcGIS_RemoteFile
    
    $UpgradeSetupsStagingPath = "C:\ArcGIS\Deployment\Downloads\$($Version)"
    Node localhost {
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $false
        }

        ArcGIS_AzureSetupsManager CleanupDownloadsFolder{
            Version = $Version
            OperationType = 'CleanupDownloadsFolder'
            ComponentNames = "All"
        }
        $Depends = @("[ArcGIS_AzureSetupsManager]CleanupDownloadsFolder")

        if($HasRelationalDataStore){
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
        
        ArcGIS_AzureSetupsManager DownloadDataStoreUpgradeSetup{
            Version = $Version
            OperationType = 'DownloadUpgradeSetups'
            ComponentNames = "DataStore"
            UpgradeSetupsSourceFileSharePath = "\\$($UpgradeVMName)\UpgradeSetups"
            UpgradeSetupsSourceFileShareCredentials = $FileshareMachineCredential
            DependsOn = $Depends
        }
        $Depends += '[ArcGIS_AzureSetupsManager]DownloadDataStoreUpgradeSetup'

        $InstallerPathOnMachine = "$($UpgradeSetupsStagingPath)\DataStore.exe"
        $InstallerVolumePathOnMachine = "$($UpgradeSetupsStagingPath)\DataStore.exe.001"
        
        ArcGIS_Install DataStoreUpgrade{
            Name = "DataStore"
            Version = $Version
            Path = $InstallerPathOnMachine
            Arguments = "/qn ACCEPTEULA=YES";
            ServiceCredential = $ServiceCredential
            ServiceCredentialIsDomainAccount = $ServiceCredentialIsDomainAccount
            ServiceCredentialIsMSA = $False
            Ensure = "Present"
            EnableMSILogging = $DebugMode
            DependsOn = $Depends
        }
        $Depends += '[ArcGIS_Install]DataStoreUpgrade'
        
        Script RemoveDataStoreInstaller
		{
			SetScript = 
			{ 
                if(-not([string]::IsNullOrEmpty($using:InstallerPathOnMachine)) -and (Test-Path $using:InstallerPathOnMachine)){
				    Remove-Item $using:InstallerPathOnMachine -Force
                }
                if(-not([string]::IsNullOrEmpty($using:InstallerVolumePathOnMachine)) -and (Test-Path $using:InstallerVolumePathOnMachine)){
                    Remove-Item $using:InstallerVolumePathOnMachine -Force
                }
			}
			TestScript = { -not(Test-Path $using:InstallerPathOnMachine) -and -not(Test-Path $using:InstallerVolumePathOnMachine)  }
			GetScript = { @{} }          
		}    
        $Depends += '[Script]RemoveDataStoreInstaller'

        if($HasRelationalDataStore -and $UpgradeFailurePatchName -and $DeploymentArtifactCredentials){

            $UpgradePatchStagingPath = "C:\ArcGIS\Deployment\Downloads\$($Version)\patches"

            # Download the patch
            ArcGIS_RemoteFile "UpgradePatchDownload"
            {
                Source = $UpgradeFailurePatchName
                Destination = (Join-Path $UpgradePatchStagingPath $UpgradeFailurePatchName)
                FileSourceType = "AzureSASUri"
                Credential = $DeploymentArtifactCredentials
                Ensure = 'Present'
            }
            $Depends += '[ArcGIS_RemoteFile]UpgradePatchDownload'
        
            ArcGIS_InstallPatch DatastoreInstallPatch
            {
                Name = "DataStore"
                Version = $Version
                DownloadPatches = $false
                PatchesDir = $UpgradePatchStagingPath
                Ensure = "Present"
                DependsOn = $Depends
            }
        }

        ArcGIS_WindowsService ArcGIS_DataStore_Service_Start
        {
            Name = 'ArcGIS Data Store'
            Credential = $ServiceCredential
            StartupType = 'Automatic'
            State = 'Running'
            DependsOn = $Depends
        }
    }
}