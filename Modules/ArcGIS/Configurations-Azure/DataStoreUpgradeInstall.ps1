Configuration DataStoreUpgradeInstall{
    param(
        [Parameter(Mandatory=$false)]
        [System.String]
        $Version = "11.5",

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
        [System.Boolean]
        $DebugMode
    )
    
	function Get-FileNameFromUrl
    {
        param(
            [string]$Url
        )
        $FileName = $Url
        if($FileName) {
            $pos = $FileName.IndexOf('?')
            if($pos -gt 0) { 
                $FileName = $FileName.Substring(0, $pos) 
            } 
            $FileName = $FileName.Substring($FileName.LastIndexOf('/')+1)   
        }     
        $FileName
    }

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_Install
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_WindowsService
    Import-DscResource -Name ArcGIS_AzureSetupDownloadsFolderManager
    
    $UpgradeSetupsStagingPath = "C:\ArcGIS\Deployment\Downloads\$($Version)"
    Node localhost {
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $false
        }

        ArcGIS_AzureSetupDownloadsFolderManager CleanupDownloadsFolder{
            Version = $Version
            OperationType = 'CleanupDownloadsFolder'
            ComponentNames = "All"
        }
        $Depends = @("[ArcGIS_AzureSetupDownloadsFolderManager]CleanupDownloadsFolder")

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
        
        ArcGIS_AzureSetupDownloadsFolderManager DownloadDataStoreUpgradeSetup{
            Version = $Version
            OperationType = 'DownloadUpgradeSetups'
            ComponentNames = "DataStore"
            UpgradeSetupsSourceFileSharePath = "\\$($UpgradeVMName)\UpgradeSetups"
            UpgradeSetupsSourceFileShareCredentials = $FileshareMachineCredential
            DependsOn = $Depends
        }
        $Depends += '[ArcGIS_AzureSetupDownloadsFolderManager]DownloadDataStoreUpgradeSetup'

        $InstallerPathOnMachine = "$($UpgradeSetupsStagingPath)\DataStore.exe"
        #ArcGIS Data Store 10.3 or 10.3.1, you must manually provide this account full control to your ArcGIS Data Store content directory 
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
				Remove-Item $using:InstallerPathOnMachine -Force
			}
			TestScript = { -not(Test-Path $using:InstallerPathOnMachine) }
			GetScript = { $null }          
		}    
        $Depends += '[Script]RemoveDataStoreInstaller'

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