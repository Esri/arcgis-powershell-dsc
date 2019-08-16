Configuration DataStoreUpgradePreInstall{
    param(
        [System.Management.Automation.PSCredential]
        $ServiceCredential,

        [Parameter(Mandatory=$false)]
        [System.String]
        $ServiceCredentialIsDomainAccount = 'false',
		
		[Parameter(Mandatory=$false)]
        [System.String]
        $DebugMode
    )
    
	Import-DscResource -Name ArcGIS_WindowsService
    
    Node localhost {
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $true
        }
        
        ArcGIS_WindowsService ArcGIS_DataStore_Service_Stop
        {
            Name = 'ArcGIS Data Store'
            Credential = $ServiceCredential
            StartupType = 'Manual'
            State = 'Stopped'
        }
    }
}