Configuration DataStoreUpgradePreInstall{
    param(
        [System.Management.Automation.PSCredential]
        $ServiceCredential,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount,
		
		[Parameter(Mandatory=$false)]
        [System.String]
        $DebugMode
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
	
    Node localhost {
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $true
        }
        
        Service ArcGIS_DataStore_Service_Stop
        {
            Name = 'ArcGIS Data Store'
            Credential = $ServiceCredential
            StartupType = 'Manual'
            State = 'Stopped'
        }
    }
}
