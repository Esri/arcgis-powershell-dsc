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
        ArcGIS_WindowsService ArcGIS_DataStore_Service_Stop
        {
            Name = 'ArcGIS Data Store'
            Credential = $ServiceCredential
            StartupType = 'Manual'
            State = 'Stopped'
        }
    }
}