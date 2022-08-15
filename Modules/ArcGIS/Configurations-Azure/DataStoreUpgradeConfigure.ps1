Configuration DataStoreUpgradeConfigure{
    param(
        [System.Management.Automation.PSCredential]
        $SiteAdministratorCredential,

        [System.Boolean]
        $ServiceCredentialIsDomainAccount,

        [System.String]
        $ServerMachineName,

		[Parameter(Mandatory=$false)]
        [System.String]
        $DebugMode
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_DataStoreUpgrade
    
    Node localhost {
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $true
        }
        
        $InstallDir = "$($env:SystemDrive)\\arcgis\\datastore"
        $DataStoreContentDirectory = "$($env:SystemDrive)\\arcgis\\datastore\\content"
       
        ArcGIS_DataStoreUpgrade DataStoreConfigUpgrade
        {
            ServerHostName = $ServerMachineName
            Ensure = 'Present'
            SiteAdministrator = $SiteAdministratorCredential
            ContentDirectory = $DataStoreContentDirectory
            InstallDir = $InstallDir
        }
    }
}
