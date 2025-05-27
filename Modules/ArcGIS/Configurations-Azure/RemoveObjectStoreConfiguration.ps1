Configuration RemoveObjectStoreConfiguration
{
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministratorCredential

    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
    Import-DSCResource -Name ArcGIS_DataStoreItemServer

    Node localhost
	{
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $false
        }

        ArcGIS_DataStoreItemServer UnRegisterObjectStore
        {
            Name = "OzoneObjectStore"
            SiteAdministrator = $SiteAdministratorCredential
            DataStoreType = "ObjectStore"
            Ensure = "Absent"
            ForceUpdate = $true
        }
    }
}