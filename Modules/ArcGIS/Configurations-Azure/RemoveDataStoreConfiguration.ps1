Configuration RemoveDataStoreConfiguration
{
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministratorCredential,

        [Parameter(Mandatory=$true)]
        [System.String]
        $DataStoreType
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
        
        ArcGIS_DataStoreItemServer "UnRegister$($DataStoreType)"
        {
            Name = if($DataStoreType -ieq "ObjectStore"){ "OzoneObjectStore" }else{ "TileCache" }
            SiteAdministrator = $SiteAdministratorCredential
            DataStoreType = $DataStoreType
            Ensure = "Absent"
            ForceUpdate = $true
        }
    }
}