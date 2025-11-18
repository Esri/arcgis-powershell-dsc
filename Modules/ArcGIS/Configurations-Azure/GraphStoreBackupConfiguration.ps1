Configuration GraphStoreBackupConfiguration{

    param(
        [Parameter(Mandatory=$false)]
        [System.String]
        $Version = "12.0"

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $GraphBackupCredential

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $GraphBackupLocation
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
    Import-DSCResource -Name ArcGIS_DataStoreBackup

    Node localhost
    {
        ArcGIS_DataStoreBackup "GraphStore-Backup"
        {
            DataStoreType = "GraphStore"
            BackupType = "Azure"
            BackupName = "GraphStoreBackup"
            BackupLocation = $GraphBackupLocation
            CloudBackupCredential = $GraphBackupCredential
            IsDefault = $True
        }
    }
}