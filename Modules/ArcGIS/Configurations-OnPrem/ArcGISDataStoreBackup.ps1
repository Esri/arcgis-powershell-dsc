Configuration ArcGISDataStoreBackup
{
    param(
        [Parameter(Mandatory=$False)]
        [System.String]
        $PrimaryDataStore,
        
        [Parameter(Mandatory=$False)]
        [System.String]
        $PrimaryBigDataStore,
        
        [Parameter(Mandatory=$False)]
        [System.String]
        $PrimaryTileCache,

        [Parameter(Mandatory=$False)]
        [System.String]
        $PrimaryGraphStore,

        [Parameter(Mandatory=$false)]
        [System.Object]
        $RelationalBackups = $null,

        [Parameter(Mandatory=$false)]
        [System.Object]
        $TileCacheBackups = $null,

        [Parameter(Mandatory=$false)]
        [System.Object]
        $SpatioTemporalBackups = $null,

        [Parameter(Mandatory=$false)]
        [System.Object]
        $GraphStoreBackups = $null
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.1.0 
    Import-DscResource -Name ArcGIS_DataStoreBackup

    Node $AllNodes.NodeName 
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }

        if((($PrimaryDataStore -ieq $Node.NodeName) -and $Node.DataStoreTypes -icontains 'Relational') -and ($null -ne $RelationalBackups))
        {
            foreach($Backup in $RelationalBackups) 
			{
                ArcGIS_DataStoreBackup "RelationalBackup-$($Backup.Name)"
                {
                    DataStoreType = 'Relational'
                    BackupType = $Backup.Type
                    BackupName = $Backup.Name
                    BackupLocation = $Backup.Location
                    CloudBackupCredential = $Backup.CloudCredential
                    IsDefault = $Backup.IsDefault
                    ForceDefaultRelationalBackupUpdate = $Backup.ForceDefaultRelationalBackupUpdate
                    ForceCloudCredentialsUpdate = $Backup.ForceCloudCredentialsUpdate
                }
            }
        }

        if(($PrimaryBigDataStore -ieq $Node.NodeName) -and ($Node.DataStoreTypes -icontains 'SpatioTemporal') -and ($null -ne $SpatioTemporalBackups))
        {
            foreach($Backup in $SpatioTemporalBackups) 
			{
                ArcGIS_DataStoreBackup "SpatioTemporalBackup-$($Backup.Name)"
                {
                    DataStoreType = 'SpatioTemporal'
                    BackupType = $Backup.Type
                    BackupName = $Backup.Name
                    BackupLocation = $Backup.Location
                    CloudBackupCredential = $Backup.CloudCredential
                    IsDefault = $Backup.IsDefault
                    ForceCloudCredentialsUpdate = $Backup.ForceCloudCredentialsUpdate
                }
            }
        }
        
        if(($PrimaryTileCache -ieq $Node.NodeName) -and ($Node.DataStoreTypes -icontains 'TileCache') -and ($null -ne $TileCacheBackups))
        {
            foreach($Backup in $TileCacheBackups) 
			{
                ArcGIS_DataStoreBackup "TileCacheBackup-$($Backup.Name)"
                {
                    DataStoreType = 'TileCache'
                    BackupType = $Backup.Type
                    BackupName = $Backup.Name
                    BackupLocation = $Backup.Location
                    CloudBackupCredential = $Backup.CloudCredential
                    IsDefault = $Backup.IsDefault
                    ForceCloudCredentialsUpdate = $Backup.ForceCloudCredentialsUpdate
                }
            }
        }

        if(($PrimaryGraphStore -ieq $Node.NodeName) -and ($Node.DataStoreTypes -icontains 'GraphStore') -and ($null -ne $GraphStoreBackups))
        {
            foreach($Backup in $GraphStoreBackups) 
			{
                ArcGIS_DataStoreBackup "GraphStoreBackup-$($Backup.Name)"
                {
                    DataStoreType = 'GraphStore'
                    BackupType = $Backup.Type
                    BackupName = $Backup.Name
                    BackupLocation = $Backup.Location
                    CloudBackupCredential = $Backup.CloudCredential
                    IsDefault = $Backup.IsDefault
                    ForceCloudCredentialsUpdate = $Backup.ForceCloudCredentialsUpdate
                }
            }
        }
    }
}
