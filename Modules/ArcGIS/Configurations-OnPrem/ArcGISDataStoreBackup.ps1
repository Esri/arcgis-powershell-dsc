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

        [Parameter(Mandatory=$false)]
        [System.Object]
        $RelationalBackups = $null,

        [Parameter(Mandatory=$false)]
        [System.Object]
        $TileCacheBackups = $null,

        [Parameter(Mandatory=$false)]
        [System.Object]
        $SpatioTemporalBackups = $null
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.2.0"}
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
    }
}