﻿Configuration DataStoreUpgradePreInstall
{
    param(
		[Parameter(Mandatory=$true)]
        [System.String]
        $PrimaryDataStore
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Node $AllNodes.NodeName {
        
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }

        if($PrimaryDataStore -ne $Node.NodeName){
            Service ArcGIS_DataStore_Service_Stop
            {
                Name = 'ArcGIS Data Store'
                StartupType = "Manual"
                State = "Stopped"
            }
        }
    }
}
