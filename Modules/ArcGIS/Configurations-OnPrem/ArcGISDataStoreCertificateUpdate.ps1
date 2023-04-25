Configuration ArcGISDataStoreCertificateUpdate 
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.1.0 
    Import-DscResource -Name ArcGIS_DataStore_TLS

    Node $AllNodes.NodeName 
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }

        ArcGIS_DataStore_TLS "DataStore_TLS_$($Node.NodeName)"{
            DatastoreMachineHostName = $Node.NodeName
            CName = $Node.SSLCertificate.CName
            CertificateFileLocation = $Node.SSLCertificate.Path
            CertificatePassword = $Node.SSLCertificate.Password
        }
    }
}
