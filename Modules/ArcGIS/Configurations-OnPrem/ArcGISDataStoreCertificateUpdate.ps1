Configuration ArcGISDataStoreCertificateUpdate 
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 3.3.2
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
            DatastoreMachineHostName = (Get-FQDN $Node.NodeName)
            SiteName = 'arcgis'
            CName = $Node.SSLCertificate.CName
            CertificateFileLocation = $Node.SSLCertificate.Path
            CertificatePassword = $Node.SSLCertificate.Password
        }
    }
}
