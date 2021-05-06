Configuration ArcGISDataStoreCertificateUpdate 
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.2.0"}
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