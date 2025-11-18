Configuration ArcGISDataStoreCertificateUpdate 
{
    param
    (
        [Parameter(Mandatory=$true)]
        [System.String]
        $Version
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 5.0.0 -Name ArcGIS_DataStore_TLS

    Node $AllNodes.NodeName 
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }

        foreach($Cert in $Node.DataStoreSSLCertificates){
            ArcGIS_DataStore_TLS "DataStore_TLS_$($Node.NodeName)_$($Cert.Type)" 
            {
                Version = $Version
                DatastoreMachineHostName = $Node.NodeName
                CName = $Cert.CName
                CertificateFileLocation = $Cert.Path
                CertificatePassword = $Cert.Password
                CertificateType = $Cert.Type
            }
        }
    }
}
