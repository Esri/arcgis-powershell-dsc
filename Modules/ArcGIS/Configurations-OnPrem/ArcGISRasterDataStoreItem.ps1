Configuration ArcGISRasterDataStoreItem
{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServiceCredential,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsMSA = $false,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServerPrimarySiteAdminCredential,

        [System.String]
        $PrimaryServerMachine,

        [System.String]
        $ExternalFileSharePath,

        [System.String]
        $FileShareName,

        [System.String]
        $FileShareLocalPath
    )
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.0.2
    Import-DscResource -Name ArcGIS_FileShare
    Import-DSCResource -Name ArcGIS_DataStoreItem

    Node $AllNodes.NodeName
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        if(-not($ExternalFileSharePath)){
            ArcGIS_FileShare RasterAnalysisFileShare
            {
                FileShareName = $FileShareName
                FileShareLocalPath = $FileShareLocalPath
                Ensure = 'Present'
                Credential = $ServiceCredential
                IsDomainAccount = $ServiceCredentialIsDomainAccount
                IsMSAAccount = $ServiceCredentialIsMSA
            }
        }
        
        ArcGIS_DataStoreItem RasterDataStoreItem
        {
            Name = "RasterFileShareDataStore"
            HostName = $PrimaryServerMachine
            Ensure = "Present"
            SiteAdministrator = $ServerPrimarySiteAdminCredential
            DataStoreType = "RasterStore"
            DataStorePath = if($ExternalFileSharePath){ $ExternalFileSharePath }else{ "\\$($Node.NodeName)\$($FileShareName)" }
        }
    }
}
