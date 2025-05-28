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
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.5.0 -Name ArcGIS_FileShare, ArcGIS_DataStoreItemServer

    Node $AllNodes.NodeName
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        $Depends = @()
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
            $Depends = @("[ArcGIS_FileShare]RasterAnalysisFileShare")
        }

        $ConnectionStringObject = @{
            DataStorePath = if($ExternalFileSharePath){ $ExternalFileSharePath }else{ "\\$($Node.NodeName)\$($FileShareName)" }
        }

        ArcGIS_DataStoreItemServer RasterDataStoreItem
        {
            Name = "RasterFileShareDataStore"
            ServerHostName = $PrimaryServerMachine
            SiteAdministrator = $ServerPrimarySiteAdminCredential
            DataStoreType = "RasterStore"
            ConnectionString = (ConvertTo-Json $ConnectionStringObject -Compress -Depth 10)
            ConnectionSecret = $null
            ForceUpdate = $True
            Ensure = "Present"
            DependsOn = $Depends
        }
    }
}
