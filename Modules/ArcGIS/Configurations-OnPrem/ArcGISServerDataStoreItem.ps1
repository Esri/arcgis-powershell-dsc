Configuration ArcGISServerDataStoreItem
{
    param(
        [Parameter(Mandatory=$true)]
        [System.String]
        $Name,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServerPrimarySiteAdminCredential,

        [Parameter(Mandatory=$true)]
        [System.String]
        $PrimaryServerMachine,

        [Parameter(Mandatory=$true)]
        [System.String]
        $ConnectionString,

        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]
        $ConnectionSecret,

        [Parameter(Mandatory=$true)]
        [System.String]
        [ValidateSet("Folder", "CloudStore", "RasterStore", "BigDataFileShare")]
        $DataStoreType,

        [Parameter(Mandatory=$true)]
        [System.Boolean]
        $IsCloudStore = $False,

        [Parameter(Mandatory=$true)]
        [System.Boolean]
        $ForceUpdate
    )
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.2.1 
    Import-DscResource -Name ArcGIS_FileShare
    Import-DSCResource -Name ArcGIS_DataStoreItemServer

    Node $AllNodes.NodeName
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }

        $Depends = $null
        
        if(($DataStoreType -ieq "RasterStore" -or $DataStoreType -ieq "BigDataFileShare") -and $IsCloudStore){
            ArcGIS_DataStoreItemServer DataStoreItemCloudStore
            {
                Name = $Name
                ServerHostName = $PrimaryServerMachine
                SiteAdministrator = $ServerPrimarySiteAdminCredential
                DataStoreType = "CloudStore"
                ConnectionString = $ConnectionString
                ConnectionSecret = $ConnectionSecret
                ForceUpdate = $ForceUpdate
            }
            $Depends = @("[ArcGIS_DataStoreItemServer]DataStoreItemCloudStore")

            $ConnectionStringObject = @{
                DataStorePath = "/cloudStores/$($Name)"   
            }
            $ConnectionString = (ConvertTo-Json $ConnectionStringObject -Compress -Depth 10)
            $Name = "$($DataStoreType)-$($Name)"
            $ConnectionSecret = $null
        }

        ArcGIS_DataStoreItemServer DataStoreItem
        {
            Name = $Name 
            ServerHostName = $PrimaryServerMachine
            SiteAdministrator = $ServerPrimarySiteAdminCredential
            DataStoreType = $DataStoreType
            ConnectionString = $ConnectionString
            ConnectionSecret = $ConnectionSecret
            ForceUpdate = $ForceUpdate
            DependsOn = $Depends
        }
    }
}