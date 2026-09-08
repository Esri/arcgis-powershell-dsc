Configuration ArcGISGeoEnrichmentServer
{
    param(
        [Parameter(Mandatory=$True)]
        [System.String]
        $Version,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $PortalAdministratorCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $DataStoreDataDirectory,
       
        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $RegisterGeoEnrichmentAsPortalUtilityService = $True,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $ForceRepair
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 5.1.2 -Name ArcGIS_GeoEnrichment

    Node $AllNodes.NodeName
    { 
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        $Depends = @()
        ArcGIS_GeoEnrichment ArcGISGeoEnrichmentServer{
            Version = $Version
            Mode = if($ForceRepair){ "Repair" }else{ "Create" }
            PortalSiteAdministrator = $PortalAdministratorCredential
            DataStoreDataDirectory = if($DataStoreDataDirectory){ $DataStoreDataDirectory }else{ $null }
            RegisterGeoEnrichmentAsPortalUtilityService = $RegisterGeoEnrichmentAsPortalUtilityService
        }
    }
}