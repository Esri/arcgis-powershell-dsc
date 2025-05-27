Configuration PortalPostUpgrade {

    param(
        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $PortalSiteAdministratorCredential,
        
        [parameter(Mandatory = $false)]
        [System.Boolean]
        $SetOnlyHostNamePropertiesFile = $False,

        [parameter(Mandatory = $false)]
        [System.String]
        $Version,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $DebugMode = $False
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.5.0 -Name ArcGIS_PortalUpgrade

    Node $AllNodes.NodeName {
        
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }

        ArcGIS_PortalUpgrade PortalUpgrade
        {
            PortalAdministrator = $PortalSiteAdministratorCredential 
            PortalHostName = $Node.NodeName
            LicenseFilePath = $Node.PortalLicenseFilePath
            SetOnlyHostNamePropertiesFile = $SetOnlyHostNamePropertiesFile
            Version = $Version
            EnableUpgradeSiteDebug = $DebugMode
        }
    }
}
