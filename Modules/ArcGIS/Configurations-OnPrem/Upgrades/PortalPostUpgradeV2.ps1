Configuration PortalPostUpgradeV2 {

    param(
        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
		$SiteAdministratorCredential
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.0.0"} 
    Import-DscResource -Name ArcGIS_PortalUpgrade 

    Node $AllNodes.NodeName {
        
        $NodeName = $Node.NodeName
        $MachineFQDN = (Get-FQDN $NodeName)

        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }

        ArcGIS_PortalUpgrade PortalUpgrade
        {
            PortalAdministrator = $SiteAdministratorCredential 
            PortalHostName = $MachineFQDN
            LicenseFilePath = $Node.PortalLicenseFilePath
        }
    }
}