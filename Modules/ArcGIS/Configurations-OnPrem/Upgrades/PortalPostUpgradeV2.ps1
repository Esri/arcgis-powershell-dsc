Configuration PortalPostUpgradeV2 {

    param(
        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
		$PortalSiteAdministratorCredential
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.0.1"} 
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
            PortalAdministrator = $PortalSiteAdministratorCredential 
            PortalHostName = $MachineFQDN
            LicenseFilePath = $Node.PortalLicenseFilePath
        }
    }
}