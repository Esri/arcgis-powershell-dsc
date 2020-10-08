Configuration ArcGISLicense 
{
    param(
        [System.Boolean]
        $ForceLicenseUpdate
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.1.1"}
    Import-DscResource -Name ArcGIS_License

    Node $AllNodes.NodeName 
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        Foreach($NodeRole in $Node.Role)
        {
            Switch($NodeRole)
            {
                'Server'
                {
                    ArcGIS_License "ServerLicense$($Node.NodeName)"
                    {
                        LicenseFilePath =  $Node.ServerLicenseFilePath
                        LicensePassword = $Node.ServerLicensePassword
                        Ensure = "Present"
                        Component = 'Server'
                        ServerRole = $Node.ServerRole 
                        Force = $ForceLicenseUpdate
                    }
                }
                'Portal'
                {
                    ArcGIS_License "PortalLicense$($Node.NodeName)"
                    {
                        LicenseFilePath = $Node.PortalLicenseFilePath
                        LicensePassword = $Node.PortalLicensePassword
                        Ensure = "Present"
                        Component = 'Portal'
                        Force = $ForceLicenseUpdate
                    }                    
                }
                'Desktop'
                {
                    ArcGIS_License "DesktopLicense$($Node.NodeName)"
                    {
                        LicenseFilePath =  $Node.DesktopLicenseFilePath
                        LicensePassword = $null
                        IsSingleUse = $True
                        Ensure = "Present"
                        Component = 'Desktop'
                        Force = $ForceLicenseUpdate
                    }
                }
                'Pro' 
                {
                    ArcGIS_License "ProLicense$($Node.NodeName)"
                    {
                        LicenseFilePath =  $Node.ProLicenseFilePath
                        LicensePassword = $null
                        IsSingleUse = $True
                        Ensure = "Present"
                        Component = 'Pro'
                        Force = $ForceLicenseUpdate
                    }                
                }
                'LicenseManager'
                {   
                    if($Node.LicenseManagerVersion -and $Node.LicenseManagerLicenseFilePath){
                        ArcGIS_License "LicenseManagerLicense$($Node.NodeName)"
                        {
                            LicenseFilePath = $Node.LicenseManagerLicenseFilePath
                            LicensePassword = $null
                            Ensure = "Present"
                            Component = 'LicenseManager'
                            Version = $Node.LicenseManagerVersion #Ignored, will default to 10.6 in ArcGIS_License.psm1
                            Force = $ForceLicenseUpdate
                        }
                    }
                }
            }
        }
    }
}