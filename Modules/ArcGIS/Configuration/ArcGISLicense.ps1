Configuration ArcGISLicense 
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_License

    Node $AllNodes.NodeName 
    {
        Foreach($NodeRole in $Node.Role)
        {
            Switch($NodeRole)
            {
                'Server'
                {
                    $ServerRole = $ConfigurationData.ConfigData.ServerRole
                    $LicenseFilePath = $ConfigurationData.ConfigData.Server.LicenseFilePath
                    if(-not($ServerRole))
                    {
                        $ServerRole = "GeneralPurposeServer"
                    }
                    elseif($ServerRole -ieq "GeoEvent")
                    {
                        $LicenseFilePath =  $ConfigurationData.ConfigData.GeoEventServer.LicenseFilePath
                    }
                    elseif($ServerRole -ieq "RasterAnalytics" -or $ServerRole -ieq "ImageHosting")
                    {
                        $ServerRole = "ImageServer"
                    }
                    
                    ArcGIS_License "ServerLicense$($Node.NodeName)"
                    {
                        LicenseFilePath =  $LicenseFilePath
                        Ensure = "Present"
                        Component = 'Server'
                        ServerRole = $ServerRole 
                    }
                }
                'Portal'
                {
                    ArcGIS_License "PortalLicense$($Node.NodeName)"
                    {
                        LicenseFilePath = $ConfigurationData.ConfigData.Portal.LicenseFilePath
                        Ensure = "Present"
                        Component = 'Portal'
                    }
                }
            }
        }
    }
}