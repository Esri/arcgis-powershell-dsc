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
                    $LicensePassword = $null
                    if($ConfigurationData.ConfigData.Server.LicensePassword)
                    {
                        $LicensePassword = $ConfigurationData.ConfigData.Server.LicensePassword
                    }

                    if(-not($ServerRole))
                    {
                        $ServerRole = "GeneralPurposeServer"
                    }
                    elseif($ServerRole -ieq "GeoEvent")
                    {
                        $LicenseFilePath =  $ConfigurationData.ConfigData.GeoEventServer.LicenseFilePath
                        if($ConfigurationData.ConfigData.GeoEventServer.LicensePassword)
                        {
                            $LicensePassword = $ConfigurationData.ConfigData.GeoEventServer.LicensePassword
                        }
                    }
                    elseif($ServerRole -ieq "RasterAnalytics" -or $ServerRole -ieq "ImageHosting")
                    {
                        $ServerRole = "ImageServer"
                    }

                    if($Node.ServerLicenseFilePath -and $Node.ServerLicensePassword)
                    {
                        $LicenseFilePath=$Node.ServerLicenseFilePath
                        $LicensePassword=$Node.ServerLicensePassword
                    }
                    
                    ArcGIS_License "ServerLicense$($Node.NodeName)"
                    {
                        LicenseFilePath =  $LicenseFilePath
                        Password = $LicensePassword
                        Ensure = "Present"
                        Component = 'Server'
                        ServerRole = $ServerRole 
                    }
                }
                'Portal'
                {
                    $LicenseFilePath = $ConfigurationData.ConfigData.Portal.LicenseFilePath
                    $LicensePassword = $null
                    if($ConfigurationData.ConfigData.Portal.LicensePassword)
                    {
                        $LicensePassword = $ConfigurationData.ConfigData.Portal.LicensePassword
                    }

                    if($Node.PortalLicenseFilePath -and $Node.PortalLicensePassword)
                    {
                        $LicenseFilePath=$Node.ServerLicenseFilePath
                        $LicensePassword=$Node.ServerLicensePassword
                    }

                    ArcGIS_License "PortalLicense$($Node.NodeName)"
                    {
                        LicenseFilePath = $LicenseFilePath
                        Password = $LicensePassword
                        Ensure = "Present"
                        Component = 'Portal'
                    }
                }
            }
        }
    }
}