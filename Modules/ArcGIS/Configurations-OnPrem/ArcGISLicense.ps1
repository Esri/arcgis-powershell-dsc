Configuration ArcGISLicense 
{
    param(
        [System.Boolean]
        $ForceLicenseUpdate
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 5.1.2 -Name ArcGIS_License

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
                    if(-not(@("GeoEvent", "WorkflowManagerServer", "RealityServer") -icontains $Node.ServerRole) -and $Node.ServerLicenseFilePath){
                        $AdditionalServerRoles = $null
                        if($Node.ServerRole -ieq "GeneralPurposeServer" -and $Node.AdditionalServerRoles){
                            $AdditionalServerRoles = ($Node.AdditionalServerRoles | Where-Object {-not(@('GeoEvent','NotebookServer','MissionServer','VideoServer','DataPipelinesServer','RealityServer') -icontains $_) })
                            if($AdditionalServerRoles.Count -eq 0){
                                $AdditionalServerRoles = $null
                            } 
                        }

                        ArcGIS_License "ServerLicense$($Node.NodeName)"
                        {
                            LicenseFilePath =  $Node.ServerLicenseFilePath
                            LicensePassword = $Node.ServerLicensePassword
                            Version = $Node.Version
                            Ensure = "Present"
                            Component = 'Server'
                            ServerRole = $Node.ServerRole
                            AdditionalServerRoles = $AdditionalServerRoles
                            Force = $ForceLicenseUpdate
                        }
                    }

                    if(($Node.ServerRole -ieq "GeoEvent" -or ($Node.ServerRole -ieq "GeneralPurposeServer" -and $Node.AdditionalServerRoles -icontains "GeoEvent")) -and $Node.GeoeventServerLicenseFilePath){
                        ArcGIS_License "GeoeventServerLicense$($Node.NodeName)"
                        {
                            LicenseFilePath = $Node.GeoeventServerLicenseFilePath
                            LicensePassword = $Node.GeoeventServerLicensePassword
                            Version = $Node.Version
                            Ensure = "Present"
                            Component = 'Server'
                            ServerRole = "GeoEvent"
                            Force = $ForceLicenseUpdate
                        }
                    }

                    if(($Node.ServerRole -ieq "WorkflowManagerServer" -or ($Node.ServerRole -ieq "GeneralPurposeServer" -and $Node.AdditionalServerRoles -icontains "WorkflowManagerServer")) -and $Node.WorkflowManagerServerLicenseFilePath){
                        ArcGIS_License "WorkflowManagerServerLicense$($Node.NodeName)"
                        {
                            LicenseFilePath =  $Node.WorkflowManagerServerLicenseFilePath
                            LicensePassword = $Node.WorkflowManagerServerLicensePassword
                            Version = $Node.Version
                            Ensure = "Present"
                            Component = 'Server'
                            ServerRole = "WorkflowManagerServer"
                            Force = $ForceLicenseUpdate
                        }
                    }

                    if($Node.ServerRole -ieq "RealityServer" -and $Node.RealityServerLicenseFilePath){
                        ArcGIS_License "RealityServerLicense$($Node.NodeName)"
                        {
                            LicenseFilePath =  $Node.RealityServerLicenseFilePath
                            LicensePassword = $Node.RealityServerLicensePassword
                            Version = $Node.Version
                            Ensure = "Present"
                            Component = 'Server'
                            ServerRole = "RealityServer"
                            Force = $ForceLicenseUpdate
                        }
                    }
                }
                'Pro' 
                {
                    ArcGIS_License "ProLicense$($Node.NodeName)"
                    {
                        LicenseFilePath =  $Node.ProLicenseFilePath
                        Version = $Node.ProVersion
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
