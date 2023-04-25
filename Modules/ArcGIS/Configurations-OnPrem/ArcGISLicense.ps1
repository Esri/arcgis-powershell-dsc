Configuration ArcGISLicense 
{
    param(
        [System.Boolean]
        $ForceLicenseUpdate
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.1.0 
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
                    if($Node.ServerRole -ine "GeoEvent" -and $Node.ServerRole -ine "WorkflowManagerServer" -and $Node.ServerLicenseFilePath){
                        ArcGIS_License "ServerLicense$($Node.NodeName)"
                        {
                            LicenseFilePath =  $Node.ServerLicenseFilePath
                            LicensePassword = $Node.ServerLicensePassword
                            Ensure = "Present"
                            Component = 'Server'
                            ServerRole = $Node.ServerRole
                            AdditionalServerRoles = if($Node.ServerRole -ieq "GeneralPurposeServer" -and $Node.AdditionalServerRoles){ if(($Node.AdditionalServerRoles | Where-Object {$_ -ine 'GeoEvent' -and $_ -ine 'NotebookServer' -and $_ -ine 'WorkflowManagerServer' -and $_ -ine 'MissionServer'}).Count -gt 0){$Node.AdditionalServerRoles | Where-Object {$_ -ine 'GeoEvent' -and $_ -ine 'NotebookServer' -and $_ -ine 'WorkflowManagerServer' -and $_ -ine 'MissionServer'}}else{$null} }else{ $null }
                            Force = $ForceLicenseUpdate
                        }
                    }

                    if(($Node.ServerRole -ieq "GeoEvent" -or ($Node.ServerRole -ieq "GeneralPurposeServer" -and $Node.AdditionalServerRoles -icontains "GeoEvent")) -and $Node.GeoeventServerLicenseFilePath){
                        ArcGIS_License "GeoeventServerLicense$($Node.NodeName)"
                        {
                            LicenseFilePath = $Node.GeoeventServerLicenseFilePath
                            LicensePassword = $Node.GeoeventServerLicensePassword
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
                            Ensure = "Present"
                            Component = 'Server'
                            ServerRole = "WorkflowManagerServer"
                            Force = $ForceLicenseUpdate
                        }
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
