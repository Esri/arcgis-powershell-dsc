Configuration ArcGISDisconnectedEnvironment
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS

    Node $AllNodes.NodeName 
    {
        Foreach($NodeRole in $Node.Role)
        {
            Switch($NodeRole)
            {
                'Server'
                {
                }
                'Portal'
                {
                    if($ConfigurationData.DisconnectedEnvironment -and $ConfigurationData.DisconnectedEnvironment.Portal)
                    {
                        ArcGIS_Portal_DisconnectedEnvironment $Node.NodeName
                        {
                            Ensure = 'Present'
                            HostName = $Node.NodeName
                            SiteAdministrator = $PSACredential
                            DisableExternalContent = if($ConfigurationData.DisconnectedEnvironment.Portal.DisableExternalContent) {$true} else {$false}
                        }
                    }
                }
            }
        }
    }
}
