Configuration ArcGISDisconnectedEnvironment
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS

    Node $AllNodes.NodeName 
    {
        $PSAPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.Password -AsPlainText -Force
        $PSACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.UserName, $PSAPassword )

        Foreach($NodeRole in $Node.Role)
        {
            Switch($NodeRole)
            {
                'Server'
                {
                    if($ConfigurationData.DisconnectedEnvironment -and $ConfigurationData.DisconnectedEnvironment.Server)
                    {
                        ArcGIS_Server_DisconnectedEnvironment $Node.NodeName
                        {
                            Ensure = 'Present'
                            HostName = $Node.NodeName
                            EnableJsApi = if($ConfigurationData.DisconnectedEnvironment.Server.EnableJsApi) {$true} else {$false}
                            EnableArcGISOnlineMapViewer = if($ConfigurationData.DisconnectedEnvironment.Server.EnableArcGISOnlineMapViewer) {$true} else {$false}
                            SiteAdministrator = $PSACredential
                        }
                    }
                }
                'Portal'
                {
                    Write-Host "Portal $NodeName"
                    #Implement DisconnectedEnvironment Steps for Portal here
                }
            }
        }
    }
}
