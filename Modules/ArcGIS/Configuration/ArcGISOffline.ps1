Configuration ArcGISOffline
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
                    if($Configuration.Offline -and $ConfigurationData.Offline.Server)
                    {
                        ArcGIS_Server_Offline $Node.NodeName
                        {
                            Ensure = 'Present'
                            HostName = $Node.NodeName
                            JSAPI = if($ConfigurationData.Offline.Server.JSAPI) {$true} else {$false}
                            ArcGISCom = if($ConfigurationData.Offline.Server.ArcGISCom) {$true} else {$false}
                            SiteAdministrator = $PSACredential
                        }
                    }
                }
                'Portal'
                {
                    Write-Host "Portal $NodeName"
                    #Implement Offline Steps for Portal here
                }
            }
        }
    }
}
