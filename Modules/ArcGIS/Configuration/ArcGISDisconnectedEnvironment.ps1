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
                    Write-Host "Portal $NodeName"
                    #Implement DisconnectedEnvironment Steps for Portal here
                }
            }
        }
    }
}
