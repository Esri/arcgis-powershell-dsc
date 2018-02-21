Configuration ArcGISOffline
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
                    Write-Host "Server $NodeName"
                    #Implement Offline Steps for Server here
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
