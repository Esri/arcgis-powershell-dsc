Configuration WebAdaptorInstall{
    param(
        [ValidateSet("ServerWebAdaptor","PortalWebAdaptor")]
        [System.String]
        $WebAdaptorRole,
        
        [System.String]
        $Version,
        
        [System.String]
        $InstallerPath,
        
        [System.String]
        $Context,
        
        [System.String]
        $ComponentHostName, 

        [System.Management.Automation.PSCredential]
		$PSACredential
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName ArcGIS 
    Import-DscResource -Name ArcGIS_WebAdaptorInstall
    Import-DscResource -Name ArcGIS_WebAdaptor

    Node $AllNodes.NodeName {
        $NodeName = $Node.NodeName 
        
        $MachineFQDN = [System.Net.DNS]::GetHostByName($NodeName).HostName

        if($WebAdaptorRole -ieq "PortalWebAdaptor"){
            $Component = 'Portal'
        }elseif($WebAdaptorRole -ieq "ServerWebAdaptor"){
            $Component = 'Server'
        }
        
        ArcGIS_WebAdaptorInstall WebAdaptorInstall
        { 
            Context = $Context 
            Path = $InstallerPath
            Arguments = "/qb VDIRNAME=$($Context) WEBSITE_ID=1";
            Ensure = "Present"
            Version = $Version
        } 

        ArcGIS_WebAdaptor "Configure$($Component)-$($MachineFQDN)"
        {
            Ensure = "Present"
            Component = $Component
            HostName =  $Node.ExternalHostName
            ComponentHostName = [System.Net.DNS]::GetHostByName($ComponentHostName).HostName
            Context = $Context
            OverwriteFlag = $False
            SiteAdministrator = $PSACredential
            DependsOn = @('[ArcGIS_WebAdaptorInstall]WebAdaptorInstall')
        }
        
    }
}