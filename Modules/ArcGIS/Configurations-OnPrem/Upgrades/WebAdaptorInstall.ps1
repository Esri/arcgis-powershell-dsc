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
        $SiteAdministratorCredential,
        
        [System.Int32]
		$WebSiteId = 1
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.1.1"} 
    Import-DscResource -Name ArcGIS_Install
    Import-DscResource -Name ArcGIS_WebAdaptor

    Node $AllNodes.NodeName {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        $NodeName = $Node.NodeName 
        
        $MachineFQDN = (Get-FQDN $NodeName)

        if($WebAdaptorRole -ieq "PortalWebAdaptor"){
            $Component = 'Portal'
        }elseif($WebAdaptorRole -ieq "ServerWebAdaptor"){
            $Component = 'Server'
        }

        $WAArguments = "/qn VDIRNAME=$($Context) WEBSITE_ID=$($WebSiteId)"
        if($Version.Split('.')[1] -gt 5){
            $WAArguments += " CONFIGUREIIS=TRUE"
        }

        ArcGIS_Install WebAdaptorInstall
        { 
            Name = $WebAdaptorRole
            Version = $Version
            Path = $InstallerPath
            WebAdaptorContext = $Context
            Arguments = $WAArguments
            Ensure = "Present"
        }

        ArcGIS_WebAdaptor "Configure$($Component)-$($MachineFQDN)"
        {
            Ensure = "Present"
            Component = $Component
            HostName =  $Node.ExternalHostName
            ComponentHostName = (Get-FQDN $ComponentHostName)
            Context = $Context
            OverwriteFlag = $False
            SiteAdministrator = $SiteAdministratorCredential
            DependsOn = @('[ArcGIS_Install]WebAdaptorInstall')
        }
    }
}