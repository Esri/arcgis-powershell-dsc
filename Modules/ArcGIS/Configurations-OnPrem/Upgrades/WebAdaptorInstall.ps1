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
		$SiteAdministratorCredential
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.1.0"} 
    Import-DscResource -Name ArcGIS_WebAdaptorInstall
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
            ComponentHostName = (Get-FQDN $ComponentHostName)
            Context = $Context
            OverwriteFlag = $False
            SiteAdministrator = $SiteAdministratorCredential
            DependsOn = @('[ArcGIS_WebAdaptorInstall]WebAdaptorInstall')
        }
        
    }
}