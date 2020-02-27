Configuration WebAdaptorUninstall{
    param(
        [System.String]
        $Version,
        
        [System.String]
        $InstallerPath,
        
        [System.String]
        $Context
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.0.0"}
    Import-DscResource -Name ArcGIS_WebAdaptorInstall

    Node $AllNodes.NodeName {
        
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }

        ArcGIS_WebAdaptorInstall WebAdaptorUninstall
        { 
            Context = $Context 
            Path = $InstallerPath
            Arguments = "/qb VDIRNAME=$($Context) WEBSITE_ID=1";
            Ensure = "Absent"
            Version = $Version
        } 
    }
}