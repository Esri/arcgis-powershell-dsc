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
    Import-DscResource -ModuleName ArcGIS 
    Import-DscResource -Name ArcGIS_WebAdaptorInstall

    Node $AllNodes.NodeName {
       
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