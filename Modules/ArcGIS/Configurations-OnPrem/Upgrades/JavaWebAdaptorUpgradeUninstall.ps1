Configuration JavaWebAdaptorUpgradeUninstall{
    param(
       [System.String]
        $OldVersion
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.4.0 -Name ArcGIS_Install

    Node $AllNodes.NodeName {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }

        ArcGIS_Install WebAdaptorUninstall
        { 
            Name = "WebAdaptorJava"
            Version = $OldVersion
            Ensure = "Absent"
        }
    }
}