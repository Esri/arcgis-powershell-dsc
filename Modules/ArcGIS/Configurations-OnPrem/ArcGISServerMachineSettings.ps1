Configuration ArcGISServerMachineSettings{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServerPrimarySiteAdminCredential,

        [Parameter(Mandatory=$false)]
        [Int32]
        $SocMaximumHeapSize
    )


    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 5.0.0 -Name ArcGIS_ServerMachineSettings

    Node $AllNodes.NodeName
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        ArcGIS_ServerMachineSettings ServerSettings
        {
            ServerHostName   = $Node.NodeName
            SiteAdministrator= $ServerPrimarySiteAdminCredential
            SocMaximumHeapSize = $SocMaximumHeapSize
        }
    }
}
