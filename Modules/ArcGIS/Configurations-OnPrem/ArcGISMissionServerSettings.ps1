Configuration ArcGISMissionServerSettings{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServerPrimarySiteAdminCredential,
        
        [Parameter(Mandatory=$false)]
        [System.String]
        $PrimaryServerMachine,

        [Parameter(Mandatory=$false)]
        [System.String]
        $ExternalDNSHostName,

        [Parameter(Mandatory=$false)]
        [System.String]
        $ServerContext
    )


    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 3.3.1
    Import-DscResource -Name ArcGIS_MissionServerSettings

    Node $AllNodes.NodeName
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        if($Node.NodeName -ieq $PrimaryServerMachine){
            ArcGIS_MissionServerSettings ArcGIS_MissionServerSettings
            {
                ServerHostName      = (Get-FQDN $Node.NodeName)
                WebContextURL       = "https://$ExternalDNSHostName/$($ServerContext)"
                WebSocketContextUrl = "wss://$ExternalDNSHostName/$($ServerContext)"
                SiteAdministrator   = $ServerPrimarySiteAdminCredential
            }
        }
    }
}