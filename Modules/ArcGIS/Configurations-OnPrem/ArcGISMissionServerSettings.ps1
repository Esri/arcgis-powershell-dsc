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
        $ServerContext,

        [Parameter(Mandatory=$false)]
        [System.String] 
        $HttpProxyHost,

        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [Nullable[System.UInt32]]    
        $HttpProxyPort,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential] 
        $HttpProxyCredential,

        [Parameter(Mandatory=$false)]
        [System.String] 
        $HttpsProxyHost,

        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [Nullable[System.UInt32]]   
        $HttpsProxyPort,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential] 
        $HttpsProxyCredential,

        [Parameter(Mandatory=$false)]
        [System.String] 
        $NonProxyHosts,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $DisableServiceDirectory = $False
    )


    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 5.0.0 -Name ArcGIS_MissionServerSettings

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
                ServerHostName      = $Node.NodeName
                WebContextURL       = "https://$ExternalDNSHostName/$($ServerContext)"
                WebSocketContextUrl = "wss://$ExternalDNSHostName/$($ServerContext)"
                SiteAdministrator   = $ServerPrimarySiteAdminCredential
                HttpProxyHost     = $HttpProxyHost
                HttpProxyPort     = $HttpProxyPort
                HttpProxyCredential  = $HttpProxyCredential

                HttpsProxyPort    = $HttpsProxyPort
                HttpsProxyHost    = $HttpsProxyHost
                HttpsProxyCredential = $HttpsProxyCredential
                
                NonProxyHosts     = $NonProxyHosts
                DisableServiceDirectory = if($DisableServiceDirectory) { $true } else { $false }
            }
        }
    }
}
