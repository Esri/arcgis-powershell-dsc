Configuration ArcGISServerSettings{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServerPrimarySiteAdminCredential,
        
        [Parameter(Mandatory=$false)]
        [System.String]
        $ServerType,

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
        $DisableServiceDirectory = $False,

        [Parameter(Mandatory=$False)]
        [System.String]
        $VideoServerLiveStreamGatewayHostName,

        [Parameter(Mandatory=$False)]
        [System.String]
        $VideoServerLiveStreamPorts,

        [Parameter(Mandatory=$false)]
        [System.String]
        $SharedKey = $null
    )


    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 5.1.2 -Name ArcGIS_ServerSettings

    Node $AllNodes.NodeName
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        ArcGIS_ServerSettings ServerSettings
        {
            ServerHostName      = $PrimaryServerMachine
            ServerType	        = if(@("MissionServer","NotebookServer","VideoServer","DataPipelinesServer") -icontains $ServerType){ $ServerType }else{ "Server" }
            WebContextURL       = if($ExternalDNSHostName){"https://$($ExternalDNSHostName)/$($ServerContext)"}else{ $null }
            WebSocketContextUrl = if($ServerType -ieq "MissionServer" -and $ExternalDNSHostName) { "wss://$($ExternalDNSHostName)/$($ServerContext)" } else { $null }
            SiteAdministrator   = $ServerPrimarySiteAdminCredential
            HttpProxyHost       = $HttpProxyHost
            HttpProxyPort       = $HttpProxyPort
            HttpProxyCredential = $HttpProxyCredential
            HttpsProxyPort      = $HttpsProxyPort
            HttpsProxyHost      = $HttpsProxyHost
            HttpsProxyCredential= $HttpsProxyCredential
            NonProxyHosts       = $NonProxyHosts
            DisableServiceDirectory = if($DisableServiceDirectory) { $true } else { $false }
            VideoServerLiveStreamGatewayHostname = if($ServerType -ieq "VideoServer"){ $VideoServerLiveStreamGatewayHostname }else{ $null }
            VideoServerLiveStreamPorts = if($ServerType -ieq "VideoServer"){ $VideoServerLivestreamPorts }else{ $null } 
            SharedKey           = $SharedKey
        }
    }
}
