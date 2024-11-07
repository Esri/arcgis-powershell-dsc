Configuration UnfederateSiteConfiguration
{
	param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministratorCredential

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $ExternalDNSHostName

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $PrivateDNSHostName

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $PortalContext

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $FederatedServerContext
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_Federation

    Node localhost
	{
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $true
        }

        ArcGIS_Federation Federate
        {
            PortalHostName = $ExternalDNSHostName
            PortalPort = 443
            PortalContext = $PortalContext
            ServiceUrlHostName = $ExternalDNSHostName
            ServiceUrlContext = $FederatedServerContext
            ServiceUrlPort = 443
            ServerSiteAdminUrlHostName = if($PrivateDNSHostName){ $PrivateDNSHostName }else{ $ExternalDNSHostName }
            ServerSiteAdminUrlPort = 443
            ServerSiteAdminUrlContext = $FederatedServerContext
            Ensure = "Absent"
            RemoteSiteAdministrator = $SiteAdministratorCredential
            ServerRole = 'FEDERATED_SERVER'
        }
    }
}