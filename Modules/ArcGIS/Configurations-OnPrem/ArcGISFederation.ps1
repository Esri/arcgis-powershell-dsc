Configuration ArcGISFederation
{    
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServerPrimarySiteAdminCredential,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $RemoteSiteAdministrator,

        [Parameter(Mandatory=$False)]
        [System.String]
        $PortalHostName,

        [Parameter(Mandatory=$False)]
        [System.Int32]
        $PortalPort,

        [Parameter(Mandatory=$False)]
        [System.String]
        $PortalContext,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ServerHostName,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ServerContext,

        [Parameter(Mandatory=$False)]
        [System.Int32]
        $ServerPort,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ServerSiteAdminUrlHostName,

        [Parameter(Mandatory=$False)]
        [System.Int32]
        $ServerSiteAdminUrlPort,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ServerSiteAdminUrlContext,

        [Parameter(Mandatory=$False)]
        [System.String]
        $PrimaryServerMachine,
        
        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $IsHostingServer,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ServerFunctions,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $IsFederatedWithRestrictedPublishing
    )
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.1.0 
    Import-DscResource -Name ArcGIS_Federation
    
    Node $AllNodes.NodeName
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        if($Node.NodeName -ieq $PrimaryServerMachine){
            ArcGIS_Federation Federate
            {
                PortalHostName = $PortalHostName
                PortalPort = $PortalPort
                PortalContext = $PortalContext
                ServiceUrlHostName = $ServerHostName
                ServiceUrlContext = $ServerContext
                ServiceUrlPort = $ServerPort
                ServerSiteAdminUrlHostName = $ServerSiteAdminUrlHostName
                ServerSiteAdminUrlPort = $ServerSiteAdminUrlPort
                ServerSiteAdminUrlContext = $ServerSiteAdminUrlContext
                Ensure = "Present"
                RemoteSiteAdministrator = $RemoteSiteAdministrator
                SiteAdministrator = $ServerPrimarySiteAdminCredential
                ServerRole = if($IsHostingServer){'HOSTING_SERVER'}else{if($IsFederatedWithRestrictedPublishing){ 'FEDERATED_SERVER_WITH_RESTRICTED_PUBLISHING' }else{'FEDERATED_SERVER'}}
                ServerFunctions = $ServerFunctions
            }  
        }     
    }
}
