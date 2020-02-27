Configuration ArcGISFederation
{    
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $SiteAdministratorCredential,
        
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
        $ServerRole
        
    )
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.0.0"}
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
                SiteAdministrator = $SiteAdministratorCredential
                ServerRole = if($IsHostingServer){'HOSTING_SERVER'}else{'FEDERATED_SERVER'}
                ServerFunctions = $ServerRole
            }  
        }     
    }
}