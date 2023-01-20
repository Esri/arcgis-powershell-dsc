Configuration PublishGISService
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $PublisherAccountCredential,

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

        $GISServices
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.0.2
    Import-DscResource -Name ArcGIS_Server_Service

    Node $AllNodes.NodeName
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        for ( $i = 0; $i -lt $GISServices.count; $i++ ){
            $Service = $GISServices[$i]
            ArcGIS_Server_Service "PublishService$($Service.Name)" {
                PublisherAccount = $PublisherAccountCredential
                PathToItemInfoFile = $Service.PathToItemInfoFile
                PathToSourceFile = $Service.PathToSourceFile
                ServiceName = $Service.Name
                ServiceType = $Service.Type
                Folder = $Service.Folder
                State = "STARTED"
                Ensure = "Present"
                ServerHostName = $ServerHostName
                ServerContext = $ServerContext
                Port = $ServerPort
                PortalHostName = $PortalHostName
                PortalPort = $PortalPort
                PortalContext = $PortalContext
            }
        }
    }
}
