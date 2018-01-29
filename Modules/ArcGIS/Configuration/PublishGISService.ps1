Configuration PublishGISService
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_Server_Service
    
    $PrimaryServerMachine = ""
    $PrimaryPortalMachine = ""
    for ( $i = 0; $i -lt $AllNodes.count; $i++ ){
        $Role = $AllNodes[$i].Role
        if($Role -icontains 'Server' -and -not($PrimaryServerMachine)){
            $PrimaryServerMachine  = $AllNodes[$i].NodeName
        }
        if($Role -icontains 'Portal' -and -not($PrimaryPortalMachine))
        {
            $PrimaryPortalMachine= $AllNodes[$i].NodeName
        }

    }

    Node $AllNodes.NodeName
    {
        if($Node.NodeName -ieq $PrimaryServerMachine){

            if($ConfigurationData.ConfigData.Portal.SslCertifcate){
                $PortalHostName = $ConfigurationData.ConfigData.Portal.SslCertifcate.Alias
                $PortalPort = 443
                $PortalContext = $ConfigurationData.ConfigData.PortalContext
            }else{
                $PortalHostName = (Get-FQDN $PrimaryPortalMachine)
                $PortalPort = 7443
                $PortalContext = "arcgis"
            }

            if($ConfigurationData.ConfigData.Server.SslCertifcate){
                $ServerHostName = $ConfigurationData.ConfigData.Server.SslCertifcate.Alias
                $ServerPort = 443
                $ServerContext = $ConfigurationData.ConfigData.ServerContext
            }else{
                $ServerHostName =(Get-FQDN $PrimaryServerMachine)
                $ServerPort = 6443
                $ServerContext = "arcgis"
            }

            $PSAPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.Password -AsPlainText -Force
            $PSACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.UserName, $PSAPassword )
            
            for ( $i = 0; $i -lt $ConfigurationData.ConfigData.GISServices.count; $i++ ){
                $Service = $ConfigurationData.ConfigData.GISServices[$i]
                ArcGIS_Server_Service PublishService{
                    ServerHostName = $ServerHostName
                    PathToSourceFile = $Service.PathToSourceFile
                    ServiceName = $Service.ServiceName
                    ServiceType = $Service.ServiceType
                    Folder = $Service.Folder
                    ServerContext = $ServerContext
                    Port = $ServerPort
                    State = "STARTED"
                    Ensure = "Present"
                    PublisherAccount = $PSACredential
                    PathToItemInfoFile = ""
                    PortalHostName = $PortalHostName
                    PortalPort = $PortalPort
                    PortalContext = $PortalContext
                }
            }
        }
    }
    
}
