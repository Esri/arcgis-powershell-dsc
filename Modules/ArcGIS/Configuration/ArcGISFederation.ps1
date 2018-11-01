Configuration ArcGISFederation
{    
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_Federation
    
    $PrimaryServerMachineNode = ""
    $PrimaryPortalMachineNode = ""
    $PrimaryServerMachine = ""
    $PrimaryPortalMachine = ""
    for ( $i = 0; $i -lt $AllNodes.count; $i++ )
    {

        $Role = $AllNodes[$i].Role
        if($Role -icontains 'Server' -and -not($PrimaryServerMachine))
        {
            $PrimaryServerMachineNode = $AllNodes[$i]
            $PrimaryServerMachine  = $PrimaryServerMachineNode.NodeName
        }

        if($Role -icontains 'Portal' -and -not($PrimaryPortalMachine))
        {
            $PrimaryPortalMachineNode = $AllNodes[$i]
            $PrimaryPortalMachine= $PrimaryPortalMachineNode.NodeName
        }
    }
    
    Node $AllNodes.NodeName
    {
        if($Node.NodeName -ieq $PrimaryServerMachine){

            $RemoteFederation = if($ConfigurationData.ConfigData.Federation){$true}else{$false}
            
            $PortalServerFederation = $False
            $HostingServer = $False
            if(-not($RemoteFederation))
            {
                $ServerCheck = (($AllNodes | Where-Object { $_.Role -icontains 'Server' }  | Measure-Object).Count -gt 0)
                $PortalCheck = (($AllNodes | Where-Object { $_.Role -icontains 'Portal' }  | Measure-Object).Count -gt 0)
                if($ServerCheck -and $PortalCheck)
                {
                    $PortalServerFederation = $True
                    if((($AllNodes | Where-Object { $_.Role -icontains 'DataStore' }  | Measure-Object).Count -gt 0))
                    {
                        $HostingServer = $True
                    }
                }
            }
            
            if($RemoteFederation -or $PortalServerFederation){
                if($RemoteFederation){
                    $PortalHostName = $ConfigurationData.ConfigData.Federation.PortalHostName
                    $PortalPort = $ConfigurationData.ConfigData.Federation.PortalPort
                    $PortalContext = $ConfigurationData.ConfigData.Federation.PortalContext
                    
                    $PortalFedPSAPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.Federation.PrimarySiteAdmin.Password -AsPlainText -Force
                    $PortalFedPSACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.Federation.PrimarySiteAdmin.UserName, $PortalFedPSAPassword )
                }else{
                    if(($AllNodes | Where-Object { ($_.Role -icontains 'PortalWebAdaptor')}  | Measure-Object).Count -gt 0){
                        $PortalWAMachineNode = ($AllNodes | Where-Object { ($_.Role -icontains 'PortalWebAdaptor')} | Select-Object -First 1)
                        $PortalWAMachineName = $PortalWAMachineNode.NodeName
                        $PortalHostName = Get-FQDN $PortalWAMachineName
                        if(($PortalWAMachineNode.SslCertifcates | Where-Object { $_.Target -icontains 'WebAdaptor'}  | Measure-Object).Count -gt 0)
                        {
                            $SSLCertificate = $PortalWAMachineNode.SslCertifcates | Where-Object { $_.Target -icontains 'WebAdaptor' }  | Select-Object -First 1
                            $PortalHostName = $SSLCertificate.Alias
                        }
                        
                        if(($AllNodes | Where-Object { ($_.Role -icontains 'LoadBalancer')}  | Measure-Object).Count -gt 0){
                            $LoadbalancerNode = ($AllNodes | Where-Object { ($_.Role -icontains 'LoadBalancer')} | Select-Object -First 1)
                            $LoadbalancerMachineName = $LoadbalancerNode.NodeName
                            $PortalHostName = Get-FQDN $LoadbalancerMachineName
                            if(($LoadbalancerNode.SslCertifcates | Where-Object { $_.Target -icontains 'LoadBalancer'}  | Measure-Object).Count -gt 0)
                            {
                                $SSLCertificate = $LoadbalancerNode.SslCertifcates | Where-Object { $_.Target -icontains 'LoadBalancer' }  | Select-Object -First 1
                                $PortalHostName = $SSLCertificate.Alias
                            }
                        }

                        if($ConfigurationData.ConfigData.ExternalLoadBalancer){
                            $PortalHostName = $ConfigurationData.ConfigData.ExternalLoadBalancer
                        }

                        $PortalPort = 443
                        $PortalContext = $ConfigurationData.ConfigData.PortalContext
                    }else{
                        $PortalHostName = Get-FQDN $PrimaryPortalMachine
                        if(($PrimaryPortalMachineNode.SslCertifcates | Where-Object { $_.Target -icontains 'Portal'}  | Measure-Object).Count -gt 0)
                        {
                            $SSLCertificate = $PrimaryPortalMachineNode.SslCertifcates | Where-Object { $_.Target -icontains 'Portal' }  | Select-Object -First 1
                            $PortalHostName = $SSLCertificate.Alias
                        }
                        $PortalPort = 7443
                        $PortalContext = 'arcgis'
                    }
                }
                
                if(($AllNodes | Where-Object { ($_.Role -icontains 'ServerWebAdaptor')}  | Measure-Object).Count -gt 0){
                    $ServerWAMachineNode = ($AllNodes | Where-Object { ($_.Role -icontains 'ServerWebAdaptor')} | Select-Object -First 1)
                    $ServerWAMachineName = $ServerWAMachineNode.NodeName
                    $ServerHostName = Get-FQDN $ServerWAMachineName
                    if(($ServerWAMachineNode.SslCertifcates | Where-Object { $_.Target -icontains 'WebAdaptor'}  | Measure-Object).Count -gt 0)
                    {
                        $SSLCertificate = $ServerWAMachineNode.SslCertifcates | Where-Object { $_.Target -icontains 'WebAdaptor' }  | Select-Object -First 1
                        $ServerHostName = $SSLCertificate.Alias
                    }
                    if(($AllNodes | Where-Object { ($_.Role -icontains 'LoadBalancer')}  | Measure-Object).Count -gt 0){
                        $LoadbalancerNode = ($AllNodes | Where-Object { ($_.Role -icontains 'LoadBalancer')} | Select-Object -First 1)
                        $LoadbalancerMachineName = $LoadbalancerNode.NodeName
                        $ServerHostName = Get-FQDN $LoadbalancerMachineName
                        if(($LoadbalancerNode.SslCertifcates | Where-Object { $_.Target -icontains 'LoadBalancer'}  | Measure-Object).Count -gt 0)
                        {
                            $SSLCertificate = $LoadbalancerNode.SslCertifcates | Where-Object { $_.Target -icontains 'LoadBalancer' }  | Select-Object -First 1
                            $ServerHostName = $SSLCertificate.Alias
                        }
                    }
                    if($ConfigurationData.ConfigData.ExternalLoadBalancer){
                        $ServerHostName = $ConfigurationData.ConfigData.ExternalLoadBalancer
                    }
                    $ServerPort = 443
                    $ServerContext = $ConfigurationData.ConfigData.ServerContext
                }else{
                    $ServerHostName = Get-FQDN $PrimaryServerMachine
                    if(($PrimaryServerMachineNode.SslCertifcates | Where-Object { $_.Target -icontains 'Server'}  | Measure-Object).Count -gt 0)
                    {
                        $SSLCertificate = $PrimaryServerMachineNode.SslCertifcates | Where-Object { $_.Target -icontains 'Server' }  | Select-Object -First 1
                        $ServerHostName = $SSLCertificate.Alias
                    }
                    $ServerPort = 6443
                    $ServerContext = 'arcgis'
                }
                    
                $ServerSiteAdminUrlHostName = $ServerHostName
                $ServerSiteAdminUrlPort = $ServerPort
                $ServerSiteAdminUrlContext = $ServerContext

                $WAAdminAccessEnabled = if($ConfigurationData.ConfigData.WebAdaptor){ $ConfigurationData.ConfigData.WebAdaptor.AdminAccessEnabled }else{ $False }

                if((($AllNodes | Where-Object { ($_.Role -icontains 'LoadBalancer') -or ($_.Role -icontains 'ServerWebAdaptor')}  | Measure-Object).Count -gt 0) -and -not($WAAdminAccessEnabled)){
                    $ServerSiteAdminUrlHostName = Get-FQDN $PrimaryServerMachine
                    if(($PrimaryServerMachineNode.SslCertifcates | Where-Object { $_.Target -icontains 'Server'}  | Measure-Object).Count -gt 0)
                    {
                        $SSLCertificate = $PrimaryServerMachineNode.SslCertifcates | Where-Object { $_.Target -icontains 'Server' }  | Select-Object -First 1
                        $ServerSiteAdminUrlHostName = $SSLCertificate.Alias
                    }
                    $ServerSiteAdminUrlPort = 6443
                    $ServerSiteAdminUrlContext = 'arcgis'
                }

                $PSAPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.Password -AsPlainText -Force
                $PSACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.UserName, $PSAPassword )

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
                    RemoteSiteAdministrator = if($PortalFedPSACredential){$PortalFedPSACredential}else{$PSACredential}
                    SiteAdministrator = $PSACredential
                    ServerRole = if($HostingServer){'HOSTING_SERVER'}else{'FEDERATED_SERVER'}
                    ServerFunctions = $ConfigurationData.ConfigData.ServerRole
                }
            }
        }
    }
}