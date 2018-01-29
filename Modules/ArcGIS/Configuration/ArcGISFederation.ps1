Configuration ArcGISFederation
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_Federation

    $PrimaryServerMachine = ""
    $PrimaryPortalMachine = ""
    $PrimaryDataStore = ""

    for ( $i = 0; $i -lt $AllNodes.count; $i++ )
    {
        $Role = $AllNodes[$i].Role
        if($Role -icontains 'Server' -and -not($PrimaryServerMachine))
        {
            $PrimaryServerMachine  = $AllNodes[$i].NodeName
        }

        if($Role -icontains 'Portal' -and -not($PrimaryPortalMachine))
        {
            $PrimaryPortalMachine= $AllNodes[$i].NodeName
        }
        if($Role -icontains 'DataStore')
        {
            $DsTypes = $AllNodes[$i].DataStoreTypes
            if($DsTypes -icontains "Relational" -and -not($PrimaryDataStore))
            {
                $PrimaryDataStore = $AllNodes[$i].NodeName 
            }
            
        }
    }

    Node $AllNodes.NodeName
    { 
        $PSAPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.Password -AsPlainText -Force
        $PSACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.UserName, $PSAPassword )

        if($ConfigurationData.ConfigData.Federation){
            $PortalHostName = $ConfigurationData.ConfigData.Federation.PortalHostName
            $PortalPort = $ConfigurationData.ConfigData.Federation.PortalPort
            $PortalContext = $ConfigurationData.ConfigData.Federation.PortalContext

            if($ConfigurationData.ConfigData.Federation.PrimarySiteAdmin){
                $PortalFedPSAPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.Federation.PrimarySiteAdmin.Password -AsPlainText -Force
                $PortalFedPSACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.Federation.PrimarySiteAdmin.UserName, $PortalFedPSAPassword )
                $PortalFederationCredential = $PortalFedPSACredential
            }else{
                $PortalFederationCredential = $PSACredential
            }
        }else{
        
            $ServerCheck = (($AllNodes | Where-Object { $_.Role -icontains 'Server' }  | Measure-Object).Count -gt 0)
            $DataStoreCheck = (($AllNodes | Where-Object { $_.Role -icontains 'DataStore' }  | Measure-Object).Count -gt 0)
            $PortalCheck = (($AllNodes | Where-Object { $_.Role -icontains 'Portal' }  | Measure-Object).Count -gt 0)
            if($ServerCheck -and $PortalCheck)
            {
                $Federation = $True

                if($DataStoreCheck)
                {
                    $HostingServer = $True
                }
            }

            if(lb){
                if(serverwa & portalwa){
                    
                }elseif(serverwa & noportalwa){

                }elseif(noserverwa & portalwa){

                }
            }else{
                if(wa){
                    if(serverwa & portalwa){

                    }elseif(serverwa & noportalwa){

                    }elseif(noserverwa & portalwa){

                    }
                }else{

                }
            }

        }



        ArcGIS_Federation Federate
        {
            PortalHostName = $PortalHostName
            PortalPort = $PortalPort
            PortalContext = $PortalContext
            ServiceUrlHostName = $ServiceUrlHostName
            ServiceUrlContext = $ServiceUrlContext
            ServiceUrlPort = $ServiceUrlPort
            ServerSiteAdminUrlHostName = $ServerSiteAdminUrlHostName
            ServerSiteAdminUrlPort = $ServerSiteAdminUrlPort
            ServerSiteAdminUrlContext = $ServerSiteAdminUrlContext
            Ensure = "Present"
            RemoteSiteAdministrator = $PortalFederationCredential
            SiteAdministrator = $PSACredential
            ServerRole = if($HostingServer){'HOSTING_SERVER'}else{'FEDERATED_SERVER'}
            ServerFunctions = $ConfigurationData.ConfigData.ServerRole
            DependsOn = $Depends
        }






    }



}