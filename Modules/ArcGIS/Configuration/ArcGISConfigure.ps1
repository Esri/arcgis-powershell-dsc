Configuration ArcGISConfigure
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS
    Import-DscResource -Name MSFT_xFirewall
    Import-DscResource -Name ArcGIS_FileShare
    Import-DscResource -Name ArcGIS_Server
    Import-DscResource -Name ArcGIS_WindowsService
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -Name ArcGIS_Portal
    Import-DscResource -Name ArcGIS_DataStore
    Import-DscResource -Name ArcGIS_IIS_TLS
    Import-DscResource -Name ArcGIS_WebAdaptor
    Import-DscResource -Name ArcGIS_Federation
    Import-DscResource -Name ArcGIS_TLSCertificateImport
    Import-DscResource -Name ArcGIS_LB
    Import-DscResource -Name ArcGIS_GeoEvent
    Import-DSCResource -Name ArcGIS_EGDB
    Import-DSCResource -Name ArcGIS_WaitForComponent
    Import-DSCResource -Name ArcGIS_WaitForFileShare
    Import-DSCResource -Name ArcGIS_WaitForSQLServer
    Import-DSCResource -Name ArcGIS_DataStoreItem
    Import-DSCResource -Name ArcGIS_Server_TLS
    Import-DSCResource -Name ArcGIS_Portal_TLS
    
    $PrimaryServerMachine = ""
    $PrimaryPortalMachine = ""
    $PrimaryDataStore = ""
    $PrimaryBigDataStore = ""
    $PrimaryTileCache = ""
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
            if($DsTypes -icontains "SpatioTemporal" -and -not($PrimaryBigDataStore))
            {
                $PrimaryBigDataStore = $AllNodes[$i].NodeName
            }
            if($DsTypes -icontains "TileCache" -and -not($PrimaryTileCache))
            {
                $PrimaryTileCache = $AllNodes[$i].NodeName
            }
        }
    }

    Node $AllNodes.NodeName
    { 
        $FileShareMachine = ($AllNodes | Where-Object { $_.Role -icontains 'FileShare' }).NodeName

        $MachineFQDN = Get-FQDN $Node.NodeName

        $SAPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.Credentials.ServiceAccount.Password -AsPlainText -Force
        $SACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.Credentials.ServiceAccount.UserName, $SAPassword )

        $PSAPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.Password -AsPlainText -Force
        $PSACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.UserName, $PSAPassword )

        $Federation = if($ConfigurationData.ConfigData.Federation){$true}else{$false}

        if(-not($Federation))
        {
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
        }

        if(-Not($ConfigurationData.ConfigData.Credentials.ServiceAccount.IsDomainAccount)){
            User ArcGIS_RunAsAccount
            {
                UserName = $ConfigurationData.ConfigData.Credentials.ServiceAccount.UserName
                Password = $SACredential
                FullName = 'ArcGIS Run As Account'
                Ensure = "Present"
                PasswordChangeRequired = $false
                PasswordNeverExpires = $true
            }
        }

        if($ConfigurationData.ConfigData.DebugMode) 
        {
			Group-Object RemoteDesktopUsers
            {
                GroupName = 'Remote Desktop Users'
                Ensure = 'Present'
                MembersToInclude = $ConfigurationData.ConfigData.Credentials.ServiceAccount.UserName
                DependsOn = if(-not($ConfigurationData.ConfigData.Credentials.ServiceAccount.IsDomainAccount)){@('[User]ArcGIS_RunAsAccount')}else{@()}
            }			
        }

        #Removes the Requirement for the Ordering inside roles.
        $NodeRoleArray = @()
        if($Node.Role -icontains "FileShare")
        {
            $NodeRoleArray += "FileShare"
        }
        if($Node.Role -icontains "RasterDataStoreItem")
        {
            $NodeRoleArray += "RasterDataStoreItem"
        }
        if($Node.Role -icontains "Server")
        {
            $NodeRoleArray += "Server"
        }
        if($Node.Role -icontains "Portal")
        {
            $NodeRoleArray += "Portal"
        }
        if($Node.Role -icontains "DataStore")
        {
            $NodeRoleArray += "DataStore"
        }
        if($Node.Role -icontains "ServerWebAdaptor")
        {
            $NodeRoleArray += "ServerWebAdaptor"
        }
        if($Node.Role -icontains "PortalWebAdaptor")
        {
            $NodeRoleArray += "PortalWebAdaptor"
        }
        if($Node.Role -icontains "LoadBalancer")
        {
            $NodeRoleArray += "LoadBalancer"
        }

        for ( $i = 0; $i -lt $NodeRoleArray.Count; $i++ )
        {
            $NodeRole = $NodeRoleArray[$i]
            Switch($NodeRole)
            {
                'Server'{
                    $Depends = @()
                    
                    $IsWebGIS = (($AllNodes | Where-Object { $_.Role -icontains 'Portal' }  | Measure-Object).Count -gt 0)
                    $IsMultiMachineServer = (($AllNodes | Where-Object { $_.Role -icontains 'Server' }  | Measure-Object).Count -gt 1)
                    $HasDataStoreNodes = (($AllNodes | Where-Object { $_.Role -icontains 'DataStore' }  | Measure-Object).Count -gt 0)
                    
                    $OpenFirewallPorts = (-not($IsWebGIS) -or ($ConfigData.ServerEndPoint -as [ipaddress]) -or $HasDataStoreNodes -or $IsMultiMachineServer)
                    
                    if($OpenFirewallPorts) # Server only deployment or behind an ILB or has DataStore nodes that need to register using admin			
                    {
                        $Depends += '[xFirewall]Server_FirewallRules'

                        xFirewall Server_FirewallRules
                        {
                                Name                  = "ArcGISServer" 
                                DisplayName           = "ArcGIS for Server" 
                                DisplayGroup          = "ArcGIS for Server" 
                                Ensure                = 'Present' 
                                Access                = "Allow" 
                                State                 = "Enabled" 
                                Profile               = ("Domain","Private","Public") 
                                LocalPort             = ("6080","6443")                       
                                Protocol              = "TCP" 
                        }
                    }    	

                    if($IsMultiMachineServer) 
                    {
                        $Depends += '[xFirewall]Server_FirewallRules_Internal' 
                        xFirewall Server_FirewallRules_Internal
                        {
                                Name                  = "ArcGISServerInternal" 
                                DisplayName           = "ArcGIS for Server Internal RMI" 
                                DisplayGroup          = "ArcGIS for Server" 
                                Ensure                = "Present" 
                                Access                = "Allow" 
                                State                 = "Enabled" 
                                Profile               = ("Domain","Private","Public")
                                LocalPort             = ("4000-4004")
                                Protocol              = "TCP" 
                        }

                        if($ConfigurationData.ConfigData.ServerRole -ieq 'GeoAnalytics') 
                        {  
                            $Depends += '[xFirewall]GeoAnalytics_InboundFirewallRules' 
                            $Depends += '[xFirewall]GeoAnalytics_OutboundFirewallRules' 

                            xFirewall GeoAnalytics_InboundFirewallRules
                            {
                                    Name                  = "ArcGISGeoAnalyticsInboundFirewallRules" 
                                    DisplayName           = "ArcGIS GeoAnalytics" 
                                    DisplayGroup          = "ArcGIS GeoAnalytics" 
                                    Ensure                = 'Present'
                                    Access                = "Allow" 
                                    State                 = "Enabled" 
                                    Profile               = ("Domain","Private","Public")
                                    LocalPort             = ("2181","2182","2190","7077")	# Spark and Zookeeper
                                    Protocol              = "TCP" 
                            }

                            xFirewall GeoAnalytics_OutboundFirewallRules
                            {
                                    Name                  = "ArcGISGeoAnalyticsOutboundFirewallRules" 
                                    DisplayName           = "ArcGIS GeoAnalytics" 
                                    DisplayGroup          = "ArcGIS GeoAnalytics" 
                                    Ensure                = 'Present'
                                    Access                = "Allow" 
                                    State                 = "Enabled" 
                                    Profile               = ("Domain","Private","Public")
                                    LocalPort             = ("2181","2182","2190","7077")	# Spark and Zookeeper
                                    Protocol              = "TCP" 
                                    Direction             = "Outbound"    
                            }

                            xFirewall GeoAnalyticsCompute_InboundFirewallRules
                            {
                                    Name                  = "ArcGISGeoAnalyticsComputeInboundFirewallRules" 
                                    DisplayName           = "ArcGIS GeoAnalytics" 
                                    DisplayGroup          = "ArcGIS GeoAnalytics" 
                                    Ensure                = 'Present'
                                    Access                = "Allow" 
                                    State                 = "Enabled" 
                                    Profile               = ("Domain","Private","Public")
                                    LocalPort             = ("56540-56550")	# GA Compute
                                    Protocol              = "TCP" 
                            }

                            xFirewall GeoAnalyticsCompute_OutboundFirewallRules
                            {
                                    Name                  = "ArcGISGeoAnalyticsComputeOutboundFirewallRules" 
                                    DisplayName           = "ArcGIS GeoAnalytics" 
                                    DisplayGroup          = "ArcGIS GeoAnalytics" 
                                    Ensure                = 'Present'
                                    Access                = "Allow" 
                                    State                 = "Enabled" 
                                    Profile               = ("Domain","Private","Public")
                                    LocalPort             = ("56540-56550")	# GA Compute
                                    Protocol              = "TCP" 
                                    Direction             = "Outbound"    
                            }
                        }
                    }
                    
                    ArcGIS_WindowsService ArcGIS_for_Server_Service
                    {
                        Name = 'ArcGIS Server'
                        Credential = $SACredential
                        StartupType = 'Automatic'
                        State = 'Running'
                        DependsOn = $Depends
                    }
                    $Depends += '[ArcGIS_WindowsService]ArcGIS_for_Server_Service' 

                    $ConfigStoreLocation =  $ConfigurationData.ConfigData.Server.ConfigStoreLocation
                    $ServerDirectoriesRootLocation = $ConfigurationData.ConfigData.Server.ServerDirectoriesRootLocation

                    if($FileShareMachine)
                    {
                        #$ConfigStoreLocation = "\\$($FileShareMachine)\$($ConfigurationData.ConfigData.FileShareName)\$($ConfigurationData.ConfigData.Server.ConfigStoreLocation)"
                        #$ServerDirectoriesRootLocation = "\\$($FileShareMachine)\$($ConfigurationData.ConfigData.FileShareName)\$($ConfigurationData.ConfigData.Server.ServerDirectoriesRootLocation)"
                        $FilePathsForServer = @()
                        $FilePathsForServer += $ConfigStoreLocation
                        $FilePathsForServer += $ServerDirectoriesRootLocation
                        
                        if($ConfigurationData.ConfigData.Credentials.ServiceAccount.IsDomainAccount){
                            $FileShareCredential = $SACredential
                        }else{
                            $FileShareCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("$FileShareMachine\$($ConfigurationData.ConfigData.Credentials.ServiceAccount.UserName)", $SAPassword )
                        }

                        if($Node.WMFVersion -gt 4){
                            WaitForAll "WaitForAllFileShareServer$($Node.NodeName)"{
                                ResourceName = "[ArcGIS_FileShare]FileShare"
                                NodeName = $FileShareMachine
                                RetryIntervalSec = 20
                                RetryCount = 30
                                DependsOn = $Depends
                            }
                            $Depends += "[WaitForAll]WaitForAllFileShareServer$($Node.NodeName)"
                        }else{
                            ArcGIS_WaitForFileShare "WaitForFileShareServer$($Node.NodeName)"
                            {
                                FilePaths = ($FilePathsForServer -join ',')
                                Ensure = "Present"
                                RetryIntervalSec = 20
                                RetryCount = 30
                                Credential = $FileShareCredential
                                DependsOn = $Depends
                            }
                            $Depends += "[ArcGIS_WaitForFileShare]WaitForFileShareServer$($Node.NodeName)"
                        }
                    }
                    <#else
                    {
                        File ConfigStoreRootLocation
                        {
                            Type = 'Directory'
                            DestinationPath  = $ConfigStoreLocation
                            Ensure = 'Present'
                            Force = $true
                        }
                    }#>

                    ArcGIS_Service_Account Server_RunAs_Account
                    {
                        Name = 'ArcGIS Server'
                        RunAsAccount = $SACredential
                        Ensure = 'Present'
                        DependsOn = $Depends
                    }

                    $Depends += '[ArcGIS_Service_Account]Server_RunAs_Account' 
                    

                    if($Node.NodeName -ine $PrimaryServerMachine)
                    {
                        if($Node.WMFVersion -gt 4){
                            WaitForAll "WaitForAllServer$($PrimaryServerMachine)"{
                                ResourceName = "[ArcGIS_Server]Server$($PrimaryServerMachine)"
                                NodeName = $PrimaryServerMachine
                                RetryIntervalSec = 60
                                RetryCount = 100
                                DependsOn = $Depends
                            }
                            $Depends += "[WaitForAll]WaitForAllServer$($PrimaryServerMachine)"
                        }else{
                            ArcGIS_WaitForComponent "WaitForServer$($PrimaryServerMachine)"
                            {
                                Component = "Server"
                                InvokingComponent = "Server"
                                ComponentHostName = (Get-FQDN $PrimaryServerMachine)
                                ComponentContext = "arcgis"
                                Ensure = "Present"
                                Credential = $PSACredential
                                RetryIntervalSec = 60
                                RetryCount = 100
                            }
                            $Depends += "[ArcGIS_WaitForComponent]WaitForServer$($PrimaryServerMachine)"
                        }
                    }

                    ArcGIS_Server "Server$($Node.NodeName)"
                    {
                        Ensure = 'Present'
                        SiteAdministrator = $PSACredential
                        ConfigurationStoreLocation = $ConfigStoreLocation
                        ServerDirectoriesRootLocation = $ServerDirectoriesRootLocation
                        Join =  if($Node.NodeName -ine $PrimaryServerMachine) { $true } else { $false } 
                        PeerServerHostName = Get-FQDN $PrimaryServerMachine
                        DependsOn = $Depends
                        LogLevel = if($ConfigurationData.ConfigData.DebugMode) { 'DEBUG' } else { 'WARNING' }
                        SingleClusterMode = if(($AllNodes | Where-Object { $_.Role -icontains 'Server' }  | Measure-Object).Count -gt 0) { $true } else { $false }
                    }

                    $Depends += "[ArcGIS_Server]Server$($Node.NodeName)"

                    if($ConfigurationData.ConfigData.GeoEventServer) 
                    { 
                        ArcGIS_Service_Account GeoEvent_RunAs_Account
                        {
                            Name = 'ArcGISGeoEvent'
                            RunAsAccount = $SACredential
                            Ensure =  "Present"
                            DependsOn = $Depends
                            DataDir = "$env:ProgramData\Esri\GeoEvent"
                        }  

                        $Depends += "[ArcGIS_Service_Account]GeoEvent_RunAs_Account"

                        ArcGIS_WindowsService ArcGIS_GeoEvent_Service
                        {
                            Name = 'ArcGISGeoEvent'
                            Credential = $SACredential
                            StartupType = 'Automatic'
                            State = 'Running'
                            DependsOn = $Depends
                        }
                        $Depends += "[ArcGIS_WindowsService]ArcGIS_GeoEvent_Service"

                        xFirewall GeoEvent_FirewallRules
                        {
                            Name                  = "ArcGISGeoEventFirewallRules" 
                            DisplayName           = "ArcGIS GeoEvent" 
                            DisplayGroup          = "ArcGIS GeoEvent" 
                            Ensure                = "Present"
                            Access                = "Allow" 
                            State                 = "Enabled" 
                            Profile               = ("Domain","Private","Public")
                            LocalPort             = ("6143","6180","5565","5575")
                            Protocol              = "TCP" 
                            DependsOn             = $Depends
                        }
                        $Depends += "[xFirewall]GeoEvent_FirewallRules"

                        ArcGIS_GeoEvent ArcGIS_GeoEvent
                        {
                            Name	                  = 'ArcGIS GeoEvent'
                            Ensure	                  =  "Present"
                            SiteAdministrator         = $PSACredential
                            WebSocketContextUrl       = "wss://$($MachineFQDN):6143/geoevent"
                            DependsOn                 = $Depends
                            #SiteAdminUrl             = if($ConfigData.ExternalDNSName) { "https://$($ConfigData.ExternalDNSName)/arcgis/admin" } else { $null }
                        }	
                        $Depends += "[xFirewall]GeoEvent_FirewallRules"
                        
                        if($IsMultiMachineServer) 
                        {
                            xFirewall GeoEvent_FirewallRules_MultiMachine
                            {
                                Name                  = "ArcGISGeoEventFirewallRulesCluster" 
                                DisplayName           = "ArcGIS GeoEvent Extension Cluster" 
                                DisplayGroup          = "ArcGIS GeoEvent Extension" 
                                Ensure                =  "Present"
                                Access                = "Allow" 
                                State                 = "Enabled" 
                                Profile               = ("Domain","Private","Public")
                                LocalPort             = ("2181","2182","2190","27271","27272","27273")										
                                Protocol              = "TCP" 
                                DependsOn             = $Depends
                            }
                            $Depends += "[xFirewall]GeoEvent_FirewallRules_MultiMachine"

                            xFirewall GeoEvent_FirewallRules_MultiMachine_OutBound
                            {
                                Name                  = "ArcGISGeoEventFirewallRulesClusterOutbound" 
                                DisplayName           = "ArcGIS GeoEvent Extension Cluster Outbound" 
                                DisplayGroup          = "ArcGIS GeoEvent Extension" 
                                Ensure                =  "Present"
                                Access                = "Allow" 
                                State                 = "Enabled" 
                                Profile               = ("Domain","Private","Public")
                                RemotePort            = ("2181","2182","2190","27271","27272","27273")										
                                Protocol              = "TCP" 
                                Direction             = "Outbound"    
                                DependsOn             = $Depends
                            }
                            $Depends += "[xFirewall]GeoEvent_FirewallRules_MultiMachine_OutBound"
                            xFirewall GeoEventService_Firewall
                            {
                                Name                  = "ArcGISGeoEventGateway"
                                DisplayName           = "ArcGIS GeoEvent Gateway"
                                DisplayGroup          = "ArcGIS GeoEvent Gateway"
                                Ensure                = 'Present'
                                Access                = "Allow"
                                State                 = "Enabled"
                                Profile               = ("Domain","Private","Public")
                                LocalPort             = ("9092")
                                Protocol              = "TCP"
                                DependsOn             = $Depends
                            }
                            $Depends += "[xFirewall]GeoEventService_Firewall"
                        }

                        if(Get-Service 'ArcGISGeoEventGateway' -ErrorAction Ignore) 
                        {
                            ArcGIS_WindowsService ArcGIS_GeoEventGateway_Service
                            {
                                Name		= 'ArcGISGeoEventGateway'
                                Credential  = $SACredential
                                StartupType = 'Automatic'
                                State       = 'Running'
                                DependsOn   = $Depends
                            }
                            $Depends += "[ArcGIS_WindowsService]ArcGIS_GeoEventGateway_Service"
                        }
                    }

                    if(($Node.NodeName -ieq $PrimaryServerMachine) -and $HasSQLServer)
                    {
                        ForEach($svr in ($AllNodes | Where-Object { $_.Role -icontains 'SQLServer' }))
                        {
                            
                            $DatabaseServerAdministratorPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.SQLServer.DatabaseAdminUser.Password -AsPlainText -Force
                            $DatabaseServerAdministratorCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.SQLServer.DatabaseAdminUser.UserName, $DatabaseServerAdministratorPassword )

                            if($Node.WMFVersion -gt 4){
                                WaitForAll "WaitForAllSQLServer$($svr.NodeName)"{
                                    ResourceName = "[Script]CreateDatabaseAdminUser"
                                    NodeName = $svr.NodeName
                                    RetryIntervalSec = 60
                                    RetryCount = 60
                                    DependsOn = $Depends
                                }
                                $Depends += "[WaitForAll]WaitForAllSQLServer$($svr.NodeName)"
                            }else{
                                ArcGIS_WaitForSQLServer "WaitForSQLServer$($svr.NodeName)"
                                {
                                    SQLServerMachineName = (Get-FQDN $svr.NodeName)
                                    Ensure = 'Present'
                                    Credential = $DatabaseServerAdministratorCredential
                                    RetryIntervalSec = 60
                                    RetryCount = 60
                                }
                                $Depends += "[WaitForAll]ArcGIS_WaitForSQLServer$($svr.NodeName)"
                            }

                            $SDEUserPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.SQLServer.SDEUser.Password -AsPlainText -Force
                            $SDEUserCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.SQLServer.SDEUser.UserName, $SDEUserPassword )
                            
                            $DatabaseUserPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.SQLServer.DatabaseUser.Password -AsPlainText -Force
                            $DatabaseUserCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.SQLServer.DatabaseUser.UserName, $DatabaseUserPassword )

                            $DatabaseServerHostName = (Get-FQDN $svr.NodeName)
                            $DatabaseName = $ConfigurationData.ConfigData.SQLServer.DatabaseName

                            if(($DatabaseOption -ine 'None') -and $DatabaseServerHostName -and $DatabaseName -and $DatabaseServerAdministratorCredential -and $SDEUserCredential -and $DatabaseUserCredential)
                            {
                                ArcGIS_EGDB RegisterEGDB
                                {
                                    DatabaseServer              = $DatabaseServerHostName
                                    DatabaseName                = $DatabaseName
                                    ServerSiteAdministrator     = $PSACredential
                                    DatabaseServerAdministrator = $DatabaseServerAdministratorCredential
                                    SDEUser                     = $SDEUserCredential
                                    DatabaseUser                = $DatabaseUserCredential
                                    IsManaged                   = $ConfigurationData.ConfigData.SQLServer.IsManaged
                                    EnableGeodatabase           = $ConfigurationData.ConfigData.SQLServer.EnableGeodatabase
                                    DatabaseType                = 'SQLServerDatabase'
                                    Ensure                      = 'Present'
                                    DependsOn                   = $Depends
                                }
                                $Depends += "[ArcGIS_EGDB]RegisterEGDB"
                            }
                        }
                    }

                    if((($AllNodes | Where-Object { ($_.Role -icontains 'LoadBalancer')}  | Measure-Object).Count -eq 0))
                    {
                        if(($AllNodes | Where-Object { ($_.Role -icontains 'ServerWebAdaptor')}  | Measure-Object).Count -eq 0)
                        {
                            if($ConfigurationData.ConfigData.Server.SslCertifcate.Path)
                            {
                                ArcGIS_Server_TLS "Server_TLS_$($Node.NodeName)"
                                {
                                    Ensure = 'Present'
                                    SiteName = 'arcgis'
                                    SiteAdministrator = $PSACredential                         
                                    CName = $ConfigurationData.ConfigData.Server.SslCertifcate.Alias
                                    RegisterWebAdaptorForCName = $False
                                    CertificateFileLocation = $ConfigurationData.ConfigData.Server.SslCertifcate.Path
                                    CertificatePassword = $ConfigurationData.ConfigData.Server.SslCertifcate.Password
                                    EnableSSL = $True
                                    DependsOn =  $Depends
                                } 
                            }
                            else
                            {
                                ArcGIS_Server_TLS "Server_TLS_$($Node.NodeName)"
                                {
                                    Ensure = 'Present'
                                    SiteName = 'arcgis'
                                    SiteAdministrator = $PSACredential                         
                                    CName = $MachineFQDN
                                    RegisterWebAdaptorForCName = $False
                                    EnableSSL = $True
                                    DependsOn =  $Depends
                                } 
                            }
                        }
                        
                        if($Federation -and ($Node.NodeName -ieq $PrimaryServerMachine))
                        {
                            if(($AllNodes | Where-Object { ($_.Role -icontains 'ServerWebAdaptor') -or ($_.Role -icontains 'PortalWebAdaptor')}  | Measure-Object).Count -eq 0)
                            {
                                if($PrimaryPortalMachine)
                                {
                                    if($PrimaryServerMachine -ine $PrimaryPortalMachine)
                                    {
                                        $PortalHostName = Get-FQDN $PrimaryPortalMachine
                                        $PortalPort = 7443
                                        $PortalContext = "arcgis"
                                        if($Node.WMFVersion -gt 4){
                                            WaitForAll "WaitForAllPortalConfigToCompleteServerFederation$($PrimaryPortalMachine)"{
                                                ResourceName = "[ArcGIS_Portal]Portal$($PrimaryPortalMachine)"
                                                NodeName = $PrimaryPortalMachine
                                                RetryIntervalSec = 60
                                                RetryCount = 60
                                                DependsOn = $Depends
                                            }
                                            $Depends += "[WaitForAll]WaitForAllPortalConfigToCompleteServerFederation$($PrimaryPortalMachine)"
                                        }else{
                                            ArcGIS_WaitForComponent "WaitForPortalConfigToCompleteServerFederation$($PrimaryPortalMachine)"{
                                                Component = "Portal"
                                                InvokingComponent = "Server"
                                                ComponentHostName = $PortalHostName
                                                ComponentContext = $PortalContext
                                                Ensure = "Present"
                                                Credential =  $PSACredential
                                                RetryIntervalSec = 60
                                                RetryCount = 60
                                                DependsOn = $Depends
                                            }
                                            $Depends += "[ArcGIS_WaitForComponent]WaitForPortalConfigToCompleteServerFederation$($PrimaryPortalMachine)"
                                        }
                                    }
                                    else
                                    {
                                        Write-Verbose "Federation happens in primary portal machine"
                                    }
                                }
                                else
                                {
                                    $PortalHostName = $ConfigurationData.ConfigData.Federation.PortalHostName
                                    $PortalPort = $ConfigurationData.ConfigData.Federation.PortalPort
                                    $PortalContext = $ConfigurationData.ConfigData.Federation.PortalContext
                                    
                                    $PortalFedPSAPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.Federation.PrimarySiteAdmin.Password -AsPlainText -Force
                                    $PortalFedPSACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.Federation.PrimarySiteAdmin.UserName, $PortalFedPSAPassword )

                                }
                            }
                            elseif(($AllNodes | Where-Object { ($_.Role -icontains 'ServerWebAdaptor') -or ($_.Role -icontains 'PortalWebAdaptor')}  | Measure-Object).Count -gt 0)
                            {
                                if(($AllNodes | Where-Object { ($_.Role -icontains 'PortalWebAdaptor')}  | Measure-Object).Count -gt 0)
                                {
                                    if(-not(($AllNodes | Where-Object { ($_.Role -icontains 'ServerWebAdaptor')}  | Measure-Object).Count -gt 0))
                                    {
                                        $PortalWAMachineName = ($AllNodes | Where-Object { ($_.Role -icontains 'PortalWebAdaptor')} | Select-Object -First 1).NodeName
                                        
                                        $PortalHostName = (Get-FQDN $PortalWAMachineName)
                                        $PortalPort = 443
                                        $PortalContext = $ConfigurationData.ConfigData.PortalContext
                                        if($Node.WMFVersion -gt 4){
                                            WaitForAll "WaitForAllWebadaptorPortalConfigFederation$($PortalWAMachineName)"{
                                                ResourceName = "[ArcGIS_WebAdaptor]ConfigurePortal$($PortalHostName)"
                                                NodeName = $PortalWAMachineName
                                                RetryIntervalSec = 60
                                                RetryCount = 60
                                                DependsOn = $Depends
                                            }
                                            $Depends += "[WaitForAll]WaitForAllPortalConfigToCompleteServerFederation$($PortalWAMachineName)"
                                        }else{
                                            ArcGIS_WaitForComponent "WaitForWebadaptorPortalConfigFederation$($PortalWAMachineName)"
                                            {
                                                Component = "PortalWA"
                                                InvokingComponent = "Server"
                                                ComponentHostName = $PortalHostName
                                                ComponentContext = $PortalContext
                                                Ensure = "Present"
                                                Credential =  $PSACredential
                                                RetryIntervalSec = 60
                                                RetryCount = 60
                                                DependsOn = $Depends
                                            }
                                            $Depends += "[ArcGIS_WaitForComponent]WaitForWebadaptorPortalConfigFederation$($PortalWAMachineName)"
                                        }
                                    }
                                }
                            }
                            if($PortalHostName -and $PortalPort -and $PortalContext )
                            {
                                $FederationFlag = $True
                                if($HostingServer)
                                {
                                    if($PrimaryDataStore)
                                    {
                                        if($Node.WMFVersion -gt 4){
                                            WaitForAll "WaitForAllDataStoreInServer$($PrimaryDataStore)"{
                                                ResourceName = "[ArcGIS_DataStore]DataStore$($PrimaryDataStore)"
                                                NodeName = $PrimaryDataStore
                                                RetryIntervalSec = 60
                                                RetryCount = 100
                                                DependsOn = $Depends
                                            }
                                            $Depends += "[WaitForAll]WaitForAllDataStoreInServer$($PrimaryDataStore)"
                                        }else{
                                            ArcGIS_WaitForComponent  "WaitForDataStoreInServer$($PrimaryDataStore)"
                                            {
                                                Component = "DataStore"
                                                InvokingComponent = "Server"
                                                ComponentHostName = (Get-FQDN $PrimaryServerMachine)
                                                ComponentContext = "arcgis"
                                                Ensure = "Present"
                                                Credential =  $PSACredential
                                                RetryIntervalSec = 60
                                                RetryCount = 100
                                                DependsOn = $Depends
                                            }
                                            $Depends += "[ArcGIS_WaitForComponent]WaitForDataStoreInServer$($PrimaryDataStore)"
                                        }
                                    }
                                    else
                                    {
                                        $FederationFlag = $False
                                    }
                                }
                                if($FederationFlag)
                                {
                                    if($ConfigurationData.ConfigData.Server.SslCertifcate.Alias)
                                    {
                                        $ServerFedHostName = $ConfigurationData.ConfigData.Server.SslCertifcate.Alias
                                    }
                                    else
                                    {
                                        $ServerFedHostName = $MachineFQDN
                                    }

                                    if($ConfigurationData.ConfigData.Portal.SslCertifcate.Alias)
                                    {
                                        $PortalFEDHostName = $ConfigurationData.ConfigData.Portal.SslCertifcate.Alias  
                                    }
                                    else
                                    {
                                        $PortalFEDHostName = $PortalHostName
                                    }

                                    ArcGIS_Federation FederateInServer
                                    {
                                        PortalHostName = $PortalFEDHostName
                                        PortalPort = $PortalPort
                                        PortalContext = $PortalContext
                                        ServiceUrlHostName = $ServerFedHostName
                                        ServiceUrlContext = 'arcgis'
                                        ServiceUrlPort = 6443
                                        ServerSiteAdminUrlHostName = $ServerFedHostName
                                        ServerSiteAdminUrlPort = 6443
                                        ServerSiteAdminUrlContext ='arcgis'
                                        Ensure = "Present"
                                        RemoteSiteAdministrator = if($PortalFedPSACredential){$PortalFedPSACredential}else{$PSACredential}
                                        SiteAdministrator = $PSACredential
                                        ServerRole = if($HostingServer){'HOSTING_SERVER'}else{'FEDERATED_SERVER'}
                                        ServerFunctions = $ConfigurationData.ConfigData.ServerRole
                                        DependsOn = $Depends
                                    }
                                }
                            }
                        }
                    }
                }
                'Portal'{
                    $Depends = @()
                    
                    if(-not($ConfigurationData.ConfigData.Credentials.ServiceAccount.IsDomainAccount)){
                        $Depends += '[User]ArcGIS_RunAsAccount'
                    }

                    $IsMultiMachinePortal = (($AllNodes | Where-Object { $_.Role -icontains 'Portal' }  | Measure-Object).Count -gt 1)
                    if($IsMultiMachinePortal -or ($ConfigData.PortalEndPoint -as [ipaddress]))
                    {
                        xFirewall Portal_FirewallRules
                        {
                                Name                  = "PortalforArcGIS" 
                                DisplayName           = "Portal for ArcGIS" 
                                DisplayGroup          = "Portal for ArcGIS" 
                                Ensure                = 'Present'
                                Access                = "Allow" 
                                State                 = "Enabled" 
                                Profile               = ("Domain","Private","Public")
                                LocalPort             = ("7080","7443","7654")                         
                                Protocol              = "TCP" 
                        }
                        $Depends += @('[xFirewall]Portal_FirewallRules')
                    }
                    else 
                    {  # If single machine, need to open 7443 to allow federation over private portal URL and 6443 for changeServerRole
                        xFirewall Portal_FirewallRules
                        {
                                Name                  = "PortalforArcGIS" 
                                DisplayName           = "Portal for ArcGIS" 
                                DisplayGroup          = "Portal for ArcGIS" 
                                Ensure                = 'Present'
                                Access                = "Allow" 
                                State                 = "Enabled" 
                                Profile               = ("Domain","Private","Public")
                                LocalPort             = ("7443")                         
                                Protocol              = "TCP" 
                        }

                        xFirewall ServerFederation_FirewallRules
                        {
                                Name                  = "ArcGISforServer-Federation" 
                                DisplayName           = "ArcGIS for Server" 
                                DisplayGroup          = "ArcGIS for Server" 
                                Ensure                = 'Present'
                                Access                = "Allow" 
                                State                 = "Enabled" 
                                Profile               = ("Domain","Private","Public")
                                LocalPort             = ("6443")                         
                                Protocol              = "TCP" 
                        }
                    }
                    
                    if($IsMultiMachinePortal) 
                    {
                                                                        
                        xFirewall Portal_Database_OutBound
                        {
                                Name                  = "PortalforArcGIS-Outbound" 
                                DisplayName           = "Portal for ArcGIS Outbound" 
                                DisplayGroup          = "Portal for ArcGIS Outbound" 
                                Ensure                = 'Present' 
                                Access                = "Allow" 
                                State                 = "Enabled" 
                                Profile               = ("Domain","Private","Public")
                                RemotePort            = ("7654","7120","7220", "7005", "7099", "7199", "5701", "5702")  # Elastic Search uses 7120,7220 and Postgres uses 7654 for replication, Hazelcast uses 5701 and 5702 (extra 2 ports for situations where unable to get port)
                                Direction             = "Outbound"                       
                                Protocol              = "TCP" 
                        }  
                        $Depends += @('[xFirewall]Portal_Database_OutBound')
                        
                        xFirewall Portal_Database_InBound
                        {
                                Name                  = "PortalforArcGIS-Inbound" 
                                DisplayName           = "Portal for ArcGIS Inbound" 
                                DisplayGroup          = "Portal for ArcGIS Inbound" 
                                Ensure                = 'Present' 
                                Access                = "Allow" 
                                State                 = "Enabled" 
                                Profile               = ("Domain","Private","Public")
                                LocalPort             = ("7120","7220", "5701", "5702")  # Elastic Search uses 7120,7220, Hazelcast uses 5701 and 5702
                                Protocol              = "TCP" 
                        }  
                        $Depends += @('[xFirewall]Portal_Database_InBound')
                    }

                    Service Portal_for_ArcGIS_Service
                    {
                        Name = 'Portal for ArcGIS'
                        Credential = $SACredential
                        StartupType = 'Automatic'
                        State = 'Running'          
                        DependsOn = $Depends
                    } 

                    $Depends += @('[Service]Portal_for_ArcGIS_Service')

                    $ContentDirectoryLocation = $ConfigurationData.ConfigData.Portal.ContentDirectoryLocation
                    if($FileShareMachine -and $ConfigurationData.ConfigData.FileShareName)
                    {
                        #$ContentDirectoryLocation = "\\$($FileShareMachine)\$($ConfigurationData.ConfigData.FileShareName)\$($ConfigurationData.ConfigData.Portal.ContentDirectoryLocation)"
                        $FilePathsForPortal = @()
                        $FilePathsForPortal += $ContentDirectoryLocation
                        if($ConfigurationData.ConfigData.Credentials.ServiceAccount.IsDomainAccount){
                            $FileShareCredential = $SACredential
                        }else{
                            $FileShareCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("$FileShareMachine\$($ConfigurationData.ConfigData.Credentials.ServiceAccount.UserName)", $SAPassword )
                        }

                        if($Node.WMFVersion -gt 4){
                            WaitForAll "WaitForAllFileSharePortal$($Node.NodeName)"{
                                ResourceName = "[ArcGIS_FileShare]FileShare"
                                NodeName = $FileShareMachine
                                RetryIntervalSec = 20
                                RetryCount = 30
                                DependsOn = $Depends
                            }
                            $Depends += "[WaitForAll]WaitForAllFileSharePortal$($Node.NodeName)"
                        }else{
                            ArcGIS_WaitForFileShare "WaitForFileSharePortal$($Node.NodeName)"{
                                FilePaths = ($FilePathsForPortal -join ',')
                                Ensure = "Present"
                                RetryIntervalSec = 20
                                RetryCount = 30
                                Credential = $FileShareCredential
                                DependsOn = $Depends
                            }
                            $Depends += "[ArcGIS_WaitForFileShare]WaitForFileSharePortal$($Node.NodeName)"
                        }
                    }
                    
                    $DataDirsForPortal = @('HKLM:\SOFTWARE\ESRI\Portal for ArcGIS')

                    if($ContentDirectoryLocation -and (-not($ContentDirectoryLocation.StartsWith('\'))))
                    {
                        $DataDirsForPortal += $ContentDirectoryLocation
                        $DataDirsForPortal += (Split-Path $ContentDirectoryLocation -Parent)

                        File ContentDirectoryLocation
                        {
                            Ensure = "Present"
                            DestinationPath = $ContentDirectoryLocation
                            Type = 'Directory'
                            DependsOn = $Depends
                        }  
                        $Depends += "[File]ContentDirectoryLocation"
                    }

                    ArcGIS_Service_Account Portal_RunAs_Account
                    {
                        Name = 'Portal for ArcGIS'
                        RunAsAccount = $SACredential
                        Ensure = "Present"
                        DataDir = $DataDirsForPortal
                        DependsOn = $Depends
                    }
                    
                    $Depends += @('[ArcGIS_Service_Account]Portal_RunAs_Account')

                    $HasLoadBalancer = (($AllNodes | Where-Object { $_.Role -icontains 'LoadBalancer' }  | Measure-Object).Count -gt 0)
                    $ExternalDNSName = [System.Net.DNS]::GetHostByName($PrimaryPortalMachine).HostName
                    if($ConfigurationData.ConfigData.Portal.SslCertifcate)
                    {
                        $ExternalDNSName = $ConfigurationData.ConfigData.Portal.SslCertifcate.Alias
                    }
                    else
                    {
                        if($HasLoadBalancer)
                        {
                            $LBMachine = ($AllNodes | Where-Object { $_.Role -icontains 'LoadBalancer' }| Sort-Object | Select-Object -First 1).NodeName
                            $ExternalDNSName = [System.Net.DNS]::GetHostByName($LBMachine).HostName
                        }
                        else
                        {
                            if((($AllNodes | Where-Object { ($_.Role -icontains 'PortalWebAdaptor')}  | Measure-Object).Count -gt 0) -and $ConfigurationData.ConfigData.PortalContext)
                            {
                                $PortalWAMachine = ($AllNodes | Where-Object { ($_.Role -icontains 'PortalWebAdaptor') }| Select-Object -First 1).NodeName
                                $ExternalDNSName = [System.Net.DNS]::GetHostByName($PortalWAMachine).HostName
                            }
                        }
                    }
                    
                    if($Node.NodeName -ine $PrimaryPortalMachine)
                    {
                        if($Node.WMFVersion -gt 4){
                            WaitForAll "WaitForAllPortal$($PrimaryPortalMachine)"{
                                ResourceName = "[ArcGIS_Portal]Portal$($PrimaryPortalMachine)"
                                NodeName = $PrimaryPortalMachine
                                RetryIntervalSec = 60
                                RetryCount = 90
                                DependsOn = $Depends
                            }
                            $Depends += "[WaitForAll]WaitForAllPortal$($PrimaryPortalMachine)"
                        }else{
                            ArcGIS_WaitForComponent "WaitForPortal$($PrimaryPortalMachine)"
                            {
                                Component = "Portal"
                                InvokingComponent = "Portal"
                                ComponentHostName = (Get-FQDN $PrimaryPortalMachine)
                                ComponentContext = "arcgis"
                                Ensure = "Present"
                                Credential =  $PSACredential
                                RetryIntervalSec = 60
                                RetryCount = 90
                                DependsOn = $Depends
                            }
                            $Depends += "[ArcGIS_WaitForComponent]WaitForPortal$($PrimaryPortalMachine)"
                        }
                    }   

                    ArcGIS_Portal "Portal$($Node.NodeName)"
                    {
                        Ensure = 'Present'
                        PortalContext = $ConfigurationData.ConfigData.PortalContext
                        PortalAdministrator = $PSACredential 
                        DependsOn =  $Depends
                        AdminEMail = $ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.Email
                        AdminSecurityQuestionIndex = 1
                        AdminSecurityAnswer = "vanilla"
                        ContentDirectoryLocation = $ContentDirectoryLocation
                        Join = if($Node.NodeName -ine $PrimaryPortalMachine) { $true } else { $false } 
                        IsHAPortal = if($IsMultiMachinePortal){$True}else{$False}
                        ExternalDNSName = $ExternalDNSName
                        PortalEndPoint = $MachineFQDN
                        PeerMachineHostName = if($Node.NodeName -ine $PrimaryPortalMachine) { (Get-FQDN $PrimaryPortalMachine) } else { "" }
                        EnableDebugLogging = $True
                    }
                    
                    if($Node.NodeName -ieq $PrimaryPortalMachine -and (($AllNodes | Where-Object { ($_.Role -icontains 'LoadBalancer')}  | Measure-Object).Count -eq 0))
                    {
                        if(($AllNodes | Where-Object { ($_.Role -icontains 'PortalWebAdaptor')}  | Measure-Object).Count -eq 0)
                        {
                            if($ConfigurationData.ConfigData.Portal.SslCertifcate.Alias)
                            {
                                ArcGIS_Portal_TLS "Portal_TLS$($Node.NodeName)"                                   
                                {
                                    Ensure = $Ensure
                                    SiteName = $PortalContext
                                    SiteAdministrator = $PSACredential
                                    CName = $ConfigurationData.ConfigData.Portal.SslCertifcate.Alias
                                    CertificateFileLocation = $ConfigurationData.ConfigData.Portal.SslCertifcate.Path
                                    CertificatePassword = $ConfigurationData.ConfigData.Portal.SslCertifcate.Password
                                    DependsOn = @("[ArcGIS_Portal]Portal$($Node.NodeName)")
                                }
                            }
                        }

                        if($Federation -and (($AllNodes | Where-Object { ($_.Role -icontains 'ServerWebAdaptor') -or ($_.Role -icontains 'PortalWebAdaptor')}  | Measure-Object).Count -eq 0))
                        {
                            if($PrimaryPortalMachine)
                            {
                                if($PrimaryServerMachine -ieq $PrimaryPortalMachine)
                                {
                                    $PortalHostName = Get-FQDN $PrimaryPortalMachine
                                    $PortalPort = 7443
                                    $PortalContext = 'arcgis'
                                    
                                    $FederationFlag = $True
                                    if($HostingServer)
                                    {
                                        if($PrimaryDataStore)
                                        {
                                            if($Node.WMFVersion -gt 4){
                                                WaitForAll "WaitForAllDataStoreInPortal$($PrimaryDataStore)"{
                                                    ResourceName = "[ArcGIS_DataStore]DataStore$($PrimaryDataStore)"
                                                    NodeName = $PrimaryDataStore
                                                    RetryIntervalSec = 60
                                                    RetryCount = 100
                                                    DependsOn = $Depends
                                                }
                                                $Depends += "[WaitForAll]WaitForAllDataStoreInPortal$($PrimaryDataStore)"
                                            }else{
                                                ArcGIS_WaitForComponent  "WaitForDataStoreInPortal$($PrimaryDataStore)"
                                                {
                                                    Component = "DataStore"
                                                    InvokingComponent = "Portal"
                                                    ComponentHostName = (Get-FQDN $PrimaryServerMachine)
                                                    ComponentContext = "arcgis"
                                                    Ensure = "Present"
                                                    Credential =  $PSACredential
                                                    RetryIntervalSec = 60
                                                    RetryCount = 100
                                                    DependsOn = $Depends
                                                }
                                                $Depends += "[ArcGIS_WaitForComponent]WaitForDataStoreInPortal$($PrimaryDataStore)"
                                            }
                                        }
                                        else
                                        {
                                            $FederationFlag = $False
                                        }
                                    }
                                    if($FederationFlag)
                                    {
                                        if($ConfigurationData.ConfigData.Server.SslCertifcate.Alias)
                                        {
                                            $ServerFEDHostName = $ConfigurationData.ConfigData.Server.SslCertifcate.Alias
                                        }
                                        else
                                        {
                                            $ServerFEDHostName = $MachineFQDN  
                                        }

                                        if($ConfigurationData.ConfigData.Portal.SslCertifcate.Alias)
                                        {
                                            $PortalFEDHostName = $ConfigurationData.ConfigData.Portal.SslCertifcate.Alias  
                                        }
                                        else
                                        {
                                            $PortalFEDHostName = $PortalHostName
                                        }

                                        ArcGIS_Federation FederateInPortal
                                        {
                                            PortalHostName = $PortalFEDHostName
                                            PortalPort = $PortalPort
                                            PortalContext = $PortalContext
                                            ServiceUrlHostName = $ServerFEDHostName
                                            ServiceUrlContext = 'arcgis'
                                            ServiceUrlPort = 6443
                                            ServerSiteAdminUrlHostName = $ServerFEDHostName
                                            ServerSiteAdminUrlPort = 6443
                                            ServerSiteAdminUrlContext ='arcgis'
                                            Ensure = "Present"
                                            RemoteSiteAdministrator = $PSACredential
                                            SiteAdministrator = $PSACredential
                                            ServerRole = if($HostingServer){'HOSTING_SERVER'}else{'FEDERATED_SERVER'}
                                            ServerFunctions = $ConfigurationData.ConfigData.ServerRole
                                            DependsOn = @("[ArcGIS_Portal]Portal$($Node.NodeName)")
                                        }
                                    }
                                }
                            }
                        } 
                    }
                    
                }
                'DataStore'{
                    $Depends = @()
                    
                    if(-not($ConfigurationData.ConfigData.Credentials.ServiceAccount.IsDomainAccount)){
                        $Depends += '[User]ArcGIS_RunAsAccount'
                    }

                    Service ArcGIS_DataStore_Service
                    {
                        Name = 'ArcGIS Data Store'
                        Credential = $SACredential
                        StartupType = 'Automatic'
                        State = 'Running'
                        DependsOn = $Depends
                    }  
                    $Depends += '[Service]ArcGIS_DataStore_Service'

                    xFirewall DataStore_FirewallRules
                    {
                            Name                  = "ArcGISDataStore" 
                            DisplayName           = "ArcGIS Data Store" 
                            DisplayGroup          = "ArcGIS Data Store" 
                            Ensure                = 'Present' 
                            Access                = "Allow" 
                            State                 = "Enabled" 
                            Profile               = ("Domain","Private","Public")
                            LocalPort             = ("2443", "9876", "29080", "29081")                        
                            Protocol              = "TCP" 
                            DependsOn             = $Depends
                    } 
                    $Depends += '[xFirewall]DataStore_FirewallRules'

                    $IsMultiMachineDataStore = ($AllNodes | Where-Object { $_.Role -icontains 'DataStore' }  | Measure-Object).Count -gt 0
                    if($IsMultiMachineDataStore) 
                    {
                        # Allow outbound traffic so that database replication can take place
                        xFirewall DataStore_FirewallRules_OutBound
                        {
                            Name                  = "ArcGISDataStore-Out" 
                            DisplayName           = "ArcGIS Data Store Out" 
                            DisplayGroup          = "ArcGIS Data Store" 
                            Ensure                = 'Present'  
                            Access                = "Allow" 
                            State                 = "Enabled" 
                            Profile               = ("Domain","Private","Public")
                            LocalPort             = ("9876")       
                            Direction             = "Outbound"                        
                            Protocol              = "TCP" 
                            DependsOn             = $Depends
                        }
                        $Depends += '[xFirewall]DataStore_FirewallRules_OutBound'
                    }

                    if(($AllNodes | Where-Object { $_.Role -icontains 'DataStore' -and $_.DataStoreTypes -icontains 'SpatioTemporal' }  | Measure-Object).Count -gt 0)
                    {
                        xFirewall SpatioTemporalDataStore_FirewallRules
                        {
                                Name                  = "ArcGISSpatioTemporalDataStore" 
                                DisplayName           = "ArcGIS Data Store" 
                                DisplayGroup          = "ArcGIS Data Store" 
                                Ensure                = 'Present'  
                                Access                = "Allow" 
                                State                 = "Enabled" 
                                Profile               = ("Domain","Private","Public")
                                LocalPort             = ("2443", "9320", "9220")                        
                                Protocol              = "TCP" 
                                DependsOn             = $Depends
                        } 
                        $Depends += '[xFirewall]SpatioTemporalDataStore_FirewallRules'
                    }
                        
                    ArcGIS_Service_Account ArcGIS_DataStore_RunAs_Account
                    {
                        Name = 'ArcGIS Data Store'
                        RunAsAccount = $SACredential
                        Ensure = 'Present'
                        DependsOn = $Depends
                        DataDir = $ConfigurationData.ConfigData.DataStore.ContentDirectoryLocation #DataStoreSpatioTemporalDataDirectory <- Needs to be checked if network location
                    }
                    $Depends += '[ArcGIS_Service_Account]ArcGIS_DataStore_RunAs_Account'

                    if(-not(($Node.Role -icontains "Server") -and ($Node.NodeName -ieq $PrimaryServerMachine)))
                    {
                        if($Node.WMFVersion -gt 4){
                            WaitForAll "WaitForAllServerConfigToComplete$($PrimaryServerMachine)"{
                                ResourceName = "[ArcGIS_Server]Server$($PrimaryServerMachine)"
                                NodeName = $PrimaryServerMachine
                                RetryIntervalSec = 60
                                RetryCount = 100
                                DependsOn = $Depends
                            }
                            $Depends += "[WaitForAll]WaitForAllServerConfigToComplete$($PrimaryServerMachine)"
                        }else{
                            ArcGIS_WaitForComponent "WaitForServerConfigToComplete$($PrimaryServerMachine)"
                            {
                                Component = "Server"
                                InvokingComponent = "DataStore"
                                ComponentHostName = (Get-FQDN $PrimaryServerMachine)
                                ComponentContext = "arcgis"
                                Ensure = "Present"
                                Credential =  $PSACredential
                                RetryIntervalSec = 60
                                RetryCount = 100
                                DependsOn = $Depends
                            }
                            $Depends += "[ArcGIS_WaitForComponent]WaitForServerConfigToComplete$($PrimaryServerMachine)"
                        }
                    }

                    $IsStandByRelational = (($Node.NodeName -ine $PrimaryDataStore) -and ($Node.Role -icontains 'DataStore' -and $Node.DataStoreTypes -icontains 'Relational'))
                    if($IsStandByRelational)
                    {
                        if($Node.WMFVersion -gt 4){
                            WaitForAll "WaitForAllRelationalDataStore$($PrimaryDataStore)"{
                                ResourceName = "[ArcGIS_DataStore]DataStore$($PrimaryDataStore)"
                                NodeName = $PrimaryDataStore
                                RetryIntervalSec = 60
                                RetryCount = 100
                                DependsOn = $Depends
                            }
                            $Depends += "[WaitForAll]WaitForAllRelationalDataStore$($PrimaryDataStore)"
                        }else{
                            ArcGIS_WaitForComponent  "WaitForRelationalDataStore$($PrimaryDataStore)"
                            {
                                Component = "DataStore"
                                InvokingComponent = "DataStore"
                                ComponentHostName = (Get-FQDN $PrimaryServerMachine)
                                ComponentContext = "arcgis"
                                Ensure = "Present"
                                Credential =  $PSACredential
                                RetryIntervalSec = 60
                                RetryCount = 100
                                DependsOn = $Depends
                            }
                            $Depends += "[ArcGIS_WaitForComponent]WaitForRelationalDataStore$($PrimaryDataStore)"
                        }
                    }
                    
                    if(($PrimaryBigDataStore -ine $Node.NodeName) -and ($Node.Role -icontains 'DataStore') -and ($Node.DataStoreTypes -icontains 'SpatioTemporal'))
                    {
                        if($Node.WMFVersion -gt 4){
                            WaitForAll "WaitForAllBigDataStore$($PrimaryBigDataStore)"{
                                ResourceName = "[ArcGIS_DataStore]DataStore$($PrimaryBigDataStore)"
                                NodeName = $PrimaryBigDataStore
                                RetryIntervalSec = 60
                                RetryCount = 100
                                DependsOn = $Depends
                            }
                            $Depends += "[WaitForAll]WaitForAllBigDataStore$($PrimaryBigDataStore)"
                        }else{
                            ArcGIS_WaitForComponent  "WaitForBigDataStore$($PrimaryBigDataStore)"
                            {
                                Component = "SpatioTemporal"
                                InvokingComponent = "DataStore"
                                ComponentHostName = (Get-FQDN $PrimaryServerMachine)
                                ComponentContext = "arcgis"
                                Ensure = "Present"
                                Credential =  $PSACredential
                                RetryIntervalSec = 60
                                RetryCount = 100
                                DependsOn = $Depends
                            }
                            $Depends += "[ArcGIS_WaitForComponent]WaitForBigDataStore$($PrimaryBigDataStore)"
                        }
                    }

                    $IsStandByTileCache = (($PrimaryTileCache -ine $Node.NodeName) -and ($Node.Role -icontains 'DataStore') -and ($Node.DataStoreTypes -icontains 'TileCache'))
                    if($IsStandByTileCache)
                    {
                        if($Node.WMFVersion -gt 4){
                            WaitForAll "WaitForAllTileCache$($PrimaryTileCache)"{
                                ResourceName = "[ArcGIS_DataStore]DataStore$($PrimaryTileCache)"
                                NodeName = $PrimaryTileCache
                                RetryIntervalSec = 60
                                RetryCount = 100
                                DependsOn = $Depends
                            }
                            $Depends += "[WaitForAll]WaitForAllTileCache$($PrimaryTileCache)"
                        }else{
                            ArcGIS_WaitForComponent  "WaitForTileCache$($PrimaryTileCache)"{
                                Component = "TileCache"
                                InvokingComponent = "DataStore"
                                ComponentHostName = (Get-FQDN $PrimaryServerMachine)
                                ComponentContext = "arcgis"
                                Ensure = "Present"
                                Credential =  $PSACredential
                                RetryIntervalSec = 60
                                RetryCount = 100
                                DependsOn = $Depends
                            }
                            $Depends += "[ArcGIS_WaitForComponent]WaitForTileCache$($PrimaryTileCache)"
                        }
                    }

                    ArcGIS_DataStore "DataStore$($Node.NodeName)"
                    {
                        Ensure = 'Present'
                        SiteAdministrator = $PSACredential
                        ServerHostName = [System.Net.DNS]::GetHostByName($PrimaryServerMachine).HostName
                        ContentDirectory = $ConfigurationData.ConfigData.DataStore.ContentDirectoryLocation
                        DependsOn = $Depends
                        IsStandby = $IsStandByRelational
                        DataStoreTypes = $Node.DataStoreTypes
                        #RunAsAccount = $ConfigData.RunAsAccount 
                        #DatabaseBackupsDirectory = $ConfigData.DataStoreBackupsDirectory
                        #FileShareRoot = $ConfigData.FileShareRoot
                    } 
                }
                {($_ -eq "ServerWebAdaptor") -or ($_ -eq "PortalWebAdaptor")}
                {
                    
                    $PortalWebAdaptorSkip = $False
                    if(($Node.Role -icontains 'ServerWebAdaptor') -and ($Node.Role -icontains 'PortalWebAdaptor'))
                    {
                        if($NodeRole -ieq "PortalWebAdaptor")
                        {
                            $PortalWebAdaptorSkip = $True
                        }
                    }
                    
                    if(-not($PortalWebAdaptorSkip))
                    {
                        $Depends = @()

                        if($ConfigurationData.ConfigData.ServerContext -or $ConfigurationData.ConfigData.PortalContext)
                        {
                            xFirewall "WebAdaptorFirewallRules$($Node.NodeName)"
                            {
                                Name                  = "IIS-ARR" 
                                DisplayName           = "IIS-ARR" 
                                DisplayGroup          = "IIS-ARR" 
                                Ensure                = 'Present'  
                                Access                = "Allow" 
                                State                 = "Enabled" 
                                Profile               = "Public"
                                LocalPort             = ("80", "443")                         
                                Protocol              = "TCP" 
                            }

                            if($Node.Role -icontains 'ServerWebAdaptor' -and $ConfigurationData.ConfigData.Server.SslCertifcate.Path)
                            {
                                $Alias = $ConfigurationData.ConfigData.Server.SslCertifcate.Alias
                                $CertificateFileLocation = $ConfigurationData.ConfigData.Server.SslCertifcate.Path
                                $CertificatePassword = $ConfigurationData.ConfigData.Server.SslCertifcate.Password
                            }
                            elseif($Node.Role -icontains 'PortalWebAdaptor' -and $ConfigurationData.ConfigData.Portal.SslCertifcate.Path)
                            {
                                $Alias = $ConfigurationData.ConfigData.Portal.SslCertifcate.Alias
                                $CertificateFileLocation = $ConfigurationData.ConfigData.Portal.SslCertifcate.Path
                                $CertificatePassword = $ConfigurationData.ConfigData.Portal.SslCertifcate.Password
                            }

                            if($CertificateFileLocation -and $CertificatePassword -and $Alias)
                            {
                                ArcGIS_IIS_TLS "WebAdaptorCertificateInstall$($Node.NodeName)"
                                {
                                    WebSiteName = 'Default Web Site'
                                    ExternalDNSName = $Alias
                                    Ensure = 'Present'
                                    CertificateFileLocation = $CertificateFileLocation
                                    CertificatePassword = $CertificatePassword
                                    DependsOn = $Depends
                                }
                            }
                            else
                            {
                                ArcGIS_IIS_TLS "WebAdaptorCertificateInstall$($Node.NodeName)"
                                {
                                    WebSiteName = 'Default Web Site'
                                    ExternalDNSName = $MachineFQDN 
                                    Ensure = 'Present'
                                    DependsOn = $Depends
                                }
                            }
                            
                            $Depends += "[ArcGIS_IIS_TLS]WebAdaptorCertificateInstall$($Node.NodeName)"
                            
                            if($Node.Role -icontains "ServerWebAdaptor")
                            {
                                $WAPrimaryServerMachine = ""
                                if($ConfigurationData.ConfigData.WebAdaptor.PrimaryServerMachine)
                                {
                                    $WAPrimaryServerMachine = $ConfigurationData.ConfigData.WebAdaptor.PrimaryServerMachine
                                }
                                else
                                {
                                    if($PrimaryServerMachine)
                                    {
                                        $WAPrimaryServerMachine = $PrimaryServerMachine
                                    }
                                    else
                                    {
                                        Write-Verbose "Primary Server URL is not set. WebAdaptor is Installed but not Configured. $PrimaryServerMachine"
                                    }
                                }

                                if($ConfigurationData.ConfigData.ServerContext -and $WAPrimaryServerMachine)
                                {
                                    #Hacky Way to overcome a conflict
                                    if(-not($Node.Role -icontains 'DataStore') -and ($WAPrimaryServerMachine -ine $Node.NodeName))
                                    {
                                        if($Node.WMFVersion -gt 4){
                                            WaitForAll "WaitForAllServerConfigToCompleteWA$($WAPrimaryServerMachine)"{
                                                ResourceName = "[ArcGIS_Server]Server$($WAPrimaryServerMachine)"
                                                NodeName = $WAPrimaryServerMachine
                                                RetryIntervalSec = 60
                                                RetryCount = 100
                                                DependsOn = $Depends
                                            }
                                            $Depends += "[WaitForAll]WaitForAllServerConfigToCompleteWA$($WAPrimaryServerMachine)"
                                        }else{
                                            ArcGIS_WaitForComponent "WaitForServerConfigToCompleteWA$($WAPrimaryServerMachine)"
                                            {
                                                Component = "server"
                                                InvokingComponent = "WebAdaptor"
                                                ComponentHostName = (Get-FQDN $WAPrimaryServerMachine)
                                                ComponentContext = "arcgis"
                                                Ensure = "Present"
                                                Credential =  $PSACredential
                                                RetryIntervalSec = 60
                                                RetryCount = 100
                                                DependsOn = $Depends
                                            }
                                            $Depends += "[ArcGIS_WaitForComponent]WaitForServerConfigToCompleteWA$($WAPrimaryServerMachine)"
                                        }
                                    }
                                    
                                    ArcGIS_WebAdaptor "ConfigureServer$($MachineFQDN)"
                                    {
                                        Ensure = "Present"
                                        Component = 'Server'
                                        HostName = $MachineFQDN 
                                        ComponentHostName = [System.Net.DNS]::GetHostByName($WAPrimaryServerMachine).HostName
                                        Context = $ConfigurationData.ConfigData.ServerContext
                                        OverwriteFlag = $False
                                        SiteAdministrator = $PSACredential
                                        DependsOn = $Depends
                                        AdminAccessEnabled = if($ConfigurationData.ConfigData.WebAdaptor.AdminAccessEnabled) { $true } else { $false }
                                    }
                                    
                                    $Depends += "[ArcGIS_WebAdaptor]ConfigureServer$($MachineFQDN)"
                                }
                            }

                            if($Node.Role -icontains "PortalWebAdaptor")
                            {
                            
                                $WAPrimaryPortalMachine = ""
                                if($ConfigurationData.ConfigData.WebAdaptor.PrimaryPortalMachine)
                                {
                                    $WAPrimaryPortalMachine = $ConfigurationData.ConfigData.WebAdaptor.PrimaryPortalMachine
                                }
                                else
                                {
                                    if(($AllNodes | Where-Object { $_.Role -icontains 'Portal'}  | Measure-Object).Count -gt 0)
                                    {
                                        $WAPrimaryPortalMachine = $PrimaryPortalMachine
                                    }
                                    else
                                    {
                                        Write-Verbose "Primary Portal URL is not set. WebAdaptor is Installed but not Configured. $PrimaryPortalMachine"
                                    }
                                }

                                if($ConfigurationData.ConfigData.PortalContext -and $WAPrimaryPortalMachine)
                                {
                                    if($WAPrimaryPortalMachine -ine $Node.NodeName)
                                    {
                                        if($Node.WMFVersion -gt 4){
                                            WaitForAll "WaitForAllPortalConfigToComplete$($WAPrimaryPortalMachine)"{
                                                ResourceName = "[ArcGIS_Portal]Portal$($WAPrimaryPortalMachine)"
                                                NodeName = $WAPrimaryPortalMachine
                                                RetryIntervalSec = 60
                                                RetryCount = 90
                                                DependsOn = $Depends
                                            }
                                            $Depends += "[WaitForAll]WaitForAllPortalConfigToComplete$($WAPrimaryPortalMachine)"
                                        }else{
                                            ArcGIS_WaitForComponent "WaitForPortalConfigToComplete$($WAPrimaryPortalMachine)"
                                            {
                                                Component = "Portal"
                                                InvokingComponent = "WebAdaptor"
                                                ComponentHostName = (Get-FQDN $WAPrimaryPortalMachine)
                                                ComponentContext = "arcgis"
                                                Ensure = "Present"
                                                Credential =  $PSACredential
                                                RetryIntervalSec = 60
                                                RetryCount = 100
                                                DependsOn = $Depends
                                            }
                                            $Depends += "[ArcGIS_WaitForComponent]WaitForPortalConfigToComplete$($WAPrimaryPortalMachine)"
                                        }
                                    }

                                    ArcGIS_WebAdaptor "ConfigurePortal$($MachineFQDN)"
                                    {
                                        Ensure = "Present"
                                        Component = 'Portal'
                                        HostName = $MachineFQDN 
                                        ComponentHostName =  [System.Net.DNS]::GetHostByName($WAPrimaryPortalMachine).HostName
                                        Context = $ConfigurationData.ConfigData.PortalContext
                                        OverwriteFlag = $False
                                        SiteAdministrator = $PSACredential
                                        DependsOn = $Depends
                                    }
                                    $Depends += "[ArcGIS_WebAdaptor]ConfigurePortal$($MachineFQDN)"
                                }
                            }

                            if($Federation -and -not(($AllNodes | Where-Object { $_.Role -icontains 'LoadBalancer' }  | Measure-Object).Count -gt 0))
                            {
                                if($Node.Role -icontains "ServerWebAdaptor")
                                {
                                    if(($AllNodes | Where-Object { $_.Role -icontains 'PortalWebAdaptor' }  | Measure-Object).Count -gt 0)
                                    {
                                        if(($AllNodes | Where-Object { ($_.Role -icontains 'PortalWebAdaptor') -and -not($_.Role -icontains 'ServerWebAdaptor')}  | Measure-Object).Count -gt 0)
                                        {
                                            $PortalWAMachineName = ($AllNodes | Where-Object { ($_.Role -icontains 'PortalWebAdaptor') -and -not($_.Role -icontains 'ServerWebAdaptor')} | Select-Object -First 1).NodeName
                                            if($PortalWAMachineName -ine $Node.NodeName)
                                            {
                                                $PortalWAMachineHostName = Get-FQDN $PortalWAMachineName
                                                if($Node.WMFVersion -gt 4){
                                                    WaitForAll "WaitForAllWebadaptorPortalConfigFederation$($PortalWAMachineName)"{
                                                        ResourceName = "[ArcGIS_WebAdaptor]ConfigurePortal$($PortalWAMachineHostName)"
                                                        NodeName = $PortalWAMachineName
                                                        RetryIntervalSec = 60
                                                        RetryCount = 100
                                                        DependsOn = $Depends
                                                    }
                                                    $Depends += "[WaitForAll]WaitForAllWebadaptorPortalConfigFederation$($PortalWAMachineName)"
                                                }else{
                                                    ArcGIS_WaitForComponent "WaitForWebadaptorPortalConfigFederation$($PortalWAMachineName)"
                                                    {
                                                        Component = "PortalWA"
                                                        InvokingComponent = "WebAdaptor"
                                                        ComponentHostName = $PortalWAMachineHostName
                                                        ComponentContext = $ConfigurationData.ConfigData.PortalContext
                                                        Ensure = "Present"
                                                        Credential =  $PSACredential
                                                        RetryIntervalSec = 60
                                                        RetryCount = 100
                                                        DependsOn = $Depends
                                                    }
                                                    $Depends += "[ArcGIS_WaitForComponent]WaitForWebadaptorPortalConfigFederation$($PortalWAMachineName)"
                                                }
                                            }
                                            $PortalHostName = (Get-FQDN $PortalWAMachineName)
                                        }
                                        else
                                        {
                                            $PortalHostName = $MachineFQDN
                                        }
                                        $PortalPort = 443
                                        $PortalContext = $ConfigurationData.ConfigData.PortalContext
                                    }
                                    else
                                    {
                                        if(($AllNodes | Where-Object { ($_.Role -icontains 'Portal')}  | Measure-Object).Count -gt 0)
                                        {
                                            $PortalHostName = (Get-FQDN $PrimaryPortalMachine)
                                            $PortalPort = 7443
                                            $PortalContext = "arcgis"
                                            if($Node.WMFVersion -gt 4){
                                                WaitForAll "WaitForAllPortalConfigToCompleteServerFederation$($PrimaryPortalMachine)"{
                                                    ResourceName = "[ArcGIS_Portal]Portal$($PrimaryPortalMachine)"
                                                    NodeName = $PrimaryPortalMachine
                                                    RetryIntervalSec = 60
                                                    RetryCount = 100
                                                    DependsOn = $Depends
                                                }
                                                $Depends += "[WaitForAll]WaitForAllPortalConfigToCompleteServerFederation$($PrimaryPortalMachine)"
                                            }else{
                                                ArcGIS_WaitForComponent "WaitForPortalConfigToCompleteServerFederation$($PrimaryPortalMachine)"
                                                {
                                                    Component = "Portal"
                                                    InvokingComponent = "WebAdaptor"
                                                    ComponentHostName = $PortalHostName
                                                    ComponentContext = $PortalContext
                                                    Ensure = "Present"
                                                    Credential =  $PSACredential
                                                    RetryIntervalSec = 60
                                                    RetryCount = 100
                                                }
                                                $Depends += "[ArcGIS_WaitForComponent]WaitForPortalConfigToCompleteServerFederation$($PrimaryPortalMachine)"
                                            }
                                        }
                                        else
                                        {
                                            $PortalHostName = $ConfigurationData.ConfigData.Federation.PortalHostName
                                            $PortalPort = $ConfigurationData.ConfigData.Federation.PortalPort
                                            $PortalContext = $ConfigurationData.ConfigData.Federation.PortalContext

                                            $PortalFedPSAPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.Federation.PrimarySiteAdmin.Password -AsPlainText -Force
                                            $PortalFedPSACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.Federation.PrimarySiteAdmin.UserName, $PortalFedPSAPassword )
                                        }
                                    }
                                    
                                    if($ConfigurationData.ConfigData.ServerContext -and  $WAPrimaryServerMachine)
                                    {
                                        if($PortalHostName -and $PortalPort -and $PortalContext)
                                        {
                                            $FederationFlag = $True
                                            if($HostingServer)
                                            {
                                                if($PrimaryDataStore)
                                                {
                                                    if($PrimaryDataStore -ine $PrimaryPortalMachine)
                                                    {
                                                        if($Node.WMFVersion -gt 4){
                                                            WaitForAll "WaitForAllDataStoreInWebAdaptor$($PrimaryDataStore)"{
                                                                ResourceName = "[ArcGIS_DataStore]DataStore$($PrimaryDataStore)"
                                                                NodeName = $PrimaryDataStore
                                                                RetryIntervalSec = 60
                                                                RetryCount = 120
                                                                DependsOn = $Depends
                                                            }
                                                            $Depends += "[WaitForAll]WaitForAllDataStoreInWebAdaptor$($PrimaryDataStore)"
                                                        }else{
                                                            ArcGIS_WaitForComponent  "WaitForDataStoreInWebAdaptor$($PrimaryDataStore)"
                                                            {
                                                                Component = "DataStore"
                                                                InvokingComponent = "WebAdaptor"
                                                                ComponentHostName = (Get-FQDN $PrimaryServerMachine)
                                                                ComponentContext = "arcgis"
                                                                Ensure = "Present"
                                                                Credential =  $PSACredential
                                                                RetryIntervalSec = 60
                                                                RetryCount = 120
                                                                DependsOn = $Depends
                                                            }
                                                            $Depends += "[ArcGIS_WaitForComponent]WaitForDataStoreInWebAdaptor$($PrimaryDataStore)"
                                                        }
                                                    }
                                                }
                                                else
                                                {
                                                    $FederationFlag = $False
                                                }
                                            }
                                            if($FederationFlag)
                                            {
                                                if($ConfigurationData.ConfigData.Server.SslCertifcate.Alias)
                                                {
                                                    $ServerFEDHostName = $ConfigurationData.ConfigData.Server.SslCertifcate.Alias
                                                }
                                                else
                                                {
                                                    $ServerFEDHostName = $MachineFQDN  
                                                }
                                                
                                                if($ConfigurationData.ConfigData.Portal.SslCertifcate.Alias)
                                                {
                                                    $PortalFEDHostName = $ConfigurationData.ConfigData.Portal.SslCertifcate.Alias  
                                                }
                                                else
                                                {
                                                    $PortalFEDHostName = $PortalHostName
                                                }

                                                if($ConfigurationData.ConfigData.WebAdaptor.AdminAccessEnabled){
                                                    $ServerSiteAdminUrlHostName = $ServerFEDHostName
                                                    $ServerSiteAdminUrlPort = 443
                                                    $ServerSiteAdminUrlContext = $ConfigurationData.ConfigData.ServerContext
                                                }else{
                                                    $ServerSiteAdminUrlHostName = (Get-FQDN $PrimaryServerMachine)
                                                    $ServerSiteAdminUrlPort = 6443
                                                    $ServerSiteAdminUrlContext = 'arcgis'
                                                }
                                                
                                                ArcGIS_Federation FederateInWA
                                                {
                                                    PortalHostName = $PortalHostName
                                                    PortalPort = $PortalPort
                                                    PortalContext = $PortalContext
                                                    ServiceUrlHostName = $ServerFEDHostName
                                                    ServiceUrlPort = 443
                                                    ServiceUrlContext = $ConfigurationData.ConfigData.ServerContext
                                                    ServerSiteAdminUrlHostName = $ServerSiteAdminUrlHostName
                                                    ServerSiteAdminUrlPort = $ServerSiteAdminUrlPort
                                                    ServerSiteAdminUrlContext = $ServerSiteAdminUrlContext
                                                    Ensure = "Present"
                                                    RemoteSiteAdministrator = if($PortalFedPSACredential){$PortalFedPSACredential}else{$PSACredential}
                                                    SiteAdministrator = $PSACredential
                                                    ServerRole = if($HostingServer){'HOSTING_SERVER'}else{'FEDERATED_SERVER'}
                                                    ServerFunctions = $ConfigurationData.ConfigData.ServerRole
                                                    DependsOn = $Depends
                                                }
                                            }
                                        }
                                        else
                                        {
                                            throw "[Warning]:No PortalHostName or PortalPort or PortalContext set for Federation" 
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                'RasterDataStoreItem'{
                    ArcGIS_FileShare RasterAnalysisFileShare
                    {
                        FileShareName = $ConfigurationData.ConfigData.DataStoreItems.RasterStore.FileShareName
                        FileShareLocalPath = $ConfigurationData.ConfigData.DataStoreItems.RasterStore.FileShareLocalPath
                        Ensure = 'Present'
                        Credential = $SACredential
                    }
                    
                    $DataStorePath = "\\$($env:ComputerName)\$($ConfigurationData.ConfigData.DataStoreItems.RasterStore.FileShareName)"
                    
                    ArcGIS_DataStoreItem RasterDataStoreItem
                    {
                        Name = "RasterFileShareDataStore"
                        HostName = (Get-FQDN $PrimaryServerMachine)
                        Ensure = "Present"
                        SiteAdministrator = $PSACredential
                        DataStoreType = "RasterStore"
                        DataStorePath = $DataStorePath
                        DependsOn = @('[ArcGIS_FileShare]RasterAnalysisFileShare')
                    }
                }
                'FileShare'{
                    $FilePathsArray = @()
                    $FilePathsArray += $ConfigurationData.ConfigData.Server.ConfigStoreLocation
                    $FilePathsArray += $ConfigurationData.ConfigData.Server.ServerDirectoriesRootLocation
                    if($ConfigurationData.ConfigData.Portal){
                        $FilePathsArray += $ConfigurationData.ConfigData.Portal.ContentDirectoryLocation
                    }
                    
                    ArcGIS_FileShare FileShare
                    {
                        FileShareName = $ConfigurationData.ConfigData.FileShareName
                        FileShareLocalPath = $ConfigurationData.ConfigData.FileShareLocalPath
                        Ensure = 'Present'
                        Credential = $SACredential
                        FilePaths = ($FilePathsArray -join ",")
                    }
                }
                'LoadBalancer'{

                    if(($AllNodes | Where-Object { $_.Role -icontains 'ServerWebAdaptor' -or $_.Role -icontains 'PortalWebAdaptor'}).count -gt 0)
                    {
                        
                        $MemberServers = ($AllNodes | Where-Object { $_.Role -icontains 'ServerWebAdaptor' }).NodeName
                        $MemberPortals = ($AllNodes | Where-Object { $_.Role -icontains 'PortalWebAdaptor' }).NodeName
                        
                        if($MemberServers)
                        {
                            ArcGIS_LB ServerLB
                            {
                                ComponentType = 'ServerWebAdaptor'
                                LBEndPoint =  $MachineFQDN
                                MemberServers= $MemberServers
                                Ensure = 'Present'
                                EnableFailedRequestTracking = $True
                            }
                        }

                        if($MemberPortals)
                        {
                            ArcGIS_LB PortalLB
                            {
                                ComponentType = 'PortalWebAdaptor'
                                LBEndPoint =  $MachineFQDN
                                MemberServers= $MemberPortals
                                Ensure = 'Present'
                                EnableFailedRequestTracking = $True
                            }
                        }
                        $Depends = @();
                        
                        ForEach($svr in ($AllNodes | Where-Object { $_.Role -icontains 'WebAdaptor'}))
                        {
                            if(($svr.Role -icontains "ServerWebAdptor") -and -not($svr.Role -ieq "PortalWebAdptor"))
                            {
                                if($Node.WMFVersion -gt 4){
                                    $NodeFQDN = Get-FQDN $svr.NodeName
                                    WaitForAll "WaitForAll$($svr.NodeName)ForLoadBalance"{
                                        ResourceName = "[ArcGIS_WebAdaptor]ConfigureServer$($NodeFQDN)"
                                        NodeName = $svr.NodeName
                                        RetryIntervalSec = 60
                                        RetryCount = 100
                                        DependsOn = $Depends
                                    }
                                    $Depends += "[WaitForAll]WaitForAll$($svr.NodeName)ForLoadBalance"
                                }else{
                                    ArcGIS_WaitForComponent "WaitFor$($svr.NodeName)ForLoadBalance"
                                    {
                                        Component = "ServerWA"
                                        InvokingComponent = "LoadBalancer"
                                        ComponentHostName = (Get-FQDN $svr.NodeName)
                                        ComponentContext = $ConfigurationData.ConfigData.ServerContext
                                        Ensure = "Present"
                                        Credential =  $PSACredential
                                        RetryIntervalSec = 60
                                        RetryCount = 100
                                    }
                                    $Depends += "[ArcGIS_WaitForComponent]WaitFor$($svr.NodeName)ForLoadBalance"
                                }
                            }
                            elseif(($svr.Role -ieq "PortalWebAdptor") -and -not($svr.Role -ieq "ServerWebAdptor"))
                            {
                                if($Node.WMFVersion -gt 4){
                                    $NodeFQDN = Get-FQDN $svr.NodeName
                                    WaitForAll "WaitForAll$($svr.NodeName)ForLoadBalance"{
                                        ResourceName = "[ArcGIS_WebAdaptor]ConfigurePortal$($NodeFQDN)"
                                        NodeName = $svr.NodeName
                                        RetryIntervalSec = 60
                                        RetryCount = 100
                                        DependsOn = $Depends
                                    }
                                    $Depends += "[WaitForAll]WaitForAll$($svr.NodeName)ForLoadBalance"
                                }else{
                                    ArcGIS_WaitForComponent "WaitFor$($svr.NodeName)ForLoadBalance"
                                    {
                                        Component = "PortalWA"
                                        InvokingComponent = "LoadBalancer"
                                        ComponentHostName =  (Get-FQDN $svr.NodeName)
                                        ComponentContext = $ConfigurationData.ConfigData.PortalContext
                                        Ensure = "Present"
                                        Credential =  $PSACredential
                                        RetryIntervalSec = 60
                                        RetryCount = 100
                                    }
                                    $Depends += "[ArcGIS_WaitForComponent]WaitFor$($svr.NodeName)ForLoadBalance"
                                }
                            }
                            elseif(($svr.Role -ieq "PortalWebAdptor") -and ($svr.Role -ieq "ServerWebAdptor"))
                            {
                                if($Node.WMFVersion -gt 4){
                                    $NodeFQDN = Get-FQDN $svr.NodeName
                                    WaitForAll "WaitForAll$($svr.NodeName)ForLoadBalance"{
                                        ResourceName = "[ArcGIS_WebAdaptor]ConfigurePortal$($NodeFQDN)"
                                        NodeName = $svr.NodeName
                                        RetryIntervalSec = 60
                                        RetryCount = 100
                                        DependsOn = $Depends
                                    }
                                    $Depends += "[WaitForAll]WaitForAll$($svr.NodeName)ForLoadBalance"
                                }else{
                                    ArcGIS_WaitForComponent "WaitFor$($svr.NodeName)ForLoadBalance"
                                    {
                                        Component = "PortalWA"
                                        InvokingComponent = "LoadBalancer"
                                        ComponentHostName =  (Get-FQDN $svr.NodeName)
                                        ComponentContext = $ConfigurationData.ConfigData.PortalContext
                                        Ensure = "Present"
                                        Credential =  $PSACredential
                                        RetryIntervalSec = 60
                                        RetryCount = 100
                                    }
                                    $Depends += "[ArcGIS_WaitForComponent]WaitFor$($svr.NodeName)ForLoadBalance"
                                }
                            }

                            ArcGIS_TLSCertificateImport "CertificateImport-$($svr.NodeName)"
                            {
                                HostName = (Get-FQDN $svr.NodeName)
                                Ensure = 'Present'
                                ApplicationPath = "/"
                                HttpsPort = 443
                                StoreLocation = 'LocalMachine'
                                StoreName = 'AuthRoot'
                                DependsOn = @("[ArcGIS_WaitForComponent]WaitFor$($svr.NodeName)ForLoadBalance")
                            }

                            $Depends += "[ArcGIS_TLSCertificateImport]CertificateImport-$($svr.NodeName)"
                        }

                        if($Federation -and ($ConfigurationData.ConfigData.PortalContext -or $ConfigurationData.ConfigData.ServerContext))
                        {    
                            
                            if(-not($ConfigurationData.ConfigData.PortalContext))
                            {
                                if($PrimaryPortalMachine)
                                {
                                    $PortalHostName = (Get-FQDN $PrimaryPortalMachine)
                                    $PortalPort = 7443
                                    $PortalContext = "arcgis"
                                    
                                    if($Node.WMFVersion -gt 4){
                                        WaitForAll "WaitForAllPortalConfigToCompleteWAFederation$($PrimaryPortalMachine)"{
                                            ResourceName = "[ArcGIS_Portal]Portal$($PrimaryPortalMachine)"
                                            NodeName = $PrimaryPortalMachine
                                            RetryIntervalSec = 60
                                            RetryCount = 100
                                            DependsOn = $Depends
                                        }
                                        $Depends += "[WaitForAll]WaitForAllPortalConfigToCompleteWAFederation$($PrimaryPortalMachine)"
                                    }else{
                                        ArcGIS_WaitForComponent "WaitForPortalConfigToCompleteWAFederation$($PrimaryPortalMachine)"
                                        {
                                            Component = "Portal"
                                            InvokingComponent = "LoadBalancer"
                                            ComponentHostName = $PortalHostName
                                            ComponentContext = $PortalContext
                                            Ensure = "Present"
                                            Credential =  $PSACredential
                                            RetryIntervalSec = 60
                                            RetryCount = 100
                                        }
                                        $Depends += "[ArcGIS_WaitForComponent]WaitForPortalConfigToCompleteWAFederation$($PrimaryPortalMachine)"
                                    }
                                }
                                else
                                {
                                    $PortalHostName = $ConfigurationData.ConfigData.Federation.PortalHostName
                                    $PortalPort = $ConfigurationData.ConfigData.Federation.PortalPort
                                    $PortalContext = $ConfigurationData.ConfigData.Federation.PortalContext

                                    $PortalFedPSAPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.Federation.PrimarySiteAdmin.Password -AsPlainText -Force
                                    $PortalFedPSACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.Federation.PrimarySiteAdmin.UserName, $PortalFedPSAPassword )
                                }

                                if($MemberServers)
                                {
                                    $ServerHostName = $MachineFQDN
                                    $ServerContext =$ConfigurationData.ConfigData.ServerContext
                                    $ServerPort = 443
                                }
                            }
                            else
                            {
                                $PortalHostName = $MachineFQDN
                                $PortalPort = 443
                                $PortalContext = $ConfigurationData.ConfigData.PortalContext
                                
                                if($PrimaryServerMachine)
                                {
                                    $ServerHostName = (Get-FQDN $PrimaryServerMachine)
                                    $ServerContext = 'arcgis'
                                    $ServerPort = 6443
                                }
                            }

                            if($PortalHostName -and $PortalPort -and $PortalContext -and $ServerHostName -and $ServerContext -and $ServerPort)
                            {
                                $FederationFlag = $True
                                if($HostingServer)
                                {
                                    if($PrimaryDataStore)
                                    {
                                        if($Node.WMFVersion -gt 4){
                                            WaitForAll "WaitForAllDataStoreInLB$($PrimaryDataStore)"{
                                                ResourceName = "[ArcGIS_DataStore]DataStore$($PrimaryDataStore)"
                                                NodeName = $PrimaryDataStore
                                                RetryIntervalSec = 60
                                                RetryCount = 100
                                                DependsOn = $Depends
                                            }
                                            $Depends += "[WaitForAll]WaitForAllDataStoreInLB$($PrimaryDataStore)"
                                        }else{
                                            ArcGIS_WaitForComponent "WaitForDataStoreInLB$($PrimaryDataStore)"
                                            {
                                                Component = "DataStore"
                                                InvokingComponent = "LoadBalancer"
                                                ComponentHostName = (Get-FQDN $PrimaryServerMachine)
                                                ComponentContext = "arcgis"
                                                Ensure = "Present"
                                                Credential =  $PSACredential
                                                RetryIntervalSec = 60
                                                RetryCount = 100
                                                DependsOn = $Depends
                                            }
                                            $Depends += "[ArcGIS_WaitForComponent]WaitForDataStoreInLB$($PrimaryDataStore)"
                                        }
                                    }
                                    else
                                    {
                                        $FederationFlag = $False
                                    }
                                }
                                if($FederationFlag)
                                {
                                    if(-not($ConfigurationData.ConfigData.WebAdaptor.AdminAccessEnabled)){
                                        $ServerSiteAdminUrlHostName = $ServerHostName
                                        $ServerSiteAdminUrlPort = $ServerPort
                                        $ServerSiteAdminUrlContext = $ServerContext
                                    }else{
                                        $ServerSiteAdminUrlHostName = (Get-FQDN $PrimaryServerMachine)
                                        $ServerSiteAdminUrlPort = 6443
                                        $ServerSiteAdminUrlContext = 'arcgis'
                                    }

                                    ArcGIS_Federation FederateInLB
                                    {
                                        PortalHostName = $PortalHostName
                                        PortalPort =  $PortalPort
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
                                        DependsOn = $Depends
                                    }
                                }
                            }
                        }
                    }
                }
                'SqlServer'{
                    xFirewall Server_FirewallRule_Database
                    {
                            Name                  = "SQL Server Database IN" 
                            DisplayName           = "SQL Server Database 1433" 
                            DisplayGroup          = "SQL Server" 
                            Ensure                = 'Present'
                            Access                = "Allow" 
                            State                 = "Enabled" 
                            Profile               = @("Domain","Private","Public") 
                            LocalPort             = "1433"                         
                            Protocol              = "TCP" 
                            DependsOn             = @('[Script]SQLServerInstall')
                    }

                    Script SetMixedModeAuthentication
                    {
                        GetScript = {
                            $null
                        }
                        TestScript = 
                        {                    
                            $result = $false
                            [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') 
                            $s = new-object ('Microsoft.SqlServer.Management.Smo.Server') "$env:ComputerName" 
                            $result = ($s.Settings.LoginMode -ieq [Microsoft.SqlServer.Management.SMO.ServerLoginMode]::Mixed)
                            $result
                        }
                        SetScript =
                        {
                            [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO')
                            $s = new-object ('Microsoft.SqlServer.Management.Smo.Server') "$env:ComputerName"
                            $s.Settings.LoginMode = [Microsoft.SqlServer.Management.SMO.ServerLoginMode]::Mixed
                            $s.Alter()
                            Stop-Service -Name 'MSSQLSERVER' -Force
                            Start-Sleep -Seconds 5
                            Start-Service -Name 'MSSQLSERVER'
                        }
                        DependsOn = @('[xFirewall]Server_FirewallRule_Database')
                    }

                    $DatabaseAdminUserName = $ConfigurationData.ConfigData.SQLServer.DatabaseAdminUser.UserName
                    $DatabaseAdminPassword = $ConfigurationData.ConfigData.SQLServer.DatabaseAdminUser.Password

                    Script CreateDatabaseAdminUser
                    {
                        GetScript = {
                            $null
                        }
                        TestScript = 
                        {                    
                            [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') | Out-Null
                            $s = new-object ('Microsoft.SqlServer.Management.Smo.Server') "$env:ComputerName" 
                            (($s.logins).Name -contains $using:DatabaseAdminUserName)    
                        }
                        SetScript =
                        {
                            [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO')
                            $s = new-object ('Microsoft.SqlServer.Management.Smo.Server') "$env:ComputerName"
                            [Microsoft.SqlServer.Management.Smo.Login]$login = New-Object Microsoft.SqlServer.Management.Smo.Login $s,$using:DatabaseAdminUserName
                            $login.LoginType = [Microsoft.SqlServer.Management.Smo.LoginType]::SqlLogin      
                            $login.Create($using:DatabaseAdminPassword)
                            $login.AddToRole("sysadmin")
                            $login.AddToRole("dbcreator")
                            $login.AddToRole("serveradmin")
                            $login.Alter()
                        }
                        DependsOn = @('[Script]SetMixedModeAuthentication')
                    }
                }
            }
        }
    }
}
