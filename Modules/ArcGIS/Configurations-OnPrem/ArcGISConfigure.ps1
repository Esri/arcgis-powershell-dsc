Configuration ArcGISConfigure
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_FileShare
    Import-DscResource -Name ArcGIS_Server
    Import-DscResource -Name ArcGIS_WindowsService
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -Name ArcGIS_Portal
    Import-DscResource -Name ArcGIS_DataStore
    Import-DscResource -Name ArcGIS_IIS_TLS
    Import-DscResource -Name ArcGIS_WebAdaptor
    Import-DscResource -Name ArcGIS_TLSCertificateImport
    Import-DscResource -Name ArcGIS_LB
    Import-DscResource -Name ArcGIS_GeoEvent
    Import-DSCResource -Name ArcGIS_EGDB
    Import-DSCResource -Name ArcGIS_WaitForComponent
    Import-DSCResource -Name ArcGIS_WaitForFileShare
    Import-DSCResource -Name ArcGIS_DataStoreItem
    Import-DSCResource -Name ArcGIS_Server_TLS
    Import-DSCResource -Name ArcGIS_Portal_TLS
    
    $PrimaryServerMachineNode = ""
    $PrimaryPortalMachineNode = ""
    $PrimaryServerMachine = ""
    $PrimaryPortalMachine = ""
    $PrimaryDataStore = ""
    $PrimaryBigDataStore = ""
    $PrimaryTileCache = ""
    $FileShareMachine = ""

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
        
        if($Role -icontains 'FileShare')
        {
            $FileShareMachine = $AllNodes[$i].NodeName
        }
    }

    Node $AllNodes.NodeName
    { 
        $SslRootOrIntermediate = if($ConfigurationData.ConfigData.SslRootOrIntermediate) { $ConfigurationData.ConfigData.SslRootOrIntermediate | ConvertTo-Json } else {''}
        
        $MachineFQDN = Get-FQDN $Node.NodeName

        $SAPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.Credentials.ServiceAccount.Password -AsPlainText -Force
        $SACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.Credentials.ServiceAccount.UserName, $SAPassword )

        $PSAPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.Password -AsPlainText -Force
        $PSACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.UserName, $PSAPassword )

        if ($ConfigurationData.ConfigData.Credentials.ADServiceUser.UserName) {
            $ADServicePassword = ConvertTo-SecureString $ConfigurationData.ConfigData.Credentials.ADServiceUser.Password -AsPlainText -Force
            $ADServiceCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.Credentials.ADServiceUser.UserName, $ADServicePassword )
        } else {
            $ADServiceCredential = $null
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
                    $HasWAonSeparateMachine = (($AllNodes | Where-Object { ($_.Role -icontains 'ServerWebAdaptor') -and ($_.NodeName -ine $Node.NodeName) } | Measure-Object).Count -gt 0)
                    $OpenFirewallPorts = (-not($IsWebGIS) -or ($ConfigData.ServerEndPoint -as [ipaddress]) -or $HasDataStoreNodes -or $IsMultiMachineServer -or $HasWAonSeparateMachine)
                    
                    if($OpenFirewallPorts) # Server only deployment or behind an ILB or has DataStore nodes that need to register using admin			
                    {
                        $Depends += '[ArcGIS_xFirewall]Server_FirewallRules'

                        ArcGIS_xFirewall Server_FirewallRules
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
                        $Depends += '[ArcGIS_xFirewall]Server_FirewallRules_Internal' 
                        ArcGIS_xFirewall Server_FirewallRules_Internal
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
                            $Depends += '[ArcGIS_xFirewall]GeoAnalytics_InboundFirewallRules' 
                            $Depends += '[ArcGIS_xFirewall]GeoAnalytics_OutboundFirewallRules' 

                            ArcGIS_xFirewall GeoAnalytics_InboundFirewallRules
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

                            ArcGIS_xFirewall GeoAnalytics_OutboundFirewallRules
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

                            ArcGIS_xFirewall GeoAnalyticsCompute_InboundFirewallRules
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

                            ArcGIS_xFirewall GeoAnalyticsCompute_OutboundFirewallRules
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

                    if($FileShareMachine -and $ConfigurationData.ConfigData.FileShareName -and $ConfigStoreLocation.StartsWith('\') -and $ServerDirectoriesRootLocation.StartsWith('\'))
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
                        DataDir = @($ConfigStoreLocation, $ServerDirectoriesRootLocation)
                        IsDomainAccount = $ConfigurationData.ConfigData.Credentials.ServiceAccount.IsDomainAccount
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

                    if ($ConfigurationData.ConfigData.Server.RegisteredDirectories -and ($Node.NodeName -ieq $PrimaryServerMachine)) {
                        ArcGIS_Server_RegisterDirectories "Server$($Node.NodeName)RegisterDirectories"
                        { 
                            Ensure = 'Present'
                            SiteAdministrator = $PSACredential
                            DirectoriesJSON = ($ConfigurationData.ConfigData.Server.RegisteredDirectories | ConvertTo-Json)
                            DependsOn = $Depends
                        }
                        $Depends += "[ArcGIS_Server_RegisterDirectories]Server$($Node.NodeName)RegisterDirectories"
                    }

                    if($ConfigurationData.ConfigData.GeoEventServer) 
                    { 
                        ArcGIS_Service_Account GeoEvent_RunAs_Account
                        {
                            Name = 'ArcGISGeoEvent'
                            RunAsAccount = $SACredential
                            Ensure =  "Present"
                            DependsOn = $Depends
                            DataDir = "$env:ProgramData\Esri\GeoEvent"
                            IsDomainAccount = $ConfigurationData.ConfigData.Credentials.ServiceAccount.IsDomainAccount
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

                        ArcGIS_xFirewall GeoEvent_FirewallRules
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
                        $Depends += "[ArcGIS_xFirewall]GeoEvent_FirewallRules"

                        ArcGIS_GeoEvent ArcGIS_GeoEvent
                        {
                            Name	                  = 'ArcGIS GeoEvent'
                            Ensure	                  =  "Present"
                            SiteAdministrator         = $PSACredential
                            WebSocketContextUrl       = "wss://$($MachineFQDN):6143/geoevent"
                            DependsOn                 = $Depends
                            #SiteAdminUrl             = if($ConfigData.ExternalDNSName) { "https://$($ConfigData.ExternalDNSName)/arcgis/admin" } else { $null }
                        }	
                        $Depends += "[ArcGIS_xFirewall]GeoEvent_FirewallRules"
                        
                        if($IsMultiMachineServer) 
                        {
                            ArcGIS_xFirewall GeoEvent_FirewallRules_MultiMachine
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
                            $Depends += "[ArcGIS_xFirewall]GeoEvent_FirewallRules_MultiMachine"

                            ArcGIS_xFirewall GeoEvent_FirewallRules_MultiMachine_OutBound
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
                            $Depends += "[ArcGIS_xFirewall]GeoEvent_FirewallRules_MultiMachine_OutBound"
                            ArcGIS_xFirewall GeoEventService_Firewall
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
                            $Depends += "[ArcGIS_xFirewall]GeoEventService_Firewall"
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
                    
                    if(($Node.SslCertificates | Where-Object { $_.Target -icontains 'Server'}  | Measure-Object).Count -gt 0)
                    {
                        $SSLCertificate = $Node.SslCertificates | Where-Object { $_.Target -icontains 'Server' }  | Select-Object -First 1
                        ArcGIS_Server_TLS "Server_TLS_$($Node.NodeName)"
                        {
                            Ensure = 'Present'
                            SiteName = 'arcgis'
                            SiteAdministrator = $PSACredential                         
                            CName = $SSLCertificate.Alias
                            RegisterWebAdaptorForCName = $False
                            CertificateFileLocation = $SSLCertificate.Path
                            CertificatePassword = $SSLCertificate.Password
                            EnableSSL = $True
                            SslRootOrIntermediate = $SslRootOrIntermediate
                            DependsOn =  $Depends
                        }
                    }
                    else{
                        if(@("10.5","10.5.1","10.4.1").Contains($ConfigurationData.ConfigData.Version)){
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
                }
                'Portal'{
                    $Depends = @()
                    
                    if(-not($ConfigurationData.ConfigData.Credentials.ServiceAccount.IsDomainAccount)){
                        $Depends += '[User]ArcGIS_RunAsAccount'
                    }

                    $IsMultiMachinePortal = (($AllNodes | Where-Object { $_.Role -icontains 'Portal' }  | Measure-Object).Count -gt 1)
                    <#if($IsMultiMachinePortal -or ($ConfigData.PortalEndPoint -as [ipaddress]))
                    {#>
                        ArcGIS_xFirewall Portal_FirewallRules
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
                        $Depends += @('[ArcGIS_xFirewall]Portal_FirewallRules')
                    <#}
                    else 
                    {  # If single machine, need to open 7443 to allow federation over private portal URL and 6443 for changeServerRole
                        ArcGIS_xFirewall Portal_FirewallRules
                        {
                                Name                  = "PortalforArcGIS" 
                                DisplayName           = "Portal for ArcGIS" 
                                DisplayGroup          = "Portal for ArcGIS" 
                                Ensure                = 'Present'
                                Access                = "Allow" 
                                State                 = "Enabled" 
                                Profile               = ("Domain","Private","Public")
                                LocalPort             = ("7080","7443")                         
                                Protocol              = "TCP" 
                        }
                    }#>
                    
                    if($IsMultiMachinePortal) 
                    {
                                                                        
                        ArcGIS_xFirewall Portal_Database_OutBound
                        {
                                Name                  = "PortalforArcGIS-Outbound" 
                                DisplayName           = "Portal for ArcGIS Outbound" 
                                DisplayGroup          = "Portal for ArcGIS Outbound" 
                                Ensure                = 'Present' 
                                Access                = "Allow" 
                                State                 = "Enabled" 
                                Profile               = ("Domain","Private","Public")
                                RemotePort            = ("7120","7220", "7005", "7099", "7199", "5701", "5702", "5703")  # Elastic Search uses 7120,7220 and Postgres uses 7654 for replication, Hazelcast uses 5701 and 5702 (extra 2 ports for situations where unable to get port)
                                Direction             = "Outbound"                       
                                Protocol              = "TCP" 
                        }  
                        $Depends += @('[ArcGIS_xFirewall]Portal_Database_OutBound')
                        
                        ArcGIS_xFirewall Portal_Database_InBound
                        {
                                Name                  = "PortalforArcGIS-Inbound" 
                                DisplayName           = "Portal for ArcGIS Inbound" 
                                DisplayGroup          = "Portal for ArcGIS Inbound" 
                                Ensure                = 'Present' 
                                Access                = "Allow" 
                                State                 = "Enabled" 
                                Profile               = ("Domain","Private","Public")
                                LocalPort             = ("7120","7220","5701", "5702", "5703")  # Elastic Search uses 7120,7220, Hazelcast uses 5701 and 5702
                                Protocol              = "TCP" 
                        }  
                        $Depends += @('[ArcGIS_xFirewall]Portal_Database_InBound')
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
                    if($FileShareMachine -and $ConfigurationData.ConfigData.FileShareName -and $ContentDirectoryLocation.StartsWith('\'))
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
                        IsDomainAccount = $ConfigurationData.ConfigData.Credentials.ServiceAccount.IsDomainAccount
                    }
                    
                    $Depends += @('[ArcGIS_Service_Account]Portal_RunAs_Account')

                    if($ConfigurationData.ConfigData.ExternalLoadBalancer){
                        $ExternalDNSName = $ConfigurationData.ConfigData.ExternalLoadBalancer
                    }else{
                        if(($AllNodes | Where-Object { ($_.Role -icontains 'PortalWebAdaptor')}  | Measure-Object).Count -gt 0){
                            $PortalWAMachineNode = ($AllNodes | Where-Object { ($_.Role -icontains 'PortalWebAdaptor')} | Select-Object -First 1)
                            $ExternalDNSName = Get-FQDN $PortalWAMachineNode.NodeName
                            if(($PortalWAMachineNode.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor'}  | Measure-Object).Count -gt 0)
                            {
                                $ExternalDNSName = ($PortalWAMachineNode.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor' }  | Select-Object -First 1).Alias
                            }

                            if(($AllNodes | Where-Object { $_.Role -icontains 'LoadBalancer' } | Measure-Object).Count -gt 0){
                                $LoadbalancerNode = ($AllNodes | Where-Object { ($_.Role -icontains 'LoadBalancer')} | Select-Object -First 1)
                                $ExternalDNSName = Get-FQDN $LoadbalancerNode.NodeName
                                if(($LoadbalancerNode.SslCertificates | Where-Object { $_.Target -icontains 'LoadBalancer'}  | Measure-Object).Count -gt 0)
                                {
                                    $ExternalDNSName = ($LoadbalancerNode.SslCertificates | Where-Object { $_.Target -icontains 'LoadBalancer' }  | Select-Object -First 1).Alias
                                }
                            }
                        }else{
                            $ExternalDNSName = Get-FQDN $PrimaryPortalMachine
                            if(($PrimaryPortalMachineNode.SslCertificates | Where-Object { $_.Target -icontains 'Portal'}  | Measure-Object).Count -gt 0)
                            {
                                $ExternalDNSName = ($PrimaryPortalMachineNode.SslCertificates | Where-Object { $_.Target -icontains 'Portal' }  | Select-Object -First 1).Alias
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

                    $VersionArray = $ConfigurationData.ConfigData.Version.Split(".")
                    $MajorVersion = $VersionArray[1]
                    
                    ArcGIS_Portal "Portal$($Node.NodeName)"
                    {
                        Ensure = 'Present'
                        PortalHostName = $MachineFQDN
                        PortalEndPoint = $MachineFQDN # This will become Internal Load Balancer endpoint for private Portal URL to acheive true HA.
                        PortalContext = $ConfigurationData.ConfigData.PortalContext
                        LicenseFilePath = if($ConfigurationData.ConfigData.Portal.LicenseFilePath -and ($MajorVersion -ge 7)){ $ConfigurationData.ConfigData.Portal.LicenseFilePath }else{ $null }
                        UserLicenseType = if($ConfigurationData.ConfigData.Portal.PortalLicenseUserType -and ($MajorVersion -ge 7)){ $ConfigurationData.ConfigData.Portal.PortalLicenseUserType }else{ $null }
                        PortalAdministrator = $PSACredential 
                        DependsOn =  $Depends
                        AdminEmail = $ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.Email
                        AdminSecurityQuestionIndex = $ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.SecurityQuestionIndex
                        AdminSecurityAnswer = $ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.SecurityAnswer
                        ContentDirectoryLocation = $ContentDirectoryLocation
                        Join = if($Node.NodeName -ine $PrimaryPortalMachine) { $true } else { $false } 
                        IsHAPortal = if($IsMultiMachinePortal){$True}else{$False}
                        ExternalDNSName = $ExternalDNSName
                        PeerMachineHostName = if($Node.NodeName -ine $PrimaryPortalMachine) { (Get-FQDN $PrimaryPortalMachine) } else { "" }
                        EnableDebugLogging = if($ConfigurationData.ConfigData.DebugMode) { $true } else { $false }
                        ADServiceUser = $ADServiceCredential
                        EnableAutomaticAccountCreation = if($ConfigurationData.ConfigData.Portal.EnableAutomaticAccountCreation) {$true} else {$false}
                        DisableServiceDirectory = if($ConfigurationData.ConfigData.Portal.DisableServiceDirectory) {$true} else {$false}
                    }

                    if(($Node.SslCertificates | Where-Object { $_.Target -icontains 'Portal'}  | Measure-Object).Count -gt 0)
                    {
                        ForEach($svr in ($AllNodes | Where-Object { $_.Role -icontains 'PortalWebAdaptor'}))
                        {
                            if(-not($svr.NodeName -ieq $Node.NodeName)){
                                if($Node.WMFVersion -gt 4){
                                    $NodeFQDN = Get-FQDN $svr.NodeName
                                    WaitForAll "WaitForAllWA$($svr.NodeName)ForPortal"{
                                        ResourceName = "[ArcGIS_WebAdaptor]ConfigurePortal$($NodeFQDN)"
                                        NodeName = $svr.NodeName
                                        RetryIntervalSec = 60
                                        RetryCount = 100
                                        DependsOn = $Depends
                                    }
                                    $Depends += "[WaitForAll]WaitForAllWA$($svr.NodeName)ForPortal"
                                }else{
                                    ArcGIS_WaitForComponent "WaitForWA$($svr.NodeName)ForPortal"
                                    {
                                        Component = "PortalWA"
                                        InvokingComponent = "Portal"
                                        ComponentHostName =  (Get-FQDN $svr.NodeName)
                                        ComponentContext = $ConfigurationData.ConfigData.PortalContext
                                        Ensure = "Present"
                                        Credential =  $PSACredential
                                        RetryIntervalSec = 60
                                        RetryCount = 100
                                        DependsOn = $Depends
                                    }
                                    $Depends += "[ArcGIS_WaitForComponent]WaitForWA$($svr.NodeName)ForPortal"
                                }
                            }
                        }
                        
                        $SSLCertificate = $Node.SslCertificates | Where-Object { $_.Target -icontains 'Portal' }  | Select-Object -First 1
                        ArcGIS_Portal_TLS "Portal_TLS$($Node.NodeName)"                                   
                        {
                            Ensure = 'Present'
                            SiteName = 'arcgis'
                            PortalEndPoint = $MachineFQDN
                            SiteAdministrator = $PSACredential
                            CName = $SSLCertificate.Alias
                            CertificateFileLocation = $SSLCertificate.Path
                            CertificatePassword = $SSLCertificate.Password
                            DependsOn = $Depends
                            SslRootOrIntermediate = $SslRootOrIntermediate
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

                    ArcGIS_xFirewall DataStore_FirewallRules
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
                    $Depends += '[ArcGIS_xFirewall]DataStore_FirewallRules'

                    $IsMultiMachineDataStore = ($AllNodes | Where-Object { $_.Role -icontains 'DataStore' }  | Measure-Object).Count -gt 0
                    if($IsMultiMachineDataStore) 
                    {
                        # Allow outbound traffic so that database replication can take place
                        ArcGIS_xFirewall DataStore_FirewallRules_OutBound
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
                        $Depends += '[ArcGIS_xFirewall]DataStore_FirewallRules_OutBound'
                    }

                    if(($AllNodes | Where-Object { $_.Role -icontains 'DataStore' -and $_.DataStoreTypes -icontains 'SpatioTemporal' }  | Measure-Object).Count -gt 0)
                    {
                        ArcGIS_xFirewall SpatioTemporalDataStore_FirewallRules
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
                        $Depends += '[ArcGIS_xFirewall]SpatioTemporalDataStore_FirewallRules'
                    }
                        
                    ArcGIS_Service_Account ArcGIS_DataStore_RunAs_Account
                    {
                        Name = 'ArcGIS Data Store'
                        RunAsAccount = $SACredential
                        Ensure = 'Present'
                        DependsOn = $Depends
                        DataDir = $ConfigurationData.ConfigData.DataStore.ContentDirectoryLocation #DataStoreSpatioTemporalDataDirectory <- Needs to be checked if network location
                        IsDomainAccount = $ConfigurationData.ConfigData.Credentials.ServiceAccount.IsDomainAccount
                    }
                    $Depends += '[ArcGIS_Service_Account]ArcGIS_DataStore_RunAs_Account'

                    if(-not(($Node.Role -icontains "Server") -and ($Node.NodeName -ieq $PrimaryServerMachine)))
                    {
                        <#if($Node.WMFVersion -gt 4){
                            WaitForAll "WaitForAllServerConfigToComplete$($PrimaryServerMachine)"{
                                ResourceName = "[ArcGIS_Server]Server$($PrimaryServerMachine)"
                                NodeName = $PrimaryServerMachine
                                RetryIntervalSec = 60
                                RetryCount = 100
                                DependsOn = $Depends
                            }
                            $Depends += "[WaitForAll]WaitForAllServerConfigToComplete$($PrimaryServerMachine)"
                        }else{#>
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
                        <#}#>
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
                        IsEnvAzure = $false
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
                            ArcGIS_xFirewall "WebAdaptorFirewallRules$($Node.NodeName)"
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

                            if(($Node.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor'}  | Measure-Object).Count -gt 0)
                            {
                                $SSLCertificate = $Node.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor' }  | Select-Object -First 1
                                ArcGIS_IIS_TLS "WebAdaptorCertificateInstall$($Node.NodeName)"
                                {
                                    WebSiteName = 'Default Web Site'
                                    ExternalDNSName = $SSLCertificate.Alias
                                    Ensure = 'Present'
                                    CertificateFileLocation = $SSLCertificate.Path
                                    CertificatePassword =  $SSLCertificate.Password
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
                                if($ConfigurationData.ConfigData.ServerContext -and $PrimaryServerMachine)
                                {
                                    #Hacky Way to overcome a conflict
                                    if(-not($Node.Role -icontains 'DataStore') -and ($PrimaryServerMachine -ine $Node.NodeName))
                                    {
                                        <#if($Node.WMFVersion -gt 4){
                                            WaitForAll "WaitForAllServerConfigToCompleteWA$($WAPrimaryServerMachine)"{
                                                ResourceName = "[ArcGIS_Server]Server$($WAPrimaryServerMachine)"
                                                NodeName = $WAPrimaryServerMachine
                                                RetryIntervalSec = 60
                                                RetryCount = 100
                                                DependsOn = $Depends
                                            }
                                            $Depends += "[WaitForAll]WaitForAllServerConfigToCompleteWA$($WAPrimaryServerMachine)"
                                        }else{#>
                                            ArcGIS_WaitForComponent "WaitForServerConfigToCompleteWA$($PrimaryServerMachine)"
                                            {
                                                Component = "server"
                                                InvokingComponent = "WebAdaptor"
                                                ComponentHostName = (Get-FQDN $PrimaryServerMachine)
                                                ComponentContext = "arcgis"
                                                Ensure = "Present"
                                                Credential =  $PSACredential
                                                RetryIntervalSec = 60
                                                RetryCount = 100
                                                DependsOn = $Depends
                                            }
                                            $Depends += "[ArcGIS_WaitForComponent]WaitForServerConfigToCompleteWA$($PrimaryServerMachine)"
                                        <#}#>
                                    }
                                    
                                    $HostName = if(($Node.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor'}  | Measure-Object).Count -gt 0){($Node.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor' }  | Select-Object -First 1).Alias}else{ $MachineFQDN }

                                    ArcGIS_WebAdaptor "ConfigureServer$($MachineFQDN)"
                                    {
                                        Ensure = "Present"
                                        Component = 'Server'
                                        HostName = $HostName
                                        ComponentHostName = (Get-FQDN $PrimaryServerMachine)
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
                                if($ConfigurationData.ConfigData.PortalContext -and $PrimaryPortalMachine)
                                {
                                    if($PrimaryPortalMachine -ine $Node.NodeName)
                                    {
                                        <#if($Node.WMFVersion -gt 4){
                                            WaitForAll "WaitForAllPortalConfigToComplete$($PrimaryPortalMachine)"{
                                                ResourceName = "[ArcGIS_Portal]Portal$($PrimaryPortalMachine)"
                                                NodeName = $PrimaryPortalMachine
                                                RetryIntervalSec = 60
                                                RetryCount = 90
                                                DependsOn = $Depends
                                            }
                                            $Depends += "[WaitForAll]WaitForAllPortalConfigToComplete$($PrimaryPortalMachine)"
                                        }else{#>
                                            ArcGIS_WaitForComponent "WaitForPortalConfigToComplete$($PrimaryPortalMachine)"
                                            {
                                                Component = "Portal"
                                                InvokingComponent = "WebAdaptor"
                                                ComponentHostName = (Get-FQDN $PrimaryPortalMachine)
                                                ComponentContext = "arcgis"
                                                Ensure = "Present"
                                                Credential =  $PSACredential
                                                RetryIntervalSec = 60
                                                RetryCount = 100
                                                DependsOn = $Depends
                                            }
                                            $Depends += "[ArcGIS_WaitForComponent]WaitForPortalConfigToComplete$($PrimaryPortalMachine)"
                                        #}
                                    }
                                    
                                    $HostName = if(($Node.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor'}  | Measure-Object).Count -gt 0){($Node.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor' }  | Select-Object -First 1).Alias}else{ $MachineFQDN }
                                
                                    ArcGIS_WebAdaptor "ConfigurePortal$($MachineFQDN)"
                                    {
                                        Ensure = "Present"
                                        Component = 'Portal'
                                        HostName = $HostName
                                        ComponentHostName =  (Get-FQDN $PrimaryPortalMachine)
                                        Context = $ConfigurationData.ConfigData.PortalContext
                                        OverwriteFlag = $False
                                        SiteAdministrator = $PSACredential
                                        DependsOn = $Depends
                                    }
                                    $Depends += "[ArcGIS_WebAdaptor]ConfigurePortal$($MachineFQDN)"
                                }
                            }
                        }
                    }
                }
                'RasterDataStoreItem'{
                    if(-not($ConfigurationData.ConfigData.DataStoreItems.RasterStore.ExternalFileSharePath)){
                        ArcGIS_FileShare RasterAnalysisFileShare
                        {
                            FileShareName = $ConfigurationData.ConfigData.DataStoreItems.RasterStore.FileShareName
                            FileShareLocalPath = $ConfigurationData.ConfigData.DataStoreItems.RasterStore.FileShareLocalPath
                            Ensure = 'Present'
                            Credential = $SACredential
                            IsDomainAccount = $ConfigurationData.ConfigData.Credentials.ServiceAccount.IsDomainAccount
                        }
                    }
                    
                    ArcGIS_DataStoreItem RasterDataStoreItem
                    {
                        Name = "RasterFileShareDataStore"
                        HostName = (Get-FQDN $PrimaryServerMachine)
                        Ensure = "Present"
                        SiteAdministrator = $PSACredential
                        DataStoreType = "RasterStore"
                        DataStorePath = if($ConfigurationData.ConfigData.DataStoreItems.RasterStore.ExternalFileSharePath){ $ConfigurationData.ConfigData.DataStoreItems.RasterStore.ExternalFileSharePath }else{ "\\$($env:ComputerName)\$($ConfigurationData.ConfigData.DataStoreItems.RasterStore.FileShareName)" }
                        DependsOn = if(-not($ConfigurationData.ConfigData.DataStoreItems.RasterStore.ExternalFileSharePath)){ @('[ArcGIS_FileShare]RasterAnalysisFileShare') }else{ @() }
                    }
                }
                'FileShare'{
                    $FilePathsArray = @()
                    if($ConfigurationData.ConfigData.Server.ConfigStoreLocation.StartsWith('\') -and $ConfigurationData.ConfigData.Server.ServerDirectoriesRootLocation.StartsWith('\')){
                        $FilePathsArray += $ConfigurationData.ConfigData.Server.ConfigStoreLocation
                        $FilePathsArray += $ConfigurationData.ConfigData.Server.ServerDirectoriesRootLocation
                    }else{
                        throw "One or both of the Config Store Location and Server Directories Root Location is not a file share location"
                    }
                    if($ConfigurationData.ConfigData.Portal){
                        if($ConfigurationData.ConfigData.Portal.ContentDirectoryLocation.StartsWith('\')){
                            $FilePathsArray += $ConfigurationData.ConfigData.Portal.ContentDirectoryLocation
                        }
                    }
                    
                    ArcGIS_FileShare FileShare
                    {
                        FileShareName = $ConfigurationData.ConfigData.FileShareName
                        FileShareLocalPath = $ConfigurationData.ConfigData.FileShareLocalPath
                        Ensure = 'Present'
                        Credential = $SACredential
                        FilePaths = ($FilePathsArray -join ",")
                        IsDomainAccount = $ConfigurationData.ConfigData.Credentials.ServiceAccount.IsDomainAccount
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
                        
                        #Install TLS Certificate

                        ForEach($svr in ($AllNodes | Where-Object { $_.Role -icontains 'ServerWebAdaptor' -or $_.Role -icontains 'PortalWebAdaptor'}))
                        {
                            if(($svr.Role -icontains "ServerWebAdaptor") -and -not($svr.Role -ieq "PortalWebAdaptor"))
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
                                        DependsOn = $Depends
                                    }
                                    $Depends += "[ArcGIS_WaitForComponent]WaitFor$($svr.NodeName)ForLoadBalance"
                                }
                            }
                            elseif(($svr.Role -ieq "PortalWebAdaptor") -and -not($svr.Role -ieq "ServerWebAdaptor"))
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
                                        DependsOn = $Depends
                                    }
                                    $Depends += "[ArcGIS_WaitForComponent]WaitFor$($svr.NodeName)ForLoadBalance"
                                }
                            }
                            elseif(($svr.Role -ieq "PortalWebAdaptor") -and ($svr.Role -ieq "ServerWebAdaptor"))
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
                                        DependsOn = $Depends
                                    }
                                    $Depends += "[ArcGIS_WaitForComponent]WaitFor$($svr.NodeName)ForLoadBalance"
                                }
                            }

                            $SSLCertificate = $svr.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor' }  | Select-Object -First 1
                            ArcGIS_TLSCertificateImport "CertificateImport-$($svr.NodeName)"
                            {
                                HostName = if($SSLCertificate -and $SSLCertificate.Alias){ $SSLCertificate.Alias }else{ Get-FQDN $svr.NodeName }
                                Ensure = 'Present'
                                ApplicationPath = "/"
                                HttpsPort = 443
                                StoreLocation = 'LocalMachine'
                                StoreName = 'AuthRoot'
                                DependsOn = $Depends
                            }

                            $Depends += "[ArcGIS_TLSCertificateImport]CertificateImport-$($svr.NodeName)"
                        }
                        
                        if(($Node.SslCertificates | Where-Object { $_.Target -icontains 'LoadBalancer'}  | Measure-Object).Count -gt 0)
                        {
                            $SSLCertificate = $Node.SslCertificates | Where-Object { $_.Target -icontains 'LoadBalancer' }  | Select-Object -First 1
                            ArcGIS_IIS_TLS "LoadBalancerCertificateInstall$($Node.NodeName)"
                            {
                                WebSiteName = 'Default Web Site'
                                ExternalDNSName = $SSLCertificate.Alias
                                Ensure = 'Present'
                                CertificateFileLocation =  $SSLCertificate.Path
                                CertificatePassword = $SSLCertificate.Password
                                DependsOn = $Depends
                            }
                        }
                        else
                        {
                            ArcGIS_IIS_TLS "LoadBalancerCertificateInstall$($Node.NodeName)"
                            {
                                WebSiteName = 'Default Web Site'
                                ExternalDNSName = $MachineFQDN 
                                Ensure = 'Present'
                                DependsOn = $Depends
                            }
                        }
                        
                        $Depends += "[ArcGIS_IIS_TLS]LoadBalancerCertificateInstall$($Node.NodeName)"
                    }
                }
            }
        }
    }
}
