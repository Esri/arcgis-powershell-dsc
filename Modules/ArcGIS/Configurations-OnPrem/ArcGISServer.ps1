Configuration ArcGISServer
{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServiceCredential,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ForceServiceCredentialUpdate = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsMSA = $false,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServerPrimarySiteAdminCredential,

        [Parameter(Mandatory=$True)]
        [System.String]
        $Version,
        
        [Parameter(Mandatory=$False)]
        [System.String]
        $PrimaryServerMachine,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ServerRole,

        [Parameter(Mandatory=$False)]
        [System.Array]
        $AdditionalServerRoles,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $OpenFirewallPorts = $False,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ConfigStoreLocation,

        [Parameter(Mandatory=$true)]
        [System.String]
        $ServerDirectoriesRootLocation,

        [Parameter(Mandatory=$false)]
        [System.Array]
        $ServerDirectories,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ServerLogsLocation = $null,

        [Parameter(Mandatory=$False)]
        [System.String]
        $LocalRepositoryPath = $null,
        
        [Parameter(Mandatory=$False)]
        [System.Object]
        $RegisteredDirectories,

        [Parameter(Mandatory=$False)]
        [ValidateSet("AzureFiles","AzureBlob","AWSS3DynamoDB")]
        [AllowNull()] 
        [System.String]
        $ConfigStoreCloudStorageType,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ConfigStoreAzureFileShareName,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ConfigStoreCloudNamespace,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ConfigStoreAWSRegion,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $ConfigStoreCloudStorageCredentials,

        [Parameter(Mandatory=$False)]
        [ValidateSet("AzureFiles")]
        [AllowNull()] 
        [System.String]
        $ServerDirectoriesCloudStorageType,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ServerDirectoriesAzureFileShareName,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ServerDirectoriesCloudNamespace,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $ServerDirectoriesCloudStorageCredentials,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $EnableHTTPSOnly = $False,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $EnableHSTS = $False,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $UsesSSL = $False,
        
        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $DebugMode = $False
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.1.0 
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_Server
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -Name ArcGIS_GeoEvent
    Import-DscResource -Name ArcGIS_WaitForComponent

    if($null -ne $ConfigStoreCloudStorageType) 
    {
        if($ConfigStoreCloudStorageType -ieq "AWSS3DynamoDB"){
            $ConfigStoreCloudStorageConnectionString="NAMESPACE=$($ConfigStoreCloudNamespace);REGION=$($ConfigStoreAWSRegion);"
            if($ConfigStoreCloudStorageCredentials){
                $ConfigStoreCloudStorageConnectionSecret="ACCESS_KEY_ID=$($ConfigStoreCloudStorageCredentials.UserName);SECRET_KEY=$($ConfigStoreCloudStorageCredentials.GetNetworkCredential().Password);"
            }
        }else{
            if($ConfigStoreCloudStorageCredentials){
                $ConfigStoreAccountName = $ConfigStoreCloudStorageCredentials.UserName
                $ConfigStoreEndpointSuffix = ''
                $ConfigStorePos = $ConfigStoreCloudStorageCredentials.UserName.IndexOf('.blob.')
                if($ConfigStorePos -gt -1) {
                    $ConfigStoreAccountName = $ConfigStoreCloudStorageCredentials.UserName.Substring(0, $ConfigStorePos)
                    $ConfigStoreEndpointSuffix = $ConfigStoreCloudStorageCredentials.UserName.Substring($ConfigStorePos + 6) # Remove the hostname and .blob. suffix to get the storage endpoint suffix
                    $ConfigStoreEndpointSuffix = ";EndpointSuffix=$($ConfigStoreEndpointSuffix)"
                }

                if($ConfigStoreCloudStorageType -ieq 'AzureFiles') {
                    $ConfigStoreAzureFilesEndpoint = if($ConfigStorePos -gt -1){$ConfigStoreCloudStorageCredentials.UserName.Replace('.blob.','.file.')}else{$ConfigStoreCloudStorageCredentials.UserName}                   
                    $ConfigStoreAzureFileShareName = $ConfigStoreAzureFileShareName.ToLower() # Azure file shares need to be lower case
                    $ConfigStoreLocation  = "\\$($ConfigStoreAzureFilesEndpoint)\$ConfigStoreAzureFileShareName\$($ConfigStoreCloudNamespace)\server\config-store"
                }
                else {
                    $ConfigStoreCloudStorageConnectionString = "NAMESPACE=$($ConfigStoreCloudNamespace)server$($ConfigStoreEndpointSuffix);DefaultEndpointsProtocol=https;AccountName=$ConfigStoreAccountName"
                    $ConfigStoreCloudStorageConnectionSecret = "AccountKey=$($ConfigStoreCloudStorageCredentials.GetNetworkCredential().Password)"
                }
            }
        }
    }

    if(($null -ne $ServerDirectoriesCloudStorageType) -and ($ServerDirectoriesCloudStorageType -ieq 'AzureFiles') -and $ServerDirectoriesCloudStorageCredentials) 
    {
        $ServerDirectoriesPos = $ServerDirectoriesCloudStorageCredentials.UserName.IndexOf('.blob.')
        $ServerDirectoriesAzureFilesEndpoint = if($ServerDirectoriesPos -gt -1){$ServerDirectoriesCloudStorageCredentials.UserName.Replace('.blob.','.file.')}else{ $ServerDirectoriesCloudStorageCredentials.UserName }                   
        $ServerDirectoriesAzureFileShareName = $ServerDirectoriesAzureFileShareName.ToLower() # Azure file shares need to be lower case
        $ServerDirectoriesRootLocation   = "\\$($ServerDirectoriesAzureFilesEndpoint)\$ServerDirectoriesAzureFileShareName\$($ServerDirectoriesCloudNamespace)\server\server-dirs" 
    }

    Node $AllNodes.NodeName
    { 
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        $IsMultiMachineServer = (($AllNodes | Measure-Object).Count -gt 1)

        $VersionArray = $Version.Split(".")
        $Depends = @()
        if($OpenFirewallPorts -or $IsMultiMachineServer ) # Server only deployment or behind an ILB or has DataStore nodes that need to register using admin			
        {
            ArcGIS_xFirewall Server_FirewallRules
            {
                Name                  = "ArcGISServer" 
                DisplayName           = "ArcGIS for Server" 
                DisplayGroup          = "ArcGIS for Server" 
                Ensure                = 'Present' 
                Access                = "Allow" 
                State                 = "Enabled" 
                Profile               = ("Domain","Private","Public") 
                LocalPort             = ("6443")                       
                Protocol              = "TCP" 
            }
            $Depends += '[ArcGIS_xFirewall]Server_FirewallRules'
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

            if($ServerRole -ieq 'GeoAnalytics' -or ($ServerRole -ieq "GeneralPurposeServer" -and $AdditionalServerRoles -icontains "GeoAnalytics")) 
            {  
                $Depends += '[ArcGIS_xFirewall]GeoAnalytics_InboundFirewallRules' 
                $Depends += '[ArcGIS_xFirewall]GeoAnalytics_OutboundFirewallRules' 

                $GeoAnalyticsPorts = @("7077")
                if($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -or $VersionArray[1] -gt 8)){
                    $GeoAnalyticsPorts += @("12181","12182","12190")
                }else{
                    $GeoAnalyticsPorts += @("2181","2182","2190")
                }

                ArcGIS_xFirewall GeoAnalytics_InboundFirewallRules
                {
                    Name                  = "ArcGISGeoAnalyticsInboundFirewallRules" 
                    DisplayName           = "ArcGIS GeoAnalytics" 
                    DisplayGroup          = "ArcGIS GeoAnalytics" 
                    Ensure                = 'Present'
                    Access                = "Allow" 
                    State                 = "Enabled" 
                    Profile               = ("Domain","Private","Public")
                    LocalPort             = $GeoAnalyticsPorts	# Spark and Zookeeper
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
                    LocalPort             = $GeoAnalyticsPorts	# Spark and Zookeeper
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

        $DataDirs = @()
        if($null -ne $CloudStorageType){
            if(-not($CloudStorageType -ieq 'AzureFiles')){
                $DataDirs = @($ServerDirectoriesRootLocation)
                if($ServerDirectories -ne $null){
                    foreach($dir in $ServerDirectories){
                        $DataDirs += $dir.physicalPath
                    }
                }
            }
        }else{
            $DataDirs = @($ConfigStoreLocation,$ServerDirectoriesRootLocation) 
            if($ServerDirectories -ne $null){
                foreach($dir in $ServerDirectories){
                    $DataDirs += $dir.physicalPath
                }
            }
        }

        if($null -ne $ServerLogsLocation){
            $DataDirs += $ServerLogsLocation
        }

        if($null -ne $LocalRepositoryPath){
            $DataDirs += $LocalRepositoryPath
        }

        ArcGIS_Service_Account Server_RunAs_Account
        {
            Name = 'ArcGIS Server'
            RunAsAccount = $ServiceCredential
            ForceRunAsAccountUpdate = $ForceServiceCredentialUpdate
            Ensure = 'Present'
            DependsOn = $Depends
            DataDir = $DataDirs
            IsDomainAccount = $ServiceCredentialIsDomainAccount
            IsMSAAccount = $ServiceCredentialIsMSA
            SetStartupToAutomatic = $True
        }

        $Depends += '[ArcGIS_Service_Account]Server_RunAs_Account' 

        if(-not($ServiceCredentialIsMSA)) 
        {
            if($ConfigStoreAzureFilesEndpoint -and $ConfigStoreCloudStorageCredentials -and ($ConfigStoreCloudStorageType -ieq 'AzureFiles')){
                $ConfigStoreFilesStorageAccountName = $ConfigStoreAzureFilesEndpoint.Substring(0, $ConfigStoreAzureFilesEndpoint.IndexOf('.'))
                $ConfigStoreStorageAccountKey       = $ConfigStoreCloudStorageCredentials.GetNetworkCredential().Password

                Script PersistConfigStoreCloudStorageCredentials
                {
                    TestScript = { 
                                    $result = cmdkey "/list:$using:ConfigStoreAzureFilesEndpoint"
                                    $result | ForEach-Object{Write-verbose -Message "cmdkey: $_" -Verbose}
                                    if($result -like '*none*')
                                    {
                                        return $false
                                    }
                                    return $true
                                }
                    SetScript = { 
                                    $result = cmdkey "/add:$using:ConfigStoreAzureFilesEndpoint" "/user:$using:ConfigStoreFilesStorageAccountName" "/pass:$using:ConfigStoreStorageAccountKey" 
                                    $result | ForEach-Object{Write-verbose -Message "cmdkey: $_" -Verbose}
                                }
                    GetScript            = { return @{} }                  
                    DependsOn            = $Depends
                    PsDscRunAsCredential = $ServiceCredential # This is critical, cmdkey must run as the service account to persist property
                }              
                $Depends += '[Script]PersistConfigStoreCloudStorageCredentials'
            }

            if($ServerDirectoriesAzureFilesEndpoint -and $ServerDirectoriesCloudStorageCredentials -and ($ServerDirectoriesCloudStorageType -ieq 'AzureFiles')){
                $ServerDirectoriesFilesStorageAccountName = $ServerDirectoriesAzureFilesEndpoint.Substring(0, $ServerDirectoriesAzureFilesEndpoint.IndexOf('.'))
                $ServerDirectoriesStorageAccountKey       = $ServerDirectoriesCloudStorageCredentials.GetNetworkCredential().Password

                Script PersistServerDirectoriesCloudStorageCredentials
                {
                    TestScript = { 
                                    $result = cmdkey "/list:$using:ServerDirectoriesAzureFilesEndpoint"
                                    $result | ForEach-Object{Write-verbose -Message "cmdkey: $_" -Verbose}
                                    if($result -like '*none*')
                                    {
                                        return $false
                                    }
                                    return $true
                                }
                    SetScript = { 
                                    $result = cmdkey "/add:$using:ServerDirectoriesAzureFilesEndpoint" "/user:$using:ServerDirectoriesFilesStorageAccountName" "/pass:$using:ServerDirectoriesStorageAccountKey" 
                                    $result | ForEach-Object{Write-verbose -Message "cmdkey: $_" -Verbose}
                                }
                    GetScript            = { return @{} }                  
                    DependsOn            = $Depends
                    PsDscRunAsCredential = $ServiceCredential # This is critical, cmdkey must run as the service account to persist property
                }              
                $Depends += '[Script]PersistServerDirectoriesCloudStorageCredentials'
            }
        }

        if($Node.NodeName -ine $PrimaryServerMachine)
        {
            if($UsesSSL){
                ArcGIS_WaitForComponent "WaitForServer$($PrimaryServerMachine)"{
                    Component = "Server"
                    InvokingComponent = "Server"
                    ComponentHostName = $PrimaryServerMachine
                    ComponentContext = "arcgis"
                    Credential = $ServerPrimarySiteAdminCredential
                    Ensure = "Present"
                    RetryIntervalSec = 60
                    RetryCount = 100
                }
                $Depends += "[ArcGIS_WaitForComponent]WaitForServer$($PrimaryServerMachine)"
            }else{
                WaitForAll "WaitForAllServer$($PrimaryServerMachine)"{
                    ResourceName = "[ArcGIS_Server]Server$($PrimaryServerMachine)"
                    NodeName = $PrimaryServerMachine
                    RetryIntervalSec = 60
                    RetryCount = 100
                    DependsOn = $Depends
                }
                $Depends += "[WaitForAll]WaitForAllServer$($PrimaryServerMachine)"
            }
        }

        ArcGIS_Server "Server$($Node.NodeName)"
        {
            Version = $Version
            ServerHostName = $Node.NodeName
            Ensure = 'Present'
            SiteAdministrator = $ServerPrimarySiteAdminCredential
            ConfigurationStoreLocation = $ConfigStoreLocation
            ServerDirectoriesRootLocation = $ServerDirectoriesRootLocation
            ServerDirectories = if($ServerDirectories -ne $null){ (ConvertTo-JSON $ServerDirectories -Depth 5) }else{ $null }
            ServerLogsLocation = $ServerLogsLocation
            LocalRepositoryPath = $LocalRepositoryPath
            Join =  if($Node.NodeName -ine $PrimaryServerMachine) { $true } else { $false } 
            PeerServerHostName = $PrimaryServerMachine
            DependsOn = $Depends
            LogLevel = if($DebugMode) { 'DEBUG' } else { 'WARNING' }
            ConfigStoreCloudStorageConnectionString = $ConfigStoreCloudStorageConnectionString
            ConfigStoreCloudStorageConnectionSecret = $ConfigStoreCloudStorageConnectionSecret
        }
        $Depends += "[ArcGIS_Server]Server$($Node.NodeName)"

        ArcGIS_Server_TLS "Server_TLS_$($Node.NodeName)"
        {
            ServerHostName = $Node.NodeName
            SiteAdministrator = $ServerPrimarySiteAdminCredential
            WebServerCertificateAlias =  if($Node.SSLCertificate){$Node.SSLCertificate.CName}else{$null}
            CertificateFileLocation = if($Node.SSLCertificate){$Node.SSLCertificate.Path}else{$null}
            CertificatePassword = if($Node.SSLCertificate){$Node.SSLCertificate.Password}else{$null}
            SslRootOrIntermediate = if($Node.SslRootOrIntermediate){$Node.SslRootOrIntermediate}else{$null}
            EnableHTTPSOnly = $EnableHTTPSOnly
            EnableHSTS = $EnableHSTS
            ServerType = "GeneralPurposeServer"
            DependsOn = $Depends
        }
        $Depends += "[ArcGIS_Server_TLS]Server_TLS_$($Node.NodeName)"
        
        if ($RegisteredDirectories -and ($Node.NodeName -ieq $PrimaryServerMachine)) {
            ArcGIS_Server_RegisterDirectories "Server$($Node.NodeName)RegisterDirectories"
            { 
                ServerHostName = $Node.NodeName
                Ensure = 'Present'
                SiteAdministrator = $ServerPrimarySiteAdminCredential
                DirectoriesJSON = $RegisteredDirectories
                DependsOn = $Depends
            }
            $Depends += "[ArcGIS_Server_RegisterDirectories]Server$($Node.NodeName)RegisterDirectories"
        }

        if($ServerRole -ieq "GeoEvent" -or ($ServerRole -ieq "GeneralPurposeServer" -and $AdditionalServerRoles -icontains "GeoEvent")) 
        { 
            #This condition is an issue
            ArcGIS_Service_Account GeoEvent_RunAs_Account
            {
                Name = 'ArcGISGeoEvent'
                RunAsAccount = $ServiceCredential
                ForceRunAsAccountUpdate = $ForceServiceCredentialUpdate
                Ensure =  "Present"
                DependsOn = $Depends
                DataDir = "$env:ProgramData\Esri\GeoEvent"
                IsDomainAccount = $ServiceCredentialIsDomainAccount
                IsMSAAccount = $ServiceCredentialIsMSA
                SetStartupToAutomatic = $True
            }
            $Depends += "[ArcGIS_Service_Account]GeoEvent_RunAs_Account"

            ArcGIS_xFirewall GeoEvent_FirewallRules
            {
                Name                  = "ArcGISGeoEventFirewallRules" 
                DisplayName           = "ArcGIS GeoEvent" 
                DisplayGroup          = "ArcGIS GeoEvent Extension" 
                Ensure                = "Present"
                Access                = "Allow" 
                State                 = "Enabled" 
                Profile               = ("Domain","Private","Public")
                LocalPort             = ("6143","6180","5565","5575")
                Protocol              = "TCP" 
                DependsOn             = $Depends
            }
            $Depends += "[ArcGIS_xFirewall]GeoEvent_FirewallRules"
            
            if($IsMultiMachineServer -and ($VersionArray[0] -eq 10 -and $VersionArray[1] -lt 9))
            {
                ArcGIS_xFirewall GeoEvent_FirewallRules_Zookeeper
				{
					Name                  = "ArcGISGeoEventFirewallRulesClusterZookeeper" 
					DisplayName           = "ArcGIS GeoEvent Extension Cluster Zookeeper" 
					DisplayGroup          = "ArcGIS GeoEvent Extension" 
					Ensure                = 'Present' 
					Access                = "Allow" 
					State                 = "Enabled" 
					Profile               = ("Domain","Private","Public")
					LocalPort             = ("4181","4182","4190")
					Protocol              = "TCP" 
				}

				ArcGIS_xFirewall GeoEvent_FirewallRule_Zookeeper_Outbound
				{
					Name                  = "ArcGISGeoEventFirewallRulesClusterOutboundZookeeper" 
					DisplayName           = "ArcGIS GeoEvent Extension Cluster Outbound Zookeeper" 
					DisplayGroup          = "ArcGIS GeoEvent Extension" 
					Ensure                = 'Present' 
					Access                = "Allow" 
					State                 = "Enabled" 
					Profile               = ("Domain","Private","Public")
					RemotePort            = ("4181","4182","4190")
					Protocol              = "TCP" 
					Direction             = "Outbound"    
				}
				$ServerDependsOn += @('[ArcGIS_xFirewall]GeoEvent_FirewallRule_Zookeeper_Outbound','[ArcGIS_xFirewall]GeoEvent_FirewallRules_Zookeeper')

                $GeoEventPorts = ("27271","27272","27273","9191","9192","9193","9194","9220","9320","5565","5575")
                if($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -or $VersionArray[1] -gt 8)){
                    $GeoEventPorts += @("12181","12182","12190")
                }else{
                    $GeoEventPorts += @("2181","2182","2190")
                }

                ArcGIS_xFirewall GeoEvent_FirewallRules_MultiMachine
                {
                    Name                  = "ArcGISGeoEventFirewallRulesCluster" 
                    DisplayName           = "ArcGIS GeoEvent Extension Cluster" 
                    DisplayGroup          = "ArcGIS GeoEvent Extension" 
                    Ensure                = "Present"
                    Access                = "Allow" 
                    State                 = "Enabled" 
                    Profile               = ("Domain","Private","Public")
                    LocalPort             = $GeoEventPorts
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
                    RemotePort            = $GeoEventPorts
                    Protocol              = "TCP" 
                    Direction             = "Outbound"    
                    DependsOn             = $Depends
                }
                $Depends += "[ArcGIS_xFirewall]GeoEvent_FirewallRules_MultiMachine_OutBound"

                ArcGIS_xFirewall GeoEventGatewayService_Firewall
                {
                    Name                  = "ArcGISGeoEventGateway"
                    DisplayName           = "ArcGIS GeoEvent Gateway"
                    DisplayGroup          = "ArcGIS GeoEvent Extension"
                    Ensure                = 'Present'
                    Access                = "Allow"
                    State                 = "Enabled"
                    Profile               = ("Domain","Private","Public")
                    LocalPort             = ("9092")
                    Protocol              = "TCP"
                    DependsOn             = $Depends
                }
                $Depends += "[ArcGIS_xFirewall]GeoEventGatewayService_Firewall"
            }

            ArcGIS_GeoEvent ArcGIS_GeoEvent
            {
                ServerHostName            = $Node.NodeName
                Name	                  = 'ArcGIS GeoEvent'
                Ensure	                  =  "Present"
                SiteAdministrator         = $ServerPrimarySiteAdminCredential
                WebSocketContextUrl       = "wss://$(Get-FQDN $Node.NodeName):6143/arcgis" #Fix this
                Version					  = $Version
                DependsOn                 = $Depends
                #SiteAdminUrl             = if($ConfigData.ExternalDNSName) { "https://$($ConfigData.ExternalDNSName)/arcgis/admin" } else { $null }
            }
        }

        if($ServerRole -ieq "WorkflowManagerServer" -or ($ServerRole -ieq "GeneralPurposeServer" -and $AdditionalServerRoles -icontains "WorkflowManagerServer")) 
        {
            #This condition is an issue
            ArcGIS_Service_Account WorkflowManager_RunAs_Account
            {
                Name = 'WorkflowManager'
                RunAsAccount = $ServiceCredential
                ForceRunAsAccountUpdate = $ForceServiceCredentialUpdate
                Ensure =  "Present"
                DependsOn = $Depends
                DataDir = "$env:ProgramData\Esri\workflowmanager"
                IsDomainAccount = $ServiceCredentialIsDomainAccount
                IsMSAAccount = $ServiceCredentialIsMSA
                SetStartupToAutomatic = $True
            }
            $Depends += "[ArcGIS_Service_Account]WorkflowManager_RunAs_Account"

            ArcGIS_xFirewall WorkflowManagerServer_FirewallRules
            {
                Name                  = "ArcGISWorkflowManagerServerFirewallRules" 
                DisplayName           = "ArcGIS Workflow Manager Server" 
                DisplayGroup          = "ArcGIS Workflow Manager Server Extension" 
                Ensure                = "Present"
                Access                = "Allow" 
                State                 = "Enabled" 
                Profile               = ("Domain","Private","Public")
                LocalPort             = ("13443")
                Protocol              = "TCP" 
                DependsOn             = $Depends
            }
            $Depends += "[ArcGIS_xFirewall]WorkflowManagerServer_FirewallRules"

            if($IsMultiMachineServer){
                $WfmPorts = @("9830", "9820", "9840", "9880")

                ArcGIS_xFirewall WorkflowManagerServer_FirewallRules_MultiMachine_OutBound
                {
                    Name                  = "ArcGISWorkflowManagerServerFirewallRulesClusterOutbound" 
                    DisplayName           = "ArcGIS WorkflowManagerServer Extension Cluster Outbound" 
                    DisplayGroup          = "ArcGIS WorkflowManagerServer Extension" 
                    Ensure                =  "Present"
                    Access                = "Allow" 
                    State                 = "Enabled" 
                    Profile               = ("Domain","Private","Public")
                    RemotePort            = $WfmPorts
                    Protocol              = "TCP" 
                    Direction             = "Outbound"    
                    DependsOn             = $Depends
                }
                $Depends += "[ArcGIS_xFirewall]WorkflowManagerServer_FirewallRules_MultiMachine_OutBound"

                ArcGIS_xFirewall WorkflowManagerServer_FirewallRules_MultiMachine_InBound
                {
                    Name                  = "ArcGISWorkflowManagerServerFirewallRulesClusterInbound"
                    DisplayName           = "ArcGIS WorkflowManagerServer Extension Cluster Inbound"
                    DisplayGroup          = "ArcGIS WorkflowManagerServer Extension"
                    Ensure                = 'Present'
                    Access                = "Allow"
                    State                 = "Enabled"
                    Profile               = ("Domain","Private","Public")
                    RemotePort            = $WfmPorts
                    Protocol              = "TCP"
                    Direction             = "Inbound"
                    DependsOn             = $Depends
                }
                $Depends += "[ArcGIS_xFirewall]WorkflowManagerServer_FirewallRules_MultiMachine_InBound"
            }
        }
    }
}
