Configuration GISServerMultiTierConfiguration
{
	param(
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $ServiceCredential

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServiceCredentialIsDomainAccount = 'false'

        ,[Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $SiteAdministratorCredential

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $PortalSiteAdministratorCredential

		,[Parameter(Mandatory=$false)]
        [System.String]
        $IsAddingServersOrRegisterEGDB 

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $FederateSite 
                
        ,[Parameter(Mandatory=$false)]
        [System.String]
        $UseCloudStorage 

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $UseAzureFiles 

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $StorageAccountCredential

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $SSLCertificatePassword

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $SSLCertificateFileUrl
                
        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServerLicenseFileUrl

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $ServerMachineNames

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServerFunctions

		,[Parameter(Mandatory=$false)]
        [System.String]
        $ServerRole

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $FileShareMachineName

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $ExternalDNSHostName    

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $FederationEndPointHostName      
		
		,[Parameter(Mandatory=$false)]
        [System.Int32]
        $OSDiskSize = 0

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $EnableDataDisk              

         ,[Parameter(Mandatory=$false)]
        [System.String]
        $FileShareName = 'fileshare' 

        ,[parameter(Mandatory = $false)]
		[System.String]
		$DatabaseOption

        ,[parameter(Mandatory = $false)]
		[System.String]
		$DatabaseServerHostName

        ,[parameter(Mandatory = $false)]
		[System.String]
		$DatabaseName

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $DatabaseServerAdministratorCredential

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $DatabaseUserCredential

        ,[parameter(Mandatory = $false)]
		[System.String]
		$IsManaged = 'True'

        ,[parameter(Mandatory = $false)]
		[System.String]
		$EnableGeodatabase = 'True'

		,[Parameter(Mandatory=$false)]
        $CloudStores
        
		,[Parameter(Mandatory=$false)]
        $WebProxyMachineNamesOnHostingServer

		,[Parameter(Mandatory=$false)]
        $GisServerMachineNamesOnHostingServer

		,[Parameter(Mandatory=$false)]
		$PortalMachineNamesOnHostingServer
		
		,[Parameter(Mandatory=$false)]
        [System.String]
        $EnableLogHarvesterPlugin

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $DebugMode
    )

    function Get-FileNameFromUrl
    {
        param(
            [string]$Url
        )
        $FileName = $Url
        if($FileName) {
            $pos = $FileName.IndexOf('?')
            if($pos -gt 0) { 
                $FileName = $FileName.Substring(0, $pos) 
            } 
            $FileName = $FileName.Substring($FileName.LastIndexOf('/')+1)   
        }     
        $FileName
    }

	Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
	Import-DscResource -Name ArcGIS_License
	Import-DscResource -Name ArcGIS_Server
	Import-DscResource -Name ArcGIS_Server_TLS
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -Name ArcGIS_WindowsService
    Import-DscResource -Name ArcGIS_Federation
    Import-DSCResource -Name ArcGIS_EGDB
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_xSmbShare
    Import-DscResource -Name ArcGIS_xDisk
	Import-DscResource -Name ArcGIS_DataStoreItem
	Import-DscResource -Name ArcGIS_TLSCertificateImport
	Import-DscResource -Name ArcGIS_GeoEvent
	Import-DscResource -Name ArcGIS_IIS_TLS
	Import-DscResource -Name ArcGIS_ReverseProxy_ARR
	Import-DscResource -Name ArcGIS_Disk
	Import-DscResource -Name ArcGIS_LogHarvester
    
    ##
    ## Download license files
    ##
    if($ServerLicenseFileUrl) {
        $ServerLicenseFileName = Get-FileNameFromUrl $ServerLicenseFileUrl
        Invoke-WebRequest -OutFile $ServerLicenseFileName -Uri $ServerLicenseFileUrl -UseBasicParsing -ErrorAction Ignore
    }    
    if($SSLCertificateFileUrl) {
        $SSLCertificateFileName = Get-FileNameFromUrl $SSLCertificateFileUrl
        Invoke-WebRequest -OutFile $SSLCertificateFileName -Uri $SSLCertificateFileUrl -UseBasicParsing -ErrorAction Ignore
    }
    
    $FolderName = $ExternalDNSHostName.Substring(0, $ExternalDNSHostName.IndexOf('.')).ToLower()
    $ServerHostName = ($ServerMachineNames -split ',') | Select-Object -First 1
    $ConfigStoreLocation  = "\\$($FileShareMachineName)\$FileShareName\$FolderName\server\config-store"
    $ServerDirsLocation   = "\\$($FileShareMachineName)\$FileShareName\$FolderName\server\server-dirs" 
    $Join = ($env:ComputerName -ine $ServerHostName)
	$IsDebugMode = $DebugMode -ieq 'true'
	$IsServiceCredentialDomainAccount = $ServiceCredentialIsDomainAccount -ieq 'true'
    $IsMultiMachineServer = ($ServerMachineNames.Length -gt 1)
	$LastServerHostName = ($ServerMachineNames -split ',') | Select-Object -Last 1

    if(($UseCloudStorage -ieq 'True') -and $StorageAccountCredential) 
    {
        $Namespace = $ExternalDNSHostName
        $Pos = $Namespace.IndexOf('.')
        if($Pos -gt 0) { $Namespace = $Namespace.Substring(0, $Pos) }        
        $Namespace = [System.Text.RegularExpressions.Regex]::Replace($Namespace, '[\W]', '') # Sanitize
        $AccountName = $StorageAccountCredential.UserName
		$EndpointSuffix = ''
        $Pos = $StorageAccountCredential.UserName.IndexOf('.blob.')
        if($Pos -gt -1) {
            $AccountName = $StorageAccountCredential.UserName.Substring(0, $Pos)
			$EndpointSuffix = $StorageAccountCredential.UserName.Substring($Pos + 6) # Remove the hostname and .blob. suffix to get the storage endpoint suffix
			$EndpointSuffix = ";EndpointSuffix=$($EndpointSuffix)"
        }
        if($UseAzureFiles -ieq 'True') {
            $AzureFilesEndpoint = $StorageAccountCredential.UserName.Replace('.blob.','.file.')         
            $FileShareName = $FileShareName.ToLower() # Azure file shares need to be lower case                      
            $ConfigStoreLocation  = "\\$($AzureFilesEndpoint)\$FileShareName\$FolderName\server\config-store"
            $ServerDirsLocation   = "\\$($AzureFilesEndpoint)\$FileShareName\$FolderName\server\server-dirs" 
        }
        else {
            $ConfigStoreCloudStorageConnectionString = "NAMESPACE=$($Namespace)$($EndpointSuffix);DefaultEndpointsProtocol=https;AccountName=$AccountName"
            $ConfigStoreCloudStorageConnectionSecret = "AccountKey=$($StorageAccountCredential.GetNetworkCredential().Password)"
        }
    }

	Node localhost
	{
		LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $true
		}
		
		if($OSDiskSize -gt 0) 
        {
            ArcGIS_Disk OSDiskSize
            {
                DriveLetter = ($env:SystemDrive -replace ":" )
                SizeInGB    = $OSDiskSize
            }
		}
			
		if($EnableDataDisk -ieq 'true')
        {
            ArcGIS_xDisk DataDisk
            {
                DiskNumber  =  2
                DriveLetter = 'F'
            }
        }

		$RemoteFederationDependsOn = @() 
		$IsGeoEventServer = ($ServerRole -and ($ServerRole -ieq 'GeoEventServer'))
		$HasValidServiceCredential = ($ServiceCredential -and ($ServiceCredential.GetNetworkCredential().Password -ine 'Placeholder'))
		if($HasValidServiceCredential) 
        {
			if(-Not($IsServiceCredentialDomainAccount)){
				User ArcGIS_RunAsAccount
				{
					UserName				= $ServiceCredential.UserName
					Password				= $ServiceCredential
					FullName				= 'ArcGIS Service Account'
					Ensure					= 'Present'
					PasswordChangeRequired  = $false
					PasswordNeverExpires	= $true
				}
			}

			ArcGIS_WindowsService ArcGIS_for_Server_Service
			{
				Name            = 'ArcGIS Server'
				Credential      = $ServiceCredential
				StartupType     = 'Automatic'
				State           = 'Running' 
				DependsOn       = if(-Not($IsServiceCredentialDomainAccount)){ @('[User]ArcGIS_RunAsAccount')}else{ @()} 
			}

			ArcGIS_Service_Account Server_Service_Account
			{
				Name            = 'ArcGIS Server'
				RunAsAccount    = $ServiceCredential
				IsDomainAccount = $IsServiceCredentialDomainAccount
				Ensure          = 'Present'
				DependsOn       = if(-Not($IsServiceCredentialDomainAccount)){ @('[User]ArcGIS_RunAsAccount','[ArcGIS_WindowsService]ArcGIS_for_Server_Service')}else{ @('[ArcGIS_WindowsService]ArcGIS_for_Server_Service')} 
			}
        
			$ServerDependsOn = @('[ArcGIS_Service_Account]Server_Service_Account', '[ArcGIS_xFirewall]Server_FirewallRules')  
			if($ServerLicenseFileName) 
			{
				ArcGIS_License ServerLicense
				{
					LicenseFilePath = (Join-Path $(Get-Location).Path $ServerLicenseFileName)
					Ensure          = 'Present'
					Component       = 'Server'
				} 
				$ServerDependsOn += '[ArcGIS_License]ServerLicense'
			}
		
			if($AzureFilesEndpoint -and $StorageAccountCredential -and ($UseAzureFiles -ieq 'True')) 
			{
				  $filesStorageAccountName = $AzureFilesEndpoint.Substring(0, $AzureFilesEndpoint.IndexOf('.'))
				  $storageAccountKey       = $StorageAccountCredential.GetNetworkCredential().Password
              
				  Script PersistStorageCredentials
				  {
					  TestScript = { 
										$result = cmdkey "/list:$using:AzureFilesEndpoint"
										$result | ForEach-Object{Write-verbose -Message "cmdkey: $_" -Verbose}
										if($result -like '*none*')
										{
											return $false
										}
										return $true
									}
					  SetScript = { $result = cmdkey "/add:$using:AzureFilesEndpoint" "/user:$using:filesStorageAccountName" "/pass:$using:storageAccountKey" 
									$result | ForEach-Object{Write-verbose -Message "cmdkey: $_" -Verbose}
								  }
					  GetScript            = { return @{} }                  
					  DependsOn            = @('[ArcGIS_Service_Account]Server_Service_Account')
					  PsDscRunAsCredential = $ServiceCredential # This is critical, cmdkey must run as the service account to persist property
				  }
				  $ServerDependsOn += '[Script]PersistStorageCredentials'
			}
			
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
			$ServerDependsOn += '[ArcGIS_xFirewall]Server_FirewallRules'

			if($ServerRole -ieq 'GeoAnalyticsServer') 
			{  
				ArcGIS_xFirewall GeoAnalytics_InboundFirewallRules
				{
						Name                  = "ArcGISGeoAnalyticsInboundFirewallRules" 
						DisplayName           = "ArcGIS GeoAnalytics" 
						DisplayGroup          = "ArcGIS GeoAnalytics" 
						Ensure                = 'Present' 
						Access                = "Allow" 
						State                 = "Enabled" 
						Profile               = ("Domain","Private","Public")
						LocalPort             = ("12181","12182","12190","7077")	# Spark and Zookeeper
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
						LocalPort             = ("12181","12182","12190","7077")	# Spark and Zookeeper
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
				$ServerDependsOn += @('[ArcGIS_xFirewall]GeoAnalyticsCompute_OutboundFirewallRules','[ArcGIS_xFirewall]GeoAnalyticsCompute_InboundFirewallRules','[ArcGIS_xFirewall]GeoAnalytics_InboundFirewallRules','[ArcGIS_xFirewall]GeoAnalytics_OutboundFirewallRules')
			}

			if($IsMultiMachineServer) 
			{
				ArcGIS_xFirewall Server_FirewallRules_Internal
				{
					Name                  = "ArcGISServerInternal"
					DisplayName           = "ArcGIS for Server Internal RMI"
					DisplayGroup          = "ArcGIS for Server"
					Ensure                = 'Present'
					Access                = "Allow"
					State                 = "Enabled"
					Profile               = ("Domain","Private","Public")
					LocalPort             = ("4000-4004")
					Protocol              = "TCP"
				}
				$ServerDependsOn += '[ArcGIS_xFirewall]Server_FirewallRules_Internal'				
			}
				
			foreach($ServiceToStop in @('Portal for ArcGIS', 'ArcGIS Data Store', 'ArcGIS Notebook Server', 'ArcGIS Mission Server'))
			{
				if(Get-Service $ServiceToStop -ErrorAction Ignore) 
			    {
				    Service "$($ServiceToStop.Replace(' ','_'))_Service"
					{
						Name			= $ServiceToStop
						Credential		= $ServiceCredential
						StartupType		= 'Manual'
						State			= 'Stopped'
						DependsOn       = if(-Not($IsServiceCredentialDomainAccount)){ @('[User]ArcGIS_RunAsAccount')}else{ @()} 
					}
				}
			}			
			
			if($IsGeoEventServer) 
			{
				WindowsFeature websockets
				{
					Name  = 'Web-WebSockets'
					Ensure = 'Present'
				}

				ArcGIS_xFirewall GeoEvent_FirewallRules_External_Port
				{
					Name                  = "ArcGISGeoEventFirewallRulesClusterExternal" 
					DisplayName           = "ArcGIS GeoEvent Extension Cluster External" 
					DisplayGroup          = "ArcGIS GeoEvent Extension" 
					Ensure                = 'Present' 
					Access                = "Allow" 
					State                 = "Enabled" 
					Profile               = ("Domain","Private","Public")
					LocalPort             = ("6143")
					Protocol              = "TCP" 
				}
				$ServerDependsOn += @('[ArcGIS_xFirewall]GeoEvent_FirewallRules_External_Port')

				if($IsMultiMachineServer) 
				{
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
					}

					ArcGIS_xFirewall GeoEvent_FirewallRules_MultiMachine
					{
							Name                  = "ArcGISGeoEventFirewallRulesCluster" 
							DisplayName           = "ArcGIS GeoEvent Extension Cluster" 
							DisplayGroup          = "ArcGIS GeoEvent Extension" 
							Ensure                = 'Present' 
							Access                = "Allow" 
							State                 = "Enabled" 
							Profile               = ("Domain","Private","Public")
							LocalPort             = ("12181","12182","12190","27271","27272","27273","4181","4182","4190","9191","9192","9193","9194","5565","5575")										
							Protocol              = "TCP" 
					}

					ArcGIS_xFirewall GeoEvent_FirewallRules_MultiMachine_OutBound
					{
							Name                  = "ArcGISGeoEventFirewallRulesClusterOutbound" 
							DisplayName           = "ArcGIS GeoEvent Extension Cluster Outbound" 
							DisplayGroup          = "ArcGIS GeoEvent Extension" 
							Ensure                = 'Present' 
							Access                = "Allow" 
							State                 = "Enabled" 
							Profile               = ("Domain","Private","Public")
							RemotePort            = ("12181","12182","12190","27271","27272","27273","4181","4182","4190","9191","9192","9193","9194","9220","9320","5565","5575")										
							Protocol              = "TCP" 
							Direction             = "Outbound"    
					}
					$ServerDependsOn += @('[ArcGIS_xFirewall]GeoEvent_FirewallRules_MultiMachine_OutBound','[ArcGIS_xFirewall]GeoEvent_FirewallRules_MultiMachine','[ArcGIS_xFirewall]GeoEventService_Firewall')
				}
				
				$DependsOnGeoevent = if(-Not($IsServiceCredentialDomainAccount)){ @('[User]ArcGIS_RunAsAccount','[ArcGIS_Server]Server')}else{ @('[ArcGIS_Server]Server')} 
				if(-Not($IsServiceCredentialDomainAccount)){
					ArcGIS_Service_Account GeoEvent_RunAs_Account
					{
						Name		 = 'ArcGISGeoEvent'
						RunAsAccount = $ServiceCredential
						IsDomainAccount = $IsServiceCredentialDomainAccount
						Ensure       = 'Present'
						DependsOn    = $DependsOnGeoevent
						DataDir      = '$env:ProgramData\Esri\GeoEvent'
					}  
					$DependsOnGeoevent += '[ArcGIS_Service_Account]GeoEvent_RunAs_Account'
				}

				ArcGIS_WindowsService ArcGIS_GeoEvent_Service
				{
					Name		= 'ArcGISGeoEvent'
					Credential  = $ServiceCredential
					StartupType = if($IsGeoEventServer) { 'Automatic' } else { 'Manual' }
					State		= if($IsGeoEventServer) { 'Running' } else { 'Stopped' }
					DependsOn   = $DependsOnGeoevent
				}
				$DependsOnGeoevent += '[ArcGIS_WindowsService]ArcGIS_GeoEvent_Service'

				if(Get-Service 'ArcGISGeoEventGateway' -ErrorAction Ignore) 
				{
					ArcGIS_WindowsService ArcGIS_GeoEventGateway_Service
					{
						Name		= 'ArcGISGeoEventGateway'
						Credential  = $ServiceCredential
						StartupType = if($IsGeoEventServer) { 'Automatic' } else { 'Manual' }
						State		= if($IsGeoEventServer) { 'Running' } else { 'Stopped' }
						DependsOn   = $DependsOnGeoevent
					}
					$DependsOnGeoevent += '[ArcGIS_WindowsService]ArcGIS_GeoEventGateway_Service'
				}

				ArcGIS_GeoEvent ArcGIS_GeoEvent
				{
					Name	                  = 'ArcGIS GeoEvent'
					Ensure	                  = 'Present'
					SiteAdministrator         = $SiteAdministratorCredential
					WebSocketContextUrl       = "wss://$($ExternalDNSHostName)/arcgis"
					DependsOn       		  = $DependsOnGeoevent
				}
			}

			ArcGIS_LogHarvester ServerLogHarvester
            {
                ComponentType = "Server"
                EnableLogHarvesterPlugin = if($EnableLogHarvesterPlugin -ieq 'true'){$true}else{$false}
				Version = "10.9.1"
                LogFormat = "csv"
                DependsOn = $ServerDependsOn
            }

            $ServerDependsOn += '[ArcGIS_LogHarvester]ServerLogHarvester'

			ArcGIS_Server Server
			{
				Ensure                                  = 'Present'
				SiteAdministrator                       = $SiteAdministratorCredential
				ConfigurationStoreLocation              = $ConfigStoreLocation
				DependsOn                               = $ServerDependsOn
				ServerDirectoriesRootLocation           = $ServerDirsLocation
				Join                                    = $Join
				PeerServerHostName                      = $ServerHostName
				LogLevel                                = if($IsDebugMode) { 'DEBUG' } else { 'WARNING' }
				SingleClusterMode                       = $true
				ConfigStoreCloudStorageConnectionString = $ConfigStoreCloudStorageConnectionString
				ConfigStoreCloudStorageConnectionSecret = $ConfigStoreCloudStorageConnectionSecret
			}
			$RemoteFederationDependsOn += @('[ArcGIS_Server]Server') 
		}

		if($SSLCertificateFileName -and $SSLCertificatePassword -and ($SSLCertificatePassword.GetNetworkCredential().Password -ine 'Placeholder'))
		{
			if(-not($IsGeoEventServer)) # In geoevent case, no need to install SSL certificate on web server
			{
				ArcGIS_Server_TLS Server_TLS
				{
					Ensure                     = 'Present'
					SiteName                   = 'arcgis'
					SiteAdministrator          = $SiteAdministratorCredential                         
					CName                      = $ExternalDNSHostName 
					CertificateFileLocation    = (Join-Path $(Get-Location).Path $SSLCertificateFileName)
					CertificatePassword        = $SSLCertificatePassword
					EnableSSL                  = -not($Join)
					DependsOn                  = if($HasValidServiceCredential) { @('[ArcGIS_Server]Server') } else { $null }
				}
			}
			else 
			{
				ArcGIS_IIS_TLS IISHTTPS
				{
					WebSiteId               = 1
					Ensure                  = 'Present'
					ExternalDNSName         = $ExternalDNSHostName                        
					CertificateFileLocation = (Join-Path $(Get-Location).Path $SSLCertificateFileName)
					CertificatePassword     = if($SSLCertificatePassword -and ($SSLCertificatePassword.GetNetworkCredential().Password -ine 'Placeholder')) { $SSLCertificatePassword } else { $null }
					DependsOn				= if($HasValidServiceCredential) { @('[ArcGIS_GeoEvent]ArcGIS_GeoEvent') } else { $null }
				}
                        
				ArcGIS_ReverseProxy_ARR WebProxy
				{
					Ensure                      = 'Present'
					ServerSiteName              = 'arcgis'
					PortalSiteName              = 'arcgis'
					ServerHostNames             = ($ServerMachineNames -split ',')
					PortalHostNames             = $null
					ExternalDNSName             = $ExternalDNSHostName
					PortalAdministrator         = $SiteAdministratorCredential
					SiteAdministrator           = $SiteAdministratorCredential
					ServerEndPoint              = $env:ComputerName
					PortalEndPoint              = $null
					EnableFailedRequestTracking = $IsDebugMode
					EnableGeoEventEndpoints     = $true
					DependsOn                   = @('[ArcGIS_IIS_TLS]IISHTTPS')						
				} 
				$RemoteFederationDependsOn += @('[ArcGIS_IIS_TLS]IISHTTPS')	
			}
		} 

		if($CloudStores -and $CloudStores.stores -and $CloudStores.stores.Count -gt 0) 
		{
            $DataStoreItems = @()
            foreach($cloudStore in $CloudStores.stores) 
			{
                $DataStorePath = $cloudStore.ContainerName
                if($cloudStore.FolderPath) {
                    $DataStorePath += "/$($cloudStore.FolderPath)"
                }
                $DataStoreItems += @{
                    Name = $cloudStore.Name
                    DataStoreType = 'CloudStore'
                    DataStorePath = $DataStorePath
                    DataStoreConnectionString = "DefaultEndpointsProtocol=https;AccountName=$($cloudStore.AccountName);AccountKey=$($cloudStore.AccountKey)"
                    DataStoreEndpoint = $cloudStore.AccountEndpoint
                }
                if($cloudStore.StoreType -ieq 'Raster') {
                    $DataStoreItems += @{
                        Name = ('Raster ' + $cloudStore.Name).Replace(' ', '_') # Replace spaces with underscores (not allowed for Cloud Stores and Raster Stores)
                        DataStoreType = 'RasterStore'
                        DataStorePath = "/cloudStores/$($cloudStore.Name)"                  
                    }
                }elseif($cloudStore.StoreType -ieq 'GeoAnalyticsBigDataFileShare'){
                    $DataStoreItems += @{
                        Name = ('Big Data File Share for ' + $cloudStore.Name)
                        DataStoreType = 'BigDataFileShare'
                        DataStorePath = "/bigDataFileShares/$($cloudStore.Name)"    
                        DataStoreEndpoint = "/cloudStores/$($cloudStore.Name)"              
                    }
                }
            }

            foreach($dataStoreItem in $DataStoreItems)
            {
                $depends = @()
                if(($dataStoreItem.DataStoreType -ieq 'Folder') -or ($dataStoreItem.DataStoreType -ieq 'BigDataFileShare')) 
                {
                    if($dataStoreItem.DataStorePath -and $dataStoreItem.DataStoreEndpoint -and $dataStoreItem.DataStorePath.IndexOf(':') -gt 0) # Not a cloud store, but a local path
                    {                        
                        $FolderDsc = "Folder-$($dataStoreItem.Name)"
                        $depends += "[File]$FolderDsc"
                        File $FolderDsc
                        {
                            Type			= 'Directory'
                            DestinationPath = $dataStoreItem.DataStorePath
                            Ensure			= 'Present'
                        }

                        if($dataStoreItem.DataStoreEndpoint -and $dataStoreItem.DataStoreType -ieq 'BigDataFileShare')
                        {
                            $FileShareDSC = "Folder-$($dataStoreItem.Name)"
                            $depends += "[ArcGIS_xSmbShare]$FileShareDSC"
                            ArcGIS_xSmbShare $FileShareDSC 
					        { 
						        Ensure		= 'Present' 
						        Name		= $dataStoreItem.DataStoreEndpoint.Substring($dataStoreItem.DataStoreEndpoint.LastIndexOf('\')+1)
						        Path		= $dataStoreItem.DataStorePath
						        FullAccess	= $DataStoreItemsFullControlAccessAccounts                          
						        DependsOn	= @("[File]$FolderDsc")          
					        }
                        }
                    }
                }
            
                ArcGIS_DataStoreItem $dataStoreItem.Name
                {
                    Name						= $dataStoreItem.Name
                    SiteAdministrator			= $SiteAdministratorCredential 
                    DataStoreType				= $dataStoreItem.DataStoreType
                    DataStoreConnectionString	= $dataStoreItem.DataStoreConnectionString
                    DataStoreEndpoint			= $dataStoreItem.DataStoreEndpoint
                    DataStorePath				= $dataStoreItem.DataStorePath
                    Ensure						= 'Present'
                    DependsOn					= $depends
				}   
				$RemoteFederationDependsOn += @("[ArcGIS_DataStoreItem]$($dataStoreItem.Name)")	
            }      
		}
		
		if(($DatabaseOption -ine 'None') -and $DatabaseServerHostName -and $DatabaseName -and $DatabaseServerAdministratorCredential -and $DatabaseUserCredential)
        {
            ArcGIS_EGDB RegisterEGDB
            {
                DatabaseServer              = $DatabaseServerHostName
                DatabaseName                = $DatabaseName
                ServerSiteAdministrator     = $SiteAdministratorCredential
                DatabaseServerAdministrator = $DatabaseServerAdministratorCredential
                DatabaseUser                = $DatabaseUserCredential
                IsManaged                   = ($IsManaged -ieq 'True')
                EnableGeodatabase           = ($EnableGeodatabase -ieq 'True')
                DatabaseType                = $DatabaseOption
                Ensure                      = 'Present'
                DependsOn                   = if($HasValidServiceCredential) { @('[ArcGIS_Server]Server') } else { $null }
            }
        }

        if(($FederateSite -ieq 'true') -and $PortalSiteAdministratorCredential -and $FederationEndPointHostName -and -not($IsAddingServersOrRegisterEGDB -ieq 'True')) 
        {
			if($LastServerHostName -ieq $env:ComputerName) # Federate on the last server node, since request might hit other non initialized nodes behind the load balancer
			{
				ArcGIS_Federation Federate
				{
					PortalHostName = $FederationEndPointHostName
					PortalPort =  443
					PortalContext = 'portal'
					ServiceUrlHostName = $ExternalDNSHostName
					ServiceUrlContext = 'arcgis'
					ServiceUrlPort = 443
					ServerSiteAdminUrlHostName = $ExternalDNSHostName
					ServerSiteAdminUrlPort = 443
					ServerSiteAdminUrlContext ='arcgis'
					Ensure = "Present"
					RemoteSiteAdministrator = $PortalSiteAdministratorCredential
					SiteAdministrator = $SiteAdministratorCredential
					ServerRole = 'FEDERATED_SERVER'
					ServerFunctions = $ServerFunctions
					DependsOn = $RemoteFederationDependsOn
				}
			}
        }

		# Import TLS certificates from web (reverse) proxy machines on the hosting server
		if($WebProxyMachineNamesOnHostingServer -and $WebProxyMachineNamesOnHostingServer.Length -gt 0 -and $PortalSiteAdministratorCredential)
		{
			$MachineNames = $WebProxyMachineNamesOnHostingServer -split ','
			foreach($MachineName in $MachineNames) 
			{
				ArcGIS_TLSCertificateImport "$($MachineName)-WebProxyTLSImport"
                {
                    HostName			= $MachineName
                    Ensure				= 'Present'
                    ApplicationPath		= '/arcgis/' # TODO non default context
                    HttpsPort			= 443
                    StoreLocation		= 'LocalMachine'
                    StoreName			= 'Root'
                    SiteAdministrator	= $PortalSiteAdministratorCredential
                }
			}
		}

		# Import TLS certificates from portal machines on the hosting server
		if($PortalMachineNamesOnHostingServer -and $PortalMachineNamesOnHostingServer.Length -gt 0 -and $PortalSiteAdministratorCredential)
		{
			$MachineNames = $PortalMachineNamesOnHostingServer -split ','
			foreach($MachineName in $MachineNames) 
			{
				ArcGIS_TLSCertificateImport "$($MachineName)-PortalTLSImport"
                {
                    HostName			= $MachineName
                    Ensure				= 'Present'
                    ApplicationPath		= '/arcgis/portaladmin/' 
                    HttpsPort			= 7443
                    StoreLocation		= 'LocalMachine'
                    StoreName			= 'Root'
                    SiteAdministrator	= $PortalSiteAdministratorCredential
                }
			}
		}

		# Import TLS certificates from GIS on the hosting server
		if($GisServerMachineNamesOnHostingServer -and $GisServerMachineNamesOnHostingServer.Length -gt 0 -and $PortalSiteAdministratorCredential)
		{
			$MachineNames = $GisServerMachineNamesOnHostingServer -split ','
			foreach($MachineName in $MachineNames) 
			{
				ArcGIS_TLSCertificateImport "$($MachineName)-ServerTLSImport"
                {
                    HostName			= $MachineName
                    Ensure				= 'Present'
                    ApplicationPath		= '/arcgis/admin/' 
                    HttpsPort			= 6443
                    StoreLocation		= 'LocalMachine'
                    StoreName			= 'Root'
                    SiteAdministrator	= $PortalSiteAdministratorCredential
                }
			}
		}
	}
}
