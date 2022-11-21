Configuration GISServerSingleTierConfiguration
{
	param(
		[Parameter(Mandatory=$false)]
        [System.String]
        $Version = '11.0'
		
		,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $ServiceCredential

        ,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount
        
        ,[Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $SiteAdministratorCredential

		,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $MachineAdministratorCredential

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
		$PortalSiteAdministratorCredential

		,[Parameter(Mandatory=$false)]
        [System.String]
        $IsAddingServersOrRegisterEGDB
		
		,[Parameter(Mandatory=$false)]
        [System.String]
		$Context

		,[Parameter(Mandatory=$false)]
        [System.String]
		$PortalContext = 'portal'

		,[Parameter(Mandatory=$false)]
        [System.String]
		$GeoeventContext

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
        [System.String]
        $PublicKeySSLCertificateFileUrl

		,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $ServerInternalCertificatePassword 
	
        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServerLicenseFileUrl

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServerMachineNames

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServerFunctions

		,[Parameter(Mandatory=$false)]
        [System.String]
        $ServerRole

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ExternalDNSHostName

		,[Parameter(Mandatory=$false)]
        [System.String]
        $PrivateDNSHostName
        
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
	Import-DscResource -Name ArcGIS_ServerSettings
	Import-DscResource -Name ArcGIS_Federation
    Import-DSCResource -Name ArcGIS_EGDB
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_xSmbShare
	Import-DscResource -Name ArcGIS_xDisk  
	Import-DscResource -Name ArcGIS_Disk  
	Import-DscResource -Name ArcGIS_DataStoreItem
	Import-DscResource -Name ArcGIS_TLSCertificateImport
	Import-DscResource -Name ArcGIS_GeoEvent	
    Import-DscResource -Name ArcGIS_LogHarvester
	
    ##
    ## Download license files
    ##
	$ServerHostName = ($ServerMachineNames -split ',') | Select-Object -First 1
	$FileShareHostName = $ServerHostName
	$ServerCertificateFileName  = 'SSLCertificateForServer.pfx'
	$ServerCertificateLocalFilePath =  (Join-Path $env:TEMP $ServerCertificateFileName)
	$ServerCertificateFileLocation = "\\$($FileShareHostName)\$FileShareName\Certs\$ServerCertificateFileName"

    if($ServerLicenseFileUrl) {
        $ServerLicenseFileName = Get-FileNameFromUrl $ServerLicenseFileUrl
        Invoke-WebRequest -OutFile $ServerLicenseFileName -Uri $ServerLicenseFileUrl -UseBasicParsing -ErrorAction Ignore
	}   
	
	if($PublicKeySSLCertificateFileUrl){
		$PublicKeySSLCertificateFileName = Get-FileNameFromUrl $PublicKeySSLCertificateFileUrl
		Invoke-WebRequest -OutFile $PublicKeySSLCertificateFileName -Uri $PublicKeySSLCertificateFileUrl -UseBasicParsing -ErrorAction Ignore
	}

    $ipaddress = (Resolve-DnsName -Name $FileShareHostName -Type A -ErrorAction Ignore | Select-Object -First 1).IPAddress    
    if(-not($ipaddress)) { $ipaddress = $FileShareHostName }
    $FileShareRootPath = "\\$ipaddress\$FileShareName"
    $FolderName = $ExternalDNSHostName.Substring(0, $ExternalDNSHostName.IndexOf('.')).ToLower()
    $ConfigStoreLocation  = "\\$($FileShareHostName)\$FileShareName\$FolderName\$($Context)\config-store"
    $ServerDirsLocation   = "\\$($FileShareHostName)\$FileShareName\$FolderName\$($Context)\server-dirs" 
    $Join = ($env:ComputerName -ine $ServerHostName)
	$IsDebugMode = $DebugMode -ieq 'true'
    $IsMultiMachineServer = (($ServerMachineNames -split ',').Length -gt 1)
	$FileShareLocalPath = (Join-Path $env:SystemDrive $FileShareName)  

	$ServerFunctionsArray = ($ServerFunctions -split ',')

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
            $ConfigStoreLocation  = "\\$($AzureFilesEndpoint)\$FileShareName\$FolderName\$($Context)\config-store"
            $ServerDirsLocation   = "\\$($AzureFilesEndpoint)\$FileShareName\$FolderName\$($Context)\server-dirs" 
        }
        else {
            $ConfigStoreCloudStorageConnectionString = "NAMESPACE=$($Namespace)$($Context)$($EndpointSuffix);DefaultEndpointsProtocol=https;AccountName=$AccountName"
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
		$HasValidServiceCredential = ($ServiceCredential -and ($ServiceCredential.GetNetworkCredential().Password -ine 'Placeholder'))
        if($HasValidServiceCredential) 
        {
			if(-Not($ServiceCredentialIsDomainAccount)){
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

			if(-not($Join)) { 
				File FileShareLocationPath
				{
					Type						= 'Directory'
					DestinationPath				= $FileShareLocalPath
					Ensure						= 'Present'
					Force						= $true
				}   
				
				$Accounts = @('NT AUTHORITY\SYSTEM')
				if($ServiceCredential) { $Accounts += $ServiceCredential.GetNetworkCredential().UserName }
				if($MachineAdministratorCredential -and ($MachineAdministratorCredential.GetNetworkCredential().UserName -ine 'Placeholder') -and ($MachineAdministratorCredential.GetNetworkCredential().UserName -ine $ServiceCredential.GetNetworkCredential().UserName)) { $Accounts += $MachineAdministratorCredential.GetNetworkCredential().UserName }
				ArcGIS_xSmbShare FileShare 
				{ 
					Ensure						= 'Present' 
					Name						= $FileShareName
					Path						= $FileShareLocalPath
					FullAccess					= $Accounts
					DependsOn					= if(-Not($ServiceCredentialIsDomainAccount)){ @('[User]ArcGIS_RunAsAccount','[File]FileShareLocationPath')}else{ @('[File]FileShareLocationPath')}     
				}
			}

            ArcGIS_WindowsService ArcGIS_for_Server_Service
            {
                Name            = 'ArcGIS Server'
                Credential      = $ServiceCredential
                StartupType     = 'Automatic'
                State           = 'Running' 
                DependsOn       = if(-Not($ServiceCredentialIsDomainAccount)){ @('[User]ArcGIS_RunAsAccount')}else{ @()}
            }

            ArcGIS_Service_Account Server_Service_Account
		    {
			    Name            = 'ArcGIS Server'
				RunAsAccount    = $ServiceCredential
				IsDomainAccount = $ServiceCredentialIsDomainAccount
			    Ensure          = 'Present'
				DependsOn       = if(-Not($ServiceCredentialIsDomainAccount)){ @('[User]ArcGIS_RunAsAccount','[ArcGIS_WindowsService]ArcGIS_for_Server_Service')}else{ @('[ArcGIS_WindowsService]ArcGIS_for_Server_Service')} 
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
		        
            if(-not($Join)) { 
                $ServerDependsOn += '[ArcGIS_xSmbShare]FileShare'                
            } 
        
            if($AzureFilesEndpoint -and $StorageAccountCredential -and ($UseAzureFiles -ieq 'True')) 
            {
                  $filesStorageAccountName = $AzureFilesEndpoint.Substring(0, $AzureFilesEndpoint.IndexOf('.'))
                  $storageAccountKey       = $StorageAccountCredential.GetNetworkCredential().Password
              
                  Script PersistStorageCredentials
                  {
                      TestScript = { 
                                        $result = cmdkey "/list:$using:AzureFilesEndpoint"
                                        $result | ForEach-Object {Write-verbose -Message "cmdkey: $_" -Verbose}
                                        if($result -like '*none*')
                                        {
                                            return $false
                                        }
                                        return $true
                                    }
                      SetScript = { $result = cmdkey "/add:$using:AzureFilesEndpoint" "/user:$using:filesStorageAccountName" "/pass:$using:storageAccountKey" 
						            $result | ForEach-Object {Write-verbose -Message "cmdkey: $_" -Verbose}
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

			if($ServerFunctionsArray -iContains 'GeoAnalyticsServer') 
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
						DependsOn		= if(-Not($ServiceCredentialIsDomainAccount)){ @('[User]ArcGIS_RunAsAccount')}else{ @()}
					}
				}
			}
			
			$IsGeoEventServer = ($ServerRole -ieq 'GeoEventServer')
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

				$DependsOnGeoevent = @('[User]ArcGIS_RunAsAccount','[ArcGIS_ServerSettings]ServerSettings')
				
				if(-Not($ServiceCredentialIsDomainAccount)){
					ArcGIS_Service_Account GeoEvent_RunAs_Account
					{
						Name		 = 'ArcGISGeoEvent'
						RunAsAccount = $ServiceCredential
						IsDomainAccount = $ServiceCredentialIsDomainAccount
						Ensure       = 'Present'
						DependsOn    = $DependsOnGeoevent 
						DataDir      = '$env:ProgramData\Esri\GeoEvent'
					}
					$DependsOnGeoevent += '[ArcGIS_Service_Account]GeoEvent_RunAs_Account'
				}	
				
				if(Get-Service 'ArcGISGeoEvent' -ErrorAction Ignore) 
				{
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
						WebSocketContextUrl       = "wss://$($ExternalDNSHostName)/$($GeoeventContext)wss"
						Version					  = $Version
						DependsOn				  = $DependsOnGeoevent
					}	
				}
			}
			
			ArcGIS_LogHarvester ServerLogHarvester
            {
                ComponentType = "Server"
                EnableLogHarvesterPlugin = if($EnableLogHarvesterPlugin -ieq 'true'){$true}else{$false}
				Version = $Version
                LogFormat = "csv"
                DependsOn = $ServerDependsOn
            }

            $ServerDependsOn += '[ArcGIS_LogHarvester]ServerLogHarvester'

			ArcGIS_Server Server
		    {
				Version                                 = $Version
			    Ensure                                  = 'Present'
			    SiteAdministrator                       = $SiteAdministratorCredential
			    ConfigurationStoreLocation              = $ConfigStoreLocation
			    DependsOn                               = $ServerDependsOn
			    ServerDirectoriesRootLocation           = $ServerDirsLocation
			    Join                                    = $Join
			    PeerServerHostName                      = $ServerHostName
			    LogLevel                                = if($IsDebugMode) { 'DEBUG' } else { 'WARNING' }
			    ConfigStoreCloudStorageConnectionString = $ConfigStoreCloudStorageConnectionString
				ConfigStoreCloudStorageConnectionSecret = $ConfigStoreCloudStorageConnectionSecret
		    }
			$RemoteFederationDependsOn += @('[ArcGIS_Server]Server') 
        
			
			Script CopyCertificateFileToLocalMachine
			{
				GetScript = {
					$null
				}
				SetScript = {    
					Write-Verbose "Copying from $using:ServerCertificateFileLocation to $using:ServerCertificateLocalFilePath"      
					$PsDrive = New-PsDrive -Name X -Root $using:FileShareRootPath -PSProvider FileSystem                 
					Write-Verbose "Mapped Drive $($PsDrive.Name) to $using:FileShareRootPath"              
					Copy-Item -Path $using:ServerCertificateFileLocation -Destination $using:ServerCertificateLocalFilePath -Force  
					if($PsDrive) {
						Write-Verbose "Removing Temporary Mapped Drive $($PsDrive.Name)"
						Remove-PsDrive -Name $PsDrive.Name -Force       
					}       
				}
				TestScript = {   
					$false
				}
				DependsOn             = if(-Not($ServiceCredentialIsDomainAccount)){@('[User]ArcGIS_RunAsAccount')}else{@()}
				PsDscRunAsCredential  = $ServiceCredential # Copy as arcgis account which has access to this share
			}
			
			ArcGIS_Server_TLS Server_TLS
			{
				ServerHostName             = $env:ComputerName
				SiteAdministrator          = $SiteAdministratorCredential                         
				WebServerCertificateAlias  = "ApplicationGateway"
				CertificateFileLocation    = $ServerCertificateLocalFilePath
				CertificatePassword        = if($ServerInternalCertificatePassword -and ($ServerInternalCertificatePassword.GetNetworkCredential().Password -ine 'Placeholder')) { $ServerInternalCertificatePassword } else { $null }
				ServerType                 = $ServerFunctions
				DependsOn                  = @('[ArcGIS_Server]Server','[Script]CopyCertificateFileToLocalMachine') 
				SslRootOrIntermediate	   = if($PublicKeySSLCertificateFileName){ [string]::Concat('[{"Alias":"AppGW-ExternalDNSCerCert","Path":"', (Join-Path $(Get-Location).Path $PublicKeySSLCertificateFileName).Replace('\', '\\'),'"}]') }else{$null}
			}

			$RemoteFederationDependsOn += @('[ArcGIS_Server_TLS]Server_TLS') 

			if($ServerFunctionsArray -iContains 'WorkflowManagerServer') 
			{
				WindowsFeature websockets
				{
					Name  = 'Web-WebSockets'
					Ensure = 'Present'
				}

				$DependsOnWfm = @('[User]ArcGIS_RunAsAccount','[ArcGIS_Server_TLS]Server_TLS')

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
				}
				$DependsOnWfm += "[ArcGIS_xFirewall]WorkflowManagerServer_FirewallRules"
	
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
					}
					$DependsOnWfm += "[ArcGIS_xFirewall]WorkflowManagerServer_FirewallRules_MultiMachine_OutBound"
	
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
					}
					$DependsOnWfm += "[ArcGIS_xFirewall]WorkflowManagerServer_FirewallRules_MultiMachine_InBound"
				}

				ArcGIS_Service_Account WorkflowManager_RunAs_Account
				{
					Name = 'WorkflowManager'
					RunAsAccount = $ServiceCredential
					Ensure =  "Present"
					DependsOn = $DependsOnWfm
					DataDir = "$env:ProgramData\Esri\workflowmanager"
					IsDomainAccount = $ServiceCredentialIsDomainAccount
					SetStartupToAutomatic = $True
				}
				$DependsOnWfm += "[ArcGIS_Service_Account]WorkflowManager_RunAs_Account"
				$RemoteFederationDependsOn += "[ArcGIS_Service_Account]WorkflowManager_RunAs_Account"

				if(Get-Service 'WorkflowManager' -ErrorAction Ignore) 
				{
					ArcGIS_WindowsService ArcGIS_WorkflowManager_Service
					{
						Name		= 'WorkflowManager'
						Credential  = $ServiceCredential
						StartupType = 'Automatic'
						State		= 'Running'
						DependsOn   = $DependsOnWfm
					}
					$RemoteFederationDependsOn += '[ArcGIS_WindowsService]ArcGIS_WorkflowManager_Service'
				}
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
		
		if($HasValidServiceCredential -and ($ServerHostName -ieq $env:ComputerName)) # Federate on first instance, health check prevents request hitting other non initialized nodes behind the load balancer
		{
			ArcGIS_ServerSettings ServerSettings
			{
				ServerContext       = $Context
				ServerHostName      = $ServerHostName
				ExternalDNSName     = $ExternalDNSHostName
				SiteAdministrator   = $SiteAdministratorCredential
				DependsOn 			= $RemoteFederationDependsOn
			}
			$RemoteFederationDependsOn += @("[ArcGIS_ServerSettings]ServerSettings")	

			if(($FederateSite -ieq 'true') -and $PortalSiteAdministratorCredential -and -not($IsAddingServersOrRegisterEGDB -ieq 'True')) 
			{
				if($ServerFunctionsArray -iContains 'WorkflowManagerServer'){
					$ServerFunctionsArray[[array]::IndexOf($ServerFunctionsArray, "WorkflowManagerServer")] = "WorkflowManager"
				}

				ArcGIS_Federation Federate
				{
					PortalHostName = $ExternalDNSHostName
					PortalPort = 443
					PortalContext = $PortalContext
					ServiceUrlHostName = $ExternalDNSHostName
					ServiceUrlContext = $Context
					ServiceUrlPort = 443
					ServerSiteAdminUrlHostName = if($PrivateDNSHostName){ $PrivateDNSHostName }else{ $ExternalDNSHostName }
					ServerSiteAdminUrlPort = 443
					ServerSiteAdminUrlContext = $Context
					Ensure = "Present"
					RemoteSiteAdministrator = $PortalSiteAdministratorCredential
					SiteAdministrator = $SiteAdministratorCredential
					ServerRole = 'FEDERATED_SERVER'
					ServerFunctions = ($ServerFunctionsArray -join ",")
					DependsOn = $RemoteFederationDependsOn
				}		
			}
        }

		if($HasValidServiceCredential -and $ServerFunctionsArray -iContains 'WorkflowManagerServer'){
			Script RestartWorkflowManagerService
			{
				GetScript = {
					$null
				}
				SetScript = {
					if($using:IsMultiMachineServer){
						$WFMConfPath = (Join-Path $env:ProgramData "\esri\workflowmanager\WorkflowManager.conf")
						if(Test-Path $WFMConfPath) {
							@('play.modules.disabled', 'play.modules.enabled')| ForEach-Object {
								$PropertyName = $_
								$PropertyValue = $null
								Get-Content $WFMConfPath | ForEach-Object {
									if($_ -and $_.TrimStart().StartsWith($PropertyName)){
										$Splits = $_.Split('=')
										if($Splits.Length -gt 1){
											$PropertyValue = $Splits[1].Trim()
										}
									}
								}
								if($null -eq $PropertyValue){
									if($PropertyName -ieq "play.modules.disabled"){
										Add-Content $WFMConfPath "`nplay.modules.disabled += `"esri.workflow.utils.inject.LocalDataProvider`""
									}
									if($PropertyName -ieq "play.modules.enabled"){
										Add-Content $WFMConfPath "`nplay.modules.enabled += `"esri.workflow.utils.inject.DistributedDataProvider`""
									}
								}
							}
						}else{
							Write-Verbose "[WARNING] Workflow Manager Configuration file not found. Please update this file manually."
						}
					}
					$ServiceName = "WorkflowManager"
					Write-Verbose "Restarting $ServiceName Service in 30 Seconds"
					Start-Sleep -Seconds 30
					Write-Verbose "Stop Service '$ServiceName'"
					Stop-Service -Name $ServiceName -Force 
					Write-Verbose 'Stopping the service' 
					Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Stopped'
					Write-Verbose 'Stopped the service'
					Write-Verbose "Restarting Service '$ServiceName' to pick up property change"
					Start-Service $ServiceName 
					Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Running'
					Write-Verbose "Restarted Service '$ServiceName'"
				}
				TestScript = {
					$false
				}
				DependsOn = $RemoteFederationDependsOn
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
					ServerType          = $ServerFunctions
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
					ServerType          = $ServerFunctions
                }
			}
		}
	}
}
