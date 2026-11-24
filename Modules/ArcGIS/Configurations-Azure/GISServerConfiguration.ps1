Configuration GISServerConfiguration
{
	param(
		[Parameter(Mandatory=$false)]
        [System.String]
        $Version = "12.2"
		
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
        [System.Boolean]
        $UseCloudStorage 

        ,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $UseAzureFiles 

		,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $IsCloudNative

        ,[Parameter(Mandatory=$false)]
        [System.String]
		[ValidateSet('AccessKey','ServicePrincipal','UserAssignedIdentity')]
        $CloudStorageAuthenticationType = "AccessKey"

		,[Parameter(Mandatory=$false)]
        [System.String]
        $UserAssignedIdentityClientId

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServicePrincipalTenantId

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServicePrincipalAuthorityHost

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $ServicePrincipalCredential

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $StorageAccountCredential

		,[Parameter(Mandatory=$false)]
        [System.String]
        $AzureCloudNativeStorageAccountAccountEndpointUrl

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $AzureCloudNativeStorageAccountContainerName

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $AzureCloudNativeStorageAccountRootDir

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $AzureCloudNativeCosmosDBAccountCredential

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $AzureCloudNativeCosmosDBAccountEndpointUrl

		,[Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeCosmosDBAccountDatabaseId

        ,[Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeCosmosDBAccountSubscriptionId

        ,[Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeCosmosDBAccountResourceGroupName

        ,[Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("Direct","Gateway")]
        $AzureCloudNativeCosmosDBAccountConnectionMode = "Gateway"

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $AzureCloudNativeServiceBusNamespaceCredential

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $AzureCloudNativeServiceBusNamespaceEndpointUrl

		,[Parameter(Mandatory=$false)]
        [System.String]
        $PublicKeySSLCertificateFileName
		
		,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $ServerInternalCertificatePassword 
	
        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServerLicenseFileName

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
        $ExternalDNSHostName

		,[Parameter(Mandatory=$false)]
        [System.String]
        $PrivateDNSHostName
        
		,[Parameter(Mandatory=$true)]
        [System.Boolean]
        $UseExistingFileShare

		,[Parameter(Mandatory=$true)]
        [System.Boolean]
        $UseFileShareMachineOfBaseDeployment

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $FileShareMachineName
        
        ,[Parameter(Mandatory=$false)]
        [System.String]
        $FileShareName = 'fileshare'

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $FileSharePath

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
		[System.Boolean]
		$EnableGeodatabase = $True

		,[parameter(Mandatory = $false)]
		[System.Boolean]
		$RegisterEGDBAsRasterStore = $False

        ,[Parameter(Mandatory=$false)]
        $CloudStores

		,[Parameter(Mandatory=$false)]
        $GisServerMachineNamesOnHostingServer

		,[Parameter(Mandatory=$false)]
		$PortalMachineNamesOnHostingServer
		
		,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $EnableLogHarvesterPlugin

		,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $IsUpdatingCertificates = $False

		,[Parameter(Mandatory=$false)]
        [System.String]
        $ServerDeepLearningLibrariesFileName

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServerCoordinateSystemsDataFileName

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServerRasterDataFileName

		,[Parameter(Mandatory=$false)]
        [System.String]
        $ServerRasterDataVersion = "1.0.1014"

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServerDJIFileName

		,[Parameter(Mandatory=$True)]
        [System.Management.Automation.PSCredential]
        $DeploymentArtifactCredentials

		,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $DebugMode		
	)
	

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
	Import-DscResource -Name ArcGIS_License
	Import-DscResource -Name ArcGIS_Server
    Import-DscResource -Name ArcGIS_Server_TLS
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -Name ArcGIS_ServerSettings
	Import-DscResource -Name ArcGIS_Federation
    Import-DSCResource -Name ArcGIS_EGDB
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_xSmbShare
	Import-DscResource -Name ArcGIS_Disk  
	Import-DscResource -Name ArcGIS_DataStoreItemServer
	Import-DscResource -Name ArcGIS_TLSCertificateImport
	Import-DscResource -Name ArcGIS_GeoEvent	
    Import-DscResource -Name ArcGIS_LogHarvester
	Import-DscResource -Name ArcGIS_Server_RegisterDirectories
	Import-DscResource -Name ArcGIS_Install
	Import-DscResource -Name ArcGIS_AzureSetupsManager
	Import-DscResource -Name ArcGIS_HostNameSettings
	Import-DscResource -Name ArcGIS_RemoteFile
	Import-DscResource -Name ArcGIS_WindowsService
	
	$FileShareRootPath = $FileSharePath
	if(-not($UseExistingFileShare)) { 
        $FileSharePath = "\\$($FileShareMachineName)\$($FileShareName)"
        
        $ipaddress = (Resolve-DnsName -Name $FileShareMachineName -Type A -ErrorAction Ignore | Select-Object -First 1).IPAddress    
        if(-not($ipaddress)) { $ipaddress = $FileShareMachineName }
        $FileShareRootPath = "\\$ipaddress\$FileShareName"
    }else{
		if($UseFileShareMachineOfBaseDeployment){
			$FileSharePath = "\\$($FileShareMachineName)\$($FileShareName)"
		}
	}
	
	$ServerCertificateFileName  = 'SSLCertificateForServer.pfx'
	$LocalCertificatePath = "$($env:SystemDrive)\\ArcGIS\\Certs"
	if(-not(Test-Path $LocalCertificatePath)){
        New-Item -Path $LocalCertificatePath -ItemType directory -ErrorAction Stop | Out-Null
    }

    $ServerCertificateLocalFilePath =  (Join-Path $LocalCertificatePath $ServerCertificateFileName)

    $FolderName = $ExternalDNSHostName.Substring(0, $ExternalDNSHostName.IndexOf('.')).ToLower()
	$HasValidServiceCredential = ($ServiceCredential -and ($ServiceCredential.GetNetworkCredential().Password -ine 'Placeholder'))
    

	$ServerHostName = ($ServerMachineNames -split ',') | Select-Object -First 1
	$Join = ($env:ComputerName -ine $ServerHostName)
	
    $IsMultiMachineServer = (($ServerMachineNames -split ',').Length -gt 1)
	$ServerFunctionsArray = ($ServerFunctions -split ',')
	
	$ConfigStoreLocation = $null
    $ServerDirsLocation = $null

	$Namespace = $ExternalDNSHostName
	$Pos = $Namespace.IndexOf('.')
	if($Pos -gt 0) { $Namespace = $Namespace.Substring(0, $Pos) }        
	$Namespace = [System.Text.RegularExpressions.Regex]::Replace($Namespace, '[\W]', '') # Sanitize

	if(-not($IsCloudNative)){
		if($UseCloudStorage -and $StorageAccountCredential) 
		{
			if($UseAzureFiles) {
				$AzureFilesEndpoint = $StorageAccountCredential.UserName.Replace('.blob.','.file.')   
				$FileShareName = $FileShareName.ToLower() # Azure file shares need to be lower case       
				$ConfigStoreLocation  = "\\$($AzureFilesEndpoint)\$FileShareName\$FolderName\$($Context)\config-store"
				$ServerDirsLocation   = "\\$($AzureFilesEndpoint)\$FileShareName\$FolderName\$($Context)\server-dirs" 
			}else{
				$ServerDirsLocation   = "$($FileSharePath)\$FolderName\$($Context)\server-dirs" 
			}
		}else{
			$ConfigStoreLocation  = "$($FileSharePath)\$FolderName\$($Context)\config-store"
			$ServerDirsLocation   = "$($FileSharePath)\$FolderName\$($Context)\server-dirs" 
		}
	}

	$ServicesToStop = @('Portal for ArcGIS', 'ArcGIS Data Store', 'ArcGIS Notebook Server', 'ArcGIS Mission Server')
	if(-not($ServerFunctionsArray -iContains 'WorkflowManagerServer')){
		$ServicesToStop += 'WorkflowManager'
	}
	if($ServerRole -ine 'GeoEventServer'){
		$ServicesToStop += @('ArcGISGeoEvent', 'ArcGISGeoEventGateway')
	}

	Node localhost
	{        
		LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $false
		}
		
		ArcGIS_Disk DiskSizeCheck
        {
            HostName = $env:ComputerName
        }    
        
		ArcGIS_AzureSetupsManager CleanupDownloadsFolder{
            Version = $Version
            OperationType = 'CleanupDownloadsFolder'
            ComponentNames = "Server"
            ServerRole = $ServerRole
        }

		$RemoteFederationDependsOn = @()
		if($HasValidServiceCredential) 
        {
			$ServerDependsOn = @()
			if($ServerLicenseFileName) {
                ArcGIS_RemoteFile "ServerLicenceFileDownload"
                {
                    Source = $ServerLicenseFileName
                    Destination = (Join-Path $(Get-Location).Path $ServerLicenseFileName)
                    FileSourceType = "AzureSASUri"
                    Credential = $DeploymentArtifactCredentials
                    Ensure = 'Present'
                }
                $ServerDependsOn += '[ArcGIS_RemoteFile]ServerLicenceFileDownload'
            }

            if($PublicKeySSLCertificateFileName) {
                ArcGIS_RemoteFile "PublicKeySSLCertificateFileDownload"
                {
                    Source = $PublicKeySSLCertificateFileName
                    Destination = (Join-Path $(Get-Location).Path $PublicKeySSLCertificateFileName)
                    FileSourceType = "AzureSASUri"
                    Credential = $DeploymentArtifactCredentials
                    Ensure = 'Present'
                }
                $ServerDependsOn += '[ArcGIS_RemoteFile]PublicKeySSLCertificateFileDownload'
            }

            if($ServerCertificateFileName) {
                ArcGIS_RemoteFile "ServerCertificateFileDownload"
                {
                    Source = "Certs/$($ServerCertificateFileName)"
                    Destination = $ServerCertificateLocalFilePath
                    FileSourceType = "AzureSASUri"
                    Credential = $DeploymentArtifactCredentials
                    Ensure = 'Present'
                }
                $ServerDependsOn += '[ArcGIS_RemoteFile]ServerCertificateFileDownload'
            }

			if(-not($IsUpdatingCertificates)){
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

				if($ServerRole -ieq "GeoEventServer"){
					ArcGIS_Install GeoEventServerInstall
					{
						Name = "GeoEvent"
						Version = $Version
						Path = "$($env:SystemDrive)\\ArcGIS\\Deployment\\Downloads\\GeoEvent\\GeoEvent.exe"
						Extract = $True
						Arguments = "/qn ACCEPTEULA=YES"
						ServiceCredential = $ServiceCredential
						ServiceCredentialIsDomainAccount = $ServiceCredentialIsDomainAccount
						EnableMSILogging = $DebugMode
						Ensure = "Present"
						DependsOn = @('[User]ArcGIS_RunAsAccount')
					}
					$ServerDependsOn += @('[ArcGIS_Install]GeoEventServerInstall')
				}

				if($ServerRole -ieq "RasterAnalytics" -or $ServerRole -ieq "RealityServer") {
					if($ServerDeepLearningLibrariesFileName) {
						$ServerDeepLearningLibrariesDestinationPath = (Join-Path $(Get-Location).Path $ServerDeepLearningLibrariesFileName)

						ArcGIS_RemoteFile "ServerDeepLearningLibrariesFileDownload"
						{
							Source = $ServerDeepLearningLibrariesFileName
							Destination = $ServerDeepLearningLibrariesDestinationPath
							FileSourceType = "AzureSASUri"
							Credential = $DeploymentArtifactCredentials
							Ensure = 'Present'
						}
						
						$IsSelfExtractingInstaller = $True
						$ServerDeepLearningLibrariesInstallPath = $null
						if($ServerDeepLearningLibrariesFileName.EndsWith('zip')){
							$IsSelfExtractingInstaller = $False
							$SetupInstallerFolderPath = (Join-Path $ENV:Temp "ServerDeepLearningLibraries")
							
							Archive "Extract-ServerDeepLearningLibraries"
							{
								Destination = $SetupInstallerFolderPath
								Path = $ServerDeepLearningLibrariesDestinationPath
								Ensure = 'Present'
								DependsOn = "[ArcGIS_RemoteFile]ServerDeepLearningLibrariesFileDownload"
							}
							$ServerDependsOn += '[Archive]Extract-ServerDeepLearningLibraries'
							$ServerDeepLearningLibrariesInstallPath = Join-Path $SetupInstallerFolderPath "setup.exe"
						}else{
							$ServerDeepLearningLibrariesInstallPath = $ServerDeepLearningLibrariesDestinationPath
							$ServerDependsOn += '[ArcGIS_RemoteFile]ServerDeepLearningLibrariesFileDownload'
						}

						ArcGIS_Install "ServerDeepLearningLibrariesInstallExtension"
						{
							Name = "ServerDeepLearningLibraries"
							Version = $Version
							Path = $ServerDeepLearningLibrariesInstallPath
							Extract = $IsSelfExtractingInstaller
							Arguments = "/qn ACCEPTEULA=YES"
							Ensure = "Present"
							DependsOn = $ServerDependsOn
						}
						$ServerDependsOn += "[ArcGIS_Install]ServerDeepLearningLibrariesInstallExtension"
					}
				}

				if($ServerRole -ieq "RealityServer"){
					ArcGIS_Install RealityServerInstall
					{
						Name = "RealityServer"
						Version = $Version
						Path = "$($env:SystemDrive)\\ArcGIS\\Deployment\\Downloads\\RealityServer\\RealityServer.exe"
						Extract = $True
						Arguments = "/qn ACCEPTEULA=YES"
						ServiceCredential = $ServiceCredential
						ServiceCredentialIsDomainAccount = $ServiceCredentialIsDomainAccount
						EnableMSILogging = $DebugMode
						Ensure = "Present"
						DependsOn = @('[User]ArcGIS_RunAsAccount')
					}
					$ServerDependsOn += @('[ArcGIS_Install]RealityServerInstall')
					
					if($ServerCoordinateSystemsDataFileName) {
						$ServerCoordinateSystemsDataDestinationPath = (Join-Path $(Get-Location).Path $ServerCoordinateSystemsDataFileName)
						ArcGIS_RemoteFile "ServerCoordinateSystemsDataDownload"
						{
							Source = $ServerCoordinateSystemsDataFileName
							Destination = $ServerCoordinateSystemsDataDestinationPath
							FileSourceType = "AzureSASUri"
							Credential = $DeploymentArtifactCredentials
							Ensure = 'Present'
						}
						$ServerDependsOn += '[ArcGIS_RemoteFile]ServerCoordinateSystemsDataDownload'
						ArcGIS_Install "ServerCoordinateSystemsDataInstallExtension"
						{
							Name = "ServerCoordinateSystemsData"
							Version = $Version
							Path = $ServerCoordinateSystemsDataDestinationPath
							Extract = $True 
							Arguments = "/qn ACCEPTEULA=YES"
							Ensure = "Present"
							DependsOn = $ServerDependsOn
						}
						$ServerDependsOn += "[ArcGIS_Install]ServerCoordinateSystemsDataInstallExtension"
					}

					if($ServerRasterDataFileName) {
						$ServerRasterDataDestinationPath = (Join-Path $(Get-Location).Path $ServerRasterDataFileName)
						ArcGIS_RemoteFile "ServerRasterDataDownload"
						{
							Source = $ServerRasterDataFileName
							Destination = $ServerRasterDataDestinationPath
							FileSourceType = "AzureSASUri"
							Credential = $DeploymentArtifactCredentials
							Ensure = 'Present'
						}
						$ServerDependsOn += '[ArcGIS_RemoteFile]ServerRasterDataDownload'
						ArcGIS_Install "ServerRasterDataInstallExtension"
						{
							Name = "ServerRasterData"
							Version = $ServerRasterDataVersion
							Path = $ServerRasterDataDestinationPath
							Extract = $True 
							Arguments = "/qn ACCEPTEULA=YES"
							Ensure = "Present"
							DependsOn = $ServerDependsOn
						}
						$ServerDependsOn += "[ArcGIS_Install]ServerRasterDataInstallExtension"
					}

					if($ServerDJIFileName) {
						$ServerDJIDestinationPath = (Join-Path $(Get-Location).Path $ServerDJIFileName)
						ArcGIS_RemoteFile "ServerDJIDownload"
						{
							Source = $ServerDJIFileName
							Destination = $ServerDJIDestinationPath
							FileSourceType = "AzureSASUri"
							Credential = $DeploymentArtifactCredentials
							Ensure = 'Present'
						}
						$ServerDependsOn += '[ArcGIS_RemoteFile]ServerDJIDownload'
						ArcGIS_Install "ServerDJIInstallExtension"
						{
							Name = "ServerDJI"
							Version = $Version
							Path = $ServerDJIDestinationPath
							Extract = $True 
							Arguments = "/qn ACCEPTEULA=YES"
							Ensure = "Present"
							DependsOn = $ServerDependsOn
						}
						$ServerDependsOn += "[ArcGIS_Install]ServerDJIInstallExtension"
					}
				}

				if($ServerFunctionsArray -iContains 'WorkflowManagerServer'){
					ArcGIS_Install WorkflowManagerServerInstall
					{
						Name = "WorkflowManagerServer"
						Version = $Version
						Path = "$($env:SystemDrive)\\ArcGIS\\Deployment\\Downloads\\WorkflowManagerServer\\WorkflowManagerServer.exe"
						Extract = $True
						Arguments = "/qn ACCEPTEULA=YES"
						ServiceCredential = $ServiceCredential
						ServiceCredentialIsDomainAccount =  $ServiceCredentialIsDomainAccount
						EnableMSILogging = $DebugMode
						Ensure = "Present"
						DependsOn = @('[User]ArcGIS_RunAsAccount')
					}
					$ServerDependsOn += @('[ArcGIS_Install]WorkflowManagerServerInstall')
				}

				# TODO - create folders in existing file share
				ArcGIS_WindowsService ArcGIS_for_Server_Service
				{
					Name            = 'ArcGIS Server'
					Credential      = $ServiceCredential
					StartupType     = 'Automatic'
					State           = 'Running' 
					DependsOn       = $ServerDependsOn
				}
				$ServerDependsOn += '[ArcGIS_WindowsService]ArcGIS_for_Server_Service'

				ArcGIS_Service_Account Server_Service_Account
				{
					Name            = 'ArcGIS Server'
					RunAsAccount    = $ServiceCredential
					IsDomainAccount = $ServiceCredentialIsDomainAccount
					Ensure          = 'Present'
					DependsOn       = $ServerDependsOn
				}	
				$ServerDependsOn += '[ArcGIS_Service_Account]Server_Service_Account'

				if($ServerLicenseFileName) 
				{
					ArcGIS_License ServerLicense
					{
						LicenseFilePath = (Join-Path $(Get-Location).Path $ServerLicenseFileName)
						Ensure          = 'Present'
						Component       = 'Server'
						Version 		= $Version
					} 
					$ServerDependsOn += '[ArcGIS_License]ServerLicense'
				}					
			
				if($UseAzureFiles -and $AzureFilesEndpoint -and $StorageAccountCredential) 
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

				foreach($ServiceToStop in $ServicesToStop)
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
					
					ArcGIS_WindowsService ArcGIS_GeoEvent_Service
					{
						Name		= 'ArcGISGeoEvent'
						Credential  = $ServiceCredential
						StartupType = if($IsGeoEventServer) { 'Automatic' } else { 'Manual' }
						State		= if($IsGeoEventServer) { 'Running' } else { 'Stopped' }
						DependsOn   = $DependsOnGeoevent
					}
					$DependsOnGeoevent += '[ArcGIS_WindowsService]ArcGIS_GeoEvent_Service'

					ArcGIS_WindowsService ArcGIS_GeoEventGateway_Service
					{
						Name		= 'ArcGISGeoEventGateway'
						Credential  = $ServiceCredential
						StartupType = if($IsGeoEventServer) { 'Automatic' } else { 'Manual' }
						State		= if($IsGeoEventServer) { 'Running' } else { 'Stopped' }
						DependsOn   = $DependsOnGeoevent
					}
					$DependsOnGeoevent += '[ArcGIS_WindowsService]ArcGIS_GeoEventGateway_Service'
				
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
				
				ArcGIS_LogHarvester ServerLogHarvester
				{
					ComponentType = "Server"
					EnableLogHarvesterPlugin = if($EnableLogHarvesterPlugin){$true}else{$false}
					Version = $Version
					LogFormat = "csv"
					DependsOn = $ServerDependsOn
				}
				$ServerDependsOn += '[ArcGIS_LogHarvester]ServerLogHarvester'

				ArcGIS_HostNameSettings ServerHostNameSettings{
					ComponentName   = "Server"
					Version         = $Version
					DependsOn       = $ServerDependsOn
				}
				$ServerDependsOn += '[ArcGIS_HostNameSettings]ServerHostNameSettings'

				$CloudProvider = "None"
				$CloudNamespace = $null
				$AzureCloudAuthenticationType = "None"
				$AzureCloudStorageAccountCredential = $null
				$AzureCloudServicePrincipalCredential = $null
				$AzureCloudServicePrincipalTenantId = $null
				$AzureCloudServicePrincipalAuthorityHost = $null
				$AzureCloudUserAssignedIdentityClientId = $null
				$AzureCloudNativeStorageAccountCredential = $null
				
				$AzureCloudNativeServiceBusNamespaceCredential
				if($UseCloudStorage -and -not($UseAzureFiles)){
					$CloudProvider = "Azure"
					$CloudNamespace = "$($Namespace)$($ServerContext)"
					$AzureCloudAuthenticationType = $CloudStorageAuthenticationType
					
					if(-not($IsCloudNative)){
						$AzureCloudStorageAccountCredential = $StorageAccountCredential
					}

					if($CloudStorageAuthenticationType -ieq "ServicePrincipal"){
						$AzureCloudServicePrincipalCredential = $ServicePrincipalCredential
						$AzureCloudServicePrincipalTenantId = $ServicePrincipalTenantId
						$AzureCloudServicePrincipalAuthorityHost = $ServicePrincipalAuthorityHost
					}

					if($CloudStorageAuthenticationType -ieq "UserAssignedIdentity"){
						$AzureCloudUserAssignedIdentityClientId = $UserAssignedIdentityClientId
					}

					if($IsCloudNative){
						if($CloudStorageAuthenticationType -ieq "AccessKey"){
							$AzureCloudNativeStorageAccountCredential = $StorageAccountCredential
						}
					}
				}

				ArcGIS_Server Server
				{
					Version                                 		 = $Version
					Ensure                                  		 = 'Present'
					SiteAdministrator                       		 = $SiteAdministratorCredential
					ConfigurationStoreLocation              		 = if(-not($Join)){ $ConfigStoreLocation }else{ $null }
					DependsOn                               		 = $ServerDependsOn
					ServerDirectoriesRootLocation           		 = $ServerDirsLocation
					Join                                    		 = $Join
					PeerServerHostName                      		 = $ServerHostName
					LogLevel                                		 = if($DebugMode) { 'DEBUG' } else { 'WARNING' }
					CloudProvider                                    = $CloudProvider
					IsCloudNativeServer                              = $IsCloudNative
					CloudNamespace                                   = $CloudNamespace
					AzureCloudAuthenticationType                     = $AzureCloudAuthenticationType
					AzureCloudStorageAccountCredential               = $AzureCloudStorageAccountCredential
					AzureCloudServicePrincipalCredential             = $AzureCloudServicePrincipalCredential
					AzureCloudServicePrincipalTenantId               = $AzureCloudServicePrincipalTenantId
					AzureCloudServicePrincipalAuthorityHost          = $AzureCloudServicePrincipalAuthorityHost
					AzureCloudUserAssignedIdentityClientId           = $AzureCloudUserAssignedIdentityClientId
					AzureCloudNativeStorageAccountCredential         = $AzureCloudNativeStorageAccountCredential
					AzureCloudNativeStorageAccountAccountEndpointUrl = $AzureCloudNativeStorageAccountAccountEndpointUrl
					AzureCloudNativeStorageAccountContainerName      = $AzureCloudNativeStorageAccountContainerName
					AzureCloudNativeStorageAccountRootDir            = $AzureCloudNativeStorageAccountRootDir
					AzureCloudNativeCosmosDBAccountCredential        = $AzureCloudNativeCosmosDBAccountCredential
					AzureCloudNativeCosmosDBAccountEndpointUrl       = $AzureCloudNativeCosmosDBAccountEndpointUrl
					AzureCloudNativeCosmosDBAccountDatabaseId        = $AzureCloudNativeCosmosDBAccountDatabaseId
					AzureCloudNativeCosmosDBAccountSubscriptionId    = $AzureCloudNativeCosmosDBAccountSubscriptionId
					AzureCloudNativeCosmosDBAccountResourceGroupName = $AzureCloudNativeCosmosDBAccountResourceGroupName
					AzureCloudNativeCosmosDBAccountConnectionMode    = $AzureCloudNativeCosmosDBAccountConnectionMode
					AzureCloudNativeServiceBusNamespaceCredential    = $AzureCloudNativeServiceBusNamespaceCredential 
					AzureCloudNativeServiceBusNamespaceEndpointUrl   = $AzureCloudNativeServiceBusNamespaceEndpointUrl
				}
				$RemoteFederationDependsOn += @('[ArcGIS_Server]Server') 
			}
			
			ArcGIS_Server_TLS Server_TLS
			{
				ServerHostName             = $env:ComputerName
				SiteAdministrator          = $SiteAdministratorCredential                         
				WebServerCertificateAlias  = "ApplicationGateway"
				CertificateFileLocation    = $ServerCertificateLocalFilePath
				CertificatePassword        = if($ServerInternalCertificatePassword -and ($ServerInternalCertificatePassword.GetNetworkCredential().Password -ine 'Placeholder')) { $ServerInternalCertificatePassword } else { $null }
				ServerType                 = "Server"
				SslRootOrIntermediate	   = if($PublicKeySSLCertificateFileName){ [string]::Concat('[{"Alias":"AppGW-ExternalDNSCerCert","Path":"', (Join-Path $(Get-Location).Path $PublicKeySSLCertificateFileName).Replace('\', '\\'),'"}]') }else{$null}
				DependsOn                  = if(-not($IsUpdatingCertificates)){ @('[ArcGIS_Server]Server') }else{ @()}
			}

			if(-not($IsUpdatingCertificates)){
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
						$WfmPorts = @("13820", "13830", "13840", "9880","11211")
		
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
							LocalPort             = $WfmPorts
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

					ArcGIS_WindowsService ArcGIS_WorkflowManager_Service
					{
						Name		= 'WorkflowManager'
						Credential  = $ServiceCredential
						StartupType = 'Automatic'
						State		= 'Running'
						DependsOn   = $DependsOnWfm
					}
					$RemoteFederationDependsOn += '[ArcGIS_WindowsService]ArcGIS_WorkflowManager_Service'
					
					if($IsMultiMachineServer){
						Script UpdateWorkflowManagerMultiMachineSettings
						{
							GetScript = {
								@{}
							}
							SetScript = {
								$WFMConfPath = (Join-Path $env:ProgramData "\esri\workflowmanager\WorkflowManager.conf")
								if(Test-Path $WFMConfPath) {
									Stop-ServiceAndWait -ServiceName "WorkflowManager" -ErrorAction Stop
									try {
										$WFMConfContent = @(Get-Content $WFMConfPath -ErrorAction Stop)
										@('play.modules.disabled', 'play.modules.enabled') | ForEach-Object {
											$PropertyName = $_
											$PropertyValue = $null
											$WFMConfContent | ForEach-Object {
												if($_ -and $_.TrimStart().StartsWith($PropertyName)){
													$Splits = $_.Split('=')
													if($Splits.Length -gt 1){
														$PropertyValue = $Splits[1].Trim()
													}
												}
											}
											if($null -eq $PropertyValue){
												if($PropertyName -ieq "play.modules.disabled"){
													Add-Content $WFMConfPath "`nplay.modules.disabled += `"esri.workflow.utils.inject.LocalDataProvider`"" -ErrorAction Stop
												}
												if($PropertyName -ieq "play.modules.enabled"){
													Add-Content $WFMConfPath "`nplay.modules.enabled += `"esri.workflow.utils.inject.DistributedDataProvider`"" -ErrorAction Stop
												}
												}
											}
									}finally{
										Start-ServiceAndWait -ServiceName "WorkflowManager" -ErrorAction Stop
									}
								}else{
									Write-Verbose "[WARNING] Workflow Manager Configuration file not found. Please update this file manually."
								}
							}
							TestScript = {
								$result = $True
								$WFMConfPath = (Join-Path $env:ProgramData "\esri\workflowmanager\WorkflowManager.conf")
								@('play.modules.disabled', 'play.modules.enabled') | ForEach-Object {
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
										$result = $False
									}
								}
								$result
							}
							DependsOn = $RemoteFederationDependsOn
						}
						$RemoteFederationDependsOn += '[Script]UpdateWorkflowManagerMultiMachineSettings'
					}
				}
			}
		}

        if(($DatabaseOption -ine 'None') -and $DatabaseServerHostName -and $DatabaseName -and $DatabaseServerAdministratorCredential -and $DatabaseUserCredential -and ($ServerHostName -ieq $env:ComputerName))
        {
            ArcGIS_EGDB RegisterEGDB
            {
                DatabaseServer              = $DatabaseServerHostName
                DatabaseName                = $DatabaseName
                ServerSiteAdministrator     = $SiteAdministratorCredential
                DatabaseServerAdministrator = $DatabaseServerAdministratorCredential
                DatabaseUser                = $DatabaseUserCredential
                EnableGeodatabase           = $EnableGeodatabase
                DatabaseType                = $DatabaseOption
				IsManaged					= $False
                Ensure                      = 'Present'
                DependsOn                   = if($HasValidServiceCredential) { @('[ArcGIS_Server]Server') } else { $null }
            }

			if($RegisterEGDBAsRasterStore){
				$ConnectionStringObject = @{
					DataStorePath = "/enterpriseDatabases/$($DatabaseServerHostName)_$($DatabaseName)"
				}

				ArcGIS_DataStoreItemServer RasterStore
				{
					Name = "RasterStore-$($DatabaseName.Replace(' ', '_'))"
					ServerHostName = $ServerHostName
					SiteAdministrator = $SiteAdministratorCredential
					DataStoreType = 'RasterStore'
					ConnectionString = (ConvertTo-Json $ConnectionStringObject -Compress -Depth 10)
					Ensure = "Present"
					DependsOn = @("[ArcGIS_EGDB]RegisterEGDB")
				}
			}
        }  

        if($CloudStores -and $CloudStores.stores -and $CloudStores.stores.Count -gt 0 -and ($ServerHostName -ieq $env:ComputerName)) 
		{
            $DataStoreItems = @()
			$CacheDirectories = @()
            foreach($cloudStore in $CloudStores.stores) 
			{
                $AuthType = $cloudStore.AzureStorageAuthenticationType
				$AzureConnectionObject = @{
					AccountName = $cloudStore.AccountName
					AccountEndpoint = $cloudStore.AccountEndpoint
					DefaultEndpointsProtocol = "https"
					OverrideEndpoint = if($cloudStore.OverrideEndpoint){ $cloudStore.OverrideEndpoint }else{ $null }
					ContainerName = $cloudStore.ContainerName
					FolderPath = if($cloudStore.Path){ $cloudStore.Path }else{ $null } 
					AuthenticationType = $AuthType
				}

				$ConnectionPassword = $null
				if($AuthType -ieq "AccessKey"){
					$ConnectionPassword = ConvertTo-SecureString $cloudStore.AccessKey -AsPlainText -Force 
				}elseif($AuthType -ieq "SASToken"){
					$ConnectionPassword = ConvertTo-SecureString $cloudStore.SASToken -AsPlainText -Force 
				}elseif($AuthType -ieq "ServicePrincipal"){
					$AzureConnectionObject["ServicePrincipalTenantId"] = $cloudStore.ServicePrincipal.TenantId
					if($cloudStore.ServicePrincipal.ContainsKey("AuthorityHost") -and -not([string]::IsNullOrEmpty($cloudStore.ServicePrincipal.AuthorityHost))){
						$AzureConnectionObject["ServicePrincipalAuthorityHost"] = $cloudStore.ServicePrincipal.AuthorityHost
					}
					$AzureConnectionObject["ServicePrincipalClientId"] = $cloudStore.ServicePrincipal.ClientId
					$ConnectionPassword = (ConvertTo-SecureString $AzureStorageObject.ServicePrincipal.ClientSecret -AsPlainText -Force)
				}elseif($AuthType -ieq "UserAssignedIdentity"){
					$AzureConnectionObject["UserAssignedIdentityClientId"] = $cloudStore.UserAssignedIdentityClientId
				}
				$ConnectionSecret = $null
				if($null -ne $ConnectionPassword){
					$ConnectionSecret = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( "PlaceHolder", $ConnectionPassword )
				}

				$ConnectionStringObject = @{
					CloudStoreType = "Azure"
					AzureStorage = $AzureConnectionObject
				}
				
				$CloudStoreName = $cloudStore.Name
                $DataStoreItems += @{
                    Name = $CloudStoreName
                    DataStoreType = 'CloudStore'
					ConnectionString = (ConvertTo-Json $ConnectionStringObject -Compress -Depth 10)
					ConnectionSecret = $ConnectionSecret
                }
                if($cloudStore.StoreType -ieq 'Raster') {
					$ConnectionStringObject = @{
						DataStorePath = "/cloudStores/$($CloudStoreName)"   
					}

					$DataStoreItems += @{
						Name = ('Raster ' + $CloudStoreName).Replace(' ', '_') # Replace spaces with underscores (not allowed for Cloud Stores and Raster Stores)
						DataStoreType = 'RasterStore'
						ConnectionString = (ConvertTo-Json $ConnectionStringObject -Compress -Depth 10)
					}
                }elseif($cloudStore.StoreType -ieq 'CacheDirectory'){
					$CacheDirectories += @{
						name = ('Cache Directory ' + $CloudStoreName).Replace(' ', '_')
						physicalPath = "/cloudStores/$($CloudStoreName)"
						directoryType = "CACHE"
					}
				}
            }

            foreach($dataStoreItem in $DataStoreItems)
            {
				ArcGIS_DataStoreItemServer $dataStoreItem.Name
				{
					Name = $dataStoreItem.Name
					ServerHostName = $ServerHostName
					SiteAdministrator = $SiteAdministratorCredential
					DataStoreType = $dataStoreItem.DataStoreType
					ConnectionString = $dataStoreItem.ConnectionString
					ConnectionSecret = $dataStoreItem.ConnectionSecret
					Ensure = "Present"
					DependsOn = $RemoteFederationDependsOn
				}
				$RemoteFederationDependsOn += @("[ArcGIS_DataStoreItemServer]$($dataStoreItem.Name)")				
			}

			if($CacheDirectories.Length -gt 0){
				ArcGIS_Server_RegisterDirectories "RegisterCacheDirectory"
				{ 
					ServerHostName = $ServerHostName
					Ensure = 'Present'
					SiteAdministrator = $SiteAdministratorCredential
					DirectoriesJSON = ($CacheDirectories | ConvertTo-Json)
					DependsOn = $RemoteFederationDependsOn
				}
				$RemoteFederationDependsOn += @("[ArcGIS_Server_RegisterDirectories]RegisterCacheDirectory")		
			}
		}
		

		if($HasValidServiceCredential -and ($ServerHostName -ieq $env:ComputerName) -and -not($IsUpdatingCertificates)) # Federate on first instance, health check prevents request hitting other non initialized nodes behind the load balancer
		{
			ArcGIS_ServerSettings ServerSettings
			{
				ServerType			= "Server"
				ServerHostName      = $ServerHostName
				WebContextURL       = if($ExternalDNSHostName){"https://$($ExternalDNSHostName)/$($Context)"}else{ $null }
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
					PortalSiteAdministrator = $PortalSiteAdministratorCredential
					SiteAdministrator = $SiteAdministratorCredential
					ServerRole = 'FEDERATED_SERVER'
					ServerFunctions = ($ServerFunctionsArray -join ",")
					DependsOn = $RemoteFederationDependsOn
				}
				$RemoteFederationDependsOn += @("[ArcGIS_Federation]Federate")	
				
				if($ServerFunctionsArray -iContains 'WorkflowManager'){
					Script RestartWorkflowManagerService
					{
						GetScript = {
							$null
						}
						SetScript = {
							Restart-ArcGISService -ComponentName "WorkflowManager" -RestartDelay 30
						}
						TestScript = {
							$false
						}
						DependsOn = $RemoteFederationDependsOn
					}
				}
			}
		}

		# Import TLS certificates from portal machines on the hosting server
		if($PortalMachineNamesOnHostingServer -and $PortalMachineNamesOnHostingServer.Length -gt 0 -and $PortalSiteAdministratorCredential -and $PortalSiteAdministratorCredential.UserName -ine "placeholder")
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
					ServerType          = 'Server'
                }
			}
		}

		# Import TLS certificates from GIS on the hosting server
		if($GisServerMachineNamesOnHostingServer -and $GisServerMachineNamesOnHostingServer.Length -gt 0 -and $PortalSiteAdministratorCredential -and $PortalSiteAdministratorCredential.UserName -ine "placeholder")
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
					ServerType          = 'Server'
                }
			}
		}
	}
}
