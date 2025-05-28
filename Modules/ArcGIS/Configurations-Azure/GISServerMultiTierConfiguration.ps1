﻿Configuration GISServerMultiTierConfiguration
{
	param(
		[Parameter(Mandatory=$false)]
        [System.String]
        $Version = "11.5"
		
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
        [System.String]
        $CloudStorageAuthenticationType = "AccessKey"

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $StorageAccountCredential

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $StorageAccountUserAssignedIdentityClientId

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $StorageAccountServicePrincipalTenantId

		,[Parameter(Mandatory=$false)]
        [System.String]
        $StorageAccountServicePrincipalAuthorityHost

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $StorageAccountServicePrincipalCredential
		
		,[Parameter(Mandatory=$false)]
        [System.String]
        $PublicKeySSLCertificateFileUrl

		,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $ServerInternalCertificatePassword

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
        [System.Boolean]
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
    Import-DscResource -Name ArcGIS_DataStoreItemServer
	Import-DscResource -Name ArcGIS_TLSCertificateImport
	Import-DscResource -Name ArcGIS_Disk
	Import-DscResource -Name ArcGIS_LogHarvester
	Import-DscResource -Name ArcGIS_Install
	Import-DscResource -Name ArcGIS_AzureSetupDownloadsFolderManager
    
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
    $ServerCertificateLocalFilePath =  (Join-Path $env:TEMP $ServerCertificateFileName)

    $FolderName = $ExternalDNSHostName.Substring(0, $ExternalDNSHostName.IndexOf('.')).ToLower()
	$ServerCertificateFileLocation = "$($FileSharePath)\Certs\$ServerCertificateFileName"
	if($UseExistingFileShare)
    {
		$ServerCertificateFileLocation = "$($FileSharePath)\$($FolderName)\$($Context)\$ServerCertificateFileName"
    }

    ##
    ## Download license files
    ##
	if($ServerLicenseFileUrl) {
        $ServerLicenseFileName = Get-FileNameFromUrl $ServerLicenseFileUrl
        Invoke-WebRequest -OutFile $ServerLicenseFileName -Uri $ServerLicenseFileUrl -UseBasicParsing -ErrorAction Ignore
	}    
	
	if($PublicKeySSLCertificateFileUrl){
		$PublicKeySSLCertificateFileName = Get-FileNameFromUrl $PublicKeySSLCertificateFileUrl
		Invoke-WebRequest -OutFile $PublicKeySSLCertificateFileName -Uri $PublicKeySSLCertificateFileUrl -UseBasicParsing -ErrorAction Ignore
	}

	$ConfigStoreLocation  = "$($FileSharePath)\$FolderName\$($Context)\config-store"
    $ServerDirsLocation   = "$($FileSharePath)\$FolderName\$($Context)\server-dirs" 
	
	$ServerHostName = ($ServerMachineNames -split ',') | Select-Object -First 1
	$Join = ($env:ComputerName -ine $ServerHostName)
	$IsMultiMachineServer = (($ServerMachineNames -split ',').Length -gt 1)
	$ServerFunctionsArray = ($ServerFunctions -split ',')
	
    if($UseCloudStorage -and $StorageAccountCredential) 
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
        if($UseAzureFiles) {
            $AzureFilesEndpoint = $StorageAccountCredential.UserName.Replace('.blob.','.file.')         
            $FileShareName = $FileShareName.ToLower() # Azure file shares need to be lower case                      
            $ConfigStoreLocation  = "\\$($AzureFilesEndpoint)\$FileShareName\$FolderName\$($Context)\config-store"
            $ServerDirsLocation   = "\\$($AzureFilesEndpoint)\$FileShareName\$FolderName\$($Context)\server-dirs" 
        }
        else {
			if(-not($Join)){
				$ConfigStoreCloudStorageConnectionString = "NAMESPACE=$($Namespace)$($Context)$($EndpointSuffix);DefaultEndpointsProtocol=https;AccountName=$($AccountName)"
				if($CloudStorageAuthenticationType -ieq 'ServicePrincipal'){
					$ClientSecret = $StorageAccountServicePrincipalCredential.GetNetworkCredential().Password
					$ConfigStoreCloudStorageConnectionString += ";CredentialType=ServicePrincipal;TenantId=$($StorageAccountServicePrincipalTenantId);ClientId=$($StorageAccountServicePrincipalCredential.Username)"
					if(-not([string]::IsNullOrEmpty($StorageAccountServicePrincipalAuthorityHost))){
						$ConfigStoreCloudStorageConnectionString += ";AuthorityHost=$($StorageAccountServicePrincipalAuthorityHost)" 
					}
					$ConfigStoreCloudStorageConnectionSecret = "ClientSecret=$($ClientSecret)"
				}elseif($CloudStorageAuthenticationType -ieq 'UserAssignedIdentity'){
					$ConfigStoreCloudStorageConnectionString += ";CredentialType=UserAssignedIdentity;ManagedIdentityClientId=$($StorageAccountUserAssignedIdentityClientId)"
					$ConfigStoreCloudStorageConnectionSecret = ""

				}elseif($CloudStorageAuthenticationType -ieq 'SASToken'){
					$ConfigStoreCloudStorageConnectionString += ";CredentialType=SASToken"
					$ConfigStoreCloudStorageConnectionSecret = "SASToken=$($StorageAccountCredential.GetNetworkCredential().Password)"

				}else{
					$ConfigStoreCloudStorageConnectionSecret = "AccountKey=$($StorageAccountCredential.GetNetworkCredential().Password)"
				}
			}
        }
    }

	$ServicesToStop = @('Portal for ArcGIS', 'ArcGIS Data Store', 'ArcGIS Notebook Server', 'ArcGIS Mission Server', 'ArcGISGeoEvent', 'ArcGISGeoEventGateway')
	if(-not($ServerFunctionsArray -iContains 'WorkflowManagerServer')){
		$ServicesToStop += 'WorkflowManager'
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

		ArcGIS_AzureSetupDownloadsFolderManager CleanupDownloadsFolder{
            Version = $Version
            OperationType = 'CleanupDownloadsFolder'
            ComponentNames = "Server"
            ServerRole = $ServerRole
        }


		$RemoteFederationDependsOn = @() 
		$HasValidServiceCredential = ($ServiceCredential -and ($ServiceCredential.GetNetworkCredential().Password -ine 'Placeholder'))
		if($HasValidServiceCredential) 
        {
			if(-not($IsUpdatingCertificates)){
				$ServerDependsOn = @()

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
					$ServerDependsOn += '[User]ArcGIS_RunAsAccount'
				}

				$ServerDependsOn = @()
				
				if($ServerRole -ieq "WorkflowManagerServer"){
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
				
				ArcGIS_LogHarvester ServerLogHarvester
				{
					ComponentType = "Server"
					EnableLogHarvesterPlugin = if($EnableLogHarvesterPlugin){$true}else{$false}
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
					ConfigurationStoreLocation              = if(-not($Join)){ $ConfigStoreLocation }else{ $null }
					DependsOn                               = $ServerDependsOn
					ServerDirectoriesRootLocation           = $ServerDirsLocation
					Join                                    = $Join
					PeerServerHostName                      = $ServerHostName
					LogLevel                                = if($DebugMode) { 'DEBUG' } else { 'WARNING' }
					ConfigStoreCloudStorageConnectionString = if(-not($Join)){ $ConfigStoreCloudStorageConnectionString }else{ $null }
					ConfigStoreCloudStorageConnectionSecret = if(-not($Join)){ $ConfigStoreCloudStorageConnectionSecret }else{ $null }
				}
				$RemoteFederationDependsOn += @('[ArcGIS_Server]Server') 
			}
			
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
				DependsOn             = if(-Not($ServiceCredentialIsDomainAccount) -and -not($IsUpdatingCertificates)){@('[User]ArcGIS_RunAsAccount')}else{@()}
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
				SslRootOrIntermediate	   = if($PublicKeySSLCertificateFileName){ [string]::Concat('[{"Alias":"AppGW-ExternalDNSCerCert","Path":"', (Join-Path $(Get-Location).Path $PublicKeySSLCertificateFileName).Replace('\', '\\'),'"}]') }else{$null}
				DependsOn                  = if(-not($IsUpdatingCertificates)){ @('[ArcGIS_Server]Server','[Script]CopyCertificateFileToLocalMachine') }else{ @('[Script]CopyCertificateFileToLocalMachine')}
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
							LocalPort            = $WfmPorts
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

					if($IsMultiMachineServer){
						Script UpdateWorkflowManagerMultiMachineSettings
						{
							GetScript = {
								$null
							}
							SetScript = {
								$WFMConfPath = (Join-Path $env:ProgramData "\esri\workflowmanager\WorkflowManager.conf")
								if(Test-Path $WFMConfPath) {
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
					$AzureConnectionObject["ServicePrincipalClientId"] = $cloudStore.ServicePrincipal.ClientId
					$ConnectionPassword = (ConvertTo-SecureString $AzureStorageObject.ServicePrincipal.ClientSecret -AsPlainText -Force)
					if($cloudStore.ServicePrincipal.AuthorityHost -and -not([string]::IsNullOrEmpty($cloudStore.ServicePrincipal.ContainsKey("AuthorityHost")))){
						$AzureConnectionObject["ServicePrincipalAuthorityHost"] = $cloudStore.ServicePrincipal.AuthorityHost
					}
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
					ServerHostName = $ServerHostName #TODO
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
        
		if($HasValidServiceCredential -and ($ServerHostName -ieq $env:ComputerName) -and -not($IsUpdatingCertificates)) # Federate on first instance, health check prevents request hitting other non initialized nodes behind the load balancer
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
			if(($FederateSite -ieq 'true') -and $PortalSiteAdministratorCredential -and -not($IsAddingServersOrRegisterEGDB -ieq 'True') ) 
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
				$RemoteFederationDependsOn += @("[ArcGIS_Federation]Federate")	

				if($ServerFunctionsArray -iContains 'WorkflowManager'){
					Script RestartWorkflowManagerService
					{
						GetScript = {
							$null
						}
						SetScript = {
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
                }
			}
		}
	}
}
