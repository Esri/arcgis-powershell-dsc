Configuration MissionServerMultiTierConfiguration{
    param(
        [Parameter(Mandatory=$false)]
        [System.String]
        $Version = "12.0"

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
        $Context

        ,[Parameter(Mandatory=$false)]
        [System.String]
		$PortalContext = 'portal'
        
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
        [ValidateSet('AccessKey','ServicePrincipal','UserAssignedIdentity')]
        $CloudStorageAuthenticationType = "AccessKey"

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $UserAssignedIdentityClientId

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServicePrincipalAuthorityHost

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServicePrincipalTenantId

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $ServicePrincipalCredential

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $StorageAccountCredential
        
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

        ,[Parameter(Mandatory=$false)]
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

		,[Parameter(Mandatory=$false)]
        $GisServerMachineNamesOnHostingServer

		,[Parameter(Mandatory=$false)]
		$PortalMachineNamesOnHostingServer

        ,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $IsUpdatingCertificates = $False

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
    Import-DscResource -Name ArcGIS_MissionServer
    Import-DscResource -Name ArcGIS_MissionServerSettings
    Import-DscResource -Name ArcGIS_Server_TLS
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -Name ArcGIS_WindowsService
    Import-DscResource -Name ArcGIS_Federation
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_xSmbShare
	Import-DscResource -Name ArcGIS_Disk  
    Import-DscResource -Name ArcGIS_TLSCertificateImport
    Import-DscResource -Name ArcGIS_Install
    Import-DscResource -Name ArcGIS_AzureSetupDownloadsFolderManager
    Import-DscResource -Name ArcGIS_HostNameSettings

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

    ##
    ## Download license files
    ##
    $HasValidServiceCredential = ($ServiceCredential -and ($ServiceCredential.GetNetworkCredential().Password -ine 'Placeholder'))
    if($HasValidServiceCredential) {
        if($ServerLicenseFileName) {
            $ServerLicenseFileUrl = "$($DeploymentArtifactCredentials.UserName)/$($ServerLicenseFileName)$($DeploymentArtifactCredentials.GetNetworkCredential().Password)"
            Invoke-WebRequest -Verbose:$False -OutFile $ServerLicenseFileName -Uri $ServerLicenseFileUrl -UseBasicParsing -ErrorAction Ignore
        }   
        
        if($PublicKeySSLCertificateFileName){
            $PublicKeySSLCertificateFileUrl = "$($DeploymentArtifactCredentials.UserName)/$($PublicKeySSLCertificateFileName)$($DeploymentArtifactCredentials.GetNetworkCredential().Password)"
            Invoke-WebRequest -Verbose:$False -OutFile $PublicKeySSLCertificateFileName -Uri $PublicKeySSLCertificateFileUrl -UseBasicParsing -ErrorAction Ignore
        }

        if($ServerCertificateFileName){
            $ServerCertificateFileUrl = "$($DeploymentArtifactCredentials.UserName)/Certs/$($ServerCertificateFileName)$($DeploymentArtifactCredentials.GetNetworkCredential().Password)"
            Invoke-WebRequest -Verbose:$False -OutFile $ServerCertificateLocalFilePath -Uri $ServerCertificateFileUrl -UseBasicParsing -ErrorAction Ignore
        }
    }

    $ServerHostName = ($ServerMachineNames -split ',') | Select-Object -First 1

    $Join = ($env:ComputerName -ine $ServerHostName)
	$IsMultiMachineServer = (($ServerMachineNames -split ',').Length -gt 1)
	$LastServerHostName = ($ServerMachineNames -split ',') | Select-Object -Last 1
    
    $ConfigStoreLocation = $null
    $ServerDirsLocation = $null
    if($UseCloudStorage -and $StorageAccountCredential) 
    {
        $Namespace = $ExternalDNSHostName
        $Pos = $Namespace.IndexOf('.')
        if($Pos -gt 0) { $Namespace = $Namespace.Substring(0, $Pos) }        
        $Namespace = [System.Text.RegularExpressions.Regex]::Replace($Namespace, '[\W]', '') # Sanitize
        if($UseAzureFiles) {
            $AzureFilesEndpoint = $StorageAccountCredential.UserName.Replace('.blob.','.file.')   
            $FileShareName = $FileShareName.ToLower() # Azure file shares need to be lower case       
            $ConfigStoreLocation  = "\\$($AzureFilesEndpoint)\$FileShareName\$FolderName\$($Context)\config-store"
            $ServerDirsLocation   = "\\$($AzureFilesEndpoint)\$FileShareName\$FolderName\$($Context)\server-dirs" 
        }else{
            $ServerDirsLocation   = "$($FileSharePath)\$FolderName\$($Context)\server-dirs"
        } 
    }else {
        $ConfigStoreLocation  = "$($FileSharePath)\$FolderName\$($Context)\config-store"
        $ServerDirsLocation   = "$($FileSharePath)\$FolderName\$($Context)\server-dirs" 
    }
    
    Node localhost
	{ 
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $false
        }
         
		$DependsOn = @()
		
		ArcGIS_Disk DiskSizeCheck
        {
            HostName = $env:ComputerName
        }
        
        WindowsFeature websockets
        {
            Name  = 'Web-WebSockets'
            Ensure = 'Present'
        }
        $DependsOn += '[WindowsFeature]websockets'

        ArcGIS_AzureSetupDownloadsFolderManager CleanupDownloadsFolder{
            Version = $Version
            OperationType = 'CleanupDownloadsFolder'
            ComponentNames = "Server"
            ServerRole = "MissionServer"
        }
        
		if($HasValidServiceCredential) 
        {
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
                        DependsOn 				= $DependsOn
                    }
                    $DependsOn += '[User]ArcGIS_RunAsAccount'
                }

                # Install Notebook Server
                ArcGIS_Install MissionServerInstall
                {
                    Name = "MissionServer"
                    Version = $Version
                    Path = "$($env:SystemDrive)\\ArcGIS\\Deployment\\Downloads\\MissionServer\\MissionServer.exe"
                    Extract = $True
                    Arguments = "/qn ACCEPTEULA=YES InstallDir=`"$($env:SystemDrive)\\ArcGIS\\MissionServer`""
                    ServiceCredential = $ServiceCredential
                    ServiceCredentialIsDomainAccount = $ServiceCredentialIsDomainAccount
                    EnableMSILogging = $DebugMode
                    Ensure = "Present"
                    DependsOn = $DependsOn
                }
                $DependsOn += '[ArcGIS_Install]MissionServerInstall'

                ArcGIS_xFirewall MissionServer_FirewallRules
                {
                    Name                  = "ArcGISMissionServer"
                    DisplayName           = "ArcGIS for Mission Server"
                    DisplayGroup          = "ArcGIS for Mission Server"
                    Ensure                = 'Present'
                    Access                = "Allow"
                    State                 = "Enabled"
                    Profile               = ("Domain","Private","Public")
                    LocalPort             = ("20443","20301")
                    Protocol              = "TCP"
                    DependsOn       	   = $DependsOn
                }
                $DependsOn += '[ArcGIS_xFirewall]MissionServer_FirewallRules'

                ArcGIS_WindowsService ArcGIS_for_MissionServer_Service
                {
                    Name            = 'ArcGIS Mission Server'
                    Credential      = $ServiceCredential
                    StartupType     = 'Automatic'
                    State           = 'Running' 
                    DependsOn       = $DependsOn
                }
                $DependsOn += '[ArcGIS_WindowsService]ArcGIS_for_MissionServer_Service'

                ArcGIS_Service_Account MissionServer_Service_Account
                {
                    Name            = 'ArcGIS Mission Server'
                    RunAsAccount    = $ServiceCredential
                    IsDomainAccount = $ServiceCredentialIsDomainAccount
                    Ensure          = 'Present'
                    DependsOn       = $DependsOn
                }
                $DependsOn += '[ArcGIS_Service_Account]MissionServer_Service_Account'

                if($ServerLicenseFileName) 
                {
                    ArcGIS_License ServerLicense
                    {
                        LicenseFilePath = (Join-Path $(Get-Location).Path $ServerLicenseFileName)
                        Ensure          = 'Present'
                        Component       = 'Server'
                        ServerRole      = 'MissionServer'
                        DependsOn       = $DependsOn
                    } 
                    $DependsOn += '[ArcGIS_License]ServerLicense'
                }

                if($UseAzureFiles -and $AzureFilesEndpoint -and $StorageAccountCredential) 
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
                        DependsOn       	   = $DependsOn
                        PsDscRunAsCredential = $ServiceCredential # This is critical, cmdkey must run as the service account to persist property
                    }
                    $DependsOn += '[Script]PersistStorageCredentials'
                }   
                
                foreach($ServiceToStop in @('ArcGIS Server', 'Portal for ArcGIS', 'ArcGIS Data Store', 'ArcGISGeoEvent', 'ArcGISGeoEventGateway', 'ArcGIS Notebook Server', 'WorkflowManager'))
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

                ArcGIS_HostNameSettings MissionServerHostNameSettings{
                    ComponentName   = "MissionServer"
                    Version         = $Version
                    DependsOn       = $DependsOn
                }
                $DependsOn += '[ArcGIS_HostNameSettings]MissionServerHostNameSettings'

                ArcGIS_MissionServer MissionServer
                {
                    Ensure                                  = 'Present'
                    ConfigurationStoreLocation              = if(-not($Join)){ $ConfigStoreLocation }else{ $null }
                    SiteAdministrator                       = $SiteAdministratorCredential
                    DependsOn                               = $DependsOn
                    ServerDirectoriesRootLocation           = $ServerDirsLocation
                    LogLevel                                = if($DebugMode) { 'DEBUG' } else { 'WARNING' }
                    CloudProvider                           = if($UseCloudStorage -and -not($UseAzureFiles) -and -not($Join)){ "Azure" }else{ "None" }
                    CloudNamespace                          = if($UseCloudStorage -and -not($UseAzureFiles) -and -not($Join)){ "$($Namespace)$($Context)" }else{ $null }
                    AzureCloudAuthenticationType = if($UseCloudStorage -and -not($UseAzureFiles) -and -not($Join)){ $CloudStorageAuthenticationType }else{ "None" }
                    AzureCloudStorageAccountCredential = if($UseCloudStorage -and -not($UseAzureFiles) -and -not($Join)){ $StorageAccountCredential }else{ $null }
                    AzureCloudServicePrincipalCredential = if($UseCloudStorage -and -not($UseAzureFiles) -and -not($Join) -and $CloudStorageAuthenticationType -ieq "ServicePrincipal"){ $ServicePrincipalCredential }else{ $null }
                    AzureCloudServicePrincipalTenantId = if($UseCloudStorage -and -not($UseAzureFiles) -and -not($Join) -and $CloudStorageAuthenticationType -ieq "ServicePrincipal"){ $ServicePrincipalTenantId }else{ $null }
                    AzureCloudServicePrincipalAuthorityHost = if($UseCloudStorage -and -not($UseAzureFiles) -and -not($Join) -and $CloudStorageAuthenticationType -ieq "ServicePrincipal"){ $ServicePrincipalAuthorityHost }else{ $null }
                    AzureCloudUserAssignedIdentityClientId = if($UseCloudStorage -and -not($UseAzureFiles) -and -not($Join) -and $CloudStorageAuthenticationType -ieq "UserAssignedIdentity"){ $UserAssignedIdentityClientId }else{ $null }
                    Join                                    = $Join
                    Version                                 = $Version
                    PeerServerHostName                      = $ServerHostName
                }
                $DependsOn += "[ArcGIS_MissionServer]MissionServer"
            }

            ArcGIS_Server_TLS Server_TLS
            {
                ServerHostName             = $env:ComputerName
                SiteAdministrator          = $SiteAdministratorCredential                         
                WebServerCertificateAlias  = "ApplicationGateway"
                CertificateFileLocation    = $ServerCertificateLocalFilePath
                CertificatePassword        = if($ServerInternalCertificatePassword -and ($ServerInternalCertificatePassword.GetNetworkCredential().Password -ine 'Placeholder')) { $ServerInternalCertificatePassword } else { $null }
                ServerType                 = "MissionServer"
                DependsOn                  = if(-not($IsUpdatingCertificates)){ @('[ArcGIS_MissionServer]MissionServer') }else{ @() }
                SslRootOrIntermediate	   = if($PublicKeySSLCertificateFileName){ [string]::Concat('[{"Alias":"AppGW-ExternalDNSCerCert","Path":"', (Join-Path $(Get-Location).Path $PublicKeySSLCertificateFileName).Replace('\', '\\'),'"}]') }else{$null}
            }
            $DependsOn += @('[ArcGIS_Server_TLS]Server_TLS')
        }

        if(($LastServerHostName -ieq $env:ComputerName) -and ($FederateSite -ieq 'true') -and $PortalSiteAdministratorCredential -and -not($IsUpdatingCertificates)) 
        {
            ArcGIS_MissionServerSettings MissionServerSettings
            {
                ServerHostName      = $ServerHostName
                WebContextURL       = "https://$ExternalDNSHostName/$($Context)"
                WebSocketContextUrl = "wss://$ExternalDNSHostName/$($Context)wss"
                SiteAdministrator   = $SiteAdministratorCredential
                DependsOn           = $DependsOn
            }
            $DependsOn += "[ArcGIS_MissionServerSettings]MissionServerSettings"

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
                ServerFunctions = $ServerFunctions
                DependsOn = $DependsOn
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
                    DependsOn           = $DependsOn
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
                    ServerType          = $ServerFunctions
                    DependsOn = $DependsOn
                }
			}
		}
    }
}
