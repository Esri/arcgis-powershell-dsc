Configuration NonGISServerConfiguration
{
    param(
        [Parameter(Mandatory=$false)]
        [System.String]
        $Version = "12.2"

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $ServerType

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
        $UseArcGISWebAdaptorForNotebookServer = $False

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $VideoServerLiveStreamGatewayHostname

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $VideoServerLiveStreamPorts

        ,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $DebugMode
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
	Import-DscResource -Name ArcGIS_License
    Import-DscResource -Name ArcGIS_NonGISServer
    Import-DscResource -Name ArcGIS_ServerSettings
    Import-DscResource -Name ArcGIS_Server_TLS
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -Name ArcGIS_Federation
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_xSmbShare
	Import-DscResource -Name ArcGIS_Disk  
    Import-DscResource -Name ArcGIS_TLSCertificateImport
    Import-DscResource -Name ArcGIS_Install
    Import-DscResource -Name ArcGIS_AzureSetupsManager
    Import-DscResource -Name ArcGIS_HostNameSettings
    Import-DscResource -Name ArcGIS_RemoteFile
    #NotebookServer
    Import-DscResource -Name ArcGIS_WebAdaptor
    Import-DscResource -Name ArcGIS_IIS_TLS
    Import-DscResource -Name ArcGIS_NotebookServerWorkspace

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
	$LastServerHostName = ($ServerMachineNames -split ',') | Select-Object -Last 1

    $IsSingleTier = ($ServerMachineNames -split ',' | ForEach-Object { $_.Trim() }) -icontains $FileShareMachineName.Trim()

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

    # Since fileshare location sharing or mapped network locations not supported for Docker Desktop, we use local directories for server-dirs.
    if($ServerType -ieq "NotebookServer" -and -not($UseArcGISWebAdaptorForNotebookServer)){
        $ServerDirsLocation = Join-Path $env:SystemDrive "arcgisnotebookserver\server-dirs"
    }

    Node localhost
	{
        LocalConfigurationManager
        {
			ActionAfterReboot   = 'ContinueConfiguration'            
            ConfigurationMode   = 'ApplyOnly'    
            RebootNodeIfNeeded  = $false
        }
         
		$DependsOn = @()
		
		ArcGIS_Disk DiskSizeCheck
        {
            HostName = $env:ComputerName
        }

        if(@("NotebookServer", "MissionServer", "VelocityServer") -icontains $ServerType){
            WindowsFeature websockets
            {
                Name    = 'Web-WebSockets'
                Ensure  = 'Present'
            }
            $DependsOn += '[WindowsFeature]websockets'
        }

        ArcGIS_AzureSetupsManager CleanupDownloadsFolder{
            Version         = $Version
            OperationType   = 'CleanupDownloadsFolder'
            ComponentNames  = "Server"
            ServerRole      = $ServerType
        }

        if($HasValidServiceCredential -and -not($IsUpdatingCertificates)){
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

            ArcGIS_Install "$($ServerType)Install"
            {
                Name                            = $ServerType
                Version                         = $Version
                Path                            = "$($env:SystemDrive)\\ArcGIS\\Deployment\\Downloads\\$($ServerType)\\$($ServerType).exe"
                Extract                         = $True
                Arguments                       = "/qn ACCEPTEULA=YES InstallDir=`"$($env:SystemDrive)\\ArcGIS\\$($ServerType)`""
                ServiceCredential               = $ServiceCredential
                ServiceCredentialIsDomainAccount= $ServiceCredentialIsDomainAccount
                EnableMSILogging                = $DebugMode
                Ensure                          = "Present"
                DependsOn                       = $DependsOn
            }
            $DependsOn += "[ArcGIS_Install]$($ServerType)Install"

            $FirewallPorts = @()
            $SRTFirewallPort = $null
            $FirewallDisplayGroupAndName = ""
            if($ServerType -ieq "NotebookServer"){
                $FirewallPorts = ("80", "443", "11443")
                $FirewallDisplayGroupAndName = "ArcGIS for Notebook Server"
            }elseif($ServerType -ieq "MissionServer"){
                $FirewallPorts = ("20443","20300","20301")
                $FirewallDisplayGroupAndName = "ArcGIS for Mission Server"
            }elseif($ServerType -ieq "DataPipelinesServer"){
                $FirewallPorts = ("14443")
                $FirewallDisplayGroupAndName = "ArcGIS for Data Pipelines Server"
            }elseif($ServerType -ieq "VideoServer"){
                $FirewallPorts = ("21443","21080")
                $FirewallDisplayGroupAndName = "ArcGIS for Video Server"
                if(-not([string]::IsNullOrEmpty($VideoServerLiveStreamPorts))){
                    $PortsObject = ConvertFrom-Json $VideoServerLiveStreamPorts
                    $FirewallPorts += ($PortsObject.RTMPPort, $PortsObject.RTSPTCPPort,"$($PortsObject.RTSPUDPPortRangeMin)-$($PortsObject.RTSPUDPPortRangeMax)")
                    $SRTFirewallPort = $PortsObject.SRTPort
                }
            }elseif($ServerType -ieq "VelocityServer"){
                $FirewallPorts = ("7143")
                $FirewallDisplayGroupAndName = "ArcGIS for Velocity Server"
            }

            ArcGIS_xFirewall "$($ServerType)_FirewallRules"
            {
                Name                  = "ArcGIS$($ServerType)"
                DisplayName           = $FirewallDisplayGroupAndName
                DisplayGroup          = $FirewallDisplayGroupAndName
                Ensure                = 'Present'
                Access                = "Allow"
                State                 = "Enabled"
                Profile               = ("Domain","Private","Public")
                LocalPort             = $FirewallPorts
                Protocol              = "TCP"
                DependsOn       	  = $DependsOn
            }
            $DependsOn += "[ArcGIS_xFirewall]$($ServerType)_FirewallRules"

            if($null -ne $SRTFirewallPort){
                ArcGIS_xFirewall "$($ServerType)_SRTFirewallRule"
                {
                    Name                  = "ArcGIS$($ServerType)SRT"
                    DisplayName           = "$FirewallDisplayGroupAndName SRT"
                    DisplayGroup          = $FirewallDisplayGroupAndName
                    Ensure                = 'Present'
                    Access                = "Allow"
                    State                 = "Enabled"
                    Profile               = ("Domain","Private","Public")
                    LocalPort             = $SRTFirewallPort
                    Protocol              = "UDP"
                    DependsOn             = $DependsOn
                }
                $DependsOn += "[ArcGIS_xFirewall]$($ServerType)_SRTFirewallRule"
            }

            # TODO - create folders in existing file share

            if($ServerType -ieq "NotebookServer" -and $UseArcGISWebAdaptorForNotebookServer){
                ArcGIS_NotebookServerWorkspace GlobalSMBMappingSetup
                {
                    FileShareCredential     = if($UseAzureFiles){ $StorageAccountCredential }else{ $ServiceCredential }
                    FileShareCredentialIsDomainAccount = if($UseAzureFiles){ $false }else{ $ServiceCredentialIsDomainAccount }
                    ArcGISWorkspaceLocation = "$($ServerDirsLocation)\arcgisworkspace"
                    FileShareEndpoint       = if($UseAzureFiles){ $AzureFilesEndpoint }else{ $FileShareMachineName }
                    FileShareName           = $FileShareName
                    IsSingleTier            = $IsSingleTier
                    Join                    = if($IsSingleTier ){ $Join }else{ $False } # check this?
                    UseAzureFiles           = ($UseAzureFiles)
                    DependsOn               = $DependsOn
                }
                $DependsOn += '[ArcGIS_NotebookServerWorkspace]GlobalSMBMappingSetup'
            
                $WAAdditionFilesPath = "C:\\ArcGIS\\Deployment\\Downloads\\WebAdaptorIIS\\AdditionalFiles"
                $WAInstallPath = "C:\\ArcGIS\\Deployment\\Downloads\\WebAdaptorIIS\\WebAdaptorIIS.exe"
                if(-not(Test-Path $WAAdditionFilesPath)){
                    $WAAdditionFilesPath = "C:\\ArcGIS\\Deployment\\Downloads\\$($Version)"
                    if(-not(Test-Path $WAAdditionFilesPath)){
                         throw "Required additional files for Web Adaptor were not found at $WAAdditionFilesPath"
                    }
                    $WAInstallPath = "$($WAAdditionFilesPath)\\WebAdaptorIIS.exe"
                }
                    
                $dotnetHostingBundlePath = Get-ChildItem -Path $WAAdditionFilesPath -Filter "*dotnet-hosting*" -Recurse | Select-Object -ExpandProperty FullName
                if([string]::IsNullOrEmpty($dotnetHostingBundlePath)){
                    throw "Required dotnet-hosting bundle file for Web Adaptor was not found at $WAAdditionFilesPath"
                }

                $webDeployPath = Get-ChildItem -Path $WAAdditionFilesPath -Filter "*WebDeploy*" -Recurse | Select-Object -ExpandProperty FullName
                if([string]::IsNullOrEmpty($webDeployPath)){
                    throw "Required Web Deploy file for Web Adaptor was not found at $WAAdditionFilesPath"
                }

                ArcGIS_Install "WebAdaptorInstall"
                {
                    Name = "WebAdaptorIIS"
                    Version = $Version 
                    Path = $WAInstallPath
                    Extract = $True
                    Arguments = "/qn ACCEPTEULA=YES VDIRNAME=$($Context) WEBSITE_ID=1 CONFIGUREIIS=TRUE "
                    WebAdaptorContext = $Context
                    WebAdaptorDotnetHostingBundlePath = $dotnetHostingBundlePath
                    WebAdaptorWebDeployPath = $webDeployPath
                    Ensure = "Present"
                }
                $DependsOn += '[ArcGIS_Install]WebAdaptorInstall'
            }


            $ServiceName = (Get-ArcGISServiceName -ComponentName $ServerType)
            ArcGIS_Service_Account "$($ServerType)_Service_Account"
            {
                Name                    = $ServiceName
                RunAsAccount            = $ServiceCredential
                IsDomainAccount         = $ServiceCredentialIsDomainAccount
                SetStartupToAutomatic   = $True
                Ensure                  = 'Present'
                DependsOn               = $DependsOn
            }
            $DependsOn += "[ArcGIS_Service_Account]$($ServerType)_Service_Account"

            if($ServerLicenseFileName) 
            {
                ArcGIS_RemoteFile "ServerLicenceFileDownload"
                {
                    Source = $ServerLicenseFileName
                    Destination = (Join-Path $(Get-Location).Path $ServerLicenseFileName)
                    FileSourceType = "AzureSASUri"
                    Credential = $DeploymentArtifactCredentials
                    Ensure = 'Present'
                }
                $DependsOn += '[ArcGIS_RemoteFile]ServerLicenceFileDownload'

                ArcGIS_License ServerLicense
                {
                    LicenseFilePath = (Join-Path $(Get-Location).Path $ServerLicenseFileName)
                    Ensure          = 'Present'
                    Component       = 'Server'
                    Version 		= $Version
                    ServerRole      = $ServerType
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

            foreach($ServiceToStop in @('ArcGIS Server', 'Portal for ArcGIS', 'ArcGIS Data Store'))
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

            ArcGIS_HostNameSettings "$($ServerType)HostNameSettings"{
                ComponentName   = $ServerType
                Version         = $Version
                DependsOn       = $DependsOn
            }
            $DependsOn += "[ArcGIS_HostNameSettings]$($ServerType)HostNameSettings"

            ArcGIS_NonGISServer $ServerType
            {
                Ensure                                  = 'Present'
                ServerType                              = $ServerType
                ConfigurationStoreLocation              = if(-not($Join)){ $ConfigStoreLocation }else{ $null }
                SiteAdministrator                       = $SiteAdministratorCredential
                DependsOn                               = $DependsOn
                ServerDirectoriesRootLocation           = $ServerDirsLocation
                ServerDirectories                       = if($UseArcGISWebAdaptorForNotebookServer){'[{"path":"G:\\","name":"arcgisworkspace","type":"WORKSPACE"}]'}else{$null}
                LogLevel                                = if($DebugMode) { 'DEBUG' } else { 'WARNING' }
                CloudProvider                           = if($UseCloudStorage -and -not($UseAzureFiles) -and -not($Join)){ "Azure" }else{ "None" }
                CloudNamespace                          = if($UseCloudStorage -and -not($UseAzureFiles) -and -not($Join)){ "$($Namespace)$($Context)" }else{ $null }
                AzureCloudAuthenticationType            = if($UseCloudStorage -and -not($UseAzureFiles) -and -not($Join)){ $CloudStorageAuthenticationType }else{ "None" }
                AzureCloudStorageAccountCredential      = if($UseCloudStorage -and -not($UseAzureFiles) -and -not($Join)){ $StorageAccountCredential }else{ $null }
                AzureCloudServicePrincipalCredential    = if($UseCloudStorage -and -not($UseAzureFiles) -and -not($Join) -and $CloudStorageAuthenticationType -ieq "ServicePrincipal"){ $ServicePrincipalCredential }else{ $null }
                AzureCloudServicePrincipalTenantId      = if($UseCloudStorage -and -not($UseAzureFiles) -and -not($Join) -and $CloudStorageAuthenticationType -ieq "ServicePrincipal"){ $ServicePrincipalTenantId }else{ $null }
                AzureCloudServicePrincipalAuthorityHost = if($UseCloudStorage -and -not($UseAzureFiles) -and -not($Join) -and $CloudStorageAuthenticationType -ieq "ServicePrincipal"){ $ServicePrincipalAuthorityHost }else{ $null }
                AzureCloudUserAssignedIdentityClientId  = if($UseCloudStorage -and -not($UseAzureFiles) -and -not($Join) -and $CloudStorageAuthenticationType -ieq "UserAssignedIdentity"){ $UserAssignedIdentityClientId }else{ $null }
                Join                                    = $Join
                Version                                 = $Version
                PeerServerHostName                      = $ServerHostName
                PortalSiteAdministrator                 = if($PortalSiteAdministratorCredential -and $PortalSiteAdministratorCredential.UserName -ine "placeholder"){ $PortalSiteAdministratorCredential }else{ $null }
            }
            $DependsOn += "[ArcGIS_NonGISServer]$($ServerType)"
        }

        if(($ServerHostName -ieq $env:ComputerName) -and ($FederateSite -ieq 'true') -and $PortalSiteAdministratorCredential -and -not($IsUpdatingCertificates))
        {
            ArcGIS_ServerSettings "$($ServerType)Settings"
            {
                ServerHostName      = $ServerHostName
                ServerType          = $ServerType
                WebContextURL       = if($ExternalDNSHostName){"https://$($ExternalDNSHostName)/$($Context)"}else{ $null }
                WebSocketContextUrl = if($ServerType -ieq "MissionServer" -and $ExternalDNSHostName){"wss://$($ExternalDNSHostName)/$($Context)wss"}else{ $null }
                SiteAdministrator   = $SiteAdministratorCredential
                DisableDockerHealthCheck = ($ServerType -ieq "NotebookServer")
                VideoServerLiveStreamPorts = if($ServerType -ieq "VideoServer"){ $VideoServerLivestreamPorts }else{ $null } 
                VideoServerLiveStreamGatewayHostname = if($ServerType -ieq "VideoServer"){ $VideoServerLiveStreamGatewayHostname }else{ $null } 
                DependsOn           = $DependsOn
            }
            $DependsOn += "[ArcGIS_ServerSettings]$($ServerType)Settings"
        }

        if($ServerCertificateFileName) {
            ArcGIS_RemoteFile "ServerCertificateFileDownload"
            {
                Source          = "Certs/$($ServerCertificateFileName)"
                Destination     = $ServerCertificateLocalFilePath
                FileSourceType  = "AzureSASUri"
                Credential      = $DeploymentArtifactCredentials
                Ensure          = 'Present'
            }
            $DependsOn += '[ArcGIS_RemoteFile]ServerCertificateFileDownload'
        }

        if($PublicKeySSLCertificateFileName) {
            ArcGIS_RemoteFile "PublicKeySSLCertificateFileDownload"
            {
                Source          = $PublicKeySSLCertificateFileName
                Destination     = (Join-Path $(Get-Location).Path $PublicKeySSLCertificateFileName)
                FileSourceType  = "AzureSASUri"
                Credential      = $DeploymentArtifactCredentials
                Ensure          = 'Present'
            }
            $DependsOn += '[ArcGIS_RemoteFile]PublicKeySSLCertificateFileDownload'
        }

        if($ServerType -ieq "NotebookServer" -and $UseArcGISWebAdaptorForNotebookServer){
            ArcGIS_IIS_TLS "WebAdaptorCertificateInstall"
            {
                WebSiteId               = 1
                ExternalDNSName         = $ExternalDNSHostName
                Ensure                  = 'Present'
                CertificateFileLocation = $ServerCertificateLocalFilePath
                CertificatePassword     = if($ServerInternalCertificatePassword -and ($ServerInternalCertificatePassword.GetNetworkCredential().Password -ine 'Placeholder')) { $ServerInternalCertificatePassword } else { $null }
                DependsOn               = $DependsOn
            }
            $DependsOn += @('[ArcGIS_IIS_TLS]WebAdaptorCertificateInstall') 
        }

        ArcGIS_Server_TLS Server_TLS
        {
            ServerHostName             = $env:ComputerName
            SiteAdministrator          = $SiteAdministratorCredential                         
            WebServerCertificateAlias  = "ApplicationGateway"
            CertificateFileLocation    = $ServerCertificateLocalFilePath
            CertificatePassword        = if($ServerInternalCertificatePassword -and ($ServerInternalCertificatePassword.GetNetworkCredential().Password -ine 'Placeholder')) { $ServerInternalCertificatePassword } else { $null }
            ServerType                 = $ServerType
            DependsOn                  = $DependsOn
            SslRootOrIntermediate	   = if($PublicKeySSLCertificateFileName){ [string]::Concat('[{"Alias":"AppGW-ExternalDNSCerCert","Path":"', (Join-Path $(Get-Location).Path $PublicKeySSLCertificateFileName).Replace('\', '\\'),'"}]') }else{$null}
        }
        $DependsOn += '[ArcGIS_Server_TLS]Server_TLS'

        if($ServerType -ieq "NotebookServer" -and $UseArcGISWebAdaptorForNotebookServer){
            $MachineFQDN = Get-FQDN $env:ComputerName

            ArcGIS_WebAdaptor "ConfigureWebAdaptor"
            {
                Version             = $Version
                Ensure              = "Present"
                Component           = $ServerType
                HostName            = $MachineFQDN
                ComponentHostName   = $MachineFQDN
                Context             = $Context
                OverwriteFlag       = $False
                SiteAdministrator   = $SiteAdministratorCredential
                AdminAccessEnabled  = $True
                DependsOn           = $DependsOn
            }
            $DependsOn += @('[ArcGIS_WebAdaptor]ConfigureWebAdaptor') 
        }

        if(($LastServerHostName -ieq $env:ComputerName) -and ($FederateSite -ieq 'true') -and $PortalSiteAdministratorCredential -and -not($IsUpdatingCertificates)) 
        {
            ArcGIS_Federation Federate
            {
                PortalHostName              = $ExternalDNSHostName
                PortalPort                  = 443
                PortalContext               = $PortalContext
                ServiceUrlHostName          = $ExternalDNSHostName
                ServiceUrlContext           = $Context
                ServiceUrlPort              = 443
                ServerSiteAdminUrlHostName  = if($PrivateDNSHostName){ $PrivateDNSHostName }else{ $ExternalDNSHostName }
                ServerSiteAdminUrlPort      = 443
                ServerSiteAdminUrlContext   = $Context
                Ensure                      = "Present"
                PortalSiteAdministrator     = $PortalSiteAdministratorCredential
                SiteAdministrator           = $SiteAdministratorCredential
                ServerRole                  = 'FEDERATED_SERVER'
                ServerFunctions             = $ServerType
                DependsOn                   = $DependsOn
            }
        }

        if($PortalSiteAdministratorCredential -and $PortalSiteAdministratorCredential.UserName -ine "placeholder"){

            # Import TLS certificates from portal machines on the hosting server
            if($PortalMachineNamesOnHostingServer -and $PortalMachineNamesOnHostingServer.Length -gt 0)
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
                        ServerType          = $ServerType
                        DependsOn           = $DependsOn
                    }
                }
            }

            # Import TLS certificates from GIS on the hosting server
            if($GisServerMachineNamesOnHostingServer -and $GisServerMachineNamesOnHostingServer.Length -gt 0)
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
                        ServerType          = $ServerType
                        DependsOn           = $DependsOn
                    }
                }
            }
        }
    }
}