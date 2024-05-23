Configuration NotebookServerMultiTierConfiguration{
    param(
        [Parameter(Mandatory=$false)]
        [System.String]
        $Version = '11.3'

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
        [System.String]
        $UseCloudStorage 

        ,[Parameter(Mandatory=$false)]
        [System.String]
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
        $FileShareMachineName

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
        [System.Int32]
        $DataDiskNumber = 2

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $FileShareName = 'fileshare' 

		,[Parameter(Mandatory=$false)]
        $GisServerMachineNamesOnHostingServer

		,[Parameter(Mandatory=$false)]
		$PortalMachineNamesOnHostingServer

        ,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $IsUpdatingCertificates = $False
        
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
    Import-DscResource -Name ArcGIS_NotebookServer
    Import-DscResource -Name ArcGIS_NotebookServerSettings
    Import-DscResource -Name ArcGIS_NotebookPostInstall
    Import-DscResource -Name ArcGIS_Server_TLS
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -Name ArcGIS_WindowsService
    Import-DscResource -Name ArcGIS_Federation
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_xSmbShare
	Import-DscResource -Name ArcGIS_xDisk  
	Import-DscResource -Name ArcGIS_Disk  
    Import-DscResource -Name ArcGIS_TLSCertificateImport
    Import-DscResource -Name ArcGIS_PendingReboot
    Import-DscResource -Name ArcGIS_Install
    Import-DscResource -Name ArcGIS_WebAdaptor
    Import-DscResource -Name ArcGIS_IIS_TLS
    Import-DscResource -Name ArcGIS_NotebookServerWorkspaceSetup

    ##
    ## Download license files
    ##
    $ServerCertificateFileName  = 'SSLCertificateForServer.pfx'
    $ServerCertificateLocalFilePath =  (Join-Path $env:TEMP $ServerCertificateFileName)
    $ServerCertificateFileLocation = "\\$($FileShareMachineName)\$FileShareName\Certs\$ServerCertificateFileName"
    
    if($ServerLicenseFileUrl) {
        $ServerLicenseFileName = Get-FileNameFromUrl $ServerLicenseFileUrl
        Invoke-WebRequest -OutFile $ServerLicenseFileName -Uri $ServerLicenseFileUrl -UseBasicParsing -ErrorAction Ignore
    }  
    
    if($PublicKeySSLCertificateFileUrl){
		$PublicKeySSLCertificateFileName = Get-FileNameFromUrl $PublicKeySSLCertificateFileUrl
		Invoke-WebRequest -OutFile $PublicKeySSLCertificateFileName -Uri $PublicKeySSLCertificateFileUrl -UseBasicParsing -ErrorAction Ignore
	}

    $ServerHostName = ($ServerMachineNames -split ',') | Select-Object -First 1

    $ipaddress = (Resolve-DnsName -Name $FileShareMachineName -Type A -ErrorAction Ignore | Select-Object -First 1).IPAddress    
    if(-not($ipaddress)) { $ipaddress = $FileShareMachineName }
    $FileShareRootPath = "\\$ipaddress\$FileShareName"    
    
    $FolderName = $ExternalDNSHostName.Substring(0, $ExternalDNSHostName.IndexOf('.')).ToLower()
    $ConfigStoreLocation  = "\\$($FileShareMachineName)\$FileShareName\$FolderName\$($Context)\config-store"
    $ServerDirsLocation   = "\\$($FileShareMachineName)\$FileShareName\$FolderName\$($Context)\server-dirs" 
    $Join = ($env:ComputerName -ine $ServerHostName)
	$IsDebugMode = $DebugMode -ieq 'true'
    $IsMultiMachineServer = (($ServerMachineNames -split ',').Length -gt 1)
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
            $ConfigStoreLocation  = "\\$($AzureFilesEndpoint)\$FileShareName\$FolderName\$($Context)\config-store"
            $ServerDirsLocation   = "\\$($AzureFilesEndpoint)\$FileShareName\$FolderName\$($Context)\server-dirs" 
        }
        else {
            if(-not($Join)){
                $ConfigStoreCloudStorageConnectionString = "NAMESPACE=$($Namespace)$($Context)$($EndpointSuffix);DefaultEndpointsProtocol=https;"
                $ConfigStoreCloudStorageAccountName = "AccountName=$($AccountName)"
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

    Node localhost
	{ 
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $true
        }
         
		$DependsOn = @()
		
		if($OSDiskSize -gt 0) 
        {
            ArcGIS_Disk OSDiskSize
            {
				DriveLetter = ($env:SystemDrive -replace ":" )
				SizeInGB    = $OSDiskSize
				DependsOn 	= $DependsOn
			}
			$DependsOn += '[ArcGIS_Disk]OSDiskSize' 
		}
		
		if($EnableDataDisk -ieq 'true')
        {
            ArcGIS_xDisk DataDisk
            {
                DiskNumber  =  $DataDiskNumber
				DriveLetter = 'F'
				DependsOn 	= $DependsOn
			}
			$DependsOn += '[ArcGIS_xDisk]DataDisk' 
        }
        
        WindowsFeature websockets
        {
            Name  = 'Web-WebSockets'
            Ensure = 'Present'
        }
        $DependsOn += '[WindowsFeature]websockets'
        
		$HasValidServiceCredential = ($ServiceCredential -and ($ServiceCredential.GetNetworkCredential().Password -ine 'Placeholder'))
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
               
                ArcGIS_NotebookServerWorkspaceSetup GlobalSMBMappingSetup
                {
                    FileShareCredential = if($UseAzureFiles -ieq 'True'){ $StorageAccountCredential }else{ $MachineAdministratorCredential}
                    ArcGISWorkspaceLocation = "$($ServerDirsLocation)\arcgisworkspace"
                    FileShareEndpoint = if($UseAzureFiles -ieq 'True'){ $AzureFilesEndpoint }else{ $FileShareMachineName }
                    FileShareName = $FileShareName
                    IsSingleTier = $False
                    Join = $False
                    UseAzureFiles = ($UseAzureFiles -ieq 'True')
                    DependsOn = $DependsOn
                }
                $DependsOn += '[ArcGIS_NotebookServerWorkspaceSetup]GlobalSMBMappingSetup'
                
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

                ArcGIS_Install "WebAdaptorInstall"
                {
                    Name = "WebAdaptorIIS"
                    Version = $Version 
                    Path = "C:\\ArcGIS\\Deployment\\Downloads\\WebAdaptorIIS\\WebAdaptorIIS.exe"
                    Extract = $True
                    Arguments = "/qn ACCEPTEULA=YES VDIRNAME=$($Context) WEBSITE_ID=1 CONFIGUREIIS=TRUE "
                    WebAdaptorContext = $Context
                    WebAdaptorDotnetHostingBundlePath = "C:\\ArcGIS\\Deployment\\Downloads\\WebAdaptorIIS\\AdditionalFiles\\dotnet-hosting-8.0.0-win.exe"
                    WebAdaptorWebDeployPath = "C:\\ArcGIS\\Deployment\\Downloads\\WebAdaptorIIS\\AdditionalFiles\\WebDeploy_amd64_en-US.msi"
                    Ensure = "Present"
                }

                ArcGIS_IIS_TLS "WebAdaptorCertificateInstall"
                {
                    WebSiteId               = 1
                    ExternalDNSName         = $ExternalDNSHostName
                    Ensure                  = 'Present'
                    CertificateFileLocation = $ServerCertificateLocalFilePath
                    CertificatePassword     = if($ServerInternalCertificatePassword -and ($ServerInternalCertificatePassword.GetNetworkCredential().Password -ine 'Placeholder')) { $ServerInternalCertificatePassword } else { $null }
                    DependsOn               = @('[ArcGIS_Install]WebAdaptorInstall', '[Script]CopyCertificateFileToLocalMachine')
                }
                $DependsOn += @('[ArcGIS_IIS_TLS]WebAdaptorCertificateInstall') 

                ArcGIS_xFirewall NotebookServer_FirewallRules
                {
                    Name                  = "ArcGISNotebookServer"
                    DisplayName           = "ArcGIS for Notebook Server"
                    DisplayGroup          = "ArcGIS for Notebook Server"
                    Ensure                = 'Present'
                    Access                = "Allow"
                    State                 = "Enabled"
                    Profile               = ("Domain","Private","Public")
                    LocalPort             = ("80","443","11443")
                    Protocol              = "TCP"
                    DependsOn       	   = $DependsOn
                }
                $DependsOn += '[ArcGIS_xFirewall]NotebookServer_FirewallRules'

                ArcGIS_WindowsService ArcGIS_for_NotebookServer_Service
                {
                    Name            = 'ArcGIS Notebook Server'
                    Credential      = $ServiceCredential
                    StartupType     = 'Automatic'
                    State           = 'Running' 
                    DependsOn       = $DependsOn
                }
                $DependsOn += '[ArcGIS_WindowsService]ArcGIS_for_NotebookServer_Service'

                ArcGIS_Service_Account NotebookServer_Service_Account
                {
                    Name            = 'ArcGIS Notebook Server'
                    RunAsAccount    = $ServiceCredential
                    IsDomainAccount = $ServiceCredentialIsDomainAccount
                    Ensure          = 'Present'
                    SetStartupToAutomatic = $True
                    DependsOn       = $DependsOn
                }
                $DependsOn += '[ArcGIS_Service_Account]NotebookServer_Service_Account'
                    
                if($ServerLicenseFileName) 
                {
                    ArcGIS_License ServerLicense
                    {
                        LicenseFilePath = (Join-Path $(Get-Location).Path $ServerLicenseFileName)
                        Ensure          = 'Present'
                        Component       = 'Server'
                        ServerRole      = 'NotebookServer'
                        DependsOn       = $DependsOn
                    } 
                    $DependsOn += '[ArcGIS_License]ServerLicense'
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
                        DependsOn       	   = $DependsOn
                        PsDscRunAsCredential = $ServiceCredential # This is critical, cmdkey must run as the service account to persist property
                    }
                    $DependsOn += '[Script]PersistStorageCredentials'
                }   
                
                foreach($ServiceToStop in @('ArcGIS Server', 'Portal for ArcGIS', 'ArcGIS Data Store', 'ArcGISGeoEvent', 'ArcGISGeoEventGateway', 'ArcGIS Mission Server', 'WorkflowManager'))
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

                ArcGIS_NotebookServer NotebookServer
                {
                    Version                                 = $Version
                    Ensure                                  = 'Present'
                    SiteAdministrator                       = $SiteAdministratorCredential
                    ConfigurationStoreLocation              = if(-not($Join)){ $ConfigStoreLocation }else{ $null }
                    ServerDirectoriesRootLocation           = $ServerDirsLocation
                    ServerDirectories                       = '[{"path":"G:\\","name":"arcgisworkspace","type":"WORKSPACE"}]'
                    LogLevel                                = if($IsDebugMode) { 'DEBUG' } else { 'WARNING' }
                    ConfigStoreCloudStorageConnectionString = if(-not($Join)){ $ConfigStoreCloudStorageConnectionString }else{ $null }
                    ConfigStoreCloudStorageAccountName      = if(-not($Join)){ $ConfigStoreCloudStorageAccountName }else{ $null }
                    ConfigStoreCloudStorageConnectionSecret = if(-not($Join)){ $ConfigStoreCloudStorageConnectionSecret }else{ $null }
                    Join                                    = $Join
                    PeerServerHostName                      = $ServerHostName
                    DependsOn                               = $DependsOn
                }
                $DependsOn += '[ArcGIS_NotebookServer]NotebookServer'
                
                ArcGIS_NotebookServerSettings NotebookServerSettings
                {
                    WebContextURL                           = "https://$ExternalDNSHostName/$($Context)"
                    SiteAdministrator                       = $SiteAdministratorCredential
                    DisableDockerHealthCheck                = $True
                    DependsOn                               = $DependsOn
                }
                $DependsOn += '[ArcGIS_NotebookServerSettings]NotebookServerSettings'

                ArcGIS_NotebookPostInstall NotebookPostInstallSamples {
                    SiteName            = $Context
                    ContainerImagePaths = @()
                    ExtractSamples      = $true
                    DependsOn           = $DependsOn
                    PsDscRunAsCredential  = $ServiceCredential # Copy as arcgis account which has access to this share
                }
                $DependsOn += '[ArcGIS_NotebookPostInstall]NotebookPostInstallSamples'
            }

            ArcGIS_Server_TLS Server_TLS
            {
                ServerHostName             = $env:ComputerName
                SiteAdministrator          = $SiteAdministratorCredential                         
                WebServerCertificateAlias  = "ApplicationGateway"
                CertificateFileLocation    = $ServerCertificateLocalFilePath
                CertificatePassword        = if($ServerInternalCertificatePassword -and ($ServerInternalCertificatePassword.GetNetworkCredential().Password -ine 'Placeholder')) { $ServerInternalCertificatePassword } else { $null }
                ServerType                 = $ServerFunctions
                DependsOn                  =  if(-not($IsUpdatingCertificates)){ @('[ArcGIS_NotebookServer]NotebookServer','[ArcGIS_NotebookServerSettings]NotebookServerSettings','[Script]CopyCertificateFileToLocalMachine') }else{ @('[Script]CopyCertificateFileToLocalMachine')  }
                SslRootOrIntermediate	   = if($PublicKeySSLCertificateFileName){ [string]::Concat('[{"Alias":"AppGW-ExternalDNSCerCert","Path":"', (Join-Path $(Get-Location).Path $PublicKeySSLCertificateFileName).Replace('\', '\\'),'"}]') }else{$null}
            }
            $DependsOn += @('[ArcGIS_Server_TLS]Server_TLS') 

            $MachineFQDN = Get-FQDN $env:ComputerName

            ArcGIS_WebAdaptor "ConfigureWebAdaptor"
            {
                Version             = $Version
                Ensure              = "Present"
                Component           = 'NotebookServer'
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
                    DependsOn = $DependsOn
                }
			}
		}
    }
}