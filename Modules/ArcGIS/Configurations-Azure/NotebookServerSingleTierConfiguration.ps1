Configuration NotebookServerSingleTierConfiguration
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
        $MachineAdministratorCredential

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $PortalSiteAdministratorCredential

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

        ,[Parameter(Mandatory=$false)]
        $WebProxyMachineNamesOnHostingServer

		,[Parameter(Mandatory=$false)]
        $GisServerMachineNamesOnHostingServer

		,[Parameter(Mandatory=$false)]
		$PortalMachineNamesOnHostingServer
        
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
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -Name ArcGIS_WindowsService
    Import-DscResource -Name ArcGIS_Federation
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_xSmbShare
	Import-DscResource -Name ArcGIS_xDisk  
	Import-DscResource -Name ArcGIS_Disk  
    Import-DscResource -Name ArcGIS_TLSCertificateImport
	Import-DscResource -Name ArcGIS_IIS_TLS
    Import-DscResource -Name ArcGIS_ReverseProxy_ARR
	
	
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
        
    $ServerHostName = ($ServerMachineNames -split ',') | Select-Object -First 1
    $FileShareMachineName = $ServerHostName # Site host architecture    
    $FolderName = $ExternalDNSHostName.Substring(0, $ExternalDNSHostName.IndexOf('.')).ToLower()
    $ConfigStoreLocation  = "\\$($FileShareMachineName)\$FileShareName\$FolderName\server\config-store"
    $ServerDirsLocation   = "\\$($FileShareMachineName)\$FileShareName\$FolderName\server\server-dirs" 
    $Join = ($env:ComputerName -ine $ServerHostName)
	$IsDebugMode = $DebugMode -ieq 'true'
	$IsServiceCredentialDomainAccount = $ServiceCredentialIsDomainAccount -ieq 'true'
    $IsMultiMachineServer = ($ServerMachineNames.Length -gt 1)
	$LastServerHostName = ($ServerMachineNames -split ',') | Select-Object -Last 1
    $FileShareLocalPath = (Join-Path $env:SystemDrive $FileShareName)  

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
            $ConfigStoreCloudStorageConnectionString = "NAMESPACE=$($Namespace)$($EndpointSuffix);DefaultEndpointsProtocol=https;"
            $ConfigStoreCloudStorageAccountName = "AccountName=$AccountName"
            $ConfigStoreCloudStorageConnectionSecret = "AccountKey=$($StorageAccountCredential.GetNetworkCredential().Password)"
        }
    }

    #Since fileshare location sharing or mapped network locations not supported for Docker Desktop, we use local directories for server-dirs.
    $ServerDirsLocation = Join-Path $env:SystemDrive "arcgisnotebookserver\server-dirs"

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
                DiskNumber  =  2
				DriveLetter = 'F'
				DependsOn 	= $DependsOn
			}
			$DependsOn += '[ArcGIS_xDisk]DataDisk' 
        }    
        
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
					DependsOn 				= $DependsOn
				}
				$DependsOn += '[User]ArcGIS_RunAsAccount'
			}

            File FileShareLocationPath
		    {
			    Type						= 'Directory'
			    DestinationPath				= $FileShareLocalPath
			    Ensure						= 'Present'
			    Force						= $true
			}
			$DependsOn += '[File]FileShareLocationPath'

			$Accounts = @('NT AUTHORITY\SYSTEM')
			if($ServiceCredential) { $Accounts += $ServiceCredential.GetNetworkCredential().UserName }
			if($MachineAdministratorCredential -and ($MachineAdministratorCredential.GetNetworkCredential().UserName -ine 'Placeholder') -and ($MachineAdministratorCredential.GetNetworkCredential().UserName -ine $ServiceCredential.GetNetworkCredential().UserName)) { $Accounts += $MachineAdministratorCredential.GetNetworkCredential().UserName }
            ArcGIS_xSmbShare FileShare 
		    { 
			    Ensure						= 'Present' 
			    Name						= $FileShareName
			    Path						= $FileShareLocalPath
			    FullAccess					= $Accounts
				DependsOn					= $DependsOn
			}
			$DependsOn += '[ArcGIS_xSmbShare]FileShare'
    
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
				IsDomainAccount = $IsServiceCredentialDomainAccount
			    Ensure          = 'Present'
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

            ArcGIS_xFirewall NotebookServer_FirewallRules
		    {
			    Name                  = "ArcGISNotebookServer"
			    DisplayName           = "ArcGIS for Notebook Server"
			    DisplayGroup          = "ArcGIS for Notebook Server"
			    Ensure                = 'Present'
			    Access                = "Allow"
			    State                 = "Enabled"
			    Profile               = ("Domain","Private","Public")
			    LocalPort             = ("11443")
				Protocol              = "TCP"
				DependsOn       	   = $DependsOn
		    }
			$DependsOn += '[ArcGIS_xFirewall]NotebookServer_FirewallRules'

            foreach($ServiceToStop in @('ArcGIS Server', 'Portal for ArcGIS', 'ArcGIS Data Store', 'ArcGISGeoEvent', 'ArcGISGeoEventGateway', 'ArcGIS Mission Server'))
			{
                if(Get-Service $ServiceToStop -ErrorAction Ignore) 
			    {
                    Service "$($ServiceToStop.Replace(' ','_'))_Service"
                    {
                        Name			= $ServiceToStop
                        Credential		= $ServiceCredential
                        StartupType		= 'Manual'
                        State			= 'Stopped'
                        DependsOn		= if(-Not($IsServiceCredentialDomainAccount)){ @('[User]ArcGIS_RunAsAccount')}else{ @()}
                    }
                }
			}
			
			ArcGIS_NotebookServer NotebookServer
		    {
			    Ensure                                  = 'Present'
			    SiteAdministrator                       = $SiteAdministratorCredential
			    ConfigurationStoreLocation              = $ConfigStoreLocation
			    DependsOn                               = $DependsOn
			    ServerDirectoriesRootLocation           = $ServerDirsLocation
			    LogLevel                                = if($IsDebugMode) { 'DEBUG' } else { 'WARNING' }
                ConfigStoreCloudStorageConnectionString = $ConfigStoreCloudStorageConnectionString
                ConfigStoreCloudStorageAccountName      = $ConfigStoreCloudStorageAccountName
                ConfigStoreCloudStorageConnectionSecret = $ConfigStoreCloudStorageConnectionSecret
                Join                                    = $False
                PeerServerHostName                      = Get-FQDN $env:ComputerName
		    }
            $DependsOn += '[ArcGIS_NotebookServer]NotebookServer'
            
            ArcGIS_NotebookServerSettings NotebookServerSettings
            {
                WebContextURL                           = "https://$ExternalDNSHostName/$($Context)"
                SiteAdministrator                       = $SiteAdministratorCredential
            }
            $DependsOn += '[ArcGIS_NotebookServerSettings]NotebookServerSettings'
        }
		
		if($SSLCertificateFileName -and $SSLCertificatePassword -and ($SSLCertificatePassword.GetNetworkCredential().Password -ine 'Placeholder'))
		{
			WindowsFeature websockets
			{
				Name  = 'Web-WebSockets'
				Ensure = 'Present'
			}
			$DependsOn += '[WindowsFeature]websockets'
			
			ArcGIS_IIS_TLS IISHTTPS
			{
				WebSiteId               = 1
				Ensure                  = 'Present'
				ExternalDNSName         = $ExternalDNSHostName                        
				CertificateFileLocation = (Join-Path $(Get-Location).Path $SSLCertificateFileName)
				CertificatePassword     = if($SSLCertificatePassword -and ($SSLCertificatePassword.GetNetworkCredential().Password -ine 'Placeholder')) { $SSLCertificatePassword } else { $null }
				DependsOn 				= $DependsOn
			}
			$DependsOn += '[ArcGIS_IIS_TLS]IISHTTPS'
			
			ArcGIS_ReverseProxy_ARR WebProxy
			{
				Ensure                      = 'Present'
				ServerSiteName              = 'arcgis'
				PortalSiteName              = 'arcgis'
				ServerHostNames             = $ServerMachineNames
				PortalHostNames             = $null
				ExternalDNSName             = $ExternalDNSHostName
				PortalAdministrator         = $SiteAdministratorCredential
				SiteAdministrator           = $SiteAdministratorCredential
				ServerEndPoint              = $env:ComputerName
				PortalEndPoint              = $null
				EnableFailedRequestTracking = $IsDebugMode
                EnableGeoEventEndpoints     = $false
                EnableNotebookServerEndpoints = $true
				DependsOn                   = $DependsOn					
			} 
			$DependsOn += '[ArcGIS_ReverseProxy_ARR]WebProxy'
		}
		
		if(($FederateSite -ieq 'true') -and $PortalSiteAdministratorCredential -and $FederationEndPointHostName) 
        {
			ArcGIS_Federation Federate
			{
				PortalHostName = $FederationEndPointHostName
				PortalPort = 443
				PortalContext = 'portal'
				ServiceUrlHostName = $ExternalDNSHostName
				ServiceUrlContext = 'notebookserver'
				ServiceUrlPort = 443
				ServerSiteAdminUrlHostName = $ExternalDNSHostName
				ServerSiteAdminUrlPort = 443
				ServerSiteAdminUrlContext ='notebookserver'
				Ensure = "Present"
				RemoteSiteAdministrator = $PortalSiteAdministratorCredential
				SiteAdministrator = $SiteAdministratorCredential
				ServerRole = 'FEDERATED_SERVER'
				ServerFunctions = $ServerFunctions
				DependsOn = $DependsOn
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
