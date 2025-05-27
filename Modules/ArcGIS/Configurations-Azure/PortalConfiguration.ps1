﻿Configuration PortalConfiguration
{
	param(
        [Parameter(Mandatory=$false)]
        [System.String]
        $Version = "11.5"

        ,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $IsAllInOneBaseDeploy = $false

        ,[Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServiceCredential

        ,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount
        
        ,[Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $SiteAdministratorCredential

        ,[Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $PortalAdministratorSecurityQuestionCredential

        ,[Parameter(Mandatory=$False)]
        [System.String]
        $PortalAdministratorEmail

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServerContext = 'server'

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $PortalContext = 'portal'

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
        $PortalInternalCertificatePassword
                
        ,[Parameter(Mandatory=$false)]
        [System.String]
        $PortalLicenseFileUrl

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $PortalLicenseUserTypeId

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $PortalMachineNames

		,[Parameter(Mandatory=$true)]
        [System.String]
        $ServerMachineNames

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
        [System.String]
        $FileShareMachineName
        
        ,[Parameter(Mandatory=$false)]
        [System.String]
        $FileShareName = 'fileshare'

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $FileSharePath
        
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
	Import-DscResource -Name ArcGIS_Portal
    Import-DscResource -Name ArcGIS_Portal_TLS
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -name ArcGIS_WindowsService
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_Disk
    Import-DscResource -Name ArcGIS_PortalSettings
    Import-DscResource -Name ArcGIS_Federation
    Import-DscResource -Name ArcGIS_AzureSetupDownloadsFolderManager
   
    $FileShareRootPath = $FileSharePath
    if(-not($UseExistingFileShare)) { 
        $FileSharePath = "\\$($FileShareMachineName)\$($FileShareName)"
        
        $ipaddress = (Resolve-DnsName -Name $FileShareMachineName -Type A -ErrorAction Ignore | Select-Object -First 1).IPAddress    
        if(-not($ipaddress)) { $ipaddress = $FileShareMachineName }
        $FileShareRootPath = "\\$ipaddress\$FileShareName"
    }

    $PortalCertificateFileName  = 'SSLCertificateForPortal.pfx'
    $PortalCertificateLocalFilePath =  (Join-Path $env:TEMP $PortalCertificateFileName)

    $FolderName = $ExternalDNSHostName.Substring(0, $ExternalDNSHostName.IndexOf('.')).ToLower()
    $PortalCertificateFileLocation = "$($FileSharePath)\Certs\$PortalCertificateFileName"
    if($UseExistingFileShare)
    {
        $PortalCertificateFileLocation = "$($FileSharePath)\$($FolderName)\$($PortalContext)\$PortalCertificateFileName"
    }
    
    ##
    ## Download license file and certificate files
    ##
    if($PortalLicenseFileUrl -and ($PortalLicenseFileUrl.Trim().Length -gt 0)) {
        $PortalLicenseFileName = Get-FileNameFromUrl $PortalLicenseFileUrl
        Invoke-WebRequest -OutFile $PortalLicenseFileName -Uri $PortalLicenseFileUrl -UseBasicParsing -ErrorAction Ignore
    }   
    
    if($PublicKeySSLCertificateFileUrl){
		$PublicKeySSLCertificateFileName = Get-FileNameFromUrl $PublicKeySSLCertificateFileUrl
		Invoke-WebRequest -OutFile $PublicKeySSLCertificateFileName -Uri $PublicKeySSLCertificateFileUrl -UseBasicParsing -ErrorAction Ignore
	}

    $ContentStoreLocation = "$($FileSharePath)\$FolderName\$($PortalContext)\content"

	$ServerHostNames = ($ServerMachineNames -split ',')
    $ServerMachineName = $ServerHostNames | Select-Object -First 1
    $PortalHostNames = ($PortalMachineNames -split ',')
    $PortalHostName = $PortalHostNames | Select-Object -First 1   
    $LastPortalHostName = $PortalHostNames | Select-Object -Last 1 
    
    $Join = ($env:ComputerName -ine $PortalHostName)    
    $PeerMachineName = $null
    if($PortalHostNames.Length -gt 1) {
      $PeerMachineName = $PortalHostNames | Select-Object -Last 1
    }
    $IsHAPortal = ($PortalHostName -ine $PeerMachineName) -and ($PeerMachineName)

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
            $FolderName = $ExternalDNSHostName.Substring(0, $ExternalDNSHostName.IndexOf('.'))
            $ContentStoreLocation = "\\$($AzureFilesEndpoint)\$FileShareName\$FolderName\$($PortalContext)\content"    
        }
        else {
            if(-not($Join)){
                $ContentDirectoryCloudContainerName = "arcgis-portal-content-$($Namespace)$($PortalContext)"
                $ContentDirectoryCloudConnectionString = "DefaultEndpointsProtocol=https;AccountName=$($AccountName)$($EndpointSuffix)"
                
                if($CloudStorageAuthenticationType -ieq 'ServicePrincipal'){
                    $ClientSecret = $StorageAccountServicePrincipalCredential.GetNetworkCredential().Password
                    $ContentDirectoryCloudConnectionString += ";tenantId=$($StorageAccountServicePrincipalTenantId);clientId=$($StorageAccountServicePrincipalCredential.Username);clientSecret=$($ClientSecret);CredentialType=servicePrincipal"
                    if(-not([string]::IsNullOrEmpty($StorageAccountServicePrincipalAuthorityHost))){
						$ContentDirectoryCloudConnectionString += ";authorityHost=$($StorageAccountServicePrincipalAuthorityHost)" 
					}
                }elseif($CloudStorageAuthenticationType -ieq 'UserAssignedIdentity'){
                    $ContentDirectoryCloudConnectionString += ";managedIdentityClientId=$($StorageAccountUserAssignedIdentityClientId);CredentialType=userAssignedIdentity"
                }elseif($CloudStorageAuthenticationType -ieq 'SASToken'){
                    $SASToken = $CloudStorageCredentials.GetNetworkCredential().Password
                    $ContentDirectoryCloudConnectionString += ";sasToken=$($SASToken);CredentialType=sasToken"
                }else{
                    $AccountKey = $StorageAccountCredential.GetNetworkCredential().Password
                    $ContentDirectoryCloudConnectionString += ";AccountKey=$($AccountKey);CredentialType=accessKey"
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
            RebootNodeIfNeeded = $false
        }
        
        ArcGIS_Disk DiskSizeCheck
        {
            HostName = $env:ComputerName
        }

        ArcGIS_AzureSetupDownloadsFolderManager CleanupDownloadsFolder{
            Version = $Version
            OperationType = 'CleanupDownloadsFolder'
            ComponentNames = if($IsAllInOneBaseDeploy){ "DataStore,Server,Portal" }else{ "Portal" }
        }

        $HasValidServiceCredential = ($ServiceCredential -and ($ServiceCredential.GetNetworkCredential().Password -ine 'Placeholder'))
        if($HasValidServiceCredential) 
        {
            $PortalDependsOn = @()

            if(-not($IsUpdatingCertificates))
            {
                if(-Not($ServiceCredentialIsDomainAccount)){
                    User ArcGIS_RunAsAccount
                    {
                        UserName       = $ServiceCredential.UserName
                        Password       = $ServiceCredential
                        FullName       = 'ArcGIS Service Account'
                        Ensure         = 'Present'
                        PasswordChangeRequired = $false
                        PasswordNeverExpires = $true
                    }
                    $PortalDependsOn += '[User]ArcGIS_RunAsAccount'
                }
           
                if($PortalLicenseFileName -and ($PortalLicenseFileName.Trim().Length -gt 0) ) 
                {
                    if([string]::IsNullOrEmpty($PortalLicenseUserTypeId)){
                        ArcGIS_License PortalLicense
                        {
                            LicenseFilePath = (Join-Path $(Get-Location).Path $PortalLicenseFileName)
                            Ensure          = 'Present'
                            Component       = 'Portal'
                        } 
                        $PortalDependsOn += '[ArcGIS_License]PortalLicense'
                    }

                    ArcGIS_WindowsService Portal_for_ArcGIS_Service
                    {
                        Name            = 'Portal for ArcGIS'
                        Credential      = $ServiceCredential
                        StartupType     = 'Automatic'
                        State           = 'Running' 
                        DependsOn       = $PortalDependsOn
                    }
                    $PortalDependsOn += '[ArcGIS_WindowsService]Portal_for_ArcGIS_Service'

                    ArcGIS_Service_Account Portal_Service_Account
                    {
                        Name            = 'Portal for ArcGIS'
                        RunAsAccount    = $ServiceCredential
                        IsDomainAccount = $ServiceCredentialIsDomainAccount
                        Ensure          = 'Present'
                        DependsOn       = $PortalDependsOn
                        DataDir         = @('HKLM:\SOFTWARE\ESRI\Portal for ArcGIS')  
                    }
                    $PortalDependsOn += '[ArcGIS_Service_Account]Portal_Service_Account'
            
                
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
                            SetScript = { 
                                            $result = cmdkey "/add:$using:AzureFilesEndpoint" "/user:$using:filesStorageAccountName" "/pass:$using:storageAccountKey" 
                                            $result | ForEach-Object{Write-verbose -Message "cmdkey: $_" -Verbose}
                                        }
                            GetScript            = { return @{} }                  
                            DependsOn            = $PortalDependsOn
                            PsDscRunAsCredential = $ServiceCredential # This is critical, cmdkey must run as the service account to persist property
                        }              
                        $PortalDependsOn += '[Script]PersistStorageCredentials'

                        $RootPathOfFileShare = "\\$($AzureFilesEndpoint)\$FileShareName"
                        Script CreatePortalContentFolder
                        {
                            TestScript = { 
                                            Test-Path $using:ContentStoreLocation
                                        }
                            SetScript = {                   
                                            Write-Verbose "Mount to $using:RootPathOfFileShare"
                                            $DriveInfo = New-PSDrive -Name 'Z' -PSProvider FileSystem -Root $using:RootPathOfFileShare
                                            if(-not(Test-Path $using:ContentStoreLocation)) {
                                                Write-Verbose "Creating folder $using:ContentStoreLocation"
                                                New-Item $using:ContentStoreLocation -ItemType directory
                                            }else {
                                                Write-Verbose "Folder '$using:ContentStoreLocation' already exists"
                                            }
                                        }
                            GetScript            = { return @{} }     
                            DependsOn            = $PortalDependsOn
                            PsDscRunAsCredential = $ServiceCredential # This is important, only arcgis account has access to the file share on AFS
                        }             
                        $PortalDependsOn += '[Script]CreatePortalContentFolder'
                    } 

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
                        DependsOn             = $PortalDependsOn
                    }
                    $PortalDependsOn += '[ArcGIS_xFirewall]Portal_FirewallRules'

                    if($IsHAPortal) 
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
                            RemotePort            =("7654","7120","7220", "7005", "7099", "7199")  # Elastic Search uses 7120,7220 and Postgres uses 7654 for replication
                            Direction             = "Outbound"                       
                            Protocol              = "TCP" 
                            DependsOn             = $PortalDependsOn
                        } 
                        $PortalDependsOn += @('[ArcGIS_xFirewall]Portal_Database_OutBound')
                        
                        ArcGIS_xFirewall Portal_Database_InBound
                        {
                            Name                  = "PortalforArcGIS-Inbound" 
                            DisplayName           = "Portal for ArcGIS Inbound" 
                            DisplayGroup          = "Portal for ArcGIS Inbound" 
                            Ensure                = 'Present'
                            Access                = "Allow" 
                            State                 = "Enabled" 
                            Profile               = ("Domain","Private","Public")
                            LocalPort             = ("7120","7220")  # Elastic Search uses 7120,7220
                            Protocol              = "TCP" 
                            DependsOn             = $PortalDependsOn
                        }  
                        $PortalDependsOn += @('[ArcGIS_xFirewall]Portal_Database_InBound')

                        $VersionArray = $Version.Split(".")
                        if($VersionArray[0] -ieq 11 -and $VersionArray -ge 3){ # 11.3 or later
                            ArcGIS_xFirewall Portal_Ignite_OutBound
                            {
                                Name                  = "PortalforArcGIS-Ignite-Outbound" 
                                DisplayName           = "Portal for ArcGIS Ignite Outbound" 
                                DisplayGroup          = "Portal for ArcGIS Ignite Outbound" 
                                Ensure                = 'Present' 
                                Access                = "Allow" 
                                State                 = "Enabled" 
                                Profile               = ("Domain","Private","Public")
                                RemotePort            = ("7820","7830", "7840") # Ignite uses 7820,7830,7840
                                Direction             = "Outbound"                       
                                Protocol              = "TCP" 
                            }  
                            $PortalDependsOn += @('[ArcGIS_xFirewall]Portal_Ignite_OutBound')
                            
                            ArcGIS_xFirewall Portal_Ignite_InBound
                            {
                                Name                  = "PortalforArcGIS-Ignite-Inbound" 
                                DisplayName           = "Portal for ArcGIS Ignite Inbound" 
                                DisplayGroup          = "Portal for ArcGIS Ignite Inbound" 
                                Ensure                = 'Present' 
                                Access                = "Allow" 
                                State                 = "Enabled" 
                                Profile               = ("Domain","Private","Public")
                                LocalPort            = ("7820","7830", "7840") # Ignite uses 7820,7830,7840
                                Protocol              = "TCP" 
                            }  
                            $PortalDependsOn += @('[ArcGIS_xFirewall]Portal_Ignite_InBound')
                        }
                    }     

                    ArcGIS_Portal Portal
                    {
                        PortalHostName                        = if($PortalHostName -ieq $env:ComputerName){ $PortalHostName }else{ $PeerMachineName }
                        Version                               = $Version
                        Ensure                                = 'Present'
                        LicenseFilePath                       = if($PortalLicenseFileName){(Join-Path $(Get-Location).Path $PortalLicenseFileName)}else{$null}
                        UserLicenseTypeId                     = if($PortalLicenseUserTypeId){$PortalLicenseUserTypeId}else{$null}
                        PortalAdministrator                   = $SiteAdministratorCredential 
                        DependsOn                             = $PortalDependsOn
                        AdminEmail                            = $PortalAdministratorEmail
                        AdminFullName                         = $SiteAdministratorCredential.UserName
                        AdminDescription                      = 'Portal Administrator'
                        AdminSecurityQuestionCredential       = if($PortalAdministratorSecurityQuestionCredential.UserName -ine "PlaceHolder"){ $PortalAdministratorSecurityQuestionCredential }else{ $null }
                        Join                                  = $Join
                        IsHAPortal                            = $IsHAPortal
                        PeerMachineHostName                   = if($Join) { $PortalHostName } else { $PeerMachineName }
                        ContentDirectoryLocation              = if(-not($Join)){ $ContentStoreLocation }else{ $null }
                        EnableDebugLogging                    = $DebugMode
                        LogLevel                              = if($DebugMode) { 'DEBUG' } else { 'WARNING' }
                        ContentDirectoryCloudConnectionString = if(-not($Join)){ $ContentDirectoryCloudConnectionString }else{ $null }
                        ContentDirectoryCloudContainerName    = if(-not($Join)){ $ContentDirectoryCloudContainerName }else{ $null }
                    } 
                    $PortalDependsOn += @('[ArcGIS_Portal]Portal')
                }
            }

            if($IsUpdatingCertificates -or ($PortalLicenseFileName -and ($PortalLicenseFileName.Trim().Length -gt 0) )){ #On add of new machine or update certificate op
                
                Script CopyCertificateFileToLocalMachine
                {
                    GetScript = {
                        $null
                    }
                    SetScript = {    
                        Write-Verbose "Copying from $using:PortalCertificateFileLocation to $using:PortalCertificateLocalFilePath"      
                        $PsDrive = New-PsDrive -Name W -Root $using:FileShareRootPath -PSProvider FileSystem                              
                        Copy-Item -Path $using:PortalCertificateFileLocation -Destination $using:PortalCertificateLocalFilePath -Force  
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
                $PortalDependsOn += '[Script]CopyCertificateFileToLocalMachine'
                
                ArcGIS_Portal_TLS ArcGIS_Portal_TLS
                {
                    PortalHostName = if($PortalHostName -ieq $env:ComputerName){ $PortalHostName }else{ $PeerMachineName }
                    SiteAdministrator       = $SiteAdministratorCredential 
                    WebServerCertificateAlias= "ApplicationGateway"
                    CertificateFileLocation = $PortalCertificateLocalFilePath 
                    CertificatePassword     = if($PortalInternalCertificatePassword -and ($PortalInternalCertificatePassword.GetNetworkCredential().Password -ine 'Placeholder')) { $PortalInternalCertificatePassword } else { $null }
                    SslRootOrIntermediate	= if($PublicKeySSLCertificateFileName){ [string]::Concat('[{"Alias":"AppGW-ExternalDNSCerCert","Path":"', (Join-Path $(Get-Location).Path $PublicKeySSLCertificateFileName).Replace('\', '\\'),'"}]') }else{$null}
                    DependsOn               = $PortalDependsOn
                }
                $PortalDependsOn += '[ArcGIS_Portal_TLS]ArcGIS_Portal_TLS'
            }

            if($env:ComputerName -ieq $PortalHostName -and (-not($IsUpdatingCertificates) -and ($PortalLicenseFileName -and ($PortalLicenseFileName.Trim().Length -gt 0)))) #On add of new machine and not on update certificate op, Perform on First machine
            {
                ArcGIS_PortalSettings PortalSettings
                {
                    ExternalDNSName     = $ExternalDNSHostName
                    PortalContext       = $PortalContext
                    PortalHostName      = $PortalHostName
                    PortalEndPoint      = if($PrivateDNSHostName){ $PrivateDNSHostName }else{ $ExternalDNSHostName }
                    PortalEndPointPort  = 443
                    PortalEndPointContext = $PortalContext
                    PortalAdministrator = $SiteAdministratorCredential
                    DependsOn = $PortalDependsOn
                }
                $PortalDependsOn = '[ArcGIS_PortalSettings]PortalSettings'
                
                ArcGIS_Federation Federate
                {
                    PortalHostName = $PortalHostName
                    ServiceUrlHostName = $ExternalDNSHostName
                    ServiceUrlContext = $ServerContext
                    ServiceUrlPort = 443
                    ServerSiteAdminUrlHostName = if($PrivateDNSHostName){ $PrivateDNSHostName }else{ $ExternalDNSHostName }
                    ServerSiteAdminUrlPort = 443
                    ServerSiteAdminUrlContext =$ServerContext
                    Ensure = 'Present'
                    RemoteSiteAdministrator = $SiteAdministratorCredential
                    SiteAdministrator = $SiteAdministratorCredential
                    ServerRole = 'HOSTING_SERVER'
                    ServerFunctions = 'GeneralPurposeServer'
                    DependsOn = $PortalDependsOn
                }
            }
            
            if(-not($IsUpdatingCertificates))
            {
                $ServicesToStop = @('ArcGIS Server', 'ArcGIS Data Store', 'ArcGISGeoEvent', 'ArcGISGeoEventGateway', 'ArcGIS Notebook Server','ArcGIS Mission Server', 'WorkflowManager')
                if($IsAllInOneBaseDeploy -ieq 'True'){
                    $ServicesToStop = @('ArcGISGeoEvent', 'ArcGISGeoEventGateway', 'ArcGIS Notebook Server', 'ArcGIS Mission Server', 'WorkflowManager')
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
                            DependsOn		= if(-Not($ServiceCredentialIsDomainAccount)){@('[User]ArcGIS_RunAsAccount')}else{@()}
                        }
                    }
                }
            }
        }
	}
}