﻿Configuration ServerConfiguration
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

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServerContext = 'server'

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
        $ServerLicenseFileUrl

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $ServerMachineNames

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $PublicKeySSLCertificateFileUrl

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $ServerInternalCertificatePassword

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $ExternalDNSHostName    
        
        ,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $EnableLogHarvesterPlugin

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

        ,[Parameter(Mandatory=$false)]
        $CloudStores

        ,[Parameter(Mandatory=$false)]
        $CloudProvidedObjectStore
        
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
    Import-DscResource -name ArcGIS_WindowsService
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_Disk
    Import-DscResource -Name ArcGIS_LogHarvester
    Import-DscResource -Name ArcGIS_ServerSettings
    Import-DscResource -Name ArcGIS_AzureSetupDownloadsFolderManager
    
    $FileShareRootPath = $FileSharePath
    if(-not($UseExistingFileShare)) { 
        $FileSharePath = "\\$($FileShareMachineName)\$($FileShareName)"
        
        $ipaddress = (Resolve-DnsName -Name $FileShareMachineName -Type A -ErrorAction Ignore | Select-Object -First 1).IPAddress    
        if(-not($ipaddress)) { $ipaddress = $FileShareMachineName }
        $FileShareRootPath = "\\$ipaddress\$FileShareName"
    }

    $ServerCertificateFileName  = 'SSLCertificateForServer.pfx'
    $ServerCertificateLocalFilePath =  (Join-Path $env:TEMP $ServerCertificateFileName)

    $FolderName = $ExternalDNSHostName.Substring(0, $ExternalDNSHostName.IndexOf('.')).ToLower()
    $ServerCertificateFileLocation = "$($FileSharePath)\Certs\$ServerCertificateFileName"
    if($UseExistingFileShare)
    {
        $ServerCertificateFileLocation = "$($FileSharePath)\$($FolderName)\$($ServerContext)\$ServerCertificateFileName"
    }

    ##
    ## Download license file and certificate files
    ##
    if($ServerLicenseFileUrl -and ($ServerLicenseFileUrl.Trim().Length -gt 0)) {
        $ServerLicenseFileName = Get-FileNameFromUrl $ServerLicenseFileUrl
        Invoke-WebRequest -OutFile $ServerLicenseFileName -Uri $ServerLicenseFileUrl -UseBasicParsing -ErrorAction Ignore
    }

    if($PublicKeySSLCertificateFileUrl){
		$PublicKeySSLCertificateFileName = Get-FileNameFromUrl $PublicKeySSLCertificateFileUrl
		Invoke-WebRequest -OutFile $PublicKeySSLCertificateFileName -Uri $PublicKeySSLCertificateFileUrl -UseBasicParsing -ErrorAction Ignore
	}
    
    $ConfigStoreLocation  = "$($FileSharePath)\$FolderName\$($ServerContext)\config-store"
    $ServerDirsLocation   = "$($FileSharePath)\$FolderName\$($ServerContext)\server-dirs" 

    $ServerHostName = ($ServerMachineNames -split ',') | Select-Object -First 1    
    $Join = ($env:ComputerName -ine $ServerHostName)
    $IsMultiMachineServer = (($ServerMachineNames -split ',').Length -gt 1)

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
            $ConfigStoreLocation  = "\\$($AzureFilesEndpoint)\$FileShareName\$FolderName\$($ServerContext)\config-store"
            $ServerDirsLocation   = "\\$($AzureFilesEndpoint)\$FileShareName\$FolderName\$($ServerContext)\server-dirs"   
        }
        else {
            if(-not($Join)){
                $ConfigStoreCloudStorageConnectionString = "NAMESPACE=$($Namespace)$($ServerContext)$($EndpointSuffix);DefaultEndpointsProtocol=https;AccountName=$($AccountName)"
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
            RebootNodeIfNeeded = $false
        }
        
        ArcGIS_Disk DiskSizeCheck
        {
            HostName = $env:ComputerName
        }

        ArcGIS_AzureSetupDownloadsFolderManager CleanupDownloadsFolder{
            Version = $Version
            OperationType = 'CleanupDownloadsFolder'
            ComponentNames = if($IsAllInOneBaseDeploy){ "DataStore,Server,Portal" }else{ "Server" }
        }
                
        $HasValidServiceCredential = ($ServiceCredential -and ($ServiceCredential.GetNetworkCredential().Password -ine 'Placeholder'))
        if($HasValidServiceCredential) 
        {
            $ServerDependsOn = @()
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
                    $ServerDependsOn += '[User]ArcGIS_RunAsAccount'
                }

                if($ServerLicenseFileName -and ($ServerLicenseFileName.Trim().Length -gt 0)) 
                {
                    ArcGIS_License ServerLicense
                    {
                        LicenseFilePath = (Join-Path $(Get-Location).Path $ServerLicenseFileName)
                        Ensure          = 'Present'
                        Component       = 'Server'
                    } 
                    $ServerDependsOn += '[ArcGIS_License]ServerLicense'

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
                            DependsOn            = $ServerDependsOn
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
                        ServerDirectoriesRootLocation           = $ServerDirsLocation
                        Join                                    = $Join
                        PeerServerHostName                      = $ServerHostName
                        LogLevel                                = if($DebugMode) { 'DEBUG' } else { 'WARNING' }
                        ConfigStoreCloudStorageConnectionString = if(-not($Join)){ $ConfigStoreCloudStorageConnectionString }else{ $null }
                        ConfigStoreCloudStorageConnectionSecret = if(-not($Join)){ $ConfigStoreCloudStorageConnectionSecret }else{ $null }
                        DependsOn                               = $ServerDependsOn
                    }
                    $ServerDependsOn += '[ArcGIS_Server]Server'
                }
            }
            
            if($IsUpdatingCertificates -or ($ServerLicenseFileName -and ($ServerLicenseFileName.Trim().Length -gt 0))){ #On add of new machine or update certificate op
                
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
                $ServerDependsOn += '[Script]CopyCertificateFileToLocalMachine'

                ArcGIS_Server_TLS Server_TLS
                {
                    ServerHostName             = $env:ComputerName
                    SiteAdministrator          = $SiteAdministratorCredential                         
                    WebServerCertificateAlias  = "ApplicationGateway"
                    CertificateFileLocation    = $ServerCertificateLocalFilePath
                    CertificatePassword        = if($ServerInternalCertificatePassword -and ($ServerInternalCertificatePassword.GetNetworkCredential().Password -ine 'Placeholder')) { $ServerInternalCertificatePassword } else { $null }
                    ServerType                 = "GeneralPurposeServer"
                    SslRootOrIntermediate	   = if($PublicKeySSLCertificateFileName){ [string]::Concat('[{"Alias":"AppGW-ExternalDNSCerCert","Path":"', (Join-Path $(Get-Location).Path $PublicKeySSLCertificateFileName).Replace('\', '\\'),'"}]') }else{$null}
                    DependsOn                  = $ServerDependsOn
                }
                $ServerDependsOn += '[ArcGIS_Server_TLS]Server_TLS'
            }

            #On add of new machine and not on update certificate op, Perform on First machine
            if($env:ComputerName -ieq $ServerHostName -and (-not($IsUpdatingCertificates) -and ($ServerLicenseFileName -and ($ServerLicenseFileName.Trim().Length -gt 0)))){ 
                ArcGIS_ServerSettings ServerSettings
                {
                    ServerContext       = $ServerContext
                    ServerHostName      = $ServerHostName
                    ExternalDNSName     = $ExternalDNSHostName
                    SiteAdministrator   = $SiteAdministratorCredential
                    DependsOn           = $ServerDependsOn
                }
            }

            if(-not($IsUpdatingCertificates)){
                $ServicesToStop = @('Portal for ArcGIS', 'ArcGIS Data Store', 'ArcGISGeoEvent', 'ArcGISGeoEventGateway', 'ArcGIS Notebook Server', 'ArcGIS Mission Server', 'WorkflowManager')
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
                DependsOn                   = $CloudStoreRegisterDependsOn
            }
            $CloudStoreRegisterDependsOn += @("[ArcGIS_EGDB]RegisterEGDB")
        }


        if((($CloudProvidedObjectStore.Count -gt 0) -or ($CloudStores -and $CloudStores.stores -and $CloudStores.stores.Count -gt 0)) -and ($ServerHostName -ieq $env:ComputerName)) 
        {
            $DataStoreItems = @()
            $CacheDirectories = @()

            $CloudStoresObj = $()
            if($CloudProvidedObjectStore -and $CloudProvidedObjectStore.Count -gt 0){
                $CloudStoresObj += @($CloudProvidedObjectStore)
            }
            if($CloudStores -and $CloudStores.stores -and $CloudStores.stores.Count -gt 0){
                $CloudStoresObj += $CloudStores.stores
            }

            foreach($cloudStore in $CloudStoresObj) 
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
                    DataStoreType = if($cloudStore.StoreType -ieq 'ObjectStore'){ 'ObjectStore' }else{ 'CloudStore' }  
                    ConnectionString = (ConvertTo-Json $ConnectionStringObject -Compress -Depth 10)
                    ConnectionSecret = $ConnectionSecret
                }
                if($cloudStore.StoreType -ieq 'CacheDirectory'){
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
                    DependsOn = $ServerDependsOn
                }
                $ServerDependsOn += @("[ArcGIS_DataStoreItemServer]$($dataStoreItem.Name)")				
            }

            if($CacheDirectories.Length -gt 0){
                ArcGIS_Server_RegisterDirectories "RegisterCacheDirectory"
                { 
                    ServerHostName = $ServerHostName
                    Ensure = 'Present'
                    SiteAdministrator = $SiteAdministratorCredential
                    DirectoriesJSON = ($CacheDirectories | ConvertTo-Json)
                    DependsOn = $ServerDependsOn
                }
                $ServerDependsOn += @("[ArcGIS_Server_RegisterDirectories]RegisterCacheDirectory")		
            }
        }

	}
}
