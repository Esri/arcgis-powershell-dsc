﻿Configuration ArcGISMissionServer
{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServiceCredential,
        
        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ForceServiceCredentialUpdate = $false,
        
        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsMSA = $false,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServerPrimarySiteAdminCredential,

        [Parameter(Mandatory=$True)]
        [System.String]
        $Version,
        
        [Parameter(Mandatory=$False)]
        [System.String]
        $PrimaryServerMachine,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ConfigStoreLocation,

        [Parameter(Mandatory=$True)]
        [System.String]
        $ServerDirectoriesRootLocation,

        [Parameter(Mandatory=$False)]
        [System.Array]
        $ServerDirectories = $null,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ServerLogsLocation = $null,

        [Parameter(Mandatory=$False)]
        [ValidateSet("AzureFiles","AzureBlob","AWSS3DynamoDB")]
        [AllowNull()] 
        [System.String]
        $ConfigStoreCloudStorageType,

        [Parameter(Mandatory=$False)]
        [ValidateSet("AccessKey","ServicePrincipal","UserAssignedIdentity","SASToken")]
        [AllowNull()] 
        $ConfigStoreAzureBlobAuthenticationType,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ConfigStoreAzureBlobUserAssignedIdentityId = $null,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ConfigStoreAzureBlobServicePrincipalTenantId = $null,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $ConfigStoreAzureBlobServicePrincipalCredentials = $null,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ConfigStoreAzureBlobServicePrincipalAuthorityHost = $null,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ConfigStoreAzureFileShareName,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ConfigStoreCloudNamespace,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ConfigStoreAWSRegion,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $ConfigStoreCloudStorageCredentials,

        [Parameter(Mandatory=$False)]
        [ValidateSet("AzureFiles")]
        [AllowNull()] 
        [System.String]
        $ServerDirectoriesCloudStorageType,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ServerDirectoriesAzureFileShareName,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ServerDirectoriesCloudNamespace,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $ServerDirectoriesCloudStorageCredentials,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $UsesSSL = $False,
        
        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $DebugMode = $False
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.5.0 -Name ArcGIS_MissionServer, ArcGIS_MissionServerSettings, ArcGIS_Server_TLS, ArcGIS_Service_Account, ArcGIS_xFirewall, ArcGIS_WaitForComponent

    if($null -ne $ConfigStoreCloudStorageType) {
        if($ConfigStoreCloudStorageType -ieq "AWSS3DynamoDB"){
            $ConfigStoreCloudStorageConnectionString="NAMESPACE=$($ConfigStoreCloudNamespace);REGION=$($ConfigStoreAWSRegion);"
            if($ConfigStoreCloudStorageCredentials){
                $ConfigStoreCloudStorageAccountName = "ACCESS_KEY_ID=$($ConfigStoreCloudStorageCredentials.UserName)"
                $ConfigStoreCloudStorageConnectionSecret="SECRET_KEY=$($ConfigStoreCloudStorageCredentials.GetNetworkCredential().Password);"
            }
        }else{
            if($ConfigStoreCloudStorageCredentials){
                $ConfigStoreAccountName = $ConfigStoreCloudStorageCredentials.UserName
                $ConfigStoreEndpointSuffix = ''
                $ConfigStorePos = $ConfigStoreCloudStorageCredentials.UserName.IndexOf('.blob.')
                if($ConfigStorePos -gt -1) {
                    $ConfigStoreAccountName = $ConfigStoreCloudStorageCredentials.UserName.Substring(0, $ConfigStorePos)
                    $ConfigStoreEndpointSuffix = $ConfigStoreCloudStorageCredentials.UserName.Substring($ConfigStorePos + 6) # Remove the hostname and .blob. suffix to get the storage endpoint suffix
                    $ConfigStoreEndpointSuffix = ";EndpointSuffix=$($ConfigStoreEndpointSuffix)"
                }
        
                if($ConfigStoreCloudStorageType -ieq 'AzureFiles') {
                    $ConfigStoreAzureFilesEndpoint = if($ConfigStorePos -gt -1){$ConfigStoreCloudStorageCredentials.UserName.Replace('.blob.','.file.')}else{$ConfigStoreCloudStorageCredentials.UserName}                   
                    $ConfigStoreAzureFileShareName = $ConfigStoreAzureFileShareName.ToLower() # Azure file shares need to be lower case
                    $ConfigStoreLocation  = "\\$($ConfigStoreAzureFilesEndpoint)\$ConfigStoreAzureFileShareName\$($ConfigStoreCloudNamespace)\missionserver\config-store"
                }
                else {
                    if(-not($Join)){
                        $ConfigStoreCloudStorageConnectionString = "NAMESPACE=$($ConfigStoreCloudNamespace)missionserver$($ConfigStoreEndpointSuffix);DefaultEndpointsProtocol=https;"
                        $ConfigStoreCloudStorageAccountName = "AccountName=$ConfigStoreAccountName"
                        if($ConfigStoreAzureBlobAuthenticationType -ieq 'ServicePrincipal'){
                            $ConfigStoreCloudStorageConnectionString += ";CredentialType=ServicePrincipal;TenantId=$($ConfigStoreAzureBlobServicePrincipalTenantId);ClientId=$($ConfigStoreAzureBlobServicePrincipalCredentials.Username)"
                            if(-not([string]::IsNullOrEmpty($ConfigStoreAzureBlobServicePrincipalAuthorityHost))){
                                $ConfigStoreCloudStorageConnectionString += ";AuthorityHost=$($ConfigStoreAzureBlobServicePrincipalAuthorityHost)" 
                            }
                            $ConfigStoreCloudStorageConnectionSecret = "ClientSecret=$($ConfigStoreAzureBlobServicePrincipalCredentials.GetNetworkCredential().Password)"
                        }elseif($ConfigStoreAzureBlobAuthenticationType -ieq 'UserAssignedIdentity'){
                            $ConfigStoreCloudStorageConnectionString += ";CredentialType=UserAssignedIdentity;ManagedIdentityClientId=$($ConfigStoreAzureBlobUserAssignedIdentityId)"
                            $ConfigStoreCloudStorageConnectionSecret = ""
                        }elseif($ConfigStoreAzureBlobAuthenticationType -ieq 'SASToken'){
                            $ConfigStoreCloudStorageConnectionString += ";CredentialType=SASToken"
                            $ConfigStoreCloudStorageConnectionSecret = "SASToken=$($ConfigStoreCloudStorageCredentials.GetNetworkCredential().Password)"
                        }else{
                            $ConfigStoreCloudStorageConnectionSecret = "AccountKey=$($ConfigStoreCloudStorageCredentials.GetNetworkCredential().Password)"
                        }
                    }
                }
            }
        }
    }
    
    if(($null -ne $ServerDirectoriesCloudStorageType) -and ($ServerDirectoriesCloudStorageType -ieq 'AzureFiles') -and $ServerDirectoriesCloudStorageCredentials)
    {
        $ServerDirectoriesPos = $ServerDirectoriesCloudStorageCredentials.UserName.IndexOf('.blob.')
        $ServerDirectoriesAzureFilesEndpoint = if($ServerDirectoriesPos -gt -1){$ServerDirectoriesCloudStorageCredentials.UserName.Replace('.blob.','.file.')}else{ $ServerDirectoriesCloudStorageCredentials.UserName }                   
        $ServerDirectoriesAzureFileShareName = $ServerDirectoriesAzureFileShareName.ToLower() # Azure file shares need to be lower case
        $ServerDirectoriesRootLocation   = "\\$($ServerDirectoriesAzureFilesEndpoint)\$ServerDirectoriesAzureFileShareName\$($ServerDirectoriesCloudNamespace)\missionserver\server-dirs" 
    }

    Node $AllNodes.NodeName
    {
        $Join = if($Node.NodeName -ine $PrimaryServerMachine) { $true } else { $false }

        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }

        $IsMultiMachineMissionServer = (($AllNodes | Measure-Object).Count -gt 1)
        $DependsOn = @()

        ArcGIS_xFirewall MissionServer_FirewallRules
        {
            Name                  = "ArcGISMissionServer"
            DisplayName           = "ArcGIS for Mission Server"
            DisplayGroup          = "ArcGIS for Mission Server"
            Ensure                = 'Present'
            Access                = "Allow"
            State                 = "Enabled"
            Profile               = ("Domain","Private","Public")
            LocalPort             = ("20443","20300","20301")
            Protocol              = "TCP"
            DependsOn       	   = $DependsOn
        }
        $DependsOn += '[ArcGIS_xFirewall]MissionServer_FirewallRules'

        $DataDirs = @()
        if($null -ne $CloudStorageType){
            if(-not($CloudStorageType -ieq 'AzureFiles')){
                $DataDirs = @($ServerDirectoriesRootLocation)
                if($ServerDirectories -ne $null){
                    foreach($dir in $ServerDirectories){
                        $DataDirs += $dir.path
                    }
                }
            }
        }else{
            $DataDirs = @($ConfigStoreLocation,$ServerDirectoriesRootLocation) 
            if($ServerDirectories -ne $null){
                foreach($dir in $ServerDirectories){
                    $DataDirs += $dir.path
                }
            }
        }

        if($null -ne $ServerLogsLocation){
            $DataDirs += $ServerLogsLocation
        }

        ArcGIS_Service_Account MissionServer_Service_Account
        {
            Name            = 'ArcGIS Mission Server'
            RunAsAccount    = $ServiceCredential
            ForceRunAsAccountUpdate = $ForceServiceCredentialUpdate
            IsDomainAccount = $ServiceCredentialIsDomainAccount
            IsMSAAccount    = $ServiceCredentialIsMSA
            SetStartupToAutomatic = $True
            Ensure          = 'Present'
            DataDir         = $DataDirs
            DependsOn       = $DependsOn
        }
        $DependsOn += '[ArcGIS_Service_Account]MissionServer_Service_Account'

        if(-not($ServiceCredentialIsMSA)) 
        {
            if($ConfigStoreAzureFilesEndpoint -and $ConfigStoreCloudStorageCredentials -and ($ConfigStoreCloudStorageType -ieq 'AzureFiles')){
                $ConfigStoreFilesStorageAccountName = $ConfigStoreAzureFilesEndpoint.Substring(0, $ConfigStoreAzureFilesEndpoint.IndexOf('.'))
                $ConfigStoreStorageAccountKey       = $ConfigStoreCloudStorageCredentials.GetNetworkCredential().Password

                Script PersistConfigStoreCloudStorageCredentials
                {
                    TestScript = { 
                                    $result = cmdkey "/list:$using:ConfigStoreAzureFilesEndpoint"
                                    $result | ForEach-Object{Write-verbose -Message "cmdkey: $_" -Verbose}
                                    if($result -like '*none*')
                                    {
                                        return $false
                                    }
                                    return $true
                                }
                    SetScript = { 
                                    $result = cmdkey "/add:$using:ConfigStoreAzureFilesEndpoint" "/user:$using:ConfigStoreFilesStorageAccountName" "/pass:$using:ConfigStoreStorageAccountKey" 
                                    $result | ForEach-Object{Write-verbose -Message "cmdkey: $_" -Verbose}
                                }
                    GetScript            = { return @{} }                  
                    DependsOn            = $Depends
                    PsDscRunAsCredential = $ServiceCredential # This is critical, cmdkey must run as the service account to persist property
                }              
                $Depends += '[Script]PersistConfigStoreCloudStorageCredentials'
            }

            if($ServerDirectoriesAzureFilesEndpoint -and $ServerDirectoriesCloudStorageCredentials -and ($ServerDirectoriesCloudStorageType -ieq 'AzureFiles')){
                $ServerDirectoriesFilesStorageAccountName = $ServerDirectoriesAzureFilesEndpoint.Substring(0, $ServerDirectoriesAzureFilesEndpoint.IndexOf('.'))
                $ServerDirectoriesStorageAccountKey       = $ServerDirectoriesCloudStorageCredentials.GetNetworkCredential().Password

                Script PersistServerDirectoriesCloudStorageCredentials
                {
                    TestScript = { 
                                    $result = cmdkey "/list:$using:ServerDirectoriesAzureFilesEndpoint"
                                    $result | ForEach-Object{Write-verbose -Message "cmdkey: $_" -Verbose}
                                    if($result -like '*none*')
                                    {
                                        return $false
                                    }
                                    return $true
                                }
                    SetScript = { 
                                    $result = cmdkey "/add:$using:ServerDirectoriesAzureFilesEndpoint" "/user:$using:ServerDirectoriesFilesStorageAccountName" "/pass:$using:ServerDirectoriesStorageAccountKey" 
                                    $result | ForEach-Object{Write-verbose -Message "cmdkey: $_" -Verbose}
                                }
                    GetScript            = { return @{} }                  
                    DependsOn            = $Depends
                    PsDscRunAsCredential = $ServiceCredential # This is critical, cmdkey must run as the service account to persist property
                }              
                $Depends += '[Script]PersistServerDirectoriesCloudStorageCredentials'
            }
        }

        if($Node.NodeName -ine $PrimaryServerMachine)
        {
            if($UsesSSL){
                ArcGIS_WaitForComponent "WaitForServer$($PrimaryServerMachine)"{
                    Component = "MissionServer"
                    InvokingComponent = "MissionServer"
                    ComponentHostName = $PrimaryServerMachine
                    ComponentContext = "arcgis"
                    Credential = $ServerPrimarySiteAdminCredential
                    Ensure = "Present"
                    RetryIntervalSec = 60
                    RetryCount = 100
                }
                $DependsOn += "[ArcGIS_WaitForComponent]WaitForServer$($PrimaryServerMachine)"
            }else{
                WaitForAll "WaitForAllServer$($PrimaryServerMachine)"{
                    ResourceName = "[ArcGIS_MissionServer]MissionServer$($PrimaryServerMachine)"
                    NodeName = $PrimaryServerMachine
                    RetryIntervalSec = 60
                    RetryCount = 100
                    DependsOn = $DependsOn
                }
                $DependsOn += "[WaitForAll]WaitForAllServer$($PrimaryServerMachine)"
            }
        }

        ArcGIS_MissionServer "MissionServer$($Node.NodeName)"
        {
            ServerHostName                          = $Node.NodeName
            Ensure                                  = 'Present'
            SiteAdministrator                       = $ServerPrimarySiteAdminCredential
            ConfigurationStoreLocation              = $ConfigStoreLocation
            ServerDirectoriesRootLocation           = $ServerDirectoriesRootLocation
            ServerDirectories                       = if($ServerDirectories -ne $null){ (ConvertTo-JSON $ServerDirectories -Depth 5) }else{ $null }
            LogLevel                                = if($IsDebugMode) { 'DEBUG' } else { 'WARNING' }
            ConfigStoreCloudStorageConnectionString = if(-not($Join)){ $ConfigStoreCloudStorageConnectionString }else{ $null }
            ConfigStoreCloudStorageAccountName      = if(-not($Join)){ $ConfigStoreCloudStorageAccountName }else{ $null }
            ConfigStoreCloudStorageConnectionSecret = if(-not($Join)){ $ConfigStoreCloudStorageConnectionSecret }else{ $null }
            ServerLogsLocation                      = $ServerLogsLocation
            Join                                    = $Join
            PeerServerHostName                      = $PrimaryServerMachine
            Version                                 = $Version
            DependsOn                               = $DependsOn
        }
        $DependsOn += "[ArcGIS_MissionServer]MissionServer$($Node.NodeName)"

        if($Node.SSLCertificate -or $Node.SslRootOrIntermediate){
            ArcGIS_Server_TLS "MissionServer_TLS_$($Node.NodeName)"
            {
                ServerHostName = $Node.NodeName
                SiteAdministrator = $ServerPrimarySiteAdminCredential                         
                WebServerCertificateAlias =  if($Node.SSLCertificate){$Node.SSLCertificate.CName}else{$null}
                CertificateFileLocation = if($Node.SSLCertificate){$Node.SSLCertificate.Path}else{$null}
                CertificatePassword = if($Node.SSLCertificate){$Node.SSLCertificate.Password}else{$null}
                SslRootOrIntermediate = if($Node.SslRootOrIntermediate){$Node.SslRootOrIntermediate}else{$null}
                ServerType = "MissionServer"
                DependsOn = $DependsOn
            }
            $DependsOn += "[ArcGIS_Server_TLS]MissionServer_TLS_$($Node.NodeName)"
        }
    }
}
