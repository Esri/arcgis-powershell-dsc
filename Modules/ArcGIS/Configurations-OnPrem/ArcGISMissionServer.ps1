Configuration ArcGISMissionServer
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

        [System.String]
        [ValidateSet("Azure","AWS", "None")]
        $CloudProvider = "None",

        [Parameter(Mandatory=$False)]
        [System.String]
        $CloudNamespace,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSRegion = "None",

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("AccessKey","IAMRole","None")]
        [AllowNull()]
        $AWSCloudAuthenticationType = "None",

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AWSCloudAccessKeyCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("AccessKey", "SASToken", "ServicePrincipal","UserAssignedIdentity","None")]
        [AllowNull()]
        $AzureCloudAuthenticationType = "None",

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureCloudStorageAccountCredential,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureCloudServicePrincipalCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudServicePrincipalTenantId,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudServicePrincipalAuthorityHost,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudUserAssignedIdentityClientId,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $UsesAzureFilesForConfigStore = $False,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $ConfigStoreAzureFilesCredentials,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ConfigStoreAzureFileShareName,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ConfigStoreAzureFilesCloudNamespace,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $UsesAzureFilesForServerDirectories = $False,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $ServerDirectoriesAzureFilesCredentials,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ServerDirectoriesAzureFileShareName,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ServerDirectoriesAzureFilesCloudNamespace,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $UsesSSL = $False,
        
        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $DebugMode = $False
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 5.0.0 -Name ArcGIS_MissionServer, ArcGIS_MissionServerSettings, ArcGIS_Server_TLS, ArcGIS_Service_Account, ArcGIS_xFirewall, ArcGIS_WaitForComponent, ArcGIS_HostNameSettings

    if($UsesAzureFilesForConfigStore){
        $ConfigStorePos = $ConfigStoreAzureFilesCredentials.UserName.IndexOf('.blob.')
        $ConfigStoreAzureFilesEndpoint = if($ConfigStorePos -gt -1){ $ConfigStoreAzureFilesCredentials.UserName.Replace('.blob.','.file.') }else{ $ConfigStoreAzureFilesCredentials.UserName }
        $ConfigStoreAzureFileShareName = $ConfigStoreAzureFileShareName.ToLower() # Azure file shares need to be lower case
        $ConfigStoreLocation = "\\$($ConfigStoreAzureFilesEndpoint)\$($ConfigStoreAzureFileShareName)\$($ConfigStoreAzureFilesCloudNamespace)\missionserver\config-store"
    }

    if($UsesAzureFilesForServerDirectories){
        $ServerDirectoriesPos = $ServerDirectoriesAzureFilesCredentials.UserName.IndexOf('.blob.')
        $ServerDirectoriesAzureFilesEndpoint = if($ServerDirectoriesPos -gt -1){$ServerDirectoriesAzureFilesCredentials.UserName.Replace('.blob.','.file.')}else{ $ServerDirectoriesAzureFilesCredentials.UserName }                   
        $ServerDirectoriesAzureFileShareName = $ServerDirectoriesAzureFileShareName.ToLower() # Azure file shares need to be lower case
        $ServerDirectoriesRootLocation = "\\$($ServerDirectoriesAzureFilesEndpoint)\$($ServerDirectoriesAzureFileShareName)\$($ServerDirectoriesAzureFilesCloudNamespace)\missionserver\server-dirs" 
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
        # Only add config store location if not using Azure Files for config store or is not using a cloud provider for config store
        if($CloudProvider -ieq "None" -and -not($UsesAzureFilesForConfigStore)){
            $DataDirs += @($ConfigStoreLocation)
        }
        # Only add server directories root location if not using Azure Files for server directories
        if(-not($UsesAzureFilesForServerDirectories)){
            $DataDirs = @($ServerDirectoriesRootLocation)
            if($ServerDirectories -ne $null){
                foreach($dir in $ServerDirectories){
                    $DataDirs += $dir.path
                }
            }
        }

        if($null -ne $ServerLogsLocation){
            $DataDirs += @($ServerLogsLocation)
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

        ArcGIS_HostNameSettings MissionServerHostNameSettings{
            ComponentName   = "MissionServer"
            Version         = $Version
            HostName        = $Node.NodeName
            DependsOn       = $DependsOn
        }
        $DependsOn += '[ArcGIS_HostNameSettings]MissionServerHostNameSettings'

        if(-not($ServiceCredentialIsMSA) -and ($UsesAzureFilesForConfigStore -or $UsesAzureFilesForServerDirectories)) 
        {
            if($UsesAzureFilesForConfigStore -and $ConfigStoreAzureFilesEndpoint -and $ConfigStoreAzureFilesCredentials){
                $ConfigStoreFilesStorageAccountName = $ConfigStoreAzureFilesEndpoint.Substring(0, $ConfigStoreAzureFilesEndpoint.IndexOf('.'))
                $ConfigStoreStorageAccountKey       = $ConfigStoreAzureFilesCredentials.GetNetworkCredential().Password

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

            if($UsesAzureFilesForServerDirectories -and $ServerDirectoriesAzureFilesEndpoint -and $ServerDirectoriesAzureFilesCredentials){
                $ServerDirectoriesFilesStorageAccountName = $ServerDirectoriesAzureFilesEndpoint.Substring(0, $ServerDirectoriesAzureFilesEndpoint.IndexOf('.'))
                $ServerDirectoriesStorageAccountKey       = $ServerDirectoriesAzureFilesCredentials.GetNetworkCredential().Password

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
            ServerLogsLocation                      = $ServerLogsLocation
            Join                                    = $Join
            PeerServerHostName                      = $PrimaryServerMachine
            Version                                 = $Version
            DependsOn                               = $DependsOn
            CloudProvider                           = $CloudProvider
            CloudNamespace                          = "$($CloudNamespace)missionserver"
            AWSCloudAuthenticationType              = $AWSCloudAuthenticationType
            AWSRegion                               = $AWSRegion
            AWSCloudAccessKeyCredential             = $AWSCloudAccessKeyCredential
            AzureCloudAuthenticationType            = $AzureCloudAuthenticationType
            AzureCloudStorageAccountCredential      = $AzureCloudStorageAccountCredential
            AzureCloudServicePrincipalCredential    = $AzureCloudServicePrincipalCredential
            AzureCloudServicePrincipalTenantId      = $AzureCloudServicePrincipalTenantId
            AzureCloudServicePrincipalAuthorityHost = $AzureCloudServicePrincipalAuthorityHost
            AzureCloudUserAssignedIdentityClientId  = $AzureCloudUserAssignedIdentityClientId
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
