Configuration ArcGISNotebookServer
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
        [System.Array]
        $ContainerImagePaths,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $ExtractNotebookServerSamplesData = $False,
        
        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $UsesSSL = $False,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $DebugMode = $False
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 5.0.0 -Name ArcGIS_NotebookServer, ArcGIS_NotebookPostInstall, ArcGIS_NotebookServerSettings, ArcGIS_Server_TLS, ArcGIS_Service_Account, ArcGIS_xFirewall, ArcGIS_WaitForComponent, ArcGIS_HostNameSettings

    if($UsesAzureFilesForConfigStore){
        $ConfigStorePos = $ConfigStoreAzureFilesCredentials.UserName.IndexOf('.blob.')
        $ConfigStoreAzureFilesEndpoint = if($ConfigStorePos -gt -1){ $ConfigStoreAzureFilesCredentials.UserName.Replace('.blob.','.file.') }else{ $ConfigStoreAzureFilesCredentials.UserName }
        $ConfigStoreAzureFileShareName = $ConfigStoreAzureFileShareName.ToLower() # Azure file shares need to be lower case
        $ConfigStoreLocation = "\\$($ConfigStoreAzureFilesEndpoint)\$($ConfigStoreAzureFileShareName)\$($ConfigStoreAzureFilesCloudNamespace)\notebookserver\config-store"
    }

    if($UsesAzureFilesForServerDirectories){
        $ServerDirectoriesPos = $ServerDirectoriesAzureFilesCredentials.UserName.IndexOf('.blob.')
        $ServerDirectoriesAzureFilesEndpoint = if($ServerDirectoriesPos -gt -1){$ServerDirectoriesAzureFilesCredentials.UserName.Replace('.blob.','.file.')}else{ $ServerDirectoriesAzureFilesCredentials.UserName }                   
        $ServerDirectoriesAzureFileShareName = $ServerDirectoriesAzureFileShareName.ToLower() # Azure file shares need to be lower case
        $ServerDirectoriesRootLocation = "\\$($ServerDirectoriesAzureFilesEndpoint)\$($ServerDirectoriesAzureFileShareName)\$($ServerDirectoriesAzureFilesCloudNamespace)\notebookserver\server-dirs" 
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

        $IsMultiMachineNotebookServer = (($AllNodes | Measure-Object).Count -gt 1)
        $DependsOn = @()

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

        $DataDirs = @()
        # Only add config store location if not using Azure Files for config store or is not using a cloud provider for config store
        if($CloudProvider -ieq "None" -and -not($UsesAzureFilesForConfigStore)){
            $DataDirs += @($ConfigStoreLocation)
        }
        # Only add server directories root location if not using Azure Files for server directories
        if(-not($UsesAzureFilesForServerDirectories)){
            $DataDirs += @($ServerDirectoriesRootLocation)
            if($ServerDirectories -ne $null){
                foreach($dir in $ServerDirectories){
                    $DataDirs += $dir.path
                }
            }
        }

        if($null -ne $ServerLogsLocation){
            $DataDirs += @($ServerLogsLocation)
        }

        ArcGIS_Service_Account NotebookServer_Service_Account
        {
            Name            = 'ArcGIS Notebook Server'
            RunAsAccount    = $ServiceCredential
            ForceRunAsAccountUpdate = $ForceServiceCredentialUpdate
            IsDomainAccount = $ServiceCredentialIsDomainAccount
            IsMSAAccount    = $ServiceCredentialIsMSA
            SetStartupToAutomatic = $True
            Ensure          = 'Present'
            DataDir         = $DataDirs
            DependsOn       = $DependsOn
        }
        $DependsOn += '[ArcGIS_Service_Account]NotebookServer_Service_Account'

        ArcGIS_HostNameSettings NotebookServerHostNameSettings{
            ComponentName   = "NotebookServer"
            Version         = $Version
            HostName        = $Node.NodeName
            DependsOn       = $DependsOn
        }
        $DependsOn += '[ArcGIS_HostNameSettings]NotebookServerHostNameSettings'

        if(-not($ServiceCredentialIsMSA) -and ($UsesAzureFilesForConfigStore -or $UsesAzureFilesForServerDirectories)) 
        {
            if($UsesAzureFilesForConfigStore -and $ConfigStoreAzureFilesCredentials -and $ConfigStoreCloudStorageCredentials){
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
                    Component = "NotebookServer"
                    InvokingComponent = "NotebookServer"
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
                    ResourceName = "[ArcGIS_NotebookServer]NotebookServer$($PrimaryServerMachine)"
                    NodeName = $PrimaryServerMachine
                    RetryIntervalSec = 60
                    RetryCount = 100
                    DependsOn = $DependsOn
                }
                $DependsOn += "[WaitForAll]WaitForAllServer$($PrimaryServerMachine)"
            }
        }

        ArcGIS_NotebookServer "NotebookServer$($Node.NodeName)"
        {
            Version                                 = $Version
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
            DependsOn                               = $DependsOn
            CloudProvider                           = $CloudProvider
            CloudNamespace                          = "$($CloudNamespace)notebookserver"
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
        $DependsOn += "[ArcGIS_NotebookServer]NotebookServer$($Node.NodeName)"

        if($Node.SSLCertificate -or $Node.SslRootOrIntermediate){
            ArcGIS_Server_TLS "NotebookServer_TLS_$($Node.NodeName)"
            {
                ServerHostName = $Node.NodeName
                SiteAdministrator = $ServerPrimarySiteAdminCredential                         
                WebServerCertificateAlias =  if($Node.SSLCertificate){$Node.SSLCertificate.CName}else{$null}
                CertificateFileLocation = if($Node.SSLCertificate){$Node.SSLCertificate.Path}else{$null}
                CertificatePassword = if($Node.SSLCertificate){$Node.SSLCertificate.Password}else{$null}
                SslRootOrIntermediate = if($Node.SslRootOrIntermediate){$Node.SslRootOrIntermediate}else{$null}
                ServerType = "NotebookServer"
                DependsOn = $DependsOn
            }
            $DependsOn += "[ArcGIS_Server_TLS]NotebookServer_TLS_$($Node.NodeName)"
        }

        $HasContainerImages = ($ContainerImagePaths.Count -gt 0)
        $ExtractSamples = ((@("10.9","10.9.1","11.0","11.1","11.2","11.3") -icontains $Version) -and $ExtractNotebookServerSamplesData -and -not($ServiceCredentialIsMSA))

        if($HasContainerImages -or $ExtractSamples){
            ArcGIS_NotebookPostInstall "NotebookPostInstall$($Node.NodeName)" {
                SiteName            = 'arcgis' 
                ContainerImagePaths = if($HasContainerImages){$ContainerImagePaths}else{$null}
                ExtractSamples      = $ExtractSamples
                DependsOn           = $DependsOn
            }
        }
    }
}
