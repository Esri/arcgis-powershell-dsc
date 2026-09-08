Configuration ArcGISNonGISServer
{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServiceCredential,

        [Parameter(Mandatory=$True)]
        [System.String]
        $Version,

        [Parameter(Mandatory=$True)]
        [System.String]
        $ServerType,
        
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

        [parameter(Mandatory = $false)]
        [ValidateSet("OFF","SEVERE","WARNING","INFO","FINE","VERBOSE","DEBUG")]
        [System.String]
        $LogLevel = 'WARNING',

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
        $NotebookServerContainerImagePaths,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $ExtractNotebookServerSamplesData = $False,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $UsesSSL = $False,

        [Parameter(Mandatory=$False)]
        [System.String]
        $VideoServerLiveStreamPorts,
        
        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $DebugMode = $False
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 5.1.2 -Name ArcGIS_NonGISServer, ArcGIS_Server_TLS, ArcGIS_Service_Account, ArcGIS_xFirewall, ArcGIS_WaitForComponent, ArcGIS_HostNameSettings, ArcGIS_NotebookPostInstall
    
    if($UsesAzureFilesForConfigStore){
        $ConfigStorePos = $ConfigStoreAzureFilesCredentials.UserName.IndexOf('.blob.')
        $ConfigStoreAzureFilesEndpoint = if($ConfigStorePos -gt -1){ $ConfigStoreAzureFilesCredentials.UserName.Replace('.blob.','.file.') }else{ $ConfigStoreAzureFilesCredentials.UserName }
        $ConfigStoreAzureFileShareName = $ConfigStoreAzureFileShareName.ToLower() # Azure file shares need to be lower case
        $ConfigStoreLocation = "\\$($ConfigStoreAzureFilesEndpoint)\$($ConfigStoreAzureFileShareName)\$($ConfigStoreAzureFilesCloudNamespace)\$($ServerType.ToLower())\config-store"
    }

    if($UsesAzureFilesForServerDirectories){
        $ServerDirectoriesPos = $ServerDirectoriesAzureFilesCredentials.UserName.IndexOf('.blob.')
        $ServerDirectoriesAzureFilesEndpoint = if($ServerDirectoriesPos -gt -1){$ServerDirectoriesAzureFilesCredentials.UserName.Replace('.blob.','.file.')}else{ $ServerDirectoriesAzureFilesCredentials.UserName }                   
        $ServerDirectoriesAzureFileShareName = $ServerDirectoriesAzureFileShareName.ToLower() # Azure file shares need to be lower case
        $ServerDirectoriesRootLocation = "\\$($ServerDirectoriesAzureFilesEndpoint)\$($ServerDirectoriesAzureFileShareName)\$($ServerDirectoriesAzureFilesCloudNamespace)\$($ServerType.ToLower())\server-dirs" 
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

        $DependsOn = @()

        $FirewallPorts = @()
        $FirewallDisplayGroupAndName = ""
        if($ServerType -ieq "NotebookServer"){
            $FirewallPorts = ("11443")
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
            }
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
            DependsOn       	   = $DependsOn
        }
        $DependsOn += "[ArcGIS_xFirewall]$($ServerType)_FirewallRules"

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

        $ServiceName = (Get-ArcGISServiceName -ComponentName $ServerType)
        ArcGIS_Service_Account "$($ServerType)_Service_Account"
        {
            Name            = $ServiceName
            RunAsAccount    = $ServiceCredential
            ForceRunAsAccountUpdate = $ForceServiceCredentialUpdate
            IsDomainAccount = $ServiceCredentialIsDomainAccount
            IsMSAAccount    = $ServiceCredentialIsMSA
            SetStartupToAutomatic = $True
            Ensure          = 'Present'
            DataDir         = $DataDirs
            DependsOn       = $DependsOn
        }
        $DependsOn += "[ArcGIS_Service_Account]$($ServerType)_Service_Account"

        ArcGIS_HostNameSettings "$($ServerType)_HostNameSettings"{
            ComponentName   = $ServerType
            Version         = $Version
            HostName        = $Node.NodeName
            DependsOn       = $DependsOn
        }
        $DependsOn += "[ArcGIS_HostNameSettings]$($ServerType)_HostNameSettings"

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
                    Component = $ServerType
                    InvokingComponent = $ServerType
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
                    ResourceName = "[ArcGIS_NonGISServer]$($ServerType)$($PrimaryServerMachine)"
                    NodeName = $PrimaryServerMachine
                    RetryIntervalSec = 60
                    RetryCount = 100
                    DependsOn = $DependsOn
                }
                $DependsOn += "[WaitForAll]WaitForAllServer$($PrimaryServerMachine)"
            }
        }

        ArcGIS_NonGISServer "$($ServerType)$($Node.NodeName)"
        {
            ServerHostName                          = $Node.NodeName
            ServerType                              = $ServerType
            Ensure                                  = 'Present'
            SiteAdministrator                       = $ServerPrimarySiteAdminCredential
            ConfigurationStoreLocation              = $ConfigStoreLocation
            ServerDirectoriesRootLocation           = $ServerDirectoriesRootLocation
            ServerDirectories                       = if($ServerDirectories -ne $null){ (ConvertTo-JSON $ServerDirectories -Depth 5) }else{ $null }
            LogLevel                                = if($DebugMode) { 'DEBUG' } else { $LogLevel }
            ServerLogsLocation                      = $ServerLogsLocation
            Join                                    = $Join
            PeerServerHostName                      = $PrimaryServerMachine
            Version                                 = $Version
            DependsOn                               = $DependsOn
            CloudProvider                           = $CloudProvider
            CloudNamespace                          = "$($CloudNamespace)$($ServerType.ToLower())"
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
        $DependsOn += "[ArcGIS_NonGISServer]$($ServerType)$($Node.NodeName)"

        if($Node.SSLCertificate -or $Node.SslRootOrIntermediate){
            ArcGIS_Server_TLS "$($ServerType)_TLS_$($Node.NodeName)"
            {
                ServerHostName = $Node.NodeName
                SiteAdministrator = $ServerPrimarySiteAdminCredential                         
                WebServerCertificateAlias =  if($Node.SSLCertificate){$Node.SSLCertificate.CName}else{$null}
                CertificateFileLocation = if($Node.SSLCertificate){$Node.SSLCertificate.Path}else{$null}
                CertificatePassword = if($Node.SSLCertificate){$Node.SSLCertificate.Password}else{$null}
                SslRootOrIntermediate = if($Node.SslRootOrIntermediate){$Node.SslRootOrIntermediate}else{$null}
                ServerType = $ServerType
                DependsOn = $DependsOn
            }
            $DependsOn += "[ArcGIS_Server_TLS]$($ServerType)_TLS_$($Node.NodeName)"
        }

        if($ServerType -ieq "NotebookServer"){
            $HasContainerImages = ($NotebookServerContainerImagePaths.Count -gt 0)
            $ExtractSamples = ((@("10.9.1","11.0","11.1","11.2","11.3") -icontains $Version) -and $ExtractNotebookServerSamplesData -and -not($ServiceCredentialIsMSA))

            if($HasContainerImages -or $ExtractSamples){
                if($ServiceCredentialIsMSA){
                    ArcGIS_NotebookPostInstall "NotebookPostInstall$($Node.NodeName)" {
                        SiteName            = 'arcgis' 
                        ContainerImagePaths = if($HasContainerImages){$NotebookServerContainerImagePaths}else{$null}
                        ExtractSamples      = $ExtractSamples
                        DependsOn           = $DependsOn
                    }
                }else{
                    ArcGIS_NotebookPostInstall "NotebookPostInstall$($Node.NodeName)" {
                        SiteName            = 'arcgis' 
                        ContainerImagePaths = if($HasContainerImages){$NotebookServerContainerImagePaths}else{$null}
                        ExtractSamples      = $ExtractSamples
                        DependsOn           = $DependsOn
                        PsDscRunAsCredential  = $ServiceCredential # Copy as arcgis account which has access to this share
                    }
                }
            }
        }
    }
}
