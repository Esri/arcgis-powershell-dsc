<#
    Exercises Invoke-ArcGISConfiguration from JSON input through workflow dispatch.
    These are orchestration unit tests, not deployment integration tests: configuration
    files, DNS/credentials as needed, and DSC execution are mocked in each scenario.
    Assertions verify selected stages, their ordering, forwarded settings, and early exits.

    Import the checked-out implementation so private helpers can be mocked in ArcGIS
    module scope. Run with Windows PowerShell 5.1/Pester 3.4.0; see ../README.md.
#>
$moduleScriptPath = Join-Path $PSScriptRoot '..\..\Modules\ArcGIS\ArcGIS.psm1'

Import-Module $moduleScriptPath

InModuleScope ArcGIS {
    # Serialize the same AllNodes/ConfigData shape consumed by the public entry point.
    # Depth 10 retains nested credentials and role settings; the JSON is later returned
    # by Get-Content mocks rather than written to a real configuration file.
    function New-MainConfigurationJson {
        param(
            [array]$Nodes,
            [hashtable]$ConfigData
        )

        @{ AllNodes = $Nodes; ConfigData = $ConfigData } | ConvertTo-Json -Depth 10
    }

    function New-ServerConfigurationData {
        return @{
            Version = '11.5'
            ServerRole = 'GeneralPurposeServer'
            ServerContext = 'server'
            Credentials = @{}
            Server = @{
                ConfigStoreLocation = 'C:\arcgis\config-store'
                ServerDirectoriesRootLocation = 'C:\arcgis\directories'
                RegisteredDirectories = @()
                EnableHTTPSOnly = $true
                EnableHSTS = $true
                SharedKey = 'shared-key'
            }
            WebAdaptor = @{}
        }
    }

    Describe 'Invoke-ArcGISConfiguration install, license, and configure flows' {
        BeforeEach {
            # Version checks have their own helper tests. Replace them here to keep
            # workflow assertions independent of target machines and CIM connections.
            Mock Assert-PowerShellVersionIs51 {}
            Mock Assert-TargetNodePowerShellVersionIs51 {}
            Mock Get-DownloadsInstallsConfigurationData { @{ AllNodes = @(@{ NodeName = 'test-node'; PSDscAllowPlainTextPassword = $true }); ConfigData = @{} } }
            $script:configurationCalls = @()
            # Preserve dispatch order and arguments for assertions below. Returning
            # true models successful DSC execution; individual failure cases override
            # this mock for a specific stage and assert later stages never run.
            Mock Invoke-DSCJob {
                $script:configurationCalls += [PSCustomObject]@{ Name = $ConfigurationName; Arguments = $Arguments }
                $true
            }
        }

        It 'runs install, license, server, machine and TLS settings, and site settings in order for a single Server deployment' {
            $configData = New-ServerConfigurationData
            $configData.Server.LicenseFilePath = 'C:\licenses\server.json'
            $configData.Server.SocMaximumHeapSize = 96
            $configData.Server.RegisteredDirectories = @(@{ Name = 'output'; PhysicalPath = 'C:\arcgis\output' })
            $script:configurationJson = New-MainConfigurationJson -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') }) -ConfigData $configData
            Mock Get-Content { $script:configurationJson }
            Mock Get-ServerEndpointDetails {
                @{ ServerServiceURL = 'server-01.contoso.com'; ServerServiceURLPort = 6443; ServerServiceURLContext = 'arcgis'; ServerSiteAdminURL = 'server-01.contoso.com'; ServerSiteAdminURLPort = 6443; ServerSiteAdminContext = 'arcgis' }
            }

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\server.json' -Mode InstallLicenseConfigure

            $script:configurationCalls.Count | Should Be 5
            $script:configurationCalls[0].Name | Should Be 'ArcGISInstall'
            $script:configurationCalls[1].Name | Should Be 'ArcGISLicense'
            $script:configurationCalls[2].Name | Should Be 'ArcGISServer'
            $script:configurationCalls[3].Name | Should Be 'ArcGISServerMachineAndTLSSettings'
            $script:configurationCalls[4].Name | Should Be 'ArcGISServerSettings'
            $script:configurationCalls[1].Arguments.ConfigurationData.AllNodes[0].ServerLicenseFilePath | Should Be 'C:\licenses\server.json'
            $script:configurationCalls[2].Arguments.ContainsKey('EnableHTTPSOnly') | Should Be $false
            $script:configurationCalls[2].Arguments.ContainsKey('SocMaximumHeapSize') | Should Be $false
            $script:configurationCalls[2].Arguments.ContainsKey('RegisteredDirectories') | Should Be $false
            $script:configurationCalls[3].Arguments.EnableHTTPSOnly | Should Be $true
            $script:configurationCalls[3].Arguments.EnableHSTS | Should Be $true
            $script:configurationCalls[3].Arguments.SocMaximumHeapSize | Should Be 96
            $script:configurationCalls[4].Arguments.SharedKey | Should Be 'shared-key'
            $directories = $script:configurationCalls[4].Arguments.RegisteredDirectories | ConvertFrom-Json
            @($directories).Count | Should Be 1
            $directories.Name | Should Be 'output'
            $directories.PhysicalPath | Should Be 'C:\arcgis\output'
        }

        It 'applies machine and TLS settings one Server node at a time before site settings' {
            $configData = New-ServerConfigurationData
            $configData.Server.ConfigStoreLocation = '\\fileserver\config-store'
            $configData.Server.ServerDirectoriesRootLocation = '\\fileserver\directories'
            $configData.Server.Remove('EnableHTTPSOnly')
            $configData.Server.Remove('EnableHSTS')
            $configData.Server.PrimarySiteAdmin = @{ UserName = 'siteadmin'; Password = 'site-password' }
            $script:configurationJson = New-MainConfigurationJson -Nodes @(
                @{ NodeName = 'server-01'; Role = @('Server'); SslCertificates = @(@{ Target = 'Server'; CNameFQDN = 'server-01.contoso.com'; Path = 'C:\certificates\server-01.pfx' }) }
                @{ NodeName = 'server-02'; Role = @('Server') }
            ) -ConfigData $configData
            Mock Get-Content { $script:configurationJson }
            Mock Get-PasswordFromObject { ConvertTo-SecureString 'site-password' -AsPlainText -Force }
            Mock Get-ServerEndpointDetails {
                @{ ServerServiceURL = 'server-01.contoso.com'; ServerServiceURLPort = 6443; ServerServiceURLContext = 'arcgis'; ServerSiteAdminURL = 'server-01.contoso.com'; ServerSiteAdminURLPort = 6443; ServerSiteAdminContext = 'arcgis' }
            }

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\server.json' -Mode InstallLicenseConfigure

            $script:configurationCalls.Name | Should Be @('ArcGISInstall', 'ArcGISLicense', 'ArcGISServer', 'ArcGISServerMachineAndTLSSettings', 'ArcGISServerMachineAndTLSSettings', 'ArcGISServerSettings')
            $machineCalls = @($script:configurationCalls | Where-Object { $_.Name -eq 'ArcGISServerMachineAndTLSSettings' })
            $machineCalls.Count | Should Be 2
            $machineCalls[0].Arguments.ConfigurationData.AllNodes[0].NodeName | Should Be 'server-01'
            $machineCalls[0].Arguments.ConfigurationData.AllNodes[0].SSLCertificate.Path | Should Be 'C:\certificates\server-01.pfx'
            $machineCalls[0].Arguments.ConfigurationData.AllNodes[0].SSLCertificate.CName | Should Be 'server-01.contoso.com'
            $machineCalls[1].Arguments.ConfigurationData.AllNodes[0].NodeName | Should Be 'server-02'
            foreach ($call in $machineCalls) {
                $call.Arguments.ConfigurationData.AllNodes.Count | Should Be 1
                $call.Arguments.ConfigurationData.AllNodes[0].PSDscAllowPlainTextPassword | Should Be $true
                $call.Arguments.Version | Should Be '11.5'
                $call.Arguments.ServerType | Should Be 'Server'
                $call.Arguments.SocMaximumHeapSize | Should Be 0
                $call.Arguments.EnableHTTPSOnly | Should Be $false
                $call.Arguments.EnableHSTS | Should Be $false
                $call.Arguments.ServerPrimarySiteAdminCredential.UserName | Should Be 'siteadmin'
                $call.Arguments.ServerPrimarySiteAdminCredential.GetNetworkCredential().Password | Should Be 'site-password'
            }
        }

        It 'stops later Server phases when <Stage> fails' -TestCases @(
            @{ Stage = 'ArcGISServer'; ExpectedNames = @('ArcGISInstall', 'ArcGISLicense', 'ArcGISServer') }
            @{ Stage = 'ArcGISServerMachineAndTLSSettings'; ExpectedNames = @('ArcGISInstall', 'ArcGISLicense', 'ArcGISServer', 'ArcGISServerMachineAndTLSSettings') }
        ) {
            param($Stage, $ExpectedNames)
            $configData = New-ServerConfigurationData
            $configData.Server.ConfigStoreLocation = '\\fileserver\config-store'
            $configData.Server.ServerDirectoriesRootLocation = '\\fileserver\directories'
            $script:configurationJson = New-MainConfigurationJson -Nodes @(
                @{ NodeName = 'server-01'; Role = @('Server') }
                @{ NodeName = 'server-02'; Role = @('Server') }
            ) -ConfigData $configData
            Mock Get-Content { $script:configurationJson }
            Mock Invoke-DSCJob {
                $script:configurationCalls += [PSCustomObject]@{ Name = $ConfigurationName; Arguments = $Arguments }
                $false
            } -ParameterFilter { $ConfigurationName -eq $Stage }

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\server.json' -Mode InstallLicenseConfigure

            $script:configurationCalls.Name | Should Be $ExpectedNames
            Assert-MockCalled Invoke-DSCJob -Exactly 0 -Scope It -ParameterFilter { $ConfigurationName -eq 'ArcGISServerSettings' }
        }

        It 'skips licensing and configuration when Install mode is requested' {
            $script:configurationJson = New-MainConfigurationJson -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') }) -ConfigData (New-ServerConfigurationData)
            Mock Get-Content { $script:configurationJson }

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\server.json' -Mode Install

            $script:configurationCalls.Count | Should Be 1
            $script:configurationCalls[0].Name | Should Be 'ArcGISInstall'
        }

        It 'uses the uninstall configuration without install-only arguments' {
            $script:configurationJson = New-MainConfigurationJson -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') }) -ConfigData (New-ServerConfigurationData)
            Mock Get-Content { $script:configurationJson }

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\server.json' -Mode Uninstall

            $script:configurationCalls.Count | Should Be 1
            $script:configurationCalls[0].Name | Should Be 'ArcGISUninstall'
            $script:configurationCalls[0].Arguments.ContainsKey('SkipPatchInstalls') | Should Be $false
            $script:configurationCalls[0].Arguments.ContainsKey('EnableMSILogging') | Should Be $false
        }

        It 'downloads setups before installation when configured and forwards the AGO credential' {
            $configData = New-ServerConfigurationData
            $configData.DownloadSetups = $true
            $configData.Credentials = @{ AGOCredential = @{ UserName = 'ago-user'; Password = 'ago-password' } }
            $script:configurationJson = New-MainConfigurationJson -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') }) -ConfigData $configData
            Mock Get-Content { $script:configurationJson }
            Mock Get-DownloadsInstallsConfigurationData { @{ AllNodes = @(@{ NodeName = 'test-node'; PSDscAllowPlainTextPassword = $true }); ConfigData = @{ DownloadSetups = $true } } }
            Mock Get-PasswordFromObject { ConvertTo-SecureString 'ago-password' -AsPlainText -Force }

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\server.json' -Mode Install

            $script:configurationCalls.Count | Should Be 2
            $script:configurationCalls[0].Name | Should Be 'ArcGISDownloads'
            $script:configurationCalls[0].Arguments.AGOCredential.UserName | Should Be 'ago-user'
            $script:configurationCalls[0].Arguments.AGOCredential.GetNetworkCredential().Password | Should Be 'ago-password'
            $script:configurationCalls[1].Name | Should Be 'ArcGISInstall'
            Assert-MockCalled Get-DownloadsInstallsConfigurationData -Exactly 2 -Scope It
        }

        It 'stops before installation when setup downloads fail' {
            $configData = New-ServerConfigurationData
            $configData.DownloadSetups = $true
            $configData.Credentials = @{ AGOCredential = @{ UserName = 'ago-user'; Password = 'ago-password' } }
            $script:configurationJson = New-MainConfigurationJson -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') }) -ConfigData $configData
            Mock Get-Content { $script:configurationJson }
            Mock Get-DownloadsInstallsConfigurationData { @{ AllNodes = @(@{ NodeName = 'test-node'; PSDscAllowPlainTextPassword = $true }); ConfigData = @{ DownloadSetups = $true } } }
            Mock Get-PasswordFromObject { ConvertTo-SecureString 'ago-password' -AsPlainText -Force }
            Mock Invoke-DSCJob { $false } -ParameterFilter { $ConfigurationName -eq 'ArcGISDownloads' }

            $exception = $null
            try { Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\server.json' -Mode Install }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Setup Downloads failed'
            Assert-MockCalled Invoke-DSCJob -Exactly 0 -Scope It -ParameterFilter { $ConfigurationName -eq 'ArcGISInstall' }
        }

        It 'runs Portal configuration, TLS settings, and portal settings after installation' {
            $configData = @{
                Version = '11.5'
                Credentials = @{}
                PortalContext = 'portal'
                Portal = @{
                    ContentDirectoryLocation = 'C:\arcgis\portal-content'
                    PortalAdministrator = @{ UserName = 'portal-admin'; Password = 'portal-password'; Email = 'admin@contoso.com'; SecurityQuestionIndex = 1; SecurityAnswer = 'answer' }
                    EnableHSTS = $true
                    EnableAutomaticAccountCreation = $true
                    DisableAnonymousAccess = $true
                }
                WebAdaptor = @{}
            }
            $script:configurationJson = New-MainConfigurationJson -Nodes @(@{ NodeName = 'portal-01'; Role = @('Portal') }) -ConfigData $configData
            Mock Get-Content { $script:configurationJson }
            Mock Get-PasswordFromObject { ConvertTo-SecureString 'portal-password' -AsPlainText -Force }
            Mock Resolve-SecretFromObject { ConvertTo-SecureString 'answer' -AsPlainText -Force }
            Mock Get-FQDN { 'portal-01.contoso.com' }

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\portal.json' -Mode InstallLicenseConfigure -UseSSL

            $script:configurationCalls.Count | Should Be 4
            $script:configurationCalls[0].Name | Should Be 'ArcGISInstall'
            $script:configurationCalls[1].Name | Should Be 'ArcGISPortal'
            $script:configurationCalls[2].Name | Should Be 'ArcGISPortalTLSSettings'
            $script:configurationCalls[3].Name | Should Be 'ArcGISPortalSettings'
            $script:configurationCalls[1].Arguments.UsesSSL | Should Be $true
            $script:configurationCalls[2].Arguments.EnableHSTS | Should Be $true
            $script:configurationCalls[3].Arguments.EnableAutomaticAccountCreation | Should Be $true
            $script:configurationCalls[3].Arguments.DisableAnonymousAccess | Should Be $true
        }

        It 'configures a relational Data Store with its backup collection after server setup' {
            $configData = New-ServerConfigurationData
            $configData.DataStore = @{
                ContentDirectoryLocation = 'C:\arcgis\datastore-content'
                Backups = @{ Relational = @(@{ Type = 'fs'; Name = 'local'; Location = 'C:\backups'; IsDefault = $true }) }
            }
            $script:configurationJson = New-MainConfigurationJson -Nodes @(
                @{ NodeName = 'server-01'; Role = @('Server') }
                @{ NodeName = 'datastore-01'; Role = @('DataStore'); DataStoreTypes = @('Relational') }
            ) -ConfigData $configData
            Mock Get-Content { $script:configurationJson }
            Mock Get-ServerEndpointDetails {
                @{ ServerServiceURL = 'server-01.contoso.com'; ServerServiceURLPort = 6443; ServerServiceURLContext = 'arcgis'; ServerSiteAdminURL = 'server-01.contoso.com'; ServerSiteAdminURLPort = 6443; ServerSiteAdminContext = 'arcgis' }
            }
            Mock Invoke-DataStoreConfigureScript { $true }

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\datastore.json' -Mode InstallLicenseConfigure

            $script:configurationCalls[0].Name | Should Be 'ArcGISInstall'
            $script:configurationCalls[1].Name | Should Be 'ArcGISLicense'
            $script:configurationCalls[2].Name | Should Be 'ArcGISServer'
            $script:configurationCalls[3].Name | Should Be 'ArcGISServerMachineAndTLSSettings'
            $script:configurationCalls[4].Name | Should Be 'ArcGISServerSettings'
            Assert-MockCalled Invoke-DataStoreConfigureScript -Exactly 1 -Scope It -ParameterFilter {
                $DataStoreType -eq 'Relational' -and
                $PrimaryDataStoreMachine -eq 'datastore-01' -and
                $Backups.Count -eq 1 -and
                $Backups[0].Name -eq 'local'
            }
        }

        It 'orchestrates a full on-prem topology through file sharing, components, every Data Store type, and federation' {
            $configData = @{
                Version = '11.5'
                ServerRole = 'GeneralPurposeServer'
                ServerContext = 'server'
                PortalContext = 'portal'
                FileShareName = 'ArcGISShare'
                FileShareLocalPath = 'C:\ArcGISShare'
                Credentials = @{}
                Server = @{
                    LicenseFilePath = 'C:\licenses\server.json'
                    ConfigStoreLocation = '\\fileserver\config-store'
                    ServerDirectoriesRootLocation = '\\fileserver\directories'
                    RegisteredDirectories = @()
                }
                Portal = @{
                    ContentDirectoryLocation = '\\fileserver\portal-content'
                    PortalAdministrator = @{ UserName = 'portal-admin'; Password = 'portal-password'; Email = 'admin@contoso.com'; SecurityQuestionIndex = 1; SecurityAnswer = 'answer' }
                }
                DataStore = @{ ContentDirectoryLocation = '\\fileserver\datastore-content' }
                WebAdaptor = @{ AdminAccessEnabled = $true; WebSiteId = 2 }
            }
            $script:configurationJson = New-MainConfigurationJson -Nodes @(
                @{ NodeName = 'files-01'; Role = @('FileShare') }
                @{ NodeName = 'server-01'; Role = @('Server') }
                @{ NodeName = 'portal-01'; Role = @('Portal') }
                @{ NodeName = 'web-01'; Role = @('WebAdaptor'); WebAdaptorConfig = @(@{ Role = 'Server' }, @{ Role = 'Portal' }) }
                @{ NodeName = 'datastore-01'; Role = @('DataStore'); DataStoreTypes = @('Relational', 'SpatioTemporal', 'TileCache', 'GraphStore', 'ObjectStore') }
            ) -ConfigData $configData
            Mock Get-Content { $script:configurationJson }
            Mock Get-FQDN { "$MachineName.contoso.com" }
            Mock Get-PasswordFromObject { ConvertTo-SecureString 'secret' -AsPlainText -Force }
            Mock Resolve-SecretFromObject { ConvertTo-SecureString 'answer' -AsPlainText -Force }
            Mock Get-ServerEndpointDetails {
                @{ ServerServiceURL = 'web-01.contoso.com'; ServerServiceURLPort = 443; ServerServiceURLContext = 'server'; ServerSiteAdminURL = 'web-01.contoso.com'; ServerSiteAdminURLPort = 443; ServerSiteAdminContext = 'server' }
            }
            $script:dataStoreTypes = @()
            Mock Invoke-DataStoreConfigureScript { $script:dataStoreTypes += $DataStoreType; $true }

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\enterprise.json' -Mode InstallLicenseConfigure

            $script:configurationCalls.Name | Should Be @('ArcGISInstall', 'ArcGISLicense', 'ArcGISFileShare', 'ArcGISServer', 'ArcGISServerMachineAndTLSSettings', 'ArcGISServerSettings', 'ArcGISPortal', 'ArcGISPortalTLSSettings', 'ArcGISPortalSettings', 'ArcGISWebAdaptor', 'ArcGISFederation')
            $script:configurationCalls[2].Arguments.FilePaths | Should Be '\\fileserver\config-store,\\fileserver\directories,\\fileserver\portal-content'
            $script:configurationCalls[3].Arguments.OpenFirewallPorts | Should Be $true
            $script:configurationCalls[9].Arguments.OverrideHTTPSBinding | Should Be $true
            $script:configurationCalls[10].Arguments.IsHostingServer | Should Be $true
            $script:dataStoreTypes | Should Be @('Relational', 'SpatioTemporal', 'TileCache', 'GraphStore', 'ObjectStore')
        }

        It 'builds all Azure cloud-native Server credentials and endpoint arguments before DSC dispatch' {
            $configData = @{
                Version = '12.0'
                ServerRole = 'GeneralPurposeServer'
                Credentials = @{}
                Server = @{
                    RegisteredDirectories = @()
                    CloudServices = @{
                        Provider = 'Azure'
                        Namespace = 'arcgis-system'
                        Tags = @{ Environment = 'test' }
                        LocalDirectory = 'C:\arcgis\cloud'
                        Azure = @{
                            Credential = @{ Type = 'ServicePrincipal'; ServicePrincipal = @{ ClientId = 'client-id'; ClientSecret = 'client-secret'; TenantId = 'tenant-id'; AuthorityHost = 'https://login.microsoftonline.com' } }
                            StorageAccount = @{ ContainerName = 'arcgis'; RootDir = 'content'; AccountEndpointURL = 'https://storage.blob.core.windows.net'; RegionEndpointURL = 'https://storage.eastus.blob.core.windows.net'; Credential = @{ Type = 'StorageAccountKey'; StorageAccountKey = @{ AccountName = 'storage'; AccountKey = 'storage-key' } } }
                            CosmosDBAccount = @{ AccountEndpointURL = 'https://cosmos.documents.azure.com'; DatabaseId = 'arcgis'; ConnectionMode = 'Gateway'; RegionEndpointURL = 'https://cosmos.eastus.documents.azure.com'; Credential = @{ Type = 'CosmosDBAccountKey'; CosmosDBAccountKey = @{ AccountName = 'cosmos'; AccountKey = 'cosmos-key' } } }
                            ServiceBusNamespace = @{ ServiceBusEndpointUrl = 'sb://arcgis.servicebus.windows.net'; RegionEndpointURL = 'sb://arcgis-east.servicebus.windows.net'; Credential = @{ Type = 'ServiceBusNamespaceAccessKey'; ServiceBusNamespaceAccessKey = @{ SharedAccessKeyName = 'RootManageSharedAccessKey'; SharedAccessKey = 'service-bus-key' } } }
                        }
                    }
                }
                WebAdaptor = @{}
            }
            $script:configurationJson = New-MainConfigurationJson -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') }) -ConfigData $configData
            Mock Get-Content { $script:configurationJson }
            Mock Resolve-SecretFromObject { ConvertTo-SecureString 'resolved-secret' -AsPlainText -Force }
            Mock Get-ServerEndpointDetails {
                @{ ServerServiceURL = 'server-01.contoso.com'; ServerServiceURLPort = 6443; ServerServiceURLContext = 'arcgis'; ServerSiteAdminURL = 'server-01.contoso.com'; ServerSiteAdminURLPort = 6443; ServerSiteAdminContext = 'arcgis' }
            }

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\cloud-server.json' -Mode InstallLicenseConfigure

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $ConfigurationName -eq 'ArcGISServer' -and
                $Arguments.IsCloudNativeServer -and
                $Arguments.CloudProvider -eq 'Azure' -and
                $Arguments.CloudNamespace -eq 'arcgis-system' -and
                $Arguments.AzureCloudAuthenticationType -eq 'ServicePrincipal' -and
                $Arguments.AzureCloudServicePrincipalCredential.UserName -eq 'client-id' -and
                $Arguments.AzureCloudNativeStorageAccountCredential.UserName -eq 'storage' -and
                $Arguments.AzureCloudNativeCosmosDBAccountCredential.UserName -eq 'cosmos' -and
                $Arguments.AzureCloudNativeServiceBusNamespaceCredential.UserName -eq 'RootManageSharedAccessKey'
            }
        }

        It 'builds AWS cloud-native Server credentials and service endpoints before DSC dispatch' {
            $configData = @{
                Version = '12.0'
                ServerRole = 'GeneralPurposeServer'
                Credentials = @{}
                Server = @{
                    RegisteredDirectories = @()
                    CloudServices = @{
                        Provider = 'AWS'
                        Namespace = 'arcgis-system'
                        AWS = @{
                            Region = 'us-east-1'
                            Credential = @{ Type = 'AccessKey'; AccessKey = @{ AccessKeyId = 'access-key'; SecretKey = 'secret-key' } }
                            AmazonS3 = @{ BucketName = 'arcgis-content'; RegionEndpointURL = 'https://s3.us-east-1.amazonaws.com'; RootDir = 'content' }
                            AmazonDynamoDB = @{ RegionEndpointURL = 'https://dynamodb.us-east-1.amazonaws.com' }
                            AmazonQueueService = @{ RegionEndpointURL = 'https://sqs.us-east-1.amazonaws.com' }
                        }
                    }
                }
                WebAdaptor = @{}
            }
            $script:configurationJson = New-MainConfigurationJson -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') }) -ConfigData $configData
            Mock Get-Content { $script:configurationJson }
            Mock Resolve-SecretFromObject { ConvertTo-SecureString 'resolved-secret' -AsPlainText -Force }
            Mock Get-ServerEndpointDetails {
                @{ ServerServiceURL = 'server-01.contoso.com'; ServerServiceURLPort = 6443; ServerServiceURLContext = 'arcgis'; ServerSiteAdminURL = 'server-01.contoso.com'; ServerSiteAdminURLPort = 6443; ServerSiteAdminContext = 'arcgis' }
            }

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\aws-server.json' -Mode InstallLicenseConfigure

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $ConfigurationName -eq 'ArcGISServer' -and
                $Arguments.IsCloudNativeServer -and
                $Arguments.CloudProvider -eq 'AWS' -and
                $Arguments.AWSRegion -eq 'us-east-1' -and
                $Arguments.AWSCloudAuthenticationType -eq 'AccessKey' -and
                $Arguments.AWSCloudAccessKeyCredential.UserName -eq 'access-key' -and
                $Arguments.AWSCloudNativeS3BucketName -eq 'arcgis-content' -and
                $Arguments.AWSCloudNativeDynamoDBRegionEndpointURL -eq 'https://dynamodb.us-east-1.amazonaws.com' -and
                $Arguments.AWSCloudNativeQueueServiceRegionEndpointURL -eq 'https://sqs.us-east-1.amazonaws.com'
            }
        }

        It 'registers an Azure user-assigned-identity Object Store before applying Server settings' {
            $configData = New-ServerConfigurationData
            $configData.Version = '11.5'
            $configData.Server.DataStoreItems = @(
                @{
                    Type = 'ObjectStore'
                    Name = 'imagery'
                    ForceUpdate = $true
                    CloudStoreAccount = @{
                        Type = 'Azure'
                        AzureStorage = @{
                            AccountName = 'storage'
                            AccountEndpoint = 'https://storage.blob.core.windows.net'
                            DefaultEndpointsProtocol = 'https'
                            OverrideEndpoint = $false
                            ContainerName = 'imagery'
                            FolderPath = 'items'
                            AuthenticationType = 'UserAssignedIdentity'
                            UserAssignedIdentityClientId = 'identity-client-id'
                        }
                    }
                }
            )
            $script:configurationJson = New-MainConfigurationJson -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') }) -ConfigData $configData
            Mock Get-Content { $script:configurationJson }
            Mock Get-ServerEndpointDetails {
                @{ ServerServiceURL = 'server-01.contoso.com'; ServerServiceURLPort = 6443; ServerServiceURLContext = 'arcgis'; ServerSiteAdminURL = 'server-01.contoso.com'; ServerSiteAdminURLPort = 6443; ServerSiteAdminContext = 'arcgis' }
            }

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\object-store.json' -Mode InstallLicenseConfigure

            $script:configurationCalls.Name | Should Be @('ArcGISInstall', 'ArcGISLicense', 'ArcGISServer', 'ArcGISServerMachineAndTLSSettings', 'ArcGISServerDataStoreItem', 'ArcGISServerSettings')
            $script:configurationCalls[4].Arguments.DataStoreType | Should Be 'ObjectStore'
            $script:configurationCalls[4].Arguments.Name | Should Be 'imagery'
            $script:configurationCalls[4].Arguments.IsCloudStore | Should Be $true
            $script:configurationCalls[4].Arguments.ForceUpdate | Should Be $true
            $script:configurationCalls[4].Arguments.ConnectionString | Should Match 'UserAssignedIdentity'
            $script:configurationCalls[4].Arguments.ConnectionString | Should Match 'identity-client-id'
            $script:configurationCalls[4].Arguments.ConnectionSecret | Should Be $null
        }

        It 'builds Server and Portal Azure Blob storage credentials for service-principal and Azure Files paths' {
            $configData = @{
                Version = '11.5'
                ServerRole = 'GeneralPurposeServer'
                Credentials = @{}
                Server = @{
                    RegisteredDirectories = @()
                    ConfigStoreCloudStorageAccount = @{
                        CloudStorageType = 'AzureBlob'
                        AzureBlobAuthenticationType = 'ServicePrincipal'
                        UserName = 'config-placeholder'
                        AzureBlobServicePrincipal = @{ ClientId = 'config-client'; ClientSecret = 'config-secret'; TenantId = 'config-tenant'; AuthorityHost = 'https://login.microsoftonline.com' }
                    }
                    ServerDirectoriesCloudStorageAccount = @{
                        CloudStorageType = 'AzureFiles'
                        UserName = 'files-user'
                        Password = 'files-password'
                        AzureFileShareName = 'server-directories'
                        CloudNamespace = 'arcgis'
                    }
                }
                Portal = @{
                    PortalAdministrator = @{ UserName = 'portal-admin'; Password = 'portal-password'; Email = 'admin@contoso.com'; SecurityQuestionIndex = 1; SecurityAnswer = 'answer' }
                    PortalContentCloudStorageAccount = @{
                        CloudStorageType = 'AzureBlob'
                        AzureBlobAuthenticationType = 'ServicePrincipal'
                        UserName = 'portal-placeholder'
                        CloudNamespace = 'arcgis'
                        AzureBlobServicePrincipal = @{ ClientId = 'portal-client'; ClientSecret = 'portal-secret'; TenantId = 'portal-tenant'; AuthorityHost = 'https://login.microsoftonline.com' }
                    }
                }
                WebAdaptor = @{}
            }
            $script:configurationJson = New-MainConfigurationJson -Nodes @(
                @{ NodeName = 'server-01'; Role = @('Server') }
                @{ NodeName = 'portal-01'; Role = @('Portal') }
            ) -ConfigData $configData
            Mock Get-Content { $script:configurationJson }
            Mock Get-FQDN { "$MachineName.contoso.com" }
            Mock Get-PasswordFromObject { ConvertTo-SecureString 'resolved-password' -AsPlainText -Force }
            Mock Resolve-SecretFromObject { ConvertTo-SecureString 'resolved-secret' -AsPlainText -Force }
            Mock Get-ServerEndpointDetails {
                @{ ServerServiceURL = 'server-01.contoso.com'; ServerServiceURLPort = 6443; ServerServiceURLContext = 'arcgis'; ServerSiteAdminURL = 'server-01.contoso.com'; ServerSiteAdminURLPort = 6443; ServerSiteAdminContext = 'arcgis' }
            }

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\azure-storage.json' -Mode InstallLicenseConfigure

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $ConfigurationName -eq 'ArcGISServer' -and
                $Arguments.CloudProvider -eq 'Azure' -and
                $Arguments.AzureCloudAuthenticationType -eq 'ServicePrincipal' -and
                $Arguments.AzureCloudStorageAccountCredential.UserName -eq 'config-placeholder' -and
                $Arguments.AzureCloudServicePrincipalCredential.UserName -eq 'config-client' -and
                $Arguments.AzureCloudServicePrincipalTenantId -eq 'config-tenant' -and
                $Arguments.UsesAzureFilesForServerDirectories -and
                $Arguments.ServerDirectoriesAzureFileShareName -eq 'server-directories' -and
                $Arguments.ServerDirectoriesAzureFilesCredentials.UserName -eq 'files-user'
            }
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $ConfigurationName -eq 'ArcGISPortal' -and
                $Arguments.CloudStorageType -eq 'AzureBlob' -and
                $Arguments.ContentStoreAzureBlobAuthenticationType -eq 'ServicePrincipal' -and
                $Arguments.ContentStoreAzureBlobServicePrincipalTenantId -eq 'portal-tenant' -and
                $Arguments.ContentStoreAzureBlobServicePrincipalCredentials.UserName -eq 'portal-client' -and
                $Arguments.CloudStorageCredentials.UserName -eq 'portal-placeholder'
            }
        }

        It 'licenses standalone single-use ArcGIS Pro and License Manager nodes without a configure step' {
            $configData = @{
                Version = '11.5'
                ProVersion = '3.6'
                LicenseManagerVersion = '2025.0'
                Credentials = @{}
                Pro = @{ AuthorizationType = 'SINGLE_USE'; LicenseFilePath = 'C:\licenses\pro.json'; LicensePassword = 'pro-license-password' }
                LicenseManager = @{ LicenseFilePath = 'C:\licenses\license-manager.lic' }
                WebAdaptor = @{}
            }
            $script:configurationJson = New-MainConfigurationJson -Nodes @(
                @{ NodeName = 'pro-01'; Role = @('Pro') }
                @{ NodeName = 'license-01'; Role = @('LicenseManager') }
            ) -ConfigData $configData
            Mock Get-Content { $script:configurationJson }
            Mock Resolve-SecretFromObject { ConvertTo-SecureString 'resolved-license-password' -AsPlainText -Force }

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\desktop.json' -Mode InstallLicenseConfigure

            $script:configurationCalls.Name | Should Be @('ArcGISInstall', 'ArcGISLicense')
            $licenseNodes = $script:configurationCalls[1].Arguments.ConfigurationData.AllNodes
            $licenseNodes.Count | Should Be 2
            $licenseNodes[0].Role[0] | Should Be 'Pro'
            $licenseNodes[0].ProVersion | Should Be '3.6'
            $licenseNodes[0].ProLicenseFilePath | Should Be 'C:\licenses\pro.json'
            $licenseNodes[0].ProLicensePassword.GetNetworkCredential().Password | Should Be 'resolved-license-password'
            $licenseNodes[1].Role[0] | Should Be 'LicenseManager'
            $licenseNodes[1].LicenseManagerVersion | Should Be '2025.0'
            $licenseNodes[1].LicenseManagerLicenseFilePath | Should Be 'C:\licenses\license-manager.lic'
        }

        It 'passes directory, authenticated email, and forward-proxy settings to Portal configuration' {
            $configData = @{
                Version = '11.5'
                Credentials = @{ ADServiceUser = @{ UserName = 'CONTOSO\directory-reader'; Password = 'directory-password' } }
                PortalContext = 'portal'
                Portal = @{
                    ContentDirectoryLocation = 'C:\arcgis\portal-content'
                    PortalAdministrator = @{ UserName = 'portal-admin'; Password = 'portal-password'; Email = 'admin@contoso.com'; SecurityQuestionIndex = 1; SecurityAnswer = 'answer' }
                    InternalLoadBalancer = 'portal-internal.contoso.com'
                    InternalLoadBalancerPort = 7443
                    EnableAutomaticAccountCreation = $true
                    DefaultRoleForUser = 'org_user'
                    DefaultUserLicenseTypeIdForUser = 'creatorUT'
                    DisableServiceDirectory = $true
                    DisableAnonymousAccess = $true
                    EmailSettings = @{ SMTPServerAddress = 'smtp.contoso.com'; From = 'arcgis@contoso.com'; Label = 'ArcGIS'; AuthenticationRequired = $true; UserName = 'smtp-user'; Password = 'smtp-password'; SMTPPort = 587; EncryptionMethod = 'STARTTLS' }
                    ForwardProxy = @{ HttpProxyHost = 'http-proxy.contoso.com'; HttpProxyPort = 8080; HttpsProxyHost = 'https-proxy.contoso.com'; HttpsProxyPort = 8443; NonProxyHosts = 'localhost'; HttpProxyCredential = @{ UserName = 'http-user'; Password = 'http-password' }; HttpsProxyCredential = @{ UserName = 'https-user'; Password = 'https-password' } }
                }
                WebAdaptor = @{}
            }
            $script:configurationJson = New-MainConfigurationJson -Nodes @(@{ NodeName = 'portal-01'; Role = @('Portal') }) -ConfigData $configData
            Mock Get-Content { $script:configurationJson }
            Mock Get-FQDN { 'portal-01.contoso.com' }
            Mock Get-PasswordFromObject { ConvertTo-SecureString 'resolved-password' -AsPlainText -Force }
            Mock Resolve-SecretFromObject { ConvertTo-SecureString 'resolved-secret' -AsPlainText -Force }

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\portal-settings.json' -Mode InstallLicenseConfigure

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $ConfigurationName -eq 'ArcGISPortalSettings' -and
                $Arguments.ADServiceCredential.UserName -eq 'CONTOSO\directory-reader' -and
                $Arguments.EnableEmailSettings -and
                $Arguments.EmailSettingsCredential.UserName -eq 'smtp-user' -and
                $Arguments.EmailSettingsSMTPPort -eq 587 -and
                $Arguments.EmailSettingsEncryptionMethod -eq 'STARTTLS' -and
                $Arguments.HttpProxyHost -eq 'http-proxy.contoso.com' -and
                $Arguments.HttpProxyPort -eq [uint32]8080 -and
                $Arguments.HttpsProxyCredential.UserName -eq 'https-user' -and
                $Arguments.EnableAutomaticAccountCreation -and
                $Arguments.DisableServiceDirectory -and
                $Arguments.DisableAnonymousAccess
            }
        }
    }

    Describe 'Invoke-ArcGISConfiguration specialized Server phases' {
        BeforeEach {
            Mock Assert-PowerShellVersionIs51 {}
            Mock Assert-TargetNodePowerShellVersionIs51 {}
            Mock Get-DownloadsInstallsConfigurationData { @{ AllNodes = @(); ConfigData = @{} } }
            Mock Get-PasswordFromObject { ConvertTo-SecureString 'phase-secret' -AsPlainText -Force }
            Mock Get-Content { $script:phaseConfigurationJson }
            Mock Get-ServerEndpointDetails {
                @{ ServerServiceURL = 'server-01.example.test'; ServerServiceURLPort = 6443; ServerServiceURLContext = 'arcgis'; ServerSiteAdminURL = 'server-01.example.test'; ServerSiteAdminURLPort = 6443; ServerSiteAdminContext = 'arcgis' }
            }
            $script:phaseCalls = @()
            Mock Invoke-DSCJob {
                $script:phaseCalls += [PSCustomObject]@{ Name = $ConfigurationName; Folder = $ConfigurationFolderPath; Arguments = $Arguments }
                $true
            }
        }

        It 'selects Notebook post-install work for <Case>' -TestCases @(
            @{ Case = 'images only'; Version = '11.5'; Images = @('C:\images\standard.tar', 'C:\images\advanced.tar'); Samples = $false; MSA = $false; ExpectedPostInstall = $true }
            @{ Case = 'samples before the last supported version'; Version = '11.2'; Images = @(); Samples = $true; MSA = $false; ExpectedPostInstall = $true }
            @{ Case = 'samples at the last supported version'; Version = '11.3'; Images = @(); Samples = $true; MSA = $false; ExpectedPostInstall = $true }
            @{ Case = 'images and samples'; Version = '11.3'; Images = @('C:\images\standard.tar'); Samples = $true; MSA = $false; ExpectedPostInstall = $true }
            @{ Case = 'no images or samples'; Version = '11.5'; Images = @(); Samples = $false; MSA = $false; ExpectedPostInstall = $false }
            @{ Case = 'MSA samples without images'; Version = '11.3'; Images = @(); Samples = $true; MSA = $true; ExpectedPostInstall = $false }
            @{ Case = 'MSA images without samples'; Version = '11.5'; Images = @('C:\images\standard.tar'); Samples = $false; MSA = $true; ExpectedPostInstall = $true }
            @{ Case = 'MSA images with samples'; Version = '11.3'; Images = @('C:\images\standard.tar'); Samples = $true; MSA = $true; ExpectedPostInstall = $true }
        ) {
            param($Case, $Version, $Images, $Samples, $MSA, $ExpectedPostInstall)
            $configData = New-ServerConfigurationData
            $configData.Version = $Version
            $configData.ServerRole = 'NotebookServer'
            $configData.Credentials.ServiceAccount = @{ UserName = 'CONTOSO\notebook$'; Password = 'dummy'; IsMSAAccount = $MSA }
            $configData.Server.PrimarySiteAdmin = @{ UserName = 'notebookadmin'; Password = 'dummy' }
            $configData.Server.ContainerImagePaths = $Images
            $configData.Server.Installer = @{}
            if ($Samples) { $configData.Server.Installer.NotebookServerSamplesDataPath = 'C:\installers\samples.exe' }
            $script:phaseConfigurationJson = New-MainConfigurationJson -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') }) -ConfigData $configData

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\notebook.json' -Mode InstallLicenseConfigure

            $expectedNames = @('ArcGISInstall', 'ArcGISLicense', 'ArcGISNonGISServer')
            if ($ExpectedPostInstall) { $expectedNames += 'ArcGISNotebookPostInstall' }
            $expectedNames += 'ArcGISServerSettings'
            $script:phaseCalls.Name | Should Be $expectedNames
            $script:phaseCalls[2].Arguments.ServerType | Should Be 'NotebookServer'
            $script:phaseCalls[2].Arguments.ContainsKey('NotebookServerContainerImagePaths') | Should Be $false
            $script:phaseCalls[2].Arguments.ContainsKey('ExtractNotebookServerSamplesData') | Should Be $false
            if ($ExpectedPostInstall) {
                $postInstall = $script:phaseCalls[3]
                $postInstall.Folder | Should Be 'Configurations-OnPrem'
                $postInstall.Arguments.Version | Should Be $Version
                $postInstall.Arguments.ContainerImagePaths.Count | Should Be $Images.Count
                if ($Images.Count -gt 0) { $postInstall.Arguments.ContainerImagePaths | Should Be $Images }
                $postInstall.Arguments.ExtractSamples | Should Be $Samples
                $postInstall.Arguments.ServiceCredentialIsMSA | Should Be $MSA
                $postInstall.Arguments.ServiceCredential.UserName | Should Be 'CONTOSO\notebook$'
                $postInstall.Arguments.ServerPrimarySiteAdminCredential.UserName | Should Be 'notebookadmin'
                $postInstall.Arguments.ServerPrimarySiteAdminCredential.GetNetworkCredential().Password | Should Be 'phase-secret'
                $postInstall.Arguments.ConfigurationData.AllNodes.Count | Should Be 1
                $postInstall.Arguments.ConfigurationData.AllNodes[0].NodeName | Should Be 'server-01'
            } else {
                Assert-MockCalled Invoke-DSCJob -Exactly 0 -Scope It -ParameterFilter { $ConfigurationName -eq 'ArcGISNotebookPostInstall' }
            }
        }

        It 'rejects Notebook sample extraction after the supported version boundary' {
            $configData = New-ServerConfigurationData
            $configData.Version = '11.4'
            $configData.ServerRole = 'NotebookServer'
            $configData.Server.Installer = @{ NotebookServerSamplesDataPath = 'C:\installers\samples.exe' }
            $script:phaseConfigurationJson = New-MainConfigurationJson -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') }) -ConfigData $configData

            { Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\notebook.json' -Mode InstallLicenseConfigure } |
                Should Throw 'Notebook Server Samples Data Path is not supported for 11.4.'

            $script:phaseCalls.Name | Should Be @('ArcGISInstall', 'ArcGISLicense')
        }

        It 'skips machine and TLS settings for <ServerRole> without certificates' -TestCases @(
            @{ ServerRole = 'NotebookServer' }
            @{ ServerRole = 'MissionServer' }
            @{ ServerRole = 'VideoServer' }
            @{ ServerRole = 'DataPipelinesServer' }
            @{ ServerRole = 'VelocityServer' }
        ) {
            param($ServerRole)
            $configData = New-ServerConfigurationData
            $configData.ServerRole = $ServerRole
            $script:phaseConfigurationJson = New-MainConfigurationJson -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') }) -ConfigData $configData

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\specialized-server.json' -Mode InstallLicenseConfigure

            $script:phaseCalls.Name | Should Be @('ArcGISInstall', 'ArcGISLicense', 'ArcGISNonGISServer', 'ArcGISServerSettings')
            $script:phaseCalls[2].Arguments.ServerType | Should Be $ServerRole
            $script:phaseCalls[3].Arguments.ServerType | Should Be $ServerRole
            Assert-MockCalled Invoke-DSCJob -Exactly 0 -Scope It -ParameterFilter { $ConfigurationName -eq 'ArcGISServerMachineAndTLSSettings' }
        }

        It 'selects only specialized Server nodes with leaf or root certificates' {
            $configData = New-ServerConfigurationData
            $configData.ServerRole = 'NotebookServer'
            $configData.Server.ConfigStoreLocation = '\\fileserver\config-store'
            $configData.Server.ServerDirectoriesRootLocation = '\\fileserver\directories'
            $script:phaseConfigurationJson = New-MainConfigurationJson -Nodes @(
                @{ NodeName = 'server-01'; Role = @('Server') }
                @{ NodeName = 'server-02'; Role = @('Server'); SslCertificates = @(@{ Target = 'Server'; CNameFQDN = 'server-02.example.test'; Path = 'C:\certificates\server-02.pfx' }) }
                @{ NodeName = 'server-03'; Role = @('Server'); SslCertificates = @(@{ Target = 'Server'; SslRootOrIntermediate = @(@{ Alias = 'root-ca'; Path = 'C:\certificates\root.cer' }) }) }
            ) -ConfigData $configData

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\notebook.json' -Mode InstallLicenseConfigure

            $script:phaseCalls.Name | Should Be @('ArcGISInstall', 'ArcGISLicense', 'ArcGISNonGISServer', 'ArcGISServerMachineAndTLSSettings', 'ArcGISServerMachineAndTLSSettings', 'ArcGISServerSettings')
            $tlsCalls = @($script:phaseCalls | Where-Object { $_.Name -eq 'ArcGISServerMachineAndTLSSettings' })
            $tlsCalls[0].Arguments.ConfigurationData.AllNodes[0].NodeName | Should Be 'server-02'
            $tlsCalls[0].Arguments.ConfigurationData.AllNodes[0].SSLCertificate.Path | Should Be 'C:\certificates\server-02.pfx'
            $tlsCalls[1].Arguments.ConfigurationData.AllNodes[0].NodeName | Should Be 'server-03'
            $roots = $tlsCalls[1].Arguments.ConfigurationData.AllNodes[0].SslRootOrIntermediate | ConvertFrom-Json
            $roots.Alias | Should Be 'root-ca'
            $roots.Path | Should Be 'C:\certificates\root.cer'
            foreach ($call in $tlsCalls) {
                $call.Arguments.ConfigurationData.AllNodes.Count | Should Be 1
                $call.Arguments.ServerType | Should Be 'NotebookServer'
                $call.Arguments.ContainsKey('SocMaximumHeapSize') | Should Be $false
                $call.Arguments.ContainsKey('EnableHTTPSOnly') | Should Be $false
                $call.Arguments.ContainsKey('EnableHSTS') | Should Be $false
            }
        }

        It 'stops Notebook configuration when <Stage> fails' -TestCases @(
            @{ Stage = 'ArcGISNonGISServer'; ExpectedNames = @('ArcGISInstall', 'ArcGISLicense', 'ArcGISNonGISServer') }
            @{ Stage = 'ArcGISServerMachineAndTLSSettings'; ExpectedNames = @('ArcGISInstall', 'ArcGISLicense', 'ArcGISNonGISServer', 'ArcGISServerMachineAndTLSSettings') }
            @{ Stage = 'ArcGISNotebookPostInstall'; ExpectedNames = @('ArcGISInstall', 'ArcGISLicense', 'ArcGISNonGISServer', 'ArcGISServerMachineAndTLSSettings', 'ArcGISNotebookPostInstall') }
        ) {
            param($Stage, $ExpectedNames)
            $configData = New-ServerConfigurationData
            $configData.ServerRole = 'NotebookServer'
            $configData.Server.ContainerImagePaths = @('C:\images\standard.tar')
            $script:phaseConfigurationJson = New-MainConfigurationJson -Nodes @(
                @{ NodeName = 'server-01'; Role = @('Server'); SslCertificates = @(@{ Target = 'Server'; CNameFQDN = 'server-01.example.test'; Path = 'C:\certificates\server.pfx' }) }
            ) -ConfigData $configData
            Mock Invoke-DSCJob {
                $script:phaseCalls += [PSCustomObject]@{ Name = $ConfigurationName; Arguments = $Arguments }
                $false
            } -ParameterFilter { $ConfigurationName -eq $Stage }

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\notebook.json' -Mode InstallLicenseConfigure

            $script:phaseCalls.Name | Should Be $ExpectedNames
            Assert-MockCalled Invoke-DSCJob -Exactly 0 -Scope It -ParameterFilter { $ConfigurationName -eq 'ArcGISServerSettings' }
        }

        It 'dispatches Server extensions for <Case>' -TestCases @(
            @{ Case = 'standalone GeoEvent'; Role = 'GeoEvent'; AdditionalRoles = @(); ExpectedExtensions = @('ArcGISGeoEvent') }
            @{ Case = 'standalone Workflow Manager'; Role = 'WorkflowManagerServer'; AdditionalRoles = @(); ExpectedExtensions = @('ArcGISWorkflowManager') }
            @{ Case = 'combined general-purpose extensions'; Role = 'GeneralPurposeServer'; AdditionalRoles = @('GeoEvent', 'WorkflowManagerServer'); ExpectedExtensions = @('ArcGISGeoEvent', 'ArcGISWorkflowManager') }
            @{ Case = 'additional roles on an unrelated Server type'; Role = 'ImageServer'; AdditionalRoles = @('GeoEvent', 'WorkflowManagerServer'); ExpectedExtensions = @() }
        ) {
            param($Case, $Role, $AdditionalRoles, $ExpectedExtensions)
            $configData = New-ServerConfigurationData
            $configData.ServerRole = $Role
            $configData.AdditionalServerRoles = $AdditionalRoles
            $configData.Credentials.ServiceAccount = @{ UserName = 'CONTOSO\svc-arcgis'; Password = 'dummy'; IsDomainAccount = $true; ForceUpdate = $true }
            $configData.Server.PrimarySiteAdmin = @{ UserName = 'siteadmin'; Password = 'dummy' }
            $configData.GeoEventServer = @{ WebSocketContextUrl = 'wss://events.example.test/geoevent' }
            $script:phaseConfigurationJson = New-MainConfigurationJson -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') }) -ConfigData $configData

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\extensions.json' -Mode InstallLicenseConfigure

            $script:phaseCalls.Name | Should Be (@('ArcGISInstall', 'ArcGISLicense', 'ArcGISServer', 'ArcGISServerMachineAndTLSSettings') + $ExpectedExtensions + @('ArcGISServerSettings'))
            $extensionCalls = @($script:phaseCalls | Where-Object { $_.Name -in @('ArcGISGeoEvent', 'ArcGISWorkflowManager') })
            $extensionCalls.Count | Should Be $ExpectedExtensions.Count
            foreach ($call in $extensionCalls) {
                $call.Folder | Should Be 'Configurations-OnPrem'
                $call.Arguments.ConfigurationData.AllNodes[0].NodeName | Should Be 'server-01'
                $call.Arguments.Version | Should Be '11.5'
                $call.Arguments.ServiceCredential.UserName | Should Be 'CONTOSO\svc-arcgis'
                $call.Arguments.ServiceCredential.GetNetworkCredential().Password | Should Be 'phase-secret'
                $call.Arguments.ServiceCredentialIsDomainAccount | Should Be $true
                $call.Arguments.ServiceCredentialIsMSA | Should Be $false
                $call.Arguments.ForceServiceCredentialUpdate | Should Be $true
                if ($call.Name -eq 'ArcGISGeoEvent') {
                    $call.Arguments.WebSocketContextUrl | Should Be 'wss://events.example.test/geoevent'
                    $call.Arguments.ServerPrimarySiteAdminCredential.UserName | Should Be 'siteadmin'
                } else {
                    $call.Arguments.ContainsKey('WebSocketContextUrl') | Should Be $false
                    $call.Arguments.ContainsKey('ServerPrimarySiteAdminCredential') | Should Be $false
                }
            }
        }

        It 'stops later extension and site settings when <Stage> fails' -TestCases @(
            @{ Stage = 'ArcGISServerMachineAndTLSSettings'; ExpectedNames = @('ArcGISInstall', 'ArcGISLicense', 'ArcGISServer', 'ArcGISServerMachineAndTLSSettings') }
            @{ Stage = 'ArcGISGeoEvent'; ExpectedNames = @('ArcGISInstall', 'ArcGISLicense', 'ArcGISServer', 'ArcGISServerMachineAndTLSSettings', 'ArcGISGeoEvent') }
            @{ Stage = 'ArcGISWorkflowManager'; ExpectedNames = @('ArcGISInstall', 'ArcGISLicense', 'ArcGISServer', 'ArcGISServerMachineAndTLSSettings', 'ArcGISGeoEvent', 'ArcGISWorkflowManager') }
        ) {
            param($Stage, $ExpectedNames)
            $configData = New-ServerConfigurationData
            $configData.AdditionalServerRoles = @('GeoEvent', 'WorkflowManagerServer')
            $script:phaseConfigurationJson = New-MainConfigurationJson -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') }) -ConfigData $configData
            Mock Invoke-DSCJob {
                $script:phaseCalls += [PSCustomObject]@{ Name = $ConfigurationName; Arguments = $Arguments }
                $false
            } -ParameterFilter { $ConfigurationName -eq $Stage }

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\extensions.json' -Mode InstallLicenseConfigure

            $script:phaseCalls.Name | Should Be $ExpectedNames
            Assert-MockCalled Invoke-DSCJob -Exactly 0 -Scope It -ParameterFilter { $ConfigurationName -eq 'ArcGISServerSettings' }
        }
    }

    Describe 'Invoke-ArcGISConfiguration WebGISDR and upgrade dispatch' {
        BeforeEach {
            Mock Assert-PowerShellVersionIs51 {}
            Mock Assert-TargetNodePowerShellVersionIs51 {}
            Mock Get-DownloadsInstallsConfigurationData { @{ AllNodes = @(); ConfigData = @{} } }
            Mock Get-PasswordFromObject { ConvertTo-SecureString 'secret' -AsPlainText -Force }
            Mock Invoke-DSCJob { $true }
        }

        It 'runs WebGISDR export with the configured Portal node, action, and timeout' {
            $configData = @{
                Version = '11.5'
                Credentials = @{}
                Portal = @{
                    Installer = @{ InstallDir = 'C:\ArcGIS\Portal' }
                    WebGISDR = @{ PropertiesFilePath = 'C:\backup\webgisdr.properties'; TimeoutInMinutes = 15; RunAsAccount = @{ UserName = 'CONTOSO\backup'; Password = 'backup-password' } }
                }
            }
            $script:configurationJson = New-MainConfigurationJson -Nodes @(@{ NodeName = 'portal-01'; Role = @('Portal') }) -ConfigData $configData
            Mock Get-Content { $script:configurationJson }

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\portal.json' -Mode WebGISDRExport

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $ConfigurationName -eq 'ArcGISWebGISDR' -and
                $Arguments.WebGISDRAction -eq 'Export' -and
                $Arguments.WebGISDRTimeoutInMinutes -eq 15 -and
                $Arguments.PortalInstallDirectory -eq 'C:\ArcGIS\Portal' -and
                $Arguments.ConfigurationData.AllNodes[0].NodeName -eq 'portal-01' -and
                $Arguments.RunAsCredential.UserName -eq 'CONTOSO\backup'
            }
        }

        It 'rejects WebGISDR when its run-as account is a managed service account' {
            $configData = @{
                Version = '11.5'
                Credentials = @{}
                Portal = @{ WebGISDR = @{ RunAsAccount = @{ UserName = 'CONTOSO\backup$'; IsMSAAccount = $true } } }
            }
            $script:configurationJson = New-MainConfigurationJson -Nodes @(@{ NodeName = 'portal-01'; Role = @('Portal') }) -ConfigData $configData
            Mock Get-Content { $script:configurationJson }
            $exception = $null

            try { Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\portal.json' -Mode WebGISDRImport }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be "DSC Automation module doesn't support use of WebGISDR when using MSA account for service account."
            Assert-MockCalled Invoke-DSCJob -Exactly 0 -Scope It
        }

        It 'dispatches hosting and federated upgrade steps in their required order' {
            $hosting = New-MainConfigurationJson -Nodes @(
                @{ NodeName = 'portal-01'; Role = @('Portal') }
                @{ NodeName = 'server-01'; Role = @('Server') }
                @{ NodeName = 'datastore-01'; Role = @('DataStore'); DataStoreTypes = @('Relational') }
            ) -ConfigData @{ Version = '11.5'; OldVersion = '11.4'; Credentials = @{} }
            $federated = New-MainConfigurationJson -Nodes @(@{ NodeName = 'federated-01'; Role = @('Server') }) -ConfigData @{ Version = '11.5'; OldVersion = '11.4'; Credentials = @{} }
            Mock Get-Content { if($Path -eq 'C:\hosting.json') { $hosting } else { $federated } }
            $script:upgradeCalls = @()
            Mock Invoke-PortalUpgradeScript { $script:upgradeCalls += 'Portal'; $true }
            Mock Invoke-ServerUpgradeScript { $script:upgradeCalls += "Server:$((@($cf.AllNodes | Where-Object { $_.Role -icontains 'Server' })[0]).NodeName)"; $true }
            Mock Invoke-DataStoreUpgradeScript { $script:upgradeCalls += 'DataStore'; $true }
            Mock Invoke-JavaWebAdaptorUninstallUpgradeScript { $script:upgradeCalls += "Java:$($cf.AllNodes[0].NodeName)"; $true }

            Invoke-ArcGISConfiguration -ConfigurationParametersFile @('C:\hosting.json', 'C:\federated.json') -Mode Upgrade -EnableMSILogging -UseSSL -DebugSwitch

            $script:upgradeCalls.Count | Should Be 6
            $script:upgradeCalls[0] | Should Be 'Portal'
            $script:upgradeCalls[1] | Should Be 'Server:server-01'
            $script:upgradeCalls[2] | Should Be 'DataStore'
            $script:upgradeCalls[3] | Should Be 'Java:portal-01'
            $script:upgradeCalls[4] | Should Be 'Server:federated-01'
            $script:upgradeCalls[5] | Should Be 'Java:federated-01'
            Assert-MockCalled Invoke-PortalUpgradeScript -Exactly 1 -Scope It -ParameterFilter { $UseWinRMSSL -and $DebugMode -and $EnableMSILogging }
            Assert-MockCalled Invoke-ServerUpgradeScript -Exactly 2 -Scope It -ParameterFilter { $UseWinRMSSL -and $DebugMode -and $EnableMSILogging }
        }

        It 'stops upgrade dispatch after the hosting Portal upgrade fails' {
            $script:configurationJson = New-MainConfigurationJson -Nodes @(
                @{ NodeName = 'portal-01'; Role = @('Portal') }
                @{ NodeName = 'server-01'; Role = @('Server') }
                @{ NodeName = 'datastore-01'; Role = @('DataStore'); DataStoreTypes = @('Relational') }
            ) -ConfigData @{ Version = '11.5'; OldVersion = '11.4'; Credentials = @{} }
            Mock Get-Content { $script:configurationJson }
            Mock Invoke-PortalUpgradeScript { $false }
            Mock Invoke-ServerUpgradeScript { throw 'Server upgrade should not run' }
            Mock Invoke-DataStoreUpgradeScript { throw 'Data Store upgrade should not run' }

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\hosting.json' -Mode Upgrade

            Assert-MockCalled Invoke-PortalUpgradeScript -Exactly 1 -Scope It
            Assert-MockCalled Invoke-ServerUpgradeScript -Exactly 0 -Scope It
            Assert-MockCalled Invoke-DataStoreUpgradeScript -Exactly 0 -Scope It
        }

        It 'rejects <Scenario> before dispatching an upgrade helper' -TestCases @(
            @{
                Scenario = 'an unsupported pre-10.9.1 source version'
                Json = '{"AllNodes":[{"NodeName":"server-01","Role":["Server"]}],"ConfigData":{"Version":"11.5","OldVersion":"10.8"}}'
                Expected = '[ERROR] DSC Module only supports upgrades from ArcGIS Enterprise 10.9.1 and above. Configuration File Name - C:\upgrade.json'
            }
            @{
                Scenario = 'a direct 10.x to 12.x upgrade'
                Json = '{"AllNodes":[{"NodeName":"server-01","Role":["Server"]}],"ConfigData":{"Version":"12.0","OldVersion":"10.9.1"}}'
                Expected = "[ERROR] ArcGIS Enterprise doesn't support upgrading from 10.x and below to 12.0 and above."
            }
            @{
                Scenario = 'the legacy PortalWebAdaptor role'
                Json = '{"AllNodes":[{"NodeName":"web-01","Role":["PortalWebAdaptor"]}],"ConfigData":{"Version":"11.5","OldVersion":"11.4"}}'
                Expected = "[ERROR] Starting from version 4.3.0, the DSC Module requires a different way of specifying the Web Adaptor Node configuration. Please make sure to update your configuration file 'C:\upgrade.json'."
            }
            @{
                Scenario = 'a retired GeoAnalytics upgrade role'
                Json = '{"AllNodes":[{"NodeName":"server-01","Role":["Server"]}],"ConfigData":{"Version":"11.4","OldVersion":"11.3","ServerRole":"GeoAnalytics"}}'
                Expected = '[ERROR] Starting at ArcGIS Enterprise 11.4, the GeoAnalytics Server role is retired. Please update the server role in the configuration file and try again.'
            }
            @{
                Scenario = 'a retired Tile Cache Data Store upgrade'
                Json = '{"AllNodes":[{"NodeName":"datastore-01","Role":["DataStore"],"DataStoreTypes":["TileCache"]}],"ConfigData":{"Version":"12.0","OldVersion":"11.5"}}'
                Expected = '[ERROR] Starting at ArcGIS Enterprise 11.5, the Tile Cache Data Store is retired. Please update your configuration file.'
            }
            @{
                Scenario = 'GeoEvent upgrade without backup configuration acknowledgement'
                Json = '{"AllNodes":[{"NodeName":"server-01","Role":["Server"]}],"ConfigData":{"Version":"11.5","OldVersion":"11.4","ServerRole":"GeoEvent","GeoEventServer":{}}}'
                Expected = "ArcGIS GeoEvent Server - You have to specify UserBackupConfigFiles as 'true' under GeoEventServer Config Data block of your json config to acknowledge that you understand your geoevent configuration will not be automatically upgraded as a part of this installation and will need to be manually imported after successful completion of the installation."
            }
        ) {
            param($Json, $Expected)
            Mock Get-Content { $Json }
            $exception = $null

            try {
                Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\upgrade.json' -Mode Upgrade
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be $Expected
            Assert-MockCalled Invoke-PortalUpgradeScript -Exactly 0 -Scope It
            Assert-MockCalled Invoke-ServerUpgradeScript -Exactly 0 -Scope It
            Assert-MockCalled Invoke-DataStoreUpgradeScript -Exactly 0 -Scope It
        }

        It 'rejects multiple non-hosting deployments in one upgrade invocation' {
            $portalJson = '{"AllNodes":[{"NodeName":"portal-01","Role":["Portal"]}],"ConfigData":{"Version":"11.5","OldVersion":"11.4","Credentials":{}}}'
            $serverJson = '{"AllNodes":[{"NodeName":"server-01","Role":["Server"]}],"ConfigData":{"Version":"11.5","OldVersion":"11.4","Credentials":{}}}'
            Mock Get-Content { if ($Path -eq 'C:\portal.json') { $portalJson } else { $serverJson } }
            $exception = $null

            try {
                Invoke-ArcGISConfiguration -ConfigurationParametersFile @('C:\portal.json', 'C:\server.json') -Mode Upgrade
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Cannot Upgrade more than one non Enterprise (Server, Portal, DataStore) Deployments at a time only. Pass only one Site at a time!'
            Assert-MockCalled Invoke-PortalUpgradeScript -Exactly 0 -Scope It
            Assert-MockCalled Invoke-ServerUpgradeScript -Exactly 0 -Scope It
        }

        It 'stops the upgrade before helper dispatch when setup download fails' {
            $script:configurationJson = '{"AllNodes":[{"NodeName":"server-01","Role":["Server"]}],"ConfigData":{"Version":"11.5","OldVersion":"11.4","Credentials":{"AGOCredential":{"UserName":"ago-user","Password":"ago-password"}},"DownloadSetups":true}}'
            Mock Get-Content { $script:configurationJson }
            Mock Get-DownloadsInstallsConfigurationData { @{ AllNodes = @(); ConfigData = @{ DownloadSetups = $true } } }
            Mock Invoke-DSCJob { $false }
            $exception = $null

            try {
                Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\upgrade.json' -Mode Upgrade
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Setup Downloads failed'
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter { $ConfigurationName -eq 'ArcGISDownloads' }
            Assert-MockCalled Invoke-ServerUpgradeScript -Exactly 0 -Scope It
        }
    }
}