<#
    Tests transformation of user configuration into DSC node and download data.
    Real builders select certificate metadata, construct dummy password credentials,
    apply Web Adaptor defaults, deduplicate shared downloads, and sanitize copies.
    Fixture paths describe input data; no certificate import or DSC compilation occurs.

    Output assertions are paired with input-preservation checks where copying is part
    of the contract. See ../README.md for the Windows PowerShell/Pester test workflow.
#>
$moduleScriptPath = Join-Path $PSScriptRoot '..\..\Modules\ArcGIS\ArcGIS.psm1'

Import-Module $moduleScriptPath

InModuleScope ArcGIS {
    Describe 'Invoke-CreateNodeToAdd' {
        It 'creates an encrypted Data Store node with typed SSL certificate credentials' {
            $node = [PSCustomObject]@{
                NodeName = 'datastore-01'
                TargetNodeEncryptionCertificateFilePath = 'C:\node.cer'
                TargetNodeEncryptionCertificateThumbprint = 'ABC123'
                SslCertificates = @(
                    [PSCustomObject]@{
                        Target = @('DataStore-Relational')
                        CNameFQDN = 'datastore.contoso.com'
                        Path = 'C:\datastore.pfx'
                        Password = 'certificate-password'
                        ImportCertificateChain = $false
                    }
                )
            }

            $result = Invoke-CreateNodeToAdd -Node $node -TargetComponent 'DataStore' -DataStoreType 'Relational'

            $result.NodeName | Should Be 'datastore-01'
            $result.CertificateFile | Should Be 'C:\node.cer'
            $result.Thumbprint | Should Be 'ABC123'
            $result.ContainsKey('PSDscAllowPlainTextPassword') | Should Be $false
            $result.DataStoreTypes[0] | Should Be 'Relational'
            $result.DataStoreSSLCertificates.Count | Should Be 1
            $result.DataStoreSSLCertificates[0].Type | Should Be 'Relational'
            $result.DataStoreSSLCertificates[0].ImportCertificateChain | Should Be $false
            $result.DataStoreSSLCertificates[0].Password.UserName | Should Be 'SSLCertPlaceholder'
            $result.DataStoreSSLCertificates[0].Password.GetNetworkCredential().Password | Should Be 'certificate-password'
        }

        It 'applies Web Adaptor context and site defaults for a Server role' {
            $node = [PSCustomObject]@{
                NodeName = 'web-01'
                WebAdaptorConfig = @(
                    @{ Role = 'Server' }
                    @{ Role = 'Portal'; Context = 'portal-adaptor'; WebSiteId = 3 }
                )
            }

            $result = Invoke-CreateNodeToAdd -Node $node -TargetComponent 'WebAdaptor' -ServerContext 'server-adaptor' -PortalContext 'portal' -WebAdaptorAdminAccessEnabled $true -WebAdaptorWebSiteId 2

            $result.PSDscAllowPlainTextPassword | Should Be $true
            $result.WebAdaptorConfig.Count | Should Be 2
            $result.WebAdaptorConfig[0].Context | Should Be 'server-adaptor'
            $result.WebAdaptorConfig[0].AdminAccessEnabled | Should Be $true
            $result.WebAdaptorConfig[0].WebSiteId | Should Be 2
            $result.WebAdaptorConfig[1].Context | Should Be 'portal-adaptor'
            $result.WebAdaptorConfig[1].WebSiteId | Should Be 3
            $result.WebAdaptorConfig[1].ContainsKey('AdminAccessEnabled') | Should Be $false
        }

        It 'omits IIS-only website identifiers for a Java Web Adaptor' {
            $node = [PSCustomObject]@{
                NodeName = 'java-web-01'
                WebAdaptorConfig = @(@{ Role = 'Server'; WebSiteId = 7 })
            }

            $result = Invoke-CreateNodeToAdd -Node $node -TargetComponent 'WebAdaptor' -ServerContext 'server-adaptor' -WebAdaptorAdminAccessEnabled $true -WebAdaptorWebSiteId 2 -IsJavaWebAdaptor $true

            $result.WebAdaptorConfig[0].Context | Should Be 'server-adaptor'
            $result.WebAdaptorConfig[0].AdminAccessEnabled | Should Be $true
            $result.WebAdaptorConfig[0].ContainsKey('WebSiteId') | Should Be $false
        }

        It 'creates a standard Server SSL certificate with root-chain data and a typed password credential' {
            $node = [PSCustomObject]@{
                NodeName = 'server-ssl-01'
                SslCertificates = @(
                    [PSCustomObject]@{
                        Target = @('Server')
                        CNameFQDN = 'server.contoso.com'
                        Path = 'C:\certificates\server.pfx'
                        Password = 'server-certificate-password'
                        ImportCertificateChain = $false
                        ForceImport = $true
                        SslRootOrIntermediate = @(@{ Path = 'C:\certificates\root.cer'; Password = 'root-password' })
                    }
                )
            }

            $result = Invoke-CreateNodeToAdd -Node $node -TargetComponent 'Server'

            $result.PSDscAllowPlainTextPassword | Should Be $true
            $result.SSLCertificate.CName | Should Be 'server.contoso.com'
            $result.SSLCertificate.Path | Should Be 'C:\certificates\server.pfx'
            $result.SSLCertificate.ImportCertificateChain | Should Be $false
            $result.SSLCertificate.ForceImport | Should Be $true
            $result.SSLCertificate.Password.UserName | Should Be 'SSLCertPlaceholder'
            $result.SSLCertificate.Password.GetNetworkCredential().Password | Should Be 'server-certificate-password'
            $rootCertificates = @($result.SslRootOrIntermediate | ConvertFrom-Json)
            $rootCertificates.Count | Should Be 1
            $rootCertificates[0].Path | Should Be 'C:\certificates\root.cer'
            $rootCertificates[0].Password | Should Be 'root-password'
        }

        It 'uses explicit Web Adaptor host, admin access, and website values over supplied defaults' {
            $node = [PSCustomObject]@{
                NodeName = 'web-override-01'
                WebAdaptorConfig = @(
                    @{ Role = 'Server'; Context = 'server'; HostName = 'wa.contoso.com'; AdminAccessEnabled = $false; WebSiteId = 9 }
                )
            }

            $result = Invoke-CreateNodeToAdd -Node $node -TargetComponent 'WebAdaptor' -ServerContext 'ignored' -WebAdaptorAdminAccessEnabled $true -WebAdaptorWebSiteId 2

            $result.WebAdaptorConfig.Count | Should Be 1
            $result.WebAdaptorConfig[0].Context | Should Be 'server'
            $result.WebAdaptorConfig[0].HostName | Should Be 'wa.contoso.com'
            $result.WebAdaptorConfig[0].AdminAccessEnabled | Should Be $false
            $result.WebAdaptorConfig[0].WebSiteId | Should Be 9
        }

        It 'uses plaintext DSC credentials when only <EncryptionProperty> is supplied' -TestCases @(
            # Encryption requires the certificate path AND thumbprint together.
            # Testing each incomplete pair catches an accidental OR condition that
            # would emit unusable node encryption settings. This pins builder behavior,
            # not a recommendation to use plaintext credentials in deployments.
            @{ EncryptionProperty = 'TargetNodeEncryptionCertificateFilePath'; EncryptionValue = 'C:\node.cer' }
            @{ EncryptionProperty = 'TargetNodeEncryptionCertificateThumbprint'; EncryptionValue = 'ABC123' }
        ) {
            param($EncryptionProperty, $EncryptionValue)
            $node = @{ NodeName = 'server-01' }
            $node[$EncryptionProperty] = $EncryptionValue

            $result = Invoke-CreateNodeToAdd -Node $node -TargetComponent 'Server'

            $result.NodeName | Should Be 'server-01'
            $result.PSDscAllowDomainUser | Should Be $true
            $result.PSDscAllowPlainTextPassword | Should Be $true
            $result.ContainsKey('CertificateFile') | Should Be $false
            $result.ContainsKey('Thumbprint') | Should Be $false
        }

        It 'omits unsupported admin access while retaining explicit Web Adaptor settings' {
            $node = @{ NodeName = 'web-01'; WebAdaptorConfig = @(@{ Role = 'Server'; Context = 'explicit-server'; AdminAccessEnabled = $false; WebSiteId = 9 }) }

            $result = Invoke-CreateNodeToAdd -Node $node -TargetComponent 'WebAdaptor' -ServerContext 'default-server' -WebAdaptorAdminAccessEnabled $true -WebAdaptorAdminAccessEnabledSupported $false -WebAdaptorWebSiteId 2

            $result.WebAdaptorConfig.Count | Should Be 1
            $result.WebAdaptorConfig[0].Role | Should Be 'Server'
            $result.WebAdaptorConfig[0].Context | Should Be 'explicit-server'
            $result.WebAdaptorConfig[0].WebSiteId | Should Be 9
            $result.WebAdaptorConfig[0].ContainsKey('AdminAccessEnabled') | Should Be $false
            $node.WebAdaptorConfig[0].AdminAccessEnabled | Should Be $false
        }

        It 'rejects an unsupported Web Adaptor role without a context' {
            $node = [PSCustomObject]@{
                NodeName = 'web-01'
                WebAdaptorConfig = @(@{ Role = 'Unknown' })
            }
            $exception = $null

            try {
                Invoke-CreateNodeToAdd -Node $node -TargetComponent 'WebAdaptor'
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Role not supported'
        }
    }

    Describe 'Get-DownloadsInstallsConfigurationData' {
        It 'deduplicates shared roles case-insensitively while retaining nodes with no remaining downloads' {
            # Shared setup downloads are assigned only once per role. A node whose
            # roles are already accounted for still remains in AllNodes, with an empty
            # role list; role casing in the caller's original data must stay unchanged.
            $configuration = [PSCustomObject]@{
                AllNodes = @(
                    [PSCustomObject]@{ NodeName = 'server-01'; Role = @('Server', 'Portal') }
                    [PSCustomObject]@{ NodeName = 'server-02'; Role = @('server', 'PORTAL') }
                )
                ConfigData = [PSCustomObject]@{ Version = '11.5' }
            }

            $result = Get-DownloadsInstallsConfigurationData -ConfigurationParamsJSON $configuration -DownloadSetupsToSharedPath $true

            $result.AllNodes.Count | Should Be 2
            $result.AllNodes[0].NodeName | Should Be 'server-01'
            ($result.AllNodes[0].Role -join ',') | Should Be 'Server,Portal'
            $result.AllNodes[1].NodeName | Should Be 'server-02'
            $result.AllNodes[1].Role.Count | Should Be 0
            ($configuration.AllNodes[1].Role -join ',') | Should Be 'server,PORTAL'
        }

        It 'preserves installer metadata and isolates sanitized downloads from the input configuration' {
            $configuration = [PSCustomObject]@{
                AllNodes = @([PSCustomObject]@{ NodeName = 'server-01'; Role = @('Server') })
                ConfigData = [PSCustomObject]@{
                    Version = '11.5'
                    Credentials = [PSCustomObject]@{ ServiceAccount = [PSCustomObject]@{ UserName = 'svc'; Password = 'service-secret' } }
                    Server = [PSCustomObject]@{
                        LicenseFilePath = 'C:\licenses\server.json'
                        Installer = [PSCustomObject]@{ Path = 'C:\installers\server.exe'; InstallDir = 'D:\ArcGIS\Server' }
                    }
                }
            }

            $result = Get-DownloadsInstallsConfigurationData -ConfigurationParamsJSON $configuration

            $result.ConfigData.Version | Should Be '11.5'
            $result.ConfigData.ContainsKey('Credentials') | Should Be $false
            $result.ConfigData.Server.ContainsKey('LicenseFilePath') | Should Be $false
            $result.ConfigData.Server.Keys.Count | Should Be 1
            $result.ConfigData.Server.Installer.Path | Should Be 'C:\installers\server.exe'
            $result.ConfigData.Server.Installer.InstallDir | Should Be 'D:\ArcGIS\Server'
            $configuration.ConfigData.Credentials.ServiceAccount.Password | Should Be 'service-secret'
            $configuration.ConfigData.Server.LicenseFilePath | Should Be 'C:\licenses\server.json'
            # Equality immediately after conversion cannot detect shared nested objects.
            # Mutate the returned installer to prove it is independent of the input.
            $result.ConfigData.Server.Installer.Path = 'C:\different.exe'
            $configuration.ConfigData.Server.Installer.Path | Should Be 'C:\installers\server.exe'
        }

        It 'deduplicates shared download roles and removes secret and install-only properties' {
            $configuration = ConvertFrom-Json @'
{
  "AllNodes": [
    { "NodeName": "server-01", "Role": ["Server", "Portal"] },
    { "NodeName": "server-02", "Role": ["Server", "DataStore"] }
  ],
  "ConfigData": {
    "Version": "11.5",
    "Credentials": { "ServiceAccount": { "UserName": "svc" } },
    "Server": { "LicenseFilePath": "C:\\server-license.json", "LogLevel": "INFO" },
    "WebAdaptor": { "AdminAccessEnabled": true }
  }
}
'@

            $result = Get-DownloadsInstallsConfigurationData -ConfigurationParamsJSON $configuration -DownloadSetupsToSharedPath $true

            $result.AllNodes.Count | Should Be 2
            $result.AllNodes[0].Role.Count | Should Be 2
            $result.AllNodes[0].Role[0] | Should Be 'Server'
            $result.AllNodes[0].Role[1] | Should Be 'Portal'
            $result.AllNodes[1].Role.Count | Should Be 1
            $result.AllNodes[1].Role[0] | Should Be 'DataStore'
            $result.AllNodes[0].PSDscAllowPlainTextPassword | Should Be $true
            $result.ConfigData.ContainsKey('Credentials') | Should Be $false
            $result.ConfigData.Server.ContainsKey('LicenseFilePath') | Should Be $false
            $result.ConfigData.Server.ContainsKey('LogLevel') | Should Be $false
            $result.ConfigData.WebAdaptor.ContainsKey('AdminAccessEnabled') | Should Be $false
        }

                It 'preserves per-node roles and uses plaintext DSC credentials by default' {
                        $configuration = ConvertFrom-Json @'
{
    "AllNodes": [
        { "NodeName": "server-01", "Role": ["Server"] },
        { "NodeName": "server-02", "Role": ["Server"] }
    ],
    "ConfigData": { "Version": "11.4" }
}
'@

                        $result = Get-DownloadsInstallsConfigurationData -ConfigurationParamsJSON $configuration

                        $result.AllNodes.Count | Should Be 2
                        $result.AllNodes[0].Role[0] | Should Be 'Server'
                        $result.AllNodes[1].Role[0] | Should Be 'Server'
                        $result.AllNodes[0].PSDscAllowPlainTextPassword | Should Be $true
                        $result.AllNodes[1].PSDscAllowPlainTextPassword | Should Be $true
                }

                It 'removes credentials and install-only properties for every supported component' {
                        $configuration = ConvertFrom-Json @'
{
    "AllNodes": [
        { "NodeName": "server-01", "Role": ["Server"] }
    ],
    "ConfigData": {
        "Version": "11.5",
        "Credentials": { "ServiceAccount": { "UserName": "svc" } },
        "SslRootOrIntermediate": ["root"],
        "FileShareLocalPath": "C:\\ArcGISShare",
        "FileShareName": "ArcGISShare",
        "Server": {
            "LicenseFilePath": "C:\\licenses\\server.json",
            "LicensePassword": "server-password",
            "ServerDirectoriesRootLocation": "C:\\arcgis\\directories",
            "ServerLogsLocation": "C:\\arcgis\\logs",
            "LogLevel": "INFO",
            "LocalRepositoryPath": "C:\\arcgis\\repository",
            "ServerDirectories": ["arcgisjobs"],
            "ConfigStoreLocation": "C:\\arcgis\\config-store"
        },
        "GeoEventServer": { "LicenseFilePath": "C:\\licenses\\geoevent.json", "LicensePassword": "geoevent-password" },
        "WorkflowManagerServer": { "LicenseFilePath": "C:\\licenses\\workflow.json", "LicensePassword": "workflow-password" },
        "RealityServer": { "LicenseFilePath": "C:\\licenses\\reality.json", "LicensePassword": "reality-password" },
        "Portal": {
            "LicenseFilePath": "C:\\licenses\\portal.json",
            "PortalLicenseUserTypeId": "creatorUT",
            "ContentDirectoryLocation": "C:\\arcgis\\portal-content",
            "LogLevel": "DEBUG"
        },
        "DataStore": { "ContentDirectoryLocation": "C:\\arcgis\\datastore-content" },
        "WebAdaptor": { "AdminAccessEnabled": true },
        "Pro": { "LicenseFilePath": "C:\\licenses\\pro.json" }
    }
}
'@

                        $result = Get-DownloadsInstallsConfigurationData -ConfigurationParamsJSON $configuration

                        $result.ConfigData.ContainsKey('Credentials') | Should Be $false
                        $result.ConfigData.ContainsKey('SslRootOrIntermediate') | Should Be $false
                        $result.ConfigData.ContainsKey('FileShareLocalPath') | Should Be $false
                        $result.ConfigData.ContainsKey('FileShareName') | Should Be $false
                        $result.ConfigData.Server.Keys.Count | Should Be 0
                        $result.ConfigData.GeoEventServer.Keys.Count | Should Be 0
                        $result.ConfigData.WorkflowManagerServer.Keys.Count | Should Be 0
                        $result.ConfigData.RealityServer.Keys.Count | Should Be 0
                        $result.ConfigData.Portal.Keys.Count | Should Be 0
                        $result.ConfigData.DataStore.Keys.Count | Should Be 0
                        $result.ConfigData.WebAdaptor.Keys.Count | Should Be 0
                        $result.ConfigData.Pro.Keys.Count | Should Be 0
                }

                It 'removes supported install-only properties while preserving Web Adaptor and encrypted-node download metadata' {
                        $configuration = ConvertFrom-Json @'
{
    "AllNodes": [
        {
            "NodeName": "server-wa-01",
            "Role": ["ServerWebAdaptor", "WebAdaptor"],
            "TargetNodeEncryptionCertificateFilePath": "C:\\node.cer",
            "TargetNodeEncryptionCertificateThumbprint": "ABC123",
            "WebAdaptorConfig": [{ "Role": "Server" }],
            "SslCertificates": [{ "Target": ["WebAdaptor"], "CNameFQDN": "web.contoso.com", "Path": "C:\\web.pfx", "Password": "pfx-password", "ImportCertificateChain": false, "ForceImport": true }]
        },
        { "NodeName": "datastore-01", "Role": ["DataStore"], "DataStoreTypes": ["Relational"] }
    ],
    "ConfigData": {
        "Version": "11.5",
        "Credentials": { "ServiceAccount": { "UserName": "svc" } },
        "SslRootOrIntermediate": { "Path": "C:\\root.cer" },
        "FileShareLocalPath": "C:\\share",
        "FileShareName": "ArcGISShare",
        "ServerContext": "server",
        "Server": {
            "LicenseFilePath": "C:\\server.json",
            "LicensePassword": "server-password",
            "ServerDirectoriesRootLocation": "C:\\directories",
            "ServerLogsLocation": "C:\\logs",
            "LogLevel": "INFO",
            "LocalRepositoryPath": "C:\\repository",
            "ServerDirectories": [{ "physicalPath": "C:\\directories\\arcgis" }],
            "ConfigStoreLocation": "C:\\config-store"
        },
        "GeoEventServer": { "LicenseFilePath": "C:\\geoevent.json", "LicensePassword": "geoevent-password" },
        "WorkflowManagerServer": { "LicenseFilePath": "C:\\workflow.json", "LicensePassword": "workflow-password" },
        "RealityServer": { "LicenseFilePath": "C:\\reality.json", "LicensePassword": "reality-password" },
        "Portal": { "LicenseFilePath": "C:\\portal.json", "PortalLicenseUserTypeId": "creatorUT", "ContentDirectoryLocation": "C:\\portal-content", "LogLevel": "WARNING" },
        "DataStore": { "ContentDirectoryLocation": "C:\\datastore-content" },
        "WebAdaptor": { "AdminAccessEnabled": true, "Installer": { "ApacheTomcat": {} } },
        "Pro": { "LicenseFilePath": "C:\\pro.json" }
    }
}
'@

                        $result = Get-DownloadsInstallsConfigurationData -ConfigurationParamsJSON $configuration

                        $result.AllNodes[0].CertificateFile | Should Be 'C:\node.cer'
                        $result.AllNodes[0].Thumbprint | Should Be 'ABC123'
                        $result.AllNodes[0].PSDscAllowPlainTextPassword | Should Be $null
                        $result.AllNodes[0].ServerContext | Should Be 'server'
                        $result.AllNodes[0].WebAdaptorConfig[0].Role | Should Be 'Server'
                        $result.AllNodes[0].SSLCertificate.CName | Should Be 'web.contoso.com'
                        $result.AllNodes[0].SSLCertificate.ImportCertificateChain | Should Be $false
                        $result.AllNodes[0].SSLCertificate.ForceImport | Should Be $true
                        $result.AllNodes[0].SSLCertificate.Password.GetNetworkCredential().Password | Should Be 'pfx-password'
                        $result.AllNodes[1].DataStoreTypes[0] | Should Be 'Relational'
                        $result.ConfigData.ContainsKey('Credentials') | Should Be $false
                        $result.ConfigData.ContainsKey('SslRootOrIntermediate') | Should Be $false
                        $result.ConfigData.ContainsKey('FileShareLocalPath') | Should Be $false
                        $result.ConfigData.ContainsKey('FileShareName') | Should Be $false
                        $result.ConfigData.Server.Keys.Count | Should Be 0
                        $result.ConfigData.GeoEventServer.Keys.Count | Should Be 0
                        $result.ConfigData.WorkflowManagerServer.Keys.Count | Should Be 0
                        $result.ConfigData.RealityServer.Keys.Count | Should Be 0
                        $result.ConfigData.Portal.Keys.Count | Should Be 0
                        $result.ConfigData.DataStore.Keys.Count | Should Be 0
                        $result.ConfigData.WebAdaptor.ContainsKey('AdminAccessEnabled') | Should Be $false
                        $result.ConfigData.Pro.Keys.Count | Should Be 0
                }
    }
}