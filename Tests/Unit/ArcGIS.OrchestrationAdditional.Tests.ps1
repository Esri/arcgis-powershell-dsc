<#
    Exercises orchestration decisions without running DSC configurations or installers.
    The real module functions build arguments and choose dispatch order; Invoke-DSCJob
    is mocked so tests can inspect those decisions without contacting target nodes.

    Run with Windows PowerShell 5.1 and Pester 3.4.0. See ../README.md for commands,
    suite responsibilities, mock conventions, and troubleshooting.
#>
$moduleScriptPath = Join-Path $PSScriptRoot '..\..\Modules\ArcGIS\ArcGIS.psm1'

Import-Module $moduleScriptPath

InModuleScope ArcGIS {
    # This minimal upgrade fixture supplies realistic role-specific settings and dummy
    # credentials. Its Windows/UNC paths are inputs to argument builders, not files
    # that tests expect to exist; external execution must remain behind mocks.
    function New-UpgradeConfiguration {
        param([array]$Nodes)

        return @{
            AllNodes = $Nodes
            ConfigData = @{
                Version = '11.5'
                OldVersion = '11.4'
                Credentials = @{ ServiceAccount = @{ UserName = 'CONTOSO\svc-arcgis'; Password = 'service-password' } }
                Server = @{
                    PrimarySiteAdmin = @{ UserName = 'siteadmin'; Password = 'site-password' }
                    LicenseFilePath = 'C:\licenses\server.json'
                    Installer = @{ Path = 'C:\installers\server.exe'; InstallDir = 'C:\ArcGIS\Server' }
                }
                Portal = @{
                    LicenseFilePath = 'C:\licenses\portal.json'
                    PortalAdministrator = @{ UserName = 'portaladmin'; Password = 'portal-password' }
                    Installer = @{ Path = 'C:\installers\portal.exe'; InstallDir = 'C:\ArcGIS\Portal' }
                }
                DataStore = @{
                    ContentDirectoryLocation = '\\fileserver\datastore'
                    Installer = @{ Path = 'C:\installers\datastore.exe'; InstallDir = 'C:\ArcGIS\DataStore' }
                }
                WebAdaptor = @{ Installer = @{ Path = 'C:\installers\webadaptor.exe' } }
            }
        }
    }

    Describe 'Invoke-DataStoreConfigureScript dispatch and backup handling' {
        BeforeEach {
            # Orchestration reads these module-scoped connection options. Reset them
            # for every case so a previous workflow cannot change dispatch behavior.
            # Secret resolution is mocked separately from credential construction:
            # the production function still builds and forwards real PSCredentials.
            $script:Credential = $null
            $script:UseWinRMSSL = $false
            $script:DebugMode = $false
            Mock Invoke-DSCJob { $true }
            Mock Get-PasswordFromObject { ConvertTo-SecureString 'backup-password' -AsPlainText -Force }
        }

        It 'dispatches each supported Data Store type with that type in the DSC arguments' -TestCases @(
            @{ DataStoreType = 'Relational' }
            @{ DataStoreType = 'TileCache' }
            @{ DataStoreType = 'SpatioTemporal' }
            @{ DataStoreType = 'GraphStore' }
            @{ DataStoreType = 'ObjectStore' }
        ) {
            param($DataStoreType)
            $arguments = @{ Version = '11.5' }
            $configurationData = @{ AllNodes = @(@{ NodeName = 'datastore-01' }) }

            $result = Invoke-DataStoreConfigureScript -DataStoreType $DataStoreType -DataStoreArguments $arguments -DataStoreConfigData $configurationData -PrimaryDataStoreMachine 'datastore-01'

            $result | Should Be $true
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $ConfigurationName -eq 'ArcGISDataStore' -and
                $ConfigurationFolderPath -eq 'Configurations-OnPrem' -and
                $Arguments.DataStoreType -eq $DataStoreType -and
                $Arguments.PrimaryDataStoreMachine -eq 'datastore-01' -and
                $Arguments.DataStoreMachineCount -eq 1 -and
                $Arguments.ConfigurationData.AllNodes[0].NodeName -eq 'datastore-01'
            }
        }

        It 'maps relational failover and point-in-time recovery settings' {
            $arguments = @{ Version = '11.5' }

            Invoke-DataStoreConfigureScript -DataStoreType Relational -DataStoreArguments $arguments -DataStoreConfigData @{ AllNodes = @(@{ NodeName = 'datastore-01' }) } -PrimaryDataStoreMachine 'datastore-01' -EnableFailoverOnPrimaryStop $true -EnablePointInTimeRecovery $true

            # Inspect the dispatched copy, not the caller's hashtable. Both the mapped
            # settings and the unchanged original matter: mutation of the caller can
            # leak relational flags into later configurations for other store types.
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $Arguments.EnableFailoverOnPrimaryStop -eq $true -and
                $Arguments.EnablePointInTimeRecovery -eq $true -and
                $Arguments.Version -eq '11.5'
            }
            $arguments.Count | Should Be 1
            $arguments.Version | Should Be '11.5'
        }

        It 'maps a complete cloud relational configuration including optional read-only and proxy endpoints' {
            $arguments = @{ Version = '11.5' }
            $admin = New-Object System.Management.Automation.PSCredential 'db-admin', (ConvertTo-SecureString 'admin-password' -AsPlainText -Force)
            $sde = New-Object System.Management.Automation.PSCredential 'sde-user', (ConvertTo-SecureString 'sde-password' -AsPlainText -Force)

            Invoke-DataStoreConfigureScript -DataStoreType Relational -DataStoreArguments $arguments -DataStoreConfigData @{ AllNodes = @(@{ NodeName = 'datastore-01' }) } -PrimaryDataStoreMachine 'datastore-01' -UseCloudRelationalStore $true -CloudRelationalStoreType AzureFlexiblePostgreSQLDatabase -CloudRelationalDatabasePort '5432' -CloudRelationalDatabaseURI 'postgres://primary' -CloudRelationalDatabaseReadonlyURI 'postgres://readonly' -CloudRelationalProxyPort '6432' -CloudRelationalProxyURI 'postgres://proxy' -CloudRelationalRegion 'eastus' -CloudRelationalDatabaseAdminUser $admin -CloudRelationalSDEUser $sde

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $Arguments.UseCloudRelationalStore -eq $true -and
                $Arguments.CloudRelationalStoreType -eq 'AzureFlexiblePostgreSQLDatabase' -and
                $Arguments.CloudRelationalDatabasePort -eq '5432' -and
                $Arguments.CloudRelationalDatabaseURI -eq 'postgres://primary' -and
                $Arguments.CloudRelationalDatabaseReadonlyURI -eq 'postgres://readonly' -and
                $Arguments.CloudRelationalProxyPort -eq '6432' -and
                $Arguments.CloudRelationalProxyURI -eq 'postgres://proxy' -and
                $Arguments.CloudRelationalRegion -eq 'eastus' -and
                $Arguments.CloudRelationalDatabaseAdminUser.UserName -eq 'db-admin' -and
                $Arguments.CloudRelationalDatabaseAdminUser.GetNetworkCredential().Password -eq 'admin-password' -and
                $Arguments.CloudRelationalSDEUser.UserName -eq 'sde-user' -and
                $Arguments.CloudRelationalSDEUser.GetNetworkCredential().Password -eq 'sde-password'
            }
            $arguments.Count | Should Be 1
            $arguments.Version | Should Be '11.5'
        }

        It 'does not add optional cloud proxy settings when <MissingSetting> is missing' -TestCases @(
            # A proxy is valid only when both fields are present. Test each missing
            # half independently to detect an accidental AND-to-OR regression.
            @{ MissingSetting = 'URI'; ProxyPort = '6432'; ProxyURI = '' }
            @{ MissingSetting = 'port'; ProxyPort = ''; ProxyURI = 'postgres://proxy' }
        ) {
            param($MissingSetting, $ProxyPort, $ProxyURI)
            $arguments = @{ Version = '11.5' }

            Invoke-DataStoreConfigureScript -DataStoreType Relational -DataStoreArguments $arguments -DataStoreConfigData @{ AllNodes = @(@{ NodeName = 'datastore-01' }) } -PrimaryDataStoreMachine 'datastore-01' -UseCloudRelationalStore $true -CloudRelationalStoreType AWSRDSPostgreSQLDatabase -CloudRelationalDatabasePort '5432' -CloudRelationalDatabaseURI 'postgres://primary' -CloudRelationalProxyPort $ProxyPort -CloudRelationalProxyURI $ProxyURI -CloudRelationalRegion 'us-east-1'

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $Arguments.UseCloudRelationalStore -eq $true -and
                $Arguments.CloudRelationalDatabaseURI -eq 'postgres://primary' -and
                -not $Arguments.ContainsKey('CloudRelationalProxyPort') -and
                -not $Arguments.ContainsKey('CloudRelationalProxyURI') -and
                -not $Arguments.ContainsKey('CloudRelationalDatabaseReadonlyURI') -and
                -not $Arguments.ContainsKey('CloudRelationalSDEUser')
            }
            $arguments.Count | Should Be 1
        }

        It 'dispatches disabled relational defaults without changing caller arguments' {
            $arguments = @{ Version = '11.5' }

            Invoke-DataStoreConfigureScript -DataStoreType Relational -DataStoreArguments $arguments -DataStoreConfigData @{ AllNodes = @(@{ NodeName = 'datastore-01' }) } -PrimaryDataStoreMachine 'datastore-01'

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $Arguments.ContainsKey('EnableFailoverOnPrimaryStop') -and
                $Arguments.EnableFailoverOnPrimaryStop -eq $false -and
                $Arguments.ContainsKey('EnablePointInTimeRecovery') -and
                $Arguments.EnablePointInTimeRecovery -eq $false -and
                -not $Arguments.ContainsKey('UseCloudRelationalStore')
            }
            $arguments.Count | Should Be 1
            $arguments.Version | Should Be '11.5'
        }

        It 'attaches local default relational backup metadata while processing the primary node' {
            $arguments = @{ Version = '11.5' }
            $nodes = @(@{ NodeName = 'datastore-01' }, @{ NodeName = 'datastore-02' })
            $backup = [PSCustomObject]@{ Type = 'fs'; Name = 'local'; Location = '\\fileserver\backup'; IsDefault = $true; ForceBackupLocationUpdate = $true }
            $script:dataStoreDispatchSnapshots = @()
            # Copy observable values while each dispatch happens. Retaining the
            # mutable Arguments reference could make every recorded call appear to
            # contain the last node's settings and hide primary-to-secondary leakage.
            Mock Invoke-DSCJob {
                $script:dataStoreDispatchSnapshots += [PSCustomObject]@{
                    NodeName = $Arguments.ConfigurationData.AllNodes[0].NodeName
                    BackupCount = if($Arguments.ContainsKey('Backups')) { $Arguments.Backups.Count } else { 0 }
                    ForceDefaultRelationalBackupUpdate = if($Arguments.ContainsKey('Backups')) { $Arguments.Backups[0].ForceDefaultRelationalBackupUpdate } else { $false }
                }
                $true
            }

            Invoke-DataStoreConfigureScript -DataStoreType Relational -DataStoreArguments $arguments -DataStoreConfigData @{ AllNodes = $nodes } -PrimaryDataStoreMachine 'datastore-01' -Backups @($backup)

            $script:dataStoreDispatchSnapshots.Count | Should Be 2
            $script:dataStoreDispatchSnapshots[0].NodeName | Should Be 'datastore-01'
            $script:dataStoreDispatchSnapshots[0].BackupCount | Should Be 1
            $script:dataStoreDispatchSnapshots[0].ForceDefaultRelationalBackupUpdate | Should Be $true
            $script:dataStoreDispatchSnapshots[1].NodeName | Should Be 'datastore-02'
            $script:dataStoreDispatchSnapshots[1].BackupCount | Should Be 0
            $script:dataStoreDispatchSnapshots[1].ForceDefaultRelationalBackupUpdate | Should Be $false
            $arguments.Count | Should Be 1
        }

        It 'attaches backups only to the case-insensitive primary when the secondary is listed first' {
            $arguments = @{ Version = '11.5' }
            # Combine reversed node order with different primary-name casing. This
            # proves backup selection uses node identity, not position or casing.
            $nodes = @(@{ NodeName = 'datastore-02' }, @{ NodeName = 'DATASTORE-01' })
            $backup = [PSCustomObject]@{ Type = 'fs'; Name = 'primary-backup'; Location = '\\fileserver\backup'; IsDefault = $true }
            $script:orderedBackupDispatches = @()
            Mock Invoke-DSCJob {
                $script:orderedBackupDispatches += [PSCustomObject]@{
                    NodeName = $Arguments.ConfigurationData.AllNodes[0].NodeName
                    NodeCount = $Arguments.ConfigurationData.AllNodes.Count
                    MachineCount = $Arguments.DataStoreMachineCount
                    HasBackups = $Arguments.ContainsKey('Backups')
                    BackupName = if($Arguments.ContainsKey('Backups')) { $Arguments.Backups[0].Name } else { $null }
                }
                $true
            }

            $result = Invoke-DataStoreConfigureScript -DataStoreType Relational -DataStoreArguments $arguments -DataStoreConfigData @{ AllNodes = $nodes } -PrimaryDataStoreMachine 'datastore-01' -Backups @($backup)

            $result | Should Be $true
            $script:orderedBackupDispatches.Count | Should Be 2
            $script:orderedBackupDispatches[0].NodeName | Should Be 'datastore-02'
            $script:orderedBackupDispatches[0].NodeCount | Should Be 1
            $script:orderedBackupDispatches[0].MachineCount | Should Be 2
            $script:orderedBackupDispatches[0].HasBackups | Should Be $false
            $script:orderedBackupDispatches[1].NodeName | Should Be 'DATASTORE-01'
            $script:orderedBackupDispatches[1].NodeCount | Should Be 1
            $script:orderedBackupDispatches[1].MachineCount | Should Be 2
            $script:orderedBackupDispatches[1].HasBackups | Should Be $true
            $script:orderedBackupDispatches[1].BackupName | Should Be 'primary-backup'
            $arguments.Count | Should Be 1
        }

        It 'clears inherited backup arguments from dispatch while preserving the caller entry' {
            # Seed stale backup data to model reuse of common orchestration arguments.
            # GraphStore dispatch must omit it without deleting the caller's entry.
            $arguments = @{ Version = '11.5'; Backups = @(@{ Name = 'caller-backup' }) }

            Invoke-DataStoreConfigureScript -DataStoreType GraphStore -DataStoreArguments $arguments -DataStoreConfigData @{ AllNodes = @(@{ NodeName = 'datastore-01' }) } -PrimaryDataStoreMachine 'datastore-01'

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $Arguments.DataStoreType -eq 'GraphStore' -and
                -not $Arguments.ContainsKey('Backups') -and
                -not $Arguments.ContainsKey('EnablePointInTimeRecovery')
            }
            $arguments.Count | Should Be 2
            $arguments.Backups.Count | Should Be 1
            $arguments.Backups[0].Name | Should Be 'caller-backup'
        }

        It 'builds Azure cloud backup credentials from the configured account' {
            $arguments = @{ Version = '11.5' }
            $backup = [PSCustomObject]@{
                Type = 'azure'; Name = 'azure'; Location = 'container'; IsDefault = $false
                CloudStorageAccount = [PSCustomObject]@{ UserName = 'storage.blob.core.windows.net'; Password = 'backup-password'; ForceUpdate = $true }
            }

            Invoke-DataStoreConfigureScript -DataStoreType Relational -DataStoreArguments $arguments -DataStoreConfigData @{ AllNodes = @(@{ NodeName = 'datastore-01' }) } -PrimaryDataStoreMachine 'datastore-01' -Backups @($backup)

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $Arguments.Backups[0].Type -eq 'azure' -and
                $Arguments.Backups[0].ForceCloudCredentialsUpdate -eq $true -and
                $Arguments.Backups[0].CloudCredential.UserName -eq 'storage.blob.core.windows.net'
            }
        }

        It 'copies an S3 region for Enterprise 11.2 and later' {
            $arguments = @{ Version = '11.2' }
            $backup = [PSCustomObject]@{
                Type = 's3'; Name = 's3'; Location = 'bucket'; IsDefault = $false
                CloudStorageAccount = [PSCustomObject]@{ UserName = 'access-key'; Password = 'backup-password'; AWSS3Region = 'us-west-2' }
            }

            Invoke-DataStoreConfigureScript -DataStoreType Relational -DataStoreArguments $arguments -DataStoreConfigData @{ AllNodes = @(@{ NodeName = 'datastore-01' }) } -PrimaryDataStoreMachine 'datastore-01' -Backups @($backup)

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter { $Arguments.Backups[0].AWSS3Region -eq 'us-west-2' }
        }

        It 'accepts an S3 backup without a region before Enterprise 11.2' {
            # The adjacent 11.1/11.2 cases pin the version boundary: region omission
            # is accepted before 11.2 but rejected at 11.2 and in later versions.
            $backup = [PSCustomObject]@{
                Type = 's3'; Name = 's3'; Location = 'bucket'
                CloudStorageAccount = [PSCustomObject]@{ UserName = 'access-key'; Password = 'backup-password' }
            }

            $result = Invoke-DataStoreConfigureScript -DataStoreType Relational -DataStoreArguments @{ Version = '11.1' } -DataStoreConfigData @{ AllNodes = @(@{ NodeName = 'datastore-01' }) } -PrimaryDataStoreMachine 'datastore-01' -Backups @($backup)

            $result | Should Be $true
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $Arguments.Backups.Count -eq 1 -and
                $Arguments.Backups[0].Location -eq 'bucket' -and
                $Arguments.Backups[0].CloudCredential.UserName -eq 'access-key' -and
                $Arguments.Backups[0].CloudCredential.GetNetworkCredential().Password -eq 'backup-password' -and
                $Arguments.Backups[0].IsDefault -eq $false -and
                $Arguments.Backups[0].ForceCloudCredentialsUpdate -eq $false -and
                -not $Arguments.Backups[0].ContainsKey('AWSS3Region')
            }
        }

        It 'rejects a non-filesystem default relational backup' {
            $exception = $null
            try {
                Invoke-DataStoreConfigureScript -DataStoreType Relational -DataStoreArguments @{ Version = '11.5' } -DataStoreConfigData @{ AllNodes = @(@{ NodeName = 'datastore-01' }) } -PrimaryDataStoreMachine 'datastore-01' -Backups @([PSCustomObject]@{ Type = 'azure'; Name = 'azure'; Location = 'container'; IsDefault = $true })
            }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Default back up for Relational DataStore can only be a local path or shared file location at 11.5'
            Assert-MockCalled Invoke-DSCJob -Exactly 0 -Scope It
        }

        It 'rejects an Azure backup account that is not a blob endpoint' {
            # Rejection must happen before secret lookup or DSC dispatch. An exact
            # error alone would miss a validation path that already performed work.
            $exception = $null
            try {
                Invoke-DataStoreConfigureScript -DataStoreType Relational -DataStoreArguments @{ Version = '11.5' } -DataStoreConfigData @{ AllNodes = @(@{ NodeName = 'datastore-01' }) } -PrimaryDataStoreMachine 'datastore-01' -Backups @([PSCustomObject]@{ Type = 'azure'; Name = 'azure'; Location = 'container'; CloudStorageAccount = [PSCustomObject]@{ UserName = 'not-a-blob-endpoint'; Password = 'backup-password' } })
            }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Error - Invalid Backup Azure Blob Storage Account'
            Assert-MockCalled Invoke-DSCJob -Exactly 0 -Scope It
            Assert-MockCalled Get-PasswordFromObject -Exactly 0 -Scope It
        }

        It 'rejects an S3 backup without a region at Enterprise 11.2 and later' {
            $exception = $null
            try {
                Invoke-DataStoreConfigureScript -DataStoreType Relational -DataStoreArguments @{ Version = '11.2' } -DataStoreConfigData @{ AllNodes = @(@{ NodeName = 'datastore-01' }) } -PrimaryDataStoreMachine 'datastore-01' -Backups @([PSCustomObject]@{ Type = 's3'; Name = 's3'; Location = 'bucket'; CloudStorageAccount = [PSCustomObject]@{ UserName = 'access-key'; Password = 'backup-password' } })
            }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Error - No region specified for AWS S3 bucket'
            Assert-MockCalled Invoke-DSCJob -Exactly 0 -Scope It
            Assert-MockCalled Get-PasswordFromObject -Exactly 0 -Scope It
        }

        It 'rejects a cloud backup with no cloud storage account' {
            $exception = $null
            try {
                Invoke-DataStoreConfigureScript -DataStoreType Relational -DataStoreArguments @{ Version = '11.5' } -DataStoreConfigData @{ AllNodes = @(@{ NodeName = 'datastore-01' }) } -PrimaryDataStoreMachine 'datastore-01' -Backups @([PSCustomObject]@{ Type = 'azure'; Name = 'azure'; Location = 'container' })
            }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'No cloud credentials provided for Cloud Backup type azure and Location container'
            Assert-MockCalled Invoke-DSCJob -Exactly 0 -Scope It
            Assert-MockCalled Get-PasswordFromObject -Exactly 0 -Scope It
        }

        It 'stops configuring additional nodes after a DSC failure' {
            $call = 0
            Mock Invoke-DSCJob { $call++; if($call -eq 1) { $false } else { $true } }
            $exception = $null

            try {
                Invoke-DataStoreConfigureScript -DataStoreType GraphStore -DataStoreArguments @{ Version = '11.5' } -DataStoreConfigData @{ AllNodes = @(@{ NodeName = 'datastore-01' }, @{ NodeName = 'datastore-02' }) } -PrimaryDataStoreMachine 'datastore-01'
            }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Configuration of ArcGIS DataStore of type GraphStore failed.'
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It
        }
    }

    Describe 'Invoke-JavaWebAdaptorUninstallUpgradeScript' {
        It 'returns success without DSC work when Java Web Adaptor is not enabled' {
            Mock Invoke-DSCJob { throw 'DSC should not be called' }

            $result = Invoke-JavaWebAdaptorUninstallUpgradeScript -cf @{ AllNodes = @(); ConfigData = @{} }

            $result | Should Be $true
            Assert-MockCalled Invoke-DSCJob -Exactly 0 -Scope It
        }

        It 'dispatches Java Web Adaptor uninstall nodes with plaintext DSC credentials' {
            Mock Invoke-DSCJob { $true }
            $configuration = @{ AllNodes = @(@{ NodeName = 'web-01'; Role = @('WebAdaptor') }); ConfigData = @{ OldVersion = '11.4'; WebAdaptor = @{ IsJavaWebAdaptor = $true } } }

            $result = Invoke-JavaWebAdaptorUninstallUpgradeScript -cf $configuration -UseWinRMSSL $true -DebugMode $true

            $result | Should Be $true
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $ConfigurationName -eq 'JavaWebAdaptorUpgradeUninstall' -and
                $UseWinRMSSL -and $DebugMode -and
                $Arguments.OldVersion -eq '11.4' -and
                $Arguments.ConfigurationData.AllNodes[0].PSDscAllowPlainTextPassword -eq $true
            }
        }

        It 'preserves encryption certificate metadata for Java Web Adaptor uninstall nodes' {
            Mock Invoke-DSCJob { $true }
            $configuration = @{ AllNodes = @(@{ NodeName = 'web-01'; Role = @('WebAdaptor'); TargetNodeEncryptionCertificateFilePath = 'C:\node.cer'; TargetNodeEncryptionCertificateThumbprint = 'ABC' }); ConfigData = @{ OldVersion = '11.4'; WebAdaptor = @{ IsJavaWebAdaptor = $true } } }

            Invoke-JavaWebAdaptorUninstallUpgradeScript -cf $configuration

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $Arguments.ConfigurationData.AllNodes[0].CertificateFile -eq 'C:\node.cer' -and
                $Arguments.ConfigurationData.AllNodes[0].Thumbprint -eq 'ABC' -and
                -not $Arguments.ConfigurationData.AllNodes[0].ContainsKey('PSDscAllowPlainTextPassword')
            }
        }

        It 'throws when the Java Web Adaptor uninstall DSC job fails' {
            Mock Invoke-DSCJob { $false }
            $exception = $null
            try {
                Invoke-JavaWebAdaptorUninstallUpgradeScript -cf @{ AllNodes = @(@{ NodeName = 'web-01'; Role = @('WebAdaptor') }); ConfigData = @{ OldVersion = '11.4'; WebAdaptor = @{ IsJavaWebAdaptor = $true } } }
            }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Uninstall of ArcGIS Java Web Adaptor failed while upgrading'
        }
    }

    Describe 'Invoke-PortalUpgradeScript dispatch and failures' {
        BeforeEach {
            Mock Get-PasswordFromObject { ConvertTo-SecureString 'secret' -AsPlainText -Force }
            Mock Invoke-DSCJob { $true }
        }

        It 'dispatches PortalUpgrade and PortalPostUpgrade for a single Portal node' {
            $configuration = New-UpgradeConfiguration -Nodes @(@{ NodeName = 'portal-01'; Role = @('Portal') })

            $result = Invoke-PortalUpgradeScript -PortalConfig $configuration -EnableMSILogging $true

            $result | Should Be $true
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter { $ConfigurationName -eq 'PortalUpgrade' -and $Arguments.ConfigurationData.AllNodes.Count -eq 1 -and $Arguments.ConfigurationData.AllNodes[0].PortalLicenseFilePath -eq 'C:\licenses\portal.json' }
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter { $ConfigurationName -eq 'PortalPostUpgrade' -and $Arguments.ConfigurationData.AllNodes[0].NodeName -eq 'portal-01' }
        }

        It 'builds a multi-machine Portal upgrade with per-node license override and web styles' {
            $configuration = New-UpgradeConfiguration -Nodes @(@{ NodeName = 'portal-01'; Role = @('Portal') }, @{ NodeName = 'portal-02'; Role = @('Portal'); PortalLicenseFilePath = 'C:\licenses\portal-02.json' })
            $configuration.ConfigData.Portal.Installer.WebStylesPath = 'C:\installers\styles.exe'
            $configuration.ConfigData.Portal.Installer.WebStylesInstallerIsSelfExtracting = $false

            Invoke-PortalUpgradeScript -PortalConfig $configuration

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $ConfigurationName -eq 'PortalUpgrade' -and
                $Arguments.IsMultiMachinePortal -eq $true -and
                $Arguments.ConfigurationData.AllNodes.Count -eq 2 -and
                $Arguments.ConfigurationData.AllNodes[1].PortalLicenseFilePath -eq 'C:\licenses\portal-02.json' -and
                $Arguments.WebStylesInstallerPath -eq 'C:\installers\styles.exe' -and
                $Arguments.WebStylesInstallerIsSelfExtracting -eq $false
            }
        }

        It 'dispatches a Portal Web Adaptor upgrade when a Portal adaptor node is present' {
            $configuration = New-UpgradeConfiguration -Nodes @(@{ NodeName = 'portal-01'; Role = @('Portal') }, @{ NodeName = 'web-01'; Role = @('WebAdaptor'); WebAdaptorConfig = @{ Role = @('Portal') } })
            $configuration.ConfigData.PortalContext = 'portal'
            Mock Invoke-CreateNodeToAdd { @{ NodeName = $Node.NodeName; WebAdaptorConfig = @(@{ Role = 'Portal'; Context = 'portal' }) } }

            Invoke-PortalUpgradeScript -PortalConfig $configuration

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter { $ConfigurationName -eq 'WebAdaptorUpgrade' -and $Arguments.WebAdaptorRole -eq 'Portal' -and $Arguments.ComponentHostName -eq 'portal-01' }
        }

        It 'stops before post-upgrade when the Portal installation job fails' {
            Mock Invoke-DSCJob { if($ConfigurationName -eq 'PortalUpgrade') { $false } else { $true } }
            $exception = $null
            try { Invoke-PortalUpgradeScript -PortalConfig (New-UpgradeConfiguration -Nodes @(@{ NodeName = 'portal-01'; Role = @('Portal') })) }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Portal Upgrade Install Step Failed'
            Assert-MockCalled Invoke-DSCJob -Exactly 0 -Scope It -ParameterFilter { $ConfigurationName -eq 'PortalPostUpgrade' }
        }

        It 'throws a post-upgrade failure after a successful Portal installation' {
            Mock Invoke-DSCJob { if($ConfigurationName -eq 'PortalPostUpgrade') { $false } else { $true } }
            $exception = $null
            try { Invoke-PortalUpgradeScript -PortalConfig (New-UpgradeConfiguration -Nodes @(@{ NodeName = 'portal-01'; Role = @('Portal') })) }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Portal Post Upgrade Step for Primary Portal Machine Failed'
        }
    }

    Describe 'Invoke-ServerUpgradeScript role mapping and failures' {
        BeforeEach {
            Mock Get-PasswordFromObject { ConvertTo-SecureString 'secret' -AsPlainText -Force }
            Mock Invoke-DSCJob { $true }
        }

        It 'maps <ConfiguredRole> to <ExpectedRole> for server upgrade nodes' -TestCases @(
            @{ ConfiguredRole = 'RasterAnalytics'; ExpectedRole = 'ImageServer' }
            @{ ConfiguredRole = 'ImageHosting'; ExpectedRole = 'ImageServer' }
            @{ ConfiguredRole = 'NotebookServer'; ExpectedRole = 'NotebookServer' }
        ) {
            param($ConfiguredRole, $ExpectedRole)
            $configuration = New-UpgradeConfiguration -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') })
            $configuration.ConfigData.ServerRole = $ConfiguredRole

            Invoke-ServerUpgradeScript -cf $configuration

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter { $ConfigurationName -eq 'ServerUpgrade' -and $Arguments.ConfigurationData.AllNodes[0].ServerRole -eq $ExpectedRole }
        }

        It 'maps ImageHosting and RasterAnalytics additional roles to ImageServer' {
            $configuration = New-UpgradeConfiguration -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') })
            $configuration.ConfigData.AdditionalServerRoles = @('ImageHosting', 'RasterAnalytics', 'GeoEvent')

            Invoke-ServerUpgradeScript -cf $configuration

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $Arguments.ConfigurationData.AllNodes[0].ServerRole -eq 'GeneralPurposeServer' -and
                $Arguments.ConfigurationData.AllNodes[0].AdditionalServerRoles.Count -eq 3 -and
                $Arguments.ConfigurationData.AllNodes[0].AdditionalServerRoles[0] -eq 'ImageServer' -and
                $Arguments.ConfigurationData.AllNodes[0].AdditionalServerRoles[1] -eq 'ImageServer' -and
                $Arguments.ConfigurationData.AllNodes[0].AdditionalServerRoles[2] -eq 'GeoEvent'
            }
        }

        It 'marks a two-node server site and dispatches an upgrade for each node' {
            $configuration = New-UpgradeConfiguration -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') }, @{ NodeName = 'server-02'; Role = @('Server') })

            Invoke-ServerUpgradeScript -cf $configuration

            Assert-MockCalled Invoke-DSCJob -Exactly 2 -Scope It -ParameterFilter { $ConfigurationName -eq 'ServerUpgrade' -and $Arguments.IsMultiMachineServerSite -eq $true }
        }

        It 'stops at the first failed server upgrade job' {
            $calls = 0
            Mock Invoke-DSCJob { $calls++; if($calls -eq 1) { $false } else { $true } }
            $exception = $null
            try { Invoke-ServerUpgradeScript -cf (New-UpgradeConfiguration -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') }, @{ NodeName = 'server-02'; Role = @('Server') })) }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Server Upgrade Failed'
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter { $ConfigurationName -eq 'ServerUpgrade' }
        }

        It 'rejects Notebook Server sample data at unsupported version <Version> before DSC dispatch' -TestCases @(
            @{ Version = '11.4' }
            @{ Version = '11.5' }
        ) {
            param($Version)
            $configuration = New-UpgradeConfiguration -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') })
            $configuration.ConfigData.Version = $Version
            $configuration.ConfigData.ServerRole = 'NotebookServer'
            $configuration.ConfigData.Server.Installer.NotebookServerSamplesDataPath = 'C:\samples.exe'
            $exception = $null
            try { Invoke-ServerUpgradeScript -cf $configuration }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Notebook Server Samples Data Path is only supported for 10.9.1, 11.0, 11.1, 11.2, 11.3.'
            Assert-MockCalled Invoke-DSCJob -Exactly 0 -Scope It
        }

        It 'adds GeoEvent and Workflow Manager credentials, installers, and patch settings to a general-purpose Server upgrade' {
            $configuration = New-UpgradeConfiguration -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') })
            $configuration.ConfigData.AdditionalServerRoles = @('GeoEvent', 'WorkflowManagerServer')
            $configuration.ConfigData.GeoEventServer = @{
                LicenseFilePath = 'C:\licenses\geoevent.json'
                LicensePassword = 'geoevent-license-password'
                UserBackupConfigFiles = $true
                Installer = @{ Path = 'C:\installers\geoevent.exe'; IsSelfExtracting = $false; PatchesDir = 'C:\patches\geoevent'; PatchInstallOrder = @('patch-1') }
            }
            $configuration.ConfigData.WorkflowManagerServer = @{
                LicenseFilePath = 'C:\licenses\workflow.json'
                LicensePassword = 'workflow-license-password'
                Installer = @{ Path = 'C:\installers\workflow.exe'; IsSelfExtracting = $false; PatchesDir = 'C:\patches\workflow'; PatchInstallOrder = @('patch-2') }
            }
            Mock Resolve-SecretFromObject { ConvertTo-SecureString 'extension-secret' -AsPlainText -Force }

            Invoke-ServerUpgradeScript -cf $configuration

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $ConfigurationName -eq 'ServerUpgrade' -and
                $Arguments.ConfigurationData.AllNodes[0].AdditionalServerRoles.Count -eq 2 -and
                $Arguments.ConfigurationData.AllNodes[0].GeoeventServerLicenseFilePath -eq 'C:\licenses\geoevent.json' -and
                $Arguments.ConfigurationData.AllNodes[0].GeoeventServerLicensePassword.GetNetworkCredential().Password -eq 'extension-secret' -and
                $Arguments.ConfigurationData.AllNodes[0].WorkflowManagerServerLicenseFilePath -eq 'C:\licenses\workflow.json' -and
                $Arguments.ConfigurationData.AllNodes[0].WorkflowManagerServerLicensePassword.GetNetworkCredential().Password -eq 'extension-secret' -and
                $Arguments.GeoEventServerInstaller -eq 'C:\installers\geoevent.exe' -and
                -not $Arguments.GeoEventServerInstallerIsSelfExtracting -and
                $Arguments.GeoEventUserBackupConfigFiles -and
                $Arguments.WorkflowManagerServerInstaller -eq 'C:\installers\workflow.exe' -and
                -not $Arguments.WorkflowManagerInstallerIsSelfExtracting -and
                $Arguments.WorkflowManagerServerPatchesDir -eq 'C:\patches\workflow'
            }
        }
    }

    Describe 'Invoke-ServerUpgradeScript Notebook post-install phases' {
        BeforeEach {
            Mock Get-PasswordFromObject { ConvertTo-SecureString 'upgrade-secret' -AsPlainText -Force }
            $script:notebookUpgradeCalls = @()
            Mock Invoke-DSCJob {
                $script:notebookUpgradeCalls += [PSCustomObject]@{
                    Name = $ConfigurationName
                    Folder = $ConfigurationFolderPath
                    Arguments = $Arguments
                    Credential = $Credential
                    UseWinRMSSL = $UseWinRMSSL
                    DebugMode = $DebugMode
                }
                $true
            }
        }

        It 'selects Notebook upgrade post-install work for <Case>' -TestCases @(
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
            $configuration = New-UpgradeConfiguration -Nodes @(@{ NodeName = 'notebook-01'; Role = @('Server') })
            $configuration.ConfigData.Version = $Version
            $configuration.ConfigData.ServerRole = 'NotebookServer'
            $configuration.ConfigData.Server.ContainerImagePaths = $Images
            $configuration.ConfigData.Credentials.ServiceAccount.IsMSAAccount = $MSA
            if ($Samples) { $configuration.ConfigData.Server.Installer.NotebookServerSamplesDataPath = 'C:\installers\samples.exe' }

            $result = Invoke-ServerUpgradeScript -cf $configuration

            $result | Should Be $true
            $expectedNames = @('ServerUpgrade')
            if ($ExpectedPostInstall) { $expectedNames += 'ArcGISNotebookPostInstall' }
            $script:notebookUpgradeCalls.Name | Should Be $expectedNames
            $script:notebookUpgradeCalls[0].Arguments.ContainsKey('ContainerImagePaths') | Should Be $false
            $script:notebookUpgradeCalls[0].Arguments.ContainsKey('SiteAdministratorCredential') | Should Be $false
            if ($Samples) {
                $script:notebookUpgradeCalls[0].Arguments.NotebookServerSamplesDataPath | Should Be 'C:\installers\samples.exe'
            }
            if ($ExpectedPostInstall) {
                $postInstall = $script:notebookUpgradeCalls[1]
                $postInstall.Folder | Should Be 'Configurations-OnPrem'
                $postInstall.Arguments.Version | Should Be $Version
                $postInstall.Arguments.ContainerImagePaths.Count | Should Be $Images.Count
                if ($Images.Count -gt 0) { $postInstall.Arguments.ContainerImagePaths | Should Be $Images }
                $postInstall.Arguments.ExtractSamples | Should Be $Samples
                $postInstall.Arguments.ServiceCredentialIsMSA | Should Be $MSA
                $postInstall.Arguments.ServiceCredential.UserName | Should Be 'CONTOSO\svc-arcgis'
                $postInstall.Arguments.ServiceCredential.GetNetworkCredential().Password | Should Be 'upgrade-secret'
                $postInstall.Arguments.ServerPrimarySiteAdminCredential.UserName | Should Be 'siteadmin'
                $postInstall.Arguments.ServerPrimarySiteAdminCredential.GetNetworkCredential().Password | Should Be 'upgrade-secret'
                $postInstall.Arguments.ConfigurationData.AllNodes.Count | Should Be 1
                $postInstall.Arguments.ConfigurationData.AllNodes[0].NodeName | Should Be 'notebook-01'
            } else {
                Assert-MockCalled Invoke-DSCJob -Exactly 0 -Scope It -ParameterFilter { $ConfigurationName -eq 'ArcGISNotebookPostInstall' }
            }
        }

        It 'runs Notebook post-install after each upgraded node with connection options' {
            $configuration = New-UpgradeConfiguration -Nodes @(
                @{ NodeName = 'notebook-01'; Role = @('Server'); TargetNodeEncryptionCertificateFilePath = 'C:\certificates\node.cer'; TargetNodeEncryptionCertificateThumbprint = 'ABC123' }
                @{ NodeName = 'notebook-02'; Role = @('Server') }
            )
            $configuration.ConfigData.Version = '12.2'
            $configuration.ConfigData.ServerRole = 'NotebookServer'
            $configuration.ConfigData.Server.ContainerImagePaths = @('C:\images\standard.tar')
            $credential = New-Object System.Management.Automation.PSCredential 'CONTOSO\deployer', (ConvertTo-SecureString 'deploy-secret' -AsPlainText -Force)

            $result = Invoke-ServerUpgradeScript -cf $configuration -Credential $credential -UseWinRMSSL $true -DebugMode $true

            $result | Should Be $true
            $script:notebookUpgradeCalls.Name | Should Be @('ServerUpgrade', 'ArcGISNotebookPostInstall', 'ServerUpgrade', 'ArcGISNotebookPostInstall')
            $postInstalls = @($script:notebookUpgradeCalls | Where-Object { $_.Name -eq 'ArcGISNotebookPostInstall' })
            $postInstalls[0].Arguments.ConfigurationData.AllNodes[0].NodeName | Should Be 'notebook-01'
            $postInstalls[0].Arguments.ConfigurationData.AllNodes[0].CertificateFile | Should Be 'C:\certificates\node.cer'
            $postInstalls[0].Arguments.ConfigurationData.AllNodes[0].Thumbprint | Should Be 'ABC123'
            $postInstalls[0].Arguments.ConfigurationData.AllNodes[0].ContainsKey('PSDscAllowPlainTextPassword') | Should Be $false
            $postInstalls[1].Arguments.ConfigurationData.AllNodes[0].NodeName | Should Be 'notebook-02'
            $postInstalls[1].Arguments.ConfigurationData.AllNodes[0].PSDscAllowPlainTextPassword | Should Be $true
            foreach ($call in $script:notebookUpgradeCalls) {
                $call.Arguments.ConfigurationData.AllNodes.Count | Should Be 1
                $call.Credential.UserName | Should Be 'CONTOSO\deployer'
                $call.Credential.GetNetworkCredential().Password | Should Be 'deploy-secret'
                $call.UseWinRMSSL | Should Be $true
                $call.DebugMode | Should Be $true
            }
        }

        It 'stops later Notebook nodes and Web Adaptors when <Stage> fails' -TestCases @(
            @{ Stage = 'ServerUpgrade'; ExpectedNames = @('ServerUpgrade') }
            @{ Stage = 'ArcGISNotebookPostInstall'; ExpectedNames = @('ServerUpgrade', 'ArcGISNotebookPostInstall') }
        ) {
            param($Stage, $ExpectedNames)
            $configuration = New-UpgradeConfiguration -Nodes @(
                @{ NodeName = 'notebook-01'; Role = @('Server') }
                @{ NodeName = 'notebook-02'; Role = @('Server') }
                @{ NodeName = 'web-01'; Role = @('WebAdaptor'); WebAdaptorConfig = @(@{ Role = 'Server' }) }
            )
            $configuration.ConfigData.ServerRole = 'NotebookServer'
            $configuration.ConfigData.Server.ContainerImagePaths = @('C:\images\standard.tar')
            Mock Invoke-DSCJob {
                $script:notebookUpgradeCalls += [PSCustomObject]@{ Name = $ConfigurationName; Arguments = $Arguments }
                $false
            } -ParameterFilter { $ConfigurationName -eq $Stage }

            { Invoke-ServerUpgradeScript -cf $configuration } | Should Throw 'Server Upgrade Failed'

            $script:notebookUpgradeCalls.Name | Should Be $ExpectedNames
            $script:notebookUpgradeCalls[0].Arguments.ConfigurationData.AllNodes[0].NodeName | Should Be 'notebook-01'
            Assert-MockCalled Invoke-DSCJob -Exactly 0 -Scope It -ParameterFilter { $ConfigurationName -eq 'WebAdaptorUpgrade' }
        }
    }

    # Upgrade tests keep the versioned fixture real but replace every DSC job.
    # Stage-specific failures must prevent subsequent dispatch, not just return an
    # error after an install/configure stage has already been attempted.
    Describe 'Invoke-DataStoreUpgradeScript ordering and failure behavior' {
        BeforeEach {
            Mock Get-PasswordFromObject { ConvertTo-SecureString 'secret' -AsPlainText -Force }
            Mock Invoke-DSCJob { $true }
        }

        It 'installs and configures a relational Data Store against the first Server node' {
            $configuration = New-UpgradeConfiguration -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') }, @{ NodeName = 'datastore-01'; Role = @('DataStore'); DataStoreTypes = @('Relational') })

            Invoke-DataStoreUpgradeScript -DSConfig $configuration

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter { $ConfigurationName -eq 'DataStoreUpgradeInstall' -and $Arguments.ConfigurationData.AllNodes[0].NodeName -eq 'datastore-01' }
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter { $ConfigurationName -eq 'DataStoreUpgradeConfigure' -and $Arguments.ServerMachineName -eq 'server-01' -and $Arguments.ConfigurationData.AllNodes[0].HasRelationalStore -eq $true }
        }

        It 'runs pre-install before Data Store installation when failover on primary stop is enabled' {
            $configuration = New-UpgradeConfiguration -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') }, @{ NodeName = 'datastore-01'; Role = @('DataStore'); DataStoreTypes = @('Relational') })
            $configuration.ConfigData.DataStore.EnableFailoverOnPrimaryStop = $true

            Invoke-DataStoreUpgradeScript -DSConfig $configuration

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter { $ConfigurationName -eq 'DataStoreUpgradePreInstall' -and $Arguments.PrimaryDataStore -eq 'datastore-01' }
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter { $ConfigurationName -eq 'DataStoreUpgradeInstall' }
        }

        It 'fails before installation when the Data Store pre-install job fails' {
            Mock Invoke-DSCJob { if($ConfigurationName -eq 'DataStoreUpgradePreInstall') { $false } else { $true } }
            $configuration = New-UpgradeConfiguration -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') }, @{ NodeName = 'datastore-01'; Role = @('DataStore'); DataStoreTypes = @('Relational') })
            $configuration.ConfigData.DataStore.EnableFailoverOnPrimaryStop = $true
            $exception = $null
            try { Invoke-DataStoreUpgradeScript -DSConfig $configuration }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Data Store Pre Upgrade Install Step failed.'
            Assert-MockCalled Invoke-DSCJob -Exactly 0 -Scope It -ParameterFilter { $ConfigurationName -eq 'DataStoreUpgradeInstall' }
        }

        It 'configures a Tile Cache store separately when it is on a different machine' {
            $configuration = New-UpgradeConfiguration -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') }, @{ NodeName = 'datastore-01'; Role = @('DataStore'); DataStoreTypes = @('Relational') }, @{ NodeName = 'tilecache-01'; Role = @('DataStore'); DataStoreTypes = @('TileCache') })

            Invoke-DataStoreUpgradeScript -DSConfig $configuration

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter { $ConfigurationName -eq 'DataStoreUpgradeConfigure' -and $Arguments.ConfigurationData.AllNodes[0].NodeName -eq 'tilecache-01' -and $Arguments.ConfigurationData.AllNodes[0].HasMultiMachineTileCache -eq $false }
        }

        It 'stops configuring after a Data Store upgrade install failure' {
            Mock Invoke-DSCJob { if($ConfigurationName -eq 'DataStoreUpgradeInstall') { $false } else { $true } }
            $exception = $null
            try { Invoke-DataStoreUpgradeScript -DSConfig (New-UpgradeConfiguration -Nodes @(@{ NodeName = 'server-01'; Role = @('Server') }, @{ NodeName = 'datastore-01'; Role = @('DataStore'); DataStoreTypes = @('Relational') })) }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Data Store Upgrade Install Step failed.'
            Assert-MockCalled Invoke-DSCJob -Exactly 0 -Scope It -ParameterFilter { $ConfigurationName -eq 'DataStoreUpgradeConfigure' }
        }

        It 'installs and configures every Data Store type on its own machine' {
            $configuration = New-UpgradeConfiguration -Nodes @(
                @{ NodeName = 'server-01'; Role = @('Server') }
                @{ NodeName = 'relational-01'; Role = @('DataStore'); DataStoreTypes = @('Relational') }
                @{ NodeName = 'tilecache-01'; Role = @('DataStore'); DataStoreTypes = @('TileCache') }
                @{ NodeName = 'spatiotemporal-01'; Role = @('DataStore'); DataStoreTypes = @('SpatioTemporal') }
                @{ NodeName = 'objectstore-01'; Role = @('DataStore'); DataStoreTypes = @('ObjectStore') }
                @{ NodeName = 'graphstore-01'; Role = @('DataStore'); DataStoreTypes = @('GraphStore') }
            )

            Invoke-DataStoreUpgradeScript -DSConfig $configuration

            Assert-MockCalled Invoke-DSCJob -Exactly 5 -Scope It -ParameterFilter { $ConfigurationName -eq 'DataStoreUpgradeInstall' }
            Assert-MockCalled Invoke-DSCJob -Exactly 5 -Scope It -ParameterFilter { $ConfigurationName -eq 'DataStoreUpgradeConfigure' }
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter { $ConfigurationName -eq 'DataStoreUpgradeConfigure' -and $Arguments.ConfigurationData.AllNodes[0].NodeName -eq 'relational-01' -and $Arguments.ConfigurationData.AllNodes[0].HasRelationalStore }
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter { $ConfigurationName -eq 'DataStoreUpgradeConfigure' -and $Arguments.ConfigurationData.AllNodes[0].NodeName -eq 'tilecache-01' -and -not $Arguments.ConfigurationData.AllNodes[0].HasMultiMachineTileCache }
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter { $ConfigurationName -eq 'DataStoreUpgradeConfigure' -and $Arguments.ConfigurationData.AllNodes[0].NodeName -eq 'spatiotemporal-01' }
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter { $ConfigurationName -eq 'DataStoreUpgradeConfigure' -and $Arguments.ConfigurationData.AllNodes[0].NodeName -eq 'objectstore-01' -and $Arguments.ConfigurationData.AllNodes[0].HasObjectStore }
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter { $ConfigurationName -eq 'DataStoreUpgradeConfigure' -and $Arguments.ConfigurationData.AllNodes[0].NodeName -eq 'graphstore-01' }
        }

        It 'preserves Data Store node encryption metadata throughout upgrade installation and configuration' {
            $configuration = New-UpgradeConfiguration -Nodes @(
                @{ NodeName = 'server-01'; Role = @('Server') }
                @{ NodeName = 'datastore-01'; Role = @('DataStore'); DataStoreTypes = @('Relational'); TargetNodeEncryptionCertificateFilePath = 'C:\datastore.cer'; TargetNodeEncryptionCertificateThumbprint = 'DATASTORE' }
            )

            Invoke-DataStoreUpgradeScript -DSConfig $configuration

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $ConfigurationName -eq 'DataStoreUpgradeInstall' -and
                $Arguments.ConfigurationData.AllNodes[0].CertificateFile -eq 'C:\datastore.cer' -and
                $Arguments.ConfigurationData.AllNodes[0].Thumbprint -eq 'DATASTORE' -and
                -not $Arguments.ConfigurationData.AllNodes[0].ContainsKey('PSDscAllowPlainTextPassword')
            }
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $ConfigurationName -eq 'DataStoreUpgradeConfigure' -and
                $Arguments.ConfigurationData.AllNodes[0].CertificateFile -eq 'C:\datastore.cer'
            }
        }

        It 'throws the correct error when <DataStoreType> configuration fails after installation' -TestCases @(
            @{ DataStoreType = 'Relational'; Expected = 'Relational Data Store Upgrade Configure Step failed.' }
            @{ DataStoreType = 'TileCache'; Expected = 'Tile Cache Data Store Upgrade Configure Step failed.' }
            @{ DataStoreType = 'SpatioTemporal'; Expected = 'Spatiotemporal Big Data Store Upgrade Configure Step failed.' }
            @{ DataStoreType = 'ObjectStore'; Expected = 'Object Store Upgrade Configure Step failed.' }
            @{ DataStoreType = 'GraphStore'; Expected = 'Graph Store Upgrade Configure Step failed.' }
        ) {
            param($DataStoreType, $Expected)
            Mock Invoke-DSCJob { if($ConfigurationName -eq 'DataStoreUpgradeConfigure') { $false } else { $true } }
            $configuration = New-UpgradeConfiguration -Nodes @(
                @{ NodeName = 'server-01'; Role = @('Server') }
                @{ NodeName = 'datastore-01'; Role = @('DataStore'); DataStoreTypes = @($DataStoreType) }
            )
            $exception = $null

            try { Invoke-DataStoreUpgradeScript -DSConfig $configuration }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be $Expected
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $ConfigurationName -eq 'DataStoreUpgradeConfigure' -and
                $Arguments.ConfigurationData.AllNodes[0].NodeName -eq 'datastore-01'
            }
        }
    }

    # IIS and Java variants forward different prerequisites. Assert their dispatched
    # settings without compiling DSC, installing IIS bundles, or touching Tomcat;
    # certificate-file values here describe node encryption metadata only.
    Describe 'Web Adaptor upgrade variants' {
        BeforeEach {
            Mock Get-PasswordFromObject { ConvertTo-SecureString 'secret' -AsPlainText -Force }
            Mock Invoke-DSCJob { $true }
        }

        It 'builds a Server Web Adaptor upgrade with modern IIS prerequisites' {
            $configuration = New-UpgradeConfiguration -Nodes @(
                @{ NodeName = 'server-01'; Role = @('Server') }
                @{ NodeName = 'web-01'; Role = @('WebAdaptor'); WebAdaptorConfig = @{ Role = @('Server') } }
            )
            $configuration.ConfigData.ServerContext = 'server'
            $configuration.ConfigData.WebAdaptor.Installer.DotnetHostingBundlePath = 'C:\installers\hosting.exe'
            $configuration.ConfigData.WebAdaptor.Installer.WebDeployPath = 'C:\installers\webdeploy.msi'
            Mock Invoke-CreateNodeToAdd { @{ NodeName = $Node.NodeName; WebAdaptorConfig = @(@{ Role = 'Server'; Context = 'server' }) } }

            Invoke-ServerUpgradeScript -cf $configuration -EnableMSILogging $true

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $ConfigurationName -eq 'WebAdaptorUpgrade' -and
                $Arguments.WebAdaptorRole -eq 'Server' -and
                $Arguments.Component -eq 'Server' -and
                $Arguments.ComponentHostName -eq 'server-01' -and
                $Arguments.DotnetHostingBundlePath -eq 'C:\installers\hosting.exe' -and
                $Arguments.WebDeployPath -eq 'C:\installers\webdeploy.msi'
            }
        }

        It 'builds a Java Portal Web Adaptor upgrade with Java-specific parameters' {
            $configuration = New-UpgradeConfiguration -Nodes @(
                @{ NodeName = 'portal-01'; Role = @('Portal') }
                @{ NodeName = 'web-01'; Role = @('WebAdaptor'); WebAdaptorConfig = @{ Role = @('Portal') } }
            )
            $configuration.ConfigData.PortalContext = 'portal'
            $configuration.ConfigData.WebAdaptor.IsJavaWebAdaptor = $true
            $configuration.ConfigData.WebAdaptor.JavaWebServerType = 'ApacheTomcat10'
            $configuration.ConfigData.WebAdaptor.JavaWebServerWebAppDirectory = 'C:\Tomcat\webapps'
            $configuration.ConfigData.WebAdaptor.Installer.InstallDir = 'C:\ArcGIS\WebAdaptorJava'
            Mock Invoke-CreateNodeToAdd { @{ NodeName = $Node.NodeName; WebAdaptorConfig = @(@{ Role = 'Portal'; Context = 'portal' }) } }

            Invoke-PortalUpgradeScript -PortalConfig $configuration

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $ConfigurationName -eq 'WebAdaptorUpgrade' -and
                $Arguments.WebAdaptorRole -eq 'Portal' -and
                $Arguments.IsJavaWebAdaptor -and
                $Arguments.JavaInstallDir -eq 'C:\ArcGIS\WebAdaptorJava' -and
                $Arguments.JavaWebServerWebAppDirectory -eq 'C:\Tomcat\webapps' -and
                $Arguments.JavaWebServerType -eq 'ApacheTomcat10'
            }
        }

        It 'retains encryption metadata when upgrading a Portal node' {
            $configuration = New-UpgradeConfiguration -Nodes @(
                @{ NodeName = 'portal-01'; Role = @('Portal'); TargetNodeEncryptionCertificateFilePath = 'C:\portal.cer'; TargetNodeEncryptionCertificateThumbprint = 'PORTAL' }
            )

            Invoke-PortalUpgradeScript -PortalConfig $configuration

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $ConfigurationName -eq 'PortalUpgrade' -and
                $Arguments.ConfigurationData.AllNodes[0].CertificateFile -eq 'C:\portal.cer' -and
                $Arguments.ConfigurationData.AllNodes[0].Thumbprint -eq 'PORTAL' -and
                -not $Arguments.ConfigurationData.AllNodes[0].ContainsKey('PSDscAllowPlainTextPassword')
            }
        }

        It 'fails the Server upgrade when its Web Adaptor upgrade job fails' {
            $configuration = New-UpgradeConfiguration -Nodes @(
                @{ NodeName = 'server-01'; Role = @('Server') }
                @{ NodeName = 'web-01'; Role = @('WebAdaptor'); WebAdaptorConfig = @{ Role = @('Server') } }
            )
            Mock Invoke-CreateNodeToAdd { @{ NodeName = $Node.NodeName; WebAdaptorConfig = @(@{ Role = 'Server'; Context = 'arcgis' }) } }
            Mock Invoke-DSCJob { if($ConfigurationName -eq 'WebAdaptorUpgrade') { $false } else { $true } }
            $exception = $null

            try { Invoke-ServerUpgradeScript -cf $configuration }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Server WebAdaptors Upgrade Failed'
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter { $ConfigurationName -eq 'ServerUpgrade' }
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter { $ConfigurationName -eq 'WebAdaptorUpgrade' }
        }
    }

    Describe 'Invoke-ArcGISConfiguration early validation and dispatch' {
        BeforeEach {
            Mock Assert-PowerShellVersionIs51 {}
            Mock Assert-TargetNodePowerShellVersionIs51 {}
            Mock Get-DownloadsInstallsConfigurationData { @{ AllNodes = @(@{ NodeName = 'server-01'; Role = @('Server'); PSDscAllowPlainTextPassword = $true }); ConfigData = @{ Version = '11.5' } } }
            Mock Invoke-DSCJob { $true }
        }

        It 'rejects <Scenario> before calling DSC' -TestCases @(
            @{ Scenario = 'Enterprise 10.8'; Json = '{"AllNodes":[{"NodeName":"server-01","Role":["Server"]}],"ConfigData":{"Version":"10.8"}}'; Expected = '[ERROR] DSC Module only supports ArcGIS Enterprise 10.9.1 and above.' }
            @{ Scenario = 'retired GeoAnalytics primary role'; Json = '{"AllNodes":[{"NodeName":"server-01","Role":["Server"]}],"ConfigData":{"Version":"11.4","ServerRole":"GeoAnalytics"}}'; Expected = '[ERROR] Starting at ArcGIS Enterprise 11.4, the GeoAnalytics Server role is retired. Please update your configuration file to modify the server role.' }
            @{ Scenario = 'retired GeoAnalytics additional role'; Json = '{"AllNodes":[{"NodeName":"server-01","Role":["Server"]}],"ConfigData":{"Version":"11.4","AdditionalServerRoles":["GeoAnalytics"]}}'; Expected = '[ERROR] Starting at ArcGIS Enterprise 11.4, the GeoAnalytics Server role is retired. Please update your configuration file to modify the server role.' }
            @{ Scenario = 'retired Tile Cache Data Store'; Json = '{"AllNodes":[{"NodeName":"datastore-01","Role":["DataStore"],"DataStoreTypes":["TileCache"]}],"ConfigData":{"Version":"12.0"}}'; Expected = '[ERROR] Starting at ArcGIS Enterprise 12.0, the Tile Cache Data Store is retired. Please update your configuration file.' }
            @{ Scenario = 'ArcGIS Pro 3.1'; Json = '{"AllNodes":[{"NodeName":"pro-01","Role":["Pro"]}],"ConfigData":{"Version":"11.5","ProVersion":"3.1"}}'; Expected = '[ERROR] DSC Module only supports ArcGIS Pro 3.2 and above.' }
            @{ Scenario = 'deprecated concurrent ArcGIS Pro license'; Json = '{"AllNodes":[{"NodeName":"pro-01","Role":["Pro"]}],"ConfigData":{"Version":"11.5","ProVersion":"3.7","Pro":{"AuthorizationType":"CONCURRENT_USE"}}}'; Expected = '[ERROR] Concurrent use license type was deprecated on July 1, 2025. It is only supported with ArcGIS Pro 3.6 and below.' }
        ) {
            param($Json, $Expected)
            Mock Get-Content { $Json }
            $exception = $null
            try { Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\config.json' -Mode Install }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be $Expected
            Assert-MockCalled Invoke-DSCJob -Exactly 0 -Scope It
        }

        It 'validates Java web server type before deployment dispatch' {
            Mock Get-Content { '{"AllNodes":[{"NodeName":"web-01","Role":["WebAdaptor"]}],"ConfigData":{"Version":"11.5","WebAdaptor":{"IsJavaWebAdaptor":true,"JavaWebServerType":"IIS"}}}' }
            Mock Test-IsValidJavaServerType { throw 'Invalid Java server type' }
            $exception = $null
            try { Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\config.json' -Mode Install }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Invalid Java server type'
            Assert-MockCalled Test-IsValidJavaServerType -Exactly 1 -Scope It -ParameterFilter { $JavaWebServerType -eq 'IIS' }
        }

        It 'rejects WebGISDR mode without its Portal WebGISDR configuration' {
            Mock Get-Content { '{"AllNodes":[{"NodeName":"portal-01","Role":["Portal"]}],"ConfigData":{"Version":"11.5"}}' }
            $exception = $null
            try { Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\config.json' -Mode WebGISDRExport }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'WebGISDR configuration is missing in the configuration file.'
            Assert-MockCalled Invoke-DSCJob -Exactly 0 -Scope It
        }

        It 'dispatches the install configuration with SSL, debug, and MSI logging flags' {
            Mock Get-Content { '{"AllNodes":[{"NodeName":"server-01","Role":["Server"]}],"ConfigData":{"Version":"11.5"}}' }

            Invoke-ArcGISConfiguration -ConfigurationParametersFile 'C:\config.json' -Mode Install -UseSSL -DebugSwitch -EnableMSILogging

            Assert-MockCalled Assert-TargetNodePowerShellVersionIs51 -Exactly 1 -Scope It -ParameterFilter { $ComputerName.Count -eq 1 -and $ComputerName[0] -eq 'server-01' -and $UseWinRMSSL }
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter { $ConfigurationName -eq 'ArcGISInstall' -and $ConfigurationFolderPath -eq 'Configurations-OnPrem' -and $UseWinRMSSL -and $DebugMode -and $Arguments.EnableMSILogging -eq $true }
        }
    }

    Describe 'Java and Tomcat validation boundaries' {
        It 'accepts each supported Java web server type' -TestCases @(
            @{ JavaWebServerType = 'ApacheTomcat9' }
            @{ JavaWebServerType = 'ApacheTomcat10' }
            @{ JavaWebServerType = 'GlassFish' }
            @{ JavaWebServerType = 'JBoss' }
            @{ JavaWebServerType = 'WebSphere' }
            @{ JavaWebServerType = 'WebLogic' }
        ) {
            param($JavaWebServerType)
            $exception = $null
            try { Test-IsValidJavaServerType -JavaWebServerType $JavaWebServerType }
            catch { $exception = $_ }

            $exception | Should Be $null
        }

        It 'enforces Tomcat version boundaries for <EnterpriseVersion> and <TomcatVersion>' -TestCases @(
            @{ EnterpriseVersion = '11.4'; TomcatVersion = '10.1.0'; Expected = 'only Apache Tomcat version 9.x is supported' }
            @{ EnterpriseVersion = '11.5'; TomcatVersion = '8.5.0'; Expected = 'must be either 9.x or 10.x' }
            @{ EnterpriseVersion = '12.0'; TomcatVersion = '9.0.90'; Expected = 'only Apache Tomcat version 10.x is supported' }
            @{ EnterpriseVersion = '11.4'; TomcatVersion = '9.0.90'; Expected = $null }
            @{ EnterpriseVersion = '11.5'; TomcatVersion = '10.1.0'; Expected = $null }
            @{ EnterpriseVersion = '12.0'; TomcatVersion = '10.1.0'; Expected = $null }
        ) {
            param($EnterpriseVersion, $TomcatVersion, $Expected)
            $exception = $null
            try { Test-IsValidTomcatConfig -TomcatConfig @{ Version = $TomcatVersion; Path = 'C:\Tomcat'; InstallDir = 'C:\Tomcat'; ServiceName = 'Tomcat'; SSLProtocol = 'TLSv1.2' } -EnterpriseVersion $EnterpriseVersion }
            catch { $exception = $_ }

            if($Expected) {
                $exception | Should Not Be $null
                $exception.Exception.Message | Should Match $Expected
            }
            else {
                $exception | Should Be $null
            }
        }
    }
}