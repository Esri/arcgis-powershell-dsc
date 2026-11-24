<#
    Covers Data Store configure/PITR request contracts, backup-tool arguments and output
    parsing, and upgrade-state interpretation. REST calls, URL/health waits, file checks,
    and process execution are mocked; no installed Data Store or CLI tool is required.

    Configure credentials are dummy PSCredentials; backup command output is synthesized
    locally so parsers run against representative table layouts. See ../../README.md.
#>
$moduleScriptPath = Join-Path $PSScriptRoot '..\..\..\Modules\ArcGIS\Modules\ArcGIS.Client\ArcGIS.Client.DataStore.psm1'

Import-Module $moduleScriptPath -Force

InModuleScope ArcGIS.Client.DataStore {
    Describe 'Data Store configure and PITR request contracts' {
        It 'waits for Data Store health and submits configure credentials and feature settings' {
            $credential = New-Object System.Management.Automation.PSCredential 'siteadmin', (ConvertTo-SecureString 'secret' -AsPlainText -Force)
            Mock Test-ArcGISComponentHealth {}
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ status = 'success'; configured = $true } }

            $response = Get-DataStoreInfo -URL 'https://datastore.example.test/arcgis' -ServerSiteAdminCredential $credential -ServerSiteUrl 'https://server.example.test/arcgis' -Referer 'https://portal.example.test'

            $response.configured | Should Be $true
            Assert-MockCalled Test-ArcGISComponentHealth -Exactly 1 -Scope It -ParameterFilter { $BaseURL -eq 'https://datastore.example.test/arcgis' -and $ComponentName -eq 'DataStore' -and $MaxWaitTimeInSeconds -eq 180 -and $SleepTimeInSeconds -eq 5 }
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://datastore.example.test/arcgis/datastoreadmin/configure' -and $HttpMethod -eq 'POST' -and $HttpFormParameters.username -eq 'siteadmin' -and $HttpFormParameters.password -eq 'secret' -and $HttpFormParameters.serverURL -eq 'https://server.example.test/arcgis' -and $HttpFormParameters.getConfigureInfo -eq 'true' -and $HttpFormParameters.dsSettings -match 'feature\.graphstore' }
        }

        It 'returns the enabled and disabled PITR states from successful responses' -TestCases @(
            @{ Enabled = $true; Expected = 'Enabled' }
            @{ Enabled = $false; Expected = 'Disabled' }
        ) {
            param($Enabled, $Expected)

            Mock Wait-ForUrl {}
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ status = 'success'; pitrEnabled = $Enabled } }

            $state = Get-PITRState -URL 'https://datastore.example.test/arcgis' -Referer 'https://portal.example.test'

            $state | Should Be $Expected
            Assert-MockCalled Wait-ForUrl -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://datastore.example.test/arcgis/datastoreadmin/configurePITR?f=json' -and $HttpMethod -eq 'GET' -and $MaxWaitTimeInSeconds -eq 180 }
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://datastore.example.test/arcgis/datastoreadmin/configurePITR' -and $HttpMethod -eq 'GET' -and $TimeOutSec -eq 600 }
        }

        It 'throws the PITR error contract for a non-successful state lookup' {
            Mock Wait-ForUrl {}
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ status = 'error' } }
            $exception = $null

            try {
                Get-PITRState -URL 'https://datastore.example.test/arcgis' -Referer 'https://portal.example.test'
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be '[ERROR] Configure PITR web request returned an error.'
        }

        It 'maps each requested PITR state to the expected enable-pitr request value' -TestCases @(
            # The API expects literal lowercase strings, not PowerShell Booleans.
            # Both directions must remain mapped correctly when constructing the form.
            @{ PITRState = 'Enabled'; ExpectedValue = 'true' }
            @{ PITRState = 'Disabled'; ExpectedValue = 'false' }
        ) {
            param($PITRState, $ExpectedValue)

            Mock Wait-ForUrl {}
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ status = 'success' } }

            Update-PITRState -URL 'https://datastore.example.test/arcgis' -Referer 'https://portal.example.test' -PITRState $PITRState

            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://datastore.example.test/arcgis/datastoreadmin/configurePITR' -and $HttpFormParameters.'enable-pitr' -eq $ExpectedValue -and $HttpFormParameters.f -eq 'json' -and $TimeOutSec -eq 600 }
        }

        It 'throws the endpoint error message when a PITR update returns an error payload' {
            Mock Wait-ForUrl {}
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ error = [PSCustomObject]@{ message = 'PITR configuration rejected' } } }
            $exception = $null

            try {
                Update-PITRState -URL 'https://datastore.example.test/arcgis' -Referer 'https://portal.example.test' -PITRState 'Enabled'
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'ERROR: failed. PITR configuration rejected'
        }
    }

    Describe 'Data Store backup tool contracts' {
        It 'parses tile-cache backup locations using the component-specific type heading' {
            # Keep the heading and intervening header rows: the parser locates the
            # component's table before reading rows. A bare data row would bypass
            # the layout that the real configurebackuplocation tool returns.
            Mock Invoke-DataStoreConfigureBackupLocationTool {
                'Backups locations for tile cache' + [System.Environment]::NewLine +
                'header one' + [System.Environment]::NewLine +
                'header two' + [System.Environment]::NewLine +
                'header three' + [System.Environment]::NewLine +
                'primary tilecache C:/arcgis/tile-backups false' + [System.Environment]::NewLine +
                'end'
            } -ParameterFilter { $DataStoreType -eq 'TileCache' -and $OperationType -eq 'list' }

            $locations = @(Get-DataStoreBackupLocation -DataStoreInstallDirectory 'C:\ArcGIS\DataStore' -DataStoreType 'TileCache' | Where-Object { $_ -is [hashtable] })

            $locations.Count | Should Be 1
            $locations[0]['Type'] | Should Be 'tilecache'
            $locations[0]['Location'] | Should Be 'C:\arcgis\tile-backups'
            $locations[0]['IsDefault'] | Should Be $false
            Assert-MockCalled Invoke-DataStoreConfigureBackupLocationTool -Exactly 1 -Scope It -ParameterFilter { $DataStoreType -eq 'TileCache' -and $OperationType -eq 'list' }
        }

        It 'returns no backup locations when the tool output does not contain the expected heading' {
            Mock Invoke-DataStoreConfigureBackupLocationTool { 'configurebackuplocation output unavailable' } -ParameterFilter { $DataStoreType -eq 'ObjectStore' -and $OperationType -eq 'list' }

            $locations = @(Get-DataStoreBackupLocation -DataStoreInstallDirectory 'C:\ArcGIS\DataStore' -DataStoreType 'ObjectStore')

            $locations.Count | Should Be 0
            Assert-MockCalled Invoke-DataStoreConfigureBackupLocationTool -Exactly 1 -Scope It -ParameterFilter { $DataStoreType -eq 'ObjectStore' -and $OperationType -eq 'list' }
        }

        It 'runs the backup tool with the store, location, and force arguments' {
            # Check arguments at the process boundary, but never execute the .bat file.
            # Distinct real/redacted dummy strings catch accidental substitution of
            # the logging-safe text into the executable command line.
            Mock Test-Path { $true }
            Mock Invoke-StartProcess { 'Completed successfully' }

            $output = Invoke-DataStoreConfigureBackupLocationTool -DataStoreInstallDirectory 'C:\ArcGIS\DataStore' -DataStoreType 'GraphStore' -OperationType 'register' -BackupLocationString 'C:\backups;password=real-secret' -RedactedBackupLocationString 'C:\backups;password=xxxxx' -ForceUpdate

            $output | Should Be 'Completed successfully'
            Assert-MockCalled Invoke-StartProcess -Exactly 1 -Scope It -ParameterFilter { $ExecPath -eq 'C:\ArcGIS\DataStore\tools\configurebackuplocation.bat' -and $Arguments -eq '--operation register --store graph --prompt no --location C:\backups;password=real-secret --force true' -and $EnvVariables.ContainsKey('AGSDATASTORE') -and $null -eq $EnvVariables['AGSDATASTORE'] }
        }

        It 'throws a process-boundary failure when the backup tool reports failed output' {
            Mock Test-Path { $true }
            Mock Invoke-StartProcess { 'failed' }
            $exception = $null

            try {
                Invoke-DataStoreConfigureBackupLocationTool -DataStoreInstallDirectory 'C:\ArcGIS\DataStore' -DataStoreType 'Relational' -OperationType 'list'
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Configure backup tool failed. Output - failed.'
        }

        It 'parses listed relational backup locations into typed result fields' {
            Mock Invoke-DataStoreConfigureBackupLocationTool {
                'Backups locations for relational' + [System.Environment]::NewLine +
                'header one' + [System.Environment]::NewLine +
                'header two' + [System.Environment]::NewLine +
                'header three' + [System.Environment]::NewLine +
                'primary relational C:/arcgis/backups true' + [System.Environment]::NewLine +
                'end'
            }

            $locations = @(Get-DataStoreBackupLocation -DataStoreInstallDirectory 'C:\ArcGIS\DataStore' -DataStoreType 'Relational' | Where-Object { $_ -is [hashtable] })

            $locations.Count | Should Be 1
            $locations[0]['Name'] | Should Be 'primary'
            $locations[0]['Location'] | Should Be 'C:\arcgis\backups'
            $locations[0]['Type'] | Should Be 'relational'
            $locations[0]['IsDefault'] | Should Be $true
            Assert-MockCalled Invoke-DataStoreConfigureBackupLocationTool -Exactly 1 -Scope It -ParameterFilter { $DataStoreType -eq 'Relational' -and $OperationType -eq 'list' }
        }
    }

    Describe 'Data Store backup CLI boundaries' {
        It 'rejects a missing backup executable without starting a process' {
            Mock Test-Path { $false }
            Mock Invoke-StartProcess { throw 'unexpected process execution' }

            { Invoke-DataStoreConfigureBackupLocationTool -DataStoreInstallDirectory 'C:\ArcGIS\DataStore' -DataStoreType 'Relational' -OperationType 'list' } | Should Throw 'C:\ArcGIS\DataStore\tools\configurebackuplocation.bat not found'

            Assert-MockCalled Test-Path -Exactly 1 -Scope It -ParameterFilter { $Path -eq 'C:\ArcGIS\DataStore\tools\configurebackuplocation.bat' }
            Assert-MockCalled Invoke-StartProcess -Exactly 0 -Scope It
        }

        It 'lists <DataStoreType> backups without location or force arguments' -TestCases @(
            @{ DataStoreType = 'Relational'; StoreArgument = 'relational' }
            @{ DataStoreType = 'TileCache'; StoreArgument = 'tileCache' }
            @{ DataStoreType = 'GraphStore'; StoreArgument = 'graph' }
            @{ DataStoreType = 'ObjectStore'; StoreArgument = 'object' }
            @{ DataStoreType = 'SpatioTemporal'; StoreArgument = 'spatiotemporal' }
        ) {
            param($DataStoreType, $StoreArgument)
            Mock Test-Path { $true }
            Mock Invoke-StartProcess { 'listed backups' }

            $output = Invoke-DataStoreConfigureBackupLocationTool -DataStoreInstallDirectory 'C:\ArcGIS\DataStore' -DataStoreType $DataStoreType -OperationType 'list' -BackupLocationString 'must-not-be-forwarded'

            $output | Should Be 'listed backups'
            Assert-MockCalled Invoke-StartProcess -Exactly 1 -Scope It
            Assert-MockCalled Invoke-StartProcess -Exactly 1 -Scope It -ParameterFilter {
                $ExecPath -eq 'C:\ArcGIS\DataStore\tools\configurebackuplocation.bat' -and
                $Arguments -ceq "--operation list --store $StoreArgument --prompt no" -and
                $EnvVariables.Count -eq 1 -and $EnvVariables.ContainsKey('AGSDATASTORE') -and
                $null -eq $EnvVariables['AGSDATASTORE']
            }
        }

        It 'passes the backup location to the <OperationType> operation without forcing an update' -TestCases @(
            @{ OperationType = 'unregister' }
            @{ OperationType = 'change' }
            @{ OperationType = 'setdefault' }
        ) {
            param($OperationType)
            Mock Test-Path { $true }
            Mock Invoke-StartProcess { 'location updated' }

            $output = Invoke-DataStoreConfigureBackupLocationTool -DataStoreInstallDirectory 'C:\ArcGIS\DataStore' -DataStoreType 'Relational' -OperationType $OperationType -BackupLocationString 'name=archive;location=C:\backups'

            $output | Should Be 'location updated'
            Assert-MockCalled Invoke-StartProcess -Exactly 1 -Scope It
            Assert-MockCalled Invoke-StartProcess -Exactly 1 -Scope It -ParameterFilter {
                $ExecPath -eq 'C:\ArcGIS\DataStore\tools\configurebackuplocation.bat' -and
                $Arguments -ceq "--operation $OperationType --store relational --prompt no --location name=archive;location=C:\backups"
            }
        }

        It 'protects verbose backup arguments using <RedactionMode> redaction' -TestCases @(
            @{
                RedactionMode = 'automatic'
                Location = 'name=archive;Password=first-secret;user=backup;PASSWORD=second-secret'
                RedactedLocation = $null
                ExpectedLogLocation = 'name=archive;Password=xxxxx;user=backup;PASSWORD=xxxxx'
            }
            @{
                RedactionMode = 'explicit'
                Location = 'name=archive;password=real-secret'
                RedactedLocation = 'name=archive;password=custom-mask'
                ExpectedLogLocation = 'name=archive;password=custom-mask'
            }
            @{
                RedactionMode = 'password-free'
                Location = 'name=archive;location=C:\backups;user=backup'
                RedactedLocation = ''
                ExpectedLogLocation = 'name=archive;location=C:\backups;user=backup'
            }
        ) {
            param($RedactionMode, $Location, $RedactedLocation, $ExpectedLogLocation)
            Mock Test-Path { $true }
            Mock Invoke-StartProcess { 'registered backup' }
            Mock Write-Verbose {}

            $output = Invoke-DataStoreConfigureBackupLocationTool -DataStoreInstallDirectory 'C:\ArcGIS\DataStore' -DataStoreType 'Relational' -OperationType 'register' -BackupLocationString $Location -RedactedBackupLocationString $RedactedLocation -ForceUpdate -Verbose

            $output | Should Be 'registered backup'
            Assert-MockCalled Invoke-StartProcess -Exactly 1 -Scope It
            Assert-MockCalled Invoke-StartProcess -Exactly 1 -Scope It -ParameterFilter {
                $Arguments -ceq "--operation register --store relational --prompt no --location $Location --force true"
            }
            Assert-MockCalled Write-Verbose -Exactly 1 -Scope It
            Assert-MockCalled Write-Verbose -Exactly 1 -Scope It -ParameterFilter {
                $Message -ceq "Backup Tool:- C:\ArcGIS\DataStore\tools\configurebackuplocation.bat --operation register --store relational --prompt no --location $ExpectedLogLocation --force true"
            }
        }

        It 'rejects an unsupported backup <ParameterName> before checking files or launching a process' -TestCases @(
            @{ ParameterName = 'DataStoreType' }
            @{ ParameterName = 'OperationType' }
        ) {
            param($ParameterName)
            Mock Test-Path { throw 'unexpected filesystem lookup' }
            Mock Invoke-StartProcess { throw 'unexpected process execution' }
            $arguments = @{
                DataStoreInstallDirectory = 'C:\ArcGIS\DataStore'
                DataStoreType = 'Relational'
                OperationType = 'list'
            }
            $arguments[$ParameterName] = 'unsupported'

            { Invoke-DataStoreConfigureBackupLocationTool @arguments } | Should Throw $ParameterName

            Assert-MockCalled Test-Path -Exactly 0 -Scope It
            Assert-MockCalled Invoke-StartProcess -Exactly 0 -Scope It
        }
    }

    Describe 'Data Store request failure gates' {
        It 'normalizes the configure URL and waits for health before submitting every feature' {
            $credential = New-Object System.Management.Automation.PSCredential 'siteadmin', (ConvertTo-SecureString 'configure-secret' -AsPlainText -Force)
            $script:configureTransitions = @()
            Mock Test-ArcGISComponentHealth { $script:configureTransitions += 'health' }
            Mock Invoke-ArcGISWebRequest {
                $script:configureTransitions += 'request'
                [PSCustomObject]@{ status = 'success'; machine = 'datastore-01' }
            }

            $response = Get-DataStoreInfo -URL 'https://datastore.example.test/arcgis///' -ServerSiteAdminCredential $credential -ServerSiteUrl 'https://server.example.test/arcgis' -Referer 'https://portal.example.test'

            $response.status | Should Be 'success'
            $response.machine | Should Be 'datastore-01'
            ($script:configureTransitions -join ',') | Should Be 'health,request'
            Assert-MockCalled Test-ArcGISComponentHealth -Exactly 1 -Scope It -ParameterFilter {
                $BaseURL -eq 'https://datastore.example.test/arcgis///' -and $ComponentName -eq 'DataStore' -and
                $MaxWaitTimeInSeconds -eq 180 -and $SleepTimeInSeconds -eq 5
            }
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter {
                $features = ($HttpFormParameters.dsSettings | ConvertFrom-Json).features
                $featureNames = ($features.PSObject.Properties.Name | Sort-Object) -join ','
                $Url -eq 'https://datastore.example.test/arcgis/datastoreadmin/configure' -and
                $HttpMethod -eq 'POST' -and $Referer -eq 'https://portal.example.test' -and
                $HttpFormParameters.f -eq 'json' -and $HttpFormParameters.getConfigureInfo -eq 'true' -and
                $HttpFormParameters.username -eq 'siteadmin' -and $HttpFormParameters.password -eq 'configure-secret' -and
                $HttpFormParameters.serverURL -eq 'https://server.example.test/arcgis' -and
                $featureNames -eq 'feature.bigdata,feature.egdb,feature.graphstore,feature.nosqldb,feature.ozobjectstore' -and
                $features.'feature.bigdata' -eq $true -and $features.'feature.egdb' -eq $true -and
                $features.'feature.graphstore' -eq $true -and $features.'feature.nosqldb' -eq $true -and
                $features.'feature.ozobjectstore' -eq $true
            }
        }

        It 'does not submit configure credentials when the health check fails' {
            $credential = New-Object System.Management.Automation.PSCredential 'siteadmin', (ConvertTo-SecureString 'configure-secret' -AsPlainText -Force)
            Mock Test-ArcGISComponentHealth { throw 'Data Store health unavailable' }
            Mock Invoke-ArcGISWebRequest { throw 'unexpected HTTP request' }

            { Get-DataStoreInfo -URL 'https://datastore.example.test/arcgis' -ServerSiteAdminCredential $credential -ServerSiteUrl 'https://server.example.test/arcgis' -Referer 'https://portal.example.test' } | Should Throw 'Data Store health unavailable'

            Assert-MockCalled Test-ArcGISComponentHealth -Exactly 1 -Scope It
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 0 -Scope It
        }

        It 'does not send a PITR request when readiness fails in <Operation>' -TestCases @(
            @{ Operation = 'Get-PITRState' }
            @{ Operation = 'Update-PITRState' }
        ) {
            param($Operation)
            Mock Wait-ForUrl { throw 'PITR endpoint unavailable' }
            Mock Invoke-ArcGISWebRequest { throw 'unexpected HTTP request' }
            $arguments = @{ URL = 'https://datastore.example.test/arcgis/'; Referer = 'https://portal.example.test' }
            if ($Operation -eq 'Update-PITRState') { $arguments.PITRState = 'Enabled' }

            { & $Operation @arguments } | Should Throw 'PITR endpoint unavailable'

            Assert-MockCalled Wait-ForUrl -Exactly 1 -Scope It -ParameterFilter {
                $Url -eq 'https://datastore.example.test/arcgis/datastoreadmin/configurePITR?f=json' -and
                $MaxWaitTimeInSeconds -eq 180 -and $SleepTimeInSeconds -eq 5 -and $HttpMethod -eq 'GET'
            }
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 0 -Scope It
        }

        It 'rejects a <ResponseKind> PITR update response without retrying' -TestCases @(
            @{ ResponseKind = 'pending'; Response = @{ status = 'pending' }; ExpectedMessage = '[ERROR] Configure PITR web request returned unknown response pending.' }
            @{ ResponseKind = 'null'; Response = $null; ExpectedMessage = '[ERROR] Configure PITR web request returned unknown response .' }
        ) {
            param($ResponseKind, $Response, $ExpectedMessage)
            Mock Wait-ForUrl {}
            Mock Invoke-ArcGISWebRequest { $Response }

            { Update-PITRState -URL 'https://datastore.example.test/arcgis/' -Referer 'https://portal.example.test' -PITRState 'Enabled' } | Should Throw $ExpectedMessage

            Assert-MockCalled Wait-ForUrl -Exactly 1 -Scope It
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter {
                $Url -eq 'https://datastore.example.test/arcgis/datastoreadmin/configurePITR' -and
                $Referer -eq 'https://portal.example.test' -and $TimeOutSec -eq 600 -and
                $HttpFormParameters.'enable-pitr' -ceq 'true' -and $HttpFormParameters.f -eq 'json'
            }
        }

        It 'propagates an HTTP failure without retrying in <Operation>' -TestCases @(
            @{ Operation = 'Get-DataStoreInfo' }
            @{ Operation = 'Get-PITRState' }
            @{ Operation = 'Update-PITRState' }
            @{ Operation = 'Test-DataStoreUpgrade' }
        ) {
            param($Operation)
            Mock Test-ArcGISComponentHealth {}
            Mock Wait-ForUrl {}
            Mock Invoke-ArcGISWebRequest { throw 'Data Store transport failed' }
            $arguments = @{ URL = 'https://datastore.example.test/arcgis'; Referer = 'https://portal.example.test' }
            if ($Operation -eq 'Get-DataStoreInfo') {
                $arguments.ServerSiteAdminCredential = New-Object System.Management.Automation.PSCredential 'siteadmin', (ConvertTo-SecureString 'configure-secret' -AsPlainText -Force)
                $arguments.ServerSiteUrl = 'https://server.example.test/arcgis'
            }
            if ($Operation -eq 'Update-PITRState') { $arguments.PITRState = 'Disabled' }

            { & $Operation @arguments } | Should Throw 'Data Store transport failed'

            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It
        }
    }

    Describe 'Data Store backup parsing boundaries' {
        It 'parses ordered <DataStoreType> backup rows with normalized paths and default flags' -TestCases @(
            @{ DataStoreType = 'GraphStore'; Heading = 'graph'; RowType = 'graph' }
            @{ DataStoreType = 'ObjectStore'; Heading = 'object'; RowType = 'object' }
            @{ DataStoreType = 'SpatioTemporal'; Heading = 'spatiotemporal'; RowType = 'spatiotemporal' }
        ) {
            param($DataStoreType, $Heading, $RowType)
            $expectedStore = $DataStoreType
            Mock Invoke-DataStoreConfigureBackupLocationTool {
                @(
                    "Backups locations for $Heading"
                    'header one'
                    'header two'
                    'header three'
                    "  primary   $RowType   C:/arcgis/primary///   true  "
                    "secondary $RowType //fileserver/archive/ false"
                    'end'
                ) -join [System.Environment]::NewLine
            }

            $locations = @(Get-DataStoreBackupLocation -DataStoreInstallDirectory 'C:\ArcGIS\DataStore' -DataStoreType $DataStoreType | Where-Object { $_ -is [hashtable] })

            $locations.Count | Should Be 2
            $locations[0].Name | Should Be 'primary'
            $locations[0].Type | Should Be $RowType
            $locations[0].Location | Should Be 'C:\arcgis\primary'
            $locations[0].IsDefault | Should Be $true
            $locations[1].Name | Should Be 'secondary'
            $locations[1].Type | Should Be $RowType
            $locations[1].Location | Should Be '\\fileserver\archive'
            $locations[1].IsDefault | Should Be $false
            Assert-MockCalled Invoke-DataStoreConfigureBackupLocationTool -Exactly 1 -Scope It
            Assert-MockCalled Invoke-DataStoreConfigureBackupLocationTool -Exactly 1 -Scope It -ParameterFilter {
                $DataStoreInstallDirectory -eq 'C:\ArcGIS\DataStore' -and $DataStoreType -eq $expectedStore -and $OperationType -eq 'list'
            }
        }

        It 'returns no locations for a table with no backup rows' {
            Mock Invoke-DataStoreConfigureBackupLocationTool {
                @('Backups locations for relational', 'header one', 'header two', 'header three', 'end') -join [System.Environment]::NewLine
            }

            $locations = @(Get-DataStoreBackupLocation -DataStoreInstallDirectory 'C:\ArcGIS\DataStore' -DataStoreType 'Relational')

            $locations.Count | Should Be 0
            Assert-MockCalled Invoke-DataStoreConfigureBackupLocationTool -Exactly 1 -Scope It -ParameterFilter {
                $DataStoreType -eq 'Relational' -and $OperationType -eq 'list'
            }
        }

        It 'rejects an unsupported store before listing backup locations' {
            Mock Invoke-DataStoreConfigureBackupLocationTool { throw 'unexpected backup tool invocation' }

            { Get-DataStoreBackupLocation -DataStoreInstallDirectory 'C:\ArcGIS\DataStore' -DataStoreType 'unsupported' } | Should Throw 'DataStoreType'

            Assert-MockCalled Invoke-DataStoreConfigureBackupLocationTool -Exactly 0 -Scope It
        }
    }

    Describe 'Data Store backup tool error handling' {
        It 'rejects an omitted store without external work in <Operation>' -TestCases @(
            @{ Operation = 'Get-DataStoreBackupLocation' }
            @{ Operation = 'Invoke-DataStoreConfigureBackupLocationTool' }
        ) {
            param($Operation)
            Mock Test-Path { $true }
            Mock Invoke-StartProcess { throw 'unexpected process execution' }
            $arguments = @{ DataStoreInstallDirectory = 'C:\ArcGIS\DataStore' }
            if ($Operation -eq 'Invoke-DataStoreConfigureBackupLocationTool') { $arguments.OperationType = 'list' }

            { & $Operation @arguments } | Should Throw 'Invalid DataStoreType'

            Assert-MockCalled Invoke-StartProcess -Exactly 0 -Scope It
            if ($Operation -eq 'Get-DataStoreBackupLocation') {
                Assert-MockCalled Test-Path -Exactly 0 -Scope It
            }
        }

        It 'propagates a backup process exception without retrying' {
            Mock Test-Path { $true }
            Mock Invoke-StartProcess { throw 'backup process could not start' }

            { Invoke-DataStoreConfigureBackupLocationTool -DataStoreInstallDirectory 'C:\ArcGIS\DataStore' -DataStoreType 'Relational' -OperationType 'list' } | Should Throw 'backup process could not start'

            Assert-MockCalled Invoke-StartProcess -Exactly 1 -Scope It
        }

        It 'rejects a failed marker after earlier successful tool output' {
            Mock Test-Path { $true }
            Mock Invoke-StartProcess { @('backup tool initialized', 'failed') }

            { Invoke-DataStoreConfigureBackupLocationTool -DataStoreInstallDirectory 'C:\ArcGIS\DataStore' -DataStoreType 'Relational' -OperationType 'list' } | Should Throw 'Configure backup tool failed. Output - backup tool initialized failed.'

            Assert-MockCalled Invoke-StartProcess -Exactly 1 -Scope It
        }
    }

    Describe 'Data Store upgrade state' {
        It 'returns false while an in-place or out-of-place upgrade is active' -TestCases @(
            @{ UpgradeType = 'inplace' }
            @{ UpgradeType = 'outplace' }
        ) {
            param($UpgradeType)

            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ upgrading = $UpgradeType } }

            Test-DataStoreUpgrade -URL 'https://datastore.example.test/arcgis' -Referer 'https://portal.example.test' | Should Be $false
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://datastore.example.test/arcgis/datastoreadmin/configure' -and $HttpMethod -eq 'GET' -and $HttpFormParameters.f -eq 'json' }
        }

        It 'returns true when Data Store is not upgrading' {
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ upgrading = $null } }

            Test-DataStoreUpgrade -URL 'https://datastore.example.test/arcgis' -Referer 'https://portal.example.test' | Should Be $true
        }

        It 'compares the active upgrade state <UpgradeType> without case sensitivity' -TestCases @(
            @{ UpgradeType = 'INPLACE' }
            @{ UpgradeType = 'OUTPLACE' }
        ) {
            param($UpgradeType)
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ upgrading = $UpgradeType } }

            Test-DataStoreUpgrade -URL 'https://datastore.example.test/arcgis' -Referer 'https://portal.example.test' | Should Be $false

            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter {
                $Url -eq 'https://datastore.example.test/arcgis/datastoreadmin/configure' -and
                $HttpMethod -eq 'GET' -and $HttpFormParameters.f -eq 'json' -and $Referer -eq 'https://portal.example.test'
            }
        }

        It 'returns ready for the inactive upgrade state <StateLabel>' -TestCases @(
            @{ StateLabel = 'empty'; UpgradeType = '' }
            @{ StateLabel = 'complete'; UpgradeType = 'complete' }
        ) {
            param($StateLabel, $UpgradeType)
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ upgrading = $UpgradeType } }

            Test-DataStoreUpgrade -URL 'https://datastore.example.test/arcgis' -Referer 'https://portal.example.test' | Should Be $true

            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It
        }
    }
}