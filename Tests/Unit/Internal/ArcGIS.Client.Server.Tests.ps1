<#
    Verifies Server client contracts: URL construction, token retry behavior, datastore
    routes and filtering, GP job/result requests, settings, and certificate/site queries.
    Invoke-ArcGISWebRequest, readiness checks, and retry delays are mocked in the owning
    module; assertions inspect actual request fields instead of contacting an endpoint.

    Dummy tokens and example.test URLs are test data only. Certificate tests validate
    request/response mapping, not a TLS handshake. See ../../README.md.
#>
$moduleScriptPath = Join-Path $PSScriptRoot '..\..\..\Modules\ArcGIS\Modules\ArcGIS.Client\ArcGIS.Client.Server.psm1'

Import-Module $moduleScriptPath -Force

InModuleScope ArcGIS.Client.Server {
    Describe 'Server URL and token helpers' {
        It 'classifies core GIS Server and specialized server roles' {
            Test-IfGISServer -ServerType 'Server' | Should Be $true
            Test-IfGISServer -ServerType 'NotebookServer' | Should Be $false
        }

        It 'builds an admin URL without duplicate separators' {
            Get-ServerAdminUrlForPath -URL 'https://server.example.test/arcgis/' -Path '/machines' | Should Be 'https://server.example.test/arcgis/admin/machines'
        }

        It 'requests a server token with credential, referer, and expiration values' {
            $credential = New-Object System.Management.Automation.PSCredential 'siteadmin', (ConvertTo-SecureString 'secret' -AsPlainText -Force)
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ token = 'server-token' } }
            Mock Start-Sleep { throw 'A successful request must not sleep.' }

            $token = Get-ServerToken -URL 'https://server.example.test/arcgis' -Credential $credential -Referer 'https://portal.example.test' -Expiration 120 -MaxAttempts 3

            $token.token | Should Be 'server-token'
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://server.example.test/arcgis/admin/generateToken' -and $HttpFormParameters.username -eq 'siteadmin' -and $HttpFormParameters.password -eq 'secret' -and $HttpFormParameters.client -eq 'referer' -and $HttpFormParameters.referer -eq 'https://portal.example.test' -and $HttpFormParameters.expiration -eq 120 -and $TimeOutSec -eq 45 }
            Assert-MockCalled Start-Sleep -Exactly 0 -Scope It
        }

        It 'stops token retries at the configured maximum attempt count' {
            # Repeated null replies exercise exhaustion rather than the success path.
            # Sleep is mocked, so these assertions pin this helper's retry policy
            # without taking real time or assuming other clients use the same policy.
            $credential = New-Object System.Management.Automation.PSCredential 'siteadmin', (ConvertTo-SecureString 'secret' -AsPlainText -Force)
            Mock Invoke-ArcGISWebRequest { $null }
            Mock Start-Sleep {}

            $token = Get-ServerToken -URL 'https://server.example.test/arcgis' -Credential $credential -Referer 'https://portal.example.test' -MaxAttempts 2

            $token | Should Be $null
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 2 -Scope It
            Assert-MockCalled Start-Sleep -Exactly 2 -Scope It -ParameterFilter { $Seconds -eq 15 }
        }
    }

    Describe 'Server datastore and GP request contracts' {
        It 'returns the machines registered for a datastore item from the mapped admin endpoint' {
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ machines = @('server-01', 'server-02') } }

            $machines = @(Get-DataStoreMachines -URL 'https://server.example.test/arcgis' -Token 'token-1' -Referer 'https://portal.example.test' -DataStorePath '/cloudStores/store-1')

            $machines | Should Be @('server-01', 'server-02')
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://server.example.test/arcgis/admin/data/items/cloudStores/store-1/machines' -and $HttpFormParameters.f -eq 'json' -and $HttpFormParameters.token -eq 'token-1' }
        }

        It 'posts a datastore machine operation to the addressed machine route' {
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ status = 'success'; action = 'unregister' } }

            $response = Invoke-DataStoreMachineOperation -URL 'https://server.example.test/arcgis' -Token 'token-1' -Referer 'https://portal.example.test' -DataStorePath '/cloudStores/store-1' -MachineFQDN 'server-02.contoso.com' -OperationName 'unregister'

            $response.action | Should Be 'unregister'
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://server.example.test/arcgis/admin/data/items/cloudStores/store-1/machines/server-02.contoso.com/unregister/' -and $HttpMethod -eq 'POST' -and $HttpFormParameters.token -eq 'token-1' }
        }

        It 'maps datastore types to the expected ArcGIS administration paths' -TestCases @(
            @{ DataStoreType = 'Folder'; Type = 'folder'; AncestorPath = '/fileShares' }
            @{ DataStoreType = 'ObjectStore'; Type = 'objectStore'; AncestorPath = '/cloudStores' }
            @{ DataStoreType = 'GraphStore'; Type = 'nosql'; AncestorPath = '/nosqlDatabases' }
            @{ DataStoreType = 'BigDataFileShare'; Type = 'bigDataFileShare'; AncestorPath = '/bigDataFileShares' }
            @{ DataStoreType = 'EnterpriseGeodatabase'; Type = 'egdb'; AncestorPath = '/enterpriseDatabases' }
        ) {
            param($DataStoreType, $Type, $AncestorPath)

            $details = Get-DSAncestorPathOrItemType -DataStoreType $DataStoreType

            $details.Type | Should Be $Type
            $details.AncestorPath | Should Be $AncestorPath
        }

        It 'filters ArcGIS Data Store graph items after requesting the mapped type and path' {
            Mock Get-DSAncestorPathOrItemType { @{ Type = 'nosql'; AncestorPath = '/nosqlDatabases' } }
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ items = @([PSCustomObject]@{ provider = 'ArcGIS Data Store'; info = [PSCustomObject]@{ dsFeature = 'GraphStore' }; path = '/nosqlDatabases/graph' }, [PSCustomObject]@{ provider = 'Other'; info = [PSCustomObject]@{ dsFeature = 'GraphStore' }; path = '/nosqlDatabases/other' }) } }

            $items = @(Find-DataItems -URL 'https://server.example.test/arcgis' -Token 'token-1' -Referer 'https://portal.example.test' -Type 'GraphStore' -IsArcGISDataStore)

            $items.Count | Should Be 1
            $items[0].path | Should Be '/nosqlDatabases/graph'
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://server.example.test/arcgis/admin/data/findItems' -and $HttpFormParameters.types -eq 'nosql' -and $HttpFormParameters.ancestorPath -eq '/nosqlDatabases' -and $HttpFormParameters.token -eq 'token-1' }
        }

        It 'sends force and item path for an unregister datastore operation' {
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ status = 'success' } }

            Invoke-DataStoreItemOperation -URL 'https://server.example.test/arcgis' -Token 'token-1' -Referer 'https://portal.example.test' -ConnectionObject @{ path = '/ignored' } -OperationName 'unregisterItem' -DataStoreItemPath '/cloudStores/store-1' -Force $true

            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://server.example.test/arcgis/admin/data/unregisterItem' -and $HttpFormParameters.itemPath -eq '/cloudStores/store-1' -and $HttpFormParameters.force -eq 'True' -and $HttpFormParameters.token -eq 'token-1' }
        }

        It 'throws the ArcGIS messages when a datastore operation reports an error' {
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ status = 'error'; messages = @('store is in use', 'try later') } }
            $exception = $null

            try {
                Invoke-DataStoreItemOperation -URL 'https://server.example.test/arcgis' -Token 'token-1' -Referer 'https://portal.example.test' -ConnectionObject @{ path = '/cloudStores/store-1' } -OperationName 'registerItem'
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be "[ERROR]:- Data Store Item operation 'registerItem' failed. Error:- store is in use,try later"
        }

        It 'returns a completed GP tool output after submit, status, and result requests' {
            # URL-filtered mocks model the three GP stages independently. Returning
            # one generic payload for every URL could hide a wrong status/result route.
            # The terminal succeeded state keeps polling local and immediately complete.
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ jobId = 'job-42'; status = [PSCustomObject]@{} } } -ParameterFilter { $Url -match '/submitJob$' }
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ jobStatus = 'esriJobSucceeded'; results = [PSCustomObject]@{ out_connectionString = [PSCustomObject]@{ paramUrl = 'results/out_connectionString' } }; status = [PSCustomObject]@{} } } -ParameterFilter { $Url -match '/jobs/job-42$' }
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ value = 'ENCRYPTED_CONNECTION'; status = [PSCustomObject]@{} } } -ParameterFilter { $Url -match '/jobs/job-42/results/out_connectionString$' }

            $connection = Invoke-GetDatabaseConnectionGPTool -URL 'https://server.example.test/arcgis' -Token 'token-1' -Referer 'https://portal.example.test' -ConnectionFileItemId 'item-1'

            $connection | Should Be 'ENCRYPTED_CONNECTION'
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 3 -Scope It
        }

        It 'throws the final GP job state when a submitted job fails' {
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ jobId = 'job-42'; status = [PSCustomObject]@{} } } -ParameterFilter { $Url -match '/submitJob$' }
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ jobStatus = 'esriJobFailed'; messages = @('invalid item'); status = [PSCustomObject]@{} } } -ParameterFilter { $Url -match '/jobs/job-42$' }
            Mock Start-Sleep { throw 'A terminal failed status must not sleep.' }
            $exception = $null

            try {
                Invoke-GetDatabaseConnectionGPTool -URL 'https://server.example.test/arcgis' -Token 'token-1' -Referer 'https://portal.example.test' -ConnectionFileItemId 'item-1'
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Match "job 'job-42' did not complete successfully\. Last status: esriJobFailed"
            Assert-MockCalled Start-Sleep -Exactly 0 -Scope It
        }
    }

    Describe 'Server Join Site polling and version boundaries' {
        BeforeEach {
            $script:joinEvents = @()
            $script:joinCredential = New-Object System.Management.Automation.PSCredential 'siteadmin', (ConvertTo-SecureString 'join-secret' -AsPlainText -Force)
            $script:joinResponse = [PSCustomObject]@{ status = 'SuCcEsS' }
            Mock Get-FQDN { 'primary.example.test' }
            Mock Test-ArcGISComponentHealth { $script:joinEvents += "health:$BaseURL" }
            Mock Invoke-ArcGISWebRequest {
                $script:joinEvents += 'join'
                $script:joinResponse
            }
            Mock Wait-RecheckAfterSeconds { $script:joinEvents += "poll:$Seconds" }
            Mock Start-Sleep { $script:joinEvents += "retry:$Seconds" }
        }

        It 'honors Join Site initialization polling for <Case>' -TestCases @(
            @{ Case = 'positive poll delay'; IncludePoll = $true; PollAfter = 7; ExpectedPollSeconds = 7 }
            @{ Case = 'zero poll delay'; IncludePoll = $true; PollAfter = 0; ExpectedPollSeconds = 60 }
            @{ Case = 'missing poll delay'; IncludePoll = $false; ExpectedPollSeconds = 60 }
        ) {
            param($Case, $IncludePoll, $PollAfter, $ExpectedPollSeconds)
            if ($IncludePoll) { $script:joinResponse | Add-Member -NotePropertyName pollAfter -NotePropertyValue $PollAfter }

            Invoke-JoinSite -URL 'https://secondary.example.test:6443/arcgis' -Credential $script:joinCredential -Referer 'https://portal.example.test' -PrimaryServerHostName 'primary' -ServerType 'Server' -Version '11.5'

            $expectedEvents = @(
                'health:https://primary.example.test:6443/arcgis', 'health:https://secondary.example.test:6443/arcgis',
                'join', "poll:$ExpectedPollSeconds",
                'health:https://secondary.example.test:6443/arcgis', 'health:https://primary.example.test:6443/arcgis'
            )
            ($script:joinEvents -join ' -> ') | Should Be ($expectedEvents -join ' -> ')
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter {
                $Url -eq 'https://secondary.example.test:6443/arcgis/admin/joinSite' -and
                $HttpFormParameters.adminURL -eq 'https://primary.example.test:6443/arcgis/admin' -and
                $HttpFormParameters.username -eq 'siteadmin' -and
                $HttpFormParameters.password -eq 'join-secret' -and
                $HttpFormParameters.f -eq 'json' -and
                $Referer -eq 'https://portal.example.test' -and $TimeOutSec -eq 360
            }
            Assert-MockCalled Wait-RecheckAfterSeconds -Exactly 1 -Scope It -ParameterFilter { $Seconds -eq $ExpectedPollSeconds -and $Multiplier -eq 1 }
            Assert-MockCalled Start-Sleep -Exactly 0 -Scope It
        }

        It 'uses the Video Server join endpoint for <Case>' -TestCases @(
            @{ Case = 'before the federation boundary'; Version = '12.1'; PortalCredential = $true; Path = '/joinSite'; IncludePortal = $false }
            @{ Case = 'at the federation boundary'; Version = '12.2'; PortalCredential = $true; Path = '/joinSiteFederated'; IncludePortal = $true }
            @{ Case = 'after the federation boundary'; Version = '12.3'; PortalCredential = $true; Path = '/joinSiteFederated'; IncludePortal = $true }
            @{ Case = 'an unspecified version'; Version = $null; PortalCredential = $true; Path = '/joinSite'; IncludePortal = $false }
            @{ Case = 'federated join without Portal credentials'; Version = '12.2'; PortalCredential = $false; Path = '/joinSiteFederated'; IncludePortal = $false }
        ) {
            param($Case, $Version, $PortalCredential, $Path, $IncludePortal)
            $portalAdmin = $null
            if ($PortalCredential) {
                $portalAdmin = New-Object System.Management.Automation.PSCredential 'portaladmin', (ConvertTo-SecureString 'portal-secret' -AsPlainText -Force)
            }

            Invoke-JoinSite -URL 'https://video.example.test/arcgis' -Credential $script:joinCredential -Referer 'https://portal.example.test' -PrimaryServerHostName 'primary' -ServerType 'VideoServer' -Version $Version -PortalSiteAdministrator $portalAdmin

            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter {
                $Url -eq "https://video.example.test/arcgis/admin$Path" -and
                $HttpFormParameters.username -eq 'siteadmin' -and
                $HttpFormParameters.password -eq 'join-secret' -and
                $HttpFormParameters.ContainsKey('portalUser') -eq $IncludePortal -and
                $HttpFormParameters.ContainsKey('portalPass') -eq $IncludePortal -and
                (-not $IncludePortal -or ($HttpFormParameters.portalUser -eq 'portaladmin' -and $HttpFormParameters.portalPass -eq 'portal-secret'))
            }
            Assert-MockCalled Start-Sleep -Exactly 0 -Scope It
        }

        It 'recovers from a <Case> Join Site response before polling initialization' -TestCases @(
            @{ Case = 'missing'; FirstResponse = $null }
            @{ Case = 'status-error'; FirstResponse = @{ status = 'error'; messages = @('site is starting'); pollAfter = 99 } }
            @{ Case = 'nested-error'; FirstResponse = @{ error = @{ code = 500; message = 'try later' }; pollAfter = 99 } }
        ) {
            param($Case, $FirstResponse)
            $script:joinRequestCount = 0
            $script:joinFirstResponse = $FirstResponse
            Mock Invoke-ArcGISWebRequest {
                $script:joinEvents += 'join'
                $script:joinRequestCount++
                if ($script:joinRequestCount -eq 1) { return $script:joinFirstResponse }
                [PSCustomObject]@{ status = 'success'; pollAfter = 3 }
            }

            Invoke-JoinSite -URL 'https://secondary.example.test:6443/arcgis' -Credential $script:joinCredential -Referer 'https://portal.example.test' -PrimaryServerHostName 'primary' -ServerType 'Server' -Version '11.5'

            $script:joinEvents | Should Be @(
                'health:https://primary.example.test:6443/arcgis', 'health:https://secondary.example.test:6443/arcgis',
                'join', 'retry:30', 'join', 'poll:3',
                'health:https://secondary.example.test:6443/arcgis', 'health:https://primary.example.test:6443/arcgis'
            )
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 2 -Scope It
            Assert-MockCalled Start-Sleep -Exactly 1 -Scope It -ParameterFilter { $Seconds -eq 30 }
            Assert-MockCalled Wait-RecheckAfterSeconds -Exactly 1 -Scope It -ParameterFilter { $Seconds -eq 3 -and $Multiplier -eq 1 }
        }
    }

    Describe 'Server site response contracts' {
        It 'uses the GIS Server checkbox representation when disabling usage metering in log settings' {
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ status = 'success' } }
            $settings = [PSCustomObject]@{ logDir = 'D:\server-logs'; logLevel = 'WARNING'; maxLogFileAge = 14; maxErrorReportsCount = 3; usageMeteringEnabled = $false }

            $response = Update-LogSettings -URL 'https://server.example.test/arcgis' -Token 'token-1' -Referer 'https://portal.example.test' -LogSettings $settings -ServerType 'Server'

            $response.status | Should Be 'success'
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://server.example.test/arcgis/admin/logs/settings/edit' -and $HttpFormParameters.logDir -eq 'D:\server-logs' -and $HttpFormParameters.usageMeteringEnabled -eq 'off' -and $HttpFormParameters.maxLogFileAge -eq 14 }
        }

        It 'serializes Server system properties for the update endpoint' {
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ status = 'success'; updated = $true } }
            $properties = [PSCustomObject]@{ virtualDirsSecurityEnabled = $true; customProperty = 'value-1' }

            $response = Set-SystemProperties -URL 'https://server.example.test/arcgis' -Token 'token-1' -Referer 'https://portal.example.test' -Properties $properties

            $response.updated | Should Be $true
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://server.example.test/arcgis/admin/system/properties/update/' -and $TimeOutSec -eq 180 -and $HttpFormParameters.token -eq 'token-1' -and ($HttpFormParameters.properties | ConvertFrom-Json).virtualDirsSecurityEnabled -eq $true -and ($HttpFormParameters.properties | ConvertFrom-Json).customProperty -eq 'value-1' }
        }

        It 'returns normalized certificate details from a successful machine certificate query' {
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ issuer = 'CN=Contoso Issuing CA'; sha1Fingerprint = 'ABC123' } }

            $certificate = Get-SSLCertificateForMachine -URL 'https://server.example.test/arcgis' -Token 'token-1' -Referer 'https://portal.example.test' -MachineName 'server-01' -SSLCertName 'web-cert'

            $certificate.Issuer | Should Be 'CN=Contoso Issuing CA'
            $certificate.Thumbprint | Should Be 'ABC123'
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://server.example.test/arcgis/admin/machines/server-01/sslCertificates/web-cert' -and $HttpMethod -eq 'GET' -and $HttpFormParameters.token -eq 'token-1' }
        }

        It 'submits every self-signed certificate field to the machine certificate generator' {
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ status = 'success'; alias = 'web-cert' } }

            $response = Invoke-GenerateSelfSignedCertificate -URL 'https://server.example.test/arcgis' -Token 'token-1' -Referer 'https://portal.example.test' -MachineName 'server-01' -CertAlias 'web-cert' -CertCommonName 'server-01.contoso.com' -CertOrganization 'Contoso' -ValidityInDays 365

            $response.alias | Should Be 'web-cert'
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://server.example.test/arcgis/admin/machines/server-01/sslCertificates/generate' -and $TimeOutSec -eq 150 -and $HttpFormParameters.alias -eq 'web-cert' -and $HttpFormParameters.commonName -eq 'server-01.contoso.com' -and $HttpFormParameters.organization -eq 'Contoso' -and $HttpFormParameters.validity -eq 365 }
        }

        It 'recognizes a ready Velocity Server site after the health check' {
            Mock Test-ArcGISComponentHealth {}
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ isSiteReady = $true; isSiteConnected = $true } }

            $created = Test-ServerSiteCreated -URL 'https://velocity.example.test/arcgis' -Type 'VelocityServer' -Referer 'https://portal.example.test'

            $created | Should Be $true
            Assert-MockCalled Test-ArcGISComponentHealth -Exactly 1 -Scope It -ParameterFilter { $BaseURL -eq 'https://velocity.example.test/arcgis' -and $ComponentName -eq 'VelocityServer' }
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://velocity.example.test/arcgis/admin' -and $HttpMethod -eq 'GET' }
        }
    }
}