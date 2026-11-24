<#
    Checks Portal admin/sharing URL selection, optional token fields, retry behavior,
    federation identity, OAuth serialization, licensing, settings, and certificate queries.
    Requests, readiness waits, and retry delays are mocked in ArcGIS.Client.Portal scope;
    the real client functions still assemble URLs, serialize payloads, and handle errors.

    Assertions distinguish sharing/rest endpoints from the OAuth sharing endpoint without
    rest. Fixture tokens, credentials, and URLs are not live resources. See ../../README.md.
#>
$moduleScriptPath = Join-Path $PSScriptRoot '..\..\..\Modules\ArcGIS\Modules\ArcGIS.Client\ArcGIS.Client.Portal.psm1'

Import-Module $moduleScriptPath -Force

InModuleScope ArcGIS.Client.Portal {
    Describe 'Portal URL and token helpers' {
        It 'builds portal admin and sharing URLs with the appropriate API roots' {
            Get-PortalAdminUrlForPath -URL 'https://portal.example.test/arcgis/' -Path '/logs/settings' | Should Be 'https://portal.example.test/arcgis/portaladmin/logs/settings'
            Get-PortalSharingApiUrlForPath -URL 'https://portal.example.test/arcgis/' -Path '/generateToken' | Should Be 'https://portal.example.test/arcgis/sharing/rest/generateToken'
            Get-PortalSharingApiUrlForPath -URL 'https://portal.example.test/arcgis/' -Path '/oauth2/apps/app-1' -NoRest | Should Be 'https://portal.example.test/arcgis/sharing/oauth2/apps/app-1'
        }

        It 'sends optional portal token client and expiration parameters when supplied' {
            $credential = New-Object System.Management.Automation.PSCredential 'portaladmin', (ConvertTo-SecureString 'secret' -AsPlainText -Force)
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ token = 'portal-token' } }
            Mock Start-Sleep { throw 'A successful token request must not sleep.' }

            $token = Get-PortalToken -URL 'https://portal.example.test/arcgis' -Credential $credential -Referer 'https://portal.example.test' -Client 'referer' -Expiration 90 -MaxAttempts 2

            $token.token | Should Be 'portal-token'
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://portal.example.test/arcgis/sharing/rest/generateToken' -and $HttpFormParameters.username -eq 'portaladmin' -and $HttpFormParameters.password -eq 'secret' -and $HttpFormParameters.referer -eq 'https://portal.example.test' -and $HttpFormParameters.client -eq 'referer' -and $HttpFormParameters.expiration -eq 90 }
            Assert-MockCalled Start-Sleep -Exactly 0 -Scope It
        }

        It 'omits optional portal token parameters when they are not supplied' {
            # Absence is a request contract, not the same as sending a null/empty key.
            # Check ContainsKey so default token requests cannot silently acquire
            # optional fields that the caller did not specify.
            $credential = New-Object System.Management.Automation.PSCredential 'portaladmin', (ConvertTo-SecureString 'secret' -AsPlainText -Force)
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ token = 'portal-token' } }

            Get-PortalToken -URL 'https://portal.example.test/arcgis' -Credential $credential -Referer 'https://portal.example.test' -MaxAttempts 1 | Out-Null

            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { -not $HttpFormParameters.ContainsKey('client') -and -not $HttpFormParameters.ContainsKey('expiration') }
        }

        It 'retries a portal token error only until the configured maximum' {
            $credential = New-Object System.Management.Automation.PSCredential 'portaladmin', (ConvertTo-SecureString 'secret' -AsPlainText -Force)
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ error = [PSCustomObject]@{ message = 'temporarily unavailable' } } }
            Mock Start-Sleep {}

            $token = Get-PortalToken -URL 'https://portal.example.test/arcgis' -Credential $credential -Referer 'https://portal.example.test' -MaxAttempts 2

            $token | Should Be $null
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 2 -Scope It
            Assert-MockCalled Start-Sleep -Exactly 1 -Scope It -ParameterFilter { $Seconds -eq 15 }
        }
    }

    Describe 'Portal certificate strict and tolerant errors' {
        BeforeEach {
            $script:portalCertificateResponse = $null
            Mock Invoke-ArcGISWebRequest { $script:portalCertificateResponse }
        }

        It 'returns strict Portal certificate results for <Case>' -TestCases @(
            @{ Case = 'a selected alias'; Alias = 'portal-web-cert'; Response = @{ alias = 'portal-web-cert'; sha1Fingerprint = 'DEF456' }; ExpectedPath = '/portal-web-cert'; ExpectedAliases = @() }
            @{ Case = 'the certificate collection'; Alias = $null; Response = @{ sslCertificates = @('portal-web-cert', 'root-ca') }; ExpectedPath = ''; ExpectedAliases = @('portal-web-cert', 'root-ca') }
            @{ Case = 'an empty certificate collection'; Alias = $null; Response = @{ sslCertificates = @() }; ExpectedPath = ''; ExpectedAliases = @() }
        ) {
            param($Case, $Alias, $Response, $ExpectedPath, $ExpectedAliases)
            $script:portalCertificateResponse = [PSCustomObject]$Response

            $certificate = Get-SSLCertificatesForPortal -URL 'https://portal.example.test/arcgis' -WebServerCertificateAlias $Alias -Token 'portal-token' -Referer 'https://portal.example.test' -MachineName 'portal-01' -ThrowOnResponseError $true

            if ($Alias) {
                $certificate.alias | Should Be 'portal-web-cert'
                $certificate.sha1Fingerprint | Should Be 'DEF456'
            } else {
                $certificate.PSObject.Properties['sslCertificates'].Name | Should Be 'sslCertificates'
                $certificate.sslCertificates.Count | Should Be $ExpectedAliases.Count
                if ($ExpectedAliases.Count -gt 0) { $certificate.sslCertificates | Should Be @('portal-web-cert', 'root-ca') }
            }
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter {
                $Url -eq "https://portal.example.test/arcgis/portaladmin/machines/portal-01/sslCertificates$ExpectedPath" -and
                $HttpMethod -eq 'GET' -and $TimeOutSec -eq 120 -and
                $HttpFormParameters.f -eq 'json' -and $HttpFormParameters.token -eq 'portal-token' -and
                $Referer -eq 'https://portal.example.test'
            }
        }

        It 'rejects strict Portal certificate responses for <Case>' -TestCases @(
            @{ Case = 'status errors'; Response = @{ status = 'error'; messages = @('certificate missing', 'check alias') }; ExpectedError = 'certificate missing check alias' }
            @{ Case = 'nested errors'; Response = @{ error = @{ code = 498; message = 'token expired' } }; ExpectedError = 'token expired' }
            @{ Case = 'null replies'; Response = $null; ExpectedError = 'response is NULL' }
        ) {
            param($Case, $Response, $ExpectedError)
            $script:portalCertificateResponse = $Response

            { Get-SSLCertificatesForPortal -URL 'https://portal.example.test/arcgis' -WebServerCertificateAlias 'web-cert' -Token 'portal-token' -Referer 'https://portal.example.test' -MachineName 'portal-01' -ThrowOnResponseError $true } |
                Should Throw $ExpectedError

            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It
        }

        It 'preserves tolerant Portal certificate responses for <Case>' -TestCases @(
            @{ Case = 'status errors'; Response = @{ status = 'error'; messages = @('certificate missing') } }
            @{ Case = 'nested errors'; Response = @{ error = @{ code = 498; message = 'token expired' } } }
            @{ Case = 'null replies'; Response = $null }
        ) {
            param($Case, $Response)
            $script:portalCertificateResponse = $Response

            $certificate = Get-SSLCertificatesForPortal -URL 'https://portal.example.test/arcgis' -Token 'portal-token' -Referer 'https://portal.example.test' -MachineName 'portal-01'

            if ($Case -eq 'status errors') {
                $certificate.status | Should Be 'error'
                $certificate.messages | Should Be @('certificate missing')
            } elseif ($Case -eq 'nested errors') {
                $certificate.error.code | Should Be 498
                $certificate.error.message | Should Be 'token expired'
            } else {
                $certificate | Should Be $null
            }
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It
        }

        It 'handles Portal certificate transport exceptions in <Case> mode' -TestCases @(
            @{ Case = 'strict'; Strict = $true }
            @{ Case = 'tolerant'; Strict = $false }
        ) {
            param($Case, $Strict)
            Mock Invoke-ArcGISWebRequest { throw [System.InvalidOperationException]::new('certificate transport unavailable') }
            if ($Strict) {
                $exception = $null
                try {
                    Get-SSLCertificatesForPortal -URL 'https://portal.example.test/arcgis' -Token 'portal-token' -Referer 'https://portal.example.test' -MachineName 'portal-01' -ThrowOnResponseError $true
                } catch { $exception = $_ }

                $exception | Should Not Be $null
                $exception.Exception.GetType().FullName | Should Be 'System.InvalidOperationException'
                $exception.Exception.Message | Should Be 'certificate transport unavailable'
            } else {
                $records = @(Get-SSLCertificatesForPortal -URL 'https://portal.example.test/arcgis' -Token 'portal-token' -Referer 'https://portal.example.test' -MachineName 'portal-01' -Verbose 4>&1)

                @($records | Where-Object { $_ -isnot [System.Management.Automation.VerboseRecord] }).Count | Should Be 0
                $warnings = @($records | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] -and $_.Message -like '*Error running Get-SSLCertificatesForPortal*certificate transport unavailable*' })
                $warnings.Count | Should Be 1
            }
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It
        }
    }

    Describe 'Portal administration request contracts' {
        It 'gets federated servers and posts an unfederation request to the selected server ID' {
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ servers = @([PSCustomObject]@{ id = 'server-1' }); status = 'success' } }

            $servers = Get-FederatedServers -URL 'https://portal.example.test/arcgis' -Token 'portal-token' -Referer 'https://portal.example.test'
            $unfederation = Invoke-UnFederateServer -URL 'https://portal.example.test/arcgis' -ServerID 'server-1' -Token 'portal-token' -Referer 'https://portal.example.test'

            $servers.servers[0].id | Should Be 'server-1'
            $unfederation.status | Should Be 'success'
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://portal.example.test/arcgis/portaladmin/federation/servers/' -and $HttpMethod -eq 'GET' -and $HttpFormParameters.token -eq 'portal-token' }
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://portal.example.test/arcgis/portaladmin/federation/servers/server-1/unfederate' -and $TimeOutSec -eq 90 -and $HttpFormParameters.token -eq 'portal-token' }
        }

        It 'updates a federated Server admin URL while retaining the federation identity fields' {
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ status = 'success' } }
            $federatedServer = [PSCustomObject]@{ id = 'server-1'; url = 'https://server.example.test/arcgis'; isHosted = $true; serverType = 'ArcGIS' }

            $response = Update-ServerAdminUrlForPortal -URL 'https://portal.example.test/arcgis' -Token 'portal-token' -Referer 'https://portal.example.test' -ServerAdminUrl 'https://server.example.test:6443/arcgis' -FederatedServer $federatedServer

            $response.status | Should Be 'success'
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://portal.example.test/arcgis/sharing/rest/portals/0123456789ABCDEF/servers/server-1/update' -and $HttpMethod -eq 'POST' -and $HttpFormParameters.name -eq 'https://server.example.test:6443/arcgis' -and $HttpFormParameters.url -eq 'https://server.example.test/arcgis' -and $HttpFormParameters.adminUrl -eq 'https://server.example.test:6443/arcgis' -and $HttpFormParameters.isHosted -and $HttpFormParameters.serverType -eq 'ArcGIS' }
        }

        It 'submits federation credentials and endpoint URLs to the federation API' {
            $credential = New-Object System.Management.Automation.PSCredential 'serveradmin', (ConvertTo-SecureString 'server-secret' -AsPlainText -Force)
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ status = 'success' } }

            Invoke-FederateServer -URL 'https://portal.example.test/arcgis' -ServerServiceUrl 'https://server.example.test/arcgis' -ServerAdminUrl 'https://server.example.test:6443/arcgis' -ServerAdminCredential $credential -PortalToken 'portal-token' -Referer 'https://portal.example.test' | Out-Null

            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://portal.example.test/arcgis/portaladmin/federation/servers/federate' -and $HttpFormParameters.url -eq 'https://server.example.test/arcgis' -and $HttpFormParameters.adminUrl -eq 'https://server.example.test:6443/arcgis' -and $HttpFormParameters.username -eq 'serveradmin' -and $HttpFormParameters.password -eq 'server-secret' -and $HttpFormParameters.token -eq 'portal-token' -and $TimeOutSec -eq 300 }
        }

        It 'serializes OAuth redirect URIs and uses the non-rest sharing path' {
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ status = 'success' } }
            $app = [PSCustomObject]@{ redirect_uris = @('https://app.example.test/callback', 'https://app.example.test/alt') }

            Update-OAuthApplication -URL 'https://portal.example.test/arcgis' -Token 'portal-token' -Referer 'https://portal.example.test' -AppId 'app-1' -AppObject $app | Out-Null

            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter {
                # Windows PowerShell 5.1 emits a JSON array as one pipeline object.
                # Direct assignment preserves its indices; @(... ConvertFrom-Json)
                # would nest it and make a correct request fail the mock filter.
                $redirectUris = $HttpFormParameters.redirect_uris | ConvertFrom-Json
                $Url -eq 'https://portal.example.test/arcgis/sharing/oauth2/apps/app-1/update' -and
                    $HttpMethod -eq 'POST' -and $HttpFormParameters.token -eq 'portal-token' -and
                    $Referer -eq 'https://portal.example.test' -and $HttpFormParameters.f -eq 'json' -and
                    $redirectUris.Count -eq 2 -and
                    $redirectUris[0] -eq 'https://app.example.test/callback' -and
                    $redirectUris[1] -eq 'https://app.example.test/alt'
            }
        }

        It 'returns the caught update error in the federated-server response contract' {
            Mock Invoke-ArcGISWebRequest { throw 'update denied' }

            $response = Update-FederatedServer -URL 'https://portal.example.test/arcgis' -Token 'portal-token' -Referer 'https://portal.example.test' -ServerId 'server-1' -ServerRole 'HOSTING_SERVER' -ServerFunction 'GeoAnalytics'

            $response.ContainsKey('error') | Should Be $true
            $response.error.Exception.Message | Should Be 'update denied'
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://portal.example.test/arcgis/portaladmin/federation/servers/server-1/update' -and $HttpFormParameters.serverRole -eq 'HOSTING_SERVER' -and $HttpFormParameters.serverFunction -eq 'GeoAnalytics' }
        }

        It 'throws the specific populate-license error returned by Portal' {
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ error = [PSCustomObject]@{ message = 'license file rejected' } } }
            $exception = $null

            try {
                Invoke-PopulateLicense -URL 'https://portal.example.test/arcgis' -Token 'portal-token' -Referer 'https://portal.example.test'
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'license file rejected'
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://portal.example.test/arcgis/portaladmin/license/populateLicense' -and $TimeOutSec -eq 3000 }
        }

        It 'forwards every log-setting field to the Portal edit endpoint' {
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ status = 'success' } }
            $settings = [PSCustomObject]@{ logDir = 'D:\portal-logs'; logLevel = 'DEBUG'; maxErrorReportsCount = 7; maxLogFileAge = 30; usageMeteringEnabled = $true }

            Update-PortalLogSettings -URL 'https://portal.example.test/arcgis' -Token 'portal-token' -Referer 'https://portal.example.test' -LogSettings $settings | Out-Null

            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://portal.example.test/arcgis/portaladmin/logs/settings/edit' -and $HttpMethod -eq 'POST' -and $HttpFormParameters.logDir -eq 'D:\portal-logs' -and $HttpFormParameters.logLevel -eq 'DEBUG' -and $HttpFormParameters.maxErrorReportsCount -eq 7 -and $HttpFormParameters.maxLogFileAge -eq 30 -and $HttpFormParameters.usageMeteringEnabled }
        }

        It 'serializes Portal system properties and returns the update response' {
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ status = 'success'; updated = $true } }
            $properties = [PSCustomObject]@{ privatePortalURL = 'https://portal-internal.example.test/arcgis'; enableAutomaticAccountCreation = $false }

            $response = Set-PortalSystemProperties -URL 'https://portal.example.test/arcgis' -Token 'portal-token' -Referer 'https://portal.example.test' -Properties $properties

            $response.updated | Should Be $true
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://portal.example.test/arcgis/portaladmin/system/properties/update/' -and $TimeOutSec -eq 360 -and $HttpFormParameters.token -eq 'portal-token' -and ($HttpFormParameters.properties | ConvertFrom-Json).privatePortalURL -eq 'https://portal-internal.example.test/arcgis' -and ($HttpFormParameters.properties | ConvertFrom-Json).enableAutomaticAccountCreation -eq $false }
        }

        It 'forwards every Portal user default setting to the sharing API' {
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ status = 'success' } }
            $defaults = [PSCustomObject]@{ role = 'org_user'; userLicenseType = 'creatorUT'; groups = 'group-1,group-2'; userType = 'creator'; apps = 'app-1'; appBundles = 'bundle-1' }

            Set-PortalUserDefaults -URL 'https://portal.example.test/arcgis' -Token 'portal-token' -Referer 'https://portal.example.test' -UserDefaultsParameters $defaults

            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://portal.example.test/arcgis/sharing/rest/portals/self/setUserDefaultSettings' -and $HttpFormParameters.role -eq 'org_user' -and $HttpFormParameters.userLicenseType -eq 'creatorUT' -and $HttpFormParameters.groups -eq 'group-1,group-2' -and $HttpFormParameters.userType -eq 'creator' -and $HttpFormParameters.apps -eq 'app-1' -and $HttpFormParameters.appBundles -eq 'bundle-1' }
        }

        It 'sends authenticated email settings and honors Portal recheck timing' {
            $credential = New-Object System.Management.Automation.PSCredential 'smtp-user', (ConvertTo-SecureString 'smtp-secret' -AsPlainText -Force)
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ status = 'success'; recheckAfterSeconds = 4 } }
            Mock Wait-RecheckAfterSeconds {}

            Update-PortalEmailSettings -URL 'https://portal.example.test/arcgis' -Token 'portal-token' -Referer 'https://portal.example.test' -SMTPServerAddress 'smtp.example.test' -From 'noreply@example.test' -Label 'Portal Mail' -AuthenticationRequired $true -Credential $credential -SMTPPort 587 -EncryptionMethod 'TLS'

            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://portal.example.test/arcgis/portaladmin/system/emailSettings/update' -and $HttpFormParameters.smtpServer -eq 'smtp.example.test' -and $HttpFormParameters.authRequired -eq 'yes' -and $HttpFormParameters.username -eq 'smtp-user' -and $HttpFormParameters.password -eq 'smtp-secret' -and $HttpFormParameters.smtpPort -eq 587 -and $HttpFormParameters.encryptionMethod -eq 'TLS' }
            Assert-MockCalled Wait-RecheckAfterSeconds -Exactly 1 -Scope It -ParameterFilter { $Seconds -eq 4 -and $Multiplier -eq 2 }
        }

        It 'returns the selected Portal certificate response from its machine certificate path' {
            Mock Invoke-ArcGISWebRequest { [PSCustomObject]@{ alias = 'portal-web-cert'; sha1Fingerprint = 'DEF456' } }

            $certificate = Get-SSLCertificatesForPortal -URL 'https://portal.example.test/arcgis' -WebServerCertificateAlias 'portal-web-cert' -Token 'portal-token' -Referer 'https://portal.example.test' -MachineName 'portal-01'

            $certificate.sha1Fingerprint | Should Be 'DEF456'
            Assert-MockCalled Invoke-ArcGISWebRequest -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://portal.example.test/arcgis/portaladmin/machines/portal-01/sslCertificates/portal-web-cert' -and $HttpMethod -eq 'GET' -and $TimeOutSec -eq 120 -and $HttpFormParameters.token -eq 'portal-token' }
        }
    }
}