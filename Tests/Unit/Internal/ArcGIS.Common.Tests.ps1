<#
    Tests private Common helpers inside their owning module: HTTP request construction,
    response/error handling, resource ownership, properties files, and component helpers.
    HTTP transport and command-based I/O are replaced by local doubles or Pester mocks;
    example.test URLs must never reach the network.

    The HTTP fixture intentionally exercises real .NET request/response objects so
    encoding, headers, JSON conversion, and disposal remain observable. See ../../README.md.
#>
$moduleScriptPath = Join-Path $PSScriptRoot '..\..\..\Modules\ArcGIS\Modules\ArcGIS.Common\ArcGIS.Common.psm1'

Import-Module $moduleScriptPath -Force

InModuleScope ArcGIS.Common {
    Describe 'Common HTTP and response helpers' {
        BeforeEach {
            # Keep mutable transport state in a distinctly named script-scope object.
            # PowerShell mocks use dynamic scope: a generic $Client variable can be
            # shadowed by the production function's local parameter of the same name.
            # Recreate all state per case so failure/status changes cannot leak.
            $script:httpTestState = @{
                ResponseBody = '{"status":"success","value":42}'
                StatusCode = 200
                SendError = $null
                ClientDisposed = $false
                Response = $null
                Sent = $null
            }
            $script:httpSendDouble = {
                param($Request, $CompletionOption)
                # Capture content before production cleanup disposes the request.
                # Save the request too, allowing separate assertions that its content
                # is unusable afterward rather than merely recording Dispose calls.
                $script:httpTestState.Sent = [PSCustomObject]@{
                    Uri = $Request.RequestUri.AbsoluteUri
                    Method = $Request.Method.Method
                    Body = if($null -ne $Request.Content) { $Request.Content.ReadAsStringAsync().GetAwaiter().GetResult() } else { $null }
                    ContentType = if($null -ne $Request.Content) { $Request.Content.Headers.ContentType.ToString() } else { $null }
                    Referer = $Request.Headers.Referrer.AbsoluteUri
                    ConnectionClose = $Request.Headers.ConnectionClose
                    CompletionOption = $CompletionOption
                    Request = $Request
                }
                if($script:httpTestState.SendError) { throw $script:httpTestState.SendError }
                $response = New-Object System.Net.Http.HttpResponseMessage -ArgumentList ([System.Net.HttpStatusCode]$script:httpTestState.StatusCode)
                $response.Content = New-Object System.Net.Http.StringContent -ArgumentList $script:httpTestState.ResponseBody
                $script:httpTestState.Response = $response
                # Return an already-completed Task with the SendAsync response type.
                # GetAwaiter().GetResult() therefore follows the normal code path
                # without starting a network request or a background worker.
                $completion = New-Object 'System.Threading.Tasks.TaskCompletionSource[System.Net.Http.HttpResponseMessage]'
                $completion.SetResult($response)
                $completion.Task
            }
            $script:httpOwnedClient = [PSCustomObject]@{ DefaultRequestHeaders = @() }
            $script:httpOwnedClient | Add-Member -MemberType ScriptMethod -Name SendAsync -Value $script:httpSendDouble
            $script:httpOwnedClient | Add-Member -MemberType ScriptMethod -Name Dispose -Value { $script:httpTestState.ClientDisposed = $true }
            # Mock the current factory, not the obsolete Invoke-WebRequest seam.
            # Production creates its client through this function; mocking the old
            # cmdlet would leave the actual HttpClient free to attempt DNS/HTTP.
            Mock New-ArcGISHttpClient { $script:httpOwnedClient }
        }

        It 'URL encodes every HTTP form key and value' {
            $body = ConvertTo-HttpBody @{ 'display name' = 'ArcGIS Server'; 'token&name' = 'a+b' }

            # Hashtable enumeration order is unspecified. Sort complete encoded pairs
            # so equality pins every key/value without inventing a wire-order contract.
            (($body -split '&' | Sort-Object) -join '&') | Should Be 'display+name=ArcGIS+Server&token%26name=a%2bb'
        }

        It 'returns an empty body for no HTTP form parameters' {
            ConvertTo-HttpBody @{} | Should Be ''
        }

        It 'throws the response error message returned by an ArcGIS endpoint' {
            $exception = $null

            try {
                Confirm-ResponseStatus -Response ([PSCustomObject]@{ status = 'error'; messages = @('permission denied') }) -Url 'https://server.example.test/admin'
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Match 'failed\. permission denied'
        }

        It 'posts a URL-encoded body and deserializes the JSON response' {
            $response = Invoke-ArcGISWebRequest -Url 'https://server.example.test/admin/edit' -HttpFormParameters @{ name = 'ArcGIS Server'; city = 'New York' } -Referer 'https://portal.example.test'

            $response.status | Should Be 'success'
            $response.value | Should Be 42
            $script:httpTestState.Sent.Uri | Should Be 'https://server.example.test/admin/edit'
            $script:httpTestState.Sent.Method | Should Be 'POST'
            (($script:httpTestState.Sent.Body -split '&' | Sort-Object) -join '&') | Should Be 'city=New+York&name=ArcGIS+Server'
            $script:httpTestState.Sent.ContentType | Should Be 'application/x-www-form-urlencoded'
            $script:httpTestState.Sent.Referer | Should Be 'https://portal.example.test/'
            $script:httpTestState.Sent.ConnectionClose | Should Be $true
            $script:httpTestState.ClientDisposed | Should Be $true
            { $script:httpTestState.Sent.Request.Content.ReadAsStringAsync() } | Should Throw
            { $script:httpTestState.Response.Content.ReadAsStringAsync() } | Should Throw
            Assert-MockCalled New-ArcGISHttpClient -Exactly 1 -Scope It -ParameterFilter {
                $TimeOutSec -eq 30 -and $UseDefaultCredentials -eq $true -and $MaximumRedirection -eq 50 -and $AllowUntrustedCertificates -eq $true
            }
        }

        It 'wraps an empty HTTP response in the request failure contract' {
            $script:httpTestState.ResponseBody = ''
            $exception = $null

            try {
                Invoke-ArcGISWebRequest -Url 'https://server.example.test/admin/edit' -HttpFormParameters @{ f = 'json' }
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Request to https://server.example.test/admin/edit failed. An unexpected error occurred: Response returned NULL'
            $script:httpTestState.ClientDisposed | Should Be $true
            { $script:httpTestState.Response.Content.ReadAsStringAsync() } | Should Throw
            Assert-MockCalled New-ArcGISHttpClient -Exactly 1 -Scope It
        }

        It 'appends encoded GET parameters to <QueryKind> without a request body' -TestCases @(
            @{ QueryKind = 'a new query'; Url = 'https://server.example.test/info'; ExpectedUri = 'https://server.example.test/info?name=a%2bb' }
            @{ QueryKind = 'an existing query'; Url = 'https://server.example.test/info?f=json'; ExpectedUri = 'https://server.example.test/info?f=json&name=a%2bb' }
        ) {
            param($QueryKind, $Url, $ExpectedUri)

            $response = Invoke-ArcGISWebRequest -Url $Url -HttpMethod GET -HttpFormParameters @{ name = 'a+b' } -TimeOutSec 7 -MaximumRedirection 2 -AllowUntrustedCertificates $false

            $response.value | Should Be 42
            $script:httpTestState.Sent.Uri | Should Be $ExpectedUri
            $script:httpTestState.Sent.Method | Should Be 'GET'
            $script:httpTestState.Sent.Body | Should Be $null
            $script:httpTestState.Sent.ConnectionClose | Should Be $false
            $script:httpTestState.ClientDisposed | Should Be $true
            Assert-MockCalled New-ArcGISHttpClient -Exactly 1 -Scope It -ParameterFilter {
                $TimeOutSec -eq 7 -and $UseDefaultCredentials -eq $false -and $MaximumRedirection -eq 2 -and $AllowUntrustedCertificates -eq $false
            }
        }

        It 'returns null for an empty successful GET without changing the URL' {
            $script:httpTestState.ResponseBody = ''

            $response = Invoke-ArcGISWebRequest -Url 'https://server.example.test/info' -HttpMethod GET

            $response | Should Be $null
            $script:httpTestState.Sent.Uri | Should Be 'https://server.example.test/info'
            $script:httpTestState.Sent.Body | Should Be $null
            $script:httpTestState.ClientDisposed | Should Be $true
        }

        It 'returns text without trying to deserialize JSON' {
            $script:httpTestState.ResponseBody = 'not JSON: status=ready'

            Invoke-ArcGISWebRequest -Url 'https://server.example.test/info' -HttpMethod GET -ResponseType Text | Should Be 'not JSON: status=ready'

            $script:httpTestState.ClientDisposed | Should Be $true
            { $script:httpTestState.Response.Content.ReadAsStringAsync() } | Should Throw
        }

        It 'returns non-success HTTP metadata in <ResponseType> mode' -TestCases @(
            # Metadata modes expose status even for errors; Headers avoids reading
            # the body, whereas Response retains it. JSON/Text have other contracts.
            @{ ResponseType = 'Response'; ExpectedContent = 'permission denied'; ExpectedCompletion = 'ResponseContentRead' }
            @{ ResponseType = 'Headers'; ExpectedContent = $null; ExpectedCompletion = 'ResponseHeadersRead' }
        ) {
            param($ResponseType, $ExpectedContent, $ExpectedCompletion)
            $script:httpTestState.StatusCode = 403
            $script:httpTestState.ResponseBody = 'permission denied'

            $response = Invoke-ArcGISWebRequest -Url 'https://server.example.test/info' -HttpMethod GET -ResponseType $ResponseType

            $response.StatusCode | Should Be 403
            $response.ReasonPhrase | Should Be 'Forbidden'
            $response.Content | Should Be $ExpectedContent
            $script:httpTestState.Sent.CompletionOption.ToString() | Should Be $ExpectedCompletion
            $script:httpTestState.ClientDisposed | Should Be $true
        }

        It 'rejects a non-success status before parsing its body and releases owned resources' {
            $script:httpTestState.StatusCode = 403
            $script:httpTestState.ResponseBody = '{"value":42}'
            $exception = $null

            try { Invoke-ArcGISWebRequest -Url 'https://server.example.test/admin/edit' }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Match 'Request to https://server\.example\.test/admin/edit failed\.'
            $exception.Exception.Message | Should Match '403'
            $script:httpTestState.ClientDisposed | Should Be $true
            { $script:httpTestState.Response.Content.ReadAsStringAsync() } | Should Throw
            { $script:httpTestState.Sent.Request.Content.ReadAsStringAsync() } | Should Throw
        }

        It 'wraps <HttpMethod> transport failures and disposes the owned client' -TestCases @(
            @{ HttpMethod = 'GET'; ExpectedPrefix = 'An unexpected error occurred:' }
            @{ HttpMethod = 'POST'; ExpectedPrefix = 'Request to https://server.example.test/info failed. An unexpected error occurred:' }
        ) {
            param($HttpMethod, $ExpectedPrefix)
            $script:httpTestState.SendError = 'simulated transport failure'
            $exception = $null

            try { Invoke-ArcGISWebRequest -Url 'https://server.example.test/info' -HttpMethod $HttpMethod }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message.StartsWith($ExpectedPrefix) | Should Be $true
            $exception.Exception.Message | Should Match 'simulated transport failure'
            $script:httpTestState.Sent.Method | Should Be $HttpMethod
            $script:httpTestState.Response | Should Be $null
            $script:httpTestState.ClientDisposed | Should Be $true
        }

        It 'leaves a supplied HTTP client caller-owned after <Outcome>' -TestCases @(
            @{ Outcome = 'a successful request'; SendError = $null }
            @{ Outcome = 'a transport failure'; SendError = 'supplied-client failure' }
        ) {
            param($Outcome, $SendError)
            $script:httpTestState.SendError = $SendError
            $suppliedClient = New-Object System.Net.Http.HttpClient
            # A supplied client must satisfy the typed production parameter. Shadow
            # SendAsync on a real instance to keep transport local while preserving
            # the genuine disposal behavior used by the ownership assertions.
            $suppliedClient | Add-Member -MemberType ScriptMethod -Name SendAsync -Force -Value $script:httpSendDouble

            try {
                $exception = $null
                $response = $null
                try { $response = Invoke-ArcGISWebRequest -Url 'https://server.example.test/info' -HttpMethod GET -HttpClient $suppliedClient }
                catch { $exception = $_ }

                if($SendError) {
                    $exception | Should Not Be $null
                    $exception.Exception.Message.StartsWith('An unexpected error occurred:') | Should Be $true
                    $exception.Exception.Message | Should Match 'supplied-client failure'
                    $script:httpTestState.Response | Should Be $null
                }else {
                    $exception | Should Be $null
                    $response.value | Should Be 42
                    { $script:httpTestState.Response.Content.ReadAsStringAsync() } | Should Throw
                }
                $script:httpTestState.Sent.Method | Should Be 'GET'
                # Setting Timeout would throw on a disposed HttpClient. This checks
                # caller ownership after success AND failure, not just response data.
                $suppliedClient.Timeout = [TimeSpan]::FromSeconds(17)
                $suppliedClient.Timeout.TotalSeconds | Should Be 17
                Assert-MockCalled New-ArcGISHttpClient -Exactly 0 -Scope It
            }
            finally { $suppliedClient.Dispose() }
        }

        It 'sends supplied content and custom headers without overriding the explicit Referer' {
            # Content is a one-use request body, unlike a reusable caller-owned client.
            # Assert disposal after sending and clean up in finally if an assertion fails.
            $content = New-Object System.Net.Http.StringContent -ArgumentList @('{"name":"ArcGIS"}', [System.Text.Encoding]::UTF8, 'application/json')

            try {
                $response = Invoke-ArcGISWebRequest -Url 'https://server.example.test/admin/edit' -Content $content -Referer 'https://trusted.example.test' -HttpHeaders @{ Referer = 'https://ignored.example.test'; 'X-ArcGIS-Test' = 'header-value' }

                $response.value | Should Be 42
                $script:httpTestState.Sent.Method | Should Be 'POST'
                $script:httpTestState.Sent.Body | Should Be '{"name":"ArcGIS"}'
                $script:httpTestState.Sent.ContentType | Should Be 'application/json; charset=utf-8'
                $script:httpTestState.Sent.Referer | Should Be 'https://trusted.example.test/'
                ($script:httpTestState.Sent.Request.Headers.GetValues('X-ArcGIS-Test') -join ',') | Should Be 'header-value'
                $script:httpTestState.Sent.Request.Headers.ExpectContinue | Should Be $false
                $script:httpTestState.ClientDisposed | Should Be $true
                { $content.ReadAsStringAsync() } | Should Throw
                { $script:httpTestState.Response.Content.ReadAsStringAsync() } | Should Throw
            }
            finally { $content.Dispose() }
        }

        It 'reports nested endpoint errors using <MessageKind>' -TestCases @(
            @{ MessageKind = 'joined messages'; ErrorResponse = @{ error = @{ messages = @('permission denied', 'token expired') } }; ExpectedMessage = 'permission denied token expired' }
            @{ MessageKind = 'a single message'; ErrorResponse = @{ error = @{ message = 'invalid token' } }; ExpectedMessage = 'invalid token' }
            @{ MessageKind = 'a top-level fallback message'; ErrorResponse = @{ status = 'ERROR'; message = 'site unavailable' }; ExpectedMessage = 'site unavailable' }
        ) {
            param($MessageKind, $ErrorResponse, $ExpectedMessage)
            $exception = $null

            try { Confirm-ResponseStatus -Response $ErrorResponse -Url 'https://server.example.test/admin' }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message.EndsWith("failed. $ExpectedMessage") | Should Be $true
        }

        It 'includes the requested URL when the endpoint response is null' {
            $exception = $null

            try { Confirm-ResponseStatus -Response $null -Url 'https://server.example.test/admin' }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Match 'response is NULL\.URL:- https://server\.example\.test/admin$'
        }

        It 'accepts successful endpoint responses without producing pipeline output' {
            @(Confirm-ResponseStatus -Response @{ status = 'success'; value = 42 } -Url 'https://server.example.test/admin').Count | Should Be 0
        }
    }

    Describe 'Common properties and hosts helpers' {
        It 'returns the value after the final matching property entry' {
            Mock Test-Path { $true }
            Mock Get-Content { @('hostname=old-host', 'unrelated=value', 'hostname=final-host ') }

            Get-PropertyFromPropertiesFile -PropertiesFilePath 'C:\ArcGIS\hostname.properties' -PropertyName 'hostname' | Should Be 'final-host'
            Assert-MockCalled Get-Content -Exactly 1 -Scope It -ParameterFilter { $Path -eq 'C:\ArcGIS\hostname.properties' }
        }

        It 'uncomments a property and writes the requested replacement value' {
            Mock Test-Path { $true }
            Mock Get-Content { @('#hostname=old-host', 'other=value') }
            Mock Set-Content {}

            $changed = Set-PropertyFromPropertiesFile -PropertiesFilePath 'C:\ArcGIS\hostname.properties' -PropertyName 'hostname' -PropertyValue 'new-host'

            $changed | Should Be $true
            Assert-MockCalled Set-Content -Exactly 1 -Scope It -ParameterFilter { $Path -eq 'C:\ArcGIS\hostname.properties' -and $Value -contains 'hostname=new-host' -and $Value -contains 'other=value' }
        }

        It 'does not write properties when the existing value already matches' {
            Mock Test-Path { $true }
            Mock Get-Content { @('hostname=server-01') }
            Mock Set-Content { throw 'The matching property must not be written.' }

            $changed = Set-PropertyFromPropertiesFile -PropertiesFilePath 'C:\ArcGIS\hostname.properties' -PropertyName 'hostname' -PropertyValue 'server-01'

            $changed | Should Be $false
            Assert-MockCalled Set-Content -Exactly 0 -Scope It
        }

        It 'appends an absent property while preserving unrelated entries and blank lines' {
            Mock Test-Path { $true }
            Mock Get-Content { @('other=value', '', '# retained comment') }
            Mock Set-Content {}

            Set-PropertyFromPropertiesFile -PropertiesFilePath 'C:\ArcGIS\hostname.properties' -PropertyName 'hostname' -PropertyValue 'server-01' | Should Be $true

            Assert-MockCalled Set-Content -Exactly 1 -Scope It -ParameterFilter {
                $Path -eq 'C:\ArcGIS\hostname.properties' -and $Force -and
                $Value.Count -eq 4 -and $Value[0] -eq 'other=value' -and $Value[1] -eq '' -and
                $Value[2] -eq '# retained comment' -and $Value[3] -eq 'hostname=server-01'
            }
        }

        It 'creates a missing properties file with only the requested entry' {
            Mock Test-Path { $false }
            Mock Get-Content { throw 'A missing file must not be read.' }
            Mock Set-Content {}

            Set-PropertyFromPropertiesFile -PropertiesFilePath 'C:\ArcGIS\hostname.properties' -PropertyName 'hostname' -PropertyValue 'server-01' | Should Be $true

            Assert-MockCalled Get-Content -Exactly 0 -Scope It
            Assert-MockCalled Set-Content -Exactly 1 -Scope It -ParameterFilter {
                $Path -eq 'C:\ArcGIS\hostname.properties' -and $Force -and
                $Value.Count -eq 1 -and $Value[0] -eq 'hostname=server-01'
            }
        }

        It 'preserves equals signs in property values and ignores comments and prefix collisions' {
            Mock Test-Path { $true }
            Mock Get-Content { @('token= first=second== ', '#token=ignored', 'tokenSuffix=wrong') }

            Get-PropertyFromPropertiesFile -PropertiesFilePath 'C:\ArcGIS\token.properties' -PropertyName 'token' | Should Be 'first=second=='
        }

        It 'returns null without reading content when the properties file is missing' {
            Mock Test-Path { $false }
            Mock Get-Content { throw 'A missing file must not be read.' }

            Get-PropertyFromPropertiesFile -PropertiesFilePath 'C:\ArcGIS\missing.properties' -PropertyName 'hostname' | Should Be $null

            Assert-MockCalled Test-Path -Exactly 1 -Scope It -ParameterFilter { $Path -eq 'C:\ArcGIS\missing.properties' }
            Assert-MockCalled Get-Content -Exactly 0 -Scope It
        }

        It 'adds an absent hosts mapping with the expected address and hostname' {
            Mock Get-Content { @('127.0.0.1 localhost', '# 192.0.2.10 ignored-host') }
            Mock Add-Content {}

            $added = Add-HostMapping -hostname 'server-01.contoso.com' -ipaddress '192.0.2.10'

            $added | Should Be $true
            Assert-MockCalled Add-Content -Exactly 2 -Scope It
            Assert-MockCalled Add-Content -Exactly 1 -Scope It -ParameterFilter { $Value -match '^192\.0\.2\.10\s+server-01\.contoso\.com' }
        }

        It 'does not duplicate an existing hosts mapping that has an inline comment' {
            Mock Get-Content { @('192.0.2.10   server-01.contoso.com # primary server') }
            Mock Add-Content { throw 'An existing mapping must not be appended.' }

            $added = Add-HostMapping -hostname 'server-01.contoso.com' -ipaddress '192.0.2.10'

            $added | Should Be $false
            Assert-MockCalled Add-Content -Exactly 0 -Scope It
        }
    }

    Describe 'Common component and process-boundary helpers' {
        It 'returns the Server registry version and install directory from the SxS registry key' {
            Mock Get-ItemProperty { [PSCustomObject]@{ RealVersion = '11.3.0'; InstallDir = 'D:\ArcGIS\Server' } }

            $details = Get-ArcGISComponentVersionAndInstallDirectory -ComponentName 'Server' -ServiceName 'ArcGIS Server'

            $details.RealVersion | Should Be '11.3.0'
            $details.InstallDir | Should Be 'D:\ArcGIS\Server'
            Assert-MockCalled Get-ItemProperty -Exactly 1 -Scope It -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\ESRI\ArcGIS_SXS_Server' }
        }

        It 'forwards configured hostname and host-identifier property paths and values' {
            Mock Get-PropertyFromPropertiesFile { 'configured-value' }
            Mock Set-PropertyFromPropertiesFile { $true }

            $hostName = Get-ConfiguredHostName -InstallDir 'C:\ArcGIS\Portal'
            $hostIdentifier = Get-ConfiguredHostIdentifier -InstallDir 'C:\ArcGIS\Portal'
            $hostIdentifierType = Get-ConfiguredHostIdentifierType -InstallDir 'C:\ArcGIS\Portal'
            $changed = Set-ConfiguredHostIdentifier -InstallDir 'C:\ArcGIS\Portal' -HostIdentifier 'portal-01.contoso.com' -HostIdentifierType 'ip'

            $hostName | Should Be 'configured-value'
            $hostIdentifier | Should Be 'configured-value'
            $hostIdentifierType | Should Be 'configured-value'
            $changed | Should Be $true
            Assert-MockCalled Get-PropertyFromPropertiesFile -Exactly 1 -Scope It -ParameterFilter { $PropertiesFilePath -eq 'C:\ArcGIS\Portal\framework\etc\hostname.properties' -and $PropertyName -eq 'hostname' }
            Assert-MockCalled Get-PropertyFromPropertiesFile -Exactly 1 -Scope It -ParameterFilter { $PropertiesFilePath -eq 'C:\ArcGIS\Portal\framework\etc\hostidentifier.properties' -and $PropertyName -eq 'hostidentifier' }
            Assert-MockCalled Get-PropertyFromPropertiesFile -Exactly 1 -Scope It -ParameterFilter { $PropertiesFilePath -eq 'C:\ArcGIS\Portal\framework\etc\hostidentifier.properties' -and $PropertyName -eq 'preferredidentifier' }
            Assert-MockCalled Set-PropertyFromPropertiesFile -Exactly 1 -Scope It -ParameterFilter { $PropertiesFilePath -eq 'C:\ArcGIS\Portal\framework\etc\hostidentifier.properties' -and $PropertyName -eq 'hostidentifier' -and $PropertyValue -eq 'portal-01.contoso.com' }
            Assert-MockCalled Set-PropertyFromPropertiesFile -Exactly 1 -Scope It -ParameterFilter { $PropertiesFilePath -eq 'C:\ArcGIS\Portal\framework\etc\hostidentifier.properties' -and $PropertyName -eq 'preferredidentifier' -and $PropertyValue -eq 'ip' }
        }

        It 'confirms an installed component from the normalized native uninstall path' {
            Mock Test-Path { $true }

            $installed = Test-Install -Name 'Server' -Version '12.2'

            $installed | Should Be $true
            Assert-MockCalled Test-Path -Exactly 1 -Scope It -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{DC0B22C6-16E1-45AF-83C3-B3FF23AE0EB5}' }
        }

        It 'rejects a supplied product ID that does not match the requested component version' {
            Mock Test-Path { throw 'A mismatched product ID must not query the registry.' }

            $installed = Test-Install -Name 'Server' -Version '12.2' -ProductId 'DIFFERENT-ID'

            $installed | Should Be $false
            Assert-MockCalled Test-Path -Exactly 0 -Scope It
        }

        It 'selects the first drive letter not reported by the mocked filesystem provider or exclusion' {
            Mock Get-PSDrive { @([PSCustomObject]@{ Name = 'C' }, [PSCustomObject]@{ Name = 'D' }, [PSCustomObject]@{ Name = 'F' }) }

            $letter = Get-AvailableDriveLetter -ExcludedLetter 'E'

            $letter | Should Be 'G'
            Assert-MockCalled Get-PSDrive -Exactly 1 -Scope It -ParameterFilter { $PSProvider -eq 'filesystem' }
        }

        It 'detects Amazon node agent elements from mocked XML content' {
            Mock Test-Path { $true }
            Mock Get-Content { '<NodeAgent><Observers><Observer platform="amazon" /></Observers><Plugins /></NodeAgent>' }

            Get-NodeAgentAmazonElementsPresent -InstallDir 'C:\ArcGIS\Portal' | Should Be $true
        }

        It 'reports no Amazon node agent elements when the XML contains only local extensions' {
            Mock Test-Path { $true }
            Mock Get-Content { '<NodeAgent><Observers><Observer platform="local" /></Observers><Plugins><Plugin platform="azure" /></Plugins></NodeAgent>' }

            Get-NodeAgentAmazonElementsPresent -InstallDir 'C:\ArcGIS\Portal' | Should Be $false
        }

        It 'builds component URLs for explicit standard and HTTPS ports' {
            Get-ArcGISComponentBaseUrl -FQDN 'server-01.contoso.com' -ComponentName 'Server' -Port 6443 | Should Be 'https://server-01.contoso.com:6443/arcgis'
            Get-ArcGISComponentBaseUrl -FQDN 'portal.contoso.com' -ComponentName 'Portal' -Port 443 -Context 'portal' | Should Be 'https://portal.contoso.com/portal'
        }

        It 'uses both server health endpoints and forwards all wait options' {
            Mock Wait-ForUrl {}

            Test-ArcGISComponentHealth -BaseURL 'https://server.example.test/arcgis' -ComponentName 'Server' -MaxWaitTimeInSeconds 12 -SleepTimeInSeconds 3 -ThrowErrors $true -HttpMethod 'POST' -MaximumRedirection 2 -RequestTimeoutInSeconds 7 -IsWebAdaptor $true

            Assert-MockCalled Wait-ForUrl -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://server.example.test/arcgis/rest/info/healthcheck?f=json' -and $MaxWaitTimeInSeconds -eq 12 -and $SleepTimeInSeconds -eq 3 -and $ThrowErrors -and $HttpMethod -eq 'POST' -and $MaximumRedirection -eq 2 -and $RequestTimeoutInSeconds -eq 7 -and $IsWebAdaptor }
            Assert-MockCalled Wait-ForUrl -Exactly 1 -Scope It -ParameterFilter { $Url -eq 'https://server.example.test/arcgis/admin' }
        }

        It 'sleeps for the configured recheck multiplier and skips zero seconds' {
            Mock Start-Sleep {}

            Wait-RecheckAfterSeconds -Seconds 4 -Multiplier 3
            Wait-RecheckAfterSeconds -Seconds 0 -Multiplier 3

            Assert-MockCalled Start-Sleep -Exactly 1 -Scope It -ParameterFilter { $Seconds -eq 12 }
        }

        It 'maps representative product names and component codes without a version matrix' {
            Get-ArcGISProductName -Name 'VelocityServer' -Version '12.2' | Should Be 'ArcGIS Velocity for ArcGIS Enterprise 12.2'
            Get-ArcGISProductName -Name 'WebAdaptorJava' -Version '12.2' | Should Be 'ArcGIS Web Adaptor (Java Platform)'
            Get-ComponentCode -ComponentName 'Server' -Version '12.2' | Should Be 'DC0B22C6-16E1-45AF-83C3-B3FF23AE0EB5'
        }

        It 'returns the final product codes for Pro 3.8 and Enterprise 12.2 components' {
            Get-ComponentCode -ComponentName 'Pro' -Version '3.8' | Should Be '99FA33F5-A747-442F-9D27-AF352BFDC57B'
            Get-ComponentCode -ComponentName 'ServerDataInteroperability' -Version '12.2' | Should Be '44FD3877-0396-44A1-89A6-E7C61ED9319B'
            Get-ComponentCode -ComponentName 'ProDataInteroperability' -Version '3.8' | Should Be '7B60525F-0323-4741-8F47-1ED0863A24E8'
            Get-ComponentCode -ComponentName 'ServerMappingChartingSolution' -Version '12.2' | Should Be '5068EFEC-A439-41AA-90D5-18CF07272C38'
            Get-ComponentCode -ComponentName 'ServerDeepLearningLibraries' -Version '12.2' | Should Be '5F6CAC9B-66AC-4402-93EE-E9FE87711346'
        }
    }
}