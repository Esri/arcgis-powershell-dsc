<#
    Covers recursive object conversion, secret-source precedence, PowerShell-version
    checks, node selection, endpoint resolution, Java/Tomcat validation, and proxy settings.
    Private helpers run in ArcGIS scope; file, environment, DNS, and remote-version
    collaborators are mocked where needed rather than queried on real target machines.

    Dummy secrets deliberately have different values to expose incorrect source selection.
    Run with Windows PowerShell 5.1/Pester 3.4.0; see ../README.md.
#>
$moduleScriptPath = Join-Path $PSScriptRoot '..\..\Modules\ArcGIS\ArcGIS.psm1'

Import-Module $moduleScriptPath

InModuleScope ArcGIS {
    Describe 'Convert-PSObjectToHashtable' {
        It 'recursively converts nested custom objects and collections' {
            $inputObject = [PSCustomObject]@{
                Name = 'ArcGIS'
                Metadata = [PSCustomObject]@{
                    Enabled = $true
                }
                Roles = @(
                    [PSCustomObject]@{ Name = 'Server' }
                    [PSCustomObject]@{ Name = 'Portal' }
                )
            }

            $result = Convert-PSObjectToHashtable -InputObject $inputObject

            $result | Should BeOfType System.Collections.Hashtable
            $result.Name | Should Be 'ArcGIS'
            $result.Metadata | Should BeOfType System.Collections.Hashtable
            $result.Metadata.Enabled | Should Be $true
            $result.Roles.Count | Should Be 2
            $result.Roles[0].Name | Should Be 'Server'
            $result.Roles[1].Name | Should Be 'Portal'
        }

        It 'preserves null pipeline values' {
            $result = @($null | Convert-PSObjectToHashtable)

            $result.Count | Should Be 1
            $result[0] | Should Be $null
        }
    }

    Describe 'Resolve-SecretFromObject' {
        It 'converts a plaintext secret from a hashtable to a secure string' {
            $secret = Resolve-SecretFromObject -Object @{ Password = 'secret-value' } -Prefix 'Password'

            # A SecureString existence/type check would not prove its contents came
            # from the right source. Decode only fixture secrets through PSCredential
            # and compare with a fixed expected value; never use real credentials here.
            $credential = New-Object System.Management.Automation.PSCredential 'test-user', $secret

            $credential.GetNetworkCredential().Password | Should Be 'secret-value'
        }

        It 'uses the environment variable provider when configured' {
            Mock Get-PasswordFromEnvironmentVariable { ConvertTo-SecureString 'from-environment' -AsPlainText -Force }

            $secret = Resolve-SecretFromObject -Object ([PSCustomObject]@{ PasswordEnvironmentVariableName = 'ARCGIS_TEST_PASSWORD' }) -Prefix 'Password'
            $credential = New-Object System.Management.Automation.PSCredential 'test-user', $secret

            $credential.GetNetworkCredential().Password | Should Be 'from-environment'
            Assert-MockCalled Get-PasswordFromEnvironmentVariable -Exactly 1 -ParameterFilter {
                $EnvironmentVariableName -eq 'ARCGIS_TEST_PASSWORD'
            }
        }

        It 'uses a configured secret file before an environment variable' {
            # Generate the encrypted fixture under the current Windows user. This
            # exercises the real SecureString conversion without storing a user-bound
            # encrypted blob in source control or reading an actual password file.
            $encryptedPassword = ConvertTo-SecureString 'from-file' -AsPlainText -Force | ConvertFrom-SecureString
            Mock Test-Path { $true }
            Mock Get-Content { $encryptedPassword }
            Mock Get-PasswordFromEnvironmentVariable { ConvertTo-SecureString 'from-environment' -AsPlainText -Force }

            $secret = Resolve-SecretFromObject -Object @{ PasswordFilePath = 'C:\password.txt'; PasswordEnvironmentVariableName = 'ARCGIS_TEST_PASSWORD'; Password = 'plaintext' } -Prefix 'Password'
            $credential = New-Object System.Management.Automation.PSCredential 'test-user', $secret

            $credential.GetNetworkCredential().Password | Should Be 'from-file'
            Assert-MockCalled Test-Path -Exactly 1 -Scope It -ParameterFilter { $Path -eq 'C:\password.txt' }
            Assert-MockCalled Get-Content -Exactly 1 -Scope It -ParameterFilter { $Path -eq 'C:\password.txt' }
            Assert-MockCalled Get-PasswordFromEnvironmentVariable -Exactly 0 -Scope It
        }

        It 'throws when the configured secret file does not exist' {
            Mock Test-Path { $false }
            Mock Get-Content { throw 'The missing file must not be read.' }
            Mock Get-PasswordFromEnvironmentVariable { throw 'A missing file must not fall back.' }
            $exception = $null

            try {
                Resolve-SecretFromObject -Object @{ PasswordFilePath = 'C:\missing-password.txt'; PasswordEnvironmentVariableName = 'ARCGIS_TEST_PASSWORD'; Password = 'plaintext' } -Prefix 'Password'
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Password file C:\missing-password.txt does not exist.'
            Assert-MockCalled Test-Path -Exactly 1 -ParameterFilter { $Path -eq 'C:\missing-password.txt' }
            Assert-MockCalled Get-Content -Exactly 0 -Scope It
            Assert-MockCalled Get-PasswordFromEnvironmentVariable -Exactly 0 -Scope It
        }

        It 'prefers the environment over plaintext for <ObjectKind> secrets' -TestCases @(
            @{ ObjectKind = 'hashtable' }
            @{ ObjectKind = 'custom object' }
        ) {
            param($ObjectKind)
            $secretObject = @{ PasswordEnvironmentVariableName = 'ARCGIS_TEST_PASSWORD'; Password = 'plaintext' }
            if($ObjectKind -eq 'custom object') { $secretObject = [PSCustomObject]$secretObject }
            Mock Get-PasswordFromEnvironmentVariable { ConvertTo-SecureString 'environment-secret' -AsPlainText -Force }

            $secret = Resolve-SecretFromObject -Object $secretObject -Prefix 'Password'
            $credential = New-Object System.Management.Automation.PSCredential 'test-user', $secret

            $credential.GetNetworkCredential().Password | Should Be 'environment-secret'
            Assert-MockCalled Get-PasswordFromEnvironmentVariable -Exactly 1 -Scope It -ParameterFilter {
                $EnvironmentVariableName -eq 'ARCGIS_TEST_PASSWORD'
            }
        }

        It 'ignores whitespace providers and resolves a custom prefix for <ObjectKind>' -TestCases @(
            @{ ObjectKind = 'hashtable' }
            @{ ObjectKind = 'custom object' }
        ) {
            param($ObjectKind)
            # Token and Password intentionally conflict. Whitespace provider names
            # must count as unconfigured, and Prefix must select Token, not Password.
            $secretObject = @{ TokenFilePath = ' '; TokenEnvironmentVariableName = "`t"; Token = 'token-secret'; Password = 'wrong-prefix' }
            if($ObjectKind -eq 'custom object') { $secretObject = [PSCustomObject]$secretObject }
            Mock Test-Path { throw 'A blank file provider must not be queried.' }
            Mock Get-PasswordFromEnvironmentVariable { throw 'A blank environment provider must not be queried.' }

            $secret = Resolve-SecretFromObject -Object $secretObject -Prefix 'Token'
            $credential = New-Object System.Management.Automation.PSCredential 'test-user', $secret

            $credential.GetNetworkCredential().Password | Should Be 'token-secret'
            Assert-MockCalled Test-Path -Exactly 0 -Scope It
            Assert-MockCalled Get-PasswordFromEnvironmentVariable -Exactly 0 -Scope It
        }

        It 'returns null for a null secret object without consulting providers' {
            Mock Test-Path { throw 'No file provider is configured.' }
            Mock Get-PasswordFromEnvironmentVariable { throw 'No environment provider is configured.' }

            Resolve-SecretFromObject -Object $null -Prefix 'Password' | Should Be $null

            Assert-MockCalled Test-Path -Exactly 0 -Scope It
            Assert-MockCalled Get-PasswordFromEnvironmentVariable -Exactly 0 -Scope It
        }

        It 'returns null when no configured secret source has a value' {
            $secret = Resolve-SecretFromObject -Object @{ Password = ''; PasswordFilePath = ''; PasswordEnvironmentVariableName = '' } -Prefix 'Password'

            $secret | Should Be $null
        }
    }

    Describe 'Assert-PowerShellVersionIs51' {
        It 'accepts Windows PowerShell 5.1' {
            $exception = $null

            try {
                Assert-PowerShellVersionIs51 -Version ([Version]'5.1.19041.1') -Scope 'test machine'
            }
            catch {
                $exception = $_
            }

            $exception | Should Be $null
        }

        It 'rejects unsupported PowerShell versions' {
            $exception = $null

            try {
                Assert-PowerShellVersionIs51 -Version ([Version]'7.4.0') -Scope 'test machine'
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be "Error: ArcGIS PowerShell DSC supports Windows PowerShell 5.1 only. Unsupported version '7.4.0' detected on test machine."
        }

        It 'rejects the adjacent unsupported version <UnsupportedVersion>' -TestCases @(
            @{ UnsupportedVersion = '5.0' }
            @{ UnsupportedVersion = '5.2' }
        ) {
            param($UnsupportedVersion)
            $exception = $null

            try { Assert-PowerShellVersionIs51 -Version ([Version]$UnsupportedVersion) -Scope 'boundary node' }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be "Error: ArcGIS PowerShell DSC supports Windows PowerShell 5.1 only. Unsupported version '$UnsupportedVersion' detected on boundary node."
        }
    }

    Describe 'Get-ConfigurationTargetNodeNames' {
        It 'returns distinct nonblank node names' {
            $configuration = @{
                AllNodes = @(
                    @{ NodeName = 'server-01' }
                    @{ NodeName = 'server-01' }
                    @{ NodeName = 'portal-01' }
                    @{ NodeName = ' ' }
                )
            }

            $nodeNames = @(Get-ConfigurationTargetNodeNames -Configuration $configuration)

            $nodeNames.Count | Should Be 2
            $nodeNames[0] | Should Be 'server-01'
            $nodeNames[1] | Should Be 'portal-01'
        }

        It 'returns no target names for <ConfigurationKind>' -TestCases @(
            @{ ConfigurationKind = 'missing AllNodes'; Configuration = @{} }
            @{ ConfigurationKind = 'empty AllNodes'; Configuration = @{ AllNodes = @() } }
            @{ ConfigurationKind = 'blank node names'; Configuration = @{ AllNodes = @(@{ NodeName = '' }, @{ NodeName = ' ' }, @{ NodeName = $null }) } }
        ) {
            param($ConfigurationKind, $Configuration)

            @(Get-ConfigurationTargetNodeNames -Configuration $Configuration).Count | Should Be 0
        }
    }

    Describe 'Test-IsLocalComputerName' {
        It 'recognizes standard local aliases' -TestCases @(
            @{ ComputerName = '.' }
            @{ ComputerName = 'localhost' }
            @{ ComputerName = '127.0.0.1' }
            @{ ComputerName = '::1' }
            @{ ComputerName = '   ' }
        ) {
            param($ComputerName)

            Test-IsLocalComputerName -ComputerName $ComputerName | Should Be $true
        }
    }

    Describe 'Assert-TargetNodePowerShellVersionIs51' {
        It 'validates every distinct target node with the supplied connection settings' {
            Mock Get-TargetWindowsPowerShellVersion { [Version]'5.1.19041.1' }
            Mock Assert-PowerShellVersionIs51 {}

            Assert-TargetNodePowerShellVersionIs51 -ComputerName @('server-01', 'server-01', 'portal-01') -UseWinRMSSL $true

            Assert-MockCalled Get-TargetWindowsPowerShellVersion -Exactly 1 -Scope It -ParameterFilter {
                $ComputerName -eq 'server-01' -and $UseWinRMSSL
            }
            Assert-MockCalled Get-TargetWindowsPowerShellVersion -Exactly 1 -Scope It -ParameterFilter {
                $ComputerName -eq 'portal-01' -and $UseWinRMSSL
            }
            Assert-MockCalled Assert-PowerShellVersionIs51 -Exactly 2 -Scope It -ParameterFilter {
                $Version.ToString() -eq '5.1.19041.1' -and $Scope -like "target machine '*'"
            }
        }

        It 'wraps remote version lookup failures with the target machine name' {
            Mock Get-TargetWindowsPowerShellVersion { throw 'registry value missing' }
            $exception = $null

            try {
                Assert-TargetNodePowerShellVersionIs51 -ComputerName 'server-01'
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be "Error: Unable to validate Windows PowerShell version on target machine 'server-01'. registry value missing"
        }
    }

    Describe 'Get-ServerEndpointDetails' {
        BeforeEach {
            Mock Get-FQDN { 'server-01.contoso.com' }
        }

        It 'uses the server FQDN and native Server port when external DNS is null' {
            $configuration = @{
                Version = '11.4'
                WebAdaptor = @{ AdminAccessEnabled = $false }
                Server = @{}
            }
            $primaryServer = [PSCustomObject]@{ NodeName = 'server-01' }

            $result = Get-ServerEndpointDetails -ConfigData $configuration -ServerRole 'Server' -PrimaryServerMachine $primaryServer -ServerExternalDNSHostName $null -WebAdaptorCheck $true

            $result.ServerServiceURL | Should Be 'server-01.contoso.com'
            $result.ServerServiceURLPort | Should Be 6443
            $result.ServerSiteAdminURL | Should Be 'server-01.contoso.com'
            $result.ServerSiteAdminURLPort | Should Be 6443
            Assert-MockCalled Get-FQDN -Exactly 1 -ParameterFilter { $MachineName -eq 'server-01' }
        }

        It 'uses the native Server port when the external DNS parameter is omitted' {
            $configuration = @{
                Version = '11.4'
                WebAdaptor = @{ AdminAccessEnabled = $false }
                Server = @{}
            }
            $primaryServer = [PSCustomObject]@{ NodeName = 'server-01' }

            $result = Get-ServerEndpointDetails -ConfigData $configuration -ServerRole 'Server' -PrimaryServerMachine $primaryServer -WebAdaptorCheck $true

            $result.ServerServiceURL | Should Be 'server-01.contoso.com'
            $result.ServerServiceURLPort | Should Be 6443
        }

        It 'prioritizes an internal load balancer for the administrative endpoint' {
            $configuration = @{
                Version = '11.4'
                ServerContext = 'server'
                WebAdaptor = @{ AdminAccessEnabled = $true }
                Server = @{ ExternalLoadBalancer = 'public.contoso.com'; InternalLoadBalancer = 'internal.contoso.com'; InternalLoadBalancerPort = 7443 }
            }
            $primaryServer = [PSCustomObject]@{ NodeName = 'server-01'; SSLCertificate = @{ CName = 'certificate.contoso.com' } }

            $result = Get-ServerEndpointDetails -ConfigData $configuration -ServerRole 'Server' -PrimaryServerMachine $primaryServer -ServerExternalDNSHostName 'external.contoso.com' -WebAdaptorCheck $true

            $result.ServerServiceURL | Should Be 'public.contoso.com'
            $result.ServerServiceURLPort | Should Be 443
            $result.ServerSiteAdminURL | Should Be 'internal.contoso.com'
            $result.ServerSiteAdminURLPort | Should Be 7443
            $result.ServerSiteAdminContext | Should Be 'arcgis'
        }

        It 'uses the Notebook Server component port for a Notebook Server role' {
            $configuration = @{
                Version = '11.5'
                WebAdaptor = @{ AdminAccessEnabled = $false }
                Server = @{}
            }
            $primaryServer = [PSCustomObject]@{ NodeName = 'server-01' }

            $result = Get-ServerEndpointDetails -ConfigData $configuration -ServerRole 'NotebookServer' -PrimaryServerMachine $primaryServer -WebAdaptorCheck $true

            $result.ServerServiceURLPort | Should Be 11443
            $result.ServerSiteAdminURLPort | Should Be 11443
        }

        It 'rejects a missing primary server node' {
            $exception = $null

            try {
                Get-ServerEndpointDetails -ConfigData @{ Server = @{} } -ServerRole 'Server' -PrimaryServerMachine ([PSCustomObject]@{}) -WebAdaptorCheck $false
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'PrimaryServerMachine is null or missing required properties.'
        }
    }

    Describe 'Test-IsValidJavaServerType' {
        It 'accepts supported Java web server types' {
            $exception = $null

            try {
                Test-IsValidJavaServerType -JavaWebServerType 'WebLogic'
            }
            catch {
                $exception = $_
            }

            $exception | Should Be $null
        }

        It 'rejects an unsupported Java web server type' {
            $exception = $null

            try {
                Test-IsValidJavaServerType -JavaWebServerType 'IIS'
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Match 'Invalid JavaWebServerType'
        }
    }

    Describe 'Test-IsValidTomcatConfig' {
        $validTomcatConfig = @{ Version = '9.0.90'; Path = 'C:\Tomcat'; InstallDir = 'C:\Tomcat'; ServiceName = 'Tomcat9'; SSLProtocol = 'TLSv1.2' }

        It 'accepts Tomcat 9 for ArcGIS Enterprise 11.4' {
            $exception = $null

            try {
                Test-IsValidTomcatConfig -TomcatConfig $validTomcatConfig -EnterpriseVersion '11.4'
            }
            catch {
                $exception = $_
            }

            $exception | Should Be $null
        }

        It 'rejects missing required Tomcat properties' {
            $exception = $null

            try {
                Test-IsValidTomcatConfig -TomcatConfig @{ Version = '10.1.0' } -EnterpriseVersion '12.0'
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be "[ERROR] Apache Tomcat configuration is missing required property 'Path'."
        }

        It 'rejects Tomcat 9 for ArcGIS Enterprise 12.0' {
            $exception = $null

            try {
                Test-IsValidTomcatConfig -TomcatConfig $validTomcatConfig -EnterpriseVersion '12.0'
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Match 'only Apache Tomcat version 10.x is supported'
        }

        It 'accepts Tomcat 10 for ArcGIS Enterprise 11.5' {
            $tomcat10Config = @{ Version = '10.1.0'; Path = 'C:\Tomcat'; InstallDir = 'C:\Tomcat'; ServiceName = 'Tomcat10'; SSLProtocol = 'TLSv1.2' }
            $exception = $null

            try {
                Test-IsValidTomcatConfig -TomcatConfig $tomcat10Config -EnterpriseVersion '11.5'
            }
            catch {
                $exception = $_
            }

            $exception | Should Be $null
        }
    }

    Describe 'Add-ForwardProxySettings' {
        It 'adds configured proxy values with unsigned integer ports' {
            $forwardProxyMap = @{
                HttpProxyHost = 'http-proxy.contoso.com'
                HttpProxyPort = 8080
                HttpsProxyHost = 'https-proxy.contoso.com'
                HttpsProxyPort = 8443
                NonProxyHosts = 'localhost;*.contoso.com'
            }
            $mapArguments = @{}

            Add-ForwardProxySettings -ForwardProxyMap $forwardProxyMap -MapArgs $mapArguments

            $mapArguments.HttpProxyHost | Should Be 'http-proxy.contoso.com'
            $mapArguments.HttpProxyPort | Should BeOfType System.UInt32
            $mapArguments.HttpProxyPort | Should Be 8080
            $mapArguments.HttpsProxyHost | Should Be 'https-proxy.contoso.com'
            $mapArguments.HttpsProxyPort | Should Be 8443
            $mapArguments.NonProxyHosts | Should Be 'localhost;*.contoso.com'
        }

        It 'rejects an HTTP proxy host without its port' {
            $exception = $null

            try {
                Add-ForwardProxySettings -ForwardProxyMap @{ HttpProxyHost = 'proxy.contoso.com' } -MapArgs @{}
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be '[ERROR] If you supply an HTTP proxy, you must provide *both* HttpProxyHost and HttpProxyPort.'
        }

        It 'converts configured HTTP and HTTPS proxy credentials to PSCredentials' {
            $forwardProxyMap = @{
                HttpProxyCredential = [PSCustomObject]@{ UserName = 'http-user'; Password = 'http-password' }
                HttpsProxyCredential = [PSCustomObject]@{ UserName = 'https-user'; Password = 'https-password' }
            }
            $mapArguments = @{}

            Add-ForwardProxySettings -ForwardProxyMap $forwardProxyMap -MapArgs $mapArguments

            $mapArguments.HttpProxyCredential.UserName | Should Be 'http-user'
            $mapArguments.HttpProxyCredential.GetNetworkCredential().Password | Should Be 'http-password'
            $mapArguments.HttpsProxyCredential.UserName | Should Be 'https-user'
            $mapArguments.HttpsProxyCredential.GetNetworkCredential().Password | Should Be 'https-password'
        }
    }
}