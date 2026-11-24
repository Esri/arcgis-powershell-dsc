<#
    Complements the canonical helper suite with DNS fallbacks, password-source errors,
    node normalization, endpoint priority, and current service lifecycle behavior.
    DNS/CIM, secret-file reads, service commands, and delays are mocked per scenario.
    No service transition or network lookup should occur on the test machine.

    Use current Start-ServiceAndWait/Stop-ServiceAndWait helpers. This suite removes
    competing ArcGIS script modules before importing the checkout so private calls
    and mocks use the intended implementation. See ../README.md.
#>
$moduleScriptPath = (Resolve-Path (Join-Path $PSScriptRoot '..\..\Modules\ArcGIS\ArcGIS.psm1')).Path

# Pester 3 selects InModuleScope by name, not path. Keep the checkout if already
# loaded, but remove other ArcGIS script modules so private calls and mocks cannot
# bind to an installed version. Run tests in a dedicated process to isolate this cleanup.
$competingModules = @(Get-Module -Name ArcGIS -All | Where-Object {
    $_.ModuleType -eq 'Script' -and $_.Path -ne $moduleScriptPath
})
foreach ($competingModule in $competingModules) {
    Remove-Module -ModuleInfo $competingModule -Force -ErrorAction Stop
}

Import-Module $moduleScriptPath -ErrorAction Stop

InModuleScope ArcGIS {
    Describe 'Get-FQDN additional resolution behavior' {
        It 'returns an IPv6 literal without attempting DNS resolution' {
            Mock Get-Command { throw 'DNS lookup should not be reached' }

            $result = Get-FQDN -MachineName '2001:db8::8'

            $result | Should Be '2001:db8::8'
            Assert-MockCalled Get-Command -Exactly 0 -Scope It
        }

        It 'uses an ANY DNS record for <MachineName>' -TestCases @(
            @{ MachineName = 'server-01'; Expected = 'server-01.contoso.com' }
            @{ MachineName = 'portal-01'; Expected = 'portal-01.contoso.com' }
            @{ MachineName = 'datastore-01'; Expected = 'datastore-01.contoso.com' }
        ) {
            param($MachineName, $Expected)

            Mock Get-Command { [PSCustomObject]@{ Name = 'Resolve-DnsName' } }
            Mock Resolve-DnsName { [PSCustomObject]@{ Name = "$Name.contoso.com"; IPAddress = '192.0.2.20' } } -ParameterFilter { $Type -eq 'ANY' }
            Mock Resolve-DnsName { throw 'A lookup should not be reached' } -ParameterFilter { $Type -eq 'A' }

            $result = Get-FQDN -MachineName $MachineName

            $result | Should Be $Expected
            Assert-MockCalled Resolve-DnsName -Exactly 1 -Scope It -ParameterFilter { $Name -eq $MachineName -and $Type -eq 'ANY' }
            Assert-MockCalled Resolve-DnsName -Exactly 0 -Scope It -ParameterFilter { $Type -eq 'A' }
        }

        It 'falls back from an empty ANY result to an A record for <MachineName>' -TestCases @(
            @{ MachineName = 'server-02'; Expected = 'server-02.contoso.com' }
            @{ MachineName = 'portal-02'; Expected = 'portal-02.contoso.com' }
            @{ MachineName = 'datastore-02'; Expected = 'datastore-02.contoso.com' }
        ) {
            param($MachineName, $Expected)

            Mock Get-Command { [PSCustomObject]@{ Name = 'Resolve-DnsName' } }
            Mock Resolve-DnsName { $null } -ParameterFilter { $Type -eq 'ANY' }
            Mock Resolve-DnsName { [PSCustomObject]@{ Name = "$Name.contoso.com"; IPAddress = '192.0.2.21' } } -ParameterFilter { $Type -eq 'A' }

            $result = Get-FQDN -MachineName $MachineName

            $result | Should Be $Expected
            Assert-MockCalled Resolve-DnsName -Exactly 1 -Scope It -ParameterFilter { $Name -eq $MachineName -and $Type -eq 'ANY' }
            Assert-MockCalled Resolve-DnsName -Exactly 1 -Scope It -ParameterFilter { $Name -eq $MachineName -and $Type -eq 'A' }
        }

        It 'uses the adapter DNS suffix when DNS cmdlets are unavailable' {
            Mock Get-Command { $null }
            Mock Get-CimInstance { [PSCustomObject]@{ Name = 'server-03'; PartOfDomain = $false; Domain = $null } } -ParameterFilter { $ClassName -eq 'Win32_ComputerSystem' }
            Mock Get-CimInstance { [PSCustomObject]@{ DNSDomain = 'contoso.com' } } -ParameterFilter { $ClassName -eq 'Win32_NetworkAdapterConfiguration' }

            $result = Get-FQDN -MachineName 'server-03'

            $result | Should Be 'server-03.contoso.com'
            Assert-MockCalled Get-CimInstance -Exactly 1 -Scope It -ParameterFilter { $ClassName -eq 'Win32_ComputerSystem' -and $ComputerName -eq 'server-03' }
            Assert-MockCalled Get-CimInstance -Exactly 1 -Scope It -ParameterFilter { $ClassName -eq 'Win32_NetworkAdapterConfiguration' -and $ComputerName -eq 'server-03' }
        }

        It 'uses the computer domain when no enabled adapter has a DNS suffix' {
            Mock Get-Command { $null }
            Mock Get-CimInstance { [PSCustomObject]@{ Name = 'server-04'; PartOfDomain = $true; Domain = 'fabrikam.com' } } -ParameterFilter { $ClassName -eq 'Win32_ComputerSystem' }
            Mock Get-CimInstance { $null } -ParameterFilter { $ClassName -eq 'Win32_NetworkAdapterConfiguration' }

            $result = Get-FQDN -MachineName 'server-04'

            $result | Should Be 'server-04.fabrikam.com'
        }

        It 'throws after ten unsuccessful fallback attempts' {
            Mock Get-Command { $null }
            Mock Get-CimInstance { [PSCustomObject]@{ Name = ''; PartOfDomain = $false; Domain = '' } } -ParameterFilter { $ClassName -eq 'Win32_ComputerSystem' }
            Mock Get-CimInstance { $null } -ParameterFilter { $ClassName -eq 'Win32_NetworkAdapterConfiguration' }
            Mock Start-Sleep {}
            $exception = $null

            try {
                Get-FQDN -MachineName 'unresolved-host'
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Unable to resolve DNS for unresolved-host'
            Assert-MockCalled Start-Sleep -Exactly 10 -Scope It -ParameterFilter { $Seconds -eq 15 }
        }
    }

    Describe 'Get-PasswordFromObject source selection' {
        It 'converts a plaintext object password into a usable secure string' {
            $password = Get-PasswordFromObject -Object ([PSCustomObject]@{ Password = 'plain-secret' })
            $credential = New-Object System.Management.Automation.PSCredential 'user', $password

            $credential.GetNetworkCredential().Password | Should Be 'plain-secret'
        }

        It 'reads a configured encrypted password file' {
            $encrypted = ConvertTo-SecureString 'file-secret' -AsPlainText -Force | ConvertFrom-SecureString
            Mock Test-Path { $true }
            Mock Get-Content { $encrypted }

            $password = Get-PasswordFromObject -Object ([PSCustomObject]@{ PasswordFilePath = 'C:\password.txt'; Password = 'plain-secret' })
            $credential = New-Object System.Management.Automation.PSCredential 'user', $password

            $credential.GetNetworkCredential().Password | Should Be 'file-secret'
            Assert-MockCalled Get-Content -Exactly 1 -Scope It -ParameterFilter { $Path -eq 'C:\password.txt' }
        }

        It 'uses an environment variable password when no file is configured' {
            Mock Get-PasswordFromEnvironmentVariable { ConvertTo-SecureString 'environment-secret' -AsPlainText -Force }

            $password = Get-PasswordFromObject -Object ([PSCustomObject]@{ PasswordEnvironmentVariableName = 'ARCGIS_TEST_SECRET'; Password = 'plain-secret' })
            $credential = New-Object System.Management.Automation.PSCredential 'user', $password

            $credential.GetNetworkCredential().Password | Should Be 'environment-secret'
            Assert-MockCalled Get-PasswordFromEnvironmentVariable -Exactly 1 -Scope It -ParameterFilter { $EnvironmentVariableName -eq 'ARCGIS_TEST_SECRET' }
        }

        It 'uses a password file ahead of an environment variable' {
            $encrypted = ConvertTo-SecureString 'file-first' -AsPlainText -Force | ConvertFrom-SecureString
            Mock Test-Path { $true }
            Mock Get-Content { $encrypted }
            Mock Get-PasswordFromEnvironmentVariable { throw 'environment provider should not be called' }

            $password = Get-PasswordFromObject -Object ([PSCustomObject]@{ PasswordFilePath = 'C:\password.txt'; PasswordEnvironmentVariableName = 'ARCGIS_TEST_SECRET'; Password = 'plain-secret' })
            $credential = New-Object System.Management.Automation.PSCredential 'user', $password

            $credential.GetNetworkCredential().Password | Should Be 'file-first'
            Assert-MockCalled Get-PasswordFromEnvironmentVariable -Exactly 0 -Scope It
        }

        It 'throws a concrete error for a missing configured password file' {
            Mock Test-Path { $false }
            $exception = $null

            try {
                Get-PasswordFromObject -Object ([PSCustomObject]@{ PasswordFilePath = 'C:\missing.txt' })
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Password file C:\missing.txt does not exist.'
        }

        It 'propagates an environment-provider failure without falling back to plaintext' {
            Mock Get-PasswordFromEnvironmentVariable { throw 'Environment Variable ARCGIS_TEST_SECRET does not exist.' }
            $exception = $null

            try {
                Get-PasswordFromObject -Object ([PSCustomObject]@{ PasswordEnvironmentVariableName = 'ARCGIS_TEST_SECRET'; Password = 'plain-secret' })
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Environment Variable ARCGIS_TEST_SECRET does not exist.'
        }
    }

    Describe 'Get-ConfigurationTargetNodeNames normalization' {
        It 'returns <ExpectedCount> distinct names for <Name>' -TestCases @(
            @{ Name = 'an empty node collection'; Nodes = @(); ExpectedCount = 0; ExpectedFirst = $null }
            @{ Name = 'a single node'; Nodes = @(@{ NodeName = 'server-01' }); ExpectedCount = 1; ExpectedFirst = 'server-01' }
            @{ Name = 'duplicate nodes'; Nodes = @(@{ NodeName = 'server-01' }, @{ NodeName = 'server-01' }); ExpectedCount = 1; ExpectedFirst = 'server-01' }
            @{ Name = 'whitespace-only nodes'; Nodes = @(@{ NodeName = ' ' }, @{ NodeName = "`t" }); ExpectedCount = 0; ExpectedFirst = $null }
            @{ Name = 'case-distinct node names'; Nodes = @(@{ NodeName = 'SERVER-01' }, @{ NodeName = 'server-01' }); ExpectedCount = 2; ExpectedFirst = 'SERVER-01' }
            @{ Name = 'mixed valid and blank nodes'; Nodes = @(@{ NodeName = '' }, @{ NodeName = 'portal-01' }, @{ NodeName = ' ' }); ExpectedCount = 1; ExpectedFirst = 'portal-01' }
        ) {
            param($Nodes, $ExpectedCount, $ExpectedFirst)

            $names = @(Get-ConfigurationTargetNodeNames -Configuration @{ AllNodes = $Nodes })

            $names.Count | Should Be $ExpectedCount
            if($ExpectedCount -gt 0) {
                $names[0] | Should Be $ExpectedFirst
            }
        }
    }

    Describe 'Test-IsLocalComputerName additional aliases' {
        It 'recognizes <ComputerName> as local' -TestCases @(
            @{ ComputerName = 'LOCALHOST' }
            @{ ComputerName = ' localhost ' }
            @{ ComputerName = '127.0.0.1 ' }
            @{ ComputerName = ' ::1' }
            @{ ComputerName = '.' }
        ) {
            param($ComputerName)

            Test-IsLocalComputerName -ComputerName $ComputerName | Should Be $true
        }
    }

    Describe 'Assert-TargetNodePowerShellVersionIs51 orchestration' {
        It 'deduplicates targets and validates each resolved version with the requested remoting settings' {
            $credential = New-Object System.Management.Automation.PSCredential 'CONTOSO\svc-arcgis', (ConvertTo-SecureString 'secret' -AsPlainText -Force)
            Mock Get-TargetWindowsPowerShellVersion { [Version]'5.1.19041.1' }
            Mock Assert-PowerShellVersionIs51 {}

            Assert-TargetNodePowerShellVersionIs51 -ComputerName @('server-01', 'server-01', 'portal-01') -Credential $credential -UseWinRMSSL $true

            Assert-MockCalled Get-TargetWindowsPowerShellVersion -Exactly 1 -Scope It -ParameterFilter { $ComputerName -eq 'server-01' -and $Credential.UserName -eq 'CONTOSO\svc-arcgis' -and $UseWinRMSSL }
            Assert-MockCalled Get-TargetWindowsPowerShellVersion -Exactly 1 -Scope It -ParameterFilter { $ComputerName -eq 'portal-01' -and $UseWinRMSSL }
            Assert-MockCalled Assert-PowerShellVersionIs51 -Exactly 1 -Scope It -ParameterFilter { $Version -eq [Version]'5.1.19041.1' -and $Scope -eq "target machine 'server-01'" }
            Assert-MockCalled Assert-PowerShellVersionIs51 -Exactly 1 -Scope It -ParameterFilter { $Scope -eq "target machine 'portal-01'" }
        }

        It 'wraps a target version lookup failure with the target machine name' {
            Mock Get-TargetWindowsPowerShellVersion { throw 'Cim session failed' }
            $exception = $null

            try { Assert-TargetNodePowerShellVersionIs51 -ComputerName 'server-remote' }
            catch { $exception = $_ }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be "Error: Unable to validate Windows PowerShell version on target machine 'server-remote'. Cim session failed"
            Assert-MockCalled Get-TargetWindowsPowerShellVersion -Exactly 1 -Scope It -ParameterFilter { $ComputerName -eq 'server-remote' }
        }
    }

    Describe 'Get-ServerEndpointDetails priority behavior' {
        BeforeEach {
            Mock Get-FQDN { 'server-01.contoso.com' }
        }

        It 'maps <ServerRole> to its component-specific native ports' -TestCases @(
            @{ ServerRole = 'MissionServer'; Port = 20443 }
            @{ ServerRole = 'NotebookServer'; Port = 11443 }
            @{ ServerRole = 'VideoServer'; Port = 21443 }
            @{ ServerRole = 'DataPipelinesServer'; Port = 14443 }
            @{ ServerRole = 'VelocityServer'; Port = 7143 }
        ) {
            param($ServerRole, $Port)
            $result = Get-ServerEndpointDetails -ConfigData @{ Version = '11.4'; Server = @{}; WebAdaptor = @{ AdminAccessEnabled = $false } } -ServerRole $ServerRole -PrimaryServerMachine ([PSCustomObject]@{ NodeName = 'server-01' }) -WebAdaptorCheck $true

            $result.ServerServiceURL | Should Be 'server-01.contoso.com'
            $result.ServerServiceURLPort | Should Be $Port
            $result.ServerSiteAdminURLPort | Should Be $Port
        }

        It 'uses the certificate CName when no external endpoint is supplied' {
            $result = Get-ServerEndpointDetails -ConfigData @{ Version = '11.4'; Server = @{}; WebAdaptor = @{ AdminAccessEnabled = $false } } -ServerRole 'Server' -PrimaryServerMachine ([PSCustomObject]@{ NodeName = 'server-01'; SSLCertificate = @{ CName = 'certificate.contoso.com' } }) -WebAdaptorCheck $true

            $result.ServerServiceURL | Should Be 'certificate.contoso.com'
            $result.ServerSiteAdminURL | Should Be 'certificate.contoso.com'
            $result.ServerServiceURLPort | Should Be 6443
        }

        It 'uses an external DNS endpoint for service and admin access when enabled' {
            $result = Get-ServerEndpointDetails -ConfigData @{ Version = '11.4'; ServerContext = 'server'; Server = @{}; WebAdaptor = @{ AdminAccessEnabled = $true } } -ServerRole 'Server' -PrimaryServerMachine ([PSCustomObject]@{ NodeName = 'server-01' }) -ServerExternalDNSHostName 'external.contoso.com' -WebAdaptorCheck $true

            $result.ServerServiceURL | Should Be 'external.contoso.com'
            $result.ServerServiceURLPort | Should Be 443
            $result.ServerSiteAdminURL | Should Be 'external.contoso.com'
            $result.ServerSiteAdminURLPort | Should Be 443
            $result.ServerSiteAdminContext | Should Be 'server'
        }

        It 'keeps the native administrator endpoint when web adaptor access is disabled' {
            $result = Get-ServerEndpointDetails -ConfigData @{ Version = '11.4'; ServerContext = 'server'; Server = @{}; WebAdaptor = @{ AdminAccessEnabled = $false } } -ServerRole 'Server' -PrimaryServerMachine ([PSCustomObject]@{ NodeName = 'server-01'; SSLCertificate = @{ CName = 'certificate.contoso.com' } }) -ServerExternalDNSHostName 'external.contoso.com' -WebAdaptorCheck $true

            $result.ServerServiceURL | Should Be 'external.contoso.com'
            $result.ServerSiteAdminURL | Should Be 'certificate.contoso.com'
            $result.ServerSiteAdminURLPort | Should Be 6443
        }

        It 'lets an external load balancer override both public endpoints when admin access is enabled' {
            $result = Get-ServerEndpointDetails -ConfigData @{ Version = '11.4'; ServerContext = 'server'; Server = @{ ExternalLoadBalancer = 'public.contoso.com' }; WebAdaptor = @{ AdminAccessEnabled = $true } } -ServerRole 'Server' -PrimaryServerMachine ([PSCustomObject]@{ NodeName = 'server-01' }) -WebAdaptorCheck $true

            $result.ServerServiceURL | Should Be 'public.contoso.com'
            $result.ServerSiteAdminURL | Should Be 'public.contoso.com'
            $result.ServerServiceURLPort | Should Be 443
            $result.ServerSiteAdminContext | Should Be 'server'
        }

        It 'keeps the native administrator endpoint when an external load balancer is not administratively reachable' {
            $result = Get-ServerEndpointDetails -ConfigData @{ Version = '11.4'; ServerContext = 'server'; Server = @{ ExternalLoadBalancer = 'public.contoso.com' }; WebAdaptor = @{ AdminAccessEnabled = $false } } -ServerRole 'Server' -PrimaryServerMachine ([PSCustomObject]@{ NodeName = 'server-01' }) -WebAdaptorCheck $true

            $result.ServerServiceURL | Should Be 'public.contoso.com'
            $result.ServerSiteAdminURL | Should Be 'server-01.contoso.com'
            $result.ServerSiteAdminURLPort | Should Be 6443
        }

        It 'uses the default port for an internal load balancer without an explicit port' {
            $result = Get-ServerEndpointDetails -ConfigData @{ Version = '11.4'; Server = @{ InternalLoadBalancer = 'internal.contoso.com' }; WebAdaptor = @{ AdminAccessEnabled = $false } } -ServerRole 'Server' -PrimaryServerMachine ([PSCustomObject]@{ NodeName = 'server-01' }) -WebAdaptorCheck $true

            $result.ServerSiteAdminURL | Should Be 'internal.contoso.com'
            $result.ServerSiteAdminURLPort | Should Be 6443
            $result.ServerSiteAdminContext | Should Be 'arcgis'
        }

        It 'enables server administrator access for Enterprise 11.5 even when the adaptor flag is false' {
            $result = Get-ServerEndpointDetails -ConfigData @{ Version = '11.5'; ServerContext = 'server'; Server = @{}; WebAdaptor = @{ AdminAccessEnabled = $false } } -ServerRole 'Server' -PrimaryServerMachine ([PSCustomObject]@{ NodeName = 'server-01' }) -ServerExternalDNSHostName 'external.contoso.com' -WebAdaptorCheck $true

            $result.ServerSiteAdminURL | Should Be 'external.contoso.com'
            $result.ServerSiteAdminURLPort | Should Be 443
        }

        It 'rejects a null configuration data map' {
            $exception = $null

            try {
                Get-ServerEndpointDetails -ConfigData $null -ServerRole 'Server' -PrimaryServerMachine ([PSCustomObject]@{ NodeName = 'server-01' }) -WebAdaptorCheck $false
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'ConfigData is null or invalid.'
        }
    }

    Describe 'Start-ServiceAndWait lifecycle behavior' {
        It 'waits once at the configured interval before observing a running service' {
            # Initial lookup, first poll, and second poll consume these states in order.
            # The queue is script-scoped so each mock call advances the same fixture;
            # Start-Sleep only records intent, avoiding real waits or clock assertions.
            $script:serviceStatuses = New-Object 'System.Collections.Generic.Queue[string]'
            @('Stopped', 'StartPending', 'Running') | ForEach-Object { $script:serviceStatuses.Enqueue($_) }
            Mock Start-Service {}
            Mock Get-Service { [PSCustomObject]@{ Status = $script:serviceStatuses.Dequeue() } }
            Mock Start-Sleep {}

            $output = @(Start-ServiceAndWait -ServiceName 'ArcGIS Server' -PollSeconds 7 -TimeoutSeconds 30)

            $output.Count | Should Be 0
            Assert-MockCalled Start-Service -Exactly 1 -Scope It -ParameterFilter { $Name -eq 'ArcGIS Server' }
            Assert-MockCalled Get-Service -Exactly 3 -Scope It -ParameterFilter { $Name -eq 'ArcGIS Server' }
            Assert-MockCalled Start-Sleep -Exactly 1 -Scope It -ParameterFilter { $Seconds -eq 7 }
        }

        It 'does not start or poll a service that is already running' {
            Mock Get-Service { [PSCustomObject]@{ Status = 'Running' } }
            Mock Start-Service {}
            Mock Start-Sleep {}

            $output = @(Start-ServiceAndWait -ServiceName 'ArcGIS Server')

            $output.Count | Should Be 0
            Assert-MockCalled Get-Service -Exactly 1 -Scope It -ParameterFilter { $Name -eq 'ArcGIS Server' }
            Assert-MockCalled Start-Service -Exactly 0 -Scope It
            Assert-MockCalled Start-Sleep -Exactly 0 -Scope It
        }

        It 'reports a service that stops during startup without another polling delay' {
            Mock Start-Service {}
            Mock Get-Service { [PSCustomObject]@{ Status = 'Stopped' } }
            Mock Start-Sleep {}

            { Start-ServiceAndWait -ServiceName 'ArcGIS Server' } | Should Throw "Service 'ArcGIS Server' stopped while waiting for it to start."

            Assert-MockCalled Start-Service -Exactly 1 -Scope It -ParameterFilter { $Name -eq 'ArcGIS Server' }
            Assert-MockCalled Get-Service -Exactly 2 -Scope It -ParameterFilter { $Name -eq 'ArcGIS Server' }
            Assert-MockCalled Start-Sleep -Exactly 0 -Scope It
        }

        It 'wraps a start request failure without entering the polling loop' {
            Mock Get-Service { [PSCustomObject]@{ Status = 'Stopped' } }
            Mock Start-Service { throw 'access denied' }
            Mock Start-Sleep {}

            { Start-ServiceAndWait -ServiceName 'ArcGIS Server' } | Should Throw "Failed to start service 'ArcGIS Server': access denied"

            Assert-MockCalled Start-Service -Exactly 1 -Scope It -ParameterFilter { $Name -eq 'ArcGIS Server' }
            Assert-MockCalled Get-Service -Exactly 1 -Scope It
            Assert-MockCalled Start-Sleep -Exactly 0 -Scope It
        }
    }

    Describe 'Stop-ServiceAndWait lifecycle behavior' {
        It 'does not send a stop request for a service that is already stopped' {
            Mock Stop-Service {}
            Mock Get-Service { [PSCustomObject]@{ Status = 'Stopped' } }
            Mock Start-Sleep {}

            $output = @(Stop-ServiceAndWait -ServiceName 'Portal for ArcGIS')

            $output.Count | Should Be 0
            Assert-MockCalled Get-Service -Exactly 1 -Scope It -ParameterFilter { $Name -eq 'Portal for ArcGIS' }
            Assert-MockCalled Stop-Service -Exactly 0 -Scope It
            Assert-MockCalled Start-Sleep -Exactly 0 -Scope It
        }

        It 'stops a running service once and waits through StopPending' {
            $script:serviceStatuses = New-Object 'System.Collections.Generic.Queue[string]'
            @('Running', 'Running', 'StopPending', 'Stopped') | ForEach-Object { $script:serviceStatuses.Enqueue($_) }
            Mock Get-Service { [PSCustomObject]@{ Status = $script:serviceStatuses.Dequeue() } }
            Mock Stop-Service {}
            Mock Start-Sleep {}

            $output = @(Stop-ServiceAndWait -ServiceName 'Portal for ArcGIS' -PollSeconds 7 -TimeoutSeconds 30)

            $output.Count | Should Be 0
            Assert-MockCalled Get-Service -Exactly 4 -Scope It -ParameterFilter { $Name -eq 'Portal for ArcGIS' }
            Assert-MockCalled Stop-Service -Exactly 1 -Scope It -ParameterFilter { $Name -eq 'Portal for ArcGIS' -and $Force }
            Assert-MockCalled Start-Sleep -Exactly 2 -Scope It -ParameterFilter { $Seconds -eq 7 }
        }
    }

    Describe 'Restart-ArcGISService additional lifecycle behavior' {
        It 'uses an explicit service name without resolving a component name' {
            # Record stop, the fixed recovery delay, and start in one sequence. Counts
            # alone would permit a regression that starts before stopping. Mock the
            # lifecycle helpers themselves so no actual SCM operation is possible.
            $script:restartTransitions = @()
            Mock Get-ArcGISServiceName { throw 'component mapping should not be called' }
            Mock Stop-ServiceAndWait { $script:restartTransitions += 'stop' }
            Mock Start-ServiceAndWait { $script:restartTransitions += 'start' }
            Mock Start-Sleep { $script:restartTransitions += 'delay' }

            Restart-ArcGISService -ServiceName 'Portal for ArcGIS' -TimeoutSeconds 42

            ($script:restartTransitions -join ',') | Should Be 'stop,delay,start'
            Assert-MockCalled Get-ArcGISServiceName -Exactly 0 -Scope It
            Assert-MockCalled Stop-ServiceAndWait -Exactly 1 -Scope It -ParameterFilter { $ServiceName -eq 'Portal for ArcGIS' -and $TimeoutSeconds -eq 42 }
            Assert-MockCalled Start-ServiceAndWait -Exactly 1 -Scope It -ParameterFilter { $ServiceName -eq 'Portal for ArcGIS' -and $TimeoutSeconds -eq 42 }
            Assert-MockCalled Start-Sleep -Exactly 1 -Scope It -ParameterFilter { $Seconds -eq 5 }
        }

        It 'propagates a start failure after completing the stop transition' {
            Mock Get-ArcGISServiceName { 'ArcGIS Data Store' }
            Mock Stop-ServiceAndWait {}
            Mock Start-ServiceAndWait { throw 'start failed' }
            Mock Start-Sleep {}

            { Restart-ArcGISService -ComponentName 'DataStore' } | Should Throw 'start failed'

            Assert-MockCalled Get-ArcGISServiceName -Exactly 1 -Scope It -ParameterFilter { $ComponentName -eq 'DataStore' }
            Assert-MockCalled Stop-ServiceAndWait -Exactly 1 -Scope It -ParameterFilter { $ServiceName -eq 'ArcGIS Data Store' }
            Assert-MockCalled Start-ServiceAndWait -Exactly 1 -Scope It -ParameterFilter { $ServiceName -eq 'ArcGIS Data Store' }
            Assert-MockCalled Start-Sleep -Exactly 1 -Scope It -ParameterFilter { $Seconds -eq 5 }
        }

        It 'does not start or delay after the stop transition fails' {
            # Restart propagates lifecycle failures. Starting after a failed stop
            # would hide the original failure and attempt an unsafe second transition.
            Mock Stop-ServiceAndWait { throw 'stop failed' }
            Mock Start-ServiceAndWait {}
            Mock Start-Sleep {}

            { Restart-ArcGISService -ServiceName 'ArcGIS Server' } | Should Throw 'stop failed'

            Assert-MockCalled Stop-ServiceAndWait -Exactly 1 -Scope It -ParameterFilter { $ServiceName -eq 'ArcGIS Server' }
            Assert-MockCalled Start-ServiceAndWait -Exactly 0 -Scope It
            Assert-MockCalled Start-Sleep -Exactly 0 -Scope It
        }
    }
}