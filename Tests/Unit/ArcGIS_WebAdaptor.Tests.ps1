$moduleScriptPath = Join-Path $PSScriptRoot '..\..\Modules\ArcGIS\DSCResources\ArcGIS_WebAdaptor\ArcGIS_WebAdaptor.psm1'
Import-Module $moduleScriptPath -Force

InModuleScope ArcGIS_WebAdaptor {
    Describe 'ArcGIS_WebAdaptor configuration idempotency' {
        BeforeEach {
            $script:waInstallLocation = Join-Path $TestDrive ('WebAdaptor12.2 ' + [guid]::NewGuid() + '\java')
            $script:waConfigFolder = Join-Path $script:waInstallLocation 'portal'
            New-Item -Path $script:waConfigFolder -ItemType Directory -Force | Out-Null
            $script:waConfigPath = Join-Path $script:waConfigFolder 'webadaptor.config'
            $script:waConfigXml = '<Config><WebServer><Portal><URL>https://component.example.test:7443</URL></Portal><GISServer><SiteURL>https://component.example.test:6443</SiteURL></GISServer></WebServer></Config>'
            Set-Content -LiteralPath $script:waConfigPath -Value $script:waConfigXml
            $script:waProduct = [PSCustomObject]@{
                InstallLocation = $script:waInstallLocation
                Version = '12.2.328'
            }
            $script:waTestParameters = @{
                Version = '12.2'
                Ensure = 'Present'
                Component = 'Portal'
                HostName = 'wa.example.test'
                ComponentHostName = 'component.example.test'
                Context = 'portal'
                IsJavaWebAdaptor = $true
            }
            Mock Get-JavaWebAdaptorHome { 'C:\fixture-webadaptor-home' }
            Mock Get-ArcGISProductDetails { $script:waProduct }
            Mock Test-URL { $true }
        }

        It 'recognizes an already configured Java Web Adaptor for <Case> on repeated checks' -TestCases @(
            @{ Case = 'Portal'; Component = 'Portal'; TrailingSlash = $false; Endpoint = 'portaladmin' }
            @{ Case = 'Server'; Component = 'Server'; TrailingSlash = $false; Endpoint = 'admin' }
            @{ Case = 'Portal with trailing separator'; Component = 'Portal'; TrailingSlash = $true; Endpoint = 'portaladmin' }
            @{ Case = 'Server with trailing separator'; Component = 'Server'; TrailingSlash = $true; Endpoint = 'admin' }
        ) {
            param($Case, $Component, $TrailingSlash, $Endpoint)
            $script:waTestParameters.Component = $Component
            if ($TrailingSlash) {
                $script:waProduct.InstallLocation += '\'
            }
            $script:waExpectedUrl = "https://wa.example.test/portal/$Endpoint"

            Test-TargetResource @script:waTestParameters | Should Be $true
            Test-TargetResource @script:waTestParameters | Should Be $true

            Assert-MockCalled Get-JavaWebAdaptorHome -Exactly 2 -Scope It
            Assert-MockCalled Test-URL -Exactly 2 -Scope It -ParameterFilter {
                $Url -eq $script:waExpectedUrl
            }
        }

        It 'requires configuration when the Java config file is missing' {
            Remove-Item -LiteralPath $script:waConfigPath

            Test-TargetResource @script:waTestParameters | Should Be $false

            Assert-MockCalled Test-URL -Exactly 0 -Scope It
        }

        It 'does not use a config file in the parent of the Java installation' {
            $parentContext = Join-Path (Split-Path $script:waInstallLocation -Parent) 'portal'
            New-Item -Path $parentContext -ItemType Directory | Out-Null
            Move-Item -LiteralPath $script:waConfigPath -Destination $parentContext

            Test-TargetResource @script:waTestParameters | Should Be $false

            Assert-MockCalled Test-URL -Exactly 0 -Scope It
        }

        It 'requires configuration when the Java config points to another component host' {
            Set-Content -LiteralPath $script:waConfigPath -Value (
                $script:waConfigXml.Replace('component.example.test', 'other.example.test'))

            Test-TargetResource @script:waTestParameters | Should Be $false

            Assert-MockCalled Test-URL -Exactly 0 -Scope It
        }

        It 'honors overwrite for an already configured Java Web Adaptor' {
            $script:waTestParameters.OverwriteFlag = $true

            Test-TargetResource @script:waTestParameters | Should Be $false

            Assert-MockCalled Test-URL -Exactly 0 -Scope It
        }

        It 'requires configuration when the Java build does not match' {
            $script:waProduct.Version = '12.1.100'

            Test-TargetResource @script:waTestParameters | Should Be $false

            Assert-MockCalled Test-URL -Exactly 0 -Scope It
        }

        It 'requires configuration when the configured Java endpoint is unavailable' {
            Mock Test-URL { $false }

            Test-TargetResource @script:waTestParameters | Should Be $false

            Assert-MockCalled Test-URL -Exactly 1 -Scope It -ParameterFilter {
                $Url -eq 'https://wa.example.test/portal/portaladmin'
            }
        }

        It 'preserves the missing machine Web Adaptor home error' {
            Mock Get-JavaWebAdaptorHome { $null }

            { Test-TargetResource @script:waTestParameters } |
                Should Throw 'AGSWEBADAPTORHOME environment variable is not set.'

            Assert-MockCalled Get-ArcGISProductDetails -Exactly 0 -Scope It
        }

        It 'keeps the IIS config path and compliance check unchanged' {
            $script:waTestParameters.IsJavaWebAdaptor = $false
            $script:waProduct.InstallLocation = $script:waConfigFolder + '\'
            Set-Content -LiteralPath $script:waConfigPath -Value (
                '{"portal":{"url":"https://component.example.test:7443"}}')

            Test-TargetResource @script:waTestParameters | Should Be $true

            Assert-MockCalled Get-JavaWebAdaptorHome -Exactly 0 -Scope It
            Assert-MockCalled Test-URL -Exactly 1 -Scope It -ParameterFilter {
                $Url -eq 'https://wa.example.test/portal/portaladmin'
            }
        }
    }

    Describe 'ArcGIS_WebAdaptor Java environment' {
        It 'reads the Web Adaptor home from machine scope' {
            Get-JavaWebAdaptorHome |
                Should Be ([Environment]::GetEnvironmentVariable('AGSWEBADAPTORHOME', 'Machine'))
        }

        BeforeEach {
            $script:javaHome = Join-Path $TestDrive ('Java Home [DSC] ' + [guid]::NewGuid())
            New-Item -Path (Join-Path $script:javaHome 'bin') -ItemType Directory -Force | Out-Null
            $script:javaPath = Join-Path $script:javaHome 'bin\java.exe'
            New-Item -Path $script:javaPath -ItemType File | Out-Null
            $script:environmentParameters = @{
                MachinePath = 'C:\Windows\System32;C:\machine-tools'
                JavaHome = $script:javaHome
                JreHome = 'C:\other-jre'
                WebAdaptorHome = 'C:\Program Files\ArcGIS\Web Adaptor'
            }
        }

        It 'prefers JAVA_HOME and prepends its bin to machine PATH' {
            $environment = Get-JavaWebAdaptorEnvironment @script:environmentParameters

            $environment.Count | Should Be 4
            $environment.PATH | Should Be "$script:javaHome\bin;C:\Windows\System32;C:\machine-tools"
            $environment.JAVA_HOME | Should Be $script:javaHome
            $environment.JRE_HOME | Should Be 'C:\other-jre'
            $environment.AGSWEBADAPTORHOME | Should Be 'C:\Program Files\ArcGIS\Web Adaptor'
        }

        It 'uses JRE_HOME when JAVA_HOME is <Case>' -TestCases @(
            @{ Case = 'unset'; JavaHome = $null }
            @{ Case = 'empty'; JavaHome = '' }
            @{ Case = 'whitespace'; JavaHome = ' ' }
        ) {
            param($Case, $JavaHome)
            $script:environmentParameters.JavaHome = $JavaHome
            $script:environmentParameters.JreHome = $script:javaHome

            $environment = Get-JavaWebAdaptorEnvironment @script:environmentParameters

            $environment.PATH | Should Be "$script:javaHome\bin;C:\Windows\System32;C:\machine-tools"
            $environment.JAVA_HOME | Should Be ([string]$JavaHome)
            $environment.JRE_HOME | Should Be $script:javaHome
        }

        It 'reports missing machine Java homes rather than using PATH' {
            $script:environmentParameters.JavaHome = ''
            $script:environmentParameters.JreHome = ' '

            { Get-JavaWebAdaptorEnvironment @script:environmentParameters } |
                Should Throw 'JAVA_HOME or JRE_HOME must be set at machine scope'
        }

        It 'rejects a <Case> selected java executable without falling back to JRE_HOME' -TestCases @(
            @{ Case = 'missing'; Directory = $false }
            @{ Case = 'directory-only'; Directory = $true }
        ) {
            param($Case, $Directory)
            $script:environmentParameters.JreHome = $script:javaHome
            $invalidHome = Join-Path $TestDrive ('Invalid Java [DSC] ' + [guid]::NewGuid())
            New-Item -Path (Join-Path $invalidHome 'bin') -ItemType Directory -Force | Out-Null
            $invalidJavaPath = Join-Path $invalidHome 'bin\java.exe'
            if ($Directory) {
                New-Item -Path $invalidJavaPath -ItemType Directory | Out-Null
            }
            $script:environmentParameters.JavaHome = $invalidHome

            { Get-JavaWebAdaptorEnvironment @script:environmentParameters } |
                Should Throw "java.exe not found at '$invalidJavaPath'."
        }

        It 'handles a <Case> machine PATH without an empty search entry' -TestCases @(
            @{ Case = 'unset'; MachinePath = $null }
            @{ Case = 'empty'; MachinePath = '' }
            @{ Case = 'whitespace'; MachinePath = ' ' }
        ) {
            param($Case, $MachinePath)
            $script:environmentParameters.MachinePath = $MachinePath

            $environment = Get-JavaWebAdaptorEnvironment @script:environmentParameters

            $environment.PATH | Should Be "$script:javaHome\bin"
        }

        It 'exposes the refreshed environment and selected Java to a real child process' {
            $script:environmentParameters.MachinePath = [Environment]::SystemDirectory
            $environment = Get-JavaWebAdaptorEnvironment @script:environmentParameters

            $output = Invoke-StartProcess -ExecPath $env:ComSpec -EnvVariables $environment -Arguments (
                '/d /c "echo %JAVA_HOME%&echo %JRE_HOME%&echo %AGSWEBADAPTORHOME%&echo %PATH%&where.exe java.exe"')
            $lines = $output.Trim() -split '\r?\n'

            $lines[0] | Should Be $script:javaHome
            $lines[1] | Should Be 'C:\other-jre'
            $lines[2] | Should Be 'C:\Program Files\ArcGIS\Web Adaptor'
            $lines[3] | Should Be "$script:javaHome\bin;$([Environment]::SystemDirectory)"
            $lines[4] | Should Be $script:javaPath
        }

        It 'reads fresh machine defaults without changing the DSC process environment' {
            $machine = @{}
            $process = @{}
            $names = @('PATH', 'JAVA_HOME', 'JRE_HOME', 'AGSWEBADAPTORHOME')
            foreach ($name in $names) {
                $machine[$name] = [Environment]::GetEnvironmentVariable($name, 'Machine')
                $process[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
            }
            Mock Test-Path { $true }
            try {
                foreach ($name in $names) {
                    [Environment]::SetEnvironmentVariable($name, "C:\stale-process-$name", 'Process')
                }

                $selectedHome = if (-not [string]::IsNullOrWhiteSpace($machine.JAVA_HOME)) {
                    $machine.JAVA_HOME
                } else {
                    $machine.JRE_HOME
                }
                if ([string]::IsNullOrWhiteSpace($selectedHome)) {
                    { Get-JavaWebAdaptorEnvironment } | Should Throw 'must be set at machine scope'
                } else {
                    $environment = Get-JavaWebAdaptorEnvironment

                    $expectedPath = Join-Path $selectedHome 'bin'
                    if (-not [string]::IsNullOrWhiteSpace($machine.PATH)) {
                        $expectedPath += ";$($machine.PATH)"
                    }
                    $environment.PATH | Should Be $expectedPath
                    $environment.JAVA_HOME | Should Be ([string]$machine.JAVA_HOME)
                    $environment.JRE_HOME | Should Be ([string]$machine.JRE_HOME)
                    $environment.AGSWEBADAPTORHOME | Should Be ([string]$machine.AGSWEBADAPTORHOME)
                }
                foreach ($name in $names) {
                    [Environment]::GetEnvironmentVariable($name, 'Process') |
                        Should Be "C:\stale-process-$name"
                }
            } finally {
                foreach ($name in $names) {
                    [Environment]::SetEnvironmentVariable($name, $process[$name], 'Process')
                }
            }
        }
    }

    Describe 'ArcGIS_WebAdaptor configuration environment forwarding' {
        BeforeEach {
            $script:configureParameters = @{
                ExecPath = 'C:\Program Files\ArcGIS\Web Adaptor\tools\ConfigureWebAdaptor.bat'
                Component = 'Server'
                HostName = 'wa.example.test'
                ComponentHostName = 'component.example.test'
                Context = 'server'
                SiteAdministrator = [PSCredential]::new(
                    'admin', (ConvertTo-SecureString 'fixture-password' -AsPlainText -Force))
                AdminAccessEnabled = $true
                Version = '11.5'
                IsJavaWebAdaptor = $true
            }
            $script:childEnvironment = @{
                PATH = 'C:\fresh-java\bin;C:\Windows\System32'
                JAVA_HOME = 'C:\fresh-java'
                JRE_HOME = $null
                AGSWEBADAPTORHOME = 'C:\fresh-webadaptor'
            }
            Mock Get-JavaWebAdaptorEnvironment { $script:childEnvironment.Clone() }
            Mock Test-ArcGISComponentHealth {}
            Mock Invoke-StartProcess { 'Configuration successful.' }
        }

        It 'passes all four fresh variables to the Java configuration child for <Case>' -TestCases @(
            @{ Case = 'Server'; Component = 'Server'; Port = 6443; Suffix = ' -a true' }
            @{ Case = 'Portal'; Component = 'Portal'; Port = 7443; Suffix = ' -r false' }
        ) {
            param($Case, $Component, $Port, $Suffix)
            $script:configureParameters.Component = $Component
            $script:expectedArguments = "-m $($Component.ToLower()) -w https://wa.example.test/server/webadaptor -g https://component.example.test:$Port -u admin -p `"fixture-password`"$Suffix"

            Start-ConfigureWebAdaptorCMDLineTool @script:configureParameters

            Assert-MockCalled Get-JavaWebAdaptorEnvironment -Exactly 1 -Scope It
            Assert-MockCalled Invoke-StartProcess -Exactly 1 -Scope It -ParameterFilter {
                $ExecPath -eq $script:configureParameters.ExecPath -and
                $Arguments -eq $script:expectedArguments -and
                $EnvVariables.Count -eq 4 -and
                $EnvVariables.PATH -eq 'C:\fresh-java\bin;C:\Windows\System32' -and
                $EnvVariables.JAVA_HOME -eq 'C:\fresh-java' -and
                $EnvVariables.ContainsKey('JRE_HOME') -and $null -eq $EnvVariables.JRE_HOME -and
                $EnvVariables.AGSWEBADAPTORHOME -eq 'C:\fresh-webadaptor'
            }
        }

        It 'leaves IIS configuration arguments and environment unchanged' {
            $script:configureParameters.IsJavaWebAdaptor = $false
            $script:configureParameters.ExecPath = 'C:\IIS\ConfigureWebAdaptor.exe'

            Start-ConfigureWebAdaptorCMDLineTool @script:configureParameters

            Assert-MockCalled Get-JavaWebAdaptorEnvironment -Exactly 0 -Scope It
            Assert-MockCalled Invoke-StartProcess -Exactly 1 -Scope It -ParameterFilter {
                $ExecPath -eq 'C:\IIS\ConfigureWebAdaptor.exe' -and $null -eq $EnvVariables -and
                $Arguments -eq '/m server /w https://wa.example.test/server/webadaptor /g https://component.example.test:6443 /u admin /p "fixture-password" /a true'
            }
        }

        It 'refreshes the Java environment on each configuration attempt' {
            $script:environmentHistory = @()
            Mock Invoke-StartProcess {
                $script:environmentHistory += $EnvVariables.PATH
                'Configuration successful.'
            }

            Start-ConfigureWebAdaptorCMDLineTool @script:configureParameters
            $script:childEnvironment.PATH = 'C:\newer-java\bin;C:\Windows\System32'
            Start-ConfigureWebAdaptorCMDLineTool @script:configureParameters

            Assert-MockCalled Get-JavaWebAdaptorEnvironment -Exactly 2 -Scope It
            $script:environmentHistory.Count | Should Be 2
            $script:environmentHistory[0] | Should Be 'C:\fresh-java\bin;C:\Windows\System32'
            $script:environmentHistory[1] | Should Be 'C:\newer-java\bin;C:\Windows\System32'
        }

        It 'does not launch configuration when Java validation fails' {
            Mock Get-JavaWebAdaptorEnvironment { throw "java.exe not found at 'C:\invalid-java\bin\java.exe'." }

            { Start-ConfigureWebAdaptorCMDLineTool @script:configureParameters } |
                Should Throw "java.exe not found at 'C:\invalid-java\bin\java.exe'."

            Assert-MockCalled Invoke-StartProcess -Exactly 0 -Scope It
        }

        It 'preserves configuration process failures for <Case>' -TestCases @(
            @{ Case = 'Java'; IsJava = $true }
            @{ Case = 'IIS'; IsJava = $false }
        ) {
            param($Case, $IsJava)
            $script:configureParameters.IsJavaWebAdaptor = $IsJava
            Mock Invoke-StartProcess { throw 'fixture configuration failure' }

            { Start-ConfigureWebAdaptorCMDLineTool @script:configureParameters } |
                Should Throw 'fixture configuration failure'
        }
    }
}
