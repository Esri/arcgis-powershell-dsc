$moduleScriptPath = Join-Path $PSScriptRoot '..\..\Modules\ArcGIS\DSCResources\ArcGIS_Tomcat\ArcGIS_Tomcat.psm1'
Import-Module $moduleScriptPath -Force

InModuleScope ArcGIS_Tomcat {
    Describe 'ArcGIS_Tomcat keytool discovery' {
        BeforeEach {
            $script:tomcatJavaHome = Join-Path $TestDrive ('Java Home [DSC] ' + [guid]::NewGuid())
            $bin = New-Item -Path (Join-Path $script:tomcatJavaHome 'bin') -ItemType Directory -Force
            $script:tomcatKeytoolPath = Join-Path $bin.FullName 'keytool.exe'
            New-Item -Path $script:tomcatKeytoolPath -ItemType File | Out-Null
        }

        It 'resolves a literal JAVA_HOME path with spaces instead of PATH or JRE_HOME' {
            Get-KeytoolPath -JavaHome $script:tomcatJavaHome -JreHome 'C:\stale-jre' |
                Should Be $script:tomcatKeytoolPath
        }

        It 'uses JRE_HOME when JAVA_HOME is <Case>' -TestCases @(
            @{ Case = 'empty'; JavaHome = '' }
            @{ Case = 'whitespace'; JavaHome = ' ' }
        ) {
            param($Case, $JavaHome)

            Get-KeytoolPath -JavaHome $JavaHome -JreHome $script:tomcatJavaHome |
                Should Be $script:tomcatKeytoolPath
        }

        It 'reports missing machine Java settings' {
            { Get-KeytoolPath -JavaHome '' -JreHome '' } |
                Should Throw 'JAVA_HOME or JRE_HOME must be set at machine scope'
        }

        It 'rejects a <Case> keytool executable with its expected path' -TestCases @(
            @{ Case = 'missing'; Directory = $false }
            @{ Case = 'directory-only'; Directory = $true }
        ) {
            param($Case, $Directory)
            Remove-Item -LiteralPath $script:tomcatKeytoolPath -Force
            if ($Directory) {
                New-Item -Path $script:tomcatKeytoolPath -ItemType Directory | Out-Null
            }

            { Get-KeytoolPath -JavaHome $script:tomcatJavaHome -JreHome '' } |
                Should Throw "keytool.exe not found at '$script:tomcatKeytoolPath'."
        }

        It 'ignores stale process Java settings when reading machine defaults' {
            $machineJavaHome = [Environment]::GetEnvironmentVariable('JAVA_HOME', 'Machine')
            $machineJreHome = [Environment]::GetEnvironmentVariable('JRE_HOME', 'Machine')
            $originalJavaHome = $env:JAVA_HOME
            $originalJreHome = $env:JRE_HOME
            Mock Test-Path { $true }
            try {
                $env:JAVA_HOME = 'C:\stale-process-java'
                $env:JRE_HOME = 'C:\stale-process-jre'

                if (-not [string]::IsNullOrWhiteSpace($machineJavaHome)) {
                    Get-KeytoolPath | Should Be (Join-Path $machineJavaHome 'bin\keytool.exe')
                } elseif (-not [string]::IsNullOrWhiteSpace($machineJreHome)) {
                    Get-KeytoolPath | Should Be (Join-Path $machineJreHome 'bin\keytool.exe')
                } else {
                    { Get-KeytoolPath } | Should Throw 'must be set at machine scope'
                }
            } finally {
                $env:JAVA_HOME = $originalJavaHome
                $env:JRE_HOME = $originalJreHome
            }
        }
    }

    Describe 'ArcGIS_Tomcat keytool invocation' {
        BeforeEach {
            $script:tomcatInstallDirectory = Join-Path $TestDrive ('Tomcat ' + [guid]::NewGuid())
            $script:tomcatConf = Join-Path $script:tomcatInstallDirectory 'conf'
            New-Item -Path $script:tomcatConf -ItemType Directory -Force | Out-Null
            $script:tomcatKeytoolPath = 'C:\Program Files\Java\new-jdk\bin\keytool.exe'
            $script:tomcatParameters = @{
                ExternalDNSName = 'gis.example.test'
                Version = '10.1.40'
                Ensure = 'Present'
                ServiceName = 'Tomcat'
                InstallDirectory = $script:tomcatInstallDirectory
            }
            Mock Get-KeytoolPath { $script:tomcatKeytoolPath }
            Mock Test-ApacheTomcatInstall { $true }
            Mock Test-ApacheTomcatServerXML { $true }
            Mock Invoke-CliTool { 'gis.example.test' }
            Mock Restart-ArcGISService {}
        }

        It 'uses the resolved path to generate a keystore' {
            Set-TargetResource @script:tomcatParameters

            Assert-MockCalled Invoke-CliTool -Exactly 1 -Scope It -ParameterFilter {
                $ExecPath -eq $script:tomcatKeytoolPath -and
                $Arguments -like '*-genkeypair*' -and
                $WorkingDirectory -eq $script:tomcatConf -and $AddJavaEnvironmentVariables
            }
            Assert-MockCalled Restart-ArcGISService -Exactly 1 -Scope It
        }

        It 'uses the resolved path to inspect an existing keystore without restarting' {
            New-Item -Path (Join-Path $script:tomcatConf 'arcgis.keystore') -ItemType File | Out-Null

            Set-TargetResource @script:tomcatParameters

            Assert-MockCalled Invoke-CliTool -Exactly 1 -Scope It -ParameterFilter {
                $ExecPath -eq $script:tomcatKeytoolPath -and $Arguments -like '*-list*'
            }
            Assert-MockCalled Restart-ArcGISService -Exactly 0 -Scope It
        }

        It 'uses the resolved path for certificate inspection and import' {
            $certificatePath = Join-Path $script:tomcatInstallDirectory 'certificate.pfx'
            New-Item -Path $certificatePath -ItemType File | Out-Null
            $script:tomcatParameters.CertificateFileLocation = $certificatePath
            $script:tomcatParameters.CertificatePassword = [PSCredential]::new(
                'certificate', (ConvertTo-SecureString 'fixture-password' -AsPlainText -Force))
            $script:tomcatCertificate = [PSCustomObject]@{ Thumbprint = 'fixture-thumbprint' }
            $script:tomcatCertificate | Add-Member -MemberType ScriptMethod -Name Import -Value {
                param($Path, $Password, $Flags)
            }
            Mock New-Object { $script:tomcatCertificate } -ParameterFilter {
                $TypeName -eq 'System.Security.Cryptography.X509Certificates.X509Certificate2'
            }
            Mock Start-Process {
                Set-Content -LiteralPath $RedirectStandardOutput -Value 'Alias name: source-certificate'
            }

            Set-TargetResource @script:tomcatParameters

            Assert-MockCalled Start-Process -Exactly 1 -Scope It -ParameterFilter {
                $FilePath -eq $script:tomcatKeytoolPath -and $ArgumentList -like '*-list*'
            }
            Assert-MockCalled Invoke-CliTool -Exactly 1 -Scope It -ParameterFilter {
                $ExecPath -eq $script:tomcatKeytoolPath -and
                $Arguments -like '*-importkeystore*' -and $Arguments -like '*source-certificate*'
            }
        }

        It 'uses the resolved path for the DSC compliance check' {
            New-Item -Path (Join-Path $script:tomcatConf 'arcgis.keystore') -ItemType File | Out-Null

            Test-TargetResource @script:tomcatParameters | Should Be $true

            Assert-MockCalled Invoke-CliTool -Exactly 1 -Scope It -ParameterFilter {
                $ExecPath -eq $script:tomcatKeytoolPath -and $Arguments -like '*-list*' -and
                $WorkingDirectory -eq $script:tomcatConf -and $AddJavaEnvironmentVariables
            }
        }

        It 'fails before changing Tomcat when keytool cannot be resolved' {
            Mock Get-KeytoolPath { throw 'keytool.exe not found at the configured Java home.' }

            { Set-TargetResource @script:tomcatParameters } | Should Throw 'keytool.exe not found'

            Assert-MockCalled Test-ApacheTomcatInstall -Exactly 0 -Scope It
            Assert-MockCalled Invoke-CliTool -Exactly 0 -Scope It
            Assert-MockCalled Restart-ArcGISService -Exactly 0 -Scope It
        }

        It 'does not require Java for uninstall or absent compliance checks' {
            Mock Get-Service { $null }
            $script:tomcatParameters.Ensure = 'Absent'

            Test-TargetResource @script:tomcatParameters | Should Be $true
            Set-TargetResource @script:tomcatParameters

            Assert-MockCalled Get-KeytoolPath -Exactly 0 -Scope It
            Assert-MockCalled Invoke-CliTool -Exactly 0 -Scope It
        }
    }
}