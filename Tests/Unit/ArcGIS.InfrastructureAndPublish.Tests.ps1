<#
    Covers service lifecycle contracts, Notebook SMB mapping, DSC log forwarding,
    Azure-image dispatch, and web/GIS publishing arguments. Service, SMB, file-write,
    and deployment commands are mocked; no ArcGIS installation is required.

    Trace-DSCJob is the exception to a purely in-memory fixture: it creates a short
    local PowerShell job to produce real verbose/error records, then removes it.
    Windows PowerShell 5.1/Pester 3.4.0 commands are documented in ../README.md.
#>
$moduleScriptPath = Join-Path $PSScriptRoot '..\..\Modules\ArcGIS\ArcGIS.psm1'

Import-Module $moduleScriptPath

InModuleScope ArcGIS {
    # Trace-DSCJob requires Job2 rather than the ordinary job returned by Start-Job.
    # Wrap real child-job streams in this minimal adapter; lifecycle methods are inert
    # because the test completes the job before tracing. CLR types cannot be unloaded,
    # so the guard permits rerunning this suite in the same PowerShell process.
    if (-not ('ArcGIS.Testing.CompletedJob2' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Collections.Generic;
using System.Management.Automation;

namespace ArcGIS.Testing
{
    public sealed class CompletedJob2 : Job2
    {
        public CompletedJob2(IList<Job> childJobs) : base("trace-job", "trace-job", childJobs) { }
        public override string StatusMessage { get { return string.Empty; } }
        public override bool HasMoreData { get { return false; } }
        public override string Location { get { return "localhost"; } }
        public override void StartJob() { }
        public override void StartJobAsync() { }
        public override void StopJob() { }
        public override void StopJobAsync() { }
        public override void SuspendJob() { }
        public override void SuspendJobAsync() { }
        public override void ResumeJob() { }
        public override void ResumeJobAsync() { }
        public override void UnblockJob() { }
        public override void UnblockJobAsync() { }
        public override void StopJob(bool force, string reason) { }
        public override void StopJobAsync(bool force, string reason) { }
        public override void SuspendJob(bool force, string reason) { }
        public override void SuspendJobAsync(bool force, string reason) { }
    }
}
'@
    }

    Describe 'Service lifecycle helpers' {
        It 'starts a service and returns as soon as it is running' {
            # The first Get-Service is an initial check; the next is a poll after
            # Start-Service. A queue makes transitions explicit without real timing.
            $script:serviceStatuses = New-Object 'System.Collections.Generic.Queue[string]'
            @('Stopped', 'Running') | ForEach-Object { $script:serviceStatuses.Enqueue($_) }
            Mock Start-Service {}
            Mock Get-Service { [PSCustomObject]@{ Status = $script:serviceStatuses.Dequeue() } }
            Mock Start-Sleep {}

            Start-ServiceAndWait -ServiceName 'ArcGIS Server'

            Assert-MockCalled Start-Service -Exactly 1 -Scope It -ParameterFilter { $Name -eq 'ArcGIS Server' }
            Assert-MockCalled Get-Service -Exactly 2 -Scope It -ParameterFilter { $Name -eq 'ArcGIS Server' }
            Assert-MockCalled Start-Sleep -Exactly 0 -Scope It
        }

        It 'sends a forced stop request for a <InitialState> service' -TestCases @(
            @{ InitialState = 'Paused' }
            @{ InitialState = 'StartPending' }
        ) {
            param($InitialState)
            $script:serviceStatuses = New-Object 'System.Collections.Generic.Queue[string]'
            @($InitialState, $InitialState, 'Stopped') | ForEach-Object { $script:serviceStatuses.Enqueue($_) }
            Mock Stop-Service {}
            Mock Get-Service { [PSCustomObject]@{ Status = $script:serviceStatuses.Dequeue() } }
            Mock Start-Sleep {}

            Stop-ServiceAndWait -ServiceName 'ArcGIS Server' -PollSeconds 4 -TimeoutSeconds 30

            Assert-MockCalled Stop-Service -Exactly 1 -Scope It -ParameterFilter { $Name -eq 'ArcGIS Server' -and $Force }
            Assert-MockCalled Get-Service -Exactly 3 -Scope It -ParameterFilter { $Name -eq 'ArcGIS Server' }
            Assert-MockCalled Start-Sleep -Exactly 1 -Scope It -ParameterFilter { $Seconds -eq 4 }
        }

        It 'propagates a missing-service lookup failure without attempting startup' {
            Mock Get-Service { throw 'service not found' }
            Mock Start-Service {}
            Mock Start-Sleep {}

            { Start-ServiceAndWait -ServiceName 'ArcGIS Server' } | Should Throw 'service not found'

            Assert-MockCalled Get-Service -Exactly 1 -Scope It -ParameterFilter { $Name -eq 'ArcGIS Server' }
            Assert-MockCalled Start-Service -Exactly 0 -Scope It
            Assert-MockCalled Start-Sleep -Exactly 0 -Scope It
        }
    }

    Describe 'Restart-ArcGISService' {
        It 'honors the restart delay before stopping and starting the resolved component service' {
            # Separate call counts cannot prove sequence. Record all transitions,
            # including the requested delay and the fixed post-stop delay, in one list.
            $script:restartTransitions = @()
            Mock Get-ArcGISServiceName { 'ArcGIS Server' }
            Mock Stop-ServiceAndWait { $script:restartTransitions += 'stop' }
            Mock Start-ServiceAndWait { $script:restartTransitions += 'start' }
            Mock Start-Sleep { $script:restartTransitions += "delay-$Seconds" }

            Restart-ArcGISService -ComponentName 'Server' -RestartDelay 3 -TimeoutSeconds 42

            ($script:restartTransitions -join ',') | Should Be 'delay-3,stop,delay-5,start'
            Assert-MockCalled Get-ArcGISServiceName -Exactly 1 -Scope It -ParameterFilter { $ComponentName -eq 'Server' }
            Assert-MockCalled Stop-ServiceAndWait -Exactly 1 -Scope It -ParameterFilter { $ServiceName -eq 'ArcGIS Server' -and $TimeoutSeconds -eq 42 }
            Assert-MockCalled Start-ServiceAndWait -Exactly 1 -Scope It -ParameterFilter { $ServiceName -eq 'ArcGIS Server' -and $TimeoutSeconds -eq 42 }
            Assert-MockCalled Start-Sleep -Exactly 1 -Scope It -ParameterFilter { $Seconds -eq 3 }
            Assert-MockCalled Start-Sleep -Exactly 1 -Scope It -ParameterFilter { $Seconds -eq 5 }
        }
    }

    Describe 'New-NotebookWorkspaceSMBGlobalMapping' {
        It 'replaces the mapping and restarts Notebook Server' {
            Mock Remove-SmbGlobalMapping {}
            Mock Get-Content { ConvertTo-SecureString 'workspace-password' -AsPlainText -Force | ConvertFrom-SecureString }
            Mock New-SmbGlobalMapping {}
            Mock Restart-ArcGISService {}

            New-NotebookWorkspaceSMBGlobalMapping -RemotePath '\\fileserver\workspace' -DriveLetter 'W' -Username 'CONTOSO\workspace' -WorkspaceUserFilePath 'C:\workspace-password.txt'

            Assert-MockCalled Remove-SmbGlobalMapping -Exactly 1 -ParameterFilter { $LocalPath -eq 'W:' -and $Force }
            Assert-MockCalled New-SmbGlobalMapping -Exactly 1 -ParameterFilter {
                $RemotePath -eq '\\fileserver\workspace' -and $LocalPath -eq 'W:' -and $Credential.UserName -eq 'CONTOSO\workspace'
            }
            Assert-MockCalled Restart-ArcGISService -Exactly 1 -ParameterFilter { $ComponentName -eq 'NotebookServer' }
        }
    }

    Describe 'Trace-DSCJob' {
        It 'writes new verbose and error records for a completed child job without touching the filesystem' {
            # Real streams exercise record forwarding, but Add-Content and directory
            # operations below are mocked so the C:\test-logs path is never created.
            $job = Start-Job -ScriptBlock {
                Write-Verbose 'Start  Resource ArcGIS_Test' -Verbose
                Write-Error 'configuration failed'
            }
            Wait-Job -Job $job | Out-Null
            $childJobs = New-Object 'System.Collections.Generic.List[System.Management.Automation.Job]'
            [void]$childJobs.Add($job.ChildJobs[0])
            $traceJob = [ArcGIS.Testing.CompletedJob2]::new($childJobs)

            Mock Get-Item { [PSCustomObject]@{ FullName = 'C:\test-logs' } }
            Mock Test-Path { $true }
            Mock New-Item {}
            Mock Add-Content {}
            Mock Write-Host {}
            Mock Write-Error {}
            Mock Write-Information {}

            Trace-DSCJob -Job $traceJob -JobName 'ArcGISConfiguration' -DebugMode $true

            Assert-MockCalled Add-Content -Exactly 2 -Scope It -ParameterFilter { $Path -like 'C:\test-logs\*' }
            Assert-MockCalled Write-Host -Exactly 1 -Scope It -ParameterFilter { $ForegroundColor -eq 'green' }
            Assert-MockCalled Write-Error -Exactly 1 -Scope It -ParameterFilter { $Message -like '*configuration failed*' }
            Assert-MockCalled New-Item -Exactly 0 -Scope It
            Remove-Job -Job $job -Force
        }
    }

    Describe 'Invoke-BuildArcGISAzureImage' {
        It 'skips downloading and dispatches the setup DSC configuration' {
            Mock Test-Path { $true }
            Mock Get-Content { '{"Installers":[{"Name":"Server"}],"WindowsFeatures":["Web-Server"]}' }
            Mock Invoke-DSCJob { $true }

            Invoke-BuildArcGISAzureImage -InstallConfigFilePath 'C:\installers.json' -BaseDirectory 'C:\ArcGIS' -SkipFilesDownload $true -UseSSL -DebugSwitch

            Assert-MockCalled Invoke-DSCJob -Exactly 0 -ParameterFilter { $ConfigurationName -eq 'ArcGISDownloadInstallers' }
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -ParameterFilter {
                $ConfigurationName -eq 'ArcGISSetupConfiguration' -and
                $ConfigurationFolderPath -eq 'Configurations-AzureImageBuild' -and
                $UseWinRMSSL -and $DebugMode -and
                $Arguments.WindowsFeatures[0] -eq 'Web-Server'
            }
        }

        It 'fails when downloading installers fails' {
            Mock Test-Path { $true }
            Mock Get-Content { '{"Installers":[],"WindowsFeatures":[]}' }
            Mock Invoke-DSCJob { $false }
            $exception = $null

            try {
                Invoke-BuildArcGISAzureImage -InstallConfigFilePath 'C:\installers.json' -BaseDirectory 'C:\ArcGIS'
            }
            catch {
                $exception = $_
            }

            $exception | Should Not Be $null
            $exception.Exception.Message | Should Be 'Error while downloading installers.'
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -ParameterFilter { $ConfigurationName -eq 'ArcGISDownloadInstallers' }
        }

        It 'passes Azure Files credentials and endpoint to the download configuration' {
            $azureFilesCredential = New-Object System.Management.Automation.PSCredential 'storage-user', (ConvertTo-SecureString 'storage-password' -AsPlainText -Force)
            Mock Test-Path { $true }
            Mock Get-Content { '{"Installers":[],"WindowsFeatures":[]}' }
            Mock Invoke-DSCJob { $true }

            Invoke-BuildArcGISAzureImage -InstallConfigFilePath 'C:\installers.json' -BaseDirectory 'C:\ArcGIS' -FileSourceType AzureFiles -AFSCredential $azureFilesCredential -AFSEndpoint 'https://storage.file.core.windows.net'

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $ConfigurationName -eq 'ArcGISDownloadInstallers' -and
                $Arguments.FileSourceType -eq 'AzureFiles' -and
                $Arguments.AFSCredential.UserName -eq 'storage-user' -and
                $Arguments.AFSEndpoint -eq 'https://storage.file.core.windows.net'
            }
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter { $ConfigurationName -eq 'ArcGISSetupConfiguration' }
        }
    }

    Describe 'Invoke-PublishWebApp' {
        It 'dispatches the web app configuration with SSL and debug flags' {
            Mock Assert-PowerShellVersionIs51 {}
            Mock Invoke-DSCJob { $true }

            Invoke-PublishWebApp -NodeName 'web-01' -WebAppName 'portal-app' -SourceDir 'C:\source' -UseSSL -DebugSwitch

            Assert-MockCalled Assert-PowerShellVersionIs51 -Exactly 1
            Assert-MockCalled Invoke-DSCJob -Exactly 1 -ParameterFilter {
                $ConfigurationName -eq 'DeployWebApp' -and
                $ConfigurationFolderPath -eq 'Configurations-OnPrem' -and
                $Arguments.NodeName -eq 'web-01' -and
                $Arguments.WebAppName -eq 'portal-app' -and
                $Arguments.SourceDir -eq 'C:\source' -and
                $UseWinRMSSL -and $DebugMode
            }
        }
    }

    Describe 'Invoke-PublishGISService' {
        It 'builds DSC data with an encrypted target node and publisher credential' {
            Mock Assert-PowerShellVersionIs51 {}
            Mock Get-Content {
                '{"ServerNode":"server-01","TargetNodeEncryptionCertificateFilePath":"C:\\node.cer","TargetNodeEncryptionCertificateThumbprint":"ABC","PublisherAccountCredential":{"UserName":"publisher","Password":"publisher-password"},"PortalHostName":"portal.contoso.com","PortalPort":443,"PortalContext":"portal","ServerHostName":"server.contoso.com","ServerPort":6443,"ServerContext":"arcgis","GISServices":[{"Name":"Cities"}]}'
            }
            Mock Invoke-DSCJob { $true }

            Invoke-PublishGISService -ConfigurationParametersFile 'C:\publish.json' -UseSSL -DebugSwitch

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -ParameterFilter {
                $ConfigurationName -eq 'PublishGISService' -and
                $ConfigurationFolderPath -eq 'Configurations-OnPrem' -and
                $UseWinRMSSL -and $DebugMode -and
                $Arguments.ConfigurationData.AllNodes[0].NodeName -eq 'server-01' -and
                $Arguments.ConfigurationData.AllNodes[0].CertificateFile -eq 'C:\node.cer' -and
                $Arguments.ConfigurationData.AllNodes[0].Thumbprint -eq 'ABC' -and
                $Arguments.PublisherAccountCredential.UserName -eq 'publisher' -and
                $Arguments.PublisherAccountCredential.GetNetworkCredential().Password -eq 'publisher-password' -and
                $Arguments.GISServices[0].Name -eq 'Cities'
            }
        }

        It 'allows a plaintext DSC credential when the target node has no encryption certificate' {
            Mock Assert-PowerShellVersionIs51 {}
            Mock Get-Content {
                '{"ServerNode":"server-01","PublisherAccountCredential":{"UserName":"publisher","Password":"publisher-password"},"PortalHostName":"portal.contoso.com","PortalPort":443,"PortalContext":"portal","ServerHostName":"server.contoso.com","ServerPort":6443,"ServerContext":"arcgis","GISServices":[]}'
            }
            Mock Invoke-DSCJob { $true }

            Invoke-PublishGISService -ConfigurationParametersFile 'C:\publish.json'

            Assert-MockCalled Invoke-DSCJob -Exactly 1 -Scope It -ParameterFilter {
                $Arguments.ConfigurationData.AllNodes[0].PSDscAllowPlainTextPassword -and
                -not $Arguments.ConfigurationData.AllNodes[0].ContainsKey('CertificateFile') -and
                -not $Arguments.ConfigurationData.AllNodes[0].ContainsKey('Thumbprint')
            }
        }
    }
}