Import-Module (Join-Path $PSScriptRoot '..\Modules\ArcGIS\DSCResources\ArcGIS_AzureSetupsManager\ArcGIS_AzureSetupsManager.psm1') -Force

InModuleScope ArcGIS_AzureSetupsManager {
    Describe 'Azure setups cleanup path handling' {
        It 'Normalizes cleanup paths - <Name>' -TestCases @(
            @{ Name = 'ShortLocal'; Path = 'C:\ArcGIS\Portal'; Regular = 'C:\ArcGIS\Portal'; Extended = '\\?\C:\ArcGIS\Portal' }
            @{ Name = 'LongLocal'; Path = 'C:\ArcGIS\' + ('nested\' * 40) + 'Portal'; Regular = 'C:\ArcGIS\' + ('nested\' * 40) + 'Portal'; Extended = '\\?\C:\ArcGIS\' + ('nested\' * 40) + 'Portal' }
            @{ Name = 'RepeatedSeparators'; Path = 'C:\\ArcGIS\\Portal'; Regular = 'C:\ArcGIS\Portal'; Extended = '\\?\C:\ArcGIS\Portal' }
            @{ Name = 'UNC'; Path = '\\server\share\Portal'; Regular = '\\server\share\Portal'; Extended = '\\?\UNC\server\share\Portal' }
            @{ Name = 'PrefixedLocal'; Path = '\\?\C:\ArcGIS\Portal'; Regular = 'C:\ArcGIS\Portal'; Extended = '\\?\C:\ArcGIS\Portal' }
            @{ Name = 'PrefixedUNC'; Path = '\\?\UNC\server\share\Portal'; Regular = '\\server\share\Portal'; Extended = '\\?\UNC\server\share\Portal' }
            @{ Name = 'EscapedLocal'; Path = '\\\\?\\C:\\temp\\new\\Portal'; Regular = 'C:\temp\new\Portal'; Extended = '\\?\C:\temp\new\Portal' }
            @{ Name = 'EscapedUNC'; Path = '\\\\?\\UNC\\server\\share\\Portal'; Regular = '\\server\share\Portal'; Extended = '\\?\UNC\server\share\Portal' }
            @{ Name = 'EscapedPrefixLocal'; Path = '\\\\?\\C:\ArcGIS\Portal'; Regular = 'C:\ArcGIS\Portal'; Extended = '\\?\C:\ArcGIS\Portal' }
            @{ Name = 'EscapedPrefixUNC'; Path = '\\\\?\\UNC\server\share\Portal'; Regular = '\\server\share\Portal'; Extended = '\\?\UNC\server\share\Portal' }
            @{ Name = 'JsonDecodedLocal'; Path = (ConvertFrom-Json -InputObject '"\\\\?\\C:\\ArcGIS\\Portal"'); Regular = 'C:\ArcGIS\Portal'; Extended = '\\?\C:\ArcGIS\Portal' }
            @{ Name = 'JsonDecodedUNC'; Path = (ConvertFrom-Json -InputObject '"\\\\?\\UNC\\server\\share\\Portal"'); Regular = '\\server\share\Portal'; Extended = '\\?\UNC\server\share\Portal' }
        ) {
            param($Name, $Path, $Regular, $Extended)

            Resolve-CleanupPath -Path $Path | Should Be $Regular
            Resolve-CleanupPath -Path $Path -UseLongPath | Should Be $Extended
        }

        It 'Rejects invalid cleanup paths - <Name>' -TestCases @(
            @{ Name = 'Null'; Path = $null }
            @{ Name = 'Empty'; Path = '' }
            @{ Name = 'Whitespace'; Path = ' ' }
        ) {
            param($Name, $Path)

            { Resolve-CleanupPath -Path $Path } | Should Throw
        }
    }

    Describe 'Azure setups filesystem cleanup' {
        BeforeEach {
            $script:CleanupRoot = Join-Path (Get-PSDrive TestDrive).Root 'Cleanup'
            [System.IO.Directory]::CreateDirectory($script:CleanupRoot) | Out-Null
            $script:StartJobCommand = Get-Command Start-Job -CommandType Cmdlet
            Mock Start-Job {
                & $script:StartJobCommand -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
            }
        }

        AfterEach {
            if ([System.IO.Directory]::Exists($script:CleanupRoot)) {
                Microsoft.PowerShell.Management\Remove-Item -LiteralPath ('\\?\' + $script:CleanupRoot) -Recurse -Force -ErrorAction Stop
            }
        }

        function New-LongPathFixture {
            param([string]$Root)

            $NestedPath = Join-Path $Root 'framework\webapps\arcgis#home\js\arcgis-app-components\types\components\arcgis-new-item\pages\arcgis-new-item-pages-data-store-database-server-connection-policy-select'
            $FilePath = Join-Path $NestedPath 'arcgis-new-item-pages-data-store-database-server-connection-policy-select.d.ts'
            [System.IO.Directory]::CreateDirectory('\\?\' + $NestedPath) | Out-Null
            [System.IO.File]::WriteAllText(('\\?\' + $FilePath), 'cleanup regression fixture')
            [System.IO.File]::SetAttributes(('\\?\' + $FilePath), [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::ReadOnly)
            $FilePath.Length | Should BeGreaterThan 260
            $Root.Length | Should BeLessThan 260
        }

        function Invoke-WithLegacyPathHandling {
            param([scriptblock]$Action)

            # DSC's WMI host can cache legacy .NET path defaults before loading the resource.
            $SwitchType = [System.IO.Path].Assembly.GetType('System.AppContextSwitches')
            $Flags = [System.Reflection.BindingFlags]'Static, NonPublic'
            $LegacyField = $SwitchType.GetField('_useLegacyPathHandling', $Flags)
            $BlockField = $SwitchType.GetField('_blockLongPaths', $Flags)
            $OriginalLegacy = $LegacyField.GetValue($null)
            $OriginalBlock = $BlockField.GetValue($null)
            try {
                $LegacyField.SetValue($null, 1)
                $BlockField.SetValue($null, 1)
                & $Action
            } finally {
                $LegacyField.SetValue($null, $OriginalLegacy)
                $BlockField.SetValue($null, $OriginalBlock)
            }
        }

        It 'RemovesLongDescendantsInLegacyDscHost - <Name>' -TestCases @(
            @{ Name = 'Local'; PathForm = 'Local' }
            @{ Name = 'RepeatedSeparators'; PathForm = 'RepeatedSeparators' }
            @{ Name = 'Prefixed'; PathForm = 'Prefixed' }
            @{ Name = 'EscapedPrefix'; PathForm = 'EscapedPrefix' }
        ) {
            param($Name, $PathForm)

            $PortalPath = Join-Path $script:CleanupRoot 'Portal [legacy]'
            New-LongPathFixture -Root $PortalPath
            $InputPath = switch ($PathForm) {
                'Local' { $PortalPath }
                'RepeatedSeparators' { $PortalPath.Replace('\', '\\') }
                'Prefixed' { '\\?\' + $PortalPath }
                'EscapedPrefix' { ('\\?\' + $PortalPath).Replace('\', '\\') }
            }

            $Output = @(Invoke-WithLegacyPathHandling {
                Invoke-AdditionalFolderOrFilesToCleanup -FileOrFolderPaths @($InputPath) -Verbose 3>&1 4>&1
            })

            [System.IO.Directory]::Exists($PortalPath) | Should Be $false
            @($Output | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }).Count | Should Be 0
            @($Output | Where-Object { "$_" -eq "Deleted file/folder: $InputPath" }).Count | Should Be 1
        }

        It 'DoesNotPrefixOrIsolateShortPathsInLegacyDscHost - <Name>' -TestCases @(
            @{ Name = 'Local'; Prefixed = $false }
            @{ Name = 'Prefixed'; Prefixed = $true }
        ) {
            param($Name, $Prefixed)

            $FilePath = Join-Path $script:CleanupRoot 'short[1].exe'
            [System.IO.File]::WriteAllText($FilePath, 'delete')
            $InputPath = if ($Prefixed) { '\\?\' + $FilePath } else { $FilePath }
            $script:RemoveItemCommand = Get-Command Remove-Item -CommandType Cmdlet
            Mock Remove-Item {
                & $script:RemoveItemCommand -LiteralPath $LiteralPath -Recurse -Force -ErrorAction Stop
            } -ParameterFilter {
                $LiteralPath -eq (Join-Path $script:CleanupRoot 'short[1].exe')
            }

            $Output = @(Invoke-WithLegacyPathHandling {
                Invoke-AdditionalFolderOrFilesToCleanup -FileOrFolderPaths @($InputPath) -Verbose 3>&1 4>&1
            })

            [System.IO.File]::Exists($FilePath) | Should Be $false
            @($Output | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }).Count | Should Be 0
            @($Output | Where-Object { "$_" -eq "Deleted file/folder: $InputPath" }).Count | Should Be 1
            Assert-MockCalled Remove-Item -Times 1 -Exactly -Scope It -ParameterFilter {
                $LiteralPath -eq (Join-Path $script:CleanupRoot 'short[1].exe')
            }
            Assert-MockCalled Start-Job -Times 0 -Exactly -Scope It
        }

        It 'CleansDownloadsInLegacyDscHost' {
            $ExistingJobIds = @(Get-Job | Select-Object -ExpandProperty Id)
            foreach ($Name in @('NotebookServer', 'WebAdaptorIIS')) {
                $Path = Join-Path $script:CleanupRoot $Name
                [System.IO.Directory]::CreateDirectory($Path) | Out-Null
                [System.IO.File]::WriteAllText((Join-Path $Path 'setup.exe'), $Name)
            }
            foreach ($Name in @('Portal', 'Server')) {
                New-LongPathFixture -Root (Join-Path $script:CleanupRoot $Name)
            }
            $ShortPath = Join-Path $script:CleanupRoot 'ShortUnused'
            [System.IO.Directory]::CreateDirectory($ShortPath) | Out-Null
            [System.IO.File]::WriteAllText((Join-Path $ShortPath 'setup.exe'), 'delete')

            $Output = @(Invoke-WithLegacyPathHandling {
                Invoke-DownloadFolderCleanup -ComponentNames 'Server' -ServerRole 'NotebookServer' -SetupsStagingFolderPath $script:CleanupRoot -Verbose 3>&1 4>&1
            })

            foreach ($Name in @('Portal', 'Server')) {
                [System.IO.Directory]::Exists((Join-Path $script:CleanupRoot $Name)) | Should Be $false
            }
            [System.IO.Directory]::Exists($ShortPath) | Should Be $false
            foreach ($Name in @('NotebookServer', 'WebAdaptorIIS')) {
                [System.IO.File]::ReadAllText((Join-Path $script:CleanupRoot "$Name\setup.exe")) | Should Be $Name
            }
            @($Output | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }).Count | Should Be 0
            Assert-MockCalled Start-Job -Times 1 -Exactly -Scope It
            Assert-MockCalled Start-Job -Times 1 -Exactly -Scope It -ParameterFilter {
                $ArgumentList[0].Paths.Count -eq 2 -and
                $ArgumentList[0].Paths -contains (Join-Path $script:CleanupRoot 'Portal') -and
                $ArgumentList[0].Paths -contains (Join-Path $script:CleanupRoot 'Server')
            }
            @(Get-Job | Where-Object { $_.Id -notin $ExistingJobIds }).Count | Should Be 0
        }

        It 'ResolvesRelativePathsInIsolatedCleanup' {
            $PortalPath = Join-Path $script:CleanupRoot 'Portal [relative]'
            New-LongPathFixture -Root $PortalPath
            Push-Location -LiteralPath $script:CleanupRoot
            try {
                $Output = @(Invoke-WithLegacyPathHandling {
                    Invoke-AdditionalFolderOrFilesToCleanup -FileOrFolderPaths @('Portal [relative]') -Verbose 3>&1 4>&1
                })

                [System.IO.Directory]::Exists($PortalPath) | Should Be $false
                @($Output | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }).Count | Should Be 0
                @($Output | Where-Object { "$_" -eq 'Deleted file/folder: Portal [relative]' }).Count | Should Be 1
            } finally {
                Pop-Location
            }
        }

        It 'WarnsAndContinuesInIsolatedCleanupAfterBlockedFile' {
            $NestedPath = Join-Path $script:CleanupRoot (('nested\' * 40) + 'files')
            [System.IO.Directory]::CreateDirectory('\\?\' + $NestedPath) | Out-Null
            $FilePath = Join-Path $NestedPath 'locked.exe'
            $NextFilePath = Join-Path $NestedPath 'next.exe'
            [System.IO.File]::WriteAllText(('\\?\' + $FilePath), 'locked')
            [System.IO.File]::WriteAllText(('\\?\' + $NextFilePath), 'delete')
            $ExistingJobIds = @(Get-Job | Select-Object -ExpandProperty Id)
            $Lock = [System.IO.File]::Open(('\\?\' + $FilePath), [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            try {
                $Output = @(Invoke-WithLegacyPathHandling {
                    Invoke-AdditionalFolderOrFilesToCleanup -FileOrFolderPaths @($FilePath, $NextFilePath) -Verbose 3>&1 4>&1
                })

                [System.IO.File]::Exists('\\?\' + $FilePath) | Should Be $true
                [System.IO.File]::Exists('\\?\' + $NextFilePath) | Should Be $false
                @($Output | Where-Object { "$_" -eq "Deleted file/folder: $FilePath" }).Count | Should Be 0
                @($Output | Where-Object { "$_" -eq "Deleted file/folder: $NextFilePath" }).Count | Should Be 1
                $Warnings = @($Output | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
                $Warnings.Count | Should Be 1
                $Warnings[0].Message | Should Match ([regex]::Escape($FilePath))
                @(Get-Job | Where-Object { $_.Id -notin $ExistingJobIds }).Count | Should Be 0
            } finally {
                $Lock.Dispose()
            }
        }

        It 'WarnsWhenIsolatedCleanupCannotStart' {
            Mock Start-Job { throw 'Cannot start cleanup worker.' } -ParameterFilter {
                $ArgumentList[0].Paths -contains (Join-Path $script:CleanupRoot 'WorkerStartFailure')
            }
            $FilePath = Join-Path $script:CleanupRoot 'WorkerStartFailure'
            New-LongPathFixture -Root $FilePath

            $Output = @(Invoke-WithLegacyPathHandling {
                Invoke-AdditionalFolderOrFilesToCleanup -FileOrFolderPaths @($FilePath) -Verbose 3>&1 4>&1
            })

            [System.IO.Directory]::Exists($FilePath) | Should Be $true
            @($Output | Where-Object { "$_" -eq "Deleted file/folder: $FilePath" }).Count | Should Be 0
            $Warnings = @($Output | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
            $Warnings.Count | Should Be 1
            $Warnings[0].Message | Should Match 'Cannot start cleanup worker'
        }

        It 'ReportsUnsupportedExtendedPathWithoutStartingAnotherJob' {
            $FilePath = Join-Path $script:CleanupRoot 'unsupported.txt'
            [System.IO.File]::WriteAllText($FilePath, 'preserve')

            $Output = @(Invoke-WithLegacyPathHandling {
                Invoke-AdditionalFolderOrFilesToCleanup -FileOrFolderPaths @($FilePath) -UseLongPath -Verbose 3>&1 4>&1
            })

            [System.IO.File]::ReadAllText($FilePath) | Should Be 'preserve'
            @($Output | Where-Object { "$_" -eq "Deleted file/folder: $FilePath" }).Count | Should Be 0
            $Warnings = @($Output | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
            $Warnings.Count | Should Be 1
            $Warnings[0].Message | Should Match ([regex]::Escape($FilePath))
            Assert-MockCalled Start-Job -Times 0 -Exactly -Scope It
        }

        It 'WarnsAndRemovesFailedIsolatedCleanupJob' {
            $script:StartJobCommand = Get-Command Start-Job -CommandType Cmdlet
            Mock Start-Job {
                & $script:StartJobCommand -ScriptBlock { throw 'Cleanup worker failed.' }
            } -ParameterFilter {
                $ArgumentList[0].Paths -contains (Join-Path $script:CleanupRoot 'WorkerExecutionFailure')
            }
            $ExistingJobIds = @(Get-Job | Select-Object -ExpandProperty Id)
            $FilePath = Join-Path $script:CleanupRoot 'WorkerExecutionFailure'
            New-LongPathFixture -Root $FilePath

            $Output = @(Invoke-WithLegacyPathHandling {
                Invoke-AdditionalFolderOrFilesToCleanup -FileOrFolderPaths @($FilePath) -Verbose 3>&1 4>&1
            })

            [System.IO.Directory]::Exists($FilePath) | Should Be $true
            @($Output | Where-Object { "$_" -eq "Deleted file/folder: $FilePath" }).Count | Should Be 0
            $Warnings = @($Output | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
            $Warnings.Count | Should Be 1
            $Warnings[0].Message | Should Match 'Cleanup worker failed'
            @(Get-Job | Where-Object { $_.Id -notin $ExistingJobIds }).Count | Should Be 0
        }

        It 'RemovesLiteralLongFilesInLegacyDscHost' {
            $NestedPath = Join-Path $script:CleanupRoot (('nested\' * 40) + 'files')
            [System.IO.Directory]::CreateDirectory('\\?\' + $NestedPath) | Out-Null
            $FilePath = Join-Path $NestedPath 'installer[1].exe'
            $OtherFilePath = Join-Path $NestedPath 'installer1.exe'
            [System.IO.File]::WriteAllText(('\\?\' + $FilePath), 'delete')
            [System.IO.File]::WriteAllText(('\\?\' + $OtherFilePath), 'preserve')
            [System.IO.File]::SetAttributes(('\\?\' + $FilePath), [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::ReadOnly)
            $FilePath.Length | Should BeGreaterThan 260

            $Output = @(Invoke-WithLegacyPathHandling {
                Invoke-AdditionalFolderOrFilesToCleanup -FileOrFolderPaths @(
                    (Join-Path $script:CleanupRoot 'missing'),
                    $FilePath
                ) -Verbose 3>&1 4>&1
            })

            [System.IO.File]::Exists('\\?\' + $FilePath) | Should Be $false
            [System.IO.File]::ReadAllText('\\?\' + $OtherFilePath) | Should Be 'preserve'
            @($Output | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }).Count | Should Be 0
            @($Output | Where-Object { "$_" -eq "Deleted file/folder: $FilePath" }).Count | Should Be 1
        }

        It 'PreservesJunctionTargetsDuringCleanup - <Name>' -TestCases @(
            @{ Name = 'CurrentHost'; LegacyHost = $false }
            @{ Name = 'LongPathRetry'; LegacyHost = $true }
        ) {
            param($Name, $LegacyHost)

            $UnusedPath = Join-Path $script:CleanupRoot 'Unused'
            $TargetPath = Join-Path $script:CleanupRoot 'Preserve'
            [System.IO.Directory]::CreateDirectory($UnusedPath) | Out-Null
            [System.IO.Directory]::CreateDirectory($TargetPath) | Out-Null
            [System.IO.File]::WriteAllText((Join-Path $TargetPath 'keep.txt'), 'preserve')
            if ($LegacyHost) {
                New-LongPathFixture -Root $UnusedPath
            }
            $JunctionPath = Join-Path $UnusedPath 'linked'
            New-Item -ItemType Junction -Path $JunctionPath -Target $TargetPath | Out-Null
            try {
                if ($LegacyHost) {
                    Invoke-WithLegacyPathHandling {
                        Invoke-AdditionalFolderOrFilesToCleanup -FileOrFolderPaths @($UnusedPath)
                    }
                } else {
                    Invoke-AdditionalFolderOrFilesToCleanup -FileOrFolderPaths @($UnusedPath)
                }

                [System.IO.Directory]::Exists($UnusedPath) | Should Be $false
                [System.IO.File]::ReadAllText((Join-Path $TargetPath 'keep.txt')) | Should Be 'preserve'
            } finally {
                if ([System.IO.Directory]::Exists($JunctionPath)) {
                    [System.IO.Directory]::Delete($JunctionPath)
                }
            }
        }

        It 'RemovesLongDescendantsFromShortRoot' {
            $PortalPath = Join-Path $script:CleanupRoot 'Portal [old]'
            New-LongPathFixture -Root $PortalPath

            $Output = @(Invoke-AdditionalFolderOrFilesToCleanup -FileOrFolderPaths @($PortalPath) -Verbose 4>&1)

            [System.IO.Directory]::Exists($PortalPath) | Should Be $false
            @($Output | Where-Object { "$_" -eq "Deleted file/folder: $PortalPath" }).Count | Should Be 1
            Assert-MockCalled Start-Job -Times 0 -Exactly -Scope It
        }

        It 'RemovesLongDescendantsUsingEscapedPrefix' {
            $PortalPath = Join-Path $script:CleanupRoot 'Portal [escaped]'
            New-LongPathFixture -Root $PortalPath
            $EscapedPath = ('\\?\' + $PortalPath).Replace('\', '\\')

            Invoke-AdditionalFolderOrFilesToCleanup -FileOrFolderPaths @($EscapedPath) -ErrorAction Stop

            [System.IO.Directory]::Exists($PortalPath) | Should Be $false
        }

        It 'RemovesLiteralFilesAndSkipsMissingPaths' {
            $FilePath = Join-Path $script:CleanupRoot 'installer[1].exe'
            $OtherFilePath = Join-Path $script:CleanupRoot 'installer1.exe'
            [System.IO.File]::WriteAllText($FilePath, 'delete')
            [System.IO.File]::WriteAllText($OtherFilePath, 'preserve')

            Invoke-AdditionalFolderOrFilesToCleanup -FileOrFolderPaths @(
                (Join-Path $script:CleanupRoot 'missing'),
                $FilePath
            )

            [System.IO.File]::Exists($FilePath) | Should Be $false
            [System.IO.File]::ReadAllText($OtherFilePath) | Should Be 'preserve'
            Assert-MockCalled Start-Job -Times 0 -Exactly -Scope It
        }

        It 'ContinuesResourceAfterBlockedDeletionWithoutFalseSuccess - <Name>' -TestCases @(
            @{ Name = 'CurrentHost'; LegacyHost = $false }
            @{ Name = 'LegacyHost'; LegacyHost = $true }
        ) {
            param($Name, $LegacyHost)

            Mock Invoke-DownloadFolderCleanup {} -ParameterFilter { $SetupsStagingFolderPath -eq 'C:\ArcGIS\Deployment\Downloads' }
            $FilePath = Join-Path $script:CleanupRoot 'locked.exe'
            $NextFilePath = Join-Path $script:CleanupRoot 'next.exe'
            [System.IO.File]::WriteAllText($FilePath, 'locked')
            [System.IO.File]::WriteAllText($NextFilePath, 'delete')
            $Lock = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            $script:CleanupOutput = @()
            try {
                {
                    $Action = {
                        Set-TargetResource -Version '12.0' -OperationType 'CleanupDownloadsFolder' -ComponentNames 'All' -AdditionalFilesOrFolderToDelete @($FilePath, $NextFilePath) -ErrorAction Stop -Verbose 3>&1 4>&1 |
                            ForEach-Object { $script:CleanupOutput += $_ }
                    }
                    if ($LegacyHost) {
                        Invoke-WithLegacyPathHandling -Action $Action
                    } else {
                        & $Action
                    }
                } | Should Not Throw

                [System.IO.File]::Exists($FilePath) | Should Be $true
                [System.IO.File]::Exists($NextFilePath) | Should Be $false
                @($script:CleanupOutput | Where-Object { "$_" -eq "Deleted file/folder: $FilePath" }).Count | Should Be 0
                $Warnings = @($script:CleanupOutput | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
                $Warnings.Count | Should Be 1
                $Warnings[0].Message | Should Match ([regex]::Escape($FilePath))
                Assert-MockCalled Start-Job -Times 0 -Exactly -Scope It
            } finally {
                $Lock.Dispose()
            }
        }

        It 'WarnsAndContinuesAfterIncompleteDeletion' {
            Mock Remove-Item {} -ParameterFilter { $LiteralPath -eq $script:CleanupRoot }
            $NextFilePath = Join-Path $script:CleanupRoot 'next.exe'
            [System.IO.File]::WriteAllText($NextFilePath, 'delete')

            $Output = @(Invoke-AdditionalFolderOrFilesToCleanup -FileOrFolderPaths @($script:CleanupRoot, $NextFilePath) -ErrorAction Stop -Verbose 3>&1 4>&1)

            [System.IO.Directory]::Exists($script:CleanupRoot) | Should Be $true
            [System.IO.File]::Exists($NextFilePath) | Should Be $false
            @($Output | Where-Object { "$_" -eq "Deleted file/folder: $script:CleanupRoot" }).Count | Should Be 0
            $Warnings = @($Output | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
            $Warnings.Count | Should Be 1
            $Warnings[0].Message | Should Match 'File/folder still exists'
        }

        It 'Continues after invalid cleanup paths - <Name>' -TestCases @(
            @{ Name = 'Null'; InvalidPath = $null }
            @{ Name = 'Empty'; InvalidPath = '' }
            @{ Name = 'Whitespace'; InvalidPath = ' ' }
        ) {
            param($Name, $InvalidPath)

            $NextFilePath = Join-Path $script:CleanupRoot 'next.exe'
            [System.IO.File]::WriteAllText($NextFilePath, 'delete')

            $Output = @(Invoke-AdditionalFolderOrFilesToCleanup -FileOrFolderPaths @($InvalidPath, $NextFilePath) -ErrorAction Stop 3>&1)

            [System.IO.Directory]::Exists($script:CleanupRoot) | Should Be $true
            [System.IO.File]::Exists($NextFilePath) | Should Be $false
            @($Output | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }).Count | Should Be 1
        }

        It 'PreservesRequiredComponentFoldersAndRemovesLongUnusedTree' {
            $RequiredFolders = @('Portal', 'WebStyles', 'DataStore', 'Server', 'SQLNativeClient')
            foreach ($Name in $RequiredFolders) {
                $Path = Join-Path $script:CleanupRoot $Name
                [System.IO.Directory]::CreateDirectory($Path) | Out-Null
                [System.IO.File]::WriteAllText((Join-Path $Path 'setup.exe'), $Name)
            }
            $UnusedPath = Join-Path $script:CleanupRoot 'Unused'
            New-LongPathFixture -Root $UnusedPath
            $LooseFile = Join-Path $script:CleanupRoot 'keep.txt'
            [System.IO.File]::WriteAllText($LooseFile, 'preserve')

            Invoke-DownloadFolderCleanup -ComponentNames 'Portal,DataStore,Server' -SetupsStagingFolderPath $script:CleanupRoot

            [System.IO.Directory]::Exists($UnusedPath) | Should Be $false
            foreach ($Name in $RequiredFolders) {
                [System.IO.File]::ReadAllText((Join-Path $script:CleanupRoot "$Name\setup.exe")) | Should Be $Name
            }
            [System.IO.File]::ReadAllText($LooseFile) | Should Be 'preserve'
        }

        It 'PreservesNotebookServerAndWebAdaptorSetups' {
            foreach ($Name in @('NotebookServer', 'WebAdaptorIIS', 'Server')) {
                [System.IO.Directory]::CreateDirectory((Join-Path $script:CleanupRoot $Name)) | Out-Null
            }

            Invoke-DownloadFolderCleanup -ComponentNames 'Server' -ServerRole 'NotebookServer' -SetupsStagingFolderPath $script:CleanupRoot

            [System.IO.Directory]::Exists((Join-Path $script:CleanupRoot 'NotebookServer')) | Should Be $true
            [System.IO.Directory]::Exists((Join-Path $script:CleanupRoot 'WebAdaptorIIS')) | Should Be $true
            [System.IO.Directory]::Exists((Join-Path $script:CleanupRoot 'Server')) | Should Be $false
        }

        It 'ContinuesDownloadCleanupAfterBlockedFolder' {
            $UnusedPath = Join-Path $script:CleanupRoot 'A-Locked'
            $NextFolderPath = Join-Path $script:CleanupRoot 'Z-Removable'
            [System.IO.Directory]::CreateDirectory($UnusedPath) | Out-Null
            [System.IO.Directory]::CreateDirectory($NextFolderPath) | Out-Null
            $FilePath = Join-Path $UnusedPath 'locked.exe'
            [System.IO.File]::WriteAllText($FilePath, 'locked')
            $Lock = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            try {
                $Output = @(Invoke-DownloadFolderCleanup -ComponentNames 'Portal' -SetupsStagingFolderPath $script:CleanupRoot -ErrorAction Stop -Verbose 3>&1 4>&1)

                [System.IO.File]::Exists($FilePath) | Should Be $true
                [System.IO.Directory]::Exists($NextFolderPath) | Should Be $false
                @($Output | Where-Object { "$_" -eq "Deleted file/folder: $UnusedPath" }).Count | Should Be 0
                $Warnings = @($Output | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
                $Warnings.Count | Should Be 1
                $Warnings[0].Message | Should Match ([regex]::Escape($UnusedPath))
            } finally {
                $Lock.Dispose()
            }
        }

        It 'WarnsWhenDownloadFolderEnumerationFails' {
            $UnreadablePath = Join-Path $script:CleanupRoot 'Unreadable'
            [System.IO.Directory]::CreateDirectory($UnreadablePath) | Out-Null
            Mock Get-ChildItem { throw 'Access to the staging folder is denied.' } -ParameterFilter { $LiteralPath -eq (Join-Path $script:CleanupRoot 'Unreadable') }

            $Output = @(Invoke-DownloadFolderCleanup -ComponentNames 'Portal' -SetupsStagingFolderPath $UnreadablePath -ErrorAction Stop 3>&1)

            [System.IO.Directory]::Exists($UnreadablePath) | Should Be $true
            $Warnings = @($Output | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
            $Warnings.Count | Should Be 1
            $Warnings[0].Message | Should Match ([regex]::Escape($UnreadablePath))
            $Warnings[0].Message | Should Match 'Access to the staging folder is denied'
        }
    }
}
