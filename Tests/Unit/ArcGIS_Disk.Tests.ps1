$moduleScriptPath = Join-Path $PSScriptRoot '..\..\Modules\ArcGIS\DSCResources\ArcGIS_Disk\ArcGIS_Disk.psm1'
Import-Module $moduleScriptPath -Force

InModuleScope ArcGIS_Disk {
    Describe 'ArcGIS_Disk partition growth' {
        BeforeEach {
            $script:diskCurrentSize = 100GB
            $script:diskMaximumSize = 100GB
            Mock Get-DiskLetterAndSizes { @{ F = 2 } }
            Mock Get-Partition {
                [PSCustomObject]@{
                    DriveLetter = 'F'
                    DiskNumber = 2
                    PartitionNumber = 1
                    Size = $script:diskCurrentSize
                }
            }
            Mock Get-PartitionSupportedSize {
                [PSCustomObject]@{ SizeMax = $script:diskMaximumSize }
            }
            Mock Resize-Partition {
                if (($Size - $script:diskCurrentSize) -lt 1MB) {
                    throw 'The size of the extent is less than the minimum of 1MB.'
                }
                $script:diskCurrentSize = $Size
            }
        }

        It 'reports compliance for a <GapBytes>-byte growth gap' -TestCases @(
            @{ GapBytes = 0; Expected = $true }
            @{ GapBytes = 512; Expected = $true }
            @{ GapBytes = 1048575; Expected = $true }
            @{ GapBytes = 1048576; Expected = $false }
            @{ GapBytes = 1049088; Expected = $false }
            @{ GapBytes = 10737418240; Expected = $false }
        ) {
            param($GapBytes, $Expected)
            $script:diskMaximumSize = $script:diskCurrentSize + $GapBytes

            Test-TargetResource -HostName 'pcFileShare' | Should Be $Expected

            Assert-MockCalled Resize-Partition -Exactly 0 -Scope It
            Assert-MockCalled Get-PartitionSupportedSize -Exactly 1 -Scope It -ParameterFilter {
                $DiskNumber -eq 2 -and $PartitionNumber -eq 1
            }
        }

        It 'sets a <GapBytes>-byte growth gap and remains idempotent' -TestCases @(
            @{ GapBytes = 0; ExpectedResizeCount = 0 }
            @{ GapBytes = 512; ExpectedResizeCount = 0 }
            @{ GapBytes = 1048575; ExpectedResizeCount = 0 }
            @{ GapBytes = 1048576; ExpectedResizeCount = 1 }
            @{ GapBytes = 1049088; ExpectedResizeCount = 1 }
            @{ GapBytes = 10737418240; ExpectedResizeCount = 1 }
        ) {
            param($GapBytes, $ExpectedResizeCount)
            $script:diskMaximumSize = $script:diskCurrentSize + $GapBytes

            Set-TargetResource -HostName 'pcFileShare' | Should Be $true
            Test-TargetResource -HostName 'pcFileShare' | Should Be $true
            Set-TargetResource -HostName 'pcFileShare' | Should Be $true

            Assert-MockCalled Resize-Partition -Exactly $ExpectedResizeCount -Scope It
            Assert-MockCalled Resize-Partition -Exactly $ExpectedResizeCount -Scope It -ParameterFilter {
                $DriveLetter -eq 'F' -and $Size -eq $script:diskMaximumSize
            }
        }

        It 'skips resizing the reported multi-terabyte partition with a sub-MiB remainder' {
            $script:diskCurrentSize = 8796075196416
            $script:diskMaximumSize = 8796076228096

            Test-TargetResource -HostName 'fuServer-0' | Should Be $true
            Set-TargetResource -HostName 'fuServer-0' | Should Be $true
            Test-TargetResource -HostName 'fuServer-0' | Should Be $true
            Set-TargetResource -HostName 'fuServer-0' | Should Be $true

            $script:diskCurrentSize | Should Be 8796075196416
            Assert-MockCalled Resize-Partition -Exactly 0 -Scope It
        }

        It 'propagates supported-size lookup failures without resizing' {
            Mock Get-PartitionSupportedSize { throw 'storage query failed' }

            { Set-TargetResource -HostName 'pcFileShare' } | Should Throw 'Get-PartitionSupportedSize failed: storage query failed'

            Assert-MockCalled Resize-Partition -Exactly 0 -Scope It
        }

        It 'rejects a maximum smaller than the current partition without resizing' {
            $script:diskMaximumSize = $script:diskCurrentSize - 512

            { Set-TargetResource -HostName 'pcFileShare' } | Should Throw 'Invalid maximum size'

            Assert-MockCalled Resize-Partition -Exactly 0 -Scope It
        }

        It 'propagates a resize failure for a supported growth extent' {
            $script:diskMaximumSize = $script:diskCurrentSize + 10GB
            Mock Resize-Partition { throw 'storage provider failure' }

            { Set-TargetResource -HostName 'pcFileShare' } | Should Throw 'storage provider failure'

            Assert-MockCalled Resize-Partition -Exactly 1 -Scope It
        }
    }
}