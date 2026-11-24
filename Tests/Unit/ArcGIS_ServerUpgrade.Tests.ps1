$arcgisModuleRoot = Join-Path $PSScriptRoot '..\..\Modules'
$originalModulePath = $env:PSModulePath
$env:PSModulePath = "$arcgisModuleRoot;$originalModulePath"
try {
    Import-Module (Join-Path $arcgisModuleRoot 'ArcGIS\ArcGIS.psd1') -Force
    . (Join-Path $arcgisModuleRoot 'ArcGIS\Configurations-OnPrem\Upgrades\ServerUpgrade.ps1')
} finally {
    $env:PSModulePath = $originalModulePath
}

function Get-UpgradeMofResource {
    param([string]$Mof, [string]$ResourceId)

    $resources = [regex]::Matches($Mof, '(?ms)^instance of \w+ as \$\w+\s*\{.*?(?=^instance of |\z)')
    $resource = @($resources | Where-Object {
        $_.Value -match ('ResourceID\s*=\s*"' + [regex]::Escape($ResourceId) + '";')
    })
    $resource.Count | Should Be 1 | Out-Null
    return $resource[0].Value
}

Describe 'On-premises ServerUpgrade component routing' {
    It 'compiles the <Case> upgrade with matching component types and ordered dependencies' -TestCases @(
        @{ Case = 'Velocity'; Role = 'VelocityServer'; Component = 'VelocityServer' }
        @{ Case = 'Notebook'; Role = 'NotebookServer'; Component = 'NotebookServer' }
        @{ Case = 'Mission'; Role = 'MissionServer'; Component = 'MissionServer' }
        @{ Case = 'Video'; Role = 'VideoServer'; Component = 'VideoServer' }
        @{ Case = 'DataPipelines'; Role = 'DataPipelinesServer'; Component = 'DataPipelinesServer' }
        @{ Case = 'GIS'; Role = 'GeneralPurposeServer'; Component = 'Server' }
    ) {
        param($Case, $Role, $Component)

        $configurationData = @{
            AllNodes = @(@{
                NodeName = 'upgrade-01'
                ServerRole = $Role
                ServerLicenseFilePath = 'C:\licenses\server.prvc'
            })
        }
        $outputPath = Join-Path $TestDrive $Case
        $originalModulePath = $env:PSModulePath
        $env:PSModulePath = "$arcgisModuleRoot;$originalModulePath"
        try {
            ServerUpgrade -ConfigurationData $configurationData -OldVersion '12.1' -Version '12.2' `
                -InstallerPath 'C:\installers\server.exe' -PatchesDir 'C:\patches' `
                -EnableDotnetSupport $false -OutputPath $outputPath -ErrorAction Stop | Out-Null
        } finally {
            $env:PSModulePath = $originalModulePath
        }
        $mof = Get-Content -LiteralPath (Join-Path $outputPath 'upgrade-01.mof') -Raw
        $install = Get-UpgradeMofResource -Mof $mof -ResourceId '[ArcGIS_Install]ServerUpgrade'
        $patch = Get-UpgradeMofResource -Mof $mof -ResourceId '[ArcGIS_InstallPatch]ServerInstallPatch'
        $hostname = Get-UpgradeMofResource -Mof $mof -ResourceId '[ArcGIS_HostNameSettings]ServerHostNameSettings'
        $upgrade = Get-UpgradeMofResource -Mof $mof -ResourceId '[ArcGIS_ServerUpgrade]ConfigureUpgrade'

        $install | Should Match ('Name\s*=\s*"' + $Component + '";')
        $install | Should Match 'Path\s*=\s*"C:\\\\installers\\\\server.exe";'
        if ($Component -eq 'Server') {
            $install | Should Match 'FeatureSet\s*=\s*\{\s*"GIS_Server"\s*\};'
        } else {
            $install | Should Not Match '"GIS_Server"'
        }
        $patch | Should Match ('Name\s*=\s*"' + $Component + '";')
        $patch | Should Match 'DependsOn\s*=\s*\{[^}]*"\[ArcGIS_Install\]ServerUpgrade"'
        $hostname | Should Match ('ComponentName\s*=\s*"' + $Component + '";')
        $hostname | Should Match 'DependsOn\s*=\s*\{[^}]*"\[ArcGIS_Install\]ServerUpgrade"'
        $hostname | Should Match 'DependsOn\s*=\s*\{[^}]*"\[ArcGIS_InstallPatch\]ServerInstallPatch"'
        $hostname | Should Match 'DependsOn\s*=\s*\{[^}]*"\[ArcGIS_License\]ServerLicenseupgrade-01"'
        $upgrade | Should Match ('ServerType\s*=\s*"' + $Component + '";')
        $upgrade | Should Match 'DependsOn\s*=\s*\{[^}]*"\[ArcGIS_HostNameSettings\]ServerHostNameSettings"'
    }
}

Import-Module (Join-Path $arcgisModuleRoot 'ArcGIS\DSCResources\ArcGIS_ServerUpgrade\ArcGIS_ServerUpgrade.psm1') -Force

InModuleScope ArcGIS_ServerUpgrade {
    Describe 'ArcGIS_ServerUpgrade Velocity support' {
        BeforeEach {
            Mock Test-Install { $true }
            Mock Get-FQDN { 'velocity.example.test' }
            Mock Test-ArcGISComponentHealth {}
            Mock Test-ServerUpgrade { $false }
            Mock Invoke-ServerUpgrade {}
            Mock Test-GISServerUpgrade { $false }
            Mock Invoke-GISServerUpgrade {}
        }

        It 'returns the Velocity upgrade resource identity' {
            $resource = Get-TargetResource -ServerHostName 'velocity' -ServerType 'VelocityServer'

            $resource.ServerHostName | Should Be 'velocity'
            $resource.ServerType | Should Be 'VelocityServer'
        }

        It 'tests the <Case> Velocity upgrade state through its own endpoint and health check' -TestCases @(
            @{ Case = 'required'; Upgraded = $false }
            @{ Case = 'complete'; Upgraded = $true }
        ) {
            param($Case, $Upgraded)
            $script:velocityUpgraded = $Upgraded
            Mock Test-ServerUpgrade { $script:velocityUpgraded }

            Test-TargetResource -ServerHostName 'velocity' -ServerType 'VelocityServer' -Version '12.2' | Should Be $Upgraded

            Assert-MockCalled Test-Install -Exactly 1 -Scope It -ParameterFilter {
                $Name -eq 'VelocityServer' -and $Version -eq '12.2'
            }
            Assert-MockCalled Test-ArcGISComponentHealth -Exactly 1 -Scope It -ParameterFilter {
                $BaseURL -eq 'https://velocity.example.test:7143/arcgis' -and $ComponentName -eq 'VelocityServer'
            }
            Assert-MockCalled Test-ServerUpgrade -Exactly 1 -Scope It -ParameterFilter {
                $URL -eq 'https://velocity.example.test:7143/arcgis' -and $Referer -eq 'https://localhost'
            }
            Assert-MockCalled Test-GISServerUpgrade -Exactly 0 -Scope It
        }

        It 'completes Velocity upgrade through its own endpoint and health check' {
            Set-TargetResource -ServerHostName 'velocity' -ServerType 'VelocityServer' -Version '12.2'

            Assert-MockCalled Test-Install -Exactly 1 -Scope It -ParameterFilter {
                $Name -eq 'VelocityServer' -and $Version -eq '12.2'
            }
            Assert-MockCalled Test-ArcGISComponentHealth -Exactly 1 -Scope It -ParameterFilter {
                $BaseURL -eq 'https://velocity.example.test:7143/arcgis' -and $ComponentName -eq 'VelocityServer'
            }
            Assert-MockCalled Invoke-ServerUpgrade -Exactly 1 -Scope It -ParameterFilter {
                $URL -eq 'https://velocity.example.test:7143/arcgis' -and $Referer -eq 'https://localhost'
            }
            Assert-MockCalled Invoke-GISServerUpgrade -Exactly 0 -Scope It
        }

        It 'rejects a Velocity upgrade in <Operation> when the target version is not installed' -TestCases @(
            @{ Operation = 'Test-TargetResource' }
            @{ Operation = 'Set-TargetResource' }
        ) {
            param($Operation)
            Mock Test-Install { $false }

            { & $Operation -ServerHostName 'velocity' -ServerType 'VelocityServer' -Version '12.2' } |
                Should Throw 'not upgraded to required Version 12.2'

            Assert-MockCalled Test-ArcGISComponentHealth -Exactly 0 -Scope It
            Assert-MockCalled Test-ServerUpgrade -Exactly 0 -Scope It
            Assert-MockCalled Invoke-ServerUpgrade -Exactly 0 -Scope It
        }

        It 'propagates Velocity readiness errors in <Operation> without attempting a site upgrade' -TestCases @(
            @{ Operation = 'Test-TargetResource' }
            @{ Operation = 'Set-TargetResource' }
        ) {
            param($Operation)
            Mock Test-ArcGISComponentHealth { throw 'server is unavailable' }

            { & $Operation -ServerHostName 'velocity' -ServerType 'VelocityServer' -Version '12.2' } |
                Should Throw 'server is unavailable'

            Assert-MockCalled Test-ServerUpgrade -Exactly 0 -Scope It
            Assert-MockCalled Invoke-ServerUpgrade -Exactly 0 -Scope It
        }

        It 'propagates Velocity site upgrade errors in <Operation>' -TestCases @(
            @{ Operation = 'Test-TargetResource' }
            @{ Operation = 'Set-TargetResource' }
        ) {
            param($Operation)
            Mock Test-ServerUpgrade { throw 'site upgrade failed' }
            Mock Invoke-ServerUpgrade { throw 'site upgrade failed' }

            { & $Operation -ServerHostName 'velocity' -ServerType 'VelocityServer' -Version '12.2' } |
                Should Throw 'site upgrade failed'
        }

        It 'retains GIS-specific upgrade handling' {
            Test-TargetResource -ServerHostName 'gis' -ServerType 'Server' -Version '12.2' | Should Be $false
            Set-TargetResource -ServerHostName 'gis' -ServerType 'Server' -Version '12.2' -EnableUpgradeSiteDebug $true

            Assert-MockCalled Test-GISServerUpgrade -Exactly 1 -Scope It -ParameterFilter {
                $URL -eq 'https://velocity.example.test:6443/arcgis' -and $Version -eq '12.2'
            }
            Assert-MockCalled Invoke-GISServerUpgrade -Exactly 1 -Scope It -ParameterFilter {
                $URL -eq 'https://velocity.example.test:6443/arcgis' -and $EnableUpgradeSiteDebug -and $Version -eq '12.2'
            }
            Assert-MockCalled Test-ArcGISComponentHealth -Exactly 2 -Scope It -ParameterFilter {
                $ComponentName -eq 'ServerAdmin'
            }
            Assert-MockCalled Test-ServerUpgrade -Exactly 0 -Scope It
            Assert-MockCalled Invoke-ServerUpgrade -Exactly 0 -Scope It
        }

        It 'retains specialized upgrade handling for <Role>' -TestCases @(
            @{ Role = 'NotebookServer'; Port = 11443 }
            @{ Role = 'MissionServer'; Port = 20443 }
            @{ Role = 'VideoServer'; Port = 21443 }
            @{ Role = 'DataPipelinesServer'; Port = 14443 }
        ) {
            param($Role, $Port)
            $script:expectedUpgradeUrl = "https://velocity.example.test:$Port/arcgis"

            Test-TargetResource -ServerHostName 'specialized' -ServerType $Role -Version '12.2' | Should Be $false
            Set-TargetResource -ServerHostName 'specialized' -ServerType $Role -Version '12.2'

            Assert-MockCalled Test-ServerUpgrade -Exactly 1 -Scope It -ParameterFilter {
                $URL -eq $script:expectedUpgradeUrl
            }
            Assert-MockCalled Invoke-ServerUpgrade -Exactly 1 -Scope It -ParameterFilter {
                $URL -eq $script:expectedUpgradeUrl
            }
            Assert-MockCalled Test-GISServerUpgrade -Exactly 0 -Scope It
            Assert-MockCalled Invoke-GISServerUpgrade -Exactly 0 -Scope It
        }
    }
}
