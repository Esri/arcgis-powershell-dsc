<#
    Smoke-tests exported utility functions through the module manifest, rather than
    accessing private helpers with InModuleScope. Literal IPv4 input avoids DNS;
    port and service-name tables pin externally visible component mappings.

    TestCases keep equivalent mappings together, with separate invalid-component
    assertions for the error contract. Run with Windows PowerShell 5.1/Pester 3.4.0;
    see ../README.md for the full suite and host-isolation requirements.
#>
$moduleManifestPath = Join-Path $PSScriptRoot '..\..\Modules\ArcGIS\ArcGIS.psd1'

Describe 'Get-FQDN' {
    BeforeAll {
        Import-Module $moduleManifestPath -Force
    }

    It 'returns an IPv4 address without DNS resolution' {
        Get-FQDN -MachineName '192.0.2.10' | Should Be '192.0.2.10'
    }
}

Describe 'Get-ArcGISEnterpriseComponentPort' {
    It 'returns the expected port for <ComponentName>' -TestCases @(
        @{ ComponentName = 'Portal'; Port = 7443 }
        @{ ComponentName = 'Server'; Port = 6443 }
        @{ ComponentName = 'DataStore'; Port = 2443 }
        @{ ComponentName = 'MissionServer'; Port = 20443 }
        @{ ComponentName = 'NotebookServer'; Port = 11443 }
        @{ ComponentName = 'VideoServer'; Port = 21443 }
        @{ ComponentName = 'DataPipelinesServer'; Port = 14443 }
        @{ ComponentName = 'VelocityServer'; Port = 7143 }
        @{ ComponentName = 'GeoEventServer'; Port = 6143 }
        @{ ComponentName = 'Monitor'; Port = 30443 }
    ) {
        param($ComponentName, $Port)

        Get-ArcGISEnterpriseComponentPort -ComponentName $ComponentName | Should Be $Port
    }

    It 'throws for an unknown component' {
        $exception = $null

        try {
            Get-ArcGISEnterpriseComponentPort -ComponentName 'Unknown' -ErrorAction Stop
        }
        catch {
            $exception = $_
        }

        $exception | Should Not Be $null
        $exception.Exception.Message | Should Be 'Unknown component name: Unknown'
    }
}

Describe 'Get-ArcGISServiceName' {
    It 'returns the expected service name for <ComponentName>' -TestCases @(
        @{ ComponentName = 'Portal'; ServiceName = 'Portal for ArcGIS' }
        @{ ComponentName = 'Portal for ArcGIS'; ServiceName = 'Portal for ArcGIS' }
        @{ ComponentName = 'Server'; ServiceName = 'ArcGIS Server' }
        @{ ComponentName = 'ArcGIS Server'; ServiceName = 'ArcGIS Server' }
        @{ ComponentName = 'DataStore'; ServiceName = 'ArcGIS Data Store' }
        @{ ComponentName = 'ArcGIS Data Store'; ServiceName = 'ArcGIS Data Store' }
        @{ ComponentName = 'MissionServer'; ServiceName = 'ArcGIS Mission Server' }
        @{ ComponentName = 'NotebookServer'; ServiceName = 'ArcGIS Notebook Server' }
        @{ ComponentName = 'VideoServer'; ServiceName = 'ArcGIS Video Server' }
        @{ ComponentName = 'DataPipelinesServer'; ServiceName = 'ArcGIS Data Pipelines Server' }
        @{ ComponentName = 'ArcGIS Data Pipelines Server'; ServiceName = 'ArcGIS Data Pipelines Server' }
        @{ ComponentName = 'VelocityServer'; ServiceName = 'Velocity' }
        @{ ComponentName = 'ArcGIS Velocity For ArcGIS Enterprise'; ServiceName = 'Velocity' }
        @{ ComponentName = 'ArcGISGeoEvent'; ServiceName = 'ArcGISGeoEvent' }
        @{ ComponentName = 'WorkflowManager'; ServiceName = 'WorkflowManager' }
    ) {
        param($ComponentName, $ServiceName)

        Get-ArcGISServiceName -ComponentName $ComponentName | Should Be $ServiceName
    }

    It 'throws for an unknown component' {
        $exception = $null

        try {
            Get-ArcGISServiceName -ComponentName 'Unknown' -ErrorAction Stop
        }
        catch {
            $exception = $_
        }

        $exception | Should Not Be $null
        $exception.Exception.Message | Should Be 'Unknown component name: Unknown'
    }
}