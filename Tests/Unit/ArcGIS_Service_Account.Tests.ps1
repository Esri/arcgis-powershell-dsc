Import-Module (Join-Path $PSScriptRoot '..\..\Modules\ArcGIS\DSCResources\ArcGIS_Service_Account\ArcGIS_Service_Account.psm1') -Force

InModuleScope ArcGIS_Service_Account {
    function Invoke-CimMethod {
        [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline = $true)]
            $InputObject,
            [string]$Name,
            [hashtable]$Arguments
        )

        throw 'CIM service changes must be mocked.'
    }

    Describe 'GeoEvent service account password updates' {
        BeforeEach {
            $script:accountUpdateEvents = New-Object System.Collections.ArrayList
            $script:accountChanges = New-Object System.Collections.ArrayList
            $script:accountCredential = New-Object System.Management.Automation.PSCredential(
                'arcgis', (ConvertTo-SecureString 'updated-test-password' -AsPlainText -Force))
            Mock Set-LogOnAsServicePolicy {}
            Mock Get-ArcGISComponentVersionAndInstallDirectory {
                if ($ComponentName -eq 'Server') {
                    @{ InstallDir = 'C:\ArcGIS\Server' }
                } else {
                    @{ InstallDir = $null }
                }
            }
            Mock Get-WindowsServiceRunAsInfo { @{ RunAsAccount = 'arcgis' } }
            Mock Test-Path { $Path -in @('C:\ArcGIS\Server', 'C:\ArcGIS\Server\GeoEvent') }
            Mock Test-Acl { $true }
            Mock Get-CimInstance {
                $serviceName = if ($Filter -eq "name='ArcGISGeoEventGateway'") {
                    'ArcGISGeoEventGateway'
                } else {
                    'ArcGISGeoEvent'
                }
                New-CimInstance -ClassName Win32_Service -Property @{ Name = $serviceName } -ClientOnly
            }
            Mock Invoke-CimMethod {
                param($InputObject, $Name, $Arguments)

                [void]$script:accountUpdateEvents.Add("Change:$($InputObject.Name)")
                [void]$script:accountChanges.Add([PSCustomObject]@{
                    ServiceName = $InputObject.Name
                    Method = $Name
                    StartName = $Arguments.StartName
                    StartPassword = $Arguments.StartPassword
                })
                @{ ReturnValue = 0 }
            }
            Mock Stop-ServiceAndWait {}
            Mock Restart-ArcGISService {
                [void]$script:accountUpdateEvents.Add("Restart:$ServiceName")
            }
            Mock Start-Sleep {}
        }

        It 'updates both GeoEvent passwords before restart when the service install lookup is empty' {
            Set-TargetResource -Name ArcGISGeoEvent -RunAsAccount $script:accountCredential `
                -Ensure Present -ForceRunAsAccountUpdate $true

            $script:accountChanges.Count | Should Be 2
            ($script:accountChanges.ServiceName -join ',') | Should Be 'ArcGISGeoEvent,ArcGISGeoEventGateway'
            foreach ($change in $script:accountChanges) {
                $change.Method | Should Be 'Change'
                $change.StartName | Should Be '.\arcgis'
                $change.StartPassword | Should Be 'updated-test-password'
            }
            ($script:accountUpdateEvents -join ',') | Should Be 'Change:ArcGISGeoEvent,Change:ArcGISGeoEventGateway,Restart:ArcGISGeoEvent'
        }

        It 'uses the correct credentials for a <Case> account' -TestCases @(
            @{ Case = 'prefixed-local'; UserName = '.\arcgis'; Domain = $false; MSA = $false; ExpectedUser = '.\arcgis' }
            @{ Case = 'domain'; UserName = 'EXAMPLE\arcgis'; Domain = $true; MSA = $false; ExpectedUser = 'EXAMPLE\arcgis' }
            @{ Case = 'managed'; UserName = 'EXAMPLE\arcgis$'; Domain = $true; MSA = $true; ExpectedUser = 'EXAMPLE\arcgis$' }
        ) {
            param($Case, $UserName, $Domain, $MSA, $ExpectedUser)
            $credential = New-Object System.Management.Automation.PSCredential(
                $UserName, (ConvertTo-SecureString 'updated-test-password' -AsPlainText -Force))

            Set-TargetResource -Name ArcGISGeoEvent -RunAsAccount $credential -Ensure Present `
                -ForceRunAsAccountUpdate $true -IsDomainAccount $Domain -IsMSAAccount $MSA

            $script:accountChanges.Count | Should Be 2
            foreach ($change in $script:accountChanges) {
                $change.StartName | Should Be $ExpectedUser
                if ($MSA) {
                    $change.StartPassword | Should BeNullOrEmpty
                } else {
                    $change.StartPassword | Should Be 'updated-test-password'
                }
            }
        }

        It 'updates both services when the account name changes without force update' {
            Mock Get-WindowsServiceRunAsInfo { @{ RunAsAccount = 'previous-account' } }

            Set-TargetResource -Name ArcGISGeoEvent -RunAsAccount $script:accountCredential -Ensure Present

            $script:accountChanges.Count | Should Be 2
            ($script:accountChanges.ServiceName -join ',') | Should Be 'ArcGISGeoEvent,ArcGISGeoEventGateway'
            foreach ($change in $script:accountChanges) {
                $change.StartName | Should Be '.\arcgis'
                $change.StartPassword | Should Be 'updated-test-password'
            }
        }

        It 'stops before cleanup and restart when the <Case> credential update fails' -TestCases @(
            @{ Case = 'server'; FailedService = 'ArcGISGeoEvent'; ExpectedCalls = 1 }
            @{ Case = 'gateway'; FailedService = 'ArcGISGeoEventGateway'; ExpectedCalls = 2 }
        ) {
            param($Case, $FailedService, $ExpectedCalls)
            $script:failedAccountService = $FailedService
            Mock Invoke-CimMethod {
                param($InputObject, $Name, $Arguments)

                if ($InputObject.Name -eq $script:failedAccountService) {
                    @{ ReturnValue = 15 }
                } else {
                    @{ ReturnValue = 0 }
                }
            }

            { Set-TargetResource -Name ArcGISGeoEvent -RunAsAccount $script:accountCredential `
                -Ensure Present -ForceRunAsAccountUpdate $true } |
                Should Throw "Service $FailedService failed. Return value - 15"

            Assert-MockCalled Invoke-CimMethod -Exactly $ExpectedCalls -Scope It
            Assert-MockCalled Stop-ServiceAndWait -Exactly 0 -Scope It
            Assert-MockCalled Restart-ArcGISService -Exactly 0 -Scope It
        }

        It 'propagates CIM errors without cleanup or restart' {
            Mock Invoke-CimMethod { throw 'service credential update denied' }

            { Set-TargetResource -Name ArcGISGeoEvent -RunAsAccount $script:accountCredential `
                -Ensure Present -ForceRunAsAccountUpdate $true } | Should Throw 'service credential update denied'

            Assert-MockCalled Stop-ServiceAndWait -Exactly 0 -Scope It
            Assert-MockCalled Restart-ArcGISService -Exactly 0 -Scope It
        }

        It 'rejects a missing service before cleanup or restart' {
            Mock Get-CimInstance { $null }

            { Set-TargetResource -Name ArcGISGeoEvent -RunAsAccount $script:accountCredential `
                -Ensure Present -ForceRunAsAccountUpdate $true } | Should Throw "Service 'ArcGISGeoEvent' was not found"

            Assert-MockCalled Invoke-CimMethod -Exactly 0 -Scope It
            Assert-MockCalled Stop-ServiceAndWait -Exactly 0 -Scope It
            Assert-MockCalled Restart-ArcGISService -Exactly 0 -Scope It
        }

        It 'rejects an unresolved parent installation before cleanup or restart' {
            Mock Get-ArcGISComponentVersionAndInstallDirectory { @{ InstallDir = $null } }

            { Set-TargetResource -Name ArcGISGeoEvent -RunAsAccount $script:accountCredential `
                -Ensure Present -ForceRunAsAccountUpdate $true } | Should Throw 'Cannot determine the ArcGIS Server install directory'

            Assert-MockCalled Invoke-CimMethod -Exactly 0 -Scope It
            Assert-MockCalled Stop-ServiceAndWait -Exactly 0 -Scope It
            Assert-MockCalled Restart-ArcGISService -Exactly 0 -Scope It
        }

        It 'cleans up the resolved GeoEvent directory without appending GeoEvent twice' {
            Mock Test-Path { $Path -like 'C:\ArcGIS\Server*' }
            Mock Get-ChildItem {}

            Set-TargetResource -Name ArcGISGeoEvent -RunAsAccount $script:accountCredential `
                -Ensure Present -ForceRunAsAccountUpdate $true

            Assert-MockCalled Get-ChildItem -Exactly 1 -Scope It -ParameterFilter {
                $Path -eq 'C:\ArcGIS\Server\GeoEvent\data'
            }
            Assert-MockCalled Get-ChildItem -Exactly 1 -Scope It -ParameterFilter {
                $Path -eq 'C:\ArcGIS\Server\GeoEvent\gateway\log'
            }
            Assert-MockCalled Get-ChildItem -Exactly 1 -Scope It -ParameterFilter {
                $Path -eq 'C:\ArcGIS\Server\GeoEvent\etc\com.esri.ges.gateway.cfg'
            }
            Assert-MockCalled Get-ChildItem -Exactly 0 -Scope It -ParameterFilter {
                $Path -like '*\GeoEvent\GeoEvent\*'
            }
        }

        It 'checks permissions on the same resolved GeoEvent directory in Test and Set' {
            Mock Test-Acl { $false }

            Test-TargetResource -Name ArcGISGeoEvent -RunAsAccount $script:accountCredential -Ensure Present | Should Be $false

            Assert-MockCalled Test-Acl -Exactly 1 -Scope It -ParameterFilter {
                $Directory -eq 'C:\ArcGIS\Server\GeoEvent'
            }
        }

        It 'returns the expected compliance state for <Case> force update' -TestCases @(
            @{ Case = 'disabled'; ForceUpdate = $false; Expected = $true }
            @{ Case = 'enabled'; ForceUpdate = $true; Expected = $false }
        ) {
            param($Case, $ForceUpdate, $Expected)

            Test-TargetResource -Name ArcGISGeoEvent -RunAsAccount $script:accountCredential `
                -Ensure Present -ForceRunAsAccountUpdate $ForceUpdate | Should Be $Expected

            Assert-MockCalled Invoke-CimMethod -Exactly 0 -Scope It
        }
    }
}