$ErrorActionPreference = 'Stop'
$sampleRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'SampleConfigs/v5/v5.2.x'
$readme = Get-Content -Raw -Path (Join-Path $sampleRoot 'README.md')
$files = @(Get-ChildItem -Path $sampleRoot -Filter '*.json' -File -Recurse)
$links = @([regex]::Matches($readme, '\]\(([^)]+\.json)\)') | ForEach-Object {
    [Uri]::UnescapeDataString($_.Groups[1].Value)
})
$migration = @([regex]::Matches($readme, '\| `([^`]+\.json)` \| `([^`]+\.json)` \|'))
$oldPaths = @($migration | ForEach-Object { $_.Groups[1].Value })
$newPaths = @($migration | ForEach-Object { $_.Groups[2].Value })
if ($migration.Count -ne $files.Count -or
    @($oldPaths | Select-Object -Unique).Count -ne $files.Count -or
    @($newPaths | Select-Object -Unique).Count -ne $files.Count) {
    throw 'The migration table must map every sample exactly once.'
}

foreach ($file in $files) {
    $relativePath = $file.FullName.Substring($sampleRoot.Length).TrimStart([char[]]@('/', '\')).Replace('\', '/')
    $config = Get-Content -Raw -Path $file.FullName | ConvertFrom-Json
    if ($file.BaseName -cnotmatch '^[A-Z][A-Za-z0-9]*(?:-[A-Z][A-Za-z0-9]*)*$' -or
        $file.BaseName -cmatch '^(BaseDeployment|GISServer)-') {
        throw "Sample filename does not follow the naming convention: $relativePath"
    }
    if (@($links | Where-Object { $_ -ceq $relativePath }).Count -ne 1) {
        throw "Expected exactly one catalog entry for $relativePath."
    }
    if (@($newPaths | Where-Object { $_ -ceq $relativePath }).Count -ne 1) {
        throw "Expected exactly one migration destination for $relativePath."
    }
    if ($relativePath -clike 'Gis Servers/*' -and
        $relativePath -cne 'Gis Servers/PublishGISService.json' -and
        $file.BaseName -cnotmatch '^(Single|Two|Three|Nine)Machine-') {
        throw "Server sample filename must begin with a machine count: $relativePath"
    }
    if ($relativePath -cmatch '^(Base Deployment|Gis Servers)/(Single|Two|Three|Nine)Machine(?:-|\.json)') {
        $expectedNodeCount = switch ($Matches[2]) { 'Single' { 1 } 'Two' { 2 } 'Three' { 3 } 'Nine' { 9 } }
        if (@($config.AllNodes).Count -ne $expectedNodeCount) {
            throw "Incorrect machine count in filename: $relativePath"
        }
    }
    if ($config.ConfigData.ServerRole -eq 'GeoAnalytics' -or
        $config.ConfigData.AdditionalServerRoles -contains 'GeoAnalytics') {
        throw "Retired GeoAnalytics Server role in $relativePath."
    }
}

foreach ($link in $links) {
    if (-not (Test-Path -LiteralPath (Join-Path $sampleRoot $link) -PathType Leaf)) {
        throw "Catalog link does not exist: $link"
    }
}

$internalLb = Get-Content -Raw -Path (Join-Path $sampleRoot 'Base Deployment/NineMachine-InternalLoadBalancer.json') | ConvertFrom-Json
$objectStores = @($internalLb.AllNodes | Where-Object { $_.Role -contains 'DataStore' -and $_.DataStoreTypes -contains 'ObjectStore' })
if ($objectStores.Count -ne 1) {
    throw 'The internal load balancer sample must have a DataStore node for ObjectStore.'
}

$java = Get-Content -Raw -Path (Join-Path $sampleRoot 'Base Deployment/ThreeMachine-JavaWebAdaptor.json') | ConvertFrom-Json
if (@($java.AllNodes).Count -ne 3 -or -not $java.ConfigData.WebAdaptor.IsJavaWebAdaptor -or
    @($java.AllNodes | Where-Object { $_.Role -contains 'WebAdaptor' }).Count -ne 2) {
    throw 'The distributed Java sample must have three nodes and two Java Web Adaptor nodes.'
}

$dr = Get-Content -Raw -Path (Join-Path $sampleRoot 'Base Deployment/WebGISDR.json') | ConvertFrom-Json
if (@($dr.AllNodes | Where-Object { $_.Role -contains 'Portal' }).Count -ne 1 -or
    -not $dr.ConfigData.Portal.Installer.InstallDir -or
    -not $dr.ConfigData.Portal.WebGISDR.PropertiesFilePath -or
    -not $dr.ConfigData.Portal.WebGISDR.RunAsAccount.UserName -or
    -not $dr.ConfigData.Portal.WebGISDR.RunAsAccount.PasswordEnvironmentVariableName) {
    throw 'The WebGISDR sample must identify a Portal node, installation, properties file, and run-as account.'
}

Write-Host "Validated $($files.Count) sample configurations and their catalog entries."
