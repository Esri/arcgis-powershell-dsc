#Requires -Version 5.1
<#
.SYNOPSIS
    Validate ArcGIS PowerShell DSC configuration JSON files.

.DESCRIPTION
    Runs module semantic rules (deprecated keys, GeoEvent split-file rules, AllNodes
    integrity). Optionally validates against ConfigurationSchemas/vX.Y.Z.json using
    Test-Json -SchemaFile (PowerShell 7.4+ required for draft 2020-12).

    Deprecated-key rules follow Esri wiki module 5.1.0 (Desktop/Insights removal) and
    4.5.0 / runtime Web Adaptor AdminAccessEnabled behavior (Enterprise 11.5+).
    See: https://github.com/Esri/arcgis-powershell-dsc/wiki/New-Variables-Introduced-in-each-PowerShell-DSC-Module-Version

    Intended as a standalone contribution under ConfigurationSchemas/ in
    Esri/arcgis-powershell-dsc. Does not import the ArcGIS DSC module.

.PARAMETER Path
    One or more configuration JSON file paths, directories, or wildcards.
    Directories expand to *.json recursively.

.PARAMETER Version
    Module version used in deprecation messages. Default 5.1.1.

.PARAMETER Schema
    Also validate each file against the JSON Schema with Test-Json -SchemaFile.

.PARAMETER SchemaPath
    Path to the schema JSON. Default: sibling v5.1.1.json next to this script
    (when installed under ConfigurationSchemas/).

.PARAMETER Strict
    Throw on the first file that fails validation.

.EXAMPLE
    .\Test-ArcGISConfigurationJson.ps1 -Path '.\SampleConfigs\v5\v5.1.1\Base Deployment\BaseDeployment-SingleMachine.json'

.EXAMPLE
    .\Test-ArcGISConfigurationJson.ps1 -Path .\my-config.json -Schema

.EXAMPLE
    .\Test-ArcGISConfigurationJson.ps1 -Path .\testdata
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('FullName')]
    [string[]]$Path,

    [string]$Version = '5.1.1',

    [switch]$Schema,

    [string]$SchemaPath,

    [switch]$Strict
)

$ErrorActionPreference = 'Stop'

$script:ValidatorRoot = $PSScriptRoot

# Embedded rules from Esri wiki (5.1.0 Desktop/Insights; 4.5.0+ AdminAccessEnabled).
# Kept in-script so ConfigurationSchemas/ stays flat (schemas + this script only).
function Get-ArcGISConfigurationDeprecatedRules {
    $json = @'
{
  "moduleVersion": "5.1.0",
  "source": "https://github.com/Esri/arcgis-powershell-dsc/wiki/New-Variables-Introduced-in-each-PowerShell-DSC-Module-Version",
  "deprecatedAllNodesRoles": ["Desktop"],
  "deprecatedConfigDataKeys": [
    "DesktopVersion",
    "InsightsVersion",
    "OldInsightsVersion",
    "Insights"
  ],
  "deprecatedInsightsInstallerKeys": [
    "Path",
    "IsSelfExtracting"
  ],
  "notes": {
    "WebAdaptor.AdminAccessEnabled": "ConfigData.WebAdaptor.AdminAccessEnabled is ignored from ArcGIS Enterprise 11.5; the module forces true.",
    "WebAdaptorConfig.AdminAccessEnabled": "AllNodes.WebAdaptorConfig.AdminAccessEnabled is ignored from ArcGIS Web Adaptor 11.5+; the module forces true."
  }
}
'@
    return $json | ConvertFrom-Json
}

function Test-ArcGISConfigurationDeprecatedKeys {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Config,

        [string]$ModuleVersion = '5.1.1'
    )

    $issues = [System.Collections.Generic.List[string]]::new()
    if ($ModuleVersion -lt '5.1.0') { return @() }

    $rules = Get-ArcGISConfigurationDeprecatedRules
    $waConfigNoteAdded = $false

    foreach ($node in @($Config.AllNodes)) {
        foreach ($badRole in @($rules.deprecatedAllNodesRoles)) {
            if ($node.Role -contains $badRole) {
                $issues.Add("AllNodes role '$badRole' is deprecated in module $ModuleVersion (node $($node.NodeName)).")
            }
        }

        foreach ($wa in @($node.WebAdaptorConfig)) {
            if (-not $wa) { continue }
            if ($wa.PSObject.Properties.Name -contains 'AdminAccessEnabled' -and -not $waConfigNoteAdded) {
                $note = $rules.notes.'WebAdaptorConfig.AdminAccessEnabled'
                if ($note) { $issues.Add([string]$note) }
                else { $issues.Add('AllNodes.WebAdaptorConfig.AdminAccessEnabled is deprecated.') }
                $waConfigNoteAdded = $true
            }
        }
    }

    if ($Config.ConfigData) {
        foreach ($key in @($rules.deprecatedConfigDataKeys)) {
            if ($Config.ConfigData.PSObject.Properties.Name -contains $key) {
                $issues.Add("ConfigData.$key is deprecated in module $ModuleVersion.")
            }
        }

        if ($Config.ConfigData.Insights -and $Config.ConfigData.Insights.Installer) {
            foreach ($ikey in @($rules.deprecatedInsightsInstallerKeys)) {
                if ($Config.ConfigData.Insights.Installer.PSObject.Properties.Name -contains $ikey) {
                    $issues.Add("ConfigData.Insights.Installer.$ikey is deprecated in module $ModuleVersion.")
                }
            }
        }

        if ($Config.ConfigData.WebAdaptor -and
            ($Config.ConfigData.WebAdaptor.PSObject.Properties.Name -contains 'AdminAccessEnabled')) {
            $note = $rules.notes.'WebAdaptor.AdminAccessEnabled'
            if ($note) { $issues.Add([string]$note) }
            else { $issues.Add('ConfigData.WebAdaptor.AdminAccessEnabled is deprecated.') }
        }
    }

    return @($issues)
}

function Test-ArcGISConfigurationSplitRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Config
    )

    $issues = [System.Collections.Generic.List[string]]::new()
    if (-not $Config.ConfigData) { return @() }

    $role = $Config.ConfigData.ServerRole

    if ($role -eq 'GeoEvent' -and $Config.ConfigData.Federation) {
        $issues.Add('GeoEvent deployment must not include a Federation block.')
    }

    if ($role -eq 'GeneralPurposeServer' -and
        $Config.ConfigData.AdditionalServerRoles -icontains 'GeoEvent') {
        $issues.Add('GeoEvent must not be listed in AdditionalServerRoles; use a separate JSON with ServerRole GeoEvent.')
    }

    return @($issues)
}

function Test-ArcGISConfigurationAllNodes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Config
    )

    $issues = [System.Collections.Generic.List[string]]::new()
    $seen = @{}
    foreach ($node in @($Config.AllNodes)) {
        $name = [string]$node.NodeName
        if ($seen.ContainsKey($name)) {
            $issues.Add("Duplicate NodeName '$name' in AllNodes.")
        }
        else {
            $seen[$name] = $true
        }

        $roles = @($node.Role)
        if ($roles.Count -eq 0 -or ($roles.Count -eq 1 -and [string]::IsNullOrWhiteSpace([string]$roles[0]))) {
            $display = if ([string]::IsNullOrWhiteSpace($name)) { '(unnamed)' } else { $name }
            $issues.Add("Node '$display' has no Role assigned.")
        }
    }

    return @($issues)
}

function Get-ArcGISConfigurationDscRoots {
    # ConfigurationSchemas/<this script> → repo root is parent
    $root = Join-Path $script:ValidatorRoot '..'
    if (Test-Path -LiteralPath (Join-Path $root 'SampleConfigs')) {
        try { (Resolve-Path -LiteralPath $root).Path } catch { $null }
    }
}

function Resolve-ArcGISConfigurationExistingPath {
    param(
        [Parameter(Mandatory)]
        [string]$InputPath
    )

    if (Test-Path -LiteralPath $InputPath) {
        return (Resolve-Path -LiteralPath $InputPath).Path
    }

    $rel = $InputPath -replace '^\.[\\/]', ''
    foreach ($root in @(Get-ArcGISConfigurationDscRoots)) {
        if ([string]::IsNullOrWhiteSpace($root)) { continue }
        $candidate = Join-Path $root $rel
        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    $null
}

function Expand-ArcGISConfigurationInputPaths {
    param(
        [Parameter(Mandatory)]
        [string[]]$Path
    )

    $expanded = [System.Collections.Generic.List[string]]::new()
    foreach ($raw in $Path) {
        $hasWildcard = [System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($raw)
        if ($hasWildcard) {
            $matches = @(Resolve-Path -Path $raw -ErrorAction SilentlyContinue)
            if ($matches.Count -eq 0) {
                $rel = $raw -replace '^\.[\\/]', ''
                foreach ($root in @(Get-ArcGISConfigurationDscRoots)) {
                    if ([string]::IsNullOrWhiteSpace($root)) { continue }
                    $matches = @(Resolve-Path -Path (Join-Path $root $rel) -ErrorAction SilentlyContinue)
                    if ($matches.Count -gt 0) { break }
                }
            }
            if ($matches.Count -eq 0) {
                throw "No files matched: $raw"
            }
            foreach ($m in $matches) {
                if (Test-Path -LiteralPath $m.Path -PathType Container) {
                    Get-ChildItem -LiteralPath $m.Path -Filter '*.json' -File -Recurse |
                        ForEach-Object { $expanded.Add($_.FullName) }
                }
                elseif ($m.Path -match '\.json$') {
                    $expanded.Add($m.Path)
                }
            }
            continue
        }

        $resolved = Resolve-ArcGISConfigurationExistingPath -InputPath $raw
        if (-not $resolved) {
            $hint = "Path not found: $raw"
            if ($raw -match '\s' -or $raw -notmatch '\.json$') {
                $hint += " Tip: quote -Path when folders contain spaces (e.g. -Path '.\SampleConfigs\v5\v5.1.1\Base Deployment\BaseDeployment-SingleMachine.json')."
            }
            throw $hint
        }

        if (Test-Path -LiteralPath $resolved -PathType Container) {
            $jsonFiles = @(Get-ChildItem -LiteralPath $resolved -Filter '*.json' -File -Recurse)
            if ($jsonFiles.Count -eq 0) {
                throw "No *.json files in directory: $resolved"
            }
            foreach ($f in $jsonFiles) { $expanded.Add($f.FullName) }
        }
        else {
            $expanded.Add($resolved)
        }
    }

    if ($expanded.Count -eq 0) {
        throw 'No configuration JSON files to validate.'
    }

    return @($expanded | Select-Object -Unique)
}

function Resolve-ArcGISConfigurationSchemaPath {
    param([string]$ExplicitPath)

    if ($ExplicitPath) {
        $resolved = Resolve-ArcGISConfigurationExistingPath -InputPath $ExplicitPath
        if (-not $resolved -or -not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
            throw "Schema file not found: $ExplicitPath"
        }
        return $resolved
    }

    $sibling = Join-Path $script:ValidatorRoot 'v5.1.1.json'
    if (Test-Path -LiteralPath $sibling) {
        return (Resolve-Path -LiteralPath $sibling).Path
    }

    foreach ($root in @(Get-ArcGISConfigurationDscRoots)) {
        $repoSchema = Join-Path $root 'ConfigurationSchemas\v5.1.1.json'
        if (Test-Path -LiteralPath $repoSchema) {
            return (Resolve-Path -LiteralPath $repoSchema).Path
        }
    }

    throw "Schema file not found. Pass -SchemaPath or place v5.1.1.json next to this script."
}

function Test-ArcGISConfigurationSupportsSchemaValidation {
    $psMajor = $PSVersionTable.PSVersion.Major
    $psMinor = $PSVersionTable.PSVersion.Minor
    if ($psMajor -gt 7) { return $true }
    if ($psMajor -eq 7 -and $psMinor -ge 4) { return $true }
    return $false
}

function Test-ArcGISConfigurationSchema {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ConfigPath,

        [Parameter(Mandatory)]
        [string]$SchemaFile
    )

    $issues = [System.Collections.Generic.List[string]]::new()

    if (-not (Test-ArcGISConfigurationSupportsSchemaValidation)) {
        $issues.Add("JSON Schema validation (-Schema) requires PowerShell 7.4+ (current: $($PSVersionTable.PSVersion)). Module rules still apply without -Schema.")
        return @($issues)
    }

    try {
        $ok = Test-Json -Path $ConfigPath -SchemaFile $SchemaFile -ErrorAction Stop
        if (-not $ok) {
            $issues.Add("JSON Schema validation failed against '$SchemaFile'.")
        }
    }
    catch {
        $msg = $_.Exception.Message
        if ([string]::IsNullOrWhiteSpace($msg)) { $msg = "$_" }
        $issues.Add("JSON Schema validation failed against '$SchemaFile': $msg")
    }

    return @($issues)
}

function Test-ArcGISConfigurationJsonFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [string]$ModuleVersion = '5.1.1',
        [switch]$Schema,
        [string]$SchemaFile,
        [switch]$Strict
    )

    $resolvedPath = $FilePath
    $raw = Get-Content -LiteralPath $resolvedPath -Raw -Encoding UTF8
    $config = $null
    try {
        $config = $raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        if ($Strict) { throw "Invalid JSON in ${resolvedPath}: $_" }
        return [pscustomobject]@{
            Path       = $resolvedPath
            ValidJson  = $false
            IssueCount = 1
            Issues     = @("Invalid JSON: $_")
            Passed     = $false
        }
    }

    $allIssues = [System.Collections.Generic.List[string]]::new()
    foreach ($issue in @(Test-ArcGISConfigurationDeprecatedKeys -Config $config -ModuleVersion $ModuleVersion)) {
        $allIssues.Add($issue)
    }
    foreach ($issue in @(Test-ArcGISConfigurationSplitRules -Config $config)) {
        $allIssues.Add($issue)
    }
    foreach ($issue in @(Test-ArcGISConfigurationAllNodes -Config $config)) {
        $allIssues.Add($issue)
    }

    if ($Schema) {
        foreach ($issue in @(Test-ArcGISConfigurationSchema -ConfigPath $resolvedPath -SchemaFile $SchemaFile)) {
            $allIssues.Add($issue)
        }
    }

    $result = [pscustomobject]@{
        Path       = $resolvedPath
        ValidJson  = $true
        IssueCount = $allIssues.Count
        Issues     = @($allIssues)
        Passed     = ($allIssues.Count -eq 0)
    }

    if ($Strict -and -not $result.Passed) {
        throw "Validation failed for ${resolvedPath}: $($allIssues -join '; ')"
    }

    return $result
}

# --- entrypoint ---
$resolvedSchema = $null
if ($Schema) {
    $resolvedSchema = Resolve-ArcGISConfigurationSchemaPath -ExplicitPath $SchemaPath
}

$inputFiles = Expand-ArcGISConfigurationInputPaths -Path $Path

$results = [System.Collections.Generic.List[object]]::new()
foreach ($file in $inputFiles) {
    $results.Add((Test-ArcGISConfigurationJsonFile `
            -FilePath $file `
            -ModuleVersion $Version `
            -Schema:$Schema `
            -SchemaFile $resolvedSchema `
            -Strict:$Strict))
}

$results | Format-Table Path, Passed, IssueCount -AutoSize
foreach ($r in $results) {
    if ($r.Issues.Count -gt 0) {
        Write-Host ""
        Write-Host $r.Path -ForegroundColor Cyan
        foreach ($issue in $r.Issues) {
            Write-Warning "  $issue"
        }
    }
}

if ($results | Where-Object { -not $_.Passed }) {
    exit 1
}
exit 0
