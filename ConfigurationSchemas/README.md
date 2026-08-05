# ArcGIS PowerShell DSC Configuration Schema

This schema adds editor validation and IntelliSense for JSON files consumed by `Invoke-ArcGISConfiguration`.

It is intended for deployment configuration documents with these top-level properties:

- `AllNodes`
- `ConfigData`

## Add the schema to a config file

Add a top-level `$schema` property to your JSON document.

Use the published schema URL:

```json
{
  "$schema": "https://esri.github.io/arcgis-powershell-dsc/ConfigurationSchemas/v5.1.1.json",
  "AllNodes": [],
  "ConfigData": {}
}
```

If you are working locally in this repository and want to reference the checked-in file instead, you can also use a relative path from your config file to `ConfigurationSchemas/v5.1.1.json`.

Example for a file under `SampleConfigs/v5/v5.1.1/...`:

```json
{
  "$schema": "../../../ConfigurationSchemas/v5.1.1.json",
  "AllNodes": [],
  "ConfigData": {}
}
```

## What the schema gives you

- Flags unknown properties and obvious shape mismatches while you edit.
- Shows allowed enum values such as supported ArcGIS Enterprise versions and server roles.
- Surfaces required properties for common blocks such as `AllNodes`, `ConfigData`, `Server`, `Portal`, `DataStore`, and `WebAdaptor`.
- Documents many fields inline through property descriptions and examples.

## How to use it in this repo

1. Start from a sample under `SampleConfigs/` that matches your deployment shape.
2. Add the `$schema` property at the top of the file.
3. Edit the JSON until your editor reports no schema validation errors.
4. Run the deployment with `Invoke-ArcGISConfiguration` and the appropriate `-Mode` value.

Example:

```powershell
Invoke-ArcGISConfiguration \
  -ConfigurationParametersFile @('C:\path\to\your-config.json') \
  -Mode InstallLicenseConfigure \
  -Credential $cred \
  -UseSSL \
  -DebugSwitch
```

## Notes

- The schema improves authoring experience, but it does not replace module runtime validation.
- Some options are version-specific. The schema encodes supported values for v5.1.1, including Enterprise versions through `12.1`.
- If your editor says a property is not allowed, verify both the property name and the location where it is defined.
- For richer examples, use the v5.1.1 sample configs under `SampleConfigs/v5/v5.1.1/`.

## Command-line validation

Editor `$schema` IntelliSense catches many shape mistakes while you edit. For a scripted check (CI or pre-deploy), run:

```powershell
# Run from the DSC repo root; quote paths that contain spaces
.\ConfigurationSchemas\Test-ArcGISConfigurationJson.ps1 `
  -Path '.\SampleConfigs\v5\v5.1.1\Base Deployment\BaseDeployment-SingleMachine.json'

# Directory or wildcard — expands recursively to *.json (module rules; invalid fixtures exit 1)
.\ConfigurationSchemas\Test-ArcGISConfigurationJson.ps1 -Path .\testdata
.\ConfigurationSchemas\Test-ArcGISConfigurationJson.ps1 -Path .\testdata\sampleconfigs\v5.1.0 -Version 5.1.0
.\ConfigurationSchemas\Test-ArcGISConfigurationJson.ps1 -Path .\testdata\sampleconfigs\v5.1.1

# v5.1.0 pin
.\ConfigurationSchemas\Test-ArcGISConfigurationJson.ps1 `
  -Path '.\SampleConfigs\v5\v5.1.0\Base Deployment\BaseDeployment-SingleMachine.json' `
  -Version 5.1.0 `
  -Schema `
  -SchemaPath '.\ConfigurationSchemas\v5.1.0.json'
```

Add `-Schema` on **PowerShell 7.4+** to also validate against `ConfigurationSchemas/v5.1.1.json` (or `v5.1.0.json`) via `Test-Json -SchemaFile` (draft 2020-12). Schema mode is strict (`additionalProperties: false`). Module semantic rules are embedded in the script and always run on Windows PowerShell 5.1:

- Deprecated keys from the [Esri variables wiki](https://github.com/Esri/arcgis-powershell-dsc/wiki/New-Variables-Introduced-in-each-PowerShell-DSC-Module-Version) (5.1.0: `Desktop` role, `DesktopVersion`, Insights keys/block; plus `WebAdaptor` / `WebAdaptorConfig` `AdminAccessEnabled` ignored from Enterprise / Web Adaptor 11.5+)
- GeoEvent split-file rules
- AllNodes integrity

`-Path` accepts files, directories (`*.json` recursive), or wildcards.
