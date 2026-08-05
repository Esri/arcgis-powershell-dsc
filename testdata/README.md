# Invalid DSC config fixtures

Intentionally broken JSON for local negative checks of `Test-ArcGISConfigurationJson.ps1`. Not for `Invoke-ArcGISConfiguration`.

Point the validator at this folder; module rules report the issues (folder run expects exit code 1 because of invalid fixtures):

```powershell
.\ConfigurationSchemas\Test-ArcGISConfigurationJson.ps1 -Path .\testdata
.\ConfigurationSchemas\Test-ArcGISConfigurationJson.ps1 -Path .\testdata\sampleconfigs\v5.1.0 -Version 5.1.0
.\ConfigurationSchemas\Test-ArcGISConfigurationJson.ps1 -Path .\testdata\sampleconfigs\v5.1.1
```

Directories expand recursively (`testdata\**\*.json`).

## Minimal fixtures

| File | Typical findings |
|------|------------------|
| `invalid-deprecated-desktop.json` | `AllNodes` role `Desktop`; `ConfigData.DesktopVersion` |
| `invalid-deprecated-insights.json` | `ConfigData.InsightsVersion`; `ConfigData.OldInsightsVersion` |
| `invalid-deprecated-insights-block.json` | `ConfigData.Insights`; `Insights.Installer.Path` / `IsSelfExtracting` |
| `invalid-webadaptor-adminaccess.json` | `ConfigData.WebAdaptor.AdminAccessEnabled` ignored note |
| `invalid-webadaptorconfig-adminaccess.json` | `AllNodes.WebAdaptorConfig.AdminAccessEnabled` ignored note |
| `invalid-geoevent-federation.json` | GeoEvent + `Federation` block |
| `invalid-additional-geoevent.json` | `GeoEvent` in `AdditionalServerRoles` |
| `invalid-allnodes.json` | Duplicate `NodeName`; empty `Role` |
| `invalid-allnodes-blank-role.json` | Blank `Role`; unnamed node with empty `Role` |
| `invalid-malformed.json` | Invalid JSON (trailing comma) |
| `valid-minimal.json` | Passes module rules (positive control) |

## SampleConfig-based fixtures

Derived from `SampleConfigs/v5/v5.1.0/` and `SampleConfigs/v5/v5.1.1/` with invalid data injected (placeholder style preserved). Schema `$schema` points at the matching `ConfigurationSchemas/vX.Y.Z.json`.

v5.1.0 and v5.1.1 folders intentionally use **different sample bases and invalid injections** (not schema-only copies), so pin-specific runs exercise distinct shapes.

| File | Based on | Typical findings |
|------|----------|------------------|
| `sampleconfigs/v5.1.0/BaseDeployment-SingleMachine-invalid-desktop.json` | `v5.1.0/Base Deployment/BaseDeployment-SingleMachine.json` | Desktop role; `DesktopVersion`; `WebAdaptor.AdminAccessEnabled` |
| `sampleconfigs/v5.1.0/BaseDeployment-DualMachine-invalid-allnodes.json` | `v5.1.0/Base Deployment/BaseDeployment-DualMachine.json` | Duplicate `NodeName`; empty `Role`; `WebAdaptor.AdminAccessEnabled` |
| `sampleconfigs/v5.1.0/GISServer-GeoEvent-invalid-federation.json` | `v5.1.0/Gis Servers/GISServer-GeoEvent.json` | GeoEvent + `Federation` |
| `sampleconfigs/v5.1.0/GISServer-GeneralPurpose-MultiServerRoles-invalid-geoevent.json` | `v5.1.0/Gis Servers/GISServer-GeneralPurpose-MultiServerRoles.json` | `Geoevent` in `AdditionalServerRoles` |
| `sampleconfigs/v5.1.0/GISServer-GeneralPurpose-invalid-insights.json` | `v5.1.0/Gis Servers/GISServer-GeneralPurpose.json` | `InsightsVersion`; `OldInsightsVersion` |
| `sampleconfigs/v5.1.1/BaseDeployment-ThreeMachine-invalid-desktop.json` | `v5.1.1/Base Deployment/BaseDeployment-ThreeMachine.json` | Desktop role; `DesktopVersion`; `WebAdaptor` / `WebAdaptorConfig` `AdminAccessEnabled` |
| `sampleconfigs/v5.1.1/BaseDeployment-MultiMachine-invalid-allnodes.json` | `v5.1.1/Base Deployment/BaseDeployment-MultiMachine.json` | Duplicate `NodeName`; empty `Role`; `WebAdaptor` / `WebAdaptorConfig` `AdminAccessEnabled` |
| `sampleconfigs/v5.1.1/GISServer-GeoEvent-invalid-federation.json` | `v5.1.1/Gis Servers/GISServer-GeoEvent.json` (dual-node WA variant) | GeoEvent + `Federation`; WA `AdminAccessEnabled` |
| `sampleconfigs/v5.1.1/BaseDeployment-SingleMachine-MultipleServerRoles-invalid-geoevent.json` | `v5.1.1/Base Deployment/BaseDeployment-SingleMachine-MultipleServerRoles.json` | `Geoevent` in `AdditionalServerRoles` (as in sample) |
| `sampleconfigs/v5.1.1/GISServer-GeneralPurpose-invalid-insights-block.json` | `v5.1.1/Gis Servers/GISServer-GeneralPurpose.json` | `ConfigData.Insights` installer block (not flat Insights version keys) |
