# v5.2.x sample configurations

These are templates for the ArcGIS PowerShell DSC module, not ready-to-run
deployments. Choose the topology closest to your environment, copy the JSON,
and replace the bracketed placeholders, example credentials, paths, and
optional values. Some placeholders describe choices in a string: replace them
with the actual JSON type (for example, `true`, not `"true"`). Remove optional
blocks that do not apply. Check component, licensing, and platform
compatibility for the ArcGIS version you are deploying.

Run the module on Windows PowerShell 5.1. For example:

```powershell
Import-Module ArcGIS
$cred = Get-Credential
Invoke-ArcGISConfiguration -ConfigurationParametersFile @('C:\configs\base.json') `
    -Mode InstallLicenseConfigure -Credential $cred -UseSSL -DebugSwitch
```

`-UseSSL` configures WinRM over HTTPS; configure WinRM and credentials for the
target machines first. `Install`, `InstallLicense`, `Uninstall`, and `Upgrade`
are also supported modes. Upgrade can require multiple configuration files;
use the configs for the actual components and versions being upgraded.

Treat all examples as sensitive after customization. Prefer password files or
machine-level environment variables to plaintext passwords. Password files are
PowerShell secure-string files, not arbitrary plaintext. The module resolves
`PasswordEnvironmentVariableName` on the machine running the orchestration;
set the named machine-level variables there. For encrypted DSC credentials,
configure both `TargetNodeEncryptionCertificateFilePath` and
`TargetNodeEncryptionCertificateThumbprint` on each target node; without them,
the module permits plaintext passwords in DSC configuration data.

The [configuration schema](../../../ConfigurationSchemas/README.md) provides
editor assistance for deployment configurations, but does not replace runtime
validation. These templates contain placeholders and may not validate against
the schema until customized; the publishing file has a different format. The
v5.2.0 schema currently enumerates Enterprise versions through 12.1, while the
cloud relational example describes an option introduced at 12.2.

## Sample naming

The folder identifies the category; filenames use PascalCase segments separated
by hyphens to describe the topology, server role, licensing type, or
distinguishing feature. Base deployment and server site filenames start with
the machine count, followed by the server role where relevant and then any
distinguishing features. The count includes every node in the template, even
if some are dedicated to supporting roles; it does not restrict how many nodes
a customized deployment can have. Workflow and Pro samples use descriptive
names instead of topology prefixes.

## Base deployments

Multi-machine examples require appropriate shared paths, DNS, load balancers,
certificates, and network access for the chosen topology.

| Sample | Description |
| --- | --- |
| [SingleMachine.json](Base%20Deployment/SingleMachine.json) | Server, Portal, Data Store, and IIS Web Adaptors on one machine; includes optional downloads and WebGISDR settings. |
| [ThreeMachine-PortalAndServerPairs.json](Base%20Deployment/ThreeMachine-PortalAndServerPairs.json) | Two Server/Portal machines plus a separate Data Store machine, with a file share and Web Adaptors. |
| [ThreeMachine.json](Base%20Deployment/ThreeMachine.json) | Separate Data Store, Portal, and Server machines, with IIS Web Adaptors alongside Portal and Server. |
| [NineMachine.json](Base%20Deployment/NineMachine.json) | Distributed Server and Portal pairs, separate Web Adaptor machines, a file share, and separate relational and object-store nodes. |
| [NineMachine-InternalLoadBalancer.json](Base%20Deployment/NineMachine-InternalLoadBalancer.json) | Similar distributed topology with internal load balancer settings for Portal and Server. |
| [SingleMachine-JavaWebAdaptor.json](Base%20Deployment/SingleMachine-JavaWebAdaptor.json) | Single-machine base deployment with Java Web Adaptors and Apache Tomcat settings. |
| [ThreeMachine-JavaWebAdaptor.json](Base%20Deployment/ThreeMachine-JavaWebAdaptor.json) | Separate Data Store, Portal, and Server machines with a Java Web Adaptor and Tomcat on each Portal and Server machine. |
| [SingleMachine-MultipleIISWebAdaptors.json](Base%20Deployment/SingleMachine-MultipleIISWebAdaptors.json) | Single-machine base deployment with multiple IIS Web Adaptor contexts. |
| [SingleMachine-MultipleServerRoles.json](Base%20Deployment/SingleMachine-MultipleServerRoles.json) | Base deployment with additional Server roles on the same machine. |
| [SingleMachine-ObjectStore.json](Base%20Deployment/SingleMachine-ObjectStore.json) | Single-machine base deployment with relational and ArcGIS object data stores. |
| [SingleMachine-CloudObjectStore.json](Base%20Deployment/SingleMachine-CloudObjectStore.json) | Single-machine base deployment with a registered cloud object store and relational Data Store. |
| [SingleMachine-CloudRelationalDataStore.json](Base%20Deployment/SingleMachine-CloudRelationalDataStore.json) | Cloud relational Data Store and registered cloud object store; the cloud relational option is marked for Enterprise 12.2 and later. |
| [SingleMachine-CloudStore.json](Base%20Deployment/SingleMachine-CloudStore.json) | Cloud storage account settings for Server configuration store and directories and Portal content. |
| [ThreeMachine-GraphStore.json](Base%20Deployment/ThreeMachine-GraphStore.json) | Single-machine base deployment plus two separate graph-store nodes. |
| [ThreeMachine-PerNodeLicenses.json](Base%20Deployment/ThreeMachine-PerNodeLicenses.json) | Three-machine base deployment with per-node license settings. |
| [ThreeMachine-PerNodeSSL.json](Base%20Deployment/ThreeMachine-PerNodeSSL.json) | Separate Data Store, Server/Web Adaptor, and Portal/Web Adaptor nodes with per-node certificates. |
| [ThreeMachine-SeparateWebAdaptor-PerNodeSSL.json](Base%20Deployment/ThreeMachine-SeparateWebAdaptor-PerNodeSSL.json) | Server/Data Store, Web Adaptor, and Portal on separate nodes with component-specific certificates and certificate chains. |
| [SingleMachine-AWSCloudServices.json](Base%20Deployment/SingleMachine-AWSCloudServices.json) | Base deployment with AWS cloud service and Portal cloud-content settings. |
| [SingleMachine-AzureCloudServices.json](Base%20Deployment/SingleMachine-AzureCloudServices.json) | Base deployment with Azure cloud service and Portal cloud-content settings. |

For Java Web Adaptors, choose a supported `JavaWebServerType` and Tomcat version
for the Enterprise release. The new three-machine example uses Tomcat 10:
the module requires Tomcat 9 before Enterprise 11.5, permits 9 or 10 at 11.5,
and requires 10 after 11.5. Its installer, Tomcat, and webapps paths must be
valid on both Web Adaptor machines, and each requires an appropriate HTTPS
certificate. Adjust the configuration to match your deployment.

## Additional server sites

Federated examples reference an existing Portal; customize federation and
licensing settings before use.

| Sample | Description |
| --- | --- |
| [SingleMachine-GeneralPurpose.json](Gis%20Servers/SingleMachine-GeneralPurpose.json) | Single-machine general-purpose Server site with federation settings. |
| [ThreeMachine-GeneralPurpose.json](Gis%20Servers/ThreeMachine-GeneralPurpose.json) | Three-machine general-purpose Server site with a shared file location. |
| [SingleMachine-GeneralPurpose-MultipleServerRoles.json](Gis%20Servers/SingleMachine-GeneralPurpose-MultipleServerRoles.json) | General-purpose Server with additional roles and a raster data store item. |
| [ThreeMachine-GeneralPurpose-MultiWebAdaptorContexts.json](Gis%20Servers/ThreeMachine-GeneralPurpose-MultiWebAdaptorContexts.json) | Server and multiple Web Adaptors with multiple contexts. |
| [SingleMachine-GeneralPurpose-Database.json](Gis%20Servers/SingleMachine-GeneralPurpose-Database.json) | General-purpose Server with SQL Server client and database configuration. |
| [SingleMachine-DataPipelinesServer.json](Gis%20Servers/SingleMachine-DataPipelinesServer.json) | Data Pipelines Server and Web Adaptor. |
| [SingleMachine-GeoEnrichmentServer.json](Gis%20Servers/SingleMachine-GeoEnrichmentServer.json) | General-purpose Server with the GeoEnrichment Server role and Web Adaptor. |
| [SingleMachine-GeoEventServer.json](Gis%20Servers/SingleMachine-GeoEventServer.json) | GeoEvent Server and Web Adaptor. |
| [SingleMachine-KnowledgeServer.json](Gis%20Servers/SingleMachine-KnowledgeServer.json) | Knowledge Server and Web Adaptor. |
| [SingleMachine-MissionServer.json](Gis%20Servers/SingleMachine-MissionServer.json) | Mission Server and Web Adaptor. |
| [SingleMachine-NotebookServer.json](Gis%20Servers/SingleMachine-NotebookServer.json) | Single-machine Notebook Server and Web Adaptor. |
| [TwoMachine-NotebookServer.json](Gis%20Servers/TwoMachine-NotebookServer.json) | Two-machine Notebook Server site with a file share and Web Adaptor. |
| [SingleMachine-RasterAnalytics-RasterFileShare.json](Gis%20Servers/SingleMachine-RasterAnalytics-RasterFileShare.json) | Raster Analytics Server with a raster file-share item and Web Adaptor. |
| [SingleMachine-RealityServer-RasterFileShare.json](Gis%20Servers/SingleMachine-RealityServer-RasterFileShare.json) | Reality Server with a raster file-share item and Web Adaptor. |
| [SingleMachine-RasterAnalytics-DataStoreItems.json](Gis%20Servers/SingleMachine-RasterAnalytics-DataStoreItems.json) | Raster Analytics Server with examples of folder, raster, big data, and cloud store registrations. |
| [SingleMachine-VelocityServer.json](Gis%20Servers/SingleMachine-VelocityServer.json) | Velocity Server with federation settings. |
| [SingleMachine-VideoServer.json](Gis%20Servers/SingleMachine-VideoServer.json) | Video Server and Web Adaptor. |
| [SingleMachine-WorkflowManagerServer.json](Gis%20Servers/SingleMachine-WorkflowManagerServer.json) | Workflow Manager Server and Web Adaptor. |

## ArcGIS Pro and License Manager

| Sample | Description |
| --- | --- |
| [LicenseManager.json](Pro/LicenseManager.json) | Standalone License Manager installation and licensing. |
| [ConcurrentUse.json](Pro/ConcurrentUse.json) | Pro machines using concurrent-use licensing with a License Manager node. The module limits concurrent-use Pro to version 3.6 or earlier. |
| [NamedUser.json](Pro/NamedUser.json) | Pro installation with named-user licensing. |
| [SingleUse.json](Pro/SingleUse.json) | Pro installation with single-use licensing and a Data Interoperability extension example. |

## Other workflows

| Sample | Description |
| --- | --- |
| [WebGISDR.json](Base%20Deployment/WebGISDR.json) | Portal-only input for WebGISDR import or export on an existing deployment. |
| [PublishGISService.json](Gis%20Servers/PublishGISService.json) | Input to `Invoke-PublishGISService`, not `Invoke-ArcGISConfiguration`; lists services and Portal/Server publishing endpoints. |

For WebGISDR, prepare the WebGISDR properties file separately, then use the
same JSON with `-Mode WebGISDRExport` or `-Mode WebGISDRImport`. The run-as
account cannot be an MSA. The properties file and Portal installation directory
must be accessible on the Portal machine.

## Filename migration

Sample paths have changed. Update external links, scripts, and commands that
reference the old paths; compatibility copies are not provided. The table covers
every v5.2.x JSON sample, including unchanged paths. Names are relative to this
directory; the JSON contents did not change as part of the renaming.

| Previous path | Current path |
| --- | --- |
| `Base Deployment/BaseDeployment-SingleMachine.json` | `Base Deployment/SingleMachine.json` |
| `Base Deployment/BaseDeployment-DualMachine.json` | `Base Deployment/ThreeMachine-PortalAndServerPairs.json` |
| `Base Deployment/BaseDeployment-ThreeMachine.json` | `Base Deployment/ThreeMachine.json` |
| `Base Deployment/BaseDeployment-MultiMachine.json` | `Base Deployment/NineMachine.json` |
| `Base Deployment/BaseDeployment-MultiMachine-InternalLoadBalancer.json` | `Base Deployment/NineMachine-InternalLoadBalancer.json` |
| `Base Deployment/BaseDeployment-SingleMachine-Java-WA.json` | `Base Deployment/SingleMachine-JavaWebAdaptor.json` |
| `Base Deployment/BaseDeployment-ThreeMachine-Java-WA.json` | `Base Deployment/ThreeMachine-JavaWebAdaptor.json` |
| `Base Deployment/BaseDeployment-SingleMachine-MultipleIIS-WA.json` | `Base Deployment/SingleMachine-MultipleIISWebAdaptors.json` |
| `Base Deployment/BaseDeployment-SingleMachine-MultipleServerRoles.json` | `Base Deployment/SingleMachine-MultipleServerRoles.json` |
| `Base Deployment/BaseDeployment-SingleMachine-ObjectStore.json` | `Base Deployment/SingleMachine-ObjectStore.json` |
| `Base Deployment/BaseDeployment-SingleMachine-CloudObjectStore.json` | `Base Deployment/SingleMachine-CloudObjectStore.json` |
| `Base Deployment/BaseDeployment-SingleMachine-CloudRelationalDataStore.json` | `Base Deployment/SingleMachine-CloudRelationalDataStore.json` |
| `Base Deployment/BaseDeployment-SingleMachine-CloudStore.json` | `Base Deployment/SingleMachine-CloudStore.json` |
| `Base Deployment/BaseDeployment-SingleMachine-GraphStore.json` | `Base Deployment/ThreeMachine-GraphStore.json` |
| `Base Deployment/BaseDeployment-ThreeMachine-per-node-licenses.json` | `Base Deployment/ThreeMachine-PerNodeLicenses.json` |
| `Base Deployment/BaseDeployment-ThreeMachine-ssl-per-Node-Example1.json` | `Base Deployment/ThreeMachine-PerNodeSSL.json` |
| `Base Deployment/BaseDeployment-ThreeMachine-ssl-per-Node-Example2.json` | `Base Deployment/ThreeMachine-SeparateWebAdaptor-PerNodeSSL.json` |
| `Base Deployment/arcgis-enterprise-with-cloud-services-aws.json` | `Base Deployment/SingleMachine-AWSCloudServices.json` |
| `Base Deployment/arcgis-enterprise-with-cloud-services-azure.json` | `Base Deployment/SingleMachine-AzureCloudServices.json` |
| `Gis Servers/GISServer-GeneralPurpose.json` | `Gis Servers/SingleMachine-GeneralPurpose.json` |
| `Gis Servers/GISServer-GeneralPurpose-MultiMachine.json` | `Gis Servers/ThreeMachine-GeneralPurpose.json` |
| `Gis Servers/GISServer-GeneralPurpose-MultiServerRoles.json` | `Gis Servers/SingleMachine-GeneralPurpose-MultipleServerRoles.json` |
| `Gis Servers/GISServer-GeneralPurpose-MultipleWA-MultiContext.json` | `Gis Servers/ThreeMachine-GeneralPurpose-MultiWebAdaptorContexts.json` |
| `Gis Servers/GISServer-Database.json` | `Gis Servers/SingleMachine-GeneralPurpose-Database.json` |
| `Gis Servers/GISServer-DataPipelines.json` | `Gis Servers/SingleMachine-DataPipelinesServer.json` |
| `Gis Servers/GISServer-GeoEnrichmentServer.json` | `Gis Servers/SingleMachine-GeoEnrichmentServer.json` |
| `Gis Servers/GISServer-GeoEvent.json` | `Gis Servers/SingleMachine-GeoEventServer.json` |
| `Gis Servers/GISServer-KnowledgeServer.json` | `Gis Servers/SingleMachine-KnowledgeServer.json` |
| `Gis Servers/GISServer-Mission.json` | `Gis Servers/SingleMachine-MissionServer.json` |
| `Gis Servers/GISServer-Notebook.json` | `Gis Servers/SingleMachine-NotebookServer.json` |
| `Gis Servers/GISServer-Notebook-MultiMachine.json` | `Gis Servers/TwoMachine-NotebookServer.json` |
| `Gis Servers/GISServer-RasterAnalytics-RasterFileShare.json` | `Gis Servers/SingleMachine-RasterAnalytics-RasterFileShare.json` |
| `Gis Servers/GISServer-RealityServer-RasterFileShare.json` | `Gis Servers/SingleMachine-RealityServer-RasterFileShare.json` |
| `Gis Servers/GISServer-ServerDataStoreItems.json` | `Gis Servers/SingleMachine-RasterAnalytics-DataStoreItems.json` |
| `Gis Servers/GISServer-Velocity.json` | `Gis Servers/SingleMachine-VelocityServer.json` |
| `Gis Servers/GISServer-VideoServer.json` | `Gis Servers/SingleMachine-VideoServer.json` |
| `Gis Servers/GISServer-WorkflowManager.json` | `Gis Servers/SingleMachine-WorkflowManagerServer.json` |
| `Pro/LicenseManager-Standalone.json` | `Pro/LicenseManager.json` |
| `Pro/Pro-Concurrent.json` | `Pro/ConcurrentUse.json` |
| `Pro/Pro-Named.json` | `Pro/NamedUser.json` |
| `Pro/Pro-SingleUse.json` | `Pro/SingleUse.json` |
| `PublishGISService.json` | `Gis Servers/PublishGISService.json` |
| `WebGISDR.json` | `Base Deployment/WebGISDR.json` |
