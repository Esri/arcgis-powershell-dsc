# ArcGIS Pester Tests

These unit tests exercise the checked-out ArcGIS PowerShell module and its internal
Common, Server, Portal, and Data Store modules. They verify configuration conversion,
workflow selection, argument forwarding, request construction, response handling,
and service lifecycle decisions without deploying ArcGIS.

## Prerequisites

- Windows with **Windows PowerShell 5.1** (`powershell.exe`), not PowerShell 7 (`pwsh`).
- **Pester 3.4.0**, the version used to validate this suite. Tests use legacy
  `Should Be`, `Should Throw`, `InModuleScope`, and `Assert-MockCalled` syntax;
  these commands are not a Pester 5 migration guide.
- The normal Windows command modules used by mocked collaborators, including
  service, CIM, and SMB cmdlets. A command generally must be discoverable before
  Pester can mock it; a minimal or non-Windows host may lack these commands.
- A local checkout of this repository. Tests import modules relative to
  `$PSScriptRoot`, so an installed ArcGIS module is not required.

No ArcGIS deployment, installer files, license files, cloud account, live endpoint,
or production credential is needed. The tests are designed for an ordinary user
session rather than an elevated deployment session.

Check the host and available Pester versions in Windows PowerShell:

```powershell
$PSVersionTable.PSVersion
Get-Module -ListAvailable Pester | Select-Object Name, Version, Path
```

If Pester 3.4.0 is missing, install it for the current user according to your
organization's PowerShell Gallery policy:

```powershell
Install-Module Pester -RequiredVersion 3.4.0 -Scope CurrentUser
```

## Run The Tests

Run the following commands from the **repository root**, not from this directory.
From a VS Code terminal running `pwsh`, start `powershell.exe -NoProfile` first;
the new shell inherits the terminal's working directory. A fresh process also
avoids stale modules or mocks from earlier runs.

### Sample Configuration Catalog

The sample catalog check requires no Pester or ArcGIS installation. It parses the v5.2.x samples, checks their naming, README
entries and migration table, and verifies key topology and retired-role
regressions:

```powershell
.\Tests\Validate-SampleConfigs.ps1
```

### Complete Unit Suite

```powershell
Import-Module Pester -RequiredVersion 3.4.0
Invoke-Pester -Script .\Tests\Unit
```

The directory argument discovers the `*.Tests.ps1` files recursively, including
the internal-module suites. Prefer an explicit version import over relying on
whichever Pester installation happens to autoload.

### One Suite Or The Internal Clients

```powershell
Import-Module Pester -RequiredVersion 3.4.0
Invoke-Pester -Script .\Tests\Unit\ArcGIS.OrchestrationAdditional.Tests.ps1
Invoke-Pester -Script .\Tests\Unit\Internal
```

The first command is useful when working on orchestration or backup handling;
the second runs Common and all three REST-client suites.

### Server Upgrade Regression Tests

```powershell
Import-Module Pester -RequiredVersion 3.4.0
Invoke-Pester -Script .\Tests\Unit\ArcGIS_ServerUpgrade.Tests.ps1
```

This suite compiles the checked-out on-premises upgrade configuration into
temporary MOF files without applying DSC. It verifies Velocity and existing server
component mappings, installer features, patch targets, and ordering from installation
through hostname configuration to site upgrade. Mocked resource tests verify
Velocity's port 7143 and component-specific health checks, upgrade state handling,
and error propagation. The checkout's module path is added only during compilation
and restored afterward; no installed ArcGIS module or live server is needed.

### Azure Setup Cleanup Compatibility

```powershell
Import-Module Pester -RequiredVersion 3.4.0
Invoke-Pester -Script .\Tests\ArcGIS_AzureSetupsManager.Tests.ps1
```

This suite uses disposable filesystem fixtures, including long paths, read-only
files, locked files, and directory junctions. It also temporarily enables the cached
.NET legacy path switches to reproduce DSC/WMI host behavior, restoring them after
each case. Cleanup first uses ordinary paths with native PowerShell filesystem
cmdlets. Only paths that raise `PathTooLongException` are retried with the extended
path prefix in one isolated PowerShell background job. This also handles short
roots with long descendants without changing global .NET settings. Other failures
are reported without a long-path retry. The caller waits for completion, forwards
warnings and verbose output, and removes the job. Run this suite in a dedicated
Windows PowerShell 5.1 process.

The cleanup implementation separates path normalization (`Resolve-CleanupPath`),
single-item deletion and verification (`Remove-CleanupItem`), and worker creation
and lifecycle (`Start-LongPathCleanupJob` / `Invoke-LongPathCleanup`).
`Invoke-AdditionalFolderOrFilesToCleanup` coordinates per-item errors and batches
only long-path failures for retry.

### Automation With A Failure Exit Code

Use this block in a dedicated Windows PowerShell process. `-PassThru` exposes the
result object; explicitly exit nonzero when tests fail rather than assuming that
`Invoke-Pester` sets the shell's process exit code. `-Quiet` suppresses normal
Pester progress, and `6>$null` suppresses informational workflow output.

```powershell
$ErrorActionPreference = 'Stop'
Import-Module Pester -RequiredVersion 3.4.0
$result = Invoke-Pester -Script .\Tests\Unit -PassThru -Quiet 6>$null

$result.TestResult |
    Where-Object { -not $_.Passed } |
    Select-Object Describe, Name, FailureMessage |
    Format-List

Write-Output "Total=$($result.TotalCount) Passed=$($result.PassedCount) Failed=$($result.FailedCount) Skipped=$($result.SkippedCount) Pending=$($result.PendingCount)"

if ($result.FailedCount -gt 0) { exit 1 }
```

A valid run should discover the intended suites and have zero failures. Review
unexpected skips, pending tests, or a sudden reduction in total tests rather than
treating a smaller green run as equivalent to complete discovery.

## Suite Map

| Suite | Responsibility |
|---|---|
| [Unit/ArcGIS.Utilities.Tests.ps1](Unit/ArcGIS.Utilities.Tests.ps1) | Exported IPv4/FQDN behavior, component ports, and service-name mappings through the module manifest. |
| [Unit/ArcGIS.Helpers.Tests.ps1](Unit/ArcGIS.Helpers.Tests.ps1) | Object conversion, secret precedence, version validation, target nodes, endpoint selection, Java/Tomcat settings, and proxy arguments. |
| [Unit/ArcGIS.AdditionalHelpers.Tests.ps1](Unit/ArcGIS.AdditionalHelpers.Tests.ps1) | DNS fallback paths, password-provider errors, endpoint priorities, and mocked start/stop/restart transitions. |
| [Unit/ArcGIS.ConfigurationData.Tests.ps1](Unit/ArcGIS.ConfigurationData.Tests.ps1) | DSC node construction, encryption metadata, certificate credentials, Web Adaptor defaults, download sanitization, deduplication, and copy isolation. |
| [Unit/ArcGIS.MainOrchestration.Tests.ps1](Unit/ArcGIS.MainOrchestration.Tests.ps1) | Public configuration workflows from JSON input through install/license/configure, per-node Server machine/TLS settings and failure gates, specialized TLS node selection, Notebook post-install and MSA rules, GeoEvent/Workflow Manager phases, site-level directory registration, WebGISDR, and upgrade dispatch. |
| [Unit/ArcGIS.OrchestrationAdditional.Tests.ps1](Unit/ArcGIS.OrchestrationAdditional.Tests.ps1) | Data Store dispatch and backup rules, component upgrades, per-node Notebook post-install ordering and failure gates, Web Adaptor variants, early failures, and Java/Tomcat validation boundaries. |
| [Unit/ArcGIS.InfrastructureAndPublish.Tests.ps1](Unit/ArcGIS.InfrastructureAndPublish.Tests.ps1) | Service transitions, Notebook SMB mapping, DSC log forwarding, Azure-image jobs, and web/GIS publishing arguments. |
| [Unit/ArcGIS_Disk.Tests.ps1](Unit/ArcGIS_Disk.Tests.ps1) | Mocked partition-growth decisions at the 1 MiB minimum, the reported multi-terabyte partition with a sub-MiB remainder, repeat-run idempotency, and storage-error propagation. No real disk changes. |
| [Unit/ArcGIS_Tomcat.Tests.ps1](Unit/ArcGIS_Tomcat.Tests.ps1) | Machine-scope Java/keytool discovery, JRE fallback, missing executable diagnostics, and absolute keytool paths for keystore creation, certificate import, and DSC compliance. No Java installation or machine environment changes. |
| [Unit/ArcGIS_WebAdaptor.Tests.ps1](Unit/ArcGIS_WebAdaptor.Tests.ps1) | Java configuration idempotency using `InstallLocation\<context>\webadaptor.config` without stripping the `java` directory, repeat checks for Portal and Server, missing/mismatched configuration and overwrite behavior, fresh machine-scope Java configuration environment, Java home precedence and executable validation, child PATH ordering, per-attempt refresh, failure propagation, and unchanged IIS behavior. No ArcGIS deployment, Java installation, or machine environment changes. |
| [Unit/ArcGIS_ServerUpgrade.Tests.ps1](Unit/ArcGIS_ServerUpgrade.Tests.ps1) | Compiled on-premises upgrade component mappings and dependencies, Velocity resource identity and upgrade endpoints, completed/pending states, failure propagation, and existing GIS/specialized dispatch. No DSC application or real upgrades. |
| [Unit/ArcGIS_Service_Account.Tests.ps1](Unit/ArcGIS_Service_Account.Tests.ps1) | GeoEvent password rotation with an empty service install lookup, credentials for both services, local/domain/managed accounts, failure gates before cleanup and restart, resolved cleanup paths, and Test/Set permission consistency. No real service or credential changes. |
| [Unit/Internal/ArcGIS.Common.Tests.ps1](Unit/Internal/ArcGIS.Common.Tests.ps1) | HTTP encoding and response modes, error handling, resource ownership, properties/hosts helpers, and component/process boundaries. |
| [Unit/Internal/ArcGIS.Client.Server.Tests.ps1](Unit/Internal/ArcGIS.Client.Server.Tests.ps1) | Server URL/token contracts, datastore routes/filtering, GP submit/status/result handling, Join Site polling/retry recovery and Video Server version boundaries, settings, certificates, and readiness. |
| [Unit/Internal/ArcGIS.Client.Portal.Tests.ps1](Unit/Internal/ArcGIS.Client.Portal.Tests.ps1) | Portal admin/sharing routes, token options, federation, OAuth serialization, licensing, settings requests, and strict/tolerant certificate response and transport errors. |
| [Unit/Internal/ArcGIS.Client.DataStore.Tests.ps1](Unit/Internal/ArcGIS.Client.DataStore.Tests.ps1) | Configure feature settings and health gates, PITR readiness/response failures, backup CLI store/operation mappings and password redaction, empty/multi-row backup parsing, process failures, and upgrade-state boundaries. |

## How The Fixtures Work

### Module Scope And Mock Boundaries

Most suites import the implementation `.psm1` and execute inside `InModuleScope`
for that module. This gives tests access to private functions and lets mocks
replace the commands resolved by the code under test. The Utilities suite instead
uses the manifest to check exported functions.

Mock the nearest external boundary while leaving the decision under test real.
Examples include `Invoke-DSCJob` for deployment, `Invoke-ArcGISWebRequest` for
client REST calls, and `Invoke-StartProcess` for the Data Store CLI. Assert the
configuration name, URL, HTTP method, arguments, or credentials received there.
Also assert forbidden calls when validation or a failed stage must prevent work.

### HTTP And Ownership

Common HTTP tests replace `New-ArcGISHttpClient` with an in-memory transport
double. It captures real .NET request objects and returns completed response
tasks, so headers, encoding, response modes, and cleanup remain testable without
network traffic. Mocking the old `Invoke-WebRequest` cmdlet would not intercept
this implementation.

A caller-supplied `HttpClient` must remain reusable after success or failure;
request content is a one-use body. Ownership tests check these separately and
dispose their own fixtures in `finally` blocks. Transport fixture state uses
distinct `$script:` names to avoid PowerShell dynamic-scope variable shadowing.

### Mutable Configuration And Dispatch

Orchestration builds a dispatched copy of caller arguments. Tests inspect values
received by `Invoke-DSCJob` and separately verify that the original hashtable
retains its inputs. For multi-node backup tests, the mock copies selected values
at dispatch time; retaining a mutable reference could make earlier calls appear
to contain the final node's settings.

Configuration-data tests also modify a returned nested installer setting to prove
the source configuration is independent. Backup fixtures exercise primary-first
and secondary-first ordering, case-insensitive primary identity, and version
boundaries such as the S3 region requirement starting at Enterprise 11.2.

### Services, Jobs, And Dummy Secrets

Service tests provide queued `Get-Service` states and mock start, stop, and sleep
commands. Call sequences and requested intervals are observable; real elapsed
time and actual Service Control Manager transitions are not tested.

The DSC logging test creates a short local `Start-Job` to obtain genuine verbose
and error records. A small guarded C# `Job2` adapter exposes those child streams
to `Trace-DSCJob`; filesystem writes are mocked and the local job is removed.
This is not a remote DSC job or an ArcGIS process.

Secrets are fixed dummy values. Tests decrypt fixture `SecureString` values via
`PSCredential` to prove source precedence, not merely non-null output. Encrypted
fixture strings are generated under the current Windows user rather than storing
user-bound encrypted blobs in the repository. Never put real credentials in tests.

### Split Server Phases

Notebook install and upgrade cases cover images, sample extraction, MSA accounts,
and the sample-data version boundary. They assert both requested post-install work
and forbidden dispatch when no work is needed or an earlier phase fails. Upgrade
fixtures retain per-node encryption metadata and forward connection options.

Specialized Server TLS fixtures mix nodes with no certificate, a leaf certificate,
and root-only certificates. Only eligible nodes receive the TLS phase; GIS-only
heap, HTTPS-only, and HSTS arguments must not be forwarded to specialized roles.
GeoEvent and Workflow Manager tests verify standalone/additional-role dispatch
and stop later phases after a failed prerequisite or extension.

Join Site tests record requests, mocked polling, retry sleeps, and health checks
in sequence. They verify that initialization polling uses the response's positive
`pollAfter` value or falls back to 60 seconds when it is zero or missing, before
the final readiness checks. The tests do not wait or perform a real join operation.

## Adding Or Maintaining Tests

1. Extend the existing suite that owns the behavior rather than creating a new
   file for every helper. Read the current implementation and neighboring tests.
2. Keep the established Pester 3.4.0 syntax and import the checked-out module.
   Place mocks in the module where the production function resolves its commands.
3. Use realistic but minimal configuration data. Parameterize equivalent sibling
   inputs with `-TestCases`; keep distinct transitions or validation paths explicit.
4. Use fixed expected values and exact request/dispatch checks. Pair error
   assertions with zero forbidden calls when early rejection is part of the contract.
5. Reset mutable fixture state for each case. Use snapshots for changing arguments,
   and clean up any real disposable objects or local jobs a fixture creates.
6. Explain the reason for non-obvious fixture shapes and regression assertions in
   comments. Avoid comments that only repeat a test name or narrate assignments.
7. Run the changed suite first, then the complete unit suite to check module/mocking
   interactions. Do not skip a failing case merely to make the suite green.

## Troubleshooting

### Wrong Host Or Pester Version

PowerShell 7 has different Windows-module availability and runtime behavior.
Use a fresh `powershell.exe -NoProfile` session and import Pester 3.4.0 explicitly.
If the import fails, check the prerequisite commands above before running tests.

### Duplicate ArcGIS Modules Or Real Service/DNS Access

Loading both an installed ArcGIS version and the checked-out implementation can
bypass mocks or cause Pester to report multiple script modules named ArcGIS.
Current lifecycle tests use `Start-ServiceAndWait` and `Stop-ServiceAndWait`.

The AdditionalHelpers suite resolves the checked-out module's full path and removes
competing loaded ArcGIS script modules before importing it. This prevents Pester 3's
name-based `InModuleScope` from seeing multiple implementations. The cleanup changes
the current session's loaded modules, so use a dedicated test process; it does not
restore the removed helper for older deployment scripts.

Inspect loaded modules without looking up obsolete command names:

```powershell
Get-Module ArcGIS -All | Select-Object Name, Path
```

Restart in a fresh process and check that the test calls current helpers from the
checkout. If example.test DNS lookups or real service operations occur, investigate
the mock boundary and module scope; do not install ArcGIS to satisfy a unit fixture.

### JSON Array Assertions On Windows PowerShell 5.1

`ConvertFrom-Json` can emit an array as one pipeline object. Assign its output
directly before checking `Count` or indexing; wrapping it in `@(...)` can add an
extra array level. The Portal OAuth test documents this distinction at its mock
filter. Preserve ordered redirect values, not just the presence of a JSON string.

## Coverage And Limits

Optional Pester coverage for the main implementation can be collected with:

```powershell
Import-Module Pester -RequiredVersion 3.4.0
Invoke-Pester -Script .\Tests\Unit -CodeCoverage .\Modules\ArcGIS\ArcGIS.psm1
```

This reports executed commands in the specified file, not all internal modules
or all DSC resources. No repository-wide coverage target is implied by this guide.
Coverage is useful for locating code to investigate, but meaningful assertions
and complete test discovery remain necessary.

Passing these tests does not validate live ArcGIS REST compatibility, real TLS
handshakes/certificate imports, DSC compilation and remote execution, installer
behavior, cloud connectivity, or actual service restarts. Static .NET calls and
typed Windows boundaries may require separate integration fixtures; command-level
Pester mocks do not intercept every such dependency.