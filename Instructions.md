# Automation for ArcGIS using Windows PowerShell DSC

## Overview
The repository contains scripts, code and samples for automating the install and configuration of ArcGIS Enterprise using Microsoft Windows PowerShell DSC (Desired State Configuration). Sample configuration data json Files for different site topologies of ArcGIS Enterprise can be found SampleConfigs Folder in this Repository.

## Supported OS
1. Windows Server 2012R2 (Limited Support for WMF4, Best Experience if WMF5 installed)
2. Windows Server 2016
3. Windows 8.1 (Limited Support for WMF4, Best Experience if WMF5 installed)
4. Windows 10

**Note** - For client SKUs', run the following commands i.e. Windows 8.1 and 10 to enable Windows PS Remoting.
```
Set-ExecutionPolicy RemoteSigned
winrm quickconfig
```

## Site Topologies
1. Single Machine ArcGIS Enterprise  
	This consists of all ArcGIS Enterprise components (Server, Portal, Data Store (relational), Web Adaptor) running on the same machine.
2. Multi Machine ArcGIS Enterprise  
	This consists of all ArcGIS Enterprise components (Server, Portal, Data Store, Web Adaptor) running on different machine.
3. Single to Multi Machine ArcGIS Server   
	This consists of all 1 to N machines running on ArcGIS Server with optional federation to a portal and an enterprise geodatabase in SQL Server that is registered with the ArcGIS Server site. .
4. Upgrade Enterprise
	This will allow you to upgrade an Enterprise 10.4 deployment to the latest release.
5. Uninstall Enterprise
	This will allow you to uninstall all components of an ArcGIS Enterprise 10.4 deployment.

#### Prerequisite Installation
1. Create a File Share 
	* Create a File Share with Sharing and Security Permissions granted to the Local System Accounts of every Machine in the cluster.
	* Copy the Module, ArcGIS Enterprise Setups (Server, Portal, WebAdaptor, Datastore), Sample Configuration JSON files, SSL Certificates and license files to the File Share.
2. Configure the prerequisites on Target Machine Nodes.
	* Open a PowerShell in the administrator mode on Target Machine Node.
	* Few options to getting started - If used, will have to be done on all Machines.
	* Install ArcGIS Module from PS Gallery on each of the machines and Orchestrating Machine (Coming Soon)
	* Download locally from (\\[File Share Machine Name]\[File Share Name]\Modules\ArcGIS) and copy to ($env:SystemDrive\Program files\WindowsPowerShell\Modules\ArcGIS) on each machines in the cluster and Orchestrating Machine.
	* Run PreReqs.bat (Appendix A) to install and configure the PreReqs on each machine in the cluster and Orchestrating Machine.
3.	Alternatively, use "Install-Prereqs.ps1" (Appendix B) on orchestrating machine and pass in the all the target server machines.
```
Install-Prereqs.ps1 -ServerMachines [Comma separated list of all target machines of the configuration] -ModuleSourcePath [module network address or local path]
```

#### Installation and Configuration, Upgrade or Uninstall of ArcGIS Enterprise
To install, configure, Upgrade or Uninstall a toplogy, use the following steps
1. Copy and edit the Configuration JSON files for your desired topology on the orchestrating machine.
2. Open a PowerShell prompt (in administrator mode) and pass the path of the JSON file (Array of paths in case of multi-site upgrades).
```
Configure-ArcGIS -ConfigurationParametersFile [[Path to Configuration json File]] -Mode [Install | Uninstall | Upgrade] -Credential [Config RunAs - Optional] 
```
or simply,

```
 Configure-ArcGIS [[Path to Configuration json File]] [Install | Uninstall | Upgrade] -Credential [Config RunAs - Optional]
```

#### Sample JSON Configurations
1. Installs and Configures
	* Base Deployment
		- Single Machine
		- Three Machine
		- Min HA
		- Max HA (Needs Testing)
	* GIS Server and Federated Servers
		- General Purpose
		- Geo Analytics
		- Geo Events (Needs Testing)
		- Raster Analytics with its own File Share (Needs Testing)
2. Uninstalls – Uses the same Configuration File used to Install the Site.
3. Upgrades Base Deployments and Federated Sites – Edit the original to Configuration File to replace the old Setup and License Paths with that of the latest version. Add a 'OldVersion' Parameter with the value of the Present Version of the Site in Use and update the ‘Version’ Parameter Value in to reflect the version to which the site is being upgraded to. 

**Note** - SSL Certificates Usage is demonstrated in (BaseDeployment-ThreeMachine-10.6-ssl.json). The extra SslCertifcate block can be added to any of the server or portal block in the given sample JSON Configuration Files.

## Variables - Configuration Parameters JSON File - Accepted Values and Description
* **AllNodes** - AllNodes param in Configuration File contains all the nodes on which the components of ArcGIS Enterprise will be installed.
	* **NodeName** -  Each node is represented by a node name which is a machine name or an IP.  
	* **Role** - Can accept one or muliple value as a comma separated list. Enter in order which you want to execute the roles on the node. Accepted values  are 'Server', 'Portal', 'DataStore', 'ServerWebAdaptor', 'PortalWebAdaptor', 'LoadBalancer', 'RasterDataStoreItem'
	* **DataStoreType** -  Valid parameter when node role is data store. Valid values are 'Relational | SpatioTemporal | TileCache'.
* **Config Data** - This will be common to all the nodes. It contains the following common variables and the configuration variable specific to the roles specified above. 
	* **Version** - The Version of the different components that will be installed or upgraded to.
	* **OldVersion** - To be provided for upgrades, present version of the different components that will be upgraded.
	* **FileShareLocalPath** - Local Path of file share on file share machine
	* **FileShareName** - Name of the file share on the Remote Machine
	* **ServerContext** - Context of the Server WebAdaptor
	* **PortalContext** - Context of the Portal WebAdaptor
	* **ServerRole** - Role value for a specialized GIS Server. Accepted Values are 'GeneralPurposeServer', 'GeoAnalytics', 'GeoEvent', 'RasterAnalytics'.
	* **Credentials**
		* **ServiceAccount** - Windows User which will be used to install and run the different services of the components. Set 'IsDomainAccount' Parameter to 'true' if Service account is a domain account.
		* **PrimarySiteAdmin** - A primary administrator user for different components of ArcGIS Enterprise.
	* **Server**
		* **Installer**
			* **Path** - The path to the installer file that should be installed. 
			* **InstallDir** - The path where the Server component will be installed. 
			* **InstallDirPython** - The path where python dependency required by Server component will be installed.
		* **LicenseFilePath**- The Path where [.pvrc] or [.ecp] license file resides. ("ImageServer","GeoEvent","GeoAnalytics","GeneralPurposeServer")
		* **ConfigStoreLocation** - Either a Local Path in case of Single Machine Deployment otherwise a Network File Share path.
		* **ServerDirectoriesRootLocation** - Either a Local Path in case of Single Machine Deployment otherwise a Network File Share path.
		* **SslCertifcate**
			* **Path** - Path of SSL Certificate - Local or network share address that needs to be installed on the components corresponding WebAdaptor.
			* **Password** - Password of the SSL certificate to be installed
			* **Alias** - Alias with which the certificate will be used.
	* **Portal**
		* **Installer**
			* **Path** - The path to the Installer file that should be installed. 
			* **InstallDir** - The path where the Portal component will be installed. 
			* **ContentDir** - The Path where the initial site will be configured.
		* **LicenseFilePath** - The Path where [.pvrc] or [.ecp] license file resides.
		* **ContentDirectoryLocation** - The path where content of a new site create will be initialized. Generally it is the ContentDir mentioned above in Installer followed by "\arcgisportal\content". Can be a completely independent path as well.
		* **SslCertifcate**
			* **Path** - Path of SSL Certificate - Local or network share address that needs to be installed on the components corresponding WebAdaptor.
			* **Password** - Password of the SSL certificate to be installed
			* **Alias** - Alias with which the certificate will be used.
	* **DataStore**
		* **Installer**
			* **Path** - The path to the installer file that should be installed. 
			* **InstallDir** - The path where the Portal component will be installed. 
		* **ContentDirectoryLocation** - Dir where the data store will be initialized.
		* **ServerHostName** - Server hostname with which the installed datastore will be configured.
	* **DataStoreItems** - Only Raster store is being tested and supported as of now. Will support Folder, CloudStore and BigDataFileShare in the coming releases.  
		* **RasterStore**  
			* **FileShareName** - Name of the Raster file share file share
			* **FileShareLocalPath** - Local path of the Raster file share on a given machine
	* **WebAdaptor**
		* **Installer**
			* **Path** - The path to the installer file that should be installed. 
		* **AdminAccessEnabled** - (Optional) Default value is False. Enables access to Server Manager and Server Admin Directories.
	* **Federation**
		* **PortalHostName** - (Optional) Required when federating specialised server with a remote Portal
		* **PortalPort** - (Optional)  Required when federating specialised server with a remote Portal
		* **PortalContext** - (Optional)  Required when federating specialised server with a remote Portal
		* **PrimarySiteAdmin** - A primary admin user for Portal with which the GIS Site will be federated with.

## Appendix A - Prereqs.bat
``` batch
@echo off

if "%1"=="-h" (
  echo The script installs ArcGIS W=Enterprise on the machine using ArcGIS Setups from Fileshare
  echo Usage: Prereqs.bat [build #] 
  echo With no parameters the script uses the latest setups from Fileshare.
  exit /b
)

set DSC_RESOURCE="[... Module FileShare Path ...]"
set DSC_RESOURCE_TARGET="C:\Program Files\WindowsPowerShell\Modules\ArcGIS"


if not exist %DSC_RESOURCE_TARGET% (
  echo Target path not found.
  md %DSC_RESOURCE_TARGET% 
)

xcopy %DSC_RESOURCE% %DSC_RESOURCE_TARGET% /E /Y

PowerShell.exe -Command "& Set-ExecutionPolicy RemoteSigned -Force;winrm quickconfig -quiet; "
```

## Appendix B - Install-PreReqs.ps1

``` powershell
Param(
    [System.Array]
    $ServerMachines,

    [System.String]
    $ModuleSourcePath
)

$Version = "0.6.0.3"
$OchestratingOS = (Get-WmiObject -Computer $env:computername -Class Win32_OperatingSystem).caption

if($OchestratingOS -match 'Windows Server 2012'){
    $DSC_TARGET = "Program Files\WindowsPowerShell\Modules\ArcGIS"
}elseif($OchestratingOS -match 'Windows Server 2016'){
    $DSC_TARGET = "Program Files\WindowsPowerShell\Modules\ArcGIS\$Version"
}

if(Test-Path "$($env:SystemDrive)\$DSC_TARGET"){
    Remove-Item "$($env:SystemDrive)\$DSC_TARGET" -Force -ErrorAction Ignore -Recurse
}
Copy-Item -Recurse -Path $ModuleSourcePath -Destination "$($env:SystemDrive)\$DSC_TARGET" -Force

foreach($machineName in $ServerMachines) {
    if(-not($machineName -ieq $env:computername)){
        Write-Host "Copying Module to $machineName"
        $RD = (Get-WMIObject -class Win32_OperatingSystem -Computername $machineName).SystemDrive
        $RemoteMachineOS = (Get-WmiObject -Computer $machineName -Class Win32_OperatingSystem).caption
        if($RemoteMachineOS -match 'Windows Server 2012'){
            $DSC_TARGET = "Program Files\WindowsPowerShell\Modules\ArcGIS"
        }elseif($RemoteMachineOS -match 'Windows Server 2016'){
            $DSC_TARGET = "Program Files\WindowsPowerShell\Modules\ArcGIS\$Version"
        }

        $RemoteSystemDrive = $RD.Substring(0,$RD.Length-1)
        if(Test-Path "\\$machineName\$RemoteSystemDrive$\$DSC_TARGET"){
            Remove-Item "\\$machineName\$RemoteSystemDrive$\$DSC_TARGET" -Force -ErrorAction Ignore -Recurse
        }
        Copy-Item $ModuleSourcePath -Destination "\\$machineName\$RemoteSystemDrive$\$DSC_TARGET" -Recurse -Force
    }
}

```