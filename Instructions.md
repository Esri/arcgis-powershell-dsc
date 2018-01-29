# Automation for ArcGIS using Windows PowerShell DSC

## Overview
The repository contains scripts, code and samples for automating the install and configuration of ArcGIS (Enterprise and Desktop) using Microsoft Windows PowerShell DSC (Desired State Configuration).

## Configurations - Configure-ArcGIS
1. **ArcGISConfiguration** 
	Configuration Script to install and configure the following Site Topologies:
	- BaseDeployment
		- SingleMachine
		- SingleMachine-SSL
		- SingleMachine-SQL
		- ThreeMachine
		- ThreeMachine-SSL
		- Min-HA
		- Min-HA-SSL
		- MultiMachine
		- MultiMachine-SSL
	- GISServer
		- GeneralPurpose
		- GeoAnalytics
		- GeoEvents
		- RasterAnalytics-Fileshare
2. **ArcGISUninstall** 
3. **ArcGISUpgrade**
	- BaseDeployment
		- SingleMachine-Upgrade
		- ThreeMachine-Upgrade
		- Min-HA-Upgrade
		- MultiMachine-Upgrade
		- MultiSite-Upgrade 
4. **ArcGISEnterprise**

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
6. Enterprise Builder (StandAlone Configuration)  
	This will install and configuration of ArcGIS Enterprise using the Enterprise Builder.

##### Prerequisite Installation
* Open a PowerShell in the administrator mode and configure the prerequisites. 
	* Install ArcGIS Module from PS Gallery 		
	* For client SKUs' of Windows, run the following commands
		* Set-ExecutionPolicy RemoteSigned
		* winrm quickconfig

	<Table>	
		<tr>
			<th></th>
			<th>Server 2016</th>
			<th>Server 2012</th>
		</tr>
		<tr>
			<td>Ochestrating VM</td>
			<td> 
				<ul> 
					<li>Install-Module ArcGIS</li>
					<li>Install-Prereqs.ps1 -ServerMachines [Comma seperated list of all target machines of the configuration] -ModuleSourcePath [module network address or local path]</li>
				</ul>
			</td>
			<td> 
				<ul> 
					<li>Install-Prereqs.ps1 -ServerMachines [Comma Seperated List of All Target Machines of the Configuration] -ModuleSourcePath [Module Network Address or Local Path]</li>
					<li> Download locally from (\\sgoel\arcgis-windows-automation\Modules\ArcGIS) and copy to (Program files\WindowsPowerShell\Modules\ArcGIS).</li>
					<li>Run PreReqs.bat in the (\\SGOEL\arcgis-windows-automation\BatchFiles\PreReqs.bat) to install and configure the PreReqs.</li>
				</ul>
			</td>
		</tr>
		<tr>
			<td>Target VM</td>
			<td>
				<ul> 
					<li>Install-Module ArcGIS</li>
					<li>Note - Don't need to do anything if Install-Prereqs.ps1 used</li>
				</ul>
			</td>
			<td>
				<ul>
					<li>Download locally from (\\sgoel\arcgis-windows-automation\Modules\ArcGIS) and copy to (Program files\WindowsPowerShell\Modules\ArcGIS).</li>
					<li>Run PreReqs.bat in the (\\SGOEL\arcgis-windows-automation\BatchFiles\PreReqs.bat) to install and configure the prerequisites.	</li>
					<li>Note - Don't need to do anything if "Install-Prereqs.ps1" used</li>
				</ul>
			</td>
		</tr>
		<tr>
			<td>File Share</td>
			<td colspan=2>Contains all install and configure resources for ArcGIS Enterprise </td>
		</tr>
	</Table>

##### Installation and Configuration or Uninstall of ArcGIS Enterprise
To install and configure a toplogy, use the following steps

* Copy and edit the input json files for your desired topology on the ochestrating machine.
* Open a PowerShell prompt (in administrator mode) and pass the path of the json file (Array of paths in case of multi site upgrades).
	
    ``` 
    Configure-ArcGIS.ps1 -ConfigurationParametersFile [[Path to Configuration json File]] -Mode [Install | Uninstall | Upgrade] -Credential [Config RunAs - Optional] 
    ```
    or simply,
	``` 
    Configure-ArcGIS.ps1 [[Path to Configuration json File]] [Install | Uninstall | Upgrade] -Credential [Config RunAs - Optional]
    ```

## Variables - Configuration Parameters JSON File - Accepted Values and Description
* **AllNodes** - AllNodes param in Configuration File contains all the nodes on which the components of ArcGIS Enterprise will be installed.
	* **NodeName** -  Each node is represented by a node name which is a machine name or an IP.  
	* **Role** - Can accept one or muliple value as a comma separated list. Enter in order which you want to execute the roles on the node. Accepted values  are 'Server', 'Portal', 'DataStore', 'ServerWebAdaptor', 'PortalWebAdaptor', 'LoadBalancer'
	* **DataStoreType** -  Valid parameter when node role is data store. Valid values are 'Relational | SpatioTemporal | TileCache'.
	* **PSDscAllowPlainTextPassword** - Is required to be true whenever we are not providing a certificate and using plain text passwords.
* **Config Data** - This will be common to all the nodes. It contains the following common variables and the configuration variable specific to the roles specified above. 
	* **Version** - The Version of the different components that will be installed or upgraded to.
	* **OldVersion** - To be provided for upgrades, present version of the different components that will be upgraded.
	* **FileShareLocalPath** - Local Path of file share on file share machine
	* **FileShareName** - Name of the file share on the Remote Machine
	* **ServerContext** - Context of the Server WebAdaptor
	* **PortalContext** - Context of the Portal WebAdaptor
	* **ServerRole** - Role value for a specialized GIS Server.
	* **Credentials**
		* **ServiceAccount** - Windows User which will be used to install and run the different services of the components.
		* **PrimarySiteAdmin** - A primary administrator user for different components of ArcGIS Enterprise.
	* **Server**
		* **Installer**
			* **Path** - The path to the installer file that should be installed. 
			* **InstallDir** - The path where the Server component will be installed. 
			* **InstallDirPython** - The path where python dependency required by Server component will be installed.
		* **LicenseFilePath**- The Path where .pvrc license file resides. ("ImageServer","GeoEvent","GeoAnalytics","GeneralPurposeServer")
		* **ConfigStoreLocation** - A Path
		* **ServerDirectoriesRootLocation** - A Path
		* **SslCertifcate**
			* **Path** - Path of SSL Certificate - Local or network share address that needs to be installed on the components corresponding WebAdaptor.
			* **Password** - Password of the SSL certificate to be installed
			* **Alias** - Alias with which the certificate will be used.
	* **Portal**
		* **Installer**
			* **Path** - The path to the Installer file that should be installed. 
			* **InstallDir** - The path where the Portal component will be installed. 
			* **ContentDir** - The Path where the initial site will be configured.
		* **LicenseFilePath** - The Path where .pvrc license file resides.
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
	* **DataStoreItems** - Only Raster store is tested. Supports Folder, CloudStore and BigDataFileShare as well.  
		* **RasterStore**  
			* **FileShareName** - Name of the Raster file share file share
			* **FileShareLocalPath** - Local path of the Raster file share on a given machine
	* **WebAdaptor**
		* **Installer**
			* **Path** - The path to the installer file that should be installed. 
	* **Federation**
		* **PortalHostName** - (Optional) Required when federating specialised server with a remote Portal
		* **PortalPort** - (Optional)  Required when federating specialised server with a remote Portal
		* **PortalContext** - (Optional)  Required when federating specialised server with a remote Portal
		* **PrimarySiteAdmin** - A primary admin user for Portal with which the GIS Site will be federated with.