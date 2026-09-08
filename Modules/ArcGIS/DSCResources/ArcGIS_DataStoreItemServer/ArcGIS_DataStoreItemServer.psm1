$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.Server.psm1'))

function Get-TargetResource {
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param(
		[parameter(Mandatory = $true)]
		[System.String]
		$Name,

		[parameter(Mandatory = $true)]
		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

		[parameter(Mandatory = $false)]
		[System.String]
		$ServerHostName,

		[parameter(Mandatory = $false)]
		[System.String]
		$ServerHostPort = 6443,

		[parameter(Mandatory = $false)]
		[System.String]
		$ServerSiteName = 'arcgis',

		[parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

		[parameter(Mandatory = $true)]
		[System.String]
		[ValidateSet("Folder", "CloudStore", "RasterStore", "BigDataFileShare", "ObjectStore", "TileCache")]
		$DataStoreType,

		[System.String]
		$ConnectionString,

		[System.Management.Automation.PSCredential]
		$ConnectionSecret,

		[System.Boolean]
		$ForceUpdate = $false
	)

	@{}
}

function Set-TargetResource {
	[CmdletBinding()]
	param(
		[parameter(Mandatory = $true)]
		[System.String]
		$Name,

		[parameter(Mandatory = $true)]
		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

		[parameter(Mandatory = $false)]
		[System.String]
		$ServerHostName,

		[parameter(Mandatory = $false)]
		[System.String]
		$ServerHostPort = 6443,

		[parameter(Mandatory = $false)]
		[System.String]
		$ServerSiteName = 'arcgis',

		[parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

		[parameter(Mandatory = $true)]
		[System.String]
		[ValidateSet("Folder", "CloudStore", "RasterStore", "BigDataFileShare", "ObjectStore", "TileCache")]
		$DataStoreType,

		[System.String]
		$ConnectionString,

		[parameter(Mandatory = $false)]
		[System.Management.Automation.PSCredential]
		$ConnectionSecret,

		[parameter(Mandatory = $false)]
		[System.Boolean]
		$ForceUpdate = $false
	)
	
	[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	$FQDN = if ($ServerHostName) { Get-FQDN $ServerHostName }else { Get-FQDN $env:COMPUTERNAME }
	$ServerBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName "Server" -Port $ServerHostPort -FQDN $FQDN -Context $ServerSiteName
	Write-Verbose "ServerBaseURL:- $ServerBaseUrl"
	$Referer = 'https://localhost'
	$token = Get-ServerToken -URL $ServerBaseUrl -Credential $SiteAdministrator -Referer $Referer 
	
	if($Ensure -ieq 'Present') {
		# Get Data Store Item Connection Object
		$DataStoreItemConnectionObject = Get-DataStoreItemConnectionObject -ItemName $Name -DataStoreType $DataStoreType -ConnectionString $ConnectionString -ConnectionSecret $ConnectionSecret
		# Validate Data Store Item Connection
		try{
			Invoke-DataStoreItemOperation -URL $ServerBaseUrl -Token $token.token -Referer $Referer -ConnectionObject $DataStoreItemConnectionObject -OperationName "validateDataItem" -Verbose
		}catch{
			throw "Validation of Data Store Item Connection failed."
		}
		
		$DataStoreItems = Get-DsItems -ItemName $Name -ServerBaseUrl $ServerBaseUrl -Token $token.token -Referer $Referer -DataStoreType $DataStoreType
		if(($DataStoreItems| Measure-Object).Count -gt 0){
			# Edit Data Store Item Connection
			Invoke-DataStoreItemOperation -URL $ServerBaseUrl -Token $token.token -Referer $Referer -ConnectionObject $DataStoreItemConnectionObject -OperationName "edit" -Verbose
		}else{
			# Register Data Store Item
			Invoke-DataStoreItemOperation -URL $ServerBaseUrl -Token $token.token -Referer $Referer -ConnectionObject $DataStoreItemConnectionObject -OperationName "registerItem" -Verbose
		}
		
	}elseif($Ensure -ieq 'Absent') {
		$DSItem = Get-DsItems -ItemName $Name -ServerBaseUrl $ServerBaseUrl -Token $token.token -Referer $Referer -DataStoreType $DataStoreType
		if(($DSItem| Measure-Object).Count -gt 0){
			Invoke-DataStoreItemOperation -URL $ServerBaseUrl -Token $token.token -Referer $Referer -DataStoreItemPath $DSItem.Path -Force $true -OperationName "unregisterItem" -Verbose
		}
	}
}



function Test-TargetResource {

	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param(
		[parameter(Mandatory = $true)]
		[System.String]
		$Name,

		[parameter(Mandatory = $true)]
		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

		[parameter(Mandatory = $false)]
		[System.String]
		$ServerHostName,

		[parameter(Mandatory = $false)]
		[System.String]
		$ServerHostPort = 6443,

		[parameter(Mandatory = $false)]
		[System.String]
		$ServerSiteName = 'arcgis',

		[parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

		[parameter(Mandatory = $true)]
		[System.String]
		[ValidateSet("Folder", "CloudStore", "RasterStore", "BigDataFileShare","ObjectStore", "TileCache")]
		$DataStoreType,

		[System.String]
		$ConnectionString,

		[System.Management.Automation.PSCredential]
		$ConnectionSecret,

		[System.Boolean]
		$ForceUpdate = $false
	)

	[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	$result = $false
	$FQDN = if ($ServerHostName) { Get-FQDN $ServerHostName }else { Get-FQDN $env:COMPUTERNAME }
	$ServerBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName "Server" -Port $ServerHostPort -FQDN $FQDN -Context $ServerSiteName
	Write-Verbose "ServerBaseURL:- $ServerBaseUrl"
	$Referer = 'https://localhost'
	
	$token = Get-ServerToken -URL $ServerBaseUrl  -Credential $SiteAdministrator -Referer $Referer 
	
	if($Ensure -ieq "Present" -and $DataStoreType -ieq "TileCache"){
		throw "TileCache Data Store registration is not supported in ArcGIS_DataStoreItemServer. Please use the ArcGIS_DataStore resource to register TileCache Data Store."
	}
	
	$DataStoreItems = Get-DsItems -ItemName $Name -ServerBaseUrl $ServerBaseUrl -Token $token.token -Referer $Referer -DataStoreType $DataStoreType
	if(($DataStoreItems| Measure-Object).Count -gt 0){
		if($ForceUpdate -and $Ensure -ieq 'Present'){
			Write-Verbose "$DataStoreType DataStore Item with name '$Name' exists. Force Update specified."
		}else{
			Write-Verbose "$DataStoreType DataStore Item with name '$Name' exists."
			$result = $true
		}
	}
	else {
		Write-Verbose "$DataStoreType DataStore Item with name '$Name' does not exist"
	}

	if($Ensure -ieq 'Present') {
        $result
    }elseif($Ensure -ieq 'Absent') {        
        -not($result)
    }
}

function Get-DsItems
{
	param(
		[System.String]
		$ItemName,

		[System.String]
		$ServerBaseUrl,
		
		[System.String]
		$Token,

		[System.String]
		$Referer,

		[System.String]
		$DataStoreType
	)
	if($ItemName -ieq "TileCache" -or $ItemName -ieq "OzoneObjectStore"){
		return @(Find-DataItems -URL $ServerBaseUrl -Token $Token -Type $DataStoreType -IsArcGISDataStore -Referer $Referer -Verbose)
	}else{
		return @(Find-DataItems -URL $ServerBaseUrl -Token $Token -Type $DataStoreType -ItemName $ItemName -Referer $Referer -Verbose)
	}
}

function Get-DataStoreItemConnectionObject {
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$ItemName,

		[System.String]
		$DataStoreType,

		[System.String]
		$ConnectionString,

		[System.Management.Automation.PSCredential]
		$ConnectionSecret
	)

	<#
		- Deconstructed Connection String Object
		@{
			DataStorePath = ""
			CloudStoreType = ""

			AzureStorage = @{
				AccountName = ""
				AccountEndpoint = ""
				DefaultEndpointsProtocol = ""

				OverrideEndpoint = ""

				ContainerName = ""
				FolderPath = ""

				AuthenticationType = ""
				
				UserAssignedIdentityClientId = ""
				
				ServicePrincipalTenantId = ""
				ServicePrincipalClientId = ""
			}
			AmazonS3 = @{
				BucketName = ""
				FolderPath = ""
				Region = ""
				RegionEndpointUrl = ""
				AuthenticationType = ""
			}
		}
	#>

	$ConnStringObj = ConvertFrom-Json $ConnectionString
	
	if ($DataStoreType -ieq 'Folder') {
		$item = @{
			type = 'folder'; 
			info = @{ 
				dataStoreConnectionType = "shared"; 
				hostName                = $null 
				path                    = $ConnStringObj.DataStorePath 
			};
			path = "/fileShares/$($ItemName)" 
		}
	}
	elseif ($DataStoreType -ieq 'RasterStore') {
		$item = @{
			type = 'rasterStore'; 
			info = @{ 
				connectionString = @{ 
					path = $ConnStringObj.DataStorePath
				};
				connectionType   = if ($ConnStringObj.DataStorePath.StartsWith('/cloudStores') -or $ConnStringObj.DataStorePath.StartsWith('/enterpriseDatabases')) { 'dataStore' } else { 'fileShare' }
			};
			path = "/rasterStores/$($ItemName)"
		}
	}
	elseif ($DataStoreType -ieq 'BigDataFileShare') {
		$item = @{
			type = 'bigDataFileShare'; 
			info = @{ 
				connectionString = @{ 
					path = $ConnStringObj.DataStorePath
				}; 
				connectionType   = if ($ConnStringObj.DataStorePath.StartsWith('/cloudStores')) { 'cloudstore' } else { 'fileShare' }
			};
			path = "/bigDataFileShares/$($ItemName)"
		}
	}
	elseif ($DataStoreType -ieq 'CloudStore' -or $DataStoreType -ieq 'ObjectStore') {
		$CloudStoreType = $ConnStringObj.CloudStoreType

		$item = @{
			type     = 'cloudStore';
			path     = "/cloudStores/$($ItemName)";
			info     = @{
				isManaged        = $false; 
				connectionString = @{};
			};
			provider = $CloudStoreType
		}

		if($DataStoreType -ieq 'ObjectStore'){
			$item = @{
				type     = 'objectStore';
				path     = "/cloudStores/$($ItemName)";
				info     = @{
					isManaged        = $True; 
					systemManaged    = $false; 
					isManagedData    = $True;
					purposes         = @('feature-tile', 'scene');
					connectionString = @{};
					encryptionInfo   = @("info.connectionString")
				};
				provider = $CloudStoreType
			}
		}

		if ($CloudStoreType -ieq "Azure") {
			$ObjectStorePath = "$($ConnStringObj.AzureStorage.ContainerName)" 
			if ($ConnStringObj.AzureStorage.FolderPath) {
				$ObjectStorePath = "$($ConnStringObj.AzureStorage.ContainerName)/$($ConnStringObj.AzureStorage.FolderPath)"
			}
			$item.info["objectStore"] = $ObjectStorePath

			$item.info.connectionString = @{ 
				accountName              = $ConnStringObj.AzureStorage.AccountName; 
				defaultEndpointsProtocol = $ConnStringObj.AzureStorage.DefaultEndpointsProtocol; #https
				accountEndpoint          = $ConnStringObj.AzureStorage.AccountEndpoint; #core.windows.net
			}
            
			$AzureCloudStoreAuthenticationType = $ConnStringObj.AzureStorage.AuthenticationType

			if ($ConnStringObj.AzureStorage.OverrideEndpoint) {
				$item.info.connectionString["regionEndpointUrl"] = $ConnStringObj.AzureStorage.OverrideEndpoint # GDAL
			}
			if ($AzureCloudStoreAuthenticationType -ieq "AccessKey") {
				$item.info.connectionString["credentialType"] = 'accessKey'
				$item.info.connectionString["accountKey"] = $ConnectionSecret.GetNetworkCredential().Password
			}
			elseif ($AzureCloudStoreAuthenticationType -ieq "SASToken") {
				$item.info.connectionString["credentialType"] = 'sasToken'
				$item.info.connectionString["sasToken"] = $ConnectionSecret.GetNetworkCredential().Password
			}
			elseif ($AzureCloudStoreAuthenticationType -ieq "ServicePrincipal") {
				$item.info.connectionString["credentialType"] = 'servicePrincipal'
				$item.info.connectionString["tenantId"] = $ConnStringObj.AzureStorage.ServicePrincipalTenantId
				$item.info.connectionString["clientId"] = $ConnStringObj.AzureStorage.ServicePrincipalClientId
				$item.info.connectionString["clientSecret"] = $ConnectionSecret.GetNetworkCredential().Password
				if($ConnStringObj.AzureStorage.ContainsKey("ServicePrincipalAuthorityHost") -and $ConnStringObj.AzureStorage.ServicePrincipalAuthorityHost -ne ""){
                    $item.info.connectionString["authorityHost"] = $ConnStringObj.AzureStorage.ServicePrincipalAuthorityHost
                }
			}
			elseif ($AzureCloudStoreAuthenticationType -ieq "UserAssignedIdentity") {
				$item.info.connectionString["credentialType"] = 'userAssignedIdentity'
				$item.info.connectionString["managedIdentityClientId"] = $ConnStringObj.AzureStorage.UserAssignedIdentityClientId
			}

			# if(-not([string]::IsNullOrEmpty($AzureTableName))){
			# 	$item.info.Add('tableStore', $AzureTableName);
			# }
		}
		elseif ($CloudStoreType -ieq "Amazon") {
			$ObjectStorePath = "$($ConnStringObj.AmazonS3.BucketName)" 
			if ($ConnStringObj.AmazonS3.FolderPath) {
				$ObjectStorePath = "$($ConnStringObj.AmazonS3.BucketName)/$($ConnStringObj.AmazonS3.FolderPath)" # GDAL
			}
			$item.info["objectStore"] = $ObjectStorePath

			$item.info.connectionString["region"] = $ConnStringObj.AmazonS3.Region

			if ($ConnStringObj.AmazonS3.RegionEndpointUrl) {
				$item.info.connectionString["regionEndpointUrl"] = $ConnStringObj.AmazonS3.RegionEndpointUrl
			}

			if($ConnStringObj.AmazonS3.AuthenticationType -eq "IAMRole"){
				$item.info.connectionString["credentialType"] = 'IAMRole'
			}else{
				$item.info.connectionString["credentialType"] = 'accessKey'
				$item.info.connectionString["accessKeyId"] = $ConnectionSecret.UserName
				$item.info.connectionString["secretAccessKey"] = $ConnectionSecret.GetNetworkCredential().Password
			}
		}
	}

	return $item
}

Export-ModuleMember -Function *-TargetResource
