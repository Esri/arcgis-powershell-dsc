$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

function Get-TargetResource {
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param(
		[parameter(Mandatory = $true)]
		[System.String]
		$Name,

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
		[ValidateSet("Folder", "CloudStore", "RasterStore", "BigDataFileShare")]
		$DataStoreType,

		[System.String]
		$ConnectionString,

		[System.Management.Automation.PSCredential]
		$ConnectionSecret,

		[System.Boolean]
		$ForceUpdate = $false
	)

	$null
}

function Set-TargetResource {
	[CmdletBinding()]
	param(
		[parameter(Mandatory = $true)]
		[System.String]
		$Name,

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
		[ValidateSet("Folder", "CloudStore", "RasterStore", "BigDataFileShare")]
		$DataStoreType,

		[parameter(Mandatory = $true)]
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
	$Scheme = if ($ServerHostPort -eq 6080 -or $ServerHostPort -eq 80) { 'http' } else { 'https' }
	$ServerUrl = "$($Scheme)://$($FQDN):$($ServerHostPort)"
	Write-Verbose "ServerURL:- $ServerUrl"
	$Referer = 'http://locahost'
	$token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName $ServerSiteName -Credential $SiteAdministrator -Referer $Referer 
	$DataStoreItemUrl = $ServerURL.TrimEnd('/') + '/' + $ServerSiteName + '/admin/data' 

	$DataStoreItemConnectionObject = Get-DataStoreItemConnectionObject -ItemName $Name -DataStoreType $DataStoreType -ConnectionString $ConnectionString -ConnectionSecret $ConnectionSecret
	Write-Verbose ($DataStoreItemConnectionObject | ConvertTo-Json -Depth 5)
	# Validate Data Store Item Connection
	if(Invoke-ValidateDataStoreItemConnection -DataStoreItemUrl $DataStoreItemUrl -Token $token.token -Referer $Referer -DataStoreItemConnectionObject $DataStoreItemConnectionObject){
		if(Test-DataStoreItemExists -ItemName $Name -DataStoreItemUrl $DataStoreItemUrl -Token $token.token -Referer $Referer -DataStoreType $DataStoreType){
			# Edit Data Store Item Connection
			Edit-DataStoreItemConnection -DataStoreItemUrl $DataStoreItemUrl -Token $token.token -Referer $Referer -DataStoreItemConnectionObject $DataStoreItemConnectionObject
		}else{
			# Register Data Store Item
			Register-DataStoreItem -DataStoreItemUrl $DataStoreItemUrl -Token $token.token -Referer $Referer -DataStoreItemConnectionObject $DataStoreItemConnectionObject
		}
	}else{
		throw "Validation of Data Store Item Connection failed."
	}
}

function Test-TargetResource {

	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param(
		[parameter(Mandatory = $true)]
		[System.String]
		$Name,

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
		[ValidateSet("Folder", "CloudStore", "RasterStore", "BigDataFileShare")]
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
	$Scheme = if ($ServerHostPort -eq 6080 -or $ServerHostPort -eq 80) { 'http' } else { 'https' }
	$ServerUrl = "$($Scheme)://$($FQDN):$($ServerHostPort)"
	Write-Verbose "ServerURL:- $ServerUrl"
	$Referer = 'http://locahost'
	$token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName $ServerSiteName -Credential $SiteAdministrator -Referer $Referer 
	
	$DataStoreItemUrl = $ServerURL.TrimEnd('/') + '/' + $ServerSiteName + '/admin/data' 
	if(Test-DataStoreItemExists -ItemName $Name -DataStoreItemUrl $DataStoreItemUrl -Token $token.token -Referer $Referer -DataStoreType $DataStoreType){
		if($ForceUpdate){
			Write-Verbose "$DataStoreType DataStore Item with name '$Name' already exists. Force Update specified."
		}else{
			Write-Verbose "$DataStoreType DataStore Item with name '$Name' already exists."
			$result = $true
		}
	}
	else {
		Write-Verbose "$DataStoreType DataStore Item with name '$Name' does not exist"
	}

	$result
}

function Test-DataStoreItemExists {
	[CmdletBinding()]
	param(
		[System.String]
		$ItemName,

		[System.String]
		$DataStoreItemUrl,

		[System.String]
		$Token, 

		[System.String]
		$Referer = 'http://localhost',

		[System.String]
		$DataStoreType
	)

	$TypeString = ""
	$AncestorPath = ""
	if ($DataStoreType -ieq 'Folder') {
		$TypeString = "folder"
		$AncestorPath = "/fileShares"
	}
	elseif ($DataStoreType -ieq 'CloudStore') {
		$TypeString = "cloudStore"
		$AncestorPath = "/cloudStores"
	}
	elseif ($DataStoreType -ieq 'BigDataFileShare') { 
		$TypeString = "bigDataFileShare"
		$AncestorPath = "/bigDataFileShares"
	}
	elseif ($DataStoreType -ieq 'RasterStore') {
		$TypeString = "rasterStores"
		$AncestorPath = "/rasterStores"
	}

	$DataItemsUrl = $DataStoreItemUrl + '/findItems'

	$DataStoreItems = Invoke-ArcGISWebRequest -Url $DataItemsUrl -HttpFormParameters  @{ f = 'json'; token = $Token; types = $TypeString; ancestorPath = $AncestorPath } -Referer $Referer 
	return (($DataStoreItems.items | Where-Object { $_.path -ieq "$($AncestorPath)/$($ItemName)" } | Measure-Object).Count -gt 0)
}

function Invoke-ValidateDataStoreItemConnection {
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[System.String]
		$DataStoreItemUrl,

		[System.String]
		$Token,

		[System.String]
		$Referer = 'http://localhost',

		[System.Object]
		$DataStoreItemConnectionObject
	)

	$FormParameters = @{ 
		f     = 'json'; 
		token = $Token; 
		item  = (ConvertTo-Json -InputObject $DataStoreItemConnectionObject -Depth 5 -Compress)
	}
	$ValidateDataStoreItemUrl = $DataStoreItemUrl+ "/validateDataItem"
	$response = Invoke-ArcGISWebRequest -Url $ValidateDataStoreItemUrl -HttpFormParameters $FormParameters -Referer $Referer 
	if ($response.status -ieq 'success') {
		Write-Verbose "Validation of Data Store Item successful"
		return $true
	}
	else {
		if (($response.status -ieq 'error') -and $response.messages) {
			throw "[ERROR]:- Validation of Data Store Item failed. $($response.messages -join ',')"
		}
	}
}

function Edit-DataStoreItemConnection {
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[System.String]
		$DataStoreItemUrl,

		[System.String]
		$Token,

		[System.String]
		$Referer = 'http://localhost',

		[System.Object]
		$DataStoreItemConnectionObject
	)

	$FormParameters = @{ 
		f     = 'json'; 
		token = $Token; 
		item  = (ConvertTo-Json -InputObject $DataStoreItemConnectionObject -Depth 5 -Compress)
	}

	$EditDataStoreItemUrl = $DataStoreItemUrl + '/items'+$($DataStoreItemConnectionObject.path)+'/edit'
	$response = Invoke-ArcGISWebRequest -Url $EditDataStoreItemUrl -HttpFormParameters $FormParameters -Referer $Referer 
	if ($response.status -ieq 'success') {
		Write-Verbose "Edit of Data Store item connection successful."
		return $true
	}
	else {
		if (($response.status -ieq 'error') -and $response.messages) {
			throw "[ERROR]:- Edit of Data Store item connection failed. $($response.messages -join ',')"
		}
	}
}

function Register-DataStoreItem {
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[System.String]
		$DataStoreItemUrl,

		[System.String]
		$Token,

		[System.String]
		$Referer = 'http://localhost',

		[System.Object]
		$DataStoreItemConnectionObject,

		[System.String]
		$OperationType = 'register'
	)
	
	$FormParameters = @{ 
		f     = 'json'; 
		token = $Token; 
		item  = (ConvertTo-Json -InputObject $DataStoreItemConnectionObject -Depth 5 -Compress)
	}

	$RegisterDataStoreItemUrl = $DataStoreItemUrl + '/registerItem'

	$response = Invoke-ArcGISWebRequest -Url $RegisterDataStoreItemUrl -HttpFormParameters $FormParameters -Referer $Referer 
	if ($response.status -ieq 'success') {
		Write-Verbose "Registration of Data Store Item successful"
		return $true
	}
	else {
		if (($response.status -ieq 'error') -and $response.messages) {
			throw "[ERROR]:- Registration of Data Store Item failed. $($response.messages -join ',')"
		}
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
	elseif ($DataStoreType -ieq 'CloudStore') {
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

			if ($ConnStringObj.OverrideEndpoint) {
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
