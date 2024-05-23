$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

<#
    .SYNOPSIS
        Configures A Datastore Item with the GIS server. ("Folder","CloudStore","RasterStore","BigDataFileShare")
    .PARAMETER Name
        Data Store Item Name Identifier
    .PARAMETER Ensure
        Take the values Present or Absent. 
        - "Present" ensures that DataStore Item is Configured if not.
        - "Absent" ensures that DataStore Item is unconfigured or derigestered with the GIS Server - Not Implemented).
    .PARAMETER SiteName
        Context of the GIS Server for which you want to create and register a data store Item
    .PARAMETER HostName
        HostName of the GIS Server for which you want to create and register a data store Item.
    .PARAMETER SiteAdministrator
        A MSFT_Credential Object - Primary Site Administrator to access the GIS Server. 
    .PARAMETER Port
         Port of the GIS Server for which you want to create and register a data store Item
    .PARAMETER DataStoreType
        DataStore Item types that can be registered with the GIS Server - "Folder","CloudStore","RasterStore","BigDataFileShare"
    .PARAMETER DataStoreConnectionString
        Required to Register an Azure Cloud Store.
    .PARAMETER DataStorePath
        DataStorePath Is a
        - Folder Location in Case of a Folder and a Raster Store 
        - Container Name when Registering a Azure Cloud Store
    .PARAMETER DataStoreTable
        DataStoreTable Is a
        - Azure Table Name when Registering a Azure Cloud Store
    .PARAMETER DataStoreEndpoint
        DataStoreEndpoint is a
        - Azure Storage Account Endpoint in case of a CloudStore.
        - Path to the Big Data File Share
        - Folder Host Name (i.e. in case of file share) when data store item type is Folder.
#>

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Name
	)

	$null
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Name,

		[parameter(Mandatory = $false)]
		[System.String]
		$SiteName = 'arcgis',

		[parameter(Mandatory = $false)]
		[System.String]
		$HostName,

        [parameter(Mandatory = $true)]
		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

        [parameter(Mandatory = $false)]
		[System.String]
		$Port = 6443,

        [parameter(Mandatory = $true)]
		[ValidateSet("Folder","CloudStore","RasterStore","BigDataFileShare")]
        [System.String]
		$DataStoreType,

		[System.String]
		$DataStoreConnectionString,

        [System.String]
        $DataStorePath,
        
        [parameter(Mandatory = $false)]
		[System.String]
        $DataStoreTable,
        
        [System.String]
		$DataStoreEndpoint
	)


    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	$result = $false
    $FQDN = if($HostName){ Get-FQDN $HostName }else{ Get-FQDN $env:COMPUTERNAME }
    $Scheme = if($Port -eq 6080 -or $Port -eq 80) { 'http' } else { 'https' }
    $ServerUrl = "$($Scheme)://$($FQDN):$Port"
      
    Write-Verbose "ServerURL:- $ServerUrl"
    $Referer = 'http://locahost'
    $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName $SiteName -Credential $SiteAdministrator -Referer $Referer 
    
    if($DataStoreType -ieq 'Folder') {
        $folders = Get-DataStoreItemsOfType -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer -Types 'folder' -AncestorPath '/fileShares'
        if(($folders.items | Where-Object { $_.path -ieq "/fileShares/$Name" } | Measure-Object).Count -gt 0) {
            Write-Verbose "Folder DataStore Item with name '$Name' already exists"           
            $result = $true
        }else {
            Write-Verbose "Folder DataStore Item with name '$Name' does not exist"
        }
    }
    elseif($DataStoreType -ieq 'CloudStore') {
        $cloudStores = Get-DataStoreItemsOfType -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer -Types 'cloudStore' -AncestorPath '/cloudStores'
        if(($cloudStores.items | Where-Object { $_.path -ieq "/cloudStores/$Name" } | Measure-Object).Count -gt 0) {
            Write-Verbose "Cloud DataStore Item with name '$Name' already exists"           
            $result = $true
        }else {
            Write-Verbose "Cloud DataStore Item with name '$Name' does not exist"
        }
    }
    elseif($DataStoreType -ieq 'BigDataFileShare') {
        $cloudStores = Get-DataStoreItemsOfType -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer -Types 'bigDataFileShare' -AncestorPath '/bigDataFileShares'
        if(($cloudStores.items | Where-Object { $_.path -ieq "/bigDataFileShares/$Name" } | Measure-Object).Count -gt 0) {
            Write-Verbose "Big Data File Share Item with name '$Name' already exists"           
            $result = $true
        }else {
            Write-Verbose "Big Data File Share Item with name '$Name' does not exist"
        }
    }
    elseif($DataStoreType -ieq 'RasterStore') {
        $rasterStores = Get-DataStoreItemsOfType -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer -Types 'rasterStore' -AncestorPath '/rasterStores'
        if(($rasterStores.items | Where-Object { $_.path -ieq "/rasterStores/$Name" } | Measure-Object).Count -gt 0) {
            Write-Verbose "Raster DataStore Item with name '$Name' already exists"           
            $result = $true
        }else {
            Write-Verbose "Raster DataStore Item with name '$Name' does not exist"
        }
    }

    if($Ensure -ieq 'Present') {
	       $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}


function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
        [parameter(Mandatory = $true)]
		[System.String]
		$Name,

		[parameter(Mandatory = $false)]
		[System.String]
		$SiteName = 'arcgis',

		[parameter(Mandatory = $false)]
		[System.String]
		$HostName,

        [parameter(Mandatory = $true)]
		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

        [parameter(Mandatory = $false)]
		[System.String]
		$Port = 6443,

        [parameter(Mandatory = $true)]
        [System.String]
		[ValidateSet("Folder","CloudStore","RasterStore","BigDataFileShare")]
		$DataStoreType,

		[System.String]
		$DataStoreConnectionString,

        [System.String]
        $DataStorePath,
        
        [parameter(Mandatory = $false)]
		[System.String]
        $DataStoreTable,

        [System.String]
		$DataStoreEndpoint
	)

	$FQDN = if($HostName){ Get-FQDN $HostName }else{ Get-FQDN $env:COMPUTERNAME }
    $Scheme = if($Port -eq 6080 -or $Port -eq 80) { 'http' } else { 'https' }
    $ServerUrl = "$($Scheme)://$($FQDN):$Port"
    Write-Verbose "ServerURL:- $ServerUrl"
    $Referer = 'http://locahost'
    $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName $SiteName -Credential $SiteAdministrator -Referer $Referer 
    
    if($DataStoreType -ieq 'Folder') {
        $folders = Get-DataStoreItemsOfType -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer -Types 'folder' -AncestorPath '/fileShares'
        if(($folders.items | Where-Object { $_.path -ieq "/fileShares/$Name" } | Measure-Object).Count -gt 0) {
            Write-Verbose "DataStore Item with name '$Name' already exists"
        }else {
            Write-Verbose "DataStore Item with name '$Name' does not exist. Registering it"
            Register-SharedFolderDataStoreItem -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token `
                                               -Referer $Referer -ItemName $Name -FolderLocalPath $DataStorePath -FolderHostName $DataStoreEndpoint 
        }
    }
    elseif($DataStoreType -ieq 'CloudStore') {
        $cloudStores = Get-DataStoreItemsOfType -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer -Types 'cloudStore' -AncestorPath '/cloudStores'
        if(($cloudStores.items | Where-Object { $_.path -ieq "/cloudStores/$Name" } | Measure-Object).Count -gt 0) {
            Write-Verbose "Cloud DataStore Item with name '$Name' already exists"  
        }else {
            Write-Verbose "Cloud DataStore Item with name '$Name' does not exist. Registering it"
            Register-AzureCloudDataStoreItem -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token `
                                             -AzureStorageConnectionString $DataStoreConnectionString -AzureStorageAccountEndpoint $DataStoreEndpoint `
                                             -Referer $Referer -ItemName $Name -AzureContainerName $DataStorePath -AzureTableName $DataStoreTable
        }
    }
    elseif($DataStoreType -ieq 'BigDataFileShare') {
        $cloudStores = Get-DataStoreItemsOfType -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer -Types 'bigDataFileShare' -AncestorPath '/bigDataFileShares'
        if(($cloudStores.items | Where-Object { $_.path -ieq "/bigDataFileShares/$Name" } | Measure-Object).Count -gt 0) {
            Write-Verbose "Big Data File Share Item with name '$Name' already exists"    
        }else {
            Write-Verbose "Big Data File Share Item with name '$Name' does not exist. Registering it"
            Register-BigDataFileShareDataStoreItem -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer `
                                                -ItemName $Name -Path $DataStoreEndpoint
        }
    }
    elseif($DataStoreType -ieq 'RasterStore') {
        $rasterStores = Get-DataStoreItemsOfType -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer -Types 'rasterStore' -AncestorPath '/rasterStores'
        if(($rasterStores.items | Where-Object { $_.path -ieq "/rasterStores/$Name" } | Measure-Object).Count -gt 0) {
            Write-Verbose "Raster DataStore Item with name '$Name' already exists"  
        }else {
            Write-Verbose "Raster DataStore Item with name '$Name' does not exist. Registering it"
            Register-RasterDataStoreItem -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token `
                                         -Referer $Referer -ItemName $Name -DataStorePath $DataStorePath
        }
    }
}


function Get-DataStoreItemsOfType
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerURL = 'https://localhost:6443', 
        
        [System.String]
        $SiteName = 'arcgis', 
        
        [System.String]
        $Token, 
        
        [System.String]
        $Referer = 'http://localhost',
        
        [System.String]
        $Types,
        
        [System.String]
        $AncestorPath
    )

    $DataItemsUrl = $ServerURL.TrimEnd('/') + '/' + $SiteName + '/admin/data/findItems' 
    Invoke-ArcGISWebRequest -Url $DataItemsUrl -HttpFormParameters  @{ f = 'json'; token = $Token; types = $Types; ancestorPath = $AncestorPath } -Referer $Referer 
}

function Register-SharedFolderDataStoreItem
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerURL = 'https://localhost:6443', 
        
        [System.String]
        $SiteName = 'arcgis', 
        
        [System.String]
        $Token, 
        
        [System.String]
        $Referer = 'http://localhost',
        
        [parameter(Mandatory = $true)]
        [System.String]
        $ItemName,
        
        [parameter(Mandatory = $true)]
        [System.String]
        $FolderLocalPath,
        
        [parameter(Mandatory = $true)]
        [System.String]
        $FolderHostName
    )
    
    $RegisterDataItemUrl = $ServerURL.TrimEnd('/') + '/' + $SiteName + '/admin/data/registerItem' 
    Write-Verbose "Register folder data item at $FolderLocalPath on host $FolderHostName"
    $item = @{ type = 'folder'; info = @{ dataStoreConnectionType = "shared"; hostName = $FolderHostName; path= $FolderLocalPath }; path = "/fileShares/$ItemName" }
    Invoke-ArcGISWebRequest -Url $RegisterDataItemUrl -HttpFormParameters  @{ f = 'json'; token = $Token; item = (ConvertTo-Json -InputObject $item -Depth 3 -Compress) } -Referer $Referer 
}

function Register-BigDataFileShareDataStoreItem
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerURL = 'https://localhost:6443', 
        
        [System.String]
        $SiteName = 'arcgis', 
        
        [System.String]
        $Token, 
        
        [System.String]
        $Referer = 'http://localhost',

        [parameter(Mandatory = $true)]
        [System.String]
        $ItemName,

        [parameter(Mandatory = $true)]
        [System.String]
        $Path
    )
    
    $RegisterDataItemUrl = $ServerURL.TrimEnd('/') + '/' + $SiteName + '/admin/data/registerItem' 
    Write-Verbose "Register big data file share data item at $Path"
    $item = @{ type = 'bigDataFileShare'; info = @{ connectionString = @{ path = $Path}; connectionType = "fileShare" }; path = "/bigDataFileShares/$ItemName" }
    $ItemJson = (ConvertTo-Json -InputObject $item -Depth 5 -Compress)    
    #$ItemJson = '{"type":"bigDataFileShare","info":{"connectionString":"{\"path\":\"' + $Path.Replace('\','\\\\') + '\"}","connectionType":"fileShare"},"path":"/bigDataFileShares/' +$ItemName +  '"}'    
    $response = Invoke-ArcGISWebRequest -Url $RegisterDataItemUrl -HttpFormParameters  @{ f = 'json'; token = $Token; item = $ItemJson } -Referer $Referer -Verbose
    Write-Verbose "Response $($response.messages -join ',')"
}

function Register-RasterDataStoreItem
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerURL = 'https://localhost:6443', 
        
        [System.String]
        $SiteName = 'arcgis', 
        
        [System.String]
        $Token, 
        
        [System.String]
        $Referer = 'http://localhost',

        [parameter(Mandatory = $true)]
        [System.String]
        $ItemName,

        [parameter(Mandatory = $true)]
        [System.String]
        $DataStorePath
    )
    
    $RegisterDataItemUrl = $ServerURL.TrimEnd('/') + '/' + $SiteName + '/admin/data/registerItem' 
    $item = @{ type = 'rasterStore'; 
                info = @{ 
                    connectionString = @{ path = $DataStorePath };
                    connectionType = if($DataStorePath.StartsWith('/cloudStores') -or $DataStorePath.StartsWith('/enterpriseDatabases')) { 'dataStore' } else { 'fileShare' }
                };
                path = "/rasterStores/$ItemName"
             }
    Invoke-ArcGISWebRequest -Url $RegisterDataItemUrl -HttpFormParameters  @{ f = 'json'; token = $Token; item = (ConvertTo-Json -InputObject $item -Depth 3 -Compress) } -Referer $Referer 
}

function Register-AzureCloudDataStoreItem
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerURL = 'https://localhost:6443', 
        
        [System.String]
        $SiteName = 'arcgis', 
        
        [System.String]
        $Token, 
        
        [System.String]
        $Referer = 'http://localhost',

        [parameter(Mandatory = $true)]
        [System.String]
        $ItemName,

        [parameter(Mandatory = $true)]
        [System.String]
        $AzureStorageConnectionString,

        [parameter(Mandatory = $true)]
        [System.String]
        $AzureStorageAccountEndpoint,

        [parameter(Mandatory = $true)]
        [System.String]
        $AzureContainerName,
        
        [parameter(Mandatory = $false)]
        [System.String]
        $AzureTableName
    )

    $ConnStringObj = ConvertFrom-StringData $AzureStorageConnectionString.Replace(";","`n")    
    $RegisterDataItemUrl = $ServerURL.TrimEnd('/') + '/' + $SiteName + '/admin/data/registerItem' 
    $item = @{ type= 'cloudStore'; 
               info = @{ isManaged = $false; 
                         connectionString = @{ accountKey  = $ConnStringObj.AccountKey; 
                                               accountName = $ConnStringObj.AccountName; 
                                               defaultEndpointsProtocol = $ConnStringObj.DefaultEndpointsProtocol; 
                                               accountEndpoint = $AzureStorageAccountEndpoint; 
                                               credentialType = 'accessKey'
                                             }; 
                         objectStore = $AzureContainerName;
                      }; 
               path = "/cloudStores/$ItemName"; 
               provider= 'azure'
             }
    if(-not([string]::IsNullOrEmpty($AzureTableName))){
        $item.info.Add('tableStore', $AzureTableName);
    }
    Invoke-ArcGISWebRequest -Url $RegisterDataItemUrl -HttpFormParameters  @{ f = 'json'; token = $Token; item = (ConvertTo-Json -InputObject $item -Depth 5 -Compress) } -Referer $Referer 
}

Export-ModuleMember -Function *-TargetResource

