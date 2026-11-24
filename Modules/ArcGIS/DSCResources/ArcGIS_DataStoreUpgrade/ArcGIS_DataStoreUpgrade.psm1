$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.DataStore.psm1'))


Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.Server.psm1'))

<#
    .SYNOPSIS
        Supports configuration changes and Updates for the Datastore configured with the Server
    .PARAMETER ServerHostName
         HostName of the GIS Server for which the datastore was created and registered.
    .PARAMETER SiteAdministrator
        A MSFT_Credential Object - Primary Site Administrator to access the GIS Server. 
    .PARAMETER ContentDirectory
        Path for the ArcGIS Data Store directory. This directory contains the data store files, plus the relational data store backup directory.
    .PARAMETER InstallDir
        Path of the Installation Directory given during initial DataStore Installation which contains the ArcGIS Data Store application files.
#>

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$ServerHostName,

	    [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

		[System.String]
        $ContentDirectory,
        
        [System.String]
		$InstallDir
    )

    @{}
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$ServerHostName,

		[parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

		[System.String]
        $ContentDirectory,
        
        [System.String]
		$InstallDir
    )
    

    $ServerFQDN = Get-FQDN $ServerHostName
    $ServerBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName "Server" -FQDN $ServerFQDN
    $Referer = $ServerBaseUrl
    Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName "Server" -MaxWaitTimeInSeconds 90 -SleepTimeInSeconds 5 -Verbose

    $Done = $false
    $NumAttempts = 0
    while(-not($Done) -and ($NumAttempts -lt 3)) {
        try {
            $token = Get-ServerToken -URL $ServerBaseUrl -Credential $SiteAdministrator -Referer $Referer 
        }
        catch {
            Write-Verbose "[WARNING]:- Server at $ServerBaseUrl did not return a token on attempt $($NumAttempts + 1). Retry after 15 seconds"
        }
        if($token) {
            Write-Verbose "Retrieved server token successfully"
            $Done = $true
        }else {
            Start-Sleep -Seconds 15
            $NumAttempts = $NumAttempts + 1
        }
    }

    $datastoreConfigFilePath = "$ContentDirectory\\etc\\arcgis-data-store-config.json"
    $datastoreConfigJSONObject = (ConvertFrom-Json (Get-Content $datastoreConfigFilePath -Raw))
    $datastoreConfigHashtable = Convert-PSObjectToHashtable $datastoreConfigJSONObject 

    #Hit the server endpoint to get the replication role
    $DatastoreBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName "DataStore"
    $DSInfoResponse = Get-DataStoreInfo -URL $DatastoreBaseUrl `
                                -ServerSiteAdminCredential $SiteAdministrator `
                                -ServerSiteUrl $ServerBaseUrl -Referer $Referer
    if($DSInfoResponse.error) {
        Write-Verbose "Error Response - $($DSInfoResponse.error | ConvertTo-Json)"
        throw [string]::Format("ERROR: failed. {0}" , $DSInfoResponse.error.message)
    }
    
    $Version = $DSInfoResponse.currentVersion
    $dstypesarray = [System.Collections.ArrayList]@()
    
    if($DSInfoResponse.relational.registered) {
        $datastoreConfigFilePath = "$ContentDirectory\\etc\\relational-config.json"
        $datastoreConfigJSONObject = (ConvertFrom-Json (Get-Content $datastoreConfigFilePath -Raw))
        $datastoreConfigHashtable = Convert-PSObjectToHashtable $datastoreConfigJSONObject 
        Write-Verbose "Relational Replication Role - $($datastoreConfigHashtable["replication.role"])"
        if($datastoreConfigHashtable["replication.role"] -ieq "PRIMARY"){
            $dstypesarray.Add('relational')
        }
    }

    if($DSInfoResponse.tileCache.registered) {
        $datastoreConfigFilePath = "$ContentDirectory\\etc\\tilecache-config.json"
        $datastoreConfigJSONObject = (ConvertFrom-Json (Get-Content $datastoreConfigFilePath -Raw))
        $datastoreConfigHashtable = Convert-PSObjectToHashtable $datastoreConfigJSONObject 
        Write-Verbose "TileCache Replication Role - $($datastoreConfigHashtable["replication.role"])"
        if($datastoreConfigHashtable["replication.role"] -ieq "PRIMARY" -or $datastoreConfigHashtable["replication.role"] -ieq "CLUSTER_MEMBER"){
            $dstypesarray.Add('tilecache')
        }
    }
    
    if($DSInfoResponse.spatioTemporal.registered) {
        $dstypesarray.Add('spatiotemporal')
    }
    if($DSInfoResponse.graphStore.registered) {
        $dstypesarray.Add('graph')
    }
    if($DSInfoResponse.objectStore.registered) {
        if(-not($DSInfoResponse.objectStore.isCloudObjectStore)){
            $dstypesarray.Add('object')
        }
    }

    if($dstypesarray.Length -gt 0){
        $dstypes = $dstypesarray -join ","
        Write-Verbose $dstypes
        $ExecPath = Join-Path $InstallDir 'tools\configuredatastore.bat'

        $EscapedSiteAdministratorPassword = $SiteAdministrator.GetNetworkCredential().Password.Replace('"', '\"')

        $Arguments = "$($ServerBaseUrl) $($SiteAdministrator.GetNetworkCredential().UserName) `"$EscapedSiteAdministratorPassword`" $($ContentDirectory) --stores $dstypes"
        $RedactedArguments = "$($ServerBaseUrl) $($SiteAdministrator.GetNetworkCredential().UserName) `"xxxxx`" $($ContentDirectory) --stores $dstypes"
        Write-verbose "Executing $ExecPath $RedactedArguments"

        try{
            Invoke-StartProcess -ExecPath $ExecPath -Arguments $Arguments -EnvVariables @{ "AGSDATASTORE" = $null } -Verbose
            Write-Verbose "Upgraded correctly"
        }catch{
            throw "Datastore upgrade failed. $($_)"
        }
    }
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$ServerHostName,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

		[System.String]
        $ContentDirectory,
        
        [System.String]
		$InstallDir
    )
    

    $ServerFQDN = Get-FQDN $ServerHostName
    $ServerBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName "Server" -FQDN $ServerFQDN
    $Referer = $ServerBaseUrl
    Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName "Server" -MaxWaitTimeInSeconds 90 -SleepTimeInSeconds 5 -Verbose
    $DatastoreBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName "DataStore"
    $result = Test-DataStoreUpgrade -URL $DatastoreBaseUrl -Referer $Referer

    $result
}

Export-ModuleMember -Function *-TargetResource
