$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

<#
    .SYNOPSIS
        Supports configuration changes and Updates for the Datastore configured with the Server
    .PARAMETER Ensure
        Indicates if the Datatore Upgrade Process should take place. Take the values Present or Absent. 
        - "Present" ensures that DataStore is Upgraded to the version specified.
        - "Absent" ensures that DataStore is not upgraded or downgraded from a give version (Not Implemented).
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

    $null
}

function Set-TargetResource
{
	[CmdletBinding()]
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
    
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null

    if($Ensure -ieq 'Present') {
        $ServerUrl = "https://$($ServerHostName):6443"   
        $Referer = $ServerUrl

        Wait-ForUrl -Url "$($ServerUrl)/arcgis/admin" -MaxWaitTimeInSeconds 90 -SleepTimeInSeconds 5

        $Done = $false
        $NumAttempts = 0
        while(-not($Done) -and ($NumAttempts -lt 3)) {
            try {
                $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer 
            }
            catch {
                Write-Verbose "[WARNING]:- Server at $ServerUrl did not return a token on attempt $($NumAttempts + 1). Retry after 15 seconds"
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
        $DSInfoResponse = Get-DataStoreInfo -DataStoreAdminEndpoint "https://localhost:2443/arcgis/datastoreadmin" -ServerSiteAdminCredential $SiteAdministrator `
                                    -ServerSiteUrl "https://$($ServerHostName):6443/arcgis" -Token $token.token -Referer $Referer
        if($DSInfoResponse.error) {
            Write-Verbose "Error Response - $($response.error | ConvertTo-Json)"
            throw [string]::Format("ERROR: failed. {0}" , $response.error.message)
        }
        
        $VersionArray = $DSInfoResponse.currentVersion.split('.')                                                               
        $dstypesarray = [System.Collections.ArrayList]@()
        
        if($DSInfoResponse.relational.registered) {
            if($VersionArray[0] -eq 11 -or (($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 8) -or $DSInfoResponse.currentVersion -ieq "10.8.1" )){
                $datastoreConfigFilePath = "$ContentDirectory\\etc\\relational-config.json"
                $datastoreConfigJSONObject = (ConvertFrom-Json (Get-Content $datastoreConfigFilePath -Raw))
                $datastoreConfigHashtable = Convert-PSObjectToHashtable $datastoreConfigJSONObject 
                Write-Verbose "Relational Replication Role - $($datastoreConfigHashtable["replication.role"])"
                if($datastoreConfigHashtable["replication.role"] -ieq "PRIMARY"){
                    $dstypesarray.Add('relational')
                }
            }else{
                Write-Verbose "Relational Replication Role - $($datastoreConfigHashtable["store.relational"]["replication.role"])"
                if($datastoreConfigHashtable["store.relational"]["replication.role"] -ieq "PRIMARY"){
                    $dstypesarray.Add('relational')
                }
            }
        }
        if($DSInfoResponse.tileCache.registered) {
            if($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 7)){
                if($VersionArray[0] -eq 10 -and $VersionArray[1] -eq 8 -and $VersionArray[2] -eq 0){
                    Write-Verbose "TileCache Replication Role - $($datastoreConfigHashtable["store.tilecache"]["replication.role"])"
                    if($datastoreConfigHashtable["store.tilecache"]["replication.role"] -ieq "PRIMARY" -or $datastoreConfigHashtable["replication.role"] -ieq "CLUSTER_MEMBER"){
                        $dstypesarray.Add('tilecache')
                    }
                }else{
                    $datastoreConfigFilePath = "$ContentDirectory\\etc\\tilecache-config.json"
                    $datastoreConfigJSONObject = (ConvertFrom-Json (Get-Content $datastoreConfigFilePath -Raw))
                    $datastoreConfigHashtable = Convert-PSObjectToHashtable $datastoreConfigJSONObject 
                    Write-Verbose "TileCache Replication Role - $($datastoreConfigHashtable["replication.role"])"
                    if($datastoreConfigHashtable["replication.role"] -ieq "PRIMARY" -or $datastoreConfigHashtable["replication.role"] -ieq "CLUSTER_MEMBER"){
                        $dstypesarray.Add('tilecache')
                    }
                }
            }else{
                Write-Verbose "TileCache Replication Role - $($datastoreConfigHashtable["store.tilecache"]["replication.role"])"
                if($datastoreConfigHashtable["store.tilecache"]["replication.role"] -ieq "PRIMARY" ){
                    $dstypesarray.Add('tilecache')
                }
            }
        }
        if($DSInfoResponse.spatioTemporal.registered) {
            $dstypesarray.Add('spatiotemporal')
        }
        
        if($dstypesarray.Length -gt 0){
            $dstypes = $dstypesarray -join ","
            Write-Verbose $dstypes
            $ServerAdminUrl = "$($ServerUrl)/arcgis"
            $ExecPath = Join-Path $InstallDir 'tools\configuredatastore.bat'
            $Arguments = "$($ServerAdminUrl) $($SiteAdministrator.GetNetworkCredential().UserName) $($SiteAdministrator.GetNetworkCredential().Password) $($ContentDirectory) --stores $dstypes"
            
            write-verbose "Executing $ExecPath"

            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $ExecPath
            $psi.Arguments = $Arguments
            $psi.UseShellExecute = $false #start the process from it's own executable file    
            $psi.RedirectStandardOutput = $true #enable the process to read from standard output
            $psi.RedirectStandardError = $true #enable the process to read from standard error
            $psi.EnvironmentVariables["AGSDATASTORE"] = [environment]::GetEnvironmentVariable("AGSDATASTORE","Machine")
            $p = [System.Diagnostics.Process]::Start($psi)
            $p.WaitForExit()
            $op = $p.StandardOutput.ReadToEnd()
            if($op -and $op.Length -gt 0) {
                Write-Verbose "Output of execution:- $op"
            }
            $err = $p.StandardError.ReadToEnd()
            if($p.ExitCode -eq 0) {                    
                Write-Verbose "Upgraded correctly"
                $result = $true
            }else {
                Write-Verbose "Upgraded did not succeed. Process exit code:- $($p.ExitCode)"
                if($err -and $err.Length -gt 0) {
                    Write-Verbose $err
                }
            }
        }   
    }else{
        Write-Verbose "Do Nothing for now"
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
    
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null

    $ServerUrl = "https://$($ServerHostName):6443"   
    $Referer = $ServerUrl
    Wait-ForUrl -Url "$ServerUrl/arcgis/admin" -MaxWaitTimeInSeconds 90 -SleepTimeInSeconds 5
    $result = $true
    $info = Invoke-ArcGISWebRequest -Url "https://localhost:2443/arcgis/datastoreadmin/configure" -HttpFormParameters @{ f = 'json'}  -Referer $Referer -HttpMethod 'GET' -Verbose 

    if($info.upgrading -and (($info.upgrading -ieq 'outplace') -or ($info.upgrading -ieq 'inplace'))){
        Write-Verbose "Upgrade in progress - $($info.upgrading)"
        $result = $false
    }

    if($Ensure -ieq 'Present') {
	    $result
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}

function Get-DataStoreInfo
{
    [CmdletBinding()]
    param(
        [System.String]
        $DataStoreAdminEndpoint, 

        [System.Management.Automation.PSCredential]
        $ServerSiteAdminCredential, 

        [System.String]
        $ServerSiteUrl,

        [System.String]
        $Token, 

        [System.String]
        $Referer
    )

    $WebParams = @{ 
                    f = 'json'
                    username = $ServerSiteAdminCredential.UserName
                    password = $ServerSiteAdminCredential.GetNetworkCredential().Password
                    serverURL = $ServerSiteUrl      
                    dsSettings = '{"features":{"feature.egdb":true,"feature.nosqldb":true,"feature.bigdata":true,"feature.graphstore":true,"feature.objectstore":true}}'
                    getConfigureInfo = 'true'
                  }  
        
   $DataStoreConfigureUrl = $DataStoreAdminEndpoint.TrimEnd('/') + '/configure'   
   Wait-ForUrl -Url  $DataStoreConfigureUrl -MaxWaitTimeInSeconds 90 -SleepTimeInSeconds 20
   Invoke-ArcGISWebRequest -Url $DataStoreConfigureUrl -HttpFormParameters $WebParams -Referer $Referer -HttpMethod 'POST' -Verbose 
   
}



Export-ModuleMember -Function *-TargetResource
