$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

<#
    .SYNOPSIS
        Resource Implements application level to handle cross node dependencies specific to the ArcGIS Enterprise Stack
    .PARAMETER Component
        Name of the Component for which the present node needs to wait for. Values accepted - Server, Portal, ServerWA, PortalWA, DataStore, SpatioTemporal, TileCache, SQLServer
    .PARAMETER InvokingComponent
        Name of component which will be waiting for component. Values accepted - Server, Portal, WebAdaptor, DataStore, PortalUpgrade
    .PARAMETER ComponentHostName
        HostName of the Component for which the present node needs to wait for.
    .PARAMETER ComponentContext
        Context of the Component for which the present node needs to wait for.
    .PARAMETER Ensure
        Take the values Present or Absent. 
        - "Present" ensures that machine waits for a target machine, for which the present node has a dependency on.
        - "Absent" - not implemented.
    .PARAMETER Credential
         A MSFT_Credential Object - Primary Site Administrator for the Component for which the present node needs to wait for.
    .PARAMETER RetryIntervalSec
        Time Interval after which the Resource will again check the status of the resource on the remote machine for which the node is waiting for.
    .PARAMETER RetryCount
        Number of Retries before the Resource is done trying to see if the resource on the target Machine is done.        
#>


function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer","Portal","ServerWA","PortalWA","DataStore","SpatioTemporal","TileCache","GraphStore","ObjectStore","UnregisterPortal")]
		[System.String]
        $Component,

        [parameter(Mandatory = $true)]
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer","Portal","WebAdaptor","DataStore","PortalUpgrade")]
		[System.String]
        $InvokingComponent,
               
        [parameter(Mandatory = $true)]
		[System.String]
        $ComponentHostName,
        
        [parameter(Mandatory = $true)]
		[System.String]
		$ComponentContext
	)
    
	$null
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer","Portal","ServerWA","PortalWA","DataStore","SpatioTemporal","TileCache","GraphStore","ObjectStore","UnregisterPortal")]
		[System.String]
        $Component,

        [parameter(Mandatory = $true)]
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer","Portal","WebAdaptor","DataStore","PortalUpgrade")]
		[System.String]
        $InvokingComponent,
        
        [parameter(Mandatory = $true)]
		[System.String]
        $ComponentHostName,
        
        [parameter(Mandatory = $true)]
		[System.String]
		$ComponentContext,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [parameter(Mandatory = $false)]
		[System.Management.Automation.PSCredential]
		$Credential,

        [parameter(Mandatory = $false)]
		[uint32]
        $RetryIntervalSec  = 30,

        [parameter(Mandatory = $false)]
		[uint32]
        $RetryCount  = 10
    )   
    
    $Referer = 'http://localhost'
    $NumCount = 0
	$Done     = $false
    $ComponentHostNameFQDN = Get-FQDN $ComponentHostName
	while ((-not $Done) -and ($NumCount++ -le $RetryCount)) 
	{
        Write-Verbose "Attempt $NumCount - $Component"
        try {
            if($Component -ieq "Server" -or $Component -ieq "NotebookServer" -or $Component -ieq "MissionServer" -or $Component -ieq "VideoServer"){
                Write-Verbose "Checking for $Component site"
                $Port = if($Component -ieq "NotebookServer"){ 11443 }elseif($Component -ieq "MissionServer"){ 20443 }elseif($Component -ieq "VideoServer"){ 21443 }else{ 6443 }
                $token = Get-ServerToken -ServerEndPoint "https://$($ComponentHostNameFQDN):$($Port)" -ServerSiteName $ComponentContext -Credential $Credential -Referer $Referer
                Write-Verbose "Checking for $Component site on '$ComponentHostName'"
                $Done = ($null -ne $token.token)
                if($Done){
                    Start-Sleep -Seconds 120
                }
            }elseif($Component -ieq "Portal"){
                Write-Verbose "Checking for Portal site on '$ComponentHostName'"
                $token = Get-PortalToken -PortalHostName $ComponentHostNameFQDN -SiteName $ComponentContext -Credential $Credential -Referer $Referer 
                $Done = ($null -ne $token.token)
            }elseif($Component -ieq "DataStore" -or $Component -ieq "SpatioTemporal" -or $Component -ieq "TileCache"){
                $token = Get-ServerToken -ServerEndPoint "https://$($ComponentHostNameFQDN):6443" -ServerSiteName $ComponentContext -Credential $Credential -Referer $Referer
                Write-Verbose "Checking if all datastore types passed as Params are registered"
                $AdditionalParams = $Component
                if($Component -ieq "DataStore"){
                    $AdditionalParams = 'Relational'
                }
                $Done = Test-DataStoreRegistered -ServerURL "https://$($ComponentHostNameFQDN):6443" -Token $token.token -Referer $Referer -Type $AdditionalParams
            }elseif($Component -ieq "PortalWA"){
                $token = Get-PortalToken -PortalHostName $ComponentHostNameFQDN -SiteName $ComponentContext -port 443 -Credential $Credential -Referer $Referer 
                $Done = ($null -ne $token.token)
                
            }elseif($Component -ieq "ServerWA"){
                $token = Get-ServerToken -ServerEndPoint "https://$($ComponentHostNameFQDN)" -ServerSiteName $ComponentContext -Credential $Credential -Referer $Referer                      
                $Done = ($null -ne $token.token)   
            }elseif($Component -ieq "UnregisterPortal"){
                $Referer = 'http://localhost'
    
                $token = Get-PortalToken -PortalHostName $ComponentHostNameFQDN -SiteName $ComponentContext -Credential $Credential -Referer $Referer 
                
                $Machines = Invoke-ArcGISWebRequest -Url ("https://$($ComponentHostNameFQDN):7443/arcgis/portaladmin/machines") -HttpFormParameters @{ f = 'json'; token = $token.token; } -Referer $Referer -HttpMethod 'GET'
                $Done = $true
                $StandbyMachine = Get-FQDN $env:COMPUTERNAME
                ForEach($m in $Machines.machines){
                    if($StandbyMachine -ieq $m.machineName){
                        $Done = $false
                        break;
                    }
                }
            }
        }catch {
            Write-Verbose "[WARNING]  The Resource is not available yet"
            Write-Verbose "[WARNING] Check returned error:- $_"
        }
        
        if(-not($Done)) {
            Write-Verbose "$Component on '$ComponentHostName' is not ready. Retrying after $RetryIntervalSec Seconds"
            Start-Sleep -Seconds $RetryIntervalSec
        }else {
            Write-Verbose "$Component on '$ComponentHostName' is ready"
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
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer","Portal","ServerWA","PortalWA","DataStore","SpatioTemporal","TileCache","GraphStore","ObjectStore","UnregisterPortal")]
		[System.String]
        $Component,

        [parameter(Mandatory = $true)]
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer","Portal","WebAdaptor","DataStore","PortalUpgrade")]
		[System.String]
        $InvokingComponent,
                
        [parameter(Mandatory = $true)]
		[System.String]
        $ComponentHostName,
        
        [parameter(Mandatory = $true)]
		[System.String]
		$ComponentContext,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [parameter(Mandatory = $false)]
		[System.Management.Automation.PSCredential]
		$Credential,

        [parameter(Mandatory = $false)]
        [uint32]
        $RetryIntervalSec  = 30,
        
        [parameter(Mandatory = $false)]
		[uint32]
        $RetryCount  = 10
	)
    
    $Referer = 'http://localhost'
    $result = $false
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $ComponentHostNameFQDN = Get-FQDN $ComponentHostName
    try {
        if($Component -ieq "Server" -or $Component -ieq "NotebookServer" -or $Component -ieq "MissionServer" -or $Component -ieq "VideoServer"){
            Write-Verbose "Checking for $Component site"
            $Port = if($Component -ieq "NotebookServer"){ 11443 }elseif($Component -ieq "MissionServer"){ 20443 }elseif($Component -ieq "VideoServer"){ 21443 }else{ 6443 }

            $token = Get-ServerToken -ServerEndPoint "https://$($ComponentHostNameFQDN):$($Port)" -ServerSiteName $ComponentContext -Credential $Credential -Referer $Referer 
            $result = ($null -ne $token.token)
            if($result){
                Write-Verbose "$Component Site Exists. Was able to retrieve token for PSA"
            }else{
                Write-Verbose "Unable to detect if $Component Site Exists. Was NOT able to retrieve token for PSA"
            }
        }
        elseif($Component -ieq "Portal"){
            Write-Verbose "Checking for Portal site on '$ComponentHostName'"
            $token = Get-PortalToken -PortalHostName $ComponentHostNameFQDN -SiteName $ComponentContext -Credential $Credential -Referer $Referer 
            $result = ($null -ne $token.token)
            if($result){
                Write-Verbose "Portal Site Exists. Was able to retrieve token for PSA. Making a secondary check"
                $PortalHealthCheck = Invoke-ArcGISWebRequest -Url "https://$($ComponentHostNameFQDN):7443/arcgis/portaladmin/healthCheck" -HttpFormParameters @{ f = 'json' } -Referer $Referer -Verbose -HttpMethod 'GET'
                if($PortalHealthCheck.status -ieq "success"){
                    $result = $true
                }else{
                    $result = $False
                    $jsresponse = ConvertTo-Json $TestPortalResponse -Compress -Depth 5
                    Write-Verbose "Unable to detect if Portal Site Exists. [WARNING]:- $jsresponse "
                }
            }else{
                Write-Verbose "Unable to detect if Portal Site Exists. Was NOT able to retrieve token for PSA"
            }
        }elseif($Component -ieq "DataStore" -or $Component -ieq "SpatioTemporal" -or $Component -ieq "TileCache" -or $Component -ieq "GraphStore" -or $Component -ieq "ObjectStore"){
            $token = Get-ServerToken -ServerEndPoint "https://$($ComponentHostNameFQDN):6443" -ServerSiteName $ComponentContext -Credential $Credential -Referer $Referer
            
            Write-Verbose "Checking if data store is registered"
            $AdditionalParams = $Component
            if($Component -ieq "DataStore"){
                $AdditionalParams = 'Relational'
            }
            $result = Test-DataStoreRegistered -ServerURL "https://$($ComponentHostNameFQDN):6443" -Token $token.token -Referer $Referer -Type $AdditionalParams
            if($result){
                Write-Verbose "All Types of DataStores are registered."
            }else{
                Write-Verbose "One or More Types of DataStore given as Parameter is not registered as Primary or Standby"
            }
        }elseif($Component -ieq "PortalWA"){
            Write-Verbose "Checking for Portal WebAdaptor"
            
            $token = Get-PortalToken -PortalHostName $ComponentHostNameFQDN -SiteName $ComponentContext -port 443 -Credential $Credential -Referer $Referer 
            $result = ($null -ne $token.token)
            if($result){
                Write-Verbose "Portal WebAdaptor Works. Was able to retrieve token for PSA"
            }else{
                Write-Verbose "Unable to detect if Portal WebAdaptor Works Correctly. Was NOT able to retrieve token for PSA"
            }
        }elseif($Component -ieq "ServerWA"){
            Write-Verbose "Checking for Server WebAdaptor"
            
            $token = Get-ServerToken -ServerEndPoint "https://$($ComponentHostNameFQDN):443" -ServerSiteName $ComponentContext -Credential $Credential -Referer $Referer 
            $result = ($null -ne $token.token)
            if($result){
                Write-Verbose "Server WebAdaptor Works. Was able to retrieve token for PSA"
            }else{
                Write-Verbose "Unable to detect if Server WebAdaptor Works Correctly. Was NOT able to retrieve token for PSA"
            }
        }elseif($Component -ieq "UnregisterPortal"){
            $Referer = 'http://localhost'

            $token = Get-PortalToken -PortalHostName $ComponentHostNameFQDN -SiteName $ComponentContext -Credential $Credential -Referer $Referer 
            
            $Machines = Invoke-ArcGISWebRequest -Url ("https://$($ComponentHostNameFQDN):7443/arcgis/portaladmin/machines") -HttpFormParameters @{ f = 'json'; token = $token.token; } -Referer $Referer -HttpMethod 'GET'
            $result = $true
            $StandbyMachine = Get-FQDN $env:COMPUTERNAME
            ForEach($m in $Machines.machines){
                if($StandbyMachine -ieq $m.machineName){
                    $result = $false
                    break;
                }
            }
        }
    }catch {
        Write-Verbose "[WARNING] The Resource is not available yet!"
        #Write-Verbose "[WARNING]:- $($_)"
    }
    
    $result
    
}

function Test-DataStoreRegistered
{
    [CmdletBinding()]
    param(
        [System.String]$ServerURL, 
        [System.String]$Token, 
        [System.String]$Referer, 
        [System.String]$Type
    )
    
    $DBTypes = $Type -split ','
    $DsTypes = ""
    if($DBTypes -icontains 'Relational') {
        $DsTypes += 'egdb'
    }
    if($DBTypes -icontains 'TileCache' -or $DBTypes -icontains 'SpatioTemporal' -or $DBTypes -icontains 'GraphStore'){
        if($DsTypes -ne ""){
            $DsTypes += ","
        }
        $DsTypes += 'nosql'
    }

    Write-Verbose $DsTypes
    
    $DataItemsUrl = $ServerURL.TrimEnd('/') + '/arcgis/admin/data/findItems' 

    Write-Verbose $DataItemsUrl
    $response = Invoke-ArcGISWebRequest -Url $DataItemsUrl -HttpFormParameters  @{ f = 'json'; token = $Token; types = $DsTypes } -Referer $Referer 
    $result = $true
    $items = ($response.items | Where-Object { $_.provider -ieq 'ArcGIS Data Store' })
    Write-Verbose ($items | ConvertTo-Json -Depth 4)
    foreach($type in $DBTypes){
        Write-Verbose $type
        if($result){
            if($type -ieq 'Relational') {
                $result = $($items | Where-Object { ($_.type -ieq "egdb") } | Measure-Object).Count -gt 0
            }elseif($type -ieq 'TileCache'){
                $result = $($items | Where-Object { ($_.type -ieq "nosql") -and ($_.info.dsFeature -ieq "tileCache") } | Measure-Object).Count -gt 0
            }elseif($type -ieq 'SpatioTemporal'){
                $result = $($items | Where-Object { ($_.type -ieq "nosql") -and ($_.info.dsFeature -ieq "spatioTemporal") } | Measure-Object).Count -gt 0
            }elseif($type -ieq 'GraphStore'){
                $result = $($items | Where-Object { ($_.type -ieq "nosql") -and ($_.info.dsFeature -ieq "graphStore") } | Measure-Object).Count -gt 0
            }elseif($type -ieq 'ObjectStore'){
                $result = $($items | Where-Object { ($_.type -ieq "cloudStore") -and ($_.info.dsFeature -ieq "objectStore") } | Measure-Object).Count -gt 0
            }
            if(-not($result)){
                break
            }
        }
    }
    $result
}

Export-ModuleMember -Function *-TargetResource
