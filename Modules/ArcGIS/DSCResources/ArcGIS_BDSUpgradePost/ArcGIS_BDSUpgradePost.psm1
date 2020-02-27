<#
    .SYNOPSIS
        Starts SpatioTemporal Datastore after Upgrade
    .PARAMETER Ensure
        Indicates if the Datatore Upgrade Process should take place. Take the values Present or Absent. 
        - "Present" ensures that DataStore is Upgraded to the version specified.
        - "Absent" ensures that DataStore is not upgraded or downgraded from a give version (Not Implemented).
    .PARAMETER ServerHostName
         HostName of the GIS Server for which the datastore was created and registered.
    .PARAMETER SiteAdministrator
        A MSFT_Credential Object - Primary Site Administrator to access the GIS Server. 
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
		$SiteAdministrator
    )
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

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
		$SiteAdministrator
    )
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    if($Ensure -ieq 'Present') {
       try{ 
        $MachineFQDN = Get-FQDN $env:ComputerName
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
    
        
        #retart big data store    
        Write-Verbose "Checking if the Spatiotemporal Big Data Store has started."
        if(-not(Test-SpatiotemporalBigDataStoreStarted -ServerURL $ServerUrl -Token $token.token -Referer $Referer -MachineFQDN $MachineFQDN)) {
            Write-Verbose "Starting the Spatiotemporal Big Data Store."
            Start-SpatiotemporalBigDataStore -ServerURL $ServerUrl -Token $token.token -Referer $Referer -MachineFQDN $MachineFQDN
        }else {
            Write-Verbose "The Spatiotemporal Big Data Store is already started."
        }
    }
    catch{
        write-verbose "Some Error - $($_)"
    } 
    }else{
        Write-Verbose "Stop BigDataStore, Do Nothing for now"
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
		$SiteAdministrator
    )
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    $result = $False

    $MachineFQDN = Get-FQDN $env:ComputerName
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
    
    Write-Verbose "Checking if the Spatiotemporal Big Data Store has started."
    if(Test-SpatiotemporalBigDataStoreStarted -ServerURL $ServerUrl -Token $token.token -Referer $Referer -MachineFQDN $MachineFQDN) {
        $result = $True
    }

    if($Ensure -ieq 'Present') {
	    $result
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}

function Test-SpatiotemporalBigDataStoreStarted
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [System.String]
        $ServerURL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $MachineFQDN
    )

   $DataItemsUrl = $ServerURL.TrimEnd('/') + '/arcgis/admin/data/findItems' 
   $response = Invoke-ArcGISWebRequest -Url $DataItemsUrl -HttpFormParameters @{ f = 'json'; token = $Token; types = 'nosql' }  -Referer $Referer    
   $dataStorePath = $null
   if($response.items -and $response.items.length -gt 0) {
        $dataStorePath = $response.items[0].path
   } else {
       throw "Spatiotemporal Big DataStore not found in arcgis data items"
   }
   Write-Verbose "Data Store Path:- $dataStorePath"
   $Url = $ServerURL.TrimEnd('/') + '/arcgis/admin/data/items' + "$dataStorePath/machines/$MachineFQDN/validate/"
   Write-Verbose $Url
   try {    
    $response = Invoke-ArcGISWebRequest -Url $Url -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer -HttpMethod 'POST'    
    $n = $response.nodes | Where-Object {$_.name -ieq (Resolve-DnsName -Type ANY $env:ComputerName).IPAddress}
    Write-Verbose "Machine Ip --> $($n.name)"
    $n -and $response.isHealthy -ieq 'True'
   }
   catch {
    Write-Verbose "[WARNING] Attempt to check if Spatiotemporal Big DataStore is started returned error:-  $_"
    $false
   }
}

function Start-SpatiotemporalBigDataStore
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerURL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $MachineFQDN
    )

   $DataItemsUrl = $ServerURL.TrimEnd('/') + '/arcgis/admin/data/findItems' 
   $response = Invoke-ArcGISWebRequest -Url $DataItemsUrl -HttpFormParameters @{ f = 'json'; token = $Token; types = 'nosql' }  -Referer $Referer    
   $dataStorePath = $null
   if($response.items -and $response.items.length -gt 0) {
        $dataStorePath = $response.items[0].path
   } else {
       throw "Spatiotemporal Big DataStore not found in arcgis data items"
   }
   Write-Verbose "Data Store Path:- $dataStorePath"
   $Url = $ServerURL.TrimEnd('/') + '/arcgis/admin/data/items' + "$dataStorePath/machines/$MachineFQDN/start/"
   Invoke-ArcGISWebRequest -Url $Url -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer -HttpMethod 'POST' -Verbose
}

Export-ModuleMember -Function *-TargetResource