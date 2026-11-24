$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.Server.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.Portal.psm1'))

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
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer","Portal","ServerWA","PortalWA","DataStore","SpatioTemporal","TileCache","GraphStore","ObjectStore","UnregisterPortal","DataPipelinesServer","VelocityServer")]
		[System.String]
        $Component,

        [parameter(Mandatory = $true)]
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer","DataPipelinesServer","Portal","WebAdaptor","DataStore","PortalUpgrade","VelocityServer")]
		[System.String]
        $InvokingComponent,
               
        [parameter(Mandatory = $true)]
		[System.String]
        $ComponentHostName,
        
        [parameter(Mandatory = $true)]
		[System.String]
		$ComponentContext
	)
    
	@{}
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer","Portal","ServerWA","PortalWA","DataStore","SpatioTemporal","TileCache","GraphStore","ObjectStore","UnregisterPortal","DataPipelinesServer","VelocityServer")]
		[System.String]
        $Component,

        [parameter(Mandatory = $true)]
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer","Portal","WebAdaptor","DataStore","PortalUpgrade","DataPipelinesServer","VelocityServer")]
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
    
    $NumCount = 0
	$Done     = $false
	$ReadinessParameters = @{
        Component = $Component
        InvokingComponent = $InvokingComponent
        ComponentHostName = $ComponentHostName
        ComponentContext = $ComponentContext
        Ensure = $Ensure
        Credential = $Credential
    }
	while ((-not $Done) -and ($NumCount++ -le $RetryCount)) 
	{
        Write-Verbose "Attempt $NumCount - $Component"
        try {
            $Done = Test-TargetResource @ReadinessParameters
            if($Done -and $Component -iin @("Server","NotebookServer","MissionServer","VideoServer","DataPipelinesServer","VelocityServer")){
                $Done = $false
                Start-Sleep -Seconds 120
                $Done = Test-TargetResource @ReadinessParameters
            }
        }catch {
            $Done = $false
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

    if(-not($Done)){
        throw "Timed out waiting for $Component on '$ComponentHostName' to become ready."
    }
}



function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer","Portal","ServerWA","PortalWA","DataStore","SpatioTemporal","TileCache","GraphStore","ObjectStore","UnregisterPortal","DataPipelinesServer","VelocityServer")]
		[System.String]
        $Component,

        [parameter(Mandatory = $true)]
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer","Portal","WebAdaptor","DataStore","PortalUpgrade","DataPipelinesServer","VelocityServer")]
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
    
    $Referer = 'https://localhost'
    $result = $false
    $ComponentHostNameFQDN = Get-FQDN $ComponentHostName
    try {
        if($Component -ieq "Server" -or $Component -ieq "NotebookServer" -or $Component -ieq "MissionServer" -or $Component -ieq "VideoServer" -or $Component -ieq "DataPipelinesServer" -or $Component -ieq "VelocityServer"){
            Write-Verbose "Checking for $Component site"
            $ServerBaseURL = Get-ArcGISComponentBaseUrl -ComponentName $Component -FQDN $ComponentHostNameFQDN
            $token = Get-ServerToken -URL $ServerBaseURL -Credential $Credential -Referer $Referer
            $result = ($null -ne $token.token)
            if($result){
                $result = $false
                $null = Test-ArcGISComponentHealth -BaseURL $ServerBaseURL -ComponentName $Component -ThrowErrors $true -Verbose
                $result = $true
                Write-Verbose "$Component Site Exists. Was able to retrieve token for PSA"
            }else{
                Write-Verbose "Unable to detect if $Component Site Exists. Was NOT able to retrieve token for PSA"
            }
        }
        elseif($Component -ieq "Portal"){
            Write-Verbose "Checking for Portal site on '$ComponentHostName'"
            $PortalBaseURL = Get-ArcGISComponentBaseUrl -ComponentName "Portal" -FQDN $ComponentHostNameFQDN
            $token = Get-PortalToken -URL $PortalBaseURL -Credential $Credential -Referer $Referer 
            $result = ($null -ne $token.token)
            if($result){
                Write-Verbose "Portal Site Exists. Was able to retrieve token for PSA. Making a secondary check"
                $result = Test-PortalAdminHealth -URL $PortalBaseURL  -Referer $Referer -Verbose
            }else{
                Write-Verbose "Unable to detect if Portal Site Exists. Was NOT able to retrieve token for PSA"
            }
        }elseif($Component -ieq "DataStore" -or $Component -ieq "SpatioTemporal" -or $Component -ieq "TileCache" -or $Component -ieq "GraphStore" -or $Component -ieq "ObjectStore"){
            $ServerBaseURL = Get-ArcGISComponentBaseUrl -ComponentName "Server" -FQDN $ComponentHostNameFQDN
            $token = Get-ServerToken -URL $ServerBaseURL -Credential $Credential -Referer $Referer
            
            Write-Verbose "Checking if data store is registered"
            $AdditionalParams = $Component
            if($Component -ieq "DataStore"){
                $AdditionalParams = 'Relational'
            }
            $result = Test-DataStoreRegistered -ServerBaseURL $ServerBaseURL -Token $token.token -Referer $Referer -Type $AdditionalParams
            if($result){
                Write-Verbose "All Types of DataStores are registered."
            }else{
                Write-Verbose "One or More Types of DataStore given as Parameter is not registered as Primary or Standby"
            }
        }elseif($Component -ieq "PortalWA"){
            Write-Verbose "Checking for Portal WebAdaptor"
            $PortalBaseURL = Get-ArcGISComponentBaseUrl -ComponentName "Portal" -FQDN $ComponentHostNameFQDN -Port 443 -Context $ComponentContext
            $token = Get-PortalToken -URL $PortalBaseURL -Credential $Credential -Referer $Referer 
            $result = ($null -ne $token.token)
            if($result){
                Write-Verbose "Portal WebAdaptor Works. Was able to retrieve token for PSA"
            }else{
                Write-Verbose "Unable to detect if Portal WebAdaptor Works Correctly. Was NOT able to retrieve token for PSA"
            }
        }elseif($Component -ieq "ServerWA"){
            Write-Verbose "Checking for Server WebAdaptor"
            $ServerBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName "Server" -FQDN $ComponentHostNameFQDN -Port 443 -Context $ComponentContext
            $token = Get-ServerToken -URL $ServerBaseUrl -Credential $Credential -Referer $Referer 
            $result = ($null -ne $token.token)
            if($result){
                Write-Verbose "Server WebAdaptor Works. Was able to retrieve token for PSA"
            }else{
                Write-Verbose "Unable to detect if Server WebAdaptor Works Correctly. Was NOT able to retrieve token for PSA"
            }
        }elseif($Component -ieq "UnregisterPortal"){
            $Referer = 'https://localhost'
            $PortalBaseURL = Get-ArcGISComponentBaseUrl -ComponentName "Portal" -FQDN $ComponentHostNameFQDN
            $token = Get-PortalToken -URL $PortalBaseURL -Credential $Credential -Referer $Referer 
            $StandbyMachine = Get-FQDN $env:COMPUTERNAME
            $IsMachineInSite = Test-MachineInPortalSite -URL $PortalBaseURL -Token $token.token  -Referer $Referer -MachineFQDN $StandbyMachine
            $result = -not($IsMachineInSite)
        }
    }catch {
        $result = $false
        Write-Verbose "[WARNING] The Resource is not available yet!"
        #Write-Verbose "[WARNING]:- $($_)"
    }
    
    $result
}

function Test-DataStoreRegistered
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerBaseURL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $Type
    )

    $items = Find-DataItems -URL $ServerBaseURL -Token $Token -Type $Type -IsArcGISDataStore -Referer $Referer -Verbose
    #Write-Verbose ($items | ConvertTo-Json -Depth 4)
    return (@($items).Count -gt 0)
}

Export-ModuleMember -Function *-TargetResource
