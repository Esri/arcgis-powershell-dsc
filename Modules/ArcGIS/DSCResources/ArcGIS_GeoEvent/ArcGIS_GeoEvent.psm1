$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.Server.psm1'))

<#
    .SYNOPSIS
        Makes a request to the installed Server to create a New Server Site or Join it to an existing Server Site
    .PARAMETER Ensure
        Indicates to make sure GeoEvents Server is Configured Correcly. Take the values Present or Absent. 
        - "Present" ensures that GeoEvents Server is Configured Correcly, if not Configured created.
        - "Absent" ensures that GeoEvents Server is unconfigured, i.e. if present (not implemented).
    .PARAMETER ServerHostName
        Optional Host Name or IP of the Machine on which the GeoEvent has been installed and is to be configured.
    .PARAMETER Version
        Version of the Geoevent Server
    .PARAMETER Name
        Name of the Geoevent Server Resource
    .PARAMETER SiteAdministrator
        A MSFT_Credential Object - Primary Site Administrator for the Server
    .PARAMETER WebSocketContextUrl
        WebSocket Url for GeoEvent Server    

#>
function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
        [parameter(Mandatory = $true)]    
        [System.String]
        $Version,

        [parameter(Mandatory = $false)]    
        [System.String]
        $ServerHostName,

		[parameter(Mandatory = $true)]
		[System.String]
		$Name
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
        $Version,

        [parameter(Mandatory = $false)]    
        [System.String]
        $ServerHostName,

		[parameter(Mandatory = $true)]
		[System.String]
		$Name,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
        $SiteAdministrator,
        
        [parameter(Mandatory = $true)]
		[System.String]
		$WebSocketContextUrl,

        [ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)

    $ServiceName = 'ArcGISGeoEvent'
    $GatewayServiceName = 'ArcGISGeoEventGateway'
    if($Ensure -ieq 'Present') {
        Write-Verbose "Stopping the service '$ServiceName'"    
        Stop-ServiceAndWait -ServiceName $ServiceName -TimeoutSeconds 300 -PollSeconds 2 -Verbose
        
		$FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
		$ServerBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName "Server" -FQDN $FQDN
		$Referer = 'https://localhost'
		Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName "Server" -MaxWaitTimeInSeconds 90 -SleepTimeInSeconds 5
		$token = Get-ServerToken -URL $ServerBaseUrl -Credential $SiteAdministrator -Referer $Referer 
        Write-Verbose "Checking if WebSocketContextURL in sys props is $WebSocketContextUrl"
        
        $sysProps = Get-SystemProperties -URL $ServerBaseUrl -Token $token.token -Referer $Referer
        if($sysProps.WebSocketContextURL -ine $WebSocketContextUrl) {
            Write-Verbose "Current Value of WebSocketContextURL in sys props is '$($sysProps.WebSocketContextURL)' and does not match '$WebSocketContextUrl'. Setting it"
            if(-not($sysProps)) { $sysProps = @{} }
			if(-not($sysProps.WebSocketContextURL)) {
				Add-Member -InputObject $sysProps -MemberType NoteProperty -Name 'WebSocketContextURL' -Value $WebSocketContextUrl
			}else {
                $sysProps.WebSocketContextURL = $WebSocketContextUrl
            }
            $setResponse = Set-SystemProperties -URL $ServerBaseUrl -Token $token.token -Referer $Referer -Properties $sysProps
            Write-Verbose "Response from Set Properties:- $setResponse"
        }
       
        Write-Verbose "Starting the service '$ServiceName'"    
		Start-ServiceAndWait -ServiceName $ServiceName -TimeoutSeconds 300 -PollSeconds 2 -Verbose
        Write-Verbose "Starting Sleep - 60 Seconds"
        Start-Sleep -Seconds 60
        Write-Verbose "Ended Sleep - 60 Seconds"
    }else{
        Write-Warning 'Absent not implemented'
    }
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [parameter(Mandatory = $false)]    
        [System.String]
        $ServerHostName,

        [parameter(Mandatory = $true)]    
        [System.String]
        $Version,

		[parameter(Mandatory = $true)]
		[System.String]
		$Name,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

        [parameter(Mandatory = $true)]
		[System.String]
		$WebSocketContextUrl,

        [ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)


	$ServiceName = 'ArcGISGeoEvent'
    $result = $true    
    $result = (Get-Service -Name $ServiceName -ErrorAction Ignore).Status -ieq 'Running'
    
    if($result) {
        $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
        $ServerBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName "Server" -FQDN $FQDN
		$Referer = 'https://localhost'
        Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName "Server" -MaxWaitTimeInSeconds 90 -SleepTimeInSeconds 5
		
        $token = Get-ServerToken -URL $ServerBaseUrl -Credential $SiteAdministrator -Referer $Referer
        Write-Verbose "Checking if WebSocketContextURL in sys props is $WebSocketContextUrl"
        $sysProps = Get-SystemProperties -URL $ServerBaseUrl -Token $token.token -Referer $Referer
        if($sysProps.WebSocketContextURL -ine $WebSocketContextUrl) {
            Write-Verbose "Current Value of WebSocketContextURL in sys props is '$($sysProps.WebSocketContextURL)'"
            $result = $false
        }
    }

    if($Ensure -ieq 'Present') {
	       $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}

Export-ModuleMember -Function *-TargetResource