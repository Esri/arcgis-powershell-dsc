$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

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
    .PARAMETER SiteAdminUrl
        Server Site Admin URL 

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

	$null
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

        [parameter(Mandatory = $false)]
		[System.String]
		$SiteAdminUrl,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $ServiceName = 'ArcGISGeoEvent'
    $GatewayServiceName = 'ArcGISGeoEventGateway'
    if($Ensure -ieq 'Present') {
        Write-Verbose "Stopping the service '$ServiceName'"    
        Stop-Service -Name $ServiceName -ErrorAction Ignore    
        Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Stopped'
        
        Write-Verbose "Installing Windows Feature: IIS-WebSockets as a PreReq for GeoEvents Server"
        if (Get-Command "Get-WindowsOptionalFeature" -errorAction SilentlyContinue)
        {
            if(-not((Get-WindowsOptionalFeature -FeatureName IIS-WebSockets -online).State -ieq "Enabled")){
                Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebSockets -All
            }
        }else{
            Write-Verbose "Unable to Install Window Feature - IIS-WebSockets"
        }

		$FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
		$ServerUrl = "https://$($FQDN):6443"   
		$Referer = $ServerUrl
		Wait-ForUrl -Url "$ServerUrl/arcgis/admin" -MaxWaitTimeInSeconds 90 -SleepTimeInSeconds 5
		$token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer 

        if($SiteAdminUrl) {
            $machineProps = Get-ArcGISMachineProperties -ServerHostName $FQDN -MachineName $FQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer 
            if($machineProps.adminURL -ine $SiteAdminUrl) {
                Write-Verbose "Configured AdminUrl '$($machineProps.adminURL)' does not match expected value of '$SiteAdminUrl'. Updating it"
                $machineProps.adminURL = $SiteAdminUrl
                try{ 
                    Set-ArcGISMachineProperties -ServerHostName $FQDN -MachineName $FQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer -MachineProperties $machineProps
                }catch {
                    Write-Verbose "[WARNING]:- Set-ArcGISMachineProperties applied. Operation typically causes a restart and does not return a response"
                }
                Write-Verbose "Updated the AdminUrl. Wait for Server to return (if it restarts)"
                Wait-ForUrl -Url "$ServerUrl/arcgis/admin" -MaxWaitTimeInSeconds 90 -SleepTimeInSeconds 5
            }
        }

        Write-Verbose "Checking if WebSocketContextURL in sys props is $WebSocketContextUrl"
        $sysProps = Get-ArcGISAdminSystemProperties -ServerHostName $FQDN -SiteName 'arcgis' -Referer $Referer -Token $token.token
        if($sysProps.WebSocketContextURL -ine $WebSocketContextUrl) {
            Write-Verbose "Current Value of WebSocketContextURL in sys props is '$($sysProps.WebSocketContextURL)' and does not match '$WebSocketContextUrl'. Setting it"
            if(-not($sysProps)) { $sysProps = @{} }
			if(-not($sysProps.WebSocketContextURL)) {
				Add-Member -InputObject $sysProps -MemberType NoteProperty -Name 'WebSocketContextURL' -Value $WebSocketContextUrl
			}else {
                $sysProps.WebSocketContextURL = $WebSocketContextUrl
            }
            $setResponse = Set-ArcGISAdminSystemProperties -ServerHostName $FQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer -Properties $sysProps
            Write-Verbose "Response from Set Properties:- $setResponse"
        }
       
        Write-Verbose "Starting the service '$ServiceName'"    
		Start-Service -Name $ServiceName -ErrorAction Ignore       
        Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Running' -Verbose
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

        [parameter(Mandatory = $false)]
		[System.String]
		$SiteAdminUrl,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null

	$ServiceName = 'ArcGISGeoEvent'
    $result = $true    
    $result = (Get-Service -Name $ServiceName -ErrorAction Ignore).Status -ieq 'Running'
    
    if($result) {
        $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
		$ServerUrl = "https://$($FQDN):6443"   
		$Referer = $ServerUrl
		Wait-ForUrl -Url "$ServerUrl/arcgis/admin" -MaxWaitTimeInSeconds 90 -SleepTimeInSeconds 5
		$token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer 

        Write-Verbose "Checking if WebSocketContextURL in sys props is $WebSocketContextUrl"
        $sysProps = Get-ArcGISAdminSystemProperties -ServerHostName $FQDN -SiteName 'arcgis' -Referer $Referer -Token $token.token
        if($sysProps.WebSocketContextURL -ine $WebSocketContextUrl) {
            Write-Verbose "Current Value of WebSocketContextURL in sys props is '$($sysProps.WebSocketContextURL)'"
            $result = $false
        }

        if($result -and $SiteAdminUrl) {
            $machineProps = Get-ArcGISMachineProperties -ServerHostName $FQDN -MachineName $FQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer 
            if($machineProps.adminURL -ine $SiteAdminUrl) {
                Write-Verbose "Configured AdminUrl '$($machineProps.adminURL)' does not match expected value of '$SiteAdminUrl'"
                $result = $false
            }
        }
    }

    if($Ensure -ieq 'Present') {
	       $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}

function Get-ArcGISMachineProperties
{
    [CmdletBinding()]
    param(
    [System.String]
        [Parameter(Mandatory=$true)]
        $ServerHostName,

        [Parameter(Mandatory=$true)]
        $MachineName,

        [System.String]
        [Parameter(Mandatory=$false)]
        $SiteName = 'arcgis',

        [System.String]
        [Parameter(Mandatory=$true)]
        $Token,        

        [System.String]
        [Parameter(Mandatory=$false)]
        $Referer = 'http://localhost',
                
        [System.Int32]
        [Parameter(Mandatory=$false)]
        $ServerPort = 6443
    )

    $Scheme = if($ServerPort -eq 6080 -or $ServerPort -eq 80) { 'http' } else { 'https' }
    Invoke-ArcGISWebRequest -Url ("$($Scheme)://$($ServerHostName):$($ServerPort)/$SiteName" + '/admin/machines/' + $MachineName + '/') -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer
}

function Set-ArcGISMachineProperties
{
    [CmdletBinding()]
    param(
    [System.String]
        [Parameter(Mandatory=$true)]
        $ServerHostName,

        [Parameter(Mandatory=$true)]
        $MachineName,

        [System.String]
        [Parameter(Mandatory=$false)]
        $SiteName = 'arcgis',

        [System.String]
        [Parameter(Mandatory=$true)]
        $Token,        

        [System.String]
        [Parameter(Mandatory=$false)]
        $Referer = 'http://localhost',
                
        [System.Int32]
        [Parameter(Mandatory=$false)]
        $ServerPort = 6443,

        [Parameter(Mandatory=$true)]
        $MachineProperties
    )
    $Props = @{ 
                machineName = $MachineProperties.machineName
                adminURL = $MachineProperties.adminURL
                webServerMaxHeapSize = $MachineProperties.webServerMaxHeapSize
                webServerCertificateAlias = $MachineProperties.webServerCertificateAlias
                appServerMaxHeapSize = $MachineProperties.appServerMaxHeapSize
                socMaxHeapSize = $MachineProperties.socMaxHeapSize
                OpenEJBPort = $MachineProperties.ports.OpenEJBPort
                JMXPort = $MachineProperties.ports.JMXPort
                NamingPort = $MachineProperties.ports.NamingPort
                DerbyPort = $MachineProperties.ports.DerbyPort
                f = 'json'
                token = $Token
              }   
              $Scheme = if($ServerPort -eq 6080 -or $ServerPort -eq 80) { 'http' } else { 'https' }
   Invoke-ArcGISWebRequest -Url ("$($Scheme)://$($ServerHostName):$($ServerPort)/$SiteName" + '/admin/machines/' + $MachineName + '/edit') -HttpFormParameters $Props -Referer $Referer -HttpMethod 'POST' 
}

function Get-ArcGISAdminSystemProperties
{
    [CmdletBinding()]
    param(
    [System.String]
        [Parameter(Mandatory=$true)]
        $ServerHostName,

        [System.String]
        [Parameter(Mandatory=$false)]
        $SiteName = 'arcgis',

        [System.String]
        [Parameter(Mandatory=$true)]
        $Token,        

        [System.String]
        [Parameter(Mandatory=$false)]
        $Referer = 'http://localhost',
                
        [System.Int32]
        [Parameter(Mandatory=$false)]
        $ServerPort = 6443
    )
    $Scheme = if($ServerPort -eq 6080 -or $ServerPort -eq 80) { 'http' } else { 'https' }
   Invoke-ArcGISWebRequest -Url ("$($Scheme)://$($ServerHostName):$($ServerPort)/$SiteName" + '/admin/system/properties/') -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer
}

function Set-ArcGISAdminSystemProperties
{
    [CmdletBinding()]
    param(
    [System.String]
        [Parameter(Mandatory=$true)]
        $ServerHostName,

        [System.String]
        [Parameter(Mandatory=$false)]
        $SiteName = 'arcgis',

        [System.String]
        [Parameter(Mandatory=$true)]
        $Token,        

        [System.String]
        [Parameter(Mandatory=$false)]
        $Referer = 'http://localhost',
                
        [System.Int32]
        [Parameter(Mandatory=$false)]
        $ServerPort = 6443,

        [Parameter(Mandatory=$true)]
        $Properties
    )
    $Scheme = if($ServerPort -eq 6080 -or $ServerPort -eq 80) { 'http' } else { 'https' }
   Invoke-ArcGISWebRequest -Url ("$($Scheme)://$($ServerHostName):$($ServerPort)/$SiteName" + '/admin/system/properties/update') -HttpFormParameters @{ f = 'json'; token = $Token; properties = (ConvertTo-Json $Properties -Depth 5) } -Referer $Referer
}

Export-ModuleMember -Function *-TargetResource

