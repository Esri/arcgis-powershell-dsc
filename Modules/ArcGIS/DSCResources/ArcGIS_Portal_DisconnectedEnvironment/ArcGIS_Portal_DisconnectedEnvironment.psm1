<#
    .SYNOPSIS
        Configures the ArcGIS Portal for Disconnected Environment
    .PARAMETER Ensure
        Take the values Present or Absent. 
        - "Present" ensures that Portal is Configured for Disconnected-Use.
        - "Absent" ensures that Portal is Configured as out-of-the-box - Not Implemented.
    .PARAMETER HostName
        Host Name of the Machine on which the ArcGIS Portal is Installed
    .PARAMETER SiteAdministrator
        Credentials to access Server/Portal with admin privileges
    .PARAMETER DisableExternalContent
        Switch for Disabling External Content
    .PARAMETER ConfigProperties
        JSON of Properties and their values in config.js
    .PARAMETER HelperServices
        Defines HelperServices which shoult be set on Portal
#>

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [System.String]
        $HostName,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator,

        [System.String]
        $ConfigProperties,

        [System.Boolean]
        $DisableExternalContent = $false,

        [System.String]
        $HelperServices
    )
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    $null 
}
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [System.String]
        $HostName,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator,

        [System.String]
        $ConfigProperties,

        [System.Boolean]
        $DisableExternalContent = $false,

        [System.String]
        $HelperServices
    )
    #[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} # Allow self-signed certificates
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    Write-Verbose "Fully Qualified Domain Name :- $HostName" 
    $PortalUrl = "https://$($HostName):7443/arcgis"
    $ServiceRestartRequired = $false

    Wait-ForUrl -Url "$PortalUrl/portaladmin/" -LogFailures
    $token = Get-PortalToken -PortalHostName $HostName -Credential $SiteAdministrator -Referer "http://localhost"

    if ($DisableExternalContent) 
    {
        Set-ExternalContentEnabled -PortalUrl $PortalUrl -Token $($token.token)
    } else {
        Write-Verbose "Disconnected Environment DisableExternalContent set to false"
    }

    if ($ConfigProperties)
    {
        $ConfigFilePath = Get-ConfigFilePath
        $ConfigProps = ConvertFrom-Json $ConfigProperties
        
        ForEach ($Property in $ConfigProps.PSObject.Properties)
        {
            if (Set-PropertyInConfigFile -ConfigFilePath $ConfigFilePath -PropertyName $Property.Name -PropertyValue $Property.Value)
            {
                $ServiceRestartRequired = $true
            }
        }
    }

    if ($HelperServices)
    {
        $HelperSrvcs = ConvertFrom-Json $HelperServices
        $CurHelperServices = Get-HelperServices -PortalUrl $PortalUrl -Token $($token.token)
        $helperServiceParams = @{}

        if($HelperSrvcs.geometry)
        {
            if ($HelperSrvcs.geometry.useHostedServer)
            {
                $HostedServerUrl = Get-HostedServerUrl -PortalUrl $PortalUrl -Token $($token.token)
                if ($HostedServerUrl)
                {
                    if (-not (Test-GeometryStatus -ServerUrl $HostedServerUrl -Token $($token.token)))
                    {
                        Set-GeometryStatus -ServerUrl $HostedServerUrl -Token $($token.token)
                    }

                    if (-not (Test-GeometrySharing -ServerUrl $HostedServerUrl -PortalUrl $PortalUrl -Token $($token.token)))
                    {
                        Set-GeometrySharing -ServerUrl $HostedServerUrl -PortalUrl $PortalUrl -Token $($token.token)
                    }
                    
                    if (-not ($CurHelperServices.geometry.url.StartsWith($HostedServerUrl)))
                    {
                        $serviceUrl = "$HostedServerUrl/rest/services/Utilities/Geometry/GeometryServer"
                        $helperServiceParams.Add("geometryService",  '{"url": "' + $serviceUrl + '" }')
                    }
                } else {
                    Write-Warning "No Hosted Server available. Geometry-Service is not working."
                }
            }
            elseif ($HelperSrvcs.geometry.url)
            {
                if ($HelperSrvcs.geometry.url -ne $CurHelperServices.geometry.url)
                {
                    $helperServiceParams.Add("geometryService",  '{"url": "' + $HelperSrvcs.geometry.url + '" }')
                }
            }
        }
        if ($helperServiceParams.Count -gt 0)
        {
            Set-HelperServices -PortalUrl $PortalUrl -Token $($token.token) -HelperServices (ConvertTo-Json $helperServiceParams)
        }
    }

    if ($ServiceRestartRequired)
    {
        Restart-PortalService
        Wait-ForUrl "$($PortalUrl)/portaladmin" -HttpMethod 'GET'
    }

}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [System.String]
        $HostName,

        [System.Management.Automation.PSCredential]
        $SiteAdministrator,

        [System.String]
        $ConfigProperties,

        [System.Boolean]
        $DisableExternalContent = $false,

        [System.String]
        $HelperServices
    )
    #[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} # Allow self-signed certificates
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    $result = $true
    Write-Verbose "Fully Qualified Domain Name :- $HostName" 
    $PortalUrl = "https://$($HostName):7443/arcgis"

    Wait-ForUrl -Url "$PortalUrl/portaladmin/" -LogFailures
    $token = Get-PortalToken -PortalHostName $HostName -Credential $SiteAdministrator -Referer "http://localhost"

    if ($result -and $DisableExternalContent)
    {
        $result = Get-ExternalContentEnabled -PortalUrl $PortalUrl -Token $($token.token)
    }

    if ($result -and $ConfigProperties)
    {
        $ConfigFilePath = Get-ConfigFilePath

        $ConfigProps = ConvertFrom-Json $ConfigProperties
        ForEach ($Property in $ConfigProps.PSObject.Properties)
        {
            if (-not (Compare-PropertyInConfigFile -ConfigFilePath $ConfigFilePath -PropertyName $Property.Name -PropertyValue $Property.Value))
            {
                $result = $false
                break
            }
        }
    }

    if ($result -and $HelperServices)
    {
        $HelperSrvcs = ConvertFrom-Json $HelperServices
        $CurHelperServices = Get-HelperServices -PortalUrl $PortalUrl -Token $($token.token)

        if($result -and ($HelperSrvcs.geometry))
        {
            if ($HelperSrvcs.geometry.useHostedServer)
            {
                $HostedServerUrl = Get-HostedServerUrl -PortalUrl $PortalUrl -Token $($token.token)
                if ($result -and -not ($HostedServerUrl))
                {
                    Write-Warning "No Hosted Server available. Geometry-Service is not working."
                    $result = $false
                }
                
                if ($result -and -not ($CurHelperServices.geometry.url.StartsWith($HostedServerUrl)))
                {
                    Write-Verbose "Current Geometry-Service $($CurHelperServices.geometry.url) does not match Hosted-Server $HostedServerUrl"
                    $result = $false
                }

                if ($result -and -not (Test-GeometryStatus -ServerUrl $HostedServerUrl -Token $($token.token)))
                {
                    Write-Verbose "Geometry-Service on Hosted-Server not running"
                    $result = $false
                }

                if ($result -and -not (Test-GeometrySharing -ServerUrl $HostedServerUrl -PortalUrl $PortalUrl -Token $($token.token)))
                {
                    Write-Verbose "Geometry-Service is not shared to Everyone"
                    $result = $false
                }
            }
            elseif ($HelperSrvcs.geometry.url)
            {
                if ($HelperSrvcs.geometry.url -ne $CurHelperServices.geometry.url)
                {
                    Write-Verbose "Current Geometry-Service: $($CurHelperServices.geometry.url) does not match configured Url $($HelperSrvcs.geometry.url)"
                    $result = $false
                }
            }
        }
    }
    
    $result
}

function Test-GeometrySharing
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerUrl,

        [System.String]
        $PortalUrl,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost'
    )

    $geometryService = Invoke-ArcGISWebRequest -Url "$ServerUrl/admin/services/Utilities/Geometry.GeometryServer" `
                    -HttpFormParameters @{ f = 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET'

    $portalItemId = $geometryService.portalProperties.portalItems[0].itemId

    $result = Test-PortalItemSharing -PortalUrl $PortalUrl -Token $Token -PortalItemId $portalItemId

    $result
}

function Set-GeometrySharing
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerUrl,

        [System.String]
        $PortalUrl,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost'


    )

    $geometryService = Invoke-ArcGISWebRequest -Url "$ServerUrl/admin/services/Utilities/Geometry.GeometryServer" `
                    -HttpFormParameters @{ f = 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET'

    $portalItemId = $geometryService.portalProperties.portalItems[0].itemId
    $sharingParams = '{ "everyone": "true" }'

    Set-PortalItemSharing -PortalUrl $PortalUrl -Token $Token -PortalItemId $portalItemId -SharingParams $sharingParams
}

function Test-PortalItemSharing
{
    [CmdletBinding()]
    param(
        [System.String]
        $PortalUrl,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost',

        [System.String]
        $PortalItemId
    )

    $result = $false
    $portalItem = Invoke-ArcGISWebRequest -Url "$PortalUrl/sharing/rest/content/items/$PortalItemId" `
                    -HttpFormParameters @{ f = 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET'

    if ($portalItem.access -ieq "public")
    {
        $result = $true
    }
    $result
}

function Set-PortalItemSharing
{
    [CmdletBinding()]
    param(
        [System.String]
        $PortalUrl,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost',

        [System.String]
        $PortalItemId,

        [System.String]
        $SharingParams
    )

    $params =  @{ f = 'json'; token = $Token; }
    $shareParams = ConvertFrom-Json $SharingParams
    ForEach ($param in $shareParams.PSObject.Properties)
    {
        $params.Add($param.Name, $param.Value)
    }
    Write-Verbose "Sharing PortalItem:- $PortalItemId, $shareParams"
    Invoke-ArcGISWebRequest -Url "$PortalUrl/sharing/rest/content/items/$PortalItemId/share" -HttpFormParameters $params -Referer $Referer
}

function Test-GeometryStatus
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerUrl,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost'
    )

    $result = $false
    $status = Invoke-ArcGISWebRequest -Url "$ServerUrl/admin/services/Utilities/Geometry.GeometryServer/status" `
                    -HttpFormParameters @{ f = 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET'

    if (($status.configuredState -eq "STARTED") -and ($status.realTimeState -eq "STARTED"))
    {
        $result = $true
    }
    $result
}

function Set-GeometryStatus
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerUrl,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost',

        [System.String]
        $Status = "STARTED"
    )

    if ($Status -eq "STARTED")
    {
        Write-Verbose "Starting Geometry-Service"
        $resp = Invoke-ArcGISWebRequest -Url "$ServerUrl/admin/services/Utilities/Geometry.GeometryServer/start" `
                    -HttpFormParameters @{ f = 'json'; token = $Token; } -Referer $Referer -TimeOutSec 300 -LogResponse
        Write-Verbose "Response:- $resp"
    } else {
        Invoke-ArcGISWebRequest -Url "$ServerUrl/admin/services/Utilities/Geometry.GeometryServer/stop" `
                    -HttpFormParameters @{ f = 'json'; token = $Token; } -Referer $Referer -TimeOutSec 300
    }
}

function Get-HelperServices
{
    [CmdletBinding()]
    param(
        [System.String]
        $PortalUrl,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost'
    )

    $result = $false
    $portalsSelf = Invoke-ArcGISWebRequest -Url "$PortalUrl/sharing/rest/portals/self" `
                    -HttpFormParameters @{ f = 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET'

    $portalsSelf.helperServices
}

function Set-HelperServices
{
    [CmdletBinding()]
    param(
        [System.String]
        $PortalUrl,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost',

        [System.String]
        $HelperServices
    )

    $params =  @{ f = 'json'; token = $Token; }
    $helperSrvcs = ConvertFrom-Json $HelperServices
    ForEach ($service in $helperSrvcs.PSObject.Properties)
    {
        $params.Add($service.Name, $service.Value)
    }
    
    Write-Verbose "Set HelperServices:- $HelperServices"
    $resp = Invoke-ArcGISWebRequest -Url "$PortalUrl/sharing/rest/portals/self/update" -HttpFormParameters $params -Referer $Referer

    Write-Verbose "Response:- $resp"
}

function Get-HostedServerUrl
{
    [CmdletBinding()]
    param(
        [System.String]
        $PortalUrl,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost'
    )

    $result = $false
    $servers = Invoke-ArcGISWebRequest -Url "$PortalUrl/portaladmin/federation/servers" `
                    -HttpFormParameters @{ f = 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET'

    ForEach ($server in $servers.servers)
    {
        if ($server.isHosted)
        {
            $result = $server.adminUrl
            break
        }
    }

    $result
}

function Get-ConfigFilePath
{
    $ServiceName = 'Portal for ArcGIS'
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir
    $Version = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).RealVersion
    if ($Version.Split('.').Count -lt 3)
    {
        $Version += '.0'
    }
    $ConfigFilePath = Join-Path $InstallDir "customizations\$Version\webapps\arcgis#home\js\arcgisonline\config.js"

    $ConfigFilePath
}

function Get-PropertyFromConfigFile
{
    [CmdletBinding()]
    param(
        [string]
        $ConfigFilePath,

        [string]
        $PropertyName
    )
    
    $PropertyValue = $null
    if(Test-Path $ConfigFilePath) {
        Get-Content $ConfigFilePath | ForEach-Object {
            if($_ -and $_.Trim().StartsWith($PropertyName)){
                $Splits = $_.Split(':')
                if($Splits.Length -gt 1){
                    $Splits = $Splits[1].Split(',')
                    $PropertyValue = $Splits[0].Trim()
                }
            }
        }
    }
    $PropertyValue
}


function Set-PropertyInConfigFile
{
    [CmdletBinding()]
    param(
        [System.String]
        $ConfigFilePath,

        [System.String]
        $PropertyName,

        [System.String]
        $PropertyValue
    )

    $Changed = $false
    $Lines = @()
    $Exists = $false
    Write-Host $ConfigFilePath
    if(Test-Path $ConfigFilePath) 
    {
        Get-Content $ConfigFilePath | ForEach-Object {
            $Line = $_
            if($_ -and $_.Trim().StartsWith($PropertyName))
            {
                $Exists = $true
                $Splits = $_.Split(':')
                if($Splits.Length -gt 1)
                {
                    $Splits = $Splits[1].Split(',')
                    $CurrentValue = $Splits[0].Trim()
                    if ($CurrentValue -ieq $PropertyValue)
                    {
                        Write-Verbose "Property entry for '$PropertyName' already exists in $ConfigFilePath  and matches expected value '$PropertyValue'"
                    }
                    else 
                    {
                        $Line = $Line.Replace($CurrentValue, $PropertyValue.ToLower())
                        Write-Verbose $Line
                        $Changed = $true
                    }
                }
            }
            $Lines += $Line
        }

        if($Changed) 
        {
            Write-Verbose "Updating file $ConfigFilePath"
            Set-Content -Path $ConfigFilePath -Value $Lines -Force
        }
        elseif(-not($Exists))
        {
            Write-Verbose "Property $PropertyName does not exist in $ConfigFilePath. Property cannot be changed."
        }
    }
    Write-Verbose "Change applied:- $Changed"
    $Changed
}

function Compare-PropertyInConfigFile
{
    [CmdletBinding()]
    param(
        [System.String]
        $ConfigFilePath,

        [System.String]
        $PropertyName,

        [System.String]
        $PropertyValue
    )

    $CurrentValue = Get-PropertyFromConfigFile -ConfigFilePath $ConfigFilePath -PropertyName $PropertyName
    if($CurrentValue -ne $PropertyValue)
    {
        Write-Verbose "Current Value for '$PropertyName' is '$CurrentValue'. Expected value is '$PropertyValue'."
        $false       
    } else {
        Write-Verbose "Current Value for '$PropertyName' is '$CurrentValue' and matches expected value. No change needed"
        $true
    }
}

function Restart-PortalService {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [System.String]
        $ServiceName = 'Portal for ArcGIS'
    )

    try {
        Write-Verbose "Restarting Service $ServiceName"
        Stop-Service -Name $ServiceName -Force -ErrorAction Ignore
        Write-Verbose 'Stopping the service'
        Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Stopped'
        Write-Verbose 'Stopped the service'
    }
    catch {
        Write-Verbose "[WARNING] Stopping Service $_"
    }

    try {
        Write-Verbose 'Starting the service'
        Start-Service -Name $ServiceName -ErrorAction Ignore
        Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Running'
        Write-Verbose "Restarted Service '$ServiceName'"
    }
    catch {
        Write-Verbose "[WARNING] Starting Service $_"
    }
}


function Get-ExternalContentEnabled 
{
    [CmdletBinding()]
    param(
        [System.String]
        $PortalUrl,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost'
    )

    $configuration = Invoke-ArcGISWebRequest -Url "$PortalUrl/portaladmin/system/content/configuration" `
                    -HttpFormParameters @{ f = 'pjson'; token = $Token; } -Referer $Referer -HttpMethod 'GET'

    if ($configuration.isExternalContentEnabled -or $configuration.error) {
        $false
    } else {
        $true
    }

}

function Set-ExternalContentEnabled 
{
    [CmdletBinding()]
    param(
        [System.String]
        $PortalUrl,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost'
    )
    $result = $true

    if(-not(Get-ExternalContentEnabled -PortalUrl $PortalUrl -Token $Token -Referer $Referer))
    {
        # updating content configuration requires reindexing which may take up to a few minutes > timeout 600
        $configuration = Invoke-ArcGISWebRequest -Url "$PortalUrl/portaladmin/system/content/configuration/update" `
                        -HttpFormParameters @{ f = 'json'; token = $Token; externalContentEnabled = 'false'} -Referer $Referer `
                        -TimeOutSec 600 -HttpMethod 'POST'
        
        Write-Verbose "External Content disabled:- $configuration"
        $result = if($configuration.status -match "success") {$true} else {$false}
    } else {
        Write-Verbose "External Content already disabled in /portaladmin/system/content/configuration - skipping"
        $result = $true
    }
    $result
}

Export-ModuleMember -Function *-TargetResource


