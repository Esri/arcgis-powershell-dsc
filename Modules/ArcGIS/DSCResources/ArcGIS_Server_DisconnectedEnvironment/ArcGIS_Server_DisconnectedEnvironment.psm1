<#
    .SYNOPSIS
        Configures the ArcGIS Server for Disconnected Environment
    .PARAMETER Ensure
        Take the values Present or Absent. 
        - "Present" ensures that Server is Configured for Disconnected-Use.
        - "Absent" ensures that Server is Configured as out-of-the-box - Not Implemented.
    .PARAMETER HostName
        Host Name of the Machine on which the ArcGIS Server is Installed
    .PARAMETER SiteAdministrator
        Credentials to access Server/Portal with admin privileges
    .PARAMETER EnableJsApi
        Boolean if JsApi for Rest-Interface should be set to Portals EnableJsApi
    .PARAMETER EnableArcGISOnlineMapViewer
        Boolean if ArcGIS.com-Map is set to Portal
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

        [System.Boolean]
        $EnableJsApi = $true,

        [System.Boolean]
        $EnableArcGISOnlineMapViewer = $false

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

        [System.Boolean]
        $EnableJsApi = $true,

        [System.Boolean]
        $EnableArcGISOnlineMapViewer = $false
    )

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    if($Ensure -ieq 'Present') 
    {
        Write-Verbose "Fully Qualified Domain Name :- $HostName" 
        $Referer = 'http://localhost'
        $ServerUrl = "http://$($HostName):6080"
        
        $result = $true
        
        Write-Verbose "Checking for Servicesdirectory on '$ServerUrl'"
        Wait-ForUrl -Url $ServerUrl -SleepTimeInSeconds 5 -HttpMethod 'GET'  
        $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer

        if ($token.token -ne $null)
        {
            $securityconfiguration = Get-AdminSettings -ServerUrl $ServerUrl -SettingUrl "arcgis/admin/security/config" `
                                -Token $token.token -Referer $Referer

            $portalProperties = $securityconfiguration.portalProperties

            if($portalProperties -and $portalProperties.portalUrl)
            {
                $servicesdirectory = Get-AdminSettings -ServerUrl $ServerUrl -SettingUrl "arcgis/admin/system/handlers/rest/servicesdirectory" `
                                    -Token $token.token -Referer $Referer
                if($EnableJsApi)
                {
                    $servicesdirectory.'jsapi.arcgis' = ($portalProperties.portalUrl).TrimEnd("/") + "/jsapi/jsapi4"
                    $servicesdirectory.'jsapi.arcgis.css' = ($portalProperties.portalUrl).TrimEnd("/") + "/jsapi/jsapi4/esri/css/main.css"
                }
                if($EnableArcGISOnlineMapViewer)
                {
                    $servicesdirectory.'arcgis.com.map' = ($portalProperties.portalUrl).TrimEnd("/") + "/home/webmap/viewer.html"
                    $servicesdirectory.'arcgis.com.map.text' = "ArcGIS Enterprise Viewer"
                }
                $servicesdirectory = ConvertTo-Json $servicesdirectory
                $result = Set-AdminSettings -ServerUrl $ServerUrl -SettingUrl "arcgis/admin/system/handlers/rest/servicesdirectory/edit" `
                                    -Token $token.token -Properties $servicesdirectory -Referer $Referer
                Write-Verbose "Set-Servicesdirectory: $result"
            }
        }
    }
    else
    {
        Write-Verbose "Absent Not Implemented Yet!"
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
        
        [System.Boolean]
        $EnableJsApi = $false,

        [System.Boolean]
        $EnableArcGISOnlineMapViewer = $false
    )
    #[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    $result = $true

    if($EnableJsApi -or $EnableArcGISOnlineMapViewer)
    {
        $result = $false
        Write-Verbose "Fully Qualified Domain Name :- $HostName" 
        $Referer = 'http://localhost'
        $ServerUrl = "http://$($HostName):6080"
        
        $result = $true
        try {        
            Write-Verbose "Checking for Servicesdirectory on '$ServerUrl'"
            Wait-ForUrl -Url $ServerUrl -SleepTimeInSeconds 5 -HttpMethod 'GET'  
            $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer

            if ($token.token -ne $null)
            {
                $securityconfiguration = Get-AdminSettings -ServerUrl $ServerUrl -SettingUrl "arcgis/admin/security/config" `
                                    -Token $token.token -Referer $Referer

                $portalProperties = $securityconfiguration.portalProperties
                
                if($portalProperties -and $portalProperties.portalUrl)
                {
                    $servicesdirectory = Get-AdminSettings -ServerUrl $ServerUrl -SettingUrl "arcgis/admin/system/handlers/rest/servicesdirectory" `
                                        -Token $token.token -Referer $Referer
                    if($result -and $EnableJsApi)
                    {
                        if(($servicesdirectory.'jsapi.arcgis' -notmatch $portalProperties.portalUrl) -or
                            ($servicesdirectory.'jsapi.arcgis.css' -notmatch $portalProperties.portalUrl))
                        {
                            Write-Verbose "JsApi not set to Portal-JsApi: $($servicesdirectory.'jsapi.arcgis')"
                            $result = $false
                        }
                    }

                    if($result -and $EnableArcGISOnlineMapViewer)
                    {
                        if(($servicesdirectory.'arcgis.com.map' -notmatch $portalProperties.portalUrl))
                        {
                            Write-Verbose "ArcGIS.com-Map not set to Portal: $($servicesdirectory.'arcgis.com.map')"
                            $result = $false
                        }
                    }
                }
                else
                {
                    Write-Verbose "Error: Server not Federated. Handler for Servicesdirectory cannot be changed."
                    $result = $false
                }
            }
        }
        catch
        {
            Write-Verbose "Error: $_"
            $result = $false
        }
    }

    $result   
}

function Get-AdminSettings
{
    [CmdletBinding()]
    Param
    (
        [System.String]
        $ServerUrl,

        [System.String]
        $SettingUrl, 

        [System.String]
        $Token, 
        
        [System.String]
        $Referer
    )

    $RequestUrl  = $ServerUrl.TrimEnd("/") + "/" + $SettingUrl.TrimStart("/")
    $props = @{ f= 'json'; token = $Token; }
    $cmdBody = To-HttpBody $props   
    $headers = @{'Content-type'='application/x-www-form-urlencoded'
                'Content-Length' = $cmdBody.Length
                'Accept' = 'text/plain'
                'Referer' = $Referer
                }

    $res = Invoke-WebRequest -Uri $RequestUrl -Body $cmdBody -Method POST -Headers $headers -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing 
    $response = $res.Content | ConvertFrom-Json
	Write-Verbose "Response from Get-AdminSettings ($RequestUrl):- $($res.Content)"
    Check-ResponseStatus $response 
    $response    
}

function Set-AdminSettings
{
    [CmdletBinding()]
    Param
    (
        [System.String]
        $ServerUrl,

        [System.String]
        $SettingUrl, 

        [System.String]
        $Token, 
        
        [System.String]
        $Referer,

        [System.String]
        $Properties
    )
    
    $COProperties = $Properties | ConvertFrom-Json
    $RequestUrl  = $ServerUrl.TrimEnd("/") + "/" + $SettingUrl.TrimStart("/")
    $props = @{ f= 'json'; token = $Token; }
    $COProperties.psobject.properties | Foreach { $props[$_.Name] = $_.Value }
    if ($props['enabled'])
    {
        $props['servicesDirEnabled'] = $props['enabled']
    }
    $cmdBody = To-HttpBody $props   
    $headers = @{'Content-type'='application/x-www-form-urlencoded'
                'Content-Length' = $cmdBody.Length
                'Accept' = 'text/plain'
                'Referer' = $Referer
                }
    $res = Invoke-WebRequest -Uri $RequestUrl -Body $cmdBody -Method POST -Headers $headers -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing 
    $response = $res.Content | ConvertFrom-Json
	Write-Verbose "Response from Set-AdminSettings ($RequestUrl):- $($res.Content)"
    Check-ResponseStatus $response 
    $response    
}


Export-ModuleMember -Function *-TargetResource


