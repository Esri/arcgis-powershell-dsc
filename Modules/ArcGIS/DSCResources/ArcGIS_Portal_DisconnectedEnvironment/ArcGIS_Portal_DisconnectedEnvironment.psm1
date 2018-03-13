<#
    .SYNOPSIS
        Configures the ArcGIS Portal for Disconnected Environment
    .PARAMETER Ensure
        Take the values Present or Absent. 
        - "Present" ensures that Server is Configured for Disconnected-Use.
        - "Absent" ensures that Server is Configured as out-of-the-box - Not Implemented.
    .PARAMETER HostName
        Host Name of the Machine on which the ArcGIS Portal is Installed
    .PARAMETER SiteAdministrator
        Credentials to access Server/Portal with admin privileges
    .PARAMETER DisableExternalContent
        Switch for Disabling External Content
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
        $EnableArcGISOnlineMapViewer = $false,

        [System.Boolean]
        $DisableExternalContent = $false

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
        $DisableExternalContent = $false
    )
    #[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} # Allow self-signed certificates
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    $FQDN = Get-FQDN $env:COMPUTERNAME   
    Write-Verbose "Fully Qualified Domain Name :- $FQDN" 
    $Referer = 'http://localhost'
    $ServerUrl = "https://$($FQDN):7443"

    Wait-ForUrl -Url "$ServerUrl/arcgis/portaladmin/" -LogFailures
    $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer

    if ($DisableExternalContent) {
        Set-ExternalContentEnabled -ServerUrl $ServerUrl -SiteName 'arcgis' -Token $($token.token) -Referer $Referer
    } else {
        Write-Verbose "Disconnected Environment DisableExternalContent set to false"
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
        $DisableExternalContent = $false
    )
    #[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} # Allow self-signed certificates
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    $result = $true
    $FQDN = Get-FQDN $env:COMPUTERNAME   
    Write-Verbose "Fully Qualified Domain Name :- $FQDN" 
    $Referer = 'http://localhost'
    $ServerUrl = "https://$($FQDN):7443"

    Wait-ForUrl -Url "$ServerUrl/arcgis/portaladmin/" -LogFailures
    $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer

    if ($result) {
        if ($DisableExternalContent) {
            $result = Get-ExternalContentEnabled -ServerUrl $ServerUrl -SiteName 'arcgis' -Token $($token.token) -Referer $Referer
        }
    }

    $result
}

function Get-ExternalContentEnabled {
    [CmdletBinding()]
    param(
        [System.String]
        $ServerUrl,

        [System.String]
        $SiteName = 'arcgis',

        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost'
    )

    $configuration = Invoke-ArcGISWebRequest -Url "$ServerUrl/$SiteName/portaladmin/system/content/configuration" `
                    -HttpFormParameters @{ f = 'pjson'; token = $Token; } -Referer $Referer -HttpMethod 'GET'

    -not($configuration.isExternalContentEnabled) # returns true when $isExternalContentEnabled is set to false

}

function Set-ExternalContentEnabled {
    [CmdletBinding()]
    param(
        [System.String]
        $ServerUrl,

        [System.String]
        $SiteName = 'arcgis',

        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost'
    )
    $result = $true

    if(-not(Get-ExternalContentEnabled -ServerUrl $ServerUrl -SiteName $SiteName -Token $Token -Referer $Referer))
    {
        # updating content configuration requires reindexing which may take up to a few minutes > timeout 600
        $configuration = Invoke-ArcGISWebRequest -Url "$ServerUrl/$SiteName/portaladmin/system/content/configuration/update" `
                        -HttpFormParameters @{ f = 'pjson'; token = $Token; externalContentEnabled = 'false'} -Referer $Referer `
                        -TimeOutSec 600 -HttpMethod 'POST'
        
        Write-Verbose "External Content disabled:- $configuration"
        $result = if($configuration.status -matches "success") {$true} else {$false}
    } else {
        Write-Verbose "External Content already disabled in /portaladmin/system/content/configuration - skipping"
        $result = $true
    }
    $result
}

Export-ModuleMember -Function *-TargetResource


