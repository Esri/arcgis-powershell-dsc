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
    .PARAMETER ConfigProperties
        JSON of Properties and their values in config.js
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

        [System.String]
        $ConfigProperties,

        [System.Boolean]
        $DisableExternalContent = $false
    )
    #[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} # Allow self-signed certificates
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    Write-Verbose "Fully Qualified Domain Name :- $HostName" 
    $PortalUrl = "https://$($HostName):7443/arcgis"
    $ServiceRestartRequired = $false

    Wait-ForUrl -Url "$PortalUrl/portaladmin/" -LogFailures
    $token = Get-PortalToken -PortalHostName $HostName -Credential $SiteAdministrator

    if ($DisableExternalContent) {
        Set-ExternalContentEnabled -ServerUrl $PortalUrl -Token $($token.token)
    } else {
        Write-Verbose "Disconnected Environment DisableExternalContent set to false"
    }
    $ConfigFilePath = Get-ConfigFilePath

    $ServiceRestartRequired = $false

    $ConfigProps = ConvertFrom-Json $ConfigProperties
    ForEach ($Property in $ConfigProps.PSObject.Properties)
    {
        if (Set-PropertyInConfigFile -ConfigFilePath $ConfigFilePath -PropertyName $Property.Name -PropertyValue $Property.Value)
        {
            $ServiceRestartRequired = $true
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
        $DisableExternalContent = $false
    )
    #[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} # Allow self-signed certificates
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    $result = $true
    Write-Verbose "Fully Qualified Domain Name :- $HostName" 
    $PortalUrl = "https://$($HostName):7443/arcgis"

    Wait-ForUrl -Url "$PortalUrl/portaladmin/" -LogFailures
    $token = Get-PortalToken -PortalHostName $HostName -Credential $SiteAdministrator

    if ($result) 
    {
        if ($DisableExternalContent) 
        {
            $result = Get-ExternalContentEnabled -ServerUrl $PortalUrl -Token $($token.token)
        }
    }

    if ($result)
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
                        $Exists = $true
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

    -not($configuration.isExternalContentEnabled) # returns true when $isExternalContentEnabled is set to false

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

    if(-not(Get-ExternalContentEnabled -ServerUrl $PortalUrl -Token $Token -Referer $Referer))
    {
        # updating content configuration requires reindexing which may take up to a few minutes > timeout 600
        $configuration = Invoke-ArcGISWebRequest -Url "$PortalUrl/portaladmin/system/content/configuration/update" `
                        -HttpFormParameters @{ f = 'pjson'; token = $Token; externalContentEnabled = 'false'} -Referer $Referer `
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


