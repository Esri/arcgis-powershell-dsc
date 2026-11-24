$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.Server.psm1'))
function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $true)]
        [ValidateSet("Create","Repair","Upgrade","Remove")]
		[System.String]
		$Mode,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
        $PortalSiteAdministrator
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

        [parameter(Mandatory = $true)]
        [ValidateSet("Create","Repair","Upgrade","Remove")]
		[System.String]
		$Mode,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
        $PortalSiteAdministrator,

        [parameter(Mandatory = $false)]    
        [System.String]
        $DataStoreDataDirectory,

        [parameter(Mandatory = $false)]
		[System.Boolean]
		$RegisterGeoEnrichmentAsPortalUtilityService
	)


    $ManageGeoEnrichmentEnvTool = Get-ManageGeoEnrichmentEnvTool
    # get the info
    $LogPath = Get-LogFileFolder
    $Arguments = "$($Mode.ToLower()) -b -y -u `"$($PortalSiteAdministrator.UserName)`" -p `"$($PortalSiteAdministrator.GetNetworkCredential().Password)`" -l `"$($LogPath)`""
    if($DataStoreDataDirectory){
        $Arguments += " -d `"$($DataStoreDataDirectory)`" "
    }
    if(-not($RegisterGeoEnrichmentAsPortalUtilityService)){
        $Arguments += " --no-utility-service"
    }
    $EnvVariables = @{}
    $EnvVariables["AGSSERVER"] = $null
    Invoke-StartProcess -ExecPath "$ManageGeoEnrichmentEnvTool" -Arguments $Arguments -EnvVariables $EnvVariables -Verbose
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $true)]
        [ValidateSet("Create","Repair","Upgrade","Remove")]
		[System.String]
		$Mode,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
        $PortalSiteAdministrator,

        [parameter(Mandatory = $false)]    
        [System.String]
        $DataStoreDataDirectory,

        [parameter(Mandatory = $false)]
		[System.Boolean]
		$RegisterGeoEnrichmentAsPortalUtilityService
	)

   
    $result = $False

    # "ArcGIS GeoEnrichment Server is not configured."
    $GEInfo = Get-GeoEnrichmentInfo -PortalSiteAdministrator $PortalSiteAdministrator
    if($GEInfo."GeoEnrichment Configuration Information"){
        $Info = $GEInfo."GeoEnrichment Configuration Information"
        $Configured = ($Info.Configured -ieq "True")
        Write-Verbose "GeoEnrichment environment configured: $($Configured). Mode: $($Mode)"
        if($Mode -ieq "Create"){
            $result = $Configured
        }
        if($Mode -ieq "Remove"){
            $result = -not($Configured)
        }
        if($Mode -ieq "Repair" -and $Mode -ieq "Upgrade"){
            if($Configured){
                $result = $false
                
                # $Info."Upgrade State" - TODO
            }else{
                throw "GeoEnrichment environment is not configured."
            }
        }
    }
    return $result
}


function Get-GeoEnrichmentInfo
{
    param(
        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
        $PortalSiteAdministrator
    )

    $ManageGeoEnrichmentEnvTool = Get-ManageGeoEnrichmentEnvTool
    $LogFolderPath = Get-LogFileFolder -Verbose
	$Arguments = "info -b -y -u `"$($PortalSiteAdministrator.UserName)`" -p `"$($PortalSiteAdministrator.GetNetworkCredential().Password)`" -l `"$($LogFolderPath)`""
    try{
	    $EnvVariables = @{}
	    $EnvVariables["AGSSERVER"] = $null
        Invoke-StartProcess -ExecPath "$ManageGeoEnrichmentEnvTool" -Arguments $Arguments -EnvVariables $EnvVariables -Verbose
        # Parse log file.
        $Info = Invoke-ParseWizardLog -LogFolderPath $LogFolderPath -Verbose
        return $Info
    }catch{
        throw "Unable to get GeoEnrichment info from Manage GeoEnrichment environment tool. Error - $_"
    }
}

function Get-LogFileFolder
{
    $timestampFolder = (Get-Date -Format 'yyyyMMddTHHmmssfff').ToString()
    $LogFolderPath = (Join-Path $env:TEMP $timestampFolder)
    New-Item -Path $LogFolderPath -ItemType Directory | Out-Null
    return $LogFolderPath
}

function Get-ManageGeoEnrichmentEnvTool
{
    $InstallDir = (Get-ArcGISComponentVersionAndInstallDirectory -ComponentName 'Server').InstallDir
    return (Join-Path $InstallDir '/tools/geoenrichment/manageEnvironment.bat')
}

function Invoke-ParseWizardLog 
{
    param (
        [Parameter(Mandatory)]
        [string]$LogFolderPath
    )

    $LogPath = (Get-ChildItem $LogFolderPath -Filter "geoenrichment_environment_configuration_*.log").FullName
    Write-Verbose $LogPath
    $content = Get-Content -Path $LogPath -Raw

    # Extract block between dashed lines
    if ($content -notmatch '(?s)-{30,}\s*(.*?)\s*-{30,}') {
        throw "No dashed section found in log."
    }

    $block = $Matches[1]

    $result = @{}
    $currentSection = $null

    foreach ($line in ($block -split "`r?`n")) {
        $line = $line.Trim()

        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        # Section header: #System Information#
        if ($line -match '^#(.+?)#$') {
            $currentSection = $Matches[1]
            $result[$currentSection] = @{}
            continue
        }

        # Key-value pair: Key: Value
        if ($currentSection -and $line -match '^(.*?):\s*(.*)$') {
            $key   = $Matches[1].Trim()
            $value = $Matches[2].Trim()

            # Normalize placeholders to $null
            if ($value -match '^\[(not\s+exist|not\s+exists|unknown)\]$') {
                $value = $null
            }

            $result[$currentSection][$key] = $value
        }
    }

    return [pscustomobject]$result
}

Export-ModuleMember -Function *-TargetResource