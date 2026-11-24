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
        Makes a request to the installed Server to Register Existing External Cache Directories with existing Server Site
    .PARAMETER ServerHostName
        Optional Host Name or IP of the Machine on which the Server has been installed and is to be configured.
    .PARAMETER Ensure
        Ensure makes sure that a Cache Directories are registered to site if specified. Take the values Present or Absent. 
        - "Present" ensures that a server site is created or the server is joined to an existing site.
        - "Absent" ensures that existing server site is deleted (Not Implemented).
    .PARAMETER SiteAdministrator
        A MSFT_Credential Object - Primary Site Administrator
    .PARAMETER DirectoriesJSON
        List of Registered Directories in JSON Format
#>
function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
        [parameter(Mandatory = $false)]    
        [System.String]
        $ServerHostName,

        [parameter(Mandatory = $true)]
        [System.String]
        $DirectoriesJSON,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,    

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator
	)

	@{}
}

function Get-DesiredSystemDirectories
{
    param([System.String] $DirectoriesJSON)

    try {
        $directories = ConvertFrom-Json -InputObject $DirectoriesJSON -ErrorAction Stop
    } catch {
        throw "DirectoriesJSON is not valid JSON: $($_.Exception.Message)"
    }

    foreach($dir in $directories) {
        if([string]::IsNullOrWhiteSpace($dir.name) -or
           [string]::IsNullOrWhiteSpace($dir.physicalPath) -or
           [string]::IsNullOrWhiteSpace($dir.directoryType)) {
            throw 'Each server directory requires a name, physicalPath, and directoryType.'
        }
    }

    $directories
}

function Test-SystemDirectoryDefinition
{
    param($Current, $Desired)

    $currentPath = ([string]$Current.physicalPath).TrimEnd([char[]]@('\','/'))
    $desiredPath = ([string]$Desired.physicalPath).TrimEnd([char[]]@('\','/'))
    ($currentPath -ieq $desiredPath) -and ($Current.directoryType -ieq $Desired.directoryType)
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
        [parameter(Mandatory = $false)]    
        [System.String]
        $ServerHostName,

        [parameter(Mandatory = $true)]
        [System.String]
        $DirectoriesJSON,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,    

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator       
	)

    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    Write-Verbose "Fully Qualified Domain Name :- $FQDN"

    $ServerBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName "Server" -FQDN $FQDN
    $Referer = $ServerBaseUrl
	Write-Verbose "Waiting for Server '$($ServerBaseUrl)' to initialize"
    Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName "Server"

    if($Ensure -ieq 'Present') {        
        $Referer = 'https://localhost' 
        try {  
            Write-Verbose "Getting the Token for site '$ServerBaseUrl'"
            $token = Get-ServerToken -URL $ServerBaseUrl -Credential $SiteAdministrator -Referer $Referer 
            if(-not $token.token) {
                throw 'No token returned.'
            }

            $desiredDirectories = @(Get-DesiredSystemDirectories -DirectoriesJSON $DirectoriesJSON)
            $responseDirectories = Get-SystemDirectories -URL $ServerBaseUrl -Token $token.token -Referer $Referer

            # Detect incompatible existing definitions before registering any missing directories.
            foreach($dir in $desiredDirectories) {
                $existing = @($responseDirectories.directories | Where-Object { $_.name -ieq $dir.name })
                if($existing.Count -gt 1) {
                    throw "Multiple registered server directories have the name '$($dir.name)'."
                }
                if($existing.Count -eq 1 -and -not(Test-SystemDirectoryDefinition -Current $existing[0] -Desired $dir)) {
                    throw "Server directory '$($dir.name)' already exists with physicalPath '$($existing[0].physicalPath)' and directoryType '$($existing[0].directoryType)'; expected '$($dir.physicalPath)' and '$($dir.directoryType)'. Update or remove it explicitly before rerunning DSC."
                }
            }

            foreach($dir in $desiredDirectories) {
                $existing = @($responseDirectories.directories | Where-Object { $_.name -ieq $dir.name })
                if($existing.Count -eq 0) {
                    Write-Verbose "Directory $($dir.name) not registered; registering it."
                    Register-SystemDirectory -URL $ServerBaseUrl -Token $token.token -Referer $Referer -Name $dir.name -PhysicalPath $dir.physicalPath -DirectoryType $dir.directoryType | Out-Null
                    $responseDirectories = Get-SystemDirectories -URL $ServerBaseUrl -Token $token.token -Referer $Referer
                    $registered = @($responseDirectories.directories | Where-Object { $_.name -ieq $dir.name })
                    if($registered.Count -ne 1 -or -not(Test-SystemDirectoryDefinition -Current $registered[0] -Desired $dir)) {
                        throw "Server directory '$($dir.name)' was not registered with the requested physicalPath and directoryType."
                    }
                } else {
                    Write-Verbose "Directory $($dir.name) already registered with the requested definition."
                }
            }
        }
        catch {
            throw "Unable to ensure server directories on '$ServerBaseUrl': $($_.Exception.Message)"
        }
    }
    elseif($Ensure -ieq 'Absent') {
        #Unregister Registered Directories
        Write-Verbose "TO BE IMPLEMENTED"
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
        $DirectoriesJSON,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,    

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator  
	)

    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    Write-Verbose "Fully Qualified Domain Name :- $FQDN" 
    $ServerBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName "Server" -FQDN $FQDN
    $Referer = $ServerBaseUrl
    $result = $true
    Write-Verbose "Getting the Token for site '$ServerBaseUrl'"
    try {  
        $token = Get-ServerToken -URL $ServerBaseUrl -Credential $SiteAdministrator -Referer $Referer
        if(-not $token.token) {
            throw 'No token returned.'
        }
        $desiredDirectories = @(Get-DesiredSystemDirectories -DirectoriesJSON $DirectoriesJSON)
        $responseDirectories = Get-SystemDirectories -URL $ServerBaseUrl -Token $token.token -Referer $Referer
        foreach($dir in $desiredDirectories) {
            $existing = @($responseDirectories.directories | Where-Object { $_.name -ieq $dir.name })
            if($existing.Count -ne 1 -or -not(Test-SystemDirectoryDefinition -Current $existing[0] -Desired $dir)) {
                Write-Verbose "Directory $($dir.name) is missing or its physicalPath or directoryType differs."
                $result = $false
                break
            }
        }
    }
    catch {
        throw "Unable to test server directories on '$ServerBaseUrl': $($_.Exception.Message)"
    }
   
    if($Ensure -ieq 'Present') {
	       $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}

Export-ModuleMember -Function *-TargetResource
