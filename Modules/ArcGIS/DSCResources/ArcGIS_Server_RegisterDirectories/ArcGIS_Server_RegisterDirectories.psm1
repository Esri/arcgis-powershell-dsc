$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

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

	$null
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
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	Write-Verbose "Waiting for Server 'https://$($FQDN):6443/arcgis/admin' to initialize"
    Wait-ForUrl "https://$($FQDN):6443/arcgis/admin" -HttpMethod 'GET'

    if($Ensure -ieq 'Present') {        
        $Referer = 'http://localhost' 
        $ServerUrl = "https://$($FQDN):6443"
        try {  
            Write-Verbose "Getting the Token for site '$ServerUrl'"
            $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer 
            if($null -ne $token.token -and $DirectoriesJSON) { #setting registered directories
                $responseDirectories = Get-RegisteredDirectories -ServerURL $ServerUrl -Token $token.token -Referer $Referer
                ForEach ($dir in ($DirectoriesJSON | ConvertFrom-Json)) 
                {
                    Write-Verbose "Testing for Directory $($dir.name)"
                    if(($responseDirectories | Where-Object { ($responseDirectories.directories.name -icontains $($dir.name))}  | Measure-Object).Count -gt 0) {
                        Write-Verbose "Directory $($dir.name) already registered > no Action required"
                    } else {
                        Write-Verbose "Directory $($dir.name) not registered > registering directory"
                        $response = Set-RegisteredDirectory -ServerURL $ServerUrl -Token $token.token -Referer $Referer -Name $dir.name -PhysicalPath $dir.physicalPath -DirectoryType $dir.directoryType
                        Write-Verbose "Set-RegisteredDirectory Response :-$response"
                    }
                }
            }else{
                throw "[Error] No Token Returned"
            }
        }
        catch {
            throw "[ERROR] GetToken returned:- $_"
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

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    Write-Verbose "Fully Qualified Domain Name :- $FQDN" 
    $Referer = 'http://localhost'
    $ServerUrl = "https://$($FQDN):6443"
    $result = $true
    Write-Verbose "Getting the Token for site '$ServerUrl'"
    $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer 
    try {  
        if($null -ne $token.token -and $DirectoriesJSON) { #setting registered directories
            $responseDirectories = Get-RegisteredDirectories -ServerURL $ServerUrl -Token $token.token -Referer $Referer
            ForEach ($dir in ($DirectoriesJSON | ConvertFrom-Json)) 
            {
                Write-Verbose "Testing for Directory $($dir.name)"
                if(($responseDirectories | Where-Object { ($responseDirectories.directories.name -icontains $($dir.name))}  | Measure-Object).Count -gt 0) {
                    Write-Verbose "Directory $($dir.name) already registered"
                } else {
                    Write-Verbose "Directory $($dir.name) not registered"
                    $result = $false
                    break
                }
            }
        }
        else{
            throw "No Token Returned"
        }
    }
    catch {
        throw "[ERROR] GetToken returned:- $_"
    }
   
    if($Ensure -ieq 'Present') {
	       $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}

function Get-RegisteredDirectories 
{ # returns list of Servers registerd Directories 
    [CmdletBinding()]
	param
	(
        [System.String]
        $ServerURL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer
	)

    $Url  = $ServerURL.TrimEnd("/") + "/arcgis/admin/system/directories"
    try{
        Invoke-ArcGISWebRequest -Url $Url -HttpFormParameters  @{ f= 'pjson'; token = $Token; } -Referer $Referer -TimeOutSec 150
    }catch{
        Write-Verbose "[WARNING] Response from $Url (Get-RegisteredDirectories) is - $_"
    }
}

function Set-RegisteredDirectory
{ # adds an directory to Server registerd Directories 
    [CmdletBinding()]
	param
	(
        [System.String]
        $ServerURL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer,

        [System.String]
        $Name,

        [System.String]
        $PhysicalPath,

        [System.String]
        $DirectoryType
	)

    $Url  = $ServerURL.TrimEnd("/") + "/arcgis/admin/system/directories/register"   
    $props = @{ f= 'pjson'; token = $Token; name = $Name; physicalPath = $PhysicalPath; directoryType = $DirectoryType; }
    try{
        Invoke-ArcGISWebRequest -Url $Url -HttpFormParameters $props -Referer $Referer -TimeOutSec 150
    }catch{
        Write-Verbose "[WARNING] Response from $Url (Get-RegisteredDirectories) is - $_"
    }
}

Export-ModuleMember -Function *-TargetResource
