<#
    .SYNOPSIS
        Makes a request to the installed Server to Register Existing External Cache Directories with existing Server Site
    .PARAMETER Ensure
        Ensure makes sure that a Cache Directories are registered to site if specified. Take the values Present or Absent. 
        - "Present" ensures that a server site is created or the server is joined to an existing site.
        - "Absent" ensures that existing server site is deleted (Not Implemented).
    .PARAMETER SiteAdministrator
        A MSFT_Credential Object - Primary Site Adminstrator
    .PARAMETER Directories
        List of Registered Directories
#>
function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
        [parameter(Mandatory = $true)]
        [System.String]
        $Directories,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,    

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator
	)
	
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

	$null
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
        [parameter(Mandatory = $true)]
        [System.String]
        $Directories,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,    

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator       
	)
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    $FQDN = Get-FQDN $env:COMPUTERNAME    
    Write-Verbose "Fully Qualified Domain Name :- $FQDN"

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	Write-Verbose "Waiting for Server 'http://$($FQDN):6080/arcgis/admin' to initialize"
    Wait-ForUrl "http://$($FQDN):6080/arcgis/admin" -HttpMethod 'GET'

    if($Ensure -ieq 'Present') {        
        $Referer = 'http://localhost' 
        $ServerUrl = "http://$($FQDN):6080"
        Write-Verbose "Checking for site on '$ServerUrl'"
        $siteExists = $false
        try {  
            $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer 
            $siteExists = ($token.token -ne $null)
        }
        catch {
            Write-Verbose "[WARNING] GetToken returned:- $_"
        }
        if($Directories) { #setting registered directories
            $responseDirectories = Get-RegisteredDirectories -ServerURL $ServerUrl -Token $token.token -Referer $Referer
            ForEach ($dir in ($Directories | ConvertFrom-Json)) 
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
        [parameter(Mandatory = $true)]
        [System.String]
        $Directories,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,    

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator  
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $FQDN = Get-FQDN $env:COMPUTERNAME   
    Write-Verbose "Fully Qualified Domain Name :- $FQDN" 
    $Referer = 'http://localhost'
    $ServerUrl = "http://$($FQDN):6080"
    $result = $false
   
    if($Directories) { # only Primary Server
        $responseDirectories = Get-RegisteredDirectories -ServerURL $ServerUrl -Token $token.token -Referer $Referer
        ForEach ($dir in ($Directories | ConvertFrom-Json)) 
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
    $props = @{ f= 'pjson'; token = $Token;  }
    $cmdBody = To-HttpBody $props    
    $headers = @{'Content-type'='application/x-www-form-urlencoded'
                'Content-Length' = $cmdBody.Length
                'Accept' = 'text/plain'
                'Referer' = $Referer
                }

    $res = Invoke-WebRequest -Uri $Url -Body $cmdBody -Method POST -Headers $headers -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing -TimeoutSec 150 -ErrorAction Ignore
    if($res -and $res.Content) {
        $response = $res.Content | ConvertFrom-Json
        $response    
    }else{
        Write-Verbose "[WARNING] Response from $Url (Get-RegisteredDirectories) is NULL"
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
    $cmdBody = To-HttpBody $props    
    $headers = @{'Content-type'='application/x-www-form-urlencoded'
                'Content-Length' = $cmdBody.Length
                'Accept' = 'text/plain'
                'Referer' = $Referer
                }

    $res = Invoke-WebRequest -Uri $Url -Body $cmdBody -Method POST -Headers $headers -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing -TimeoutSec 150 -ErrorAction Ignore
    if($res -and $res.Content) {
        $response = $res.Content | ConvertFrom-Json
        $response    
    }else{
        Write-Verbose "[WARNING] Response from $Url (RegisterDirectory) is NULL"
    }
}

Export-ModuleMember -Function *-TargetResource