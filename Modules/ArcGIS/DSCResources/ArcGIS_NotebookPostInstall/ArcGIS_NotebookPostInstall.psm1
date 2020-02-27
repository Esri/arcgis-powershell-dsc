function Get-TargetResource {
    [CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
    (
        [parameter(Mandatory = $true)]
		[System.String]
        $SiteName,

        [parameter(Mandatory = $true)]    
        [System.Array]
        $ContainerImagePaths

    )
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false
    $null
}

function Set-TargetResource {
    [CmdletBinding()]
	param
    (
        [parameter(Mandatory = $true)]
		[System.String]
        $SiteName,

        [parameter(Mandatory = $true)]    
        [System.Array]
        $ContainerImagePaths
    )
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false
    
    $ServiceName = 'ArcGIS Notebook Server'
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir  

    $PostInstallUtilityToolPath = (Join-Path $InstallDir ( Join-Path 'tools' ( Join-Path 'postInstallUtility' 'PostInstallUtility.bat')))
    foreach ($ImagePath in $ContainerImagePaths) {
        Write-Verbose "Loading container image at path $ImagePath"
        $StdOutLogFile = [System.IO.Path]::GetTempFileName()
        $StdErrLogFile = [System.IO.Path]::GetTempFileName()
        Start-Process -FilePath $PostInstallUtilityToolPath -ArgumentList "-l $ImagePath" -Wait -Verbose -RedirectStandardOutput $StdOutLogFile -RedirectStandardError $StdErrLogFile -NoNewWindow
        $StdOut = Get-Content $StdOutLogFile -Raw
        if($null -ne $StdOut -and $StdOut.Length -gt 0) {
            Write-Verbose $StdOut
        }
        if($StdOut -icontains 'error' -or $StdOut -icontains 'failed') { throw "Error Loading Container Image at path - $ImagePath. StdOut Error:- $StdOut"}
        [string]$StdErr = Get-Content $StdErrLogFile -Raw
        if($null -ne $StdErr -and $StdErr.Length -gt 0) {
            Write-Verbose "[ERROR] $StdErr"
        }
        if($StdErr -icontains 'error' -or $StdErr -icontains 'failed') { throw "Error Loading Container Image at path - $ImagePath. StdOut Error:- $StdOut"}
        Remove-Item $StdOutLogFile -Force -ErrorAction Ignore
        Remove-Item $StdErrLogFile -Force -ErrorAction Ignore  
        Write-Verbose "Container image at path $ImagePath loaded."
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
        $SiteName,
        
        [parameter(Mandatory = $true)]    
        [System.Array]
        $ContainerImagePaths
    )
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    $ServiceName = 'ArcGIS Notebook Server'
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir  

    $PostInstallUtilityToolPath = (Join-Path $InstallDir ( Join-Path 'tools' ( Join-Path 'postInstallUtility' 'PostInstallUtility.bat')))
    if(Test-Path $PostInstallUtilityToolPath){
        $StdOutLogFile = [System.IO.Path]::GetTempFileName()
        $StdErrLogFile = [System.IO.Path]::GetTempFileName()
        Start-Process -FilePath $PostInstallUtilityToolPath -ArgumentList "-d" -Wait -Verbose -RedirectStandardOutput $StdOutLogFile -RedirectStandardError $StdErrLogFile -NoNewWindow
        $StdOut = Get-Content $StdOutLogFile -Raw
        if($null -ne $StdOut -and $StdOut.Length -gt 0) {
            Write-Verbose $StdOut
        }
        if($StdOut -icontains 'error' -or $StdOut -icontains 'failed') { throw "Error with Docker Configuration - $Image Path. StdOut Error:- $StdOut"}
        [string]$StdErr = Get-Content $StdErrLogFile -Raw
        if($null -ne $StdErr -and $StdErr.Length -gt 0) {
            Write-Verbose "[ERROR] $StdErr"
        }
        if($StdErr -icontains 'error' -or $StdErr -icontains 'failed') { throw "Error with Docker Configuration - $Image Path. StdOut Error:- $StdErr"}
        Remove-Item $StdOutLogFile -Force -ErrorAction Ignore
        Remove-Item $StdErrLogFile -Force -ErrorAction Ignore
        Write-Verbose "Trying to intall images if not already installed."
    }else{
        throw "Post Install Utility Tool not found."
    }
    $false
}

Export-ModuleMember -Function *-TargetResource