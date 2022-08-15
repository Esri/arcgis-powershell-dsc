$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

function Get-TargetResource {
    [CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
    (
        [parameter(Mandatory = $true)]
		[System.String]
        $SiteName,

        [parameter(Mandatory = $False)]    
        [System.Array]
        $ContainerImagePaths,

        [parameter(Mandatory = $False)]    
        [System.Boolean]
        $ExtractSamples = $False
    )
    
    $null
}

function Set-TargetResource {
    [CmdletBinding()]
	param
    (
        [parameter(Mandatory = $true)]
		[System.String]
        $SiteName,

        [parameter(Mandatory = $False)]    
        [System.Array]
        $ContainerImagePaths,

        [parameter(Mandatory = $False)]    
        [System.Boolean]
        $ExtractSamples = $False
    )
    
    if($ContainerImagePaths.Length -gt 0){
        foreach ($ImagePath in $ContainerImagePaths) {
            try{
                Write-Verbose "Loading container image at path $ImagePath"
                Invoke-PostInstallUtility -Arguments "-l $ImagePath" -Verbose
                Write-Verbose "Container image at path $ImagePath loaded."
            }catch{
                throw "[ERROR] Error Loading Container Image at path - $ImagePath - $_"
            }
        }
    }
    else
    {
        Write-Verbose "No Container Images to Load."
    }
    if($ExtractSamples){
        try{
            Write-Verbose "Extracting Notebook Server Samples Data"
            Invoke-PostInstallUtility -Arguments "-x" -Verbose
            Write-Verbose "Notebook Server Samples Data extracted."
        }catch{
            throw "[ERROR] Error extracting Notebook Server Samples Data - $_"
        }
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
        
        [parameter(Mandatory = $False)]    
        [System.Array]
        $ContainerImagePaths,

        [parameter(Mandatory = $False)]    
        [System.Boolean]
        $ExtractSamples = $False
    )

    $Result = $True
    try{
        if($ContainerImagePaths.Length -gt 0){
            try{
                Invoke-PostInstallUtility -Arguments "-d" -Verbose
            }catch{
                throw "[ERROR] Error with Docker Configuration - $_"
            }
            $Result = $False
            Write-Verbose "Trying to intall images if not already installed."
        }
        if($ExtractSamples){
            $Result = $False
            Write-Verbose "Trying to extract Notebook Server Samples Data if not already extracted."
        }
    }catch{
        throw $_
    }

    $Result
}

function Invoke-PostInstallUtility
{
    [CmdletBinding()]
	param
    (
        [System.String]
        $Arguments
    )

    $ServiceName = 'ArcGIS Notebook Server'
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir
    $PostInstallUtilityToolPath = (Join-Path $InstallDir ( Join-Path 'tools' ( Join-Path 'postInstallUtility' 'PostInstallUtility.bat')))
    if(Test-Path $PostInstallUtilityToolPath){
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $PostInstallUtilityToolPath
        $psi.Arguments = $Arguments
        $psi.UseShellExecute = $false #start the process from it's own executable file    
        $psi.RedirectStandardOutput = $true #enable the process to read from standard output
        $psi.RedirectStandardError = $true #enable the process to read from standard error
        $psi.EnvironmentVariables["AGSNOTEBOOK"] = [environment]::GetEnvironmentVariable("AGSNOTEBOOK","Machine")

        $p = [System.Diagnostics.Process]::Start($psi)
        $p.WaitForExit()
        $op = $p.StandardOutput.ReadToEnd()
        if($p.ExitCode -eq 0) {
            Write-Verbose $op
            if($op -icontains 'error' -or $op -icontains 'failed') { throw "$op"}
        }else{
            $err = $p.StandardError.ReadToEnd()
            Write-Verbose $err
            if($err -and $err.Length -gt 0) {
                throw "Output - $op. Error - $err"
            }
        }
    }else{
        throw "Post Install Utility Tool not found."
    }
}



Export-ModuleMember -Function *-TargetResource
