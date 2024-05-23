$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory = $True)]    
        [System.String]
        $Version,

        [System.String] 
        [parameter(Mandatory = $True)]
        $PortalInstallDirectory,

        [ValidateSet('Import', 'Export')]
        [parameter(Mandatory = $True)]
        [System.String]
        $Action,

        [parameter(Mandatory = $True)]
        [System.String]
        $PropertiesFilePath,

        [parameter(Mandatory = $False)]
        [System.Int32] 
        $TimeoutInMinutes = 3600 # 10 hours
    )

    $null 
}
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $True)]    
        [System.String]
        $Version,

        [System.String] 
        [parameter(Mandatory = $True)]
        $PortalInstallDirectory,

        [ValidateSet('Import', 'Export')]
        [parameter(Mandatory = $True)]
        [System.String]
        $Action,

        [parameter(Mandatory = $True)]
        [System.String]
        $PropertiesFilePath,

        [parameter(Mandatory = $False)]
        [System.Int32] 
        $TimeoutInMinutes = 3600 # 10 hours
    )

    $WebGISToolPath = Join-Path -Path $PortalInstallDirectory 'tools\webgisdr\webgisdr.bat'
    if(-not(Test-Path $WebGISToolPath -PathType Leaf)){
        throw "$WebGISToolPath not found"
    }

    if(-not(Test-Path $PropertiesFilePath -PathType Leaf)){
        throw "$PropertiesFilePath not found"
    }

    Write-Verbose "WebGIS DR $($Action) started by user $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)."

    $Arguments = $null
    # Code to set the desired state
    if($Action -eq 'Import') {
        $Arguments = " --import --file `"$($PropertiesFilePath)`""
    }elseif($Action -eq 'Export') {
        $Arguments = " --export --file `"$($PropertiesFilePath)`""
    }else {
        throw "Invalid Action"
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $WebGISToolPath
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false #start the process from it's own executable file    
    $psi.RedirectStandardOutput = $true #enable the process to read from standard output
    $psi.RedirectStandardError = $true #enable the process to read from standard error 
    $psi.EnvironmentVariables["AGSPORTAL"] = [environment]::GetEnvironmentVariable("AGSPortal","Machine")
    $p = [System.Diagnostics.Process]::Start($psi)
    $TimeoutInMilliseconds = $TimeoutInMinutes * 60 * 1000
    $p.WaitForExit($TimeoutInMilliseconds)
    if(-not $p.HasExited) {
        $p.Kill()
        throw "WebGIS DR $($Action) timed out after $($TimeoutInMinutes) minutes."
    }

    $op = $p.StandardOutput.ReadToEnd()
    if($op -and $op.Length -gt 0) {
        Write-Host "Output:- $op"
    }
    $err = $p.StandardError.ReadToEnd()
    if($err -and $err.Length -gt 0) {
        Write-Host $err
    }
    if($p.ExitCode -eq 0) {                    
        Write-Host "WebGIS DR $($Action) finished successfully."
    }else {
        throw "WebGIS DR $($Action) failed. Process exit code:- $($p.ExitCode). Error - $(err)"
    }
}

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [parameter(Mandatory = $True)]    
        [System.String]
        $Version,

        [System.String] 
        [parameter(Mandatory = $True)]
        $PortalInstallDirectory,

        [ValidateSet('Import', 'Export')]
        [parameter(Mandatory = $True)]
        [System.String]
        $Action,

        [parameter(Mandatory = $True)]
        [System.String]
        $PropertiesFilePath,

        [parameter(Mandatory = $False)]
        [System.Int32] 
        $TimeoutInMinutes = 3600 # 10 hours
    )

    $False
}

Export-ModuleMember -Function *-TargetResource