<#
    .SYNOPSIS
        Installs a given component of the ArcGIS Enterprise Stack.
    .PARAMETER Ensure
        Indicates if the Component is to be installed or uninstalled if not present. Take the values Present or Absent. 
        - "Present" ensures that component is installed, if not already installed. 
        - "Absent" ensures that component is uninstalled or removed, if installed.
    .PARAMETER Name
        Name of ArcGIS Enterprise Component to be installed.
    .PARAMETER PatchesDir
        Path to Installer for patches for the Component - Can be a Physical Location or Network Share Address.
    .PARAMETER Version
        Version of the Component being Installed.
#>

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Name,

		[parameter(Mandatory = $true)]
		[System.String]
		$PatchesDir,

		[parameter(Mandatory = $true)]
		[System.String]
        $Version,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
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
		$Name,

		[parameter(Mandatory = $true)]
		[System.String]
		$PatchesDir,

		[parameter(Mandatory = $true)]
		[System.String]
        $Version,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    if($Ensure -eq 'Present') {
        # test & install patches
        Write-Verbose "Installing Patches"
        if ($PatchesDir) {
            $files = Get-ChildItem "$PatchesDir"        
            Foreach ($file in $files) {
                Write-Verbose " > PatchFile : $file | Fullname : $($file.Fullname)"
                if (Test-PatchInstalled -mspPath $($file.FullName)) {
                    Write-Verbose " > Patch installed - no Action required"
                } else {
                    Write-Verbose " > Patch not installed - installing"
                    Install-Patch -mspPath $file.FullName
                }
            }
        }
    }
    elseif($Ensure -eq 'Absent') {
        #Uninstall Patch
    }
    Write-Verbose "In Set-Resource for $Name"
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [parameter(Mandatory = $true)]
		[System.String]
		$Name,

		[parameter(Mandatory = $true)]
		[System.String]
		$PatchesDir,

		[parameter(Mandatory = $true)]
		[System.String]
        $Version,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    $result = $false
    
    $trueName = if ($Name -ieq 'DataStore') { 'Data Store' } else { $Name }
    $ver = get-wmiobject Win32_Product| Where-Object {$_.Name -match $trueName -and $_.Vendor -eq 'Environmental Systems Research Institute, Inc.'}
	Write-Verbose "Installed Version $($ver.Version)"

    $result = Test-Install -Name $Name -Version $Version

    #test for installed patches
    if($result -and $PatchesDir) {
        $files = Get-ChildItem "$PatchesDir"        
        Foreach ($file in $files) {
            Write-Verbose " > PatchFile : $file | Fullname : $($file.Fullname)"
            if (Test-PatchInstalled -mspPath $($file.FullName)) {
                Write-Verbose " > Patch installed"
            } else {
                Write-Verbose " > Patch not installed"
                $result = $false
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

Function Test-PatchInstalled{
    [OutputType([System.Boolean])]
	param
    (
        [System.String]
        $mspPath
    )

    $Patch_qfe_id = Get-MSPqfeID -patchnamepath $mspPath # extract qfe-id from *.msp
    $test_qfe_id = "$Patch_qfe_id"
    $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $Reg_qfe_ids = Get-ItemProperty $RegPath | sort -Property QFE_ID | select-object QFE_ID # search uninstall-path for all 'QFE_ID' Objects

    $test = $false
    Foreach ($Reg_qfe_id in $Reg_qfe_ids) {
        if ($($Reg_qfe_id.QFE_ID) -ieq $test_qfe_id) {
            $test = $true # patch is installed
        }
    }

    $test
}

Function Install-Patch{
    [OutputType([System.Boolean])]
	param
    (
        [System.String]
        $mspPath
    )

    $arguments = "/update "+ '"' + $mspPath +'"' + " /quiet"
    Write-Verbose $arguments
    try {
        Start-Process -FilePath msiexec.exe -ArgumentList $Arguments -Wait
    } catch {
        Write-Verbose "Error in Install-Patch :-$_"
    }
}

Export-ModuleMember -Function *-TargetResource