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

Function Test-PatchInstalled {
        
    [OutputType([System.Boolean])]
    Param(
        # The path to the patch file
        [System.String]
        $MSPPath
    )

    $Test = $False

    # Confirm the Patch file exists, let upstream handle the error
    If ( -Not (Test-Path -PathType Leaf -Path $MSPPath) ) {
        Write-Warning -Message "The Patch File $MSPPath is not accessible"
        Return $Test
    }
    
    # Extract the QFE-ID from the *.msp
    $Patch_QFE_ID = Get-MSPQFEID -PatchNamePath $MSPPath
    $Test_QFE_ID = "$Patch_QFE_ID"

    If ( [String]::IsNullOrEmpty($Test_QFE_ID) ) {
        Write-Warning -Message "Unable to extract the QFE-ID from the Patch file $MSPPath"
        Return $Test
    }

    # A list of Registry Paths to check
    $RegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" ,
        "HKLM:\SOFTWARE\ESRI\Portal for ArcGIS\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\ArcGIS Data Store\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\Server10.3\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\Server10.4\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\Server10.5\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\Server10.6\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\Server10.7\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\ArcGISPro\Updates\*" ,
        "HKLM:\SOFTWARE\WOW6432Node\ESRI\Desktop10.4\Updates\*" ,
        "HKLM:\SOFTWARE\WOW6432Node\ESRI\Desktop10.5\Updates\*" ,
        "HKLM:\SOFTWARE\WOW6432Node\ESRI\Desktop10.6\Updates\*" ,
        "HKLM:\SOFTWARE\WOW6432Node\ESRI\Desktop10.7\Updates\*"
    )
    
    ForEach ( $RegPath in $RegPaths ) {
           
        If ( Test-Path -PathType Container -Path $RegPath ) {
        
            #  Search the Registry path for all 'QFE_ID' Objects
            $Reg_QFE_IDs = Get-ItemProperty $RegPath | Sort-Object -Property QFE_ID | Select-Object QFE_ID

            ForEach ( $Reg_QFE_ID in $Reg_QFE_IDs ) {

                If ( [String]::IsNullOrEmpty($Reg_QFE_ID.QFE_ID) ) {
                    Continue
                }
            
                Write-Verbose -Message "Comparing QFE ID $Test_QFE_ID against ID $($Reg_QFE_ID.QFE_ID)"
                
                If ( $( $Reg_QFE_ID.QFE_ID ) -ieq $Test_QFE_ID ) {
                
                    # The patch is installed, skip further processing
                    Write-Verbose -Message "Patch already installed: $MSPPath - $Test_QFE_ID"
                    $Test = $True
                    Return $Test

                }

            }

        } Else {

            Continue

        }

    }

    Return $Test

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