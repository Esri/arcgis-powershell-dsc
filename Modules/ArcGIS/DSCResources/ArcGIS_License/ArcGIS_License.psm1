<#
    .SYNOPSIS
        Licenses the product (Server or Portal) depending on the params specified.
    .PARAMETER Ensure
        Take the values Present or Absent. 
        - "Present" ensures that Component in Licensed, if not.
        - "Absent" ensures that Component in Unlicensed (Not Implemented).
    .PARAMETER LicenseFilePath
        Path to License File 
    .PARAMETER Component
        Product being Licensed (Server or Portal)
    .PARAMETER ServerRole
        (Optional - Required only for Server) Server Role for which the product is being Licensed
    .PARAMETER Force
        Boolean to Force the product to be licensed again, even if already done.

#>

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$LicenseFilePath
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
        $LicenseFilePath,
        
        [parameter(Mandatory = $false)]
		[System.String]
		$Password,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [ValidateSet("Server","Portal","Desktop","Pro")]
		[System.String]
		$Component,

		[ValidateSet("ImageServer","GeoEvent","GeoAnalytics","GeneralPurposeServer","HostingServer")]
		[System.String]
        $ServerRole = 'GeneralPurposeServer',
        
        [parameter(Mandatory = $false)]
        [System.Boolean]
		$Force= $False
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

	if(-not(Test-Path $LicenseFilePath)){
        throw "License file not found at $LicenseFilePath"
    }

    if($Ensure -ieq 'Present') {
        [string]$RealVersion = @()
        try{
            $ErrorActionPreference = "Stop"; #Make all errors terminating
            <#$RegistryPath = 'HKLM:\SOFTWARE\ESRI\ArcGIS'
            if($Component -ieq 'Desktop' -or $Component -ieq 'Pro') {
                $RegistryPath = 'HKLM:\SOFTWARE\WoW6432Node\esri\ArcGIS'
            } 
            $RealVersion = (Get-ItemProperty -Path $RegistryPath).RealVersion#>
            $RealVersion = (get-wmiobject Win32_Product| Where-Object {$_.Name -match $Component -and $_.Vendor -eq 'Environmental Systems Research Institute, Inc.'}).Version
        }catch{
            
        }finally{
            $ErrorActionPreference = "Continue"; #Reset the error action pref to default
        }
        Write-Verbose "RealVersion of ArcGIS Software Installed:- $RealVersion" 
        $Version = $RealVersion.Split('.')[0] + '.' + $RealVersion.Split('.')[1] 
        $Arguments = " -s -ver $Version"    
        
        Write-Verbose "Licensing from $LicenseFilePath" 
       
        if($Component -ieq 'Desktop' -or $Component -ieq 'Pro') {
            Write-Verbose "Version $Version Component $Component" 
            License-Software -Product $Component -LicenseFilePath $LicenseFilePath -Arguments $Arguments -Password $Password
        }
        else {
            Write-Verbose "Version $Version Component $Component Role $ServerRole" 
            $StdOutputLogFilePath = Join-Path $env:TEMP "$(Get-Date -format "dd-MM-yy-HH-mm")-stdlog.txt"
            $StdErrLogFilePath = Join-Path $env:TEMP "$(Get-Date -format "dd-MM-yy-HH-mm")-stderr.txt"
            Write-Verbose "StdOutputLogFilePath:- $StdOutputLogFilePath" 
            Write-Verbose "StdErrLogFilePath:- $StdErrLogFilePath" 
            License-Software -Product $Component -LicenseFilePath $LicenseFilePath `
                         -Arguments $Arguments -Password $Password -StdOutputLogFilePath $StdOutputLogFilePath `
                         -StdErrLogFilePath $StdErrLogFilePath
        }
    }else {
        throw "Ensure = 'Absent' not implemented"
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
        $LicenseFilePath,
        
        [parameter(Mandatory = $false)]
		[System.String]
		$Password,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

		[ValidateSet("Server","Portal","Desktop","Pro")]
		[System.String]
		$Component,

		[ValidateSet("ImageServer","GeoEvent","GeoAnalytics","GeneralPurposeServer","HostingServer")]
		[System.String]
        $ServerRole = 'GeneralPurposeServer',
        
        [parameter(Mandatory = $false)]
        [System.Boolean]
		$Force = $False
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    [string]$RealVersion = @()

	$result = $false
    try{
        $ErrorActionPreference = "Stop"; #Make all errors terminating
        <#$RegistryPath = 'HKLM:\SOFTWARE\ESRI\ArcGIS'
        if($Component -ieq 'Desktop' -or $Component -ieq 'Pro') {
            $RegistryPath = 'HKLM:\SOFTWARE\WoW6432Node\esri\ArcGIS'
        } 
        $RealVersion = (Get-ItemProperty -Path $RegistryPath).RealVersion#>
        $RealVersion = (get-wmiobject Win32_Product| Where-Object {$_.Name -match $Component -and $_.Vendor -eq 'Environmental Systems Research Institute, Inc.'}).Version
    }catch{
        
    }finally{
        $ErrorActionPreference = "Continue"; #Reset the error action pref to default
    }
    Write-Verbose "RealVersion of ArcGIS Software Installed:- $RealVersion" 
    $Version = $RealVersion.Split('.')[0] + '.' + $RealVersion.Split('.')[1] 
    Write-Verbose "Version $Version" 
    if($Component -ieq 'Desktop') {
        
        $RegPath = "HKLM:\SOFTWARE\Wow6432Node\esri\Python$($Version)"
        if(Test-Path $RegPath -ErrorAction Ignore) {            
            $PythonInstallDir = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\esri\Python$($Version)").PythonDir
            $PythonPath = ((Get-ChildItem -Path $PythonInstallDir -Filter 'python.exe' -Recurse -File) | Select-Object -First 1 -ErrorAction Ignore)        
            $PythonInterpreterPath = $PythonPath.FullName

            $TempPythonFile = [System.IO.Path]::GetTempFileName()
            Set-Content -Path $TempPythonFile -Value 'import arcpy' -Force            
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $PythonInterpreterPath
            $psi.Arguments = $TempPythonFile
            $psi.UseShellExecute = $false #start the process from it's own executable file    
            $psi.RedirectStandardOutput = $true #enable the process to read from standard output
            $psi.RedirectStandardError = $true #enable the process to read from standard error

            try 
            {
                Write-Verbose "Testing for desktop initialization using arcpy script and Python interpreter path at $PythonInterpreterPath"
                $p = [System.Diagnostics.Process]::Start($psi)
                $p.WaitForExit()
                $op = $p.StandardOutput.ReadToEnd()
                if($op -and $op.Length -gt 0) {
                    Write-Verbose "Output of python execution:- $op"
                }
                $err = $p.StandardError.ReadToEnd()
                if($err -and $err.Length -gt 0) {
                    Write-Verbose "Error  of python execution process:- $err"
                }
                if($p.ExitCode -eq 0) {                    
                    Write-Verbose "Arcpy initialized correctly indicating successful desktop initialization"
                    if($force){
                        $result = $false
                    }else{
                        $result = $true
                    }
                }else {
                    Write-Verbose "Arcpy initialization did not succeed. Process exit code:- $($p.ExitCode) $p"
                }
            }
            catch{
                Write-Verbose "Error testing for arcpy initialization. Error:- $_"
            }
            finally{
                if($TempPythonFile -and (Test-Path $TempPythonFile)) {
                    Remove-Item $TempPythonFile -ErrorAction Ignore
                }
            }
        }
    }
    elseif($Component -ieq 'Pro') {
        Write-Verbose "TODO:- Check for Pro license"
    }
    else {
        Write-Verbose "License Check Component:- $Component ServerRole:- $ServerRole"
        $file = "$env:SystemDrive\Program Files\ESRI\License$($Version)\sysgen\keycodes"
        if(Test-Path $file) {        
            $searchtexts = @()
            $searchtext = if($RealVersion.StartsWith('10.4')) { 'server' } else { 'svr' }
            if($Component -ieq 'Portal') {
                $searchtexts += 'portal1_'
                $searchtexts += 'portal2_'
                $searchtext = 'portal_'
            }
            elseif($ServerRole -ieq 'ImageServer') {
			    $searchtext = 'imgsvr'
		    }
		    elseif($ServerRole -ieq 'GeoEvent') {
			    $searchtext = 'geoesvr'
		    }
		    elseif($ServerRole -ieq 'GeoAnalytics') {
			    $searchtext = 'geoasvr'
		    }
            $searchtexts += $searchtext
            foreach($text in $searchtexts) {
                Write-Verbose "Looking for text '$text' in $file"
                Get-Content $file | ForEach-Object {             
                    if($_ -and $_.ToString().StartsWith($text)) {
                        Write-Verbose "Text '$text' found"
                        if($force){
                            $result = $false
                        }else{
                            $result = $true
                        }
                    }
                }
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


Export-ModuleMember -Function *-TargetResource

