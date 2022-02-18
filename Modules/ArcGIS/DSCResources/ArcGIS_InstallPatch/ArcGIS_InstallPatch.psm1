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
    .PARAMETER PatchInstallOrder
        Array of Patch Installer file names to specify the Installation order of Patch and the patches to install
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

        [parameter(Mandatory = $false)]
		[System.Array]
		$PatchInstallOrder,

		[parameter(Mandatory = $true)]
		[System.String]
        $Version,

        [parameter(Mandatory = $false)]
		[System.String]
		$ProductId,

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

        [parameter(Mandatory = $false)]
		[System.Array]
		$PatchInstallOrder,

		[parameter(Mandatory = $true)]
		[System.String]
        $Version,

        [parameter(Mandatory = $false)]
		[System.String]
		$ProductId,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    if($Ensure -eq 'Present') {
        # test & install patches
        Write-Verbose "Installing Patches"
        if ($PatchesDir) {
            if($PatchInstallOrder.Length -gt 0){
                foreach ($Patch in $PatchInstallOrder) {
                    $PatchFileName = Split-Path $Patch -leaf
                    $PatchLocation = (Join-Path $PatchesDir $PatchFileName)
                    Write-Verbose " > PatchFile : $PatchFileName | Fullname : $($PatchLocation)"
                    if (Test-PatchInstalled -mspPath $PatchLocation) {
                        Write-Verbose " > Patch installed - no Action required"
                    }else{
                        Write-Verbose " > Patch not installed - installing"
                        if(Install-Patch -mspPath $PatchLocation -Verbose){
                            Write-Verbose " > Patch installed - successfully"
                        }else{
                            Write-Verbose " > Patch installation failed"
                        }
                    }
                }
            }else{
                $files = Get-ChildItem "$PatchesDir"        
                Foreach ($file in $files) {
                    Write-Verbose " > PatchFile : $file | Fullname : $($file.Fullname)"
                    if (Test-PatchInstalled -mspPath $($file.FullName)) {
                        Write-Verbose " > Patch installed - no Action required"
                    } else {
                        Write-Verbose " > Patch not installed - installing"
                        if(Install-Patch -mspPath $file.FullName -Verbose){
                            Write-Verbose " > Patch installed - successfully"
                        }else{
                            Write-Verbose " > Patch installation failed"
                        }
                    }
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

        [parameter(Mandatory = $false)]
		[System.Array]
		$PatchInstallOrder,

		[parameter(Mandatory = $true)]
		[System.String]
        $Version,

        [parameter(Mandatory = $false)]
		[System.String]
		$ProductId,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    $result = $false
    
    $ComponentName = $Name
    if($Name -ieq "ArcGIS Pro"){
        $ComponentName = 'Pro'
    }elseif($Name -ieq "ArcGIS Desktop"){
        $ComponentName = 'Desktop'
    }elseif($Name -ieq "ArcGIS License Manager"){
        $ComponentName = 'LicenseManager'
    }elseif($Name -ieq "ArcGIS for Server"){
        $ComponentName = 'Server'
    }elseif($Name -ieq "Web Styles"){
        $ComponentName = 'WebStyles'
    }elseif($Name -ieq "DataStore"){
        $ComponentName = 'DataStore'
    }elseif($Name -ieq "GeoEvent"){
        $ComponentName = 'GeoEvent'
    }elseif($Name -ieq "Notebook Server"){
        $ComponentName = 'NotebookServer'
    }elseif($Name -ieq "Mission Server"){
        $ComponentName = 'MissionServer'
    }elseif($Name -ieq "Workflow Manager Server"){
        $ComponentName = 'WorkflowManagerServer'
    }elseif($Name -ieq "Workflow Manager WebApp"){
        $ComponentName = 'WorkflowManagerWebApp'
    }elseif($Name -ieq "Insights"){
        $ComponentName = 'Insights'
    }elseif($Name -ieq "WebAdaptor"){
        $ComponentName = 'WebAdaptor'
    }

    if(-not($ProductId)){
        $trueName = Get-ArcGISProductName -Name $ComponentName -Version $Version
        
        $InstallObject = (Get-ArcGISProductDetails -ProductName $trueName)
        if($Name -ieq 'WebAdaptor'){
            if($InstallObject.Length -gt 1){
                Write-Verbose "Multiple Instances of Web Adaptor are already installed - $($InstallObject.Version)"
            }
            foreach($wa in $InstallObject){
                $result = Test-Install -Name 'WebAdaptor' -Version $Version -ProductId $wa.IdentifyingNumber.TrimStart("{").TrimEnd("}") -Verbose
                if($result -ieq $True){
                    Write-Verbose "Found Web Adaptor Installed for Version $Version"
                    break
                }else{
                    $result = $False
                }
            }
        }else{
            Write-Verbose "Installed Version $($InstallObject.Version)"
            $result = Test-Install -Name $ComponentName -Version $Version
        }
    }else{
        $result = Test-Install -Name $ComponentName -ProductId $ProductId
    }
   
    #test for installed patches
    if($result -and $PatchesDir) {
        if($PatchInstallOrder.Length -gt 0){
            foreach ($Patch in $PatchInstallOrder) {
                $PatchFileName = Split-Path $Patch -leaf
                $PatchLocation = (Join-Path $PatchesDir $PatchFileName)
                Write-Verbose " > PatchFile : $PatchFileName | Fullname : $($PatchLocation)"
                if (Test-PatchInstalled -mspPath $PatchLocation) {
                    Write-Verbose " > Patch installed"
                }else{
                    Write-Verbose " > Patch not installed"
                    $result = $false
                }
            }
        }else{
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
        "HKLM:\SOFTWARE\ESRI\ArcGIS Insights\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\Server10.3\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\Server10.4\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\Server10.5\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\Server10.6\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\Server10.7\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\Server10.8\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\Server10.9\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\GeoEvent10.6\Server\Updates\*",
        "HKLM:\SOFTWARE\ESRI\GeoEvent10.7\Server\Updates\*",
        "HKLM:\SOFTWARE\ESRI\GeoEvent10.8\Server\Updates\*",
        "HKLM:\SOFTWARE\ESRI\GeoEvent10.9\Server\Updates\*",
        "HKLM:\SOFTWARE\ESRI\ArcGISPro\Updates\*" ,
        "HKLM:\SOFTWARE\WOW6432Node\ESRI\Desktop10.4\Updates\*" ,
        "HKLM:\SOFTWARE\WOW6432Node\ESRI\Desktop10.5\Updates\*" ,
        "HKLM:\SOFTWARE\WOW6432Node\ESRI\Desktop10.6\Updates\*" ,
        "HKLM:\SOFTWARE\WOW6432Node\ESRI\Desktop10.7\Updates\*",
        "HKLM:\SOFTWARE\WOW6432Node\ESRI\Desktop10.8\Updates\*",
        "HKLM:\SOFTWARE\WOW6432Node\ESRI\ArcGIS Web Adaptor (IIS) 10.8.1\Updates\*"
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

function Install-Patch{
    [OutputType([System.Boolean])]
	param
    (
        [System.String]
        $mspPath
    )

    if(Test-Path $mspPath){
        $arguments = "/update "+ '"' + $mspPath +'"' + " /quiet"
        Write-Verbose $arguments
        try {
            $PatchInstallProc = Start-Process -FilePath msiexec.exe -ArgumentList $Arguments -Wait -Verbose -PassThru
            if($PatchInstallProc.ExitCode -ne 0){
                Write-Verbose "Error while installing patch :- exited with status code $($PatchInstallProc.ExitCode)"
                return $false
            }else{
                Write-Verbose "Patch Installation successful."
                return $true
            }
        } catch {
            Write-Verbose "Error in Install-Patch :-$_"
            return $false
        }
    }else{
        Write-Verbose "Patch '$mspPath' path doesn't exist"
        return $false
    }
}

# http://www.andreasnick.com/85-reading-out-an-msp-product-code-with-powershell.html
<# 
.SYNOPSIS 
    Get the Patch Code from an Microsoft Installer Patch MSP
.DESCRIPTION 
    Get a Patch Code from an Microsoft Installer Patch MSP (Andreas Nick 2015)
.NOTES 
    $NULL for an error
.LINK
.RETURNVALUE
  [String] Product Code
.PARAMETER
  [IO.FileInfo] Path to the msp file
#>
function Get-MSPqfeID {
    param (
        [IO.FileInfo] $patchnamepath
          
    )
    try {
        $wi = New-Object -com WindowsInstaller.Installer
        $mspdb = $wi.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $Null, $wi, $($patchnamepath.FullName, 32))
        $su = $mspdb.GetType().InvokeMember("SummaryInformation", "GetProperty", $Null, $mspdb, $Null)
        #$pc = $su.GetType().InvokeMember("PropertyCount", "GetProperty", $Null, $su, $Null)

        [String] $qfeID = $su.GetType().InvokeMember("Property", "GetProperty", $Null, $su, 3)
        return $qfeID
    }
    catch {
        Write-Output -InputObject $_.Exception.Message
        return $NULL
    }
}

Export-ModuleMember -Function *-TargetResource