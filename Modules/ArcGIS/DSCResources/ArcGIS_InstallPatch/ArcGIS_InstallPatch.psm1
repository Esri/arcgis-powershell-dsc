$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

<#
    .SYNOPSIS
        Installs a given component of the ArcGIS Enterprise Stack.
    .PARAMETER Ensure
        Indicates if the Component is to be installed or uninstalled if not present. Take the values Present or Absent. 
        - "Present" ensures that component is installed, if not already installed. 
        - "Absent" ensures that component is uninstalled or removed, if installed.
    .PARAMETER Name
        Name of ArcGIS Enterprise Component to be installed.
    .PARAMETER DownloadPatches
        Download patches from Esri patch downloads endpoint
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

        [parameter(Mandatory = $false)]
		[System.Boolean]
		$DownloadPatches = $False,

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

        [parameter(Mandatory = $false)]
		[System.Boolean]
		$DownloadPatches = $False,

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

    if($Ensure -eq 'Present') {
        if($DownloadPatches){
            if(-not(Test-Path $PatchesDir) -and -not($PatchesDir.StartsWith('\'))){
                Write-Verbose "Creating Directory $PatchesDir"
                New-Item $PatchesDir -ItemType directory
            }	
            $PatchManifest = Get-PatchManifestFromESRIDownloads -ProductName $Name -Version $Version
            if($PatchInstallOrder.Count -eq 0) {
                foreach($Patch in $PatchManifest.GetEnumerator()){
                    Invoke-TestDownloadInstallPatch -Patch $Patch.Value -PatchesDir $PatchesDir -Verbose 
                }
            }else{
				foreach($PatchFileName in $PatchInstallOrder){
					if($PatchManifest.Contains($PatchFileName.ToLower())){
                        Invoke-TestDownloadInstallPatch -Patch $PatchManifest[$PatchFileName.ToLower()] -PatchesDir $PatchesDir -Verbose 
                    }
                }
            }
        }else{
            if($PatchInstallOrder.Length -eq 0){
                $PatchInstallOrder = ( Get-ChildItem $PatchesDir | Sort-Object { $_.CreationTime } ).FullName
            }

            foreach($Patch in $PatchInstallOrder) {
                $PatchFileName = Split-Path $Patch -leaf
                $PatchLocation = (Join-Path $PatchesDir $PatchFileName)
                Write-Verbose "Checking Patch File at $($PatchLocation)"
                $QFEId = Get-QFEId -PatchLocation $PatchLocation # Extract the QFE-ID from the *.msp
                if (Test-PatchInstalled -QFEId $QFEId) {
                    Write-Verbose "Patch File at $($PatchLocation) with QFE Id $QFEId installed"
                }else{
                    Write-Verbose "Patch File at $($PatchLocation) with QFE Id $QFEId not installed"
                    if(Install-Patch -mspPath $PatchLocation -Verbose){
                        Write-Verbose "Installation was successful for patch file at $($PatchLocation) with QFE Id $QFEId"
                    }else{
                        Write-Verbose "Installation failed for patch file at $($PatchLocation) with QFE Id $QFEId not installed"
                    }
                }
            }
        }
    }
    elseif($Ensure -eq 'Absent') {
        #Uninstall Patch not implemented
    }
}

function Invoke-TestDownloadInstallPatch
{
    param
	(
        $Patch,

        [System.String]
        $PatchesDir
    )

    $QFEId = $Patch.QFE_ID
    if(Test-PatchInstalled -QFEId $QFEId){
        Write-Verbose "Patch with QFE Id $QFEId installed."
    }else{
        Write-Verbose "Patch with QFE Id $QFEId not installed"
        $PatchLocation = Join-Path $PatchesDir $Patch.FileName
        try {
            Write-Verbose "Downloading Patch $($Patch.Name) with QFE Id $QFEId"
            $wc = New-Object System.Net.WebClient;
            $wc.DownloadFile($Patch.PatchFileUrl, $PatchLocation)        
        }
        catch {
            throw "Error downloading remote file. Error - $_"
        }
        if(Install-Patch -mspPath $PatchLocation -Verbose){
            Write-Verbose "Installation was successful for patch file at $($PatchLocation) with QFE Id $QFEId"
        }else{
            Write-Verbose "Installation failed for patch file at $($PatchLocation) with QFE Id $QFEId not installed"
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
		$Name,

        [parameter(Mandatory = $false)]
		[System.Boolean]
		$DownloadPatches = $False,

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

    $result = $false

    if(-not($ProductId)){
        $FullProductName = Get-ArcGISProductName -Name $Name -Version $Version
        $InstallObject = (Get-ArcGISProductDetails -ProductName $FullProductName)
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
            $result = Test-Install -Name $Name -Version $Version
        }
    }else{
        $result = Test-Install -Name $Name -ProductId $ProductId
    }

    if($result){
        if($DownloadPatches){
            $PatchManifest = Get-PatchManifestFromESRIDownloads -ProductName $Name -Version $Version
            if($PatchInstallOrder.Count -eq 0) {
                foreach($Patch in $PatchManifest.GetEnumerator()){
                    $QFEId = $Patch.Value.QFE_ID
                    if(Test-PatchInstalled -QFEId $QFEId){
                        Write-Verbose "Patch with QFE Id $QFEId installed"
                    }else{
                        Write-Verbose "Patch with QFE Id $QFEId not installed"
                        $result = $false
                        break;
                    }
                }
            }else{
                foreach($PatchFileName in $PatchInstallOrder){
                    if($PatchManifest.Contains($PatchFileName.ToLower())){
                        $Patch = $PatchManifest[$PatchFileName.ToLower()]
						$QFEId = $Patch.QFE_ID
                        if(Test-PatchInstalled -QFEId $QFEId){
                            Write-Verbose "Patch with QFE Id $QFEId installed"
                        }else{
                            Write-Verbose "Patch with QFE Id $QFEId not installed"
                            $result = $false
                            break;
                        }
                    }
                }
            }
        }else{
            if($PatchInstallOrder.Length -eq 0){
                $PatchInstallOrder = ( Get-ChildItem $PatchesDir | Sort-Object { $_.CreationTime } ).FullName
            }

            foreach($Patch in $PatchInstallOrder) {
                $PatchFileName = Split-Path $Patch -leaf
                $PatchLocation = (Join-Path $PatchesDir $PatchFileName)
                Write-Verbose "Checking Patch File at $($PatchLocation)"
                $QFEId = Get-QFEId -PatchLocation $PatchLocation # Extract the QFE-ID from the *.msp
                if (Test-PatchInstalled -QFEId $QFEId) {
                    Write-Verbose "Patch File at $($PatchLocation) with QFE Id $QFEId installed"
                }else{
                    Write-Verbose "Patch File at $($PatchLocation) with QFE Id $QFEId not installed"
                    $result = $false
                    break;
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

function Get-PatchManifestFromESRIDownloads
{
    param(
        [System.String]
        $ProductName,

        [System.String]
        $Version        
    )

    #TODO - Tackle multiple patches for a installer
    $ProductNameArray = @()
    if($ProductName -ieq "Desktop"){
        $ProductNameArray += "ArcMap"
    }elseif($ProductName -ieq "DataStore"){
        $ProductNameArray += "ArcGIS Data Store"
    }elseif($ProductName -ieq "Portal"){
        $ProductNameArray += "Portal for ArcGIS"
    }elseif($ProductName -ieq "Server"){
        $ProductNameArray += "ArcGIS Server"
    }elseif($ProductName -ieq "WebAdaptor"){
        $ProductNameArray += "ArcGIS Web Adaptor (IIS)"
    }elseif($ProductName -ieq "WorkflowManagerServer"){
        $ProductNameArray += "ArcGIS Workflow Manager Server"
    }elseif($ProductName -ieq "MissionServer"){
        $ProductNameArray += "ArcGIS Mission Server"
    }elseif($ProductName -ieq "NotebookServer"){
        $ProductNameArray += "ArcGIS Notebook Server"
    }elseif($ProductName -ieq "GeoEvent"){
        $ProductNameArray += "ArcGIS GeoEvent Server"
        $ProductNameArray += "GeoEvent"
    }

    $MinifiedVersion = $Version.Replace(".","")
    $wc = New-Object System.Net.WebClient
    $PatchManifestJsonString = $wc.DownloadString("https://downloads.esri.com/patch_notification/patches.json")
    $AllPatches = ConvertFrom-Json $PatchManifestJsonString
	$ParsedPatchesObject = [ordered]@{}
	$AllPatchesForVersion = ($AllPatches.Product | Where-Object { $_.Version -ieq $Version })
	if($null -ne $AllPatchesForVersion){
        $PatchesForProduct = $AllPatchesForVersion.patches | Where-Object { @(Compare-Object -ReferenceObject ($_.Products.Split(",") | % { $_.Trim() }) -DifferenceObject $ProductNameArray -IncludeEqual -excludedifferent).count -gt 0 }
		if($null -ne $PatchesForProduct){
			$PatchesForProductSorted = $PatchesForProduct | Sort-Object {[System.DateTime]::ParseExact($_.ReleaseDate, "MM/dd/yyyy", $null)}
			foreach($Patch in $PatchesForProductSorted){
				if($Patch.PatchFiles.Length -gt 0){
					try{ 
						foreach($PatchFileUrl in $Patch.PatchFiles){
							if($PatchFileUrl.Contains(".msp") -and $PatchFileUrl.Contains($MinifiedVersion)){
								$PatchFileName = Split-Path "$(($PatchFileUrl -split ".msp")[0]).msp" -leaf
                                $ParsedPatchesObject[$PatchFileName.ToLower()] = @{
									"Name" = $Patch.name
									"FileName" = $PatchFileName
									"QFE_ID" = $Patch.QFE_ID
									"ReleaseDate" = $Patch.ReleaseDate
									"PatchFileUrl" = $PatchFileUrl
									"Critical" = $Patch.Critical
									#"SHA256sum" = ($Patch.SHA256sums | Where-Object { $_.StartsWith($PatchFileName)} | Select-Object -First 1 ).Split(':')[1]
								}
							}
						}
					}catch{
						Write-Verbose "$($Patch.Name) $_"
						throw $_
					}
				}
			}
		}
	}
    return $ParsedPatchesObject
}

#TODO - Logic is flawed. doesn't cover all products, use product name, patch name and version. Needs optimizations
function Test-PatchInstalled 
{ 
    [OutputType([System.Boolean])]
    Param(
        [System.String]
        $QFEId
    )
    
    $RegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" ,
        "HKLM:\SOFTWARE\ESRI\Portal for ArcGIS\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\ArcGIS Data Store\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\ArcGIS Notebook Server\Updates\*",
        "HKLM:\SOFTWARE\ESRI\ArcGIS Insights\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\Server10.3\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\Server10.4\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\Server10.5\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\Server10.6\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\Server10.7\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\Server10.8\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\Server10.9\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\Server11.0\Updates\*" ,
        "HKLM:\SOFTWARE\ESRI\GeoEvent10.6\Server\Updates\*",
        "HKLM:\SOFTWARE\ESRI\GeoEvent10.7\Server\Updates\*",
        "HKLM:\SOFTWARE\ESRI\GeoEvent10.8\Server\Updates\*",
        "HKLM:\SOFTWARE\ESRI\GeoEvent10.9\Server\Updates\*",
        "HKLM:\SOFTWARE\ESRI\GeoEvent11.0\Server\Updates\*",
        "HKLM:\SOFTWARE\ESRI\ArcGISPro\Updates\*" ,
        "HKLM:\SOFTWARE\WOW6432Node\ESRI\Desktop10.4\Updates\*" ,
        "HKLM:\SOFTWARE\WOW6432Node\ESRI\Desktop10.5\Updates\*" ,
        "HKLM:\SOFTWARE\WOW6432Node\ESRI\Desktop10.6\Updates\*" ,
        "HKLM:\SOFTWARE\WOW6432Node\ESRI\Desktop10.7\Updates\*",
        "HKLM:\SOFTWARE\WOW6432Node\ESRI\Desktop10.8\Updates\*",
        "HKLM:\SOFTWARE\WOW6432Node\ESRI\ArcGIS Web Adaptor (IIS) 10.8\Updates\*",
        "HKLM:\SOFTWARE\WOW6432Node\ESRI\ArcGIS Web Adaptor (IIS) 10.8.1\Updates\*",
        "HKLM:\SOFTWARE\WOW6432Node\ESRI\ArcGIS Web Adaptor (IIS) 10.9\Updates\*",
        "HKLM:\SOFTWARE\WOW6432Node\ESRI\ArcGIS Web Adaptor (IIS) 10.9.1\Updates\*",
        "HKLM:\SOFTWARE\WOW6432Node\ESRI\ArcGIS Web Adaptor (IIS) 11.0\Updates\*"
    )
    
    foreach($RegPath in $RegPaths){
        if(Test-Path -PathType Container -Path $RegPath){
            #  Search the Registry path for all 'QFE_ID' Objects
            $Reg_QFE_IDs = Get-ItemProperty $RegPath | Sort-Object -Property QFE_ID | Select-Object QFE_ID
            foreach($Reg_QFE_ID in $Reg_QFE_IDs){
                if(-not([string]::IsNullOrEmpty($Reg_QFE_ID.QFE_ID))){
                    Write-Verbose -Message "Comparing QFE ID $QFEId against ID $($Reg_QFE_ID.QFE_ID)"
                    $QFEIdsArray = ($Reg_QFE_ID.QFE_ID.Split(",") | % { $_.Trim() }) 
                    if($QFEIdsArray -iContains $QFEId)
                    {
                        # The patch is installed, skip further processing
                        Write-Verbose -Message "Patch with QFE Id $QFEId already installed"
                        return $true
                    }
                }
            }
        }
    }
    return $false
}

function Install-Patch
{
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
# Get a Patch Code from an Microsoft Installer Patch MSP (Andreas Nick 2015)
function Get-QFEId
{
    param (
        [System.String]
        $PatchLocation
    )
    if(-not(Test-Path $PatchLocation)){
        throw "Patch File $PatchLocation is not accessible"
    }
    try{
        $wi = New-Object -com WindowsInstaller.Installer
        $mspdb = $wi.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $Null, $wi, $($PatchLocation, 32))
        $su = $mspdb.GetType().InvokeMember("SummaryInformation", "GetProperty", $Null, $mspdb, $Null)
        #$pc = $su.GetType().InvokeMember("PropertyCount", "GetProperty", $Null, $su, $Null)
        [string] $qfeID = $su.GetType().InvokeMember("Property", "GetProperty", $Null, $su, 3)
        return $qfeID
    }
    catch
    {
        throw "Unable to extract the QFE-ID from the Patch file at location $PatchLocation - $($_.Exception.Message)"
    }
}

Export-ModuleMember -Function *-TargetResource