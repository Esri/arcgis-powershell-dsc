<#
    .SYNOPSIS
        Installation Resource to Install WebAdaptors. Takes Care of multiple installations of a WebAdaptor. 
        Resource Implemented specifically to support multiple WebAdaptors on a Single Machine.
    .PARAMETER Ensure
        Take the values Present or Absent. 
        - "Present" ensures that WebAdaptor is Installed along with all it prerequisites.
        - "Absent" ensures that WebAdaptor is uninstalled.
    .PARAMETER Context
        Context with which the Web Adaptor Needs to be Installed.
    .PARAMETER Version
        Version of the WebAdaptor to be Installed.
    .PARAMETER Path
        Installer Path of the Webdaptor.
    .PARAMETER Arguments
        A MSFT_Credential Object - Primary Site Adminstrator.
    .PARAMETER LogPath
        Path where the Install logs will be saved.
    .PARAMETER PreRequisiteWindowsFeatures
        PreRequisiteWindowsFeatures Features Required to be installed before Web Adaptor Installation takes place.
#>

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
        $Context,
        
        [parameter(Mandatory = $true)]
		[System.String]
		$Version,

		[parameter(Mandatory = $true)]
		[System.String]
		$Path

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
        $Context,
        
        [parameter(Mandatory = $true)]
		[System.String]
		$Version,

		[parameter(Mandatory = $true)]
		[System.String]
		$Path,

		[parameter(Mandatory = $true)]
		[System.String]
		$Arguments,

		[System.String]
		$LogPath,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    if($Ensure -eq 'Present') {
        if(-not(Test-Path $Path)){
            throw "$Path is not found or inaccessible"
        }

        $PreRequisiteWindowsFeatures = @("IIS-ManagementConsole", "IIS-ManagementScriptingTools",
                                        "IIS-ManagementService", "IIS-ISAPIExtensions",
                                        "IIS-ISAPIFilter", "IIS-RequestFiltering",
                                        "IIS-WindowsAuthentication", "IIS-StaticContent",
                                        "IIS-ASPNET45", "IIS-NetFxExtensibility45")

        foreach($pr in $PreRequisiteWindowsFeatures){
            Write-Verbose "Installing Windows Feature: $pr"
            if (Get-Command "Get-WindowsOptionalFeature" -errorAction SilentlyContinue)
            {
                if(-not((Get-WindowsOptionalFeature -FeatureName $pr -online).State -ieq "Enabled")){
                    Enable-WindowsOptionalFeature -Online -FeatureName $pr -All -NoRestart
                }
            }else{
                 Write-Verbose "Please check the Machine Operating System Compatatbilty"
            }
        }
        
        $ExecPath = $null
        if((Get-Item $Path).length -gt 5mb)
        {
            Write-Verbose 'Self Extracting Installer'

            $TempFolder = Join-Path ([System.IO.Path]::GetTempPath()) "WebAdaptor\$($Context)"

            if(Test-Path $TempFolder)
            {
                Remove-Item -Path $TempFolder -Recurse 
            }
            if(-not(Test-Path $TempFolder))
            {
                New-Item $TempFolder -ItemType directory            
            }  
                       
            $SevenZipPath = Join-Path ${env:ProgramFiles} (Join-Path '7-Zip' '7z.exe')
            if(-not(Test-Path $SevenZipPath)) 
            {
                Write-Verbose "7Zip not found at $SevenZipPath"
                Write-Verbose 'Installing 7Zip'
                  
                $MsiFile = Join-Path $TempFolder '7Zip.msi'
                Invoke-WebRequest -Uri 'https://osdn.net/frs/redir.php?m=pumath&f=sevenzip%2F64449%2F7z938-x64.msi' -OutFile $MsiFile
                Write-Verbose "msiexec /i $MsiFile /quiet"
                Invoke-Expression "msiexec /i $MsiFile /quiet"
                Start-Sleep -Seconds 30 # Allow files to be copied to Program Files
            }
            if(-not(Test-Path $SevenZipPath)) 
            {
                throw "7-Zip not found at $SevenZipPath"
            }

            Write-Verbose "Extracting $Path to $TempFolder"
            Write-Verbose """$SevenZipPath"" x -y $Path -o$TempFolder"
            Start-Process -FilePath $SevenZipPath -ArgumentList " x -y $Path -o$TempFolder" -Wait
            Write-Verbose 'Done Extracting. Waiting 15 seconds to allow the extractor to close files'
            Start-Sleep -Seconds 15 # To allow 7-zip to close files

            $SetupExe = Get-ChildItem -Path $TempFolder -Filter 'Setup.exe' -Recurse | Select-Object -First 1
            $ExecPath = $SetupExe.FullName
            if(-not($ExecPath) -or (-not(Test-Path $ExecPath))) {
               Write-Verbose 'Setup.exe not found in extracted contents'
               $SetupExe = Get-ChildItem -Path $TempFolder -Filter '*.exe' -Recurse | Select-Object -First 1
               $ExecPath = $SetupExe.FullName
               if(-not($ExecPath) -or (-not(Test-Path $ExecPath))) {
                   Write-Verbose "Executable .exe not found in extracted contents to install. Looking for .msi"
                   $SetupExe = Get-ChildItem -Path $TempFolder -Filter '*.msi' -Recurse | Select-Object -First 1
                   $ExecPath = $SetupExe.FullName
                   if(-not($ExecPath) -or (-not(Test-Path $ExecPath))) {
                        throw "Neither .exe nor .msi not found in extracted contents to install"
                   }               
               }               
            }
        
            Write-Verbose "Executing $ExecPath with arguments $Arguments"
            Write-Verbose "$ExecPath $Arguments"
            if($LogPath) {
                Start-Process -FilePath $ExecPath -ArgumentList $Arguments -Wait -RedirectStandardOutput $LogPath
            }else {
                Start-Process -FilePath $ExecPath -ArgumentList $Arguments -Wait
            }
        }
        else {
			Write-Verbose "Installing Software using installer at $Path and arguments $Arguments"            
            if($LogPath) {
                Start-Process -FilePath $Path -ArgumentList $Arguments -Wait -RedirectStandardOutput $LogPath
            }else {
                Start-Process -FilePath $Path -ArgumentList $Arguments -Wait
            } 
        }
        Write-Verbose "Giving Permissions to Folders for IIS_IUSRS"
        foreach($p in (Get-ChildItem "$($env:SystemDrive)\Windows\Microsoft.NET\Framework*\v*\Temporary ASP.NET Files").FullName){
            icacls $p /grant 'IIS_IUSRS:(OI)(CI)F' /T
        }
        icacls "$($env:SystemDrive)\Windows\TEMP\" /grant 'IIS_IUSRS:(OI)(CI)F' /T
    }
    elseif($Ensure -eq 'Absent') {
        $WAInstalls = (get-wmiobject Win32_Product| Where-Object {$_.Name -match 'Web Adaptor' -and $_.Vendor -eq 'Environmental Systems Research Institute, Inc.'})
        foreach($wa in $WAInstalls){
            if($wa.InstallLocation -match "\\$($Context)\\"){
                #SanityCheck - if($ProductIds -contains $wa.IdentifyingNumber)
                $ProdId = $wa.IdentifyingNumber
                if(-not($ProdId.StartsWith('{'))){
                    $ProdId = '{' + $ProdId
                }
                if(-not($ProdId.EndsWith('}'))){
                    $ProdId = $ProdId + '}'
                }
                Write-Verbose "msiexec /x ""$ProdId"" /quiet"
                Start-Process 'msiexec' -ArgumentList "/x ""$ProdId"" /quiet" -wait
                break
            }
        }
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
        $Context,
        
        [parameter(Mandatory = $true)]
		[System.String]
		$Version,

		[parameter(Mandatory = $true)]
		[System.String]
		$Path,

		[parameter(Mandatory = $true)]
		[System.String]
		$Arguments,

		[System.String]
		$LogPath,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    $WAInstalls = (get-wmiobject Win32_Product| Where-Object {$_.Name -match 'Web Adaptor' -and $_.Vendor -eq 'Environmental Systems Research Institute, Inc.'})
    if($WAInstalls.Length -gt 1){
        Write-Verbose "Multiple Instances of Web Adaptor are already installed"
    }
    $result = $false
    foreach($wa in $WAInstalls){
        if($wa.InstallLocation -match "\\$($Context)\\"){
            $result = $true
            break
        }else{
            $result = $false
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

