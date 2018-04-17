<#
    .SYNOPSIS
        Installs a given component of the ArcGIS Enterprise Stack.
    .PARAMETER Ensure
        Indicates if the Component is to be installed or uninstalled if not present. Take the values Present or Absent. 
        - "Present" ensures that component is installed, if not already installed. 
        - "Absent" ensures that component is uninstalled or removed, if installed.
    .PARAMETER Name
        Name of ArcGIS Enterprise Component to be installed.
    .PARAMETER Path
        Path to Installer for the Component - Can be a Physical Location or Network Share Address.
    .PARAMETER Version
        Version of the Component being Installed.
    .PARAMETER Arguments
        Additional Command Line Arguments required by the installer to complete intallation of the give component successfully.
    .PARAMETER LogPath
        Optional Path where the Logs generated during the Install will be stored.
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
		$Path,

		[parameter(Mandatory = $true)]
		[System.String]
		$Version,

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
		$Path,

		[parameter(Mandatory = $true)]
		[System.String]
		$Version,

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

        $ExecPath = $null
        if((Get-Item $Path).length -gt 5mb)
        {
            Write-Verbose 'Self Extracting Installer'
            $ProdId = Get-ComponentCode -ComponentName $Name -Version $Version
            $TempFolder = Join-Path ([System.IO.Path]::GetTempPath()) $ProdId
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
                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = $ExecPath
                $psi.Arguments = $Arguments
                $psi.UseShellExecute = $false #start the process from it's own executable file    
                $psi.RedirectStandardOutput = $true #enable the process to read from standard output
                $psi.RedirectStandardError = $true #enable the process to read from standard error
                
                $p = [System.Diagnostics.Process]::Start($psi)
                $p.WaitForExit()
                $op = $p.StandardOutput.ReadToEnd()
                if($op -and $op.Length -gt 0) {
                    Write-Verbose "Output of execution:- $op"
                }
                $err = $p.StandardError.ReadToEnd()
                if($err -and $err.Length -gt 0) {
                    Write-Verbose $err
                }

                if($Name -ieq "Portal"){
                    if($Version -ieq "10.5"){
                        $ArgsArray = $Arguments.Split('=')
                        $Done = $False
                        $NumCount = 0
                        $RetryIntervalSec  = 30
                        $RetryCount  = 15
                        while(-not($Done) -and ($NumCount++ -le $RetryCount)){
                            if(Test-Path "$($ArgsArray[2])\arcgisportal\content\items\portal" ){
                                $Done = $True
                            }else{
                                Write-Verbose "Portal Dependencies Still being Unpacked"
                                Start-Sleep -Seconds $RetryIntervalSec
                            }
                        }
                    }
                    
                    Write-Verbose "Waiting just in case for Portal to finish unpacking any additional dependecies - 120 Seconds"
                    Start-Sleep -Seconds 120
                    if($Version -ieq "10.5"){
                        if(-not(Test-Path "$($ArgsArray[2])\arcgisportal\content\items\portal")){
                            throw "Portal Dependencies Didn't Unpack!"
                        }
                    }
                }
            }
        }
        else {
            Write-Verbose "Installing Software using installer at $Path and arguments $Arguments"            
            if($LogPath) {
                Start-Process -FilePath $Path -ArgumentList $Arguments -Wait -RedirectStandardOutput $LogPath
            }else {
                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = $Path
                $psi.Arguments = $Arguments
                $psi.UseShellExecute = $false #start the process from it's own executable file    
                $psi.RedirectStandardOutput = $true #enable the process to read from standard output
                $psi.RedirectStandardError = $true #enable the process to read from standard error
                
                $p = [System.Diagnostics.Process]::Start($psi)
                $p.WaitForExit()
                $op = $p.StandardOutput.ReadToEnd()
                if($op -and $op.Length -gt 0) {
                    Write-Verbose "Output of execution:- $op"
                }
                $err = $p.StandardError.ReadToEnd()
                if($err -and $err.Length -gt 0) {
                    Write-Verbose "Error:- $err"
                }
            } 
        }
        Write-Verbose "Validating the $Name Installation"
        $result = Test-Install -Name $Name -Version $Version
        if(-not($result)){
            throw "Failed to Install $Name"
        }else{
            Write-Verbose "$Name installation was successful!"
        }
    }
    elseif($Ensure -eq 'Absent') {
        $ProdId = Get-ComponentCode -ComponentName $Name -Version $Version
        if(-not($ProdId.StartsWith('{'))){
            $ProdId = '{' + $ProdId
        }
        if(-not($ProdId.EndsWith('}'))){
            $ProdId = $ProdId + '}'
        }
        Write-Verbose "msiexec /x ""$ProdId"" /quiet"
        Start-Process 'msiexec' -ArgumentList "/x ""$ProdId"" /quiet" -wait
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
		$Path,

		[parameter(Mandatory = $true)]
		[System.String]
		$Version,

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

    $result = $false
    
    $trueName = if ($Name -ieq 'DataStore') { 'Data Store' } else { $Name }
    $ver = get-wmiobject Win32_Product| Where-Object {$_.Name -match $trueName -and $_.Vendor -eq 'Environmental Systems Research Institute, Inc.'}
	Write-Verbose "Installed Version $($ver.Version)"

    $result = Test-Install -Name $Name -Version $Version

    if($Ensure -ieq 'Present') {
	       $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}

Export-ModuleMember -Function *-TargetResource