<#
    .SYNOPSIS
        Resource Implements a wait for to check if the file share is available, if not waits for it.
    .PARAMETER FilePaths
        String Array of File Shares Paths to check for while waiting
    .PARAMETER Credential
        A MSFT_Credential Object - Credentials to access FileShare Path.
    .PARAMETER Ensure
        Take the values Present or Absent. 
        - "Present" ensures that machine waits for a target machine, for which the present node has a dependency on.
        - "Absent" - not implemented.
    .PARAMETER RetryIntervalSec
        Time Interval after which the Resource will again check the status of the resource on the remote machine for which the node is waiting for.
    .PARAMETER RetryCount
        Number of Retries before the Resource is done trying to see if the resource on the target Machine is done.        
#>


function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
        [parameter(Mandatory = $true)]
		[System.String]
        $FilePaths
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
        $FilePaths,
        
        [parameter(Mandatory = $False)]
		[System.Management.Automation.PSCredential]
        $Credential,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [parameter(Mandatory = $false)]
		[uint32]
        $RetryIntervalSec  = 30,

        [parameter(Mandatory = $false)]
		[uint32]
        $RetryCount  = 10
    )   
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false
    
    $FilePathArray = $FilePaths -Split ","
    
    $NumCount = 0
	$Done     = $false
	while (-not($Done) -and ($NumCount++ -le $RetryCount)) 
	{
        ForEach($path in $FilePathArray){
            if(Test-FileSharePath -FilePath $path -Credential $Credential){
                $Done = $True
            } else {
                $Done = $False
            }
            if(-not($Done)){
                break
            }
        }
        
        if(-not($Done)) {
            Write-Verbose "All File Share are not Accessible. Retrying after $RetryIntervalSec Seconds"
            Start-Sleep -Seconds $RetryIntervalSec
        }else {
            Write-Verbose "All Specified File Share paths are Accessible."
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
        $FilePaths,

        [parameter(Mandatory = $False)]
		[System.Management.Automation.PSCredential]
        $Credential,
        
		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [parameter(Mandatory = $false)]
		[uint32]
        $RetryIntervalSec  = 30,

        [parameter(Mandatory = $false)]
		[uint32]
        $RetryCount  = 10
	)
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false
    $result = $True
    $FilePathArray = $FilePaths -Split ","
    ForEach($path in $FilePathArray){
       if(Test-FileSharePath -FilePath $path -Credential $Credential){
            $result = $True
        } else {
           $result = $False
        }
        if(-not($result)){
            break
        }
    }
    $result
}

Function Test-FileSharePath
{
    [CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
        $FilePath,

        [parameter(Mandatory = $False)]
		[System.Management.Automation.PSCredential]
        $Credential
    )
    
    $drive = Get-FreeDriveLetter
    try{
        Write-Verbose $Credential.UserName
		Write-Verbose $FilePath
		
		$FilePath = $FilePath.Trim()
		$SubFilePaths = $FilePath.Split('\', [System.StringSplitOptions]::RemoveEmptyEntries)
		$FilesharePath = "\"
		For ($i=0; $i -lt $SubFilePaths.Length; $i++) {
			$FilesharePath = "$FilesharePath\$($SubFilePaths[$i])"
		}

        New-PSDrive -Name $drive -PSProvider FileSystem -Root $FilesharePath -Credential $Credential -ErrorAction Stop
        If (Test-Path $drive){
            Remove-PSDrive $drive
            $True
        }else{
            $False
        }
    }catch{
		$False
    }
}

function Get-FreeDriveLetter {
    $drives = [io.driveinfo]::getdrives() | ForEach-Object {$_.name[0]}
    $alpha = 65..90 | ForEach-Object { [char]$_ }
    $avail = Compare-Object $drives $alpha | Select-Object -ExpandProperty inputobject
    $avail[0]
}

Export-ModuleMember -Function *-TargetResource