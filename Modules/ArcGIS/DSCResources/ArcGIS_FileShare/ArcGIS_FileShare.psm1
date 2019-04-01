<#
    .SYNOPSIS
        Creates a File Share for the Server and Portal to be shared in a High Availabilty Setup.
	.PARAMETER Ensure
		Indicates if the FileShare will be created and given the necessary Permissions. Take the values Present or Absent. 
        - "Present" ensures that FileShare is Created, if not already created.
        - "Absent" ensures that FileShare is removed, i.e. if present.
    .PARAMETER FileShareName
        Name of the FileShare as seen by Remote Resources.
    .PARAMETER FileShareLocalPath
        Local Path on Machine for the FileShare.
    .PARAMETER Credential
		UserName or Domain Account UserName which will have access to the File Share over the network.
	.PARAMETER IsDomainAccount
		Is Credential a Domain Account.
	.PARAMETER FilePaths
		FileShare Paths to be created.
	
#>

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$FileShareName,

		[parameter(Mandatory = $true)]
		[System.String]
		$FileShareLocalPath,

		[parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
        $Credential,

		[parameter(Mandatory = $false)]
		[System.String]
        $FilePaths,
        
        [System.Boolean]
        $IsDomainAccount = $false
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
		$FileShareName,

		[parameter(Mandatory = $true)]
		[System.String]
		$FileShareLocalPath,

		[parameter(Mandatory = $false)]
		[System.String]
        $FilePaths,

		[parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
        $Credential,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,
        
        [System.Boolean]
        $IsDomainAccount = $false
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    if($Ensure -eq 'Present') {
		$fs = Get-WmiObject -Class Win32_Share -Filter "Name='$FileShareName'"
		
		$UserName = $Credential.UserName
		if(-not($IsDomainAccount)){
			$SAPassword = ConvertTo-SecureString $Credential.GetNetworkCredential().Password -AsPlainText -Force
			$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("$($env:ComputerName)\$($Credential.UserName)", $SAPassword )
		}

		if($fs -ieq $NULL){
			New-Item $FileShareLocalPath -type directory;
			New-SMBShare -Name $FileShareName -Path $FileShareLocalPath -FullAccess $UserName
		}
		$fs = Get-WmiObject -Class Win32_Share -Filter "Name='$FileShareName'"
		if($fs -and -not(($fs | Get-Acl | Select-Object -ExpandProperty Access | Where-Object identityreference -eq $Credential.UserName).FileSystemRights -imatch "FullControl")){
			$acl = Get-Acl $FileShareLocalPath
			$permission = "$($UserName)","FullControl","ContainerInherit,ObjectInherit","None","Allow"
			$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
			$acl.SetAccessRule($accessRule)
			$acl | Set-Acl $FileShareLocalPath
		}
		if(($null -ne $FilePaths) -and ($FilePaths -ne "")){
			$FilePathArray = $FilePaths -Split ","
			ForEach($path in $FilePathArray){
				if(-not(Test-FileSharePath -FilePath $path -Credential $Credential)){
					Create-FileShareFolder -FilePath $path -Credential $Credential
				} 
			}
		}
    }
    elseif($Ensure -eq 'Absent') {
		if ($share = Get-WmiObject -Class Win32_Share -Filter "Name='$FileShareName'"){ 
			$share.delete() 
		}
    }
    Write-Verbose "In Set-Resource for ArcGIS FileShare"
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [parameter(Mandatory = $true)]
		[System.String]
		$FileShareName,

		[parameter(Mandatory = $true)]
		[System.String]
		$FileShareLocalPath,

		[parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
        $Credential,

		[parameter(Mandatory = $false)]
		[System.String]
        $FilePaths,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,
        
        [System.Boolean]
        $IsDomainAccount = $false
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    $result = $false
	
	if(-not($IsDomainAccount)){
		$SAPassword = ConvertTo-SecureString $Credential.GetNetworkCredential().Password -AsPlainText -Force
		$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("$($env:ComputerName)\$($Credential.UserName)", $SAPassword )
	}
	
	$fs = Get-WmiObject -Class Win32_Share -Filter "Name='$FileShareName'"
	if($fs){
		if(($fs | Get-Acl | Select-Object -ExpandProperty Access | Where-Object identityreference -eq $Credential.UserName).FileSystemRights -imatch "FullControl"){
			$result = $True
		}else{
            Write-Verbose "Correct Permissions are not granted."
		}
	}else{
		Write-Verbose "FileShare Not Found"
		if(Test-Path $FileShareLocalPath){
			Throw "FileShareLocalPath already exist. Please Choose Another One!"
		}
		$fsPath = $FileShareLocalPath -replace "\\","\\"
		if(Get-WmiObject Win32_Share -Filter "path='$fsPath'"){
			Throw "File Share Local Path already has a FileShare defined for it. Please Choose Another One!"
		}
	}
	if($result -and (($null -ne $FilePaths) -and ($FilePaths -ne ""))){
		$result = $false
		$FilePathArray = $FilePaths -Split ","
		ForEach($path in $FilePathArray){
		   if(Test-FileSharePath -FilePath $path -Credential $Credential){
				$result = $True
			} else {
				$result = $False
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

Function Create-FileShareFolder
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
	$FilePath = $FilePath.Trim()
	$drive = Get-FreeDriveLetter
	$SubFilePaths = $FilePath.Split('\', [System.StringSplitOptions]::RemoveEmptyEntries)
	$FilesharePath = "\"
	$MappedFilePath = "$($drive):"
	For ($i=0; $i -lt $SubFilePaths.Length; $i++) {
		if($i -lt 2){
			$FilesharePath = "$FilesharePath\$($SubFilePaths[$i])"
		}else{
			$MappedFilePath = "$MappedFilePath\$($SubFilePaths[$i])"
		}
	}
	try{
		New-PSDrive -Name $drive -PSProvider FileSystem -Root $FilesharePath -Credential $Credential -ErrorAction Stop
		New-Item -ItemType directory -Path $MappedFilePath
		Remove-PSDrive $drive
	}catch{
		Throw "Unable to create Folder $($FilePath) - $($_)"
	}
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
    $drives = [io.driveinfo]::getdrives() | % {$_.name[0]}
    $alpha = 65..90 | % { [char]$_ }
    $avail = diff $drives $alpha | select -ExpandProperty inputobject
    $avail[0]
}

Export-ModuleMember -Function *-TargetResource