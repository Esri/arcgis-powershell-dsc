$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

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
	.PARAMETER IsMSAAccount
		Is Credential a Managed Service Account.
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
		
		[parameter(Mandatory = $false)]
        [System.Boolean]
        $IsDomainAccount = $false,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsMSAAccount = $false
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
        
        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsDomainAccount = $false,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsMSAAccount = $false
	)

    if($Ensure -eq 'Present') {
		$fs = Get-CimInstance -Class Win32_Share -Filter "Name='$FileShareName'"
		
		$UserName = $Credential.UserName
		if(-not($IsDomainAccount) -and -not($IsMSAAccount)){
			$UserName = "$($env:ComputerName)\$($Credential.UserName)"
		}

		if(-not($fs)){
			Write-Verbose "FileShare Not Found"
			if(Test-Path $FileShareLocalPath){
				Write-Verbose "FileShareLocalPath already exist."
			}else{
				New-Item $FileShareLocalPath -type directory
			}
			
			$fsPath = $FileShareLocalPath -replace "\\","\\"
			$fs = Get-CimInstance Win32_Share -Filter "path='$fsPath'"
			if(($fs | Where-Object { $_.Name -ieq $FileShareName }).Name -ine $FileShareName ){
				Write-Verbose "File Share Local Path already has a FileShare defined for it and none match $FileShareName. Creating another share on $FileShareLocalPath"
				New-SMBShare -Name $FileShareName -Path $FileShareLocalPath -FullAccess $UserName
			}
		}
				
		$fs = Get-CimInstance -Class Win32_Share -Filter "Name='$FileShareName'"
		if(-not(($fs | Get-Acl | Select-Object -ExpandProperty Access | Where-Object identityreference -eq $UserName).FileSystemRights -imatch "FullControl")){
			$acl = Get-Acl $FileShareLocalPath
			$permission = "$($UserName)","FullControl","ContainerInherit,ObjectInherit","None","Allow"
			$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
			$acl.SetAccessRule($accessRule)
			$acl | Set-Acl $FileShareLocalPath
		}			
		if(($null -ne $FilePaths) -and ($FilePaths -ne "")){
			$FilePathArray = $FilePaths -Split ","
			ForEach($path in $FilePathArray){
				if(-not(Test-FileSharePath -FilePath $path -UserName $UserName -FileShareLocalPath $FileShareLocalPath )){
					New-FileShareFolder -FilePath $path -UserName $UserName -FileShareLocalPath $FileShareLocalPath
				} 
			}
		}
    }
    elseif($Ensure -eq 'Absent') {
		if ($share = Get-CimInstance -Class Win32_Share -Filter "Name='$FileShareName'"){ 
			try{
				Remove-CimInstance -CimInstance $share
			} catch [Exception] {
				Write-Verbose $_ | out-string
			}
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
        
        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsDomainAccount = $false,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsMSAAccount = $false
	)

    $result = $false
	
	$UserName = $Credential.UserName
	if(-not($IsDomainAccount) -and -not($IsMSAAccount)){
		$UserName = "$($env:ComputerName)\$($Credential.UserName)"
	}
	
	$fs = Get-CimInstance -Class Win32_Share -Filter "Name='$FileShareName'"
	if($fs){
		if(($fs | Get-Acl | Select-Object -ExpandProperty Access | Where-Object identityreference -eq $UserName).FileSystemRights -imatch "FullControl"){
			$result = $True
		}else{
            Write-Verbose "Correct Permissions are not granted."
		}
	}else{
		Write-Verbose "FileShare Not Found"
		if(Test-Path $FileShareLocalPath){
			Write-Verbose "File Share Local Path $FileShareLocalPath already exists."
		}
		$fsPath = $FileShareLocalPath -replace "\\","\\"
		$fs = Get-CimInstance Win32_Share -Filter "path='$fsPath'"
		if(-not(($fs | Where-Object { $_.Name -ieq $FileShareName }).Name)){
			$result = $False	
		}
	}
	if($result -and (($null -ne $FilePaths) -and ($FilePaths -ne ""))){
		$result = $false
		$FilePathArray = $FilePaths -Split ","
		ForEach($path in $FilePathArray){
		   if(Test-FileSharePath -FilePath $path -FileShareLocalPath $FileShareLocalPath -UserName $UserName){
				$result = $True
			} else {
				$result = $False
				break;
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

Function New-FileShareFolder
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$FilePath,
		
		[parameter(Mandatory = $true)]
		[System.String]
		$FileShareLocalPath,

        [parameter(Mandatory = $False)]
		[System.String]
		$UserName
	)
	$FilePath = $FilePath.Trim()
	$SubFilePaths = $FilePath.Split('\', [System.StringSplitOptions]::RemoveEmptyEntries)
	$MappedFilePath = $FileShareLocalPath
	for ($i=2; $i -lt $SubFilePaths.Length; $i++) {
		$MappedFilePath = "$MappedFilePath\$($SubFilePaths[$i])"
	}
	try{
		if(-not(Test-Path $MappedFilePath)){
			New-Item -ItemType directory -Path $MappedFilePath
		}
		if(-not(($MappedFilePath | Get-Acl | Select-Object -ExpandProperty Access | Where-Object identityreference -eq $UserName).FileSystemRights -imatch "FullControl")){
			$acl = Get-Acl $MappedFilePath
			$permission = "$($UserName)","FullControl","ContainerInherit,ObjectInherit","None","Allow"
			$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
			$acl.SetAccessRule($accessRule)
			$acl | Set-Acl $MappedFilePath
		}
	}catch{
		Throw "Unable to create new Folder $($FilePath) - $($_)"
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
		
		[parameter(Mandatory = $true)]
		[System.String]
		$FileShareLocalPath,

        [parameter(Mandatory = $False)]
		[System.String]
		$UserName
	)

	$FilePath = $FilePath.Trim()
	$SubFilePaths = $FilePath.Split('\', [System.StringSplitOptions]::RemoveEmptyEntries)
	$MappedFilePath = $FileShareLocalPath
	for ($i=2; $i -lt $SubFilePaths.Length; $i++) {
		$MappedFilePath = "$MappedFilePath\$($SubFilePaths[$i])"
	}

	if(-not(Test-Path $MappedFilePath) -or -not(($MappedFilePath | Get-Acl | Select-Object -ExpandProperty Access | Where-Object identityreference -eq $UserName).FileSystemRights -imatch "FullControl")){
		$False
	}else{
		$True
	}
}


Export-ModuleMember -Function *-TargetResource
