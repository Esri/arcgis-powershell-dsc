$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

<#
    .SYNOPSIS
        Installs a given msi
    .PARAMETER Ensure
        Indicates if the Component is to be installed or uninstalled if not present. Take the values Present or Absent. 
        - "Present" ensures that component is installed, if not already installed. 
        - "Absent" ensures that component is uninstalled or removed, if installed.
    .PARAMETER Name
        Name of MSI Component to be installed.
    .PARAMETER Path
        Path to Installer for the MSI Component - Can be a Physical Location or Network Share Address.
    .PARAMETER ProductId
        ProductId (GUID) of the Component being Installed.
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

		[parameter(Mandatory = $false)]
		[System.String]
		$Path,

		[parameter(Mandatory = $true)]
		[System.String]
		$ProductId
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
		[System.String]
		$Path,

		[parameter(Mandatory = $true)]
		[System.String]
		$ProductId,

		[parameter(Mandatory = $false)]
		[System.String]
		$Arguments,

		[System.String]
		$LogPath,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)
	
	Write-Verbose "In Set-Resource for $Name"
	
    if($Ensure -eq 'Present') {
        if(-not(Test-Path $Path)){
            throw "$Path is not found or inaccessible"
        }
		
		try{
			Write-Verbose "Installing Software using installer at $Path and arguments $Arguments"  
        	Write-Verbose "Installing MSI Package $Name"
			Write-Verbose "msiexec /i $Path $Arguments"
			Start-Process 'msiexec' -ArgumentList "/i ""$Path"" $Arguments" -Wait
			Start-Sleep -Seconds 30 #Allow files to be copied to Program Files
			Write-Verbose "Validating the $Name Installation"
			$result = $False
			$Attempt = 1
			while(!$result -and $Attempt -lt 4){
				Write-Verbose "Testing MSI Package - Attempt $Attempt"
				$result = Test-Install -Name $Name -ProductId $ProductId  
				Start-Sleep -Seconds 20 #Allow files to be copied to Program Files
				$Attempt++
			}
			
			if(-not($result)){
				throw "Failed to Install $Name"
			}else{
				Write-Verbose "$Name installation was successful!"
			}
		}catch{
			Write-Verbose "[Error] $_ "
			throw "[Error] $_ "
		}

    }
    elseif($Ensure -eq 'Absent') {
        $ProdId = $ProductId   
        [System.Guid]$tempVar = [System.Guid]::Empty
        if([System.Guid]::TryParse($ProdId, [ref]$tempVar)) 
        {
            if(-not($ProdId.StartsWith('{'))){
                $ProdId = '{' + $ProdId
            }
            if(-not($ProdId.EndsWith('}'))){
                $ProdId = $ProdId + '}'
            }        
            Write-Verbose "msiexec /x ""$ProdId"" /quiet"
            Start-Process 'msiexec' -ArgumentList "/x ""$ProdId"" /quiet"
        }else {
            throw "Unable to install product $ProdId which is not specified as a GUID"
        }
    }
}


function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[System.String]
		$Name,

		[parameter(Mandatory = $false)]
		[System.String]
		$Path,

		[parameter(Mandatory = $true)]
		[System.String]
		$ProductId,

		[parameter(Mandatory = $false)]
		[System.String]
		$Arguments,

		[System.String]
		$LogPath,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)
	
	$result = $false
	
	$result = Test-Install -Name $Name -ProductId $ProductId  

    if($Ensure -ieq 'Present') {
	       $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}

Export-ModuleMember -Function *-TargetResource

