<#
    .SYNOPSIS
        Licenses the product (Server or Portal) depending on the params specified.
    .PARAMETER Ensure
        Take the values Present or Absent. 
        - "Present" ensures that Component in Licensed, if not.
        - "Absent" ensures that Component in Unlicensed (Not Implemented).
    .PARAMETER LicenseFilePath
        Path to License File 
    .PARAMETER LicensePassword
        Optional Password for the corresponding License File 
    .PARAMETER Version
        Optional Version for the corresponding License File 
    .PARAMETER Component
        Product being Licensed (Server or Portal)
    .PARAMETER ServerRole
        (Optional - Required only for Server) Server Role for which the product is being Licensed
    .PARAMETER IsSingleUse
        Boolean to tell if Pro or Desktop is using Single Use License.
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
		[System.Management.Automation.PSCredential]
        $LicensePassword,

        [parameter(Mandatory = $false)]
		[System.String]
		$Version,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [ValidateSet("Server","Portal","Desktop","Pro","LicenseManager")]
		[System.String]
		$Component,

		[ValidateSet("ImageServer","GeoEvent","GeoAnalytics","GeneralPurposeServer","HostingServer","NotebookServer","MissionServer")]
		[System.String]
        $ServerRole = 'GeneralPurposeServer',

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsSingleUse,
        
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
        if(-not($Version)){
            try{
                $ErrorActionPreference = "Stop"; #Make all errors terminating
                <#$RegistryPath = 'HKLM:\SOFTWARE\ESRI\ArcGIS'
                if($Component -ieq 'Desktop' -or $Component -ieq 'Pro') {
                    $RegistryPath = 'HKLM:\SOFTWARE\WoW6432Node\esri\ArcGIS'
                } 
                $RealVersion = (Get-ItemProperty -Path $RegistryPath).RealVersion#>
                $ComponentName = if($Component -ieq "LicenseManager"){ "License Manager" }elseif($Component -ieq "Server"){ if($ServerRole -ieq 'NotebookServer'){ "Notebook Server" }elseif($ServerRole -ieq 'MissionServer'){ "Mission Server" }else{ "ArcGIS Server" } } else{ $Component }
                $RealVersion = (Get-CimInstance Win32_Product| Where-Object {$_.Name -match $ComponentName -and $_.Vendor -eq 'Environmental Systems Research Institute, Inc.'}).Version
            }catch{
                throw "Couldn't Find The Product - $Component"            
            }finally{
                $ErrorActionPreference = "Continue"; #Reset the error action pref to default
            }
        }else{
            $RealVersion = $Version
        }
        Write-Verbose "RealVersion of ArcGIS Software:- $RealVersion" 
        $RealVersion = $RealVersion.Split('.')[0] + '.' + $RealVersion.Split('.')[1] 

        $LicenseVersion = if($Component -ieq 'Pro' -or $Component -ieq 'LicenseManager'){ '10.6' }else{ $RealVersion }
        Write-Verbose "Licensing from $LicenseFilePath" 
        if(@('Desktop', 'Pro', 'LicenseManager') -icontains $Component) {
            Write-Verbose "Version $LicenseVersion Component $Component" 
            Invoke-LicenseSoftware -Product $Component -LicenseFilePath $LicenseFilePath -Version $LicenseVersion -LicensePassword $LicensePassword -IsSingleUse $IsSingleUse
        }
        else {
            Write-Verbose "Version $LicenseVersion Component $Component Role $ServerRole" 
            $StdOutputLogFilePath = Join-Path $env:TEMP "$(Get-Date -format "dd-MM-yy-HH-mm")-stdlog.txt"
            $StdErrLogFilePath = Join-Path $env:TEMP "$(Get-Date -format "dd-MM-yy-HH-mm")-stderr.txt"
            Write-Verbose "StdOutputLogFilePath:- $StdOutputLogFilePath" 
            Write-Verbose "StdErrLogFilePath:- $StdErrLogFilePath" 
            Invoke-LicenseSoftware -Product $Component -ServerRole $ServerRole -LicenseFilePath $LicenseFilePath `
                         -Version $LicenseVersion -LicensePassword $LicensePassword -IsSingleUse $IsSingleUse `
                         -StdOutputLogFilePath $StdOutputLogFilePath -StdErrLogFilePath $StdErrLogFilePath
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
		[System.Management.Automation.PSCredential]
		$LicensePassword,

        [parameter(Mandatory = $false)]
		[System.String]
		$Version,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

		[ValidateSet("Server","Portal","Desktop","Pro","LicenseManager")]
		[System.String]
		$Component,

		[ValidateSet("ImageServer","GeoEvent","GeoAnalytics","GeneralPurposeServer","HostingServer","NotebookServer","MissionServer")]
		[System.String]
        $ServerRole = 'GeneralPurposeServer',

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsSingleUse,
        
        [parameter(Mandatory = $false)]
        [System.Boolean]
		$Force = $False
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    [string]$RealVersion = @()
    $result = $false
    if(-not($Version)){
        try{
            $ErrorActionPreference = "Stop"; #Make all errors terminating
            <#$RegistryPath = 'HKLM:\SOFTWARE\ESRI\ArcGIS'
            if($Component -ieq 'Desktop' -or $Component -ieq 'Pro') {
                $RegistryPath = 'HKLM:\SOFTWARE\WoW6432Node\esri\ArcGIS'
            } 
            $RealVersion = (Get-ItemProperty -Path $RegistryPath).RealVersion#>
            $ComponentName = if($Component -ieq "LicenseManager"){ "License Manager" }elseif($Component -ieq "Server"){ if($ServerRole -ieq 'NotebookServer'){ "Notebook Server" }elseif($ServerRole -ieq 'MissionServer'){ "Mission Server" }else{ "ArcGIS Server" } } else{ $Component }
            $RealVersion = (Get-CimInstance Win32_Product| Where-Object {$_.Name -match $ComponentName -and $_.Vendor -eq 'Environmental Systems Research Institute, Inc.'}).Version
        }catch{
            throw "Couldn't Find The Product - $Component"        
        }finally{
            $ErrorActionPreference = "Continue"; #Reset the error action pref to default
        }
    }else{
        $RealVersion = $Version
    }

    Write-Verbose "RealVersion of ArcGIS Software to be Licensed:- $RealVersion" 
    $RealVersion = $RealVersion.Split('.')[0] + '.' + $RealVersion.Split('.')[1] 
    $LicenseVersion = if($Component -ieq 'Pro'){ '10.6' }else{ $RealVersion }

    Write-Verbose "Version $LicenseVersion" 
    if($Component -ieq 'Desktop') {
        Write-Verbose "TODO:- Check for Desktop license. For now forcing Software Authorization Tool to License Pro."
    }
    elseif($Component -ieq 'Pro') {
        Write-Verbose "TODO:- Check for Pro license. For now forcing Software Authorization Tool to License Pro."
    }
    elseif($Component -ieq 'LicenseManager') {
        Write-Verbose "TODO:- Check for License Manger license. For now forcing Software Authorization Tool to License."
    }
    else {
        Write-Verbose "License Check Component:- $Component ServerRole:- $ServerRole"
        $file = "$env:SystemDrive\Program Files\ESRI\License$($LicenseVersion)\sysgen\keycodes"
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
            elseif($ServerRole -ieq 'NotebookServer') {
                $searchtexts += 'notebooksstdsvr'
			    $searchtext = 'notebooksadvsvr'
            }
            elseif($ServerRole -ieq 'MissionServer') {
                $searchtexts += 'missionsvr_4'
                $searchtext = 'missionsvr'
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

