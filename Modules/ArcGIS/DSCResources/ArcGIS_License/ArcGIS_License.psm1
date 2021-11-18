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

		[ValidateSet("ImageServer","GeoEvent","GeoAnalytics","GeneralPurposeServer","HostingServer","NotebookServer","MissionServer","WorkflowManagerServer")]
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
                $ComponentName = if($Component -ieq "LicenseManager"){ "License Manager" }elseif($Component -ieq "Server"){ if($ServerRole -ieq 'NotebookServer'){ "ArcGIS Notebook Server" }elseif($ServerRole -ieq 'MissionServer'){ "ArcGIS Mission Server" }else{ "ArcGIS Server" } } else{ $Component }
                $RealVersion = (Get-ArcGISProductDetails -ProductName $ComponentName).Version
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
            Invoke-LicenseSoftware -Product $Component -LicenseFilePath $LicenseFilePath `
                        -Version $LicenseVersion -LicensePassword $LicensePassword -IsSingleUse $IsSingleUse -Verbose
        } else {
            Write-Verbose "Version $LicenseVersion Component $Component Role $ServerRole" 
            Invoke-LicenseSoftware -Product $Component -ServerRole $ServerRole -LicenseFilePath $LicenseFilePath `
                        -Version $LicenseVersion -LicensePassword $LicensePassword -IsSingleUse $IsSingleUse -Verbose
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

		[ValidateSet("ImageServer","GeoEvent","GeoAnalytics","GeneralPurposeServer","HostingServer","NotebookServer","MissionServer","WorkflowManagerServer")]
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
            $ComponentName = if($Component -ieq "LicenseManager"){ "License Manager" }elseif($Component -ieq "Server"){ if($ServerRole -ieq 'NotebookServer'){ "ArcGIS Notebook Server" }elseif($ServerRole -ieq 'MissionServer'){ "ArcGIS Mission Server" }else{ "ArcGIS Server" } } else{ $Component }
            $RealVersion = (Get-ArcGISProductDetails -ProductName $ComponentName).Version
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
            elseif($ServerRole -ieq 'WorkflowManagerServer') {
                $searchtexts += 'workflowsvr_4'
                $searchtext = 'workflowsvr'
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

function Invoke-LicenseSoftware
{
    [CmdletBinding()]
    param
    (
		[string]
        $Product, 

        [string]
        $ServerRole, 
        
        [string]
		$LicenseFilePath, 
        
        [System.Management.Automation.PSCredential]
        $LicensePassword, 
        
		[string]
		$Version,
        
        [System.Boolean]
        $IsSingleUse
    )

    $SoftwareAuthExePath = "$env:SystemDrive\Program Files\Common Files\ArcGIS\bin\SoftwareAuthorization.exe"
    $LMReloadUtilityPath = ""
    if(@('Desktop','Pro','LicenseManager') -icontains $Product) {
        $SoftwareAuthExePath = "$env:SystemDrive\Program Files (x86)\Common Files\ArcGIS\bin\SoftwareAuthorization.exe"
        if($IsSingleUse -or ($Product -ne 'LicenseManager')){
            if($Product -ieq 'Desktop'){
                $SoftwareAuthExePath = "$env:SystemDrive\Program Files (x86)\Common Files\ArcGIS\bin\softwareauthorization.exe"
            }elseif($Product -ieq 'Pro'){
                $InstallLocation = (Get-ArcGISProductDetails -ProductName "ArcGIS Pro" | Where-Object {$_.Name -ieq "ArcGIS Pro"}).InstallLocation
                $SoftwareAuthExePath = "$($InstallLocation)bin\SoftwareAuthorizationPro.exe"
            }
        }else{
            $LMInstallLocation = (Get-ArcGISProductDetails -ProductName "License Manager").InstallLocation
            if($LMInstallLocation){
                $SoftwareAuthExePath = "$($LMInstallLocation)bin\SoftwareAuthorizationLS.exe"
                $LMReloadUtilityPath = "$($LMInstallLocation)bin\lmutil.exe"
            }
        }
    }else{
        if($Product -ieq "Server" -and ($ServerRole -ieq "NotebookServer" -or $ServerRole -ieq "MissionServer" ) -and ($Version.Split('.')[1] -ge 8)){
            $ServerTypeName = "ArcGIS Server"
            if($ServerRole -ieq "NotebookServer"){ 
                $ServerTypeName = "ArcGIS Notebook Server" 
            }elseif($ServerRole -ieq "MissionServer"){ 
                $ServerTypeName = "ArcGIS Mission Server"
            }
            $InstallLocation = (Get-ArcGISProductDetails -ProductName $ServerTypeName).InstallLocation
            if($ServerRole -ieq "MissionServer"){
                $SoftwareAuthExePath = "$($InstallLocation)bin\SoftwareAuthorization.exe"
            }else{
                $SoftwareAuthExePath = "$($InstallLocation)framework\bin\SoftwareAuthorization.exe"
            }
        }
    }
    Write-Verbose "Licensing Product [$Product] using Software Authorization Utility at $SoftwareAuthExePath" -Verbose
    
    $Params = '-s -ver {0} -lif "{1}"' -f $Version,$licenseFilePath
    if($null -ne $LicensePassword){
        $Params = '-s -ver {0} -lif "{1}" -password {2}' -f $Version,$licenseFilePath,$LicensePassword.GetNetworkCredential().Password
    }
    Write-Verbose "[Running Command] $SoftwareAuthExePath $Params" -Verbose
    
    [bool]$Done = $false
    [int]$AttemptNumber = 1
    $err = $null
    while(-not($Done) -and ($AttemptNumber -le 10)) {
        if(-not(Test-Path $SoftwareAuthExePath -PathType Leaf)){
            throw "$SoftwareAuthExePath not found"
        }
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $SoftwareAuthExePath
        $psi.Arguments = $Params
        $psi.UseShellExecute = $false #start the process from it's own executable file    
        $psi.RedirectStandardOutput = $true #enable the process to read from standard output
        $psi.RedirectStandardError = $true #enable the process to read from standard error
    
        $p = [System.Diagnostics.Process]::Start($psi)
        $p.WaitForExit()
        $result = $null
        $op = $p.StandardOutput.ReadToEnd()
        if($p.ExitCode -eq 0) {
            if($op -and (($op.IndexOf('Error') -gt -1) -or ($op.IndexOf('(null)') -gt -1))) {
                $err = "[ERROR] - Attempt $AttemptNumber - Licensing for Product [$Product] failed. Software Authorization Utility returned $op"
                Write-Verbose $err
                Start-Sleep -Seconds (Get-Random -Maximum 61 -Minimum 30)
            }else{
                $Done = $True
                $err = $null
            }
        }else{
            $err = $p.StandardError.ReadToEnd()
            Write-Verbose $err
            if($err -and $err.Length -gt 0) {
                throw  "[ERROR] - Attempt $AttemptNumber - Licensing for Product [$Product] failed. Software Authorization Utility returned Output - $op. Error - $err"
            }
        }
        $AttemptNumber += 1
    }
    if($null -ne $err){
        throw $err
    }
    if($Product -ieq 'Desktop' -or $Product -ieq 'Pro') {
        Write-Verbose "Sleeping for 2 Minutes to finish Licensing"
        Start-Sleep -Seconds 120
    }
    if($Product -ieq 'LicenseManager'){
		Write-Verbose "Re-readings Licenses"
        if(-not(Test-Path $LMReloadUtilityPath -PathType Leaf)){
            throw "$LMReloadUtilityPath not found"
        }
        $psilm = New-Object System.Diagnostics.ProcessStartInfo
        $psilm.FileName = $LMReloadUtilityPath
        $psilm.Arguments = 'lmreread -c @localhost'
        $psilm.UseShellExecute = $false #start the process from it's own executable file    
        $psilm.RedirectStandardOutput = $true #enable the process to read from standard output
        $psilm.RedirectStandardError = $true #enable the process to read from standard error
        
        $plm = [System.Diagnostics.Process]::Start($psilm)
        $plm.WaitForExit()
        $oplm = $p.StandardOutput.ReadToEnd()
        if($p.ExitCode -eq 0) {
            Write-Verbose "License Manager tool operation successful - $oplm"
        }else{
            $errlm = $plm.StandardError.ReadToEnd()
            Write-Verbose $errlm
            if($errlm -and $errlm.Length -gt 0) {
                throw "License Manager tool failed to re-read licenses. Output - $oplm. Error - $errlm"
            }
        }
	}
    Write-Verbose "Finished Licensing Product [$Product]" -Verbose
}

Export-ModuleMember -Function *-TargetResource