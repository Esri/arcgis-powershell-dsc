$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

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
    .PARAMETER AdditionalServerRole
        (Optional - Only valid for General Purpose Server) Additional Server Role for which the product is being Licensed
    .PARAMETER IsSingleUse
        Boolean to tell if Pro is using Single Use License.
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

	@{} 
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

        [ValidateSet("Server","Portal","Pro","LicenseManager","Monitor")]
		[System.String]
		$Component,

		[ValidateSet("ImageServer","GeoEvent","GeoAnalytics","GeneralPurposeServer","HostingServer","NotebookServer","MissionServer","WorkflowManagerServer","KnowledgeServer","VideoServer","RealityServer","DataPipelinesServer","GeoEnrichmentServer")]
		[System.String]
        $ServerRole = 'GeneralPurposeServer',

        [parameter(Mandatory = $False)]    
        [System.Array]
        $AdditionalServerRoles,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsSingleUse,
        
        [parameter(Mandatory = $false)]
        [System.Boolean]
		$Force= $False
	)

	if(-not(Test-Path $LicenseFilePath)){
        throw "License file not found at $LicenseFilePath"
    }

    if($Ensure -ieq 'Present') {
        $LicenseVersion = Get-LicenseVersion -Component $Component -ServerRole $ServerRole -Version $Version -Verbose
        Write-Verbose "Licensing from $LicenseFilePath" 
        if(@('Pro', 'LicenseManager') -icontains $Component) {
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

		[ValidateSet("Server","Portal","Pro","LicenseManager","Monitor")]
		[System.String]
		$Component,

		[ValidateSet("ImageServer","GeoEvent","GeoAnalytics","GeneralPurposeServer","HostingServer","NotebookServer","MissionServer","WorkflowManagerServer","KnowledgeServer","VideoServer","RealityServer","DataPipelinesServer","GeoEnrichmentServer")]
		[System.String]
        $ServerRole = 'GeneralPurposeServer',

        [parameter(Mandatory = $False)]    
        [System.Array]
        $AdditionalServerRoles,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsSingleUse,
        
        [parameter(Mandatory = $false)]
        [System.Boolean]
		$Force = $False
	)
    
    $result = $false
    $LicenseVersion = Get-LicenseVersion -Component $Component -ServerRole $ServerRole -Version $Version -Verbose
    
    if($Component -ieq 'Pro') {
        Write-Verbose "TODO:- Check for Pro license. For now forcing Software Authorization Tool to License Pro."
    }
    elseif($Component -ieq 'LicenseManager') {
        Write-Verbose "TODO:- Check for License Manger license. For now forcing Software Authorization Tool to License."
    }
    else {
        if(-not($Force)){
            Write-Verbose "License Check Component:- $Component"
            $result = Test-LicenseForRole -LicenseVersion $LicenseVersion -Component $Component -ServerRole $ServerRole
            if($result){
                if($Component -ieq "Server"){
                    Write-Verbose "$Component is licensed correctly for $ServerRole"
                    foreach($AdditionalRole in $AdditionalServerRoles){
                        $result = Test-LicenseForRole -LicenseVersion $LicenseVersion -Component $Component -ServerRole $AdditionalRole
                        if($result -eq $False){
                            Write-Verbose "$Component is not licensed correctly for server role $AdditionalRole"
                            break
                        }
                    }
                }else{
                    Write-Verbose "$Component is licensed correctly"
                }
            }else{
                Write-Verbose "$Component is not licensed correctly"
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

function Get-LicenseVersion{
    [CmdletBinding()]
    param
    (
        [System.String]
        $Component,

        [System.String]
        $ServerRole,

        [System.String]
		$Version
    )

    [string]$RealVersion = @()
    if(-not($Version) -or [string]::IsNullOrWhiteSpace($Version)){
        try{
            $ErrorActionPreference = "Stop"; #Make all errors terminating
            $ComponentName = Get-ArcGISProductName -Name $Component
            if($Component -ieq "Server"){
                if(@("NotebookServer","MissionServer","VideoServer","DataPipelinesServer","GeoEnrichmentServer") -icontains $ServerRole){
                    $ComponentName = Get-ArcGISProductName -Name $ServerRole
                }
            }

            $RealVersion = (Get-ArcGISProductDetails -ProductName $ComponentName).Version
        }catch{
            throw "Couldn't find the product - $Component"            
        }finally{
            $ErrorActionPreference = "Continue"; #Reset the error action pref to default
        }
    }else{
        $RealVersion = $Version
    }
    Write-Verbose "RealVersion of ArcGIS Software:- $RealVersion" 
    $RealVersionString = "$(([version]$RealVersion).Major).$(([version]$RealVersion).Minor)"
    $LicenseVersion = if($Component -ieq 'Pro' -or $Component -ieq 'LicenseManager'){ '10.6' }else{ $RealVersionString }
    Write-Verbose "Version $LicenseVersion" 
    return $LicenseVersion
}


function Invoke-LicenseSoftware
{
    [CmdletBinding()]
    param
    (
		[System.String]
        $Product, 

        [System.String]
        $ServerRole,
        
        [System.String]
		$LicenseFilePath, 
        
        [System.Management.Automation.PSCredential]
        $LicensePassword, 
        
		[System.String]
		$Version,
        
        [System.Boolean]
        $IsSingleUse
    )

    $SoftwareAuthExePath = "$env:SystemDrive\Program Files\Common Files\ArcGIS\bin\SoftwareAuthorization.exe"
    $LMReloadUtilityPath = ""
    if(@('Pro','LicenseManager') -icontains $Product) {
        $SoftwareAuthExePath = "$env:SystemDrive\Program Files (x86)\Common Files\ArcGIS\bin\SoftwareAuthorization.exe"
        if($IsSingleUse -or ($Product -ne 'LicenseManager')){
            if($Product -ieq 'Pro'){
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
        if($Product -ieq "Server"){
            $ServerTypeName = "ArcGIS Server"
            if($ServerRole -ieq "NotebookServer"){ 
                $ServerTypeName = "ArcGIS Notebook Server" 
            }elseif($ServerRole -ieq "MissionServer"){ 
                $ServerTypeName = "ArcGIS Mission Server"
            }elseif($ServerRole -ieq "VideoServer"){ 
                $ServerTypeName = "ArcGIS Video Server"
            }elseif($ServerRole -ieq "DataPipelinesServer"){ 
                $ServerTypeName = "ArcGIS Data Pipelines Server"
            }elseif($ServerRole -ieq "GeoEnrichmentServer"){ 
                $ServerTypeName = "GeoEnrichmentServer"
            }

            Write-Verbose "Server product name - $ServerTypeName"

            $InstallLocation = (Get-ArcGISProductDetails -ProductName $ServerTypeName).InstallLocation
            if([version]$Version -ge "11.2"){
                $SoftwareAuthExePath = "$($InstallLocation)tools\SoftwareAuthorization\SoftwareAuthorization.exe"
            }else{
                if(($ServerRole -ieq "NotebookServer" -or $ServerRole -ieq "MissionServer" -or $ServerRole -ieq "VideoServer" -or $ServerRole -ieq "DataPipelinesServer")){
                    if($ServerRole -ieq "MissionServer"){
                        $SoftwareAuthExePath = "$($InstallLocation)bin\SoftwareAuthorization.exe"
                    }else{
                        $SoftwareAuthExePath = "$($InstallLocation)framework\bin\SoftwareAuthorization.exe"
                    }
                }
            }
        }
    }
    Write-Verbose "Licensing Product [$Product] using Software Authorization Utility at $SoftwareAuthExePath" -Verbose
    
    $Params = '-s -ver {0} -lif "{1}"' -f $Version,$licenseFilePath
    $RedactedArguments = '-s -ver {0} -lif "{1}"' -f $Version,$licenseFilePath
    if($null -ne $LicensePassword){
        $Params = '-s -ver {0} -lif "{1}" -password {2}' -f $Version,$licenseFilePath,$LicensePassword.GetNetworkCredential().Password
        $RedactedArguments = '-s -ver {0} -lif "{1}" -password {2}' -f $Version,$licenseFilePath,"xxxxx"
    }
    Write-Verbose "[Running Command] $SoftwareAuthExePath $RedactedArguments" -Verbose
    
    [bool]$Done = $false
    [int]$AttemptNumber = 1
    $err = $null
    while(-not($Done) -and ($AttemptNumber -le 10)) {
        if(-not(Test-Path $SoftwareAuthExePath -PathType Leaf)){
            throw "$SoftwareAuthExePath not found"
        }

        try{
            $op = Invoke-StartProcess -ExecPath $SoftwareAuthExePath -Arguments $Params -Verbose
            if($op -and (($op.IndexOf('Error') -gt -1) -or ($op.IndexOf('(null)') -gt -1))) {
                $err = "[ERROR] - Attempt $AttemptNumber - Licensing for Product [$Product] failed. Software Authorization Utility returned $op"
                Write-Verbose $err
                Start-Sleep -Seconds (Get-Random -Maximum 61 -Minimum 30)
            }else{
                $Done = $True
                $err = $null
            }
        }catch{
            throw  "[ERROR] - Attempt $AttemptNumber - Licensing for Product [$Product] failed. Software Authorization Utility error - $_"
        }

        $AttemptNumber += 1
    }
    if($null -ne $err){
        throw $err
    }
    if($Product -ieq 'Pro') {
        Write-Verbose "Sleeping for 2 Minutes to finish Licensing"
        Start-Sleep -Seconds 120
    }
    if($Product -ieq 'LicenseManager'){
		Write-Verbose "Re-readings Licenses"
        if(-not(Test-Path $LMReloadUtilityPath -PathType Leaf)){
            throw "$LMReloadUtilityPath not found"
        }
        try{
            $oplm = Invoke-StartProcess -ExecPath $LMReloadUtilityPath -Arguments 'lmreread -c @localhost' -Verbose
            Write-Verbose "License Manager tool operation successful - $oplm"
        }catch{
            throw "License Manager tool failed to re-read licenses. $_"
        }
	}
    Write-Verbose "Finished Licensing Product [$Product]" -Verbose
}

function Test-LicenseForRole{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [System.String]
        $LicenseVersion,

        [System.String]
        $Component,

        [System.String]
        $ServerRole
    )
    
    $file = "$env:SystemDrive\Program Files\ESRI\License$($LicenseVersion)\sysgen\keycodes"
    if(Test-Path $file){ 
        $result = $true
        $KeyCodesFileContents = Get-Content $file

        $searchtexts = @()
        if($Component -ieq 'Portal') {
            $searchtexts = @('portal_', 'portal1_', 'portal2_')
        }
        elseif($Component -ieq 'Monitor') {
            $searchtexts = @('arcsysmon')
        }
        elseif($Component -ieq 'Server'){
            Write-Verbose "ServerRole:- $ServerRole"
            $searchtexts = @('svr', 'svradv')
            if($ServerRole -ieq 'ImageServer') {
                $searchtexts = @('imgsvr')
            }
            if($ServerRole -ieq 'GeoEvent') {
                $searchtexts = @('geoesvr')
            }
            if($ServerRole -ieq 'WorkflowManagerServer') {
                $searchtexts = @('workflowsvr','workflowsvradv')
            }
            if($ServerRole -ieq 'GeoAnalytics') {
                $searchtexts = @('geoesvr')
            }
            if($ServerRole -ieq 'KnowledgeServer'){ 
                $searchtexts = @('knwldgsvr')
            }
            if($ServerRole -ieq 'NotebookServer') {
                $searchtexts = @('notebooksstdsvr','notebooksadvsvr')
            }
            if($ServerRole -ieq 'MissionServer') {
                $searchtexts = @('missionsvr')
            }
            if($ServerRole -ieq 'VideoServer') {
                $searchtexts = @('videosvr')
            }
            if($ServerRole -ieq 'RealityServer') {
                $searchtexts = @('realitysvr')
            }
            if($ServerRole -ieq 'DataPipelinesServer') {
                $searchtexts = @('datapipelinesvr')
            }
            if($ServerRole -ieq 'GeoEnrichmentServer') {
                $searchtexts = @('businesssvr') # TODO - Check for "svradv"
            }
        }
        
        # All of the search texts should exist in the keygen
        $TextFound = $False
        foreach($KeyCodeLine in $KeyCodesFileContents){
            if($null -ne ($searchtexts | Where-Object { $KeyCodeLine -ilike "$($_),*" })){
                Write-Verbose "License search keywords found."
                $TextFound = $True
                break
            }
        }
        if($TextFound -ieq $False){
            Write-Verbose "License search keywords not found."
            $result = $False
        }
        $result
    }else{
        $False
    }
}

Export-ModuleMember -Function *-TargetResource
