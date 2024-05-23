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
    .PARAMETER Path
        Path to Installer for the Component - Can be a Physical Location or Network Share Address.
    .PARAMETER Version
        Version of the Component being Installed.
    .PARAMETER Arguments
        Additional Command Line Arguments required by the installer to complete intallation of the give component successfully.
    .PARAMETER WebAdaptorContext
        Context with which the Web Adaptor Needs to be Installed.
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
		$ProductId,

		[parameter(Mandatory = $false)]
		[System.String]
		$Path,
        
        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $Extract = $True,

		[parameter(Mandatory = $true)]
		[System.String]
		$Version,

		[parameter(Mandatory = $false)]
		[System.String]
		$Arguments,

        [parameter(Mandatory = $false)]
		[System.Array]
		$FeatureSet,

        [parameter(Mandatory = $false)]
		[System.String]
        $WebAdaptorContext,

        [parameter(Mandatory = $false)]
		[System.String]
        $WebAdaptorDotnetHostingBundlePath,

        [parameter(Mandatory = $false)]
		[System.String]
        $WebAdaptorWebDeployPath,

        [parameter(Mandatory = $false)]
		[System.String]
        $ProDotnetDesktopRuntimePath,

        [parameter(Mandatory = $false)]
		[System.String]
        $ProEdgeWebView2RuntimePath,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $ServiceCredential,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsMSA = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $EnableMSILogging = $false,

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
		[System.String]
        $Path,

        [parameter(Mandatory = $false)]
		[System.String[]]
        $VolumePaths,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $Extract = $True,

        [parameter(Mandatory = $false)]
		[System.String]
		$ProductId,

		[parameter(Mandatory = $true)]
		[System.String]
		$Version,

		[parameter(Mandatory = $false)]
		[System.String]
		$Arguments,

        [parameter(Mandatory = $false)]
		[System.Array]
		$FeatureSet,

        [parameter(Mandatory = $false)]
		[System.String]
        $WebAdaptorContext,

        [parameter(Mandatory = $false)]
		[System.String]
        $WebAdaptorDotnetHostingBundlePath,

        [parameter(Mandatory = $false)]
		[System.String]
        $WebAdaptorWebDeployPath,

        [parameter(Mandatory = $false)]
		[System.String]
        $ProDotnetDesktopRuntimePath,

        [parameter(Mandatory = $false)]
		[System.String]
        $ProEdgeWebView2RuntimePath,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $ServiceCredential,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsMSA = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $EnableMSILogging = $false,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)
    
    $ComponentName = $Name
    $IsWebAdaptorIIS = $False
    if($Name.StartsWith('WebAdaptorIIS')){
        $ComponentName = "WebAdaptorIIS"
        $IsWebAdaptorIIS = $true
    }

    if($Ensure -eq 'Present') {
        if(-not(Test-Path $Path)){
            throw "$Path is not found or inaccessible"
        }

        if($IsWebAdaptorIIS){
            Invoke-WebAdaptorIISPreRequsitesInstallation -Verbose

            # Install Web Deploy - msi package
            if($WebAdaptorWebDeployPath -and (Test-Path $WebAdaptorWebDeployPath)){
                Invoke-StartProcess -ExecPath "msiexec" -Arguments "/i `"$WebAdaptorWebDeployPath`" ADDLOCAL=ALL /qn /norestart LicenseAccepted=`"0`"" -Verbose
            }                

            # Install DotNet Hosting bundle - exe package
            if($WebAdaptorDotnetHostingBundlePath -and (Test-Path $WebAdaptorDotnetHostingBundlePath)){
                Invoke-StartProcess -ExecPath $WebAdaptorDotnetHostingBundlePath -Arguments "/install /quiet /norestart" -Verbose
            }
        }

        if($Name -ieq 'Pro' -and $ProDotnetDesktopRuntimePath -and (Test-Path $ProDotnetDesktopRuntimePath)){
            # Install DotNet Desktop Runtime - exe package
            Invoke-StartProcess -ExecPath $ProDotnetDesktopRuntimePath -Arguments "/install /quiet /norestart" -Verbose
        }

        if($Name -ieq 'Pro' -and $ProEdgeWebView2RuntimePath -and (Test-Path $ProEdgeWebView2RuntimePath)){
            # Check if Edge WebView 2 Runtime is already installed
            $EdgeWebView2RuntimeInstalled = "HKEY_CURRENT_USER\Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
            $EdgeWebView2Runtime64Installed = "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
            $EdgeWebView2Runtime32Installed = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
            if(-not(Test-Path $EdgeWebView2RuntimeInstalled) -and -not(Test-Path $EdgeWebView2Runtime64Installed) -and -not(Test-Path $EdgeWebView2Runtime32Installed)){
                # Install Edge Web View 2 Runtime - exe package
                Invoke-StartProcess -ExecPath $ProEdgeWebView2RuntimePath -Arguments "/silent /install" -Verbose
            }else{
                Write-Verbose "Edge WebView 2 Runtime is already installed"
            }
        }

        $ExecPath = $null
        if($Extract)
        {
            Write-Verbose 'Self Extracting Installer'

            $ProdIdObject = if(-not($ProductId)){ Get-ComponentCode -ComponentName $ComponentName -Version $Version }else{ $ProductId }
            $ProdId = $ProductId
            if(-not($ProductId)){
                if($IsWebAdaptorIIS){
                    $ProdId =  $ProdIdObject[0] 
                }else{
                    $ProdId = $ProdIdObject
                }
            }

            $TempFolder = Join-Path ([System.IO.Path]::GetTempPath()) $ProdId
            if(Test-Path $TempFolder)
            {
                Remove-Item -Path $TempFolder -Recurse 
            }
            if(-not(Test-Path $TempFolder))
            {
                New-Item $TempFolder -ItemType directory            
            }  

            Write-Verbose "Extracting $Path to $TempFolder"
            $ArgumentsList = "/s /d $TempFolder"
            $VersionSplit = $Version.Split('.')
            if($VersionSplit[0] -eq 11 -and $VersionSplit[1] -gt 2){
                $ArgumentsList = "/s /d $TempFolder /x"
            }
            $SetupExtractProc = (Start-Process -FilePath $Path -ArgumentList $ArgumentsList -Wait -NoNewWindow  -Verbose -PassThru)

            if($SetupExtractProc.ExitCode -ne 0){
                if($VersionSplit[0] -eq 11 -and $VersionSplit[1] -gt 2 -and ($ComponentName -ieq "Server" -or $ComponentName -ieq "Portal")){
                    #TODO - generalize this at a later point
                    if(-not(Test-Path "$($Path).001")){
                        throw "Associated Volume of the setup is not found at $Path. Please make sure all the volumes are present in the same location"
                    }
                }
                throw "Error while extracting setup for '$ComponentName' at Path '$Path' :- exited with status code $($SetupExtractProc.ExitCode)"
            }else{
                Write-Verbose 'Done Extracting. Waiting 15 seconds to allow the extractor to close files'
            }
            Start-Sleep -Seconds 15

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
                        throw "Neither .exe nor .msi found in extracted contents to install"
                   }               
               }               
            }   
        }else{
            Write-Verbose "Installing Software using installer at $Path"
            $ExecPath = $Path
        }

        if($ExecPath -iMatch ".msi"){
            $Arguments = "/i `"$ExecPath`" $Arguments"
            $ExecPath = "msiexec"
        }

        if(($null -ne $ServiceCredential) -and (@("Server","Portal","WebStyles","DataStore","GeoEvent","NotebookServer","MissionServer","VideoServer","WorkflowManagerServer","WorkflowManagerWebApp","NotebookServerSamplesData", "Insights") -icontains $ComponentName)){
            if(-not(@("WorkflowManagerServer","WorkflowManagerWebApp","GeoEvent","Insights") -icontains $ComponentName)){
                $Arguments += " USER_NAME=$($ServiceCredential.UserName)"
            }
            
            if($ServiceCredentialIsMSA){
                $Arguments += " MSA=TRUE";
            }else{
                $Arguments += " PASSWORD=`"$($ServiceCredential.GetNetworkCredential().Password)`"";
            }
        }

        if($FeatureSet.Count -gt 0){
            if(Test-ProductInstall -Name $Name -ProductId $ProductId -Version $Version -WebAdaptorContext $WebAdaptorContext){
                if($Name -ieq "DataStore"){
                    if(@("11.0","11.1","11.2","11.3") -iContains $Version){
                        $AddLocalFeatureSet, $RemoveFeatureSet = Test-DataStoreFeautureSet -FeatureSet $FeatureSet -DSInstalled $True
                        if($AddLocalFeatureSet.Count -gt 0){
                            $AddFeatureSetString = [System.String]::Join(",", $AddLocalFeatureSet)
                            $Arguments += " ADDLOCAL=$($AddFeatureSetString)"
                        }
                        if($RemoveFeatureSet.Count -gt 0){
                            $RemoveFeatureSetString = [System.String]::Join(",", $RemoveFeatureSet)
                            $Arguments += " REMOVE=$($RemoveFeatureSetString)"
                        }
                    }
                }else{
                    $AddFeatureSetString = [System.String]::Join(",", $FeatureSet)
                    $Arguments += " ADDLOCAL=$($AddFeatureSetString)"
                }
            }else{
                if($Name -ieq "DataStore"){
                    if(@("11.0","11.1","11.2","11.3") -iContains $Version){
                        $AddLocalFeatureSet, $RemoveFeatureSet = Test-DataStoreFeautureSet -FeatureSet $FeatureSet -DSInstalled $False
                        $AddFeatureSetString = [System.String]::Join(",", $AddLocalFeatureSet)
                        $Arguments += " ADDLOCAL=$($AddFeatureSetString)"
                    }
                }else{
                    $AddFeatureSetString = [System.String]::Join(",", $FeatureSet)
                    $Arguments += " ADDLOCAL=$($AddFeatureSetString)"
                }
            }
        }

        if($EnableMSILogging){
            $MSILogFileName = if($WebAdaptorContext){ "$($Name)_$($WebAdaptorContext)_install.log" }else{ "$($Name)_install.log" }
            $MSILogPath = (Join-Path $env:TEMP $MSILogFileName.replace(' ',''))
            Write-Verbose "Logs for $Name will be written to $MSILogPath" 
            $Arguments += " /L*v $MSILogPath";
        }
            
        #Install arcgis setup
        Invoke-StartProcess -ExecPath $ExecPath -Arguments $Arguments -Verbose

        Write-Verbose "Validating the $Name Installation"
        $result = Test-ProductInstall -Name $Name -ProductId $ProductId -Version $Version -WebAdaptorContext $WebAdaptorContext

        if(-not($result)){
			throw "Failed to Install $Name"
		}else{
			Write-Verbose "$Name installation was successful!"
		}

        if(($Name -ieq "Portal") -or ($Name -ieq "Portal for ArcGIS")){
            Write-Verbose "Waiting just in case for Portal to finish unpacking any additional dependecies - 120 Seconds"
            Start-Sleep -Seconds 120
        }
        
        if($IsWebAdaptorIIS){
            Write-Verbose "Giving Permissions to Folders for IIS_IUSRS"
            foreach($p in (Get-ChildItem "$($env:SystemDrive)\Windows\Microsoft.NET\Framework*\v*\Temporary ASP.NET Files").FullName){
                icacls $p /grant 'IIS_IUSRS:(OI)(CI)F' /T
            }
            icacls "$($env:SystemDrive)\Windows\TEMP\" /grant 'IIS_IUSRS:(OI)(CI)F' /T

            Import-Module WebAdministration | Out-Null
            Write-Verbose "Increasing Web Request Timeout to 1 hour"
            $WebSiteId = 1
            $Arguments.Split(' ') | Foreach-Object {
                $key,$value = $_.Split('=')
                if($key -ieq "WEBSITE_ID"){
                    $WebSiteId = $value
                }
            }
            $IISWebSiteName = (Get-Website | Where-Object {$_.ID -eq $WebSiteId}).Name
            Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$($IISWebSiteName)/$($WebAdaptorContext)"  -filter "system.web/httpRuntime" -name "executionTimeout" -value "01:00:00"
        }
    }
    elseif($Ensure -eq 'Absent') {
        $ProdIdObject = if(-not($ProductId)){ Get-ComponentCode -ComponentName $ComponentName -Version $Version }else{ $ProductId }
        if($IsWebAdaptorIIS){
            $WAInstalls = (Get-ArcGISProductDetails -ProductName 'ArcGIS Web Adaptor')
            $prodIdSetFlag = $False
            foreach($wa in $WAInstalls){
				$WAProdId = $wa.IdentifyingNumber.TrimStart("{").TrimEnd("}")
				if($wa.InstallLocation -match "\\$($WebAdaptorContext)\\" -and ($ProdIdObject -icontains $WAProdId)){
                    $ProdIdObject = $WAProdId 
                    $prodIdSetFlag = $True
					break
                }
            }
            if(-not($prodIdSetFlag)){
                throw "Given product Id doesn't match the product id for the version specified for Component $Name"
            }
        }
        
        if(-not($ProdIdObject.StartsWith('{'))){
            $ProdIdObject = '{' + $ProdIdObject
        }
        if(-not($ProdIdObject.EndsWith('}'))){
            $ProdIdObject = $ProdIdObject + '}'
        }
        Write-Verbose "msiexec /x ""$ProdIdObject"" /quiet"
        $UninstallProc = (Start-Process -FilePath msiexec.exe -ArgumentList "/x ""$ProdIdObject"" /quiet" -Wait -Verbose -PassThru)
        if($UninstallProc.ExitCode -ne 0){
            throw "Error while uninstalling '$ComponentName' :- exited with status code $($UninstallProc.ExitCode)"
        }else{
            Write-Verbose "Uninstallation successful."
        }

        if($IsWebAdaptorIIS){
            Import-Module WebAdministration | Out-Null
            $WebSiteId = 1
            $Arguments.Split(' ') | Foreach-Object {
                $key,$value = $_.Split('=')
                if($key -ieq "WEBSITE_ID"){
                    $WebSiteId = $value
                }
            }
            $IISWebSiteName = (Get-Website | Where-Object {$_.ID -eq $WebSiteId}).Name
            Remove-WebConfigurationLocation -Name "$($IISWebSiteName)/$($WebAdaptorContext)"
        }

        if($ComponentName -ieq "Server"){
            $ServerComponenetsInstalled = Get-ArcGISProductDetails -ProductName "ArcGIS Server"
            foreach($ServerComponent in $ServerComponenetsInstalled){
                Write-Verbose "Uninstalling '$($ServerComponent.Name)' with Product Id '$($ServerComponent.IdentifyingNumber)' "
                Write-Verbose "msiexec /x ""$($ServerComponent.IdentifyingNumber)"" /quiet"
                $UninstallServerCompProc = (Start-Process -FilePath msiexec.exe -ArgumentList "/x ""$($ServerComponent.IdentifyingNumber)"" /quiet" -Wait -Verbose -PassThru)
                if($UninstallServerCompProc.ExitCode -ne 0){
                    throw "Error while uninstalling Server Component '$($ServerComponent.Name)' :- exited with status code $($UninstallServerCompProc.ExitCode)"
                }else{
                    Write-Verbose "Uninstallation successful."
                }
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
		$Name,

		[parameter(Mandatory = $false)]
		[System.String]
        $Path,
        
        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $Extract = $True,
        
        [parameter(Mandatory = $false)]
		[System.String]
		$ProductId,
		
		[parameter(Mandatory = $true)]
		[System.String]
		$Version,

		[parameter(Mandatory = $false)]
		[System.String]
		$Arguments,

        [parameter(Mandatory = $false)]
		[System.Array]
		$FeatureSet,

        [parameter(Mandatory = $false)]
		[System.String]
        $WebAdaptorContext,

        [parameter(Mandatory = $false)]
		[System.String]
        $WebAdaptorDotnetHostingBundlePath,

        [parameter(Mandatory = $false)]
		[System.String]
        $WebAdaptorWebDeployPath,

        [parameter(Mandatory = $false)]
		[System.String]
        $ProDotnetDesktopRuntimePath,

        [parameter(Mandatory = $false)]
		[System.String]
        $ProEdgeWebView2RuntimePath,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $ServiceCredential,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsMSA = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $EnableMSILogging = $false,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)

	$result = Test-ProductInstall -Name $Name -ProductId $ProductId -Version $Version -WebAdaptorContext $WebAdaptorContext
    if($result -and $FeatureSet.Count -gt 0){
        if($Name -ieq "DataStore"){
            if(@("11.0","11.1","11.2","11.3") -iContains $Version){
                $AddLocalFeatureSet, $RemoveFeatureSet = Test-DataStoreFeautureSet -FeatureSet $FeatureSet -DSInstalled $True
                $result = ($AddLocalFeatureSet.Count -eq 0 -and $RemoveFeatureSet.Count -eq 0)
            }
        }elseif($Name -ieq "Server"){
            if($Version -ieq "10.9.1"){
                # Get all the feature that are installed.
                # Create an add and remove feature list
            }elseif(@("11.0","11.1","11.2","11.3") -iContains $Version){
                #Get all the feature that are installed.
                #Create an add and remove feature list
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

function Test-ProductInstall
{
    [CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [parameter(Mandatory = $true)]
		[System.String]
		$Name,

        [parameter(Mandatory = $false)]
		[System.String]
		$ProductId,
		
		[parameter(Mandatory = $true)]
		[System.String]
		$Version,

        [parameter(Mandatory = $false)]
		[System.String]
        $WebAdaptorContext
    )

    $result = $False

    if(-not($ProductId)){
        $IsWebAdaptorIIS = $False
        $ComponentName = $Name
        if($Name.StartsWith('WebAdaptorIIS')){
            $ComponentName = "WebAdaptorIIS"
            $IsWebAdaptorIIS = $true
        }

        $trueName = Get-ArcGISProductName -Name $ComponentName -Version $Version
        $InstallObject = (Get-ArcGISProductDetails -ProductName $trueName)
        if($IsWebAdaptorIIS){
            if($InstallObject.Length -gt 1){
                Write-Verbose "Multiple Instances of Web Adaptor are already installed"
            }
            $result = $false
            Write-Verbose "Checking if any of the installed Web Adaptor are installed with context $($WebAdaptorContext)"
            foreach($wa in $InstallObject){
                if($wa.InstallLocation -match "\\$($WebAdaptorContext)\\"){
                    $result = Test-Install -Name $ComponentName -Version $Version -ProductId $wa.IdentifyingNumber.TrimStart("{").TrimEnd("}") -Verbose
					break
                }else{
                    Write-Verbose "Component with $($WebAdaptorContext) is not installed on this machine"
                    $result = $false
                }
            }
        }else{
            Write-Verbose "Installed Version $($InstallObject.Version)"
            $result = Test-Install -Name $Name -Version $Version
        }
    }else{
        $result = Test-Install -Name $Name -ProductId $ProductId
    }

    $result
}

function Test-DataStoreFeautureSet {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $false)]
		[System.Array]
		$FeatureSet,

        [parameter(Mandatory = $false)]
		[System.Boolean]
		$DSInstalled = $False
    )

    $DSFeatureNameMapping = @{
        Relational = "relational"
        GraphStore = "graph"
        ObjectStore = "object"
        Spatiotemporal = "spatiotemporal"
        TileCache = "tilecache"
    }

    $AddLocalFeatureSet = @()
    $RemoveFeatureSet = @()
    
    if($DSInstalled){
        $InstalledFeatures = (Get-ItemProperty -Path "HKLM:\SOFTWARE\ESRI\ArcGIS Data Store\DataStoreTypes")
        foreach ($h in $DSFeatureNameMapping.GetEnumerator()) {
            if($InstalledFeatures.$($h.Name) -ieq $true){
                if(-not($FeatureSet -icontains $h.Name -or $FeatureSet -icontains "ALL")){
                    $RemoveFeatureSet += @($h.Value)
                }
            }else{
                if($FeatureSet -icontains $h.Name -or $FeatureSet -icontains "ALL"){
                    $AddLocalFeatureSet += @($h.Value)
                }
            }
        }

    }else{
        if($FeatureSet -icontains "ALL"){
            $AddLocalFeatureSet = @("ALL")
        }else{
            foreach($f in $FeatureSet){
                $AddLocalFeatureSet += @($DSFeatureNameMapping[$f])
            }
        }
    }

    return $AddLocalFeatureSet,$RemoveFeatureSet
}

function Invoke-WebAdaptorIISPreRequsitesInstallation
{
    Write-Verbose "Installing Pre-Requsites"
    $PreRequisiteWindowsFeatures = @("IIS-ManagementConsole", "IIS-ManagementScriptingTools",
                                "IIS-ManagementService", "IIS-ISAPIExtensions",
                                "IIS-ISAPIFilter", "IIS-RequestFiltering",
                                "IIS-WindowsAuthentication", "IIS-StaticContent",
                                "IIS-ASPNET45", "IIS-NetFxExtensibility45", "IIS-WebSockets")

    foreach($pr in $PreRequisiteWindowsFeatures){
        if (Get-Command "Get-WindowsOptionalFeature" -errorAction SilentlyContinue)
        {
            if(-not((Get-WindowsOptionalFeature -FeatureName $pr -online).State -ieq "Enabled")){
                Write-Verbose "Installing Windows Feature: $pr"
                Enable-WindowsOptionalFeature -Online -FeatureName $pr -All
            }else{
                Write-Verbose "Windows Feature: $pr already exists."
            }
        }else{
            Write-Verbose "Please check the Machine Operating System Compatatbilty"
        }
    }
}

function Invoke-StartProcess
{
    [CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$ExecPath,

		[parameter(Mandatory = $false)]
		[System.String]
        $Arguments
    )

    Write-Verbose "Executing $ExecPath"
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
        Write-Verbose "Output:- $op"
    }
    $err = $p.StandardError.ReadToEnd()
    if($err -and $err.Length -gt 0) {
        Write-Verbose $err
    }
    if($p.ExitCode -eq 0) {                    
        Write-Verbose "Install process finished successfully."
    }else {
        throw "Install failed. Process exit code:- $($p.ExitCode). Error - $err"
    }
}

Export-ModuleMember -Function *-TargetResource
