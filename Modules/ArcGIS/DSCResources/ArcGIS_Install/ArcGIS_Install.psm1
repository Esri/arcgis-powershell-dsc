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

		[parameter(Mandatory = $true)]
		[System.String]
		$Version,

		[parameter(Mandatory = $false)]
		[System.String]
		$Arguments,

		[System.String]
        $WebAdaptorContext,

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

		[parameter(Mandatory = $false)]
		[System.String]
        $Path,

        [parameter(Mandatory = $false)]
		[System.String]
		$ProductId,

		[parameter(Mandatory = $true)]
		[System.String]
		$Version,

		[parameter(Mandatory = $false)]
		[System.String]
		$Arguments,

		[System.String]
        $WebAdaptorContext,

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

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false
    
    $ComponentName = $Name
    if($Name -ieq 'ServerWebAdaptor' -or $Name -ieq 'PortalWebAdaptor'){
        $ComponentName = "WebAdaptor"
    }

    if($Ensure -eq 'Present') {
        if(-not(Test-Path $Path)){
            throw "$Path is not found or inaccessible"
        }

        if($Name -ieq 'ServerWebAdaptor' -or $Name -ieq 'PortalWebAdaptor'){
            Write-Verbose "Installing Pre-Requsites: $pr"
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

        $ExecPath = $null
        if((Get-Item $Path).length -gt 5mb)
        {
            Write-Verbose 'Self Extracting Installer'

            $ProdIdObject = if(-not($ProductId)){ Get-ComponentCode -ComponentName $ComponentName -Version $Version }else{ $ProductId }
            $ProdId = $ProductId
            if(-not($ProductId)){
                if($Name -ieq 'ServerWebAdaptor' -or $Name -ieq 'PortalWebAdaptor'){
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
            Start-Process -FilePath $Path -ArgumentList "/s /d $TempFolder" -Wait -NoNewWindow
            Write-Verbose 'Done Extracting. Waiting 15 seconds to allow the extractor to close files'
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
            if($ExecPath -iMatch ".msi"){
                $Arguments = "/i `"$ExecPath`" $Arguments"
                $ExecPath = "msiexec"
            }
        }else{
            Write-Verbose "Installing Software using installer at $Path"
            $ExecPath = $Path
        }

        if(($null -ne $ServiceCredential) -and (@("Server","Portal","WebStyles","DataStore","GeoEvent","NotebookServer","MissionServer","WorkflowManagerServer","WorkflowManagerWebApp","NotebookServerSamplesData", "Insights") -icontains $ComponentName)){
            if(-not(@("WorkflowManagerServer","WorkflowManagerWebApp","GeoEvent","Insights") -icontains $ComponentName)){
                $Arguments += " USER_NAME=$($ServiceCredential.UserName)"
            }
            
            if($ServiceCredentialIsMSA){
                $Arguments += " MSA=TRUE";
            }else{
                $Arguments += " PASSWORD=`"$($ServiceCredential.GetNetworkCredential().Password)`"";
            }
        }

        if($EnableMSILogging){
            $MSILogFileName = if($WebAdaptorContext){ "$($Name)_$($WebAdaptorContext)_install.log" }else{ "$($Name)_install.log" }
            $MSILogPath = (Join-Path $env:TEMP $MSILogFileName)
            Write-Verbose "Logs for $Name will be written to $MSILogPath" 
            $Arguments += " /L*v $MSILogPath";
        }
            
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
            Write-Verbose "Output of execution:- $op"
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

        if(($Name -ieq "Portal") -or ($Name -ieq "Portal for ArcGIS")){
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
        
        if($Name -ieq 'ServerWebAdaptor' -or $Name -ieq 'PortalWebAdaptor'){
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

        Write-Verbose "Validating the $Name Installation"
        $result = $false
        if(-not($ProductId)){
            $trueName = Get-ArcGISProductName -Name $Name -Version $Version
            
            $InstallObject = (Get-ArcGISProductDetails -ProductName $trueName)

            if($Name -ieq 'ServerWebAdaptor' -or $Name -ieq 'PortalWebAdaptor'){
                if($InstallObject.Length -gt 1){
                    Write-Verbose "Multiple Instances of Web Adaptor are already installed"
                }
                Write-Verbose "Checking if any of the installed Web Adaptor are installed with context $($WebAdaptorContext)"
                foreach($wa in $InstallObject){
                    $WAProdId = $wa.IdentifyingNumber.TrimStart("{").TrimEnd("}")
                    if($wa.InstallLocation -match "\\$($WebAdaptorContext)\\"){
                        $result = Test-Install -Name "WebAdaptor" -Version $Version -ProductId $WAProdId
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
		
		if(-not($result)){
			throw "Failed to Install $Name"
		}else{
			Write-Verbose "$Name installation was successful!"
		}
    }
    elseif($Ensure -eq 'Absent') {
        $ProdIdObject = if(-not($ProductId)){ Get-ComponentCode -ComponentName $ComponentName -Version $Version }else{ $ProductId }
        if($Name -ieq 'ServerWebAdaptor' -or $Name -ieq 'PortalWebAdaptor'){
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
        Start-Process 'msiexec' -ArgumentList "/x ""$ProdIdObject"" /quiet" -wait
        if($Name -ieq 'ServerWebAdaptor' -or $Name -ieq 'PortalWebAdaptor'){
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
        
        [parameter(Mandatory = $false)]
		[System.String]
		$ProductId,
		
		[parameter(Mandatory = $true)]
		[System.String]
		$Version,

		[parameter(Mandatory = $false)]
		[System.String]
		$Arguments,

		[System.String]
        $WebAdaptorContext,

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

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

	$result = $false
    
    if(-not($ProductId)){
        $trueName = Get-ArcGISProductName -Name $Name -Version $Version        
        
        $InstallObject = (Get-ArcGISProductDetails -ProductName $trueName)
        if($Name -ieq 'ServerWebAdaptor' -or $Name -ieq 'PortalWebAdaptor'){
            if($InstallObject.Length -gt 1){
                Write-Verbose "Multiple Instances of Web Adaptor are already installed"
            }
            $result = $false
            Write-Verbose "Checking if any of the installed Web Adaptor are installed with context $($WebAdaptorContext)"
            foreach($wa in $InstallObject){
                if($wa.InstallLocation -match "\\$($WebAdaptorContext)\\"){
                    $result = Test-Install -Name 'WebAdaptor' -Version $Version -ProductId $wa.IdentifyingNumber.TrimStart("{").TrimEnd("}") -Verbose
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
    
    if($Ensure -ieq 'Present') {
		$result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}

Export-ModuleMember -Function *-TargetResource