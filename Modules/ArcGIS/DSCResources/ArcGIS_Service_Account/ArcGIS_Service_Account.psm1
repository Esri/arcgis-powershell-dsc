$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

<#
    .SYNOPSIS
        Resource to make the Data Directories accesssible to given Run as Account for a given ArcGIS Component.
    .PARAMETER Ensure
        Take the values Present or Absent. 
        - "Present" ensures the Data Directories are accesssible to given Run as Account for a given ArcGIS Component.
        - "Absent" ensures the Data Directories are made in accesssible to given Run as Account for a given ArcGIS Component(Not Implemented).
    .PARAMETER Name
        Name of the ArcGIS Component that is being configured.
    .PARAMETER RunAsAccount
        A MSFT_Credential Object - Run as Account, Account to which the DataDir Folders be made accessible
    .PARAMETER DataDir
        Data Directory paths to which the necessary permissions need to be given.
    .PARAMETER IsDomainAccount
        Is the given RunAsAccount a domain-account?
    .PARAMETER IsMSAAccount
        Is the given RunAsAccount a Managed Service Accounts?
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
		[System.Management.Automation.PSCredential]
        $RunAsAccount,
        
        [parameter(Mandatory = $False)]
		[System.Boolean]
        $ForceRunAsAccountUpdate,

		[System.String[]]
		$DataDir,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,
		
		[parameter(Mandatory = $false)]
        [System.Boolean]
        $IsDomainAccount = $false,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsMSAAccount = $false,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $SetStartupToAutomatic = $false
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

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
        $RunAsAccount,
        
        [parameter(Mandatory = $False)]
		[System.Boolean]
        $ForceRunAsAccountUpdate,

		[System.String[]]
		$DataDir,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,
		
		[parameter(Mandatory = $false)]
        [System.Boolean]
        $IsDomainAccount = $false,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsMSAAccount = $false,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $SetStartupToAutomatic = $false
	)

    if($Ensure -ieq 'Present') {
        
        $ExpectedRunAsUserName = $RunAsAccount.UserName
        Write-Verbose "RunAsAccount Username:- $ExpectedRunAsUserName"
        if($ExpectedRunAsUserName -and $ExpectedRunAsUserName.StartsWith('.\')){
            $ExpectedRunAsUserName = $ExpectedRunAsUserName.Substring(2) # Remove the current machine prefix
            Write-Verbose "Removing the machine prefix for the expected RunAsAccount to $ExpectedRunAsUserName"
        }

        #Add Run As account to
        Write-Verbose "Adding Log On As a Service Policy for RunAsAccount Username:- $ExpectedRunAsUserName"
        Set-LogOnAsServicePolicy -UserName $ExpectedRunAsUserName
        Write-Verbose "Successfully added Log On As a Service Policy for RunAsAccount Username:- $ExpectedRunAsUserName"

		$RegKey = Get-EsriRegistryKeyForService -ServiceName $Name
        $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir
        Write-Verbose "Install Dir for $Name is $InstallDir"
        $RestartService = $False
        if($InstallDir) 
        { 
            $InstallDir = $InstallDir.TrimEnd('\')
            if(Test-Path $InstallDir){
                Write-Verbose "Checking if RunAs Account '$ExpectedRunAsUserName' has the required permissions to $InstallDir"
                if(-not(Test-Acl $InstallDir $ExpectedRunAsUserName $IsDomainAccount $IsMSAAccount)) {
                    Write-Verbose "Providing RunAs Account '$ExpectedRunAsUserName' has the required permissions to $InstallDir"
                    Write-Verbose "icacls.exe $InstallDir /grant $($ExpectedRunAsUserName):(OI)(CI)F"
                    icacls.exe $InstallDir /grant "$($ExpectedRunAsUserName):(OI)(CI)F"
                }else {
                    Write-Verbose "RunAs Account '$ExpectedRunAsUserName' has the required permissions to $InstallDir"
                } 
            }

            # Get Current Run as account or if Force Update run as account set
            $WindowsService = (Get-CimInstance Win32_Service -filter "Name='$Name'" | Select-Object -First 1)
            if($null -ne $WindowsService){
                $CurrentRunAsAccount = $WindowsService.StartName
                if($CurrentRunAsAccount -and $CurrentRunAsAccount.StartsWith('.\')){            
                    $CurrentRunAsAccount = $CurrentRunAsAccount.Substring(2) # Remove the current machine prefix
                    Write-Verbose "Removing the machine prefix for the current RunAsAccount to $CurrentRunAsAccount"
                }

                if($ForceRunAsAccountUpdate -or ($CurrentRunAsAccount -ne $ExpectedRunAsUserName)){
                    $RestartService = $True

                    if(@('ArcGIS Server','Portal for ArcGIS', 'ArcGIS Notebook Server', 'ArcGIS Mission Server','ArcGIS Data Store') -icontains $Name){
                        $psi = New-Object System.Diagnostics.ProcessStartInfo
                        $ExecPath = $InstallDir
                        if($Name -ieq 'ArcGIS Server'){
                            $ExecPath = Join-Path $ExecPath '\\bin\\ServerConfigurationUtility.exe'
                            $psi.EnvironmentVariables["AGSSERVER"] = [environment]::GetEnvironmentVariable("AGSSERVER","Machine")
                        }
                        elseif(@('Portal for ArcGIS', 'ArcGIS Notebook Server', 'ArcGIS Mission Server') -icontains $Name){
                            $ExecPath = Join-Path $ExecPath '\\tools\\ConfigUtility\\configureserviceaccount.bat'
                            if($Name -ieq 'Portal for ArcGIS'){
                                $psi.EnvironmentVariables["AGSPORTAL"] = [environment]::GetEnvironmentVariable("AGSPortal","Machine")
                            }elseif($Name -ieq 'ArcGIS Notebook Server'){
                                $psi.EnvironmentVariables["AGSNOTEBOOK"] = [environment]::GetEnvironmentVariable("AGSNOTEBOOK","Machine")
                            }elseif($Name -ieq 'ArcGIS Mission Server'){
                                $psi.EnvironmentVariables["AGSMISSION"] = [environment]::GetEnvironmentVariable("AGSMISSION","Machine")
                            }
                        }
                        elseif($Name -ieq 'ArcGIS Data Store'){
                            $ExecPath = Join-Path $ExecPath '\\tools\\configureserviceaccount.bat'
                            $psi.EnvironmentVariables["AGSDATASTORE"] = [environment]::GetEnvironmentVariable("AGSDATASTORE","Machine")
                        }
                        $psi.FileName = $ExecPath
                        
                        $Arguments = ""
                        if($Name -ieq 'ArcGIS Server'){
                            $Arguments = "/username $($ExpectedRunAsUserName)"
                            if(-not($IsMSAAccount)){
                                $Arguments += " /password `"$($RunAsAccount.GetNetworkCredential().Password)`""
                            }
                        }else{
                            $Arguments = "--username $($ExpectedRunAsUserName)"
                            if(-not($IsMSAAccount)){
                                $Arguments += " --password `"$($RunAsAccount.GetNetworkCredential().Password)`""
                            }
                        }
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
                        
                        if($p.ExitCode -eq 0) {                    
                            Write-Verbose "Initialized correctly indicating successful desktop initialization"
                        }else {
                            throw "Service Account Update did not succeed. Process exit code:- $($p.ExitCode). Error - $err"
                        }
                    }else{
                        $StartName = if(-not($IsMSAAccount) -and -not($IsDomainAccount)){ ".\$($ExpectedRunAsUserName)" }else{ $ExpectedRunAsUserName }
                        $ChangeObject = @{StartName=$StartName;}
                        if(-not($IsMSAAccount)){
                            $ChangeObject += @{StartPassword=$RunAsAccount.GetNetworkCredential().Password;}
                        }

                        Write-Verbose "Updating Service Account for service $Name."
                        $ReturnValue = ($WindowsService | Invoke-CimMethod -Name Change -Arguments $ChangeObject).ReturnValue
                        if($ReturnValue -eq 0){
                            Write-Verbose "Service Account Change Operation for Service $Name successful."
                            if($Name -ieq "ArcGISGeoEvent"){
                                $GeoeventGatewayService = Get-CimInstance Win32_Service -filter "name='ArcGISGeoEventGateway'" 
                                if($null -ne $GeoeventGatewayService){
                                    Write-Verbose "Updating Service Account for service ArcGISGeoEventGateway."
                                    $GeoeventGatewayReturnValue = ($GeoeventGatewayService | Invoke-CimMethod -Name Change -Arguments $ChangeObject)
                                    if($GeoeventGatewayReturnValue -eq 0){
                                        Write-Verbose "Service Account Change Operation for Service ArcGISGeoEventGateway successful."
                                    }else{
                                        throw "Service Account Change Operation for Service ArcGISGeoEventGateway failed. Return value - $ReturnValue"
                                    }
                                }
                            }
                        }else{
                            throw "Service Account Change Operation for Service $Name failed. Return value - $ReturnValue"
                        }
                    }
                }else{
                    Write-Verbose "Service Account needs no updates."
                }
            }
            else{
                throw "$Name service not found. Please check and try again."
            }
        }

        if($DataDir) 
        {
            foreach($DataDirectory in $DataDir) 
            {
                if(-not($DataDirectory.StartsWith('\'))){
                    $LocalPath = $DataDirectory
                    if($LocalPath.StartsWith('HKLM:\')) {
                        $LocalPath = (Get-Item ((Get-ItemProperty ($LocalPath) -ErrorAction Ignore).ContentDir))                        
                    }elseif($LocalPath.StartsWith('$env:')){
                        $LocalPath = $ExecutionContext.InvokeCommand.ExpandString("$DataDirectory")
                    }
                    if($LocalPath -and (Test-Path $LocalPath)) 
                    {
                        Write-Verbose "Checking Permissions on $LocalPath"
                        if(-not(Test-Acl $LocalPath $ExpectedRunAsUserName $IsDomainAccount $IsMSAAccount)) {
                            Write-Verbose "Permissions are not set for $LocalPath"
                            Write-Verbose "Providing RunAs Account '$ExpectedRunAsUserName' the required permissions to $LocalPath"
                            Write-Verbose "icacls.exe $LocalPath /grant $($ExpectedRunAsUserName):(OI)(CI)F"
                            icacls.exe $LocalPath /grant "$($ExpectedRunAsUserName):(OI)(CI)F"
                        }  else {
                            Write-Verbose "RunAs Account '$ExpectedRunAsUserName' has the required permissions to $LocalPath"
                        }             
                    }                
                }
            }
        }

        if($Name -ieq 'ArcGISGeoEvent') {
            $RestartService = $True
			###
			### GeoEvent needs additional permissions set and delete zookeeper folder
			###
			$GeoEventProgramData = Join-Path $env:ProgramData 'Esri\GeoEvent'						
			if(Test-Path $GeoEventProgramData) {
                # Backup Geoevent program data folder
                $GeoEventProgramDataBackupFolder = Join-Path $env:ProgramData "Esri\GeoEvent-Backup-$(Get-Date -Format "MMddyyyy-HHmmss")"
                if(Test-Path $GeoEventProgramDataBackupFolder){
                    $GeoEventProgramDataBackupFolder = Join-Path $env:ProgramData "Esri\GeoEvent-Backup-$(Get-Date -Format "MMddyyyy-HHmmss")"   
                }
                New-Item $GeoEventProgramDataBackupFolder -ItemType "directory" 
                Write-Verbose "Backing up $GeoEventProgramData to $GeoEventProgramDataBackupFolder"
                Copy-Item -Path "$GeoEventProgramData\*" -Destination $GeoEventProgramDataBackupFolder -Recurse
                
                $ZooKeeperFolder = Join-Path $GeoEventProgramData 'zookeeper'
                if(Test-Path $ZooKeeperFolder) {
                    Write-Verbose "Deleting ZooKeeper folder $ZooKeeperFolder"
                    Remove-Item -Path $ZooKeeperFolder -Recurse -Force 
                }
				$ZooKeeperFile = Join-Path $GeoEventProgramData 'zookeeper.properties'
				if(Test-Path $ZooKeeperFile) {
                    Write-Verbose "Deleting ZooKeeper file $ZooKeeperFile"
                    Remove-Item -Path $ZooKeeperFile -Recurse -Force -ErrorAction Ignore
                }
				$ZooKeeperFile = Join-Path $GeoEventProgramData 'zookeeper-dynamic.properties'
				if(Test-Path $ZooKeeperFile) {
                    Write-Verbose "Deleting ZooKeeper file $ZooKeeperFile"
                    Remove-Item -Path $ZooKeeperFile -Recurse -Force -ErrorAction Ignore
                }
            }
            
            #Add a check for 10.6

			###
			### GeoEvent Clean up - the karaf data folder and ProgramData (after stopping the service)
			### GeoEventGateway Clean up  - the Gatewaylog and ProgramData (after stopping the service)
			###
			@('ArcGISGeoEvent', 'ArcGISGeoEventGateway') | ForEach-Object{
				try {			    
					$ServiceName = $_
					Write-Verbose "Stopping Service $ServiceName"
					Stop-Service -Name $ServiceName -Force -ErrorAction Ignore
					Write-Verbose 'Stopping the service' 
					Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Stopped'	
					Write-Verbose 'Stopped the service'
				}catch {
					Write-Verbose "[WARNING] Stopping Service $_"
				}
            }
            
			if(-not($InstallDir)) {
				# GeoEvent is always installed in Server's install directory
				$RegKey = Get-EsriRegistryKeyForService -ServiceName 'ArcGIS Server'
				$InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir
            }
            
			if($InstallDir) {
				$InstallDir = Join-Path $InstallDir 'GeoEvent'
                $GeoEventKarafDataFolder = Join-Path $InstallDir 'data'		
				$GeoEventGatewayLogFolder = Join-Path $InstallDir 'gateway\log'		
                $GeoEventGatewayConfig = Join-Path $InstallDir 'etc\com.esri.ges.gateway.cfg'

				$GeoEventProgramData = Join-Path $env:ProgramData 'Esri\GeoEvent'		
				$GeoEventGatewayProgramData = Join-Path $env:ProgramData 'Esri\GeoEvent-Gateway'
                
                

				@($GeoEventKarafDataFolder, $GeoEventGatewayLogFolder, $GeoEventGatewayConfig, $GeoEventProgramData, $GeoEventGatewayProgramData) | ForEach-Object{ 
					$FolderToDelete = $_
					Write-Verbose "Clean up Folder:- $FolderToDelete"
					if(Test-Path $FolderToDelete) {
						Write-Verbose "Recursively delete Folder:- $FolderToDelete"
						Get-ChildItem -Path $FolderToDelete | ForEach-Object { Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction Ignore }
					}
				}
			}

			###
			### At 10.5 and beyond GE uses the Zookeeper component of ArcGIS Server which stores in local
			### 
			$ZooKeeperFolder = Join-Path $env:SystemDrive 'arcgisserver\local\zookeeper'
			if(Test-Path $ZooKeeperFolder) {
                Write-Verbose "Deleting ZooKeeper folder $ZooKeeperFolder in local path"
                Remove-Item -Path $ZooKeeperFolder -Recurse -Force 
            }
        }

        if($Name -ieq 'WorkflowManager') {
            $RestartService = $True
        }

        if($SetStartupToAutomatic){
            try{
                if($Name -ieq 'ArcGISGeoEvent'){
                    $GeoeventStartupTypeIsAutoDelayed = (Test-ServiceStartupType -ServiceName $Name -ExpectedStartupType "AutomaticDelayedStart" -Verbose)
                    if(-not($GeoeventStartupTypeIsAutoDelayed)){
                        Write-Verbose "Setting Startup Type for ArcGIS GeoEvent to AutomaticDelayedStart"
                        Set-ServiceStartupType -ServiceName $Name -StartupType "AutomaticDelayedStart" -Verbose
                    }
                    $GeoeventGatewayStartupTypeIsAutoDelayed = (Test-ServiceStartupType -ServiceName 'ArcGISGeoEventGateway' -ExpectedStartupType "Automatic" -Verbose)
                    if(-not($GeoeventGatewayStartupTypeIsAutoDelayed)){
                        Write-Verbose "Setting Startup Type for ArcGIS GeoEvent Gateway to Automatic"
                        Set-ServiceStartupType -ServiceName 'ArcGISGeoEventGateway' -StartupType "Automatic" -Verbose
                    }
                }else{
                    $ServiceStartupTypeIsAuto = (Test-ServiceStartupType -ServiceName $Name -ExpectedStartupType "Automatic" -Verbose) # TODO - why is this check failing ?
                    if(-not($ServiceStartupTypeIsAuto)){
                        Write-Verbose "Setting Startup Type for $Name to Automatic"
                        Set-ServiceStartupType -ServiceName $Name -StartupType "Automatic" -Verbose
                    }
                }
            }catch{
                throw "Service Startup Type change failed. Error - $_"
            }
        }

        ###
        ### If the Service Credentials are changed. Restart the Service (just in case) TODO:- Revisit if this is needed
        ###
        if($RestartService){
            Restart-ArcGISService -ServiceName $Name -Verbose
            
            if($Name -ieq 'ArcGISGeoEvent'){
                Start-Sleep -Seconds 180
            }elseif( $Name -ieq 'ArcGIS Data Store'){
                Wait-ForUrl -Url "https://localhost:2443/arcgis/datastoreadmin/configure?f=json" -MaxWaitTimeInSeconds 180 -SleepTimeInSeconds 10 -HttpMethod 'GET' -Verbose
            }
        }
    }else{
        Write-Warning 'Absent not implemented'
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
		$Name,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
        $RunAsAccount,
        
        [parameter(Mandatory = $False)]
		[System.Boolean]
        $ForceRunAsAccountUpdate,

		[System.String[]]
		$DataDir,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,
		
		[parameter(Mandatory = $false)]
        [System.Boolean]
        $IsDomainAccount = $false,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsMSAAccount = $false,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $SetStartupToAutomatic = $false
	)

    $result = $true
    $ExpectedRunAsUserName = $RunAsAccount.UserName
    Write-Verbose "RunAsAccount Username:- $RunAsUserName"
    if($ExpectedRunAsUserName -and $ExpectedRunAsUserName.StartsWith('.\')){            
        $ExpectedRunAsUserName = $ExpectedRunAsUserName.Substring(2) # Remove the current machine prefix
        Write-Verbose "Removing the machine prefix for the RunAsAccount to $ExpectedRunAsUserName"
    }

    $RegKey = Get-EsriRegistryKeyForService -ServiceName $Name
    $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir
    if($InstallDir -and (Test-Path $InstallDir)) {
        Write-Verbose "Install Dir for $Name is $InstallDir"
        if(-not(Test-Acl $InstallDir $ExpectedRunAsUserName $IsDomainAccount $IsMSAAccount)) {
			Write-Verbose "Permissions are not set for $InstallDir"
            $result = $false
        }
    }

    # Get Current Run as account or if Force Update run as account set
    $CurrentRunAsAccount = (Get-CimInstance Win32_Service -filter "Name='$Name'" | Select-Object -First 1 ).StartName
    if($CurrentRunAsAccount -and $CurrentRunAsAccount.StartsWith('.\')){            
        $CurrentRunAsAccount = $CurrentRunAsAccount.Substring(2) # Remove the current machine prefix
        Write-Verbose "Removing the machine prefix for the current RunAsAccount to $CurrentRunAsAccount"
    }

    if($ForceRunAsAccountUpdate -or ($CurrentRunAsAccount -ne $ExpectedRunAsUserName)){
        $result = $false
    }

    if($SetStartupToAutomatic){
        if($Name -ieq 'ArcGISGeoEvent') {
            $result = (Test-ServiceStartupType -ServiceName 'ArcGISGeoEvent' -ExpectedStartupType "AutomaticDelayedStart" -Verbose)
            if($result){
                $result = (Test-ServiceStartupType -ServiceName 'ArcGISGeoEventGateway' -ExpectedStartupType "Automatic" -Verbose)
            }
        }else{
            Write-Verbose "Checking Service Startup Type $Name."
            $result = (Test-ServiceStartupType -ServiceName $Name -ExpectedStartupType "Automatic" -Verbose)
        }
    }
    
    if($result) {
        if($DataDir) {
            foreach($DataDirectory in $DataDir) {
                if($result -and -not($DataDirectory.StartsWith('\'))) {
                    $LocalPath = $DataDirectory
                    if($LocalPath.StartsWith('HKLM:\')) {
                        $LocalPath = (Get-Item ((Get-ItemProperty ($LocalPath) -ErrorAction Ignore).ContentDir))                        
                    }elseif($LocalPath.StartsWith('$env:')){
                        $LocalPath = $ExecutionContext.InvokeCommand.ExpandString("$DataDirectory")
                    }
                    if($LocalPath -and (Test-Path $LocalPath)) 
                    {
                        Write-Verbose "Checking Permissions on $LocalPath"
                        if(-not(Test-Acl $LocalPath $ExpectedRunAsUserName $IsDomainAccount $IsMSAAccount)) {
				            Write-Verbose "Permissions are not set for $LocalPath"
                            $result = $false
                        }
                    }else{
                        # TODO
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

function Test-ServiceStartupType
{
    [CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [parameter(Mandatory = $true)]
		[System.String]
		$ServiceName,

        [parameter(Mandatory = $true)]
		[System.String]
        [ValidateSet("Automatic", "AutomaticDelayedStart", "Manual", "Disabled")]
		$ExpectedStartupType
    )

    Write-Verbose "Checking if StartupType is $ExpectedStartupType for service $ServiceName."
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "sc.exe"
    $psi.Arguments = "qc `"$ServiceName`""
    $psi.UseShellExecute = $false #start the process from it's own executable file    
    $psi.RedirectStandardOutput = $true #enable the process to read from standard output
    $psi.RedirectStandardError = $true #enable the process to read from standard error
    
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.WaitForExit()
    $op = $p.StandardOutput.ReadToEnd()
    $result = $False
    if($p.ExitCode -eq 0) {
        Write-Verbose "Output - $op"
        $StartupType = $op -split [Environment]::NewLine | Where-Object { $_ -match "START_TYPE" } | ForEach-Object { ($_ -replace '\s+', ' ').trim().Split(" ") | Select-Object -Last 1 }
        Write-Verbose "Computed Startup type - $StartupType"
        if($StartupType -ieq "DEMAND_START"){
            $result = $ExpectedStartupType -ieq "Manual"
        }elseif($StartupType -ieq "AUTO_START"){
            $result = $ExpectedStartupType -ieq "Automatic"
        }elseif($StartupType -ieq "(DELAYED)"){
            $result = $ExpectedStartupType -ieq "AutomaticDelayedStart"
        }elseif($StartupType -ieq "DISABLED"){
            $result = $ExpectedStartupType -ieq "Disabled"
        }
    }else{
        $err = $p.StandardError.ReadToEnd()
        Write-Verbose $err
    }
    $result
}

function Set-ServiceStartupType
{
    [CmdletBinding()]
	param
	(
        [parameter(Mandatory = $true)]
		[System.String]
		$ServiceName,

        [parameter(Mandatory = $true)]
		[System.String]
        [ValidateSet("Automatic", "AutomaticDelayedStart", "Manual", "Disabled")]
		$StartupType
    )

    $st = "auto"
    if($StartupType -ieq "Automatic"){
        $st ="auto"
    }elseif($StartupType -ieq "AutomaticDelayedStart"){
        $st = "delayed-auto"
    }elseif($StartupType -ieq "Manual"){
        $st ="demand"
    }elseif($StartupType -ieq "Disabled"){
        $st ="disabled"
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "sc.exe"
    $psi.Arguments = "config `"$ServiceName`" start= $st"
    $psi.UseShellExecute = $false #start the process from it's own executable file    
    $psi.RedirectStandardOutput = $true #enable the process to read from standard output
    $psi.RedirectStandardError = $true #enable the process to read from standard error
    
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.WaitForExit()
    $op = $p.StandardOutput.ReadToEnd()
    if($p.ExitCode -eq 0) {
        Write-Verbose "Successfully changed StartupType to $StartupType for service $ServiceName. Output - $op"
    }else{
        $err = $p.StandardError.ReadToEnd()
        Write-Verbose $err
        if($err -and $err.Length -gt 0) {
            throw "Failed to set StartupType to $StartupType for service $ServiceName. Error - $err"
        }
    }
}
function Test-Acl {
    [CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [parameter(Mandatory = $true)]
		[System.String]
		$Directory,

        [parameter(Mandatory = $true)]
		[System.String]
		$RunAsUsername,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsDomainAccount = $false,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsMSAAccount = $false
    )

    $result = $true
    if(-not($IsDomainAccount) -and -not($IsMSAAccount))
    {
        $RunAsUserName = "$env:ComputerName\$RunAsUsername"
    }
    Write-Verbose "Testing Permission for User $RunAsUserName on Directory $Directory"
    $acl = Get-Acl $Directory | Select-Object -ExpandProperty Access | Where-Object {$_.IdentityReference -ieq "$RunAsUserName"} | Where-Object {$_.FileSystemRights -ieq "FullControl"}
    if((-not($acl)) -or ($acl.AccessControlType -ine 'Allow')) {
        $result = $false
    }
    $result
}

<#
.Synopsis
Grants log on as service right to the given user
#>
function Set-LogOnAsServicePolicy
{
    [CmdletBinding()]
	param
	(
        [System.String]
        $UserName
    )

    $logOnAsServiceText=@"
        namespace LogOnAsServiceHelper
        {
            using Microsoft.Win32.SafeHandles;
            using System;
            using System.Runtime.ConstrainedExecution;
            using System.Runtime.InteropServices;
            using System.Security;

            public class NativeMethods
            {
                #region constants
                // from ntlsa.h
                private const int POLICY_LOOKUP_NAMES = 0x00000800;
                private const int POLICY_CREATE_ACCOUNT = 0x00000010;
                private const uint ACCOUNT_ADJUST_SYSTEM_ACCESS = 0x00000008;
                private const uint ACCOUNT_VIEW = 0x00000001;
                private const uint SECURITY_ACCESS_SERVICE_LOGON = 0x00000010;

                // from LsaUtils.h
                private const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034;

                // from lmcons.h
                private const int UNLEN = 256;
                private const int DNLEN = 15;

                // Extra characteres for "\","@" etc.
                private const int EXTRA_LENGTH = 3;
                #endregion constants

                #region interop structures
                /// <summary>
                /// Used to open a policy, but not containing anything meaqningful
                /// </summary>
                [StructLayout(LayoutKind.Sequential)]
                private struct LSA_OBJECT_ATTRIBUTES
                {
                    public UInt32 Length;
                    public IntPtr RootDirectory;
                    public IntPtr ObjectName;
                    public UInt32 Attributes;
                    public IntPtr SecurityDescriptor;
                    public IntPtr SecurityQualityOfService;

                    public void Initialize()
                    {
                        this.Length = 0;
                        this.RootDirectory = IntPtr.Zero;
                        this.ObjectName = IntPtr.Zero;
                        this.Attributes = 0;
                        this.SecurityDescriptor = IntPtr.Zero;
                        this.SecurityQualityOfService = IntPtr.Zero;
                    }
                }

                /// <summary>
                /// LSA string
                /// </summary>
                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
                private struct LSA_UNICODE_STRING
                {
                    internal ushort Length;
                    internal ushort MaximumLength;
                    [MarshalAs(UnmanagedType.LPWStr)]
                    internal string Buffer;

                    internal void Set(string src)
                    {
                        this.Buffer = src;
                        this.Length = (ushort)(src.Length * sizeof(char));
                        this.MaximumLength = (ushort)(this.Length + sizeof(char));
                    }
                }

                /// <summary>
                /// Structure used as the last parameter for LSALookupNames
                /// </summary>
                [StructLayout(LayoutKind.Sequential)]
                private struct LSA_TRANSLATED_SID2
                {
                    public uint Use;
                    public IntPtr SID;
                    public int DomainIndex;
                    public uint Flags;
                };
                #endregion interop structures

                #region safe handles
                /// <summary>
                /// Handle for LSA objects including Policy and Account
                /// </summary>
                private class LsaSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
                {
                    [DllImport("advapi32.dll")]
                    private static extern uint LsaClose(IntPtr ObjectHandle);

                    /// <summary>
                    /// Prevents a default instance of the LsaPolicySafeHAndle class from being created.
                    /// </summary>
                    private LsaSafeHandle(): base(true)
                    {
                    }

                    /// <summary>
                    /// Calls NativeMethods.CloseHandle(handle)
                    /// </summary>
                    /// <returns>the return of NativeMethods.CloseHandle(handle)</returns>
                    [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
                    protected override bool ReleaseHandle()
                    {
                        long returnValue = LsaSafeHandle.LsaClose(this.handle);
                        return returnValue != 0;
                
                    }
                }

                /// <summary>
                /// Handle for IntPtrs returned from Lsa calls that have to be freed with
                /// LsaFreeMemory
                /// </summary>
                private class SafeLsaMemoryHandle : SafeHandleZeroOrMinusOneIsInvalid
                {
                    [DllImport("advapi32")]
                    internal static extern int LsaFreeMemory(IntPtr Buffer);

                    private SafeLsaMemoryHandle() : base(true) { }

                    private SafeLsaMemoryHandle(IntPtr handle)
                        : base(true)
                    {
                        SetHandle(handle);
                    }

                    private static SafeLsaMemoryHandle InvalidHandle
                    {
                        get { return new SafeLsaMemoryHandle(IntPtr.Zero); }
                    }

                    override protected bool ReleaseHandle()
                    {
                        return SafeLsaMemoryHandle.LsaFreeMemory(handle) == 0;
                    }

                    internal IntPtr Memory
                    {
                        get
                        {
                            return this.handle;
                        }
                    }
                }
                #endregion safe handles

                #region interop function declarations
                /// <summary>
                /// Opens LSA Policy
                /// </summary>
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaOpenPolicy(
                    IntPtr SystemName,
                    ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
                    uint DesiredAccess,
                    out LsaSafeHandle PolicyHandle
                );

                /// <summary>
                /// Convert the name into a SID which is used in remaining calls
                /// </summary>
                [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
                private static extern uint LsaLookupNames2(
                    LsaSafeHandle PolicyHandle,
                    uint Flags,
                    uint Count,
                    LSA_UNICODE_STRING[] Names,
                    out SafeLsaMemoryHandle ReferencedDomains,
                    out SafeLsaMemoryHandle Sids
                );

                /// <summary>
                /// Opens the LSA account corresponding to the user's SID
                /// </summary>
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaOpenAccount(
                    LsaSafeHandle PolicyHandle,
                    IntPtr Sid,
                    uint Access,
                    out LsaSafeHandle AccountHandle);

                /// <summary>
                /// Creates an LSA account corresponding to the user's SID
                /// </summary>
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaCreateAccount(
                    LsaSafeHandle PolicyHandle,
                    IntPtr Sid,
                    uint Access,
                    out LsaSafeHandle AccountHandle);

                /// <summary>
                /// Gets the LSA Account access
                /// </summary>
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaGetSystemAccessAccount(
                    LsaSafeHandle AccountHandle,
                    out uint SystemAccess);

                /// <summary>
                /// Sets the LSA Account access
                /// </summary>
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaSetSystemAccessAccount(
                    LsaSafeHandle AccountHandle,
                    uint SystemAccess);
                #endregion interop function declarations

                /// <summary>
                /// Sets the Log On As A Service Policy for <paramref name="userName"/>, if not already set.
                /// </summary>
                /// <param name="userName">the user name we want to allow logging on as a service</param>
                /// <exception cref="ArgumentNullException">If the <paramref name="userName"/> is null or empty.</exception>
                /// <exception cref="InvalidOperationException">In the following cases:
                ///     Failure opening the LSA Policy.
                ///     The <paramref name="userName"/> is too large.
                ///     Failure looking up the user name.
                ///     Failure opening LSA account (other than account not found).
                ///     Failure creating LSA account.
                ///     Failure getting LSA account policy access.
                ///     Failure setting LSA account policy access.
                /// </exception>
                public static void SetLogOnAsServicePolicy(string userName)
                {
                    if (String.IsNullOrEmpty(userName))
                    {
                        throw new ArgumentNullException("userName");
                    }

                    LSA_OBJECT_ATTRIBUTES objectAttributes = new LSA_OBJECT_ATTRIBUTES();
                    objectAttributes.Initialize();

                    // All handles are delcared in advance so they can be closed on finally
                    LsaSafeHandle policyHandle = null;
                    SafeLsaMemoryHandle referencedDomains = null;
                    SafeLsaMemoryHandle sids = null;
                    LsaSafeHandle accountHandle = null;

                    try
                    {
                        uint status = LsaOpenPolicy(
                            IntPtr.Zero,
                            ref objectAttributes,
                            POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT,
                            out policyHandle);

                        if (status != 0)
                        {
                            throw new InvalidOperationException("CannotOpenPolicyErrorMessage");
                        }

                        // Unicode strings have a maximum length of 32KB. We don't want to create
                        // LSA strings with more than that. User lengths are much smaller so this check
                        // ensures userName's length is useful
                        if (userName.Length > UNLEN + DNLEN + EXTRA_LENGTH)
                        {
                            throw new InvalidOperationException("UserNameTooLongErrorMessage");
                        }

                        LSA_UNICODE_STRING lsaUserName = new LSA_UNICODE_STRING();
                        lsaUserName.Set(userName);

                        LSA_UNICODE_STRING[] names = new LSA_UNICODE_STRING[1];
                        names[0].Set(userName);

                        status = LsaLookupNames2(
                            policyHandle,
                            0,
                            1,
                            new LSA_UNICODE_STRING[] { lsaUserName },
                            out referencedDomains,
                            out sids);

                        if (status != 0)
                        {
                            throw new InvalidOperationException("CannotLookupNamesErrorMessage");
                        }

                        LSA_TRANSLATED_SID2 sid = (LSA_TRANSLATED_SID2)Marshal.PtrToStructure(sids.Memory, typeof(LSA_TRANSLATED_SID2));

                        status = LsaOpenAccount(policyHandle,
                                            sid.SID,
                                            ACCOUNT_VIEW | ACCOUNT_ADJUST_SYSTEM_ACCESS,
                                            out accountHandle);

                        uint currentAccess = 0;

                        if (status == 0)
                        {
                            status = LsaGetSystemAccessAccount(accountHandle, out currentAccess);

                            if (status != 0)
                            {
                                throw new InvalidOperationException("CannotGetAccountAccessErrorMessage");
                            }

                        }
                        else if (status == STATUS_OBJECT_NAME_NOT_FOUND)
                        {
                            status = LsaCreateAccount(
                                policyHandle,
                                sid.SID,
                                ACCOUNT_ADJUST_SYSTEM_ACCESS,
                                out accountHandle);

                            if (status != 0)
                            {
                                throw new InvalidOperationException("CannotCreateAccountAccessErrorMessage");
                            }
                        }
                        else
                        {
                            throw new InvalidOperationException("CannotOpenAccountErrorMessage");
                        }

                        if ((currentAccess & SECURITY_ACCESS_SERVICE_LOGON) == 0)
                        {
                            status = LsaSetSystemAccessAccount(
                                accountHandle,
                                currentAccess | SECURITY_ACCESS_SERVICE_LOGON);
                            if (status != 0)
                            {
                                throw new InvalidOperationException("CannotSetAccountAccessErrorMessage");
                            }
                        }
                    }
                    finally
                    {
                        if (policyHandle != null) { policyHandle.Close(); }
                        if (referencedDomains != null) { referencedDomains.Close(); }
                        if (sids != null) { sids.Close(); }
                        if (accountHandle != null) { accountHandle.Close(); }
                    }
                }
            }
        }
"@
    
    try
    {
        $existingType=[LogOnAsServiceHelper.NativeMethods]
    }
    catch
    {
        $logOnAsServiceText=$logOnAsServiceText.Replace("CannotOpenPolicyErrorMessage",$LocalizedData.CannotOpenPolicyErrorMessage)
        $logOnAsServiceText=$logOnAsServiceText.Replace("UserNameTooLongErrorMessage",$LocalizedData.UserNameTooLongErrorMessage)
        $logOnAsServiceText=$logOnAsServiceText.Replace("CannotLookupNamesErrorMessage",$LocalizedData.CannotLookupNamesErrorMessage)
        $logOnAsServiceText=$logOnAsServiceText.Replace("CannotOpenAccountErrorMessage",$LocalizedData.CannotOpenAccountErrorMessage)
        $logOnAsServiceText=$logOnAsServiceText.Replace("CannotCreateAccountAccessErrorMessage",$LocalizedData.CannotCreateAccountAccessErrorMessage)
        $logOnAsServiceText=$logOnAsServiceText.Replace("CannotGetAccountAccessErrorMessage",$LocalizedData.CannotGetAccountAccessErrorMessage)
        $logOnAsServiceText=$logOnAsServiceText.Replace("CannotSetAccountAccessErrorMessage",$LocalizedData.CannotSetAccountAccessErrorMessage)
        Add-Type $logOnAsServiceText -Verbose
    }

    if($userName.StartsWith(".\"))
    {
        $userName = $userName.Substring(2)
    }

    try
    {
        [LogOnAsServiceHelper.NativeMethods]::SetLogOnAsServicePolicy($userName)
    }
    catch
    {
        $errorMessage = $LocalizedData.ErrorSetingLogOnAsServiceRightsForUser -f $userName,$_.Exception.Message

        $errorCategory=[System.Management.Automation.ErrorCategory]::InvalidArgument
        $exception = New-Object System.ArgumentException $errorMessage;
        $errorRecord = New-Object System.Management.Automation.ErrorRecord $exception,"ErrorSetingLogOnAsServiceRightsForUser", $errorCategory, $null
        throw $errorRecord
    }
}

data LocalizedData
{
    # culture="en-US"
    ConvertFrom-StringData @"
ErrorSetingLogOnAsServiceRightsForUser=Error granting '{0}' the right to log on as a service. Message: '{1}'.
CannotOpenPolicyErrorMessage=Cannot open policy manager
UserNameTooLongErrorMessage=User name is too long
CannotLookupNamesErrorMessage=Failed to lookup user name
CannotOpenAccountErrorMessage=Failed to open policy for user
CannotCreateAccountAccessErrorMessage=Failed to create policy for user
CannotGetAccountAccessErrorMessage=Failed to get user policy rights
CannotSetAccountAccessErrorMessage=Failed to set user policy rights
"@
}

Export-ModuleMember -Function *-TargetResource
