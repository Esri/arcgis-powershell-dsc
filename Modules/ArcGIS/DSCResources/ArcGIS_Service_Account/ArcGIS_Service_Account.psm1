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

		[System.String[]]
		$DataDir,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,
		
		[parameter(Mandatory = $false)]
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
		$Name,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$RunAsAccount,

		[System.String[]]
		$DataDir,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,
		
		[parameter(Mandatory = $false)]
        [System.Boolean]
        $IsDomainAccount = $false
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    if($Ensure -ieq 'Present') {
        $RunAsUserName = $RunAsAccount.UserName
        $RunAsPassword = $RunAsAccount.GetNetworkCredential().Password
		$RunAsPassword = $RunAsPassword.Replace('"', '""')
   
        Write-Verbose "RunAsAccount Username:- $RunAsUserName"
        if($RunAsUserName -and $RunAsUserName.StartsWith('.\')){            
            $RunAsUserName = $RunAsUserName.Substring(2) # Remove the current machine prefix
            Write-Verbose "Removing the machine prefix for the RunAsAccount to $RunAsUserName"
        }

		$RegKey = Get-EsriRegistryKeyForService -ServiceName $Name
        $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir
        Write-Verbose "Install Dir for $Name is $InstallDir"
        if($InstallDir) 
        { 
           $InstallDir = $InstallDir.TrimEnd('\')
           if(Test-Path $InstallDir) 
           {
			   if(<#$Name -ieq 'ArcGIS Server' -OR $Name -ieq 'Portal for ArcGIS' -or#> $Name -ieq 'ArcGIS Data Store'){
					$ExecPath = $InstallDir
                    $Arguments = '/username ' + $($RunAsUserName) + ' /password "' + $($RunAsPassword) +'"'
                    Write-Verbose "Running configureserviceaccount.bat for user - $($RunAsUserName)"
                    if($Name -ieq 'ArcGIS Server'){
                        $ExecPath = Join-Path $ExecPath '\\bin\\ServerConfigurationUtility.exe'
                    }elseif($Name -ieq 'Portal for ArcGIS'){
                        $ExecPath = Join-Path $ExecPath '\\tools\\ConfigUtility\\configureserviceaccount.bat'
                    }
                    elseif($Name -ieq 'ArcGIS Data Store'){
                        $ExecPath = Join-Path $ExecPath '\\tools\\configureserviceaccount.bat'
			        }
                    Write-Verbose "Providing RunAs Account '$RunAsUserName' has the required permissions to $InstallDir"
                    Write-Verbose "configureserviceaccount $InstallDir /grant $($RunAsUserName):(OI)(CI)F"
                    
                    $psi = New-Object System.Diagnostics.ProcessStartInfo
                    $psi.FileName = $ExecPath
                    $psi.Arguments = $Arguments
                    $psi.UseShellExecute = $false #start the process from it's own executable file    
                    $psi.RedirectStandardOutput = $true #enable the process to read from standard output
                    $psi.RedirectStandardError = $true #enable the process to read from standard error
                    $psi.EnvironmentVariables["AGSPORTAL"] = [environment]::GetEnvironmentVariable("AGSPortal","Machine")
                    $psi.EnvironmentVariables["AGSDATASTORE"] = [environment]::GetEnvironmentVariable("AGSDATASTORE","Machine")
                    $psi.EnvironmentVariables["AGSSERVER"] = [environment]::GetEnvironmentVariable("AGSSERVER","Machine")
                    

                    $p = [System.Diagnostics.Process]::Start($psi)
                    $p.WaitForExit()
                    $op = $p.StandardOutput.ReadToEnd()
                    if($op -and $op.Length -gt 0) {
                        Write-Verbose "Output of execution:- $op"
                    }
                    $err = $p.StandardError.ReadToEnd()
                    
		            if($p.ExitCode -eq 0) {                    
                        Write-Verbose "Initialized correctly indicating successful desktop initialization"
                        $result = $true
                    }else {
                        Write-Verbose "Initialization did not succeed. Process exit code:- $($p.ExitCode) $err"
                    }

			   }else{
				   if(-not(Test-Acl $InstallDir $RunAsUserName $IsDomainAccount)) {
                        Write-Verbose "Providing RunAs Account '$RunAsUserName' has the required permissions to $InstallDir"
                        Write-Verbose "icacls.exe $InstallDir /grant $($RunAsUserName):(OI)(CI)F"
                        icacls.exe $InstallDir /grant "$($RunAsUserName):(OI)(CI)F"
                    }else {
                        Write-Verbose "RunAs Account '$RunAsUserName' has the required permissions to $InstallDir"
                    }   
			   }     
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
                        if(-not(Test-Acl $LocalPath $RunAsUserName $IsDomainAccount)) {
                            Write-Verbose "Permissions are not set for $LocalPath"
                            Write-Verbose "Providing RunAs Account '$RunAsUserName' the required permissions to $LocalPath"
                            Write-Verbose "icacls.exe $LocalPath /grant $($RunAsUserName):(OI)(CI)F"
                            icacls.exe $LocalPath /grant "$($RunAsUserName):(OI)(CI)F"
                        }  else {
                            Write-Verbose "RunAs Account '$RunAsUserName' has the required permissions to $LocalPath"
                        }             
                    }                
                }
            }
        }

        if($Name -ieq 'ArcGISGeoEvent') {
			###
			### GeoEvent needs additional permissions set and delete zookeeper folder
			###
			$GeoEventProgramData = Join-Path $env:ProgramData 'Esri\GeoEvent'						
			if(Test-Path $GeoEventProgramData) {
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
					Write-Verbose "Restarting Service $ServiceName"
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

				$GeoEventProgramData = Join-Path $env:ProgramData 'Esri\GeoEvent'		
				$GeoEventGatewayProgramData = Join-Path $env:ProgramData 'Esri\GeoEvent-Gateway'		

				@($GeoEventKarafDataFolder, $GeoEventGatewayLogFolder, $GeoEventProgramData, $GeoEventGatewayProgramData) | ForEach-Object{ 
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


        <#
        if(-not($DataDir) -and ($Name -ieq 'Portal for ArcGIS')) {
            $DataDir = (Get-Item ((Get-ItemProperty ("HKLM:\SOFTWARE\ESRI\$Name")).ContentDir))
        }
        if($DataDir) 
        {
            $DataDir = $DataDir.TrimEnd('\')
            if(Test-Path $DataDir) 
            {
                $acl = Get-Acl $DataDir | Select-Object -ExpandProperty Access | Where-Object {$_.IdentityReference -ieq "$env:ComputerName\$RunAsUserName"}
                if((-not($acl)) -or ($acl.FileSystemRights -ine 'FullControl') -or ($acl.AccessControlType -ine 'Allow')) {
                    Write-Verbose "Providing RunAs Account '$RunAsUserName' has the required permissiones to $DataDir"
                    Write-Verbose "icacls.exe $DataDir /grant $($RunAsUserName):(OI)(CI)F"
                    icacls.exe $DataDir /grant "$($RunAsUserName):(OI)(CI)F"

					## TEMPORARY
					if($Name -ieq 'Portal for ArcGIS') {
						$DataDirParent = Split-Path -Path $DataDir -Parent
						Write-Verbose "Providing RunAs Account '$RunAsUserName' has the required permissiones to $DataDirParent"
						Write-Verbose "icacls.exe $DataDirParent /grant $($RunAsUserName):(OI)(CI)F"
						icacls.exe $DataDirParent /grant "$($RunAsUserName):(OI)(CI)F"
					}
                }else {
                    Write-Verbose "RunAs Account '$RunAsUserName' has the required permissiones to $DataDir"
                }   
            }
        }

		if($Name -ieq 'ArcGISGeoEvent') {
			###
			### GeoEvent needs additional permissions set and delete zookeeper folder
			###
			$GeoEventProgramData = Join-Path $env:ProgramData 'Esri\GeoEvent'			
			if(Test-Path $GeoEventProgramData) {
				Write-Verbose "Program Data Dir for $Name is $GeoEventProgramData"
				$acl = Get-Acl $GeoEventProgramData | Select-Object -ExpandProperty Access | Where-Object {$_.IdentityReference -ieq "$env:ComputerName\$RunAsUserName"}
				if((-not($acl)) -or ($acl.FileSystemRights -ine 'FullControl') -or ($acl.AccessControlType -ine 'Allow')) {
                    Write-Verbose "Providing Required Permissions to Program Data Folder for RunAs Account"
                    Write-Verbose "icacls.exe $GeoEventProgramData /grant $($RunAsUserName):(OI)(CI)F"
					icacls.exe $GeoEventProgramData /grant "$($RunAsUserName):(OI)(CI)F"

                    $ZooKeeperFolder = Join-Path $GeoEventProgramData 'zookeeper'
                    if(Test-Path $ZooKeeperFolder) {
                        Write-Verbose "Deleting ZooKeeper folder $ZooKeeperFolder"
                        Remove-Item -Path $ZooKeeperFolder -Recurse -Force 
                    }
				} else {
					Write-Verbose 'Permissions to Program Data Folder for RunAs Account are already correct'
				}				
			}
		}
        #>

		if($Name -ine 'ArcGIS Data Store')  # No need to restart DataStore - the mandatory property change for 'failover_on_primary_stop' will take care of it
		{
			###
			### If the Service Credentials are changed. Restart the Service (just in case) TODO:- Revisit if this is needed
			###
			try {			    
				Write-Verbose "Restarting Service $Name"
				Stop-Service -Name $Name -Force -ErrorAction Ignore
				Write-Verbose 'Stopping the service' 
				Wait-ForServiceToReachDesiredState -ServiceName $Name -DesiredState 'Stopped'	
				Write-Verbose 'Stopped the service'		    
			}catch {
				Write-Verbose "[WARNING] Stopping Service $_"
			}
			try {				
				Write-Verbose 'Starting the service'
				Start-Service -Name $Name -ErrorAction Ignore       
				Wait-ForServiceToReachDesiredState -ServiceName $Name -DesiredState 'Running'
                Write-Verbose "Restarted Service $Name"
                if($Name -ieq 'ArcGISGeoEvent'){
                    Start-Sleep -Seconds 180
                }
			}catch {
				Write-Verbose "[WARNING] Starting Service $_"
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

		[System.String[]]
		$DataDir,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,
		
		[parameter(Mandatory = $false)]
        [System.Boolean]
        $IsDomainAccount = $false
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    $result = $true
    $RunAsUserName = $RunAsAccount.UserName
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $Name
    $InstallDir =(Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir    

    Write-Verbose "RunAsAccount Username:- $RunAsUserName"
    if($RunAsUserName -and $RunAsUserName.StartsWith('.\')){            
        $RunAsUserName = $RunAsUserName.Substring(2) # Remove the current machine prefix
        Write-Verbose "Removing the machine prefix for the RunAsAccount to $RunAsUserName"
    }

    if($InstallDir -and (Test-Path $InstallDir)) {
        Write-Verbose "Install Dir for $Name is $InstallDir"
        if(-not(Test-Acl $InstallDir $RunAsUserName $IsDomainAccount)) {
			Write-Verbose "Permissions are not set for $InstallDir"
            $result = $false
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
                        if(-not(Test-Acl $LocalPath $RunAsUserName $IsDomainAccount)) {
				            Write-Verbose "Permissions are not set for $LocalPath"
                            $result = $false
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

        [System.Boolean]
        $IsDomainAccount = $false
    )

    $result = $true
    if(-not($IsDomainAccount))
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



Export-ModuleMember -Function *-TargetResource

