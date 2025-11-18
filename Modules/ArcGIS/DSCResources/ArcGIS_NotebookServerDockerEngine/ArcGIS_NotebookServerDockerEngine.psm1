$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

function Get-TargetResource {
    [CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
    (
        [parameter(Mandatory = $true)]
		[System.String]
        $SiteName,

        [parameter(Mandatory = $true)]
		[System.String]
        $DockerEngineBinariesArchiveUrl,

        [parameter(Mandatory = $true)]
		[System.String]
        $ServiceCredentialUsername,

        [parameter(Mandatory = $true)]
        [System.Boolean]
        $ForceUpdate
    )
    
    $null
}

function Set-TargetResource {
    [CmdletBinding()]
	param
    (
        [parameter(Mandatory = $true)]
		[System.String]
        $SiteName,

        [parameter(Mandatory = $true)]
		[System.String]
        $DockerEngineBinariesArchiveUrl,

        [parameter(Mandatory = $true)]
		[System.String]
        $ServiceCredentialUsername,

        [parameter(Mandatory = $true)]
        [System.Boolean]
        $ForceUpdate
    )

    # Check if windows container feature is enabled
    $WindowsContainerFeature = Get-WindowsFeature -Name Containers
    if($WindowsContainerFeature.Installed -eq $false){
        Write-Verbose "Enabling Windows Containers Feature"
        Enable-WindowsOptionalFeature -Online -FeatureName containers -All -NoRestart
    }
    
    $DockerInstallPath = "$Env:ProgramFiles\Docker"
    $DockerDaemonExePath = Join-Path $DockerInstallPath "dockerd.exe"
    $DockerExePath = Join-Path $DockerInstallPath "docker.exe"
    # Install Docker Engine
    # Download Docker Engine binaries from url
    $InstallDocker = $true
    if(Get-Service docker -ErrorAction Ignore){
        Write-Verbose "Docker Service is already running."
        if($ForceUpdate){
            Write-Verbose "Force Update is set to true. Stopping Docker Service"
            Stop-Service docker
            Write-Verbose "Docker Service Stopped"

            # Unregister docker service
            Write-Verbose "Unregistering Docker Service"
            &$($DockerDaemonExePath) --unregister-service
            Write-Verbose "Docker Service Unregistered"

            # Uninstall Docker 
            Write-Verbose "Uninstalling Docker Engine"
            if(Test-Path $DockerInstallPath){
                Remove-Item -Path $DockerInstallPath -Recurse -Force
            }
            Write-Verbose "Docker Engine Uninstalled"
        }else{
            Write-Verbose "Skipping Docker Engine Installation as it is already installed."
            $InstallDocker = $False
        }
    }else{
        Write-Verbose "Docker Service is not running."
    }

    if($InstallDocker){
        $DockerEnginerZipFileName = Get-FileNameFromUrl $DockerEngineBinariesArchiveUrl
        $DockerEnginerZipFilePath =  (Join-Path $env:TEMP $DockerEnginerZipFileName)
        Invoke-WebRequest -Verbose:$False -OutFile $DockerEnginerZipFilePath -Uri $DockerEngineBinariesArchiveUrl -UseBasicParsing -ErrorAction Ignore

        Write-Verbose "Installing Docker Engine"
        Expand-Archive $DockerEnginerZipFilePath -DestinationPath $Env:ProgramFiles

        # Register docker service
        &$($DockerDaemonExePath) --register-service 
        # Start docker service
        Start-Service docker
        #Test docker engine
        &$($DockerExePath) info
        Write-Verbose "Docker Engine Installed"

        #Add docker to Path
        $env:Path = $env:Path + ";$($DockerInstallPath)"
        # Add docker to the system path
        [Environment]::SetEnvironmentVariable('Path', $env:Path, [System.EnvironmentVariableTarget]::Machine)
    }

    # Create a 'docker-users' Local Group if not exists
    if (-not(Get-LocalGroup -Name 'docker-users' -ErrorAction Ignore)) {
        New-LocalGroup -Name 'docker-users' -Description 'Docker Users' 
    }else{
        Write-Verbose "Local Group 'docker-users' already exists"
    }

    # Add the service account to the 'docker-users' Local Group if not exists
    if (-not(Get-LocalGroupMember -Group 'docker-users' -Member $ServiceCredentialUsername -ErrorAction Ignore)) {   
        Add-LocalGroupMember -Group 'docker-users' -Member $ServiceCredentialUsername 
    }else{
        Write-Verbose "Service account '$($ServiceCredentialUsername)' already exists in the 'docker-users' Local Group"
    }

    $DockerConfigDirectory = "$($Env:ProgramData)\Docker\config"
    $DockerDaemonConfigurationFile = (Join-Path $DockerConfigDirectory "daemon.json")
    if(Test-Path $DockerDaemonConfigurationFile){
        $DockerDaemonConfiguration = Get-Content -Path $DockerDaemonConfigurationFile -Raw | ConvertFrom-Json
        #If not, add "group" key with value "docker-users" to the docker config file
        if(-not($DockerDaemonConfiguration.group) `
                -or ($DockerDaemonConfiguration.group -ine 'docker-users')){
            $DockerDaemonConfiguration.group = 'docker-users'
            $DockerDaemonConfiguration | ConvertTo-Json | Set-Content -Path $DockerDaemonConfigurationFile
        }else{
            Write-Verbose "Docker Daemon Configuration already has 'group' key with value 'docker-users'"
        }
    }else{
        $DockerDaemonConfiguration = @{
            group = "docker-users"
        }
        # check if config directory exists
        if(-not(Test-Path $DockerConfigDirectory)){
            New-Item -Path $DockerConfigDirectory -ItemType Directory
        }
        $DockerDaemonConfiguration | ConvertTo-Json | Set-Content -Path $DockerDaemonConfigurationFile
    }

    if(-not(Test-DockerAPIAccess)){
        Write-Verbose "Enabling Docker API Access"
        $scProcess = Start-Process "sc" -ArgumentList "config docker binpath= `"\`"C:\Program Files\docker\dockerd.exe\`" --run-service -H tcp://localhost:2375 -H npipe://`"" -Wait -Verbose -NoNewWindow -PassThru
        if($scProcess.ExitCode -eq 0) {
            Write-Verbose "Successfully updated config for docker service. Output - $($scProcess.StandardOutput)"
        }else{
            Write-Verbose "Failed to update config for docker service. Error - $($scProcess.StandardError)"
        }
        Write-Verbose "Docker API Access Enabled"
    }

    Write-Verbose "Restarting Docker Service"
    Restart-Service docker
    Write-Verbose "Docker Service Restarted"

    if(Test-DockerAPIAccess){
        Write-Verbose "Docker API is accessible"
    }else{
        Write-Verbose "[WARNING] Docker API is not accessible. Please check the Docker Engine installation."
    }
}

function Test-DockerAPIAccess {
    # Enable Docker API access
    # Check if docker api available on port 2375
    $DockerAPIPort = 2375
    $DockerAPIPortStatus = Test-NetConnection -ComputerName localhost -Port $DockerAPIPort
    if($DockerAPIPortStatus.TcpTestSucceeded -eq $false){
        Write-Verbose "Docker API is not available on port $DockerAPIPort."
    }else{
        Write-Verbose "Docker API is available on port $DockerAPIPort"
    }
    return $DockerAPIPortStatus.TcpTestSucceeded
}
function Test-TargetResource
{
    [CmdletBinding()]
	[OutputType([System.Boolean])]
	param
    (
        [parameter(Mandatory = $true)]
		[System.String]
        $SiteName,
        
        [parameter(Mandatory = $true)]
		[System.String]
        $DockerEngineBinariesArchiveUrl,

        [parameter(Mandatory = $true)]
		[System.String]
        $ServiceCredentialUsername,

        [parameter(Mandatory = $true)]
        [System.Boolean]
        $ForceUpdate
    )

    $Result = $True

    if($ForceUpdate){
        Write-Verbose "Force Update is set to true. Skipping Test-TargetResource"
        $Result = $False
    }else{
        $WindowsContainerFeature = Get-WindowsFeature -Name Containers
        if($WindowsContainerFeature.Installed -eq $false){
            $Result = $False
        }else{
            if($DockerEngineBinariesArchiveUrl){
                # Check if Docker Engine is already installed
                if(Get-Service docker -ErrorAction Ignore) { 
                    Write-Verbose "Docker Service is running."
                    # Check if the service account is added to the 'docker-users' Local Group
                    if (-not (Get-LocalGroupMember -Group 'docker-users' -Member $ServiceCredentialUsername -ErrorAction Ignore)) {   
                        Write-Verbose "Service account '$($ServiceCredentialUsername)' is not added to the 'docker-users' Local Group."
                        $Result = $False
                    }else{
                        Write-Verbose "Service account '$($ServiceCredentialUsername)' is added to the 'docker-users' Local Group."
                    }
                }else{
                    Write-Verbose "Docker Service is not running."
                    $Result = $False
                }
            }else{
                throw "[ERROR] Docker Engine Binaries Archive URL is required."
            }
        }
    }

    $Result
}

function Get-FileNameFromUrl
{
    param(
        [string]$Url
    )
    $FileName = $Url
    if($FileName) {
        $pos = $FileName.IndexOf('?')
        if($pos -gt 0) { 
            $FileName = $FileName.Substring(0, $pos) 
        } 
        $FileName = $FileName.Substring($FileName.LastIndexOf('/')+1)   
    }     
    $FileName
}

Export-ModuleMember -Function *-TargetResource
