$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.Portal.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.Server.psm1'))

<#
    .SYNOPSIS
        Configures a WebAdaptor
    .PARAMETER Version
        String to indicate the Version of WebAdaptor installed
    .PARAMETER Ensure
        Take the values Present or Absent. 
        - "Present" ensures that WebAdaptor is Configured.
        - "Absent" ensures that WebAdaptor is unconfigured - Not Implemented.
    .PARAMETER Component
        Sets the type of WebAdaptor to be installed - Server, Notebook Server, Mission Server or Portal
    .PARAMETER HostName
        Host Name of the Machine on which the WebAdaptor is Installed
    .PARAMETER ComponentHostName
        Host Name of the Server or Portal to be configured with the WebAdaptor
    .PARAMETER Context
        Context with which the WebAdaptor is to be Configured, same as the one with which it was installed.
    .PARAMETER OverwriteFlag
        Boolean to indicate whether overwrite of the webadaptor settings already configured should take place or not.
    .PARAMETER SiteAdministrator
        A MSFT_Credential Object - Primary Site Administrator.
    .PARAMETER AdminAccessEnabled
        Boolean to indicate whether Admin Access to Sever Admin API and Manager is enabled or not. Default - True
    .PARAMETER IsJavaWebAdaptor
        Boolean to indicate whether using Java WebAdaptor or IIS WebAdaptor. Default - False
    .PARAMETER JavaWebServerWebAppDirectory
        String Path to web server's web application directory. Default value is ''
    .PARAMETER JavaWebServerType
        String to indicate the Java web server type
#>

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory = $True)]    
        [System.String]
        $Version,

        [ValidateSet("Present","Absent")]
        [parameter(Mandatory = $True)]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer", "DataPipelinesServer","Portal","Monitor")]
        [System.String]
        $Component,

        [parameter(Mandatory = $true)]
		[System.String]
		$HostName,

		[parameter(Mandatory = $true)]
		[System.String]
		$ComponentHostName,

        [parameter(Mandatory = $true)]
        [System.String]
        $Context,

        [parameter(Mandatory = $False)]
        [System.Boolean]
        $OverwriteFlag = $false,

        [System.Management.Automation.PSCredential]
		$SiteAdministrator,
        
        [System.Boolean]
        $AdminAccessEnabled = $true,

        [System.Boolean]
        $IsJavaWebAdaptor = $False,

        [System.String]
        $JavaWebServerWebAppDirectory,

        [System.String]
        $JavaWebServerType
    )

    @{}
}
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $True)]    
        [System.String]
        $Version,

        [ValidateSet("Present","Absent")]
        [parameter(Mandatory = $True)]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer","DataPipelinesServer","Portal","Monitor")]
        [System.String]
        $Component,

        [parameter(Mandatory = $true)]
		[System.String]
		$HostName,

		[parameter(Mandatory = $true)]
		[System.String]
		$ComponentHostName,

        [parameter(Mandatory = $true)]
        [System.String]
        $Context,

        [parameter(Mandatory = $False)]
        [System.Boolean]
        $OverwriteFlag = $false,

        [System.Management.Automation.PSCredential]
        $SiteAdministrator,
        
        [System.Boolean]
        $AdminAccessEnabled = $true,

        [System.Boolean]
        $IsJavaWebAdaptor = $False,

        [System.String]
        $JavaWebServerWebAppDirectory,

        [System.String]
        $JavaWebServerType
    )

    if($Ensure -ieq 'Present') {
        $ExecPath = ""
        if($IsJavaWebAdaptor){
            $ConfigureToolPath = '\tools\ConfigureWebAdaptor.bat'
            $JavaWAInstalls = (Get-ArcGISProductDetails -ProductName "ArcGIS Web Adaptor (Java Platform) $($Version)")
            # Assumption is that we only have one version of WA installed on the machine.
            $InstallLocation = ($JavaWAInstalls | Select-Object -First 1).InstallLocation
            $ExecPath = Join-Path $InstallLocation $ConfigureToolPath
            $ArcGISWarFile = "arcgis.war"  # Default value
            if([version]$Version -lt [version]"12.0"){
                switch ($JavaWebServerType) {
                    "ApacheTomcat10" { $ArcGISWarFile = "arcgis_tomcat10.war" }
                    Default { $ArcGISWarFile = "arcgis.war" }
                }
            }

            Write-Verbose "ArcGISWarFile is: $ArcGISWarFile"
            $ArcGISWarPath = Join-Path $InstallLocation $ArcGISWarFile
            $ArcGISWarDeployPath = Join-Path $JavaWebServerWebAppDirectory "$($Context).war"
            Write-Verbose "ArcGISWarPath is: $ArcGISWarPath"
            Write-Verbose "ArcGISWarDeployPath is: $ArcGISWarDeployPath"
            Copy-Item -Path $ArcGISWarPath -Destination $ArcGISWarDeployPath -Force
            #Waiting 30 seconds for war to auto deploy
            Start-Sleep -Seconds 30
            #Adding additional wait of upto 120 seconds for web adaptor url to be available
            Wait-ForUrl "https://$($HostName)/$($Context)/webadaptor" -MaxWaitTimeInSeconds 120 -ThrowErrors $true -Verbose -IsWebAdaptor $true

        }else{
            $ConfigureToolPath = '\ArcGIS\WebAdaptor\IIS\Tools\ConfigureWebAdaptor.exe'
            $ConfigureToolPath = "\ArcGIS\WebAdaptor\IIS\$($Version)\Tools\ConfigureWebAdaptor.exe"
            $ExecPath = Join-Path ${env:CommonProgramFiles(x86)} $ConfigureToolPath
            if(@("11.1", "11.2", "11.3", "11.4", "11.5", "12.0", "12.1", "12.2") -icontains $Version){
                $ExecPath = Join-Path ${env:CommonProgramFiles} $ConfigureToolPath
            }
        }

        $NumAttempts = 0
        while (-not($Done) -and ($NumAttempts++ -le 10)){
            try{
                Start-ConfigureWebAdaptorCMDLineTool -ExecPath $ExecPath -Component $Component -ComponentHostName $ComponentHostName -HostName $HostName -Context $Context -SiteAdministrator $SiteAdministrator -AdminAccessEnabled $AdminAccessEnabled -Version $Version -IsJavaWebAdaptor $IsJavaWebAdaptor -Verbose
                $Done = $true
            }catch{
                $SleepTimeInSeconds = 30
                if($Component -ieq 'Portal' -and ($_ -imatch "The underlying connection was closed: An unexpected error occurred on a receive." -or $_ -imatch "The operation timed out while waiting for a response from the portal application")){
                    Write-Verbose "[WARNING]:- Error:- $_."
                    try{
                        $PortalWABaseURL = "https://$($HostName)/$($Context)"
                        Test-ArcGISComponentHealth -BaseURL $PortalWABaseURL -ComponentName "Portal" -MaxWaitTimeInSeconds 600 -SleepTimeInSeconds $SleepTimeInSeconds -ThrowErrors $true -Verbose -IsWebAdaptor $true
                        $Done = $true
                    }catch{
                        Write-Verbose "[WARNING]:- $_. Retrying in $SleepTimeInSeconds Seconds"
                        Start-Sleep -Seconds $SleepTimeInSeconds
                    }
                }else{
                    throw "[ERROR]:- $_"
                }
            }
        }
    }else{
        if($IsJavaWebAdaptor){
            # Unregister Web Adaptor
            Unregister-WebAdaptor -Component $Component -ComponentHostName $ComponentHostName -SiteAdministrator $SiteAdministrator -Referer 'https://localhost'
            
            # Remove war file
            $ArcGISWarDeployPath = Join-Path $JavaWebServerWebAppDirectory "$($Context).war"
			Remove-Item $ArcGISWarDeployPath -Force -ErrorAction Ignore
            #Waiting 30 seconds for war to auto remove
            Start-Sleep -Seconds 30
            
            $JavaWAInstalls = (Get-ArcGISProductDetails -ProductName "ArcGIS Web Adaptor (Java Platform) $($Version)")
            # Remove Web Adaptor Config File
            $InstallObject = ($JavaWAInstalls | Select-Object -First 1)
            if(Test-ArcGISJavaWebAdaptorBuildNumberToMatch -InstallObjectVersion $InstallObject.Version -VersionToMatch $Version){
                $WAConfigFolder = (Join-Path $InstallObject.InstallLocation $Context)
                $WAConfigPath = Join-Path $WAConfigFolder 'webadaptor.config'
                if((Test-Path $WAConfigFolder) -and (Test-Path $WAConfigPath)){
                    $WAConfigPath = Join-Path $WAConfigFolder 'webadaptor.config'
                    Remove-Item $WAConfigPath -Force -ErrorAction Ignore
                }
            }
        }else{
            Write-Verbose "Absent Not Implemented Yet!"
        }
    }
}

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [parameter(Mandatory = $True)]    
        [System.String]
        $Version,

        [ValidateSet("Present","Absent")]
        [parameter(Mandatory = $True)]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer","DataPipelinesServer","Portal","Monitor")]
        [System.String]
        $Component,

        [parameter(Mandatory = $true)]
		[System.String]
		$HostName,

		[parameter(Mandatory = $true)]
		[System.String]
		$ComponentHostName,

        [parameter(Mandatory = $true)]
        [System.String]
        $Context,

        [parameter(Mandatory = $False)]
        [System.Boolean]
        $OverwriteFlag = $false,

        [System.Management.Automation.PSCredential]
		$SiteAdministrator,
        
        [System.Boolean]
        $AdminAccessEnabled = $true,

        [System.Boolean]
        $IsJavaWebAdaptor = $False,

        [System.String]
        $JavaWebServerWebAppDirectory,

        [System.String]
        $JavaWebServerType
    )

    $result = $True
    $WAConfigSiteUrl = $null
    if($IsJavaWebAdaptor){
        #For JAVA Web Adaptor we will always require AGSWEBADAPTORHOME to be set.
        $AGSWEBADAPTORHOME_Path = Get-JavaWebAdaptorHome
        if([string]::IsNullOrEmpty($AGSWEBADAPTORHOME_Path)){
            throw "AGSWEBADAPTORHOME environment variable is not set."
        }

        $JavaWAInstalls = (Get-ArcGISProductDetails -ProductName "ArcGIS Web Adaptor (Java Platform) $($Version)")
        $JavaWAInstalls = Get-ArcGISProductDetails -ProductName "ArcGIS Web Adaptor (Java Platform) $($Version)"
        if (-not $JavaWAInstalls) {
            Write-Verbose "No Java Web Adaptor installation found for version $Version."
            $result = $False
            return $result
        }
        $InstallObject = ($JavaWAInstalls | Select-Object -First 1)
        if (-not $InstallObject) {
            Write-Verbose "Install object is null for version $Version."
            $result = $False
            return $result
        }
        if(Test-ArcGISJavaWebAdaptorBuildNumberToMatch -InstallObjectVersion $InstallObject.Version -VersionToMatch $Version){
            Write-Verbose "Java Web Adaptor build number matches $Version."
            $WAConfigFolder = Join-Path $InstallObject.InstallLocation $Context
            $WAConfigPath = Join-Path $WAConfigFolder 'webadaptor.config'
            Write-Verbose "WAConfigFolder folder is: $WAConfigFolder"
            Write-Verbose "WAConfigPath file is: $WAConfigPath"
			if((Test-Path $WAConfigFolder) -and (Test-Path $WAConfigPath)){
                try {
                    [xml]$WAConfig = Get-Content $WAConfigPath -ErrorAction Stop
                } catch {
                    Write-Verbose "Error reading webadaptor config file at '$WAConfigPath': $_"
                    $result = $False
                    return $result
                }
                $WAConfigSiteUrl = if($Component -ieq "Portal"){ $WAConfig.Config.WebServer.Portal.URL }else{ $WAConfig.Config.WebServer.GISServer.SiteURL }
            }else{
                Write-Verbose "No config file found for webadaptor at '$($WAConfigFolder)'"
                $result = $False
            }
        }else{
            Write-Verbose "Installed Java Web Adaptor version doesn't match $Version"
            $result = $False
        }
    }else{
        $ExistingWA = $False
        $IISWAInstalls = (Get-ArcGISProductDetails -ProductName 'ArcGIS Web Adaptor')
        foreach($wa in $IISWAInstalls){
            if($wa.InstallLocation -match "\\$($Context)\\"){
                $WAConfigPath = Join-Path $wa.InstallLocation 'WebAdaptor.config'
                $WAConfigSiteUrl = $null
                if(@("11.1", "11.2", "11.3", "11.4", "11.5", "12.0", "12.1", "12.2") -icontains $Version){
                    $WAConfig = (Get-Content $WAConfigPath | ConvertFrom-Json)
                    $WAConfigSiteUrl = if($Component -ieq "Portal"){ $WAConfig.portal.url }else{ $WAConfig.gisserver.url }
                }else{
                    [xml]$WAConfig = Get-Content $WAConfigPath
                    $WAConfigSiteUrl = if($Component -ieq "Portal"){ $WAConfig.Config.Portal.URL }else{ $WAConfig.Config.GISServer.SiteURL }
                }
                $ExistingWA = $True
                break
            }
        }

        if(-not($ExistingWA)){
            Write-Verbose "None of the installed IIS Web Adaptors' version match $Version"
            $result = $False
        }
    }
    
    if($OverwriteFlag -or -not($result)){
        $result =  $false
    }else{
        if($Ensure -ieq 'Present'){ # Only do this check when the web adaptor is to be configured
            $Port = Get-ArcGISEnterpriseComponentPort -ComponentName $Component 
            $SiteURL = "https://$($ComponentHostName):$($Port)"
            if($WAConfigSiteUrl -like $SiteURL){
                if((@("Server", "NotebookServer", "MissionServer","DataPipelinesServer","VideoServer") -iContains $Component)){
                    if (Test-URL "https://$Hostname/$Context/admin"){
                        if($Component -ieq "Server"){
                            $result = if(-not($AdminAccessEnabled)){ $false }else{ $true }
                        }else{
                            $result =  $true
                        }
                    }else{
                        if($Component -ieq "Server"){
                            $result = if($AdminAccessEnabled){ $false }else{ $true }
                        }else{
                            $result =  $false
                        }
                    }
                }elseif($Component -ieq "Portal"){
                    if(Test-URL "https://$Hostname/$Context/portaladmin"){
                        $result =  $true
                    }else{
                        $result =  $false
                    }
                }elseif($Component -ieq "Monitor"){
                    if(Test-URL "https://$Hostname/$Context/monitor"){
                        $result =  $true
                    }else{
                        $result =  $false
                    }
                }else{
                    $result= $False
                }
            }else{
                $result= $False
            }
        }
    }
        
    if($Ensure -ieq 'Present') {
        $result
    }elseif($Ensure -ieq 'Absent') {        
        -not($result)
    }
}

function Start-ConfigureWebAdaptorCMDLineTool{
    [CmdletBinding()]
    param (
        [System.String]
        $ExecPath,

        [System.String]
        $Component,

        [parameter(Mandatory = $true)]
		[System.String]
		$HostName,

		[parameter(Mandatory = $true)]
		[System.String]
		$ComponentHostName,

        [parameter(Mandatory = $true)]
        [System.String]
        $Context,

        [System.Management.Automation.PSCredential]
        $SiteAdministrator,
        
        [System.Boolean]
        $AdminAccessEnabled = $false,

        [System.String]
		$Version,

        [System.Boolean]
        $IsJavaWebAdaptor = $False
    )
	
    $WAMode = ""
    switch ($Component) {
        "Server"             { $WAMode = "server"; break }   
        "NotebookServer"     { $WAMode = "notebook"; break }
        "MissionServer"      { $WAMode = "mission"; break }
        "VideoServer"        { $WAMode = "video"; break }
        "DataPipelinesServer"{ $WAMode = "datapipelines"; break }
        "Monitor"            { $WAMode = "monitor"; break }
        "Portal"             { $WAMode = "portal"; break }
        Default { }
    }

    $Port = Get-ArcGISEnterpriseComponentPort -ComponentName $Component
    $SiteURL = "https://$($ComponentHostName):$($Port)"
    $WAUrl = "https://$($HostName)/$($Context)/webadaptor"
    Write-Verbose "SiteURL - $SiteURL, WA URL - $WAUrl"
    Test-ArcGISComponentHealth -BaseURL "$($SiteURL)/arcgis" -ComponentName $Component

    $EscapedSiteAdministratorPassword = $SiteAdministrator.GetNetworkCredential().Password.Replace('"', '\"')
    $Arguments = ""
    if($IsJavaWebAdaptor){
        $Arguments = "-m $WAMode -w $WAUrl -g $SiteURL -u $($SiteAdministrator.UserName) -p `"$EscapedSiteAdministratorPassword`""
    }else{
        $Arguments = "/m $WAMode /w $WAUrl /g $SiteURL /u $($SiteAdministrator.UserName) /p `"$EscapedSiteAdministratorPassword`""
    }

    if($Component -ieq 'Server') {
        $AdminAccessString = "false"
        if($AdminAccessEnabled){
            $AdminAccessString = "true"
        }
        $Arguments += if($IsJavaWebAdaptor){ " -a $AdminAccessString" }else{ " /a $AdminAccessString" }
    }

    if($Component -ieq 'Portal'){
        if($IsJavaWebAdaptor){
            $Arguments += " -r false"
        }else{
            $Arguments += " /r false"
        }
    }

    $op = $null
    try{
        $ProcessParameters = @{
            ExecPath = $ExecPath
            Arguments = $Arguments
        }
        if($IsJavaWebAdaptor){
            $ProcessParameters["EnvVariables"] = Get-JavaWebAdaptorEnvironment
        }
        $op = Invoke-StartProcess @ProcessParameters -Verbose
		if(($null -eq $op) -or $op.trim().StartsWith("ERROR") -or ($op -imatch "The underlying connection was closed: An unexpected error occurred on a receive.") -or ($op -imatch "The operation timed out while waiting for a response from the portal application")){
            throw "Web Adaptor configuration failed. Error - $op"
        }else{
            Write-Verbose "Configuration successful."
        }
    }catch{
        throw "Web Adaptor configuration failed. Error - $_. $op"
    }
}

function Get-JavaWebAdaptorHome {
    [Environment]::GetEnvironmentVariable('AGSWEBADAPTORHOME', 'Machine')
}

function Get-JavaWebAdaptorEnvironment {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [System.String]
        $MachinePath = [Environment]::GetEnvironmentVariable('PATH', 'Machine'),

        [System.String]
        $JavaHome = [Environment]::GetEnvironmentVariable('JAVA_HOME', 'Machine'),

        [System.String]
        $JreHome = [Environment]::GetEnvironmentVariable('JRE_HOME', 'Machine'),

        [System.String]
        $WebAdaptorHome = [Environment]::GetEnvironmentVariable('AGSWEBADAPTORHOME', 'Machine')
    )

    $JavaDirectory = if (-not [string]::IsNullOrWhiteSpace($JavaHome)) { $JavaHome } else { $JreHome }
    if ([string]::IsNullOrWhiteSpace($JavaDirectory)) {
        throw 'JAVA_HOME or JRE_HOME must be set at machine scope to locate java.exe for Java Web Adaptor configuration.'
    }

    $JavaBin = Join-Path -Path $JavaDirectory -ChildPath 'bin'
    $JavaPath = Join-Path -Path $JavaBin -ChildPath 'java.exe'
    if (-not (Test-Path -LiteralPath $JavaPath -PathType Leaf)) {
        throw "java.exe not found at '$JavaPath'."
    }

    $ChildPath = $JavaBin
    if (-not [string]::IsNullOrWhiteSpace($MachinePath)) {
        $ChildPath += ";$MachinePath"
    }

    return @{
        PATH = $ChildPath
        JAVA_HOME = $JavaHome
        JRE_HOME = $JreHome
        AGSWEBADAPTORHOME = $WebAdaptorHome
    }
}

function Test-URL
{
    [CmdletBinding()]
    param (
        [System.String]
        $Url
    )

    Write-Verbose "Checking url: $Url"

    try{
        Wait-ForUrl $Url -HttpMethod 'GET' -Verbose -ThrowErrors $true
        Write-Verbose "$Url is accessible."
        return $true
    }catch{
        Write-Verbose "$Url is not accessible. $_"
        return $false
    }
}

function Unregister-WebAdaptor{
    [CmdletBinding()]
    param(
        [System.String]
        $Component,

		[System.String]
		$HostName, 

        [System.String]
		$ComponentHostName, 

        [System.Management.Automation.PSCredential]
        $SiteAdministrator,

        [System.String]
		$Referer = 'https://localhost'
    )

    $WebAdaptorUrl = "https://$($HostName)/$($Context)"
    $token = $null
    if($Component -ieq "Portal"){
        $PortalBaseURL = Get-ArcGISComponentBaseUrl -ComponentName "Portal" -FQDN $ComponentHostName
        $token = Get-PortalToken -URL $PortalBaseURL -Credential $SiteAdministrator -Referer $Referer
        Unregister-PortalWebAdaptor -URL $PortalBaseURL -WebAdaptorURL $WebAdaptorUrl -Referer $Referer -Token $token.token
    }else{
        $ServerBaseURL = Get-ArcGISComponentBaseUrl -ComponentName $Component -FQDN $ComponentHostName
        $token = Get-ServerToken -URL $ServerBaseURL -Credential $SiteAdministrator -Referer $Referer
        Unregister-ServerWebAdaptor -URL $ServerBaseURL -WebAdaptorURL $WebAdaptorUrl -Referer $Referer -Token $token.token
    }
}

function Test-ArcGISJavaWebAdaptorBuildNumberToMatch
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [System.String]
        $InstallObjectVersion,

        [System.String]
        $VersionToMatch
    )

    $VersionWithBuild = switch ($VersionToMatch) {
        "10.9.1" { "10.9.28388" }
        "11.0" { "11.0" }
        "11.1" { "11.1" }
        "11.2" { "11.2" }
        "11.3" { "11.3" }
        "11.4" { "11.4" }
        "11.5" { "11.5" }
        "12.0" { "12.0" }
        "12.1" { "12.1" }
        "12.2" { "12.2" }
        Default {
            throw "Version $VersionToMatch not supported"
        }
    }

    return $InstallObjectVersion -imatch $VersionWithBuild
}

Export-ModuleMember -Function *-TargetResource