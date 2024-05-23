$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

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
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer","Portal")]
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
        $JavaWebServerWebAppDirectory
    )

    $null 
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
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer","Portal")]
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
        $JavaWebServerWebAppDirectory
    )

    if($Ensure -ieq 'Present') {
        $ExecPath = ""
        if($IsJavaWebAdaptor){
            $ConfigureToolPath = '\tools\ConfigureWebAdaptor.bat'
            $JavaWAInstalls = (Get-ArcGISProductDetails -ProductName "ArcGIS Web Adaptor (Java Platform) $($Version)")
            # Assumption is that we only have one version of WA installed on the machine.
            $InstallLocation = ($JavaWAInstalls | Select-Object -First 1).InstallLocation
            $ExecPath = Join-Path $InstallLocation $ConfigureToolPath
            $ArcGISWarPath = Join-Path $InstallLocation "arcgis.war"
            $ArcGISWarDeployPath = Join-Path $JavaWebServerWebAppDirectory "$($Context).war"
            Copy-Item -Path $ArcGISWarPath -Destination $ArcGISWarDeployPath -Force
            #Waiting 30 seconds for war to auto deploy
            Start-Sleep -Seconds 30
            #Adding additional wait of upto 120 seconds for web adaptor url to be available
            Wait-ForUrl "https://$($HostName)/$($Context)/webadaptor" -MaxWaitTimeInSeconds 120 -ThrowErrors -Verbose -IsWebAdaptor

        }else{
            $ConfigureToolPath = '\ArcGIS\WebAdaptor\IIS\Tools\ConfigureWebAdaptor.exe'
            $ConfigureToolPath = "\ArcGIS\WebAdaptor\IIS\$($Version)\Tools\ConfigureWebAdaptor.exe"
            $ExecPath = Join-Path ${env:CommonProgramFiles(x86)} $ConfigureToolPath
            if($Version.StartsWith("11.1") -or $Version.StartsWith("11.2") -or $Version.StartsWith("11.3")){
                $ExecPath = Join-Path ${env:CommonProgramFiles} $ConfigureToolPath
            }
        }

        try{
            Start-ConfigureWebAdaptorCMDLineTool -ExecPath $ExecPath -Component $Component -ComponentHostName $ComponentHostName -HostName $HostName -Context $Context -SiteAdministrator $SiteAdministrator -AdminAccessEnabled $AdminAccessEnabled -Version $Version -IsJavaWebAdaptor $IsJavaWebAdaptor
        }catch{
            $SleepTimeInSeconds = 30
            if($Component -ieq 'Portal' -and ($_ -imatch "The underlying connection was closed: An unexpected error occurred on a receive." -or $_ -imatch "The operation timed out while waiting for a response from the portal application")){
                Write-Verbose "[WARNING]:- Error:- $_."
                $PortalWAUrlHealthCheck = "https://$($HostName)/$($Context)/portaladmin/healthCheck"
                #$WAUrl = "https://$($HostName)/$($Context)/webadaptor"
                try{
                    Wait-ForUrl $PortalWAUrlHealthCheck -HttpMethod 'GET' -MaxWaitTimeInSeconds 600 -SleepTimeInSeconds $SleepTimeInSeconds -ThrowErrors -Verbose -IsWebAdaptor
                }catch{
                    Write-Verbose "[WARNING]:- $_. Retrying in $SleepTimeInSeconds Seconds"
                    Start-Sleep -Seconds $SleepTimeInSeconds
                    $NumAttempts        = 2 
                    $Done               = $false
                    while (-not($Done) -and ($NumAttempts++ -le 10)){
                        try{
                            Start-ConfigureWebAdaptorCMDLineTool -ExecPath $ExecPath -Component $Component -ComponentHostName $ComponentHostName -HostName $HostName -Context $Context -SiteAdministrator $SiteAdministrator -AdminAccessEnabled $AdminAccessEnabled -Version $Version -IsJavaWebAdaptor $IsJavaWebAdaptor
                        }catch{
                            Write-Verbose "[WARNING]:- Error:- $_."
                            if($_ -imatch "The underlying connection was closed: An unexpected error occurred on a receive." -or $_ -imatch "The operation timed out while waiting for a response from the portal application"){
                                try{
                                    Wait-ForUrl $PortalWAUrlHealthCheck -HttpMethod 'GET' -MaxWaitTimeInSeconds 600 -SleepTimeInSeconds $SleepTimeInSeconds -ThrowErrors -Verbose -IsWebAdaptor
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
                }
            }else{
                throw "[ERROR]:- $_"
            }
        }
    }else{
        if($IsJavaWebAdaptor){
            # Unregister Web Adaptor
            Unregister-WebAdaptor -Component $Component -ComponentHostName $ComponentHostName -SiteAdministrator $SiteAdministrator -Referer 'http://localhost'
            
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
        [ValidateSet("Server","NotebookServer","MissionServer","VideoServer","Portal")]
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
        $JavaWebServerWebAppDirectory
    )

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null

    
    $ServerSiteURL = if($Component -ieq "NotebookServer"){"https://$($ComponentHostName):11443"}elseif($Component -ieq "MissionServer"){"https://$($ComponentHostName):20443"}elseif($Component -ieq "VideoServer"){"https://$($ComponentHostName):21443"}else{"https://$($ComponentHostName):6443"}
    $PortalSiteUrl = "https://$($ComponentHostName):7443"
    $result = $True
    $WAConfigSiteUrl = $null
    if($IsJavaWebAdaptor){
        #For JAVA Web Adaptor we will always require AGSWEBADAPTORHOME to be set.
        $AGSWEBADAPTORHOME_Path = [environment]::GetEnvironmentVariable("AGSWEBADAPTORHOME","Machine")
        if([string]::IsNullOrEmpty($AGSWEBADAPTORHOME_Path)){
            throw "AGSWEBADAPTORHOME environment variable is not set."
        }

        $JavaWAInstalls = (Get-ArcGISProductDetails -ProductName "ArcGIS Web Adaptor (Java Platform) $($Version)")
        $InstallObject = ($JavaWAInstalls | Select-Object -First 1)
        if(Test-ArcGISJavaWebAdaptorBuildNumberToMatch -InstallObjectVersion $InstallObject.Version -VersionToMatch $Version){
            $WAConfigFolder = Join-Path $InstallObject.InstallLocation $Context
            $WAConfigPath = Join-Path $WAConfigFolder 'webadaptor.config'
			if((Test-Path $WAConfigFolder) -and (Test-Path $WAConfigPath)){
                [xml]$WAConfig = Get-Content $WAConfigPath
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
                if($wa.Version.StartsWith("11.1") -or $wa.Version.StartsWith("11.2") -or $Version.StartsWith("11.3")){
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
            if((@("Server", "NotebookServer", "MissionServer","VideoServer") -iContains $Component) -and ($WAConfigSiteUrl -like $ServerSiteURL)){
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
            }elseif(($Component -ieq "Portal") -and ($WAConfigSiteUrl -like $PortalSiteUrl)){
                if(Test-URL "https://$Hostname/$Context/portaladmin"){
                    $result =  $true
                }else{
                    $result =  $false
                }
            }
            else{
                $result = $false
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
	
    $Arguments = ""
    if($Component -ieq 'Server') {
        $AdminAccessString = "false"
        if($AdminAccessEnabled){
            $AdminAccessString = "true"
        }

        $SiteURL = "https://$($ComponentHostName):6443"
        $WAUrl = "https://$($HostName)/$($Context)/webadaptor"
        Write-Verbose $WAUrl
        $SiteUrlCheck = "$($SiteURL)/arcgis/rest/info?f=json"
        Wait-ForUrl $SiteUrlCheck -HttpMethod 'GET'
        if($IsJavaWebAdaptor){
            $Arguments = "-m server -w $WAUrl -g $SiteURL -u $($SiteAdministrator.UserName) -p $($SiteAdministrator.GetNetworkCredential().Password) -a $AdminAccessString"
        }else{
            $Arguments = "/m server /w $WAUrl /g $SiteURL /u $($SiteAdministrator.UserName) /p $($SiteAdministrator.GetNetworkCredential().Password) /a $AdminAccessString"
        }
    }
    elseif($Component -ieq 'NotebookServer') {
        $SiteURL = "https://$($ComponentHostName):11443"
        $WAUrl = "https://$($HostName)/$($Context)/webadaptor"
        Write-Verbose $WAUrl
        $SiteUrlCheck = "$($SiteURL)/arcgis/rest/info?f=json"
        Wait-ForUrl $SiteUrlCheck -HttpMethod 'GET'
        $WAMode = if($Version.StartsWith("10.7")){ "server" }else{ "notebook" }
        if($IsJavaWebAdaptor){
            $Arguments = "-m $WAMode -w $WAUrl -g $SiteURL -u $($SiteAdministrator.UserName) -p $($SiteAdministrator.GetNetworkCredential().Password)"
        }else{
            $Arguments = "/m $WAMode /w $WAUrl /g $SiteURL /u $($SiteAdministrator.UserName) /p $($SiteAdministrator.GetNetworkCredential().Password)"
        }

        if($Version.StartsWith("10.7")){
            $AdminAccessString = "false"
            if($AdminAccessEnabled){
                $AdminAccessString = "true"
            }
            if($IsJavaWebAdaptor){
                $Arguments += " -a $AdminAccessString"
            }else{
                $Arguments += " /a $AdminAccessString"
            }
        }
    }
    elseif($Component -ieq 'MissionServer') {
        $SiteURL = "https://$($ComponentHostName):20443"
        $WAUrl = "https://$($HostName)/$($Context)/webadaptor"
        Write-Verbose $WAUrl
        $SiteUrlCheck = "$($SiteURL)/arcgis/rest/info?f=json"
        Wait-ForUrl $SiteUrlCheck -HttpMethod 'GET'
        $WAMode = "mission"
        if($IsJavaWebAdaptor){
            $Arguments = "-m $WAMode -w $WAUrl -g $SiteURL -u $($SiteAdministrator.UserName) -p $($SiteAdministrator.GetNetworkCredential().Password)"
        }else{
            $Arguments = "/m $WAMode /w $WAUrl /g $SiteURL /u $($SiteAdministrator.UserName) /p $($SiteAdministrator.GetNetworkCredential().Password)"
        }
    }elseif($Component -ieq 'VideoServer') {
        $SiteURL = "https://$($ComponentHostName):21443"
        $WAUrl = "https://$($HostName)/$($Context)/webadaptor"
        Write-Verbose $WAUrl
        $SiteUrlCheck = "$($SiteURL)/arcgis/rest/info?f=json"
        Wait-ForUrl $SiteUrlCheck -HttpMethod 'GET'
        $WAMode = "video"
        if($IsJavaWebAdaptor){
            $Arguments = "-m $WAMode -w $WAUrl -g $SiteURL -u $($SiteAdministrator.UserName) -p $($SiteAdministrator.GetNetworkCredential().Password)"
        }else{
            $Arguments = "/m $WAMode /w $WAUrl /g $SiteURL /u $($SiteAdministrator.UserName) /p $($SiteAdministrator.GetNetworkCredential().Password)"
        }
    }
    elseif($Component -ieq 'Portal'){
        $SiteURL = "https://$($ComponentHostName):7443"
        $WAUrl = "https://$($HostName)/$($Context)/webadaptor"
        Write-Verbose $WAUrl
        $SiteUrlCheck = "$($SiteURL)/arcgis/sharing/rest/info?f=json"
        Wait-ForUrl $SiteUrlCheck -HttpMethod 'GET'
        if($IsJavaWebAdaptor){
            $Arguments = "-m portal -w $WAUrl -g $SiteURL -u $($SiteAdministrator.UserName) -p $($SiteAdministrator.GetNetworkCredential().Password)"
        }else{
            $Arguments = "/m portal /w $WAUrl /g $SiteURL /u $($SiteAdministrator.UserName) /p $($SiteAdministrator.GetNetworkCredential().Password)"
        }

        $VersionArray = $Version.Split('.')
        if(($VersionArray[0] -eq 11) -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 8) -or ($Version -ieq "10.8.1")){
            if($IsJavaWebAdaptor){
                $Arguments += " -r false"
            }else{
                $Arguments += " /r false"
            }
        }
    }
	
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
        if($op.trim().StartsWith("ERROR") -or ($_ -imatch "The underlying connection was closed: An unexpected error occurred on a receive.") -or ($op -imatch "The operation timed out while waiting for a response from the portal application")){
            throw $op
        }
    }
    $err = $p.StandardError.ReadToEnd()
    if($err -and $err.Length -gt 0) {
        Write-Verbose $err
        throw $err
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
        Invoke-ArcGISWebRequest -Url $Url -HttpMethod GET -HttpFormParameters @{ f = 'json'; }
		Write-Verbose "$Url is accessible."
        return $true
    }catch [System.Net.WebException]{
        return $false
    }
}

function Unregister-WebAdaptor{
    [CmdletBinding()]
    param(
        $Component,

		[System.String]
		$HostName, 

        [System.String]
		$ComponentHostName, 

        [System.Management.Automation.PSCredential]
        $SiteAdministrator,

        [System.String]
		$Referer = 'http://localhost'
    )

    $token = $null
    $WASystemUrl = ""
    if($Component -ieq "Portal"){
        $token = Get-PortalToken -PortalHostName $ComponentHostName -Credential $SiteAdministrator -Referer $Referer
        $WASystemUrl = "https://$($ComponentHostName):7443/arcgis/portaladmin/system/webadaptors"
    }else{
        $ServerUrl = if($Component -ieq "NotebookServer"){"https://$($ComponentHostName):11443"}elseif($Component -ieq "MissionServer"){"https://$($ComponentHostName):20443"}elseif($Component -ieq "VideoServer"){"https://$($ComponentHostName):21443"}else{"https://$($ComponentHostName):6443"}
        $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer 
        $WASystemUrl = "$($ServerUrl)/arcgis/admin/system/webadaptors"
    }
   
    $WebAdaptors = Invoke-ArcGISWebRequest -HttpMethod "GET" -Url $WASystemUrl -HttpFormParameters @{ token = $token.token; f = 'json' } -Referer $Referer
    
    $WebAdaptors.webAdaptors | ForEach-Object {
        $WebAdaptorUrl = "https://$($HostName)/$($Context)"
        if($_.webAdaptorURL -ieq  $WebAdaptorUrl) {
            Write-Verbose "Webadaptor with URL $($_.webAdaptorURL) exists. Unregistering the web adaptor"
            Invoke-ArcGISWebRequest -Url ("$($WASystemUrl)/$WebAdaptorId/unregister") -HttpFormParameters  @{ f = 'json'; token = $token.token } -Referer $Referer -TimeoutSec 300    
        }
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
        "10.4.1" {  "10.7.5686" }
        "10.5.0" { "10.7.6491" }
        "10.5.1" { "10.7.7333" }
        "10.6.0" { "10.7.8321" }
        "10.6.1" { "10.7.9270" }
        "10.7.0" { "10.7.10450" }
        "10.7.1" { "10.7.11595" }
        "10.8.0" { "10.8.12790" }
        "10.8.1" { "10.8.14362" }
        "10.9.0" { "10.9.26417" }
        "10.9.1" { "10.9.28388" }
        "11.1" { "11.1" }
        "11.2" { "11.2" }
        "11.3" { "11.3" }
        Default {
            throw "Version $VersionToMatch not supported"
        }
    }

    return $InstallObjectVersion -imatch $VersionWithBuild
}


Export-ModuleMember -Function *-TargetResource