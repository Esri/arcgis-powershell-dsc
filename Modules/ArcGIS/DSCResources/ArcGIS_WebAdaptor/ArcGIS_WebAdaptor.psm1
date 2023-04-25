$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

<#
    .SYNOPSIS
        Configures a WebAdaptor
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
#>

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [ValidateSet("Server","NotebookServer","MissionServer","Portal")]
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

        [parameter(Mandatory = $true)]
        [System.Boolean]
        $OverwriteFlag = $false,

        [System.Management.Automation.PSCredential]
		$SiteAdministrator,
        
        [System.Boolean]
        $AdminAccessEnabled = $true
    )

    $null 
}
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [ValidateSet("Server","NotebookServer","MissionServer","Portal")]
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

        [parameter(Mandatory = $true)]
        [System.Boolean]
        $OverwriteFlag = $false,

        [System.Management.Automation.PSCredential]
        $SiteAdministrator,
        
        [System.Boolean]
        $AdminAccessEnabled = $true
    )


    if($Ensure -ieq 'Present') {
        $WAInstalls = (Get-ArcGISProductDetails -ProductName 'ArcGIS Web Adaptor')
        $ConfigureToolPath = '\ArcGIS\WebAdaptor\IIS\Tools\ConfigureWebAdaptor.exe'
		$Version = ""
        $WAConfigureToolParentPath = ${env:CommonProgramFiles(x86)}

        foreach($wa in $WAInstalls){
            if($wa.InstallLocation -match "\\$($Context)\\"){
				$Version = $wa.Version
                if($wa.Version.StartsWith("10.7")){
                    $Version = if($wa.Name -match "10.7.1"){ "10.7.1" }else{ "10.7" }
                    $ConfigureToolPath = "\ArcGIS\WebAdaptor\IIS\$($Version)\Tools\ConfigureWebAdaptor.exe"
                    break
                }elseif($wa.Version.StartsWith("10.8")){	
                    $Version = if($wa.Name -match "10.8.1"){ "10.8.1" }else{ "10.8" }
                    $ConfigureToolPath = "\ArcGIS\WebAdaptor\IIS\$($Version)\Tools\ConfigureWebAdaptor.exe"
				    break
                }elseif($wa.Version.StartsWith("10.9")){	
                    $Version = if($wa.Name -match "10.9.1"){ "10.9.1" }else{ "10.9" }
                    $ConfigureToolPath = "\ArcGIS\WebAdaptor\IIS\$($Version)\Tools\ConfigureWebAdaptor.exe"
				    break
                }elseif($wa.Version.StartsWith("11.0")){	
                    $Version = "11.0"
                    $ConfigureToolPath = "\ArcGIS\WebAdaptor\IIS\$($Version)\Tools\ConfigureWebAdaptor.exe"
				    break
                }elseif($wa.Version.StartsWith("11.1")){	
                    $Version = "11.1"
                    $ConfigureToolPath = "\ArcGIS\WebAdaptor\IIS\$($Version)\Tools\ConfigureWebAdaptor.exe"
				    break
                }
            }        
        }
        
        $ExecPath = Join-Path ${env:CommonProgramFiles(x86)} $ConfigureToolPath
        if($Version.StartsWith("11.1")){
            $ExecPath = Join-Path ${env:CommonProgramFiles} $ConfigureToolPath
        }

        try{
            Start-RegisterWebAdaptorCMDLineTool -ExecPath $ExecPath -Component $Component -ComponentHostName $ComponentHostName -HostName $HostName -Context $Context -SiteAdministrator $SiteAdministrator -AdminAccessEnabled $AdminAccessEnabled -Version $Version
        }catch{
            $SleepTimeInSeconds = 30
            if($Component -ieq 'Portal' -and ($_ -imatch "The underlying connection was closed: An unexpected error occurred on a receive." -or $_ -imatch "The operation timed out while waiting for a response from the portal application")){
                Write-Verbose "[WARNING]:- Error:- $_."
                $PortalWAUrlHealthCheck = "https://$($HostName)/$($Context)/portaladmin/healthCheck"
                $WAUrl = "https://$($HostName)/$($Context)/webadaptor"
                try{
                    Wait-ForUrl $PortalWAUrlHealthCheck -HttpMethod 'GET' -MaxWaitTimeInSeconds 600 -SleepTimeInSeconds $SleepTimeInSeconds -ThrowErrors -Verbose -IsWebAdaptor
                }catch{
                    Write-Verbose "[WARNING]:- $_. Retrying in $SleepTimeInSeconds Seconds"
                    Start-Sleep -Seconds $SleepTimeInSeconds
                    $NumAttempts        = 2 
                    $Done               = $false
                    while (-not($Done) -and ($NumAttempts++ -le 10)){
                        try{
                            Start-RegisterWebAdaptorCMDLineTool -ExecPath $ExecPath -Component $Component -ComponentHostName $ComponentHostName -HostName $HostName -Context $Context -SiteAdministrator $SiteAdministrator -AdminAccessEnabled $AdminAccessEnabled -Version $Version
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
        Write-Verbose "Absent Not Implemented Yet!"
    }
}

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [ValidateSet("Server","NotebookServer","MissionServer","Portal")]
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

        [parameter(Mandatory = $true)]
        [System.Boolean]
        $OverwriteFlag = $false,

        [System.Management.Automation.PSCredential]
		$SiteAdministrator,
        
        [System.Boolean]
        $AdminAccessEnabled = $true
    )

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $WAInstalls = (Get-ArcGISProductDetails -ProductName 'ArcGIS Web Adaptor')
    $result = $false

    $ServerSiteURL = if($Component -ieq "NotebookServer"){"https://$($ComponentHostName):11443"}elseif($Component -ieq "MissionServer"){"https://$($ComponentHostName):20443"}else{"https://$($ComponentHostName):6443"}
    $PortalSiteUrl = "https://$($ComponentHostName):7443"

    foreach($wa in $WAInstalls){
        if($wa.InstallLocation -match "\\$($Context)\\"){
            $WAConfigPath = Join-Path $wa.InstallLocation 'WebAdaptor.config'
            $WAConfigSiteUrl = $null
            if($wa.Version.StartsWith("11.1")){
                $WAConfig = (Get-Content $WAConfigPath | ConvertFrom-Json)
                $WAConfigSiteUrl = $WAConfig.url
            }else{
                [xml]$WAConfig = Get-Content $WAConfigPath
                $WAConfigSiteUrl = if($Component -ieq "Portal"){ $WAConfig.Config.Portal.URL }else{ $WAConfig.Config.GISServer.SiteURL }
            }
            
            if((@("Server", "NotebookServer", "MissionServer") -iContains $Component) -and ($WAConfigSiteUrl -like $ServerSiteURL)){
                if($OverwriteFlag){
                    $result =  $false
                }else{
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
                }
            }elseif(($Component -ieq "Portal") -and ($WAConfigSiteUrl -like $PortalSiteUrl)){
                if($OverwriteFlag){
                    $result =  $false
                }else{
                    if(Test-URL "https://$Hostname/$Context/portaladmin"){
                        $result =  $true
                    }else{
                        $result =  $false
                    }
                }
            }else{
                $result = $false
            }
            break
        }
    }
    $result
}

function Start-RegisterWebAdaptorCMDLineTool{
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
		$Version        
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
        $Arguments = "/m server /w $WAUrl /g $SiteURL /u $($SiteAdministrator.UserName) /p $($SiteAdministrator.GetNetworkCredential().Password) /a $AdminAccessString"
    }
    elseif($Component -ieq 'NotebookServer') {
        $SiteURL = "https://$($ComponentHostName):11443"
        $WAUrl = "https://$($HostName)/$($Context)/webadaptor"
        Write-Verbose $WAUrl
        $SiteUrlCheck = "$($SiteURL)/arcgis/rest/info?f=json"
        Wait-ForUrl $SiteUrlCheck -HttpMethod 'GET'
        $WAMode = if($Version.StartsWith("10.7")){ "server" }else{ "notebook" }
        $Arguments = "/m $WAMode /w $WAUrl /g $SiteURL /u $($SiteAdministrator.UserName) /p $($SiteAdministrator.GetNetworkCredential().Password)"

        if($Version.StartsWith("10.7")){
            $AdminAccessString = "false"
            if($AdminAccessEnabled){
                $AdminAccessString = "true"
            }
            $Arguments += " /a $AdminAccessString"
        }
    }
    elseif($Component -ieq 'MissionServer') {
        $SiteURL = "https://$($ComponentHostName):20443"
        $WAUrl = "https://$($HostName)/$($Context)/webadaptor"
        Write-Verbose $WAUrl
        $SiteUrlCheck = "$($SiteURL)/arcgis/rest/info?f=json"
        Wait-ForUrl $SiteUrlCheck -HttpMethod 'GET'
        $WAMode = "mission"
        $Arguments = "/m $WAMode /w $WAUrl /g $SiteURL /u $($SiteAdministrator.UserName) /p $($SiteAdministrator.GetNetworkCredential().Password)"
    }
    elseif($Component -ieq 'Portal'){
        $SiteURL = "https://$($ComponentHostName):7443"
        $WAUrl = "https://$($HostName)/$($Context)/webadaptor"
        Write-Verbose $WAUrl
        $SiteUrlCheck = "$($SiteURL)/arcgis/sharing/rest/info?f=json"
        Wait-ForUrl $SiteUrlCheck -HttpMethod 'GET'
        $Arguments = "/m portal /w $WAUrl /g $SiteURL /u $($SiteAdministrator.UserName) /p $($SiteAdministrator.GetNetworkCredential().Password)"
        $VersionArray = $Version.Split('.')
        if(($VersionArray[0] -eq 11) -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 8) -or ($Version -ieq "10.8.1")){
            $Arguments += " /r false"
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
        Write-Verbose "Output of execution:- $op"
        if($op.StartsWith("ERROR") -or ($_ -imatch "The underlying connection was closed: An unexpected error occurred on a receive.") -or ($op -imatch "The operation timed out while waiting for a response from the portal application")){
            throw $op
        }
    }
    $err = $p.StandardError.ReadToEnd()
    if($err -and $err.Length -gt 0) {
        Write-Verbose $err
        throw $err
    }
}


function Test-URL([string]$Url){
    Write-Verbose "Checking url: $Url"

    try{
        $HTTP_Response_Available = Invoke-ArcGISWebRequest -Url $Url -HttpMethod GET -HttpFormParameters @{ f = 'json'; }
        return $true
    }catch [System.Net.WebException]{
        return $false
    }
}


Export-ModuleMember -Function *-TargetResource


