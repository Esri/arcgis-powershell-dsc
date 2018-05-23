<#
    .SYNOPSIS
        Runs security scans for ArcGIS Server or ArcGIS Portal
    .PARAMETER Ensure
        Take the values Present or Absent.
        - "Present" ensures that security scan is ran.
        - "Absent" ensures that security scan is not ran.
    .PARAMETER SiteAdministrator
         A MSFT_Credential Object - Primary Site Adminstrator
    .PARAMETER PortalAdministrator
         A MSFT_Credential Object - Initial Adminstrator Account
    .PARAMETER HostName
        Host name of the machine the scan is performed
    .PARAMETER ComponentName
        Name of the ArcGIS component to scan
    .PARAMETER OutputPath
        Path where Results should be output
#>

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator,

        [parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        $PortalAdministrator,

        [parameter(Mandatory = $true)]
		[System.String]
		$HostName,

        [parameter(Mandatory = $true)]
		[System.String]
		$ComponentName,

        [parameter(Mandatory = $true)]
        [System.String]
        $OutputPath
    )

    $null
}

function Set-TargetResource
{
    [CmdletBinding()]
    param (
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator,

        [parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        $PortalAdministrator,

        [parameter(Mandatory = $true)]
		[System.String]
		$HostName,

        [parameter(Mandatory = $true)]
		[System.String]
		$ComponentName,

        [parameter(Mandatory = $true)]
        [System.String]
        $OutputPath
    )

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    if($Ensure -eq 'Present'){
        if($ComponentName -eq 'Server'){
            $ServiceName = 'ArcGIS Server'
            $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
            $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir
            Write-Verbose "Installation Directory: $InstallDir"

            $ScriptPath = Join-Path $InstallDir 'tools\admin\serverScan.py'
            $Arguments = "-n $HostName -u $($SiteAdministrator.UserName) -p $($SiteAdministrator.GetNetworkCredential().Password) -o $OutputPath"
            Write-Verbose "Running: $ScriptPath $Arguments"

            Start-Process -FilePath $ScriptPath -ArgumentList $Arguments -Wait
            }elseif($ComponentName -eq 'Portal'){
                $ServiceName = 'Portal for ArcGIS'
                $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
                $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir
                Write-Verbose "Installation Directory: $InstallDir"

                $ScriptPath = Join-Path $InstallDir 'tools\security\portalScan.py'
                $Arguments = "-n $HostName -u $($PortalAdministrator.UserName) -p $($PortalAdministrator.GetNetworkCredential().Password) -o $OutputPath"
                Write-Verbose "Running: $ScriptPath $Arguments"

                Start-Process -FilePath $ScriptPath -ArgumentList $Arguments -Wait
            }
    }elseif($Ensure -eq 'Absent'){}
}

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator,

        [parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        $PortalAdministrator,

        [parameter(Mandatory = $true)]
		[System.String]
		$HostName,

        [parameter(Mandatory = $true)]
		[System.String]
		$ComponentName,

        [parameter(Mandatory = $true)]
        [System.String]
        $OutputPath
    )

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    $Result = [System.Boolean]
    $IsInstalled = $null
    $Result = $true

    if($ComponentName -eq 'Server'){
        Try{
            $IsInstalled = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like '*ArcGIS*Server*'} | Select-Object DisplayName | Select-Object -First 1
            if($IsInstalled -ne $null){
                Write-Verbose "ArcGIS Server is installed"
                $ServerUrl = "https://$($HostName):6443"
                $Referer = $ServerUrl
                Try{
                    $Token = Get-ServerToken -ServerEndPoint $ServerUrl -Credential $SiteAdministrator -Referer $Referer
                }Catch{}

                if(-not($Token.token)){
                    Write-Verbose "Unable to retrieve token for Site Administrator"
                }else{
                    Write-Verbose "Server site seems to be configured"
                    $Result = $false
                }
            }else{
                Write-Verbose "ArcGIS Server is not installed"
            }
            }Catch{}
        }elseif($ComponentName -eq 'Portal'){
        Try{
            $IsInstalled = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like '*Portal*ArcGIS*'} | Select-Object DisplayName | Select-Object -First 1
            if($IsInstalled -ne $null){
                Write-Verbose "ArcGIS Portal is installed"
                $PortalUrl = "https://$($HostName):7443"
                $Referer = $PortalUrl
                Try{
                    $Token = Get-PortalToken -PortalHostName $HostName -Credential $PortalAdministrator -Referer $Referer
                }Catch{}

                if(-not($Token.token)){
                    Write-Verbose "Unable to retrieve token for Portal Administrator"
                }else{
                    Write-Verbose "Portal site seems to be configured"
                    $Result = $false
                }
            }else{
                Write-Verbose "ArcGIS Portal is not installed"
            }
            }Catch{}
        }
    $Result
}

Export-ModuleMember -Function *-TargetResource