﻿$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

<#
    .SYNOPSIS
        Makes a request to the installed Video Server to set the Web Context 
    .PARAMETER ServerHostName
        Optional Host Name or IP of the Machine on which the Video Server has been installed and is to be configured.
    .PARAMETER WebContextURL
        External Enpoint when using a reverse proxy server and the URL to your site does not end with the default string /arcgis (all lowercase). 
    .PARAMETER SiteAdministrator
        A MSFT_Credential Object - Primary Site Administrator
#>
function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
    (
        [parameter(Mandatory = $false)]    
        [System.String]
        $ServerHostName,

        [parameter(Mandatory = $true)]
        [System.String]
        $WebContextURL, 
        
        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator
    )
    
    $null
}

function Set-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(	
        [parameter(Mandatory = $false)]    
        [System.String]
        $ServerHostName,

        [parameter(Mandatory = $true)]
        [System.String]
        $WebContextURL,    
        
        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator
	)
    
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null

    if($VerbosePreference -ine 'SilentlyContinue') 
    {        
        Write-Verbose ("Site Administrator UserName:- " + $SiteAdministrator.UserName) 
    }

    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    Write-Verbose "Fully Qualified Domain Name :- $FQDN"
    $Referer = 'http://localhost'
    $ServerUrl = "https://$($FQDN):21443"
    
	Write-Verbose "Waiting for Server 'https://$($FQDN):21443/arcgis/admin' to initialize"
    Wait-ForUrl "https://$($FQDN):21443/arcgis/admin" -HttpMethod 'GET'
    #Write-Verbose 'Get Server Token'   
    $token = Get-ServerToken -ServerEndPoint "https://$($FQDN):21443" -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer
 
    $AdminSettingsModified = $False
    $systemProperties = Get-AdminSettings -ServerUrl $ServerUrl -SettingUrl "arcgis/admin/system/properties" -Token $token.token
    if($WebContextURL -and (-not($systemProperties.WebContextURL) -or $systemProperties.WebContextURL -ine $WebContextURL)){
        Write-Verbose "Web Context URL '$($systemProperties.WebContextURL)' doesn't match expected value '$WebContextURL'"
        if(-not($systemProperties.WebContextURL)){
            Add-Member -InputObject $systemProperties -MemberType NoteProperty -Name "WebContextURL" -Value $WebContextURL
        }else{
            $systemProperties.WebContextURL = $WebContextURL
        }
        $AdminSettingsModified = $True
    }
    
    if($AdminSettingsModified){
        Set-AdminSettings -ServerUrl $ServerUrl -SettingUrl "arcgis/admin/system/properties/update" -Token $token.token -Properties $systemProperties

        $MaxWaitTimeInSeconds = 120
        $SleepTimeInSeconds = 10
        $TotalElapsedTimeInSeconds = 0
        Write-Verbose "Waiting for up to $($MaxWaitTimeInSeconds) seconds for video server to restart"
        while(-not($Done) -and ($TotalElapsedTimeInSeconds -lt $MaxWaitTimeInSeconds)){
            try{
                # if available sleep and try again.
                Wait-ForUrl "$($ServerUrl)/arcgis/rest/info/healthcheck/?f=json" -MaxWaitTimeInSeconds 10 -HttpMethod 'GET' -ThrowErrors
                Write-Verbose "Video web server is still available. Trying again in $($SleepTimeInSeconds) seconds"
                Start-Sleep -Seconds $SleepTimeInSeconds
                $TotalElapsedTimeInSeconds += $SleepTimeInSeconds
            }catch{
                # if error and most likely Video server has become unavailable then exit loop
                Write-Verbose "Video server is likely restarting as result of update of system properties:- $($_)"
                $Done = $true
            }
        }
        
        Write-Verbose "Waiting up to 6 minutes for Video server healtcheck endpoint '$($ServerUrl)/arcgis/rest/info/healthcheck' to come back up"
        Wait-ForUrl "$($ServerUrl)/arcgis/rest/info/healthcheck/?f=json" -MaxWaitTimeInSeconds 360 -HttpMethod 'GET' -Verbose
        Write-Verbose "Finished waiting for Video server healtcheck endpoint '$($ServerUrl)/arcgis/rest/info/healthcheck' to come back up"
    }    
}

function Test-TargetResource
{
    [CmdletBinding()]
	[OutputType([System.Boolean])]
	param
    (   
        [parameter(Mandatory = $false)]    
        [System.String]
        $ServerHostName,
        
        [parameter(Mandatory = $true)]
        [System.String]
        $WebContextURL,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator,

        [System.Boolean]
        $DisableServiceDirectory
    )

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    Write-Verbose "Fully Qualified Domain Name :- $FQDN" 
    $Referer = 'http://localhost'
    $ServerUrl = "https://$($FQDN):21443"
    Write-Verbose "Checking for site on '$ServerUrl'"
    Wait-ForUrl -Url $ServerUrl -SleepTimeInSeconds 5 -HttpMethod 'GET'
    $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer 
    $result = ($null -ne $token.token)
    if($result){
        Write-Verbose "Site Exists. Was able to retrieve token for PSA"
    }else{
        throw "Unable to detect if Site Exists. Was NOT able to retrieve token for PSA"
    }
   
    $result = $true
    $systemProperties = Get-AdminSettings -ServerUrl $ServerUrl -SettingUrl "arcgis/admin/system/properties/" -Token $token.token
    if($result){
        if($WebContextURL){
            if(-not($systemProperties.WebContextURL) -or $systemProperties.WebContextURL -ine $WebContextURL){
                Write-Verbose "Web Context URL '$($systemProperties.WebContextURL)' doesn't match expected value '$WebContextURL'"
                $result = $false
            }
        }
    }

    $result
}

function Get-AdminSettings
{
    [CmdletBinding()]
    Param
    (
        [System.String]
        $ServerUrl,
        
        [System.String]
        $SettingUrl,
        
        [System.String]
        $Token
    )
    $RequestParams = @{ f= 'json'; token = $Token; }
    $RequestUrl  = $ServerUrl.TrimEnd("/") + "/" + $SettingUrl.TrimStart("/")
    $Response = Invoke-ArcGISWebRequest -Url $RequestUrl -HttpFormParameters $RequestParams
    Confirm-ResponseStatus $Response
    $Response
}

function Set-AdminSettings
{
    [CmdletBinding()]
    Param
    (
        [System.String]
        $ServerUrl,

        [System.String]
        $SettingUrl,
        
        [System.String]
        $Token,
        
        $Properties
    )
    $RequestUrl  = $ServerUrl.TrimEnd("/") + "/" + $SettingUrl.TrimStart("/")
    $RequestParams = @{ f= 'json'; token = $Token; properties = ( $Properties | ConvertTo-Json -Depth 5 -Compress ) }
    $Response = Invoke-ArcGISWebRequest -Url $RequestUrl -HttpFormParameters $RequestParams
    if($response.status -ieq "success"){
        Write-Verbose "Admin Settings Update Successfully"
    }else{
        Write-Verbose "[WARNING]: Code:- $($response.error.code), Error:- $($response.error.message)" 
    }
}


Export-ModuleMember -Function *-TargetResource
