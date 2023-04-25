$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

<#
    .SYNOPSIS
        Makes a request to the installed Mission Server to set the Web Context & Web Socket URL  
    .PARAMETER ServerHostName
        Optional Host Name or IP of the Machine on which the Mission Server has been installed and is to be configured.
    .PARAMETER WebContextURL
        External Enpoint when using a reverse proxy server and the URL to your site does not end with the default string /arcgis (all lowercase). 
    .PARAMETER WebSocketContextURL
        External WebSocket Enpoint when using a reverse proxy server and the URL to your site does not end with the default string /arcgis (all lowercase). 
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

        [parameter(Mandatory = $false)]
        [System.String]
        $WebSocketContextUrl,   
        
        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator,
        
		[System.Boolean]
        $DisableServiceDirectory
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

        [parameter(Mandatory = $false)]
        [System.String]
        $WebSocketContextUrl,
        
        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator,

        [System.Boolean]
        $DisableServiceDirectory
	)
    
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null

    if($VerbosePreference -ine 'SilentlyContinue') 
    {        
        Write-Verbose ("Site Administrator UserName:- " + $SiteAdministrator.UserName) 
    }

    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    Write-Verbose "Fully Qualified Domain Name :- $FQDN"
    $Referer = 'http://localhost'
    $ServerUrl = "https://$($FQDN):20443"
    $ServiceName = 'ArcGIS Mission Server'
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir  
    
	Write-Verbose "Waiting for Server 'https://$($FQDN):20443/arcgis/admin' to initialize"
    Wait-ForUrl "https://$($FQDN):20443/arcgis/admin" -HttpMethod 'GET'
    #Write-Verbose 'Get Server Token'   
    $token = Get-ServerToken -ServerEndPoint "https://$($FQDN):20443" -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer
 
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
    if($WebSocketContextUrl -and (-not($systemProperties.WebSocketContextURL) -or $systemProperties.WebSocketContextURL -ine $WebSocketContextUrl)){
        Write-Verbose "Web Socket Context URL '$($systemProperties.WebSocketContextURL)' doesn't match expected value '$WebSocketContextUrl'"
        if(-not($systemProperties.WebSocketContextURL)){
            Add-Member -InputObject $systemProperties -MemberType NoteProperty -Name "WebSocketContextURL" -Value $WebSocketContextUrl
        }else{
            $systemProperties.WebSocketContextURL = $WebSocketContextUrl
        }
        $AdminSettingsModified = $True
    }

    if($systemProperties.disableServicesDirectory -ine $DisableServiceDirectory){
        if(Get-Member -InputObject $systemProperties -name "disableServicesDirectory" -Membertype NoteProperty){
            $systemProperties.disableServicesDirectory = $DisableServiceDirectory
        }else{
            Add-Member -InputObject $systemProperties -MemberType NoteProperty -Name "disableServicesDirectory" -Value $DisableServiceDirectory
        }
    
        $AdminSettingsModified = $True
    }

    if($AdminSettingsModified){
        Set-AdminSettings -ServerUrl $ServerUrl -SettingUrl "arcgis/admin/system/properties/update" -Token $token.token -Properties $systemProperties
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

        [parameter(Mandatory = $false)]
        [System.String]
        $WebSocketContextUrl,
        
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
    $ServerUrl = "https://$($FQDN):20443"
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
        
        if($result -and $WebSocketContextUrl){
            if(-not($systemProperties.WebSocketContextURL) -or $systemProperties.WebSocketContextURL -ine $WebContextURL){
                Write-Verbose "Web Socket Context URL '$($systemProperties.WebSocketContextURL)' doesn't match expected value '$WebSocketContextUrl'"
                $result = $false
            }
        }
    }

    if($result -and $systemProperties.disableServicesDirectory -ine $DisableServiceDirectory){
        Write-Verbose "DisableServicesDirectory for Mission Server doesn't match expected value '$DisableServiceDirectory'"
        $result = $false
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
