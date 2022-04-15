function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
        [parameter(Mandatory = $false)]
		[System.String]
        $ServerContext,
        
        [parameter(Mandatory = $true)]
		[System.String]
		$ServerHostName,

		[parameter(Mandatory = $false)]
		[System.String]
		$ExternalDNSName,

	    [System.String]
		$ServerEndPoint,

		[System.Management.Automation.PSCredential]
		$SiteAdministrator
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

	$null
}


function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
        [parameter(Mandatory = $false)]
		[System.String]
        $ServerContext,
        
        [parameter(Mandatory = $true)]
		[System.String]
		$ServerHostName,

		[parameter(Mandatory = $false)]
		[System.String]
		$ExternalDNSName,

	    [System.String]
        $ServerEndPoint,
        
        [System.Int32]
        $ServerEndPointPort = 6443,
        
        [System.String]
		$ServerEndPointContext = 'arcgis',

		[System.Management.Automation.PSCredential]
		$SiteAdministrator
    )
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

	[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	$ServerFQDN = Get-FQDN $ServerHostName
    $Referer = if($ExternalDNSName){"https://$($ExternalDNSName)/$($ServerContext)"}else{"https://localhost"}
    Write-Verbose "Getting Server Token for user '$($SiteAdministrator.UserName)' from 'https://$($ServerFQDN):6443'"

	$serverToken = Get-ServerToken -ServerEndPoint "https://$($ServerFQDN):6443" -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer
    if(-not($serverToken.token)) {
        Write-Verbose "Get Server Token Response:- $serverToken"
        throw "Unable to retrieve Server Token for '$($SiteAdministrator.UserName)'"
    }
	Write-Verbose "Connected to Server successfully and retrieved token for '$($SiteAdministrator.UserName)'"
	if($ServerEndPoint){
		$ExpectedPrivateServerUrl = if($ServerEndPointPort -ieq 443){ "https://$($ServerEndPoint)/$($ServerEndPointContext)" }else{ "https://$($ServerEndPoint):$($ServerEndPointPort)/$($ServerEndPointContext)" }
		$WebAdaptorsForServer = Get-WebAdaptorsConfigForServer -ServerUrl "https://$($ServerFQDN):6443/arcgis" -Token $serverToken.token -Referer $Referer
		$ExistingWebAdaptor = $WebAdaptorsForServer.webAdaptors | Where-Object { $_.webAdaptorURL -ieq $ExpectedPrivateServerUrl }
		if(-not($ExistingWebAdaptor)) {
			#Register the ServerEndpoint as a (dummy) web adaptor for server				
			Write-Verbose 'Registering the Server Endpoint as a Web Adaptor for Server'
			Write-Verbose "Register $ExpectedPrivateServerUrl as web adaptor"
			$ServerEndPointHttpPort = if($ServerEndPointPort -eq 443){ 80 }else{ 6080 }
			Register-WebAdaptorForServer -ServerUrl "https://$($ServerFQDN):6443" -Token $serverToken.token -Referer $Referer -SiteName 'arcgis' `
											-WebAdaptorUrl $ExpectedPrivateServerUrl -MachineName $ServerEndPoint -HttpPort $ServerEndPointHttpPort -HttpsPort $ServerEndPointPort
			Write-Verbose 'Finished Registering the ServerEndPoint as a Web Adaptor for Server'

			$WebAdaptorsForServer = Get-WebAdaptorsConfigForServer -ServerUrl "https://$($ServerFQDN):6443/arcgis" -Token $serverToken.token -Referer $Referer
			$VerifyWebAdaptor = $WebAdaptorsForServer.webAdaptors | Where-Object { $_.webAdaptorURL -ieq $ExpectedPrivateServerUrl }
			if(-not($VerifyWebAdaptor)) {
				Write-Verbose "[WARNING] Unable to verify the web adaptor that was just registered for $ServerEndPoint with URL $ExpectedPrivateServerUrl"
			}
		}
		else{
			Write-Verbose "Web Adaptor for $ServerEndPoint with URL $ExpectedPrivateServerUrl already exists on the Server"
		}
	}
	
	if ($ExternalDNSName){
		$serverSysProps = Get-ServerSystemProperties -ServerHostName $ServerFQDN -Token $serverToken.token -Referer $Referer	
		if($serverSysProps) {
			Write-Verbose "System Properties:- $(ConvertTo-Json $serverSysProps -Depth 3 -Compress)"
		}else {
			Write-Verbose "System Properties is NULL"
		}
		$ExpectedServerWebContextUrl = "https://$($ExternalDNSName)/$($ServerContext)"	
		if($serverSysProps.WebContextURL -ieq $ExpectedServerWebContextUrl) {
			Write-Verbose "Server System Properties > WebContextUrl is correctly set to '$($ExpectedServerWebContextUrl)'"
		}else{
			$result = $false
			Write-Verbose "Server System Properties > WebContextUrl is NOT correctly set to '$($ExpectedServerWebContextUrl)'"
			if(-not($serverSysProps.WebContextURL)) {
				Add-Member -InputObject $serverSysProps -MemberType NoteProperty -Name 'WebContextURL' -Value $ExpectedServerWebContextUrl
			}else{
				$serverSysProps.WebContextURL = $ExpectedServerWebContextUrl
			}	
			Write-Verbose "Updating Server System Properties to set WebContextUrl to $ExpectedServerWebContextUrl"
			Set-ServerSystemProperties -ServerHostName $ServerFQDN -Token $serverToken.token -Referer $Referer -Properties $serverSysProps
			Write-Verbose "Updated Server System Properties to set WebContextUrl to $ExpectedServerWebContextUrl"
		}
	}
    
    Write-Verbose "Waiting for Url 'https://$($ServerFQDN):6443/arcgis/rest/info/healthCheck' to respond"
	Wait-ForUrl -Url "https://$($ServerFQDN):6443/arcgis/rest/info/healthCheck" -SleepTimeInSeconds 10 -MaxWaitTimeInSeconds 150 -HttpMethod 'GET' -Verbose

}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [parameter(Mandatory = $false)]
		[System.String]
        $ServerContext,
        
        [parameter(Mandatory = $true)]
		[System.String]
		$ServerHostName,

		[parameter(Mandatory = $false)]
		[System.String]
		$ExternalDNSName,

	    [System.String]
        $ServerEndPoint,
        
        [System.Int32]
        $ServerEndPointPort = 6443,
        
        [System.String]
		$ServerEndPointContext = 'arcgis',

		[System.Management.Automation.PSCredential]
		$SiteAdministrator
    )
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

	[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	$ServerFQDN = Get-FQDN $ServerHostName
    $ServerHttpsUrl = "https://$($ServerFQDN):6443" 
    $Referer = $ServerHttpsUrl	
    Write-Verbose "Getting Server Token for user '$($SiteAdministrator.UserName)' from 'https://$($ServerFQDN):6443'"

    $serverToken = Get-ServerToken -ServerEndPoint "https://$($ServerFQDN):6443" -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer
    if(-not($serverToken.token)) {
        Write-Verbose "Get Server Token Response:- $serverToken"
        throw "Unable to retrieve Server Token for '$($SiteAdministrator.UserName)'"
    }
    Write-Verbose "Connected to Server successfully and retrieved token for '$($SiteAdministrator.UserName)'"
    
	$result = $true
	if($result){
		$serverSysProps = Get-ServerSystemProperties -ServerHostName $ServerFQDN -Token $serverToken.token -Referer $Referer	
		if($serverSysProps) {
			Write-Verbose "System Properties:- $(ConvertTo-Json $serverSysProps -Depth 3 -Compress)"
		}else {
			Write-Verbose "System Properties is NULL"
		}
		if($ExternalDNSName){
			$ExpectedServerWebContextUrl = "https://$($ExternalDNSName)/$($ServerContext)"	
			if($serverSysProps.WebContextURL -ieq $ExpectedServerWebContextUrl) {
				Write-Verbose "Server System Properties > WebContextUrl is correctly set to '$($ExpectedServerWebContextUrl)'"
			}else{
				$result = $false
				Write-Verbose "Server System Properties > WebContextUrl is NOT correctly set to '$($ExpectedServerWebContextUrl)'"
			}
		}
	}

	if($result -and $ServerEndPoint) {
		$ExpectedPrivateServerUrl = if($ServerEndPointPort -ieq 443){ "https://$($ServerEndPoint)/$($ServerEndPointContext)" }else{ "https://$($ServerEndPoint):$($ServerEndPointPort)/$($ServerEndPointContext)" }
		
		$WebAdaptorsForServer = Get-WebAdaptorsConfigForServer -ServerUrl "https://$($ServerFQDN):6443/arcgis" -Token $serverToken.token -Referer $Referer
		$ExistingWebAdaptor = $WebAdaptorsForServer.webAdaptors | Where-Object { $_.webAdaptorURL -ieq $ExpectedPrivateServerUrl }

		if(-not($ExistingWebAdaptor)) {
			$result = $false
			Write-Verbose "Web Adaptor for url '$WebAdaptorUrl' is not set"
		}
	}		

	$result    
	
}

function Get-ServerSystemProperties
{
    [CmdletBinding()]
    param(        
        [System.String]
		$ServerHostName, 

        [System.String]
		$ContextName = 'arcgis', 

		[System.Int32]
		$AdminEndpointHttpsPort = 6443,

        [System.String]
		$Token, 

        [System.String]
		$Referer
    )
    
    Invoke-ArcGISWebRequest -Url ("https://$($ServerHostName):$($AdminEndpointHttpsPort)/$($ContextName)" + '/admin/system/properties/') -HttpMethod 'Get' -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer 
}

function Set-ServerSystemProperties
{
    [CmdletBinding()]
    param(
        
        [System.String]
		$ServerHostName, 

        [System.String]
		$ContextName = 'arcgis', 

		[System.Int32]
		$AdminEndpointHttpsPort = 6443,

        [System.String]
		$Token, 

        [System.String]
		$Referer,

        $Properties
    )
    
    try {
        Invoke-ArcGISWebRequest -Url("https://$($ServerHostName):$($AdminEndpointHttpsPort)/$($ContextName)" + '/admin/system/properties/update/') -HttpFormParameters @{ f = 'json'; token = $Token; properties = (ConvertTo-Json $Properties -Depth 4) } -Referer $Referer -TimeOutSec 180
    }catch {
        Write-Verbose "[WARNING] Request to Set-ServerSystemProperties returned error:- $_"
    }
}

function Get-WebAdaptorsConfigForServer
{
    [CmdletBinding()]
    param(
      [System.String]
	  $ServerUrl,

      [System.String]
	  $Token, 

      [System.String]
	  $Referer
    )

    $GetWebAdaptorsUrl = $ServerUrl.TrimEnd('/') + "/admin/system/webadaptors"  
    Invoke-ArcGISWebRequest -Url $GetWebAdaptorsUrl -HttpFormParameters  @{ f= 'json'; token = $Token } -HttpMethod 'GET' -Referer $Referer -TimeoutSec 30    
}

function Register-WebAdaptorForServer 
{
    [CmdletBinding()]
    param(
        [System.String]
		$ServerUrl, 

        [System.String]
		$SiteName, 

        [System.String]
		$Token, 

        [System.String]
		$Referer, 

        [System.String]
		$WebAdaptorUrl, 

        [System.String]
		$MachineName, 

        [System.Int32]
		$HttpPort = 80, 

        [System.Int32]
		$HttpsPort = 443
    )

    [System.String]$RegisterWebAdaptorsUrl = $ServerUrl.TrimEnd('/') + "/$SiteName/admin/system/webadaptors/register"  
    $WebParams = @{ token = $Token
                    f = 'json'
                    webAdaptorURL = $WebAdaptorUrl
                    machineName = $MachineName
                    httpPort = $HttpPort.ToString()
                    httpsPort = $HttpsPort.ToString()
                    isAdminEnabled = 'true'
                  }
    Invoke-ArcGISWebRequest -Url $RegisterWebAdaptorsUrl -HttpFormParameters $WebParams -Referer $Referer       
}

Export-ModuleMember -Function *-TargetResource
