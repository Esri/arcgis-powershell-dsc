function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $false)]
		[System.String]
		$ExternalDNSName,

		[parameter(Mandatory = $false)]
		[System.String]
		$PortalContext,
        
        [parameter(Mandatory = $true)]
		[System.String]
		$PortalHostName,

		[System.String]
        $PortalEndPoint,
        
        [System.String]
        $PortalEndPointPort,

        [System.String]
        $PortalEndPointContext,

		[System.Management.Automation.PSCredential]
		$PortalAdministrator
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
		$ExternalDNSName,

		[parameter(Mandatory = $false)]
		[System.String]
		$PortalContext,
        
	    [parameter(Mandatory = $true)]
		[System.String]
		$PortalHostName,

		[System.String]
        $PortalEndPoint,
        
        [System.Int32]
        $PortalEndPointPort = 7443,

        [System.String]
        $PortalEndPointContext = 'arcgis',

		[System.Management.Automation.PSCredential]
		$PortalAdministrator
    )
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

	[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $PortalFQDN = Get-FQDN $PortalHostName
    $Referer = if($ExternalDNSName){"https://$($ExternalDNSName)/$($PortalContext)"}else{"https://localhost"}
    Write-Verbose "Getting Portal Token for user '$($PortalAdministrator.UserName)' from 'https://$($PortalFQDN):7443'"

    $PortalToken = Get-PortalToken -PortalHostName $PortalFQDN -Port 7443 -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
    if(-not($PortalToken.token)) {
        throw "Unable to retrieve Portal Token for '$($PortalAdministrator.UserName)'"
    }else {
		Write-Verbose "Retrieved Portal Token"
	}
    Write-Verbose "Connected to Portal successfully and retrieved token for '$($PortalAdministrator.UserName)'"

	$sysProps = Get-PortalSystemProperties -PortalHostName $PortalFQDN -SiteName 'arcgis' -Token $PortalToken.token -Referer $Referer
	if (-not($sysProps)) {
		$sysProps = @{ }
	}
	
    if($ExternalDNSName){
        $ExpectedWebContextUrl = "https://$($ExternalDNSName)/$($PortalContext)"
        if ($sysProps.WebContextURL -ine $ExpectedWebContextUrl) {
            Write-Verbose "Portal System Properties > WebContextUrl is NOT correctly set to '$($ExpectedWebContextUrl)'"
            if (-not($sysProps.WebContextURL)) {
                Add-Member -InputObject $sysProps -MemberType NoteProperty -Name 'WebContextURL' -Value $ExpectedWebContextUrl
            }
            else {
                $sysProps.WebContextURL = $ExpectedWebContextUrl
            }			
        }
        else {
            Write-Verbose "Portal System Properties > WebContextUrl is correctly set to '$($sysProps.WebContextURL)'"
        }
    }

    # Check if private portal URL is set correctly
    $ExpectedPrivatePortalUrl = if($PortalEndPointPort -ieq 443){ "https://$($PortalEndPoint)/$($PortalEndPointContext)" }else{ "https://$($PortalEndPoint):$($PortalEndPointPort)/$($PortalEndPointContext)" }
    
    if ($sysProps.privatePortalURL -ine $ExpectedPrivatePortalUrl) {
        Write-Verbose "Portal System Properties > privatePortalURL is NOT correctly set to '$($ExpectedPrivatePortalUrl)'"
        if (-not($sysProps.privatePortalURL)) {
            Add-Member -InputObject $sysProps -MemberType NoteProperty -Name 'privatePortalURL' -Value $ExpectedPrivatePortalUrl
        }
        else {
            $sysProps.privatePortalURL = $ExpectedPrivatePortalUrl
        }			
    }
    else {
        Write-Verbose "Portal System Properties > privatePortalURL is correctly set to '$($sysProps.privatePortalURL)'"
    }
    
    Write-Verbose "Updating Portal System Properties"
    try {
        Wait-ForUrl -Url "https://$($PortalFQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET'
        Set-PortalSystemProperties -PortalHostName $PortalFQDN -SiteName 'arcgis' -Token $PortalToken.token -Referer $Referer -Properties $sysProps
    } catch {
        Write-Verbose "Error setting Portal System Properties :- $_"
        Write-Verbose "Request: Set-PortalSystemProperties -PortalHostName $PortalFQDN -SiteName 'arcgis' -Token $PortalToken.token -Referer $Referer -Properties $sysProps"
    }
    Write-Verbose "Waiting 5 minutes for web server to apply changes before polling for endpoint being available" 
    Start-Sleep -Seconds 300 # Add a 5 minute wait to allow the web server to go down
    Write-Verbose "Updated Portal System Properties. Waiting for portaladmin endpoint 'https://$($PortalFQDN):7443/arcgis/portaladmin/' to come back up"
    Wait-ForUrl -Url "https://$($PortalFQDN):7443/arcgis/portaladmin/" -MaxWaitTimeInSeconds 300 -HttpMethod 'GET' -Verbose
    Write-Verbose "Finished waiting for portaladmin endpoint 'https://$($PortalFQDN):7443/arcgis/portaladmin/' to come back up"
    
    if ($ExternalDNSName){
        $WebAdaptorUrl = "https://$($ExternalDNSName)/$($PortalContext)"
        $WebAdaptorsForPortal = Get-WebAdaptorsForPortal -PortalHostName $PortalFQDN -SiteName 'arcgis' -Token $PortalToken.token -Referer $Referer
        Write-Verbose "Current number of WebAdaptors on Portal:- $($WebAdaptorsForPortal.webAdaptors.Length)"
        $AlreadyExists = $false
        $WebAdaptorsForPortal.webAdaptors | Where-Object { $_.httpPort -eq 80 -and $_.httpsPort -eq 443 } | ForEach-Object {
            if ($_.webAdaptorURL -ine $WebAdaptorUrl) {
                Write-Verbose "Unregister Web Adaptor with Url $WebAdaptorUrl"
                UnRegister-WebAdaptorForPortal -PortalHostName $PortalFQDN -SiteName 'arcgis' -Token $PortalToken.token -Referer $Referer -WebAdaptorId $_.id             
            } 
            else {
                Write-Verbose "Webadaptor with require properties URL $($_.webAdaptorURL) and Name $($_.machineName) already exists"
                $AlreadyExists = $true
            }
        }

        if(-not($AlreadyExists)) {
            
            #Register the PortalEndPoint as a (dummy) web adaptor for Portal
            Write-Verbose "Registering the ExternalDNSName Endpoint with Url $WebAdaptorUrl and MachineName $PortalEndPoint as a Web Adaptor for Portal"
            try{
                Wait-ForUrl -Url "https://$($PortalFQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET'
                $registerResponse = Register-WebAdaptorForPortal -PortalHostName $PortalFQDN -SiteName 'arcgis' -Token $PortalToken.token `
                                                                    -Referer $Referer -WebAdaptorUrl $WebAdaptorUrl `
                                                                    -MachineName $PortalEndPoint -HttpPort 80 -HttpsPort 443
            } catch {
                Write-Verbose "Error registering Webadaptor for Portal :- $_"    
                Write-Verbose "Request: Register-WebAdaptorForPortal -PortalHostName $PortalFQDN -SiteName 'arcgis' -Token XXX -Referer $Referer -WebAdaptorUrl $WebAdaptorUrl -MachineName $PortalEndPoint -HttpPort 80 -HttpsPort 443"
            }

            if($registerResponse) {												
                Write-Verbose "Register WebAdaptor Response:- $(ConvertTo-Json -Depth 5 $registerResponse -Compress)"
            }else { 
                Write-Verbose "Register WebAdaptor Response is null indicating a stopped web server" 
                Start-Sleep -Seconds 180 # Wait for Portal admin to stop/start asynchronously
                Write-Verbose "Waiting for portaladmin endpoint to come back up"
                Wait-ForUrl -Url "https://$($PortalFQDN):7443/arcgis/portaladmin/" -MaxWaitTimeInSeconds 300 -HttpMethod 'GET' 
            }

            $WebAdaptorsForPortal = Get-WebAdaptorsForPortal -PortalHostName $PortalFQDN -SiteName 'arcgis' -Token $PortalToken.token -Referer $Referer
            if($WebAdaptorsForPortal) {												
                Write-Verbose "WebAdaptors Response:- $(ConvertTo-Json -Depth 5 $WebAdaptorsForPortal -Compress)"
            }else { 
                Write-Verbose "WebAdaptors Response is null indicating a stopped web server" 
                Start-Sleep -Seconds 180 # Wait for Portal to stop/start asynchronously
                Write-Verbose "Waiting for portaladmin endpoint to come back up"
                Wait-ForUrl -Url "https://$($PortalFQDN):7443/arcgis/portaladmin/" -MaxWaitTimeInSeconds 180 -HttpMethod 'GET' 
            }
            Write-Verbose "Number of Registered Web Adaptors: $($WebAdaptorsForPortal.webAdaptors.Length)"
            $VerifyWebAdaptor = $WebAdaptorsForPortal.webAdaptors | Where-Object { $_.webAdaptorURL -ieq $WebAdaptorUrl -and $_.httpPort -eq 80 -and $_.httpsPort -eq 443 }
            if(-not($VerifyWebAdaptor)) {
                Write-Verbose "[WARNING] Unable to verify the web adaptor that was just registered for $($WebAdaptorUrl)"
            }   
        }
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
		$ExternalDNSName,

		[parameter(Mandatory = $false)]
		[System.String]
		$PortalContext,
        
	    [parameter(Mandatory = $true)]
		[System.String]
		$PortalHostName,

		[System.String]
        $PortalEndPoint,
        
        [System.Int32]
        $PortalEndPointPort = 7443,

        [System.String]
        $PortalEndPointContext = 'arcgis',

		[System.Management.Automation.PSCredential]
		$PortalAdministrator
    )
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

	[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $PortalFQDN = Get-FQDN $PortalHostName
    $Referer = if($ExternalDNSName){"https://$($ExternalDNSName)/$($PortalContext)"}else{"https://localhost"}
	Write-Verbose "Getting Portal Token for user '$($PortalAdministrator.UserName)' from 'https://$($PortalFQDN):7443'"

	$PortalToken = Get-PortalToken -PortalHostName $PortalFQDN -Port 7443 -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
	if(-not($PortalToken.token)) {
		throw "Unable to retrieve Portal Token for '$($PortalAdministrator.UserName)'"
	}else {
		Write-Verbose "Retrieved Portal Token"
	}
	Write-Verbose "Connected to Portal successfully and retrieved token for '$($PortalAdministrator.UserName)'"

	$result = $true
    Write-Verbose "Get System Properties"
    # Check if web context URL is set correctly							
    $sysProps = Get-PortalSystemProperties -PortalHostName $PortalFQDN -SiteName 'arcgis' -Token $PortalToken.token -Referer $Referer
    if($sysProps) {
		Write-Verbose "System Properties:- $(ConvertTo-Json $sysProps -Depth 3 -Compress)"
        if($ExternalDNSName){
            $ExpectedWebContextUrl = "https://$($ExternalDNSName)/$($PortalContext)"	
            if ($sysProps.WebContextURL -ieq $ExpectedWebContextUrl) {
                Write-Verbose "Portal System Properties > WebContextUrl is correctly set to '$($ExpectedWebContextUrl)'"
            } else {
                $result = $false
                Write-Verbose "Portal System Properties > WebContextUrl is NOT correctly set to '$($ExpectedWebContextUrl)'"
            }
        }

        if ($result) {
            # Check if private portal URL is set correctly
            $ExpectedPrivatePortalUrl = if($PortalEndPointPort -ieq 443){ "https://$($PortalEndPoint)/$($PortalEndPointContext)" }else{ "https://$($PortalEndPoint):$($PortalEndPointPort)/$($PortalEndPointContext)" }
            if ($sysProps.privatePortalURL -ieq $ExpectedPrivatePortalUrl) {						
                Write-Verbose "Portal System Properties > privatePortalURL is correctly set to '$($ExpectedPrivatePortalUrl)'"
            } else {
                $result = $false
                Write-Verbose "Portal System Properties > privatePortalURL is NOT correctly set to '$($ExpectedPrivatePortalUrl)'"
            }
        }
        
        if ($result -and $ExternalDNSName) {
            $ExpectedUrl = "https://$ExternalDNSName/$PortalContext"
            $webadaptorConfigs = Get-WebAdaptorsForPortal -PortalHostName $PortalFQDN -SiteName 'arcgis' -Token $PortalToken.token -Referer $Referer
            $result = $false
            $webadaptorConfigs.webAdaptors | Where-Object { $_.httpPort -eq 80 -and $_.httpsPort -eq 443 } | ForEach-Object {
                if ($_.webAdaptorURL -ieq $ExpectedUrl) {
                    Write-Verbose "WebAdaptor URL $($_.webAdaptorURL) matches $ExpectedUrl"
                    $result = $True
                }
            }
        }
    }else {
        Write-Verbose "System Properties is NULL"
    }

	$result
}

function Get-PortalSystemProperties {
    [CmdletBinding()]
    param(        
        [System.String]
		$PortalHostName, 

        [System.String]
		$SiteName = 'arcgis', 

        [System.Int32]
		$Port = 7443,

        [System.String]
		$Token, 

        [System.String]
		$Referer = 'http://localhost'
    )
    
    Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):$($Port)/$($SiteName)" + '/portaladmin/system/properties/') -HttpMethod 'GET' -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer 
}

function Set-PortalSystemProperties {
    [CmdletBinding()]
    param(
        
        [System.String]
		$PortalHostName, 

        [System.String]
		$SiteName = 'arcgis', 

        [System.Int32]
		$Port = 7443,

        [System.String]
		$Token, 

        [System.String]
		$Referer = 'http://localhost',

        $Properties
    )
    
    try {
        Invoke-ArcGISWebRequest -Url("https://$($PortalHostName):$($Port)/$($SiteName)" + '/portaladmin/system/properties/update/') -HttpFormParameters @{ f = 'json'; token = $Token; properties = (ConvertTo-Json $Properties -Depth 4) } -Referer $Referer -TimeOutSec 360
    }
    catch {
        Write-Verbose "[WARNING] Request to Set-PortalSystemProperties returned error:- $_"
    }
}

function Get-WebAdaptorsForPortal {
    [CmdletBinding()]
    param(
		[System.String]
		$PortalHostName = 'localhost', 

        [System.String]
		$SiteName = 'arcgis', 

        [System.Int32]
		$Port = 7443,
		
        [System.String]
		$Token, 

        [System.String]
		$Referer = 'http://localhost'
    )
    $GetWebAdaptorsUrl = "https://$($PortalHostName):$($Port)/$($SiteName)" + "/portaladmin/system/webadaptors"
    try{
		Invoke-ArcGISWebRequest -Url $GetWebAdaptorsUrl -HttpFormParameters @{ token = $Token; f = 'json' } -Referer $Referer -TimeoutSec 240 -HttpMethod 'GET'    
	}catch{
		Write-Verbose "[WARNING] Get-WebAdaptorsForPortal request to $($GetWebAdaptorsUrl) did not succeed. Error:- $_"
		$null
	}   
}

function Register-WebAdaptorForPortal {
    [CmdletBinding()]
    param(
        [System.String]
		$PortalHostName = 'localhost', 

        [System.String]
		$SiteName = 'arcgis', 

        [System.Int32]
		$Port = 7443,
		
        [System.String]
		$Token, 

        [System.String]
		$Referer = 'http://localhost', 

        [System.String]
		$WebAdaptorUrl, 

        [System.String]
		$MachineName, 

        [System.Int32]
		$HttpPort = 80, 

		[System.Int32]
		$HttpsPort = 443
    )
    [System.String]$RegisterWebAdaptorsUrl = ("https://$($PortalHostName):$($Port)/$($SiteName)" + "/portaladmin/system/webadaptors/register")
	Write-Verbose "Register Web Adaptor URL:- $RegisterWebAdaptorsUrl"
    $WebParams = @{ token = $Token
                    f = 'json'
                    webAdaptorURL = $WebAdaptorUrl
                    machineName = $MachineName
                    httpPort = $HttpPort.ToString()
                    httpsPort = $HttpsPort.ToString()
                  }
	try {
		Invoke-ArcGISWebRequest -Url $RegisterWebAdaptorsUrl -HttpFormParameters $WebParams -Referer $Referer -TimeoutSec 3000 -ErrorAction Ignore
	}
	catch {
		Write-Verbose "[WARNING] Register-WebAdaptorForPortal returned an error. Error:- $_"
	}
}

function UnRegister-WebAdaptorForPortal {
    [CmdletBinding()]
    param(
        [System.String]
		$PortalHostName = 'localhost', 

        [System.String]
		$SiteName = 'arcgis', 

        [System.Int32]
		$Port = 7443,
		
        [System.String]
		$Token, 

        [System.String]
		$Referer = 'http://localhost',
		 
        [System.String]
		$WebAdaptorId
    )
    
    $UnRegisterWebAdaptorsUrl = "https://$($PortalHostName):$($Port)/$($SiteName)/portaladmin/system/webadaptors/$WebAdaptorId/unregister"
    try {
        Invoke-ArcGISWebRequest -Url $UnRegisterWebAdaptorsUrl -HttpFormParameters  @{ f = 'json'; token = $Token } -Referer $Referer -TimeoutSec 300  
    }catch{
        Write-Verbose "[WARNING] UnRegister-WebAdaptorForPortal on $UnRegisterWebAdaptorsUrl failed with error $($_)"
    }    
}

Export-ModuleMember -Function *-TargetResource
