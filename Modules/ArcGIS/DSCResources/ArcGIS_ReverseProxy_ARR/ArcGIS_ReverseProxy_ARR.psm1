function Add-RewriteRule
{
	[CmdletBinding()]
	param(
		  [string]
		  $Filter, 

		  [string]
		  $PSPath, 

		  [string]
		  $RuleName, 

		  [bool]
		  $StopProcessing, 

          [string]
		  $Url,  

		  [switch]
		  $IsHttp, 

		  [string]
		  $ServerPort,  

		  [string]
		  $RewriteUrl
	)

    $ExistingRule = Get-WebConfigurationProperty -Name Collection -PSPath $PSPath -Filter $Filter | Where-Object { $_.Name -ieq $RuleName }
    if($ExistingRule -eq $null) {   
        Add-WebConfigurationProperty -PSPath $PSPath  -Filter $Filter -name "." `
                         -Value @{
                                    name=$RuleName 
                                    stopProcessing=$StopProcessing.ToString().ToLowerInvariant()
                                    match = @{ url = $Url }
                                    action = @{ type = 'Rewrite'; url = $RewriteUrl }
                                 }
   
        $httpsPattern = 'on'
        if($IsHttp) {
            $httpsPattern = 'off'
        }
        $list = @{
         pspath = $PSPath
         filter = "$Filter/rule[@name='$RuleName']/conditions"
         Value = @{
            input = '{HTTPS}'        
            pattern = $httpsPattern        
          }
        }
        Add-WebConfiguration @list

        $list = @{
         pspath = $PSPath
         filter = "$Filter/rule[@name='$RuleName']/conditions"
         Value = @{
            input = '{SERVER_PORT}'        
            pattern = $ServerPort        
          }
        }
        Add-WebConfiguration @list
    
        $list = @{
         pspath = $PSPath
         filter = "$Filter/rule[@name='$RuleName']/serverVariables"
         Value = @{
            name = 'HTTP_X_FORWARDED_HOST'        
            value = '{HTTP_HOST}'        
          }
        }
        Add-WebConfiguration @list

        $list = @{
         pspath = $PSPath
         filter = "$Filter/rule[@name='$RuleName']/serverVariables"
         Value = @{
            name = 'ORIGINAL_URL'        
            value = '{HTTP_HOST}'        
          }
        }
        Add-WebConfiguration @list
    }else {
        Write-Verbose "Rule $($RuleName) already exists"
    }
}

function Add-WebSocketsRewriteRule
{
    [CmdletBinding()]
	param(
		  [string]
		  $Filter, 

		  [string]
		  $PSPath, 

		  [string]
		  $RuleName
	)

    Add-WebConfigurationProperty -PSPath $PSPath -Filter $Filter -name "." `
                         -Value @{
                                    name= $RuleName
                                    match = @{ url = "(.*)" }
                                    action = @{ type = 'None' }
                                 }

    $list = @{
            pspath = "IIS:\"
            filter = "$Filter/rule[@name='$RuleName']/conditions"
            Value = @{
                input = '{HTTP_UPGRADE}'        
                pattern = "^websocket$"        
            }
        }
    Add-WebConfiguration @list

    $list = @{
            pspath = "IIS:\"
            filter = "$Filter/rule[@name='$RuleName']/conditions"
            Value = @{
                input = '{HTTP_SEC_WEBSOCKET_EXTENSIONS}'        
                pattern = "^(.*)(permessage-deflate)(;?)(.*)"        
            }
        }
    Add-WebConfiguration @list

    $list = @{
            pspath = $PSPath
            filter = "$Filter/rule[@name='$RuleName']/serverVariables"
            Value = @{
                name = 'HTTP_SEC_WEBSOCKET_EXTENSIONS'        
                value = '{C:1}{C:4}'        
            }
        }
    Add-WebConfiguration @list
}

function Add-OutboundRewriteRule
{
	[CmdletBinding()]
	param(
		[string]$Filter, 
		[string]$PSPath, 
		[string]$RuleName, 
		[switch]$IsHttp, 
		[switch]$IsServerEndpoint, 
		[string]$PreConditionName,
        [string]$ServerEndpoint,
		[string]$PortalEndpoint,
        [System.Boolean]
        $EnableGeoEventEndpoints,
        [System.Boolean]
		$EnableNotebookServerEndpoints
	)

    $ExistingRule = Get-WebConfigurationProperty -Name Collection -PSPath $PSPath -Filter $Filter | Where-Object { $_.Name -ieq $RuleName }
    if($ExistingRule -eq $null) {  
		
        $Port = if($IsServerEndpoint) { if($IsHttp) { '6(?:1|0)80' } else { '6(?:1|4)43' } } else { if($IsHttp) { '7080' } else { '7443' } }
        if($EnableNotebookServerEndpoints){
            $Port = '11443'
        }
		$Scheme = if($IsHttp) { 'http' } else { 'https' }
		$Pattern = "^$($Scheme)://[^/]+:$($Port)/(?:arcgis|portal|server)/(.*)"
		$RewriteContextName = if($EnableGeoEventEndpoints) { 'arcgis' } else { if($IsServerEndpoint) { 'server' } else { 'portal' } }
		$RewriteUrl = "$($Scheme)://{ORIGINAL_URL}/$($RewriteContextName)/{R:1}" 
		if($EnableGeoEventEndpoints -or $EnableNotebookServerEndpoints) {
			if($EnableNotebookServerEndpoints){
                $Pattern = "^$($Scheme)://[^/]+:$($Port)/(?:arcgis)/(.*)"
                $RewriteUrl = "$($Scheme)://{ORIGINAL_URL}/notebookserver/{R:1}" 
            }else{
                $Pattern = "^$($Scheme)://[^/]+:$($Port)/(.*)" 
                $RewriteUrl = "$($Scheme)://{ORIGINAL_URL}/{R:1}"
            }
        }
        
        Add-WebConfigurationProperty -PSPath $PSPath  -Filter $Filter -name "." `
                         -Value @{
                                    name=$RuleName 
                                    preCondition= $PreConditionName
                                    match = @{ serverVariable = 'RESPONSE_Location'; pattern = $Pattern }
                                    action = @{ type = 'Rewrite'; value = $RewriteUrl }
                                 }
                                 
        $list = @{
         pspath = $PSPath
         filter = "$Filter/rule[@name='$RuleName']/conditions"
         Value = @{
            input = '{ORIGINAL_URL}'        
            pattern = '.+'        
          }
        }
        Add-WebConfiguration @list 
    }else {
        Write-Verbose "Precondition $($PreConditionName) already exists"
    }
}

function Add-OutboundRulePreCondition
{
	[CmdletBinding()]
	param(
		[string]$Filter, 
		[string]$PSPath, 
		[string]$PreConditionName, 
		[string]$ResponseStatusPattern
	)

    $PSPath = 'IIS:\Sites\Default Web Site'
    $Filter = '/system.webServer/rewrite/outboundRules/preConditions'
    $PreConditionName = 'IsRedirection'

    $ExistingPreCondition =  Get-WebConfigurationProperty -Name Collection -PSPath $PSPath -Filter $Filter | Where-Object { $_.Name -ieq $PreConditionName }
    if($ExistingPreCondition -eq $null) {
        Add-WebConfigurationProperty -PSPath $PSPath -Filter "$Filter" -Name . -Value $PreConditionName 

        $list = @{
                 pspath = $PSPath
                 filter = "$Filter/preCondition[@name='$PreConditionName']"
                 Value = @{
                    input = '{RESPONSE_STATUS}'        
                    pattern = $ResponseStatusPattern        
                  }
                }
         Add-WebConfiguration @list 
     }else {
        Write-Verbose "Precondition $($PreConditionName) already exists"
    }
}

function Add-RedirectRule
{
	[CmdletBinding()]
	param(
		  $Filter, 

		  [string]
		  $PSPath, 

		  [string]
		  $RuleName, 

		  [bool]
		  $StopProcessing, 

          [string]
		  $ExternalDnsName,  

          [string]
		  $SiteName = 'arcgis',  

		  [switch]
		  $IsHttp
	)

    $ExistingRule = Get-WebConfigurationProperty -Name Collection -PSPath $PSPath -Filter $Filter | Where-Object { $_.Name -ieq $RuleName }

    if(-not($ExistingRule)) {

        $ServerPort = 443
        $httpsPattern = 'on'
        $RedirectUrl = "https://$($ExternalDnsName)/portal/home/"
        if($IsHttp) {
            $RedirectUrl = "http://$($ExternalDnsName)/portal/home/"
            $httpsPattern = 'off'
            $ServerPort = 80
        } 

        Add-WebConfigurationProperty -PSPath $PSPath -Filter $Filter -name "." `
                         -Value @{
                                    name=$RuleName 
                                    stopProcessing=$StopProcessing.ToString().ToLowerInvariant()
                                    match = @{ url = "^/?$|(?:portal|arcgis)(/?)$" }
                                    action = @{ type = 'Redirect'; url = $RedirectUrl; redirectType = 'SeeOther' }
                                 }               

        $list = @{
         pspath = $PSPath
         filter = "$Filter/rule[@name='$RuleName']/conditions"
         Value = @{
            input = '{HTTPS}'        
            pattern = $httpsPattern        
          }
        }
        Add-WebConfiguration @list

        $list = @{
         pspath = $PSPath
         filter = "$Filter/rule[@name='$RuleName']/conditions"
         Value = @{
            input = '{SERVER_PORT}'        
            pattern = $ServerPort        
          }
        }
        Add-WebConfiguration @list
    
        $list = @{
         pspath = $PSPath
         filter = "$Filter/rule[@name='$RuleName']/serverVariables"
         Value = @{
            name = 'HTTP_X_FORWARDED_HOST'        
            value = '{HTTP_HOST}'        
          }
        }
        Add-WebConfiguration @list

        $list = @{
         pspath = $PSPath
         filter = "$Filter/rule[@name='$RuleName']/serverVariables"
         Value = @{
            name = 'ORIGINAL_URL'        
            value = '{HTTP_HOST}'        
          }
        }
        Add-WebConfiguration @list

        
    }else {
        Write-Verbose "Rule $($RuleName) already exists"
    }
}

function Disable-IdleTimeOutOnApplicationPool 
{
	[CmdletBinding()]
	param(
		[string]$AppPoolName = 'DefaultAppPool'
	)

    $appPool = Get-ChildItem IIS:\AppPools | Where-Object { $_.Name -ieq $AppPoolName }
    if($appPool) {
        &  "$env:SystemRoot\system32\inetsrv\appcmd" set config /section:applicationPools "/[name='$AppPoolName'].processModel.idleTimeout:0.00:00:00"
    }
}

function Set-MaxUploadSize
{
	[CmdletBinding()]
	param(
		[string]$WebSiteName
	) 

    & "$env:SystemRoot\system32\inetsrv\appcmd" set config $WebSiteName /section:system.webServer/security/requestFiltering /requestLimits.maxAllowedContentLength:2147483647
}

function Enable-FailedRequestTracking
{
	[CmdletBinding()]
	param(
		[string]$WebSiteName
	)

    & "$env:SystemRoot\system32\inetsrv\appcmd"  set config -section:system.applicationHost/sites "/[name='$WebSiteName'].traceFailedRequestsLogging.enabled:True" /commit:apphost
    & "$env:SystemRoot\system32\inetsrv\appcmd" set config -section:system.applicationHost/sites "/[name='$WebSiteName'].traceFailedRequestsLogging.maxLogFiles:10" /commit:apphost
    & "$env:SystemRoot\system32\inetsrv\appcmd" set config -section:system.applicationHost/sites "/[name='$WebSiteName'].traceFailedRequestsLogging.directory:%SystemDrive%\inetpub\logs\FailedReqLogFiles" /commit:apphost
}

function Has-WebAdaptorVirtualDirectory
{
	[CmdletBinding()]
	param(
	)

    $exists = $false
    Get-Website | ForEach-Object {
       [string]$SiteName = $_.Name
       $wa = Get-WebApplication -Site $SiteName | ForEach-Object { 
            if($_.path -ieq '/arcgis') {
                $exists = $true           
            } 
        }
    }
    $exists
}

function Remove-WebAdaptorVirtualDirectory
{    
	[CmdletBinding()]
	param(
	)

    $webSites = Get-Website
    if($webSites)
    {
        foreach($webSite in $webSites) {
            [string]$SiteName = $webSite.Name
            $webapps = Get-WebApplication -Site $SiteName
            foreach($wa in $webapps) {
                if($wa.path -ieq '/arcgis') {
                    Write-Verbose "Removing Virtual Directory $($wa.path) located at $($wa.PhysicalPath)"
                    Remove-Item -Path $wa.PhysicalPath -Force -Recurse                    
                    Remove-WebApplication -Name $wa.path -Site $SiteName            
                } 
            }
        }
    }    
}

function Import-CertFromServerIntoTrustedCertStore
{
	[CmdletBinding()]
	param(
		[string]$Url
	)
    
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert = $args[1]
        [System.Net.Security.SslPolicyErrors]$errors = $args[3]
        if($errors -ne [System.Net.Security.SslPolicyErrors]::None) {
            
            if(-not(Test-Path "Cert:\LocalMachine\Trust\$($cert.Thumbprint)")) {
                Write-Verbose "Importing Certificate '$($cert.Thumbprint)' to Local Machine trusted root store"
                $certStore = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store Root, LocalMachine
                $certStore.Open("MaxAllowed")
                $certStore.Add($cert)
                $certStore.Close()            
                Write-Verbose "Imported Certificate to Local Machine trusted store"
            }else {
                Write-Verbose "Certificate '$($cert.Thumbprint)' already exists in Local Machine trusted store"
            }
        }
    }

    try
    {
        Write-Verbose "Connecting to $Url to retrieve SSL certificate"
        [System.Net.HttpWebRequest]$request = [System.Net.WebRequest]::Create($Url)
        [System.Net.HttpWebResponse]$response = $request.GetResponse()
        $respStream = $response.GetResponseStream()
        Write-Verbose "Successfully connected to $Url"
    }
    catch{
        Write-Verbose "[WARNING]:- Error Connecting to $Url. Error:- $_"
    }
    finally 
    {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
		[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    }
}


function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$ExternalDNSName,

		[parameter(Mandatory = $true)]
		[System.String]
		$ServerSiteName,

		[parameter(Mandatory = $true)]
		[System.String]
		$PortalSiteName
    )
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

	$null
}


function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
		[System.String[]]
		$ServerHostNames,

		[parameter(Mandatory = $true)]
		[System.String]
		$ExternalDNSName,

		[parameter(Mandatory = $true)]
		[System.String]
		$ServerSiteName,

		[System.String[]]
		$PortalHostNames,

		[System.String]
		$ServerEndPoint,

		[System.String]
		$PortalEndPoint,

		[parameter(Mandatory = $true)]
		[System.String]
		$PortalSiteName,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

		[System.Management.Automation.PSCredential]
		$PortalAdministrator,

		[System.Boolean]
		$EnableFailedRequestTracking,

		[System.Boolean]
        $EnableGeoEventEndpoints,
        
        [System.Boolean]
        $EnableNotebookServerEndpoints
	)
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	$CurrVerbosePreference = $VerbosePreference # Save current preference
	$VerbosePreference = 'SilentlyContinue' # quieten it to ignore verbose output from Importing WebAdmin (bug in Powershell for this module) 
	Import-Module WebAdministration | Out-Null
	$VerbosePreference = $CurrVerbosePreference # reset it back to previous preference
    
    #Write-Verbose "Removing Virtual Directory" 
    #Remove-WebAdaptorVirtualDirectory 
    #Write-Verbose "Removed Virtual Directory"

    $SiteName = 'Default Web Site'
    $WebSiteFolder = [System.Environment]::ExpandEnvironmentVariables((Get-Website -Name $SiteName).physicalPath)
    $ServerVDir = Join-Path $WebSiteFolder 'server'
    $PortalVDir = Join-Path $WebSiteFolder 'portal'
    $GeoEventVDir = Join-Path $WebSiteFolder 'geoevent'
    $NotebookServerVDir = Join-Path $WebSiteFolder 'notebookserver'
	$ArcGISVDir = Join-Path $WebSiteFolder 'arcgis'
    ###
    ### Check Physical Directorys and Virtual Directories
    ###
	if(-not($EnableGeoEventEndpoints) -and -not($EnableNotebookServerEndpoints)) {	
		if(-not(Test-Path $ServerVDir)){
			Write-Verbose "Folder for Server Virtual Directory $ServerVDir does not exist. Creating it"
			New-Item $ServerVDir -ItemType directory
		}else {
			Write-Verbose "Folder for Server Virtual Directoy $ServerVDir already exists"
		}

		if(-not(Get-WebVirtualDirectory -Site $SiteName -Name 'server' )){
			Write-Verbose "Virtual Directory for Server does not exist in website '$SiteName'. Creating it"
			New-WebVirtualDirectory -Site $SiteName -Name 'server' -PhysicalPath $ServerVDir
		}else {
			Write-Verbose "Virtual Directory for Server already exists in website '$SiteName'"
		}
	}

    if($PortalEndPoint -and $PortalEndPoint.Trim().Length -gt 0) {        
        if(-not(Test-Path $PortalVDir)){
            Write-Verbose "Folder for Portal Virtual Directory $PortalVDir does not exist. Creating it"
            New-Item $PortalVDir -ItemType directory
        }else {
            Write-Verbose "Folder for Portal Virtual Directoy $PortalVDir already exists"
        }

        if(-not(Get-WebVirtualDirectory -Site $SiteName -Name 'portal' )){
            Write-Verbose "Virtual Directory for Portal does not exist in website '$SiteName'. Creating it"
            New-WebVirtualDirectory -Site $SiteName -Name 'portal' -PhysicalPath $PortalVDir
        }else {
            Write-Verbose "Virtual Directory for portal already exists in website '$SiteName'"
        }
    }

    if($EnableGeoEventEndpoints) 
    {
		if(-not(Test-Path $ArcGISVDir)){
            Write-Verbose "Folder for arcgis Virtual Directory $ArcGISVDir does not exist. Creating it"
            New-Item $ArcGISVDir -ItemType directory
        }else {
            Write-Verbose "Folder for arcgis Virtual Directoy $ArcGISVDir already exists"
        }

        if(-not(Get-WebVirtualDirectory -Site $SiteName -Name 'arcgis' )){
            Write-Verbose "Virtual Directory for arcgis does not exist in website '$SiteName'. Creating it"
            New-WebVirtualDirectory -Site $SiteName -Name 'arcgis' -PhysicalPath $ArcGISVDir
        }else {
            Write-Verbose "Virtual Directory for arcgis already exists in website '$SiteName'"
        }

        if(-not(Test-Path $GeoEventVDir)){
            Write-Verbose "Folder for GeoEvent Virtual Directory $GeoEventVDir does not exist. Creating it"
            New-Item $GeoEventVDir -ItemType directory
        }else {
            Write-Verbose "Folder for GeoEvent Virtual Directoy $GeoEventVDir already exists"
        }

        if(-not(Get-WebVirtualDirectory -Site $SiteName -Name 'geoevent' )){
            Write-Verbose "Virtual Directory for GeoEvent does not exist in website '$SiteName'. Creating it"
            New-WebVirtualDirectory -Site $SiteName -Name 'geoevent' -PhysicalPath $GeoEventVDir
        }else {
            Write-Verbose "Virtual Directory for GeoEvent already exists in website '$SiteName'"
        }
    }

    if($EnableNotebookServerEndpoints) 
    {
		if(-not(Test-Path $NotebookServerVDir)){
            Write-Verbose "Folder for Notebook Server Virtual Directory $NotebookServerVDir does not exist. Creating it"
            New-Item $NotebookServerVDir -ItemType directory
        }else {
            Write-Verbose "Folder for Notebook Server Virtual Directoy $NotebookServerVDir already exists"
        }

        if(-not(Get-WebVirtualDirectory -Site $SiteName -Name 'notebookserver' )){
            Write-Verbose "Virtual Directory for Notebook Server does not exist in website '$SiteName'. Creating it"
            New-WebVirtualDirectory -Site $SiteName -Name 'notebookserver' -PhysicalPath $NotebookServerVDir
        }else {
            Write-Verbose "Virtual Directory for Notebook Server already exists in website '$SiteName'"
        }
    }

    ###
    ### Enable the proxy (at the machine level)
    ###
    $pspath = 'MACHINE/WEBROOT/APPHOST'
    $filter = "system.webServer/proxy"
    $config = Get-WebConfiguration -Filter $filter -PSPath $pspath
    if(!$config) 
    {
        Write-Verbose "Configuration for '$filter' does not exist in '$pspath'. Adding it"
        $config = @{ enabled = $true; reverseRewriteHostInResponseHeaders = $false } 
        Set-WebConfiguration -InputObject $config -Filter $filter -PSPath $pspath
        Write-Verbose "Finished Updating the configuration for '$filter' at '$pspath'"
    }
    else {
        Write-Verbose "Configuration for '$filter' already exists in '$pspath'"
        [bool]$hasChanged = $false
        if($config.enabled -eq $false) {
            Write-Verbose "Enabling Reverse Proxy"
            $config.enabled = $true
            $hasChanged = $true
        }
        if(($config.reverseRewriteHostInResponseHeaders -eq $null) -or ($config.reverseRewriteHostInResponseHeaders -eq $true)) {
            Write-Verbose "Disabling ReverseRewriteHostInResponseHeaders"
            $config.reverseRewriteHostInResponseHeaders = $false
            $hasChanged = $true
        }      
        if($hasChanged) {
            Write-Verbose "Updating the configuration for '$filter' at '$pspath' with changes"
            Set-WebConfiguration -InputObject $config -Filter $filter -PSPath $pspath
            Write-Verbose "Finished Updating the configuration for '$filter' at '$pspath' with changes"
        }
    }  
        
    ### 
    ### Enable Server Variables (at the machine level)
    ###
    $filter = "system.webServer/rewrite/allowedServerVariables"
    if(!(Get-WebConfigurationProperty -PSPath $pspath -Filter $filter -Name Collection)) {
        Write-Verbose "Updating the configuration for '$filter' at '$pspath'. Allowing Server Variables"
        Add-WebConfigurationProperty -PSPath $pspath -Filter $filter -Name . -Value 'HTTP_X_FORWARDED_HOST' 
        Add-WebConfigurationProperty -PSPath $pspath -Filter $filter -Name . -Value 'ORIGINAL_URL'
        Write-Verbose "Updated the configuration for '$filter' at '$pspath' with changes"
    }                
        

    $pspath = "IIS:\Sites\$SiteName\server"
    if($ServerEndPoint -and (-not($ServerEndPoint -as [ipaddress]))) {
        $ServerEndPoint = Get-FQDN -MachineName $ServerEndPoint 
    }
    $ServerHttpPort = '6080'
    $ServerHttpsPort = '6443'
	$GeoEventHttpPort  = '6180'
    $GeoEventHttpsPort  = '6143'
    $NotebookServerHttpsPort = '11443'

    if($PortalEndPoint -and (-not($PortalEndPoint -as [ipaddress]))) {
        $PortalEndPoint = Get-FQDN -MachineName $PortalEndPoint 
    }
     
    $PortalHttpPort = '7080'
    $PortalHttpsPort = '7443'
    $filter = '/system.webServer/rewrite/rules'
    if($ServerEndPoint -and $ServerEndPoint.Trim().Length -gt 0) {
        if($EnableNotebookServerEndpoints){
            # ARR Doesn't support Sec-WebSocket-Extensions = permessage-deflate > Getting around by filtering it out
            # https://community.esri.com/thread/208716-geoevent-websockets-in-106-with-arr
            Add-WebSocketsRewriteRule -PSPath "IIS:\" -Filter '/system.webServer/rewrite/globalRules' -RuleName "Web Sockets ISS ARR Support Rule"

            $pspath = "IIS:\Sites\$SiteName\notebookserver"
            # We forward HTTP to HTTPS Endpoint of Notebook Server
            Write-Verbose "Adding Rewrite rule 'RP-HTTP-WebSocket-NotebookServer' for Url 'http://$($ServerEndPoint):$NotebookServerHttpsPort/arcgis/{R:0}'"
            Add-RewriteRule -RuleName 'RP-HTTP-WebSocket-NotebookServer' -StopProcessing $true -Url '^ws:\/.*' `
                        -IsHttp -RewriteUrl "https://$($ServerEndPoint):$NotebookServerHttpsPort/arcgis/{R:0}" -ServerPort '80' -Filter $filter -PSPath $pspath 

            Write-Verbose "Adding Rewrite rule 'RP-HTTPS-WebSocket-NotebookServer' for Url 'http://$($ServerEndPoint):$NotebookServerHttpsPort/arcgis/{R:0}'"
            Add-RewriteRule -RuleName 'RP-HTTPS-WebSocket-NotebookServer' -StopProcessing $true -Url '^wss:\/.*' `
                        -RewriteUrl "https://$($ServerEndPoint):$NotebookServerHttpsPort/arcgis/{R:0}" -ServerPort '443' -Filter $filter -PSPath $pspath 

            # We forward HTTP to HTTPS Endpoint of Notebook Server
            Write-Verbose "Adding Rewrite rule 'RP-HTTP-NotebookServer' for Url 'https://$($ServerEndPoint):$NotebookServerHttpsPort/arcgis/{R:0}'"
            Add-RewriteRule -RuleName 'RP-HTTP-NotebookServer' -StopProcessing $true -Url '.*' `
                        -IsHttp -RewriteUrl "https://$($ServerEndPoint):$NotebookServerHttpsPort/arcgis/{R:0}" -ServerPort '80' -Filter $filter -PSPath $pspath 
        
            Write-Verbose "Adding Rewrite rule 'RP-HTTPS-NotebookServer' for Url 'https://$($ServerEndPoint):$NotebookServerHttpsPort/arcgis/{R:0}'"
            Add-RewriteRule -RuleName 'RP-HTTPS-NotebookServer' -StopProcessing $true -Url '.*' `
                        -RewriteUrl "https://$($ServerEndPoint):$NotebookServerHttpsPort/arcgis/{R:0}" -ServerPort '443' -Filter $filter -PSPath $pspath
        }else{
            if($EnableGeoEventEndpoints) {	
                Add-WebSocketsRewriteRule -PSPath "IIS:\" -Filter '/system.webServer/rewrite/globalRules' -RuleName "Web Sockets ISS ARR Support Rule"

                $pspath = "IIS:\Sites\$SiteName\arcgis"	
                Write-Verbose "Adding Rewrite rule 'RP-HTTP-WebSocket-GeoEvent' for Url 'http://$($ServerEndPoint):$GeoEventHttpPort/arcgis/{R:0}'"
                Add-RewriteRule -RuleName 'RP-HTTP-WebSocket-GeoEvent' -StopProcessing $true -Url '^ws/.*' `
                            -IsHttp -RewriteUrl "http://$($ServerEndPoint):$GeoEventHttpPort/arcgis/{R:0}" -ServerPort '80' -Filter $filter -PSPath $pspath 

                ### Workaround (Removed) - we forward HTTPS to HTTP Endpoint of GeoEvent to avoid certificate issues with IIS+ARR and Jetty on backend
                Write-Verbose "Adding Rewrite rule 'RP-HTTPS-WebSocket-GeoEvent' for Url 'https://$($ServerEndPoint):$GeoEventHttpsPort/arcgis/{R:0}'"
                Add-RewriteRule -RuleName 'RP-HTTPS-WebSocket-GeoEvent' -StopProcessing $true -Url '^ws/.*' `
                            -RewriteUrl "https://$($ServerEndPoint):$GeoEventHttpsPort/arcgis/{R:0}" -ServerPort '443' -Filter $filter -PSPath $pspath 
                
                Write-Verbose "Adding Rewrite rule 'RP-HTTP-Server' for Url 'http://$($ServerEndPoint):$ServerHttpPort/arcgis/{R:0}'"
                Add-RewriteRule -RuleName 'RP-HTTP-Server' -StopProcessing $true -Url '.*' `
                            -IsHttp -RewriteUrl "http://$($ServerEndPoint):$ServerHttpPort/arcgis/{R:0}" -ServerPort '80' -Filter $filter -PSPath $pspath 
            
                Write-Verbose "Adding Rewrite rule 'RP-HTTPS-Server' for Url 'https://$($ServerEndPoint):$ServerHttpPort/arcgis/{R:0}'"
                Add-RewriteRule -RuleName 'RP-HTTPS-Server' -StopProcessing $true -Url '.*' `
                            -RewriteUrl "https://$($ServerEndPoint):$ServerHttpsPort/arcgis/{R:0}" -ServerPort '443' -Filter $filter -PSPath $pspath	

                $pspath = "IIS:\Sites\$SiteName\geoevent"	
                Write-Verbose "Adding Rewrite rule 'RP-HTTP-GeoEvent' for Url 'http://$($ServerEndPoint):$GeoEventHttpPort/{R:0}'"
                Add-RewriteRule -RuleName 'RP-HTTP-GeoEvent' -StopProcessing $true -Url '.*' `
                            -IsHttp -RewriteUrl "http://$($ServerEndPoint):$GeoEventHttpPort/geoevent/{R:0}" -ServerPort '80' -Filter $filter -PSPath $pspath 
            
                Write-Verbose "Adding Rewrite rule 'RP-HTTPS-GeoEvent' for Url 'https://$($ServerEndPoint):$GeoEventHttpsPort/{R:0}'"
                Add-RewriteRule -RuleName 'RP-HTTPS-GeoEvent' -StopProcessing $true -Url '.*' `
                            -RewriteUrl "https://$($ServerEndPoint):$GeoEventHttpsPort/geoevent/{R:0}" -ServerPort '443' -Filter $filter -PSPath $pspath
            }
            else {
                $pspath = "IIS:\Sites\$SiteName\server"
                Write-Verbose "Adding Rewrite rule 'RP-HTTP-Server' for Url 'http://$($ServerEndPoint):$ServerHttpPort/arcgis/{R:0}'"
                Add-RewriteRule -RuleName 'RP-HTTP-Server' -StopProcessing $true -Url '.*' `
                            -IsHttp -RewriteUrl "http://$($ServerEndPoint):$ServerHttpPort/arcgis/{R:0}" -ServerPort '80' -Filter $filter -PSPath $pspath 
            
                Write-Verbose "Adding Rewrite rule 'RP-HTTPS-Server' for Url 'https://$($ServerEndPoint):$ServerHttpPort/arcgis/{R:0}'"
                Add-RewriteRule -RuleName 'RP-HTTPS-Server' -StopProcessing $true -Url '.*' `
                            -RewriteUrl "https://$($ServerEndPoint):$ServerHttpsPort/arcgis/{R:0}" -ServerPort '443' -Filter $filter -PSPath $pspath			
            }
        }
    }
            
    if($PortalEndPoint -and $PortalEndPoint.Trim().Length -gt 0) {

        $pspath = "IIS:\Sites\$SiteName"
        Write-Verbose "Adding Rewrite rule 'RP-HTTP-BaseContextPath'"
        Add-RedirectRule -RuleName 'RP-HTTP-BaseContextPath' -StopProcessing $true -SiteName 'portal' `
                    -IsHttp -ExternalDnsName $ExternalDNSName -Filter $filter -PSPath $pspath 

        Write-Verbose "Adding Rewrite rule 'RP-HTTPS-BaseContextPath'"
        Add-RedirectRule -RuleName 'RP-HTTPS-BaseContextPath' -StopProcessing $true -SiteName 'portal' `
                    -ExternalDnsName $ExternalDNSName -Filter $filter -PSPath $pspath 

        $pspath = "IIS:\Sites\$SiteName\portal"
        Write-Verbose "Adding Rewrite rule 'RP-HTTP-Portal' for Url 'http://$($PortalEndPoint):$PortalHttpPort/{R:0}'"
        Add-RewriteRule -RuleName 'RP-HTTP-Portal' -StopProcessing $true -Url '.*' `
                    -IsHttp -RewriteUrl "http://$($PortalEndPoint):$PortalHttpPort/arcgis/{R:0}" -ServerPort '80' -Filter $filter -PSPath $pspath 

        Write-Verbose "Adding Rewrite rule 'RP-HTTPS-Portal' for Url 'https://$($PortalEndPoint):$PortalHttpsPort/{R:0}'"
        Add-RewriteRule -RuleName 'RP-HTTPS-Portal' -StopProcessing $true -Url '.*' `
                    -RewriteUrl "https://$($PortalEndPoint):$PortalHttpsPort/arcgis/{R:0}" -ServerPort '443' -Filter $filter -PSPath $pspath  
    }	

	###
	### Outbound rules for server
	###
	$pspath = "IIS:\Sites\$SiteName\server"
    $PreConditionName = 'IsRedirection'
    $filter = '/system.webServer/rewrite/outboundRules'	

    if(-not($EnableGeoEventEndpoints) -and -not($EnableNotebookServerEndpoints)) {	
        Write-Verbose "Adding Outbound Response Rule 'Rewrite Location Header Server HTTP'"
        Add-OutboundRewriteRule -RuleName 'Rewrite Location Header Server HTTP' -Filter $filter -PSPath $pspath -PreConditionName $PreConditionName -IsHttp -PortalEndpoint $PortalEndPoint -ServerEndpoint $ServerEndPoint -EnableGeoEventEndpoints $EnableGeoEventEndpoints -IsServerEndpoint

        Write-Verbose "Adding Outbound Response Rule 'Rewrite Location Header Server HTTPS'"
        Add-OutboundRewriteRule -RuleName 'Rewrite Location Header Server HTTPS' -Filter $filter -PSPath $pspath -PreConditionName $PreConditionName -PortalEndpoint $PortalEndPoint -ServerEndpoint $ServerEndPoint -EnableGeoEventEndpoints $EnableGeoEventEndpoints -IsServerEndpoint
    
	    $filter = '/system.webServer/rewrite/outboundRules/preConditions'
        Write-Verbose "Adding PreCondition for outbound Response Rule"
        Add-OutboundRulePreCondition -Filter $filter -PSPath $pspath -PreConditionName $PreConditionName -ResponseStatusPattern '3\d\d'
    }

	if($EnableGeoEventEndpoints) {	
        @("IIS:\Sites\$SiteName\geoevent", "IIS:\Sites\$SiteName\arcgis") | %{
			$pspath = $_
			Write-Verbose "Processing PSPath '$pspath'"
			$PreConditionName = 'IsRedirection'
			$filter = '/system.webServer/rewrite/outboundRules'	
			Write-Verbose "Adding Outbound Response Rule 'Rewrite Location Header GeoEvent Server HTTP'"
			Add-OutboundRewriteRule -RuleName 'Rewrite Location Header Server HTTP' -Filter $filter -PSPath $pspath -PreConditionName $PreConditionName -IsHttp -PortalEndpoint $PortalEndPoint -ServerEndpoint $ServerEndPoint -EnableGeoEventEndpoints $EnableGeoEventEndpoints -IsServerEndpoint

			Write-Verbose "Adding Outbound Response Rule 'Rewrite Location Header GeoEvent Server HTTPS'"
			Add-OutboundRewriteRule -RuleName 'Rewrite Location Header Server HTTPS' -Filter $filter -PSPath $pspath -PreConditionName $PreConditionName -PortalEndpoint $PortalEndPoint -ServerEndpoint $ServerEndPoint -EnableGeoEventEndpoints $EnableGeoEventEndpoints -IsServerEndpoint
    
			$filter = '/system.webServer/rewrite/outboundRules/preConditions'
			Write-Verbose "Adding PreCondition for outbound Response Rule"
			Add-OutboundRulePreCondition -Filter $filter -PSPath $pspath -PreConditionName $PreConditionName -ResponseStatusPattern '3\d\d'
		}
    }
    
    if($EnableNotebookServerEndpoints){
        ###
		### Outbound rules for Notebook Server
		###
        $pspath = "IIS:\Sites\$SiteName\notebookserver"
        Write-Verbose "Processing PSPath '$pspath'"
        $PreConditionName = 'IsRedirection'
        $filter = '/system.webServer/rewrite/outboundRules'	
        Write-Verbose "Adding Outbound Response Rule 'Rewrite Location Header Notebook Server HTTP'"
        Add-OutboundRewriteRule -RuleName 'Rewrite Location Header Server HTTP' -Filter $filter -PSPath $pspath -PreConditionName $PreConditionName `
                                   -IsHttp -PortalEndpoint $PortalEndPoint -ServerEndpoint $ServerEndPoint -EnableGeoEventEndpoints $EnableGeoEventEndpoints `
                                   -EnableNotebookServerEndpoints $EnableNotebookServerEndpoints

        Write-Verbose "Adding Outbound Response Rule 'Rewrite Location Header Notebook Server HTTPS'"
        Add-OutboundRewriteRule -RuleName 'Rewrite Location Header Server HTTPS' -Filter $filter -PSPath $pspath -PreConditionName $PreConditionName `
                                    -PortalEndpoint $PortalEndPoint -ServerEndpoint $ServerEndPoint -EnableGeoEventEndpoints $EnableGeoEventEndpoints `
                                    -EnableNotebookServerEndpoints $EnableNotebookServerEndpoints

        $filter = '/system.webServer/rewrite/outboundRules/preConditions'
        Write-Verbose "Adding PreCondition for outbound Response Rule"
        Add-OutboundRulePreCondition -Filter $filter -PSPath $pspath -PreConditionName $PreConditionName -ResponseStatusPattern '3\d\d'
		
    }

	if($PortalEndPoint -and $PortalEndPoint.Trim().Length -gt 0) {
		###
		### Outbound rules for portal
		###
		$pspath = "IIS:\Sites\$SiteName\portal"
		$filter = '/system.webServer/rewrite/outboundRules'	
		Write-Verbose "Adding Outbound Response Rule 'Rewrite Location Header Portal HTTP'"
		Add-OutboundRewriteRule -RuleName 'Rewrite Location Header Portal HTTP' -Filter $filter -PSPath $pspath -PreConditionName $PreConditionName -IsHttp -PortalEndpoint $PortalEndPoint -ServerEndpoint $ServerEndPoint -EnableGeoEventEndpoints $EnableGeoEventEndpoints 

		Write-Verbose "Adding Outbound Response Rule 'Rewrite Location Header Portal HTTPS'"
		Add-OutboundRewriteRule -RuleName 'Rewrite Location Header Portal HTTPS' -Filter $filter -PSPath $pspath -PreConditionName $PreConditionName -PortalEndpoint $PortalEndPoint -ServerEndpoint $ServerEndPoint -EnableGeoEventEndpoints $EnableGeoEventEndpoints 
    
		$filter = '/system.webServer/rewrite/outboundRules/preConditions'
		Write-Verbose "Adding PreCondition for outbound Response Rule"
		Add-OutboundRulePreCondition -Filter $filter -PSPath $pspath -PreConditionName $PreConditionName -ResponseStatusPattern '3\d\d'
    }
    
    $ServerHostNames | ForEach-Object {
        if($_ -and $_.Length -gt 0) {  
			$FqdnOfHost = Get-FQDN -MachineName $_
            Write-Verbose "Machine:- $FqdnOfHost"       			
			$Url = if($EnableNotebookServerEndpoints){"https://$($FqdnOfHost):$NotebookServerHttpsPort/arcgis/admin/"}else{"https://$($FqdnOfHost):$ServerHttpsPort/arcgis/admin/"}
			Write-Verbose "Wait for $Url to initialize"
			Wait-ForUrl -Url $Url -HttpMethod 'POST' -MaxWaitTimeInSeconds 30 -LogFailures
			Write-Verbose "Import certificate for Server from $Url"
            Import-CertFromServerIntoTrustedCertStore -Url $Url

			if($EnableGeoEventEndpoints) {
				$Url = "https://$($FqdnOfHost):$GeoEventHttpsPort/geoevent/admin/"
				Write-Verbose "Wait for $Url to initialize"
				Wait-ForUrl -Url $Url -HttpMethod 'POST' -MaxWaitTimeInSeconds 30 -LogFailures
				Write-Verbose "Import certificate for GeoEvent Endpoint from $Url"
				Import-CertFromServerIntoTrustedCertStore -Url $Url
			}
        }
    }
   
    $PortalHostNames | ForEach-Object {
        if($_ -and $_.Length -gt 0) {   
            $FqdnOfHost = Get-FQDN -MachineName $_
            Write-Verbose "Machine:- $FqdnOfHost"       
			$Url = "https://$($FqdnOfHost):$PortalHttpsPort/arcgis/portaladmin/"
			#Write-Verbose "Wait for $Url to initialize"
			#Wait-ForUrl -Url $Url -LogFailures
			#Write-Verbose "Finished waiting. Now import certificate for Portal from $Url"
            Import-CertFromServerIntoTrustedCertStore -Url $Url
        }
    }    

    Write-Verbose 'Disable Idle Timeout on Application Pool'
    Disable-IdleTimeOutOnApplicationPool -AppPoolName 'DefaultAppPool'
    
    Write-Verbose 'Increase the max upload size on the default website'
    Set-MaxUploadSize -WebSiteName $SiteName  
    if($EnableFailedRequestTracking) {
        Write-Verbose 'Enabling failed request tracking'
        Enable-FailedRequestTracking -WebSiteName $SiteName      
    }
}


function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[System.String[]]
		$ServerHostNames,

		[parameter(Mandatory = $true)]
		[System.String]
		$ExternalDNSName,

		[parameter(Mandatory = $true)]
		[System.String]
		$ServerSiteName,

		[System.String[]]
		$PortalHostNames,

		[System.String]
		$ServerEndPoint,

		[System.String]
		$PortalEndPoint,

		[parameter(Mandatory = $true)]
		[System.String]
		$PortalSiteName,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

		[System.Management.Automation.PSCredential]
		$PortalAdministrator,

		[System.Boolean]
		$EnableFailedRequestTracking,

		[System.Boolean]
		$EnableGeoEventEndpoints,
        
        [System.Boolean]
        $EnableNotebookServerEndpoints
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	$result = $true
    
    if($Ensure -ieq 'Present') {
      
        $SiteName = 'Default Web Site'
        $WebSiteFolder = [System.Environment]::ExpandEnvironmentVariables((Get-Website -Name $SiteName).physicalPath)
        $ServerVDir = Join-Path $WebSiteFolder 'server'
        $PortalVDir = Join-Path $WebSiteFolder 'portal'
        $GeoEventVDir = Join-Path $WebSiteFolder 'geoevent'
        $NotebookServerVDir = Join-Path $WebSiteFolder 'notebookserver'
		$ArcGISVDir = Join-Path $WebSiteFolder 'arcgis'

        ###
        ### Check Physical Directorys
        ###
		if(-not($EnableGeoEventEndpoints) -and -not($EnableNotebookServerEndpoints)) {	
			if(-not(Test-Path $ServerVDir)){
				Write-Verbose "Folder for Server Virtual Directory $ServerVDir does not exist"
				$result = $false
			}else {
				Write-Verbose "Folder for Server Virtual Directoy $ServerVDir already exists"
			}
		}

        if($result) {
            if($PortalEndPoint -and $PortalEndPoint.Trim().Length -gt 0) {
                if(-not(Test-Path $PortalVDir)){
                    Write-Verbose "Folder for Portal Virtual Directory $PortalVDir does not exist"
                    $result = $false
                }else {
                    Write-Verbose "Folder for Portal Virtual Directoy $PortalVDir already exists"
                }
            }
        }

        if($EnableGeoEventEndpoints) {       
		
			if($result) {
                if(-not(Test-Path $ArcGISVDir)){
                    Write-Verbose "Folder for arcgis Virtual Directory $ArcGISVDir does not exist"
                    $result = $false
                }else {
                    Write-Verbose "Folder for arcgis Virtual Directoy $ArcGISVDir already exists"
                }
            }

            if($result) {
                if(-not(Test-Path $GeoEventVDir)){
                    Write-Verbose "Folder for GeoEvent Virtual Directory $GeoEventVDir does not exist"
                    $result = $false
                }else {
                    Write-Verbose "Folder for GeoEvent Virtual Directoy $GeoEventVDir already exists"
                }
            }
        }

        if($EnableNotebookServerEndpoints) {       
			if($result) {
                if(-not(Test-Path $NotebookServerVDir)){
                    Write-Verbose "Folder for Notebook Server Virtual Directory $NotebookServerVDir does not exist"
                    $result = $false
                }else {
                    Write-Verbose "Folder for Notebook Server Virtual Directoy $NotebookServerVDir already exists"
                }
            }
        }


        $WebConfigPath = Join-Path $WebSiteFolder "web.config" 
        if(Test-Path $WebConfigPath) {
            [xml]$WebConfig = Get-Content $WebConfigPath -Raw
            if(-not($WebConfig.configuration.'system.webServer'.security.requestFiltering.requestLimits.maxAllowedContentLength)) {
                Write-Verbose "MaxAllowedContentLength property does not exist in $WebConfigPath"
                $result = $false
            }else {
                Write-Verbose "MaxAllowedContentLength property exists in $WebConfigPath"
            }
        }        

        if($result) 
        {
            $CurrVerbosePreference = $VerbosePreference # Save current preference
			$VerbosePreference = 'SilentlyContinue' # quieten it to ignore verbose output from Importing WebAdmin (bug in Powershell for this module) 
			Import-Module WebAdministration | Out-Null
			$VerbosePreference = $CurrVerbosePreference # reset it back to previous preference
            #Start-Sleep -Seconds 30
            #Write-Verbose 'Checking Web Adaptor VDir'
            #$result = -not(Has-WebAdaptorVirtualDirectory)
            #Write-Verbose "VDir Present:- $result"
        
            if(-not($EnableGeoEventEndpoints) -or -not($EnableNotebookServerEndpoints)) {
                if(-not(Get-WebVirtualDirectory -Site $SiteName -Name 'server' )){
                    Write-Verbose "Virtual Directory for Server does not exist in website '$SiteName'"
                    $result = $false
                }else {
                    Write-Verbose "Virtual Directory for Server already exists in website '$SiteName'"
                }
            }

            if($result) {
                if($PortalEndPoint -and $PortalEndPoint.Trim().Length -gt 0) {                
                    if(-not(Get-WebVirtualDirectory -Site $SiteName -Name 'portal' )){
                        Write-Verbose "Virtual Directory for Portal does not exist in website '$SiteName'"
                        $result = $false
                    }else {
                        Write-Verbose "Virtual Directory for Portal already exists in website '$SiteName'"
                    }
                }
            }

            if($EnableGeoEventEndpoints) 
            {
				if($result) {
                    if(-not(Get-WebVirtualDirectory -Site $SiteName -Name 'arcgis' )){
                        Write-Verbose "Virtual Directory for arcgis does not exist in website '$SiteName'"
                        $result = $false
                    }else {
                        Write-Verbose "Virtual Directory for arcgis already exists in website '$SiteName'"
                    }
                }

                if($result) {
                    if(-not(Get-WebVirtualDirectory -Site $SiteName -Name 'geoevent' )){
                        Write-Verbose "Virtual Directory for GeoEvent does not exist in website '$SiteName'"
                        $result = $false
                    }else {
                        Write-Verbose "Virtual Directory for GeoEvent already exists in website '$SiteName'"
                    }
                }
            }

            if($EnableNotebookServerEndpoints) {       
                if($result) {
                    if(-not(Get-WebVirtualDirectory -Site $SiteName -Name 'notebookserver' )){
                        Write-Verbose "Virtual Directory for Notebook Server does not exist in website '$SiteName'"
                        $result = $false
                    }else {
                        Write-Verbose "Virtual Directory for Notebook Server already exists in website '$SiteName'"
                    }
                }
            }

            $pspath = 'MACHINE/WEBROOT/APPHOST'
            $filter = "system.webServer/proxy"
            $config = Get-WebConfiguration -Filter $filter -PSPath $pspath
            if(!$config) {
                [bool]$needsChanges = $false
                if($config.enabled -eq $false) {                
                    $needsChanges = $true
                }
                if(($config.reverseRewriteHostInResponseHeaders -eq $null) -or ($config.reverseRewriteHostInResponseHeaders -eq $true)) {                
                    $needsChanges = $true
                }      
                if($needsChanges) {
                    Write-Verbose "URL Rewrite not enabled"
                    $result = $false
                }
            }

            if($result) {
                $filter = "system.webServer/rewrite/allowedServerVariables"
                if(!(Get-WebConfigurationProperty -PSPath $pspath -Filter $filter -Name Collection)) {
                    $result = $false
                }
            }

            $pspath = "IIS:\Sites\$SiteName\server"
            $filter = '/system.webServer/rewrite/rules'

            if(-not($EnableGeoEventEndpoints) -and -not($EnableNotebookServerEndpoints)) {
                if($result) {            
                    if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter $Filter | Where-Object { $_.Name -ieq 'RP-HTTP-Server' }) -eq $null) {   
                        Write-Verbose "URL Rewrite Rule 'RP-HTTP-Server' not found"
                        $result = $false
                    }
                } 
                if($result) {            
                    if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter $Filter | Where-Object { $_.Name -ieq 'RP-HTTPS-Server' }) -eq $null) {   
                        Write-Verbose "URL Rewrite Rule 'RP-HTTPS-Server' not found"
                        $result = $false
                    }
                } 
            }

            if($PortalEndPoint -and $PortalEndPoint.Trim().Length -gt 0) {
                $pspath = "IIS:\Sites\$SiteName\portal"
                if($result) {            
                    if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter $Filter | Where-Object { $_.Name -ieq 'RP-HTTP-Portal' }) -eq $null) {   
                        Write-Verbose "URL Rewrite Rule 'RP-HTTP-Portal' not found"
                        $result = $false
                    }
                } 
                if($result) {          
                    if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter $Filter | Where-Object { $_.Name -ieq 'RP-HTTPS-Portal' }) -eq $null) {   
                        Write-Verbose "URL Rewrite Rule 'RP-HTTPS-Portal' not found"
                        $result = $false
                    }
                }  

                $pspath = "IIS:\Sites\$SiteName"
                if($result) {            
                    if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter $Filter | Where-Object { $_.Name -ieq 'RP-HTTP-BaseContextPath' }) -eq $null) {   
                        Write-Verbose "URL Rewrite Rule 'RP-HTTP-BaseContextPath' not found"
                        $result = $false
                    }
                } 
                if($result) {          
                    if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter $Filter | Where-Object { $_.Name -ieq 'RP-HTTPS-BaseContextPath' }) -eq $null) {   
                        Write-Verbose "URL Rewrite Rule 'RP-HTTPS-BaseContextPath' not found"
                        $result = $false
                    }
                }  
            }
			if($EnableGeoEventEndpoints) {
				
				$pspath = "IIS:\Sites\$SiteName\arcgis"
				if($result) {            
					if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter $Filter | Where-Object { $_.Name -ieq 'RP-HTTP-Server' }) -eq $null) {   
						Write-Verbose "URL Rewrite Rule 'RP-HTTP-Server' not found"
						$result = $false
					}
				} 
				if($result) {            
					if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter $Filter | Where-Object { $_.Name -ieq 'RP-HTTPS-Server' }) -eq $null) {   
						Write-Verbose "URL Rewrite Rule 'RP-HTTPS-Server' not found"
						$result = $false
					}
				} 

				if($result) {            
					if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter $Filter | Where-Object { $_.Name -ieq 'RP-HTTP-WebSocket-GeoEvent' }) -eq $null) {   
						Write-Verbose "URL Rewrite Rule 'RP-HTTP-WebSocket-GeoEvent' not found"
						$result = $false
					}
				} 
				if($result) {            
					if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter $Filter | Where-Object { $_.Name -ieq 'RP-HTTPS-WebSocket-GeoEvent' }) -eq $null) {   
						Write-Verbose "URL Rewrite Rule 'RP-HTTPS-WebSocket-GeoEvent' not found"
						$result = $false
					}
				} 
                
				$pspath = "IIS:\Sites\$SiteName\geoevent"
				if($result) {           
					if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter $Filter | Where-Object { $_.Name -ieq 'RP-HTTP-GeoEvent' }) -eq $null) {   
						Write-Verbose "URL Rewrite Rule 'RP-HTTP-GeoEvent' not found"
                        $result = $false
					}
				} 
				if($result) {    
					if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter $Filter | Where-Object { $_.Name -ieq 'RP-HTTPS-GeoEvent' }) -eq $null) {   
						Write-Verbose "URL Rewrite Rule 'RP-HTTPS-GeoEvent' not found"
                        $result = $false
					}
				}  
            }
            
            if($EnableNotebookServerEndpoints) {
                # if($result) {            
				# 	if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter $Filter | Where-Object { $_.Name -ieq 'RP-HTTP-WebSocket-GeoEvent' }) -eq $null) {   
				# 		Write-Verbose "URL Rewrite Rule 'RP-HTTP-WebSocket-GeoEvent' not found"
				# 		$result = $false
				# 	}
				# } 
				if($result) {            
					if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter $Filter | Where-Object { $_.Name -ieq 'RP-HTTPS-WebSocket-NotebookServer' }) -eq $null) {   
						Write-Verbose "URL Rewrite Rule 'RP-HTTPS-WebSocket-NotebookServer' not found"
						$result = $false
					}
				} 
                
				$pspath = "IIS:\Sites\$SiteName\notebookserver"
				# if($result) {           
				# 	if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter $Filter | Where-Object { $_.Name -ieq 'RP-HTTP-GeoEvent' }) -eq $null) {   
				# 		Write-Verbose "URL Rewrite Rule 'RP-HTTP-GeoEvent' not found"
                #         $result = $false
				# 	}
				# } 
				if($result) {    
					if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter $Filter | Where-Object { $_.Name -ieq 'RP-HTTPS-NotebookServer' }) -eq $null) {   
						Write-Verbose "URL Rewrite Rule 'RP-HTTPS-GeoEvent' not found"
                        $result = $false
					}
				}  

            }
        }
        $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}


Export-ModuleMember -Function *-TargetResource

