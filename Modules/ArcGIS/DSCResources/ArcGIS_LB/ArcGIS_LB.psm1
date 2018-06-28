<#
    .SYNOPSIS
        Configures a WebFarm - ISS + ARR Load Balancer based on the Component - Server, Portal, WebAdaptor, ServerWebAdaptor, PortalWebAdaptor
    .PARAMETER Ensure
        Indicates to configure or unconfigure the Application Level Load Balancer. Take the values Present or Absent. 
        - "Present" ensures that WebFarm - ISS + ARR Load Balancer is Configured, if not already Configured. 
        - "Absent" ensures that WebFarm - ISS + ARR Load Balancer is unconfigured, if Configured. .
    .PARAMETER ComponentType
        Key - Path to Configuration store - Can be a Physical Location or Network Share Address. 
        Accepts the following Values - Server, Portal, WebAdaptor, ServerWebAdaptor, PortalWebAdaptor
    .PARAMETER LBEndPoint
        A HostName - Exposed End point of the server on which the Load Balancer is installed.
    .PARAMETER MemberServers
        List of the servers to be Load Balanced
    .PARAMETER EnableFailedRequestTracking
        Enables Failed Request Tracking for Debugging of Requests.
    .PARAMETER SiteName
        Optional Site Name on IIS which acts as a Reverse Proxy to the WebFarm. Required when you have multiple setups to load balance using the same LB.
#>

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
    }
}

function Add-OutboundRewriteRule
{
	[CmdletBinding()]
	param(
		[string]$Filter, 
		[string]$PSPath, 
		[string]$RuleName, 
        [switch]$IsHttp, 
        [string]$PreConditionName
	)

    $ExistingRule = Get-WebConfigurationProperty -Name Collection -PSPath $PSPath -Filter $Filter | Where-Object { $_.Name -ieq $RuleName }
    if($ExistingRule -eq $null) {  
		
        [string]$Pattern =  '^https://[^/]+/(.*)' 
        [string]$RewriteUrl =  'https://{ORIGINAL_URL}/{R:1}'
        if($IsHttp) {
            $Pattern =  '^http://[^/]+/(.*)'
            $RewriteUrl = 'http://{ORIGINAL_URL}/{R:1}' 
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

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[ValidateSet("Server","Portal")]
        [parameter(Mandatory = $true)]    
        [System.String]
		$ComponentType,

		[parameter(Mandatory = $true)]
		[System.String]
        $LBEndPoint,
        
        [parameter(Mandatory = $true)]
        [System.String[]]
        $MemberServers,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

		[System.Boolean]
		$EnableFailedRequestTracking
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

	$null
}


function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
        [ValidateSet("Server","Portal","WebAdaptor","ServerWebAdaptor","PortalWebAdaptor")]
        [parameter(Mandatory = $true)]    
        [System.String]
		$ComponentType,

		[parameter(Mandatory = $true)]
		[System.String]
        $LBEndPoint,
        
        [parameter(Mandatory = $true)]
        [System.String[]]
        $MemberServers,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

		[System.Boolean]
		$EnableFailedRequestTracking,
        
        [System.String]
        $SiteName = "Default Web Site"
    )
 
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false
   
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	$CurrVerbosePreference = $VerbosePreference # Save current preference
	$VerbosePreference = 'SilentlyContinue' # quieten it to ignore verbose output from Importing WebAdmin (bug in Powershell for this module) 
	Import-Module WebAdministration | Out-Null
	$VerbosePreference = $CurrVerbosePreference # reset it back to previous preference
    
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
    
    $PSPathFarm = 'MACHINE/WEBROOT/APPHOST'
    $ErrorActionPreference = 'STOP'

    $FarmName = "$($ComponentType)Farm"

    if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter "webFarms" | Where-Object { $_.Name -ieq $FarmName }) -eq $null) {  
        Write-Verbose "No Farm Found. Configuring $FarmName" 
        Add-WebConfigurationProperty -PSPath $PSPath -Filter "webFarms" -Name "." -Value @{name=$FarmName}
    }
    

    $pspath = "IIS:\Sites\$($SiteName)"
    
    if($ComponentType -ieq 'Server'){
        $ServerHttpPort = 6080
        $ServerHttpsPort = 6443
        
        $httpBinding = Get-WebBinding -Name $SiteName -Protocol "http" -port $ServerHttpPort
        if(-not($httpBinding)){
            New-WebBinding -Name $SiteName -IPAddress "*" -Port $ServerHttpPort
        }
        
        $httpsBinding = Get-WebBinding -Name $SiteName -Protocol "https" -port $ServerHttpsPort
        if(-not($httpsBinding)){
            New-WebBinding -Name $SiteName -IPAddress "*" -Protocol "https" -Port $ServerHttpsPort -SslFlags 0
        }

        $newCert = New-SelfSignedCertificate -DnsName $LBEndPoint -CertStoreLocation cert:\LocalMachine\My
        $binding = Get-WebBinding -Name $SiteName -Protocol "https"
        $binding.AddSslCertificate($newCert.GetCertHashString(), "My")

        foreach ($server in $MemberServers) {
            if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter "webFarms/webFarm[@name='$FarmName']" | Where-Object { $_.address -ieq $server }) -eq $null){
                Add-WebConfigurationProperty -PSPath $PSPathFarm -Filter "webFarms/webFarm[@name='$FarmName']" -Name "." -Value @{address=$server}
                Set-WebConfigurationProperty -PSPath $PSPathFarm -Filter "webFarms/webFarm[@name='$FarmName']/server[@address='$server']" -Name "applicationRequestRouting" -Value @{httpPort=$ServerHttpPort}
                Set-WebConfigurationProperty -PSPath $PSPathFarm -Filter "webFarms/webFarm[@name='$FarmName']/server[@address='$server']" -Name "applicationRequestRouting" -Value @{httpsPort=$ServerHttpsPort}
            }
        }
        
        $filter = '/system.webServer/rewrite/rules'
        Write-Verbose "Adding Rewrite rule 'LB-RP-HTTP-Server' for Url 'http://$($FarmName)/{R:0}'"
        Add-RewriteRule -RuleName 'LB-RP-HTTP-Server' -StopProcessing $true -Url '^[^/]+/(manager|admin|rest|services|mobile|tokens|login|help)(/?)(.*)' `
                    -IsHttp -RewriteUrl "http://$($FarmName)/{R:0}" -ServerPort $ServerHttpPort -Filter $filter -PSPath $pspath 
        
        Write-Verbose "Adding Rewrite rule 'LB-RP-HTTPS-Server' for Url 'https://$($FarmName)/{R:0}'"
        Add-RewriteRule -RuleName 'LB-RP-HTTPS-Server' -StopProcessing $true -Url '^[^/]+/(manager|admin|rest|services|mobile|tokens|login|help)(/?)(.*)' `
                    -RewriteUrl "https://$($FarmName)/{R:0}" -ServerPort $ServerHttpsPort -Filter $filter -PSPath $pspath

    }elseif($ComponentType -ieq 'Portal'){
        $PortalHttpPort = 7080
        $PortalHttpsPort = 7443
        
        $httpBinding = Get-WebBinding -Name $SiteName -Protocol "http"  -port $PortalHttpPort
        if(-not($httpBinding)){
            New-WebBinding -Name $SiteName -IPAddress "*" -Port $PortalHttpPort
        }
        
        $httpsBinding = Get-WebBinding -Name $SiteName -Protocol "https" -port $PortalHttpsPort
        if(-not($httpsBinding)){
            New-WebBinding -Name $SiteName -IPAddress "*" -Protocol "https" -Port $PortalHttpsPort -SslFlags 0
        }

        $newCert = New-SelfSignedCertificate -DnsName $LBEndPoint -CertStoreLocation cert:\LocalMachine\My
        $binding = Get-WebBinding -Name $SiteName -Protocol "https"
        $binding.AddSslCertificate($newCert.GetCertHashString(), "My")
        
        foreach ($server in $MemberServers) {
            if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter "webFarms/webFarm[@name='$FarmName']" | Where-Object { $_.address -ieq $server }) -eq $null){
                Add-WebConfigurationProperty -PSPath $PSPathFarm -Filter "webFarms/webFarm[@name='$FarmName']" -Name "." -Value @{address=$server}
                Set-WebConfigurationProperty -PSPath $PSPathFarm -Filter "webFarms/webFarm[@name='$FarmName']/server[@address='$server']" -Name "applicationRequestRouting" -Value @{httpPort=$PortalHttpPort}
                Set-WebConfigurationProperty -PSPath $PSPathFarm -Filter "webFarms/webFarm[@name='$FarmName']/server[@address='$server']" -Name "applicationRequestRouting" -Value @{httpsPort=$PortalHttpsPort}
            }
        }

        $filter = '/system.webServer/rewrite/rules'
        Write-Verbose "Adding Rewrite rule 'LB-RP-HTTP-Portal' for Url 'http://$($FarmName)/{R:0}'"
        Add-RewriteRule -RuleName 'LB-RP-HTTP-Portal' -StopProcessing $true -Url '.*' `
                    -IsHttp -RewriteUrl "http://$($FarmName)/{R:0}" -ServerPort $PortalHttpPort -Filter $filter -PSPath $pspath 

        Write-Verbose "Adding Rewrite rule 'LB-RP-HTTPS-Portal' for Url 'https://$($FarmName)/{R:0}'"
        Add-RewriteRule -RuleName 'LB-RP-HTTPS-Portal' -StopProcessing $true -Url '.*' `
                    -RewriteUrl "https://$($FarmName)/{R:0}" -ServerPort $PortalHttpsPort -Filter $filter -PSPath $pspath  
    }elseif($ComponentType -ieq 'WebAdaptor' -or $ComponentType -ieq 'ServerWebAdaptor' -or $ComponentType -ieq 'PortalWebAdaptor'){
        $WAHttpPort = 80
        $WAHttpsPort = 443
        $httpBinding = Get-WebBinding -Name $SiteName -Protocol "http" -port $WAHttpPort
        if(-not($httpBinding)){
            New-WebBinding -Name $SiteName -IPAddress "*" -Port $WAHttpPort
        }
        
        $httpsBinding = Get-WebBinding -Name $SiteName -Protocol "https" -port $WAHttpsPort
        if(-not($httpsBinding)){
            New-WebBinding -Name $SiteName -IPAddress "*" -Protocol "https" -Port $WAHttpsPort -SslFlags 0
        }
        $newCert = New-SelfSignedCertificate -DnsName $LBEndPoint -CertStoreLocation cert:\LocalMachine\My
        $binding = Get-WebBinding -Name $SiteName -Protocol "https"
        $binding.AddSslCertificate($newCert.GetCertHashString(), "My")
        
        foreach ($server in $MemberServers) {
            if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter "webFarms/webFarm[@name='$FarmName']" | Where-Object { $_.address -ieq $server }) -eq $null){
                Add-WebConfigurationProperty -PSPath $PSPathFarm -Filter "webFarms/webFarm[@name='$FarmName']" -Name "." -Value @{address=$server}
                Set-WebConfigurationProperty -PSPath $PSPathFarm -Filter "webFarms/webFarm[@name='$FarmName']/server[@address='$server']" -Name "applicationRequestRouting" -Value @{httpPort=$WAHttpPort}
                Set-WebConfigurationProperty -PSPath $PSPathFarm -Filter "webFarms/webFarm[@name='$FarmName']/server[@address='$server']" -Name "applicationRequestRouting" -Value @{httpsPort=$WAHttpsPort}
            }
        }

        $filter = '/system.webServer/rewrite/rules'
        Write-Verbose "Adding Rewrite rule 'LB-RP-HTTP-WA-$ComponentType' for Url 'http://$($FarmName)/{R:0}'"
        Add-RewriteRule -RuleName "LB-RP-HTTP-WA-$ComponentType" -StopProcessing $true -Url '.*' `
                    -IsHttp -RewriteUrl "http://$($FarmName)/{R:0}" -ServerPort $WAHttpPort -Filter $filter -PSPath $pspath 

        Write-Verbose "Adding Rewrite rule 'LB-RP-HTTPS-WA-$ComponentType' for Url 'https://$($FarmName)/{R:0}'"
        Add-RewriteRule -RuleName "LB-RP-HTTPS-WA-$ComponentType" -StopProcessing $true -Url '.*' `
                    -RewriteUrl "https://$($FarmName)/{R:0}" -ServerPort $WAHttpsPort -Filter $filter -PSPath $pspath  
    }

    $PreConditionName = 'IsRedirection'
    $filter = '/system.webServer/rewrite/outboundRules'
    Write-Verbose "Adding Outbound Response Rule 'Rewrite Location Header HTTP'"
    Add-OutboundRewriteRule -RuleName 'Rewrite Location Header HTTP' -Filter $filter -PSPath $pspath -PreConditionName $PreConditionName -IsHttp 

    Write-Verbose "Adding Outbound Response Rule 'Rewrite Location Header HTTPS'"
    Add-OutboundRewriteRule -RuleName 'Rewrite Location Header HTTPS' -Filter $filter -PSPath $pspath -PreConditionName $PreConditionName 
        
    $filter = '/system.webServer/rewrite/outboundRules/preConditions'
    Write-Verbose "Adding PreCondition for outbound Response Rule"
    Add-OutboundRulePreCondition -Filter $filter -PSPath $pspath -PreConditionName $PreConditionName -ResponseStatusPattern '3\d\d'

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
		[ValidateSet("Server","Portal","WebAdaptor","ServerWebAdaptor","PortalWebAdaptor")]
        [parameter(Mandatory = $true)]    
        [System.String]
		$ComponentType,

		[parameter(Mandatory = $true)]
		[System.String]
        $LBEndPoint,
        
        [parameter(Mandatory = $true)]
        [System.String[]]
        $MemberServers,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

		[System.Boolean]
		$EnableFailedRequestTracking,
        
        [System.String]
        $SiteName = "Default Web Site"
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	$result = $true #False
    
    if($Ensure -ieq 'Present') {
      
        $WebConfigPath = Join-Path $env:SystemDrive "inetpub\wwwroot\web.config" #TODO:- can we get the path from IIS or WMI
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


            $FarmName = "$($ComponentType)Farm"
            
            if($result) {
                if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter "webFarms" | Where-Object { $_.Name -ieq $FarmName }) -eq $null) {   
                    Write-Verbose "Web Farm $FarmName not found"
                    $result = $false
                }
            }
            
            foreach ($server in $MemberServers) {
                if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter "webFarms/webFarm[@name='$FarmName']" | Where-Object { $_.Address -ieq $server }) -eq $null){
                    Write-Verbose "Web Farm $FarmName not found"
                    $result = $false
                }
            }

            $pspath = "IIS:\Sites\$($SiteName)"
            $filter = '/system.webServer/rewrite/rules'
            if($result) {
                if($ComponentType -ieq 'Server'){
                    if($result) {            
                        if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter $Filter | Where-Object { $_.Name -ieq 'LB-RP-HTTP-Server' }) -eq $null) {   
                            Write-Verbose "URL Rewrite Rule 'LB-RP-HTTP-Server' not found"
                            $result = $false
                        }
                    } 
                    if($result) {            
                        if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter $Filter | Where-Object { $_.Name -ieq 'LB-RP-HTTPS-Server' }) -eq $null) {   
                            Write-Verbose "URL Rewrite Rule 'LB-RP-HTTPS-Server' not found"
                            $result = $false
                        }
                    } 
                }
                elseif($ComponentType -ieq 'Portal'){
                    if($result) {            
                        if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter $Filter | Where-Object { $_.Name -ieq 'RP-HTTP-Portal' }) -eq $null) {   
                            Write-Verbose "URL Rewrite Rule 'LB-RP-HTTP-Portal' not found"
                            $result = $false
                        }
                    } 
                    if($result) {          
                        if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter $Filter | Where-Object { $_.Name -ieq 'RP-HTTPS-Portal' }) -eq $null) {   
                            Write-Verbose "URL Rewrite Rule 'LB-RP-HTTPS-Portal' not found"
                            $result = $false
                        }
                    }   
                }
                elseif($ComponentType -ieq 'WebAdaptor' -or $ComponentType -ieq 'ServerWebAdaptor' -or $ComponentType -ieq 'PortalWebAdaptor'){
                    if($result) {            
                        if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter $Filter | Where-Object { $_.Name -ieq "LB-RP-HTTP-WA-$ComponentType" }) -eq $null) {   
                            Write-Verbose "URL Rewrite Rule 'LB-RP-HTTP-WA-$ComponentType' not found"
                            $result = $false
                        }
                    } 
                    if($result) {          
                        if((Get-WebConfigurationProperty -Name Collection -PSPath $pspath -Filter $Filter | Where-Object { $_.Name -ieq "LB-RP-HTTP-WA-$ComponentType" }) -eq $null) {   
                            Write-Verbose "URL Rewrite Rule 'LB-RP-HTTPS-WA-$ComponentType' not found"
                            $result = $false
                        }
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