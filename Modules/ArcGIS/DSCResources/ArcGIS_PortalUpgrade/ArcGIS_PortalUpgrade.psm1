$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
        [parameter(Mandatory = $true)]
        [System.String]
        $PortalHostName,

        [parameter(Mandatory = $true)]
		[System.String]
		$PortalAdministrator,
        
        [parameter(Mandatory = $false)]
		[System.String]
        $LicenseFilePath = $null,
        
        [parameter(Mandatory = $false)]
		[System.Boolean]
        $SetOnlyHostNamePropertiesFile,
    
        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $ImportExternalPublicCertAsRoot = $False
	)

    $null
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
        [parameter(Mandatory = $true)]
        [System.String]
        $PortalHostName,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
        $PortalAdministrator,
        
        [parameter(Mandatory = $false)]
		[System.String]
        $LicenseFilePath = $null,
        
        [parameter(Mandatory = $false)]
		[System.Boolean]
        $SetOnlyHostNamePropertiesFile,
    
        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $ImportExternalPublicCertAsRoot = $False
	)

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $FQDN = Get-FQDN $PortalHostName
    $Referer = "https://localhost"

    $VersionArray = $Version.Split(".")
	
	$ServiceName = 'Portal for ArcGIS'
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir  

    $RestartRequired = $false
    $hostname = Get-ConfiguredHostName -InstallDir $InstallDir
    if($hostname -ieq $FQDN) {
        Write-Verbose "Configured hostname '$hostname' matches expected value '$FQDN'"        
    }else {
        Write-Verbose "Configured hostname '$hostname' does not match expected value '$FQDN'. Setting it"
        if(Set-ConfiguredHostName -InstallDir $InstallDir -HostName $FQDN) { 
            # Need to restart the service to pick up the hostname 
			Write-Verbose "hostname.properties file was modified. Need to restart the '$ServiceName' service to pick up changes"
            $RestartRequired = $true 
        }
    }

    if(Get-NodeAgentAmazonElementsPresent -InstallDir $InstallDir) {
        Write-Verbose "Removing EC2 Listener from NodeAgent xml file"
        if(Remove-NodeAgentAmazonElements -InstallDir $InstallDir) {
             # Need to restart the service to pick up the EC2
             $RestartRequired = $true
         }  
    }

    $InstallDir = Join-Path $InstallDir 'framework\runtime\ds' 

    $expectedHostIdentifierType = if($FQDN -as [ipaddress]){ 'ip' }else{ 'hostname' }
	$hostidentifier = Get-ConfiguredHostIdentifier -InstallDir $InstallDir
	$hostidentifierType = Get-ConfiguredHostIdentifierType -InstallDir $InstallDir
	if(($hostidentifier -ieq $FQDN) -and ($hostidentifierType -ieq $expectedHostIdentifierType)) {        
        Write-Verbose "In Portal DataStore Configured host identifier '$hostidentifier' matches expected value '$FQDN' and host identifier type '$hostidentifierType' matches expected value '$expectedHostIdentifierType'"        
	}else {
		Write-Verbose "In Portal DataStore Configured host identifier '$hostidentifier' does not match expected value '$FQDN' or host identifier type '$hostidentifierType' does not match expected value '$expectedHostIdentifierType'. Setting it"
		if(Set-ConfiguredHostIdentifier -InstallDir $InstallDir -HostIdentifier $FQDN -HostIdentifierType $expectedHostIdentifierType) { 
            # Need to restart the service to pick up the hostidentifier 
            Write-Verbose "In Portal DataStore Hostidentifier.properties file was modified. Need to restart the '$ServiceName' service to pick up changes"
            $RestartRequired = $true 
        }
    }
    
    if($RestartRequired) {    
        Restart-ArcGISService -ServiceName $ServiceName -Verbose
		Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET' -Verbose
    }

    if(-not($SetOnlyHostNamePropertiesFile)){
        $result = $false
        try{
            $TestPortalResponse = Invoke-ArcGISWebRequest -Url "https://$($FQDN):7443/arcgis/portaladmin" -HttpFormParameters @{ f = 'json' } -Referer $Referer -Verbose -HttpMethod 'GET'
            if($TestPortalResponse.status -ieq "error" -and $TestPortalResponse.isUpgrade -ieq $true -and $TestPortalResponse.messages[0] -ieq "The portal site has not been upgraded. Please upgrade the site and try again."){
                $result =$false
            }else{
                if(($null -ne $TestPortalResponse.error) -and $TestPortalResponse.error.message -ieq 'Token Required.'){
                    Write-Verbose "Looks Like upgrade already Occured!"
                    $PortalHealthCheck = Invoke-ArcGISWebRequest -Url "https://$($FQDN):7443/arcgis/portaladmin/healthCheck" -HttpFormParameters @{ f = 'json' } -Referer $Referer -Verbose -HttpMethod 'GET'
                    if($PortalHealthCheck.status -ieq "success"){
                        $result = $true
                    }
                }elseif($TestPortalResponse.status -ieq 'error' -and $TestPortalResponse.isUpgrade -ieq $true -and $TestPortalResponse.messages[0] -ieq "The portal site has not been upgraded. Please upgrade the site and try again."){
                    $result = $false
                }else{
                    $jsresponse = ConvertTo-Json $TestPortalResponse -Compress -Depth 5
                    Write-Verbose "[WARNING]:- $jsresponse "
                }
            }
        }catch{
            $result = $false
            Write-Verbose "[WARNING]:- $_"
        }

        if(-not($result)){
            [string]$UpgradeUrl = "https://$($FQDN):7443/arcgis/portaladmin/upgrade"

            $WebParams = @{ 
                isBackupRequired = $true
                isRollbackRequired = $true
                f = 'json'
            }
            if($VersionArray[0] -ieq 11){
                $WebParams["async"] = $true
            } 

            $UpgradeResponse = $null
            if($LicenseFilePath){ 
                $UpgradeResponse = Invoke-UploadFile -url $UpgradeUrl -filePath $LicenseFilePath -fileContentType 'application/json' -fileParameterName 'file' `
                                    -Referer $Referer -formParams $WebParams -Verbose 
                $UpgradeResponse = ConvertFrom-JSON $UpgradeResponse
            } else {
                $UpgradeResponse = Invoke-ArcGISWebRequest -Url $UpgradeUrl -HttpFormParameters $WebParams -Referer $Referer -TimeOutSec 86400 -Verbose 
            }
            
            if($VersionArray[0] -ieq 11){
                if($UpgradeResponse.status -ieq "in progress"){
                    Write-Verbose "Upgrade in Progress"
        			$PortalReady = $false
                    while(-not($PortalReady)){
                        $UpgradeResponse = Invoke-ArcGISWebRequest -Url $UpgradeUrl -HttpFormParameters @{f = 'json'} -Referer $Referer -Verbose -HttpMethod 'GET'
                        if($UpgradeResponse.status -ieq "in progress"){
                            Write-Verbose "Response received:- Upgrade in progress"  
                            Start-Sleep -Seconds 20
                            $Attempts = $Attempts + 1
                        }else{
                            Write-Verbose "Response received:- $($UpgradeResponse.status)"
                            break
                        }
                    }
                }
            }

            if($UpgradeResponse.status -ieq 'success' -or $UpgradeResponse.status -ieq 'success with warnings') {
                Write-Verbose "Upgrade Successful"
                if($UpgradeResponse.status -ieq 'success with warnings'){
                    Write-Verbose "[WARNING]:- $(ConvertTo-Json $UpgradeResponse -Compress -Depth 5)"
                }
                if($null -ne $UpgradeResponse.recheckAfterSeconds) 
                {
                    Write-Verbose "Sleeping for $($UpgradeResponse.recheckAfterSeconds*2) seconds"
                    Start-Sleep -Seconds ($UpgradeResponse.recheckAfterSeconds*2)
                }

                Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET' -Verbose
                $Attempts = 0
                while(-not($PrimaryReady) -and ($Attempts -lt 10)) {
                    $HealthCheckUrl = "https://$($FQDN):7443/arcgis/portaladmin/healthCheck/?f=json"
                    Write-Verbose "Making request to health check URL '$HealthCheckUrl'" 
                    try {
                        $Response = Invoke-ArcGISWebRequest -Url $HealthCheckUrl -TimeoutSec 90 -HttpFormParameters @{ f = 'json' } -Referer $Referer -Verbose -HttpMethod 'GET'
                        if ($Response.status){
                            if($Response.status -ieq "success"){
                                Write-Verbose "Health check succeeded"
                                $PrimaryReady = $true
                            }elseif ($Response.status -ieq "error") { 
                                throw [string]::Format("ERROR: {0}",($Response.messages -join " "))
                            }else{
                                throw "Unknow Error"
                            }
                        }elseif ($Response.error) { 
                            throw [string]::Format("ERROR: {0}",($Response.messages -join " "))
                            throw "ERROR: $($Response.error.messages)"
                        }else{
                            throw "Unknow Error"
                        }
                    }catch {
                        Write-Verbose "Health check did not suceed. Error:- $_"
                        Start-Sleep -Seconds 30
                        $Attempts = $Attempts + 1
                    }        
                }
            }else{
                throw  "[ERROR]:- $(ConvertTo-Json $UpgradeResponse -Compress -Depth 5)"
            }
            
            $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer -Verbose
            if(-not($token.token)) {
                throw "Unable to retrieve Portal Token for '$($PortalAdministrator.UserName)'"
            }
            Write-Verbose "Connected to Portal successfully and retrieved token for '$($PortalAdministrator.UserName)'"

            if($LicenseFilePath){
                Write-Verbose 'Populating Licenses'
                [string]$populateLicenseUrl = "https://$($FQDN):7443/arcgis/portaladmin/license/populateLicense"
                $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
                $populateLicenseResponse = Invoke-ArcGISWebRequest -Url $populateLicenseUrl -HttpMethod "POST" -HttpFormParameters @{f = 'json'; token = $token.token} -Referer $Referer -TimeOutSec 3000 -Verbose
                if ($populateLicenseResponse.error -and $populateLicenseResponse.error.message) {
                    Write-Verbose "Error from Populate Licenses:- $($populateLicenseResponse.error.message)"
                    throw $populateLicenseResponse.error.message
                }
            }

            Write-Verbose "Waiting for portal to start."
            try {
                $token = Get-PortalToken -PortalHostName $FQDN -SiteName "arcgis" -Credential $PortalAdministrator -Referer $Referer -MaxAttempts 40 -Verbose
            } catch {
                Write-Verbose $_
            }

            Write-Verbose "Post Upgrade Step"
            [string]$postUpgradeUrl = "https://$($FQDN):7443/arcgis/portaladmin/postUpgrade"
            $postUpgradeResponse = Invoke-ArcGISWebRequest -Url $postUpgradeUrl -HttpFormParameters @{f = 'json'; token = $token.token} -Referer $Referer -TimeOutSec 3000 -Verbose
            $ResponseJSON = (ConvertTo-Json $postUpgradeResponse -Compress -Depth 5)
            Write-Verbose "Response received from post upgrade step $ResponseJSON" 
            if($postUpgradeResponse.status -ieq "success"){
                Write-Verbose "Sleeping for $($postUpgradeResponse.recheckAfterSeconds*3) seconds"
                Start-Sleep -Seconds ($postUpgradeResponse.recheckAfterSeconds*3)
                Write-Verbose "Post Upgrade Step Successful"
            }else{
                throw  "[ERROR]:- $(ConvertTo-Json $ResponseJSON -Compress -Depth 5)"
            }

            Write-Verbose "Waiting for portal to start."
            try {
                $token = Get-PortalToken -PortalHostName $FQDN -SiteName "arcgis" -Credential $PortalAdministrator -Referer $Referer -MaxAttempts 40 -Verbose
            } catch {
                Write-Verbose $_
            }
            
            if(($VersionArray[0] -eq 10 -and $VersionArray[1] -lt 8) -or $Version -ieq "10.8" -or $Version -ieq "10.8.0"){
                Write-Verbose "Reindexing Portal"
                Invoke-UpgradeReindex -PortalHttpsUrl "https://$($FQDN):7443" -PortalSiteName 'arcgis' -Referer $Referer -Token $token.token
            }
        }

        if(Get-LivingAtlasStatus -PortalHttpsUrl "https://$($FQDN):7443" -PortalSiteName 'arcgis' -Referer $Referer -Token $token.token){
            Write-Verbose "Upgrading Living Atlas content"
            if(Test-IfLivingAtlasUpgraded -PortalHttpsUrl "https://$($FQDN):7443" -PortalSiteName 'arcgis' -Referer $Referer -Token $token.token){
                Write-Verbose "Living Atlas content is already upgraded."
            }else{
                Write-Verbose "Upgrading Living Atlas content."
                Invoke-UpgradeLivingAtlas -PortalHttpsUrl "https://$($FQDN):7443" -PortalSiteName 'arcgis' -Referer $Referer -Token $token.token
            }
        }

        if(($VersionArray[0] -eq 11 -or $Version -ieq "10.9.1") -and $ImportExternalPublicCertAsRoot){
            $sysProps = Invoke-ArcGISWebRequest -Url ("https://$($FQDN):7443/arcgis/portaladmin/system/properties/") -HttpMethod 'GET' -HttpFormParameters @{ f = 'json'; token = $token.token } -Referer $Referer 
            Write-Verbose "Portal System Properties WebContextUrl is set to '$($sysProps.WebContextURL)'"
            
            $webRequest = [Net.WebRequest]::Create("$($sysProps.WebContextURL)/portaladmin/healthCheck?f=json")
            try { $webRequest.GetResponse() } catch {}
            $cert = $webRequest.ServicePoint.Certificate
            $bytes = $cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            $CertOnDiskPath = Join-Path $env:TEMP "$($cert.Thumbprint).cer"
            Set-Content -value $bytes -encoding byte -path $CertOnDiskPath

            $Machines = Invoke-ArcGISWebRequest -Url ("https://$($FQDN):7443/arcgis/portaladmin/machines") -HttpFormParameters @{ f = 'json'; token = $token.token; } -Referer $Referer -HttpMethod 'GET'
            foreach($m in $Machines.machines){
                $MachineName = $m.machineName
                $CertsUrl = "https://$($FQDN):7443/arcgis/portaladmin/machines/$MachineName/sslCertificates"
                $Certs = Invoke-ArcGISWebRequest -Url $CertsUrl -HttpFormParameters @{ f = 'json'; token = $token.token } -Referer $Referer -HttpMethod 'GET' -TimeOutSec 120
                $ExternalCertAlias = "AppGW-ExternalDNSCerCert"
                if($Certs.sslCertificates -icontains $ExternalCertAlias) {
                    Write-Verbose "Public key of External Certificate used by App Gateway already imported as a root certificate."
                } else {
                    Write-Verbose "Importing Public key of External Certificate used by App Gateway as a root certificate."
                    $ImportCertUrl = "https://$($FQDN):7443/arcgis/portaladmin/machines/$MachineName/sslCertificates/importRootOrIntermediate"
                    $props = @{ f= 'json'; token = $token.token; alias = $ExternalCertAlias; norestart = $true  } 
                    $res = Invoke-UploadFile -url $ImportCertUrl -filePath $CertOnDiskPath -fileContentType 'application/x-pkcs12' -formParams $props -Referer $Referer -fileParameterName 'file'    
                    if($res) {
                        $response = $res | ConvertFrom-Json
                        Confirm-ResponseStatus $response -Url $ImportCertUrl
                    } else {
                        Write-Verbose "[WARNING] Response from $ImportCertUrl was null"
                    }
                }
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
        [parameter(Mandatory = $true)]
        [System.String]
        $PortalHostName,
        
        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$PortalAdministrator,
        
        [parameter(Mandatory = $false)]
		[System.String]
		$LicenseFilePath = $null,
        
        [parameter(Mandatory = $false)]
		[System.Boolean]
        $SetOnlyHostNamePropertiesFile,
    
        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $ImportExternalPublicCertAsRoot = $False
	)

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $FQDN = Get-FQDN $PortalHostName
    $Referer = "https://localhost"
    $result = $false

    $ServiceName = 'Portal for ArcGIS'
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir  

    $hostname = Get-ConfiguredHostName -InstallDir $InstallDir
    if ($hostname -ieq $FQDN) {
        Write-Verbose "Configured hostname '$hostname' matches expected value '$FQDN'"
        $result = $true
    }
    else {
        Write-Verbose "Configured hostname '$hostname' does not match expected value '$FQDN'"
        $result = $false
    }

    if($result) {
        if(Get-NodeAgentAmazonElementsPresent -InstallDir $InstallDir) {
            Write-Verbose "Amazon Elements present in NodeAgentExt.xml. Will be removed in Set Method"
            $result = $false
        }         
    }

    if ($result) {
        $InstallDir = Join-Path $InstallDir 'framework\runtime\ds' 

        $expectedHostIdentifierType = if($FQDN -as [ipaddress]){ 'ip' }else{ 'hostname' }
		$hostidentifier = Get-ConfiguredHostIdentifier -InstallDir $InstallDir
		$hostidentifierType = Get-ConfiguredHostIdentifierType -InstallDir $InstallDir
		if (($hostidentifier -ieq $FQDN) -and ($hostidentifierType -ieq $expectedHostIdentifierType)) {        
            Write-Verbose "In Portal DataStore Configured host identifier '$hostidentifier' matches expected value '$FQDN' and host identifier type '$hostidentifierType' matches expected value '$expectedHostIdentifierType'"        
        }
        else {
			Write-Verbose "In Portal DataStore Configured host identifier '$hostidentifier' does not match expected value '$FQDN' or host identifier type '$hostidentifierType' does not match expected value '$expectedHostIdentifierType'. Setting it"
			$result = $false
        }
    }

    if ($result -and -not($SetOnlyHostNamePropertiesFile)) {
        Wait-ForUrl -Url "https://$($FQDN):7443/arcgis/portaladmin" -MaxWaitTimeInSeconds 600 -SleepTimeInSeconds 15 -HttpMethod 'GET'
        try{
            $TestPortalResponse = Invoke-ArcGISWebRequest -Url "https://$($FQDN):7443/arcgis/portaladmin" -HttpFormParameters @{ f = 'json' } -Referer $Referer -Verbose -HttpMethod 'GET'
            if($TestPortalResponse.status -ieq "error" -and $TestPortalResponse.isUpgrade -ieq $true -and $TestPortalResponse.messages[0] -ieq "The portal site has not been upgraded. Please upgrade the site and try again."){
                $result =$false
            }else{
                if(($null -ne $TestPortalResponse.error) -and $TestPortalResponse.error.message -ieq 'Token Required.'){
                    Write-Verbose "Looks Like upgrade already Occured!"
                    $PortalHealthCheck = Invoke-ArcGISWebRequest -Url "https://$($FQDN):7443/arcgis/portaladmin/healthCheck" -HttpFormParameters @{ f = 'json' } -Referer $Referer -Verbose -HttpMethod 'GET'
                    if($PortalHealthCheck.status -ieq "success"){
                        $result = $true
                    }
                }elseif($TestPortalResponse.status -ieq 'error' -and $TestPortalResponse.isUpgrade -ieq $true -and $TestPortalResponse.messages[0] -ieq "The portal site has not been upgraded. Please upgrade the site and try again."){
                    $result = $false
                }else{
                    $jsresponse = ConvertTo-Json $TestPortalResponse -Compress -Depth 5
                    Write-Verbose "[WARNING]:- $jsresponse "
                }
            }
        }catch{
            $result = $false
            Write-Verbose "[WARNING]:- $_"
        }
    }

    if($result){
        try {
            $token = Get-PortalToken -PortalHostName $FQDN -SiteName "arcgis" -Credential $PortalAdministrator -Referer $Referer -Verbose
            if(Get-LivingAtlasStatus -PortalHttpsUrl "https://$($FQDN):7443" -PortalSiteName 'arcgis' -Referer $Referer -Token $token.token){
                Write-Verbose "Checking if Living Atlas Content needs to be upgraded"
                if(Test-IfLivingAtlasUpgraded -PortalHttpsUrl "https://$($FQDN):7443" -PortalSiteName 'arcgis' -Referer $Referer -Token $token.token){
                    Write-Verbose "Living Atlas Content already upgraded."
                }else{
                    Write-Verbose "Living Atlas Content needs upgradation."
                    $result = $false
                }
            }
        } catch {
            Write-Verbose $_
            $result = $false
        }
    }
    $result 
}

function Invoke-UpgradeReindex
{
    [CmdletBinding()]
    param(
        [System.String]
        $PortalHttpsUrl, 
        
        [System.String]
		$PortalSiteName = 'arcgis', 

        [System.String]
		$Token, 

        [System.String]
		$Referer = 'http://localhost'
        
    )

    [string]$ReindexSiteUrl = $PortalHttpsUrl.TrimEnd('/') + "/$PortalSiteName/portaladmin/system/indexer/reindex"

    $WebParams = @{ 
                    mode = 'FULL_MODE'
                    f = 'json'
                    token = $Token
                  }

    Write-Verbose "Making request to $ReindexSiteUrl to create the site"
    $Response = Invoke-ArcGISWebRequest -Url $ReindexSiteUrl -HttpFormParameters $WebParams -Referer $Referer -TimeOutSec 3000 -Verbose 
    $ResponseJSON = (ConvertTo-JSON $Response -Depth 5 -Compress )
    Write-Verbose "Response received from Reindex site $ResponseJSON"  
    if($Response.error -and $Response.error.message) {
        throw $Response.error.message
    }
    if($Response.status -ieq 'success') {
        Write-Verbose "Reindexing Successful"
    }
}

function Get-LivingAtlasStatus
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [System.String]
        $PortalHttpsUrl, 
        
        [System.String]
        $PortalSiteName = 'arcgis', 
        
        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost'
    )
    
    $LAStatusURL = $PortalHttpsUrl.TrimEnd('/') + "/$PortalSiteName/sharing/rest/search"
    $resp = Invoke-ArcGISWebRequest -Url $LAStatusURL -HttpFormParameters @{ f = 'json'; token = $Token; q = "owner:esri_livingatlas" } -Referer $Referer
    if($resp.total -gt 0){
        Write-Verbose "Living Atlas content found."
        $true
    }else{
        Write-Verbose "Living Atlas content not found."
        $false
    }
}

function Get-LivingAtlasGroupIds
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [System.String]
        $PortalHttpsUrl, 
        
        [System.String]
        $PortalSiteName = 'arcgis', 
        
        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost'
    )
    $result = @()
    $LAGroupIdsURL = $PortalHttpsUrl.TrimEnd('/') + "/$PortalSiteName/sharing/rest/community/groups"
    $resp = Invoke-ArcGISWebRequest -Url $LAGroupIdsURL -HttpFormParameters @{ f = 'json'; token = $Token; q = "owner:esri_livingatlas" } -Referer $Referer
    if($resp.total -gt 0){
        foreach($group in $resp.results){
            $result += $group.id
        }
    }
    $result
}

function Invoke-UpgradeLivingAtlas
{
    [CmdletBinding()]
    param(
        [System.String]
        $PortalHttpsUrl, 
        
        [System.String]
        $PortalSiteName = 'arcgis', 

        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost'
    )

    $LivingAtlasGroupIds = Get-LivingAtlasGroupIds -PortalHttpsUrl $PortalHttpsUrl -PortalSiteName $PortalSiteName -Referer $Referer -Token $Token
    foreach($groupId in $LivingAtlasGroupIds){
        $done = $False
        $attempts = 0
        while(-not($done)){
            $LAUpgradeURL = $PortalHttpsUrl.TrimEnd('/') + "/$PortalSiteName/portaladmin/system/content/livingatlas/upgrade"
            try{
				$resp = Invoke-ArcGISWebRequest -Url $LAUpgradeURL -HttpFormParameters @{ f = 'json'; token = $Token; groupId = $groupId } -Referer $Referer -Verbose
				if($resp.status -eq "success"){
					Write-Verbose "Upgraded Living Atlas Content For GroupId - $groupId"
                    $done = $True
				}
			}catch{         
                if($attempts -eq 3){
                    Write-Verbose "Unable to Living Atlas Content For GroupId - $groupId"
                }
            }
			if($attempts -eq 3){
                $done = $True
            }
			$attempts++
        }
    }
}

function Test-IfLivingAtlasUpgraded
{
    [CmdletBinding()]
    param(
        [System.String]
        $PortalHttpsUrl, 
        
        [System.String]
        $PortalSiteName = 'arcgis', 

        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost'
    )
    $result = $False
    $LivingAtlasGroupIds = Get-LivingAtlasGroupIds -PortalHttpsUrl $PortalHttpsUrl -PortalSiteName $PortalSiteName -Referer $Referer -Token $Token
    foreach($groupId in $LivingAtlasGroupIds){
        $done = $False
        $attempts = 0
        while(-not($done)){
            $LAUpgradeStatusCheckURL = $PortalHttpsUrl.TrimEnd('/') + "/$PortalSiteName/portaladmin/system/content/livingatlas/status"
            try{
				$resp = Invoke-ArcGISWebRequest -Url $LAUpgradeStatusCheckURL -HttpFormParameters @{ f = 'json'; token = $Token; groupId = $groupId } -Referer $Referer -Verbose
                if($resp.upgraded -eq $True -or $resp.upgraded -ieq 'true'){
                    $result = $True
                }else{
                    $result = $False
                }
                $done = $True
			}catch{
				if($attempts -eq 3){
					Write-Verbose "Unable to Living Atlas Content For GroupId - $groupId - Please Follow Mannual Steps specified in the Documentation"
					$done = $True
                    $result = $False
				}
			}
            if($attempts -eq 3){
                $done = $True
            }
			$attempts++
        }
        if($result -ieq $False){
            break
        }
    }
    $Result
}

Export-ModuleMember -Function *-TargetResource