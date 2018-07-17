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
        [parameter(Mandatory = $true)]
        [System.String]
        $PortalHostName,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$PortalAdministrator
	)
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $FQDN = Get-FQDN $PortalHostName
    $Referer = "https://localhost"

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

    $InstallDir = Join-Path $InstallDir 'framework\runtime\ds' 

    $expectedHostIdentifierType = 'hostname'
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
		Restart-PortalService -ServiceName $ServiceName
        Wait-ForUrl "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET' 
    }


    [string]$UpgradeUrl = "https://$($FQDN):7443/arcgis/portaladmin/upgrade"
    $UpgradeResponse = Invoke-ArcGISWebRequest -Url $UpgradeUrl -HttpFormParameters @{f = 'json'; isBackupRequired = $true; isRollbackRequired = $true} -Referer $Referer -TimeOutSec 86400 -LogResponse 
    $ResponseJSON = ConvertTo-Json $UpgradeResponse -Compress -Depth 5
    Write-Verbose "Response received from Upgrade site $ResponseJSON"  
    if($UpgradeResponse.error) {
        Write-Verbose
        throw  "[ERROR]:- $ResponseJSON"
    }
    if($Response.status -ieq 'success') {
        Write-Verbose "Upgrade Successful"
        if($UpgradeResponse.recheckAfterSeconds -ne $null) 
        {
            Write-Verbose "Sleeping for $($UpgradeResponse.recheckAfterSeconds*2) seconds"
            Start-Sleep -Seconds ($UpgradeResponse.recheckAfterSeconds*2)
        }
    }  
    
    Wait-ForPortalToStart -PortalHttpsUrl "https://$($FQDN):7443" -PortalSiteName "arcgis" -PortalAdminCredential $PortalAdministrator -Referer $Referer

    $token = Get-PortalToken -PortalHostName $FQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
    if(-not($token.token)) {
        throw "Unable to retrieve Portal Token for '$PortalAdminUserName'"
    }
    Write-Verbose "Connected to Portal successfully and retrieved token for '$($PortalAdministrator.UserName)'"

    Write-Verbose "Post Upgrade Step"
    [string]$postUpgradeUrl = "https://$($FQDN):7443/arcgis/portaladmin/postUpgrade"
    $postUpgradeResponse = Invoke-ArcGISWebRequest -Url $postUpgradeUrl -HttpFormParameters @{f = 'json'; token = $token.token} -Referer $Referer -TimeOutSec 3000 -LogResponse 
    $ResponseJSON = ConvertTo-Json $postUpgradeResponse -Compress -Depth 5
    Write-Verbose "Response received from Upgrade site $postUpgradeResponse"  
    if($postUpgradeResponse.status -ieq "success"){
        Write-Verbose "Post Upgrade Step Successful"
    }

    Write-Verbose "Reindexing Portal"
    Upgrade-Reindex -PortalHttpsUrl "https://$($FQDN):7443" -PortalSiteName 'arcgis' -Referer $Referer -Token $token.token

    Write-Verbose "Upgrading Living Atlas Content"
    if(Get-LivingAtlasStatus -PortalHttpsUrl "https://$($FQDN):7443" -PortalSiteName 'arcgis' -Referer $Referer -Token $token.token){
        Upgrade-LivingAtlas -PortalHttpsUrl "https://$($FQDN):7443" -PortalSiteName 'arcgis' -Referer $Referer -Token $token.token
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
		$PortalAdministrator
	)
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    $FQDN = Get-FQDN $PortalHostName
    $Referer = "https://localhost"
    
    Wait-ForUrl -Url "https://$($FQDN):7443/arcgis/portaladmin" -MaxWaitTimeInSeconds 600 -SleepTimeInSeconds 15 -HttpMethod 'GET'

    $TestPortalResponse = Invoke-ArcGISWebRequest -Url "https://$($FQDN):7443/arcgis/portaladmin" -HttpFormParameters @{ f = 'json' } -Referer $Referer -LogResponse -HttpMethod 'GET'
    if($TestPortalResponse.status -ieq "error" -and $TestPortalResponse.isUpgrade -ieq $true -and $TestPortalResponse.messages[0] -ieq "The portal site has not been upgraded. Please upgrade the site and try again."){
        $false
    }else{
        $PortalHealthCheck = Invoke-ArcGISWebRequest -Url "https://$($FQDN):7443/arcgis/portaladmin/healthCheck" -HttpFormParameters @{ f = 'json' } -Referer $Referer -LogResponse -HttpMethod 'GET'
        if($PortalHealthCheck.status -ieq "success"){
            $true
        }else{
            $jsresponse = ConvertTo-Json $TestPortalResponse -Compress -Depth 5
            Write-Verbose "[WARNING]:- $jsresponse "
        }
    }
}

function Upgrade-Reindex(){

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
    $Response = Invoke-ArcGISWebRequest -Url $ReindexSiteUrl -HttpFormParameters $WebParams -Referer $Referer -TimeOutSec 3000 -LogResponse 
    Write-Verbose "Response received from Reindex site $Response "  
    if($Response.error -and $Response.error.message) {
        throw $Response.error.message
    }
    if($Response.status -ieq 'success') {
        Write-Verbose "Reindexing Successful"
    }
}

function Wait-ForPortalToStart
{
    [CmdletBinding()]
    param(
        [string]$PortalHttpsUrl, 
        [string]$PortalSiteName, 
        [System.Management.Automation.PSCredential]$PortalAdminCredential, 
        [string]$Referer,
        [int]$MaxAttempts = 40,
        [int]$SleepTimeInSeconds = 15
    )

    ##
    ## Wait for the Portal Admin to start back up
    ##
    [string]$CheckPortalAdminUrl = $PortalHttpsUrl.TrimEnd('/') + "/$PortalSiteName/sharing/rest/generateToken"  
    $WebParams = @{ username = $PortalAdminCredential.UserName 
                    password = $PortalAdminCredential.GetNetworkCredential().Password                 
                    client = 'requestip'
                    f = 'json'
                  }
    $HttpBody = To-HttpBody $WebParams
    [bool]$Done = $false
    [int]$NumOfAttempts = 0
    Write-Verbose "Check sharing API Url:- $CheckPortalAdminUrl"
    $Headers = @{'Content-type'='application/x-www-form-urlencoded'
                  'Content-Length' = $HttpBody.Length
                  'Accept' = 'text/plain'     
                  'Referer' = $Referer             
                }
    while(($Done -eq $false) -and ($NumOfAttempts -lt $MaxAttempts))
    {
        if($NumOfAttempts -gt 1) {
            Write-Verbose "Attempt # $NumOfAttempts"            
        }
        
        $response = $null
        Try {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
            [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
            $response = Invoke-RestMethod -Method Post -Uri $CheckPortalAdminUrl -Headers $Headers -Body $HttpBody -TimeoutSec 30 # -MaximumRedirection 1
            if(($response -ne $null) -and ($response.token -ne $null) -and ($response.token.Length -gt 0))        {    
                Write-Verbose "Portal returned a token successfully"  
                $Done = $true                
            }elseif($response -ne $null){
                Write-Verbose (ConvertTo-Json $response -Compress -Depth 5)
                if($NumOfAttempts -gt 1) {
                    Write-Verbose "Sleeping for $SleepTimeInSeconds seconds"
                }
                Start-Sleep -Seconds $SleepTimeInSeconds
                $NumOfAttempts++
            }
        }catch{
            Write-Verbose "[WARNING]:- Exception:- $($_)"     
        }
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
    $resp = Invoke-ArcGISWebRequest -Url $LAStatusURL -HttpFormParameters @{ f = 'json'; token = $Token; q = "owner:esri_livingatlas" } -Referer $Referer -LogResponse
    if($resp.total -gt 0){
        $true
    }else{
        $false
    }
}

function Upgrade-LivingAtlas
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

    $result = @{}
    [string[]]$LivingAtlasGroupIds =  "81f4ed89c3c74086a99d168925ce609e", "6646cd89ff1849afa1b95ed670a298b8"

    ForEach ($groupId in $LivingAtlasGroupIds)
    {
        $done = $true
        $attempts = 0
        while($done){
            $LAUpgradeURL = $PortalHttpsUrl.TrimEnd('/') + "/$PortalSiteName/portaladmin/system/content/livingatlas/upgrade"
            try{
				$resp = Invoke-ArcGISWebRequest -Url $LAUpgradeURL -HttpFormParameters @{ f = 'json'; token = $Token; groupId = $groupId } -Referer $Referer -LogResponse
				if($resp.status -eq "success"){
					Write-Verbose "Upgraded Living Atlas Content For GroupId - $groupId"
					$done = $false
				}
			}catch{
				if($attempts -eq 3){
					Write-Verbose "Unable to update Living Atlas Content For GroupId - $groupId - Please Follow Manual Steps specified in the Documentation"
					$done = $false
				}
			}
			$attempts++
        }
    }
}

function Restart-PortalService
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [System.String]
        $ServiceName = 'Portal for ArcGIS'
    )

    try 
    {
		Write-Verbose "Restarting Service $ServiceName"
		Stop-Service -Name $ServiceName -Force -ErrorAction Ignore
		Write-Verbose 'Stopping the service' 
		Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Stopped'
		Write-Verbose 'Stopped the service'
	}catch {
        Write-Verbose "[WARNING] Stopping Service $_"
    }

	try {
		Write-Verbose 'Starting the service'
		Start-Service -Name $ServiceName -ErrorAction Ignore        
		Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Running'
		Write-Verbose "Restarted Service '$ServiceName'"
	}catch {
        Write-Verbose "[WARNING] Starting Service $_"
    }
}

Export-ModuleMember -Function *-TargetResource