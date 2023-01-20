$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

<#
    .SYNOPSIS
        Makes a request to the installed Server to create a New Server Site or Join it to an existing Server Site
    .PARAMETER ServerHostName
        Optional Host Name or IP of the Machine on which the Server has been installed and is to be configured.
    .PARAMETER Ensure
        Ensure makes sure that a Server site is configured and joined to site if specified. Take the values Present or Absent. 
        - "Present" ensures that a server site is created or the server is joined to an existing site.
        - "Absent" ensures that existing server site is deleted (Not Implemented).
    .PARAMETER ConfigurationStoreLocation
        Key - Path to Configuration store - Can be a Physical Location or Network Share Address
    .PARAMETER ServerDirectoriesRootLocation
        Path to Server Root Directories - Can be a Physical Location or Network Share Address
    .PARAMETER ServerDirectories
        Default Server Directories Object.
    .PARAMETER ServerLogsLocation
        Location for the Server Logs
    .PARAMETER LocalRepositoryPath
        Default location for the local repository
    .PARAMETER ConfigStoreCloudStorageConnectionString
        Connection string to Azure Cloud Storage Account to configure a Site with config store using a Cloud Store
    .PARAMETER ConfigStoreCloudStorageConnectionSecret
        Connection string Secret to Azure Cloud Storage Account to configure a Site with config store using a Cloud Store
    .PARAMETER SiteAdministrator
        A MSFT_Credential Object - Primary Site Administrator
    .PARAMETER Join
        Boolean to indicate whether to Join or Create a new Site
    .PARAMETER PeerServerHostName
        Required Host Name of the Peer Machine in case the Site Needs to be joined to an existing Server Site with the said HostName.
    .PARAMETER LogLevel
        Defines the Logging Level of Server. Can have values - "OFF","SEVERE","WARNING","INFO","FINE","VERBOSE","DEBUG" 
    .PARAMETER EnableUsageMetering
        Boolean to indicate whether to enable the internal usage metering plugin
#>
function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
        [parameter(Mandatory = $True)]    
        [System.String]
        $Version,

        [parameter(Mandatory = $false)]    
        [System.String]
        $ServerHostName,

		[ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,    

        [parameter(Mandatory = $true)]
        [System.String]
        $ConfigurationStoreLocation,

        [System.String]
        $ConfigStoreCloudStorageConnectionString,

        [System.String]
        $ConfigStoreCloudStorageConnectionSecret,

        [parameter(Mandatory = $true)]
        [System.String]
        $ServerDirectoriesRootLocation,

        [parameter(Mandatory = $false)]
        [System.String]
        $ServerDirectories= $null,

        [parameter(Mandatory = $false)]
		[System.String]
        $ServerLogsLocation = $null,

        [parameter(Mandatory = $false)]
		[System.String]
        $LocalRepositoryPath = $null,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator,

        [System.Boolean]
        $Join,

        [System.String]
        $PeerServerHostName,

        [System.String]
        $LogLevel,

        [System.Boolean]
        $EnableUsageMetering
	)

	$null
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
        [parameter(Mandatory = $True)]    
        [System.String]
        $Version,

        [parameter(Mandatory = $false)]    
        [System.String]
        $ServerHostName,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [parameter(Mandatory = $true)]
		[System.String]
		$ConfigurationStoreLocation,

        [System.String]
        $ConfigStoreCloudStorageConnectionString,

        [System.String]
        $ConfigStoreCloudStorageConnectionSecret,

        [parameter(Mandatory = $true)]
		[System.String]
        $ServerDirectoriesRootLocation,

        [parameter(Mandatory = $false)]
        [System.String]
        $ServerDirectories,
        
        [parameter(Mandatory = $false)]
		[System.String]
        $ServerLogsLocation = $null,

        [parameter(Mandatory = $false)]
		[System.String]
        $LocalRepositoryPath = $null,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

        [System.Boolean]
		$Join,

        [System.String]
        $PeerServerHostName,
        
        [System.String]
		$LogLevel,

        [System.Boolean]
        $EnableUsageMetering
	)
    
    if($VerbosePreference -ine 'SilentlyContinue') 
    {        
        Write-Verbose ("Site Administrator UserName:- " + $SiteAdministrator.UserName) 
        #Write-Verbose ("PSA Password:- " + $SiteAdministrator.GetNetworkCredential().Password) 
    }

    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    Write-Verbose "Fully Qualified Domain Name :- $FQDN"

	$ServiceName = 'ArcGIS Server'
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir
    
	[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	Write-Verbose "Waiting for Server 'https://$($FQDN):6443/arcgis/admin' to initialize"
    Wait-ForUrl "https://$($FQDN):6443/arcgis/admin" -HttpMethod 'GET'
    Wait-ForUrl -Url "https://$($FQDN):6443/arcgis/rest/info/healthCheck?f=json" -HttpMethod 'GET'

    if($Ensure -ieq 'Present') {
       
        $Referer = 'http://localhost' 

        $RestartRequired = $false
        $configuredHostName = Get-ConfiguredHostName -InstallDir $InstallDir
        if($configuredHostName -ine $FQDN){
            Write-Verbose "Configured Host Name '$configuredHostName' is not equal to '$($FQDN)'. Setting it"
            if(Set-ConfiguredHostName -InstallDir $InstallDir -HostName $FQDN) { 
				# Need to restart the service to pick up the hostname 
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

        if($RestartRequired) {
			Restart-ArcGISService -ServiceName $ServiceName -Verbose

			Write-Verbose "Waiting for Server 'https://$($FQDN):6443/arcgis/admin' to initialize"
            Wait-ForUrl "https://$($FQDN):6443/arcgis/admin" -HttpMethod 'GET' -Verbose
            Wait-ForUrl -Url "https://$($FQDN):6443/arcgis/rest/info/healthCheck?f=json" -HttpMethod 'GET'
            Start-Sleep -Seconds 30
        }

        $ServerUrl = "https://$($FQDN):6443"
        Write-Verbose "Checking for site on '$ServerUrl'"
        $siteExists = $false
        try {  
            $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer 
            $siteExists = ($null -ne $token.token)
        }
        catch {
            Write-Verbose "[WARNING] GetToken returned:- $_"
        }

        if($Join) {
            if(-not($siteExists)) {
                Write-Verbose 'Joining to Server Site'
                Join-Site -ServerName $PeerServerHostName -Credential $SiteAdministrator -Referer $Referer -CurrentMachineServerHostName $FQDN -Version $Version
                Write-Verbose 'Joined to Server Site'
            }else{
                Write-Verbose "Skipping Join site operation. $FQDN already belongs to a site."
            }
        }else {
            if(-not($siteExists)) {
                [int]$Attempt = 1
                [bool]$Done = $false
                while(-not($Done) -and ($Attempt -le 3)) {                
                    try {
						Write-Verbose 'Creating Site'
						if($Attempt -gt 1) {
							Write-Verbose "Attempt # $Attempt"   
						}            
                        Invoke-CreateSite -ServerURL $ServerUrl -Credential $SiteAdministrator `
                                    -ConfigurationStoreLocation $ConfigurationStoreLocation `
                                    -ServerDirectoriesRootLocation $ServerDirectoriesRootLocation -ServerDirectories $ServerDirectories `
                                    -ConfigStoreCloudStorageConnectionString $ConfigStoreCloudStorageConnectionString `
                                    -ConfigStoreCloudStorageConnectionSecret $ConfigStoreCloudStorageConnectionSecret `
                                    -LogLevel $LogLevel -ServerLogsLocation $ServerLogsLocation -LocalRepositoryPath $LocalRepositoryPath -Verbose 
                        $Done = $true
                        Write-Verbose 'Created Site'
                    }
                    catch {
                        Write-Verbose "[WARNING] Error while creating site on attempt $Attempt Error:- $_"
                        if($Attempt -lt 1) {
                            # If the site failed to create because of permissions. Restart the service and try again
                            Restart-ArcGISService -ServiceName $ServiceName -Verbose

							Write-Verbose "Waiting for Server 'https://$($FQDN):6443/arcgis/admin' to initialize"
                            Wait-ForUrl -Url "https://$($FQDN):6443/arcgis/admin" -HttpMethod 'GET'
                            Wait-ForUrl -Url "https://$($FQDN):6443/arcgis/rest/info/healthCheck?f=json" -HttpMethod 'GET'
                        }else {
                            Write-Verbose "[WARNING] Unable to create Site. Error:- $_"
                            if($_.ToString().IndexOf('The remote name could not be resolved') -gt -1) {
								if($Attempt -ge 3) {
									$err = "Failed to create site after multiple attempts due to network initialization. Please retry using the back and finish buttons"
								}else {
									Write-Verbose "Possible networking initialization error." # ArcGIS Server was not able to resolve the host (networking race conditions). Retry
								}
                            } else {
                                $err = $_
                                Write-Verbose $err
                            }
                            $retryTime = if($ConfigStoreCloudStorageConnectionString){ 120 }else{ 45 }
                            Write-Verbose "Retrying site creation after $retryTime seconds"
                            Start-Sleep -Seconds $retryTime
                        }
                        if($Attempt -ge 3){
                            throw $_
                        }
                    }
                    $Attempt = $Attempt + 1
                }
            }

            if(-not($Join)) {
				Write-Verbose "Waiting for Server 'https://$($FQDN):6443/arcgis/admin' to initialize"
                Wait-ForUrl -Url "https://$($FQDN):6443/arcgis/admin" -Verbose -MaxWaitTimeInSeconds 180 -HttpMethod 'GET'
                Wait-ForUrl -Url "https://$($FQDN):6443/arcgis/rest/info/healthCheck?f=json" -HttpMethod 'GET'
                #Write-Verbose "Get Server Token" 
                $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer  
                #Write-Verbose "Got Server Token $($token.token)" 
            }

            Write-Verbose "Waiting for Server 'https://$($FQDN):6443/arcgis/admin' to initialize"
            Wait-ForUrl -Url "https://$($FQDN):6443/arcgis/admin" -HttpMethod 'GET'
            Wait-ForUrl -Url "https://$($FQDN):6443/arcgis/rest/info/healthCheck?f=json" -HttpMethod 'GET'

            #Write-Verbose 'Get Server Token'   
            $token = Get-ServerToken -ServerEndPoint "https://$($FQDN):6443" -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer

			Write-Verbose "Ensuring Log Level $LogLevel"	
            $logSettings = Get-LogSettings -ServerURL $ServerUrl -Token $token.token -Referer $Referer
            Write-Verbose "Current Log Level:- $($logSettings.settings.logLevel)"

            if($logSettings.settings.logLevel -ine $LogLevel -or ($logSettings.settings.usageMeteringEnabled -ne $EnableUsageMetering) -or (-not([string]::IsNullOrEmpty($ServerLogsLocation)) -and ($logSettings.settings.logDir.TrimEnd("/") -ne $ServerLogsLocation.TrimEnd("/"))) ) {
                if(-not([string]::IsNullOrEmpty($ServerLogsLocation))){
                    $logSettings.settings.logDir = $ServerLogsLocation
                }
                $logSettings.settings.logLevel = $LogLevel
                $logSettings.settings.usageMeteringEnabled = $EnableUsageMetering
                Write-Verbose "Updating log level to $($logSettings.settings.logLevel), log dir to $($logSettings.settings.logDir) and usageMeteringEnabled to $($logSettings.settings.usageMeteringEnabled)"
                Update-LogSettings -ServerURL "https://$($FQDN):6443" -Token $token.token -Referer $Referer -logSettings $logSettings.settings 
                Write-Verbose "Updated log level to $($logSettings.settings.logLevel), log dir to $($logSettings.settings.logDir) and usageMeteringEnabled to $($logSettings.settings.usageMeteringEnabled)"
            }
        }
    }
    elseif($Ensure -ieq 'Absent') {
        Write-Verbose 'Deleting Site'
        Invoke-DeleteSite -ServerURL "https://$($FQDN):6443" -Credential $SiteAdministrator
        Write-Verbose 'Deleted Site'

        Write-Verbose "Deleting contents of $ConfigStoreRootLocation"
        Remove-Item $ConfigurationStoreLocation -Recurse -Force
        Write-Verbose "Deleted contents of $ServerDirectoriesRootLocation"  
        Remove-Item $ServerDirectoriesRootLocation -Recurse -Force
    }
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [parameter(Mandatory = $True)]    
        [System.String]
        $Version,

        [parameter(Mandatory = $false)]    
        [System.String]
        $ServerHostName,

        [parameter(Mandatory = $true)]
        [System.String]
        $ConfigurationStoreLocation,
        
        [ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [parameter(Mandatory = $true)]
		[System.String]
        $ServerDirectoriesRootLocation,

        [parameter(Mandatory = $false)]
        [System.String]
        $ServerDirectories,

        [parameter(Mandatory = $false)]
		[System.String]
        $ServerLogsLocation = $null,
        
        [parameter(Mandatory = $false)]
		[System.String]
        $LocalRepositoryPath = $null,
        
        [System.String]
        $ConfigStoreCloudStorageConnectionString,

        [System.String]
        $ConfigStoreCloudStorageConnectionSecret,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

        [System.Boolean]
		$Join,

        [System.String]
        $PeerServerHostName,
        
        [System.String]
		$LogLevel,

        [System.Boolean]
        $EnableUsageMetering
    )
    
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    Write-Verbose "Fully Qualified Domain Name :- $FQDN" 
    $Referer = 'http://localhost'
    $ServerUrl = "https://$($FQDN):6443"
    $result = $false
    try {        
        Write-Verbose "Checking for site on '$ServerUrl'"
        Wait-ForUrl -Url $ServerUrl -SleepTimeInSeconds 5 -HttpMethod 'GET'  
        Wait-ForUrl -Url "https://$($FQDN):6443/arcgis/rest/info/healthCheck?f=json" -HttpMethod 'GET'
        $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer 
        $result = ($null -ne $token.token)
        if($result){
            Write-Verbose "Site Exists. Was able to retrieve token for PSA"
        }else{
            Write-Verbose "Unable to detect if Site Exists. Was NOT able to retrieve token for PSA"
        }
    }
    catch {
        Write-Verbose "[WARNING]:- $($_)"
    }

    if($result -and $LogLevel){
        #Write-Verbose "Token $($token.token)"
        $logSettings = Get-LogSettings -ServerURL $ServerUrl -Token $token.token -Referer $Referer
        Write-Verbose "Current Log Level $($logSettings.settings.logLevel)"
        if($logSettings.settings.logLevel -ine $LogLevel) {
            Write-Verbose "Current Log Level $($logSettings.settings.logLevel) not set to '$LogLevel'"
            $result = $false
        }
        if($result -and -not([string]::IsNullOrEmpty($ServerLogsLocation)) -and ($logSettings.settings.logDir.TrimEnd("/") -ne $ServerLogsLocation.TrimEnd("/"))){
            Write-Verbose "Current Server Log Directory $($logSettings.settings.logDir.TrimEnd("/")) not set to '$($ServerLogsLocation.TrimEnd("/"))'"
            $result = $false
        }
        if($result -and $logSettings.settings.usageMeteringEnabled -ne $EnableUsageMetering) {
            Write-Verbose "Current usageMeteringEnabled not set to $($logSettings.settings.usageMeteringEnabled)"
            $result = $false
        }
    }
    
    if($result) {
        $ServiceName = 'ArcGIS Server'
        $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
        $InstallDir =(Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir 
        $configuredHostName = Get-ConfiguredHostName -InstallDir $InstallDir
        if($configuredHostName -ine $FQDN){
            Write-Verbose "Configured Host Name '$configuredHostName' is not equal to '$FQDN'"
            $result = $false
        }

		if($result) {
            if(Get-NodeAgentAmazonElementsPresent -InstallDir $InstallDir) {
                Write-Verbose "Amazon Elements present in NodeAgentExt.xml. Will be removed in Set Method"
                $result = $false
            }         
        }
    }

    if($Ensure -ieq 'Present') {
	       $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}


<#
    .SYNOPSIS
        Makes a request to the installed Server to create a New Server Site
    .PARAMETER ServerURL
        Url of Server
    .PARAMETER UserName
        UserName of the Primary Site Administrator
    .PARAMETER Password
        Password of the Primary Site Administrator
    .PARAMETER ConfigurationStoreLocation
        Path to Configuration store - Can be a Physical Location or Network Share Address
    .PARAMETER ServerDirectoriesRootLocation
         Path to Server Directories - Can be a Physical Location or Network Share Address
    .PARAMETER TimeOut
        Time in Seconds after the web request to the server for creating site Times out i.e. return an error after the said period for a response
#>


function Invoke-CreateSite
{    
    [CmdletBinding()]
    Param
    (
        [System.String]
        $ServerURL,

        [System.Management.Automation.PSCredential]
        $Credential, 

        [System.String]
        $ConfigurationStoreLocation,

        [System.String]
        $ConfigStoreCloudStorageConnectionString,

        [System.String]
        $ConfigStoreCloudStorageConnectionSecret,

        [System.String]
        $ServerDirectoriesRootLocation,

        [System.String]
        $ServerDirectories,
        
        [System.String]
        $LocalRepositoryPath,

        [System.Int32]
        $TimeOut = 1000,
        
        [System.String]
        $ServerLogsLocation,

        [System.String]
        $LogLevel = "WARNING"
    )

    $createNewSiteUrl  = $ServerURL.TrimEnd("/") + "/arcgis/admin/createNewSite"
    $baseHostUrl       = $ServerURL.TrimEnd("/") + "/"

    if($ConfigStoreCloudStorageConnectionString -and $ConfigStoreCloudStorageConnectionString.Length -gt 0){
        if($ConfigStoreCloudStorageConnectionString.IndexOf('AccountName=') -gt -1){
            Write-Verbose "Using Azure Cloud Storage for the config store"
            $configStoreConnection = @{ 
                                        type= "AZURE"; 
                                        connectionString = $ConfigStoreCloudStorageConnectionString;
                                        connectionSecret = $ConfigStoreCloudStorageConnectionSecret
                                    }
        }else{
            Write-Verbose "Using AWS Cloud Storage for the config store"
            $configStoreConnection = @{ 
                type= "AMAZON"; 
                connectionString = $ConfigStoreCloudStorageConnectionString;
            }

            if($ConfigStoreCloudStorageConnectionSecret -and $ConfigStoreCloudStorageConnectionSecret.Length -gt 0){
                $configStoreConnection.Add("connectionSecret",$ConfigStoreCloudStorageConnectionSecret)
            }
        }
        $Timeout = 2 * $Timeout # Double the timeout if using cloud storage for the config store        
    }else{
        Write-Verbose "Using File System Based Storage for the config store"
        $configStoreConnection = @{ type= "FILESYSTEM"; connectionString = $ConfigurationStoreLocation }
    }

    if(-not([string]::IsNullOrEmpty($LocalRepositoryPath ))){  
        $configStoreConnection["localRepositoryPath"] = $LocalRepositoryPath
    }

    $ServerDirectoriesObject = (ConvertFrom-Json $ServerDirectories)
    $directories = @{directories = @()}

    $directories.directories += if(($ServerDirectoriesObject | Where-Object {$_.name -ieq "arcgissystem"}| Measure-Object).Count -gt 0){
        ($ServerDirectoriesObject | Where-Object {$_.name -ieq "arcgissystem"})
    }else{
        @{ name = "arcgissystem";
            physicalPath = "$ServerDirectoriesRootLocation\arcgissystem";
            directoryType = "SYSTEM";
            cleanupMode = "NONE";
            maxFileAge = 0
        }
    }

    $directories.directories += if(($ServerDirectoriesObject | Where-Object {$_.name -ieq "arcgisjobs"}| Measure-Object).Count -gt 0){
        ($ServerDirectoriesObject | Where-Object {$_.name -ieq "arcgisjobs"})
    }else{
        @{ name = "arcgisjobs";
            physicalPath = "$ServerDirectoriesRootLocation\arcgisjobs";
            directoryType = "JOBS";
            cleanupMode = "TIME_ELAPSED_SINCE_LAST_MODIFIED";
            maxFileAge = 360
        }
    }

    $directories.directories += if(($ServerDirectoriesObject | Where-Object {$_.name -ieq "arcgisoutput"}| Measure-Object).Count -gt 0){
        ($ServerDirectoriesObject | Where-Object {$_.name -ieq "arcgisoutput"})
    }else{
        @{ name = "arcgisoutput";
            physicalPath = "$ServerDirectoriesRootLocation\arcgisoutput";
            directoryType = "OUTPUT";
            cleanupMode = "TIME_ELAPSED_SINCE_LAST_MODIFIED";
            maxFileAge = 10
        }
    }

    $directories.directories += if(($ServerDirectoriesObject | Where-Object {$_.name -ieq "arcgiscache"}| Measure-Object).Count -gt 0){
        ($ServerDirectoriesObject | Where-Object {$_.name -ieq "arcgiscache"})
    }else{
        @{ name = "arcgiscache";
            physicalPath = "$ServerDirectoriesRootLocation\arcgiscache";
            directoryType = "CACHE";
            cleanupMode = "NONE";
            maxFileAge = 0
        }
    }

    $requestParams = @{ 
                        f = "json"
                        username = $Credential.UserName
                        password = $Credential.GetNetworkCredential().Password
                        configStoreConnection = ConvertTo-Json $configStoreConnection -Compress -Depth 4
                        directories = ConvertTo-Json $directories -Compress
                        runAsync = "false"
                    }
    if(-not([string]::IsNullOrEmpty($ServerLogsLocation))){           
        $requestParams["logsSettings"] = (ConvertTo-Json -Compress -InputObject @{
            logLevel= $LogLevel;
            logDir= $ServerLogsLocation;
            maxErrorReportsCount= 10;
            maxLogFileAge= 90
        })
    }

    # make sure Tomcat is up and running BEFORE sending a request
    Write-Verbose "Waiting for Server 'https://$($FQDN):6443/arcgis/admin' to initialize"
    Wait-ForUrl -Url $baseHostUrl -SleepTimeInSeconds 5 -HttpMethod 'GET'

    $httpRequestBody = ConvertTo-HttpBody -props $requestParams
    #Write-Verbose $requestParams
    $response = Invoke-RestMethod -Method Post -Uri $createNewSiteUrl -Body $httpRequestBody -TimeoutSec $TimeOut
    Write-Verbose "Response from CreateSite:- $($response | ConvertTo-Json)"
	$responseMessages = ($response.messages -join ', ')
	if ($response.status -and ($response.status -ieq "error")) { 
        throw "CreateSite Failed. Error:- $responseMessages"
    }
}


function Get-LogSettings
{
    [CmdletBinding()]
    Param
    (
        [System.String]
        $ServerURL, 

        [System.String]
        $Token, 
        
        [System.String]
        $Referer
    )

    $GetLogSettingsUrl  = $ServerURL.TrimEnd("/") + "/arcgis/admin/logs/settings"
    $params = @{ f = 'json'; token = $Token; }
    $response = Invoke-ArcGISWebRequest -Url $GetLogSettingsUrl -HttpFormParameters $params -Referer $Referer
    Write-Verbose "Response from GetLogSettings:- $($response.Content)"
    Confirm-ResponseStatus $response 
    $response    
}

function Update-LogSettings
{
    [CmdletBinding()]
    Param
    (
        [System.String]
        $ServerURL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer,

        $logSettings
    )    
    $usageMeteringEnabled = if($logSettings.usageMeteringEnabled) { 'on' } else { 'off' } # API uses a checkbox and hence need to provide on/off values
    $UpdateLogSettingsUrl  = $ServerURL.TrimEnd("/") + "/arcgis/admin/logs/settings/edit"
    $props = @{ f= 'json'; token = $Token; logDir = $logSettings.logDir; logLevel = $logSettings.logLevel; 
                maxLogFileAge = $logSettings.maxLogFileAge; maxErrorReportsCount = $logSettings.maxErrorReportsCount;
                usageMeteringEnabled = $usageMeteringEnabled }
    $response = Invoke-ArcGISWebRequest -Url $UpdateLogSettingsUrl -HttpFormParameters $props -Referer $Referer
    Confirm-ResponseStatus $response
    $response
}

function Join-Site
{ 
    [CmdletBinding()]
    Param
    (
        [System.String]
        $ServerName,

        [System.String]
        $ClusterName="default",

        [System.Management.Automation.PSCredential]
        $Credential,

        [System.String]
        $Referer,

        [System.String]
        $CurrentMachineServerHostName,

        [System.String]
        $Version
    )

    $ServerFQDN = Get-FQDN $ServerName

	$SiteServerURL = "https://$($ServerFQDN):6443/arcgis/admin"
	$LocalAdminURL = "https://localhost:6443/arcgis/admin"
	$JoinSiteUrl   = "$LocalAdminURL/joinSite"

	$JoinSiteParams = @{ adminURL= $SiteServerURL; f = 'json'; username = $Credential.UserName; password = $Credential.GetNetworkCredential().Password }

	Write-Verbose "Waiting for Site Server URL $SiteServerUrl to respond"
	Wait-ForUrl $SiteServerUrl -Verbose    
                  
	Write-Verbose "Waiting for Local Admin URL $LocalAdminURL to respond"
	Wait-ForUrl $LocalAdminURL -Verbose  
    
    $NumAttempts        = 0           
	$SleepTimeInSeconds = 30
	$Success            = $false
	$Done               = $false
	while ((-not $Done) -and ($NumAttempts++ -lt 5)){               
        $response = Invoke-ArcGISWebRequest -Url $JoinSiteUrl -HttpFormParameters $JoinSiteParams -Referer $Referer -TimeOutSec 360
		if($response) {
			if ($response -and $response.status -and ($response.status -ine "error")) {
                if($response.pollAfter){
                    Start-Sleep -Seconds $response.pollAfter
                }
				$Done    = $true
				$Success = $true
				break
			}
		}
    
		Write-Verbose "Attempt # $NumAttempts failed."
		if ($response.status)   { Write-Verbose "`tStatus   : $($response.status)."   }
		if ($response.messages) { Write-Verbose "`tMessages : $($response.messages)." }
		Write-Verbose "Retrying after $SleepTimeInSeconds seconds..."
        Start-Sleep -Seconds $SleepTimeInSeconds 
	}

    if(-not($Success)){
		throw "Failed to Join Site after multiple attempts. Error on last attempt:- $($response.messages)"
	}

	Write-Verbose "Successfully Joined Site:- $SiteServerURL"  
	Write-Verbose "Waiting for Site Server URL $SiteServerUrl to respond"

	Start-Sleep -Seconds 30  # Wait for Server to come back up

	##
	## Adding site (might) restart the server instance (Wait for admin endpoint to comeback up)
	##
	$LocalMachineFQDN = "https://$($CurrentMachineServerHostName):6443/arcgis/admin/"
	Write-Verbose "Waiting for Machine URL $LocalMachineFQDN to respond"
	Wait-ForUrl $LocalMachineFQDN -Verbose
  
	Write-Verbose "Waiting for Site Server URL $SiteServerUrl to respond"
	Wait-ForUrl $SiteServerUrl -Verbose   
  
	####### Get new token 
	$token = Get-ServerToken -ServerEndPoint "https://localhost:6443" -ServerSiteName 'arcgis' -Credential $Credential -Referer $Referer 
    
    ####### Add to cluster
    $VersionArray = $Version.Split(".")

    if($VersionArray[0] -eq 10 -and $VersionArray[1] -lt 8){
        Write-Verbose "Adding machine '$CurrentMachineServerHostName' to cluster '$clusterName'"  
        $AddMachineUrl  = "$LocalAdminURL/clusters/$clusterName/machines/add" 
        $AddMachineParams = @{ token = $token.token; f = 'json';machineNames = $CurrentMachineServerHostName }

        $NumAttempts        = 1 
        $SleepTimeInSeconds = 30
        $Success            = $false
        $Done               = $false
        while ((-not $Done) -and ($NumAttempts++ -le 3)){
            $response = Invoke-ArcGISWebRequest -Url $AddMachineUrl -HttpFormParameters $AddMachineParams -Referer $Referer -TimeOutSec 180
            if ($response -and $response.status -and ($response.status -ine "error")) {
                $Done    = $true
                $Success = $true
                break
            }
        
            Write-Verbose "Attempt # $NumAttempts failed."
            if ($response.status)   { Write-Verbose "`tStatus   : $($response.status)."   }
            if ($response.messages) { Write-Verbose "`tMessages : $($response.messages)." }
            Write-Verbose "Retrying after $SleepTimeInSeconds seconds..."
            Start-Sleep -Seconds $SleepTimeInSeconds 
        }

        if(-not($Success)){
            throw "Failed to add machine to cluster. Error on last attempt:- $($response.messages)"
        }

        Write-Verbose "Machine '$CurrentMachineServerHostName' is added to cluster '$clusterName'"
    }
}  

function Invoke-DeleteSite
{    
    [CmdletBinding()]
    Param
    (
        [System.String]
        $ServerURL,

        [System.Management.Automation.PSCredential]
        $Credential,

        [System.Int32]
        $TimeOut = 300
    )

    $Referer = $ServerURL
    $token = Get-ServerToken -ServerEndPoint $ServerURL -ServerSiteName 'arcgis' -Credential $Credential -Referer $Referer
    $DeleteSiteUrl  = $ServerURL.TrimEnd("/") + "/arcgis/admin/deleteSite" 
    $response = Invoke-ArcGISWebRequest -Url $DeleteSiteUrl -HttpFormParameters @{ f= 'json'; token = $token.token; } -Referer $Referer -TimeOutSec $TimeOut
    Write-Verbose ($response.messages -join ', ') 
}

Export-ModuleMember -Function *-TargetResource
