<#
    .SYNOPSIS
        Makes a request to the installed Server to create a New Server Site or Join it to an existing Server Site
    .PARAMETER Ensure
        Ensure makes sure that a Server site is configured and joined to site if specified. Take the values Present or Absent.
        - "Present" ensures that a server site is created or the server is joined to an existing site.
        - "Absent" ensures that existing server site is deleted (Not Implemented).
    .PARAMETER ConfigurationStoreLocation
        Key - Path to Configuration store - Can be a Physical Location or Network Share Address
    .PARAMETER ServerDirectoriesRootLocation
        Path to Server Root Directories - Can be a Physical Location or Network Share Address
    .PARAMETER SiteAdministrator
        A MSFT_Credential Object - Primary Site Adminstrator
    .PARAMETER Join
        Boolean to indicate whether to Join or Create a new Site
    .PARAMETER PeerServerHostName
        Required Host Name of the Peer Machine in case the Site Needs to be joined to an existing Server Site with the said HostName.
    .PARAMETER SingleClusterMode
        Enables Single Cluster Mode for Machine
    .PARAMETER LogLevel
        Defines the Logging Level of Server. Can have values - "OFF","SEVERE","WARNING","INFO","FINE","VERBOSE","DEBUG"
    .PARAMETER  Platform
-        Define the platform on which the Server is being installed - (Not Used)
    .PARAMETER DisableServiceDirectory
        Boolean to indicate whether to disable the service directory for ArcGIS Server
#>

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
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
        $SingleClusterMode,

        [System.String]
        $Platform,

        [System.Boolean]
        $DisableServiceDirectory
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

	$null
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
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
        $SingleClusterMode,

        [System.String]
        $Platform,

        [System.Boolean]
        $DisableServiceDirectory
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    if($VerbosePreference -ine 'SilentlyContinue')
    {
        Write-Verbose ("Site Administrator UserName:- " + $SiteAdministrator.UserName)
        #Write-Verbose ("PSA Password:- " + $SiteAdministrator.GetNetworkCredential().Password)
    }

    $FQDN = Get-FQDN $env:COMPUTERNAME
    Write-Verbose "Fully Qualified Domain Name :- $FQDN"

	$ServiceName = 'ArcGIS Server'
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	Write-Verbose "Waiting for Server 'http://$($FQDN):6080/arcgis/admin' to initialize"
    Wait-ForUrl "http://$($FQDN):6080/arcgis/admin" -HttpMethod 'GET'

    if($Ensure -ieq 'Present') {

        $Referer = 'http://localhost'

        $RestartRequired = $false
        $configuredHostName = Get-ConfiguredHostName -InstallDir $InstallDir
        if($configuredHostName -ine $FQDN){
            Write-Verbose "Configured Host Name $configuredHostName is not equal to $($FQDN). Setting it"
            if(Set-ConfiguredHostName -InstallDir $InstallDir -HostName $FQDN) {
                # Need to restart the service to pick up the hostname
                $RestartRequired = $true
            }
        }

		$RemoveEC2ObserverFromNodeAdentXml = $false
		[string]$RealVersion = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\ESRI\ArcGIS').RealVersion
		$DeploymentImageVersion = New-Object 'System.Version' -ArgumentList $RealVersion
		Write-Verbose "Version of ArcGIS Server is $DeploymentImageVersion"
		if($DeploymentImageVersion.Major -le 10 -and $DeploymentImageVersion.Minor -le 5 -and $DeploymentImageVersion.Build -le 6491) {
			Write-Verbose "Version of ArcGIS Server requires removal of EC2 Listener from NodeAgent xml file"
			$RemoveEC2ObserverFromNodeAdentXml = $true
		}else {
			Write-Verbose "Version of ArcGIS Server does not require removal of EC2 Listener from NodeAgent xml file"
		}
        if($RemoveEC2ObserverFromNodeAdentXml -and $Platform -ine 'amazon') {
            if(Get-NodeAgentAmazonElementsPresent -InstallDir $InstallDir) {
               if(Remove-NodeAgentAmazonElements -InstallDir $InstallDir) {
                    # Need to restart the service to pick up the EC2
                    $RestartRequired = $true
                }
            }
        }

        if($RestartRequired) {

			try {
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
				Write-Verbose "Restarted Service $ServiceName"
			}catch {
                Write-Verbose "[WARNING] Starting Service $_"
            }

			Write-Verbose "Waiting for Server 'http://$($FQDN):6080/arcgis/admin' to initialize"
            Wait-ForUrl "http://$($FQDN):6080/arcgis/admin" -HttpMethod 'GET'
        }

        if($Join) {
            Write-Verbose 'Joining Site'

            Join-Site -ServerName $PeerServerHostName -Credential $SiteAdministrator -Referer $Referer -CurrentMachineName $env:ComputerName

            Write-Verbose 'Joined Site'
        }
        else {
            $ServerUrl = "http://$($FQDN):6080"
            Write-Verbose "Checking for site on '$ServerUrl'"
            $siteExists = $false
            try {
                $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer
                $siteExists = ($token.token -ne $null)
            }
            catch {
                Write-Verbose "[WARNING] GetToken returned:- $_"
            }

            if(-not($siteExists)) {

                Wait-ForHostNameResolution -InstallDir $InstallDir -FQDN $FQDN -MaxAttempts 10 -RetryIntervalInSeconds 5

                [int]$Attempt = 1
                [bool]$Done = $false
                while(-not($Done) -and ($Attempt -le 3)) {
                    try {
						Write-Verbose 'Creating Site'
						if($Attempt -gt 1) {
							Write-Verbose "Attempt # $Attempt"
						}
                        Create-Site -ServerURL $ServerUrl -Credential $SiteAdministrator -ConfigurationStoreLocation $ConfigurationStoreLocation `
                                    -ServerDirectories $ServerDirectoriesRootLocation -Verbose -ConfigStoreCloudStorageConnectionString $ConfigStoreCloudStorageConnectionString `
                                    -ConfigStoreCloudStorageConnectionSecret $ConfigStoreCloudStorageConnectionSecret
                        $Done = $true
                        Write-Verbose 'Created Site'
                    }
                    catch {
                        Write-Verbose "[WARNING] Error while creating site on attempt $Attempt Error:- $_"
                        if($Attempt -lt 1) {
                            # If the site failed to create because of permissions. Restart the service and try again
                            Write-Verbose "Restarting Service $ServiceName"
                            Stop-Service -Name $ServiceName  -Force
                            Write-Verbose 'Stopping the service'
                            Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Stopped'
                            Write-Verbose 'Starting the service'
                            Start-Service -Name $ServiceName
                            Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Running'
                            Write-Verbose "Restarted Service $ServiceName"

							Write-Verbose "Waiting for Server 'http://$($FQDN):6080/arcgis/admin' to initialize"
                            Wait-ForUrl -Url "http://$($FQDN):6080/arcgis/admin" -HttpMethod 'GET'
                        }else {
                            Write-Verbose "[WARNING] Unable to create Site. Error:- $_"
                            if($_.ToString().IndexOf('The remote name could not be resolved') -gt -1) {
								if($Attempt -ge 3) {
									throw "Failed to create site after multiple attempts due to network initialization. Please retry using the back and finish buttons"
								}else {
									# ArcGIS Server was not able to resolve the host (networking race conditions). Retry
									Write-Verbose "Possible networking initialization error. Retry site creation after 30 seconds"
									Start-Sleep -Seconds 30
								}
                            }else {
                                throw $_
                            }
                        }
                    }
                    $Attempt = $Attempt + 1
                }
            }

            if(-not($Join)) {
				Write-Verbose "Waiting for Server 'http://$($FQDN):6080/arcgis/admin' to initialize"
                Wait-ForUrl -Url "http://$($FQDN):6080/arcgis/admin" -LogFailures -MaxWaitTimeInSeconds 180 -HttpMethod 'GET'
                #Write-Verbose "Get Server Token"
                $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer
                #Write-Verbose "Got Server Token $($token.token)"
            }

            if($SingleClusterMode) {
                Write-Verbose "Get Single Cluster Mode Setting"
                $deploymentConfig = Get-SingleClusterModeOnServer -ServerURL $ServerUrl -Token $token.token -Referer $Referer
                Write-Verbose "Current Single Cluster Mode $($deploymentConfig)" # .singleClusterMode
                if(-not($deploymentConfig.singleClusterMode)) {
                    Write-Verbose "Enabling Single Cluster Mode"
                    Set-SingleClusterModeOnServer -ServerURL $ServerUrl -Token $token.token -Referer $Referer -SingleClusterMode $true
                }
            }

            if($DisableServiceDirectory) {
                Write-Verbose "Get Service Directory Setting"
                $servicesdirectory = Get-AdminSettings -ServerUrl $ServerUrl -SettingUrl "arcgis/admin/system/handlers/rest/servicesdirectory" -Token $token.token
                if($servicesdirectory.enabled -eq "true") {
                    $dirStatus = "enabled"
                } else {
                    $dirStatus = "disabled"
                }
                Write-Verbose "Current Service Directory Setting:- $dirStatus"
                if($servicesdirectory.enabled -eq $DisableServiceDirectory) {
                    Write-Verbose "Updating Service Directory Setting"
                    $servicesdirectory.enabled = (!$DisableServiceDirectory)
                    $servicesdirectory = ConvertTo-Json $servicesdirectory
                    Set-AdminSettings -ServerUrl $ServerUrl -SettingUrl "arcgis/admin/system/handlers/rest/servicesdirectory/edit" -Token $token.token -Properties $servicesdirectory
                }
            }

		    Write-Verbose "Waiting for Server 'http://$($FQDN):6080/arcgis/admin' to initialize"
            Wait-ForUrl -Url "http://$($FQDN):6080/arcgis/admin" -HttpMethod 'GET'

            #Write-Verbose 'Get Server Token'
            $token = Get-ServerToken -ServerEndPoint "http://$($FQDN):6080" -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer

			Write-Verbose "Ensuring Log Level $LogLevel"
            $logSettings = Get-LogSettings -ServerURL $ServerUrl -Token $token.token -Referer $Referer
            Write-Verbose "Current Log Level:- $($logSettings.settings.logLevel)"

            if($logSettings.settings.logLevel -ine $LogLevel) {
                $logSettings.settings.logLevel = $LogLevel
                Write-Verbose "Updating log level to $($logSettings.settings.logLevel)"
                Update-LogSettings -ServerURL "http://$($FQDN):6080" -Token $token.token -Referer $Referer -logSettings $logSettings.settings
                #Write-Verbose "Updated log level to $($logSettings.settings.logLevel)"
            }
        }
    }
    elseif($Ensure -ieq 'Absent') {
        Write-Verbose 'Deleting Site'
        Delete-Site -ServerURL "http://$($FQDN):6080" -Credential $SiteAdministrator
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
		[parameter(Mandatory = $true)]
		[System.String]
		$ConfigurationStoreLocation,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [parameter(Mandatory = $true)]
		[System.String]
		$ServerDirectoriesRootLocation,

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
		$SingleClusterMode,

        [System.String]
        $Platform,

        [System.Boolean]
        $DisableServiceDirectory
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $FQDN = Get-FQDN $env:COMPUTERNAME
    Write-Verbose "Fully Qualified Domain Name :- $FQDN"
    $Referer = 'http://localhost'
    $ServerUrl = "http://$($FQDN):6080"
    $result = $false
    try {
        Write-Verbose "Checking for site on '$ServerUrl'"
        Wait-ForUrl -Url $ServerUrl -SleepTimeInSeconds 5 -HttpMethod 'GET'
        $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer
        $result = ($token.token -ne $null)
        if($result){
            Write-Verbose "Site Exists. Was able to retrieve token for PSA"
        }else{
            Write-Verbose "Unable to detect if Site Exists. Was NOT able to retrieve token for PSA"
        }
    }
    catch {
        Write-Verbose "[WARNING]:- $($_)"
    }

    if($result -and $LogLevel) {
        #Write-Verbose "Token $($token.token)"
        $logSettings = Get-LogSettings -ServerURL $ServerUrl -Token $token.token -Referer $Referer
        Write-Verbose "Current Log Level $($logSettings.settings.logLevel)"
        if($logSettings.settings.logLevel -ine $LogLevel) {
            Write-Verbose "Current Log Level $($logSettings.settings.logLevel) not set to '$LogLevel'"
            $result = $false
        }
    }

    if($result -and $SingleClusterMode) {
        Write-Verbose "Get Single Cluster Mode Setting"
        $deploymentConfig = Get-SingleClusterModeOnServer -ServerURL $ServerUrl -Token $token.token -Referer $Referer
        Write-Verbose "Current Single Cluster Mode Setting:- $($deploymentConfig.singleClusterMode)"
        if(-not($deploymentConfig.singleClusterMode)){
            Write-Verbose "Single cluster mode not set"
            $result = $false
        }
    }

    if($result -and $DisableServiceDirectory) {
        Write-Verbose "Get Service Directory Setting"
        $servicesdirectory = Get-AdminSettings -ServerUrl $ServerUrl -SettingUrl "arcgis/admin/system/handlers/rest/servicesdirectory" -Token $token.token
        if($servicesdirectory.enabled -eq "true") {
            $dirStatus = "enabled"
        } else {
            $dirStatus = "disabled"
        }
        Write-Verbose "Current Service Directory Setting:- $dirStatus"
        if($servicesdirectory.enabled -eq $DisableServiceDirectory) {
            $result = $false
        }
    }

    if($result) {
        $ServiceName = 'ArcGIS Server'
        $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
        $InstallDir =(Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir
        $configuredHostName = Get-ConfiguredHostName -InstallDir $InstallDir
        if($configuredHostName -ine $FQDN){
            Write-Verbose "Configured Host Name $configuredHostName is not equal to $FQDN"
            $result = $false
        }

		if($result) {
			$RemoveEC2ObserverFromNodeAdentXml = $false
			[string]$RealVersion = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\ESRI\ArcGIS').RealVersion
			$DeploymentImageVersion = New-Object 'System.Version' -ArgumentList $RealVersion
			if($DeploymentImageVersion.Major -le 10 -and $DeploymentImageVersion.Minor -le 5 -and $DeploymentImageVersion.Build -le 6491) {
				$RemoveEC2ObserverFromNodeAdentXml = $true
			}
			if($RemoveEC2ObserverFromNodeAdentXml -and ($Platform -ine 'amazon')) {
				if(Get-NodeAgentAmazonElementsPresent -InstallDir $InstallDir) {
					Write-Verbose "Amazon Elements present in NodeAgentExt.xml"
					$result = $false
				}
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
    .PARAMETER ServerDirectories
         Path to Server Directories - Can be a Physical Location or Network Share Address
    .PARAMETER TimeOut
        Time in Seconds after the web request to the server for creating site Times out i.e. return an error after the said period for a response
#>


function Create-Site
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
        $ServerDirectories,

        [System.Int32]
        $TimeOut = 1000<#,

        [System.String]
        $InstallDirectory,

        [System.String]
        $LogLevel = "WARNING"#>
    )


    $createNewSiteUrl  = $ServerURL.TrimEnd("/") + "/arcgis/admin/createNewSite"
    $baseHostUrl       = $ServerURL.TrimEnd("/") + "/"

    if(($ConfigStoreCloudStorageConnectionString) -and ($ConfigStoreCloudStorageConnectionSecret) -and ($ConfigStoreCloudStorageConnectionString.IndexOf('AccountName=') -gt -1))
    {
        Write-Verbose "Using Azure Cloud Storage for the config store"
        $configStoreConnection = @{ type= "AZURE";
                                    connectionString = $ConfigStoreCloudStorageConnectionString;
                                    connectionSecret = $ConfigStoreCloudStorageConnectionSecret
                                }
        $Timeout = 2 * $Timeout # Double the timeout if using cloud storage for the config store
    }
    else {
        Write-Verbose "Using File System Based Storage for the config store"
        $configStoreConnection = @{ type= "FILESYSTEM"; connectionString = $ConfigurationStoreLocation }
    }

    $directories = @{ directories = @(
                        @{ name = "arcgiscache";
                            physicalPath = "$ServerDirectories\arcgiscache";
                            directoryType = "CACHE";
			                cleanupMode = "NONE";
			                maxFileAge = 0
                        },
                        @{ name = "arcgisjobs";
                            physicalPath = "$ServerDirectories\arcgisjobs";
                            directoryType = "JOBS";
			                cleanupMode = "TIME_ELAPSED_SINCE_LAST_MODIFIED";
			                maxFileAge = 360
                        },
                        @{ name = "arcgisoutput";
                            physicalPath = "$ServerDirectories\arcgisoutput";
                            directoryType = "OUTPUT";
			                cleanupMode = "TIME_ELAPSED_SINCE_LAST_MODIFIED";
			                maxFileAge = 10
                        },
                        @{ name = "arcgissystem";
                            physicalPath = "$ServerDirectories\arcgissystem";
                            directoryType = "SYSTEM";
			                cleanupMode = "NONE";
			                maxFileAge = 0
                        }
                    )
                }


        <#$logsSettings = @{
                logLevel= $LogLevel;
                logDir= "$InstallDirectory\logs\\";
                maxErrorReportsCount= 10;
                maxLogFileAge= 90
        }#>


    $requestParams = @{
                        f = "json"
                        username = $Credential.UserName
                        password = $Credential.GetNetworkCredential().Password
                        configStoreConnection = ConvertTo-Json $configStoreConnection -Compress -Depth 4
                        directories = ConvertTo-Json $directories -Compress
                        #logsSettings = ConvertTo-Json $logsSettings -Compress
                        runAsync = "false"
                        }

    # make sure Tomcat is up and running BEFORE sending a request
    Write-Verbose "Waiting for Server 'http://$($FQDN):6080/arcgis/admin' to initialize"
    Wait-ForUrl -Url $baseHostUrl -SleepTimeInSeconds 5 -HttpMethod 'GET'

    $httpRequestBody = To-HttpBody -props $requestParams
    Write-Verbose $requestParams
    $response = Invoke-RestMethod -Method Post -Uri $createNewSiteUrl -Body $httpRequestBody -TimeoutSec $TimeOut

    if ($response.status -and ($response.status -ieq "error")) {
        $response.messages | Out-String
    }

    $responseMessages = ($response.messages -join ', ')
    Write-Verbose "Response from CreateSite:- $responseMessages"

    if($responseMessages -and ($responseMessages.IndexOf('Failed to create the site') -gt -1)) {
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
    $props = @{ f= 'json'; token = $Token; }
    $cmdBody = To-HttpBody $props
    $headers = @{'Content-type'='application/x-www-form-urlencoded'
                'Content-Length' = $cmdBody.Length
                'Accept' = 'text/plain'
                'Referer' = $Referer
                }

    $res = Invoke-WebRequest -Uri $GetLogSettingsUrl -Body $cmdBody -Method POST -Headers $headers -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing
    $response = $res.Content | ConvertFrom-Json
	Write-Verbose "Response from Create Site:- $response"
    Check-ResponseStatus $response
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
    $UpdateLogSettingsUrl  = $ServerURL.TrimEnd("/") + "/arcgis/admin/logs/settings/edit"
    $props = @{ f= 'json'; token = $Token; logDir = $logSettings.logDir; logLevel = $logSettings.logLevel;
                maxLogFileAge = $logSettings.maxLogFileAge; maxErrorReportsCount = $logSettings.maxErrorReportsCount;
                usageMeteringEnabled = $logSettings.usageMeteringEnabled }
    $cmdBody = To-HttpBody $props
    $headers = @{'Content-type'='application/x-www-form-urlencoded'
                'Content-Length' = $cmdBody.Length
                'Accept' = 'text/plain'
                'Referer' = $Referer
                }

    $res = Invoke-WebRequest -Uri $UpdateLogSettingsUrl -Body $cmdBody -Method POST -Headers $headers -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing
    $response = $res.Content | ConvertFrom-Json
    Check-ResponseStatus $response
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
      $CurrentMachineName
  )

	$SiteServerURL = "http://$($ServerName):6080/arcgis/admin"
	$LocalAdminURL = "http://localhost:6080/arcgis/admin"
	$JoinSiteUrl   = "$LocalAdminURL/joinSite"

	$HttpBody = To-HttpBody @{ adminURL = $SiteServerURL   # Web Params
								f        = 'json'
								username = $Credential.UserName
								password = $Credential.GetNetworkCredential().Password }

	$Headers = @{ 'Content-type'   = 'application/x-www-form-urlencoded'
				'Content-Length' = $HttpBody.Length
				'Accept'         = 'text/plain'
				'Referer'        = $Referer }

	Write-Verbose "Waiting for Site Server URL $SiteServerUrl to respond"
	Wait-ForUrl $SiteServerUrl -LogFailures

	Write-Verbose "Waiting for Local Admin URL $LocalAdminURL to respond"
	Wait-ForUrl $LocalAdminURL -LogFailures

	$NumAttempts        = 0
	$SleepTimeInSeconds = 30
	$Success            = $false
	$Done               = $false
	while ((-not $Done) -and ($NumAttempts++ -lt 3))
	{
        $response = Invoke-WebRequest -Uri $JoinSiteUrl -Body $HttpBody -Method POST -Headers $Headers -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing -TimeoutSec 180
        Write-Verbose "Response from JoinSite:- $($response.Content)"
        $json = $response.Content | ConvertFrom-Json
        if ($json -and $json.status -and ($json.status -ine "error")) {
            $Done    = $true
            $Success = $true
            break
        }

        Write-Verbose "Attempt # $NumAttempts failed."
        if ($json.status)   { Write-Verbose "`tStatus   : $($json.status)."   }
        if ($json.messages) { Write-Verbose "`tMessages : $($json.messages)." }
        Write-Verbose "Retrying after $SleepTimeInSeconds seconds..."
        Sleep -Seconds $SleepTimeInSeconds
	}

	if (-not $Success) {
		throw "Failed to Join Site after multiple attempts. Error on last attempt:- $($json.messages)"
	}

	Write-Verbose "Successfully Joined Site:- $SiteServerURL"
	Write-Verbose "Waiting for Site Server URL $SiteServerUrl to respond"

	Sleep -Seconds 30  # Wait for Server to come back up

	##
	## Adding site (might) restart the server instance (Wait for admin endpoint to comeback up)
	##
	$LocalMachineFQDN = "http://$(Get-FQDN $CurrentMachineName):6080/arcgis/admin/"
	Write-Verbose "Waiting for Machine URL $LocalMachineFQDN to respond"
	Wait-ForUrl $LocalMachineFQDN -LogFailures

	Write-Verbose "Waiting for Site Server URL $SiteServerUrl to respond"
	Wait-ForUrl $SiteServerUrl -LogFailures

	####### Get new token
	$token = Get-ServerToken -ServerEndPoint "http://localhost:6080" -ServerSiteName 'arcgis' -Credential $Credential -Referer $Referer
	#Write-Verbose "Server Token:- $($token.token)"

	####### Add to cluster
	Write-Verbose "Adding machine '$CurrentMachineName' to cluster '$clusterName'"
	$AddMachineUrl  = "$LocalAdminURL/clusters/$clusterName/machines/add"

	$HttpBody = To-HttpBody @{ token        = $token.token      # WebParams
								f            = 'json'
                                machineNames = $CurrentMachineName
                            }

	$Headers = @{ 'Content-type'   = 'application/x-www-form-urlencoded'
					'Content-Length' = $HttpBody.Length
					'Accept'         = 'text/plain'
                    'Referer'        = $Referer
                }

	$NumAttempts        = 1
	$SleepTimeInSeconds = 30
	$Success            = $false
	$Done               = $false
	while ((-not $Done) -and ($NumAttempts++ -le 3))
	{
        $res  = Invoke-WebRequest -Uri $AddMachineUrl -Body $HttpBody -Method POST -Headers $Headers -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing -TimeoutSec 180
        Write-Verbose "Response from AddMachine:- $($response.Content)"
        $json = $response.Content | ConvertFrom-Json
        if ($json -and $json.status -and ($json.status -ine "error")) {
            $Done    = $true
            $Success = $true
            break
        }

		Write-Verbose "Attempt # $NumAttempts failed."
		if ($json.status)   { Write-Verbose "`tStatus   : $($json.status)."   }
		if ($json.messages) { Write-Verbose "`tMessages : $($json.messages)." }
		Write-Verbose "Retrying after $SleepTimeInSeconds seconds..."
		Sleep -Seconds $SleepTimeInSeconds
	}

	if (-not $Success) {
		throw "Failed to add machine to cluster. Error on last attempt:- $($json.messages)"
	}

   Write-Verbose "Machine '$CurrentMachineName' is added to cluster '$clusterName'"

}

function Delete-Site
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

    $RequestParams = @{
                    f = "json"
                    token= $token.token
                    }
    $HttpBody = To-HttpBody -props $RequestParams

    $Headers = @{'Content-type'='application/x-www-form-urlencoded'
                  'Content-Length' = $HttpBody.Length
                  'Accept' = 'text/plain'
                  'Referer' = $Referer
                }
    $response = Invoke-RestMethod -Method Post -Uri $DeleteSiteUrl -Body $HttpBody -Headers $Headers -TimeoutSec $TimeOut
    Write-Verbose ($response.messages -join ', ')
}


function Set-SingleClusterModeOnServer
{
    [CmdletBinding()]
	param
	(
        [System.String]
        $ServerURL,

        [System.String]
        $Token,

        [System.String]
        $Referer,

        [System.Boolean]
        $SingleClusterMode
	)

    $DeploymentUpdateUrl  = $ServerURL.TrimEnd("/") + "/arcgis/admin/system/deployment/update/"
    $props = @{ f= 'json'; token = $Token;singleClusterMode = $SingleClusterMode.ToString().ToLowerInvariant(); deploymentConfig = $SingleClusterMode.ToString().ToLowerInvariant()  }
    $cmdBody = To-HttpBody $props
    $headers = @{'Content-type'='application/x-www-form-urlencoded'
                'Content-Length' = $cmdBody.Length
                'Accept' = 'text/plain'
                'Referer' = $Referer
                }
    try{
        $res = Invoke-WebRequest -Uri $DeploymentUpdateUrl -Body $cmdBody -Method POST -Headers $headers -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing -TimeoutSec 150 -ErrorAction Ignore
        if($res -and $res.Content) {
            $response = $res.Content | ConvertFrom-Json
            Check-ResponseStatus $response -Url $DeploymentUpdateUrl
            $response
        }
        else {
            Write-Verbose "[WARNING] Response from $DeploymentUpdateUrl is NULL"
        }
    }
    catch
    {
        Write-Verbose "[EXCEPTION] $_"
    }
}

function Wait-ForHostNameResolution
{
    [CmdletBinding()]
    param(
        [System.String]
        $InstallDir,

        [System.String]
        $FQDN,

        [System.Int32]
        $MaxAttempts = 12,

        [System.Int32]
        $RetryIntervalInSeconds = 30
    )

    $JavaExe = Join-Path $InstallDir 'framework\runtime\jre\bin\java.exe' # Use the JRE in Server Install Directory
    if(-not(Test-Path $JavaExe)){
        throw "java.exe not found at $JavaExe"
    }
    $JavaClassFilePath = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules\ArcGIS\DSCResources\ArcGIS_Server\FQDN.class'
    if(-not(Test-Path $JavaClassFilePath)) {
        Write-Warning "Java Test Class not found at $JavaClassFilePath"
    }
    else {
        $NumAttempts = 0
        $Done = $false
        $NumSuccess = 0
        while(-not($Done) -and ($NumAttempts -lt $MaxAttempts))
        {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $JavaExe
            $psi.Arguments = 'FQDN'
            $psi.WorkingDirectory = (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules\ArcGIS\DSCResources\ArcGIS_Server')
            $psi.UseShellExecute = $false #start the process from it's own executable file
            $psi.RedirectStandardOutput = $true #enable the process to read from standard output
            $psi.RedirectStandardError = $true #enable the process to read from standard error

            $p = [System.Diagnostics.Process]::Start($psi)
            $op = $p.StandardOutput.ReadToEnd().Trim()
            if($op -ieq $FQDN) {
                Write-Verbose "Name Resolution output '$op' matches expected '$FQDN'"
                $NumSuccess++
                if($NumSuccess -gt 2) { $Done = $true } else{ Start-Sleep -Seconds 5}
            }else {
                $NumAttempts++
                Write-Verbose "Name Resolution output '$op' does not match expected '$FQDN'. Retrying after $RetryIntervalInSeconds seconds"
                Start-Sleep -Seconds $RetryIntervalInSeconds
            }
        }
    }
}

function Get-NodeAgentAmazonElementsPresent
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [System.String]
        $InstallDir
    )

    $Enabled = $false
    $File = Join-Path $InstallDir 'framework\etc\NodeAgentExt.xml'
    if(Test-Path $File){
        [xml]$xml = Get-Content $File
        if((($xml.NodeAgent.Observers.Observer | Where-Object { $_.platform -ieq 'amazon'}).Length -gt 0) -or `
                ($xml.NodeAgent.Observers.Observer.platform -ieq 'amazon') -or `
                (($xml.NodeAgent.Plugins.Plugin | Where-Object { $_.platform -ieq 'amazon'}).Length -gt 0) -or `
                ($xml.NodeAgent.Plugins.Plugin.platform -ieq 'amazon'))
        {
            Write-Verbose "Amazon elements exist in $File"
            $Enabled = $true
        }
    }

    $Enabled
}

function Remove-NodeAgentAmazonElements
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [System.String]
        $InstallDir
    )

    $Changed = $false
    $File = Join-Path $InstallDir 'framework\etc\NodeAgentExt.xml'
    if(Test-Path $File){
        [xml]$xml = Get-Content $File
        if($xml.NodeAgent.Observers.Observer.platform -ieq 'amazon')
        {
            $xml.NodeAgent.Observers.RemoveChild($xml.NodeAgent.Observers.Observer)
            Write-Verbose "Amazon Observer exists in $File. Removing it"
            $Changed = $true
        }
        if($xml.NodeAgent.Plugins.Plugin.platform -ieq 'amazon')
        {
            $xml.NodeAgent.Plugins.RemoveChild($xml.NodeAgent.Plugins.Plugin)
            Write-Verbose "Amazon plugin exists in $File. Removing it"
            $Changed = $true
        }
        if($Changed) {
            $xml.Save($File)
        }
    }

    $Changed
}

function Get-SingleClusterModeOnServer
{
    [CmdletBinding()]
	param
	(
        [System.String]
        $ServerURL,

        [System.String]
        $Token,

        [System.String]
        $Referer
	)

    $GetDeploymentUrl  = $ServerURL.TrimEnd("/") + "/arcgis/admin/system/deployment/"
    $props = @{ f= 'json'; token = $Token;  }
    $cmdBody = To-HttpBody $props
    $headers = @{'Content-type'='application/x-www-form-urlencoded'
                'Content-Length' = $cmdBody.Length
                'Accept' = 'text/plain'
                'Referer' = $Referer
                }

    $res = Invoke-WebRequest -Uri $GetDeploymentUrl -Body $cmdBody -Method POST -Headers $headers -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing -TimeoutSec 150 -ErrorAction Ignore
    if($res -and $res.Content) {
        Write-Verbose $res.Content
        $response = $res.Content | ConvertFrom-Json
        Check-ResponseStatus $response -Url $GetDeploymentUrl
        $response
    }else {
        Write-Verbose "[WARNING] Response from $GetDeploymentUrl is NULL"
    }
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
    Check-ResponseStatus $Response
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

        [System.String]
        $Properties
    )

    $RequestUrl  = $ServerUrl.TrimEnd("/") + "/" + $SettingUrl.TrimStart("/")
    $COProperties = $Properties | ConvertFrom-Json
    $RequestParams = @{ f= 'json'; token = $Token; }
    $COProperties.psobject.properties | ForEach-Object { $RequestParams[$_.Name] = $_.Value }
    $Response = Invoke-ArcGISWebRequest -Url $RequestUrl -HttpFormParameters $RequestParams
    Write-Verbose $Response
    Check-ResponseStatus $Response
    $Response
}

Export-ModuleMember -Function *-TargetResource