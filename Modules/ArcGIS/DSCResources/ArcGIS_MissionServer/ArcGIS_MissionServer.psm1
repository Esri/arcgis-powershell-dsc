$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

<#
    .SYNOPSIS
        Makes a request to the installed Mission Server to create a New Server Site
    .PARAMETER ServerHostName
        Optional Host Name or IP of the Machine on which the Mission Server has been installed and is to be configured.
    .PARAMETER Ensure
        Ensure makes sure that a Mission Server site is configured. Take the values Present or Absent. 
        - "Present" ensures that a Mission server site is created.
        - "Absent" ensures that existing Mission server site is deleted.
    .PARAMETER ConfigurationStoreLocation
        Key - Path to Configuration store - Can be a Physical Location or Network Share Address
    .PARAMETER ServerDirectoriesRootLocation
        Path to Mission Server Root Directories - Can be a Physical Location or Network Share Address
    .PARAMETER ServerDirectories
        Default Server Directories Object.
    .PARAMETER ConfigStoreCloudStorageConnectionString
        Connection string to Azure Cloud Storage Account to configure a Site with config store using a Cloud Store
    .PARAMETER ConfigStoreCloudStorageAccountName
        Account Name of the Azure Cloud Storage Account to configure a Site with config store using a Cloud Store
    .PARAMETER ConfigStoreCloudStorageConnectionSecret
        Connection string Secret to Azure Cloud Storage Account to configure a Site with config store using a Cloud Store
    .PARAMETER SiteAdministrator
        A MSFT_Credential Object - Primary Site Administrator
    .PARAMETER LogLevel
        Defines the Logging Level of Mission Server. Can have values - "OFF","SEVERE","WARNING","INFO","FINE","VERBOSE","DEBUG" 
#>
function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $false)]    
        [System.String]
        $ServerHostName,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,    

        [parameter(Mandatory = $False)]
        [System.String]
        $ConfigurationStoreLocation,

        [parameter(Mandatory = $False)]
        [System.String]
        $ConfigStoreCloudStorageConnectionString,
        
        [parameter(Mandatory = $False)]
        [System.String]
        $ConfigStoreCloudStorageAccountName,

        [parameter(Mandatory = $False)]
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

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $Join,

        [parameter(Mandatory = $false)]
        [System.String]
        $PeerServerHostName,
        
        [parameter(Mandatory = $false)]
        [System.String]
        $LogLevel
    )

    $null
}

function Set-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(	
        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $false)]    
        [System.String]
        $ServerHostName,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,    

        [parameter(Mandatory = $False)]
        [System.String]
        $ConfigurationStoreLocation,

        [parameter(Mandatory = $False)]
        [System.String]
        $ConfigStoreCloudStorageConnectionString,

        [parameter(Mandatory = $False)]
        [System.String]
        $ConfigStoreCloudStorageAccountName,

        [parameter(Mandatory = $False)]
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

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $Join,

        [parameter(Mandatory = $false)]
        [System.String]
        $PeerServerHostName,
        
        [parameter(Mandatory = $false)]
        [System.String]
        $LogLevel
	)

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null

    if($VerbosePreference -ine 'SilentlyContinue') 
    {        
        Write-Verbose ("Site Administrator UserName:- " + $SiteAdministrator.UserName) 
    }

    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    Write-Verbose "Fully Qualified Domain Name :- $FQDN"

    $ServiceName = 'ArcGIS Mission Server'
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir  
    
	Write-Verbose "Waiting for Server 'https://$($FQDN):20443/arcgis/admin' to initialize"
    Wait-ForUrl "https://$($FQDN):20443/arcgis/admin" -HttpMethod 'GET'
    if($Ensure -ieq 'Present') {       
        $Referer = 'http://localhost' 
        $RestartRequired = $false

        Write-Verbose "Mission Server Version is $Version"
        if($Version -ne "10.8"){
            $configuredHostName = Get-ConfiguredHostName -InstallDir $InstallDir
            if($configuredHostName -ine $FQDN){
                Write-Verbose "Configured Host Name '$configuredHostName' is not equal to '$($FQDN)'. Setting it"
                if(Set-ConfiguredHostName -InstallDir $InstallDir -HostName $FQDN) { 
                    # Need to restart the service to pick up the hostname 
                    $RestartRequired = $true 
                }
            }
        }

        if($RestartRequired) {
			Restart-ArcGISService -ServiceName $ServiceName -Verbose

			Write-Verbose "Waiting for Server 'https://$($FQDN):20443/arcgis/admin' to initialize"
            Wait-ForUrl "https://$($FQDN):20443/arcgis/admin" -HttpMethod 'GET' -Verbose
        }

        $ServerUrl = "https://$($FQDN):20443"
        Write-Verbose "Checking for Mission Server site on '$ServerUrl'"
        $siteExists = $false
        try {  
            $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer
            $siteExists = ($null -ne $token.token)
        }
        catch {
            Write-Verbose "[WARNING] GetToken returned:- $_"
        }
        if(-not($siteExists)) 
        {
            if($Join){
                Write-Verbose 'Joining Site'
                Join-Site -ServerName $PeerServerHostName -Credential $SiteAdministrator -Referer $Referer
                Write-Verbose 'Joined Site'
            }else{
                [int]$Attempt = 1
                [bool]$Done = $false
                while(-not($Done) -and ($Attempt -le 3)) {
                    try {
                        Write-Verbose 'Creating Site'
                        if($Attempt -gt 1) {
                            Write-Verbose "Attempt # $Attempt"   
                        }            
                        Invoke-CreateSite -ServerURL $ServerUrl -Credential $SiteAdministrator -ConfigurationStoreLocation $ConfigurationStoreLocation `
                                        -ServerDirectoriesRootLocation $ServerDirectoriesRootLocation -Version $Version `
                                        -ServerDirectories $ServerDirectories -ConfigStoreCloudStorageConnectionString $ConfigStoreCloudStorageConnectionString `
                                        -ConfigStoreCloudStorageAccountName $ConfigStoreCloudStorageAccountName `
                                        -ConfigStoreCloudStorageConnectionSecret $ConfigStoreCloudStorageConnectionSecret `
                                        -ServerLogsLocation $ServerLogsLocation -LogLevel $LogLevel -Verbose
                        $Done = $true
                        Write-Verbose 'Created Site'
                    }catch{
                        Write-Verbose "[WARNING] Error while creating site on attempt $Attempt Error:- $_"
                        if($Attempt -lt 1) {
                            Restart-ArcGISService -ServiceName $ServiceName -Verbose

                            Write-Verbose "Waiting for Server 'https://$($FQDN):20443/arcgis/admin' to initialize"
                            Wait-ForUrl -Url "https://$($FQDN):20443/arcgis/admin" -HttpMethod 'GET'
                        }else{
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
            Write-Verbose "Waiting for Server 'https://$($FQDN):20443/arcgis/admin' to initialize"
            Wait-ForUrl -Url "https://$($FQDN):20443/arcgis/admin" -HttpMethod 'GET' -Verbose
        }else{
            Write-Verbose "Site Already Exists."
        }

        #Write-Verbose 'Get Server Token'   
        $token = Get-ServerToken -ServerEndPoint "https://$($FQDN):20443" -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer

        Write-Verbose "Ensuring Log Level $LogLevel"	
        $logSettings = Get-LogSettings -ServerURL $ServerUrl -Token $token.token -Referer $Referer
        Write-Verbose "Current Log Level:- $($logSettings.logLevel)"

        if(($logSettings.logLevel -ine $LogLevel) -or (-not([string]::IsNullOrEmpty($ServerLogsLocation)) -and ($logSettings.logDir -ne $ServerLogsLocation))){
            if(-not([string]::IsNullOrEmpty($ServerLogsLocation))){
                $logSettings.logDir = $ServerLogsLocation
            }
            $logSettings.logLevel = $LogLevel
            Write-Verbose "Updating log level to $($logSettings.logLevel) and log dir to $($logSettings.logDir)"
            Update-LogSettings -ServerURL "https://$($FQDN):20443" -Token $token.token -Referer $Referer -logSettings $logSettings 
            #Write-Verbose "Updated log level to $($logSettings.settings.logLevel)"
        }
    }
    elseif($Ensure -ieq 'Absent') {
        Write-Verbose 'Deleting Site'
        Invoke-DeleteSite -ServerURL "https://$($FQDN):20443" -Credential $SiteAdministrator
        Write-Verbose 'Site Deleted'

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
        $Version,

        [parameter(Mandatory = $false)]    
        [System.String]
        $ServerHostName,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,    

        [parameter(Mandatory = $False)]
        [System.String]
        $ConfigurationStoreLocation,

        [parameter(Mandatory = $False)]
        [System.String]
        $ConfigStoreCloudStorageConnectionString,

        [parameter(Mandatory = $False)]
        [System.String]
        $ConfigStoreCloudStorageAccountName,

        [parameter(Mandatory = $False)]
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

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $Join,

        [parameter(Mandatory = $false)]
        [System.String]
        $PeerServerHostName,
        
        [parameter(Mandatory = $false)]
        [System.String]
        $LogLevel
    )

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    Write-Verbose "Fully Qualified Domain Name :- $FQDN" 
    $Referer = 'http://localhost'
    $ServerUrl = "https://$($FQDN):20443"
    $result = $false
    try {        
        Write-Verbose "Checking for site on '$ServerUrl'"
        Wait-ForUrl -Url "$($ServerUrl)/arcgis/admin" -SleepTimeInSeconds 5 -HttpMethod 'GET'
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
        $logSettings = Get-LogSettings -ServerURL $ServerUrl -Token $token.token -Referer $Referer 
        Write-Verbose "Current Log Level $($logSettings.logLevel)"
        if($logSettings.logLevel -ine $LogLevel) {
            Write-Verbose "Current Log Level $($logSettings.logLevel) not set to '$LogLevel'"
            $result = $false
        }
        if($result -and -not([string]::IsNullOrEmpty($ServerLogsLocation)) -and ($logSettings.logDir -ne $ServerLogsLocation)){
            Write-Verbose "Current Server Log Level $($logSettings.logDir) not set to '$ServerLogsLocation'"
            $result = $false
        }
    }

    Write-Verbose "Mission Server Version is $Version"
    if($result -and ($Version -ne "10.8")) {
        $ServiceName = 'ArcGIS Mission Server'
        $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
        $InstallDir =(Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir 
        $configuredHostName = Get-ConfiguredHostName -InstallDir $InstallDir
        if($configuredHostName -ine $FQDN){
            Write-Verbose "Configured Host Name '$configuredHostName' is not equal to '$FQDN'"
            $result = $false
        }
    }

    if($Ensure -ieq 'Present') {
	    $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}

function Invoke-CreateSite
{    
    [CmdletBinding()]
    Param
    (
        [System.String]
        $Version,

        [System.String]
        $ServerURL,

        [System.Management.Automation.PSCredential]
        $Credential, 

        [System.String]
        $ConfigurationStoreLocation,

        [System.String]
        $ConfigStoreCloudStorageConnectionString,

        [System.String]
        $ConfigStoreCloudStorageAccountName,

        [System.String]
        $ConfigStoreCloudStorageConnectionSecret,

        [System.String]
        $ServerDirectoriesRootLocation,

        [System.String]
        $ServerDirectories,

        [System.Int32]
        $TimeOut = 1000,
        
        [System.String]
        $ServerLogsLocation,

        [System.String]
        $LogLevel = "WARNING"
    )
  
    $createNewSiteUrl  = $ServerURL.TrimEnd("/") + "/arcgis/admin/createNewSite"  
    $baseHostUrl       = $ServerURL.TrimEnd("/") + "/"
    Write-Verbose "Mission Server Version - $Version"
    
    $configStoreConnection = $null
    if($ConfigStoreCloudStorageConnectionString -and $ConfigStoreCloudStorageConnectionString.Length -gt 0)
    {
        if(($ConfigStoreCloudStorageAccountName.IndexOf('AccountName=') -gt -1)){
            Write-Verbose "Using Azure Cloud Storage for the config store"
            $configStoreConnection = @{ 
                    configPersistenceType = "AZURE";
                    connectionString = $ConfigStoreCloudStorageConnectionString;
                    username = $ConfigStoreCloudStorageAccountName.Replace([regex]::escape("AccountName="),[string]::Empty);
                    password = $ConfigStoreCloudStorageConnectionSecret.Replace([regex]::escape("AccountKey="),[string]::Empty);
                    className = "com.esri.arcgis.carbon.persistence.impl.azure.AzureConfigPersistence"
                }
        } else {
            Write-Verbose "Using AWS Cloud Storage S3 for the config store"
            $configStoreConnection = @{ 
                configPersistenceType = "AMAZON";
                connectionString = $ConfigStoreCloudStorageConnectionString;
                className = "com.esri.arcgis.carbon.persistence.impl.amazon.AmazonConfigPersistence"
            }

            if($ConfigStoreCloudStorageAccountName -and $ConfigStoreCloudStorageAccountName.Length -gt 0){
                $configStoreConnection.Add("username",$ConfigStoreCloudStorageAccountName.Replace([regex]::escape("ACCESS_KEY_ID="),[string]::Empty))
                $configStoreConnection.Add("password",$ConfigStoreCloudStorageConnectionSecret.Replace([regex]::escape("SECRET_KEY="),[string]::Empty))
            }
        }
        $Timeout = 2 * $Timeout # Double the timeout if using cloud storage for the config store
    } else {
        Write-Verbose "Using File System Based Storage for the config store"
        $configStoreConnection = @{ 
                                    configPersistenceType= "FILESYSTEM"
                                    connectionString = $ConfigurationStoreLocation
                                    className = "com.esri.arcgis.carbon.persistence.impl.filesystem.FSConfigPersistence"
                                }
    }

    $directories =  @()
    $ServerDirectoriesObject = (ConvertFrom-Json $ServerDirectories)
    if($Version -eq "10.8"){
        $directories += if(($ServerDirectoriesObject | Where-Object {$_.name -ieq "arcgisworkspace"}| Measure-Object).Count -gt 0){
            ($ServerDirectoriesObject | Where-Object {$_.name -ieq "arcgisworkspace"})
        }else{
            @{
                name = "arcgisworkspace"
                path = "$ServerDirectoriesRootLocation\arcgisworkspace"
                type = "WORKSPACE"
            }
        }
    }

    $directories += if(($ServerDirectoriesObject | Where-Object {$_.name -ieq "arcgisoutput"}| Measure-Object).Count -gt 0){
        ($ServerDirectoriesObject | Where-Object {$_.name -ieq "arcgisoutput"})
    }else{
        @{
            name = "arcgisoutput"
            path = "$ServerDirectoriesRootLocation\arcgisoutput"
            type = "OUTPUT"
        }
    }

    $directories += if(($ServerDirectoriesObject | Where-Object {$_.name -ieq "arcgissystem"}| Measure-Object).Count -gt 0){
        ($ServerDirectoriesObject | Where-Object {$_.name -ieq "arcgissystem"})
    }else{
        @{
            name = "arcgissystem"
            path = "$ServerDirectoriesRootLocation\arcgissystem"
            type = "SYSTEM"
        }
    }

    $directories += if(($ServerDirectoriesObject | Where-Object {$_.name -ieq "arcgisjobs"}| Measure-Object).Count -gt 0){
        ($ServerDirectoriesObject | Where-Object {$_.name -ieq "arcgisjobs"})
    }else{
        @{
            name = "arcgisjobs"
            path = "$ServerDirectoriesRootLocation\arcgisjobs"
            type = "JOBS"
        }
    }

    $requestParams = @{ 
                        username = $Credential.UserName
                        password = $Credential.GetNetworkCredential().Password
                        configStoreConnection = ConvertTo-JSON $configStoreConnection -Compress -Depth 5
                        directories = ConvertTo-JSON $directories -Compress
                        #logsSettings = "{}"
                        async = "false"
                        f = "pjson"
                    }

    if(-not([string]::IsNullOrEmpty($ServerLogsLocation))){           
        $requestParams["logsSettings"] = (ConvertTo-Json -Compress -InputObject @{
            logLevel = $LogLevel;
            logDir = $ServerLogsLocation;
            maxErrorReportsCount = 10;
            maxLogFileAge = 90;
            usageMeteringEnabled = $False
        })
    }

    # make sure Tomcat is up and running BEFORE sending a request
    Write-Verbose "Waiting for Server 'https://$($FQDN):20443/arcgis/admin' to initialize"
    Wait-ForUrl -Url $baseHostUrl -SleepTimeInSeconds 5 -HttpMethod 'GET' -Verbose

    $httpRequestBody = ConvertTo-HttpBody -props $requestParams
    $response = Invoke-RestMethod -Method Post -Uri $createNewSiteUrl -Body $httpRequestBody -TimeoutSec $TimeOut 
    
    if($response.status -ieq "success"){
        Write-Verbose "Site Created Successfully!"
    }else{
        Write-Verbose ("Response from CreateSite:-" + ($response | ConvertTo-JSON -Depth 5))
        if($response.error){
            throw "Create Site Failed.  Code:- $($response.error.code), Error:- $($response.error.message)"
        }
    }   
}

function Join-Site
{
    [CmdletBinding()]
    Param
    (
      [System.String]
      $ServerName,
  
      [System.Management.Automation.PSCredential]
      $Credential,
  
      [System.String]
      $Referer
    )

    $ServerFQDN = Get-FQDN $ServerName

	$SiteServerURL = "https://$($ServerFQDN):20443/arcgis/admin"
	$LocalAdminURL = "https://localhost:20443/arcgis/admin"
	$JoinSiteUrl   = "$LocalAdminURL/joinSite"

	$JoinSiteParams = @{ adminURL = $SiteServerURL; f = 'json'; username = $Credential.UserName; password = $Credential.GetNetworkCredential().Password }
	Write-Verbose "Waiting for Site Server URL $SiteServerUrl to respond"
	Wait-ForUrl $SiteServerUrl -Verbose    
                  
	Write-Verbose "Waiting for Local Admin URL $LocalAdminURL to respond"
	Wait-ForUrl $LocalAdminURL -Verbose  
    
    $NumAttempts        = 0           
	$SleepTimeInSeconds = 30
	$Success            = $false
	$Done               = $false
	while ((-not $Done) -and ($NumAttempts++ -lt 3)){                 
        $response = Invoke-ArcGISWebRequest -Url $JoinSiteUrl -HttpFormParameters $JoinSiteParams -Referer $Referer -TimeOutSec 360
        if($response) {
			if ($response -and $response.status -and ($response.status -ieq "success")) {
				$Done    = $true
                $Success = $true
                Write-Verbose "Join Site operation successful. Waiting for $($response.pollAfter) seconds for Mission Server to initialize."
                if($response.pollAfter){
                    Start-Sleep -Seconds $response.pollAfter
                }
				break
			}
        }
        Write-Verbose "Attempt # $NumAttempts failed."
		if ($response.status)   { Write-Verbose "`tStatus   : $($response.status)."   }
		if ($response.messages) { Write-Verbose "`tMessages : $($response.messages)." }
		Write-Verbose "Retrying after $SleepTimeInSeconds seconds..."
        Start-Sleep -Seconds $SleepTimeInSeconds 
    }

    if (-not($Success)) {
		throw "Failed to Join Site after multiple attempts. Error on last attempt:- $($json.messages)"
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

    $ServerURL = $ServerURL.TrimEnd("/") + "/arcgis/admin/logs/settings"
    Invoke-ArcGISWebRequest -Url $ServerURL -HttpFormParameters  @{ f= 'json'; token = $Token } -Referer $Referer -TimeoutSec 30 -HttpMethod 'GET'    
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
    $props = @{ f= 'pjson'; token = $Token; logDir = $logSettings.logDir; logLevel = $logSettings.logLevel; 
                maxLogFileAge = $logSettings.maxLogFileAge; maxErrorReportsCount = $logSettings.maxErrorReportsCount;
                usageMeteringEnabled = $logSettings.usageMeteringEnabled }

    $response = Invoke-ArcGISWebRequest -Url $UpdateLogSettingsUrl -HttpFormParameters $props -Referer $Referer
    if($response.status -ieq "success"){
        Write-Verbose "Log Settings Update Successfully"
    }else{
        Write-Verbose "[WARNING]: Code:- $($response.error.code), Error:- $($response.error.message)" 
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

    $RequestParams = @{
                        f = "json"
                        token= $token.token
                    } 
    $HttpBody = ConvertTo-HttpBody -props $RequestParams
    
    $Headers = @{
                    'Content-type'='application/x-www-form-urlencoded'
                    'Content-Length' = $HttpBody.Length
                    'Accept' = 'text/plain'
                    'Referer' = $Referer
                }
    $response = Invoke-RestMethod -Method Post -Uri $DeleteSiteUrl -Body $HttpBody -Headers $Headers -TimeoutSec $TimeOut
    Write-Verbose ($response | ConvertTo-Json -Depth 5)
}

Export-ModuleMember -Function *-TargetResource
