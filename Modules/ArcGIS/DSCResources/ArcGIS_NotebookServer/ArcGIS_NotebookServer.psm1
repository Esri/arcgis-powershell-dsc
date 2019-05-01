<#
    .SYNOPSIS
        Makes a request to the installed Notebook Server to create a New Server Site
    .PARAMETER Ensure
        Ensure makes sure that a Notebook Server site is configured. Take the values Present or Absent. 
        - "Present" ensures that a Notebook server site is created.
        - "Absent" ensures that existing Notebook server site is deleted.
    .PARAMETER ConfigurationStoreLocation
        Key - Path to Configuration store - Can be a Physical Location or Network Share Address
    .PARAMETER ServerDirectoriesRootLocation
        Path to Notebook Server Root Directories - Can be a Physical Location or Network Share Address
    .PARAMETER ConfigStoreCloudStorageConnectionString
        Connection string to Azure Cloud Storage Account to configure a Site with config store using a Cloud Store
    .PARAMETER ConfigStoreCloudStorageConnectionSecret
        Connection string Secret to Azure Cloud Storage Account to configure a Site with config store using a Cloud Store
    .PARAMETER SiteAdministrator
        A MSFT_Credential Object - Primary Site Administrator
    .PARAMETER LogLevel
        Defines the Logging Level of Notebook Server. Can have values - "OFF","SEVERE","WARNING","INFO","FINE","VERBOSE","DEBUG" 
    .PARAMETER WebContextURL
        External Enpoint when using a reverse proxy server and the URL to your site does not end with the default string /arcgis (all lowercase). 
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
        
        [parameter(Mandatory = $false)]
        [System.String]
        $LogLevel,

        [parameter(Mandatory = $false)]
        [System.String]
        $WebContextURL
    )

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false
    
    $null
}

function Set-TargetResource
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
        
        [parameter(Mandatory = $false)]
        [System.String]
        $LogLevel,

        [parameter(Mandatory = $false)]
        [System.String]
        $WebContextURL
	)
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null

    if($VerbosePreference -ine 'SilentlyContinue') 
    {        
        Write-Verbose ("Site Administrator UserName:- " + $SiteAdministrator.UserName) 
    }

    $FQDN = Get-FQDN $env:COMPUTERNAME    
    Write-Verbose "Fully Qualified Domain Name :- $FQDN"

    $ServiceName = 'ArcGIS Notebook Server'
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir  
    
	Write-Verbose "Waiting for Server 'https://$($FQDN):11443/arcgis/admin' to initialize"
    Wait-ForUrl "https://$($FQDN):11443/arcgis/admin" -HttpMethod 'GET'
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

			Write-Verbose "Waiting for Server 'https://$($FQDN):11443/arcgis/admin' to initialize"
            Wait-ForUrl "https://$($FQDN):11443/arcgis/admin" -HttpMethod 'GET'
        }


        $ServerUrl = "https://$($FQDN):11443"
        Write-Verbose "Checking for Notebook Server site on '$ServerUrl'"
        $siteExists = $false
        try {  
            $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer
            $siteExists = ($token.token -ne $null)
        }
        catch {
            Write-Verbose "[WARNING] GetToken returned:- $_"
        }

        if(-not($siteExists)) {

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
                }catch{
                    Write-Verbose "[WARNING] Error while creating site on attempt $Attempt Error:- $_"
                    if($Attempt -lt 1) {
                        Write-Verbose "Restarting Service $ServiceName"
                        Stop-Service -Name $ServiceName  -Force
                        Write-Verbose 'Stopping the service' 
                        Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Stopped'                            
                        Write-Verbose 'Starting the service'
                        Start-Service -Name $ServiceName         
                        Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Running'
                        Write-Verbose "Restarted Service $ServiceName"

                        Write-Verbose "Waiting for Server 'https://$($FQDN):11443/arcgis/admin' to initialize"
                        Wait-ForUrl -Url "https://$($FQDN):11443/arcgis/admin" -HttpMethod 'GET'
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

            Write-Verbose "Waiting for Server 'https://$($FQDN):11443/arcgis/admin' to initialize"
            Wait-ForUrl -Url "https://$($FQDN):11443/arcgis/admin" -HttpMethod 'GET' -Verbose
        }else{
            Write-Verbose "Site Already Exists."
        }

        #Write-Verbose 'Get Server Token'   
        $token = Get-ServerToken -ServerEndPoint "https://$($FQDN):11443" -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer

        Write-Verbose "Ensuring Log Level $LogLevel"	
        $logSettings = Get-LogSettings -ServerURL $ServerUrl -Token $token.token -Referer $Referer
        Write-Verbose "Current Log Level:- $($logSettings.logLevel)"

        if($logSettings.logLevel -ine $LogLevel) {
            $logSettings.logLevel = $LogLevel
            Write-Verbose "Updating log level to $($logSettings.logLevel)"
            Update-LogSettings -ServerURL "https://$($FQDN):11443" -Token $token.token -Referer $Referer -logSettings $logSettings 
            #Write-Verbose "Updated log level to $($logSettings.settings.logLevel)"
        }

        if($WebContextURL){
            $systemProperties = Get-AdminSettings -ServerUrl $ServerUrl -SettingUrl "arcgis/admin/system/properties/" -Token $token.token
            if(-not($systemProperties.WebContextURL) -or $systemProperties.WebContextURL -ine $WebContextURL){
                Write-Verbose "Web Context URL '$($systemProperties.WebContextURL)' doesn't match expected value '$WebContextURL'"
                if(-not($systemProperties.WebContextURL)){
                    Add-Member -InputObject $systemProperties -MemberType NoteProperty -Name "WebContextURL" -Value $WebContextURL
                }else{
                    $systemProperties.WebContextURL = $WebContextURL
                }
                Set-AdminSettings -ServerUrl $ServerUrl -SettingUrl "arcgis/admin/system/properties/update" -Token $token.token -Properties $systemProperties
            }
        }   
    }
    elseif($Ensure -ieq 'Absent') {
        Write-Verbose 'Deleting Site'
        Delete-Site -ServerURL "https://$($FQDN):11443" -Credential $SiteAdministrator
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
        
        [parameter(Mandatory = $false)]
        [System.String]
        $LogLevel,

        [parameter(Mandatory = $false)]
        [System.String]
        $WebContextURL
    )

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $FQDN = Get-FQDN $env:COMPUTERNAME   
    Write-Verbose "Fully Qualified Domain Name :- $FQDN" 
    $Referer = 'http://localhost'
    $ServerUrl = "https://$($FQDN):11443"
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

    if($result -and $LogLevel){
        $logSettings = Get-LogSettings -ServerURL $ServerUrl -Token $token.token -Referer $Referer 
        Write-Verbose "Current Log Level $($logSettings.logLevel)"
        if($logSettings.logLevel -ine $LogLevel) {
            Write-Verbose "Current Log Level $($logSettings.settings.logLevel) not set to '$LogLevel'"
            $result = $false
        }
    }

    if($result -and $WebContextURL){
        $systemProperties = Get-AdminSettings -ServerUrl $ServerUrl -SettingUrl "arcgis/admin/system/properties/" -Token $token.token
        if(-not($systemProperties.WebContextURL) -or $systemProperties.WebContextURL -ine $WebContextURL){
            Write-Verbose "Web Context URL '$($systemProperties.WebContextURL)' doesn't match expected value '$WebContextURL'"
            $result = $false
        }
    }

    if($result) {
        $ServiceName = 'ArcGIS Notebook Server'
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
        $TimeOut = 1000
    )
  
    $createNewSiteUrl  = $ServerURL.TrimEnd("/") + "/arcgis/admin/createNewSite"  
    $baseHostUrl       = $ServerURL.TrimEnd("/") + "/"
        
    if(($ConfigStoreCloudStorageConnectionString) -and ($ConfigStoreCloudStorageConnectionSecret) -and ($ConfigStoreCloudStorageConnectionString.IndexOf('AccountName=') -gt -1))
    {
        Write-Verbose "Using Azure Cloud Storage for the config store"
        $configStoreConnection = @{ 
                                    configPersistenceType= "AZURE";
                                    connectionString = $ConfigStoreCloudStorageConnectionString + ";" + $ConfigStoreCloudStorageConnectionSecret;
                                    className = "com.esri.arcgis.carbon.persistence.impl.azure.AzureConfigPersistence"
                                }

        $Timeout = 2 * $Timeout # Double the timeout if using cloud storage for the config store
    }
    else {
        Write-Verbose "Using File System Based Storage for the config store"
        $configStoreConnection = @{ 
                                    configPersistenceType= "FILESYSTEM"
                                    connectionString = $ConfigurationStoreLocation
                                    className = "com.esri.arcgis.carbon.persistence.impl.filesystem.FSConfigPersistence"
                                }
    }  
    
    $directories =  @( 
                        @{
                            name = "arcgisworkspace"
                            path = "$ServerDirectories\arcgisworkspace"
                            type = "WORKSPACE"
                        },
                        @{
                            name = "arcgisoutput"
                            path = "$ServerDirectories\arcgisoutput"
                            type = "OUTPUT"
                        },
                        @{
                            name = "arcgissystem"
                            path = "$ServerDirectories\arcgissystem"
                            type = "SYSTEM"
                        }
                    )
                    

    $requestParams = @{ 
                        username = $Credential.UserName
                        password = $Credential.GetNetworkCredential().Password
                        configStoreConnection = ConvertTo-JSON $configStoreConnection -Compress -Depth 5
                        directories = ConvertTo-JSON $directories -Compress
                        #logsSettings = "{}"
                        async = "false"
                        f = "pjson"
                       }

    # make sure Tomcat is up and running BEFORE sending a request
    Write-Verbose "Waiting for Server 'https://$($FQDN):11443/arcgis/admin' to initialize"
    Wait-ForUrl -Url $baseHostUrl -SleepTimeInSeconds 5 -HttpMethod 'GET' -Verbose

    $httpRequestBody = To-HttpBody -props $requestParams
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
    Write-Verbose ($logSettings | ConvertTo-JSON -Depth 5)
    $props = @{ f= 'pjson'; token = $Token; logDir = $logSettings.logDir; logLevel = $logSettings.logLevel; 
                maxLogFileAge = $logSettings.maxLogFileAge; maxErrorReportsCount = $logSettings.maxErrorReportsCount;
                usageMeteringEnabled = $logSettings.usageMeteringEnabled }
    $cmdBody = To-HttpBody $props   
    $headers = @{
                    'Content-type'='application/x-www-form-urlencoded'
                    'Content-Length' = $cmdBody.Length
                    'Accept' = 'text/plain'
                    'Referer' = $Referer
                }

    $res = Invoke-WebRequest -Uri $UpdateLogSettingsUrl -Body $cmdBody -Method POST -Headers $headers -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing 
    $response = $res | ConvertFrom-Json

    if($response.status -ieq "success"){
        Write-Verbose "Log Settings Update Successfully"
    }else{
        Write-Verbose "[WARNING]: Code:- $($response.error.code), Error:- $($response.error.message)" 
    }
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
    
    $Headers = @{
                    'Content-type'='application/x-www-form-urlencoded'
                    'Content-Length' = $HttpBody.Length
                    'Accept' = 'text/plain'
                    'Referer' = $Referer
                }
    $response = Invoke-RestMethod -Method Post -Uri $DeleteSiteUrl -Body $HttpBody -Headers $Headers -TimeoutSec $TimeOut
    Write-Verbose ($response | ConvertTo-Json -Depth 5)
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