$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))


function Test-IfGISServer{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerType
    )
    return -not(@("NotebookServer","MissionServer","VideoServer","DataPipelinesServer") -icontains $ServerType)
}

function Get-ServerAdminUrlForPath{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $Path
    )
    return $URL.TrimEnd('/') + "/admin" + $Path
}
            
function Get-ServerToken
{
    [CmdletBinding()]
    param(
		[Parameter(Mandatory=$true)]
        [System.String]
		$URL,

		[parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$Credential,

		[Parameter(Mandatory=$true)]
        [System.String]
		$Referer, 

        [System.Int32]
        $Expiration=1000,

        [System.Int32]
        $MaxAttempts = 10
    )

    $GenerateServerTokenUrl = (Get-ServerAdminUrlForPath -URL $URL -Path "/generateToken")
    $token = $null
    $Done = $false
	$NumAttempts = 0
	while(-not($Done) -and ($NumAttempts -lt $MaxAttempts)) {
		try {
			$token = Invoke-ArcGISWebRequest -Url $GenerateServerTokenUrl -HttpFormParameters @{ username = $Credential.GetNetworkCredential().UserName; password = $Credential.GetNetworkCredential().Password; client = 'referer'; referer = $Referer; expiration = $Expiration; f = 'json' } -Referer $Referer -TimeOutSec 45 
		}
		catch {
			Write-Verbose "[WARNING]:- Server at $GenerateServerTokenUrl did not return a token on attempt $($NumAttempts + 1). Retry after 15 seconds"
		}
		if($token) {
			Write-Verbose "Retrieved server token successfully"
			$Done = $true
		}else {
			Start-Sleep -Seconds 15
			$NumAttempts = $NumAttempts + 1
		}
	}
    $token
}

function Test-ServerSiteCreated
{
    [CmdletBinding()]
    param(
		[Parameter(Mandatory=$true)]
        [System.String]
		$URL,

		[Parameter(Mandatory=$true)]
        [System.String]
		$Referer
    )

    $result = $false
    try {
        Test-ArcGISComponentHealth -BaseURL $URL -ComponentName "ServerAdmin" -Verbose
        $ServerAdminURL = Get-ServerAdminUrlForPath -URL $URL
        $SiteCreatedCheckResponse = Invoke-ArcGISWebRequest -Url $ServerAdminURL -HttpFormParameters @{ referer = $Referer; f = 'json' } -Referer $Referer -HttpMethod "GET"

        $code = $null
        if ($SiteCreatedCheckResponse.code) {
            $code = $SiteCreatedCheckResponse.code
        } elseif ($SiteCreatedCheckResponse.error.code) {
            $code = $SiteCreatedCheckResponse.error.code
        }

        if ($SiteCreatedCheckResponse.status -ieq "error" -or $SiteCreatedCheckResponse.error) {
            if ($code -eq 499) {
                Write-Verbose "Server site is already created."
                $result = $true
            } else {
                $result = $false
            }
        } else {
            throw "Unknown response - $(ConvertTo-Json $SiteCreatedCheckResponse -Compress)"
        }
    }
    catch {
        $errMsg = "[ERROR] Unable to detect server site. $_"
        Write-Verbose $errMsg
        throw $errMsg
    }

    return $result
}


# Datastore

function Invoke-GetDatabaseConnectionGPTool
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer,

        [System.String]
        $ConnectionFileItemId
    )

    $ToolPath = $URL.TrimEnd('/') + '/rest/services/System/PublishingTools/GPServer/Get%20Database%20Connection%20String'

    [string]$SubmitJobUrl = $ToolPath.TrimEnd('/') + "/submitJob"
    Write-Verbose "Submitting Job to $SubmitJobUrl"
    $response = Invoke-ArcGISWebRequest -Url $SubmitJobUrl -HttpFormParameters @{ token = $Token; f = 'json'; in_inputData = $ConnectionFileItemId; in_connDataType = 'UPLOADED_CONNECTION_FILE_ID' } -Referer $Referer -TimeOutSec 60
    if($null -ne $response.status.error) {
        throw "Error submitting job to 'Get Database Connection' GP Tool $($response.status.error.messages)"
    }

    [string]$JobId = $response.jobId
    [int]$NumAttempts = 0
    [bool]$Done = 0
    [string]$CheckJobStatusUrl = $ToolPath.TrimEnd('/') + "/jobs/$JobId"
    [string]$ParamUrl = $null
    
    $LastJobStatus = $null

    while(-not($Done) -and $NumAttempts -lt 10) {
        Write-Verbose "Get Database Connection GP Tool job status URL - $CheckJobStatusUrl"
        
        $response = Invoke-ArcGISWebRequest -Url $CheckJobStatusUrl -HttpFormParameters @{ token = $Token; f = 'json'; } -Referer $Referer -TimeOutSec 60

        if($null -ne $response.status.error) {
            throw "Error checking job status for job $JobId. Error:- $($response.status.error.messages)"
        }
        
        $LastJobStatus = $response.jobStatus

        if($response.jobStatus -eq 'esriJobSucceeded') {
            $ParamUrl = $response.results.out_connectionString.paramUrl
            $Done = $true
        }elseif($LastJobStatus -ieq "esriJobFailed" -or `
               $LastJobStatus -ieq "esriJobCancelled" -or `
               $LastJobStatus -ieq "esriJobTimedOut") {

            throw "Get Database Connection GP Tool job '$JobId' did not complete successfully. Last status: $LastJobStatus. Http Response - $($response.messages | ConvertTo-Json -Depth 10)"
        }

        else {
            Start-Sleep -Seconds 30
        }
        $NumAttempts++
    }

    if(-not($Done))
    {
        throw "Get Database Connection GP Tool job '$JobId' did not reach 'esriJobSucceeded' after $NumAttempts polling attempts. Last status: $LastJobStatus"
    }

    [string]$OutParamUrl = $ToolPath.TrimEnd('/') + "/jobs/" + "$JobId/$ParamUrl"
    Write-Verbose "Get Job Result at $OutParamUrl"
    $response = Invoke-ArcGISWebRequest -Url $OutParamUrl -HttpFormParameters @{ token = $Token; f = 'json'; } -Referer $Referer -TimeOutSec 60
    if($null -ne $response.status.error) {
        throw "Error retrieving job output for job $JobId. Error:- $($response.status.error.messages)"
    }

    return $response.value
}


function Invoke-GPServiceOperation
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer,

        [System.String]
        $ServicePath,

        [System.String]
        [ValidateSet("start","stop","status")]
        $OperationName
    )

    # TODO - Check if status call needs to be a GET?
    $ServiceStartOperationUrl = Get-ServerAdminUrlForPath -URL $URL -Path ('/services/' + $ServicePath.Trim('/') + "/$($OperationName)")
    Invoke-ArcGISWebRequest -Url $ServiceStartOperationUrl -HttpFormParameters  @{ f = 'json'; token = $Token } -Referer $Referer -HttpMethod 'POST' -Verbose
}

function Find-DataItems
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer,

        [System.String]
        $Type,

        [switch]
        $IsArcGISDataStore,
        
        [System.String]
        $ItemName
    )
    
    $TypeStringAndAncestorPath = Get-DSAncestorPathOrItemType -DataStoreType $Type
    $DataItemsUrl = Get-ServerAdminUrlForPath -URL $URL -Path '/data/findItems'
    $response = Invoke-ArcGISWebRequest -Url $DataItemsUrl -HttpFormParameters @{ f = 'json'; token = $Token; types = $TypeStringAndAncestorPath["Type"]; ancestorPath = $TypeStringAndAncestorPath["AncestorPath"] } -Referer $Referer -Verbose
    if($IsArcGISDataStore){
        if(@('nosql', 'cloudStore') -icontains $TypeStringAndAncestorPath["Type"]){
            return @($response.items | Where-Object { ($_.provider -ieq 'ArcGIS Data Store') -and ($_.info.dsFeature -ieq $Type) })
        }else{
            return @($response.items | Where-Object { ($_.provider -ieq 'ArcGIS Data Store') })
        }
    }else{
        if(-not([string]::IsNullOrEmpty($ItemName))){
            return ($response.items | Where-Object { $_.path -ieq "$($TypeStringAndAncestorPath["AncestorPath"])/$($ItemName)" })
        }
    }
        
    return @($response.items)
}

# TODO - Validate this
function Get-DSAncestorPathOrItemType {
	[CmdletBinding()]
	param
	(
		[System.String]
		$DataStoreType
	)

	$TypeString = ""
	$AncestorPath = ""
	if ($DataStoreType -ieq 'Folder') {
		$TypeString = "folder"
		$AncestorPath = "/fileShares"
	}
	elseif ($DataStoreType -ieq 'CloudStore') {
		$TypeString = "cloudStore"
		$AncestorPath = "/cloudStores"
	}
	elseif ($DataStoreType -ieq 'ObjectStore') {
		$TypeString = "objectStore"
		$AncestorPath = "/cloudStores"
	}
	elseif (@('TileCache','SpatioTemporal','GraphStore') -icontains $DataStoreType) {
		$TypeString = "nosql"
		$AncestorPath = "/nosqlDatabases"
	}
	elseif ($DataStoreType -ieq 'BigDataFileShare') { 
		$TypeString = "bigDataFileShare"
		$AncestorPath = "/bigDataFileShares"
	}
	elseif ($DataStoreType -ieq 'RasterStore') {
		$TypeString = "rasterStore"
		$AncestorPath = "/rasterStores"
	}else{
        $TypeString = "egdb"
		$AncestorPath = "/enterpriseDatabases"
    }
	return @{
        Type = $TypeString
        AncestorPath = $AncestorPath
    }
}

function Invoke-DataStoreItemOperation
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer,

        [System.Object]
        $ConnectionObject,

        [System.String]
        [ValidateSet("edit", "registerItem", "unregisterItem", "validateDataItem")]
        $OperationName,

        [System.String]
		$DataStoreItemPath,

		[System.Boolean]
		$Force = $false
    )

    $FormParameters = @{ 
		f     = 'json' 
		token = $Token
		item  = (ConvertTo-Json -InputObject $ConnectionObject -Depth 5 -Compress)
	}

    if($OperationName -ieq "unregisterItem"){
        $FormParameters["itemPath"] = $DataStoreItemPath
        if($Force){
            $FormParameters["force"] = "true"
        }
    }else{
        $FormParameters["item"]  = (ConvertTo-Json -InputObject $ConnectionObject -Depth 5 -Compress)
    }

    $OperationPath = if($OperationName -ieq 'edit') {
        "/data/items$($ConnectionObject.path)/edit"
    }else {
        "/data/$($OperationName)"
    }
    $Url = Get-ServerAdminUrlForPath -URL $URL -Path $OperationPath
    $response = Invoke-ArcGISWebRequest -Url $Url -HttpFormParameters $FormParameters -Referer $Referer -TimeOutSec 90
    if ($response.status -ieq 'success') 
    {
		Write-Verbose "Data Store Item operation '$($OperationName)' successful"
	} 
    else {
        $ErrorPrefix = "[ERROR]:- Data Store Item operation '$($OperationName)' failed."
		if (($response.status -ieq 'error') -and $response.messages) 
        {
			throw "$($ErrorPrefix) Error:- $($response.messages -join ',')"
		}
        if($null -ne $response.status.error) 
        {
            throw "$($ErrorPrefix) Error:- $($response.status.error.messages -join ',')"
        }
        if($response.success -eq $false) 
        {
            throw "$($ErrorPrefix) Response:- $($response | ConvertTo-Json -Depth 10)" 
        }
	}
}

function Get-DataStoreMachines
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer,

        [System.String]
        $DataStorePath 
    )

    $MachinesInDataStoreUrl = Get-ServerAdminUrlForPath -URL $URL -Path ('/data/items' + $DataStorePath + '/machines')
    $response = (Invoke-ArcGISWebRequest -Url $MachinesInDataStoreUrl -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer -Verbose)
    return $response.machines
}

function Invoke-DataStoreMachineOperation
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer,

        [System.String]
        $DataStorePath, 

        [System.String]
        $MachineFQDN,

        [System.String]
        $OperationName
    )

    $MachinesInDataStoreUrl = Get-ServerAdminUrlForPath -URL $URL -Path ('/data/items' + $DataStorePath + "/machines/$($MachineFQDN)/$($OperationName)/")
    return (Invoke-ArcGISWebRequest -Url $MachinesInDataStoreUrl -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer -HttpMethod 'POST' -Verbose)
}

function Test-MachineExists
{
    [CmdletBinding()]
    Param
    (
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
		$Referer,

        [System.String]
		$MachineName
    )
    $GetMachinesUrl  = Get-ServerAdminUrlForPath -URL $URL -Path "/machines/"
    $AllMachines = Invoke-ArcGISWebRequest -Url $GetMachinesUrl -HttpFormParameters @{ f= 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET' -TimeoutSec 150
    if(($AllMachines.machines | Where-Object { $_.machineName -ieq $MachineName -or $_.machineName -ieq $env:COMPUTERNAME }  | Measure-Object).Count -eq 0) {
        throw "Not able to find machine in site with either hostname $MachineName or fully qualified domain name $FQDN"
    }
}

function Get-MachineProperties
{
    [CmdletBinding()]
    Param
    (
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
		$Referer,

        [System.String]
		$MachineName
    )

    Test-MachineExists -URL $URL -Token $Token -Referer $Referer -MachineName $MachineName
    
    $GetMachinePropertiesUrl  = Get-ServerAdminUrlForPath -URL $URL -Path ("/machines/" + $MachineName + '/')
    Invoke-ArcGISWebRequest -Url $GetMachinePropertiesUrl -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer -HttpMethod 'GET' -TimeoutSec 150
}

function Update-MachineProperties
{
    [CmdletBinding()]
    Param
    (
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
		$Referer,

        [System.String]
		$MachineName,

        [System.String]
        $WebServerCertificateAlias,

        [System.Int32]
        $SocMaxHeapSize = -1,

        [System.Int32]
        $MaxAttempts = 5,

        [System.Int32]
        $SleepTimeInSecondsBetweenAttempts = 30
    )

    $CurrentProperties = Get-MachineProperties -URL $URL -Token $Token -MachineName $MachineName -Referer $Referer
    
    if(-not([string]::IsNullOrEmpty($WebServerCertificateAlias))){
        $CurrentProperties.webServerCertificateAlias = $WebServerCertificateAlias
    }
    if($SocMaxHeapSize -gt 0 -and ($SocMaxHeapSize -ine $CurrentProperties.socMaxHeapSize)){
        $CurrentProperties.socMaxHeapSize = $SocMaxHeapSize
    }
    
    $UpdatePropertiesObject = Convert-PSObjectToHashtable -InputObject $CurrentProperties
    $UpdateMachinePropertiesUrl  = Get-ServerAdminUrlForPath -URL $URL -Path ("/machines/" + $MachineName + '/edit')
    if($UpdateMachinePropertiesUrl -imatch "6443" -and $UpdatePropertiesObject.ContainsKey("ports")){
        $UpdatePropertiesObject.ports = $null
    }

    $UpdatePropertiesObject["f"] = 'json'
    $UpdatePropertiesObject["token"] = $Token

    [bool]$Done = $false
    [int]$Attempt = 0
    while(-not($Done) -and $Attempt -lt $MaxAttempts) 
    {
        $Attempt++
        $AttemptStr = 'Updating machine properties. '
        $AttemptStr += "Attempt #$($Attempt)"
        Write-Verbose $AttemptStr
        try {    
            $response = Invoke-ArcGISWebRequest -Url $UpdateMachinePropertiesUrl -HttpFormParameters $UpdatePropertiesObject -Referer $Referer -TimeOutSec 150 -Verbose
            Confirm-ResponseStatus $response -Url $UpdateMachinePropertiesUrl
            Write-Verbose "Update of machine properties successful! Server will restart now."
            $Done = $true
        }
        catch
        {                
            if($Attempt -ge $MaxAttempts) {
                throw "Machine properties update failed after $MaxAttempts. Error:- $($_)"
            }else{
                Write-Verbose "[WARNING] Retrying. Machine properties update failed. Response:- $($_)"
            }
        }
        if(-not($Done)){
            Start-Sleep -Seconds $SleepTimeInSecondsBetweenAttempts
        }
        
    }
    if(-not($Done)){
        throw "Machine properties update failed after $MaxAttempts attempts."
    }
    $response
}

# Server


function Invoke-JoinSite
{ 
    [CmdletBinding()]
    Param
    (
        [System.String]
        $URL, 

        [System.Management.Automation.PSCredential]
        $Credential, 
        
        [System.String]
        $Referer,

        [System.String]
        $PrimaryServerHostName,

        [System.String]
        $ServerType
    )

    $PrimaryServerFQDN = Get-FQDN $PrimaryServerHostName    
    $PrimaryServerBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName $ServerType -FQDN $PrimaryServerFQDN
    $PrimaryServerAdminUrl = (Get-ServerAdminUrlForPath -URL $PrimaryServerBaseUrl -Path "")
    Write-Verbose "Waiting for Site Server URL $PrimaryServerBaseUrl to respond"
	Test-ArcGISComponentHealth -BaseURL $PrimaryServerBaseUrl -ComponentName $ServerType -Verbose

    Write-Verbose "Waiting for Local Server Admin URL $URL to respond"
	Test-ArcGISComponentHealth -BaseURL $URL -ComponentName $ServerType -Verbose

    $JoinSiteUrl = Get-ServerAdminUrlForPath -URL $URL -Path "/joinSite"

    $JoinSiteParams = @{ 
                        adminURL = $PrimaryServerAdminUrl
                        f = 'json'
                        username = $Credential.UserName
                        password = $Credential.GetNetworkCredential().Password 
                    }

    $NumAttempts        = 0           
	$SleepTimeInSeconds = 30
	$Success            = $false
	$Done               = $false
	while ((-not $Done) -and ($NumAttempts++ -lt 5)){
        $response = Invoke-ArcGISWebRequest -Url $JoinSiteUrl -HttpFormParameters $JoinSiteParams -Referer $Referer -TimeOutSec 360
        if ($response -and $response.status -and ($response.status -ine "error")) {
            $Done    = $true
            $Success = $true
            Write-Verbose "Join Site operation successful."
            if($response.pollAfter){
                Write-Verbose "Waiting for $($response.pollAfter) seconds for server to initialize."
                Wait-RecheckAfterSeconds -Seconds $response.pollAfter -Multiplier 1 -Verbose
            }
            break
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

    ##
	## Adding site (might) restart the server instance (Wait for admin endpoint to comeback up)
	##
	Write-Verbose "Waiting for Local Server Admin URL $URL to respond"
    Test-ArcGISComponentHealth -BaseURL $URL -ComponentName $ServerType -Verbose

	Write-Verbose "Waiting for Site Server URL $PrimaryServerBaseUrl to respond"
    Test-ArcGISComponentHealth -BaseURL $PrimaryServerBaseUrl -ComponentName $ServerType -Verbose
}

function Invoke-DeleteSite
{
    [CmdletBinding()]
    Param
    (
        [System.String]
        $URL,

        [System.Management.Automation.PSCredential]
        $Credential,

        [System.Int32]
        $TimeOut = 300
    )

    $Referer = $URL
    $token = Get-ServerToken -URL $URL -Credential $Credential -Referer $Referer
    $DeleteSiteUrl  = Get-ServerAdminUrlForPath -URL $URL -Path "/deleteSite" 
    $response = Invoke-ArcGISWebRequest -Url $DeleteSiteUrl -HttpFormParameters @{ f= 'json'; token = $token.token; } -Referer $Referer -TimeOutSec $TimeOut
    Write-Verbose ($response.messages -join ', ') 
}

function Get-LogSettings
{
    [CmdletBinding()]
    Param
    (
        [System.String]
        $URL, 

        [System.String]
        $Token, 
        
        [System.String]
        $Referer
    )

    $GetLogSettingsUrl  = Get-ServerAdminUrlForPath -URL $URL -Path "/logs/settings"
    $params = @{ f = 'json'; token = $Token; }
    $response = Invoke-ArcGISWebRequest -Url $GetLogSettingsUrl -HttpFormParameters $params -Referer $Referer -HttpMethod 'GET' 
    Write-Verbose "Response from GetLogSettings:- $(ConvertTo-Json -Compress -Depth 5 -InputObject $response)"
    Confirm-ResponseStatus $response 
    $response
}

function Update-LogSettings
{
    [CmdletBinding()]
    Param
    (
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer,

        $LogSettings,

        [System.String]
        $ServerType
    )   

    $UpdateLogSettingsUrl  = Get-ServerAdminUrlForPath -URL $URL -Path "/logs/settings/edit"
    $props = @{ 
        f= 'json' 
        token = $Token
        logDir = $logSettings.logDir
        logLevel = $logSettings.logLevel
        maxLogFileAge = $logSettings.maxLogFileAge
        maxErrorReportsCount = $logSettings.maxErrorReportsCount
    }

    if(Test-IfGISServer -ServerType $ServerType){
        # API uses a checkbox and hence need to provide on/off values
        $props['usageMeteringEnabled'] = if($logSettings.usageMeteringEnabled) { 'on' } else { 'off' } 
    }

    $response = Invoke-ArcGISWebRequest -Url $UpdateLogSettingsUrl -HttpFormParameters $props -Referer $Referer
    Confirm-ResponseStatus $response
    $response
    #  if($response.status -ieq "success"){
    #     Write-Verbose "Log Settings Update Successfully"
    # }else{
    #     Write-Verbose "[WARNING]: Code:- $($response.error.code), Error:- $($response.error.message)" 
    # }
}

function Get-SystemProperties
{
    [CmdletBinding()]
    Param
    (
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
		$Referer
    )
    $RequestParams = @{ f= 'json'; token = $Token; }
    $RequestUrl  = Get-ServerAdminUrlForPath -URL $URL -Path "/system/properties"
    $Response = Invoke-ArcGISWebRequest -Url $RequestUrl -HttpFormParameters $RequestParams -HttpMethod 'GET'  -Referer $Referer
    Confirm-ResponseStatus $Response
    $Response
}

function Set-SystemProperties
{
    [CmdletBinding()]
    Param
    (
        [System.String]
        $URL, 

        [System.String]
        $Token,
        
        $Properties, 

        [System.String]
		$Referer
    )
    $RequestUrl  = Get-ServerAdminUrlForPath -URL $URL -Path "/system/properties/update/"
    $RequestParams = @{ f= 'json'; token = $Token; properties = ( $Properties | ConvertTo-Json -Depth 5 -Compress ) }
    $Response = Invoke-ArcGISWebRequest -Url $RequestUrl -HttpFormParameters $RequestParams -Referer $Referer -TimeOutSec 180
    if($response.status -ieq "success"){
        Write-Verbose "System properties update successful"
        $Response
    }else{
        Write-Verbose "[WARNING]: Code:- $($response.error.code), Error:- $($response.error.message)" 
    }
}

function Get-SystemDirectories { 
    
    [CmdletBinding()]
	param
	(
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer
	)

    $GetRegDirUrl = Get-ServerAdminUrlForPath -URL $URL -Path "/system/directories"
    try{
        $Response =Invoke-ArcGISWebRequest -Url $GetRegDirUrl -HttpFormParameters @{ f= 'json'; token = $Token; } -Referer $Referer -TimeOutSec 150
        Confirm-ResponseStatus $Response
        $Response
    }catch{
        Write-Verbose "[WARNING] Response from $GetRegDirUrl (Get-RegisteredDirectories) is - $_"
    }
}

function Register-SystemDirectory { 
    [CmdletBinding()]
	param
	(
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer,

        [System.String]
        $Name,

        [System.String]
        $PhysicalPath,

        [System.String]
        $DirectoryType
	)

    $RegDirUrl  = Get-ServerAdminUrlForPath -URL $URL -Path "/system/directories/register"   
    $props = @{ f= 'pjson'; token = $Token; name = $Name; physicalPath = $PhysicalPath; directoryType = $DirectoryType; }
    try{
        $Response = Invoke-ArcGISWebRequest -Url $RegDirUrl -HttpFormParameters $props -Referer $Referer -TimeOutSec 150
        Confirm-ResponseStatus $Response
        $Response
    }catch{
        Write-Verbose "[WARNING] Response from $RegDirUrl (Set-RegisteredDirectories) is - $_"
    }
}

function Get-SecurityConfig
{
    [CmdletBinding()]
	param
	(
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer
	)
    
    $GetSecurityConfigUrl  = Get-ServerAdminUrlForPath -URL $URL -Path "/security/config/"
    $Response = Invoke-ArcGISWebRequest -Url $GetSecurityConfigUrl -HttpFormParameters @{ f= 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET' -TimeOutSec 30
    Confirm-ResponseStatus $Response
    $Response
}

function Update-SecurityConfig
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
		$Referer, 

        [System.String]
		$Token,
        
        [System.Object]
        $Properties,

        [System.Boolean]
        $EnableHTTPSOnly,
        
        [System.Boolean]
        $EnableHSTS,

        [System.String]
        $AuthenticationTier,    

        [System.Int32]
		$MaxAttempts = 5
	)

    $UpdateSecurityConfigUrl  = Get-ServerAdminUrlForPath -URL $URL -Path "/security/config/update"

    $props = @{
        f= 'json'
        token = $Token
    }

    if([string]::IsNullOrEmpty($AuthenticationTier)){
        $props["httpsProtocols"] = if($null -eq $Properties.httpsProtocols) {"TLSv1.2,TLSv1.1,TLSv1"}else{$Properties.httpsProtocols}
        $props["cipherSuites"] = $Properties.cipherSuites
        $props["Protocol"] = if($EnableHTTPSOnly){ "HTTPS" }else{ "HTTP_AND_HTTPS" }
        $props["authenticationTier"] = $Properties.authenticationTier
        $props["HSTSEnabled"] = "$($EnableHSTS)"
        $props["portalProperties"] = (ConvertTo-Json $Properties.portalProperties -Compress)
        $props["allowedAdminAccessIPs"]= if($null -eq $Properties.allowedAdminAccessIPs) { "" }else{$Properties.allowedAdminAccessIPs}
        $props["allowDirectAccess"]= $Properties.allowDirectAccess
        $props["allowInternetCORSEnabled"]= $Properties.allowInternetCORSAccess
        $props["virtualDirsSecurityEnabled"] = $Properties.virtualDirsSecurityEnabled
    }else{
        $securityConfig = @{
            authenticationTier = 'GIS_SERVER'
        }
        $props["securityConfig"] = ConvertTo-Json $securityConfig -Depth 5 -Compress
    }

    $Done = $false
    $NumAttempts = 0
    while(-not($Done) -and ($NumAttempts -lt $MaxAttempts)) {
        $NumAttempts++
        try {
            Write-Verbose "Update Security Config"
			Write-Verbose "Attempt $NumAttempts"
			$response = Invoke-ArcGISWebRequest -Url $UpdateSecurityConfigUrl -HttpFormParameters $props -Referer $Referer -TimeOutSec 300 -Verbose
            Confirm-ResponseStatus $response -Url $UpdateSecurityConfigUrl
            $Done = $true
        }
        catch {
            if($NumAttempts -ge $MaxAttempts){
                throw $_
            }
            Write-Verbose "[WARNING] Update security config attempt $NumAttempts failed $($_). Retrying after 30 seconds"
            Start-Sleep -Seconds 30
        }
    }
    if(-not($Done)){
        throw "Failed to update security config after $MaxAttempts attempt(s)."
    }
}

function Get-SecurityTokenSharedKey
{
    [CmdletBinding()]
	param
	(
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer
	)

    $RequestParams = @{ f= 'json'; token = $Token; }
    $RequestUrl  = Get-ServerAdminUrlForPath -URL $URL -Path "/security/tokens"
    $Response = Invoke-ArcGISWebRequest -Url $RequestUrl -HttpFormParameters $RequestParams -Referer $Referer
    Confirm-ResponseStatus $Response
    return $Response
}

function Update-SecurityTokenSharedKey 
{
    [CmdletBinding()]
	param
	(
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer,

        [System.String]
        $SharedKey
	)

    if($SharedKey){
		Write-Verbose "Get Token and Shared Key Setting"
		$TokenSettings = Get-SecurityTokenSharedKey -URL $ServerBaseUrl -Token $Token -Referer $Referer -Verbose
		if($TokenSettings.properties.sharedKey -ine $SharedKey){
			Write-Verbose "Shared Key is not set as expected. Updating shared key."	
			$RequestUrl = Get-ServerAdminUrlForPath -URL $URL -Path "/security/tokens/update"
            $TokenSettingsProperties = ConvertTo-Json $Properties
            $RequestParams = @{ f = 'json'; token = $Token; tokenManagerConfig = $TokenSettingsProperties }
            $Response = Invoke-ArcGISWebRequest -Url $RequestUrl -HttpFormParameters $RequestParams -Referer $Referer
            Confirm-ResponseStatus $Response
            $Response
		}else{
			Write-Verbose "Shared Key is set as expected"
		}
	}
}

function Get-ServiceDirectorySettings
{
    [CmdletBinding()]
	param
	(
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer
	)

    $RequestParams = @{ f= 'json'; token = $Token; }
    $RequestUrl  = Get-ServerAdminUrlForPath -URL $URL -Path "/system/handlers/rest/servicesdirectory"
    $Response = Invoke-ArcGISWebRequest -Url $RequestUrl -HttpFormParameters $RequestParams -Referer $Referer
    Confirm-ResponseStatus $Response
    return $Response
}

function Update-ServiceDirectorySettings
{
    [CmdletBinding()]
	param
	(
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer,

        [System.Boolean]
        $DisableServiceDirectory
	)

    $ServiceDirectoryProperties = Get-ServiceDirectorySettings -URL $URL -Token $Token -Referer $Referer -Verbose
    $RequestParams = Convert-PSObjectToHashtable -InputObject $ServiceDirectoryProperties
    if([System.Convert]::ToBoolean($RequestParams.enabled) -ine -not($DisableServiceDirectory)) {
        $RequestParams.enabled = if($DisableServiceDirectory){"false"}else{"true"}
        $RequestUrl = Get-ServerAdminUrlForPath -URL $URL -Path "/system/handlers/rest/servicesdirectory/edit"
        $RequestParams["f"] = 'json'
        $RequestParams["token"] = $Token
        $Response = Invoke-ArcGISWebRequest -Url $RequestUrl -HttpFormParameters $RequestParams -Referer $Referer 
        Write-Verbose $Response
        Confirm-ResponseStatus $Response
        $Response
    }
}


function Invoke-DeleteSSLCertForMachine
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $MachineName, 

        [System.String]
        $SSLCertName
    )
     
    $DeleteSSlCertUrl  = Get-ServerAdminUrlForPath -URL $URL -Path "/machines/$MachineName/sslCertificates/$SSLCertName/delete"
    Invoke-ArcGISWebRequest -Url $DeleteSSlCertUrl -HttpFormParameters @{ f= 'json'; token = $Token; } -Referer $Referer -HttpMethod 'POST' -TimeoutSec 150
}

function Invoke-GenerateSelfSignedCertificate
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $MachineName,

        [System.String]
        $CertAlias, 

        [System.String]
        $CertCommonName, 

        [System.String]
        $CertOrganization, 

        [System.String]
        $ValidityInDays = 1825

    )

    $GenerateSelfSignedCertUrl  = Get-ServerAdminUrlForPath -URL $URL -Path "/machines/$MachineName/sslCertificates/generate"
    $props = @{ f= 'json'; token = $Token; alias = $CertAlias; commonName = $CertCommonName; organization = $CertOrganization; validity = $ValidityInDays } 
    Invoke-ArcGISWebRequest -Url $GenerateSelfSignedCertUrl -HttpFormParameters $props -Referer $Referer -TimeOutSec 150
}

function Import-ExistingCertificate
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL, 
        
        [System.String]
        $Token, 
        
        [System.String]
        $Referer, 
        
        [System.String]
        $MachineName, 
        
        [System.String]
        $CertAlias, 
        
        [System.Management.Automation.PSCredential]
        $CertificatePassword, 
        
        [System.String]
        $CertificateFilePath,
        
        [System.String]
        $ServerType,

        [System.String]
        $Version,

        [System.Boolean]
        $ImportCertificateChain = $true
    )

    $ImportCACertUrl  = Get-ServerAdminUrlForPath -URL $URL -Path "/machines/$MachineName/sslCertificates/importExistingServerCertificate"
    $props = @{ f= 'json';  alias = $CertAlias; certPassword = $CertificatePassword.GetNetworkCredential().Password  }
    # Conditionally add importCertificateChain if Version is >= 11.3
    if ($Version -and ([version]$Version -ge [version]"11.3") `
    -and (-not(@("Server", "NotebookServer", "MissionServer","VideoServer","DataPipelinesServer") -iContains $ServerType))) {
        $props["importCertificateChain"] = $ImportCertificateChain
    }

    $Header = @{}
    if(-not(@("Server", "NotebookServer", "MissionServer","VideoServer","DataPipelinesServer") -iContains $ServerType)){
        $props["token"] = $Token;
    }else{
        $Header["X-Esri-Authorization"] = "Bearer $Token"
    }

    $res = Invoke-UploadFile -url $ImportCACertUrl -filePath $CertificateFilePath -fileContentType 'application/x-pkcs12' -formParams $props -Referer $Referer -fileParameterName 'certFile' -httpHeaders $Header -Verbose 
    if($res) {
        $response = $res | ConvertFrom-Json
        Confirm-ResponseStatus $response -Url $ImportCACertUrl
    } else {
        Write-Verbose "[WARNING] Response from $ImportCACertUrl was $res"
    }
}

function Import-RootOrIntermediateCertificate
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [string]
        $MachineName,

        [System.String]
        $CertAlias, 

        [System.String]
        $CertificateFilePath,

        [System.String]
        $CertificateFileName
    )
    
    $ImportCertUrl  = Get-ServerAdminUrlForPath -URL $URL -Path "/machines/$MachineName/sslCertificates/importRootOrIntermediate"
    $props = @{ f= 'json'; token = $Token; alias = $CertAlias; } 
    $res = Invoke-UploadFile -url $ImportCertUrl -filePath $CertificateFilePath -fileContentType 'application/x-pkcs12' `
                            -formParams $props -Referer $Referer -fileParameterName 'rootCACertificate' -fileName $CertificateFileName    
    if($res) {
        $response = $res | ConvertFrom-Json
        Confirm-ResponseStatus $response -Url $ImportCertUrl
    } else {
        Write-Verbose "[WARNING] Response from $ImportCertUrl was null"
    }
}

function Get-AllSSLCertificateForMachine
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL, 
        
        [System.String]
        $Token, 
        
        [System.String]
        $Referer, 
        
        [System.String]
        $MachineName
    )
    $certURL = Get-ServerAdminUrlForPath -URL $URL -Path "/machines/$MachineName/sslCertificates/"
    Invoke-ArcGISWebRequest -Url $certURL -HttpFormParameters @{ f= 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET' 
}

function Get-SSLCertificateForMachine
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [System.String]
        $URL, 
        
        [System.String]
        $Token, 
        
        [System.String]
        $Referer, 
        
        [System.String]
        $MachineName, 
        
        [System.String]
        $SSLCertName
    )
    $CertUrl  = Get-ServerAdminUrlForPath -URL $URL -Path "/machines/$MachineName/sslCertificates/$SSLCertName"
    try{
        $json = Invoke-ArcGISWebRequest -Url $CertUrl -HttpFormParameters @{ f= 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET'  
        if($json.error){
            $errMsgs = ($json.error.messages -join ', ')
            Write-Verbose "[WARNING] Response from $CertUrl is $errMsgs"
            $null
        }elseif($json.status -and $json.status -ieq "error"){
            $errMsgs = ($json.messages -join ', ')
            Write-Verbose "[WARNING] Response from $CertUrl is $errMsgs"
            $null
        }else{
            $issuer = $json.issuer
            $thumbprint = $json.sha1Fingerprint
            @{
                Issuer = $issuer
                Thumbprint = $thumbprint
            }
        }
    }
    catch{
        # If no cert exists, an error is returned
        Write-Verbose "[WARNING] Error checking $CertUrl Error:- $_"
        $null
    }
}

function Get-ServerRootAndIntermdiateCertificatesToUpdate
{
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $True)]
        [System.String]
        $URL,

        [parameter(Mandatory = $True)]
        [System.String]
        $ServerType,

        [parameter(Mandatory = $True)]
        [System.String]
        $Token,

        [System.String]
        $Referer,

        [System.String]
        $MachineName, 

        [System.String]
        $SslRootOrIntermediate
    )

    $ExistingCerts = Get-AllSSLCertificateForMachine -URL $URL -Token $Token -Referer $Referer -MachineName $MachineName 
    $AllCertificates = if(-not(Test-IfGISServer -ServerType $ServerType)){ $ExistingCerts.sslCertificates }else{ $ExistingCerts.certificates}
    $ExpectedCerts = ($SslRootOrIntermediate | ConvertFrom-Json)
    $MissingCerts = @()
    foreach ($Cert in $ExpectedCerts){
        if ($AllCertificates -icontains $Cert.Alias){
            Write-Verbose "RootOrIntermediate $($Cert.Alias) is in List of SSL-Certificates. Validating if thumbprint matches the existing certificate"
            $RootOrIntermediateCertForMachine = Get-SSLCertificateForMachine -URL $URL -Token $Token -Referer $Referer -MachineName $MachineName -SSLCertName $Cert.Alias.ToLower() -Verbose
            Write-Verbose "Existing Cert Issuer $($RootOrIntermediateCertForMachine.Issuer) and Thumbprint $($RootOrIntermediateCertForMachine.Thumbprint)"
            $NewCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $Cert.Path
            Write-Verbose "Issuer and Thumprint for the supplied certificate is $($NewCert.Issuer) and $($NewCert.Thumbprint) respectively."
            if($RootOrIntermediateCertForMachine.Thumbprint -ine $NewCert.Thumbprint){
                Write-Verbose "Thumbprints for Certificate with Alias $($Cert.Alias) doesn't match that of existing cetificate."
                $Cert | Add-Member -NotePropertyName "Present" -NotePropertyValue $true
                $MissingCerts += ($Cert)
            }else{
                Write-Verbose "Thumbprints for Certificate with Alias $($Cert.Alias) match that of existing cetificate."
            }
        }else{
            Write-Verbose "RootOrIntermediate $($Cert.Alias) is NOT in List of SSL-Certificates"
            ($Cert | Add-Member -NotePropertyName "Present" -NotePropertyValue $False)
            $MissingCerts += ($Cert)
        }
    }

    return $MissingCerts
}

function Set-ServerRootAndIntermdiateCertificates
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [parameter(Mandatory = $True)]
        [System.String]
        $URL,

        [parameter(Mandatory = $True)]
        [System.String]
        $ServerType,

        [parameter(Mandatory = $True)]
        [System.String]
        $Token,

        [System.String]
        $Referer,

        [System.String]
        $MachineName, 

        [System.String]
        $SslRootOrIntermediate
    )

    $RestartRequired = $False
    $MissingCerts = Get-ServerRootAndIntermdiateCertificatesToUpdate -URL $URL -ServerType $ServerType `
                                                -Token $Token -Referer $Referer -MachineName $MachineName `
                                                -SslRootOrIntermediate $SslRootOrIntermediate -Verbose
    
    if($MissingCerts.Count -gt 0){
        $RestartRequired = $True
        foreach ($Cert in $MissingCerts){
            if($Cert.Present){
                Write-Verbose "Thumbprints for Certificate with Alias $($Cert.Alias) doesn't match that of existing cetificate. Deleting existing certificate"
                $res = Invoke-DeleteSSLCertForMachine -URL $URL -Token $Token -Referer $Referer -MachineName $MachineName -SSLCertName $Cert.Alias.ToLower()
                Write-Verbose "Delete existing certificate successful - $($res | ConvertTo-Json)"
            }

            try{
                Import-RootOrIntermediateCertificate -URL $URL -Token $Token -Referer $Referer -MachineName $MachineName -CertAlias $Cert.Alias.ToLower() -CertificateFilePath $Cert.Path
            }catch{
                Write-Verbose "Error in Import-RootOrIntermediateCertificate :- $_"
            }
        }
    }

    if($RestartRequired){
        Write-Verbose "Server root and intermediate certificates were updated. Restart required."
    }

    return $RestartRequired
}


function Get-ConfigStoreConnectionJson
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerType,

        [System.String]
        [ValidateSet("Azure","AWS","None")]
        $CloudProvider = "None",

        [System.String]
        $ConfigurationStoreLocation,

        [System.String]
        $LocalRepositoryPath,
        
        [parameter(Mandatory = $false)]
        [System.String]
        $CloudNamespace,

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("AccessKey","IAMRole","AccessKey","ServicePrincipal","UserAssignedIdentity", "SASToken", "None")]
        $AuthenticationType = "None",

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSRegion,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AccessKeyCredential,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $ServicePrincipalCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ServicePrincipalTenantId,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ServicePrincipalAuthorityHost,

        [Parameter(Mandatory=$False)]
        [System.String]
        $UserAssignedIdentityClientId,
        
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $StorageAccountCredential
    )

    $configStoreConnection = @{}
    if($CloudProvider -ine "None"){
        if($CloudProvider -ieq "AWS"){
            Write-Verbose "Using AWS S3 Cloud Storage and Dynamo DB for the config store"
            $configStoreConnection = @{
                connectionString = "NAMESPACE=$($CloudNamespace);REGION=$($AWSRegion);";
            }

            if(Test-IfGISServer -ServerType $ServerType ){
                $configStoreConnection['type'] = "AMAZON";
                if($AuthenticationType -ieq 'AccessKey'){
                    $configStoreConnection["connectionSecret"] ="ACCESS_KEY_ID=$($AccessKeyCredential.UserName);SECRET_KEY=$($AccessKeyCredential.GetNetworkCredential().Password);"
                }
            }else{
                $configStoreConnection['configPersistenceType'] = "AMAZON";
                $configStoreConnection["className"]= "com.esri.arcgis.carbon.persistence.impl.amazon.AmazonConfigPersistence"
                if($AuthenticationType -ieq "AccessKey"){
                    if($AccessKeyCredential){
                        $configStoreConnection["username"]= $AccessKeyCredential.UserName
                        $configStoreConnection["password"]= $AccessKeyCredential.GetNetworkCredential().Password
                    }else{
                        throw "AWS Cloud Storage Access Key is not provided"
                    }
                }
            }
        }

        if($CloudProvider -ieq "Azure"){
            Write-Verbose "Using Azure Cloud Storage for the config store"

            $AccountName = $StorageAccountCredential.UserName
            $EndpointSuffix = ''
            $Pos = $StorageAccountCredential.UserName.IndexOf('.blob.')
            if($Pos -gt -1) {
                $AccountName = $StorageAccountCredential.UserName.Substring(0, $Pos)
                $EndpointSuffix = $StorageAccountCredential.UserName.Substring($Pos + 6) # Remove the hostname and .blob. suffix to get the storage endpoint suffix
                $EndpointSuffix = ";EndpointSuffix=$($EndpointSuffix)"
            }
        
            $ConfigStoreCloudStorageConnectionString = "NAMESPACE=$($CloudNamespace)$($EndpointSuffix);DefaultEndpointsProtocol=https;"
            if($AuthenticationType -ieq 'ServicePrincipal'){
                $ClientSecret = $ServicePrincipalCredential.GetNetworkCredential().Password
                $ConfigStoreCloudStorageConnectionString += ";CredentialType=ServicePrincipal;TenantId=$($ServicePrincipalTenantId);ClientId=$($ServicePrincipalCredential.Username)"
                if(-not([string]::IsNullOrEmpty($ServicePrincipalAuthorityHost))){
                    $ConfigStoreCloudStorageConnectionString += ";AuthorityHost=$($ServicePrincipalAuthorityHost)" 
                }
                $ConfigStoreCloudStorageConnectionSecret = "ClientSecret=$($ClientSecret)"
            }elseif($AuthenticationType -ieq 'UserAssignedIdentity'){
                $ConfigStoreCloudStorageConnectionString += ";CredentialType=UserAssignedIdentity;ManagedIdentityClientId=$($UserAssignedIdentityClientId)"
                $ConfigStoreCloudStorageConnectionSecret = ""
            }elseif($AuthenticationType -ieq 'SASToken'){
                $SASToken = $StorageAccountCredential.GetNetworkCredential().Password
                $ConfigStoreCloudStorageConnectionString += ";CredentialType=SASToken"
                $ConfigStoreCloudStorageConnectionSecret = "SASToken=$($SASToken)"
            }else{
                $AccountKey = $StorageAccountCredential.GetNetworkCredential().Password
                if(Test-IfGISServer -ServerType $ServerType){
                    $ConfigStoreCloudStorageConnectionSecret = "AccountKey=$($AccountKey)"
                }else{
                    $ConfigStoreCloudStorageConnectionSecret = "$($AccountKey)"
                }
            }
            
            if(Test-IfGISServer -ServerType $ServerType){
                $ConfigStoreCloudStorageConnectionString += ";AccountName=$($AccountName)"
                $configStoreConnection = @{ 
                    type= "AZURE"
                    connectionString = $ConfigStoreCloudStorageConnectionString                
                }

                if($AuthenticationType -ine 'UserAssignedIdentity'){
                    $configStoreConnection["connectionSecret"] = $ConfigStoreCloudStorageConnectionSecret
                }

            }else{
                $configStoreConnection = @{ 
                    configPersistenceType = "AZURE";
                    connectionString = $ConfigStoreCloudStorageConnectionString;
                    username = $AccountName;
                    className = "com.esri.arcgis.carbon.persistence.impl.azure.AzureConfigPersistence"
                }
                if($AuthenticationType -ine 'UserAssignedIdentity'){
                    $configStoreConnection["password"] = $ConfigStoreCloudStorageConnectionSecret
                }
            }
        }
    }else{
        Write-Verbose "Using file system based storage for the config store"
        if(Test-IfGISServer -ServerType $ServerType ){
            $configStoreConnection = @{ 
                                        type= "FILESYSTEM"
                                        connectionString = $ConfigurationStoreLocation 
                                    }

        }else{
            $configStoreConnection = @{ 
                configPersistenceType= "FILESYSTEM"
                connectionString = $ConfigurationStoreLocation
                className = "com.esri.arcgis.carbon.persistence.impl.filesystem.FSConfigPersistence"
            }
        }
    }   

    if(-not([string]::IsNullOrEmpty($LocalRepositoryPath ))){  
        $configStoreConnection["localRepositoryPath"] = $LocalRepositoryPath
    }

    return (ConvertTo-JSON $configStoreConnection -Compress -Depth 5)
}

function Get-AWSCloudConfigJson
{
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $false)]
        [System.String]
        $CloudNamespace,

        [Parameter(Mandatory=$False)]
        [System.String]
        $Tags,

        [Parameter(Mandatory=$False)]
        [System.String]
        $LocalDirectory,

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("AccessKey","IAMRole", "None")]
        $AuthenticationType = "None",

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSRegion,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AccessKeyCredential,
        
        [Parameter(Mandatory=$False)]
        [System.String]
        $S3BucketName,

        [Parameter(Mandatory=$False)]
        [System.String]
        $S3RegionEndpointURL,

        [Parameter(Mandatory=$False)]
        [System.String]
        $S3RootDir,

        [Parameter(Mandatory=$False)]
        [System.String]
        $DynamoDBRegionEndpointURL,

        [Parameter(Mandatory=$False)]
        [System.String]
        $SQSRegionEndpointURL
    )

    $CloudConfigJson = @{
        name = "AWS"
        namespace = $CloudNamespace
    }

    if(-not([string]::IsNullOrEmpty($Tags))){
        [System.Array]$tags = (ConvertFrom-Json $Tags)
        $CloudConfigJson['cloudServiceTags'] = $tags
    }

    if(-not([string]::IsNullOrEmpty($LocalDirectory))){
        $CloudConfigJson["localDirectory"] = $LocalDirectory
    }

    $CloudConfigJson["region"] = $AWSRegion 

    $AWSCredential = @{
        type = if($AuthenticationType -ieq "IAMRole") { "IAM-ROLE" } else { "ACCESS-KEY" }
    }
    if($AuthenticationType -ieq "AccessKey"){
        $AWSCredential["secret"] = @{
            accessKey = $AccessKeyCredential.UserName
            secretKey = $AccessKeyCredential.GetNetworkCredential().Password
        }
    }
    $CloudConfigJson["credential"] = $AWSCredential
    $CloudConfigJson["cloudServices"] = @(
        @{
            "name"= "AWS S3"
            "type"=  "objectStore"
            "usage"= "DEFAULT"
            "connection" = @{
                "bucketName" = $S3BucketName
                "regionEndpointUrl" = $S3RegionEndpointURL
                "rootDir" = $S3RootDir
            }
            "category" = "storage"
        },
        @{
            "name" = "Amazon Dynamo DB"
            "type" = "tableStore"
            "connection" = @{
                "regionEndpointUrl" = $DynamoDBRegionEndpointURL
            }
            "category" = "storage"
        },
        @{
            "name" = "Amazon Queue Service"
            "type" = "queueService"
            "connection" = @{
                "regionEndpointUrl" = $SQSRegionEndpointURL
            }
            "category" = "queue"
        }
    )

    return (ConvertTo-Json -Compress -InputObject @($CloudConfigJson) -Depth 10)
}

function Get-AzureCloudConfigJson
{
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $false)]
        [System.String]
        $CloudNamespace,

        [Parameter(Mandatory=$False)]
        [System.String]
        $Tags,

        [Parameter(Mandatory=$False)]
        [System.String]
        $LocalDirectory,

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("AccessKey","ServicePrincipal","UserAssignedIdentity", "SASToken", "None")]
        $AuthenticationType = "None",
        
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $ServicePrincipalCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ServicePrincipalTenantId,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ServicePrincipalAuthorityHost,

        [Parameter(Mandatory=$False)]
        [System.String]
        $UserAssignedIdentityClientId,
        
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $StorageAccountCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $StorageAccountContainerName,

        [Parameter(Mandatory=$False)]
        [System.String]
        $StorageAccountRootDir,

        [Parameter(Mandatory=$False)]
        [System.String]
        $StorageAccountAccountEndpointUrl,

        [Parameter(Mandatory=$False)]
        [System.String]
        $StorageAccountRegionEndpointUrl,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $CosmosDBAccountCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $CosmosDBAccountEndpointUrl,

        [Parameter(Mandatory=$False)]
        [System.String]
        $CosmosDBRegionEndpointUrl,

        [Parameter(Mandatory=$False)]
        [System.String]
        $CosmosDBAccountDatabaseId,

        [Parameter(Mandatory=$False)]
        [System.String]
        $CosmosDBAccountSubscriptionId,

        [Parameter(Mandatory=$False)]
        [System.String]
        $CosmosDBAccountResourceGroupName,

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("Direct","Gateway")]
        $CosmosDBAccountConnectionMode = "Gateway",

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $ServiceBusNamespaceCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ServiceBusNamespaceEndpointUrl,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ServiceBusNamespaceRegionEndpointUrl
    )

    $CloudConfigJson = @{
        name = "AZURE"
        namespace = $CloudNamespace
    }

    if(-not([string]::IsNullOrEmpty($Tags))){
        [System.Array]$tags = (ConvertFrom-Json $Tags)
        $CloudConfigJson['cloudServiceTags'] = $tags
    }

    if(-not([string]::IsNullOrEmpty($LocalDirectory))){
        $CloudConfigJson["localDirectory"] = $LocalDirectory
    }

    if($AuthenticationType -ieq "ServicePrincipal"){
        $CloudConfigJson["credential"] = @{
            type = "SERVICE-PRINCIPAL"
            authorityHost = $ServicePrincipalAuthorityHost
            secret = @{
                tenantId = $ServicePrincipalTenantId
                clientId = $ServicePrincipalCredential.UserName
                clientSecret = $ServicePrincipalCredential.GetNetworkCredential().Password
            }
        }
    }elseif($AuthenticationType -ieq "UserAssignedIdentity"){
        $CloudConfigJson["credential"] = @{
            type = "USER-ASSIGNED-IDENTITY"
            secret = @{
                managedIdentityClientId = $UserAssignedIdentityClientId
            }
        }
    }
    
    $StorageAccount = @{
        "name" = "Azure Blob Store"
        "type" = "objectStore"
        "usage" = "DEFAULT"
        "category" = "storage"
        "connection" = @{
            "containerName" = $StorageAccountContainerName
            "rootDir" = $StorageAccountRootDir
            "accountEndpointUrl" = $StorageAccountAccountEndpointUrl
        }
    }
    
    if($StorageAccountRegionEndpointUrl){
        $StorageAccount.connection["regionEndpointUrl"] = $StorageAccountRegionEndpointUrl
    }

    if($AuthenticationType -ieq "AccessKey"){
        $StorageAccount.connection["credential"] = @{
            type = "STORAGE-ACCOUNT-KEY"
            secret = @{
                "storageAccountName"= $StorageAccountCredential.UserName
                "storageAccountKey"= $StorageAccountCredential.GetNetworkCredential().Password
            }
        }            
    }

    $CosmosDB = @{
        "name" = "Azure Cosmos DB"
        "type" = "tableStore"
        "category" = "storage"
        "connection" = @{
            "accountEndpointUrl" = $CosmosDBAccountEndpointUrl
            "databaseId" = $CosmosDBAccountDatabaseId
            "cosmosDBConnectionMode" = $CosmosDBAccountConnectionMode
        }
    }
    if($CosmosDBRegionEndpointUrl){
        $CosmosDB.connection["regionEndpointUrl"] = $CosmosDBRegionEndpointUrl
    }

    if($AuthenticationType -ieq "AccessKey"){
        $CosmosDB.connection["credential"] = @{
            type = "COSMOSDB-ACCOUNT-KEY"
            secret = @{
                accountName = $CosmosDBAccountCredential.UserName
                accountKey = $CosmosDBAccountCredential.GetNetworkCredential().Password
            }
        }
    }else{
        if(-not([string]::IsNullOrEmpty($CosmosDBAccountSubscriptionId)) -and -not([string]::IsNullOrEmpty($CosmosDBAccountResourceGroupName))){
            $CosmosDB.connection["subscriptionId"] = $CosmosDBAccountSubscriptionId
            $CosmosDB.connection["resourceGroupName"] = $CosmosDBAccountResourceGroupName
        }
    }

    $ServiceBus = @{
        "name" = "Azure Service Bus"
        "type" = "queueService"
        "category" = "queue"
        "connection" = @{
            "serviceBusEndpointUrl" = $ServiceBusNamespaceEndpointUrl
        }
    }
    if($ServiceBusNamespaceRegionEndpointUrl){
        $ServiceBus.connection["regionEndpointUrl"] = $ServiceBusNamespaceRegionEndpointUrl
    }

    if($AuthenticationType -ieq "AccessKey"){
        $ServiceBus.connection["credential"] = @{
            type = "SERVICEBUS-ACCESS-KEY"
            secret = @{
                "sharedAccessKeyName" = $ServiceBusNamespaceCredential.UserName
                "sharedAccessKey" = $ServiceBusNamespaceCredential.GetNetworkCredential().Password
            }
        }
    }

    $CloudConfigJson["cloudServices"] = @( $StorageAccount, $CosmosDB, $ServiceBus )

    return (ConvertTo-Json -Compress -InputObject @($CloudConfigJson) -Depth 10)
}

function Invoke-CreateSite
{
    [CmdletBinding()]
    Param
    (
        [System.String]
        $Version,

        [System.String]
        $URL,

        [System.Management.Automation.PSCredential]
        $Credential,

        [System.String]
        $ServerType,
        
        [System.String]
        $ConfigurationStoreLocation,

        [System.String]
        $ServerDirectoriesRootLocation,

        [System.String]
        $ServerDirectories,

        [System.String]
        $LocalRepositoryPath,

        [System.String]
        $ServerLogsLocation,

        [System.String]
        [ValidateSet("OFF","SEVERE","WARNING","INFO","FINE","VERBOSE","DEBUG")]
        $LogLevel = "WARNING",

        [System.Int32]
        $TimeOut = 1000,

        [System.String]
        [ValidateSet("Azure","AWS","None")]
        $CloudProvider = "None",

        [System.Boolean]
        $UseCloudServicesSystemDirectories,

        [parameter(Mandatory = $false)]
        [System.String]
        $CloudNamespace,

        [Parameter(Mandatory=$False)]
        [System.String]
        $CloudServiceTags,

        [Parameter(Mandatory=$False)]
        [System.String]
        $LocalDirectory,

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("AccessKey","IAMRole", "None")]
        $AWSCloudAuthenticationType = "None",

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSRegion,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AWSCloudAccessKeyCredential,
        
        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSS3BucketName,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSS3RegionEndpointURL,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSS3RootDir,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSDynamoDBRegionEndpointURL,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSQueueServiceRegionEndpointURL,

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("AccessKey","ServicePrincipal","UserAssignedIdentity", "SASToken", "None")]
        $AzureAuthenticationType = "None",
        
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureServicePrincipalCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureServicePrincipalTenantId,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureServicePrincipalAuthorityHost,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureUserAssignedIdentityClientId,
        
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureStorageAccountCredential,
        
        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureStorageAccountContainerName,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureStorageAccountRootDir,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureStorageAccountAccountEndpointUrl,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureStorageAccountRegionEndpointUrl,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureCosmosDBAccountCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCosmosDBAccountEndpointUrl,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCosmosDBRegionEndpointUrl,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCosmosDBAccountDatabaseId,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCosmosDBAccountSubscriptionId,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCosmosDBAccountResourceGroupName,

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("Direct","Gateway")]
        $AzureCosmosDBAccountConnectionMode = "Gateway",

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureServiceBusNamespaceCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureServiceBusNamespaceEndpointUrl,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureServiceBusNamespaceRegionEndpointUrl
    )

    $CreateNewSiteUrl  = Get-ServerAdminUrlForPath -URL $URL -Path "/createNewSite"
    Write-Verbose "$ServerType Version - $Version"

    $requestParams = @{ 
        f = "json"
        username = $Credential.UserName
        password = $Credential.GetNetworkCredential().Password
    }

    if(-not([string]::IsNullOrEmpty($ServerLogsLocation))){           
        $requestParams["logsSettings"] = (ConvertTo-Json -Compress -InputObject @{
            logLevel = $LogLevel;
            logDir = $ServerLogsLocation;
            maxErrorReportsCount= 10;
            maxLogFileAge= 90
        })
    }

    $CloudServerArgs = @{}
    if($CloudProvider -ine "None"){
        $CloudServerArgs = @{
            CloudNamespace = $CloudNamespace
        }

        if($CloudProvider -ieq "AWS"){
            $CloudServerArgs["AuthenticationType"] = $AWSCloudAuthenticationType
            $CloudServerArgs["AWSRegion"] = $AWSRegion

            if($AWSCloudAuthenticationType -ieq "AccessKey"){
                $CloudServerArgs["AccessKeyCredential"] = $AWSCloudAccessKeyCredential
            }
        }

        if($CloudProvider -ieq "AZURE"){
            $CloudServerArgs["AuthenticationType"] = $AzureAuthenticationType
            if($AzureAuthenticationType -ieq "ServicePrincipal"){
                $CloudServerArgs["ServicePrincipalCredential"] = $AzureServicePrincipalCredential
                $CloudServerArgs["ServicePrincipalTenantId"] = $AzureServicePrincipalTenantId
                $CloudServerArgs["ServicePrincipalAuthorityHost"] = $AzureServicePrincipalAuthorityHost
            }
            if($AzureAuthenticationType -ieq "UserAssignedIdentity"){
                $CloudServerArgs["UserAssignedIdentityClientId"] = $AzureUserAssignedIdentityClientId
            }

            if(-not($UseCloudServicesSystemDirectories) -or $AzureAuthenticationType -ieq "AccessKey"){
                $CloudServerArgs["StorageAccountCredential"] = $AzureStorageAccountCredential
            }
        }
    }

    if(-not($UseCloudServicesSystemDirectories)){
        $CloudServerArgs["ServerType"] = $ServerType
        $CloudServerArgs["ConfigurationStoreLocation"] = $ConfigurationStoreLocation
        $CloudServerArgs["LocalRepositoryPath"] = $LocalRepositoryPath
        $CloudServerArgs["CloudProvider"] = $CloudProvider
        $configStoreConnectionJson = Get-ConfigStoreConnectionJson @CloudServerArgs 
        
        $requestParams["configStoreConnection"] = $configStoreConnectionJson
        
        $ServerDirectoriesObject = @()
        if(-not([string]::IsNullOrEmpty($ServerDirectories))){
            $ServerDirectoriesObject = (ConvertFrom-Json $ServerDirectories)
        }
        
        $directories =  @()
        if(Test-IfGISServer -ServerType $ServerType){
            $requestParams["runAsync"] = "false"

            # Server Directories
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

        }else{
            $requestParams["async"] = "false"
            if($ServerType -ieq "VideoServer"){
                $directories += if(($ServerDirectoriesObject | Where-Object {$_.name -ieq "arcgisvideouploads"}| Measure-Object).Count -gt 0){
                    ($ServerDirectoriesObject | Where-Object {$_.name -ieq "arcgisvideouploads"})
                }else{
                    @{
                        name = "arcgisvideouploads"
                        path = "$ServerDirectoriesRootLocation\arcgisvideouploads"
                        type = "UPLOADS"
                    }
                }

                $directories += if(($ServerDirectoriesObject | Where-Object {$_.name -ieq "arcgisvideoservices"}| Measure-Object).Count -gt 0){
                    ($ServerDirectoriesObject | Where-Object {$_.name -ieq "arcgisvideoservices"})
                }else{
                    @{
                        name = "arcgisvideoservices"
                        path = "$ServerDirectoriesRootLocation\arcgisvideoservices"
                        type = "DATA"
                    }
                }

            }else{
                if($ServerType -ieq "NotebookServer"){
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
            }
        }

        $requestParams['directories'] = ConvertTo-Json $directories -Compress
    }else{
        if(Test-IfGISServer -ServerType $ServerType){
            $requestParams["runAsync"] = "false"

            $CloudServerArgs["Tags"] = $CloudServiceTags
            $CloudServerArgs["LocalDirectory"] = $LocalDirectory

            if($CloudProvider -ieq "AWS"){
                $CloudServerArgs["S3BucketName"] = $AWSS3BucketName
                $CloudServerArgs["S3RegionEndpointURL"] = $AWSS3RegionEndpointURL
                $CloudServerArgs["S3RootDir"] = $AWSS3RootDir
                $CloudServerArgs["DynamoDBRegionEndpointURL"] = $AWSDynamoDBRegionEndpointURL
                $CloudServerArgs["SQSRegionEndpointURL"] = $AWSQueueServiceRegionEndpointURL

                $requestParams['cloudConfigJson'] = Get-AWSCloudConfigJson @CloudServerArgs
            }

            if($CloudProvider -ieq "AZURE"){
                if($AzureAuthenticationType -ieq "AccessKey"){
                    $CloudServerArgs["CosmosDBAccountCredential"] = $AzureCosmosDBAccountCredential
                    $CloudServerArgs["ServiceBusNamespaceCredential"] = $AzureServiceBusNamespaceCredential
                }
            
                if($AzureAuthenticationType -ieq "SASToken"){
                    throw "SASToken is not supported for Native Cloud Storage"
                }

                $CloudServerArgs["StorageAccountContainerName"] = $AzureStorageAccountContainerName
                $CloudServerArgs["StorageAccountRootDir"] = $AzureStorageAccountRootDir
                $CloudServerArgs["StorageAccountAccountEndpointUrl"] = $AzureStorageAccountAccountEndpointUrl
                if($AzureStorageAccountRegionEndpointUrl){
                    $CloudServerArgs["StorageAccountRegionEndpointUrl"] = $AzureStorageAccountRegionEndpointUrl
                }
                
                $CloudServerArgs["CosmosDBAccountEndpointUrl"] = $AzureCosmosDBAccountEndpointUrl
                if($AzureCosmosDBRegionEndpointUrl){
                    $CloudServerArgs["CosmosDBRegionEndpointUrl"] = $AzureCosmosDBRegionEndpointUrl
                }

                $CloudServerArgs["CosmosDBAccountDatabaseId"] = $AzureCosmosDBAccountDatabaseId
                if(-not([string]::IsNullOrEmpty($AzureCosmosDBAccountSubscriptionId))){
                    $CloudServerArgs["CosmosDBAccountSubscriptionId"] = $AzureCosmosDBAccountSubscriptionId
                }
                if(-not([string]::IsNullOrEmpty($AzureCosmosDBAccountResourceGroupName))){
                    $CloudServerArgs["CosmosDBAccountResourceGroupName"] = $AzureCosmosDBAccountResourceGroupName
                }
                $CloudServerArgs["CosmosDBAccountConnectionMode"] = $AzureCosmosDBAccountConnectionMode

                $CloudServerArgs["ServiceBusNamespaceEndpointUrl"] = $AzureServiceBusNamespaceEndpointUrl
                if($AzureServiceBusNamespaceRegionEndpointUrl){
                    $CloudServerArgs["ServiceBusNamespaceRegionEndpointUrl"] = $AzureServiceBusNamespaceRegionEndpointUrl
                }

                $requestParams['cloudConfigJson'] = Get-AzureCloudConfigJson @CloudServerArgs
            }


        }else{
            throw "$ServerType doesn't support all system directories in cloud services" # TODO - refine message
        }
    }

    # make sure Tomcat is up and running BEFORE sending a request
    Write-Verbose "Waiting for Server '$($URL)' to initialize"
    Test-ArcGISComponentHealth -BaseURL $URL -ComponentName $ServerType -SleepTimeInSeconds 5

    #Write-Verbose $requestParams
    [int]$Attempt = 1
    [bool]$Done = $false
    while(-not($Done) -and ($Attempt -le 3)) {  # Max of three attempts             
        try {
            Write-Verbose 'Creating Site'
            if($Attempt -gt 1) {
                Write-Verbose "Attempt # $Attempt"   
            }            
            
            $response = Invoke-ArcGISWebRequest -Url $CreateNewSiteUrl -HttpFormParameters $requestParams -TimeOutSec $TimeOut -Verbose 
            if($response.status -ieq "success"){
                Write-Verbose "Site created successfully!"
            }else{
                $responseMessages = ($response.messages -join ', ')
                if ($response.status -and ($response.status -ieq "error")) { 
                    throw "Create site failed. Error:- $responseMessages"
                }
                if($response.error){
                    throw "Create site failed. Code:- $($response.error.code), Error:- $($response.error.message)"
                }
            }

            $Done = $true
            Write-Verbose 'Site created.' 
        }
        catch {
            Write-Verbose "[WARNING] Error while creating site on attempt $Attempt. Error:- $_"
            # First attempt - If the site failed to create because of permissions. Restart the service and try again
            if($Attempt -eq 1) { 
                Restart-ArcGISService -ComponentName $ServerType -Verbose

                Write-Verbose "Waiting for server '$($URL)' to initialize"
                Test-ArcGISComponentHealth -BaseURL $URL -ComponentName $ServerType -SleepTimeInSeconds 5
            } else {
                if($_.ToString().IndexOf('The remote name could not be resolved') -gt -1) {
                    # 3rd attempt - throw the error.
                    if($Attempt -eq 3) {
                        throw "Failed to create site after multiple attempts due to network initialization."
                    }else {
                        # Retry on second attempt if networking error
                        Write-Verbose "Possible networking initialization error." 
                    }
                } else { # if not a network issue, throw error on second attempt
                    throw $_
                }
                
                $retryTime = if($CloudProvider -ine "None"){ 120 }else{ 45 }
                Write-Verbose "Retrying site creation after $retryTime seconds"
                Start-Sleep -Seconds $retryTime
            }
            if($Attempt -eq 3){
                throw $_
            }
        }
        $Attempt = $Attempt + 1
    }
}

function Test-GISServerUpgrade
{
    [CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [System.String]
        $URL,

        [System.String]
        $Version,
        
        [System.String]
        $Referer
    )

    [string]$ServerUpgradeUrl = Get-ServerAdminUrlForPath -URL $URL -Path "/upgrade"
    $result = $false
    $ResponseStatus = Invoke-ArcGISWebRequest -Url $ServerUpgradeUrl -HttpFormParameters @{f = 'json'} -Referer $Referer -Verbose -HttpMethod 'GET'
    if($ResponseStatus.upgradeStatus -ieq "UPGRADE_REQUIRED" -or $ResponseStatus.upgradeStatus -ieq "LAST_ATTEMPT_FAILED" -or $ResponseStatus.upgradeStatus -ieq "IN_PROGRESS"){
        $result = $false
    }else{
        if(($ResponseStatus.code -ieq '404') -and ($ResponseStatus.status -ieq 'error')){
            $result = Test-GISServerUpgradeStatus -URL $URL -Referer $Referer -Version $Version -Verbose
        } else {
            Write-Verbose "Error Code - $($ResponseStatus.code), Error Messages - $($ResponseStatus.messages)"
            $result = $false
        }
    }
    return $result
}

function Test-GISServerUpgradeStatus
{
    [CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [System.String]
        $URL,

        [System.String]
        $Version,
        
        [System.String]
        $Referer
    ) 

    $ServerRestInfoUrl = $URL.TrimEnd('/') + "/rest/info"
    Write-Verbose "Additional checks for Server upgrades."
    $Info = Invoke-ArcGISWebRequest -Url $ServerRestInfoUrl -HttpFormParameters @{f = 'json';} -HttpMethod "GET" -Referer $Referer -Verbose
    $currentversion = "$($Info.currentVersion)"
    Write-Verbose "Current Version Installed - $currentversion"
    
    if($currentversion -ieq "10.91"){
        $currentversion = "10.9.1"
    }elseif($currentversion -ieq "11"){
        $currentversion = "11.0"
    }elseif($currentversion -ieq "12"){
        $currentversion = "12.0"
    }

    $CurrentVersionObject = ([version]$currentversion)
    $NormalizedCurrentVersion = [version]::new(
        $CurrentVersionObject.Major,
        $CurrentVersionObject.Minor,
        $(if($CurrentVersionObject.Build -lt 0) { 0 } else { $CurrentVersionObject.Build })
    )

    $ExpectedVersionObject = [version]$Version
    $NormalizedExpectedVersion = [version]::new(
        $ExpectedVersionObject.Major,
        $ExpectedVersionObject.Minor,
        $(if($ExpectedVersionObject.Build -lt 0) { 0 } else { $ExpectedVersionObject.Build })
    )

    $result = ($NormalizedCurrentVersion -eq $NormalizedExpectedVersion)
    if($result){
        Write-Verbose 'Server upgrade successful'
    }
    return $result   
}

function Test-ServerUpgrade
{
    [CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [System.String]
        $URL,
        
        [System.String]
        $Referer
    )

    [string]$ServerUpgradeUrl = Get-ServerAdminUrlForPath -URL $URL -Path "/upgrade"
    $result = $false
    $ResponseStatus = Invoke-ArcGISWebRequest -Url $ServerUpgradeUrl -HttpFormParameters @{f = 'json'} -Referer $Referer -Verbose -HttpMethod 'GET'
    if($ResponseStatus.isUpgrade -ieq $true ){
        $result = $false
    }else{
        $result = $true
        Write-Host "Server is already upgraded to required Version."
    }
    return $result
}

function Invoke-ServerUpgrade
{
    [CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [System.String]
        $URL,
        
        [System.String]
        $Referer
    )

    [string]$ServerUpgradeUrl = Get-ServerAdminUrlForPath -URL $URL -Path "/upgrade"
    $ResponseStatus = Invoke-ArcGISWebRequest -Url $ServerUpgradeUrl -HttpFormParameters @{f = 'json'} -Referer $Referer -Verbose -HttpMethod 'GET'
    if($ResponseStatus.isUpgrade -ieq $true){
        Write-Verbose "Making request to $ServerUpgradeUrl to upgrade the site"
        $Response = Invoke-ArcGISWebRequest -Url $ServerUpgradeUrl -HttpFormParameters @{ f = 'json' } -Referer $Referer -Verbose
        if($Response.status -ieq "success"){
            Write-Verbose 'Server Upgrade Successful'
        }else{
            throw "An error occurred. Upgrade request response - $Response"
        }
    }else{
        Write-Verbose 'Server is already upgraded'
    }   
}

function Invoke-GISServerUpgrade
{
    [CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [System.String]
        $URL,
        
        [System.String]
        $Referer,

        [System.String]
        $Version,

        [System.Boolean]
        $EnableUpgradeSiteDebug
    )

    [string]$ServerLocalUrl = Get-ServerAdminUrlForPath -URL $URL -Path "/local"
    Write-Verbose "Making request to $ServerLocalUrl before upgrading the site"
    Invoke-ArcGISWebRequest -Url $ServerLocalUrl -HttpFormParameters @{f = 'json'} -Referer $Referer -Verbose

    [string]$ServerUpgradeUrl = Get-ServerAdminUrlForPath -URL $URL -Path "/upgrade"
    Write-Verbose "Making request to $ServerUpgradeUrl to Upgrade the site"
    $UpgradeParameters = @{f = 'json'; runAsync='true'}
    if([version]$Version -ge "11.0" -and $EnableUpgradeSiteDebug){
        $UpgradeParameters.Add("enableDebug", 'true')
    }

    $Response = Invoke-ArcGISWebRequest -Url $ServerUpgradeUrl -HttpFormParameters $UpgradeParameters -Referer $Referer -Verbose
    try{
        if($Response){
            if($Response.upgradeStatus -ieq 'IN_PROGRESS' -or $Response.upgradeStatus -ieq 'In Progress' -or ($Response.status -ieq "error" -and $Response.code -ieq 403 -and ($Response.messages -imatch "Upgrade in progress."))) {
                Write-Verbose "Upgrade in Progress"
                $ServerReady = $false
                $Attempts = 0

                $MaxWaitTimeInSeconds = 3600 * 4 # 4 hours
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                while((-not($ServerReady)) -and ($stopwatch.Elapsed.TotalSeconds -lt $MaxWaitTimeInSeconds)) {
                    
                    $ResponseStatus = Invoke-ArcGISWebRequest -Url $ServerUpgradeUrl -HttpFormParameters $UpgradeParameters -Referer $Referer -Verbose -HttpMethod 'GET'
                    
                    Write-Verbose "Response received:- $(ConvertTo-Json -Depth 5 -Compress -InputObject $ResponseStatus)"
                    if(($ResponseStatus.upgradeStatus -ine 'IN_PROGRESS' -or $ResponseStatus.upgradeStatus -ieq 'In Progress') -and ([version]$Version -gt "11.3")){
                        foreach($Stage in $ResponseStatus.stages){
                            Write-Verbose "$($Stage.name) : $($Stage.state)"
                        }
                    }

                    if($ResponseStatus.upgradeStatus -ieq 'Success' -or $ResponseStatus.upgradeStatus -ieq 'Success with warnings' -or (($ResponseStatus.upgradeStatus -ne 'IN_PROGRESS') -and ($ResponseStatus.upgradeStatus -ne 'In Progress') -and ($ResponseStatus.code -ieq '404') -and ($ResponseStatus.status -ieq 'error'))){
                        if(Test-GISServerUpgradeStatus -URL $URL -Referer $Referer -Version $Version -Verbose){
                            $ServerReady = $True
                            break
                        }
                    }elseif(($ResponseStatus.status -ieq "error") -and ($ResponseStatus.code -ieq '500')){
                        throw $ResponseStatus.messages
                        break
                    }elseif($ResponseStatus.upgradeStatus -ieq "LAST_ATTEMPT_FAILED"){
                        throw $ResponseStatus.messages
                        break
                    }

                    Start-Sleep -Seconds 5
                    $Attempts = $Attempts + 1
                }
                $stopwatch.Stop()
                
                if(-not($ServerReady)){
                    throw "Server upgrade timeout. Server not ready after 4 hours."
                }
            }else{
                throw "Unknown error. Response - $(ConvertTo-Json -Depth 5 -Compress -InputObject $Response)"  
            }  
        }else{
            throw "$ServerUpgradeUrl returned a null response."
        }
    }catch{
        throw "[ERROR] Upgrade failure. $_"
    }
}

function Unregister-ServerWebAdaptor
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $WebAdaptorURL,

        [System.String]
        $Referer = 'https://localhost',

        [System.String]
        $Token
    )

    $WASystemUrl = "$($URL)/admin/system/webadaptors"
    $WebAdaptors = Invoke-ArcGISWebRequest -HttpMethod "GET" -Url $WASystemUrl -HttpFormParameters @{ token = $Token; f = 'json' } -Referer $Referer

    $WebAdaptors.webAdaptors | ForEach-Object {
        if($_.webAdaptorURL -ieq  $WebAdaptorUrl) {
            Write-Verbose "Webadaptor with URL $($_.webAdaptorURL) exists. Unregistering the web adaptor"
            Invoke-ArcGISWebRequest -Url ("$($WASystemUrl)/$($_.id)/unregister") -HttpFormParameters  @{ f = 'json'; token = $Token } -Referer $Referer -TimeoutSec 300    
        }
    }
}

function Test-VideoServerLiveStreamPortsNeedsUpdates{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [System.String]
        $URL,

        [System.String]
        $Referer = 'https://localhost',

        [System.String]
        $Token,

        [System.String]
        $Ports
    )

    $PortsObject = ConvertFrom-Json $Ports
    <# ex. {"RTMPPort":1935,"RTSPTCPPort":554,"RTSPUDPPortRangeMin":50100,"RTSPUDPPortRangeMax":50200} #>

    [string]$LiveStreamPortsUrl = Get-ServerAdminUrlForPath -URL $URL -Path "/system/livestream"
    $Response  = Invoke-ArcGISWebRequest -HttpMethod "GET" -Url $LiveStreamPortsUrl -HttpFormParameters @{ token = $Token; f = 'json' } -Referer $Referer
    Confirm-ResponseStatus $Response -Url $LiveStreamPortsUrl
    if(-not($Response.livestreamPorts)){
        throw "Live stream ports response did not include livestreamPorts."
    }
    #Ex. response - {"livestreamPorts":{"rangeMax":65535,"rtspPort":554,"rangeMin":49152,"rtmpPort":1935}}
    $CurrentPorts = $Response.livestreamPorts
    $NeedsUpdates = $false

    if($null -ne $PortsObject.RTMPPort -and ([int]$PortsObject.RTMPPort -ne [int]$CurrentPorts.rtmpPort)){
        Write-Verbose "Video Server RTMP port '$($CurrentPorts.rtmpPort)' doesn't match expected value '$($PortsObject.RTMPPort)'"
        $NeedsUpdates = $true
    }

    if($null -ne $PortsObject.RTSPTCPPort -and ([int]$PortsObject.RTSPTCPPort -ne [int]$CurrentPorts.rtspPort)){
        Write-Verbose "Video Server RTSP TCP port '$($CurrentPorts.rtspPort)' doesn't match expected value '$($PortsObject.RTSPTCPPort)'"
        $NeedsUpdates = $true
    }

    if($null -ne $PortsObject.RTSPUDPPortRangeMin -and ([int]$PortsObject.RTSPUDPPortRangeMin -ne [int]$CurrentPorts.rangeMin)){
        Write-Verbose "Video Server RTSP UDP port range min '$($CurrentPorts.rangeMin)' doesn't match expected value '$($PortsObject.RTSPUDPPortRangeMin)'"
        $NeedsUpdates = $true
    }

    if($null -ne $PortsObject.RTSPUDPPortRangeMax -and ([int]$PortsObject.RTSPUDPPortRangeMax -ne [int]$CurrentPorts.rangeMax)){
        Write-Verbose "Video Server RTSP UDP port range max '$($CurrentPorts.rangeMax)' doesn't match expected value '$($PortsObject.RTSPUDPPortRangeMax)'"
        $NeedsUpdates = $true
    }

    return $NeedsUpdates
}

function Set-UpdateVideoServerLivestreamPorts
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [System.String]
        $URL,

        [System.String]
        $Referer = 'https://localhost',

        [System.String]
        $Token,

        [System.String]
        $Ports
    )

    # ex. {"RTMPPort":1935,"RTSPTCPPort":554,"RTSPUDPPortRangeMin":50100,"RTSPUDPPortRangeMax":50200}
    $PortsObject = ConvertFrom-Json $Ports
    
    $HttpFormParams = @{ 
        f = 'json'
        token = $Token
        rtmpPort = [int]$PortsObject.RTMPPort
        rtspPort = [int]$PortsObject.RTSPTCPPort
        rangeMin = [int]$PortsObject.RTSPUDPPortRangeMin
        rangeMax = [int]$PortsObject.RTSPUDPPortRangeMax
    }

    [string]$LiveStreamPortsUpdateUrl = Get-ServerAdminUrlForPath -URL $URL -Path "/system/livestream/serverPorts"
    $Response  = Invoke-ArcGISWebRequest -HttpMethod "POST" -Url $LiveStreamPortsUpdateUrl -HttpFormParameters $HttpFormParams -Referer $Referer
    Confirm-ResponseStatus $Response -Url $LiveStreamPortsUpdateUrl
    return ($Response.success -ieq 'true')
}


Export-ModuleMember -Function *