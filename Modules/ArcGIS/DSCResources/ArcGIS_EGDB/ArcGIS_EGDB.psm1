$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

<#
    .SYNOPSIS
        Configures a Refrenced or Managed Geo Database
    .PARAMETER Ensure
        Indicates if the GeoDatabase should be configured or not. Take the values Present or Absent. 
        - "Present" ensures that GeoDatabase is Configured with a server whether as a refrenced or Managed one.
        - "Absent" ensures that GeoDatabase is Un-Configured i.e. when present (Not Implemented).    
    .PARAMETER DatabaseServer
        Host Name of the Machine on which the GeoDatabase is installed and Configured. 
    .PARAMETER DatabaseName
        Name of the GeoDatabase
    .PARAMETER ServerSiteAdministrator
         A MSFT_Credential Object - Primary site administrator of the Server to register the GeoDatabase.
    .PARAMETER DatabaseServerAdministrator
        A MSFT_Credential Object - Database Admin User
    .PARAMETER SDEUser
        A MSFT_Credential Object - A SDE User
    .PARAMETER DatabaseUser
        A MSFT_Credential Object - A Geo-Database User
    .PARAMETER IsManaged
         Boolean to Indicate if the GeoDatabase is Managed.
    .PARAMETER EnableGeodatabase
        Boolean parameter to Indicate Enabling of a Geo-Database.
    .PARAMETER DatabaseType
        Type of Database Product used to install the GeoDatabase - "AzureSQLDatabase","SQLServerDatabase","AzurePostgreSQLDatabase","AzureMISQLDatabase"
#>

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$DatabaseServer,

        [parameter(Mandatory = $true)]
		[System.String]
		$DatabaseName
	)
	
	$returnValue = @{
		DatabaseServer = $DatabaseServer
        DatabaseName = $DatabaseName
	}

	$returnValue	
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$DatabaseServer,

        [parameter(Mandatory = $true)]
		[System.String]
		$DatabaseName,

        [parameter(Mandatory = $true)]
		[PSCredential]
		$ServerSiteAdministrator,

        [parameter(Mandatory = $true)]
		[PSCredential]
		$DatabaseServerAdministrator,
        
        [parameter(Mandatory = $false)]
		[PSCredential]
        $SDEUser,

        [parameter(Mandatory = $true)]
		[PSCredential]
		$DatabaseUser,

        [parameter(Mandatory = $true)]
		[System.Boolean]
		$IsManaged,

        [parameter(Mandatory = $true)]
		[System.Boolean]
		$EnableGeodatabase,

        [parameter(Mandatory = $true)]
        [ValidateSet("SQLServerDatabase","AzureSQLDatabase","AzureMISQLDatabase","AzurePostgreSQLDatabase","AzureFlexiblePostgreSQLDatabase")]
		[System.String]
		$DatabaseType,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)
	
	if($Ensure -ieq 'Present') {
        Write-Verbose "Waiting for 'https://localhost:6443/arcgis/admin/' to intialize"
        Wait-ForUrl -Url 'https://localhost:6443/arcgis/admin/' -Verbose

        $ServerUrl = "https://localhost:6443/"

        $Referer = 'https://localhost:6443'
        Write-Verbose "Retrieve token for site admin $($ServerSiteAdministrator.UserName)"
        $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Referer $Referer -Credential $ServerSiteAdministrator

        Write-Verbose "Ensure the Publishing GP Service (Tool) is started on Server"
        $PublishingToolsPath = 'System/PublishingTools.GPServer'
        [int]$NumAttempts = 0
        [bool]$Done = $False
        while(-not($Done) -and ($NumAttempts -lt 10)) {
            Write-Verbose "Sleeping for 1 minutes for the Publishing Service To Come up"
            Start-Sleep -Seconds 60
            $serviceStatus = Get-ServiceStatus -ServerURL $ServerUrl -Token $token.token -Referer $Referer -ServicePath $PublishingToolsPath
            Write-Verbose "Service Status :- $serviceStatus"
            if($serviceStatus.configuredState -ine 'STARTED' -or $serviceStatus.realTimeState -ine 'STARTED') {
                Write-Verbose "Starting Service $PublishingToolsPath"
                Start-ServerService -ServerURL $ServerUrl -Token $token.token -Referer $Referer -ServicePath $PublishingToolsPath
            }else{
                Write-Verbose "Service $PublishingToolsPath are started."
                break;
            }
            $NumAttempts++
        }

        $IsPostgres = ($DatabaseType -ieq 'AzurePostgreSQLDatabase' -or $DatabaseType -ieq 'AzureFlexiblePostgreSQLDatabase')
        
        $SdeUserName = "sde"
        $SdeUserPasswordSecureObject = if($SDEUser){ $SDEUser.Password }else{ $DatabaseUser.Password }
        $SDECredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($SdeUserName, $SdeUserPasswordSecureObject )
        if($IsPostgres){
            Import-Module -Name (Join-Path $PSScriptRoot 'ArcGIS_EGDB.PostgreSQL.psm1')
            Invoke-CreatePostgreSQLSDEIfNotExist -DatabaseType $DatabaseType -DatabaseServer $DatabaseServer `
                            -DatabaseName $DatabaseName -DatabaseServerAdministrator $DatabaseServerAdministrator `
                            -SDECredential $SDECredential -DatabaseUser $DatabaseUser `
                            -EnableGeodatabase $EnableGeodatabase -Verbose
        }else{
            Import-Module -Name (Join-Path $PSScriptRoot 'ArcGIS_EGDB.MSSQL.psm1')
            Invoke-CreateMSSQLSDEIfNotExist -DatabaseType $DatabaseType -DatabaseServer $DatabaseServer `
                            -DatabaseName $DatabaseName -DatabaseServerAdministrator $DatabaseServerAdministrator `
                            -SDECredential $SDECredential -DatabaseUser $DatabaseUser -Verbose
        }
        
        try {
            $DBType =  if($IsPostgres){ "POSTGRESQL" }else{ "SQLSERVER" } 

            $ServiceName = 'ArcGIS Server'
            $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
            $RealVersion = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).RealVersion
            $InstallDir =(Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir
            Write-Verbose "RealVersion of ArcGIS Software Installed:- $RealVersion"
            $RealVersionArr = $RealVersion.Split(".")
            $Version = $RealVersionArr[0] + '.' + $RealVersionArr[1] 
            $UsePython3 = ($RealVersion -eq "10.9.1" -or $RealVersionArr -eq 11)
            if($UsePython3){
                $PythonInstallDir = Join-Path $InstallDir "\\framework\\runtime\\ArcGIS\\bin\\Python\\envs\\arcgispro-py3"
            }else{
                $PythonInstallDir = (Get-ItemProperty -Path "HKLM:\SOFTWARE\ESRI\Python$($Version)").PythonDir    
            }
            $PythonPath = ((Get-ChildItem -Path $PythonInstallDir -Filter 'python.exe' -Recurse -File) | Select-Object -First 1 -ErrorAction Ignore)
            if($null -eq $PythonPath) {
                throw "Python not found on machine. Please install Python."
            }
            $PythonInterpreterPath = $PythonPath.FullName

            if($EnableGeodatabase) 
            {
                $PythonScriptFileName = if($UsePython3){'enable_enterprise_gdb_3x.py'}else{'enable_enterprise_gdb.py'}
                $PythonScriptPath = Join-Path $PSScriptRoot $PythonScriptFileName
                if(-not(Test-Path $PythonScriptPath)){
                    throw "$PythonScriptPath not found"
                }

                $LicenseFilePath = "$env:SystemDrive\Program Files\ESRI\License$($Version)\sysgen\keycodes"
                if(-not (Test-Path $LicenseFilePath)) {
                    throw "License file not found at expected location $LicenseFilePath" 
                }
                ## Having a space in the path to the license file causes issue
                ## Copy the file temporarily to root of the system drive
                $TempFolderPath = Join-Path "$env:SystemDrive\ArcGIS\Deployment" 'Temp'
                if(-not(Test-Path $TempFolderPath))
                {
                    Write-Verbose "Creating folder $TempFolderPath"
                    New-Item $TempFolderPath -ItemType directory -Force 
                }
                Copy-Item -Path $LicenseFilePath -Destination (Join-Path $TempFolderPath 'licensecopytemp.ecp') -Force
                $LicenseFilePath = (Join-Path $TempFolderPath 'licensecopytemp.ecp')        
                Write-Verbose "Temp copy of license $LicenseFilePath"
                if(-not (Test-Path $LicenseFilePath)) {
                    throw "License file that was copied was not found at expected location $LicenseFilePath" 
                }

                Write-Verbose 'Enabling Geodatabase'       
                $SdeConnectUserName = if($DatabaseType -ieq "AzurePostgreSQLDatabase"){ "$($SdeUserName)@$($DatabaseServer.Split(".")[0])" }else{ $SdeUserName }
                $Arguments = " ""$PythonScriptPath"" --DBMS $DBType -s $DatabaseServer -d $DatabaseName -u $SdeConnectUserName -p $($SDECredential.GetNetworkCredential().Password) -l $LicenseFilePath"
                Write-Verbose "[Running Command] $PythonInterpreterPath $Arguments "
                $StdOutLogFile = [System.IO.Path]::GetTempFileName()
                $StdErrLogFile = [System.IO.Path]::GetTempFileName()
                Start-Process -FilePath $PythonInterpreterPath -ArgumentList $Arguments -RedirectStandardError $StdErrLogFile -RedirectStandardOutput $StdOutLogFile -Wait
                Write-Verbose "$StdOutLogFile"
                $StdOut = Get-Content $StdOutLogFile -Raw
                if($null -ne $StdOut -and $StdOut.Length -gt 0) {
                    Write-Verbose $StdOut
                }
                if($StdOut -icontains 'ERROR') { throw "Error Enabling Geodatabase. StdOut Error:- $StdOut"}
                [string]$StdErr = Get-Content $StdErrLogFile -Raw
                if($null -ne $StdErr -and $StdErr.Length -gt 0) {
                    Write-Verbose "[ERROR] $StdErr"
                }
                if($StdErr -icontains 'ERROR') { throw "Error Enabling Geodatabase. StdErr Error:- $StdErr"}
                Remove-Item $StdOutLogFile -Force -ErrorAction Ignore
                Remove-Item $StdErrLogFile -Force -ErrorAction Ignore  
            }

            #region Create Connection file
            $OpFolder = $env:TEMP
            $OpFile = "$($DatabaseServer)_$($DatabaseName)_$($DatabaseUserName).sde"
            $SDEFile = Join-Path $OpFolder $OpFile 
            $PythonScriptFileName = if($UsePython3){'create_connection_file_3x.py'}else{'create_connection_file.py'}
            $PythonScriptPath = Join-Path $PSScriptRoot $PythonScriptFileName
            if(-not(Test-Path $PythonScriptPath)){
                throw "$PythonScriptPath not found"
            }

			$DatabaseUserName = $DatabaseUser.UserName
            $DBConnectUserName = if($DatabaseType -ieq "AzurePostgreSQLDatabase"){"$($DatabaseUserName)@$($DatabaseServer.Split(".")[0])" }else{ $DatabaseUserName }
            $Arguments = " ""$PythonScriptPath"" --DBMS $DBType -s $DatabaseServer -d $DatabaseName -u $DBConnectUserName -p $($DatabaseUser.GetNetworkCredential().Password) -o $OpFolder -f $OpFile"
            
            Write-Verbose "[Running Command] $PythonInterpreterPath $Arguments"
            $StdOutLogFile = [System.IO.Path]::GetTempFileName()
            $StdErrLogFile = [System.IO.Path]::GetTempFileName()
            Start-Process -FilePath $PythonInterpreterPath -ArgumentList $Arguments -RedirectStandardError $StdErrLogFile -RedirectStandardOutput $StdOutLogFile -Wait
            $StdOut = Get-Content $StdOutLogFile -Raw

            if($null -ne $StdOut -and $StdOut.Length -gt 0) {
                Write-Verbose $StdOut
            }
            $SDELogContents = $null
            if($IsPostgres){
                $SDELogFilePath = Join-Path $env:Temp 'sde_setup' #check
            }else{
                $SDELogFilePath = Join-Path $env:Temp 'sdedc_SQL Server'
            }
            if(Test-Path $SDELogFilePath) {
                $SDELogContents = (Get-Content $SDELogFilePath -Raw)
                Write-Verbose $SDELogContents                
            }
            #if($SDELogContents -and $SDELogContents.IndexOf('Fail') -gt -1){
                #   throw "[ERROR] $SDELogContents"
            #}
            if($StdOut -and ($StdOut.IndexOf('ERROR') -gt -1)) { throw "Error Creating Connection File. StdOut Error:- $StdOut"}
            $StdErr = Get-Content $StdErrLogFile -Raw
            if($null -ne $StdErr -and $StdErr.Length -gt 0) {
                Write-Verbose "[ERROR] $StdErr"
            }
            if($StdErr -icontains 'ERROR') { throw "Error Creating Connection File. StdErr Error:- $StdErr"}
            Remove-Item $StdOutLogFile -Force -ErrorAction Ignore
            Remove-Item $StdErrLogFile -Force -ErrorAction Ignore
            #endregion    

            $ServerUrl = 'https://localhost:6443/'
            $dataItems = Get-ArcGISEGDBDataItems -SiteName 'arcgis' -Token $token.token -Referer $Referer 
            $dataItemForDatabase = $dataItems | Where-Object { $DatabaseServer -ieq $_.SERVER -and $DatabaseName -ieq $_.DATABASE }    
            if(-not($dataItemForDatabase))
            {
                Write-Verbose "Item for database '$DatabaseName' in Server '$DatabaseServer' is NOT registered. Registering now."
                Register-EGDBWithServerSite -ServerUrl $ServerUrl -SiteName 'arcgis' -SDEFilePath $SDEFile `
                                                -Server $DatabaseServer -Database $DatabaseName `
                                                -Token $token.token -Referer $Referer `
                                                -IsManaged $IsManaged
            }else {
                Write-Verbose "Item for database '$DatabaseName' in Server '$DatabaseServer' is already registered"
            }
        }
        finally
        {
            ##
            ## Remove License File 
            ##
            if($LicenseFilePath -and (Test-Path $LicenseFilePath)) {
                Write-Verbose "Removing License File $LicenseFilePath"
                Remove-Item $LicenseFilePath -ErrorAction Ignore | Out-Null
            }
        
            ##
            ## Remove .sde file
            ##
            if($null -ne $SDEFile -and $SDEFile.Length -gt 0 -and (Test-Path $SDEFile)) {
                Write-Verbose "Removing SDEFile $SDEFile"
                Remove-Item $SDEFile -ErrorAction Ignore | Out-Null
            }

            if($TempFolderPath -and $TempFolderPath.Length -gt 0 -and (Test-Path $TempFolderPath)) {
                Write-Verbose "Removing TempFolder $TempFolderPath"
                Remove-Item $TempFolderPath -ErrorAction Ignore | Out-Null
            }
         }
    }
    elseif($Ensure -ieq 'Absent') {        
        Write-Warning "Absent has not been implemented"
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
		$DatabaseServer,

        [parameter(Mandatory = $true)]
		[System.String]
		$DatabaseName,

        [parameter(Mandatory = $true)]
		[PSCredential]
		$ServerSiteAdministrator,

        [parameter(Mandatory = $true)]
		[PSCredential]
		$DatabaseServerAdministrator,

        [parameter(Mandatory = $false)]
		[PSCredential]
        $SDEUser,

        [parameter(Mandatory = $true)]
		[PSCredential]
		$DatabaseUser,

        [parameter(Mandatory = $true)]
		[System.Boolean]
		$IsManaged,

        [parameter(Mandatory = $true)]
		[System.Boolean]
		$EnableGeodatabase,

        [parameter(Mandatory = $true)]
        [ValidateSet("SQLServerDatabase","AzureSQLDatabase","AzureMISQLDatabase","AzurePostgreSQLDatabase","AzureFlexiblePostgreSQLDatabase")]
		[System.String]
		$DatabaseType,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)
    

    $result = $false    
    $ServerUrl = 'https://localhost:6443/'
    $Referer = $ServerUrl
	[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    
	Write-Verbose "Waiting for 'https://localhost:6443/arcgis/admin/' to intialize"
    Wait-ForUrl -Url 'https://localhost:6443/arcgis/admin/' -Verbose

    $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Referer $Referer -Credential $ServerSiteAdministrator
    
    if(($Ensure -ieq 'Present') -and (!$token.token)) {
        throw "Unable to retrieve token for user '$($ServerSiteAdministrator.UserName)'. Please enter valid credentials for the server site administrator"
    }

    # $DatabaseServerToCheck = if($IsManaged) { $null } else { $DatabaseServer }
    # $DatabaseNameToCheck = if($IsManaged) { $null } else { $DatabaseName }
    $dataItems = Get-ArcGISEGDBDataItems -SiteName 'arcgis' -Token $token.token -Referer $Referer 
    $dataItemForDatabase = $dataItems | Where-Object { $DatabaseServer -ieq $_.SERVER -and $DatabaseName -ieq $_.DATABASE }    
    if($IsManaged) {  
        Write-Verbose "Server can have only 1 managed database. Verify this" 
        $managedDatabaseItem = $dataItems | Where-Object { $_.isManaged }     
        if($dataItemForDatabase -and ($managedDatabaseItem.id -ieq $dataItemForDatabase.id)) {
            Write-Verbose "Data Item exists and is the managed database"
            $result = $true # Item exists and is the managed database
        }elseif($managedDatabaseItem -and ($managedDatabaseItem.id -ine $dataItemForDatabase.id)) {
            throw "A Managed Database with Server '$($managedDatabaseItem.SERVER)' and Database '$($managedDatabaseItem.DATABASE)' is already registered with id '$($managedDatabaseItem.id)'"
        }
    }else {
        Write-Verbose "Server can have multiple unmanaged database. Check if this database is already registered as an item"
        if($dataItemForDatabase) {
            Write-Verbose "Data Item already exists for this database"
            $result = $true
        }else {
            Write-Verbose "Data Item does not exist for this database"
        }
    }
     
    if($Ensure -ieq 'Present') {           
	       $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }	
    
}

function Get-ArcGISEGDBDataItems
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerHostName = 'localhost', 

        [System.String]
        $SiteName = 'arcgis', 

        [string]
        $Token, 

        [System.String]
        $Referer
    )
    
   $response = Invoke-ArcGISWebRequest -Url ("https://$($ServerHostName):6443/$SiteName" + '/admin/data/findItems') -HttpFormParameters @{ f = 'json'; token = $Token; types = 'egdb' } -Referer $Referer 
   $DataItems = @()
   foreach($item in $response.items) {
        $DataItem = @{ id = $item.id; isManaged = $item.info.isManaged }
        if($item.info.connectionString) {
           $ConnStringSplits = $item.info.connectionString.Split(';')
            foreach($ConnStringSplit in  $ConnStringSplits) {
                $KeyValuePairSplits = $ConnStringSplit.Split('=')
                $Key = $KeyValuePairSplits[0]
                if($Key -and $KeyValuePairSplits.Length -gt 1) {
                    $Value = $KeyValuePairSplits[1]
                    $DataItem.Add($Key, $Value)
                }
            }               
        }
        $DataItems += $DataItem   
   }     
   $DataItems
}


function UploadFile([Uri]$url, [string]$requestUri, [string]$filePath, [string]$fileContentType, $formParams, $Referer) 
{    
    $endPoint = $url.AbsoluteUri 
    
    [System.Net.WebRequest]$webRequest = [System.Net.WebRequest]::Create($endPoint)
    $webRequest.ServicePoint.Expect100Continue = $false
    $webRequest.Method = "POST"    
    if($Referer) {
        $webRequest.Referer = $Referer
    }

    $boundary = [System.Guid]::NewGuid().ToString()
    $header = "--{0}" -f $boundary
    $footer = "--{0}--" -f $boundary
    $webRequest.ContentType = "multipart/form-data; boundary={0}" -f $boundary

    [System.IO.Stream]$reqStream = $webRequest.GetRequestStream()    

    $enc = [System.Text.Encoding]::GetEncoding("UTF-8")
    $headerPlusNewLine = $header + [System.Environment]::NewLine
    [byte[]]$headerBytes = $enc.GetBytes($headerPlusNewLine)
    [void]$reqStream.Write($headerBytes,0, $headerBytes.Length)

    [System.IO.FileInfo]$fileInfo = New-Object "System.IO.FileInfo" -ArgumentList $filePath   

    #### File Header ####
    $fileHeader = "Content-Disposition: form-data; name=""{0}""; filename=""{1}""" -f "itemFile", $fileInfo.Name
    $fileHeader = $fileHeader + [System.Environment]::NewLine
    [byte[]]$fileHeaderBytes = $enc.GetBytes($fileHeader)
    [void]$reqStream.Write($fileHeaderBytes,0, $fileHeaderBytes.Length)
    
    #### File Content Type ####
    [string]$fileContentTypeStr = "Content-Type: {0}" -f $fileContentType;
    $fileContentTypeStr = $fileContentTypeStr + [System.Environment]::NewLine + [System.Environment]::NewLine
    [byte[]]$fileContentTypeBytes = $enc.GetBytes($fileContentTypeStr)
    [void]$reqStream.Write($fileContentTypeBytes,0, $fileContentTypeBytes.Length)    
    
    #### File #####
    [System.IO.FileStream]$fileStream = New-Object 'System.IO.FileStream' -ArgumentList @($filePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
    $fileStream.CopyTo($reqStream)
    $fileStream.Flush()
    $fileStream.Close()

    #### Use StreamWrite to write remaining form parameters ####
    [System.IO.StreamWriter]$streamWriter = New-Object 'System.IO.StreamWriter' -ArgumentList $reqStream
        
    [void]$streamWriter.WriteLine("")
    
    foreach($formParam in $formParams.GetEnumerator()) {
        [void]$streamWriter.WriteLine($header)
        [void]$streamWriter.WriteLine(("Content-Disposition: form-data; name=""{0}""" -f $formParam.Name))
        [void]$streamWriter.WriteLine("")
        [void]$streamWriter.WriteLine($formParam.Value)
    }     
    [void]$streamWriter.WriteLine($footer)
    $streamWriter.Flush()  
     
    $resp = $webRequest.GetResponse()
    $rs = $resp.GetResponseStream()
    [System.IO.StreamReader]$sr = New-Object System.IO.StreamReader -argumentList $rs
    $sr.ReadToEnd()
}


function Register-EGDBWithServerSite
{
    [CmdletBinding()]
     param(
        [System.String]
        $ServerUrl, 

        [System.String]
        $SiteName, 

        [System.String]
        $SDEFilePath, 

        [System.String]
        $Server, 

        [System.String]
        $Database, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.Boolean]
        $IsManaged
    )

    [System.Reflection.Assembly]::LoadWithPartialName("System.Net") | Out-Null
    
    ###
    ### Check that the system publishing tool is available
    ###
    [string]$PubGPServerUrl = $ServerUrl.TrimEnd('/') + "/$SiteName" + '/admin/services/System/PublishingTools.GPServer/status'
    Write-Verbose "Checking that the system publishing tool is available at $PubGPServerUrl"
    
    $WebParams =  @{ token = $Token; f = 'json' }

    $response = Invoke-ArcGISWebRequest -Url $PubGPServerUrl -HttpFormParameters $WebParams -Referer $Referer -TimeOutSec 60
    if($null -ne $response.status.error) {
        throw "Error checking System Publishing Tool:- $($response.status.error.messages)"
    }
    if($response.configuredState -ne 'STARTED' -or $response.realTimeState -ne 'STARTED') {
        throw "Publishing Tools GP Server not in STARTED State. Configured State:- $($response.configuredState), Realtime State:- $($response.realTimeState)"
    }
    
    [string]$UploadItemUrl = $ServerUrl.TrimEnd('/') + "/$SiteName" + '/admin/uploads/upload'
    Write-Verbose "Uploading File $SDEFilePath to $UploadItemUrl"
    $res = UploadFile -url $UploadItemUrl -requestUri $UploadItemUrl -filePath $SDEFilePath -fileContentType 'application/octet-stream' -formParams $WebParams -Referer $Referer
    $response = $res | ConvertFrom-Json
    if($null -ne $response.status.error) {
        throw "Error uploading .sde file. Error:- $($response.status.error.messages)"
    }
    $ItemId = $response.item.itemID
        
    ###
    ### Submit a job to to the 'Get Database Connection' GP Tool 
    ###
    [string]$SubmitJobUrl = $ServerUrl.TrimEnd('/') + "/$SiteName" + '/rest/services/System/PublishingTools/GPServer/Get%20Database%20Connection%20String/submitJob'
    Write-Verbose "Submitting Job to $SubmitJobUrl"
    $response = Invoke-ArcGISWebRequest -Url $SubmitJobUrl -HttpFormParameters @{ token = $Token; f = 'json'; in_inputData = $ItemId; in_connDataType = 'UPLOADED_CONNECTION_FILE_ID' } -Referer $Referer -TimeOutSec 60
    if($null -ne $response.status.error) {
        throw "Error submitting job to 'Get Database Connection' GP Tool $($response.status.error.messages)"
    }

    [string]$JobId = $response.jobId
    [int]$NumAttempts = 0
    [bool]$Done = 0
    [string]$CheckJobStatusUrl = $ServerUrl.TrimEnd('/') + "/$SiteName" + '/rest/services/System/PublishingTools/GPServer/Get%20Database%20Connection%20String/jobs/' + $JobId
    [string]$ParamUrl = $null
    while((-not $Done) -and $NumAttempts -lt 10) {
        Write-Verbose "Checking Job status at $CheckJobStatusUrl"
        $response = Invoke-ArcGISWebRequest -Url $CheckJobStatusUrl -HttpFormParameters @{ token = $Token; f = 'json'; } -Referer $Referer -TimeOutSec 60
        if($null -ne $response.status.error) {
            throw "Error checking job status for job $JobId. Error:- $($response.status.error.messages)"
        }
        if($response.jobStatus -eq 'esriJobSucceeded') {
            $ParamUrl = $response.results.out_connectionString.paramUrl
            $Done = $true
        }
        else {
            Start-Sleep -Seconds 30
        }
        $NumAttempts++
    }

    [string]$OutParamUrl = $ServerUrl.TrimEnd('/') + "/$SiteName" + '/rest/services/System/PublishingTools/GPServer/Get%20Database%20Connection%20String/jobs/' + "$JobId/$ParamUrl"
    Write-Verbose "Get Job Result at $OutParamUrl"
    $response = Invoke-ArcGISWebRequest -Url $OutParamUrl -HttpFormParameters @{ token = $Token; f = 'json'; } -Referer $Referer -TimeOutSec 60
    if($null -ne $response.status.error) {
        throw "Error retrieving job output for job $JobId. Error:- $($response.status.error.messages)"
    }

    ##
    ## Validating Data Item
    ##
    [string]$ConnString = $response.value
    [string]$ValidateDataItemUrl = $ServerUrl.TrimEnd('/') + "/$SiteName" + '/admin/data/validateDataItem'
    $item = @{
                type = 'egdb'
                info = @{
                    dataStoreConnectionType = if($IsManaged){'serverOnly'}else{'shared'}
                    isManaged = $IsManaged
                    connectionString = $ConnString
                }
                path = "/enterpriseDatabases/$($Server)_$($Database)"
            }
    
    $DataItemParams = @{ token = $Token; f = 'json'; item = (ConvertTo-Json $item -Depth 6) }
    Write-Verbose "Validating Item Result at $ValidateDataItemUrl"
    $response = Invoke-ArcGISWebRequest -Url $ValidateDataItemUrl -HttpFormParameters $DataItemParams -Referer $Referer -TimeOutSec 60
    if($null -ne $response.status.error) {
        throw "Error Validating Item Result at $ValidateDataItemUrl. Error:- $($response.status.error.messages)"
    }
    if($response.status -ne "success") {
        throw "Error Validating Item Result at $ValidateDataItemUrl. Result:- $($response | ConvertTo-Json -Depth 10)"
    }

    ##
    ## Registering Data Item
    ##
    [string]$RegisterDataItemUrl = $ServerUrl.TrimEnd('/') + "/$SiteName" + '/admin/data/registerItem'
    Write-Verbose "Registering Item Result at $RegisterDataItemUrl"    
    $response = Invoke-ArcGISWebRequest -Url $RegisterDataItemUrl -HttpFormParameters $DataItemParams -Referer $Referer -TimeOutSec 90
    if($null -ne $response.status.error) {
        throw "Error Registering Item at $RegisterDataItemUrl Error:- $($response.status.error.messages -join ',')"
    }
    if($response.success -eq $false) {
        throw "Error validating item $RegisterDataItemUrl . Response $($response | ConvertTo-Json -Depth 10)" 
    }
    Write-Verbose "Response received from registerItem $($response | ConvertTo-Json -Depth 10)"    
}

function Get-ServiceStatus
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerURL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer,

        [System.String]
        $ServicePath
    )

   $ServiceStatusUrl = $ServerURL.TrimEnd('/') + '/arcgis/admin/services/' + $ServicePath.Trim('/') + '/status'    
   Invoke-ArcGISWebRequest -Url $ServiceStatusUrl -HttpFormParameters  @{ f = 'json'; token = $Token } -Referer $Referer 
}

function Start-ServerService
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerURL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer,

        [System.String]
        $ServicePath
    )

   $ServiceStartOperationUrl = $ServerURL.TrimEnd('/') + '/arcgis/admin/services/' + $ServicePath.Trim('/') + '/start' 
   Invoke-ArcGISWebRequest -Url $ServiceStartOperationUrl -HttpFormParameters  @{ f = 'json'; token = $Token } -Referer $Referer -HttpMethod 'POST' -Verbose
}

Export-ModuleMember -Function *-TargetResource