$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.Server.psm1'))

function ConvertTo-EGDBProcessArgument
{
    param(
        [AllowEmptyString()]
        [System.String]
        $Argument
    )

    $EscapedArgument = [regex]::Replace($Argument, '(\\*)"', '$1$1\"')
    $EscapedArgument = [regex]::Replace($EscapedArgument, '(\\+)$', '$1$1')
    '"' + $EscapedArgument + '"'
}

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
        Type of Database Product used to install the GeoDatabase 
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
        [ValidateSet("SQLServerDatabase","AzureSQLDatabase","AzureMISQLDatabase","AzureFlexiblePostgreSQLDatabase","AWSRDSPostgreSQLDatabase","AWSAuroraPostgreSQLDatabase")]
		[System.String]
		$DatabaseType,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)
	
	if($Ensure -ieq 'Present') {
        $ServerBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName "Server"
	    Write-Verbose "Waiting for '$($ServerBaseUrl)' to intialize"
        Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName "Server" -Verbose

        $Referer = $ServerBaseUrl
        Write-Verbose "Retrieve token for site admin $($ServerSiteAdministrator.UserName)"    
        $token = Get-ServerToken -URL $ServerBaseUrl -Referer $Referer -Credential $ServerSiteAdministrator

        Write-Verbose "Ensure the Publishing GP Service (Tool) is started on Server"
        $PublishingToolsPath = 'System/PublishingTools.GPServer'
        [int]$NumAttempts = 0
        [bool]$Done = $False
        while(-not($Done) -and ($NumAttempts -lt 10)) {
            Write-Verbose "Sleeping for 1 minutes for the Publishing Service to start"
            Start-Sleep -Seconds 60

            $serviceStatus = Invoke-GPServiceOperation -URL $ServerBaseUrl -Token $token.token -Referer $Referer -ServicePath $PublishingToolsPath -OperationName "status"           
            Write-Verbose "Service Status :- $serviceStatus"
            if($serviceStatus.configuredState -ine 'STARTED' -or $serviceStatus.realTimeState -ine 'STARTED') {
                Write-Verbose "Starting Service $PublishingToolsPath"
                Invoke-GPServiceOperation -URL $ServerBaseUrl -Token $token.token -Referer $Referer -ServicePath $PublishingToolsPath -OperationName "start"
            }else{
                Write-Verbose "Service $PublishingToolsPath are started."
                break;
            }
            $NumAttempts++
        }

        $IsPostgres = @("AzureFlexiblePostgreSQLDatabase","AWSRDSPostgreSQLDatabase","AWSAuroraPostgreSQLDatabase") -icontains $DatabaseType
        
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

            $ServerRegValue = Get-ArcGISComponentVersionAndInstallDirectory -ComponentName 'Server'
            $RealVersion = $ServerRegValue.RealVersion
            $RealVersionArr = $RealVersion.Split(".")
            $Version = $RealVersionArr[0] + '.' + $RealVersionArr[1] 
            $InstallDir =  $ServerRegValue.InstallDir
            Write-Verbose "RealVersion of ArcGIS Software Installed:- $RealVersion"
            $PythonInstallDir = Join-Path $InstallDir "\\framework\\runtime\\ArcGIS\\bin\\Python\\envs\\arcgispro-py3"
            
            $PythonPath = ((Get-ChildItem -Path $PythonInstallDir -Filter 'python.exe' -Recurse -File) | Select-Object -First 1 -ErrorAction Ignore)
            if($null -eq $PythonPath) {
                throw "Python not found on machine. Please install Python."
            }
            $PythonInterpreterPath = $PythonPath.FullName

            if($EnableGeodatabase) 
            {
                $PythonScriptFileName = 'enable_enterprise_gdb_3x.py'
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
                $SdeConnectUserName = $SdeUserName
                $SDEPassword = $SDECredential.GetNetworkCredential().Password
                $ArgumentValues = @($PythonScriptPath, '--DBMS', $DBType, '-s', $DatabaseServer, '-d', $DatabaseName, '-u', $SdeConnectUserName, '-p', $SDEPassword, '-l', $LicenseFilePath)
                $Arguments = ($ArgumentValues | ForEach-Object { ConvertTo-EGDBProcessArgument -Argument $_ }) -join ' '
                $RedactedArguments = $Arguments.Replace((ConvertTo-EGDBProcessArgument -Argument $SDEPassword), '"xxxxx"')
                Write-Verbose "[Running Command] $PythonInterpreterPath $RedactedArguments "
                $StdOutLogFile = [System.IO.Path]::GetTempFileName()
                $StdErrLogFile = [System.IO.Path]::GetTempFileName()
                $PythonProcess = Start-Process -FilePath $PythonInterpreterPath -ArgumentList $Arguments -RedirectStandardError $StdErrLogFile -RedirectStandardOutput $StdOutLogFile -Wait -PassThru -ErrorAction Stop
                Write-Verbose "$StdOutLogFile"
                $StdOut = Get-Content $StdOutLogFile -Raw
                if($null -ne $StdOut -and $StdOut.Length -gt 0) {
                    Write-Verbose $StdOut
                }
                [string]$StdErr = Get-Content $StdErrLogFile -Raw
                if($null -ne $StdErr -and $StdErr.Length -gt 0) {
                    Write-Verbose "[ERROR] $StdErr"
                }
                if(($PythonProcess.ExitCode -ne 0) -or ($StdOut -imatch '\bERROR\b') -or ($StdErr -imatch '\bERROR\b')) {
                    throw "Error Enabling Geodatabase. Process exit code:- $($PythonProcess.ExitCode). StdOut:- $StdOut StdErr:- $StdErr Logs retained at '$StdOutLogFile' and '$StdErrLogFile'."
                }
                Remove-Item $StdOutLogFile -Force -ErrorAction Ignore
                Remove-Item $StdErrLogFile -Force -ErrorAction Ignore  
            }

            #region Create Connection file
            $OpFolder = $env:TEMP
            $DatabaseUserName = $DatabaseUser.UserName
            $OpFile = "$($DatabaseServer)_$($DatabaseName)_$($DatabaseUserName).sde"
            $SDEFile = Join-Path $OpFolder $OpFile 
            $PythonScriptFileName = 'create_connection_file_3x.py'
            $PythonScriptPath = Join-Path $PSScriptRoot $PythonScriptFileName
            if(-not(Test-Path $PythonScriptPath)){
                throw "$PythonScriptPath not found"
            }
            $DatabasePassword = $DatabaseUser.GetNetworkCredential().Password
            $ArgumentValues = @($PythonScriptPath, '--DBMS', $DBType, '-s', $DatabaseServer, '-d', $DatabaseName, '-u', $DatabaseUserName, '-p', $DatabasePassword, '-o', $OpFolder, '-f', $OpFile)
            $Arguments = ($ArgumentValues | ForEach-Object { ConvertTo-EGDBProcessArgument -Argument $_ }) -join ' '
            $RedactedArguments = $Arguments.Replace((ConvertTo-EGDBProcessArgument -Argument $DatabasePassword), '"xxxxx"')
            Write-Verbose "[Running Command] $PythonInterpreterPath $RedactedArguments"
            $StdOutLogFile = [System.IO.Path]::GetTempFileName()
            $StdErrLogFile = [System.IO.Path]::GetTempFileName()
            $PythonProcess = Start-Process -FilePath $PythonInterpreterPath -ArgumentList $Arguments -RedirectStandardError $StdErrLogFile -RedirectStandardOutput $StdOutLogFile -Wait -PassThru -ErrorAction Stop
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
            $StdErr = Get-Content $StdErrLogFile -Raw
            if($null -ne $StdErr -and $StdErr.Length -gt 0) {
                Write-Verbose "[ERROR] $StdErr"
            }
            if(($PythonProcess.ExitCode -ne 0) -or ($StdOut -imatch '\bERROR\b') -or ($StdErr -imatch '\bERROR\b')) {
                throw "Error Creating Connection File. Process exit code:- $($PythonProcess.ExitCode). StdOut:- $StdOut StdErr:- $StdErr Logs retained at '$StdOutLogFile' and '$StdErrLogFile'."
            }
            if(-not(Test-Path -LiteralPath $SDEFile -PathType Leaf)) {
                throw "Error Creating Connection File. Python exited successfully but did not create '$SDEFile'. StdOut:- $StdOut StdErr:- $StdErr Logs retained at '$StdOutLogFile' and '$StdErrLogFile'."
            }
            Remove-Item $StdOutLogFile -Force -ErrorAction Ignore
            Remove-Item $StdErrLogFile -Force -ErrorAction Ignore
            #endregion    

            $dataItems = Get-ArcGISEGDBDataItems -URL $ServerBaseUrl -Token $token.token -Referer $Referer 
            $dataItemForDatabase = $dataItems | Where-Object { $DatabaseServer -ieq $_.SERVER -and $DatabaseName -ieq $_.DATABASE }    
            if(-not($dataItemForDatabase))
            {
                Write-Verbose "Item for database '$DatabaseName' in Server '$DatabaseServer' is NOT registered. Registering now."
                Register-EGDBWithServerSite -URL $ServerBaseUrl -SDEFilePath $SDEFile `
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
        [ValidateSet("SQLServerDatabase","AzureSQLDatabase","AzureMISQLDatabase","AzureFlexiblePostgreSQLDatabase","AWSRDSPostgreSQLDatabase","AWSAuroraPostgreSQLDatabase")]
		[System.String]
		$DatabaseType,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)
    

    $result = $false    
    $Referer = 'https://localhost:6443/'
    
    $ServerBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName "Server"
	Write-Verbose "Waiting for '$($ServerBaseUrl)' to intialize"
    Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName "Server" -Verbose
    
    $token = Get-ServerToken -URL $ServerBaseUrl -Referer $Referer -Credential $ServerSiteAdministrator
    
    if(($Ensure -ieq 'Present') -and (!$token.token)) {
        throw "Unable to retrieve token for user '$($ServerSiteAdministrator.UserName)'. Please enter valid credentials for the server site administrator"
    }

    # Check if database name is mixed. Not supported by ArcGIS
    if($DatabaseName -cne $DatabaseName.ToLower()){
        throw "Uppercase and mixed-case object names are not supported for geodatabases."
    }

    # $DatabaseServerToCheck = if($IsManaged) { $null } else { $DatabaseServer }
    # $DatabaseNameToCheck = if($IsManaged) { $null } else { $DatabaseName }
    $dataItems = Get-ArcGISEGDBDataItems -URL $ServerBaseUrl -Token $token.token -Referer $Referer 
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
        $URL, 

        [string]
        $Token, 

        [System.String]
        $Referer
    )

    $items = Find-DataItems -URL $URL -Token $Token -Referer $Referer -Verbose
    $DataItems = @()
    foreach($item in $items) {
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

function Register-EGDBWithServerSite
{
    [CmdletBinding()]
     param(
        [System.String]
        $URL, 

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

    if(-not(Test-Path -LiteralPath $SDEFilePath -PathType Leaf)) {
        throw "Database connection file '$SDEFilePath' does not exist. Cannot register enterprise database '$Database' on '$Server'."
    }

    ###
    ### Check that the system publishing tool is available
    ###
    $serviceStatus = Invoke-GPServiceOperation -URL $URL -Token $Token -Referer $Referer -ServicePath "System/PublishingTools.GPServer" -OperationName "status"
    Write-Verbose "Service Status :- $serviceStatus"
    if($null -ne $serviceStatus.status.error) {
        $errMsgs = if($serviceStatus.status.error.messages){ ($serviceStatus.status.error.messages -join ' ') }else{ $serviceStatus.status.error.message }
        throw "Error checking System Publishing Tool:- $errMsgs"
    }
    if($serviceStatus.configuredState -ne 'STARTED' -or $serviceStatus.realTimeState -ne 'STARTED') {
        throw "Publishing Tools GP Server not in STARTED State. Configured State:- $($serviceStatus.configuredState), Realtime State:- $($serviceStatus.realTimeState)"
    }

    [string]$UploadItemUrl = $URL.TrimEnd('/') + '/admin/uploads/upload'
    Write-Verbose "Uploading File $SDEFilePath to $UploadItemUrl"
    $res = Invoke-UploadFile -url $UploadItemUrl -filePath $SDEFilePath -fileContentType 'application/octet-stream' `
                -formParams  @{ token = $Token; f = 'json' } -Referer $Referer -fileParameterName "itemFile"
    $response = $res | ConvertFrom-Json
    Write-Verbose ($res)
    if($response.status -ieq "error") {
        throw "Error uploading .sde file. Error:- $($response.messages | ConvertTo-Json -Depth 5)"
    }
    $ItemId = $response.item.itemID
        
    ###
    ### Submit a job to to the 'Get Database Connection' GP Tool 
    ###
    [string]$ConnString = Invoke-GetDatabaseConnectionGPTool -URL $URL -Token $Token -Referer $Referer -ConnectionFileItemId $ItemId -Verbose
    
    ##
    ## Validating Data Item
    ##
    $ItemConnectionObject = @{
                type = 'egdb'
                info = @{
                    dataStoreConnectionType = if($IsManaged){'serverOnly'}else{'shared'}
                    isManaged = $IsManaged
                    connectionString = $ConnString
                }
                path = "/enterpriseDatabases/$($Server)_$($Database)"
            }

    Invoke-DataStoreItemOperation -URL $URL -Token $Token -Referer $Referer -ConnectionObject $ItemConnectionObject -OperationName "validateDataItem" -Verbose

    ##
    ## Registering Data Item
    ##
    Invoke-DataStoreItemOperation -URL $URL -Token $Token -Referer $Referer -ConnectionObject $ItemConnectionObject -OperationName "registerItem" -Verbose
}

Export-ModuleMember -Function *-TargetResource