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
        Type of Database Product used to install the GeoDatabase - "SQLServerDatabase" (PGSQL - Support to be added next)
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
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false
	
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
        [ValidateSet("AzureSQLDatabase","SQLServerDatabase")]
		[System.String]
		$DatabaseType,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    if($Ensure -ieq 'Present') {
        
        Write-Verbose "Sleeping for 2 minutes for the Publishing Service To Come up"
        Start-Sleep -Seconds 120

        Write-Verbose "Waiting for 'https://localhost:6443/arcgis/admin/' to intialize"
        Wait-ForUrl -Url 'https://localhost:6443/arcgis/admin/' -LogFailures

        $Referer = 'http://localhost:6080'
        Write-Verbose "Retrieve token for site admin $($ServerSiteAdministrator.UserName)"
        $token = Get-ServerToken -ServerEndPoint "http://localhost:6080/" -ServerSiteName 'arcgis' -Referer $Referer -Credential $ServerSiteAdministrator

        Test-ConnectivityToServer -Server $DatabaseServer -Credential $DatabaseServerAdministrator
            
        $ConnString = Create-DatabaseConnectionString -Server $DatabaseServer -Credential $DatabaseServerAdministrator 
        $DbConnString = Create-DatabaseConnectionString -Server $DatabaseServer -Credential $DatabaseServerAdministrator -Database $DatabaseName
            
        [bool]$IsSqlAzure = $DatabaseType -ieq 'AzureSQLDatabase'
        [string]$mgd = 'Non Managed'
        if($IsManaged) {
            $mgd = 'Managed'
        }
        $SkipLoginExpiration = -not($IsSqlAzure)
        $SdeUserName =  'sde'   
        if($SDEUser){
            $SdeUserPassword = $SDEUser.GetNetworkCredential().Password
        }else{  
            $SdeUserPassword = $DatabaseUser.GetNetworkCredential().Password
        }

        $SDEPassword = ConvertTo-SecureString $SdeUserPassword -AsPlainText -Force
        $SDECredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($SdeUserName, $SDEPassword )

        $DatabaseUserName = $DatabaseUser.UserName
        $DatabaseUserPassword = $DatabaseUser.GetNetworkCredential().Password

        ###
        ### Ensure Database exists
        ###                
        if(-not(Does-DatabaseExist $ConnString -DatabaseName $DatabaseName)) {
            Write-Verbose "Creating Database '$DatabaseName' in Server '$DatabaseServer'"
            Create-Database -ConnString $ConnString -DatabaseName $DatabaseName        
			Enable-DatabasePrivilegesForGeoDatabaseAdministrator -ConnString $ConnString -DatabaseName $DatabaseName             
        } 

        ###
        ### Create SDE User (if not exist)
        ###
        if(-not(Does-LoginExist -ConnString $ConnString -UserName $SdeUserName)) {
            Write-Verbose "Creating Login for User '$SdeUserName' in Server '$DatabaseServer'"
            Create-Login -ConnString $ConnString -Credential $SDECredential -SkipExpiration:$SkipLoginExpiration
        }
        ###
        ### Ensure Sde Exists in the database. If not create one and set its schema.
        ### 
        if(-not(Does-SqlUserExist -ConnString $DbConnString -UserName $SdeUserName))
        {                    
            Write-Verbose "Creating User '$SdeUserName' in Database '$DatabaseName'"
            Create-SqlUser -ConnString $DbConnString -UserName $SdeUserName -DefaultSchema '' # Create with no schema

            $schema = $SdeUserName
            if(-not(Does-SchemaExist -ConnString $DbConnString -SchemaName $schema)){
                Write-Verbose "Creating Schema '$schema' in Database '$DatabaseName'"
                Create-Schema -ConnString $DbConnString -SchemaName $schema 
            }

            Write-Verbose "Assigning schema '$schema' to User '$SdeUserName' in Database '$DatabaseName'"
            Assign-SchemaPrivilegesForSqlUser -ConnString $DbConnString -UserName $SdeUserName -Schema $schema
        }else {
            

            $TestConnString = Create-DatabaseConnectionString -Server $DatabaseServer -Database $DatabaseName -Credential $SDECredential
            try {
                Test-Login -ConnString $TestConnString
                Write-Verbose "User account $SdeUserName is a valid login"
            }catch {
                throw "Unable to login using Credentials provided for $SdeUserName."
            }
        }
            
        ##
        ## Grant neccessary privilages to Geodatabase Administrator 'sde'
        ##
        Grant-PrivilegesForGeodatabaseAdministrator -ConnString $DbConnString -UserName $SdeUserName -GrantViewDatabaseState:$IsSqlAzure

        ###
        ### Ensure schema 'sde' exists in the database
        ###
        $schema = 'sde' # Needed Schema for ArcSDE
        if(-not(Does-SchemaExist -ConnString $DbConnString -SchemaName $schema)){
            Write-Verbose "Creating Schema '$schema' in Database '$DatabaseName'"
            Create-Schema -ConnString $DbConnString -SchemaName $schema -SchemaOwnerName $schema
        }
            
        ###
        ### Ensure Login for the user exists
        ###                 
        if(-not(Does-LoginExist -ConnString $ConnString -UserName $DatabaseUserName)) {
            Write-Verbose "Creating Login for User '$DatabaseUserName' in Server '$DatabaseServer'"
            Create-Login -ConnString $ConnString -Credential $DatabaseUser -SkipExpiration:$SkipLoginExpiration
        }                                      

        ###
        ### Ensure User Exists. If not create one and set its schema. 
        ### 
        if(-not(Does-SqlUserExist -ConnString $DbConnString -UserName $DatabaseUserName))
        {
            Write-Verbose "Creating User '$DatabaseUserName' in Database '$DatabaseName'"
            Create-SqlUser -ConnString $DbConnString -UserName $DatabaseUserName -DefaultSchema '' # create user without schema. This will be assigned in the next step
                    
            $schema = $DatabaseUserName
            if(-not(Does-SchemaExist -ConnString $DbConnString -SchemaName $schema)) {
                Write-Verbose "Creating Schema '$schema' in Database '$DatabaseName'"
                Create-Schema -ConnString $DbConnString -SchemaName $schema
            }

            Write-Verbose "Assigning schema '$schema' to User '$DatabaseUserName' in Database '$DatabaseName'"
            Assign-SchemaPrivilegesForSqlUser -ConnString $DbConnString -UserName $DatabaseUserName -Schema $schema

        }else {
            $TestConnString = Create-DatabaseConnectionString -Server $DatabaseServer -Database $DatabaseName -Credential $DatabaseUser
            try {
                Test-Login -ConnString $TestConnString
                Write-Verbose "User account $DatabaseUserName is a valid login"
            }catch {
                throw "Unable to login using Credentials provided for $DatabaseUserName."
            }
        }

        Write-Verbose "Ensuring neccessary privileges for '$DatabaseUserName' in Database '$DatabaseName'"
        Grant-PrivilegesForSdeUser -ConnString $DbConnString -UserName $DatabaseUserName

        try {

            if($EnableGeodatabase) 
            {
                [string]$RealVersion = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\ESRI\ArcGIS').RealVersion
                Write-Verbose "RealVersion of ArcGIS Software Installed:- $RealVersion"
                $Version = $RealVersion.Split('.')[0] + '.' + $RealVersion.Split('.')[1] 
                Write-Verbose "Product Version of ArcGIS Software Installed:- $Version"

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

                $PythonScriptFileName = 'SqlServer_enable_enterprise_gdb.py'   
                $PythonScriptPath = Join-Path "$env:ProgramFiles\WindowsPowerShell\Modules\ArcGIS\DSCResources\ArcGIS_EGDB" $PythonScriptFileName
                if(-not(Test-Path $PythonScriptPath)){
                    throw "$PythonScriptPath not found"
                }
                $PythonInstallDir = (Get-ItemProperty -Path "HKLM:\SOFTWARE\ESRI\Python$($Version)").PythonDir
                $PythonPath = ((Get-ChildItem -Path $PythonInstallDir -Filter 'python.exe' -Recurse -File) | Select-Object -First 1 -ErrorAction Ignore)
                if($PythonPath -eq $null) {
                    throw "Python27 not found on machine. Please install Python."
                }
                $PythonInterpreterPath = $PythonPath.FullName

                Write-Verbose 'Enabling Geodatabase'            
                $Arguments = " ""$PythonScriptPath"" -s $DatabaseServer -d $DatabaseName -u $SdeUserName -p $SdeUserPassword -l $LicenseFilePath "
                Write-Verbose "[Running Command] $PythonInterpreterPath ""$PythonScriptPath"" -s $DatabaseServer -d $DatabaseName -u $SdeUserName -l $LicenseFilePath "
                $StdOutLogFile = [System.IO.Path]::GetTempFileName()
                $StdErrLogFile = [System.IO.Path]::GetTempFileName()
                Start-Process -FilePath $PythonInterpreterPath -ArgumentList $Arguments -RedirectStandardError $StdErrLogFile -RedirectStandardOutput $StdOutLogFile -Wait
                Write-Verbose "$StdOutLogFile"
                $StdOut = Get-Content $StdOutLogFile -Raw
                if($StdOut -ne $null -and $StdOut.Length -gt 0) {
                    Write-Verbose $StdOut
                }
                if($StdOut -icontains 'ERROR') { throw "Error Enabling Geodatabase. StdOut Error:- $StdOut"}
                [string]$StdErr = Get-Content $StdErrLogFile -Raw
                if($StdErr -ne $null -and $StdErr.Length -gt 0) {
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
            $PythonScriptFileName = 'SqlServer_create_connection_file.py'
            $PythonScriptPath = Join-Path "$env:ProgramFiles\WindowsPowerShell\Modules\ArcGIS\DSCResources\ArcGIS_EGDB" $PythonScriptFileName
            if(-not(Test-Path $PythonScriptPath)){
                throw "$PythonScriptPath not found"
            }

            $Arguments = " ""$PythonScriptPath"" -s $DatabaseServer -d $DatabaseName -u $DatabaseUserName -p $DatabaseUserPassword -o $OpFolder -f $OpFile"
            Write-Verbose "[Running Command] $PythonInterpreterPath ""$PythonScriptPath"" -s $DatabaseServer -d $DatabaseName -u $DatabaseUserName -o $OpFolder -f $OpFile"
            $StdOutLogFile = [System.IO.Path]::GetTempFileName()
            $StdErrLogFile = [System.IO.Path]::GetTempFileName()
            Start-Process -FilePath $PythonInterpreterPath -ArgumentList $Arguments -RedirectStandardError $StdErrLogFile -RedirectStandardOutput $StdOutLogFile -Wait
            $StdOut = Get-Content $StdOutLogFile -Raw

            if($StdOut -ne $null -and $StdOut.Length -gt 0) {
                Write-Verbose $StdOut
            }
            $SDELogContents = $null
            $SDELogFilePath = Join-Path $env:Temp 'sdedc_SQL Server'
            if(Test-Path $SDELogFilePath) {
                $SDELogContents = (Get-Content $SDELogFilePath -Raw)
                Write-Verbose $SDELogContents                
            }
            #if($SDELogContents -and $SDELogContents.IndexOf('Fail') -gt -1){
                #   throw "[ERROR] $SDELogContents"
            #}
            if($StdOut -and ($StdOut.IndexOf('ERROR') -gt -1)) { throw "Error Creating Connection File. StdOut Error:- $StdOut"}
            $StdErr = Get-Content $StdErrLogFile -Raw
            if($StdErr -ne $null -and $StdErr.Length -gt 0) {
                Write-Verbose "[ERROR] $StdErr"
            }
            if($StdErr -icontains 'ERROR') { throw "Error Creating Connection File. StdErr Error:- $StdErr"}
            Remove-Item $StdOutLogFile -Force -ErrorAction Ignore
            Remove-Item $StdErrLogFile -Force -ErrorAction Ignore
            #endregion    

            $ServerUrl = 'http://localhost:6080/'
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
            if($SDEFile -ne $null -and $SDEFile.Length -gt 0 -and (Test-Path $SDEFile)) {
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
        [ValidateSet("AzureSQLDatabase","SQLServerDatabase")]
		[System.String]
		$DatabaseType,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
    )
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false
	
    $result = $false    
    $ServerUrl = 'http://localhost:6080/'
    $Referer = $ServerUrl
	[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    
	Write-Verbose "Waiting for 'https://localhost:6443/arcgis/admin/' to intialize"
    Wait-ForUrl -Url 'https://localhost:6443/arcgis/admin/' -LogFailures

    $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Referer $Referer -Credential $ServerSiteAdministrator
    
    if(($Ensure -ieq 'Present') -and (!$token.token)) {
        throw "Unable to retrieve token for user '$($ServerSiteAdministrator.UserName)'. Please enter valid credentials for the server site administrator"
    }

    $DatabaseServerToCheck = if($IsManaged) { $null } else { $DatabaseServer }
    $DatabaseNameToCheck = if($IsManaged) { $null } else { $DatabaseName }
    $dataItems = Get-ArcGISEGDBDataItems -SiteName 'arcgis' -Token $token.token -Referer $Referer 
    $dataItemForDatabase = $dataItems | Where-Object { $DatabaseServer -ieq $_.SERVER -and $DatabaseName -ieq $_.DATABASE }    
    if($IsManaged) {  
        Write-Verbose "Server can have only 1 managed database. Verify this" 
        $managedDatabaseItem = $dataItems | Where-Object { $_.isManaged }     
        if($dataItemForDatabase -and ($managedDatabaseItem.id -ieq $dataItemForDatabase.id)) {
            Write-Verbose "Data Item exists and is the managed database"
            $result = $true # Item exists and is the managed database
        }elseif($managedDatabaseItem -and ($managedDatabaseItem.id -ine $dataItemForDatabase.id)) {
            throw "A Managed Database with Server '$($managedDatabaseItem.SERVER)' and Database '$($managedDatabaseItem.DATABASE)' is already registered with id ''"
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
     
   $response = Invoke-ArcGISWebRequest -Url ("http://$($ServerHostName):6080/$SiteName" + '/admin/data/findItems') -HttpFormParameters @{ f = 'json'; token = $Token; types = 'egdb' } -Referer $Referer 
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

   [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
   [System.Reflection.Assembly]::LoadWithPartialName("System.Net") | Out-Null
   [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
   [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    ###
    ### Check that the system publishing tool is available
    ###
    [string]$PubGPServerUrl = $ServerUrl.TrimEnd('/') + "/$SiteName" + '/admin/services/System/PublishingTools.GPServer/status'
    Write-Verbose "Checking that the system publishing tool is available at $PubGPServerUrl"
    $WebParams = @{ token = $Token
                    f = 'json'
                  }
    $HttpRequestBody = To-HttpBody -props $WebParams
    $Headers = @{'Content-type'='application/x-www-form-urlencoded'
                  'Content-Length' = $HttpRequestBody.Length
                  'Accept' = 'text/plain'     
                  'Referer' = $Referer             
                }
    $res = Invoke-WebRequest -Method Post -Uri $PubGPServerUrl -Body $HttpRequestBody -Headers $Headers -UseDefaultCredentials -UseBasicParsing -TimeoutSec 60 
    $response = $res.Content | ConvertFrom-Json
    if($response.status.error -ne $null) {
        throw "Error checking System Publishing Tool:- $($response.status.error.messages)"
    }
    if($response.configuredState -ne 'STARTED' -or $response.realTimeState -ne 'STARTED') {
        throw "Publishing Tools GP Server not in STARTED State. Configured State:- $($response.configuredState), Realtime State:- $($response.realTimeState)"
    }
    
    [string]$UploadItemUrl = $ServerUrl.TrimEnd('/') + "/$SiteName" + '/admin/uploads/upload'
    Write-Verbose "Uploading File $SDEFilePath to $UploadItemUrl"
    $res = UploadFile -url $UploadItemUrl -requestUri $UploadItemUrl -filePath $SDEFilePath -fileContentType 'application/octet-stream' -formParams $WebParams -Referer $Referer
    $response = $res | ConvertFrom-Json
    if($response.status.error -ne $null) {
        throw "Error uploading .sde file. Error:- $($response.status.error.messages)"
    }
    $ItemId = $response.item.itemID
        
    ###
    ### Submit a job to to the 'Get Database Connection' GP Tool 
    ###
    [string]$SubmitJobUrl = $ServerUrl.TrimEnd('/') + "/$SiteName" + '/rest/services/System/PublishingTools/GPServer/Get%20Database%20Connection%20String/submitJob'
    Write-Verbose "Submitting Job to $SubmitJobUrl"
    $WebParams = @{ token = $Token
                    f = 'json'
                    in_inputData = $ItemId
                    in_connDataType = 'UPLOADED_CONNECTION_FILE_ID'
                  }
     $HttpRequestBody = To-HttpBody -props $WebParams
     $Headers = @{'Content-type'='application/x-www-form-urlencoded'
                  'Content-Length' = $HttpRequestBody.Length
                  'Accept' = 'text/plain'     
                  'Referer' = $Referer             
                }
     $res = Invoke-WebRequest -Method Post -Uri $SubmitJobUrl -Body $HttpRequestBody -Headers $Headers -UseDefaultCredentials -UseBasicParsing -TimeoutSec 60 
     $response = $res.Content | ConvertFrom-Json
     if($response.status.error -ne $null) {
        throw "Error submitting job to 'Get Database Connection' GP Tool $($response.status.error.messages)"
     }

     [string]$JobId = $response.jobId
     [int]$NumAttempts = 0
     [bool]$Done = 0
     [string]$CheckJobStatusUrl = $ServerUrl.TrimEnd('/') + "/$SiteName" + '/rest/services/System/PublishingTools/GPServer/Get%20Database%20Connection%20String/jobs/' + $JobId
     $WebParams = @{ token = $Token
                     f = 'json'                   
                  }
     $HttpRequestBody = To-HttpBody -props $WebParams
     $Headers = @{'Content-type'='application/x-www-form-urlencoded'
                  'Content-Length' = $HttpRequestBody.Length
                  'Accept' = 'text/plain'     
                  'Referer' = $Referer             
                }
     [string]$ParamUrl = $null
     while((-not $Done) -and $NumAttempts -lt 10) {
        $res = Invoke-WebRequest -Method Post -Uri $CheckJobStatusUrl -Body $HttpRequestBody -Headers $Headers -UseDefaultCredentials -UseBasicParsing -TimeoutSec 60
        $response = $res.Content | ConvertFrom-Json 
        Write-Verbose "Checking Job status at $CheckJobStatusUrl"
        if($response.status.error -ne $null) {
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
     $WebParams = @{ token = $Token
                     f = 'json'                   
                  }
     $HttpRequestBody = To-HttpBody -props $WebParams
     $Headers = @{'Content-type'='application/x-www-form-urlencoded'
                  'Content-Length' = $HttpRequestBody.Length
                  'Accept' = 'text/plain'     
                  'Referer' = $Referer             
                }
     $res = Invoke-WebRequest -Method Post -Uri $OutParamUrl -Body $HttpRequestBody -Headers $Headers -UseDefaultCredentials -UseBasicParsing -TimeoutSec 60 
     $response = $res.Content | ConvertFrom-Json 
     if($response.status.error -ne $null) {
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
                    dataStoreConnectionType = 'serverOnly'
                    isManaged = $IsManaged
                    connectionString = $ConnString
                }
                path = "/enterpriseDatabases/$Server_$Database"
            }
    $WebParams = @{ token = $Token
                    f = 'json' 
                    item = ConvertTo-Json $item -Depth 6                  
                  }     
     $HttpRequestBody = To-HttpBody -props $WebParams
     $Headers = @{'Content-type'='application/x-www-form-urlencoded'
                  'Content-Length' = $HttpRequestBody.Length
                  'Accept' = 'text/plain'     
                  'Referer' = $Referer             
                }
     Write-Verbose "Validating  Item Result at $ValidateDataItemUrl"
     $res = Invoke-WebRequest -Method Post -Uri $ValidateDataItemUrl -Body $HttpRequestBody -Headers $Headers -UseDefaultCredentials -UseBasicParsing -TimeoutSec 90 
     $response = $res.Content | ConvertFrom-Json 
     if($response.status.error -ne $null) {
        throw "Error retrieving job output for job $JobId. Error:- $($response.status.error.messages)"
    }

    ##
    ## Registering Data Item
    ##
    [string]$RegisterDataItemUrl = $ServerUrl.TrimEnd('/') + "/$SiteName" + '/admin/data/registerItem'
    Write-Verbose "Validating  Item Result at $RegisterDataItemUrl"    
     $res = Invoke-WebRequest -Method Post -Uri $RegisterDataItemUrl -Body $HttpRequestBody -Headers $Headers -UseDefaultCredentials -UseBasicParsing -TimeoutSec 90 
     $response = $res.Content | ConvertFrom-Json 
     if($response.status.error -ne $null) {
        throw "Error retrieving job output for job $JobId. Error:- $($response.status.error.messages -join ',')"
    }
    if($response.success -eq $false) {
        throw "Error validating item $RegisterDataItemUrl . Response $($res.Content)" 
    }
    Write-Verbose "Response received from registerItem $($res.Content)"    
}

function Execute-SqlScalar
{
	[CmdletBinding()]
	param(
		[string]$ConnString,
		[string]$sql
	) 

	### TODO:- SQL Injection Validation
    $result = -1
    if($sql -ne $null -and $sql.Length -gt 0)
    {
        [System.Data.SqlClient.SqlConnection]$conn = New-Object System.Data.SqlClient.SqlConnection -ArgumentList $ConnString
        Try
        {
            $conn.Open()
            [System.Data.SqlClient.SqlCommand]$command = $conn.CreateCommand()
            $command.Connection = $conn    
            $command.CommandText = $sql     
            $command.CommandType = [System.Data.CommandType]::Text 
            $result = $command.ExecuteScalar()
        }
        finally
        {
            if($conn){
                try {
                    $conn.Close() 
                }
                catch{
                }
            }  
        }     
    }
    $result
}

function Execute-SqlNonQuery 
{
	[CmdletBinding()]
    param(
        [string]$ConnString,
        [string]$sql
    )

    if($sql -ne $null -and $sql.Length -gt 0)
    {
        [System.Data.SqlClient.SqlConnection]$conn = New-Object System.Data.SqlClient.SqlConnection -ArgumentList $ConnString    
        Try
        {            
            $conn.Open()
            [System.Data.SqlClient.SqlCommand]$command = $conn.CreateCommand()
            $command.Connection = $conn    
            $command.CommandText = $sql
            $command.CommandType = [System.Data.CommandType]::Text
            [void]$command.ExecuteNonQuery()
        }   
        finally
        {
            if($conn){
                try {
                    $conn.Close() 
                }
                catch{
                }
            }  
        }  
    }
}

function Create-DatabaseConnectionString
{
    param(
        [string]
        $Server,
        [string]
        $Database, 
        [System.Management.Automation.PSCredential]
        $Credential, 
        [switch]
        $UseIntergratedSecurity
    )
    $str = "Data Source=$Server;User ID=$($Credential.UserName);Password=$($Credential.GetNetworkCredential().Password)"
    if($Database -and $Database.Length -gt 0) {
        $str += ";Initial Catalog=$Database"
    }    
    if($UseIntergratedSecurity) {
        $str += ";Intergrated Security=true"
    }
    $str
}

function Test-ConnectivityToServer
{
    param(
        [string]
        $Server, 
        [System.Management.Automation.PSCredential]
        $Credential
    )

    $connStr = Create-DatabaseConnectionString -Server $Server -Credential $Credential
    try {
        Does-DatabaseExist -ConnString $connStr -DatabaseName 'master'
    }
    catch{
        throw "Unable to connect to Server '$Server' using UserID:- '$($Credential.UserName)'. Please verify that the server is reachable"
    }
}

function Test-Login
{
    param (
        [string]$ConnString
    )
    $sql = 'SELECT COUNT(*) from sys.tables'
    Execute-SqlNonQuery -ConnString $ConnString -sql $sql
}

function Does-LoginExist([string]$ConnString, [string]$UserName) {
    $sql = "SELECT COUNT(name) from sys.sql_logins WHERE name = '$UserName'"    
    $count = Execute-SqlScalar -ConnString $ConnString -sql $sql
    $count -gt 0
}

function Create-Login([string]$ConnString,  [System.Management.Automation.PSCredential]$Credential, [switch]$SkipExpiration){
    $sql = "CREATE LOGIN [$($Credential.UserName)] WITH PASSWORD = '$($Credential.GetNetworkCredential().Password)'"
    if($SkipExpiration){
        $sql += ' , CHECK_EXPIRATION=OFF, CHECK_POLICY=ON'
    }
    Execute-SqlNonQuery -ConnString $ConnString -sql $sql
}

function Delete-Login([string]$ConnString, [string]$UserName){
    $sql = "DROP LOGIN [$UserName]"
    Execute-SqlNonQuery -ConnString $ConnString -sql $sql
}

function Create-Database([string]$ConnString, [string]$DatabaseName)
{
    $sql = "CREATE DATABASE [$DatabaseName]"
    Execute-SqlNonQuery -ConnString $ConnString -sql $sql
}

function Enable-DatabasePrivilegesForGeoDatabaseAdministrator([string]$ConnString, [string]$DatabaseName)
{
    $sql = "ALTER DATABASE [$DatabaseName] SET READ_COMMITTED_SNAPSHOT ON"
    Execute-SqlNonQuery -ConnString $ConnString -sql $sql

	$sql = "ALTER DATABASE [$DatabaseName] SET ALLOW_SNAPSHOT_ISOLATION ON"
    Execute-SqlNonQuery -ConnString $ConnString -sql $sql
}

function Change-DatabaseOwnership([string]$ConnString, [string]$UserName)
{
    $sql = "EXEC sp_changedbowner N'$UserName'"
    Execute-SqlNonQuery -ConnString $ConnString -sql $sql
}

function Does-DatabaseExist([string]$ConnString, [string]$DatabaseName)
{
    $sql = "SELECT COUNT(name) from sys.sysdatabases WHERE name = '$DatabaseName'"   
    $count = Execute-SqlScalar -ConnString $ConnString -sql $sql
    $count -gt 0
}

function Does-SqlUserExist([string]$ConnString, [string]$UserName)
{
    $sql = "SELECT COUNT(NAME) FROM SYS.DATABASE_PRINCIPALS WHERE Name = '$UserName'"
    $count = Execute-SqlScalar -ConnString $ConnString -sql $sql
    $count -gt 0
}

function Create-SqlUser([string]$ConnString, [string]$UserName, [string]$DefaultSchema = $UserName)
{
    $sql = "CREATE USER [$UserName] FOR LOGIN [$UserName]"
    if($DefaultSchema -and $DefaultSchema.Length -gt 0){
        $sql += " WITH DEFAULT_SCHEMA = [$DefaultSchema]"
    }
    Execute-SqlNonQuery -ConnString $ConnString -sql $sql
    if($DefaultSchema -and $DefaultSchema.Length -gt 0) {
        $sql = "GRANT CONTROL ON SCHEMA::[$DefaultSchema] TO [$UserName]"
        Execute-SqlNonQuery -ConnString $ConnString -sql $sql
    }
}

function Assign-SchemaPrivilegesForSqlUser([string]$ConnString, [string]$UserName, [string]$Schema)
{
    $sql = "ALTER USER [$UserName] WITH DEFAULT_SCHEMA = [$Schema]"   
    Execute-SqlNonQuery -ConnString $ConnString -sql $sql

    $sql = "GRANT CONTROL ON SCHEMA::[$Schema] TO [$UserName]"
    Execute-SqlNonQuery -ConnString $ConnString -sql $sql

    $sql = "ALTER AUTHORIZATION ON SCHEMA::[$Schema] TO [$UserName]"
    Execute-SqlNonQuery -ConnString $ConnString -sql $sql
}

function Drop-SqlUser([string]$ConnString, [string]$UserName)
{
    $sql = "DROP USER [$UserName]"    
    Execute-SqlNonQuery -ConnString $ConnString -sql $sql
}

function Does-SchemaExist([string]$ConnString, [string]$SchemaName)
{
    $sql = "SELECT Count(Name) FROM sys.schemas WHERE name = '$SchemaName'"
    $count = Execute-SqlScalar -ConnString $ConnString -sql $sql
    $count -gt 0
}

function Create-Schema([string]$ConnString, [string]$SchemaName, [string]$SchemaOwnerName)
{
    if($SchemaOwnerName -and $SchemaOwnerName.Length -gt 0) {
        $sql = "CREATE SCHEMA [$SchemaName] AUTHORIZATION $SchemaOwnerName" 
    }
    else {
        $sql = "CREATE SCHEMA [$SchemaName]" 
    }
    Execute-SqlNonQuery -ConnString $ConnString -sql $sql
}

function Grant-PrivilegesForGeodatabaseAdministrator([string]$ConnString, [string]$UserName, [switch]$GrantViewDatabaseState)
{
    <#
    $sql = "SP_DROPUSER '$UserName'"
    Execute-SqlNonQuery -ConnString $ConnString -sql $sql

    $sql = "EXEC sp_changedbowner '$UserName'"
    Execute-SqlNonQuery -ConnString $ConnString -sql $sql
    #>
    
    $sql = "GRANT CREATE PROCEDURE TO [$UserName]"
    Execute-SqlNonQuery -ConnString $ConnString -sql $sql

    $sql = "GRANT CREATE FUNCTION TO [$UserName]"
    Execute-SqlNonQuery -ConnString $ConnString -sql $sql

    $sql = "GRANT CREATE TABLE TO [$UserName]"
    Execute-SqlNonQuery -ConnString $ConnString -sql $sql

    $sql = "GRANT CREATE VIEW TO [$UserName]"
    Execute-SqlNonQuery -ConnString $ConnString -sql $sql

    if($GrantViewDatabaseState) {
        $sql = "GRANT VIEW DATABASE STATE TO [$UserName]"
        Execute-SqlNonQuery -ConnString $ConnString -sql $sql
    }
}

function Grant-PrivilegesForSdeUser([string]$ConnString, [string]$UserName)
{
    #$sql = "EXEC sp_addrolemember N'db_datareader', N'$UserName'"
    #Execute-SqlNonQuery -ConnString $ConnString -sql $sql

    #$sql = "EXEC sp_addrolemember N'db_datawriter', N'$UserName'"
    #Execute-SqlNonQuery -ConnString $ConnString -sql $sql

    #$sql = "EXEC sp_addrolemember N'db_ddladmin', N'$UserName'"
    #Execute-SqlNonQuery -ConnString $ConnString -sql $sql

    #$sql = "EXEC sp_addrolemember N'db_owner', N'$UserName'"    
    #Execute-SqlNonQuery -ConnString $ConnString -sql $sql

    $sql = "GRANT CREATE FUNCTION TO [$UserName]"
    Execute-SqlNonQuery -ConnString $ConnString -sql $sql

    $sql = "GRANT CREATE PROCEDURE TO [$UserName]"
    Execute-SqlNonQuery -ConnString $ConnString -sql $sql
    
    $sql = "GRANT CREATE TABLE TO [$UserName]"
    Execute-SqlNonQuery -ConnString $ConnString -sql $sql

    $sql = "GRANT CREATE VIEW TO [$UserName]"
    Execute-SqlNonQuery -ConnString $ConnString -sql $sql

    #$sql = "GRANT CONTROL ON SCHEMA::[sde] TO [$UserName]"
    #Execute-SqlNonQuery -ConnString $ConnString -sql $sql

    #$sql = "GRANT CONTROL ON SCHEMA::[dbo] TO [$UserName]"
    #Execute-SqlNonQuery -ConnString $ConnString -sql $sql

    #$sql = "GRANT INSERT,UPDATE,DELETE,SELECT to [$UserName]"
    #Execute-SqlNonQuery -ConnString $ConnString -sql $sql

    #$sql = "GRANT CREATE XML SCHEMA COLLECTION to [$UserName]"
    #Execute-SqlNonQuery -ConnString $ConnString -sql $sql
}


Export-ModuleMember -Function *-TargetResource



