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
        [ValidateSet("AzureSQLDatabase","SQLServerDatabase","AzurePostgreSQLDatabase","AzureMISQLDatabase")]
		[System.String]
		$DatabaseType,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false
	
	if($Ensure -ieq 'Present') {
        #Add check if possible
        
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

        [bool]$IsPostgres = $DatabaseType -ieq 'AzurePostgreSQLDatabase'
        [bool]$IsSqlAzure = ($DatabaseType -ieq 'AzureSQLDatabase' -or $DatabaseType -ieq 'AzureMISQLDatabase')
        [string]$mgd = 'Non Managed'
        if($IsManaged) {
            $mgd = 'Managed'
        }
        $SkipLoginExpiration = -not($IsSqlAzure)

        if($IsPostgres){
            Test-ConnectivityToPostgresServer -Server $DatabaseServer -Database "postgres" -Credential $DatabaseServerAdministrator
        }else{
            Test-ConnectivityToServer -Server $DatabaseServer -Credential $DatabaseServerAdministrator
        }
        
        $ConnString = Get-DatabaseConnectionString -Server $DatabaseServer -Credential $DatabaseServerAdministrator
        $TestDBConnString = $ConnString
        if($IsPostgres){
            $ConnString = Get-PostgresDatabaseConnectionString -Server $DatabaseServer -Database $DatabaseName -Credential $DatabaseServerAdministrator
            $TestDBConnString = Get-PostgresDatabaseConnectionString -Server $DatabaseServer -Database "postgres" -Credential $DatabaseServerAdministrator
        }
        
        $DbConnString = Get-DatabaseConnectionString -Server $DatabaseServer -Credential $DatabaseServerAdministrator -Database $DatabaseName
        if($IsPostgres){
            $DbConnString = $ConnString
        }

        $SdeUserName =  'sde'   
        $SdeUserPassword = $DatabaseUser.GetNetworkCredential().Password
        $SdeUserPasswordSecureObject = $DatabaseUser.Password
        if($SDEUser){
            $SdeUserPassword = $SDEUser.GetNetworkCredential().Password
            $SdeUserPasswordSecureObject = $SDEUser.Password
        }

        $SDECredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($SdeUserName, $SdeUserPasswordSecureObject )
        
        $DatabaseUserName = $DatabaseUser.UserName
        $DatabaseUserPassword = $DatabaseUser.GetNetworkCredential().Password

        ###
        ### Ensure Database exists
        ###                
        if(-not(Test-DatabaseExist $TestDBConnString -DatabaseName $DatabaseName -IsPostgres:$IsPostgres)) {
            Write-Verbose "Creating Database '$DatabaseName' in Server '$DatabaseServer'"
            Invoke-CreateDatabase -ConnString $TestDBConnString -DatabaseName $DatabaseName -IsPostgres:$IsPostgres   
        } 
        if(-not($IsPostgres)){
            Enable-DatabasePrivilegesForGeoDatabaseAdministrator -ConnString $ConnString -DatabaseName $DatabaseName
        }
        ###
        ### Create SDE User (if not exist)
        ###
        if(-not(Test-LoginExist -ConnString $ConnString -UserName $SdeUserName -IsPostgres:$IsPostgres)) {
            Write-Verbose "Creating Login for User '$SdeUserName' in Server '$DatabaseServer'"
            Invoke-CreateLogin -ConnString $ConnString -Credential $SDECredential -SkipExpiration:$SkipLoginExpiration -IsPostgres:$IsPostgres
        }
        ###
        ### Ensure Sde Exists in the database. If not create one and set its schema.
        ### 
        if(-not(Test-SqlUserExist -ConnString $DbConnString -UserName $SdeUserName -IsPostgres:$IsPostgres) -or -not(Test-SchemaExist -ConnString $DbConnString -SchemaName $schema -IsPostgres:$IsPostgres))
        {          
            if(-not(Test-SqlUserExist -ConnString $DbConnString -UserName $SdeUserName -IsPostgres:$IsPostgres)){          
                Write-Verbose "Creating User '$SdeUserName' in Database '$DatabaseName'"
                Invoke-CreateSqlUser -ConnString $DbConnString -Credential $SDECredential -DefaultSchema '' -IsPostgres:$IsPostgres # Create with no schema
            }

            $schema = $SdeUserName
            if(-not(Test-SchemaExist -ConnString $DbConnString -SchemaName $schema -IsPostgres:$IsPostgres)){
                Write-Verbose "Creating Schema '$schema' in Database '$DatabaseName'"
                if($IsPostgres){
                    Invoke-CreateSchemaPostgres -ConnString $DbConnString -SchemaName $schema
                }else{
                    Invoke-CreateSchema -ConnString $DbConnString -SchemaName $schema 
                }
            }

            Write-Verbose "Assigning schema '$schema' to User '$SdeUserName' in Database '$DatabaseName'"
            Invoke-AssignSchemaPrivilegesForSqlUser -ConnString $DbConnString -UserName $SdeUserName -DatabaseName $DatabaseName -Schema $schema -IsPostgres:$IsPostgres -DbAdminUsername $DatabaseServerAdministrator.UserName
        }else {


            $TestConnString = Get-DatabaseConnectionString -Server $DatabaseServer -Database $DatabaseName -Credential $SDECredential
            if($IsPostgres){
                $TestConnString = Get-PostgresDatabaseConnectionString -Server $DatabaseServer -Credential $SDECredential -Database $DatabaseName
            }
            try {
                Test-Login -ConnString $TestConnString -IsPostgres:$IsPostgres
                Write-Verbose "User account $SdeUserName is a valid login"
            }catch {
                throw "Unable to login using Credentials provided for $SdeUserName."
            }
        }
            
        ##
        ## Grant necessary privilages to Geodatabase Administrator 'sde'
        ##
        Grant-PrivilegesForGeodatabaseAdministrator -ConnString $DbConnString -UserName $SdeUserName -GrantViewDatabaseState:$IsSqlAzure -IsPostgres:$IsPostgres
        
        ###
        ### Ensure schema 'sde' exists in the database
        ###
        $schema = 'sde' # Needed Schema for ArcSDE
        if(-not(Test-SchemaExist -ConnString $DbConnString -SchemaName $schema -IsPostgres:$IsPostgres)){
            Write-Verbose "Creating Schema '$schema' in Database '$DatabaseName'"
			#$DbConnStringForSde = Get-PostgresDatabaseConnectionString -Server $DatabaseServer -UserName $schema -Password $DatabaseServerAdministrator.GetNetworkCredential().Password -Database $DatabaseName 
            if($IsPostgres){
				Invoke-CreateSchemaPostgres -ConnString $ConnString -SchemaName $schema -SchemaOwnerName $schema -DbAdminUsername $DatabaseServerAdministrator.UserName
			}else{
				Invoke-CreateSchema -ConnString $DbConnString -SchemaName $schema -SchemaOwnerName $schema 
			}
        }
            
        ###
        ### Ensure Login for the user exists
        ###    
        if(-not(Test-LoginExist -ConnString $ConnString -UserName $DatabaseUserName -IsPostgres:$IsPostgres)) {
            Write-Verbose "Creating Login for User '$DatabaseUserName' in Server '$DatabaseServer'"
            Invoke-CreateLogin -ConnString $ConnString -Credential $DatabaseUser -SkipExpiration:$SkipLoginExpiration -IsPostgres:$IsPostgres
        }    
                                          

        ###
        ### Ensure User Exists. If not create one and set its schema. 
        ### 
        $schema = $DatabaseUserName
        if(-not(Test-SqlUserExist -ConnString $DbConnString -UserName $DatabaseUserName -IsPostgres:$IsPostgres) -or -not(Test-SchemaExist -ConnString $DbConnString -SchemaName $schema -IsPostgres:$IsPostgres))
        {
            if(-not(Test-SqlUserExist -ConnString $DbConnString -UserName $DatabaseUserName -IsPostgres:$IsPostgres)){
                Write-Verbose "Creating User '$DatabaseUserName' in Database '$DatabaseName'"
                Invoke-CreateSqlUser -ConnString $DbConnString -Credential $DatabaseUser -DefaultSchema '' -IsPostgres:$IsPostgres # create user without schema. This will be assigned in the next step
            }

            $schema = $DatabaseUserName
            if(-not(Test-SchemaExist -ConnString $DbConnString -SchemaName $schema -IsPostgres:$IsPostgres)){
                Write-Verbose "Creating Schema '$schema' in Database '$DatabaseName'"
                if($IsPostgres){
                    Invoke-CreateSchemaPostgres -ConnString $DbConnString -SchemaName $schema -SchemaOwnerName $DatabaseUserName -DbAdminUsername $DatabaseServerAdministrator.UserName
                }else{
                    Invoke-CreateSchema -ConnString $DbConnString -SchemaName $schema 
                }
            }

            Write-Verbose "Assigning schema '$schema' to User '$DatabaseUserName' in Database '$DatabaseName'"
            Invoke-AssignSchemaPrivilegesForSqlUser -ConnString $DbConnString -DatabaseName $DatabaseName -UserName $DatabaseUserName -Schema $schema -IsPostgres:$IsPostgres -DbAdminUsername $DatabaseServerAdministrator.UserName

        }else {
            $TestConnString = Get-DatabaseConnectionString -Server $DatabaseServer -Database $DatabaseName -Credential $DatabaseUser
            if($IsPostgres){
                $TestConnString = Get-PostgresDatabaseConnectionString -Server $DatabaseServer -Credential $DatabaseUser -Database $DatabaseName
            }
            try {
                Test-Login -ConnString $TestConnString -IsPostgres:$IsPostgres
                Write-Verbose "User account $DatabaseUserName is a valid login"
            }catch {
                throw "Unable to login using Credentials provided for $DatabaseUserName."
            }
        }

        ###
        ### Ensure schema DatabaseUserName exists in the database
        ###
        $schema = $DatabaseUserName # Needed Schema for ArcSDE
        if(-not(Test-SchemaExist -ConnString $DbConnString -SchemaName $schema -IsPostgres:$IsPostgres)){
            Write-Verbose "Creating Schema '$schema' in Database '$DatabaseName'"
            if($IsPostgres){
                Invoke-CreateSchemaPostgres -ConnString $DbConnString -SchemaName $schema -SchemaOwnerName $DatabaseUserName -DbAdminUsername $DatabaseServerAdministrator.UserName
            }else{
                Invoke-CreateSchema -ConnString $DbConnString -SchemaName $schema -SchemaOwnerName $DatabaseUserName
            }
            Write-Verbose "Assigning schema '$schema' to User '$DatabaseUserName' in Database '$DatabaseName'"
            Invoke-AssignSchemaPrivilegesForSqlUser -ConnString $DbConnString -UserName $DatabaseUserName -DatabaseName $DatabaseName -Schema $schema -IsPostgres:$IsPostgres -DbAdminUsername $DatabaseServerAdministrator.UserName
        }

        Write-Verbose "Ensuring necessary privileges for '$DatabaseUserName' in Database '$DatabaseName'"
        if($IsPostgres){
            Grant-PrivilegesForSdeUser -ConnString $ConnString -UserName $DatabaseUserName -IsPostgres -SchemaName 'sde'
        }else{
            Grant-PrivilegesForSdeUser -ConnString $DbConnString -UserName $DatabaseUserName -SchemaName 'sde'
        }
        
        try {
            [string]$RealVersion = (Get-ArcGISProductDetails -ProductName "ArcGIS Server").Version
			Write-Verbose "RealVersion of ArcGIS Software Installed:- $RealVersion"
            $Version = $RealVersion.Split('.')[0] + '.' + $RealVersion.Split('.')[1] 
            Write-Verbose "Product Version of ArcGIS Software Installed:- $Version"

			$DBType =  if($IsPostgres){ "POSTGRESQL" }else{ "SQLSERVER" } 

			$PythonScriptFileName = 'enable_enterprise_gdb.py'   
            $PythonScriptPath = Join-Path "$env:ProgramFiles\WindowsPowerShell\Modules\ArcGIS\DSCResources\ArcGIS_EGDB" $PythonScriptFileName
            if(-not(Test-Path $PythonScriptPath)){
                throw "$PythonScriptPath not found"
            }
            $PythonInstallDir = (Get-ItemProperty -Path "HKLM:\SOFTWARE\ESRI\Python$($Version)").PythonDir
            $PythonPath = ((Get-ChildItem -Path $PythonInstallDir -Filter 'python.exe' -Recurse -File) | Select-Object -First 1 -ErrorAction Ignore)
            if($null -eq $PythonPath) {
                throw "Python27 not found on machine. Please install Python."
            }
            $PythonInterpreterPath = $PythonPath.FullName

            if($EnableGeodatabase) 
            {

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
               
				$SDEEnableUserName = $SdeUserName
				if($IsPostgres){ 
					$SDEEnableUserName = "$($SdeUserName)@$($DatabaseServer.Split(".")[0])"
				}
                $Arguments = " ""$PythonScriptPath"" --DBMS $DBType -s $DatabaseServer -d $DatabaseName -u $SDEEnableUserName -p $SdeUserPassword -l $LicenseFilePath"
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
            }else{
                if($IsPostgres){
                    Write-Verbose "Enabling PostGIS Extension for Postgres Database - $DatabaseName"
                    Enable-PostgresPostGISExtension -ConnString $DbConnString
                }
            }
        

            #region Create Connection file
            $OpFolder = $env:TEMP
            $OpFile = "$($DatabaseServer)_$($DatabaseName)_$($DatabaseUserName).sde"
            $SDEFile = Join-Path $OpFolder $OpFile 
            $PythonScriptFileName = 'create_connection_file.py'
            $PythonScriptPath = Join-Path "$env:ProgramFiles\WindowsPowerShell\Modules\ArcGIS\DSCResources\ArcGIS_EGDB" $PythonScriptFileName
            if(-not(Test-Path $PythonScriptPath)){
                throw "$PythonScriptPath not found"
            }

			$DBConnectUserName = $DatabaseUserName
			if($IsPostgres){ 
				$DBConnectUserName = "$($DatabaseUserName)@$($DatabaseServer.Split(".")[0])"
			}

            $Arguments = " ""$PythonScriptPath"" --DBMS $DBType -s $DatabaseServer -d $DatabaseName -u $DBConnectUserName -p $DatabaseUserPassword -o $OpFolder -f $OpFile"
            
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
        [ValidateSet("AzureSQLDatabase","SQLServerDatabase","AzurePostgreSQLDatabase","AzureMISQLDatabase")]
		[System.String]
		$DatabaseType,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

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
                    dataStoreConnectionType = 'serverOnly'
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

function Invoke-ExecuteSqlScalar
{
    [CmdletBinding()]
    [OutputType([System.Int32])]
	param(
        [System.String]
        $ConnString,

        [System.String]
        $sql
	) 

	### TODO:- SQL Injection Validation
    $result = -1
    if($null -ne $sql -and $sql.Length -gt 0)
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

function Invoke-ExecuteSqlNonQuery 
{
	[CmdletBinding()]
    param(
        [System.String]
        $ConnString,

        [System.String]
        $sql
    )

    if($null -ne $sql -and $sql.Length -gt 0)
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

function Invoke-ExecutePostgresQuery{
    [CmdletBinding()]
	param(
        [System.String]
        $ConnString,
        
        [System.String]
        $sql
    ) 

    $ConnStringArray = $ConnString.split(";")
    $HostName = $ConnStringArray[0].split("=")[1]
    $Port = $ConnStringArray[1].split("=")[1]
    $Database = $ConnStringArray[2].split("=")[1]
    $UserName = $ConnStringArray[3].split("=")[1]
    $Password = $ConnStringArray[4].split("=")[1]
    $InstallerPath = $ConnStringArray[5].split("=")[1]
    
    $PsqlExePath  = Join-Path $InstallerPath "framework\runtime\pgsql\bin\psql.exe" 
    $exeArgsHash = "-h $HostName -p $Port -U $UserName -c ""$($sql)"" -w $Database"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $PsqlExePath
    $psi.Arguments =  $exeArgsHash
    $psi.UseShellExecute = $false #start the process from it's own executable file    
    $psi.RedirectStandardOutput = $true #enable the process to read from standard output
    $psi.RedirectStandardError = $true #enable the process to read from standard error
    $psi.EnvironmentVariables["PGPASSWORD"] = $Password
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.WaitForExit()
    $op = $p.StandardOutput.ReadToEnd()
    $err = $p.StandardError.ReadToEnd()
    
    if($p.ExitCode -eq 0) {                    
        Write-Verbose "Query $sql - Executed Successfully!"
        if($op -and $op.Length -gt 0) {
            return $op
        }
    }else {
        throw "Error executing query - $err"
    }
}

function Get-DatabaseConnectionString
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [System.String]
        $Server,

        [System.String]
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

function Get-PostgresDatabaseConnectionString
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [System.String]
        $Server,

        [System.String]
        $Database, 

        [System.Management.Automation.PSCredential]
        $Credential
    )

    $PortalInstallationDirectory = (Get-ArcGISProductDetails -ProductName "Portal").InstallLocation
    if($PortalInstallationDirectory){
        $InstallerPath = $PortalInstallationDirectory
    }else{
        $DatastoreInstallationDirectory = (Get-ArcGISProductDetails -ProductName "Data Store").InstallLocation
        if($DatastoreInstallationDirectory){
            $InstallerPath = $DatastoreInstallationDirectory
        }else{
            throw "Neither ArcGIS Portal or ArcGIS Datastore is installed. PSQL needed for the Resource to access Azure PostgreSQL"
        }
    }
	$ServerName = $Server.Split(".")[0]
	$UserId = "$($Credential.UserName)@$($ServerName)"
    $str = "Server=$Server;Port=5432;Database=$Database;Uid=$UserId;Pwd=$($Credential.GetNetworkCredential().Password);InstPath=$InstallerPath"
    $str
}

function Test-ConnectivityToServer
{
    [CmdletBinding()]
    param(
        [System.String]
        $Server, 

        [System.Management.Automation.PSCredential]
        $Credential
    )
    
    $connStr = Get-DatabaseConnectionString -Server $Server -Credential $Credential
    try {
        Test-DatabaseExist -ConnString $connStr -DatabaseName 'master'
    }
    catch{
        throw "Unable to connect to Server '$Server' using UserID:- '$($Credential.UserName)'. Please verify that the server is reachable"
    }
}

function Test-ConnectivityToPostgresServer
{
    [CmdletBinding()]
    param(
        [System.String]
        $Server,

        [System.String]
        $Database, 

        [System.Management.Automation.PSCredential]
        $Credential
    )
    $connStr = Get-PostgresDatabaseConnectionString -Server $Server -Credential $Credential -Database $Database
    try {
        Test-DatabaseExist -ConnString $connStr -DatabaseName $Database -IsPostgres
    }
    catch{
        throw "Unable to connect to Server '$Server' using UserID:- '$($Credential.UserName)'. Please verify that the server is reachable"
    }
}

function Test-Login
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString,

        [switch]
        $IsPostgres
    )
    if($IsPostgres){
        $sql = 'SELECT COUNT(*) from pg_catalog.pg_user'
        Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
    }else{
        $sql = 'SELECT COUNT(*) from sys.tables'
        Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql
    }   
}

function Test-LoginExist
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString,

        [System.String]
        $UserName,

        [switch]
        $IsPostgres
    )

    if($IsPostgres){
        $sql = "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='$UserName'"    
        $result = Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
        $resultarr = $result.split([Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries)
        if($resultarr -imatch "(0 rows)"){
            $count = 0
        }else{
            $count = [int] ($result.split([Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries)[2])
        }
    }else{
        $sql = "SELECT COUNT(name) from sys.sql_logins WHERE name = '$UserName'"    
        $count = Invoke-ExecuteSqlScalar -ConnString $ConnString -sql $sql
    }
    $count -gt 0 
}

function Invoke-CreateLogin
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.Management.Automation.PSCredential]
        $Credential,

        [switch]
        $SkipExpiration,

        [switch]
        $IsPostgres
    )
    if($IsPostgres){
		$sql = "CREATE ROLE $($Credential.UserName) LOGIN ENCRYPTED PASSWORD '$($Credential.GetNetworkCredential().Password)'" 
        Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
    }else{
        $sql = "CREATE LOGIN [$($Credential.UserName)] WITH PASSWORD = '$($Credential.GetNetworkCredential().Password)'"
        if($SkipExpiration){
            $sql += ' , CHECK_EXPIRATION=OFF, CHECK_POLICY=ON'
        }
        Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql
    }
}

function Invoke-DeleteLogin
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $UserName, 
       
        [switch]
        $IsPostgres
    )

    if($IsPostgres){
        $sql = "DROP USER $UserName"
        Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
    }else{
        $sql = "DROP LOGIN [$UserName]"
        Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql
    }
}
function Invoke-CreateDatabase
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $DatabaseName, 
       
        [switch]
        $IsPostgres
    )

    if($IsPostgres){
        $sql = "CREATE DATABASE $DatabaseName"
        Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
    }else{
        $sql = "CREATE DATABASE [$DatabaseName]"
        Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql
    }
}

function Enable-DatabasePrivilegesForGeoDatabaseAdministrator
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $DatabaseName
    )

    $sql = "ALTER DATABASE $DatabaseName SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE"
    Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql

    $sql = "ALTER DATABASE $DatabaseName SET ALLOW_SNAPSHOT_ISOLATION ON"
    Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql
}

function Invoke-ChangeDatabaseOwnership([string]$ConnString, [string]$UserName,[string]$DatabaseName, [switch]$IsPostgres)
{
    if($IsPostgres){
        $sql = "ALTER DATABASE $DatabaseName OWNER TO $UserName"
        Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
    }else{
        $sql = "EXEC sp_changedbowner N'$UserName'"
        Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql
    }
}

function Test-DatabaseExist
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $DatabaseName, 
       
        [switch]
        $IsPostgres
    )

    if($IsPostgres){
        $sql = "SELECT 1 AS result FROM pg_database WHERE datname='$DatabaseName'"
        $result = Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
        $resultarr = $result.split([Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries)
        if($resultarr -imatch "(0 rows)"){
            $count = 0
        }else{
            $count = [int] ($result.split([Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries)[2])
        }
    }else{
        $sql = "SELECT COUNT(name) from sys.sysdatabases WHERE name = '$DatabaseName'"   
        $count = Invoke-ExecuteSqlScalar -ConnString $ConnString -sql $sql  
    }
    $count -gt 0 
}

function Test-SqlUserExist
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $UserName, 
       
        [switch]
        $IsPostgres
    )

    if($IsPostgres){
        $sql = "SELECT 1 FROM pg_roles WHERE rolname='$UserName'" 
        $result = Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
        $resultarr = $result.split([Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries)
        if($resultarr -imatch "(0 rows)"){
            $count = 0
        }else{
            $count = [int] ($result.split([Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries)[2])
        }
    }else{
        $sql = "SELECT COUNT(NAME) FROM SYS.DATABASE_PRINCIPALS WHERE Name = '$UserName'"
        $count = Invoke-ExecuteSqlScalar -ConnString $ConnString -sql $sql
    }
    $count -gt 0
}

function Invoke-CreateSqlUser
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.Management.Automation.PSCredential]
        $Credential, 

        [System.String]
        $DefaultSchema = $Credential.UserName,
       
        [switch]
        $IsPostgres
    )
    $UserName = $Credential.UserName
    if($IsPostgres){
		$sql = "CREATE ROLE $UserName LOGIN ENCRYPTED PASSWORD '$($Credential.GetNetworkCredential().Password)'" 
        Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
    }else{
        $sql = "CREATE USER [$UserName] FOR LOGIN [$UserName]"
        if($DefaultSchema -and $DefaultSchema.Length -gt 0){
            $sql += " WITH DEFAULT_SCHEMA = [$DefaultSchema]"
        }
        Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql
        if($DefaultSchema -and $DefaultSchema.Length -gt 0) {
            $sql = "GRANT CONTROL ON SCHEMA::[$DefaultSchema] TO [$UserName]"
            Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql
        }
    }
}

function Invoke-AssignSchemaPrivilegesForSqlUser
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $DbAdminUsername, 

        [System.String]
        $DatabaseName, 

        [System.String]
        $UserName, 

        [System.String]
        $Schema,
       
        [switch]
        $IsPostgres
    )

    if($IsPostgres){
        $sql = "GRANT $UserName TO $DbAdminUsername"
		Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql

		$sql = "ALTER SCHEMA $Schema OWNER TO $UserName"
		Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql

		$sql = "REVOKE $UserName FROM $DbAdminUsername" 
		Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
    }else{
        $sql = "ALTER USER [$UserName] WITH DEFAULT_SCHEMA = [$Schema]"   
        Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql

        $sql = "GRANT CONTROL ON SCHEMA::[$Schema] TO [$UserName]"
        Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql

        $sql = "ALTER AUTHORIZATION ON SCHEMA::[$Schema] TO [$UserName]"
        Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql
    }
}

function Invoke-DropSqlUser
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $UserName,
       
        [switch]
        $IsPostgres
    )

    if($IsPostgres){
        $sql = "DROP USER $UserName"    
        Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
    }else{
        $sql = "DROP USER [$UserName]"    
        Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql
    }
}

function Test-SchemaExist
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $SchemaName,
       
        [switch]
        $IsPostgres
    )

    if($IsPostgres){
        $sql = "SELECT 1 FROM information_schema.schemata WHERE schema_name = '$SchemaName'"
        $result = Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
        $resultarr = $result.split([Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries)
        if($resultarr -imatch "(0 rows)"){
            $count = 0
        }else{
            $count = [int] ($result.split([Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries)[2])
        }
	}
	else{
		$sql = "SELECT Count(Name) FROM sys.schemas WHERE name = '$SchemaName'"
		$count = Invoke-ExecuteSqlScalar -ConnString $ConnString -sql $sql
    }
    $count -gt 0
}

function Invoke-CreateSchemaPostgres
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $SchemaName,
       
        [System.String]
        $SchemaOwnerName,

        [System.String]
        $DbAdminUsername
    )
    
    if($SchemaOwnerName -and $SchemaOwnerName.Length -gt 0) {
		$sql = "CREATE SCHEMA $SchemaName AUTHORIZATION $DbAdminUsername" 
		Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql

		$sql = "GRANT $SchemaOwnerName TO $DbAdminUsername"
		Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql

		$sql = "ALTER SCHEMA $SchemaName OWNER TO $SchemaOwnerName" 
		Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql

		$sql = "REVOKE $SchemaOwnerName FROM $DbAdminUsername" 
		Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
	}
	else {
		$sql = "CREATE SCHEMA $SchemaName" 
		Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
	}
}

function Invoke-CreateSchema
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $SchemaName,
       
        [System.String]
        $SchemaOwnerName
    )
    
    if($SchemaOwnerName -and $SchemaOwnerName.Length -gt 0) {
		$sql = "CREATE SCHEMA [$SchemaName] AUTHORIZATION $SchemaOwnerName" 
	}
	else {
		$sql = "CREATE SCHEMA [$SchemaName]" 
	}
	Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql
}

function Grant-PrivilegesForGeodatabaseAdministrator
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $UserName,
       
        [switch]
        $GrantViewDatabaseState,
       
        [switch]
        $IsPostgres
    )
    
    if($IsPostgres){
        $sql ="GRANT azure_pg_admin TO $UserName";
        Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
    }else{
        <#
        $sql = "SP_DROPUSER '$UserName'"
        Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql

        $sql = "EXEC sp_changedbowner '$UserName'"
        Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql
        #>
        Write-Verbose "Granting Permissions"
        $sql = "GRANT CREATE PROCEDURE TO [$UserName]"
        Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql

        $sql = "GRANT CREATE FUNCTION TO [$UserName]"
        Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql

        $sql = "GRANT CREATE TABLE TO [$UserName]"
        Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql

        $sql = "GRANT CREATE VIEW TO [$UserName]"
        Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql

        if($GrantViewDatabaseState) {
            $sql = "GRANT VIEW DATABASE STATE TO [$UserName]"
            Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql
        }	
    }

}

function Grant-PrivilegesForSdeUser
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $UserName,
       
        [System.String]
        $SchemaName = "sde",
       
        [switch]
        $IsPostgres
    )

	if($IsPostgres){
        $sql ="GRANT USAGE ON SCHEMA $SchemaName TO $UserName";
        Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
    }else{
        #$sql = "EXEC sp_addrolemember N'db_datareader', N'$UserName'"
        #Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql

        #$sql = "EXEC sp_addrolemember N'db_datawriter', N'$UserName'"
        #Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql

        #$sql = "EXEC sp_addrolemember N'db_ddladmin', N'$UserName'"
        #Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql

        #$sql = "EXEC sp_addrolemember N'db_owner', N'$UserName'"    
        #Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql

        $sql = "GRANT CREATE FUNCTION TO [$UserName]"
        Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql

        $sql = "GRANT CREATE PROCEDURE TO [$UserName]"
        Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql

        $sql = "GRANT CREATE TABLE TO [$UserName]"
        Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql

        $sql = "GRANT CREATE VIEW TO [$UserName]"
        Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql

        #$sql = "GRANT CONTROL ON SCHEMA::[sde] TO [$UserName]"
        #Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql

        #$sql = "GRANT CONTROL ON SCHEMA::[dbo] TO [$UserName]"
        #Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql

        #$sql = "GRANT INSERT,UPDATE,DELETE,SELECT to [$UserName]"
        #Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql

        #$sql = "GRANT CREATE XML SCHEMA COLLECTION to [$UserName]"
        #Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql
    }
}

function Enable-PostgresPostGISExtension {
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString
    )

    $sql = "CREATE EXTENSION postgis"
    Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql

    $sql = "CREATE EXTENSION fuzzystrmatch"
    Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql

    $sql = "CREATE EXTENSION postgis_tiger_geocoder"
    Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql

    $sql = "CREATE EXTENSION postgis_topology"
    Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
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



