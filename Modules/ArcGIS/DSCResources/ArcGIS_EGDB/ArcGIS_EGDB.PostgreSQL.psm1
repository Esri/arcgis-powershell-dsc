function Invoke-CreatePostgreSQLSDEIfNotExist
{
    [CmdletBinding()]
    param
	(
        [System.String]
        [ValidateSet("AzurePostgreSQLDatabase","AzureFlexiblePostgreSQLDatabase")]
        $DatabaseType,

        [System.String]
        $DatabaseServer,

        [System.String]
        $DatabaseName,

        [PSCredential]
        $DatabaseServerAdministrator,

        [PSCredential]
        $SDECredential,

        [PSCredential]
        $DatabaseUser,

        [System.Boolean]
        $IsAzureFlexibleServer,

        [System.Boolean]
        $EnableGeodatabase
    )

    Write-Verbose "Testing connection to Database Server $($DatabaseServer)."
    Test-ConnectivityToPostgresServer -Server $DatabaseServer -Database "postgres" `
                            -Credential $DatabaseServerAdministrator -DatabaseType $DatabaseType
    Write-Verbose "Connection to Database Server $($DatabaseServer) successful!"

    $TestDBConnString = Get-PostgresDatabaseConnectionString -Server $DatabaseServer -Database "postgres" `
                            -Credential $DatabaseServerAdministrator -DatabaseType $DatabaseType
    ###
    ### Ensure Database exists
    ###                
    if(-not(Test-PostgresDatabaseExist $TestDBConnString -DatabaseName $DatabaseName)) {
        Write-Verbose "Creating Database '$DatabaseName' in Server '$DatabaseServer'"
        Invoke-PostgresCreateDatabase -ConnString $TestDBConnString -DatabaseName $DatabaseName
    }else{
        Write-Verbose "Database '$DatabaseName' in Server '$DatabaseServer' exists"
    }

    $DbConnString = Get-PostgresDatabaseConnectionString -Server $DatabaseServer -Database $DatabaseName `
                        -Credential $DatabaseServerAdministrator -DatabaseType $DatabaseType
 
    if($EnableGeodatabase){
        Write-Verbose "Enabling PostGIS Extension for Postgres Database - $DatabaseName"
        Enable-PostgresPostGISExtension -ConnString $DbConnString
    }

    $SdeUserName = "sde"
    ###
    ### Create SDE User (if not exist)
    ###
    if(-not(Test-PostgreSQLLoginExist -ConnString $DbConnString -UserName $SdeUserName)) {
        Write-Verbose "Creating Login for User '$SdeUserName' in Server '$DatabaseServer'"
        Invoke-PostgresCreateLogin -ConnString $DbConnString -Credential $SDECredential
    }else{
        Write-Verbose "Login for User '$SdeUserName' exists in Server '$DatabaseServer'"
    }
    
    ###
    ### Ensure Sde Exists in the database. If not create one.
    ###
    if(-not(Test-PostgresUserExist -ConnString $DbConnString -UserName $SdeUserName)){
        Write-Verbose "Creating User '$SdeUserName' in Database '$DatabaseName'"
        Invoke-CreatePostgresUser -ConnString $DbConnString -Credential $SDECredential -DefaultSchema '' # Create with no schema
    }else{
        Write-Verbose "User '$SdeUserName' exists in Database '$DatabaseName'"
    }
        
    $DbConnStringForSdeUser = Get-PostgresDatabaseConnectionString -Server $DatabaseServer -Credential $SDECredential `
                        -Database $DatabaseName -DatabaseType $DatabaseType
    try {
        Test-PostgresLogin -ConnString $DbConnStringForSdeUser
        Write-Verbose "User account $SdeUserName is a valid login"
    }catch {
        throw "Unable to login using Credentials provided for $SdeUserName."
    }

    ##
    ## Grant necessary privilages to Geodatabase Administrator 'sde'
    ##
    Grant-PrivilegesForPostgresGeodatabaseAdministrator -ConnString $DbConnString -UserName $SdeUserName

    ##
    ## Ensure schema 'sde' exists in the database, # Needed Schema for ArcSDE
    ##
    $schema = $SdeUserName
    if(-not(Test-PostgresSchemaExist -ConnString $DbConnStringForSdeUser -SchemaName $schema)){
        Write-Verbose "Creating Schema '$schema' in Database '$DatabaseName'"
        Invoke-CreateSchemaPostgres -ConnString $DbConnString -SchemaName $schema `
                    -SchemaOwnerName $schema -DbAdminUsername $DatabaseServerAdministrator.UserName
    }else{
        Write-Verbose "Schema '$schema' exists in Database '$DatabaseName'"
    }

    $DatabaseUserName = $DatabaseUser.UserName
    ###
    ### Ensure Login for the user exists
    ###
    if(-not(Test-PostgreSQLLoginExist -ConnString $DbConnString -UserName $DatabaseUserName)) {
        Write-Verbose "Creating Login for User '$DatabaseUserName' in Server '$DatabaseServer'"
        Invoke-PostgresCreateLogin -ConnString $DbConnString -Credential $DatabaseUser
    }else{
        Write-Verbose "Login for User '$DatabaseUserName' exists in Server '$DatabaseServer'"
    }
    
    ###
    ### Ensure Database User Exists in the database. If not create one.
    ###
    if(-not(Test-PostgresUserExist -ConnString $DbConnString -UserName $DatabaseUserName)){
        Write-Verbose "Creating User '$DatabaseUserName' in Database '$DatabaseName'"
        Invoke-CreatePostgresUser -ConnString $DbConnString -Credential $DatabaseUser -DefaultSchema '' # Create with no schema
    }else{
        Write-Verbose "User '$DatabaseUserName' exists in Database '$DatabaseName'"
    }

    $DbConnStringForDBUser = Get-PostgresDatabaseConnectionString -Server $DatabaseServer -Credential $DatabaseUser `
                            -Database $DatabaseName -DatabaseType $DatabaseType
    try {
        Test-PostgresLogin -ConnString $DbConnStringForDBUser
        Write-Verbose "User account $DatabaseUserName is a valid login"
    }catch {
        throw "Unable to login using Credentials provided for $DatabaseUserName."
    }

    ##
    ## Ensure schema 'DatabaseUserName' exists in the database, # Needed Schema for ArcSDE
    ##
    $schema = $DatabaseUserName
    if(-not(Test-PostgresSchemaExist -ConnString $DbConnStringForDBUser -SchemaName $schema)){
        Write-Verbose "Creating Schema '$schema' in Database '$DatabaseName'"
        Invoke-CreateSchemaPostgres -ConnString $DbConnString -SchemaName $schema `
            -SchemaOwnerName $DatabaseUserName -DbAdminUsername $DatabaseServerAdministrator.UserName
    }else{
        Write-Verbose "Schema '$schema' exists in Database '$DatabaseName'"
    }

    Write-Verbose "Ensuring necessary privileges for '$DatabaseUserName' in Database '$DatabaseName'"
    Grant-PrivilegesForPostgresSdeUser -ConnString $DbConnStringForSdeUser -UserName $DatabaseUserName -SchemaName 'sde'
}

function Test-PostgreSQLLoginExist
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString,

        [System.String]
        $UserName
    )

    $sql = "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='$UserName'"    
    $result = Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
    $resultarr = $result.split([Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries)
    if($resultarr -imatch "(0 rows)"){
        $count = 0
    }else{
        $count = [int] ($result.split([Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries)[2])
    }
    $count -gt 0 
}

function Test-ConnectivityToPostgresServer
{
    [CmdletBinding()]
    param(
        [System.String]
        $Server,

        [System.String]
        $Database, 

        [System.String]
        $DatabaseType, 

        [System.Management.Automation.PSCredential]
        $Credential
    )
    $connStr = Get-PostgresDatabaseConnectionString -Server $Server -Credential $Credential -Database $Database -DatabaseType $DatabaseType
    try {
        Test-PostgresDatabaseExist -ConnString $connStr -DatabaseName $Database
    }
    catch{
        throw "Unable to connect to Server '$Server' using UserID:- '$($Credential.UserName)'. Please verify that the server is reachable"
    }
}

function Test-PostgresLogin
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString
    )
    
    $sql = 'SELECT COUNT(*) from pg_catalog.pg_user'
    Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
}

function Invoke-PostgresCreateLogin
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.Management.Automation.PSCredential]
        $Credential
    )

    $sql = "CREATE ROLE $($Credential.UserName) LOGIN ENCRYPTED PASSWORD '$($Credential.GetNetworkCredential().Password)'" 
    Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
}

function Invoke-PostgresDeleteLogin
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $UserName
    )

    $sql = "DROP USER $UserName"
    Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
}

function Invoke-PostgresCreateDatabase
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $DatabaseName
    )

    $sql = "CREATE DATABASE $DatabaseName"
    Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
}

function Test-PostgresDatabaseExist
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $DatabaseName
    )

    $sql = "SELECT 1 AS result FROM pg_database WHERE datname='$DatabaseName'"
    $result = Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
    $resultarr = $result.split([Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries)
    if($resultarr -imatch "(0 rows)"){
        $count = 0
    }else{
        $count = [int] ($result.split([Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries)[2])
    }
    $count -gt 0
}

function Test-PostgresUserExist
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $UserName
    )

    $sql = "SELECT 1 FROM pg_roles WHERE rolname='$UserName'" 
    $result = Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
    $resultarr = $result.split([Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries)
    if($resultarr -imatch "(0 rows)"){
        $count = 0
    }else{
        $count = [int] ($result.split([Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries)[2])
    }
    $count -gt 0
}

function Invoke-CreatePostgresUser
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.Management.Automation.PSCredential]
        $Credential, 

        [System.String]
        $DefaultSchema = $Credential.UserName
    )
    $UserName = $Credential.UserName
    $sql = "CREATE ROLE $UserName LOGIN ENCRYPTED PASSWORD '$($Credential.GetNetworkCredential().Password)'" 
    Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
}

function Invoke-AssignSchemaPrivilegesForPostgresUser
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
        $Schema
    )
    
    $sql = "GRANT $UserName TO $DbAdminUsername"
    Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql

    $sql = "ALTER SCHEMA $Schema OWNER TO $UserName"
    Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql

    $sql = "REVOKE $UserName FROM $DbAdminUsername" 
    Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
}

function Invoke-DropPostgresUser
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $UserName
    )

    $sql = "DROP USER $UserName"    
    Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql    
}

function Test-PostgresSchemaExist
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $SchemaName
    )

    $sql = "SELECT 1 FROM information_schema.schemata WHERE schema_name = '$SchemaName'"
    $result = Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
    $resultarr = $result.split([Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries)
    if($resultarr -imatch "(0 rows)"){
        $count = 0
    }else{
        $count = [int] ($result.split([Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries)[2])
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

function Grant-PrivilegesForPostgresGeodatabaseAdministrator
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $UserName,
       
        [switch]
        $GrantViewDatabaseState
    )
    
    $sql ="GRANT azure_pg_admin TO $UserName";
    Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
}

function Grant-PrivilegesForPostgresSdeUser
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $UserName,
       
        [System.String]
        $SchemaName = "sde"
    )
    $sql ="GRANT USAGE ON SCHEMA $SchemaName TO $UserName";
    Invoke-ExecutePostgresQuery -ConnString $ConnString -sql $sql
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
    
    $PsqlExePath = ""
    if( $null -ne [Environment]::GetEnvironmentVariable('PSQL_EXE_PATH', 'MACHINE')){
        $PsqlExePath = [Environment]::GetEnvironmentVariable('PSQL_EXE_PATH', 'MACHINE')
    }else{
        if($InstallerPath -ieq "None"){
            throw "Neither ArcGIS Portal or ArcGIS Datastore is installed. PSQL needed for the Resource to access Azure PostgreSQL"
        }else{
            $PsqlExePath  = Join-Path $InstallerPath "framework\runtime\pgsql\bin\psql.exe" 
        }
    }
   
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

function Get-PostgresDatabaseConnectionString
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [System.String]
        $DatabaseType,

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
            $InstallerPath = "None"
        }
    }

    $UserId = if($DatabaseType -ieq "AzurePostgreSQLDatabase"){ "$($Credential.UserName)@$($Server.Split(".")[0])" }else{ $Credential.UserName }
    $str = "Server=$Server;Port=5432;Database=$Database;Uid=$UserId;Pwd=$($Credential.GetNetworkCredential().Password);InstPath=$InstallerPath"
    $str
}

Export-ModuleMember -Function @(
    "Invoke-CreatePostgreSQLSDEIfNotExist"
)