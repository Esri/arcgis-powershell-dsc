function Invoke-CreateMSSQLSDEIfNotExist
{
    [CmdletBinding()]
    param
	(
        [System.String]
        [ValidateSet("SQLServerDatabase","AzureSQLDatabase","AzureMISQLDatabase")]
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
        $DatabaseUser
    )

    $IsSqlAzure = ($DatabaseType -ieq 'AzureSQLDatabase' -or $DatabaseType -ieq 'AzureMISQLDatabase')
    $SkipLoginExpiration= -not($IsSqlAzure)

    Write-Verbose "Testing connection to Database Server $($DatabaseServer)."
    Test-ConnectivityToSQLServer -Server $DatabaseServer -Credential $DatabaseServerAdministrator
    Write-Verbose "Connection to Database Server $($DatabaseServer) successful!"

    $SQLServerConnString = Get-DatabaseConnectionString -Server $DatabaseServer -Credential $DatabaseServerAdministrator
    ###
    ### Ensure Database exists
    ### 
    if(-not(Test-SQLDatabaseExist $SQLServerConnString -DatabaseName $DatabaseName)) {
        if($DatabaseType -ieq 'AzureSQLDatabase'){
            throw "AzureSQLDatabase Database creation type not supported. Please create the database as a pre-req."
        }else{
            Write-Verbose "Creating Database '$DatabaseName' in Server '$DatabaseServer'"
            Invoke-CreateSQLDatabase -ConnString $SQLServerConnString -DatabaseName $DatabaseName
        }
    }else{
        Write-Verbose "Database '$DatabaseName' in Server '$DatabaseServer' exists"
    }

    Write-Verbose "Enabling Database Privileges for GeoDatabase Administrator on Database '$DatabaseName'"
    Enable-DatabasePrivilegesForSQLGeoDatabaseAdministrator -ConnString $SQLServerConnString -DatabaseName $DatabaseName

    $SdeUserName = "sde"
    ###
    ### Create SDE User (if not exist)
    ###
    if(-not(Test-SQLLoginExist -ConnString $SQLServerConnString -UserName $SdeUserName)) {
        Write-Verbose "Creating Login for User '$SdeUserName' in Server '$DatabaseServer'"
        Invoke-SQLCreateLogin -ConnString $SQLServerConnString -Credential $SDECredential -SkipExpiration:$SkipLoginExpiration
    }else{
        Write-Verbose "Login for User '$SdeUserName' exists in Server '$DatabaseServer'"
    }

    ###
    ### Ensure Sde Exists in the database. If not create one.
    ### 
    $DbConnString = Get-DatabaseConnectionString -Server $DatabaseServer -Credential $DatabaseServerAdministrator -Database $DatabaseName
    if(-not(Test-SQLUserExist -ConnString $DbConnString -UserName $SdeUserName)){
        Write-Verbose "Creating User '$SdeUserName' in Database '$DatabaseName'"
        Invoke-CreateSqlUser -ConnString $DbConnString -Credential $SDECredential -DefaultSchema '' # Create with no schema
    }else{
        Write-Verbose "User '$SdeUserName' exists in Database '$DatabaseName'"    
    }

    $DbConnStringForSdeUser = Get-DatabaseConnectionString -Server $DatabaseServer -Database $DatabaseName -Credential $SDECredential
    try {
        Test-SQLLogin -ConnString $DbConnStringForSdeUser
        Write-Verbose "User account $SdeUserName is a valid login"
    }catch {
        throw "Unable to login using Credentials provided for $SdeUserName."
    }

    ##
    ## Grant necessary privilages to Geodatabase Administrator 'sde'
    ##
    Grant-PrivilegesForSQLGeodatabaseAdministrator -ConnString $DbConnString -UserName $SdeUserName -GrantViewDatabaseState

    ##
    ## Ensure schema 'sde' exists in the database, # Needed Schema for ArcSDE
    ##  
    $schema = $SdeUserName
    if(-not(Test-SQLSchemaExist -ConnString $DbConnStringForSdeUser -SchemaName $schema)){
        Write-Verbose "Creating Schema '$schema' in Database '$DatabaseName'"
        Invoke-CreateSQLSchema -ConnString $DbConnString -SchemaName $schema

        Write-Verbose "Making user '$SdeUserName' owner of schema '$schema' in Database '$DatabaseName'"
        Invoke-AssignSchemaPrivilegesForSqlUser -ConnString $DbConnString -UserName $SdeUserName -DatabaseName $DatabaseName `
                                -Schema $schema -DbAdminUsername $DatabaseServerAdministrator.UserName
    }else{
        Write-Verbose "Schema '$schema' exists in Database '$DatabaseName'"
    }

    $DatabaseUserName = $DatabaseUser.UserName
    ###
    ### Ensure Login for the user exists
    ###
    if(-not(Test-SQLLoginExist -ConnString $SQLServerConnString -UserName $DatabaseUserName)) {
        Write-Verbose "Creating Login for User '$DatabaseUserName' in Server '$DatabaseServer'"
        Invoke-SQLCreateLogin -ConnString $SQLServerConnString -Credential $DatabaseUser -SkipExpiration:$SkipLoginExpiration
    }else{
        Write-Verbose "Login for User '$DatabaseUserName' exists in Server '$DatabaseServer'"
    }

    ###
    ### Ensure Database User Exists in the database. If not create one.
    ###
    if(-not(Test-SQLUserExist -ConnString $DbConnString -UserName $DatabaseUserName)){
        Write-Verbose "Creating User '$DatabaseUserName' in Database '$DatabaseName'"
        Invoke-CreateSqlUser -ConnString $DbConnString -Credential $DatabaseUser -DefaultSchema '' # Create with no schema
    }else{
        Write-Verbose "User '$DatabaseUserName' exists in Database '$DatabaseName'"   
    }

    $DbConnStringForDBUser = Get-DatabaseConnectionString -Server $DatabaseServer -Database $DatabaseName -Credential $DatabaseUser
    try {
        Test-SQLLogin -ConnString $DbConnStringForDBUser
        Write-Verbose "User account $DatabaseUserName is a valid login"
    }catch {
        throw "Unable to login using Credentials provided for $DatabaseUserName."
    }

    ##
    ## Ensure schema 'DatabaseUserName' exists in the database, # Needed Schema for ArcSDE
    ##
    $schema = $DatabaseUserName
    if(-not(Test-SQLSchemaExist -ConnString $DbConnStringForDBUser -SchemaName $schema)){
        Write-Verbose "Creating Schema '$schema' in Database '$DatabaseName'"
        Invoke-CreateSQLSchema -ConnString $DbConnString -SchemaName $schema
        
        Write-Verbose "Assigning schema '$schema' to User '$DatabaseUserName' in Database '$DatabaseName'"
        Invoke-AssignSchemaPrivilegesForSqlUser -ConnString $DbConnString -DatabaseName $DatabaseName `
                    -UserName $DatabaseUserName -Schema $schema `
                    -DbAdminUsername $DatabaseServerAdministrator.UserName
    }else{
        Write-Verbose "Schema '$schema' exists in Database '$DatabaseName'"
    }

    Write-Verbose "Ensuring necessary privileges for '$DatabaseUserName' in Database '$DatabaseName'"
    Grant-PrivilegesForSQLSdeUser -ConnString $DbConnString -UserName $DatabaseUserName -SchemaName 'sde'
}

function Test-SQLLoginExist
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString,

        [System.String]
        $UserName
    )

    $sql = "SELECT COUNT(name) from sys.sql_logins WHERE name = '$UserName'"    
    $count = Invoke-ExecuteSqlScalar -ConnString $ConnString -sql $sql
    $count -gt 0 
}

function Test-ConnectivityToSQLServer
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
        Test-SQLDatabaseExist -ConnString $connStr -DatabaseName 'master'
    }
    catch{
        throw "Unable to connect to Server '$Server' using UserID:- '$($Credential.UserName)'. Please verify that the server is reachable"
    }
}

function Test-SQLLogin
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString
    )
    
    $sql = 'SELECT COUNT(*) from sys.tables'
    Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql
}

function Invoke-SQLCreateLogin
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.Management.Automation.PSCredential]
        $Credential,

        [switch]
        $SkipExpiration
    )
    
    $sql = "CREATE LOGIN [$($Credential.UserName)] WITH PASSWORD = '$($Credential.GetNetworkCredential().Password)'"
    if($SkipExpiration){
        $sql += ' , CHECK_EXPIRATION=OFF, CHECK_POLICY=ON'
    }
    Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql
}

function Invoke-SQLDeleteLogin
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $UserName
    )
    $sql = "DROP LOGIN [$UserName]"
    Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql    
}

function Invoke-CreateSQLDatabase
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $DatabaseName
    )

    $sql = "CREATE DATABASE [$DatabaseName]"
    Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql    
}

function Test-SQLDatabaseExist
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $DatabaseName
    )
    
    $sql = "SELECT COUNT(name) from sys.sysdatabases WHERE name = '$DatabaseName'"   
    $count = Invoke-ExecuteSqlScalar -ConnString $ConnString -sql $sql  
    $count -gt 0 
}

function Test-SQLUserExist
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $UserName
    )

    $sql = "SELECT COUNT(NAME) FROM SYS.DATABASE_PRINCIPALS WHERE Name = '$UserName'"
    $count = Invoke-ExecuteSqlScalar -ConnString $ConnString -sql $sql
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
        $DefaultSchema = $Credential.UserName
    )
    $UserName = $Credential.UserName
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
        $Schema
    )

    $sql = "ALTER USER [$UserName] WITH DEFAULT_SCHEMA = [$Schema]"   
    Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql

    $sql = "GRANT CONTROL ON SCHEMA::[$Schema] TO [$UserName]"
    Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql

    $sql = "ALTER AUTHORIZATION ON SCHEMA::[$Schema] TO [$UserName]"
    Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql
}

function Invoke-DropSQLUser
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $UserName
    )

    $sql = "DROP USER [$UserName]"    
    Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql    
}

function Test-SQLSchemaExist
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $SchemaName
    )

    $sql = "SELECT Count(Name) FROM sys.schemas WHERE name = '$SchemaName'"
    $count = Invoke-ExecuteSqlScalar -ConnString $ConnString -sql $sql
    $count -gt 0
}

function Invoke-CreateSQLSchema
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

function Invoke-ChangeSQLDatabaseOwnership
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $UserName, 

        [System.String]
        $DatabaseName
    )
    $sql = "EXEC sp_changedbowner N'$UserName'"
    Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql
}


function Enable-DatabasePrivilegesForSQLGeoDatabaseAdministrator
{
    [CmdletBinding()]
    param (
        [System.String]
        $ConnString, 

        [System.String]
        $DatabaseName
    )

    $sql = "ALTER DATABASE [$DatabaseName] SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE"
    Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql

    $sql = "ALTER DATABASE [$DatabaseName] SET ALLOW_SNAPSHOT_ISOLATION ON"
    Invoke-ExecuteSqlNonQuery -ConnString $ConnString -sql $sql
}

function Grant-PrivilegesForSQLGeodatabaseAdministrator
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

function Grant-PrivilegesForSQLSdeUser
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
            $command.CommandTimeout = 180 # Database creation doesn't complete within 30 seconds
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

Export-ModuleMember -Function @(
    "Invoke-CreateMSSQLSDEIfNotExist"
)