<#
    .SYNOPSIS
        Resource Implements application level to handle cross node dependencies on SQL Server specific to the ArcGIS Enterprise Stack.
    .PARAMETER Ensure
        Take the values Present or Absent. 
        - "Present" ensures that machine waits for a target SQL machine, for which the present Server node has a dependency on.
        - "Absent" - not implemented.
    .PARAMETER SQLServerMachineName
        HostName of SQL Server Machine that the SQL Server needs to Wait for.
    .PARAMETER Credential
         A MSFT_Credential Object - Database Admin User.
    .PARAMETER RetryIntervalSec
        Time Interval after which the Resource will again check the status of the resource on the remote machine for which the node is waiting for.
    .PARAMETER RetryCount
        Number of Retries before the Resource is done trying to see if the resource on the target Machine is done.        
#>


function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
        $SQLServerMachineName
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false
    
	$null
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
        $SQLServerMachineName,
        
        [ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,
        
        [parameter(Mandatory = $false)]
		[System.Management.Automation.PSCredential]
		$Credential,

        [parameter(Mandatory = $false)]
        [uint32]
        $RetryIntervalSec  = 30,
        
        [parameter(Mandatory = $false)]
		[uint32]
        $RetryCount  = 10
    )   
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false
    
    $NumCount = 0
	$Done     = $false
	while ((-not $Done) -and ($NumCount++ -le $RetryCount)) 
	{
        $database = "master"
        $connectionString = "Server=$SQLServerMachineName;uid=$($Credential.UserName); pwd=$($Credential.GetNetworkCredential().Password);Database=$database;Integrated Security=False;"
        $connection = New-Object System.Data.SqlClient.SqlConnection
        $connection.ConnectionString = $connectionString
        $connection.Open()
        if($connection.State -eq 1) {
            Write-Verbose "Connection Successful"
            $connection.Close()
            $Done = $True
        }else{
            Write-Verbose "SQL Server is not ready. Retrying after $RetryIntervalSec Seconds"
            Start-Sleep -Seconds $RetryIntervalSec
        }
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
        $SQLServerMachineName,

        [ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,
        
        [parameter(Mandatory = $false)]
		[System.Management.Automation.PSCredential]
		$Credential,

        [parameter(Mandatory = $false)]
        [uint32]
        $RetryIntervalSec  = 30,
        
        [parameter(Mandatory = $false)]
		[uint32]
        $RetryCount  = 10
	)
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    $result = $false
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $database = "master"
    $connectionString = "Server=$SQLServerMachineName;uid=$($Credential.UserName); pwd=$($Credential.GetNetworkCredential().Password);Database=$database;Integrated Security=False;"
    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connectionString
    $connection.Open()
    if ($connection.State -eq 1) {
        Write-Verbose "Connection Successful"
        $connection.Close()
       $result =  $True
    } else {
        Write-Verbose "Connection Unsuccessful"
       $result =  $False
    }
    
    $result
    
}

Export-ModuleMember -Function *-TargetResource