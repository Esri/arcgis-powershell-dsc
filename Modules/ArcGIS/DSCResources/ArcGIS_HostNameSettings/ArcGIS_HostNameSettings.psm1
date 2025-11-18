$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
        [Parameter(Mandatory = $true)]
        [System.String]
        $ComponentName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [Parameter(Mandatory = $false)]
        [System.String]
        $HostName
    )
    
    $null
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
        [Parameter(Mandatory = $true)]
        [System.String]
        $ComponentName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [Parameter(Mandatory = $false)]
        [System.String]
        $HostName
    )

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $FQDN = if($HostName){ Get-FQDN $HostName }else{ Get-FQDN $env:COMPUTERNAME }

    Write-Verbose "Fully Qualified Domain Name :- $FQDN"
    $ServiceName = Get-ArcGISServiceName -ComponentName $ComponentName
    Write-Verbose "Service Name :- $ServiceName"
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $InstallDir =(Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir 
    $RestartRequired = $false

    if($ComponentName -ine "DataStore"){
        $hostname = Get-ConfiguredHostName -InstallDir $InstallDir
        if($hostname -ieq $FQDN) {
            Write-Verbose "Configured hostname '$hostname' matches expected value '$FQDN'"        
        }else {
            Write-Verbose "Configured hostname '$hostname' does not match expected value '$FQDN'. Setting it"
            if(Set-ConfiguredHostName -InstallDir $InstallDir -HostName $FQDN) { 
                # Need to restart the service to pick up the hostname 
                Write-Verbose "hostname.properties file was modified. Need to restart the '$ServiceName' service to pick up changes"
                $RestartRequired = $true 
            }
        }
    }
    
    if($ComponentName -ieq "Portal" -or $ComponentName -ieq "Server"){
        if(Get-NodeAgentAmazonElementsPresent -InstallDir $InstallDir) {
            Write-Verbose "Removing EC2 Listener from NodeAgent xml file"
            if(Remove-NodeAgentAmazonElements -InstallDir $InstallDir) {
                # Need to restart the service to pick up the EC2
                $RestartRequired = $true
            }  
        }
    }

    if($ComponentName -ieq "Portal" -or $ComponentName -ieq "DataStore"){
        $MessagePrefix = ""
        if($ComponentName -ieq "Portal"){
            $InstallDir = Join-Path $InstallDir 'framework\runtime\ds' 
            $MessagePrefix = "Portal "
        }

        $expectedHostIdentifierType = if($FQDN -as [ipaddress]){ 'ip' }else{ 'hostname' }
        $hostidentifier = Get-ConfiguredHostIdentifier -InstallDir $InstallDir
        $hostidentifierType = Get-ConfiguredHostIdentifierType -InstallDir $InstallDir
        if(($hostidentifier -ieq $FQDN) -and ($hostidentifierType -ieq $expectedHostIdentifierType)) {        
            Write-Verbose "In $($MessagePrefix)DataStore configured host identifier '$hostidentifier' matches expected value '$FQDN' and host identifier type '$hostidentifierType' matches expected value '$expectedHostIdentifierType'"        
        }else {
            Write-Verbose "In $($MessagePrefix)DataStore configured host identifier '$hostidentifier' does not match expected value '$FQDN' or host identifier type '$hostidentifierType' does not match expected value '$expectedHostIdentifierType'. Setting it"
            if(Set-ConfiguredHostIdentifier -InstallDir $InstallDir -HostIdentifier $FQDN -HostIdentifierType $expectedHostIdentifierType) { 
                # Need to restart the service to pick up the hostidentifier 
                Write-Verbose "In $($MessagePrefix)DataStore Hostidentifier.properties file was modified. Need to restart the '$ServiceName' service to pick up changes"
                $RestartRequired = $true 
            }
        }
    }

    if($RestartRequired) {    
        Restart-ArcGISService -ServiceName $ServiceName -Verbose
        $HealthCheckUrl = Get-HealthCheckUrl -ComponentName $ComponentName -FQDN $FQDN
        Write-Verbose "Waiting for $ComponentName to initialize. Health check url - '$HealthCheckUrl'"
        Wait-ForUrl $HealthCheckUrl -HttpMethod 'GET' -MaxWaitTimeInSeconds 600 -Verbose
    }
}

function Get-HealthCheckUrl {
    param(
        [System.String]
        $ComponentName,
        
        [System.String]
        $FQDN
    )

    switch ($ComponentName) {
        'Portal' { return "https://$($FQDN):7443/arcgis/portaladmin/" }
        'Server' { return "https://$($FQDN):6443/arcgis/admin/" }
        'DataStore' { return "https://$($FQDN):2443/arcgis/datastore/" }
        'MissionServer' { return "https://$($FQDN):20443/arcgis/admin/" }
        'NotebookServer' { return "https://$($FQDN):11443/arcgis/admin/" }
        'VideoServer' { return "https://$($FQDN):21443/arcgis/admin/" }
        default { throw "Unknown component name: $ComponentName" }
    }
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [Parameter(Mandatory = $true)]
        [System.String]
        $ComponentName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [Parameter(Mandatory = $false)]
        [System.String]
        $HostName
    )

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $FQDN = if($HostName){ Get-FQDN $HostName }else{ Get-FQDN $env:COMPUTERNAME }
    $result = $true

    Write-Verbose "Fully Qualified Domain Name :- $FQDN"
    $ServiceName = Get-ArcGISServiceName -ComponentName $ComponentName
    Write-Verbose "Service Name :- $ServiceName"
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $InstallDir =(Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir 
    $hostname = Get-ConfiguredHostName -InstallDir $InstallDir
    
    if ($hostname -ieq $FQDN) {
        Write-Verbose "Configured hostname '$hostname' matches expected value '$FQDN'"
        $result = $true
    }
    else {
        Write-Verbose "Configured hostname '$hostname' does not match expected value '$FQDN'"
        $result = $false
    }

    if($result -and ($ComponentName -ieq "Portal" -or $ComponentName -ieq "Server")) {
        if(Get-NodeAgentAmazonElementsPresent -InstallDir $InstallDir) {
            Write-Verbose "Amazon Elements present in NodeAgentExt.xml. Will be removed in Set Method"
            $result = $false
        }         
    }

    if ($result -and ($ComponentName -ieq "Portal" -or $ComponentName -ieq "DataStore")){
        $InstallDir = Join-Path $InstallDir 'framework\runtime\ds' 
        $MessagePrefix = ""
        if($ComponentName -ieq "Portal"){
            $InstallDir = Join-Path $InstallDir 'framework\runtime\ds' 
            $MessagePrefix = "Portal "
        }
        $expectedHostIdentifierType = if($FQDN -as [ipaddress]){ 'ip' }else{ 'hostname' }
		$hostidentifier = Get-ConfiguredHostIdentifier -InstallDir $InstallDir
		$hostidentifierType = Get-ConfiguredHostIdentifierType -InstallDir $InstallDir
		if (($hostidentifier -ieq $FQDN) -and ($hostidentifierType -ieq $expectedHostIdentifierType)) {        
            Write-Verbose "In $($MessagePrefix)DataStore configured host identifier '$hostidentifier' matches expected value '$FQDN' and host identifier type '$hostidentifierType' matches expected value '$expectedHostIdentifierType'"        
        }
        else {
			Write-Verbose "In $($MessagePrefix)DataStore configured host identifier '$hostidentifier' does not match expected value '$FQDN' or host identifier type '$hostidentifierType' does not match expected value '$expectedHostIdentifierType'."
			$result = $false
        }
    }

    $result
}

