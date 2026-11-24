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
    
    @{}
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

    $FQDN = if($HostName){ Get-FQDN $HostName }else{ Get-FQDN $env:COMPUTERNAME }

    Write-Verbose "Fully Qualified Domain Name :- $FQDN"
    $InstallDir = (Get-ArcGISComponentVersionAndInstallDirectory -ComponentName $ComponentName).InstallDir
    $RestartRequired = $false

    if($ComponentName -ine "DataStore"){
        $hostname = Get-ConfiguredHostName -InstallDir $InstallDir
        if($hostname -ieq $FQDN) {
            Write-Verbose "Configured hostname '$hostname' matches expected value '$FQDN'"        
        }else {
            Write-Verbose "Configured hostname '$hostname' does not match expected value '$FQDN'. Setting it"
            if(Set-ConfiguredHostName -InstallDir $InstallDir -HostName $FQDN) { 
                # Need to restart the service to pick up the hostname 
                Write-Verbose "hostname.properties file was modified. Need to restart the '$ComponentName' service to pick up changes"
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
                Write-Verbose "In $($MessagePrefix)DataStore Hostidentifier.properties file was modified. Need to restart the '$ComponentName' service to pick up changes"
                $RestartRequired = $true 
            }
        }
    }

    if($RestartRequired) {
        if($ComponentName -ieq "VelocityServer"){
            $VelocityServerServices = Get-VelocityServerServiceNames
            foreach($ServiceName in $VelocityServerServices){
                Restart-ArcGISService -ServiceName $ServiceName -Verbose
            }
        }else{
            Restart-ArcGISService -ComponentName $ComponentName -Verbose
        }
        
        $BaseURL = Get-ArcGISComponentBaseUrl -ComponentName $ComponentName -FQDN $FQDN
        Write-Verbose "Waiting for $ComponentName to initialize. $($BaseURL)"
        $Component = if($ComponentName -ieq "Portal"){ "PortalSharing" }else{ $ComponentName }
        Test-ArcGISComponentHealth -BaseURL $BaseURL -ComponentName $Component -MaxWaitTimeInSeconds 600 -Verbose
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

    $FQDN = if($HostName){ Get-FQDN $HostName }else{ Get-FQDN $env:COMPUTERNAME }
    $result = $true

    Write-Verbose "Fully Qualified Domain Name :- $FQDN"
    $InstallDir = (Get-ArcGISComponentVersionAndInstallDirectory -ComponentName $ComponentName).InstallDir
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

