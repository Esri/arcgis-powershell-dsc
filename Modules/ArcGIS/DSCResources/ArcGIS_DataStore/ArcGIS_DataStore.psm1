$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.DataStore.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.Server.psm1'))

<#
    .SYNOPSIS
        Configures Datastore with the GIS server. 
        - Can be a primary or secondary in case of Relational DataStore. 
        - Can be 1 or upto n in case of a BDS. 
        - TileCache - not sure.
    .PARAMETER Ensure
        Take the values Present or Absent. 
        - "Present" ensures that DataStore is Configured if not.
        - "Absent" ensures that DataStore is unconfigured or derigestered with the GIS Server - Not Implemented).
    .PARAMETER Version
        Optional Version of DataStore to be configured
    .PARAMETER DatastoreMachineHostName
        Optional Host Name or IP of the Machine on which the DataStore has been installed and is to be configured.
    .PARAMETER ServerHostName
        HostName of the GIS Server for which you want to create and register a data store.
    .PARAMETER SiteAdministrator
        A MSFT_Credential Object - Primary Site Administrator to access the GIS Server. 
    .PARAMETER ContentDirectory
         Path for the ArcGIS Data Store directory. This directory contains the data store files, plus the relational data store backup directory.
    .PARAMETER DataStoreTypes
        The type of data store to create on the machine.('Relational','SpatioTemporal','TileCache'). Value for this can be one or more. 
    .PARAMETER EnableFailoverOnPrimaryStop
        Boolean to Indicate if failover Enabled when service on Primary machine is stopped.
    .PARAMETER IsTileCacheDataStoreClustered
        Boolean to Indicate if the Tile Cache Datastore is clustered or not.
    .PARAMETER IsObjectDataStoreClustered
        Boolean to Indicate if the Object store is clustered or not.
    .PARAMETER PITRState
        String to indicate if to enable or disable or do nothing with respect to Point In Time Recovery (Relational only).
#>

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $false)]    
        [System.String]
        $DatastoreMachineHostName,

        [ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

		[parameter(Mandatory = $true)]
		[System.String]
		$ServerHostName,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

		[System.String]
		$ContentDirectory,

        [System.Array]
        $DataStoreTypes,
        
        [System.Boolean]
        $IsTileCacheDataStoreClustered = $false,

        [System.Boolean]
        $IsObjectDataStoreClustered = $false,

        [System.Boolean]
        $IsGraphStoreClustered = $false,
        
        [System.Boolean]
		$EnableFailoverOnPrimaryStop = $false,

        [parameter(Mandatory = $False)]
        [ValidateSet("Enabled","Disabled")]
        $PITRState = "Disabled",

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $UseCloudRelationalStore = $False,

        [Parameter(Mandatory=$false)]
        [ValidateSet('AzureFlexiblePostgreSQLDatabase','AWSRDSPostgreSQLDatabase','AWSAuroraPostgreSQLDatabase', 'None')]
        [System.String]
        $CloudRelationalStoreType = 'None',

        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalDatabasePort,

        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalDatabaseURI,

        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalDatabaseReadonlyURI,   

        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalProxyPort,

        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalProxyURI,
        
        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalRegion,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $CloudRelationalDatabaseAdminUser,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $CloudRelationalSDEUser
	)
    
	@{}
}


function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $false)]    
        [System.String]
        $DatastoreMachineHostName,

		[parameter(Mandatory = $true)]
		[System.String]
		$ServerHostName,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

		[System.String]
		$ContentDirectory,

        [System.Array]
        $DataStoreTypes,

        [System.Boolean]
        $IsTileCacheDataStoreClustered = $false,

        [System.Boolean]
        $IsObjectDataStoreClustered = $false,

        [System.Boolean]
        $IsGraphStoreClustered = $false,
        
        [System.Boolean]
        $EnableFailoverOnPrimaryStop = $false,

        [parameter(Mandatory = $False)]
        [ValidateSet("Enabled","Disabled")]
        $PITRState = "Disabled",

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $UseCloudRelationalStore = $False,

        [Parameter(Mandatory=$false)]
        [ValidateSet('AzureFlexiblePostgreSQLDatabase','AWSRDSPostgreSQLDatabase','AWSAuroraPostgreSQLDatabase', 'None')]
        [System.String]
        $CloudRelationalStoreType = 'None',

        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalDatabasePort,

        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalDatabaseURI,

        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalDatabaseReadonlyURI,

        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalProxyPort,

        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalProxyURI,
        
        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalRegion,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $CloudRelationalDatabaseAdminUser,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $CloudRelationalSDEUser
	)

    if($Ensure -ieq 'Present') {
        $MachineFQDN = if($DatastoreMachineHostName){ Get-FQDN $DatastoreMachineHostName }else{ Get-FQDN $env:COMPUTERNAME }
        $Referer = "https://$($MachineFQDN):2443"

        $DataStoreInstallDirectory = (Get-ArcGISComponentVersionAndInstallDirectory -ComponentName 'DataStore').InstallDir
        $RestartRequired = $false
        
        $FailoverPropertyModified = $False
        $ExpectedFailoverEnabledString = 'false'
        $PropertiesFilePath = Join-Path $DataStoreInstallDirectory 'framework\etc\datastore.properties'
        $FailoverPropertyName = 'failover_on_primary_stop'
        if($DataStoreTypes -icontains "Relational"){
            $FailoverEnabledString = Get-PropertyFromPropertiesFile -PropertiesFilePath $PropertiesFilePath -PropertyName $FailoverPropertyName
            Write-Verbose "Current value of property $FailoverPropertyName is $FailoverEnabledString"
            $IsFailoverEnabled = ($FailoverEnabledString -ieq 'true')
            $ExpectedFailoverEnabledString = if($EnableFailoverOnPrimaryStop){ 'true' }else{ 'false' }
            if($IsFailoverEnabled -ine $EnableFailoverOnPrimaryStop) { 
                Write-Verbose "Property '$FailoverPropertyName' will be modified. Need to restart the DataStore service to pick up changes"
                $FailoverPropertyModified = $true
                $RestartRequired = $true
            } else {
                Write-Verbose "Property value '$FailoverEnabledString' for '$FailoverPropertyName' matches expected value of '$($ExpectedFailoverEnabledString)'"
            }	
        }

        if($RestartRequired){
            Write-Verbose "Stopping the DataStore service before applying property change"
            $ServiceName = $ServiceName = Get-ArcGISServiceName -ComponentName "DataStore"
            Stop-ServiceAndWait -ServiceName $ServiceName -TimeoutSeconds 300 -PollSeconds 2 -Verbose
            Write-Verbose 'Stopped the service'
            
            if($FailoverPropertyModified -and ($DataStoreTypes -icontains "Relational")){
                Write-Verbose "Property '$FailoverPropertyName' will be changed to $ExpectedFailoverEnabledString in 'datastore.properties' file"
                Set-PropertyFromPropertiesFile -PropertiesFilePath $PropertiesFilePath -PropertyName $FailoverPropertyName -PropertyValue $ExpectedFailoverEnabledString -Verbose
                Write-Verbose "datastore.properties file was modified."
            }
            
            Write-Verbose "Starting DataStore service to pick up property change"
            Start-ServiceAndWait -ServiceName $ServiceName -TimeoutSeconds 300 -PollSeconds 2 -Verbose
            Write-Verbose "Restarted DataStore service"

            Test-ArcGISComponentHealth -BaseURL "https://$($MachineFQDN):2443/arcgis" -ComponentName "DataStore" -MaxWaitTimeInSeconds 180 -SleepTimeInSeconds 5 -Verbose
        } else {
            Write-Verbose "Properties are up to date. No need to restart the 'ArcGIS Data Store' Service"
        }

        $ServerFQDN = Get-FQDN $ServerHostName
        $ServerBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName "Server" -FQDN $ServerFQDN
        Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName "Server" -MaxWaitTimeInSeconds 90 -SleepTimeInSeconds 5 -Verbose

        $token = Get-ServerToken -URL $ServerBaseUrl -Credential $SiteAdministrator -Referer $Referer 

        if(($DataStoreTypes -icontains "Relational") -or ($DataStoreTypes -icontains "TileCache")){ 
            Write-Verbose "Ensure the Publishing GP Service (Tool) is started on Server"
            $PublishingToolsPath = 'System/PublishingTools.GPServer'
            $Attempts  = 1
            $MaxAttempts = 5
            $SleepTimeInSeconds = 20
            while ($true)
            {
                Write-Verbose "Checking state of Service '$PublishingToolsPath'. Attempt # $Attempts" 
                $serviceStatus = Invoke-GPServiceOperation -URL $ServerBaseUrl -Token $token.token -Referer $Referer -ServicePath $PublishingToolsPath -OperationName "status"
                Write-Verbose "Service Status :- $serviceStatus"
                
                if($serviceStatus.configuredState -ieq 'STARTED' -and $serviceStatus.realTimeState -ieq 'STARTED'){
                    Write-Verbose "State of Service '$PublishingToolsPath' is STARTED"
                    break
                }else{
                    if($serviceStatus.configuredState -ine 'STARTED' -or $serviceStatus.realTimeState -ine 'STARTED'){
                        Write-Verbose "Waiting $SleepTimeInSeconds seconds for Service '$PublishingToolsPath' to be started"
                        Start-Sleep -Seconds $SleepTimeInSeconds
                    }else{
                        Write-Verbose "Trying to Start Service $PublishingToolsPath"
                        Invoke-GPServiceOperation -URL $ServerBaseUrl -Token $token.token -Referer $Referer -ServicePath $PublishingToolsPath -OperationName "start"
                        Start-Sleep -Seconds $SleepTimeInSeconds
                    }
                }
                
                $serviceStatus = Invoke-GPServiceOperation -URL $ServerBaseUrl -Token $token.token -Referer $Referer -ServicePath $PublishingToolsPath -OperationName "status"
                if($serviceStatus.configuredState -ieq 'STARTED' -and $serviceStatus.realTimeState -ieq 'STARTED'){
                    Write-Verbose "State of Service '$PublishingToolsPath' is STARTED. Service Status :- $serviceStatus"
                    break
                }else{
                    if($Attempts -le $MaxAttempts){
                        $Attempts += 1
                        Write-Verbose "Waiting $SleepTimeInSeconds seconds. Current  Service Status :- $serviceStatus"
                        Start-Sleep -Seconds $SleepTimeInSeconds
                    }else{
                        Write-Verbose "Unable to get $PublishingToolsPath started successfully. Service Status :- $serviceStatus"
                        break
                    }
                }
            }
        }

        $DataStoreBaseURL = 'https://localhost:2443/arcgis'
        $DSToRegisterOrConfigure = @{
            ServerBaseURL = $ServerBaseUrl
            Token = $token.token
            Referer = $Referer
            DataStoreTypes = $DataStoreTypes
            MachineFQDN = $MachineFQDN
            DataStoreBaseURL = $DataStoreBaseURL
            DataStoreContentDirectory = $ContentDirectory
            ServerSiteAdminCredential = $SiteAdministrator
            IsTileCacheDataStoreClustered = $IsTileCacheDataStoreClustered
            IsObjectDataStoreClustered = $IsObjectDataStoreClustered
            IsGraphStoreClustered = $IsGraphStoreClustered
            Version = $Version
            DataStoreInstallDirectory = $DataStoreInstallDirectory
            UseCloudRelationalStore = $UseCloudRelationalStore
        }
        
        $DatastoresToRegisterOrConfigure = Get-DataStoreTypesToRegisterOrConfigure @DSToRegisterOrConfigure
        
        if($DatastoresToRegisterOrConfigure.Count -gt 0){
            $DatastoresToRegisterOrConfigureString = ($DatastoresToRegisterOrConfigure -join ',')
            Write-Verbose "Registering or configuring datastores $DatastoresToRegisterOrConfigureString"
            $RegisterDatastoreArgs = @{
                Version = $Version
                DataStoreBaseURL = $DataStoreBaseURL
                ServerSiteAdminCredential = $SiteAdministrator
                ServerBaseUrl = $ServerBaseUrl
                DataStoreContentDirectory = $ContentDirectory
                Token = $token.token
                Referer = $Referer
                MachineFQDN = $MachineFQDN
                DataStoreTypes = $DataStoreTypes
                IsTileCacheDataStoreClustered = $IsTileCacheDataStoreClustered
                IsObjectDataStoreClustered = $IsObjectDataStoreClustered
                IsGraphStoreClustered = $IsGraphStoreClustered
                DataStoreInstallDirectory = $DataStoreInstallDirectory
                UseCloudRelationalStore = $UseCloudRelationalStore
                CloudRelationalStoreType = $CloudRelationalStoreType
                CloudRelationalDatabasePort = $CloudRelationalDatabasePort
                CloudRelationalDatabaseURI = $CloudRelationalDatabaseURI
                CloudRelationalDatabaseReadonlyURI = $CloudRelationalDatabaseReadonlyURI
                CloudRelationalProxyPort = $CloudRelationalProxyPort
                CloudRelationalProxyURI = $CloudRelationalProxyURI
                CloudRelationalRegion = $CloudRelationalRegion
                CloudRelationalDatabaseAdminUser = $CloudRelationalDatabaseAdminUser
                CloudRelationalSDEUser = $CloudRelationalSDEUser
            }

            Invoke-RegisterOrConfigureDataStore @RegisterDatastoreArgs
        }

        if($DataStoreTypes -icontains "SpatioTemporal"){
            Write-Verbose "Checking if the Spatiotemporal Big Data Store has started."
            if(-not(Test-SpatiotemporalBigDataStoreStarted -ServerBaseURL $ServerBaseUrl -Token $token.token -Referer $Referer -MachineFQDN $MachineFQDN)) {
                Write-Verbose "Starting the Spatiotemporal Big Data Store."
                Start-SpatiotemporalBigDataStore -ServerBaseURL $ServerBaseUrl -Token $token.token -Referer $Referer -MachineFQDN $MachineFQDN
                $TestBDSStatus = Test-SpatiotemporalBigDataStoreStarted -ServerBaseURL $ServerBaseUrl -Token $token.token -Referer $Referer -MachineFQDN $MachineFQDN
                Write-Verbose "Just Checking:- $($TestBDSStatus)"
            }else {
                Write-Verbose "The Spatiotemporal Big Data Store is already started."
            }
        }

        if($DataStoreTypes -icontains "Relational"){
            $CurrPITRState = Get-PITRState -URL $DataStoreBaseURL -Referer $Referer -Verbose
            Write-Verbose "Current PITR state is $CurrPITRState. Requested $PITRState"
            if($PITRState -ine $CurrPITRState) {
                Update-PITRState -PITRState $PITRState -URL $DataStoreBaseURL -Referer $Referer -Verbose
            }
        }
    }elseif($Ensure -ieq 'Absent') {        
        throw "ArcGIS_DataStore unregister method not implemented!"
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
        $Version,

        [parameter(Mandatory = $false)]    
        [System.String]
        $DatastoreMachineHostName,

		[parameter(Mandatory = $true)]
		[System.String]
		$ServerHostName,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

        [System.String]
		$ContentDirectory,

        [System.Array]
        $DataStoreTypes,

        [System.Boolean]
        $IsTileCacheDataStoreClustered = $false,

        [System.Boolean]
        $IsObjectDataStoreClustered = $false,

        [System.Boolean]
        $IsGraphStoreClustered = $false,
        
        [System.Boolean]
        $EnableFailoverOnPrimaryStop = $false,
        
        [parameter(Mandatory = $False)]
        [ValidateSet("Enabled","Disabled")]
        $PITRState = "Disabled",

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $UseCloudRelationalStore = $False,

        [Parameter(Mandatory=$false)]
        [ValidateSet('AzureFlexiblePostgreSQLDatabase','AWSRDSPostgreSQLDatabase','AWSAuroraPostgreSQLDatabase','None')]
        [System.String]
        $CloudRelationalStoreType = 'None',

        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalDatabasePort,

        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalDatabaseURI,

        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalDatabaseReadonlyURI,   

        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalProxyPort,

        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalProxyURI,
        
        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalRegion,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $CloudRelationalDatabaseAdminUser,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $CloudRelationalSDEUser
    )
    

    $result = $true
    
    $MachineFQDN = if($DatastoreMachineHostName){ Get-FQDN $DatastoreMachineHostName }else{ Get-FQDN $env:COMPUTERNAME }
    $Referer = "https://$($MachineFQDN):2443"
    
    $DataStoreInstallDirectory = (Get-ArcGISComponentVersionAndInstallDirectory -ComponentName 'DataStore').InstallDir

    if($DataStoreTypes -icontains "Relational"){
        $PropertiesFilePath = Join-Path $DataStoreInstallDirectory 'framework\etc\datastore.properties'
        $FailoverPropertyName = 'failover_on_primary_stop'
        $FailoverEnabledString = Get-PropertyFromPropertiesFile -PropertiesFilePath $PropertiesFilePath -PropertyName $FailoverPropertyName
        Write-Verbose "Current value of property $FailoverPropertyName is $FailoverEnabledString"
        $IsFailoverEnabled = ($FailoverEnabledString -ieq 'true')
        $ExpectedFailoverEnabledString = if($EnableFailoverOnPrimaryStop){ 'true' }else{ 'false' }
        if($IsFailoverEnabled -ine $EnableFailoverOnPrimaryStop){
            $result = $False
            Write-Verbose "Property Value for '$FailoverPropertyName' is not set to expected value '$ExpectedFailoverEnabledString'"
        } else {
            Write-Verbose "Property value '$FailoverEnabledString' for '$FailoverPropertyName' matches expected value of '$ExpectedFailoverEnabledString'"
        }
    }

    
    $ServerFQDN = Get-FQDN $ServerHostName
    $DataStoreBaseURL = 'https://localhost:2443/arcgis'
    if($result) {
        $ServerBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName "Server" -FQDN $ServerFQDN
        Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName "Server" -MaxWaitTimeInSeconds 90 -SleepTimeInSeconds 5 -Verbose
        $token = Get-ServerToken -URL $ServerBaseUrl -Credential $SiteAdministrator -Referer $Referer 

        $RegisterOrConfigureDataStoreArgs = @{
            ServerBaseURL = $ServerBaseUrl
            Token = $token.token
            Referer = $Referer
            DataStoreTypes = $DataStoreTypes
            MachineFQDN = $MachineFQDN
            DataStoreBaseURL = $DataStoreBaseURL
            DataStoreContentDirectory = $ContentDirectory
            ServerSiteAdminCredential = $SiteAdministrator
            IsTileCacheDataStoreClustered = $IsTileCacheDataStoreClustered
            IsObjectDataStoreClustered = $IsObjectDataStoreClustered
            IsGraphStoreClustered = $IsGraphStoreClustered
            Version = $Version
            DataStoreInstallDirectory = $DataStoreInstallDirectory
            UseCloudRelationalStore = $UseCloudRelationalStore
        }

        $DatastoresToRegisterOrConfigure = Get-DataStoreTypesToRegisterOrConfigure @RegisterOrConfigureDataStoreArgs

        if($DatastoresToRegisterOrConfigure.Count -gt 0){
            $result = $false
        }else{
            if(($DataStoreTypes -icontains "SpatioTemporal") -and -not($DatastoresToRegisterOrConfigure -icontains "SpatioTemporal")){
                $resultSpatioTemporal = Test-SpatiotemporalBigDataStoreStarted -ServerBaseURL $ServerBaseUrl -Token $token.token -Referer $Referer -MachineFQDN $MachineFQDN -Verbose
                if($resultSpatioTemporal) {
                    Write-Verbose 'Big data store is started'
                }else {
                    $result = $false
                    Write-Verbose 'Big data store is not started'
                }
            }
        }
    } 

    if($result) {
        if(($DataStoreTypes -icontains "Relational")) {
            $CurrPITRState = Get-PITRState -URL $DataStoreBaseURL -Referer $Referer -Verbose
            Write-Verbose "Current PITR state is $CurrPITRState"
            if($PITRState -ine $CurrPITRState){
                Write-Verbose "Current PITR state does not match requested status $PITRState"
                $result = $false
            }
        }
    }

    if($Ensure -ieq 'Present') {
        $result
    }elseif($Ensure -ieq 'Absent') {        
        -not($result)
    }
}

function Invoke-RegisterOrConfigureDataStore
{
    [CmdletBinding()]
    param(
        [System.String]
        $Version,

        [System.String]
        $DataStoreBaseURL,

        [System.Management.Automation.PSCredential]
        $ServerSiteAdminCredential, 

        [System.String]
        $ServerBaseUrl, 

        [System.String]
        $DataStoreContentDirectory, 

        [System.Int32]
        $MaxAttempts = 5, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $MachineFQDN,
        
        [System.Array]
        $DataStoreTypes,

        [System.Boolean]
        $IsTileCacheDataStoreClustered,

        [System.Boolean]
        $IsObjectDataStoreClustered,

        [System.Boolean]
        $IsGraphStoreClustered,

        [System.String]
        $DataStoreInstallDirectory,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $UseCloudRelationalStore = $False,

        [Parameter(Mandatory=$false)]
        [ValidateSet('AzureFlexiblePostgreSQLDatabase','AWSRDSPostgreSQLDatabase','AWSAuroraPostgreSQLDatabase', 'None')]
        [System.String]
        $CloudRelationalStoreType = 'None',

        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalDatabasePort,

        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalDatabaseURI,

        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalDatabaseReadonlyURI,    

        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalProxyPort,

        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalProxyURI,
        
        [Parameter(Mandatory=$false)]
        [System.String]
        $CloudRelationalRegion,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $CloudRelationalDatabaseAdminUser,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $CloudRelationalSDEUser
    )

    Write-Verbose "Version of DataStore is $Version"
    if(-not($DataStoreContentDirectory)) { 
        throw "Must specify 'DataStoreContentDirectory'" 
    }

    $featuresJson = @{}
    
    if($DataStoreTypes -icontains 'Relational') {
        $featuresJson.add("feature.egdb",$true)
        Write-Verbose "Adding Relational as a data store type"
    }
    if($DataStoreTypes -icontains 'TileCache') {
        $featuresJson.add("feature.nosqldb",$true)
        Write-Verbose "Adding Tile Cache as a data store type"
    }
    if($DataStoreTypes -icontains 'SpatioTemporal') {
        $featuresJson.add("feature.bigdata",$true)
        Write-Verbose "Adding SpatioTemporal as a data store type"
    }
    if($DataStoreTypes -icontains 'GraphStore') {
        $featuresJson.add("feature.graphstore",$true)
        Write-Verbose "Adding GraphStore as a data store type"
    }
    if($DataStoreTypes -icontains 'ObjectStore') {
        $featuresJson.add("feature.ozobjectstore",$true)
        Write-Verbose "Adding ObjectStore as a data store type"
    }

	$dsSettings = @{
		directory = $DataStoreContentDirectory.Replace('\\', '\').Replace('\\', '\'); 
		features = $featuresJson;
	}

    if($DataStoreTypes -icontains "Relational" -and $UseCloudRelationalStore){
        $providerName = $null
        $serviceName = $null

        switch ($CloudRelationalStoreType) {
            'AzureFlexiblePostgreSQLDatabase' {
                $providerName = 'AZURE'
                $serviceName = 'Azure PostgreSQL'
            }
            'AWSRDSPostgreSQLDatabase' {
                $providerName = 'AWS'
                $serviceName = 'AWS RDS for PostgreSQL'
            }
            'AWSAuroraPostgreSQLDatabase' {
                $providerName = 'AWS'
                $serviceName = 'AWS Aurora for PostgreSQL'
            }
            default {
                throw "Unsupported cloud relational store type '$CloudRelationalStoreType'."
            }
        }

        $connection = @{
            region = $CloudRelationalRegion
            dbUri = $CloudRelationalDatabaseURI
            dbPort = $CloudRelationalDatabasePort
            credential = @{
                type = 'databaseUser'
                databaseUsers = @{
                    adminUser = @{
                        authType = 'PASSWORD'
                        name = $CloudRelationalDatabaseAdminUser.UserName
                        password = $CloudRelationalDatabaseAdminUser.GetNetworkCredential().Password
                    }
                }
            }
        }

        if ($CloudRelationalProxyURI -and $CloudRelationalProxyPort) {
            $connection['proxyUri'] = $CloudRelationalProxyURI
            $connection['proxyPort'] = $CloudRelationalProxyPort
        }

        if ($CloudRelationalSDEUser) {
            $connection['credential']['databaseUsers']['sdeUser'] = @{
                authType = 'PASSWORD'
                name = $CloudRelationalSDEUser.UserName
                password = $CloudRelationalSDEUser.GetNetworkCredential().Password
            }
        }

        if ($CloudRelationalStoreType -eq 'AWSAuroraPostgreSQLDatabase' -and `
            -not [string]::IsNullOrWhiteSpace($CloudRelationalDatabaseReadonlyURI)) {
            $connection['dbReadonlyUri'] = $CloudRelationalDatabaseReadonlyURI
        }

        $CloudRelationalStoreObject = @{
            name = $providerName
            cloudServices = @(
                @{
                    name = $serviceName
                    category = 'databases'
                    type = 'relationalStore'
                    instanceProvided = $true
                    usage = "DEFAULT"
                    connection = $connection
                }
            )
        }

        $CloudRelationalStoreJson = (ConvertTo-Json -Compress -InputObject $CloudRelationalStoreObject -Depth 10)
        $dsSettings.add("storeSetting.relational", @{
            cloudDbProvider = $CloudRelationalStoreJson
        })

        #$dsSettings.add("referer",$Referer)
    }


	if($DataStoreTypes -icontains "TileCache" -and $IsTileCacheDataStoreClustered){
        $dsSettings.add("storeSetting.tileCache",@{deploymentMode="cluster"})
        $dsSettings.add("referer",$Referer)
    }

    if($DataStoreTypes -icontains "ObjectStore" -and ([version]$Version -ge "11.0") -and $IsObjectDataStoreClustered){
        $dsSettings.add("storeSetting.objectStore",@{deploymentMode="cluster"})
        $dsSettings.add("referer",$Referer)
    }

    if($DataStoreTypes -icontains "GraphStore" -and ([version]$Version -ge "11.5")){
        if($IsGraphStoreClustered){
            $dsSettings.add("storeSetting.graphStore",@{deploymentMode="cluster"})
        }else{
            $dsSettings.add("storeSetting.graphStore",@{deploymentMode="singleInstance"})
        }
        $dsSettings.add("referer",$Referer)
    }    

    $WebParams = @{ 
                    username = $ServerSiteAdminCredential.UserName
                    password = $ServerSiteAdminCredential.GetNetworkCredential().Password
                    serverURL = $ServerBaseURL
                    dsSettings = (ConvertTo-Json $dsSettings -Compress)
                    f = 'json'
                }
   
    Write-Verbose "Register DataStore at $DataStoreBaseURL with DataStore Content directory at $DataStoreContentDirectory for server $ServerBaseURL"
   
    [bool]$Done = $false
    [System.Int32]$NumAttempts = 1
    while(-not($Done)) {
        Write-Verbose "Register DataStore Attempt $NumAttempts"
        [bool]$failed = $false
        $response = $null
        try {
            $DatastoresToRegisterFlag = $true
            if($NumAttempts -gt 1) {
                Write-Verbose "Checking if datastore is registered"
                $DSTypesToArgs = @{
                    ServerBaseURL = $ServerBaseURL
                    Token = $Token
                    Referer = $Referer
                    DataStoreTypes = $DataStoreTypes
                    MachineFQDN = $MachineFQDN
                    DataStoreBaseURL = $DataStoreBaseURL
                    ServerSiteAdminCredential = $ServerSiteAdminCredential
                    IsTileCacheDataStoreClustered = $IsTileCacheDataStoreClustered
                    IsObjectDataStoreClustered = $IsObjectDataStoreClustered
                    IsGraphStoreClustered = $IsGraphStoreClustered
                    DataStoreContentDirectory = $DataStoreContentDirectory
                    Version = $Version
                    DataStoreInstallDirectory = $DataStoreInstallDirectory
                    UseCloudRelationalStore = $UseCloudRelationalStore
                }

                $DatastoresToRegisterOrConfigure = Get-DataStoreTypesToRegisterOrConfigure @DSTypesToArgs

                $DatastoresToRegisterFlag = ($DatastoresToRegisterOrConfigure.Count -gt 0)
            }

            if($DatastoresToRegisterFlag) {
                Write-Verbose "Register DataStore on Machine $MachineFQDN"    
                $StartTime = get-date

                $DataStoreConfigureUrl = $DataStoreBaseURL.TrimEnd('/') + '/datastoreadmin/configure'    
                $response = Invoke-ArcGISWebRequest -Url $DataStoreConfigureUrl -HttpFormParameters $WebParams -Referer $Referer -TimeOutSec 600 -Verbose
                $RunTime = New-TimeSpan -Start $StartTime -End (get-date) 
                Write-Verbose "Run time was $($RunTime.Hours) hours, $($RunTime.Minutes) minutes, $($RunTime.Seconds) seconds"
                if($response.error) {
                    Write-Verbose "Error Response - $($response.error | ConvertTo-Json)"
                    throw [string]::Format("ERROR: failed. {0}" , $response.error.message)
                }
            }
        }
        catch
        {
            Write-Verbose "[WARNING]:- $_"
            $failed = $true
        }
        if($failed -or $response.error){ 
            if($NumAttempts -ge $MaxAttempts) {
                throw "Register Data Store Failed after multiple attempts. $($response.error)"
            }else{
                Write-Verbose "Attempt [$NumAttempts] Failed. Retrying after 45 seconds"
                Start-Sleep -Seconds 45
            } 
        }else {
            $Done = $true
        }         
        $NumAttempts++
    }
}

function Get-DataStoreTypesToRegisterOrConfigure
{
    [CmdletBinding()]
    param(
        [System.String]
        $Version,

        [System.String]
        $ServerBaseURL, 

        [System.String]
        $DataStoreBaseURL,

        [System.Management.Automation.PSCredential]
        $ServerSiteAdminCredential, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.Array]
        $DataStoreTypes, 
        
        [System.String]
        $MachineFQDN,

        [System.Boolean]
        $IsTileCacheDataStoreClustered,

        [System.Boolean]
        $IsObjectDataStoreClustered,

        [System.Boolean]
        $IsGraphStoreClustered,

        [System.String]
        $DataStoreContentDirectory,

        [System.String]
        $DataStoreInstallDirectory,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $UseCloudRelationalStore = $False
    )

    $DataStoreInfo = Get-DataStoreInfo -URL $DataStoreBaseURL -ServerSiteAdminCredential $ServerSiteAdminCredential `
                                        -ServerSiteUrl $ServerBaseURL -Referer $Referer 

    $DatastoresToRegister = @()
    foreach($dstype in $DataStoreTypes){
        Write-Verbose "Checking if $dstype Datastore is registered"
        $dsTestResult = $false
        if($dstype -ieq 'Relational'){
            $dsTestResult = $DataStoreInfo.relational.registered
        }elseif($dstype -ieq 'TileCache') {
            $dsTestResult = $DataStoreInfo.tileCache.registered
        }elseif($dstype -ieq 'SpatioTemporal'){
            $dsTestResult = $DataStoreInfo.spatioTemporal.registered
        }elseif($dstype -ieq 'GraphStore'){
            $dsTestResult = $DataStoreInfo.graphStore.registered
        }elseif($dstype -ieq 'ObjectStore'){
            if($DataStoreInfo.currentVersion -ieq "11.0.0" -or $DataStoreInfo.currentVersion -ieq "11.1.0"){
                $ObjectStoreConfigFile = Join-Path $DataStoreContentDirectory "etc\ozobjectstore-config.json"
                if(Test-Path $ObjectStoreConfigFile){
                    $ObjectConfig = (Get-Content $ObjectStoreConfigFile | ConvertFrom-Json)
                    $dsTestResult = ($ObjectConfig.'datastore.registered') -ieq $True
                }else{
                    $dsTestResult = $False
                }
            }else{
                $dsTestResult = ($DataStoreInfo.objectStore.registered -and -not($DataStoreInfo.objectStore.isCloudObjectStore))
            }
        }

        $ServerArgs = @{
            ServerBaseURL = $ServerBaseURL
            Token = $Token
            Referer = $Referer
            Type = "$dstype"
            MachineFQDN = $MachineFQDN
            IsTileCacheDataStoreClustered = $IsTileCacheDataStoreClustered
            IsObjectDataStoreClustered = $IsObjectDataStoreClustered
            IsGraphStoreClustered = $IsGraphStoreClustered
            Version = $Version
            DataStoreInstallDirectory = $DataStoreInstallDirectory
            UseCloudRelationalStore = $UseCloudRelationalStore
        }
        
        $serverTestResult = Test-DataStoreRegistered @ServerArgs -Verbose

        if($dsTestResult -and $serverTestResult){
            Write-Verbose "The machine with FQDN '$MachineFQDN' already participates in a '$dstype' data store"
        }else{
            $DatastoresToRegister += $dstype
            Write-Verbose "The machine with FQDN '$MachineFQDN' does NOT participates in a registered '$dstype' data store"
        }
    }

    $DatastoresToRegister
}

function Test-DataStoreRegistered
{
    [CmdletBinding()]
    param(
        [System.String]
        $Version,

        [System.String]
        $ServerBaseURL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $Type, 
        
        [System.String]
        $MachineFQDN,

        [System.Boolean]
        $IsTileCacheDataStoreClustered,

        [System.Boolean]
        $IsObjectDataStoreClustered,

        [System.Boolean]
        $IsGraphStoreClustered,

        [System.String]
        $DataStoreInstallDirectory,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $UseCloudRelationalStore = $False
    )

    $result = $false

    $items = Find-DataItems -URL $ServerBaseURL -Token $Token -Referer $Referer -Type $Type -IsArcGISDataStore -Verbose
    $registered = ($items | Measure-Object).Count -gt 0
    if($registered){
        $DB = ($items | Select-Object -First 1)
        $Machines = Get-DataStoreMachines -URL $ServerBaseURL -Token $Token -Referer $Referer -DataStorePath $DB.path -Verbose
        $result = ($Machines | Where-Object { $_.name -ieq $MachineFQDN } | Measure-Object).Count -gt 0

        if($result -and ($Type -like "Relational") -and $UseCloudRelationalStore){
            if($null -eq $DB.info.cloudDbConfig){
                throw "[ERROR] Relational Store cannot be converted to Cloud Relational Store."
            }else{
                Write-Verbose "Relational Store is already configured to use Cloud Relational Store."
            }
        }

        if($result -and ($Type -like "TileCache")){
            $tcArchTerminology = "primaryStandby"
            if($IsTileCacheDataStoreClustered){
                if($DB.info.architecture -ieq $tcArchTerminology){
                    $result = $false
                }else{
                    Write-Verbose "Tilecache Architecture is already set to Cluster."
                }    
            }else{
                if($DB.info.architecture -ieq $tcArchTerminology){
                    Write-Verbose "Tilecache Architecture is already set to $($tcArchTerminology)."
                }else{
                    #$result = $false
                    Write-Verbose "Tilecache Architecture is set to Cluster. Cannot be converted to $($tcArchTerminology)."
                }
            }
        }

        if($result -and ($Type -like "ObjectStore")){
            if($IsObjectDataStoreClustered){
                if($DB.info.deployMode -ieq "singleInstance"){ 
                    throw "[ERROR] Object store architecture is already set to Single Instance. Cannot be converted to cluster."
                }else{
                    Write-Verbose "Object store architecture is already set to Cluster."
                }
            }else{
                if($DB.info.deployMode -ieq "singleInstance"){
                    Write-Verbose "Object store Architecture is already set to Single Instance."
                }else{
                    #$result = $false
                    throw "[ERROR] Object store Architecture is set to Cluster. Cannot be converted to Single Instance."
                }
            }
        }

        if($result -and ($Type -like "GraphStore")){
            if([version]$Version -ge "11.5"){
               if($IsGraphStoreClustered){
                    if($DB.info.deploymentMode -ieq "singleInstance"){ 
                        Write-Verbose "Graph store architecture is already set to Single Instance. A backup location needs to be configured to be converted to Cluster mode."
                        # Check if backup location is configured
                        $GraphStoreBackupLocations = Get-DataStoreBackupLocation -DataStoreType "GraphStore" -DataStoreInstallDirectory $DataStoreInstallDirectory -Verbose
                        $BackupLocation = ($GraphStoreBackupLocations | Select-Object -First 1 )
                        if($null -eq $BackupLocation){
                            # if only one machine is present, don't throw an error, just add a warning. 
                            # If multiple machines are present, throw an error.
                            $NumberOfGraphStoreMachines = $DB.info.machines.Count
                            if($NumberOfGraphStoreMachines -eq 1){
                                Write-Verbose "[WARNING] Graph store backup location is not configured."
                            }else{
                                throw "[ERROR] Graph store backup location is not configured. Cannot be converted to Cluster mode without a backup location."
                            }
                        }
                    }else{
                        Write-Verbose "Graph store architecture is already set to Cluster."
                    }
                }else{
                    if($DB.info.deploymentMode -ieq "singleInstance"){
                        Write-Verbose "Graph store Architecture is already set to Single Instance."
                    }else{
                        #$result = $false
                        throw "[ERROR] Graph store Architecture is set to Cluster. Cannot be converted to Single Instance."
                    }
                }
            }
        }
    }

    $result
}

function Get-NumberOfTileCacheDatastoreMachines
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerBaseURL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer
    )

    $items = Find-DataItems -URL $ServerBaseURL -Token $Token -Referer $Referer -Type "TileCache" -IsArcGISDataStore -Verbose
    $DB = ( $items | Select-Object -First 1)
    $Machines = Get-DataStoreMachines -URL $ServerBaseURL -Token $Token -Referer $Referer -DataStorePath $DB.path -Verbose
    return ($Machines | Measure-Object).Count
}


function Test-SpatiotemporalBigDataStoreStarted
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [System.String]
        $ServerBaseURL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $MachineFQDN
    )

    $items = Find-DataItems -URL $ServerBaseURL -Token $Token -Referer $Referer -Type "SpatioTemporal" -IsArcGISDataStore -Verbose
    $dataStorePath = $null
    if(@($items).Count -gt 0) {
        $DB = ($items | Select-Object -First 1)
        $dataStorePath = $DB.path
    } else {
        throw "SpatioTemporal Data Store not found."
    }

    Write-Verbose "Data Store Path:- $dataStorePath"
    try {    
        $response = Invoke-DataStoreMachineOperation -URL $ServerBaseURL -Token $Token -Referer $Referer -DataStorePath $dataStorePath -MachineFQDN $MachineFQDN -OperationName "validate"
        $n = $response.nodes | Where-Object {($_.name -ieq (Resolve-DnsName -Type ANY $env:ComputerName).IPAddress) -or ($_.name -ieq $MachineFQDN)}
        #Write-Verbose "Machine Ip --> $($n.name)"
        $n -and $response.isHealthy -ieq 'True'
    }
    catch {
        Write-Verbose "[WARNING] Attempt to check if SpatioTemporal Data Store is started returned error:-  $_"
        $false
    }
}

function Start-SpatiotemporalBigDataStore
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerBaseURL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $MachineFQDN
    )

    $items = Find-DataItems -URL $ServerBaseURL -Token $Token -Referer $Referer -Type "SpatioTemporal" -IsArcGISDataStore -Verbose

    $dataStorePath = $null
    if(@($items).Count -gt 0) {
        $DB = ($items | Select-Object -First 1)
        $dataStorePath = $DB.path
    } else {
        throw "SpatioTemporal Data Store not found."
    }

    Write-Verbose "Data Store Path:- $dataStorePath"
    return Invoke-DataStoreMachineOperation -URL $ServerBaseURL -Token $Token -Referer $Referer -DataStorePath $dataStorePath -MachineFQDN $MachineFQDN -OperationName "start"
}

Export-ModuleMember -Function *-TargetResource