$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

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
    .PARAMETER IsStandby
        Boolean to Indicate if the datastore (Relational only) being configured with a GIS Server is a Standby Server.(Only Supports 1 StandBy Server)
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

        [System.Boolean]
		$IsStandby,

        [System.Array]
        $DataStoreTypes,
        
        [System.Boolean]
        $IsTileCacheDataStoreClustered = $false,

        [System.Boolean]
        $IsObjectDataStoreClustered = $false,
        
        [System.Boolean]
		$EnableFailoverOnPrimaryStop = $false,

        [parameter(Mandatory = $False)]
        [ValidateSet("Enabled","Disabled")]
        $PITRState = "Disabled"
	)
    

	$null
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

        [System.Boolean]
		$IsStandby,

        [System.Array]
        $DataStoreTypes,

        [System.Boolean]
        $IsTileCacheDataStoreClustered = $false,

        [System.Boolean]
        $IsObjectDataStoreClustered = $false,
        
        [System.Boolean]
        $EnableFailoverOnPrimaryStop = $false,

        [parameter(Mandatory = $False)]
        [ValidateSet("Enabled","Disabled")]
        $PITRState = "Disabled"
	)

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    if($Ensure -ieq 'Present') {
        $MachineFQDN = if($DatastoreMachineHostName){ Get-FQDN $DatastoreMachineHostName }else{ Get-FQDN $env:COMPUTERNAME }
        $Referer = "https://$($MachineFQDN):2443"

        $ServiceName = 'ArcGIS Data Store'
        $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
        $DataStoreInstallDirectory = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir.TrimEnd('\')  

        $RestartRequired = $false
        $expectedHostIdentifierType = if($MachineFQDN -as [ipaddress]){ 'ip' }else{ 'hostname' }
        $hostidentifier = Get-ConfiguredHostIdentifier -InstallDir $DataStoreInstallDirectory
        $hostidentifierType = Get-ConfiguredHostIdentifierType -InstallDir $DataStoreInstallDirectory
        Write-Verbose "Current value of property hostidentifier is '$hostidentifier' and hostidentifierType is '$hostidentifierType'"
        if(($hostidentifier -ieq $MachineFQDN) -and ($hostidentifierType -ieq $expectedHostIdentifierType)) {
            Write-Verbose "Configured host identifier '$hostidentifier' matches expected value '$MachineFQDN' and host identifier type '$hostidentifierType' matches expected value '$expectedHostIdentifierType'"        
        } else {
            Write-Verbose "Configured host identifier '$hostidentifier' does not match expected value '$MachineFQDN' or host identifier type '$hostidentifierType' does not match expected value '$expectedHostIdentifierType'. Setting it"
            if(Set-ConfiguredHostIdentifier -InstallDir $DataStoreInstallDirectory -HostIdentifier $MachineFQDN -HostIdentifierType $expectedHostIdentifierType) { 
                # Need to restart the service to pick up the hostidentifier 
                Write-Verbose "Hostidentifier.properties file was modified. Need to restart the '$ServiceName' service to pick up changes"
                $RestartRequired = $true 
            }
        }

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
                Write-Verbose "Property '$FailoverPropertyName' will be modified. Need to restart the '$ServiceName' service to pick up changes"
                $FailoverPropertyModified = $true
                $RestartRequired = $true
            } else {
                Write-Verbose "Property value '$FailoverEnabledString' for '$FailoverPropertyName' matches expected value of '$($ExpectedFailoverEnabledString)'"
            }	
        }

        if($RestartRequired){
            Write-Verbose "Stop Service '$ServiceName' before applying property change"
            Stop-Service -Name $ServiceName -Force 
            Write-Verbose 'Stopping the service' 
            Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Stopped'
            Write-Verbose 'Stopped the service'
            
            if($FailoverPropertyModified -and ($DataStoreTypes -icontains "Relational")){
                Write-Verbose "Property '$FailoverPropertyName' will be changed to $ExpectedFailoverEnabledString in 'datastore.properties' file"
                Set-PropertyFromPropertiesFile -PropertiesFilePath $PropertiesFilePath -PropertyName $FailoverPropertyName -PropertyValue $ExpectedFailoverEnabledString -Verbose
                Write-Verbose "datastore.properties file was modified."
            }
            
            Write-Verbose "Restarting Service '$ServiceName' to pick up property change"
            Start-Service $ServiceName 
            Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Running'
            Write-Verbose "Restarted Service '$ServiceName'"
            
            Wait-ForUrl -Url "https://$($MachineFQDN):2443/arcgis/datastoreadmin/configure?f=json" -MaxWaitTimeInSeconds 180 -SleepTimeInSeconds 5 -HttpMethod 'GET' -Verbose
        }else {
            Write-Verbose "Properties are up to date. No need to restart the 'ArcGIS Data Store' Service"
        }

        $ServerFQDN = Get-FQDN $ServerHostName
        $ServerUrl = "https://$($ServerFQDN):6443"   
        Wait-ForUrl -Url "$ServerUrl/arcgis/admin" -MaxWaitTimeInSeconds 90 -SleepTimeInSeconds 5 -Verbose
        $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer 

        if(($DataStoreTypes -icontains "Relational") -or ($DataStoreTypes -icontains "TileCache")){ 
            Write-Verbose "Ensure the Publishing GP Service (Tool) is started on Server"
            $PublishingToolsPath = 'System/PublishingTools.GPServer'
            $Attempts  = 1
            $MaxAttempts = 5
            $SleepTimeInSeconds = 20
            while ($true)
            {
                Write-Verbose "Checking state of Service '$PublishingToolsPath'. Attempt # $Attempts"    
                $serviceStatus = Get-ServiceStatus -ServerURL $ServerUrl -Token $token.token -Referer $Referer -ServicePath $PublishingToolsPath
                Write-Verbose "Service Status :- $serviceStatus"
                
                if($serviceStatus.configuredState -ieq 'STARTED' -and $serviceStatus.realTimeState -ieq 'STARTED'){
                    Write-Verbose "State of Service '$PublishingToolsPath' is STARTED"
                    break
                }else{
                    if(($serviceStatus.configuredState -ieq 'STARTED' -or $serviceStatus.realTimeState -ine 'STARTED') -or ($serviceStatus.configuredState -ine 'STARTED' -or $serviceStatus.realTimeState -ieq 'STARTED')){
                        Write-Verbose "Waiting $SleepTimeInSeconds seconds for Service '$PublishingToolsPath' to be started"
                        Start-Sleep -Seconds $SleepTimeInSeconds
                    }else{
                        Write-Verbose "Trying to Start Service $PublishingToolsPath"
                        Start-ServerService -ServerURL $ServerUrl -Token $token.token -Referer $Referer -ServicePath $PublishingToolsPath
                        Start-Sleep -Seconds $SleepTimeInSeconds
                    }
                }
                
                $serviceStatus = Get-ServiceStatus -ServerURL $ServerUrl -Token $token.token -Referer $Referer -ServicePath $PublishingToolsPath
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

        $DataStoreAdminEndpoint = 'https://localhost:2443/arcgis/datastoreadmin'
        $DatastoresToRegisterOrConfigure = Get-DataStoreTypesToRegisterOrConfigure -ServerURL $ServerUrl -Token $token.token -Referer $Referer `
                                    -DataStoreTypes $DataStoreTypes -MachineFQDN $MachineFQDN `
                                    -DataStoreAdminEndpoint $DataStoreAdminEndpoint -ServerSiteAdminCredential $SiteAdministrator `
                                    -IsTileCacheDataStoreClustered $IsTileCacheDataStoreClustered `
                                    -IsObjectDataStoreClustered $IsObjectDataStoreClustered -DataStoreContentDirectory $ContentDirectory
        
        #Check if the TileCache mode is correct, only for 10.8.1 and above                                                            
        if($DatastoresToRegisterOrConfigure.Count -gt 0){
            $DatastoresToRegisterOrConfigureString = ($DatastoresToRegisterOrConfigure -join ',')
            Write-Verbose "Registering or configuring datastores $DatastoresToRegisterOrConfigureString"
            Invoke-RegisterOrConfigureDataStore -DataStoreAdminEndpoint $DataStoreAdminEndpoint -ServerSiteAdminCredential $SiteAdministrator `
                                -ServerUrl $ServerUrl -DataStoreContentDirectory $ContentDirectory -ServerAdminUrl "$ServerUrl/arcgis/admin" `
                                -Token $token.token -Referer $Referer -MachineFQDN $MachineFQDN -DataStoreTypes $DataStoreTypes `
                                -IsTileCacheDataStoreClustered $IsTileCacheDataStoreClustered -DataStoreInstallDirectory $DataStoreInstallDirectory `
                                -IsObjectDataStoreClustered $IsObjectDataStoreClustered
        }

        if($DataStoreTypes -icontains "SpatioTemporal"){
            Write-Verbose "Checking if the Spatiotemporal Big Data Store has started."
            if(-not(Test-SpatiotemporalBigDataStoreStarted -ServerURL $ServerUrl -Token $token.token -Referer $Referer -MachineFQDN $MachineFQDN)) {
                Write-Verbose "Starting the Spatiotemporal Big Data Store."
                Start-SpatiotemporalBigDataStore -ServerURL $ServerUrl -Token $token.token -Referer $Referer -MachineFQDN $MachineFQDN
                $TestBDSStatus = Test-SpatiotemporalBigDataStoreStarted -ServerURL $ServerUrl -Token $token.token -Referer $Referer -MachineFQDN $MachineFQDN
                Write-Verbose "Just Checking:- $($TestBDSStatus)"
            }else {
                Write-Verbose "The Spatiotemporal Big Data Store is already started."
            }
        }

        if($DataStoreTypes -icontains "Relational"){
            $CurrPITRState = Get-PITRState -DataStoreAdminEndpoint $DataStoreAdminEndpoint -Referer $Referer -Verbose 
            Write-Verbose "Current PITR state is $CurrPITRState. Requested $PITRState"
            if($PITRState -ine $CurrPITRState) {
                Set-PITRState -PITRState $PITRState -DataStoreAdminEndpoint $DataStoreAdminEndpoint -Referer $Referer -Verbose
            }
        }
    }elseif($Ensure -ieq 'Absent') {        
        throw "ArcGIS_DataStore Deregister Method not implemented!"
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

        [System.Boolean]
		$IsStandby,

        [System.Array]
        $DataStoreTypes,

        [System.Boolean]
        $IsTileCacheDataStoreClustered = $false,

        [System.Boolean]
        $IsObjectDataStoreClustered = $false,
        
        [System.Boolean]
        $EnableFailoverOnPrimaryStop = $false,
        
        [parameter(Mandatory = $False)]
        [ValidateSet("Enabled","Disabled")]
        $PITRState = "Disabled"
    )
    

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $result = $true
    
    $MachineFQDN = if($DatastoreMachineHostName){ Get-FQDN $DatastoreMachineHostName }else{ Get-FQDN $env:COMPUTERNAME }
    $Referer = "https://$($MachineFQDN):2443"
    
    $ServiceName = 'ArcGIS Data Store'
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $DataStoreInstallDirectory = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir.TrimEnd('\')

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

    if($result) {
        $expectedHostIdentifierType = if($MachineFQDN -as [ipaddress]){ 'ip' }else{ 'hostname' }
        $hostidentifier = Get-ConfiguredHostIdentifier -InstallDir $DataStoreInstallDirectory
        $hostidentifierType = Get-ConfiguredHostIdentifierType -InstallDir $DataStoreInstallDirectory
        Write-Verbose "Current value of property hostidentifier is '$hostidentifier' and hostidentifierType is '$hostidentifierType'"
        if(($hostidentifier -ieq $MachineFQDN) -and ($hostidentifierType -ieq $expectedHostIdentifierType)) {
            Write-Verbose "Configured host identifier '$hostidentifier' matches expected value '$MachineFQDN' and host identifier type '$hostidentifierType' matches expected value '$expectedHostIdentifierType'"
        }else {
            Write-Verbose "Configured host identifier '$hostidentifier' does not match expected value '$MachineFQDN' or host identifier type '$hostidentifierType' does not match expected value '$expectedHostIdentifierType'. Setting it"
            $result = $false
        }
    }
    
    $ServerFQDN = Get-FQDN $ServerHostName
    $ServerUrl = "https://$($ServerFQDN):6443"
    if($result) {
        Wait-ForUrl -Url "$ServerUrl/arcgis/admin" -MaxWaitTimeInSeconds 90 -SleepTimeInSeconds 5 -Verbose
        $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer 
        
        $DataStoreAdminEndpoint = 'https://localhost:2443/arcgis/datastoreadmin'
        $DatastoresToRegisterOrConfigure = Get-DataStoreTypesToRegisterOrConfigure -ServerURL $ServerUrl -Token $token.token -Referer $Referer `
                                    -DataStoreTypes $DataStoreTypes -MachineFQDN $MachineFQDN `
                                    -DataStoreAdminEndpoint $DataStoreAdminEndpoint -ServerSiteAdminCredential $SiteAdministrator `
                                    -IsTileCacheDataStoreClustered $IsTileCacheDataStoreClustered `
                                    -IsObjectDataStoreClustered $IsObjectDataStoreClustered -DataStoreContentDirectory $ContentDirectory

        if($DatastoresToRegisterOrConfigure.Count -gt 0){
            $result = $false
        }else{
            if(($DataStoreTypes -icontains "SpatioTemporal") -and -not($DatastoresToRegisterOrConfigure -icontains "SpatioTemporal")){
                $resultSpatioTemporal = Test-SpatiotemporalBigDataStoreStarted -ServerURL $ServerUrl -Token $token.token -Referer $Referer -MachineFQDN $MachineFQDN -Verbose
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
            $CurrPITRState = Get-PITRState -DataStoreAdminEndpoint $DataStoreAdminEndpoint -Referer $Referer -Verbose
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
        $DataStoreAdminEndpoint,

        [System.Management.Automation.PSCredential]
        $ServerSiteAdminCredential, 

        [System.String]
        $ServerUrl, 

        [System.String]
        $DataStoreContentDirectory, 

        [System.Int32]
        $MaxAttempts = 5, 

        [System.String]
        $ServerAdminUrl, 

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

        [System.String]
        $DataStoreInstallDirectory
    )

    Write-Verbose "Version of DataStore is $Version"
    $VersionArray = $Version.Split('.')

    $ServerSiteUrl = $ServerURL.TrimEnd('/') + '/arcgis'

    if(!$DataStoreContentDirectory) { throw "Must Specify DataStoreContentDirectory" }

    $featuresJson = @{}
    if($DataStoreTypes) {
        foreach($dstype in $DataStoreTypes) {
            if($dstype -ieq 'Relational') {
		        $featuresJson.add("feature.egdb",$true)
                Write-Verbose "Adding Relational as a data store type"
            }
            elseif($dstype -ieq 'TileCache') {
		        $featuresJson.add("feature.nosqldb",$true)
                Write-Verbose "Adding Tile Cache as a data store type"
            }
            elseif($dstype -ieq 'SpatioTemporal') {
		        $featuresJson.add("feature.bigdata",$true)
                Write-Verbose "Adding SpatioTemporal as a data store type"
            }
            elseif($dstype -ieq 'GraphStore') {
		        $featuresJson.add("feature.graphstore",$true)
                Write-Verbose "Adding GraphStore as a data store type"
            }
            elseif($dstype -ieq 'ObjectStore') {
		        $featuresJson.add("feature.ozobjectstore",$true)
                Write-Verbose "Adding ObjectStore as a data store type"
            }
        }
    }

	$dsSettings = @{
		directory = $DataStoreContentDirectory.Replace('\\', '\').Replace('\\', '\'); 
		features = $featuresJson;
	}

	if($DataStoreTypes -icontains "TileCache" -and ($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -and (($VersionArray[1] -gt 8) -or ($Version -ieq "10.8.1")))) -and $IsTileCacheDataStoreClustered){
        $dsSettings.add("storeSetting.tileCache",@{deploymentMode="cluster"})
        $dsSettings.add("referer",$Referer)
    }

    if($DataStoreTypes -icontains "ObjectStore" -and ($VersionArray[0] -eq 11) -and $IsObjectDataStoreClustered){
        $dsSettings.add("storeSetting.objectStore",@{deploymentMode="cluster"})
        $dsSettings.add("referer",$Referer)
    }

    $WebParams = @{ 
                    username = $ServerSiteAdminCredential.UserName
                    password = $ServerSiteAdminCredential.GetNetworkCredential().Password
                    serverURL = $ServerSiteUrl
                    dsSettings = (ConvertTo-Json $dsSettings -Compress)
                    f = 'json'
                }
   
    $DataStoreConfigureUrl = $DataStoreAdminEndpoint.TrimEnd('/') + '/configure'    
    Write-Verbose "Register DataStore at $DataStoreAdminEndpoint with DataStore Content directory at $DataStoreContentDirectory for server $ServerSiteUrl"
   
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
                $DatastoresToRegisterOrConfigure = Get-DataStoreTypesToRegisterOrConfigure -ServerURL $ServerUrl -Token $Token `
                                            -Referer $Referer -DataStoreTypes $DataStoreTypes -MachineFQDN $MachineFQDN `
                                            -DataStoreAdminEndpoint $DataStoreAdminEndpoint -ServerSiteAdminCredential $ServerSiteAdminCredential `
                                            -IsTileCacheDataStoreClustered $IsTileCacheDataStoreClustered `
                                            -IsObjectDataStoreClustered $IsObjectDataStoreClustered -DataStoreContentDirectory $DataStoreContentDirectory

                $DatastoresToRegisterFlag = ($DatastoresToRegisterOrConfigure.Count -gt 0)
            }            
            if($DatastoresToRegisterFlag) {
                Write-Verbose "Register DataStore on Machine $MachineFQDN"    
                $StartTime = get-date 
                $response = Invoke-ArcGISWebRequest -Url $DataStoreConfigureUrl -HttpFormParameters $WebParams -Referer $Referer -TimeOutSec 600 -Verbose
                $RunTime = New-TimeSpan -Start $StartTime -End (get-date) 
                Write-Verbose "Execution time was $($RunTime.Hours) hours, $($RunTime.Minutes) minutes, $($RunTime.Seconds) seconds"
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

    # If we switch from primary standby to cluster mode at 10.8.1, add machine fails with @{code=500; message=Attempt to configure data 
    # store failed.\\nCaused by: This machine cannot be added to the 'tile cache' data store because it cannot access backup location(s) 
    # '[C:/arcgis/datastore/content/backup/tilecache/]' registered with that data store. Ensure that the listed locations are shared 
    # directories and that the ArcGIS Data Store account has permissions to them.; details=}
    # Includes a fix where we unregister the default backup location for 10.8.1 after the switch when only 1 machine is present
    if($DataStoreTypes -icontains "TileCache" -and ($Version -ieq "10.8.1") -and $IsTileCacheDataStoreClustered){
        if((Get-NumberOfTileCacheDatastoreMachines -ServerURL $ServerUrl -Token $Token -Referer $Referer) -eq 1){
            $TilecacheBackupLocations = Get-DataStoreBackupLocation -DataStoreType "TileCache" -DataStoreInstallDirectory $DataStoreInstallDirectory -Verbose
            $DefaultBackup = ($TilecacheBackupLocations | Where-Object { $_.IsDefault -ieq $true } | Select-Object -First 1 )
            if(($null -ne $DefaultBackup) -and -not([string]::IsNullOrEmpty($DefaultBackup.Location))){
                $PathInfo=[System.Uri]$DefaultBackup.Location;
                if(-not($PathInfo.IsUnc)){  
                    Write-Verbose "Unregistering backup location $($DefaultBackup.Location)"
                    Invoke-DataStoreConfigureBackupLocationTool -BackupLocationString "type=$($DefaultBackup.Type);name=$($DefaultBackup.Name)" `
                                                        -DataStoreInstallDirectory $DataStoreInstallDirectory `
                                                        -DataStoreType "TileCache" -OperationType "unregister" -Verbose 
                    Write-Verbose "Unregister of backup location $($DefaultBackup.Location) successful"
                }
            }
        }
    }
}
function Get-DataStoreTypesToRegisterOrConfigure
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerURL, 

        [System.String]
        $DataStoreAdminEndpoint,

        [System.Management.Automation.PSCredential]
        $ServerSiteAdminCredential, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $Type, 
        
        [System.Array]
        $DataStoreTypes, 
        
        [System.String]
        $MachineFQDN,

        [System.Boolean]
        $IsTileCacheDataStoreClustered,

        [System.Boolean]
        $IsObjectDataStoreClustered,

        [System.String]
        $DataStoreContentDirectory
    )

    $DataStoreInfo = Get-DataStoreInfo -DataStoreAdminEndpoint $DataStoreAdminEndpoint -ServerSiteAdminCredential $ServerSiteAdminCredential `
                                        -ServerSiteUrl "$ServerURL/arcgis" -Referer $Referer 

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
            $ObjectStoreConfigFile = Join-Path $DataStoreContentDirectory "etc\ozobjectstore-config.json"
            if(Test-Path $ObjectStoreConfigFile){
                $ObjectConfig = (Get-Content $ObjectStoreConfigFile | ConvertFrom-Json)
                $dsTestResult = ($ObjectConfig.'datastore.registered') -ieq $True
            }else{
                $dsTestResult = $False
            }
        }
        $serverTestResult = Test-DataStoreRegistered -ServerURL $ServerUrl -Token $Token -Referer $Referer -Type "$dstype" -MachineFQDN $MachineFQDN -IsTileCacheDataStoreClustered $IsTileCacheDataStoreClustered -IsObjectDataStoreClustered $IsObjectDataStoreClustered -Verbose

        if($dsTestResult -and $serverTestResult){
            Write-Verbose "The machine with FQDN '$MachineFQDN' already participates in a '$dstype' data store"
        }else{
            $DatastoresToRegister += $dstype
            Write-Verbose "The machine with FQDN '$MachineFQDN' does NOT participates in a registered '$dstype' data store"
        }
    }

    $DatastoresToRegister
}

function Get-DataStoreInfo
{
    [CmdletBinding()]
    param(
        [System.String]
        $DataStoreAdminEndpoint,
        
        [System.Management.Automation.PSCredential]
        $ServerSiteAdminCredential, 
        
        [System.String]
        $ServerSiteUrl,
        
        [System.String]
        $Referer
    )

    $WebParams = @{ 
                    f = 'json'
                    username = $ServerSiteAdminCredential.UserName
                    password = $ServerSiteAdminCredential.GetNetworkCredential().Password
                    serverURL = $ServerSiteUrl      
                    dsSettings = '{"features":{"feature.egdb":true,"feature.nosqldb":true,"feature.bigdata":true,"feature.graphstore":true,"feature.ozobjectstore":true}}'
                    getConfigureInfo = 'true'
                }       

   $DataStoreConfigureUrl = $DataStoreAdminEndpoint.TrimEnd('/') + '/configure'  
   Wait-ForUrl -Url "$($DataStoreConfigureUrl)?f=json" -MaxWaitTimeInSeconds 180 -SleepTimeInSeconds 5 -HttpMethod 'GET' -Verbose
   Invoke-ArcGISWebRequest -Url $DataStoreConfigureUrl -HttpFormParameters $WebParams -Referer $Referer -HttpMethod 'POST' -Verbose 
}

function Test-DataStoreRegistered
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
        $Type, 
        
        [System.String]
        $MachineFQDN,

        [System.Boolean]
        $IsTileCacheDataStoreClustered,

        [System.Boolean]
        $IsObjectDataStoreClustered
    )

    $result = $false

    if($Type -like "SpatioTemporal" -or $Type -like "TileCache" -or $Type -like "GraphStore"){
        $DBType ='nosql'
    }
    elseif($Type -like "ObjectStore"){
        $DBType = "cloudStore"
    }
    else{
        $DBType ='egdb'
    }   

    $DataItemsUrl = $ServerURL.TrimEnd('/') + '/arcgis/admin/data/findItems' 
    $response = Invoke-ArcGISWebRequest -Url $DataItemsUrl -HttpFormParameters  @{ f = 'json'; token = $Token; types = $DBType } -Referer $Referer -Verbose
    
    $registered= $($response.items | Where-Object { $_.provider -ieq 'ArcGIS Data Store' } | Measure-Object).Count -gt 0
    if($DBType -ieq 'nosql' -or $DBType -ieq 'cloudStore'){
        $registered = $($response.items | Where-Object { ($_.provider -ieq 'ArcGIS Data Store') -and ($_.info.dsFeature -ieq $Type) } | Measure-Object).Count -gt 0
    }

    if($registered){
        $DB = $($response.items | Where-Object { $_.provider -ieq 'ArcGIS Data Store' } | Select-Object -First 1)
        if($DBType -ieq 'nosql' -or $DBType -ieq 'cloudStore'){
            $DB = ($response.items | Where-Object { ($_.provider -ieq 'ArcGIS Data Store') -and ($_.info.dsFeature -ieq $Type) } | Select-Object -First 1)
        }

        $MachinesInDataStoreUrl = $ServerURL.TrimEnd('/') + '/arcgis/admin/data/items' + $DB.path + '/machines'
        $response = Invoke-ArcGISWebRequest -Url $MachinesInDataStoreUrl -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer -Verbose
        $result = ($response.machines | Where-Object { $_.name -ieq $MachineFQDN } | Measure-Object).Count -gt 0

        if($result -and ($Type -like "TileCache")){
            $VersionArray = $DB.info.storeRelease.Split(".")
            if(($VersionArray[0] -eq 11) -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 8) -or ($DB.info.storeRelease -ieq "10.8.1")){
                $tcArchTerminology = if(($VersionArray[0] -eq 11) -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 8)){ "primaryStandby" }else{ "masterSlave" } 
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
    }

    $result
}

function Get-NumberOfTileCacheDatastoreMachines
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerURL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer
    )

    $DataItemsUrl = $ServerURL.TrimEnd('/') + '/arcgis/admin/data/findItems' 
    $response = Invoke-ArcGISWebRequest -Url $DataItemsUrl -HttpFormParameters  @{ f = 'json'; token = $Token; types = 'nosql' } -Referer $Referer 
    $DB = ($response.items | Where-Object { ($_.provider -ieq 'ArcGIS Data Store') -and ($_.info.dsFeature -ieq "TileCache") } | Select-Object -First 1)
    $MachinesInDataStoreUrl = $ServerURL.TrimEnd('/') + '/arcgis/admin/data/items' + $DB.path + '/machines'
    $response = Invoke-ArcGISWebRequest -Url $MachinesInDataStoreUrl -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer 
    ($response.machines | Measure-Object).Count
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

function Stop-ServerService
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

   $ServiceStopOperationUrl = $ServerURL.TrimEnd('/') + '/arcgis/admin/services/' + $ServicePath.Trim('/') + '/stop' 
   Invoke-ArcGISWebRequest -Url $ServiceStopOperationUrl -HttpFormParameters  @{ f = 'json'; token = $Token } -Referer $Referer 
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

function Test-SpatiotemporalBigDataStoreStarted
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [System.String]
        $ServerURL, 

        [System.String]
        $Token, 

        [System.String]
        $Referer, 

        [System.String]
        $MachineFQDN
    )

   $DataItemsUrl = $ServerURL.TrimEnd('/') + '/arcgis/admin/data/findItems' 
   $response = Invoke-ArcGISWebRequest -Url $DataItemsUrl -HttpFormParameters @{ f = 'json'; token = $Token; types = 'nosql' }  -Referer $Referer    
   $dataStorePath = $null
   if($response.items -and $response.items.length -gt 0) {
        $done = $false
		$i = 0
		while(-not($done) -and ($i -lt $response.items.length)) {
                       $dsType = $response.items[$i].info.dsFeature
			if($dsType -ieq "spatioTemporal") {		
				Write-Verbose "SpatioTemporal DataStore $dataStorePath found"        
                $dataStorePath = $response.items[$i].path
                $done = $true
			}
			$i = $i + 1
		}
   } else {
       throw "Spatiotemporal Big DataStore not found in arcgis data items"
   }
   Write-Verbose "Data Store Path:- $dataStorePath"
   $Url = $ServerURL.TrimEnd('/') + '/arcgis/admin/data/items' + "$dataStorePath/machines/$MachineFQDN/validate/"
   Write-Verbose $Url
   try {    
    $response = Invoke-ArcGISWebRequest -Url $Url -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer -HttpMethod 'POST'
    $n = $response.nodes | Where-Object {($_.name -ieq (Resolve-DnsName -Type ANY $env:ComputerName).IPAddress) -or ($_.name -ieq $MachineFQDN)}
    Write-Verbose "Machine Ip --> $($n.name)"
    $n -and $response.isHealthy -ieq 'True'
   }
   catch {
    Write-Verbose "[WARNING] Attempt to check if Spatiotemporal Big DataStore is started returned error:-  $_"
    $false
   }
}

function Start-SpatiotemporalBigDataStore
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
        $MachineFQDN
    )

   $DataItemsUrl = $ServerURL.TrimEnd('/') + '/arcgis/admin/data/findItems' 
   $response = Invoke-ArcGISWebRequest -Url $DataItemsUrl -HttpFormParameters @{ f = 'json'; token = $Token; types = 'nosql' }  -Referer $Referer    
   $dataStorePath = $null
   if($response.items -and $response.items.length -gt 0) {
        $dataStorePath = $response.items[0].path
   } else {
       throw "Spatiotemporal Big DataStore not found in arcgis data items"
   }
   Write-Verbose "Data Store Path:- $dataStorePath"
   $Url = $ServerURL.TrimEnd('/') + '/arcgis/admin/data/items' + "$dataStorePath/machines/$MachineFQDN/start/"
   Invoke-ArcGISWebRequest -Url $Url -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer -HttpMethod 'POST' -Verbose
}

function Get-PITRState
{
    [CmdletBinding()]
    param(
        [System.String]
        $DataStoreAdminEndpoint,

        [System.String]
        $Referer
    )
    
    $result = $null
    $WebParams = @{ 
        f = 'json'
    }

    $DataStoreConfigurePITRUrl = $DataStoreAdminEndpoint.TrimEnd('/') + '/configurePITR'  
    Wait-ForUrl -Url "$($DataStoreConfigurePITRUrl)?f=json" -MaxWaitTimeInSeconds 180 -SleepTimeInSeconds 5 -HttpMethod 'GET' -Verbose
    $Response = Invoke-ArcGISWebRequest -Url $DataStoreConfigurePITRUrl -HttpFormParameters $WebParams -Referer $Referer -TimeOutSec 600 -HttpMethod "GET" -Verbose
    if($Response.status -ieq "success"){
        if($Response.pitrEnabled -ieq $True){
            $result = 'Enabled'
        }else {
            $result = 'Disabled'
        }
    }else{
        throw "[ERROR] Configure PITR web request returned an error."
    }
    
    $result  
}

function Set-PITRState
{
    [CmdletBinding()]
    param(
        [System.String]
        $DataStoreAdminEndpoint,

        [System.String]
        $Referer,

        [System.String]
        $PITRState
    )

    $WebParams = @{ 
        f = 'json'
        "enable-pitr" = if ($PITRState -ieq 'Enabled') { "true" }else{ "false" }
    }

    $DataStoreConfigurePITRUrl = $DataStoreAdminEndpoint.TrimEnd('/') + '/configurePITR'
    Wait-ForUrl -Url "$($DataStoreConfigurePITRUrl)?f=json" -MaxWaitTimeInSeconds 180 -SleepTimeInSeconds 5 -HttpMethod 'GET' -Verbose
    $Response = Invoke-ArcGISWebRequest -Url $DataStoreConfigurePITRUrl -HttpFormParameters $WebParams -Referer $Referer -TimeOutSec 600 -Verbose
    if($response.error) {
        Write-Verbose "Error Response - $($response.error | ConvertTo-Json)"
        throw [string]::Format("ERROR: failed. {0}" , $response.error.message)
    }else{
        if($Response.status -ieq "success"){
            Write-Verbose "PITR state changed to  $PITRState"
        }else{
            throw "[ERROR] Configure PITR web request returned unknown response $($Response.status)."
        }
    }
}

Export-ModuleMember -Function *-TargetResource
