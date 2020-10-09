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
    .PARAMETER DatastoreMachineHostName
        Optional Host Name or IP of the Machine on which the DataStore has been installed and is to be configured.
    .PARAMETER ServerHostName
        HostName of the GIS Server for which you want to create and register a data store.
    .PARAMETER SiteAdministrator
        A MSFT_Credential Object - Primary Site Administrator to access the GIS Server. 
    .PARAMETER ContentDirectory
         Path for the ArcGIS Data Store directory. This directory contains the data store files, plus the relational data store backup directory.
    .PARAMETER DatabaseBackupsDirectory
        ArcGIS Data Store automatically generates backup files for relational data stores. Default location for the backup files is on the same machine as ArcGIS Data Store
        Sentinel values:
        - [string] backuplocation path : set default backup location
        - empty string : remove default backup location
        - "NotManaged": (=default) do nothing
    .PARAMETER IsStandby
        Boolean to Indicate if the datastore (Relational only) being configured with a GIS Server is a Standby Server.(Only Supports 1 StandBy Server)
    .PARAMETER FileShareRoot
        Path of a Remote Network Location - a Remote FileShare for Database Backup
    .PARAMETER DataStoreTypes
        The type of data store to create on the machine.('Relational','SpatioTemporal','TileCache'). Value for this can be one or more. 
    .PARAMETER RunAsAccount
        A MSFT_Credential Object - Run as Account for DataStore Window Service.
    .PARAMETER IsEnvAzure
        Boolean to Indicate if the Deployment Environment is On-Prem or Azure Cloud Services
    .PARAMETER PITRState
        String to indicate if to enable or disable or do nothing with respect to Point In Time Recovery (Relational only).
#>
function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
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

        [System.String]
		$DatabaseBackupsDirectory = "NotManaged",

		[System.Boolean]
		$IsStandby,

        [System.String]
		$FileShareRoot,

        [System.Array]
        $DataStoreTypes,

        [System.Management.Automation.PSCredential]
        $RunAsAccount,
        
        [System.Boolean]
        $IsTileCacheDataStoreClustered = $false,
        
        [System.Boolean]
        $IsEnvAzure = $false,
        
        [ValidateSet("Enabled","Disabled","NotManaged")]
        [System.String]
		$PITRState = 'NotManaged'        
	)
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

	$null
}


function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
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

        [System.String]
		$DatabaseBackupsDirectory = "NotManaged",
               
		[System.Boolean]
		$IsStandby,

        [System.String]
		$FileShareRoot,

        [System.Array]
        $DataStoreTypes,

        [System.Management.Automation.PSCredential]
		$RunAsAccount,
        
        [System.Boolean]
        $IsTileCacheDataStoreClustered = $false,
        
        [System.Boolean]
        $IsEnvAzure = $false,

        [ValidateSet("Enabled","Disabled","NotManaged")]
        [System.String]
		$PITRState = 'NotManaged'        
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $MachineFQDN = if($DatastoreMachineHostName){ Get-FQDN $DatastoreMachineHostName }else{ Get-FQDN $env:COMPUTERNAME }
    $Referer = "https://$($MachineFQDN):2443"

    $ServiceName = 'ArcGIS Data Store'
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $DataStoreInstallDirectory = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir.TrimEnd('\')  

    if(($DataStoreTypes -icontains "Relational") -or ($DataStoreTypes -icontains "TileCache")){ 
        $RestartRequired = $false
        $expectedHostIdentifierType = if($MachineFQDN -as [ipaddress]){ 'ip' }else{ 'hostname' }
        $hostidentifier = Get-ConfiguredHostIdentifier -InstallDir $DataStoreInstallDirectory
        $hostidentifierType = Get-ConfiguredHostIdentifierType -InstallDir $DataStoreInstallDirectory
        Write-Verbose "Current value of property hostidentifier is '$hostidentifier' and hostidentifierType is '$hostidentifierType'"
        if(($hostidentifier -ieq $MachineFQDN) -and ($hostidentifierType -ieq $expectedHostIdentifierType)) {
            Write-Verbose "Configured host identifier '$hostidentifier' matches expected value '$MachineFQDN' and host identifier type '$hostidentifierType' matches expected value '$expectedHostIdentifierType'"        
        }else {
            Write-Verbose "Configured host identifier '$hostidentifier' does not match expected value '$MachineFQDN' or host identifier type '$hostidentifierType' does not match expected value '$expectedHostIdentifierType'. Setting it"
            if(Set-ConfiguredHostIdentifier -InstallDir $DataStoreInstallDirectory -HostIdentifier $MachineFQDN -HostIdentifierType $expectedHostIdentifierType) { 
                # Need to restart the service to pick up the hostidentifier 
                Write-Verbose "Hostidentifier.properties file was modified. Need to restart the '$ServiceName' service to pick up changes"
                $RestartRequired = $true 
            }
        }
       
        if($IsEnvAzure){
            $PropertiesFilePath = Join-Path $DataStoreInstallDirectory 'framework\etc\datastore.properties' 	
            $PropertyName = 'failover_on_primary_stop'
            $CurrentValue = Get-PropertyFromPropertiesFile -PropertiesFilePath $PropertiesFilePath -PropertyName $PropertyName
            Write-Verbose "Current value of property $PropertyName is $CurrentValue"
            if($CurrentValue -ine 'true') { 
                Write-Verbose "Property '$PropertyName' will be modified. Need to restart the '$ServiceName' service to pick up changes"
                $RestartRequired = $true
            }else {
                Write-Verbose "Property value '$CurrentValue' for '$PropertyName' matches expected value of 'true'"
            }
        }
	
        if($RestartRequired){
            Write-Verbose "Stop Service '$ServiceName' before applying property change"
            Stop-Service -Name $ServiceName -Force 
            Write-Verbose 'Stopping the service' 
            Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Stopped'
            Write-Verbose 'Stopped the service'
            
            if(-not($IsEnvAzure) -or ($IsEnvAzure -and (Set-PropertyFromPropertiesFile -PropertiesFilePath $PropertiesFilePath -PropertyName $PropertyName -PropertyValue 'true' -Verbose))){
                Write-Verbose "Restarting Service '$ServiceName' to pick up property change"
                Start-Service $ServiceName 
                Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Running'
                Write-Verbose "Restarted Service '$ServiceName'"
            }
            
            Wait-ForUrl -Url "https://$($MachineFQDN):2443/arcgis/datastoreadmin/configure?f=json" -MaxWaitTimeInSeconds 150 -SleepTimeInSeconds 5 -HttpMethod 'GET' -Verbose
        }else {
            Write-Verbose "Properties are up to date. No need to restart the 'ArcGIS Data Store' Service"
        }	
    }

    $ServerFQDN = Get-FQDN $ServerHostName
    $ServerUrl = "https://$($ServerFQDN):6443"   
    Wait-ForUrl -Url "$ServerUrl/arcgis/admin" -MaxWaitTimeInSeconds 90 -SleepTimeInSeconds 5 -Verbose
    $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer 

    if(($DataStoreTypes -icontains "Relational") -or ($DataStoreTypes -icontains "TileCache")){ 
        Write-Verbose "Ensure the Publishing GP Service (Tool) is started on Server"
        $PublishingToolsPath = 'System/PublishingTools.GPServer'
        $serviceStatus = Get-ServiceStatus -ServerURL $ServerUrl -Token $token.token -Referer $Referer -ServicePath $PublishingToolsPath
        Write-Verbose "Service Status :- $serviceStatus"
        if($serviceStatus.configuredState -ine 'STARTED' -or $serviceStatus.realTimeState -ine 'STARTED') {
            Write-Verbose "Starting Service $PublishingToolsPath"
            Start-ServerService -ServerURL $ServerUrl -Token $token.token -Referer $Referer -ServicePath $PublishingToolsPath
        
            $serviceStatus = Get-ServiceStatus -ServerURL $ServerUrl -Token $token.token -Referer $Referer -ServicePath $PublishingToolsPath
            Write-Verbose "Verifying Service Status :- $serviceStatus"
        }
    }

    $DataStoreAdminEndpoint = 'https://localhost:2443/arcgis/datastoreadmin'
    $DatastoresToRegisterOrConfigure = Get-DataStoreTypesToRegisterOrConfigure -ServerURL $ServerUrl -Token $token.token -Referer $Referer `
                                -DataStoreTypes $DataStoreTypes -MachineFQDN $MachineFQDN `
                                -DataStoreAdminEndpoint $DataStoreAdminEndpoint -ServerSiteAdminCredential $SiteAdministrator `
                                -IsTileCacheDataStoreClustered $IsTileCacheDataStoreClustered
    
    #Check if the TileCache mode is correct, only for 10.8.1 and above                                                            
    if($DatastoresToRegisterOrConfigure.Count -gt 0){
        $DatastoresToRegisterOrConfigureString = ($DatastoresToRegisterOrConfigure -join ',')
        Write-Verbose "Registering or configuring datastores $DatastoresToRegisterOrConfigureString"
        Invoke-RegisterOrConfigureDataStore -DataStoreAdminEndpoint $DataStoreAdminEndpoint -ServerSiteAdminCredential $SiteAdministrator `
                            -ServerUrl $ServerUrl -DataStoreContentDirectory $ContentDirectory -ServerAdminUrl "$ServerUrl/arcgis/admin" `
                            -Token $token.token -Referer $Referer -MachineFQDN $MachineFQDN -DataStoreTypes $DataStoreTypes `
                            -IsTileCacheDataStoreClustered $IsTileCacheDataStoreClustered
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

    if(-not($DataStoreTypes -icontains "SpatioTemporal") -and -not($IsStandby) -and $DatabaseBackupsDirectory -and ($DatabaseBackupsDirectory -ne "NotManaged")){
        $currLocation = Get-BackupLocation -Type "Relational"
        Write-Verbose "Current backup location is $currLocation. Requested $DatabaseBackupsDirectory"
        
        if($DatabaseBackupsDirectory -ine $currLocation)
        {
            if($DatabaseBackupsDirectory){
                ### WORKAROUND:- Since the DSC LCM (Local Configuration Manager) runs as Local System, it cannot access network resources
                ### The workaround is to use Mapped Drives using PS-Drive which is the only currently supported mechanism for accessing network resources
                ### Hence map a dummy drive  

                #region Map Drive Workaround   
                $DriveLetter = 'O'    
                Write-Verbose "About to map $FileShareRoot to $DriveLetter with Credentials $($RunAsAccount.UserName)"            
                $DriveInfo = $null
                try {
                    if(Get-PSDrive -Name $DriveLetter -ErrorAction Ignore) {
                        Remove-PSDrive -Name $DriveLetter -Force
                    }
                    $DriveInfo = New-PSDrive -Name $DriveLetter -PSProvider FileSystem -Root $FileShareRoot -Credential $RunAsAccount 
                    Write-Verbose "Mapped Drive $($DriveInfo.Name)"
                }
                catch
                {
                    Write-Verbose "[Warning] Error mapping using network root path $FileShareRoot. Error:- $_"        
                }
                if(-not($DriveInfo)) 
                {
                    Write-Verbose "Unable to map drive using Path $FileShareRoot"
                    [string[]]$Splits = $FileShareRoot.Split('\', [System.StringSplitOptions]::RemoveEmptyEntries)
                    Write-Verbose "Splits $Splits"
                    $HostName = $Splits[0]
                    Write-Verbose "File Share Host Name $HostName"
                    if(-not($HostName -as [ipaddress])) {
                        $ipaddress = (Resolve-DnsName -Name $HostName -Type A).IPAddress
                        Write-Verbose "IP Address of $HostName is $ipaddress"
                        $filesharePath = [System.String]::Join('\', $Splits, 1, $Splits.Length -1)
                        $RootPath = "\\$($ipaddress)\$($filesharePath)"
                        Write-Verbose "Root Path $RootPath"
                        if(Get-PSDrive -Name $DriveLetter -ErrorAction Ignore) {
                            Remove-PSDrive -Name $DriveLetter -Force
                        }
                        Write-Verbose "Attempt to map drive using IP address path $RootPath"
                        $DriveInfo = New-PSDrive -Name $DriveLetter -PSProvider FileSystem -Root $RootPath -Credential $RunAsAccount
                        if(-not($DriveInfo)){
                            Write-Verbose "Unable to map drive using IP address either"
                        }
                    }
                }
                #endregion

                $PathOnShare = $DatabaseBackupsDirectory
                $Pos = $DatabaseBackupsDirectory.IndexOf($FileShareRoot, [System.StringComparison]::InvariantCultureIgnoreCase)
                if($Pos -gt -1) {
                    $PathOnShare = $DatabaseBackupsDirectory.Substring($Pos + $FileShareRoot.Length)
                }
                if($DriveInfo) 
                {
                    $MappedDrivePath = "$($DriveInfo.Name):" + $PathOnShare
                    $LogsDir = Join-Path $MappedDrivePath 'deploylogs'
                    Write-Verbose "LogDir:- $LogsDir"
                    if(-not(Test-Path $LogsDir -ErrorAction Ignore))
                    {
                        Write-Verbose "Creating LogsDir:- $LogsDir"
                        New-Item $LogsDir -ItemType directory
                    }
                    Add-Content (Join-Path $LogsDir 'log.txt') -Value "$(Get-Date) Database backup directory $DatabaseBackupsDirectory" -ErrorAction Ignore
                }

                # Permissions can only be set on local drive. Test-Path throws exception when filepath is remote.
                if(Test-Path $DatabaseBackupsDirectory -ErrorAction Ignore) {
                    if($RunAsAccount) {           
                        Write-Verbose "Grant RunAsAccount $($RunAsAccount.UserName) permissions on $DatabaseBackupsDirectory using icacls.exe"
                        Write-Verbose "icacls.exe $DatabaseBackupsDirectory /grant $($RunAsAccount.UserName):(OI)(CI)F"
                        &icacls.exe $DatabaseBackupsDirectory /grant "$($RunAsAccount.UserName):(OI)(CI)F"
                    }    
                }

                if($currLocation){    
                    Write-Verbose "Unregistering existing backup location $currLocation"
                    Set-BackupLocation -BackupDirectory $currLocation -Register $false
                    Write-Verbose "Existing backup location $currLocation unregistered"
                }

                Write-Verbose "Updating backup location to $DatabaseBackupsDirectory"
                Set-BackupLocation -BackupDirectory $DatabaseBackupsDirectory -Register $true
                Write-Verbose "Updated backup location to $DatabaseBackupsDirectory"

                if($DriveInfo) {
                    Write-Verbose "Remove Mapped Drive $($DriveInfo.Name)"
                    Remove-PSDrive -Name $DriveInfo.Name -Force
                }
            }else {
                Write-Verbose "Unregistering existing backup location $currLocation"
                Set-BackupLocation -BackupDirectory $currLocation -Register $false
                Write-Verbose "Existing backup location $currLocation unregistered"
            }  
        }         
    }

    if(($DataStoreTypes -icontains "Relational") -and ($PITRState -ne "NotManaged") -and -not($IsStandby)){
        $CurrPITRState = Get-PITRState
        Write-Verbose "Current PITR state is $CurrPITRState. Requested $PITRState"
        if($PITRState -ine $CurrPITRState) {
            Set-PITRState -PITRState $PITRState
        }
    }
}


function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
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

        [System.String]
		$DatabaseBackupsDirectory = 'NotManaged',
                
		[System.Boolean]
		$IsStandby,

        [System.String]
		$FileShareRoot,

        [System.Array]
        $DataStoreTypes,

        [System.Management.Automation.PSCredential]
        $RunAsAccount,
        
        [System.Boolean]
        $IsTileCacheDataStoreClustered = $false,
        
        [System.Boolean]
        $IsEnvAzure = $false,
        
        [ValidateSet("Enabled","Disabled","NotManaged")]
        [System.String]
		$PITRState = 'NotManaged'        
    )
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $result = $true
    
    $MachineFQDN = if($DatastoreMachineHostName){ Get-FQDN $DatastoreMachineHostName }else{ Get-FQDN $env:COMPUTERNAME }
    $Referer = "https://$($MachineFQDN):2443"
    $ServerFQDN = Get-FQDN $ServerHostName
    $ServerUrl = "https://$($ServerFQDN):6443"
    
    if(($DataStoreTypes -icontains "Relational") -or ($DataStoreTypes -icontains "TileCache")){ 
        if($IsEnvAzure){
            $DataStoreInstallDirectory = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\ESRI\ArcGIS Data Store').InstallDir.TrimEnd('\')
            $PropertiesFile = Join-Path $DataStoreInstallDirectory 'framework\etc\datastore.properties' 
            $PropertyName = 'failover_on_primary_stop'
            $CurrentValue = Get-PropertyFromPropertiesFile -PropertiesFilePath $PropertiesFile -PropertyName $PropertyName
            Write-Verbose "Current value of property $PropertyName is '$CurrentValue'"
            $result = ($CurrentValue -ieq 'true')
        }

        if($result) {
            $ServiceName = 'ArcGIS Data Store'
            $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
            $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir  
            $expectedHostIdentifierType = if($MachineFQDN -as [ipaddress]){ 'ip' }else{ 'hostname' }
            $hostidentifier = Get-ConfiguredHostIdentifier -InstallDir $InstallDir
            $hostidentifierType = Get-ConfiguredHostIdentifierType -InstallDir $InstallDir
            Write-Verbose "Current value of property hostidentifier is '$hostidentifier' and hostidentifierType is '$hostidentifierType'"
            if(($hostidentifier -ieq $MachineFQDN) -and ($hostidentifierType -ieq $expectedHostIdentifierType)) {        
                Write-Verbose "Configured host identifier '$hostidentifier' matches expected value '$MachineFQDN' and host identifier type '$hostidentifierType' matches expected value '$expectedHostIdentifierType'"        
            }else {
                Write-Verbose "Configured host identifier '$hostidentifier' does not match expected value '$MachineFQDN' or host identifier type '$hostidentifierType' does not match expected value '$expectedHostIdentifierType'. Setting it"
                $result = $false
            }
        }else {
            if($IsEnvAzure){
                Write-Verbose "Property Value for 'failover_on_primary_stop' is not set to expected value 'true'"
            }
        }
    }

    Wait-ForUrl -Url "$ServerUrl/arcgis/admin" -MaxWaitTimeInSeconds 90 -SleepTimeInSeconds 5 -Verbose
    $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer 
    
    $DataStoreAdminEndpoint = 'https://localhost:2443/arcgis/datastoreadmin'
    $DatastoresToRegisterOrConfigure = Get-DataStoreTypesToRegisterOrConfigure -ServerURL $ServerUrl -Token $token.token -Referer $Referer `
                                -DataStoreTypes $DataStoreTypes -MachineFQDN $MachineFQDN `
                                -DataStoreAdminEndpoint $DataStoreAdminEndpoint -ServerSiteAdminCredential $SiteAdministrator `
                                -IsTileCacheDataStoreClustered $IsTileCacheDataStoreClustered

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

    if(-not($DataStoreTypes -icontains "SpatioTemporal") -and $result -and ($DatabaseBackupsDirectory -ne "NotManaged")) {
        $currLocation = Get-BackupLocation -Type "Relational"
        Write-Verbose "Current backup location is $currLocation"
        if($DatabaseBackupsDirectory -ine $currLocation){
            Write-Verbose "Current backup location does not match $DatabaseBackupsDirectory"
            $result = $false
        }
    }

    if(($DataStoreTypes -icontains "Relational") -and ($PITRState -ne "NotManaged") -and $result) {
        $CurrPITRState = Get-PITRState
        Write-Verbose "Current PITR state is $currPITRState"
        if($PITRState -ine $currPITRState){
            Write-Verbose "Current PITR state does not match requested status $PITRState"
            $result = $false
        }
    }

    if($Ensure -ieq 'Present') {
        $result
    }elseif($Ensure -ieq 'Absent') {        
        -not($result)
    }
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
        $Token, 
        
        [System.String]
        $Referer, 
        
        [System.String]
        $MachineFQDN
    )

    $WebParams = @{ 
                    f = 'json'
                    username = $ServerSiteAdminCredential.UserName
                    password = $ServerSiteAdminCredential.GetNetworkCredential().Password
                    serverURL = $ServerSiteUrl      
                    dsSettings = '{"features":{"feature.egdb":true,"feature.nosqldb":true,"feature.bigdata":true}}'
                    getConfigureInfo = 'true'
                  }       

   $DataStoreConfigureUrl = $DataStoreAdminEndpoint.TrimEnd('/') + '/configure'  
   Wait-ForUrl -Url  $DataStoreConfigureUrl -MaxWaitTimeInSeconds 90 -SleepTimeInSeconds 20 
   Invoke-ArcGISWebRequest -Url $DataStoreConfigureUrl -HttpFormParameters $WebParams -Referer $Referer -HttpMethod 'POST' -Verbose 
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
        $IsTileCacheDataStoreClustered
    )

    [string]$RealVersion = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\ESRI\ArcGIS Data Store').RealVersion
    Write-Verbose "Version of DataStore is $RealVersion"
    $VersionArray = $RealVersion.Split('.')

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
            }elseif($dstype -ieq 'SpatioTemporal') {
		        $featuresJson.add("feature.bigdata",$true)
                Write-Verbose "Adding SpatioTemporal as a data store type"
            }
        }
    }

	$dsSettings = @{
		directory = $DataStoreContentDirectory.Replace('\\', '\').Replace('\\', '\'); 
		features = $featuresJson;
	}

	if($DataStoreTypes -icontains "TileCache" -and (($VersionArray[1] -gt 8) -or ($RealVersion -ieq "10.8.1")) -and $IsTileCacheDataStoreClustered){
        $dsSettings.add("storeSetting.tileCache",@{deploymentMode="cluster"})
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
                                            -IsTileCacheDataStoreClustered $IsTileCacheDataStoreClustered

                $DatastoresToRegisterFlag = ($DatastoresToRegisterOrConfigure.Count -gt 0)
            }            
            if($DatastoresToRegisterFlag) {
                Write-Verbose "Register DataStore on Machine $MachineFQDN"    
                $response = Invoke-ArcGISWebRequest -Url $DataStoreConfigureUrl -HttpFormParameters $WebParams -Referer $Referer -TimeOutSec 600 -Verbose
                if($response.error) {
                    Write-Verbose "Error Response - $($response.error)"
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
                Write-Verbose "Attempt [$NumAttempts] Failed. Retrying after 30 seconds"
                Start-Sleep -Seconds 30
            } 
        }else {
            $Done = $true
        }         
        $NumAttempts++
    }

    if($DataStoreTypes -icontains "TileCache" -and ($RealVersion -ieq "10.8.1") -and $IsTileCacheDataStoreClustered){
        if((Get-NumberOfTileCacheDatastoreMachines -ServerURL $ServerUrl -Token $Token -Referer $Referer) -eq 1){
            $TilecacheBackupLocation = Get-BackupLocation -Type "TileCache"
            if(-not([string]::IsNullOrEmpty($TilecacheBackupLocation))){
                Write-Verbose "Unregistering backup location to $TilecacheBackupLocation"
                Delete-BackupLocation -BackupDirectory $TilecacheBackupLocation -Type "TileCache"
                Write-Verbose "Unregistering backup location to $TilecacheBackupLocation"
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
        $IsTileCacheDataStoreClustered
    )

    $DataStoreInfo = Get-DataStoreInfo -DataStoreAdminEndpoint $DataStoreAdminEndpoint -ServerSiteAdminCredential $ServerSiteAdminCredential `
                                        -ServerSiteUrl "$ServerURL/arcgis" -Token $Token -Referer $Referer 

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
        }

        $serverTestResult = Test-DataStoreRegistered -ServerURL $ServerUrl -Token $Token -Referer $Referer -Type "$dstype" -MachineFQDN $MachineFQDN -IsTileCacheDataStoreClustered $IsTileCacheDataStoreClustered -Verbose
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
        $IsTileCacheDataStoreClustered
    )

    $result = $false

    if($Type -like "SpatioTemporal" -or $Type -like "TileCache"){
        $DBType ='nosql'
    }else{
        $DBType ='egdb'
    }   

    $DataItemsUrl = $ServerURL.TrimEnd('/') + '/arcgis/admin/data/findItems' 
    $response = Invoke-ArcGISWebRequest -Url $DataItemsUrl -HttpFormParameters  @{ f = 'json'; token = $Token; types = $DBType } -Referer $Referer -Verbose
    $registered= $($response.items | Where-Object { $_.provider -ieq 'ArcGIS Data Store' } | Measure-Object).Count -gt 0
    if( $DBType -ieq 'nosql'){
        $registered = $($response.items | Where-Object { ($_.provider -ieq 'ArcGIS Data Store') -and ($_.info.dsFeature -ieq $Type) } | Measure-Object).Count -gt 0
    }

    if($registered){
        $DB = $($response.items | Where-Object { $_.provider -ieq 'ArcGIS Data Store' } | Select-Object -First 1)
        if( $DBType -ieq 'nosql'){
            $DB = ($response.items | Where-Object { ($_.provider -ieq 'ArcGIS Data Store') -and ($_.info.dsFeature -ieq $Type) } | Select-Object -First 1)
        }

        $MachinesInDataStoreUrl = $ServerURL.TrimEnd('/') + '/arcgis/admin/data/items' + $DB.path + '/machines'
        $response = Invoke-ArcGISWebRequest -Url $MachinesInDataStoreUrl -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer -Verbose
        $result = ($response.machines | Where-Object { $_.name -ieq $MachineFQDN } | Measure-Object).Count -gt 0

        if($result -and ($Type -like "TileCache")){
            $VersionArray = $DB.info.storeRelease.Split(".")
            if(($VersionArray[1] -gt 8) -or ($DB.info.storeRelease -ieq "10.8.1")){
                if($IsTileCacheDataStoreClustered){
                    if($DB.info.architecture -ieq "masterSlave"){
                        $result = $false
                    }else{
                        Write-Verbose "Tilecache Architecture is already set to Cluster."
                    }    
                }else{
                    if($DB.info.architecture -ieq "masterSlave"){
                        Write-Verbose "Tilecache Architecture is already set to masterSlave."
                    }else{
                        #$result = $false
                        Write-Verbose "Tilecache Architecture is set to Cluster. Cannot be converted to masterSlave."
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

function Get-BackupLocation
{
    [CmdletBinding()]
    param(
        [System.String]
        $Type
    )

    $DataStoreInstallDirectory = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\ESRI\ArcGIS Data Store').InstallDir.TrimEnd('\')

    $BackupToolPath = Join-Path $DataStoreInstallDirectory 'tools\describedatastore.bat'
    
    if(-not(Test-Path $BackupToolPath -PathType Leaf)){
        throw "$BackupToolPath not found"
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $BackupToolPath
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false #start the process from it's own executable file    
    $psi.RedirectStandardOutput = $true #enable the process to read from standard output
    $psi.RedirectStandardError = $true #enable the process to read from standard error

    $p = [System.Diagnostics.Process]::Start($psi)

    $op = $p.StandardOutput.ReadToEnd()
    $TypeString = if($Type -ieq "Relational"){ "relational" }elseif($Type -ieq "TileCache"){ "tile" }else{ "spatio" }
    $DatastoreInfo = $op -split 'Information for' | Where-Object { $_.Trim().StartsWith($TypeString) } | Select-Object -First 1
    $location = (($DatastoreInfo -split [System.Environment]::NewLine) | Where-Object { $_.StartsWith('Backup location') } | Select-Object -First 1)
    if($location) {
        $pos = $location.LastIndexOf('.')
        if($pos -gt -1) {
            # The output of backup location is a filepath of this format //something/like/this
            # To be able to make a comparison with the DatabaseBackupsDirectory param (\\something\like\that) replace forward slash with backslash
            $location = ($location.Substring($pos + 1) -replace "\/", "\")
        }
        if($location -eq "null") {
            $location = ""
        }
    }
    $location

}

function Delete-BackupLocation
{
    [CmdletBinding()]
    param(
        [System.String]
        $Type,

        [System.String]
        $BackupDirectory
    )

    $DataStoreInstallDirectory = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\ESRI\ArcGIS Data Store').InstallDir.TrimEnd('\')

    $BackupToolPath = Join-Path $DataStoreInstallDirectory 'tools\configurebackuplocation.bat'
    
    if(-not(Test-Path $BackupToolPath -PathType Leaf)){
        throw "$BackupToolPath not found"
    }

    $TypeString = if($Type -ieq "Relational"){ "relational" }elseif($Type -ieq "TileCache"){ "tileCache" }else{ "spatiotemporal" }
    $Arguments = " --operation unregister --location $BackupDirectory --store $TypeString --prompt no "

    Write-Verbose "Backup Unregister Tool:- $BackupToolPath $Arguments"

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $BackupToolPath
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false #start the process from it's own executable file    
    $psi.RedirectStandardOutput = $true #enable the process to read from standard output
    $psi.RedirectStandardError = $true #enable the process to read from standard error

    $p = [System.Diagnostics.Process]::Start($psi)

    $op = $p.StandardOutput.ReadToEnd()
    Write-Verbose $op
    if($op -ccontains 'failed') {
        throw "Backup Unregister Tool Failed. $op"
    }

    if($p.StandardError){
        $err = $p.StandardError.ReadToEnd()
		if($err -and $err.Length -gt 0) {
			throw "Error Updating Backup location. Error:- $err"
		}
    }
}

function Set-BackupLocation
{
    [CmdletBinding()]
    param(    
        [System.String]
        $BackupDirectory

        ,[System.Boolean]
        $Register
    )

    $DataStoreInstallDirectory = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\ESRI\ArcGIS Data Store').InstallDir.TrimEnd('\')

    $BackupToolPath = Join-Path $DataStoreInstallDirectory 'tools\configurebackuplocation.bat'
    
    if(-not(Test-Path $BackupToolPath -PathType Leaf)){
        throw "$BackupToolPath not found"
    }

    $DataStoreTypesAsString = $DataStoreTypes -join ','
    if ($Register){
        $Arguments = "--operation register --store $DataStoreTypesAsString --location $BackupDirectory --prompt no "       
    }else{
        $Arguments = "--operation unregister --store $DataStoreTypesAsString --location $BackupDirectory --prompt no "    
    }

    
    Write-Verbose "Backup Tool:- $BackupToolPath $Arguments"

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $BackupToolPath
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false #start the process from it's own executable file    
    $psi.RedirectStandardOutput = $true #enable the process to read from standard output
    $psi.RedirectStandardError = $true #enable the process to read from standard error

    $p = [System.Diagnostics.Process]::Start($psi)

    $op = $p.StandardOutput.ReadToEnd()
    Write-Verbose $op
    if($op -ccontains 'failed') {
        throw "Backup Tool Failed. $op"
    }

    if($p.StandardError){
        $err = $p.StandardError.ReadToEnd()
        if($err -and $err.Length -gt 0) {
            Write-Verbose "Error Updating Backup location. Error:- $err"
        }
    }
}

function Get-PITRState
{
    [CmdletBinding()]
    param(
    )

    $DataStoreInstallDirectory = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\ESRI\ArcGIS Data Store').InstallDir.TrimEnd('\')

    $DescribeDatastoreToolPath = Join-Path $DataStoreInstallDirectory 'tools\describedatastore.bat'
    
    if(-not(Test-Path $DescribeDatastoreToolPath -PathType Leaf)){
        throw "$DescribeDatastoreToolPath not found"
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $DescribeDatastoreToolPath
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false #start the process from it's own executable file    
    $psi.RedirectStandardOutput = $true #enable the process to read from standard output
    $psi.RedirectStandardError = $true #enable the process to read from standard error

    $p = [System.Diagnostics.Process]::Start($psi)

    $op = $p.StandardOutput.ReadToEnd()
    $PITREnabled = (($op -split [System.Environment]::NewLine) | Where-Object { $_.StartsWith('Is Point-in-time recovery enabled') } | Select-Object -First 1)
    if($PITREnabled) {
        $pos = $PITREnabled.LastIndexOf('.')
        if($pos -gt -1) {
            $PITREnabled = $PITREnabled.Substring($pos + 1)
        }
    }
    if($PITREnabled -eq 'yes'){
        $result = 'Enabled'
    }else {
        $result = 'Disabled'
    }
    $result  
}

function Set-PITRState
{
    [CmdletBinding()]
    param(   
        [System.String]
        $PITRState
    )

    $DataStoreInstallDirectory = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\ESRI\ArcGIS Data Store').InstallDir.TrimEnd('\')

    $DBPropertiesToolPath = Join-Path $DataStoreInstallDirectory 'tools\changedbproperties.bat'
    
    if(-not(Test-Path $DBPropertiesToolPath -PathType Leaf)){
        throw "$DBPropertiesToolPath not found"
    }

    if($PITRState -ne "NotManaged") {
        if ($PITRState -ieq 'Enabled') {
            $Arguments = "--store relational --pitr enable --prompt no"
        }    
        else {
            $Arguments = "--store relational --pitr disable --prompt no"
        }

        Write-Verbose "changedbproperties:- $DBPropertiesToolPath $Arguments"

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $DBPropertiesToolPath
        $psi.Arguments = $Arguments
        $psi.UseShellExecute = $false #start the process from it's own executable file    
        $psi.RedirectStandardOutput = $true #enable the process to read from standard output
        $psi.RedirectStandardError = $true #enable the process to read from standard error

        $p = [System.Diagnostics.Process]::Start($psi)

        $op = $p.StandardOutput.ReadToEnd()
        Write-Verbose $op
        if($op -ccontains 'failed') {
            throw "Setting PITR state failed. $op"
        }

        if($p.StandardError){
            $err = $p.StandardError.ReadToEnd()
            if($err -and $err.Length -gt 0) {
                Write-Verbose "Error Setting PITR state. Error:- $err"
            }
        }
    }
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


Export-ModuleMember -Function *-TargetResource
