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
    .PARAMETER ServerHostName
        HostName of the GIS Server for which you want to create and register a data store.
    .PARAMETER SiteAdministrator
        A MSFT_Credential Object - Primary Site Adminstrator to access the GIS Server. 
    .PARAMETER ContentDirectory
         Path for the ArcGIS Data Store directory. This directory contains the data store files, plus the relational data store backup directory.
    .PARAMETER DatabaseBackupsDirectory
        ArcGIS Data Store automatically generates backup files for relational data stores. Default location for the backup files is on the same machine as ArcGIS Data Store
    .PARAMETER IsStandby
        Boolean to Indicate if the datastore (Relational only) being configured with a GIS Server is a Standby Server.(Only Supports 1 StandBy Server)
    .PARAMETER FileShareRoot
        Path of a Remote Network Location - a Remote FileShare for Database Backup
    .PARAMETER DataStoreTypes
        The type of data store to create on the machine.('Relational','SpatioTemporal','TileCache'). Value for this can be one or more. 
    .PARAMETER RunAsAccount
        A MSFT_Credential Object - Run as Account for DataStore Window Service.
#>
function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
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
		$DatabaseBackupsDirectory,

		[System.Boolean]
		$IsStandby,

        [System.String]
		$FileShareRoot,

        [System.Array]
        $DataStoreTypes,

        [System.Management.Automation.PSCredential]
		$RunAsAccount
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
		$DatabaseBackupsDirectory,

		[System.Boolean]
		$IsStandby,

        [System.String]
		$FileShareRoot,

        [System.Array]
        $DataStoreTypes,

        [System.Management.Automation.PSCredential]
		$RunAsAccount
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

	$MachineFQDN = Get-FQDN $env:ComputerName
	
    $ServiceName = 'ArcGIS Data Store'
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $DataStoreInstallDirectory = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir.TrimEnd('\')  

    if(-not($DataStoreTypes -icontains "SpatioTemporal")){
        $RestartRequired = $false
        $expectedHostIdentifierType = 'hostname'
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
   
        if($RestartRequired)
        {
            Write-Verbose "Stop Service '$ServiceName' before applying property change"
            Stop-Service -Name $ServiceName -Force 
            Write-Verbose 'Stopping the service' 
            Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Stopped'
            Write-Verbose 'Stopped the service'
            
            Write-Verbose "Restarting Service '$ServiceName' to pick up property change"
            Start-Service $ServiceName 
            Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Running'
            Write-Verbose "Restarted Service '$ServiceName'"
            
            Wait-ForUrl -Url "https://$($MachineFQDN):2443/arcgis/datastoreadmin/" -MaxWaitTimeInSeconds 90 -SleepTimeInSeconds 5 -HttpMethod 'GET'
        }else {
            Write-Verbose "Properties are up to date. No need to restart the 'ArcGIS Data Store' Service"
        }	
    }

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $FQDN = Get-FQDN $ServerHostName
    $ServerUrl = "http://$($FQDN):6080"   
    $ServerHttpsUrl = "https://$($FQDN):6443"   
    $Referer = $ServerUrl
    Wait-ForUrl -Url "$ServerUrl/arcgis/admin" -MaxWaitTimeInSeconds 90 -SleepTimeInSeconds 5
    
    $Done = $false
	$NumAttempts = 0
	while(-not($Done) -and ($NumAttempts -lt 10)) {
		try {
			$token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer 
		}
		catch {
			Write-Verbose "[WARNING]:- Server at $ServerUrl did not return a token on attempt $($NumAttempts + 1). Retry after 15 seconds"
		}
		if($token) {
			Write-Verbose "Retrieved server token successfully"
			$Done = $true
		}else {
			Start-Sleep -Seconds 15
			$NumAttempts = $NumAttempts + 1
		}
	}
    
    $DataStoreAdminEndpoint = 'https://localhost:2443/arcgis/datastoreadmin'
    
    if(-not($DataStoreTypes -icontains "SpatioTemporal")){

        Write-Verbose "Checking if data store is registered"
        $result = Test-DataStoreRegistered -ServerURL $ServerUrl -Token $token.token -Referer $Referer -Type "Relational"
        if($result) {
            Write-Verbose "A Data Store has been registered. Now checking if this machine ($env:ComputerName) belongs to it"
            $result = Test-MachineParticipatingInDataStore -ServerURL $ServerURL -Token $token.token -Referer $Referer -MachineFQDN (Get-FQDN $env:ComputerName)
            if($result) {
                Write-Verbose "The machine $($env:ComputerName) already participates in the data store"
            }
        }
        
        if(-not($result)) {

            # Ensure the Publishing GP Service (Tool) is started
            $PublishingToolsPath = 'System/PublishingTools.GPServer'
            $serviceStatus = Get-ServiceStatus -ServerURL $ServerUrl -Token $token.token -Referer $Referer -ServicePath $PublishingToolsPath
            Write-Verbose "Service Status :- $serviceStatus"
            if($serviceStatus.configuredState -ine 'STARTED' -or $serviceStatus.realTimeState -ine 'STARTED') {
                Write-Verbose "Starting Service $PublishingToolsPath"
                Start-ServerService -ServerURL $ServerUrl -Token $token.token -Referer $Referer -ServicePath $PublishingToolsPath
            
                $serviceStatus = Get-ServiceStatus -ServerURL $ServerUrl -Token $token.token -Referer $Referer -ServicePath $PublishingToolsPath
                Write-Verbose "Verifying Service Status :- $serviceStatus"
            }

            Register-DataStore -DataStoreAdminEndpoint $DataStoreAdminEndpoint -ServerSiteAdminCredential $SiteAdministrator `
                            -ServerSiteUrl "https://$($FQDN):6443/arcgis" -DataStoreContentDirectory $ContentDirectory -ServerAdminUrl "$ServerUrl/arcgis/admin" `
                            -Token $token.token -Referer $Referer -MachineFQDN $MachineFQDN -DataStoreTypes $DataStoreTypes
        } 
    
        if($DataStoreTypes) {
            $info = Get-DataStoreInfo -DataStoreAdminEndpoint 'https://localhost:2443/arcgis/datastoreadmin' -ServerSiteAdminCredential $SiteAdministrator -ServerSiteUrl "https://$($FQDN):6443/arcgis" `
                                    -Token $token.token -Referer $Referer 
            $allTypesRegistered = $true
            foreach($dstype in $DataStoreTypes) {
                if($dstype -ieq 'Relational') {
                    if(-not($info.relational.registered)) {
                        Write-Verbose "Data Store Type 'Relational' not registered"
                        $allTypesRegistered = $false
                    }else {
                        Write-Verbose "Data Store Type 'Relational' is registered"
                    }
                }
                elseif($dstype -ieq 'TileCache') {
                    if(-not($info.tileCache.registered)) {
                        Write-Verbose "Data Store Type 'TileCache' not registered"
                        $allTypesRegistered = $false
                    }else {
                        Write-Verbose "Data Store Type 'TileCache' is registered"
                    }
                }
            }

            if(-not($allTypesRegistered)) {
                Write-Verbose "Not all requred data store types '$($DataStoreTypes.ToString())' are registered. Attempting registration again"
                Register-DataStore -DataStoreAdminEndpoint $DataStoreAdminEndpoint -ServerSiteAdminCredential $SiteAdministrator `
                            -ServerSiteUrl "https://$($FQDN):6443/arcgis" -DataStoreContentDirectory $ContentDirectory -ServerAdminUrl "$ServerUrl/arcgis/admin" `
                            -Token $token.token -Referer $Referer -MachineFQDN $MachineFQDN -DataStoreTypes $DataStoreTypes
            }
        }
    }

    if($DataStoreTypes -icontains "SpatioTemporal"){
        Write-Verbose "Checking if spatiotemporal big data store is registered"
        $DsRegistered = $false
        $result = Test-DataStoreRegistered -ServerURL $ServerUrl -Token $token.token -Referer $Referer -Type "SpatioTemporal"
        if($result) {
            Write-Verbose "A Data Store has been registered. Now checking if this machine ($env:ComputerName) with FQDN '$MachineFQDN' belongs to it"
            $result = Test-MachineParticipatingInBigDataStore -ServerURL $ServerURL -Token $token.token -Referer $Referer -MachineFQDN $MachineFQDN
            if($result) {
                Write-Verbose "The machine $($env:ComputerName) with FQDN '$MachineFQDN' already participates in the data store"
                $DsRegistered = $true
            }else {
                Write-Verbose "The machine $($env:ComputerName) with FQDN '$MachineFQDN' does NOT participates in the registered data store"
            }
        }else {
            Write-Verbose "A Spatiotemporal Big Data Store has not been registered."
        }
        
        if(-not($DsRegistered)) {
            Write-Verbose "A Spatiotemporal Big Data Store has not been registered. Registering now."
            Register-DataStore -DataStoreAdminEndpoint $DataStoreAdminEndpoint -ServerSiteAdminCredential $SiteAdministrator -ServerSiteUrl "$ServerHttpsUrl/arcgis" -DataStoreContentDirectory $ContentDirectory `
                                -ServerAdminUrl "$ServerHttpsUrl/arcgis/admin" -Token $token.token -Referer $Referer -MachineFQDN $MachineFQDN -DataStoreTypes $DataStoreTypes
        }	
        Write-Verbose "Checking if the Spatiotemporal Big Data Store has started."
        if(-not(Test-SpatiotemporalBigDataStoreStarted -ServerURL $ServerUrl -Token $token.token -Referer $Referer -MachineFQDN $FQDN)) {
            Write-Verbose "Starting the Spatiotemporal Big Data Store."
            Start-SpatiotemporalBigDataStore -ServerURL $ServerUrl -Token $token.token -Referer $Referer -MachineFQDN $FQDN
            $x = Test-SpatiotemporalBigDataStoreStarted -ServerURL $ServerUrl -Token $token.token -Referer $Referer -MachineFQDN $FQDN
            Write-Verbose "Just Checking:- $($x)"
        }else {
            Write-Verbose "The Spatiotemporal Big Data Store is already started."
        }
    }

    if(-not($DataStoreTypes -icontains "SpatioTemporal")){
        if(-not($IsStandby) -and $DatabaseBackupsDirectory) {
            $currLocation = Get-BackupLocation
            Write-Verbose "Current backup location is $currLocation. Requested $DatabaseBackupsDirectory"
            if($DatabaseBackupsDirectory -ine $currLocation)
            {

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
                    if(-not(Test-Path $LogsDir))
                    {
                        Write-Verbose "Creating LogsDir:- $LogsDir"
                        New-Item $LogsDir -ItemType directory
                    }
                    Add-Content (Join-Path $LogsDir 'log.txt') -Value "$(Get-Date) Database backup directory $DatabaseBackupsDirectory" -ErrorAction Ignore
                }

                if($RunAsAccount) {           
                    Write-Verbose "Grant RunAsAccount $($RunAsAccount.UserName) permissions on $DatabaseBackupsDirectory using icacls.exe"
                    Write-Verbose "icacls.exe $DatabaseBackupsDirectory /grant $($RunAsAccount.UserName):(OI)(CI)F"
                    &icacls.exe $DatabaseBackupsDirectory /grant "$($RunAsAccount.UserName):(OI)(CI)F"
                }    

                Write-Verbose "Updating backup location to $DatabaseBackupsDirectory"
                Set-BackupLocation -BackupDirectory $DatabaseBackupsDirectory
                Write-Verbose "Updated backup location to $DatabaseBackupsDirectory"

                if($DriveInfo) {
                    Write-Verbose "Remove Mapped Drive $($DriveInfo.Name)"
                    Remove-PSDrive -Name $DriveInfo.Name -Force
                }   
            }
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
		$DatabaseBackupsDirectory,

		[System.Boolean]
		$IsStandby,

        [System.String]
		$FileShareRoot,

        [System.Array]
        $DataStoreTypes,

        [System.Management.Automation.PSCredential]
		$RunAsAccount
	)
 
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	$result = $true
    $resultSpatioTemporal = $false
    
    
    $FQDN = Get-FQDN $ServerHostName
    $MachineFQDN = Get-FQDN $env:ComputerName
    $ServerUrl = "http://$($FQDN):6080"   
    $Referer = $ServerUrl
    
    if(-not($DataStoreTypes -icontains "SpatioTemporal")){
        
        $ServiceName = 'ArcGIS Data Store'
        $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
        $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir  
        $expectedHostIdentifierType = 'hostname'
        $hostidentifier = Get-ConfiguredHostIdentifier -InstallDir $InstallDir
        $hostidentifierType = Get-ConfiguredHostIdentifierType -InstallDir $InstallDir
        Write-Verbose "Current value of property hostidentifier is '$hostidentifier' and hostidentifierType is '$hostidentifierType'"
        if(($hostidentifier -ieq $MachineFQDN) -and ($hostidentifierType -ieq $expectedHostIdentifierType)) {        
            Write-Verbose "Configured host identifier '$hostidentifier' matches expected value '$MachineFQDN' and host identifier type '$hostidentifierType' matches expected value '$expectedHostIdentifierType'"        
        }else {
            Write-Verbose "Configured host identifier '$hostidentifier' does not match expected value '$MachineFQDN' or host identifier type '$hostidentifierType' does not match expected value '$expectedHostIdentifierType'. Setting it"
            $result = $false
        }

        if($result){
        	$token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer

            Write-Verbose "Checking if data store is registered"
            $result = Test-DataStoreRegistered -ServerURL $ServerUrl -Token $token.token -Referer $Referer -Type "Relational"
            if($result) {
                Write-Verbose "A Data Store has been registered. Now checking if this machine ($env:ComputerName) belongs to it"
                $result = Test-MachineParticipatingInDataStore -ServerURL $ServerURL -Token $token.token -Referer $Referer -MachineFQDN $MachineFQDN
                if($result) {
                    Write-Verbose "The machine $($env:ComputerName) participates in the data store"
                }else {
                    Write-Verbose "The machine $($env:ComputerName) does not participate in the data store"
                }
            }
        }
        
    }

    if($DataStoreTypes -icontains "SpatioTemporal"){       
        $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer

        Write-Verbose "Checking if Spatiotemporal big data store is registered"
        $resultSpatioTemporal = Test-DataStoreRegistered -ServerURL $ServerUrl -Token $token.token -Referer $Referer  -type "SpatioTemporal"
        if($resultSpatioTemporal) {
            Write-Verbose "A Spatiotemporal Big Data Store has been registered. Now checking if this machine ($env:ComputerName) belongs to it"
            $resultSpatioTemporal = Test-MachineParticipatingInBigDataStore -ServerURL $ServerURL -Token $token.token -Referer $Referer -MachineFQDN $MachineFQDN
            if($resultSpatioTemporal) {
                Write-Verbose "The machine $($env:ComputerName) participates in the Spatiotemporal big data store"
            }else {
                Write-Verbose "The machine $($env:ComputerName) does not participate in the Spatiotemporal big data store"
            }
        }else {
            Write-Verbose "A Spatiotemporal Big Data Store has not been registered."
        }

        if($resultSpatioTemporal) {
            $resultSpatioTemporal = Test-SpatiotemporalBigDataStoreStarted -ServerURL $ServerUrl -Token $token.token -Referer $Referer -MachineFQDN $FQDN
            if($resultSpatioTemporal) {
                Write-Verbose 'Big data store is started'
            }else {
                Write-Verbose 'Big data store is not started'
            }
        }
        
    }
	
    if(($result -or $resultSpatioTemporal) -and $DataStoreTypes) { 
        if(-not($token)) {  
			$token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer 
		}
    
        Write-Verbose $token.token
        
        $info = Get-DataStoreInfo -DataStoreAdminEndpoint "https://$($MachineFQDN):2443/arcgis/datastoreadmin" -ServerSiteAdminCredential $SiteAdministrator -ServerSiteUrl "https://$($FQDN):6443/arcgis" `
                                   -Token $token.token -Referer $Referer 
        
        foreach($dstype in $DataStoreTypes) {
            if($dstype -ieq 'Relational') {
                if(-not($info.relational.registered)) {
                    Write-Verbose "Data Store Type 'Relational' not registered"
                    $result = $false
                }else {
					Write-Verbose "Data Store Type 'Relational' is registered"
				}
            }
            elseif($dstype -ieq 'TileCache') {
                if(-not($info.tileCache.registered)) {
                    Write-Verbose "Data Store Type 'TileCache' not registered"
                    $result = $false
                }else {
					Write-Verbose "Data Store Type 'TileCache' is registered"
				}
            }
			elseif($dstype -ieq 'SpatioTemporal') {
                if(-not($info.spatioTemporal.registered)) {
                    Write-Verbose "Data Store Type 'SpatioTemporal' not registered"
                    if($DataStoreTypes -icontains "SpatioTemporal"){
                        $resultSpatioTemporal = $false
                    }else{
                        $result = $false
                    }
                }else {
					Write-Verbose "Data Store Type 'SpatioTemporal' is registered"
				}
            }
        }
        if(-not($DataStoreTypes.Contains('SpatioTemporal'))){
            $resultSpatioTemporal = $true
        }
    }

    if(-not($DataStoreTypes -icontains "SpatioTemporal") -and $result) {
        if($DatabaseBackupsDirectory) {
            $currLocation = Get-BackupLocation
            Write-Verbose "Current backup location is $currLocation"
            if($DatabaseBackupsDirectory -ine $currLocation){
                Write-Verbose "Current backup location does not match $DatabaseBackupsDirectory"
                $result = $false
            }
        }
    }

    if($Ensure -ieq 'Present') {
	       $result -and $resultSpatioTemporal  
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result -and $resultSpatioTemporal))
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
        
   $HttpBody = To-HttpBody $WebParams
   #Write-Verbose ($WebParams | ConvertTo-Json -Depth 4)
   $DataStoreConfigureUrl = $DataStoreAdminEndpoint.TrimEnd('/') + '/configure'   
   Wait-ForUrl -Url  $DataStoreConfigureUrl -MaxWaitTimeInSeconds 90 -SleepTimeInSeconds 20
   Invoke-ArcGISWebRequest -Url $DataStoreConfigureUrl -HttpFormParameters $WebParams -Referer $Referer -HttpMethod 'POST' -LogResponse 
   
}

function Register-DataStore
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
        $DataStoreTypes
    )

    if(!$DataStoreContentDirectory) { throw "Must Specify DataStoreContentDirectory" }

    $featuresJson = ',"features":{'
    if($DataStoreTypes) {
        $first = $true
        foreach($dstype in $DataStoreTypes) {
            if($dstype -ieq 'Relational') {
                if(-not($first)){ $featuresJson += ',' } 
                $first = $false
                $featuresJson += '"feature.egdb":true'
                Write-Verbose "Adding Relational as a data store type"
            }
            elseif($dstype -ieq 'TileCache') {
                if(-not($first)){ $featuresJson += ',' } 
                $first = $false
                $featuresJson += '"feature.nosqldb":true'
                Write-Verbose "Adding Tile Cache as a data store type"
            }elseif($dstype -ieq 'SpatioTemporal') {
                if(-not($first)){ $featuresJson += ',' } 
                $first = $false
				$featuresJson += '"feature.bigdata":true'
                Write-Verbose "Adding SpatioTemporal as a data store type"
			}
        }
    }
    $featuresJson += '}'

    $WebParams = @{ 
                    f = 'json'
                    username = $ServerSiteAdminCredential.UserName
                    password = $ServerSiteAdminCredential.GetNetworkCredential().Password
                    serverURL = $ServerSiteUrl
                    dsSettings = '{"directory":"' + $DataStoreContentDirectory.Replace('\', '\\') + '"' + $featuresJson + '}'
                  }  
   Write-Verbose ($WebParams | ConvertTo-Json -Depth 4)
   $HttpBody = To-HttpBody $WebParams
   
   $DataStoreConfigureUrl = $DataStoreAdminEndpoint.TrimEnd('/') + '/configure'    
   Write-Verbose "Register DataStore at $DataStoreAdminEndpoint with DataStore Content directory at $DataStoreContentDirectory for server $ServerSiteUrl"
   
   [bool]$Done = $false
   [System.Int32]$NumAttempts = 1
   while(-not($Done)) {
        Write-Verbose "Register DataStore Attempt $NumAttempts"
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} # Allow self-signed certificates        
        [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
        [bool]$failed = $false
        $response = $null
        try {
            $alreadyRegistered = $false
            if($NumAttempts -gt 1) {
                Write-Verbose "Checking if datastore is registered"
                $dataStoreExists = Test-DataStoreRegistered -ServerURL $ServerAdminUrl -Token $Token -Referer $Referer
                Write-Verbose "DataStore registration status:- $alreadyRegistered"

                if($dataStoreExists) {
                   $alreadyRegistered = Test-MachineParticipatingInDataStore -ServerURL $ServerAdminUrl -Token $Token -Referer $Referer -MachineFQDN $MachineFQDN
                }
            }            
            if(-not($alreadyRegistered)) {
                Write-Verbose "Register DataStore on Machine $MachineFQDN"                
                $response = Invoke-RestMethod -Uri $DataStoreConfigureUrl -Method POST -Body $HttpBody -TimeoutSec 300 -ErrorAction Ignore
                #Write-Verbose $response  
                if($response.error) {
                    Write-Verbose $response.error 
                }
                Check-ResponseStatus $response -Url $DataStoreConfigureUrl
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
        $Type
    )
    if($Type -like "SpatioTemporal"  -or $Type -like "TileCache"){
        $DBType ='nosql'
    }else{
        $DBType ='egdb'
    }
    
    $DataItemsUrl = $ServerURL.TrimEnd('/') + '/arcgis/admin/data/findItems' 
    $response = Invoke-ArcGISWebRequest -Url $DataItemsUrl -HttpFormParameters  @{ f = 'json'; token = $Token; types = $DBType } -Referer $Referer 
    $registered = $($response.items | Where-Object { $_.provider -ieq 'ArcGIS Data Store' } | Measure-Object).Count -gt 0
    $registered
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
   Invoke-ArcGISWebRequest -Url $ServiceStartOperationUrl -HttpFormParameters  @{ f = 'json'; token = $Token } -Referer $Referer -HttpMethod 'GET'
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

function Test-MachineParticipatingInDataStore
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
    $response = Invoke-ArcGISWebRequest -Url $DataItemsUrl -HttpFormParameters @{ f = 'json'; token = $Token; types = 'egdb' } -Referer $Referer 
   
    $dataStorePath = $null
    if($response.items -and $response.items.length -gt 0) {
        $dataStorePath = $response.items[0].path
        Write-Verbose "DataStore $dataStorePath found"        
    }else {
        Write-Verbose "DataStore path not found"
    }

    $exists = $false
    if($dataStorePath) 
    {      
           $MachinesInDataStoreUrl = $ServerURL.TrimEnd('/') + '/arcgis/admin/data/items' + $dataStorePath + '/machines'
           $response = Invoke-ArcGISWebRequest -Url $MachinesInDataStoreUrl -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer 
           $exists = ($response.machines | Where-Object { $_.name -ieq $MachineFQDN } | Measure-Object).Count -gt 0
    }
    $exists
}

function Test-MachineParticipatingInBigDataStore
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
    $response = Invoke-ArcGISWebRequest -Url $DataItemsUrl -HttpFormParameters @{ f = 'json'; token = $Token; types = 'nosql' } -Referer $Referer 
    
    $exists = $false
    $dataStorePath = $null
    if($response.items -and $response.items.length -gt 0) {
		$done = $false
		$i = 0
		while(-not($done) -and ($i -lt $response.items.length)) {
			$dataStorePath = $response.items[$i].path	
			if($dataStorePath) {		
				Write-Verbose "NoSQL DataStore $dataStorePath found"        
				$MachinesInDataStoreUrl = $ServerURL.TrimEnd('/') + '/arcgis/admin/data/items' + $dataStorePath + '/machines'
				$response = Invoke-ArcGISWebRequest -Url $MachinesInDataStoreUrl -HttpFormParameters @{ f = 'json'; token = $Token }  -Referer $Referer 
				$exists = ($response.machines | Where-Object { $_.name -ieq $MachineFQDN } | Measure-Object).Count -gt 0
				if($exists) {
					Write-Verbose "Machine with FQDN $MachineFQDN found for data store:- $dataStorePath"
					$done = $true
				}
			}
			$i = $i + 1
		}
    }else {
        Write-Verbose "DataStore path not found"
    }

    $exists
}

function Get-BackupLocation
{
    [CmdletBinding()]
    param(
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
    $location = (($op -split [System.Environment]::NewLine) | Where-Object { $_.StartsWith('Backup location') } | Select-Object -First 1)
    if($location) {
        $pos = $location.LastIndexOf('.')
        if($pos -gt -1) {
            $location = $location.Substring($pos + 1)
        }
    }
    $location
}

function Set-BackupLocation
{
    [CmdletBinding()]
    param(    
        [System.String]
        $BackupDirectory
    )

    $DataStoreInstallDirectory = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\ESRI\ArcGIS Data Store').InstallDir.TrimEnd('\')

    $BackupToolPath = Join-Path $DataStoreInstallDirectory 'tools\changebackuplocation.bat'
    
    if(-not(Test-Path $BackupToolPath -PathType Leaf)){
        throw "$BackupToolPath not found"
    }
    if(-not(Test-Path $BackupDirectory)){
        Write-Verbose "Creating backup location $BackupDirectory"
        New-Item -Path $BackupDirectory -ItemType directory
    }

    $Arguments = "$BackupDirectory --is-shared-folder true --prompt no "

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
function Test-SpatiotemporalBigDataStoreStarted
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
   $Url = $ServerURL.TrimEnd('/') + '/arcgis/admin/data/items' + "$dataStorePath/machines/$MachineFQDN/validate/"
   Write-Verbose $Url
   try {    
    $response = Invoke-ArcGISWebRequest -Url $Url -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer -HttpMethod 'POST'    
    $n = $response.nodes | Where-Object {$_.name -ieq (Resolve-DnsName -Type ANY $env:ComputerName).IPAddress}
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
   Invoke-ArcGISWebRequest -Url $Url -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer -HttpMethod 'POST' -LogResponse
}


Export-ModuleMember -Function *-TargetResource

