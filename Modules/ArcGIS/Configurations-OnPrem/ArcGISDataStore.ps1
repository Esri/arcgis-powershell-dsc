Configuration ArcGISDataStore 
{
    param(
        [Parameter(Mandatory=$true)]    
        [System.String]
        $Version,

        [Parameter(Mandatory=$True)]
        [ValidateSet('Relational','TileCache','SpatioTemporal','GraphStore','ObjectStore')]
        [System.String]
        $DataStoreType,

        [Parameter(Mandatory=$true)]
        [System.Int32]
        $DataStoreMachineCount,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServiceCredential,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ForceServiceCredentialUpdate = $False,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount = $False,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsMSA = $False,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServerPrimarySiteAdminCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ContentDirectoryLocation,

        [Parameter(Mandatory=$False)]
        [System.String]
        $PrimaryServerMachine,

        [Parameter(Mandatory=$False)]
        [System.String]
        $PrimaryDataStoreMachine,
        
        [Parameter(Mandatory=$False)]
        [System.Array]
        $Backups = $null,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $EnableFailoverOnPrimaryStop = $False,
        
        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $EnablePointInTimeRecovery = $False,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $UsesSSL = $False,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $DebugMode = $False
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.5.0 -Name ArcGIS_xFirewall, ArcGIS_Service_Account, ArcGIS_DataStore, ArcGIS_DataStoreBackup

    $VersionArray = $Version.Split('.')

    Node $AllNodes.NodeName 
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
       
        $Depends = @()

        ArcGIS_xFirewall DataStore_FirewallRules
        {
            Name                  = "ArcGISDataStore" 
            DisplayName           = "ArcGIS Data Store" 
            DisplayGroup          = "ArcGIS Data Store" 
            Ensure                = 'Present' 
            Access                = "Allow" 
            State                 = "Enabled" 
            Profile               = ("Domain","Private","Public")
            LocalPort             = ("2443")                        
            Protocol              = "TCP" 
            DependsOn             = $Depends
        } 

        if($DataStoreType -ieq 'Relational'){
            ArcGIS_xFirewall Relational_DataStore_FirewallRules
            {
                Name                  = "ArcGISRelationalDataStore" 
                DisplayName           = "ArcGIS Relational Data Store" 
                DisplayGroup          = "ArcGIS Data Store" 
                Ensure                = 'Present' 
                Access                = "Allow" 
                State                 = "Enabled" 
                Profile               = ("Domain","Private","Public")
                LocalPort             = ("9876")                        
                Protocol              = "TCP" 
                DependsOn             = $Depends
            }
            $Depends += '[ArcGIS_xFirewall]Relational_DataStore_FirewallRules'

            if($DataStoreMachineCount -gt 1)
            {
                # Allow outbound traffic so that database replication can take place
                ArcGIS_xFirewall Relational_DataStore_FirewallRules_OutBound
                {
                    Name                  = "ArcGISDataStore-Out" 
                    DisplayName           = "ArcGIS Relational Data Store Out" 
                    DisplayGroup          = "ArcGIS Data Store" 
                    Ensure                = 'Present'  
                    Access                = "Allow" 
                    State                 = "Enabled" 
                    Profile               = ("Domain","Private","Public")
                    LocalPort             = ("9876")       
                    Direction             = "Outbound"                        
                    Protocol              = "TCP" 
                    DependsOn             = $Depends
                }
                $Depends += '[ArcGIS_xFirewall]Relational_DataStore_FirewallRules_OutBound'
            }

            if($VersionArray[0] -gt 10){
                ArcGIS_xFirewall Queue_DataStore_FirewallRules
                {
                    Name                  = "ArcGISQueueDataStore-Out" 
                    DisplayName           = "ArcGIS Queue Data Store Out" 
                    DisplayGroup          = "ArcGIS Data Store" 
                    Ensure                = 'Present'  
                    Access                = "Allow" 
                    State                 = "Enabled" 
                    Profile               = ("Domain","Private","Public")
                    LocalPort             = ("45671","45672")                      
                    Protocol              = "TCP" 
                    DependsOn             = $Depends
                }
                $Depends += '[ArcGIS_xFirewall]Queue_DataStore_FirewallRules'
            }

            if(($VersionArray[0] -gt 11) -or ($VersionArray[0] -eq 11 -and $VersionArray[1] -ge 5)){
                ArcGIS_xFirewall MemoryCache_DataStore_FirewallRules
                {
                    Name                  = "ArcGISMemoryCacheDataStore" 
                    DisplayName           = "ArcGIS Memory Cache Data Store" 
                    DisplayGroup          = "ArcGIS Data Store" 
                    Ensure                = 'Present'  
                    Access                = "Allow" 
                    State                 = "Enabled" 
                    Profile               = ("Domain","Private","Public")
                    LocalPort             = ("9820","9840","9850")
                    Protocol              = "TCP" 
                    DependsOn             = $Depends
                }
                $Depends += '[ArcGIS_xFirewall]MemoryCache_DataStore_FirewallRules'
            }
        }

        if($DataStoreType -ieq  'TileCache'){
            ArcGIS_xFirewall TileCache_DataStore_FirewallRules
		    {
                Name                  = "ArcGISTileCacheDataStore" 
                DisplayName           = "ArcGIS Tile Cache Data Store" 
                DisplayGroup          = "ArcGIS Data Store" 
                Ensure                = 'Present' 
                Access                = "Allow" 
                State                 = "Enabled" 
                Profile               = ("Domain","Private","Public")
                LocalPort             = if(($VersionArray[0] -eq 11) -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 7)){ ("29079-29082") }else{ ("29080", "29081") }                
                Protocol              = "TCP" 
                DependsOn             = $Depends
            }
            $Depends += @('[ArcGIS_xFirewall]TileCache_DataStore_FirewallRules')

            ArcGIS_xFirewall TileCache_FirewallRules_OutBound
            {
                Name                  = "ArcGISTileCacheDataStore-Out" 
                DisplayName           = "ArcGIS TileCache Data Store Out" 
                DisplayGroup          = "ArcGIS Data Store" 
                Ensure                = 'Present'
                Access                = "Allow" 
                State                 = "Enabled" 
                Profile               = ("Domain","Private","Public")
                LocalPort             = if(($VersionArray[0] -eq 11) -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 7)){ ("29079-29082") }else{ ("29080", "29081") }
                Direction             = "Outbound"                        
                Protocol              = "TCP" 
                DependsOn             = $Depends
            } 
            $Depends += @('[ArcGIS_xFirewall]TileCache_FirewallRules_OutBound')

            if(($DataStoreMachineCount -gt 1) -and (($VersionArray[0] -eq 11) -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 7))){
                ArcGIS_xFirewall MultiMachine_TileCache_DataStore_FirewallRules
                {
                    Name                  = "ArcGISMultiMachineTileCacheDataStore" 
                    DisplayName           = "ArcGIS Multi Machine Tile Cache Data Store" 
                    DisplayGroup          = "ArcGIS Data Store" 
                    Ensure                = 'Present' 
                    Access                = "Allow" 
                    State                 = "Enabled" 
                    Profile               = ("Domain","Private","Public")
                    LocalPort             = ("4369","29083-29090")                
                    Protocol              = "TCP" 
                    DependsOn             = $Depends
                }
                $Depends += @('[ArcGIS_xFirewall]MultiMachine_TileCache_DataStore_FirewallRules')

                ArcGIS_xFirewall MultiMachine_TileCache_FirewallRules_OutBound
                {
                    Name                  = "ArcGISMultiMachineTileCacheDataStore-Out" 
                    DisplayName           = "ArcGIS Multi Machine TileCache Data Store Out" 
                    DisplayGroup          = "ArcGIS TileCache Data Store" 
                    Ensure                = 'Present'
                    Access                = "Allow" 
                    State                 = "Enabled" 
                    Profile               = ("Domain","Private","Public")
                    LocalPort             = ("4369","29083-29090")     
                    Direction             = "Outbound"                        
                    Protocol              = "TCP" 
                    DependsOn             = $Depends
                } 
                $Depends += @('[ArcGIS_xFirewall]MultiMachine_TileCache_FirewallRules_OutBound')
            }
        }

        if($DataStoreType -ieq 'SpatioTemporal'){
            ArcGIS_xFirewall SpatioTemporalDataStore_FirewallRules
            {
                Name                  = "ArcGISSpatioTemporalDataStore" 
                DisplayName           = "ArcGIS SpatioTemporal Data Store" 
                DisplayGroup          = "ArcGIS Data Store" 
                Ensure                = 'Present'  
                Access                = "Allow" 
                State                 = "Enabled" 
                Profile               = ("Domain","Private","Public")
                LocalPort             = ("9320", "9220")
                Protocol              = "TCP" 
                DependsOn             = $Depends
            } 
            $Depends += '[ArcGIS_xFirewall]SpatioTemporalDataStore_FirewallRules'
        }
        
        if($DataStoreType -ieq 'GraphStore'){
            ArcGIS_xFirewall GraphDataStore_FirewallRules
            {
                Name                  = "ArcGISGraphDataStore" 
                DisplayName           = "ArcGIS Graph Data Store" 
                DisplayGroup          = "ArcGIS Data Store" 
                Ensure                = 'Present'  
                Access                = "Allow" 
                State                 = "Enabled" 
                Profile               = ("Domain","Private","Public")
                # if the machine count is greater than 2, then it is a clustered graph store with 3 machines
                # else it is a graph store in primary standby mode or single machine deployment
                LocalPort             = if($DataStoreMachineCount -gt 1){ if($DataStoreMachineCount -gt 2){ ("9828","9829","9830","9831") }else{ ("9829","9831") } }else{ ("9829") }
                Protocol              = "TCP" 
                DependsOn             = $Depends
            } 
            $Depends += '[ArcGIS_xFirewall]GraphDataStore_FirewallRules'
        }

        if($DataStoreType -ieq 'ObjectStore'){
            ArcGIS_xFirewall ObjectDataStore_FirewallRules
		    {
			    Name                  = "ArcGISObjectDataStore" 
			    DisplayName           = "ArcGIS Object Data Store" 
			    DisplayGroup          = "ArcGIS Object Data Store" 
			    Ensure                = 'Present'
			    Access                = "Allow" 
			    State                 = "Enabled" 
			    Profile               = ("Domain","Private","Public")
			    LocalPort             = ("29878","29879")                        
			    Protocol              = "TCP" 
		    }
            $Depends += '[ArcGIS_xFirewall]ObjectDataStore_FirewallRules'

            if($DataStoreMachineCount -gt 2){
                $ObjectStorePorts = @("9820", "9830", "9840", "9880", "29874", "29876", "29882","29875","29877","29883","29860-29863","29858","29859")
                if(($VersionArray[0] -gt 11) -or ($VersionArray[0] -eq 11 -and $VersionArray[1] -gt 5)){
                    $ObjectStorePorts = @("29860-29863","29858","29859")
                }

                ArcGIS_xFirewall ObjectDataStore_MultiMachine_FirewallRules
                {
                    Name                  = "ArcGISObjectMultiMachineDataStore" 
                    DisplayName           = "ArcGIS Object Multi Machine Data Store" 
                    DisplayGroup          = "ArcGIS Object Multi Machine Data Store" 
                    Ensure                = 'Present'
                    Access                = "Allow" 
                    State                 = "Enabled" 
                    Profile               = ("Domain","Private","Public")
                    LocalPort             = $ObjectStorePorts
                    Protocol              = "TCP" 
                }
                $Depends += @('[ArcGIS_xFirewall]ObjectDataStore_MultiMachine_FirewallRules')
            }            
        }

        ArcGIS_Service_Account ArcGIS_DataStore_RunAs_Account
        {
            Name = 'ArcGIS Data Store'
            RunAsAccount = $ServiceCredential
            Ensure = 'Present'
            DependsOn = $Depends
            DataDir = $ContentDirectoryLocation #DataStoreSpatioTemporalDataDirectory <- Needs to be checked if network location
            IsDomainAccount = $ServiceCredentialIsDomainAccount
            IsMSAAccount = $ServiceCredentialIsMSA
            ForceRunAsAccountUpdate = $ForceServiceCredentialUpdate
            SetStartupToAutomatic = $True
        }
        $Depends += '[ArcGIS_Service_Account]ArcGIS_DataStore_RunAs_Account'

        ArcGIS_DataStore "$($DataStoreType)-DataStore$($Node.NodeName)"
        {
            DatastoreMachineHostName = $Node.NodeName
            Version = $Version
            Ensure = 'Present'
            SiteAdministrator = $ServerPrimarySiteAdminCredential
            ServerHostName = $PrimaryServerMachine
            ContentDirectory = $ContentDirectoryLocation
            DataStoreTypes = @($DataStoreType)
            EnableFailoverOnPrimaryStop = $EnableFailoverOnPrimaryStop
            IsTileCacheDataStoreClustered =  if($DataStoreType -ieq 'TileCache'){ (($DataStoreMachineCount -gt 2) -or ($Version -ieq "10.8.0"))} else{ $False }
            IsObjectDataStoreClustered = if($DataStoreType -ieq 'ObjectStore'){ ($DataStoreMachineCount -gt 2)} else{ $False }
            IsGraphStoreClustered = if($DataStoreType -ieq 'GraphStore'){ ($DataStoreMachineCount -gt 2)} else{ $False }
            PITRState = if($EnablePointInTimeRecovery){ "Enabled" }else{ "Disabled" }
            DependsOn = $Depends
        }
        $DataStoreDependsOn = @("[ArcGIS_DataStore]$($DataStoreType)-DataStore$($Node.NodeName)")

        if(($PrimaryDataStoreMachine -ieq $Node.NodeName) -and ($null -ne $Backups)){
            foreach($Backup in $Backups) 
			{
                ArcGIS_DataStoreBackup "$($DataStoreType)-Backup-$($Backup.Name)"
                {
                    DataStoreType = $DataStoreType
                    BackupType = $Backup.Type
                    BackupName = $Backup.Name
                    BackupLocation = $Backup.Location
                    AWSS3Region = if($Backup.AWSS3Region){ $Backup.AWSS3Region }else{ $null}
                    CloudBackupCredential = $Backup.CloudCredential
                    IsDefault = $Backup.IsDefault
                    ForceDefaultRelationalBackupUpdate = if($DataStoreType -eq 'Relational'){ $Backup.ForceDefaultRelationalBackupUpdate }else{ $False }
                    ForceCloudCredentialsUpdate = $Backup.ForceCloudCredentialsUpdate
                    DependsOn = $DataStoreDependsOn
                }
            }
        }
    }
}
