Configuration ArcGISDataStore 
{
    param(
        [Parameter(Mandatory=$true)]    
        [System.String]
        $Version,

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
        $PrimaryDataStore,
        
        [Parameter(Mandatory=$False)]
        [System.String]
        $PrimaryBigDataStore,
        
        [Parameter(Mandatory=$False)]
        [System.String]
        $PrimaryTileCache,

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
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 3.3.1
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -Name ArcGIS_DataStore
    Import-DscResource -Name ArcGIS_WaitForComponent

    Node $AllNodes.NodeName 
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }

        $VersionArray = $Version.Split(".")
        $MajorVersion = $VersionArray[1]
        $MinorVersion = if($VersionArray.Count -eq 3){ $VersionArray[2] }else { 0 }
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


        if(($AllNodes | Where-Object { $_.DataStoreTypes -icontains 'Relational' }  | Measure-Object).Count -gt 0){
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

            $IsMultiMachineDataStore = (($AllNodes | Where-Object { $_.DataStoreTypes -icontains 'Relational' } | Measure-Object).Count -gt 1)
            if($IsMultiMachineDataStore)
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
        }

        if(($AllNodes | Where-Object { $_.DataStoreTypes -icontains 'TileCache' }  | Measure-Object).Count -gt 0){
            ArcGIS_xFirewall TileCache_DataStore_FirewallRules
		    {
                Name                  = "ArcGISTileCacheDataStore" 
                DisplayName           = "ArcGIS Tile Cache Data Store" 
                DisplayGroup          = "ArcGIS Data Store" 
                Ensure                = 'Present' 
                Access                = "Allow" 
                State                 = "Enabled" 
                Profile               = ("Domain","Private","Public")
                LocalPort             = if($MajorVersion -gt 7){ ("29079-29082") }else{ ("29080", "29081") }                
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
                LocalPort             = if($MajorVersion -gt 7){ ("29079-29082") }else{ ("29080", "29081") }
                Direction             = "Outbound"                        
                Protocol              = "TCP" 
                DependsOn             = $Depends
            } 
            $Depends += @('[ArcGIS_xFirewall]TileCache_FirewallRules_OutBound')

            $TileCacheMachineCount = ($AllNodes | Where-Object { $_.DataStoreTypes -icontains 'TileCache' } | Measure-Object).Count
            if(($TileCacheMachineCount -gt 1) -and ($MajorVersion -gt 7)){
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

        if(($AllNodes | Where-Object { $_.DataStoreTypes -icontains 'SpatioTemporal' }  | Measure-Object).Count -gt 0)
        {
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

        
        $IsStandByRelational = (($Node.NodeName -ine $PrimaryDataStore) -and $Node.DataStoreTypes -icontains 'Relational')
        if($IsStandByRelational)
        {
            if($UsesSSL){
                ArcGIS_WaitForComponent "WaitForRelationalDataStore$($PrimaryDataStore)"{
                    Component = "DataStore"
                    InvokingComponent = "DataStore"
                    ComponentHostName = (Get-FQDN $PrimaryServerMachine)
                    ComponentContext = "arcgis"
                    Credential = $ServerPrimarySiteAdminCredential
                    Ensure = "Present"
                    RetryIntervalSec = 60
                    RetryCount = 100
                }
                $DependsOn += "[ArcGIS_WaitForComponent]WaitForRelationalDataStore$($PrimaryDataStore)"
            }else{
                WaitForAll "WaitForAllRelationalDataStore$($PrimaryDataStore)"
                {
                    ResourceName = "[ArcGIS_DataStore]DataStore$($PrimaryDataStore)"
                    NodeName = $PrimaryDataStore
                    RetryIntervalSec = 60
                    RetryCount = 100
                    DependsOn = $Depends
                }
                $Depends += "[WaitForAll]WaitForAllRelationalDataStore$($PrimaryDataStore)"
            }
        }

        if(($PrimaryBigDataStore -ine $Node.NodeName) -and ($Node.DataStoreTypes -icontains 'SpatioTemporal'))
        {
            if($UsesSSL){
                ArcGIS_WaitForComponent "WaitForBigDataStore$($PrimaryBigDataStore)"{
                    Component = "SpatioTemporal"
                    InvokingComponent = "DataStore"
                    ComponentHostName = (Get-FQDN $PrimaryServerMachine)
                    ComponentContext = "arcgis"
                    Credential = $ServerPrimarySiteAdminCredential
                    Ensure = "Present"
                    RetryIntervalSec = 60
                    RetryCount = 100
                }
                $DependsOn += "[ArcGIS_WaitForComponent]WaitForBigDataStore$($PrimaryBigDataStore)"
            }else{
                WaitForAll "WaitForAllBigDataStore$($PrimaryBigDataStore)"{
                    ResourceName = "[ArcGIS_DataStore]DataStore$($PrimaryBigDataStore)"
                    NodeName = $PrimaryBigDataStore
                    RetryIntervalSec = 60
                    RetryCount = 100
                    DependsOn = $Depends
                }
                $Depends += "[WaitForAll]WaitForAllBigDataStore$($PrimaryBigDataStore)"
            }
        }

        if(($PrimaryTileCache -ine $Node.NodeName) -and ($Node.DataStoreTypes -icontains 'TileCache'))
        {
            if($UsesSSL){
                ArcGIS_WaitForComponent "WaitForTileCache$($PrimaryTileCache)"{
                    Component = "TileCache"
                    InvokingComponent = "DataStore"
                    ComponentHostName = (Get-FQDN $PrimaryServerMachine)
                    ComponentContext = "arcgis"
                    Credential = $ServerPrimarySiteAdminCredential
                    Ensure = "Present"
                    RetryIntervalSec = 60
                    RetryCount = 100
                }
                $DependsOn += "[ArcGIS_WaitForComponent]WaitForTileCache$($PrimaryTileCache)"
            }else{
                WaitForAll "WaitForAllTileCache$($PrimaryTileCache)"{
                    ResourceName = "[ArcGIS_DataStore]DataStore$($PrimaryTileCache)"
                    NodeName = $PrimaryTileCache
                    RetryIntervalSec = 60
                    RetryCount = 100
                    DependsOn = $Depends
                }
                $Depends += "[WaitForAll]WaitForAllTileCache$($PrimaryTileCache)"
            }
        }

        ArcGIS_DataStore "DataStore$($Node.NodeName)"
        {
            DatastoreMachineHostName = (Get-FQDN $Node.NodeName)
            Ensure = 'Present'
            SiteAdministrator = $ServerPrimarySiteAdminCredential
            ServerHostName = (Get-FQDN $PrimaryServerMachine)
            ContentDirectory = $ContentDirectoryLocation
            DependsOn = $Depends
            IsStandby = $IsStandByRelational
            DataStoreTypes = $Node.DataStoreTypes
            EnableFailoverOnPrimaryStop = $EnableFailoverOnPrimaryStop
            IsTileCacheDataStoreClustered = (($TileCacheMachineCount -gt 2) -or ($MajorVersion -eq 8 -and $MinorVersion -eq 0))
            PITRState = if($EnablePointInTimeRecovery){ "Enabled" }else{ "Disabled" }
        }     
    }
}