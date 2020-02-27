Configuration TileCacheDataStoreConfiguration{
	param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServiceCredential

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServiceCredentialIsDomainAccount = 'false'

        ,[Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $SiteAdministratorCredential
        
        ,[Parameter(Mandatory=$true)]
        [System.String]
        $IsMultiMachineTileCache

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $TileCacheDataStoreMachineNames

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $ServerMachineNames

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $FileShareMachineName

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $DataStoreTypes = 'TileCache'
        
        ,[Parameter(Mandatory=$false)]
        [System.Int32]
        $OSDiskSize = 0

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $EnableDataDisk  

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $FileShareName = 'fileshare' 
        
        ,[Parameter(Mandatory=$false)]
        [System.String]
        $DebugMode
    )
        
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
	Import-DscResource -Name ArcGIS_DataStore
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -name ArcGIS_WindowsService
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_xDisk
    Import-DscResource -Name ArcGIS_Disk
    
    $TileCacheDataStoreHostNames = ($TileCacheDataStoreMachineNames -split ',')    
    $ServerHostNames = ($ServerMachineNames -split ',')
    $ServerMachineName = $ServerHostNames | Select-Object -First 1    
    $IsDebugMode = $DebugMode -ieq 'true'    
    $IsServiceCredentialDomainAccount = $ServiceCredentialIsDomainAccount -ieq 'true'
    $DataStoreContentDirectory = "$($env:SystemDrive)\\arcgis\\datastore\\content"

	Node localhost
	{
        $DataStoreDependsOn = @()
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $true
        }
        
        if($OSDiskSize -gt 0) 
        {
            ArcGIS_Disk OSDiskSize
            {
                DriveLetter = ($env:SystemDrive -replace ":" )
                SizeInGB    = $OSDiskSize
            }
        }
        
        if($EnableDataDisk -ieq 'true')
        {
            ArcGIS_xDisk DataDisk
            {
                DiskNumber  =  2
                DriveLetter = 'F'
            }
        }

        $HasValidServiceCredential = ($ServiceCredential -and ($ServiceCredential.GetNetworkCredential().Password -ine 'Placeholder'))
        if($HasValidServiceCredential) 
        {
            if(-Not($IsServiceCredentialDomainAccount)){
                User ArcGIS_RunAsAccount
                {
                    UserName       = $ServiceCredential.UserName
                    Password       = $ServiceCredential
                    FullName       = 'ArcGIS Service Account'
                    Ensure         = 'Present'
                    PasswordChangeRequired = $false
                    PasswordNeverExpires = $true
                }
                $DataStoreDependsOn += @('[User]ArcGIS_RunAsAccount')
            }

            ArcGIS_WindowsService ArcGIS_DataStore_Service
            {
                Name            = 'ArcGIS Data Store'
                Credential      = $ServiceCredential
                StartupType     = 'Automatic'
                State           = 'Running' 
                DependsOn       = $DataStoreDependsOn
            }
            $DataStoreDependsOn += @('[ArcGIS_WindowsService]ArcGIS_DataStore_Service')
                
            ArcGIS_Service_Account DataStore_Service_Account
		    {
			    Name            = 'ArcGIS Data Store'
                RunAsAccount    = $ServiceCredential
                IsDomainAccount = $IsServiceCredentialDomainAccount
			    Ensure          = 'Present'
			    DependsOn       = $DataStoreDependsOn
                DataDir         = $DataStoreContentDirectory  
            }
            $DataStoreDependsOn += @('[ArcGIS_Service_Account]DataStore_Service_Account')

            ArcGIS_xFirewall TileCacheDataStore_FirewallRules
		    {
			    Name                  = "ArcGISTileCacheDataStore" 
			    DisplayName           = "ArcGIS Data Store" 
			    DisplayGroup          = "ArcGIS Data Store" 
			    Ensure                = 'Present'
			    Access                = "Allow" 
			    State                 = "Enabled" 
			    Profile               = ("Domain","Private","Public")
			    LocalPort             = ("2443","29079-29082")                        
			    Protocol              = "TCP" 
            }    
            $DataStoreDependsOn += @('[ArcGIS_xFirewall]TileCacheDataStore_FirewallRules')

            ArcGIS_xFirewall TileCache_FirewallRules_OutBound
            {
                Name                  = "ArcGISTileCacheDataStore-Out" 
                DisplayName           = "ArcGIS TileCache Data Store Out" 
                DisplayGroup          = "ArcGIS TileCache Data Store" 
                Ensure                = 'Present'
                Access                = "Allow" 
                State                 = "Enabled" 
                Profile               = ("Domain","Private","Public")
                LocalPort             = ("29079-29082")       
                Direction             = "Outbound"                        
                Protocol              = "TCP" 
            } 
            $DataStoreDependsOn += @('[ArcGIS_xFirewall]TileCache_FirewallRules_OutBound')
            
            if($IsMultiMachineTileCache) {
                ArcGIS_xFirewall MultiMachine_TileCache_DataStore_FirewallRules
                {
                    Name                  = "ArcGISMultiMachineTileCacheDataStore" 
                    DisplayName           = "ArcGIS Multi Machine Tile Cache Data Store" 
                    DisplayGroup          = "ArcGIS Tile Cache Data Store" 
                    Ensure                = 'Present' 
                    Access                = "Allow" 
                    State                 = "Enabled" 
                    Profile               = ("Domain","Private","Public")
                    LocalPort             = ("4369","29083-29090")                        
                    Protocol              = "TCP" 
                }
                $DataStoreDependsOn += @('[ArcGIS_xFirewall]MultiMachine_TileCache_DataStore_FirewallRules')

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
                } 
                $DataStoreDependsOn += @('[ArcGIS_xFirewall]MultiMachine_TileCache_FirewallRules_OutBound')
            }

            ArcGIS_DataStore TileCacheDataStore
		    {
			    Ensure				= 'Present'
			    SiteAdministrator	= $SiteAdministratorCredential 
			    ServerHostName		= $ServerMachineName
			    ContentDirectory	= $DataStoreContentDirectory
                DataStoreTypes		= $DataStoreTypes
                IsEnvAzure          = $true
			    DependsOn			= $DataStoreDependsOn
		    }
            
            foreach($ServiceToStop in @('ArcGIS Server', 'Portal for ArcGIS', 'ArcGISGeoEvent', 'ArcGISGeoEventGateway', 'ArcGIS Notebook Server'))
		    {
			    if(Get-Service $ServiceToStop -ErrorAction Ignore) 
			    {
				    Service "$($ServiceToStop.Replace(' ','_'))_Service"
				    {
					    Name			= $ServiceToStop
					    Credential		= $ServiceCredential
					    StartupType		= 'Manual'
					    State			= 'Stopped'
					    DependsOn		= if(-Not($IsServiceCredentialDomainAccount)){@('[User]ArcGIS_RunAsAccount')}else{@()}
				    }
			    }
		    }
        }
	}
}