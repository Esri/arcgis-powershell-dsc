Configuration DataStoreConfiguration
{
	param(
        [Parameter(Mandatory=$false)]
        [System.String]
        $Version = "12.0"

        ,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $IsAllInOneBaseDeploy = $false

        ,[Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServiceCredential

        ,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount

        ,[Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $SiteAdministratorCredential

        ,[Parameter(Mandatory=$true)]
        [System.Array]
        $DataStoreTypes
        
        ,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $IsDualMachineRelationalDataStore = $false

        ,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $IsMultiMachineGraphStore = $false

        ,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $IsMultiMachineSpatioTemporalDataStore = $false

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $ServerMachineNames

        ,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $DebugMode
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
	Import-DscResource -Name ArcGIS_DataStore
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -name ArcGIS_WindowsService
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_Disk
    Import-DscResource -Name ArcGIS_AzureSetupDownloadsFolderManager
    Import-DscResource -Name ArcGIS_HostNameSettings
    
    $ServerHostNames = ($ServerMachineNames -split ',')
    $ServerMachineName = $ServerHostNames | Select-Object -First 1
    $DataStoreContentDirectory = "$($env:SystemDrive)\\arcgis\\datastore\\content"
    
	Node localhost
	{
        $DataStoreDependsOn = @()

        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $false
        }
        
        ArcGIS_Disk DiskSizeCheck
        {
            HostName = $env:ComputerName
        }

        # check if the current machine is in the list of server names
        $IsCurrentMachineInServerList = $false
        if($IsAllInOneBaseDeploy){
            foreach ($ServerName in $ServerHostNames) {
                if ($env:COMPUTERNAME -eq $ServerName) {
                    $IsCurrentMachineInServerList = $true
                    break
                }
            }
        }

        ArcGIS_AzureSetupDownloadsFolderManager CleanupDownloadsFolder{
            Version = $Version
            OperationType = 'CleanupDownloadsFolder'
            ComponentNames = if($IsCurrentMachineInServerList){ "DataStore,Server,Portal" }else{ "DataStore" }
        }

        $HasValidServiceCredential = ($ServiceCredential -and ($ServiceCredential.GetNetworkCredential().Password -ine 'Placeholder'))
        if($HasValidServiceCredential) 
        {
            if(-Not($ServiceCredentialIsDomainAccount)){
                User ArcGIS_RunAsAccount
                {
                    UserName       = $ServiceCredential.UserName
                    Password       = $ServiceCredential
                    FullName       = 'ArcGIS Service Account'
                    Ensure         = 'Present'
                    PasswordChangeRequired = $false
                    PasswordNeverExpires = $true
                }
            }

            ArcGIS_WindowsService ArcGIS_DataStore_Service
            {
                Name            = 'ArcGIS Data Store'
                Credential      = $ServiceCredential
                StartupType     = 'Automatic'
                State           = 'Running' 
                DependsOn       = if(-Not($ServiceCredentialIsDomainAccount)){ @('[User]ArcGIS_RunAsAccount')}else{ @()}
            }
                
            ArcGIS_Service_Account DataStore_Service_Account
		    {
			    Name            = 'ArcGIS Data Store'
                RunAsAccount    = $ServiceCredential
                Ensure          = 'Present'
			    DependsOn       = if(-Not($ServiceCredentialIsDomainAccount)){ @('[User]ArcGIS_RunAsAccount','[ArcGIS_WindowsService]ArcGIS_DataStore_Service')}else{ @('[ArcGIS_WindowsService]ArcGIS_DataStore_Service')}
                DataDir         = $DataStoreContentDirectory  
                IsDomainAccount = $ServiceCredentialIsDomainAccount
            }
            $DataStoreDependsOn +=  @('[ArcGIS_Service_Account]DataStore_Service_Account')
            
            if($DataStoreTypes -icontains "Relational")
            {
                ArcGIS_xFirewall DataStore_FirewallRules
                {
                    Name                  = "ArcGISDataStore" 
                    DisplayName           = "ArcGIS Data Store" 
                    DisplayGroup          = "ArcGIS Data Store" 
                    Ensure                = 'Present' 
                    Access                = "Allow" 
                    State                 = "Enabled" 
                    Profile               = ("Domain","Private","Public")
                    LocalPort             = ("2443", "9876")                        
                    Protocol              = "TCP" 
                }
                $DataStoreDependsOn += @('[ArcGIS_xFirewall]DataStore_FirewallRules')

                ArcGIS_xFirewall Queue_DataStore_FirewallRules_OutBound
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
                }
                $DataStoreDependsOn += '[ArcGIS_xFirewall]Queue_DataStore_FirewallRules_OutBound'

                if($IsDualMachineRelationalDataStore)
                {
                    ArcGIS_xFirewall DataStore_FirewallRules_OutBound
                    {
                        Name                  = "ArcGISDataStore-Out" 
                        DisplayName           = "ArcGIS Data Store Out" 
                        DisplayGroup          = "ArcGIS Data Store" 
                        Ensure                = 'Present'
                        Access                = "Allow" 
                        State                 = "Enabled" 
                        Profile               = ("Domain","Private","Public")
                        LocalPort             = ("9876")       
                        Direction             = "Outbound"                        
                        Protocol              = "TCP" 
                    } 

                    $DataStoreDependsOn += @('[ArcGIS_xFirewall]DataStore_FirewallRules_OutBound')
                }

                if($Version -ieq "12.0"){
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
                    }
                    $DataStoreDependsOn += '[ArcGIS_xFirewall]MemoryCache_DataStore_FirewallRules'
                }
            }

            if($DataStoreTypes -icontains "SpatioTemporal")
            {
                ArcGIS_xFirewall SpatioTemporalDataStore_FirewallRules
                {
                    Name                  = "ArcGISSpatioTemporalDataStore" 
                    DisplayName           = "ArcGIS SpatioTemporal Data Store" 
                    DisplayGroup          = "ArcGIS SpatioTemporal Data Store" 
                    Ensure                = 'Present'
                    Access                = "Allow" 
                    State                 = "Enabled" 
                    Profile               = ("Domain","Private","Public")
                    LocalPort             = ("2443", "9220")                        
                    Protocol              = "TCP" 
                } 
                $DataStoreDependsOn += @('[ArcGIS_xFirewall]SpatioTemporalDataStore_FirewallRules')

                if($IsMultiMachineSpatioTemporalDataStore){
                    ArcGIS_xFirewall SpatioTemporalDataStore_MultiMachine_FirewallRules
                    {
                        Name                  = "ArcGISSpatioTemporalMultiMachineDataStore" 
                        DisplayName           = "ArcGIS SpatioTemporal Multi Machine Data Store" 
                        DisplayGroup          = "ArcGIS SpatioTemporal Multi Machine Data Store" 
                        Ensure                = 'Present'
                        Access                = "Allow" 
                        State                 = "Enabled" 
                        Profile               = ("Domain","Private","Public")
                        LocalPort             = ("9320")                        
                        Protocol              = "TCP" 
                    } 
                    $DataStoreDependsOn += @('[ArcGIS_xFirewall]SpatioTemporalDataStore_MultiMachine_FirewallRules')
                }
            }

            if($DataStoreTypes -icontains "GraphStore"){
                ArcGIS_xFirewall GraphDataStore_FirewallRules
                {
                    Name                  = "ArcGISGraphDataStore" 
                    DisplayName           = "ArcGIS Graph Data Store" 
                    DisplayGroup          = "ArcGIS Graph Data Store" 
                    Ensure                = 'Present'
                    Access                = "Allow" 
                    State                 = "Enabled" 
                    Profile               = ("Domain","Private","Public")
                    LocalPort             = if($IsMultiMachineGraphStore){ ("2443","9828","9829","9830","9831") }else{ ("2443","9829") }
                    Protocol              = "TCP" 
                }
                $DataStoreDependsOn += @('[ArcGIS_xFirewall]GraphDataStore_FirewallRules')
            }

            ArcGIS_HostNameSettings DataStoreHostNameSettings{
                ComponentName   = "DataStore"
                Version         = $Version
                DependsOn       = $DataStoreDependsOn
            }
            $DataStoreDependsOn += '[ArcGIS_HostNameSettings]DataStoreHostNameSettings'

            ArcGIS_DataStore DataStore
		    {
			    Ensure                     = 'Present'
                Version                    = $Version
			    SiteAdministrator          = $SiteAdministratorCredential
			    ServerHostName             = $ServerMachineName
			    ContentDirectory           = $DataStoreContentDirectory
			    DataStoreTypes             = $DataStoreTypes
                IsGraphStoreClustered      = $IsMultiMachineGraphStore
                EnableFailoverOnPrimaryStop= $true
			    DependsOn                  = $DataStoreDependsOn
		    } 
 
            $ServicesToStop = @('ArcGIS Server', 'Portal for ArcGIS', 'ArcGISGeoEvent', 'ArcGISGeoEventGateway', 'ArcGIS Notebook Server', 'ArcGIS Mission Server', 'WorkflowManager')
            if($IsAllInOneBaseDeploy -ieq 'True'){
                $ServicesToStop = @('ArcGISGeoEvent', 'ArcGISGeoEventGateway', 'ArcGIS Notebook Server', 'ArcGIS Mission Server', 'WorkflowManager')
            }

		    foreach($ServiceToStop in $ServicesToStop)
		    {
			    if(Get-Service $ServiceToStop -ErrorAction Ignore) 
			    {
				    Service "$($ServiceToStop.Replace(' ','_'))_Service"
				    {
					    Name			= $ServiceToStop
					    Credential		= $ServiceCredential
					    StartupType		= 'Manual'
					    State			= 'Stopped'
					    DependsOn		= if(-Not($ServiceCredentialIsDomainAccount)){ @('[User]ArcGIS_RunAsAccount')}else{ @()}
				    }
			    }
		    }
        }
	}
}
