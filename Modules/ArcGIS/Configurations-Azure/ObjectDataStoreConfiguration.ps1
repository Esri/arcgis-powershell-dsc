Configuration ObjectDataStoreConfiguration
{
	param(
        [Parameter(Mandatory=$false)]
        [System.String]
        $Version = '11.1'

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
        [System.String]
        $ObjectDataStoreMachineNames

        ,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $IsObjectDataStoreClustered = $False

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $ServerMachineNames

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $FileShareMachineName

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $DataStoreTypes = 'ObjectStore'
        
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
    
    $ObjectDataStoreHostNames = ($ObjectDataStoreMachineNames -split ',')    
    $ServerHostNames = ($ServerMachineNames -split ',')
    $ServerMachineName = $ServerHostNames | Select-Object -First 1    
    $IsDebugMode = $DebugMode -ieq 'true'
    $DataStoreContentDirectory = "$($env:SystemDrive)\\arcgis\\datastore\\content"

	Node localhost
	{
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
                DependsOn       = if(-Not($ServiceCredentialIsDomainAccount)){@('[User]ArcGIS_RunAsAccount')}else{@()}
            }
                
            ArcGIS_Service_Account DataStore_Service_Account
		    {
			    Name            = 'ArcGIS Data Store'
                RunAsAccount    = $ServiceCredential
                IsDomainAccount = $ServiceCredentialIsDomainAccount
			    Ensure          = 'Present'
			    DependsOn       = if(-Not($ServiceCredentialIsDomainAccount)){@('[User]ArcGIS_RunAsAccount','[ArcGIS_WindowsService]ArcGIS_DataStore_Service')}else{@('[ArcGIS_WindowsService]ArcGIS_DataStore_Service')}
                DataDir         = $DataStoreContentDirectory  
		    }
            
            ArcGIS_xFirewall ObjectDataStore_FirewallRules
		    {
			    Name                  = "ArcGISObjectDataStore" 
			    DisplayName           = "ArcGIS Object Data Store" 
			    DisplayGroup          = "ArcGIS Object Data Store" 
			    Ensure                = 'Present'
			    Access                = "Allow" 
			    State                 = "Enabled" 
			    Profile               = ("Domain","Private","Public")
			    LocalPort             = ("2443","29878","29879")                        
			    Protocol              = "TCP" 
		    }
            $DataStoreDependsOn = @('[ArcGIS_xFirewall]ObjectDataStore_FirewallRules', '[ArcGIS_Service_Account]DataStore_Service_Account') 

            if($ObjectDataStoreHostNames.Length -gt 1){
                ArcGIS_xFirewall ObjectDataStore_MultiMachine_FirewallRules
                {
                    Name                  = "ArcGISObjectMultiMachineDataStore" 
                    DisplayName           = "ArcGIS Object Multi Machine Data Store" 
                    DisplayGroup          = "ArcGIS Object Multi Machine Data Store" 
                    Ensure                = 'Present'
                    Access                = "Allow" 
                    State                 = "Enabled" 
                    Profile               = ("Domain","Private","Public")
                    LocalPort             = ("9820", "9830", "9840", "9880", "29874", "29876", "29882","29875","29877","29883","29860-29863","29858","29859")
                    Protocol              = "TCP" 
                }
                $DataStoreDependsOn += @('[ArcGIS_xFirewall]ObjectDataStore_MultiMachine_FirewallRules')
            }

            ArcGIS_DataStore ObjectDataStore
		    {
			    Ensure				= 'Present'
                Version             = $Version
			    SiteAdministrator	= $SiteAdministratorCredential 
			    ServerHostName		= $ServerMachineName
			    ContentDirectory	= $DataStoreContentDirectory
                DataStoreTypes		= $DataStoreTypes
                IsObjectDataStoreClustered = $IsObjectDataStoreClustered
                DependsOn			= $DataStoreDependsOn
		    }

            foreach($ServiceToStop in @( 'ArcGIS Server', 'Portal for ArcGIS', 'ArcGISGeoEvent', 'ArcGISGeoEventGateway', 'ArcGIS Notebook Server', 'ArcGIS Mission Server', 'WorkflowManager'))
		    {
			    if(Get-Service $ServiceToStop -ErrorAction Ignore) 
			    {
				    Service "$($ServiceToStop.Replace(' ','_'))_Service"
				    {
					    Name			= $ServiceToStop
					    Credential		= $ServiceCredential
					    StartupType		= 'Manual'
					    State			= 'Stopped'
					    DependsOn		= if(-Not($ServiceCredentialIsDomainAccount)){@('[User]ArcGIS_RunAsAccount')}else{@()}
				    }
			    }
		    }
        }
	}
}
