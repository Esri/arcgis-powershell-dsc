Configuration GraphDataStoreConfiguration
{
	param(
        [Parameter(Mandatory=$false)]
        [System.String]
        $Version = 11.4

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
        $GraphDataStoreMachineNames

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $ServerMachineNames

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $DataStoreTypes = 'GraphStore'
        
        ,[Parameter(Mandatory=$true)]
        [System.Boolean]
        $UseExistingFileShare

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $FileShareMachineName
        
        ,[Parameter(Mandatory=$false)]
        [System.String]
        $FileShareName = 'fileshare'

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $FileSharePath
        
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
    
    $GraphDataStoreHostNames = ($GraphDataStoreMachineNames -split ',')    
    $ServerHostNames = ($ServerMachineNames -split ',')
    $ServerMachineName = $ServerHostNames | Select-Object -First 1    
    $DataStoreContentDirectory = "$($env:SystemDrive)\\arcgis\\datastore\\content"

	Node localhost
	{
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $true
        }
        
        ArcGIS_Disk DiskSizeCheck
        {
            HostName = $env:ComputerName
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

            ArcGIS_xFirewall GraphDataStore_FirewallRules
		    {
			    Name                  = "ArcGISGraphDataStore" 
			    DisplayName           = "ArcGIS Graph Data Store" 
			    DisplayGroup          = "ArcGIS Graph Data Store" 
			    Ensure                = 'Present'
			    Access                = "Allow" 
			    State                 = "Enabled" 
			    Profile               = ("Domain","Private","Public")
			    LocalPort             = if($GraphDataStoreHostNames.Length -gt 1){ ("2443","9829", "9831") }else{ ("2443","9829") }
			    Protocol              = "TCP" 
		    }    

            ArcGIS_DataStore GraphDataStore
		    {
			    Ensure				= 'Present'
                Version             = $Version
			    SiteAdministrator	= $SiteAdministratorCredential 
			    ServerHostName		= $ServerMachineName
			    ContentDirectory	= $DataStoreContentDirectory
                DataStoreTypes		= $DataStoreTypes
                EnableFailoverOnPrimaryStop= $true
			    DependsOn			= @('[ArcGIS_xFirewall]GraphDataStore_FirewallRules', '[ArcGIS_Service_Account]DataStore_Service_Account') 
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
