Configuration DiskConfiguration
{   	
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_Disk
    
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
    }
}
