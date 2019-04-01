Configuration DiskConfiguration
{   	
    Import-DscResource -Name MSFT_xDisk     
    Import-DscResource -Name ArcGIS_Disk
    
    Node localhost
    {   
		LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $true
        }

		ArcGIS_Disk OSDiskSize
        {
            DriveLetter = 'C'
            SizeInGB    = 4096
        }

		$DataDiskDriveLetter = 'F'
        $Depends = @()
        if((Get-Partition | Measure-Object).Count -ne (Get-Disk | Measure-Object).Count) 
        {
            xDisk DataDisk
			{
				DiskNumber = 2
				DriveLetter = $DataDiskDriveLetter
			}   
            $Depends += '[xDisk]DataDisk'
        }
		
        if(Get-Partition -DriveLetter $DataDiskDriveLetter -ErrorAction Ignore) 
		{
			ArcGIS_Disk DataDiskSize
			{
				DriveLetter = $DataDiskDriveLetter
				SizeInGB    = 4095
				DependsOn   = $Depends			
			}	
		}
    }
}