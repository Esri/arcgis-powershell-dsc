Configuration DiskConfiguration
{   	
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_xDisk     
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
        $UnallocatedDataDisks = Get-Disk | Where-Object partitionstyle -eq 'raw'
        if(($UnallocatedDataDisks | Measure-Object).Count -gt 0)
        {
            ArcGIS_xDisk DataDisk
			{
				DiskNumber = 2
				DriveLetter = $DataDiskDriveLetter
			}   
            $Depends += '[ArcGIS_xDisk]DataDisk'
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
