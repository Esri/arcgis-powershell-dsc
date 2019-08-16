Configuration DataStoreUpgradeInstall{
    param(
        [System.String]
        $Version,

        [System.Management.Automation.PSCredential]
        $ServiceCredential,

        [System.String]
        $ServiceCredentialIsDomainAccount = 'false',

		[System.Management.Automation.PSCredential]
        $FileshareMachineCredential,

        [System.String]
        $InstallerPath,
        
		[Parameter(Mandatory=$false)]
        [System.String]
        $DebugMode
    )
    
	function Extract-FileNameFromUrl
    {
        param(
            [string]$Url
        )
        $FileName = $Url
        if($FileName) {
            $pos = $FileName.IndexOf('?')
            if($pos -gt 0) { 
                $FileName = $FileName.Substring(0, $pos) 
            } 
            $FileName = $FileName.Substring($FileName.LastIndexOf('/')+1)   
        }     
        $FileName
    }

    Import-DscResource -Name ArcGIS_Install
    Import-DscResource -Name ArcGIS_WindowsService
    
    Node localhost {
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $true
        }

        $Depends = @()
        $VersionArray = $Version.Split(".")
        $MajorVersion = $VersionArray[1]
        $MinorVersion = $VersionArray[2]

		$InstallerFileName = Split-Path $InstallerPath -Leaf

		$fPassword = ConvertTo-SecureString $FileshareMachineCredential.GetNetworkCredential().Password -AsPlainText -Force
        $fCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("SiteUpgradeVM\$($FileshareMachineCredential.UserName)", $fPassword )

        $InstallerPathOnMachine = "$env:TEMP\datastore\$InstallerFileName" 

		File DownloadInstallerFromFileShare      
		{            	
			Ensure = "Present"              	
			Type = "File"             	
			SourcePath = $InstallerPath 	
			DestinationPath =  $InstallerPathOnMachine     
			Credential = $fCredential     
			DependsOn = $Depends  
		}

        $Depends += '[File]DownloadInstallerFromFileShare'

        #ArcGIS Data Store 10.3 or 10.3.1, you must manually provide this account full control to your ArcGIS Data Store content directory 
        ArcGIS_Install DataStoreUpgrade{
            Name = "DataStore"
            Version = $Version
            Path = $InstallerPathOnMachine
            Arguments = "/qb USER_NAME=$($ServiceCredential.UserName) PASSWORD=$($ServiceCredential.GetNetworkCredential().Password)";
            Ensure = "Present"
            DependsOn = $Depends
        }

        $Depends += '[ArcGIS_Install]DataStoreUpgrade'
        
        Script RemoveInstaller
		{
			SetScript = 
			{ 
				Remove-Item $using:InstallerPathOnMachine -Force
			}
			TestScript = { -not(Test-Path $using:InstallerPathOnMachine) }
			GetScript = { $null }          
		}
            
        $Depends += '[Script]RemoveInstaller'
        
        # Fix for BDS Not Upgrading Bug - Setup needs to run as local account system
        # But in that case it cannot access (C:\Windows\System32\config\systemprofile\AppData\Local)
        if(-not(($MajorVersion -eq 7) -and ($MinorVersion -eq 1))){
            ArcGIS_WindowsService ArcGIS_DataStore_Service_Stop
            {
                Name = 'ArcGIS Data Store'
                Credential = $ServiceCredential
                StartupType = 'Manual'
                State = 'Stopped'
                DependsOn = $Depends
            }
            $Depends += '[ArcGIS_WindowsService]ArcGIS_DataStore_Service_Stop'

            $InstallDir = "$($env:SystemDrive)\arcgis\datastore"

            File CreateUpgradeFile
            {
                Ensure          = "Present"
                DestinationPath = "$($InstallDir)\etc\upgrade.txt"
                Contents        = ""
                Type            = "File"
                DependsOn = @('[ArcGIS_WindowsService]ArcGIS_DataStore_Service_Stop')
            }  
            $Depends += '[File]CreateUpgradeFile'

            Service ArcGIS_DataStore_Service_Start
            {
                Name = 'ArcGIS Data Store'
                Credential = $ServiceCredential
                StartupType = 'Automatic'
                State = 'Running'
                DependsOn = $Depends
            }
        }
    }
}