Configuration PortalUpgrade{

    param(
        [Parameter(Mandatory=$false)]
        [System.String]
        $Version = '11.1',

		[parameter(Mandatory = $true)]
        [System.String]
        $PortalInstallerPath,

        [parameter(Mandatory = $false)]
        [System.String]
        $WebStylesInstallerPath,
		
		[parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
        $FileshareMachineCredential,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $ServiceCredential,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount,

		[Parameter(Mandatory=$false)]
        [System.String]
        $DebugMode		
    )

	function Get-FileNameFromUrl
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

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_Install 
    Import-DscResource -name ArcGIS_WindowsService
    Import-DscResource -Name ArcGIS_Service_Account
    
    $IsDebugMode = $DebugMode -ieq 'true'

    Node localhost {
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $true
        }

        if(-Not($ServiceCredentialIsDomainAccount)){
            User ArcGIS_RunAsAccount
            {
                UserName = $ServiceCredential.UserName
                Password = $ServiceCredential
                FullName = 'ArcGIS Run As Account'
                Ensure = "Present"
            }
        }

        $Depends = @()

        $InstallerFileName = Split-Path $PortalInstallerPath -Leaf
        $InstallerPathOnMachine = "$env:TEMP\portal\$InstallerFileName"
        
		File DownloadInstallerFromFileShare      
		{            	
			Ensure = "Present"              	
			Type = "File"             	
			SourcePath = $PortalInstallerPath 	
			DestinationPath = $InstallerPathOnMachine    
			Credential = $FileshareMachineCredential     
			DependsOn = $Depends  
        }
        
        ArcGIS_Install PortalUpgradeInstall
        { 
            Name = "Portal"
            Version = $Version
            Path = $InstallerPathOnMachine
            Arguments = "/qn ACCEPTEULA=YES";
            ServiceCredential = $ServiceCredential
            ServiceCredentialIsDomainAccount = $ServiceCredentialIsDomainAccount
            ServiceCredentialIsMSA = $False
            Ensure = "Present"
            DependsOn = $Depends
        }

		$Depends += '[ArcGIS_Install]PortalUpgradeInstall'
        
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

        $WebStylesInstallerFileName = Split-Path $WebStylesInstallerPath -Leaf
        $WebStylesInstallerPathOnMachine = "$env:TEMP\webstyles\$WebStylesInstallerFileName"
        File DownloadWebStylesInstallerFromFileShare      
        {            	
            Ensure = "Present"              	
            Type = "File"             	
            SourcePath = $WebStylesInstallerPath 	
            DestinationPath = $WebStylesInstallerPathOnMachine    
            Credential = $FileshareMachineCredential     
            DependsOn = $Depends  
        }
        $Depends += '[File]DownloadWebStylesInstallerFromFileShare'
        
        ArcGIS_Install "WebStylesInstall"
        { 
            Name = "WebStyles"
            Version = $Version
            Path = $WebStylesInstallerPathOnMachine
            Arguments = "/qn"
            Ensure = "Present"
            DependsOn = $Depends
        }

        $Depends += '[ArcGIS_Install]WebStylesInstall'

        Script RemoveWebStylesInstaller
        {
            SetScript = 
            { 
                Remove-Item $using:WebStylesInstallerPathOnMachine -Force
            }
            TestScript = { -not(Test-Path $using:WebStylesInstallerPathOnMachine) }
            GetScript = { $null }          
        }
        $Depends += '[Script]RemoveWebStylesInstaller'
        
        ArcGIS_WindowsService Portal_for_ArcGIS_Service
        {
            Name            = 'Portal for ArcGIS'
            Credential      = $ServiceCredential
            StartupType     = 'Automatic'
            State           = 'Running' 
            DependsOn       = $Depends
        }

        $Depends += '[ArcGIS_WindowsService]Portal_for_ArcGIS_Service'
        
        $DataDirsForPortal = @('HKLM:\SOFTWARE\ESRI\Portal for ArcGIS')

        ArcGIS_Service_Account Portal_Service_Account
		{
			Name            = 'Portal for ArcGIS'
            RunAsAccount    = $ServiceCredential
            IsDomainAccount = $ServiceCredentialIsDomainAccount
			Ensure          = 'Present'
            DependsOn       = if(-Not($ServiceCredentialIsDomainAccount)){@('[User]ArcGIS_RunAsAccount','[ArcGIS_WindowsService]Portal_for_ArcGIS_Service')}else{@('[ArcGIS_WindowsService]Portal_for_ArcGIS_Service')}
            DataDir         = $DataDirsForPortal
        }
    }
}
