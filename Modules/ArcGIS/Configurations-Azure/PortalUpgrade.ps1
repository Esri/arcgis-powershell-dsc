Configuration PortalUpgrade{

    param(
        [Parameter(Mandatory=$false)]
        [System.String]
        $Version = "12.0",

        [parameter(Mandatory = $true)]
        [System.String]
        $UpgradeVMName,

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
        [System.Boolean]
        $IsMultiMachinePortal,

        [Parameter(Mandatory=$True)]
        [System.Management.Automation.PSCredential]
        $DeploymentArtifactCredentials,

		[Parameter(Mandatory=$false)]
        [System.Boolean]
        $DebugMode
    )

	Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_Install 
    Import-DscResource -name ArcGIS_WindowsService
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -Name ArcGIS_HostNameSettings
    
    $UpgradeSetupsStagingPath = "C:\ArcGIS\Deployment\Downloads\$($Version)"

    Node localhost {
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $false
        }

        if(-Not($ServiceCredentialIsDomainAccount)){
            User ArcGIS_RunAsAccount
            {
                UserName = $ServiceCredential.UserName
                Password = $ServiceCredential
                FullName = 'ArcGIS Service Account'
                Ensure = "Present"
            }
        }

        ArcGIS_AzureSetupDownloadsFolderManager CleanupDownloadsFolder{
            Version = $Version
            OperationType = 'CleanupDownloadsFolder'
            ComponentNames = "All"
        }
        $Depends = @("[ArcGIS_AzureSetupDownloadsFolderManager]CleanupDownloadsFolder")

        $VersionArray = $Version.Split(".")
        if($IsMultiMachinePortal -and (($VersionArray[0] -gt 11) -or ($VersionArray[0] -ieq 11 -and $VersionArray[1] -ge 3))){ # 11.3 or later
            ArcGIS_xFirewall Portal_Ignite_OutBound
            {
                Name                  = "PortalforArcGIS-Ignite-Outbound" 
                DisplayName           = "Portal for ArcGIS Ignite Outbound" 
                DisplayGroup          = "Portal for ArcGIS Ignite Outbound" 
                Ensure                = 'Present' 
                Access                = "Allow" 
                State                 = "Enabled" 
                Profile               = ("Domain","Private","Public")
                RemotePort            = ("7820","7830", "7840") # Ignite uses 7820,7830,7840
                Direction             = "Outbound"                       
                Protocol              = "TCP" 
            }  
            $Depends += @('[ArcGIS_xFirewall]Portal_Ignite_OutBound')
            
            ArcGIS_xFirewall Portal_Ignite_InBound
            {
                Name                  = "PortalforArcGIS-Ignite-Inbound" 
                DisplayName           = "Portal for ArcGIS Ignite Inbound" 
                DisplayGroup          = "Portal for ArcGIS Ignite Inbound" 
                Ensure                = 'Present' 
                Access                = "Allow" 
                State                 = "Enabled" 
                Profile               = ("Domain","Private","Public")
                LocalPort            = ("7820","7830", "7840") # Ignite uses 7820,7830,7840
                Protocol              = "TCP" 
            }  
            $Depends += @('[ArcGIS_xFirewall]Portal_Ignite_InBound')
        }

        ArcGIS_AzureSetupDownloadsFolderManager DownloadPortalUpgradeSetup{
            Version = $Version
            OperationType = 'DownloadUpgradeSetups'
            ComponentNames = "Portal"
            UpgradeSetupsSourceFileSharePath = "\\$($UpgradeVMName)\UpgradeSetups"
            UpgradeSetupsSourceFileShareCredentials = $FileshareMachineCredential
            DependsOn = $Depends
        }
        $Depends += '[ArcGIS_AzureSetupDownloadsFolderManager]DownloadPortalUpgradeSetup'
        
        
        $PortalInstallerPathOnMachine = "$($UpgradeSetupsStagingPath)\PortalforArcGIS.exe"
		$PortalInstallerVolumePathOnMachine = "$($UpgradeSetupsStagingPath)\PortalforArcGIS.exe.001"
        $WebStylesInstallerPathOnMachine = "$($UpgradeSetupsStagingPath)\WebStyles.exe"

        ArcGIS_Install PortalUpgradeInstall
        { 
            Name = "Portal"
            Version = $Version
            Path = $PortalInstallerPathOnMachine
            Arguments = "/qn ACCEPTEULA=YES";
            ServiceCredential = $ServiceCredential
            ServiceCredentialIsDomainAccount = $ServiceCredentialIsDomainAccount
            ServiceCredentialIsMSA = $False
            Ensure = "Present"
            EnableMSILogging = $DebugMode
            DependsOn = $Depends
        }
		$Depends += '[ArcGIS_Install]PortalUpgradeInstall'
        
        ArcGIS_Install "WebStylesInstall"
        { 
            Name = "WebStyles"
            Version = $Version
            Path = $WebStylesInstallerPathOnMachine
            Arguments = "/qn"
            Ensure = "Present"
            EnableMSILogging = $DebugMode
            DependsOn = $Depends
        }
        $Depends += '[ArcGIS_Install]WebStylesInstall'

        Script RemovePortalAndWebStyleInstallers
		{
			SetScript = 
			{ 
                if(-not([string]::IsNullOrEmpty($using:PortalInstallerPathOnMachine)) -and (Test-Path $using:PortalInstallerPathOnMachine)){
				    Remove-Item $using:PortalInstallerPathOnMachine -Force
                }
                if(-not([string]::IsNullOrEmpty($using:PortalInstallerVolumePathOnMachine)) -and (Test-Path $using:PortalInstallerVolumePathOnMachine)){
                    Remove-Item $using:PortalInstallerVolumePathOnMachine -Force
                }
                if(-not([string]::IsNullOrEmpty($using:WebStylesInstallerPathOnMachine)) -and (Test-Path $using:WebStylesInstallerPathOnMachine)){
                    Remove-Item $using:WebStylesInstallerPathOnMachine -Force
                }
			}
			TestScript = { -not(Test-Path $using:PortalInstallerPathOnMachine) -and -not(Test-Path $using:PortalInstallerVolumePathOnMachine) -and -not(Test-Path $using:WebStylesInstallerPathOnMachine) }
			GetScript = { $null }
            DependsOn = $Depends
		}
        $Depends += '[Script]RemovePortalAndWebStyleInstallers'
        
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

        ArcGIS_HostNameSettings PortalHostNameSettings
        {
            ComponentName   = "Portal"
            Version         = $Version
            HostName        = $env:COMPUTERNAME
            DependsOn       = @('[ArcGIS_Service_Account]Portal_Service_Account')
        }
    }
}