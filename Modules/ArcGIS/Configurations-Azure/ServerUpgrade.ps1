Configuration ServerUpgrade{
    param(
        [Parameter(Mandatory=$false)]
        [System.String]
        $Version = "12.2",

        [Parameter(Mandatory=$True)]
        [System.String]
        $OldVersion,

        [System.Management.Automation.PSCredential]
        $ServiceCredential,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount,

		[System.Management.Automation.PSCredential]
        $FileshareMachineCredential,

        [parameter(Mandatory = $true)]
        [System.String]
        $UpgradeVMName,

        [System.String]
        $ServerLicenseFileName,

		[System.String]
        $ServerRole,
        
		[Parameter(Mandatory=$false)]
        [System.Boolean]
        $IsNotebookServerWebAdaptorUpgrade = $False,

        [Parameter(Mandatory=$false)]
        [System.String]
        $NotebookWebAdaptorContext = "",

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
		$SiteAdministratorCredential,
		
		[Parameter(Mandatory=$false)]
        [System.Boolean]
        $DebugMode,

        [Parameter(Mandatory=$True)]
        [System.Management.Automation.PSCredential]
        $DeploymentArtifactCredentials,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $IsMultiMachineServerSite,
        
        [Parameter(Mandatory=$false)]
        [ValidateRange(0, 65535)]
        [System.Int32]
        $VideoServerSrtPort = 9710
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_Install 
    Import-DscResource -Name ArcGIS_License
    Import-DscResource -Name ArcGIS_ServerUpgrade 
    Import-DscResource -Name ArcGIS_xFirewall 
    Import-DscResource -Name ArcGIS_WebAdaptor
    Import-DscResource -Name ArcGIS_AzureSetupsManager
    Import-DscResource -Name ArcGIS_HostNameSettings
    Import-DscResource -Name ArcGIS_RemoteFile
    Import-DscResource -Name ArcGIS_WindowsService
    
    $ServiceCredentialUserName = $ServiceCredential.UserName
    $UpgradeSetupsStagingPath = "C:\ArcGIS\Deployment\Downloads\$($Version)"

    Node localhost {
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $false
        }

		ArcGIS_AzureSetupsManager CleanupDownloadsFolder{
            Version = $Version
            OperationType = 'CleanupDownloadsFolder'
            ComponentNames = "All"
        }
        $Depends = @("[ArcGIS_AzureSetupsManager]CleanupDownloadsFolder")
        
        if(-Not($ServiceCredentialIsDomainAccount)){
            User ArcGIS_RunAsAccount
            {
                UserName = $ServiceCredential.UserName
                Password = $ServiceCredential
                FullName = 'ArcGIS Service Account'
                Ensure = "Present"
            }
            $Depends += '[User]ArcGIS_RunAsAccount'
        }

        if($ServerRole -ieq "NotebookServer" -and (@("10.9.1","11.0","11.1","11.2","11.3") -icontains $OldVersion)){
            ArcGIS_Install NotebookUninstallSamplesData{
                Name = "NotebookServerSamplesData"
                Version = $OldVersion
                Ensure = "Absent"
                DependsOn = $Depends
            }
            $Depends += '[ArcGIS_Install]NotebookUninstallSamplesData'
        }

        ArcGIS_AzureSetupsManager DownloadServerUpgradeSetup{
            Version = $Version
            OperationType = 'DownloadUpgradeSetups'
            ComponentNames = "Server"
            ServerRole = $ServerRole
            UpgradeSetupsSourceFileSharePath = "\\$($UpgradeVMName)\UpgradeSetups"
            UpgradeSetupsSourceFileShareCredentials = $FileshareMachineCredential
            DependsOn = $Depends
        }
        $Depends += '[ArcGIS_AzureSetupsManager]DownloadServerUpgradeSetup'

        $InstallerFileName = "ArcGISforServer.exe"
        if($ServerRole -ieq "NotebookServer"){
            $InstallerFileName = "NotebookServer.exe"
        }
        if($ServerRole -ieq "MissionServer"){
            $InstallerFileName = "MissionServer.exe"
        }

        if($ServerRole -ieq "VideoServer"){
            $InstallerFileName = "VideoServer.exe"
        }
		$InstallerPathOnMachine = "$($UpgradeSetupsStagingPath)\$InstallerFileName"
        $InstallerVolumePathOnMachine = ""
        if((@("Server", "VideoServer") -icontains $ServerRole -and [version]$Version -ge "12.2") -or (-not(@("NotebookServer", "MissionServer", "VideoServer") -icontains $ServerRole))){
            $InstallerVolumePathOnMachine = "$($InstallerPathOnMachine).001"
        }

        if(Get-Service 'ArcGISGeoEvent' -ErrorAction Ignore){
            ArcGIS_WindowsService ArcGIS_GeoEvent_Service_Stop
            {
                Name = 'ArcGISGeoEvent'
                Credential = $ServiceCredential
                StartupType = 'Manual'
                State = 'Stopped'
                DependsOn = $Depends
            }
            $Depends += "[ArcGIS_WindowsService]ArcGIS_GeoEvent_Service_Stop"

            if(Get-Service 'ArcGISGeoEventGateway' -ErrorAction Ignore) 
            {
                ArcGIS_WindowsService ArcGIS_GeoEventGateway_Service
                {
                    Name		= 'ArcGISGeoEventGateway'
                    Credential  = $ServiceCredential
                    StartupType = 'Manual'
                    State = 'Stopped'
                    DependsOn   = $Depends
                }
                $Depends += "[ArcGIS_WindowsService]ArcGIS_GeoEventGateway_Service"
            }
        }

        if(Get-Service 'WorkflowManager' -ErrorAction Ignore){
            ArcGIS_WindowsService ArcGIS_WorkflowManager_Service_Stop
            {
                Name = 'WorkflowManager'
                Credential = $ServiceCredential
                StartupType = 'Manual'
                State = 'Stopped'
                DependsOn = $Depends
            }
            $Depends += "[ArcGIS_WindowsService]ArcGIS_WorkflowManager_Service_Stop"
        }
      
        ArcGIS_Install ServerUpgrade{
            Name = if($ServerRole -ieq "NotebookServer"){ "NotebookServer" }elseif($ServerRole -ieq "MissionServer"){ "MissionServer" }elseif($ServerRole -ieq "VideoServer"){ "VideoServer" }else{ "Server" } 
            Version = $Version
            Path = $InstallerPathOnMachine
            Arguments = "/qn ACCEPTEULA=YES";
            ServiceCredential = $ServiceCredential
            ServiceCredentialIsDomainAccount =  $ServiceCredentialIsDomainAccount
            ServiceCredentialIsMSA = $False
            Ensure = "Present"
            EnableMSILogging = $DebugMode
            DependsOn = $Depends
        }

        $Depends += '[ArcGIS_Install]ServerUpgrade'
        
		Script RemoveServerInstaller
		{
			SetScript = 
			{ 
                if(-not([string]::IsNullOrEmpty($using:InstallerPathOnMachine)) -and (Test-Path $using:InstallerPathOnMachine)){
				    Remove-Item $using:InstallerPathOnMachine -Force
                }
                if(-not([string]::IsNullOrEmpty($using:InstallerVolumePathOnMachine))){
                    Remove-Item $using:InstallerVolumePathOnMachine -Force
                }
			}
			TestScript = { -not(Test-Path $using:InstallerPathOnMachine) -and -not(Test-Path $using:InstallerVolumePathOnMachine) }
			GetScript = { @{} }
            DependsOn = '[ArcGIS_Install]ServerUpgrade'
		}
        $Depends += '[Script]RemoveServerInstaller'

        $ServerLicenseRole = $ServerRole
        if(-not($ServerRole) -or ($ServerRole -ieq "GeoEventServer")){
            $ServerLicenseRole = "GeneralPurposeServer"
        }
        if($ServerRole -ieq "RasterAnalytics" -or $ServerRole -ieq "ImageHosting"){
            $ServerLicenseRole = "ImageServer"
        }
        if($ServerRole -ieq "NotebookServer"){
            $ServerLicenseRole = "NotebookServer"
        }
        if($ServerRole -ieq "MissionServer"){
            $ServerLicenseRole = "MissionServer"
        }
        if($ServerRole -ieq "MissionServer"){
            $ServerLicenseRole = "MissionServer"
        }
        if($ServerRole -ieq "WorkflowManagerServer"){
            $ServerLicenseRole = "WorkflowManagerServer"
        }
        
		## Download license file

        if($ServerLicenseFileName) {
            ArcGIS_RemoteFile "ServerLicenseFileDownload"
            {
                Source = $ServerLicenseFileName
                Destination = (Join-Path $(Get-Location).Path $ServerLicenseFileName)
                FileSourceType = "AzureSASUri"
                Credential = $DeploymentArtifactCredentials
                Ensure = 'Present'
            }
            $Depends += '[ArcGIS_RemoteFile]ServerLicenseFileDownload'
        }

        ArcGIS_License ServerLicense
        {
            LicenseFilePath = (Join-Path $(Get-Location).Path $ServerLicenseFileName)
            Ensure          = 'Present'
            Component       = "Server"
            ServerRole      = $ServerLicenseRole
            Version 	    = $Version
            Force           = $True
            DependsOn       = $Depends
        }

        $Depends += '[ArcGIS_License]ServerLicense'

        ArcGIS_HostNameSettings ServerHostNameSettings{
            ComponentName   = if($ServerRole -ieq "NotebookServer"){ "NotebookServer" }elseif($ServerRole -ieq "MissionServer"){ "MissionServer" }elseif($ServerRole -ieq "VideoServer"){ "VideoServer" }else{ "Server" } 
            Version         = $Version
            HostName        = $env:ComputerName
            DependsOn       = $Depends
        }
        $Depends += '[ArcGIS_HostNameSettings]ServerHostNameSettings'
        
        ArcGIS_ServerUpgrade "$($ServerRole)ConfigureUpgrade"{
            Version = $Version
            ServerType = if($ServerRole -ieq "NotebookServer"){ "NotebookServer" }elseif($ServerRole -ieq "MissionServer"){ "MissionServer" }elseif($ServerRole -ieq "VideoServer"){ "VideoServer" }else{ "Server" }
            ServerHostName = $env:ComputerName
            EnableUpgradeSiteDebug = $DebugMode
            DependsOn = $Depends
        }
        $Depends += "[ArcGIS_ServerUpgrade]$($ServerRole)ConfigureUpgrade"

        if($ServerRole -ieq "NotebookServer"){
            #For Notebook Server at the end of install use the Configure app to finish the upgrade process.
            if($IsNotebookServerWebAdaptorUpgrade){
                ArcGIS_Install "WebAdaptorIISUninstall"
                { 
                    Name = "WebAdaptorIIS"
                    Version = $OldVersion
                    WebAdaptorContext = $NotebookWebAdaptorContext
                    Arguments = "WEBSITE_ID=1"
                    Ensure = "Absent"
                    DependsOn = $Depends
                }
 
                $WebDeployInstallerPathOnMachine = "$($UpgradeSetupsStagingPath)\WebDeploy_amd64_en-US.msi"
                $DotnetHostingBundleInstallerPathOnMachine = "$($UpgradeSetupsStagingPath)\dotnet-hosting-win.exe"
                $NotebookContainerPathOnMachine = "$($UpgradeSetupsStagingPath)\arcgis-notebook-python-windows-$($Version).tar.gz"
                $WebAdaptorInstallerPathOnMachine = "$($UpgradeSetupsStagingPath)\WebAdaptorIIS.exe"
                
                # Install the new hosting bundle
                ArcGIS_Install "WebAdaptorInstall"
                {
                    Name = "WebAdaptorIIS"
                    Version = $Version 
                    Path = $WebAdaptorInstallerPathOnMachine
                    Extract = $True
                    Arguments = "/qn ACCEPTEULA=YES VDIRNAME=$($NotebookWebAdaptorContext) WEBSITE_ID=1 CONFIGUREIIS=TRUE "
                    WebAdaptorContext = $NotebookWebAdaptorContext
                    WebAdaptorDotnetHostingBundlePath = $DotnetHostingBundleInstallerPathOnMachine
                    WebAdaptorWebDeployPath = $WebDeployInstallerPathOnMachine
                    Ensure = "Present"
                    DependsOn =  @('[ArcGIS_Install]WebAdaptorIISUninstall')
                }
    
                $MachineFQDN = Get-FQDN $env:ComputerName
                ArcGIS_WebAdaptor "ConfigureWebAdaptor"
                {
                    Version             = $Version
                    Ensure              = "Present"
                    Component           = 'NotebookServer'
                    HostName            = $MachineFQDN
                    ComponentHostName   = $MachineFQDN
                    Context             = $NotebookWebAdaptorContext
                    OverwriteFlag       = $False
                    SiteAdministrator   = $SiteAdministratorCredential
                    AdminAccessEnabled  = $True
                    DependsOn           = @('[ArcGIS_Install]WebAdaptorInstall')
                }

                ArcGIS_NotebookPostInstall NotebookPostInstall {
                    SiteName            = $NotebookWebAdaptorContext
                    Version             = $Version
                    ContainerImagePaths = @($NotebookContainerPathOnMachine) # Add the path to the container images
                    ExtractSamples      = $false
                    SiteAdministrator   = $SiteAdministratorCredential
                    DependsOn           = @("[ArcGIS_ServerUpgrade]$($ServerRole)ConfigureUpgrade")
                    PsDscRunAsCredential  = $ServiceCredential # Copy as arcgis account which has access to this share
                }

                Script RemoveContainer
                {
                    SetScript = 
                    { 
                        Remove-Item $using:NotebookContainerPathOnMachine -Force
                    }
                    TestScript = { -not(Test-Path $using:NotebookContainerPathOnMachine) }
                    GetScript = { @{} }
                    DependsOn = @('[ArcGIS_NotebookPostInstall]NotebookPostInstall','[ArcGIS_WebAdaptor]ConfigureWebAdaptor')
                }
            }   
        }

        #Upgrade GeoEvents
        if($ServerRole -ieq "GeoEventServer"){
            Script ArcGIS_GeoEvent_Service_Stop_for_Upgrade
            {
                TestScript  = {  return $false }
                SetScript   = { 
                    @('ArcGISGeoEvent', 'ArcGISGeoEventGateway') | ForEach-Object{
                        $ServiceName = $_
                        Write-Verbose "Stopping the service '$ServiceName'"
                        Stop-ServiceAndWait -ServiceName $ServiceName -TimeoutSeconds 300 -PollSeconds 2 -Verbose
                        Write-Verbose "Service '$ServiceName' stopped successfully." 
                    }
                }
                GetScript   = { return @{} }                  
                DependsOn   = $Depends
            }
            $Depends += '[Script]ArcGIS_GeoEvent_Service_Stop_for_Upgrade'

            $GeoEventInstallerPathOnMachine = "$($UpgradeSetupsStagingPath)\GeoEvent.exe"
            ArcGIS_Install GeoEventServerUpgrade{
                Name = "GeoEvent"
                Version = $Version
                Path = $GeoEventInstallerPathOnMachine
                Arguments = "/qn USERBACKUPCONFIGFILES=YES";
                ServiceCredential = $ServiceCredential
                ServiceCredentialIsDomainAccount = $ServiceCredentialIsDomainAccount
                ServiceCredentialIsMSA = $False
                Ensure = "Present"
                EnableMSILogging = $DebugMode
                DependsOn = $Depends
            }
 
            ArcGIS_WindowsService ArcGIS_GeoEvent_Service_Start
            {
                Name = 'ArcGISGeoEvent'
                Credential = $ServiceCredential
                StartupType = 'Automatic'
                State = 'Running'
                DependsOn = $Depends
            }
            $Depends += "[ArcGIS_WindowsService]ArcGIS_GeoEvent_Service_Start"

            if(Get-Service 'ArcGISGeoEventGateway' -ErrorAction Ignore) 
            {
                ArcGIS_WindowsService ArcGIS_GeoEventGateway_Service_Start
                {
                    Name		= 'ArcGISGeoEventGateway'
                    Credential  = $ServiceCredential
                    StartupType = 'Automatic'
                    State       = 'Running'
                    DependsOn   = $Depends
                }
                $Depends += "[ArcGIS_WindowsService]ArcGIS_GeoEventGateway_Service_Start"
            }
        }

        if($ServerRole -ieq "WorkflowManagerServer"){
            $Depends += '[ArcGIS_ServerUpgrade]ServerConfigureUpgrade'

            $WorkflowManagerServerInstallerPathOnMachine = "$($UpgradeSetupsStagingPath)\WorkflowManagerServer.exe"
            ArcGIS_Install WorkflowManagerServerUpgrade
            {
                Name = "WorkflowManagerServer"
                Version = $Version
                Path = $WorkflowManagerServerInstallerPathOnMachine
                Arguments = "/qn"
                ServiceCredential = $ServiceCredential
                ServiceCredentialIsDomainAccount = $ServiceCredentialIsDomainAccount
                ServiceCredentialIsMSA = $False
                Ensure = "Present"
                EnableMSILogging = $DebugMode
                DependsOn = $Depends
            }
            $Depends += '[ArcGIS_Install]WorkflowManagerInstall'

            Script RemoveWorkflowManagerServerInstaller
            {
                SetScript = 
                { 
                    Remove-Item $using:WorkflowManagerServerInstallerPathOnMachine -Force
                }
                TestScript = { -not(Test-Path $using:WorkflowManagerServerInstallerPathOnMachine) }
                GetScript = { @{} }          
            }
            $Depends += '[Script]RemoveWorkflowManagerServerInstaller'
            
            if($IsMultiMachineServerSite -and ([version]$Version -ge "11.3")){ # 11.3 or later
                $WfmPorts = @("13820", "13830", "13840", "9880", "11211")

                ArcGIS_xFirewall WorkflowManagerServer_FirewallRules_MultiMachine_OutBound
                {
                    Name                  = "ArcGISWorkflowManagerServerFirewallRulesClusterOutbound" 
                    DisplayName           = "ArcGIS WorkflowManagerServer Extension Cluster Outbound" 
                    DisplayGroup          = "ArcGIS WorkflowManagerServer Extension" 
                    Ensure                =  "Present"
                    Access                = "Allow" 
                    State                 = "Enabled" 
                    Profile               = ("Domain","Private","Public")
                    RemotePort            = $WfmPorts
                    Protocol              = "TCP" 
                    Direction             = "Outbound"
                }
                $DependsOnWfm += "[ArcGIS_xFirewall]WorkflowManagerServer_FirewallRules_MultiMachine_OutBound"

                ArcGIS_xFirewall WorkflowManagerServer_FirewallRules_MultiMachine_InBound
                {
                    Name                  = "ArcGISWorkflowManagerServerFirewallRulesClusterInbound"
                    DisplayName           = "ArcGIS WorkflowManagerServer Extension Cluster Inbound"
                    DisplayGroup          = "ArcGIS WorkflowManagerServer Extension"
                    Ensure                = 'Present'
                    Access                = "Allow"
                    State                 = "Enabled"
                    Profile               = ("Domain","Private","Public")
                    LocalPort            = $WfmPorts
                    Protocol              = "TCP"
                    Direction             = "Inbound"
                }
                $DependsOnWfm += "[ArcGIS_xFirewall]WorkflowManagerServer_FirewallRules_MultiMachine_InBound"
            }
        }

        if($ServerRole -ieq "VideoServer" -and [version]$OldVersion -le "12.1" -and [version]$Version -ge [version]"12.2"){
            ArcGIS_xFirewall "VideoServer_SRTFirewallRule"
            {
                Name                  = "ArcGISVideoServerSRT"
                DisplayName           = "ArcGIS for Video Server SRT"
                DisplayGroup          = "ArcGIS for Video Server"
                Ensure                = 'Present'
                Access                = "Allow"
                State                 = "Enabled"
                Profile               = ("Domain","Private","Public")
                LocalPort             = $VideoServerSrtPort
                Protocol              = "UDP"
                DependsOn             = $Depends
            }
        }
    }
}