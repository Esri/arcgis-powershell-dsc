Configuration ServerUpgrade{
    param(
        [Parameter(Mandatory=$false)]
        [System.String]
        $Version = "12.0",

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
        $IsMultiMachineServerSite
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_Install 
    Import-DscResource -Name ArcGIS_License 
    Import-DscResource -Name ArcGIS_WindowsService 
    Import-DscResource -Name ArcGIS_ServerUpgrade 
    Import-DscResource -Name ArcGIS_NotebookServerUpgrade 
    Import-DscResource -Name ArcGIS_MissionServerUpgrade
    Import-DscResource -Name ArcGIS_xFirewall 
    Import-DscResource -Name ArcGIS_WebAdaptor
    Import-DscResource -Name ArcGIS_AzureSetupDownloadsFolderManager
    Import-DscResource -Name ArcGIS_HostNameSettings
    
    $ServiceCredentialUserName = $ServiceCredential.UserName
    $UpgradeSetupsStagingPath = "C:\ArcGIS\Deployment\Downloads\$($Version)"

    Node localhost {
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $false
        }

		ArcGIS_AzureSetupDownloadsFolderManager CleanupDownloadsFolder{
            Version = $Version
            OperationType = 'CleanupDownloadsFolder'
            ComponentNames = "All"
        }
        $Depends = @("[ArcGIS_AzureSetupDownloadsFolderManager]CleanupDownloadsFolder")
        
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

        if($ServerRole -ieq "NotebookServer" -and (@("10.9","10.9.1","11.0","11.1","11.2","11.3") -icontains $OldVersion)){
            ArcGIS_Install NotebookUninstallSamplesData{
                Name = "NotebookServerSamplesData"
                Version = $OldVersion
                Ensure = "Absent"
                DependsOn = $Depends
            }
            $Depends += '[ArcGIS_Install]NotebookUninstallSamplesData'
        }

        ArcGIS_AzureSetupDownloadsFolderManager DownloadServerUpgradeSetup{
            Version = $Version
            OperationType = 'DownloadUpgradeSetups'
            ComponentNames = "Server"
            ServerRole = $ServerRole
            UpgradeSetupsSourceFileSharePath = "\\$($UpgradeVMName)\UpgradeSetups"
            UpgradeSetupsSourceFileShareCredentials = $FileshareMachineCredential
            DependsOn = $Depends
        }
        $Depends += '[ArcGIS_AzureSetupDownloadsFolderManager]DownloadServerUpgradeSetup'

        $InstallerFileName = "ArcGISforServer.exe"
        if($ServerRole -ieq "NotebookServer"){
            $InstallerFileName = "NotebookServer.exe"
        }
        if($ServerRole -ieq "MissionServer"){
            $InstallerFileName = "MissionServer.exe"
        }
		$InstallerPathOnMachine = "$($UpgradeSetupsStagingPath)\$InstallerFileName"
        $InstallerVolumePathOnMachine = ""
        if($ServerRole -ine "NotebookServer" -and $ServerRole -ine "MissionServer"){
            $InstallerVolumePathOnMachine = "$($InstallerPathOnMachine).001"
        }

        if(Get-Service 'ArcGISGeoEvent' -ErrorAction Ignore){
            Service ArcGIS_GeoEvent_Service_Stop
            {
                Name = 'ArcGISGeoEvent'
                Credential = $ServiceCredential
                StartupType = 'Manual'
                State = 'Stopped'
                DependsOn = $Depends
            }
            $Depends += "[Service]ArcGIS_GeoEvent_Service_Stop"

            if(Get-Service 'ArcGISGeoEventGateway' -ErrorAction Ignore) 
            {
                Service ArcGIS_GeoEventGateway_Service
                {
                    Name		= 'ArcGISGeoEventGateway'
                    Credential  = $ServiceCredential
                    StartupType = 'Manual'
                    State = 'Stopped'
                    DependsOn   = $Depends
                }
                $Depends += "[Service]ArcGIS_GeoEventGateway_Service"
            }
        }

        if(Get-Service 'WorkflowManager' -ErrorAction Ignore){
            Service ArcGIS_WorkflowManager_Service_Stop
            {
                Name = 'WorkflowManager'
                Credential = $ServiceCredential
                StartupType = 'Manual'
                State = 'Stopped'
                DependsOn = $Depends
            }
            $Depends += "[Service]ArcGIS_WorkflowManager_Service_Stop"
        }
      
        ArcGIS_Install ServerUpgrade{
            Name = if($ServerRole -ieq "NotebookServer"){ "NotebookServer" }elseif($ServerRole -ieq "MissionServer"){ "MissionServer" }else{ "Server" } 
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
			GetScript = { $null }          
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
            $ServerLicenseFileUrl = "$($DeploymentArtifactCredentials.UserName)/$($ServerLicenseFileName)$($DeploymentArtifactCredentials.GetNetworkCredential().Password)"
            Invoke-WebRequest -Verbose:$False -OutFile $ServerLicenseFileName -Uri $ServerLicenseFileUrl -UseBasicParsing -ErrorAction Ignore
        }

		ArcGIS_License ServerLicense
        {
            LicenseFilePath = (Join-Path $(Get-Location).Path $ServerLicenseFileName)
            Ensure = 'Present'
            Component = "Server"
            ServerRole = $ServerLicenseRole
            Force = $True
            DependsOn = $Depends
        }

        $Depends += '[ArcGIS_License]ServerLicense'

        ArcGIS_HostNameSettings ServerHostNameSettings{
            ComponentName   = if($ServerRole -ieq "NotebookServer"){ "NotebookServer" }elseif($ServerRole -ieq "MissionServer"){ "MissionServer" }else{ "Server" } 
            Version         = $Version
            HostName        = $env:ComputerName
            DependsOn       = $Depends
        }
        $Depends += '[ArcGIS_HostNameSettings]ServerHostNameSettings'
        
        if($ServerRole -ieq "NotebookServer"){
            #For Notebook Server at the end of install use the Configure app to finish the upgrade process.
            ArcGIS_NotebookServerUpgrade NotebookServerConfigureUpgrade{
                Version = $Version
                ServerHostName = $env:ComputerName
                DependsOn = $Depends
            }
            $Depends += '[ArcGIS_NotebookServerUpgrade]NotebookServerConfigureUpgrade'

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
                    ContainerImagePaths = @($NotebookContainerPathOnMachine) # Add the path to the container images
                    ExtractSamples      = $false
                    DependsOn           = @('[ArcGIS_NotebookServerUpgrade]NotebookServerConfigureUpgrade')
                    PsDscRunAsCredential  = $ServiceCredential # Copy as arcgis account which has access to this share
                }

                Script RemoveContainer
                {
                    SetScript = 
                    { 
                        Remove-Item $using:NotebookContainerPathOnMachine -Force
                    }
                    TestScript = { -not(Test-Path $using:NotebookContainerPathOnMachine) }
                    GetScript = { $null }
                    DependsOn = @('[ArcGIS_NotebookPostInstall]NotebookPostInstall','[ArcGIS_WebAdaptor]ConfigureWebAdaptor')
                }
            }
            
        }elseif($ServerRole -ieq "MissionServer"){
            ArcGIS_MissionServerUpgrade MissionServerConfigureUpgrade{
                Version = $Version
                ServerHostName = $env:ComputerName
                DependsOn = $Depends
            }
        }else{
            ArcGIS_ServerUpgrade ServerConfigureUpgrade{
                Version = $Version
                ServerHostName = $env:ComputerName
                EnableUpgradeSiteDebug = $DebugMode
                DependsOn = $Depends
            }
        }

        #Upgrade GeoEvents
        if($ServerRole -ieq "GeoEventServer"){
            
            $Depends += '[ArcGIS_ServerUpgrade]ServerConfigureUpgrade'

            Script ArcGIS_GeoEvent_Service_Stop_for_Upgrade
            {
                TestScript  = {  return $false }
                SetScript   = { 
                    @('ArcGISGeoEvent', 'ArcGISGeoEventGateway') | ForEach-Object{
                        $ServiceName = $_
                        Write-Verbose "Stopping the service '$ServiceName'"    
                        Stop-Service -Name $ServiceName -ErrorAction Ignore    
                        Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Stopped'
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
                GetScript = { $null }          
            }
            $Depends += '[Script]RemoveWorkflowManagerServerInstaller'
            
            $VersionArray = $Version.Split(".")
            if($IsMultiMachineServerSite -and (($VersionArray[0] -gt 11) -or ($VersionArray[0] -ieq 11 -and $VersionArray -ge 3))){ # 11.3 or later
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
    }
}
