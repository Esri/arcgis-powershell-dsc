Configuration ServerUpgrade{
    param(
        [Parameter(Mandatory=$false)]
        [System.String]
        $Version = '11.3',

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

        [System.String]
        $ServerInstallerPath,

        [System.String]
        $ServerInstallerVolumePath,

        [System.String]
        $ServerLicenseFileUrl,

		[System.String]
        $ServerRole,
        
		[Parameter(Mandatory=$false)]
        [System.String]
        $GeoEventServerInstallerPath = "",

        [Parameter(Mandatory=$false)]
        [System.String]
        $NotebookSamplesDataInstallerPath = "",

        [Parameter(Mandatory=$false)]
        [System.String]
        $WorkflowManagerServerInstallerPath = "",

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $IsNotebookServerWebAdaptorUpgrade = $False,

        [Parameter(Mandatory=$false)]
        [System.String]
        $DotnetHostingBundleInstallerPath = "",

        [Parameter(Mandatory=$false)]
        [System.String]
        $WebDeployInstallerPath = "",

        [Parameter(Mandatory=$false)]
        [System.String]
        $WebAdaptorInstallerPath = "",

        [Parameter(Mandatory=$false)]
        [System.String]
        $NotebookWebAdaptorContext = "",

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
		$SiteAdministratorCredential,
		
		[Parameter(Mandatory=$false)]
        [System.String]
        $DebugMode,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $IsMultiMachineServerSite
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
    Import-DscResource -Name ArcGIS_License 
    Import-DscResource -Name ArcGIS_WindowsService 
    Import-DscResource -Name ArcGIS_ServerUpgrade 
    Import-DscResource -Name ArcGIS_NotebookServerUpgrade 
    Import-DscResource -Name ArcGIS_MissionServerUpgrade
    Import-DscResource -Name ArcGIS_NotebookPostInstall 
    Import-DscResource -Name ArcGIS_xFirewall 
    Import-DscResource -Name ArcGIS_WebAdaptor
    $IsDebugMode = $DebugMode -ieq 'true'

    Node localhost {
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $true
        }

		$Depends = @()
        if(-Not($ServiceCredentialIsDomainAccount)){
            User ArcGIS_RunAsAccount
            {
                UserName = $ServiceCredential.UserName
                Password = $ServiceCredential
                FullName = 'ArcGIS Run As Account'
                Ensure = "Present"
            }
            $Depends += '[User]ArcGIS_RunAsAccount'
        }

		$InstallerFileName = Split-Path $ServerInstallerPath -Leaf
		$InstallerPathOnMachine = "$env:TEMP\Server\$InstallerFileName"

        File DownloadInstallerFromFileShare      
		{            	
			Ensure = "Present"              	
			Type = "File"             	
			SourcePath = $ServerInstallerPath 	
			DestinationPath = $InstallerPathOnMachine     
			Credential = $FileshareMachineCredential     
			DependsOn = $Depends  
        }
        $Depends += '[File]DownloadInstallerFromFileShare'

        $InstallerVolumePathOnMachine = ""
        if(-not([string]::IsNullOrEmpty($ServerInstallerVolumePath))){
            $InstallerVolumeFileName = Split-Path $ServerInstallerVolumePath -Leaf
            $InstallerVolumePathOnMachine = "$env:TEMP\Server\$InstallerVolumeFileName"

            File DownloadInstallerVolumeFromFileShare      
            {            	
                Ensure = "Present"              	
                Type = "File"             	
                SourcePath = $ServerInstallerVolumePath 	
                DestinationPath = $InstallerVolumePathOnMachine     
                Credential = $FileshareMachineCredential     
                DependsOn = $Depends  
            }
            $Depends += '[File]DownloadInstallerVolumeFromFileShare'
        }
        
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
      
        ArcGIS_Install ServerUpgrade{
            Name = if($ServerRole -ieq "NotebookServer"){ "NotebookServer" }elseif($ServerRole -ieq "MissionServer"){ "MissionServer" }else{ "Server" } 
            Version = $Version
            Path = $InstallerPathOnMachine
            Arguments = "/qn ACCEPTEULA=YES";
            ServiceCredential = $ServiceCredential
            ServiceCredentialIsDomainAccount =  $ServiceCredentialIsDomainAccount
            ServiceCredentialIsMSA = $False
            Ensure = "Present"
            EnableMSILogging = $IsDebugMode
            DependsOn = $Depends
        }

        $Depends += '[ArcGIS_Install]ServerUpgrade'
        
		Script RemoveInstaller
		{
			SetScript = 
			{ 
				Remove-Item $using:InstallerPathOnMachine -Force
                if(-not([string]::IsNullOrEmpty($using:InstallerVolumePathOnMachine))){
                    Remove-Item $using:InstallerVolumePathOnMachine -Force
                }
			}
			TestScript = { -not(Test-Path $using:InstallerPathOnMachine) }
			GetScript = { $null }          
		}
        $Depends += '[Script]RemoveInstaller'

        if($ServerRole -ieq "NotebookServer"){
            $NotebookSamplesDataInstallerFileName = Split-Path $NotebookSamplesDataInstallerPath -Leaf
            $NotebookSamplesDataInstallerPathOnMachine = "$env:TEMP\NBServer\$NotebookSamplesDataInstallerFileName"

            File DownloadNotebookSampleInstallerFromFileShare      
            {            	
                Ensure = "Present"              	
                Type = "File"             	
                SourcePath = $NotebookSamplesDataInstallerPath 	
                DestinationPath = $NotebookSamplesDataInstallerPathOnMachine     
                Credential = $FileshareMachineCredential     
                DependsOn = $Depends  
            }
            $Depends += '[File]DownloadNotebookSampleInstallerFromFileShare'
            
            ArcGIS_Install NotebookInstallSamplesData{
                Name = "NotebookServerSamplesData"
                Version = $Version
                Path = $NotebookSamplesDataInstallerPathOnMachine
                Arguments = "/qn";
                ServiceCredential = $ServiceCredential
                ServiceCredentialIsDomainAccount =  $ServiceCredentialIsDomainAccount
                ServiceCredentialIsMSA = $False
                Ensure = "Present"
                EnableMSILogging = $IsDebugMode
                DependsOn = $Depends
            }
            $Depends += '[ArcGIS_Install]NotebookInstallSamplesData'

            Script RemoveNotebookSamplesDataInstaller
            {
                SetScript = 
                { 
                    Remove-Item $using:NotebookSamplesDataInstallerPathOnMachine -Force
                }
                TestScript = { -not(Test-Path $using:NotebookSamplesDataInstallerPathOnMachine) }
                GetScript = { $null }          
            }
            $Depends += '[Script]RemoveNotebookSamplesDataInstaller'
        }

        if(($ServerRole -ieq "GeoAnalyticsServer") -and $IsMultiMachineServerSite){
            ArcGIS_xFirewall GeoAnalytics_InboundFirewallRules
            {
                    Name                  = "ArcGISGeoAnalyticsInboundFirewallRules" 
                    DisplayName           = "ArcGIS GeoAnalytics" 
                    DisplayGroup          = "ArcGIS GeoAnalytics" 
                    Ensure                = 'Present' 
                    Access                = "Allow" 
                    State                 = "Enabled" 
                    Profile               = ("Domain","Private","Public")
                    LocalPort             = ("12181","12182","12190","7077")	# Spark and Zookeeper
                    Protocol              = "TCP" 
            }
            $Depends += '[ArcGIS_xFirewall]GeoAnalytics_InboundFirewallRules'

            ArcGIS_xFirewall GeoAnalytics_OutboundFirewallRules
            {
                    Name                  = "ArcGISGeoAnalyticsOutboundFirewallRules" 
                    DisplayName           = "ArcGIS GeoAnalytics" 
                    DisplayGroup          = "ArcGIS GeoAnalytics" 
                    Ensure                = 'Present' 
                    Access                = "Allow" 
                    State                 = "Enabled" 
                    Profile               = ("Domain","Private","Public")
                    LocalPort             = ("12181","12182","12190","7077")	# Spark and Zookeeper
                    Protocol              = "TCP" 
                    Direction             = "Outbound"    
            }
            $Depends += '[ArcGIS_xFirewall]GeoAnalytics_OutboundFirewallRules'

        }

        $ServerLicenseRole = $ServerRole
        if(-not($ServerRole) -or ($ServerRole -ieq "GeoEventServer")){
            $ServerLicenseRole = "GeneralPurposeServer"
        }
        if($ServerRole -ieq "RasterAnalytics" -or $ServerRole -ieq "ImageHosting"){
            $ServerLicenseRole = "ImageServer"
        }
        if($ServerRole -ieq "GeoAnalyticsServer"){
            $ServerLicenseRole = "GeoAnalytics"
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
		if($ServerLicenseFileUrl) {
			$ServerLicenseFileName = Get-FileNameFromUrl $ServerLicenseFileUrl
			Invoke-WebRequest -OutFile $ServerLicenseFileName -Uri $ServerLicenseFileUrl -UseBasicParsing -ErrorAction Ignore
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
        
        if($ServerRole -ieq "NotebookServer"){
            #For Notebook Server at the end of install use the Configure app to finish the upgrade process.
            ArcGIS_NotebookServerUpgrade NotebookServerConfigureUpgrade{
                Ensure = "Present"
                Version = $Version
                ServerHostName = $env:ComputerName
                DependsOn = $Depends
            }
            $Depends += '[ArcGIS_NotebookServerUpgrade]NotebookServerConfigureUpgrade'

            ArcGIS_NotebookPostInstall NotebookPostInstallSamples {
                SiteName            = "arcgis"
                ContainerImagePaths = @()
                ExtractSamples      = $true
                DependsOn           = $Depends
                PsDscRunAsCredential  = $ServiceCredential # Copy as arcgis account which has access to this share
            }

            if($IsNotebookServerWebAdaptorUpgrade){
                ArcGIS_Install "WebAdaptorIISUninstall"
                { 
                    Name = "WebAdaptorIIS"
                    Version = $OldVersion
                    WebAdaptorContext = $NotebookWebAdaptorContext
                    Arguments = "WEBSITE_ID=1"
                    Ensure = "Absent"
                    DependsOn = @("[ArcGIS_NotebookPostInstall]NotebookPostInstallSamples")
                }
    
                $WebDeployFileName = Split-Path $WebDeployInstallerPath -Leaf
                $WebDeployInstallerPathOnMachine = "$env:TEMP\WebAdaptor\$WebDeployFileName"
    
                File DownloadWebDeployInstallerFromFileShare      
                {            	
                    Ensure = "Present"              	
                    Type = "File"             	
                    SourcePath = $WebDeployInstallerPath 	
                    DestinationPath = $WebDeployInstallerPathOnMachine     
                    Credential = $FileshareMachineCredential     
                    DependsOn = @('[ArcGIS_Install]WebAdaptorIISUninstall')
                }
    
                $DotnetHostingBundleFileName = Split-Path $DotnetHostingBundleInstallerPath -Leaf
                $DotnetHostingBundleInstallerPathOnMachine = "$env:TEMP\WebAdaptor\$DotnetHostingBundleFileName"
    
                File DownloadHostingBundleInstallerFromFileShare      
                {            	
                    Ensure = "Present"              	
                    Type = "File"             	
                    SourcePath = $DotnetHostingBundleInstallerPath 	
                    DestinationPath = $DotnetHostingBundleInstallerPathOnMachine     
                    Credential = $FileshareMachineCredential     
                    DependsOn = @('[ArcGIS_Install]WebAdaptorIISUninstall')
                }
    
                $WebAdaptorInstallerFileName = Split-Path $WebAdaptorInstallerPath -Leaf
                $WebAdaptorInstallerPathOnMachine = "$env:TEMP\WebAdaptor\$WebAdaptorInstallerFileName"
                File DownloadWebAdaptorInstallerFromFileShare      
                {            	
                    Ensure = "Present"              	
                    Type = "File"             	
                    SourcePath = $WebAdaptorInstallerPath 	
                    DestinationPath = $WebAdaptorInstallerPathOnMachine     
                    Credential = $FileshareMachineCredential     
                    DependsOn = @('[ArcGIS_Install]WebAdaptorIISUninstall')
                }
    
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
                    DependsOn =  @('[File]DownloadWebDeployInstallerFromFileShare','[File]DownloadHostingBundleInstallerFromFileShare','[File]DownloadWebAdaptorInstallerFromFileShare')
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
                    SiteAdministrator   = $NotebookSiteAdministratorCredential
                    AdminAccessEnabled  = $True
                    DependsOn           = @('[ArcGIS_WebAdaptor]WebAdaptorInstall')
                }
            }
            
        }elseif($ServerRole -ieq "MissionServer"){
            ArcGIS_MissionServerUpgrade MissionServerConfigureUpgrade{
                Ensure = "Present"
                Version = $Version
                ServerHostName = $env:ComputerName
                DependsOn = $Depends
            }
        }else{
            ArcGIS_ServerUpgrade ServerConfigureUpgrade{
                Ensure = "Present"
                Version = $Version
                ServerHostName = $env:ComputerName
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
            $ServerDependsOn += '[Script]ArcGIS_GeoEvent_Service_Stop_for_Upgrade'

            $GeoEventInstallerFileName = Split-Path $GeoEventServerInstallerPath -Leaf
            $GeoEventInstallerPathOnMachine = "$env:TEMP\Server\$GeoEventInstallerFileName"

            File GeoeventDownloadInstallerFromFileShare      
            {            	
                Ensure = "Present"              	
                Type = "File"             	
                SourcePath = $GeoEventServerInstallerPath 	
                DestinationPath = $GeoEventInstallerPathOnMachine     
                Credential = $FileshareMachineCredential     
                DependsOn = $Depends  
            }
            $Depends += '[File]GeoeventDownloadInstallerFromFileShare'

            ArcGIS_Install GeoEventServerUpgrade{
                Name = "GeoEvent"
                Version = $Version
                Path = $GeoEventInstallerPathOnMachine
                Arguments = "/qn USERBACKUPCONFIGFILES=YES";
                ServiceCredential = $ServiceCredential
                ServiceCredentialIsDomainAccount = $ServiceCredentialIsDomainAccount
                ServiceCredentialIsMSA = $False
                Ensure = "Present"
                EnableMSILogging = $IsDebugMode
                DependsOn = $Depends
            }

            if($IsMultiMachineServerSite){
                ArcGIS_xFirewall GeoEvent_FirewallRules_MultiMachine
                {
                        Name                  = "ArcGISGeoEventFirewallRulesCluster" 
                        DisplayName           = "ArcGIS GeoEvent Extension Cluster" 
                        DisplayGroup          = "ArcGIS GeoEvent Extension" 
                        Ensure                = 'Present' 
                        Access                = "Allow" 
                        State                 = "Enabled" 
                        Profile               = ("Domain","Private","Public")
                        LocalPort             = ("12181","12182","12190","27271","27272","27273","4181","4182","4190","9191","9192","9193","9194","5565","5575")
                        Protocol              = "TCP" 
                }
                $Depends += "[ArcGIS_xFirewall]GeoEvent_FirewallRules_MultiMachine"

                ArcGIS_xFirewall GeoEvent_FirewallRules_MultiMachine_OutBound
                {
                        Name                  = "ArcGISGeoEventFirewallRulesClusterOutbound" 
                        DisplayName           = "ArcGIS GeoEvent Extension Cluster Outbound" 
                        DisplayGroup          = "ArcGIS GeoEvent Extension" 
                        Ensure                = 'Present' 
                        Access                = "Allow" 
                        State                 = "Enabled" 
                        Profile               = ("Domain","Private","Public")
                        RemotePort            = ("12181","12182","12190","27271","27272","27273","4181","4182","4190","9191","9192","9193","9194","9220","9320","5565","5575")
                        Protocol              = "TCP" 
                        Direction             = "Outbound"    
                }
                $Depends += "[ArcGIS_xFirewall]GeoEvent_FirewallRules_MultiMachine_OutBound"
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

            $WorkflowManagerServerInstallerFileName = Split-Path $WorkflowManagerServerInstallerPath -Leaf
            $WorkflowManagerServerInstallerPathOnMachine = "$env:TEMP\WFMServer\$WorkflowManagerServerInstallerFileName"

            File DownloadWorkflowManagerInstallerFromFileShare      
            {            	
                Ensure = "Present"              	
                Type = "File"             	
                SourcePath = $WorkflowManagerServerInstallerPath 	
                DestinationPath = $WorkflowManagerServerInstallerPathOnMachine     
                Credential = $FileshareMachineCredential     
                DependsOn = $Depends  
            }
            $Depends += '[File]DownloadWorkflowManagerInstallerFromFileShare'
            
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
                EnableMSILogging = $IsDebugMode
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
            if($IsMultiMachineServerSite -and ($VersionArray[0] -ieq 11 -and $VersionArray -ge 3)){ # 11.3 or later
                $WfmPorts = @("13820", "13830", "13840", "9880")

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
                    RemotePort            = $WfmPorts
                    Protocol              = "TCP"
                    Direction             = "Inbound"
                }
                $DependsOnWfm += "[ArcGIS_xFirewall]WorkflowManagerServer_FirewallRules_MultiMachine_InBound"
            }
        }
    }
}
