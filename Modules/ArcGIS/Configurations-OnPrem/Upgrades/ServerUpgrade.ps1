Configuration ServerUpgrade{
    param(
        [System.String]
        $Version,

        [System.Management.Automation.PSCredential]
        $ServiceAccount,
        
        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsServiceAccountDomainAccount = $False,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsServiceAccountMSA = $False,

        [System.String]
        $InstallerPath,

        [System.String]
        $InstallDir,
        
        [System.String]
        $GeoEventServerInstaller,

        [System.Array]
        $ContainerImagePaths,

        [System.String]
        $NotebookServerSamplesDataPath,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $EnableMSILogging = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $IsMultiMachineServerSite = $false
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.2.0"} 
    Import-DscResource -Name ArcGIS_Install 
    Import-DscResource -Name ArcGIS_License 
    Import-DscResource -Name ArcGIS_ServerUpgrade 
    Import-DscResource -Name ArcGIS_NotebookServerUpgrade 
    Import-DscResource -Name ArcGIS_NotebookPostInstall
    Import-DscResource -Name ArcGIS_MissionServerUpgrade 
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_WindowsService
    
    Node $AllNodes.NodeName {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        $NodeName = $Node.NodeName
        $MachineFQDN = Get-FQDN $NodeName
        $VersionArray = $Version.Split(".")
        $MajorVersion = $VersionArray[1]
        $MinorVersion = if($VersionArray.Length -gt 2){ $VersionArray[2] }else{ 0 }
        
        $Depends = @()
        
        if($Node.ServerRole -ieq "GeoEvent"){
            Service ArcGIS_GeoEvent_Service_Stop
            {
                Name        = "ArcGISGeoEvent"
                StartupType = "Manual"
                State       = "Stopped"
                DependsOn   = $Depends
            }
            $Depends += '[Service]ArcGIS_GeoEvent_Service_Stop'

            Service ArcGIS_GeoEventGateway_Service_Stop
            {
                Name        = "ArcGISGeoEventGateway"
                StartupType = "Manual"
                State       = "Stopped"
                DependsOn   = $Depends
            }
            $Depends += '[Service]ArcGIS_GeoEventGateway_Service_Stop'

        }

        ArcGIS_Install ServerUpgrade{
            Name = if($Node.ServerRole -ieq "NotebookServer"){ "NotebookServer" }elseif($Node.ServerRole -ieq "MissionServer"){ "MissionServer" }else{ "Server" } 
            Version = $Version
            Path = $InstallerPath
            Arguments = if($MajorVersion -gt 8){"/qn ACCEPTEULA=YES"}else{"/qn"};
            ServiceCredential = $ServiceAccount
            ServiceCredentialIsDomainAccount =  $IsServiceAccountDomainAccount
            ServiceCredentialIsMSA = $IsServiceAccountMSA
            EnableMSILogging = $EnableMSILogging
            Ensure = "Present"
            DependsOn = $Depends
        }
        $Depends += '[ArcGIS_Install]ServerUpgrade'

        if((($MajorVersion -gt 8) -and $NotebookServerSamplesDataPath)){
            ArcGIS_Install "NotebookServerSamplesData$($Node.NodeName)"
            { 
                Name = "NotebookServerSamplesData"
                Version = $Version
                Path = $NotebookServerSamplesDataPath
                Arguments = "/qn"
                ServiceCredential = $ServiceCredential
                ServiceCredentialIsDomainAccount =  $IsServiceAccountDomainAccount
                ServiceCredentialIsMSA = $IsServiceAccountMSA
                EnableMSILogging = $EnableMSILogging
                Ensure = "Present"
                DependsOn = $Depends
            }
            $Depends += "[ArcGIS_Install]NotebookServerSamplesData$($Node.NodeName)"
        }
        
        if(($Node.ServerRole -ieq "GeoAnalytics") -and ($MajorVersion -gt 8) -and $IsMultiMachineServerSite){
            $GeoAnalyticsPorts = @("7077","12181","12182","12190")
            ArcGIS_xFirewall GeoAnalytics_InboundFirewallRules
            {
                Name                  = "ArcGISGeoAnalyticsInboundFirewallRules" 
                DisplayName           = "ArcGIS GeoAnalytics" 
                DisplayGroup          = "ArcGIS GeoAnalytics" 
                Ensure                = 'Present'
                Access                = "Allow" 
                State                 = "Enabled" 
                Profile               = ("Domain","Private","Public")
                LocalPort             = $GeoAnalyticsPorts	# Spark and Zookeeper
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
                LocalPort             = $GeoAnalyticsPorts	# Spark and Zookeeper
                Protocol              = "TCP" 
                Direction             = "Outbound"    
            }
            $Depends += '[ArcGIS_xFirewall]GeoAnalytics_OutboundFirewallRules'
        }

        ArcGIS_License ServerLicense
        {
            LicenseFilePath = $Node.ServerLicenseFilePath
            LicensePassword = if($Node.ServerLicensePassword){ $Node.ServerLicensePassword }else{ $null }
            Ensure = "Present"
            Component = 'Server'
            ServerRole = $Node.ServerRole 
            Force = $True
            DependsOn = $Depends
        }
        $Depends += '[ArcGIS_License]ServerLicense'

        if($ServerRole -ieq "NotebookServer"){
            ArcGIS_NotebookServerUpgrade NotebookServerConfigureUpgrade{
                Ensure = "Present"
                Version = $Version
                ServerHostName = $MachineFQDN
                DependsOn = $Depends
            }
           
            if(($ContainerImagePaths.Count -gt 0) -or (($MajorVersion -gt 8) -and $NotebookServerSamplesDataPath)){
                $Depends += '[ArcGIS_NotebookServerUpgrade]NotebookServerConfigureUpgrade'

                if($IsServiceAccountMSA){
                    ArcGIS_NotebookPostInstall "NotebookPostInstall$($Node.NodeName)" {
                        SiteName            = 'arcgis' 
                        ContainerImagePaths = $ContainerImagePaths
                        ExtractSamples      = $false
                        DependsOn           = $Depends
                    }
                }else{
                    ArcGIS_NotebookPostInstall "NotebookPostInstall$($Node.NodeName)" {
                        SiteName            = 'arcgis' 
                        ContainerImagePaths = $ContainerImagePaths
                        ExtractSamples      = (($MajorVersion -gt 8) -and $NotebookServerSamplesDataPath)
                        DependsOn           = $Depends
                        PsDscRunAsCredential  = $ServiceCredential # Copy as arcgis account which has access to this share
                    }
                }
            }
        }elseif($ServerRole -ieq "MissionServer"){
            ArcGIS_MissionServerUpgrade MissionServerConfigureUpgrade{
                Ensure = "Present"
                Version = $Version
                ServerHostName = $MachineFQDN
                DependsOn = $Depends
            }
        }else{
            ArcGIS_ServerUpgrade ServerConfigureUpgrade{
                Ensure = "Present"
                Version = $Version
                ServerHostName = $MachineFQDN
                DependsOn = $Depends
            }
        }

        #Upgrade GeoEvents
        if($Node.ServerRole -ieq "GeoEvent"){
            $Depends += '[ArcGIS_ServerUpgrade]ServerConfigureUpgrade'

            ArcGIS_Install GeoEventServerUpgrade{
                Name = "GeoEvent"
                Version = $Version
                Path = $GeoEventServerInstaller
                Arguments = "/qn";
                ServiceCredential = $ServiceAccount
                ServiceCredentialIsDomainAccount = $IsServiceAccountDomainAccount
                ServiceCredentialIsMSA = $IsServiceAccountMSA
                EnableMSILogging = $EnableMSILogging
                Ensure = "Present"
                DependsOn = $Depends
            }
            $Depends += "[ArcGIS_Install]GeoEventServerUpgrade"

            ArcGIS_xFirewall GeoEventService_Firewall
            {
                Name                  = "ArcGISGeoEventGateway"
                DisplayName           = "ArcGIS GeoEvent Gateway"
                DisplayGroup          = "ArcGIS GeoEvent Gateway"
                Ensure                = 'Present'
                Access                = "Allow"
                State                 = "Enabled"
                Profile               = ("Domain","Private","Public")
                LocalPort             = ("9092")
                Protocol              = "TCP"
                DependsOn             = $Depends
            }
            $Depends += "[ArcGIS_xFirewall]GeoEventService_Firewall"

            if(($MajorVersion -gt 8) -and $IsMultiMachineServerSite){
                $GeoEventPorts = ("12181","12182","12190","27271","27272","27273","9191","9192","9193","9194","9220","9320","5565","5575")
                ArcGIS_xFirewall GeoEvent_FirewallRules_MultiMachine
                {
                    Name                  = "ArcGISGeoEventFirewallRulesCluster" 
                    DisplayName           = "ArcGIS GeoEvent Extension Cluster" 
                    DisplayGroup          = "ArcGIS GeoEvent Extension" 
                    Ensure                = "Present"
                    Access                = "Allow" 
                    State                 = "Enabled" 
                    Profile               = ("Domain","Private","Public")
                    LocalPort             = $GeoEventPorts
                    Protocol              = "TCP" 
                    DependsOn             = $Depends
                }
                $Depends += "[ArcGIS_xFirewall]GeoEvent_FirewallRules_MultiMachine"

                ArcGIS_xFirewall GeoEvent_FirewallRules_MultiMachine_OutBound
                {
                    Name                  = "ArcGISGeoEventFirewallRulesClusterOutbound" 
                    DisplayName           = "ArcGIS GeoEvent Extension Cluster Outbound" 
                    DisplayGroup          = "ArcGIS GeoEvent Extension" 
                    Ensure                =  "Present"
                    Access                = "Allow" 
                    State                 = "Enabled" 
                    Profile               = ("Domain","Private","Public")
                    RemotePort            = $GeoEventPorts
                    Protocol              = "TCP" 
                    Direction             = "Outbound"    
                    DependsOn             = $Depends
                }
                $Depends += "[ArcGIS_xFirewall]GeoEvent_FirewallRules_MultiMachine_OutBound"
            }

            ArcGIS_WindowsService ArcGIS_GeoEvent_Service_Start
            {
                Name = 'ArcGISGeoEvent'
                StartupType = 'Automatic'
                State = 'Running'
                DependsOn = $Depends
            }
            $Depends += "[ArcGIS_WindowsService]ArcGIS_GeoEvent_Service_Start"

            if(Get-Service 'ArcGISGeoEventGateway' -ErrorAction Ignore) 
            {
                ArcGIS_WindowsService ArcGIS_GeoEventGateway_Service
                {
                    Name		= 'ArcGISGeoEventGateway'
                    StartupType = 'Automatic'
                    State       = 'Running'
                    DependsOn   = $Depends
                }
                $Depends += "[ArcGIS_WindowsService]ArcGIS_GeoEventGateway_Service"
            }

        }      
    }
}