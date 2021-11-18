Configuration ServerUpgrade{
    param(
        [parameter(Mandatory = $true)]
        [System.String]
        $OldVersion,

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

        [System.String]
        $WorkflowManagerServerInstaller,

        [System.Array]
        $ContainerImagePaths,

        [System.String]
        $NotebookServerSamplesDataPath,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $EnableMSILogging = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $IsMultiMachineServerSite = $false,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $EnableArcMapRuntime = $False,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $EnableDotnetSupport = $False,

        [Parameter(Mandatory=$false)]
        $Extensions = $null
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.3.0"} 
    Import-DscResource -Name ArcGIS_Install 
    Import-DscResource -Name ArcGIS_License 
    Import-DscResource -Name ArcGIS_ServerUpgrade 
    Import-DscResource -Name ArcGIS_NotebookServerUpgrade 
    Import-DscResource -Name ArcGIS_NotebookPostInstall
    Import-DscResource -Name ArcGIS_MissionServerUpgrade 
    Import-DscResource -Name ArcGIS_xFirewall
    
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
        
        $ServerTypeName = if($Node.ServerRole -ieq "NotebookServer"){ "NotebookServer" }elseif($Node.ServerRole -ieq "MissionServer"){ "MissionServer" }else{ "Server" }

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

        $ServerUpgradeInstallArguments = if($MajorVersion -gt 8){"/qn ACCEPTEULA=YES"}else{"/qn"}
        if($ServerTypeName -ieq "Server"){
            if($Version -ieq "10.9.1"){
                $ServerUpgradeInstallArguments = "/qn ACCEPTEULA=YES"
                if(-not($EnableArcMapRuntime) -and -not($EnableDotnetSupport)){
                    $ServerUpgradeInstallArguments += " ADDLOCAL=GIS_Server"
                }elseif($EnableArcMapRuntime -and -not($EnableDotnetSupport)){
                    $ServerUpgradeInstallArguments += " ADDLOCAL=ArcMap"
                }elseif(-not($EnableArcMapRuntime) -and $EnableDotnetSupport){
                    $ServerUpgradeInstallArguments += " ADDLOCAL=DotNetSupport"
                }
            }
        }

        ArcGIS_Install ServerUpgrade{
            Name = $ServerTypeName
            Version = $Version
            Path = $InstallerPath
            Arguments = $ServerUpgradeInstallArguments
            ServiceCredential = $ServiceAccount
            ServiceCredentialIsDomainAccount =  $IsServiceAccountDomainAccount
            ServiceCredentialIsMSA = $IsServiceAccountMSA
            EnableMSILogging = $EnableMSILogging
            Ensure = "Present"
            DependsOn = $Depends
        }
        $Depends += '[ArcGIS_Install]ServerUpgrade'

        if($ServerTypeName -ieq "Server" -and $null -ne $Extensions){
            if($MajorVersion -gt 8){
                ArcGIS_Install "ServerUpgradeUninstallLocationReferencingExtension"
                {
                    Name = "ServerLocationReferencing"
                    Version = $OldVersion
                    Ensure = "Absent"
                    DependsOn = $Depends
                }
                $Depends += '[ArcGIS_Install]ServerUpgradeUninstallLocationReferencingExtension'
            }

            foreach ($Extension in $Extensions.GetEnumerator())
            {
                $Arguments = "/qn"
                if($Extension.Value.Features -and $Extension.Value.Features.Count -gt 0){
                    $Features = $null
                    if($Extension.Value.Features -icontains "ALL"){
                        $Features = "ALL"
                    }else{
                        $Extension.Value.Features | % {
                            if($null -eq $Features){ 
                                $Features = $_
                            }else{
                                $Features += ",$_"
                            }
                        }
                    }

                    $Arguments += " ADDLOCAL=$Features"
                }

                ArcGIS_Install "Server$($Extension.Key)UpgradeInstallExtension"
                {
                    Name = "Server$($Extension.Key)"
                    Version = $Version
                    Path = $Extension.Value.Installer.Path
                    Arguments = $Arguments
                    EnableMSILogging = $EnableMSILogging
                    Ensure = "Present"
                }
                $Depends += "[ArcGIS_Install]Server$($Extension.Key)UpgradeInstallExtension"
            }
        }

        if((($MajorVersion -gt 8) -and $NotebookServerSamplesDataPath)){
            ArcGIS_Install "NotebookServerSamplesData$($Node.NodeName)Upgrade"
            { 
                Name = "NotebookServerSamplesData"
                Version = $Version
                Path = $NotebookServerSamplesDataPath
                Arguments = "/qn"
                ServiceCredential = $ServiceAccount
                ServiceCredentialIsDomainAccount =  $IsServiceAccountDomainAccount
                ServiceCredentialIsMSA = $IsServiceAccountMSA
                EnableMSILogging = $EnableMSILogging
                Ensure = "Present"
                DependsOn = $Depends
            }
            $Depends += "[ArcGIS_Install]NotebookServerSamplesData$($Node.NodeName)Upgrade"
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
                        PsDscRunAsCredential  = $ServiceAccount # Copy as arcgis account which has access to this share
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
        if($Node.ServerRole -ieq "WorkflowManagerServer"){
            $Depends += '[ArcGIS_ServerUpgrade]ServerConfigureUpgrade'

            ArcGIS_Install WorkflowManagerServerUpgrade
            {
                Name = "WorkflowManagerServer"
                Version = $Version
                Path = $WorkflowManagerServerInstaller
                Arguments = "/qn"
                ServiceCredential = $ServiceAccount
                ServiceCredentialIsDomainAccount =  $IsServiceAccountDomainAccount
                ServiceCredentialIsMSA = $IsServiceAccountMSA
                EnableMSILogging = $EnableMSILogging
                Ensure = "Present"
                DependsOn = $Depends
            }
            $Depends += "[ArcGIS_Install]WorkflowManagerServerUpgrade"
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

            ArcGIS_Service_Account GeoEvent_RunAs_Account_Update
            {
                Name = 'ArcGISGeoEvent'
                RunAsAccount = $ServiceAccount
                Ensure =  "Present"
                DependsOn = $Depends
                DataDir = "$env:ProgramData\Esri\GeoEvent"
                IsDomainAccount = $IsServiceAccountDomainAccount
                IsMSAAccount = $IsServiceAccountMSA
                SetStartupToAutomatic = $True
            }
            $Depends += "[ArcGIS_Service_Account]GeoEvent_RunAs_Account_Update"
        }      
    }
}