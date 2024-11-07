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

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $InstallerIsSelfExtracting = $True,

        [System.String]
        $PatchesDir,

        [System.Array]
        $PatchInstallOrder,
        
        [System.String]
        $InstallDir,

        [System.String]
        $GeoEventServerInstaller,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $GeoEventServerInstallerIsSelfExtracting = $True,

        [System.String]
        $GeoEventServerPatchesDir,

        [System.Array]
        $GeoEventServerPatchInstallOrder,

        [System.Boolean]
        $GeoEventUserBackupConfigFiles,

        [System.String]
        $WorkflowManagerServerInstaller,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $WorkflowManagerInstallerIsSelfExtracting = $True,

        [System.String]
        $WorkflowManagerServerPatchesDir,

        [System.Array]
        $WorkflowManagerServerPatchInstallOrder,

        [System.Array]
        $ContainerImagePaths,

        [System.String]
        $NotebookServerSamplesDataPath,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $NotebookServerSamplesDataInstallerIsSelfExtracting = $True,

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
        $Extensions = $null,

        [System.Boolean]
        $DownloadPatches = $False,

        [System.Boolean]
        $SkipPatchInstalls = $False,

        [System.String]
        $DotnetDesktopRuntimePath = $null,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $DebugMode = $False
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.4.0 -Name ArcGIS_Install, ArcGIS_License, ArcGIS_ServerUpgrade, ArcGIS_NotebookServerUpgrade, ArcGIS_NotebookPostInstall, ArcGIS_MissionServerUpgrade, ArcGIS_VideoServerUpgrade, ArcGIS_xFirewall, ArcGIS_InstallPatch, ArcGIS_Service_Account
    
    Node $AllNodes.NodeName {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        $VersionArray = $Version.Split(".")
        $Depends = @()
        
        $ServerTypeName = if($Node.ServerRole -ieq "NotebookServer"){ "NotebookServer" }elseif($Node.ServerRole -ieq "MissionServer"){ "MissionServer" }elseif($Node.ServerRole -ieq "VideoServer"){ "VideoServer" }else{ "Server" }

        if($Node.ServerRole -ieq "GeoEvent" -or ($Node.ServerRole -ieq "GeneralPurposeServer" -and $Node.AdditionalServerRoles -icontains "GeoEvent")){
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

        $ServerUpgradeInstallArguments = if($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 8)){"/qn ACCEPTEULA=YES"}else{"/qn"}
        $ServerFeatureSet = @()
        if($ServerTypeName -ieq "Server"){
            if($VersionArray[0] -eq 11){
                if(-not($EnableDotnetSupport)){
                    $ServerFeatureSet = @("GIS_Server")
                }
            }elseif($Version -ieq "10.9.1"){
                $ServerUpgradeInstallArguments = "/qn ACCEPTEULA=YES"
                if(-not($EnableArcMapRuntime) -and -not($EnableDotnetSupport)){
                    $ServerFeatureSet = @("GIS_Server")
                }elseif($EnableArcMapRuntime -and -not($EnableDotnetSupport)){
                    $ServerFeatureSet = @("ArcMap")
                }elseif(-not($EnableArcMapRuntime) -and $EnableDotnetSupport){
                    $ServerFeatureSet = @("DotNetSupport")
                }
            }
        }

        ArcGIS_Install ServerUpgrade{
            Name = $ServerTypeName
            Version = $Version
            Path = $InstallerPath
            Extract = $InstallerIsSelfExtracting
            Arguments = $ServerUpgradeInstallArguments
            FeatureSet = $ServerFeatureSet
            ServiceCredential = $ServiceAccount
            ServiceCredentialIsDomainAccount = $IsServiceAccountDomainAccount
            ServiceCredentialIsMSA = $IsServiceAccountMSA
            EnableMSILogging = $EnableMSILogging
            DotnetDesktopRuntimePath = $DotnetDesktopRuntimePath
            Ensure = "Present"
            DependsOn = $Depends
        }
        $Depends += '[ArcGIS_Install]ServerUpgrade'

        if($ServerTypeName -ieq "Server" -and $null -ne $Extensions){
            
            if(($VersionArray[0] -eq 11) -or ($Version -ieq "10.9.1")){
                ArcGIS_Install "ServerUpgradeUninstallWorkflowManagerClasicExtension"
                {
                    Name = "ServerWorkflowManagerClassic"
                    Version = $OldVersion
                    Ensure = "Absent"
                    DependsOn = $Depends
                }
                $Depends += '[ArcGIS_Install]ServerUpgradeUninstallWorkflowManagerClasicExtension'
            }

            if($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 8)){
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
                $ServerExtensionFeatureSet = @()
                if($Extension.Value.Features -and $Extension.Value.Features.Count -gt 0){
                    if($Extension.Value.Features -icontains "ALL"){
                        $ServerExtensionFeatureSet = @( "ALL" )
                    }else{
                        $Extension.Value.Features | % {
                            $ServerExtensionFeatureSet += @( $_ )
                        }
                    }
                }

                ArcGIS_Install "Server$($Extension.Key)UpgradeInstallExtension"
                {
                    Name = "Server$($Extension.Key)"
                    Version = $Version
                    Path = $Extension.Value.Installer.Path
                    Extract = if($Extension.Value.Installer.IsSelfExtracting){ $Extension.Value.Installer.IsSelfExtracting }else{ $True }
                    Arguments = $Arguments
                    FeatureSet = $ServerExtensionFeatureSet
                    EnableMSILogging = $EnableMSILogging
                    Ensure = "Present"
                }
                $Depends += "[ArcGIS_Install]Server$($Extension.Key)UpgradeInstallExtension"
            }
        }

        if ($PatchesDir -and -not($SkipPatchInstalls)) {
            ArcGIS_InstallPatch ServerInstallPatch
            {
                Name = $ServerTypeName
                Version = $Version
                DownloadPatches = $DownloadPatches
                PatchesDir = $PatchesDir
                PatchInstallOrder = $PatchInstallOrder
                Ensure = "Present"
            }
            $Depends += "[ArcGIS_InstallPatch]ServerInstallPatch"
        }

        if(@("10.9","10.9.1","11.0","11.1","11.2","11.3") -icontains $Version -and $NotebookServerSamplesDataPath){
            ArcGIS_Install "NotebookServerSamplesData$($Node.NodeName)Upgrade"
            { 
                Name = "NotebookServerSamplesData"
                Version = $Version
                Path = $NotebookServerSamplesDataPath
                Extract = $NotebookServerSamplesDataInstallerIsSelfExtracting
                Arguments = "/qn"
                ServiceCredential = $ServiceAccount
                ServiceCredentialIsDomainAccount = $IsServiceAccountDomainAccount
                ServiceCredentialIsMSA = $IsServiceAccountMSA
                EnableMSILogging = $EnableMSILogging
                Ensure = "Present"
                DependsOn = $Depends
            }
            $Depends += "[ArcGIS_Install]NotebookServerSamplesData$($Node.NodeName)Upgrade"
        }else{
            ArcGIS_Install NotebookUninstallSamplesData{
                Name = "NotebookServerSamplesData"
                Version = $OldVersion
                Ensure = "Absent"
                DependsOn = $Depends
            }
            $Depends += '[ArcGIS_Install]NotebookUninstallSamplesData'
        }

        if((($Node.ServerRole -ieq "GeoAnalytics") -or ($Node.ServerRole -ieq "GeneralPurposeServer" -and $Node.AdditionalServerRoles -icontains "GeoAnalytics")) -and ($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 8)) -and $IsMultiMachineServerSite){
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

        if($Node.ServerRole -ine "GeoEvent" -and $Node.ServerRole -ine "WorkflowManagerServer" -and $Node.ServerLicenseFilePath){
            $AdditionalRoles = $null
            if($Node.ServerRole -ieq "GeneralPurposeServer" -and $Node.AdditionalServerRoles){
                $AddRoles = ($Node.AdditionalServerRoles | Where-Object { -not(@('GeoEvent', 'NotebookServer','WorkflowManagerServer', 'MissionServer', 'VideoServer') -iContains $_ ) })
                if($AddRoles.Count -gt 0){
                    $AdditionalRoles = $AddRoles
                }
            }

            ArcGIS_License "ServerLicense$($Node.NodeName)"
            {
                LicenseFilePath = $Node.ServerLicenseFilePath
                LicensePassword = if($Node.ServerLicensePassword){ $Node.ServerLicensePassword }else{ $null }
                Ensure = "Present"
                Component = 'Server'
                ServerRole = $Node.ServerRole
                AdditionalServerRoles = $AdditionalRoles
                Force = $True
                DependsOn = $Depends
            }
            $Depends += "[ArcGIS_License]ServerLicense$($Node.NodeName)"
        }

        if(($Node.ServerRole -ieq "GeoEvent" -or ($Node.ServerRole -ieq "GeneralPurposeServer" -and $Node.AdditionalServerRoles -icontains "GeoEvent")) -and $Node.GeoeventServerLicenseFilePath){
            ArcGIS_License "GeoeventServerLicense$($Node.NodeName)"
            {
                LicenseFilePath =  $Node.GeoeventServerLicenseFilePath
                LicensePassword = $Node.GeoeventServerLicensePassword
                Ensure = "Present"
                Component = 'Server'
                ServerRole = "GeoEvent"
                Force = $True
            }
            $Depends += "[ArcGIS_License]GeoeventServerLicense$($Node.NodeName)"
        }

        if(($Node.ServerRole -ieq "WorkflowManagerServer" -or ($Node.ServerRole -ieq "GeneralPurposeServer" -and $Node.AdditionalServerRoles -icontains "WorkflowManagerServer")) -and $Node.WorkflowManagerServerLicenseFilePath){
            ArcGIS_License "WorkflowManagerServerLicense$($Node.NodeName)"
            {
                LicenseFilePath =  $Node.WorkflowManagerServerLicenseFilePath
                LicensePassword = $Node.WorkflowManagerServerLicensePassword
                Ensure = "Present"
                Component = 'Server'
                ServerRole = "WorkflowManagerServer"
                Force = $True
            }
            $Depends += "[ArcGIS_License]WorkflowManagerServerLicense$($Node.NodeName)"
        }

        if($Node.ServerRole -ieq "NotebookServer"){
            ArcGIS_NotebookServerUpgrade NotebookServerConfigureUpgrade{
                Version = $Version
                ServerHostName = $Node.NodeName
                DependsOn = $Depends
            }
           
            if(($ContainerImagePaths.Count -gt 0) -or (($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 8)) -and $NotebookServerSamplesDataPath)){
                $Depends += '[ArcGIS_NotebookServerUpgrade]NotebookServerConfigureUpgrade'

                if($IsServiceAccountMSA){
                    ArcGIS_NotebookPostInstall "NotebookPostInstall$($Node.NodeName)" {
                        SiteName            = "arcgis"
                        ContainerImagePaths = $ContainerImagePaths
                        ExtractSamples      = $false
                        DependsOn           = $Depends
                    }
                }else{
                    ArcGIS_NotebookPostInstall "NotebookPostInstall$($Node.NodeName)" {
                        SiteName            = 'arcgis' 
                        ContainerImagePaths = $ContainerImagePaths
                        ExtractSamples      = (($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 8)) -and $NotebookServerSamplesDataPath)
                        DependsOn           = $Depends
                        PsDscRunAsCredential  = $ServiceAccount # Copy as arcgis account which has access to this share
                    }
                }
            }
        }elseif($Node.ServerRole -ieq "MissionServer"){
            ArcGIS_MissionServerUpgrade MissionServerConfigureUpgrade{
                Version = $Version
                ServerHostName = $Node.NodeName
                DependsOn = $Depends
            }
        }elseif($Node.ServerRole -ieq "VideoServer"){
            ArcGIS_VideoServerUpgrade VideoServerConfigureUpgrade{
                Version = $Version
                ServerHostName = $Node.NodeName
                DependsOn = $Depends
            }
        }else{
            ArcGIS_ServerUpgrade ServerConfigureUpgrade{
                Version = $Version
                ServerHostName = $Node.NodeName
                DependsOn = $Depends
                EnableUpgradeSiteDebug = $DebugMode
            }
        }

        #Upgrade Workflow Manager Server
        if($Node.ServerRole -ieq "WorkflowManagerServer" -or ($Node.ServerRole -ieq "GeneralPurposeServer" -and $Node.AdditionalServerRoles -icontains "WorkflowManagerServer")){
            $Depends += '[ArcGIS_ServerUpgrade]ServerConfigureUpgrade'

            ArcGIS_Install WorkflowManagerServerUpgrade
            {
                Name = "WorkflowManagerServer"
                Version = $Version
                Path = $WorkflowManagerServerInstaller
                Extract = $WorkflowManagerInstallerIsSelfExtracting
                Arguments = "/qn"
                ServiceCredential = $ServiceAccount
                ServiceCredentialIsDomainAccount = $IsServiceAccountDomainAccount
                ServiceCredentialIsMSA = $IsServiceAccountMSA
                EnableMSILogging = $EnableMSILogging
                Ensure = "Present"
                DependsOn = $Depends
            }
            $Depends += "[ArcGIS_Install]WorkflowManagerServerUpgrade"

            if ($WorkflowManagerServerPatchesDir -and -not($SkipPatchInstalls)) {
                ArcGIS_InstallPatch WorkflowManagerServerPatches
                {
                    Name = "WorkflowManagerServer"
                    Version = $Version
                    DownloadPatches = $DownloadPatches
                    PatchesDir = $WorkflowManagerServerPatchesDir
                    PatchInstallOrder = $WorkflowManagerServerPatchInstallOrder
                    Ensure = "Present"
                    DependsOn = $Depends
                }
                $Depends += "[ArcGIS_InstallPatch]WorkflowManagerServerPatches"
            }

            # MultiMachine upgrade
            $VersionArray = $Version.Split(".")
            if($IsMultiMachineServerSite -and ($VersionArray[0] -ieq 11 -and $VersionArray -ge 3)){
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
                    DependsOn             = $Depends
                }
                $Depends += "[ArcGIS_xFirewall]WorkflowManagerServer_FirewallRules_MultiMachine_OutBound"

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
                    DependsOn             = $Depends
                }
                $Depends += "[ArcGIS_xFirewall]WorkflowManagerServer_FirewallRules_MultiMachine_InBound"
            }
        }

        #Upgrade GeoEvents
        if($Node.ServerRole -ieq "GeoEvent" -or ($Node.ServerRole -ieq "GeneralPurposeServer" -and $Node.AdditionalServerRoles -icontains "GeoEvent")){
            $Depends += '[ArcGIS_ServerUpgrade]ServerConfigureUpgrade'

            $GEArguments = "/qn"
            if($GeoEventUserBackupConfigFiles -and $Version.StartsWith("11.")){
                $GEArguments += " USERBACKUPCONFIGFILES=YES"
            }

            ArcGIS_Install GeoEventServerUpgrade{
                Name = "GeoEvent"
                Version = $Version
                Path = $GeoEventServerInstaller
                Extract = $GeoEventServerInstallerIsSelfExtracting
                Arguments = $GEArguments
                ServiceCredential = $ServiceAccount
                ServiceCredentialIsDomainAccount = $IsServiceAccountDomainAccount
                ServiceCredentialIsMSA = $IsServiceAccountMSA
                EnableMSILogging = $EnableMSILogging
                Ensure = "Present"
                DependsOn = $Depends
            }
            $Depends += "[ArcGIS_Install]GeoEventServerUpgrade"

            if ($GeoEventServerPatchesDir -and -not($SkipPatchInstalls)) {
                ArcGIS_InstallPatch GeoEventServerPatches
                {
                    Name = "GeoEvent"
                    Version = $Version
                    DownloadPatches = $DownloadPatches
                    PatchesDir = $GeoEventServerPatchesDir
                    PatchInstallOrder = $GeoEventServerPatchInstallOrder
                    Ensure = "Present"
                    DependsOn = $Depends
                }
                $Depends += "[ArcGIS_InstallPatch]GeoEventServerPatches"
            }

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

            if(($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 8)) -and $IsMultiMachineServerSite){
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
