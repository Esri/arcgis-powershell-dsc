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
        $DownloadPatches = $False
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.1.0 
    Import-DscResource -Name ArcGIS_Install 
    Import-DscResource -Name ArcGIS_License 
    Import-DscResource -Name ArcGIS_ServerUpgrade 
    Import-DscResource -Name ArcGIS_NotebookServerUpgrade 
    Import-DscResource -Name ArcGIS_NotebookPostInstall
    Import-DscResource -Name ArcGIS_MissionServerUpgrade 
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_InstallPatch
    
    Node $AllNodes.NodeName {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        $VersionArray = $Version.Split(".")
        $Depends = @()
        
        $ServerTypeName = if($Node.ServerRole -ieq "NotebookServer"){ "NotebookServer" }elseif($Node.ServerRole -ieq "MissionServer"){ "MissionServer" }else{ "Server" }

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

        if ($PatchesDir) {
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

        if(($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 8)) -and $NotebookServerSamplesDataPath){
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
            ArcGIS_License "ServerLicense$($Node.NodeName)"
            {
                LicenseFilePath = $Node.ServerLicenseFilePath
                LicensePassword = if($Node.ServerLicensePassword){ $Node.ServerLicensePassword }else{ $null }
                Ensure = "Present"
                Component = 'Server'
                ServerRole = $Node.ServerRole
                AdditionalServerRoles = if($Node.ServerRole -ieq "GeneralPurposeServer" -and $Node.AdditionalServerRoles){ if(($Node.AdditionalServerRoles | Where-Object {$_ -ine 'GeoEvent' -and $_ -ine 'NotebookServer' -and $_ -ine 'WorkflowManagerServer' -and $_ -ine 'MissionServer'}).Count -gt 0){ $Node.AdditionalServerRoles | Where-Object {$_ -ine 'GeoEvent' -and $_ -ine 'NotebookServer' -and $_ -ine 'WorkflowManagerServer' -and $_ -ine 'MissionServer'} }else{$null} }else{ $null }
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
                Ensure = "Present"
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
                Ensure = "Present"
                Version = $Version
                ServerHostName = $Node.NodeName
                DependsOn = $Depends
            }
        }else{
            ArcGIS_ServerUpgrade ServerConfigureUpgrade{
                Ensure = "Present"
                Version = $Version
                ServerHostName = $Node.NodeName
                DependsOn = $Depends
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

            if ($WorkflowManagerServerPatchesDir) {
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

            if ($GeoEventServerPatchesDir) {
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
