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
        $ContainerImagePaths
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.0.0"} 
    Import-DscResource -Name ArcGIS_Install 
    Import-DscResource -Name ArcGIS_License 
    Import-DscResource -Name ArcGIS_WindowsService
    Import-DscResource -Name ArcGIS_ServerUpgrade 
    Import-DscResource -Name ArcGIS_NotebookServerUpgrade 
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
        
        $Depends = @()
        if(-not($IsServiceAccountDomainAccount)){
            User ArcGIS_RunAsAccount
            {
                UserName = $ServiceAccount.UserName
                Password = $ServiceAccount
                FullName = 'ArcGIS Run As Account'
                Ensure = "Present"
            }

            $Depends += '[User]ArcGIS_RunAsAccount'
        }

        if($Node.ServerRole -ieq "GeoEvent"){
            ArcGIS_WindowsService ArcGIS_GeoEvent_Service_Stop
            {
                Name = 'ArcGISGeoEvent'
                Credential = $ServiceAccount
                StartupType = 'Manual'
                State = 'Stopped'
                DependsOn = $Depends
            }
            $Depends += '[ArcGIS_WindowsService]ArcGIS_GeoEvent_Service_Stop'
        }

        ArcGIS_Install ServerUpgrade{
            Name = if($Node.ServerRole -ieq "NotebookServer"){ "NotebookServer" }else{ "Server" } 
            Version = $Version
            Path = $InstallerPath
            Arguments = "/qb USER_NAME=$($ServiceAccount.UserName) PASSWORD=$($ServiceAccount.GetNetworkCredential().Password)";
            Ensure = "Present"
            DependsOn = $Depends
        }

        $Depends += '[ArcGIS_Install]ServerUpgrade'

        ArcGIS_License ServerLicense
        {
            LicenseFilePath = $Node.ServerLicenseFilePath
            LicensePassword = $Node.ServerLicensePassword
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

            if($ContainerImagePaths.Count -gt 0){
                ArcGIS_NotebookUpgradePostInstall "NotebookPostInstall$($Node.NodeName)" {
                    SiteName            = 'arcgis' 
                    ContainerImagePaths = $ContainerImagePaths
                    InstallDir          = $InstallDir
                    DependsOn           = $Depends
                }
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
                Arguments = "/qb PASSWORD=$($ServiceAccount.GetNetworkCredential().Password)";
                Ensure = "Present"
                DependsOn = $Depends
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
            
            ArcGIS_WindowsService ArcGIS_GeoEvent_Service_Start
            {
                Name = 'ArcGISGeoEvent'
                Credential = $ServiceAccount
                StartupType = 'Automatic'
                State = 'Running'
                DependsOn = $Depends
            }

            if(Get-Service 'ArcGISGeoEventGateway' -ErrorAction Ignore) 
            {
                ArcGIS_WindowsService ArcGIS_GeoEventGateway_Service
                {
                    Name		= 'ArcGISGeoEventGateway'
                    Credential  = $ServiceAccount
                    StartupType = 'Automatic'
                    State       = 'Running'
                    DependsOn   = $Depends
                }
                $Depends += "[ArcGIS_WindowsService]ArcGIS_GeoEventGateway_Service"
            }
            <# 9220,9320#>
        }
    }
}