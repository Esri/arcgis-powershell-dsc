Configuration ServerUpgrade{
    param(
        [System.String]
        $Version,

        [System.Management.Automation.PSCredential]
        $ServiceAccount,
        
        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsSADomainAccount = $False,

        [System.String]
        $InstallerPath,

        [System.String]
        $LicensePath,

        [System.String]
        $LicensePassword,

        [System.String]
        $ServerRole,
        
        [System.String]
        $GeoEventServerInstaller

    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName ArcGIS 
    Import-DscResource -Name ArcGIS_Install 
    Import-DscResource -Name ArcGIS_License 
    Import-DscResource -Name ArcGIS_ServerUpgrade 
    
    Node $AllNodes.NodeName {
        $NodeName = $Node.NodeName

        $MachineFQDN = [System.Net.DNS]::GetHostByName($NodeName).HostName
        
        $Depends = @()
        if(-not($IsSADomainAccount)){
            User ArcGIS_RunAsAccount
            {
                UserName = $ServiceAccount.UserName
                Password = $ServiceAccount
                FullName = 'ArcGIS Run As Account'
                Ensure = "Present"
            }

            $Depends += '[User]ArcGIS_RunAsAccount'
        }

        ArcGIS_Install ServerUpgrade{
            Name = "Server"
            Version = $Version
            Path = $InstallerPath
            Arguments = "/qb USER_NAME=$($ServiceAccount.UserName) PASSWORD=$($ServiceAccount.GetNetworkCredential().Password)";
            Ensure = "Present"
            DependsOn = $Depends
        }

        $Depends += '[ArcGIS_Install]ServerUpgrade'

        if(-not($ServerRole) -or ($ServerRole -ieq "GeoEvent")){
            $ServerRole = "GeneralPurposeServer"
        }
        if($ServerRole -ieq "RasterAnalysis" -or $ServerRole -ieq "ImageHosting"){
            $ServerRole = "ImageServer"
        }
        
        ArcGIS_License ServerLicense
        {
            LicenseFilePath = $LicensePath
            Password = $LicensePassword
            Ensure = "Present"
            Component = 'Server'
            ServerRole = $ServerRole 
            Force = $True
            DependsOn = $Depends
        }

        $Depends += '[ArcGIS_License]ServerLicense'

        ArcGIS_ServerUpgrade ServerConfigureUpgrade{
            Ensure = "Present"
            Version = $Version
            ServerHostName = $MachineFQDN
            DependsOn = $Depends
        }

        #Upgrade GeoEvents
        if($ServerRole -ieq "GeoEvent"){
            $Depends += '[ArcGIS_ServerUpgrade]ServerConfigureUpgrade'

            ArcGIS_WindowsService ArcGIS_GeoEvent_Service_Stop
            {
                Name = 'ArcGISGeoEvent'
                Credential = $ServiceAccount
                StartupType = 'Manual'
                State = 'Stopped'
                DependsOn = $Depends
            }

            ArcGIS_Install GeoEventServerUpgrade{
                Name = "GeoEvent"
                Version = $Version
                Path = $GeoEventServerInstaller
                Arguments = "/qb PASSWORD=$($ServiceAccount.GetNetworkCredential().Password)";
                Ensure = "Present"
                DependsOn = $Depends
            }

            xFirewall GeoEventService_Firewall
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
            $Depends += "[xFirewall]GeoEventService_Firewall"
            
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