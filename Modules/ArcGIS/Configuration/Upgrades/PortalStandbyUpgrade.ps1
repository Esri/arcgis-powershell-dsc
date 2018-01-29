Configuration PortalStandbyUpgrade{
    
    param(
        [System.String]
        $OldVersion,

        [System.String]
        $Version,
        
        [System.String]
        $InstallerPath,

        [System.String]
        $InstallDir,
        
        [System.String]
        $ContentDir,
        
        [System.String]
        $LicensePath,
        
        [System.String]
        $Context,

        [System.Management.Automation.PSCredential]
        $ServiceAccount,

        [System.Management.Automation.PSCredential]
        $PrimarySiteAdmin, 

        [System.String]
        $FileShareMachine,

        [System.String]
        $FileShareName,

        [System.String]
        $ContentDirectoryLocation,

        [System.String]
        $ExternalDNSName,

        [System.String]
        $PrimarySiteAdminEmail,

        [System.String]
        $PrimaryPortalMachine
    )
    
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName ArcGIS 
    Import-DscResource -Name ArcGIS_Install 
    Import-DscResource -Name ArcGIS_License 
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -Name ArcGIS_Portal 
    
    Node $AllNodes.NodeName {
        $NodeName = $Node.NodeName

        $MachineFQDN = [System.Net.DNS]::GetHostByName($NodeName).HostName
        $PrimaryPortalHostName = [System.Net.DNS]::GetHostByName($PrimaryPortalMachine).HostName
        
        $Depends = @()
        
        User ArcGIS_RunAsAccount
        {
            UserName = $ServiceAccount.UserName
            Password = $ServiceAccount
            FullName = 'ArcGIS Run As Account'
            Ensure = "Present"
        }

        ArcGIS_Install PortalUninstallStandby
        { 
            Name = "Portal"
            Version = $OldVersion
            Path = $InstallerPath
            Arguments = "/qn INSTALLDIR=$($InstallDir) CONTENTDIR=$($ContentDir)";
            Ensure = "Absent"
        }

        File DirectoryRemove
        {
            Ensure = "Absent"  
            Type = "Directory" 
            Force = $true
            DestinationPath = $ContentDir  
        }
        
        ArcGIS_Install PortalInstall
        { 
            Name = "Portal"
            Version = $Version
            Path = $InstallerPath
            Arguments = "/qn INSTALLDIR=$($InstallDir) CONTENTDIR=$($ContentDir)";
            Ensure = "Present"
        }
        
        ArcGIS_License PortalLicense
        {
            LicenseFilePath = $LicenseFilePath
            Ensure = "Present"
            Component = 'Portal'
            DependsOn = "[ArcGIS_Install]PortalInstall"
        }

        Service Portal_for_ArcGIS_Service
        {
            Name = 'Portal for ArcGIS'
            Credential = $ServiceAccount
            StartupType = 'Automatic'
            State = 'Running'          
            DependsOn = @('[User]ArcGIS_RunAsAccount')
        }

        $ContentDirectoryLocation = "\\$($FileShareMachine)\$($FileShareName)\$($ContentDirectoryLocation)"
                        
        $ServiceAccountsDepends =  @('[User]ArcGIS_RunAsAccount', '[Service]Portal_for_ArcGIS_Service')
        $DataDirsForPortal = @('HKLM:\SOFTWARE\ESRI\Portal for ArcGIS')

        ArcGIS_Service_Account Portal_RunAs_Account
        {
            Name = 'Portal for ArcGIS'
            RunAsAccount = $ServiceAccount
            Ensure = "Present"
            DataDir = $DataDirsForPortal
            DependsOn = $ServiceAccountsDepends
        }
                        
        $Depends += @("[ArcGIS_License]PortalLicense",'[ArcGIS_Service_Account]Portal_RunAs_Account')
        ArcGIS_Portal "PortalStandBy"
        {
            Ensure = 'Present'
            PortalContext = $Context
            PortalAdministrator = $PSACredential 
            DependsOn =  $Depends
            AdminEMail = $PrimarySiteAdminEmail
            AdminSecurityQuestionIndex = 1
            AdminSecurityAnswer = "vanilla"
            ContentDirectoryLocation = $ContentDirectoryLocation
            Join = $true
            IsHAPortal = $true
            ExternalDNSName = $ExternalDNSName
            PortalEndPoint = $MachineFQDN
            PeerMachineHostName = $PrimaryPortalHostName
            EnableDebugLogging = $True
        }

    }

}