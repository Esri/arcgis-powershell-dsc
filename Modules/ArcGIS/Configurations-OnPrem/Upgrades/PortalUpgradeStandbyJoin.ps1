Configuration PortalUpgradeStandbyJoin{
    param(
        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $true)]
        [System.String]
        $PrimaryPortalMachine,
        
        [parameter(Mandatory = $true)]
        [System.String]
        $Context,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $PrimarySiteAdmin,

        [parameter(Mandatory = $true)]
        [System.String]
        $PrimarySiteAdminEmail,

        [parameter(Mandatory = $true)]
        [System.String]
        $ContentDirectoryLocation,
        
        [parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [System.String]
        $ExternalDNSName,

        [parameter(Mandatory = $false)]
        [System.String]
        $LicenseFilePath,

        [parameter(Mandatory = $false)]
        [System.String]
        $UserLicenseType
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName ArcGIS 
    Import-DscResource -Name ArcGIS_Portal
    Import-DscResource -Name ArcGIS_PortalUpgrade 
    
    Node $AllNodes.NodeName {
        $NodeName = $Node.NodeName
        $MachineFQDN = [System.Net.DNS]::GetHostByName($NodeName).HostName
        $PrimaryPortalFQDN = [System.Net.DNS]::GetHostByName($PrimaryPortalMachine).HostName
        $VersionArray = $Version.Split(".")
        $MajorVersion = $VersionArray[1]
        ArcGIS_Portal "PortalStandByUpgradeJoin"
        {
            Ensure = 'Present'
            PortalEndPoint = $MachineFQDN
            PortalContext = $Context
            LicenseFilePath                       = if($MajorVersion -ge 7){ $LicenseFilePath } else {$null}
            UserLicenseType                       = if(($MajorVersion -ge 7) -and $UserLicenseType){ $UserLicenseType } else {$null}
            PortalAdministrator = $PrimarySiteAdmin 
            AdminEmail = $PrimarySiteAdminEmail
            AdminSecurityQuestionIndex = $ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.SecurityQuestionIndex
            AdminSecurityAnswer = $ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.SecurityAnswer
            ContentDirectoryLocation = $ContentDirectoryLocation
            Join = $true
            IsHAPortal = $true
            ExternalDNSName = $ExternalDNSName
            PeerMachineHostName = $PrimaryPortalFQDN
            EnableDebugLogging = $True
        } 
    }
}