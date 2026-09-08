Configuration PortalUpgrade{
    param(
        [parameter(Mandatory = $true)]
        [System.String]
        $OldVersion,

        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $true)]        
        [System.String]
        $InstallerPath,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $InstallerIsSelfExtracting = $True,

        [parameter(Mandatory = $false)]
        [System.String]
        $PatchesDir,

        [parameter(Mandatory = $false)]
        [System.Array]
        $PatchInstallOrder,

        [parameter(Mandatory = $false)]        
        [System.String]
        $WebStylesInstallerPath,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $WebStylesInstallerIsSelfExtracting = $True,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $ServiceAccount,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsServiceAccountDomainAccount = $False,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsServiceAccountMSA = $False,

        [System.Boolean]
        $DownloadPatches = $False,

        [System.Boolean]
        $SkipPatchInstalls = $False,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $EnableMSILogging = $false,

        [parameter(Mandatory = $False)]
        [System.Boolean]
        $IsMultiMachinePortal = $False
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 5.1.2 -Name ArcGIS_Install, ArcGIS_Service_Account, ArcGIS_InstallPatch, ArcGIS_xFirewall, ArcGIS_HostNameSettings

    Node $AllNodes.NodeName {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        $Depends = @()
        
        if($IsMultiMachinePortal -and ([version]$Version -ge "11.3")){ # 11.3 or later
            ArcGIS_xFirewall Portal_Ignite_OutBound
            {
                Name                  = "PortalforArcGIS-Ignite-Outbound" 
                DisplayName           = "Portal for ArcGIS Ignite Outbound" 
                DisplayGroup          = "Portal for ArcGIS Ignite Outbound" 
                Ensure                = 'Present' 
                Access                = "Allow" 
                State                 = "Enabled" 
                Profile               = ("Domain","Private","Public")
                RemotePort            = ("7820","7830", "7840") # Ignite uses 7820,7830,7840
                Direction             = "Outbound"                       
                Protocol              = "TCP" 
            }  
            $Depends += @('[ArcGIS_xFirewall]Portal_Ignite_OutBound')
            
            ArcGIS_xFirewall Portal_Ignite_InBound
            {
                Name                  = "PortalforArcGIS-Ignite-Inbound" 
                DisplayName           = "Portal for ArcGIS Ignite Inbound" 
                DisplayGroup          = "Portal for ArcGIS Ignite Inbound" 
                Ensure                = 'Present' 
                Access                = "Allow" 
                State                 = "Enabled" 
                Profile               = ("Domain","Private","Public")
                LocalPort            = ("7820","7830", "7840") # Ignite uses 7820,7830,7840
                Protocol              = "TCP" 
            }  
            $Depends += @('[ArcGIS_xFirewall]Portal_Ignite_InBound')
        }

        ArcGIS_Install PortalUpgrade
        { 
            Name = "Portal"
            Version = $Version
            Path = $InstallerPath
            Extract = $InstallerIsSelfExtracting
            Arguments = "/qn ACCEPTEULA=YES"
            ServiceCredential = $ServiceAccount
            ServiceCredentialIsDomainAccount =  $IsServiceAccountDomainAccount
            ServiceCredentialIsMSA = $IsServiceAccountMSA
            EnableMSILogging = $EnableMSILogging
            Ensure = "Present"
            DependsOn = $Depends
        }
        $Depends += '[ArcGIS_Install]PortalUpgrade'

        if($WebStylesInstallerPath){
            ArcGIS_Install "WebStylesInstall"
            { 
                Name = "WebStyles"
                Version = $Version
                Path = $WebStylesInstallerPath
                Extract = $WebStylesInstallerIsSelfExtracting
                Arguments = "/qn"
                ServiceCredential = $ServiceAccount
                ServiceCredentialIsDomainAccount =  $IsServiceAccountDomainAccount
                ServiceCredentialIsMSA = $IsServiceAccountMSA
                EnableMSILogging = $EnableMSILogging
                Ensure = "Present"
                DependsOn = $Depends
            }
            $Depends += '[ArcGIS_Install]WebStylesInstall'
        }

        if ($PatchesDir -and -not($SkipPatchInstalls)) {
            ArcGIS_InstallPatch PortalInstallPatch
            {
                Name = "Portal"
                Version = $Version
                DownloadPatches = $DownloadPatches
                PatchesDir = $PatchesDir
                PatchInstallOrder = $PatchInstallOrder
                Ensure = "Present"
            }
            $Depends += "[ArcGIS_InstallPatch]PortalInstallPatch"
        }

        $DataDirsForPortal = @('HKLM:\SOFTWARE\ESRI\Portal for ArcGIS')
        ArcGIS_Service_Account Portal_RunAs_Account
        {
            Name = 'Portal for ArcGIS'
            RunAsAccount = $ServiceAccount
            Ensure = "Present"
            DataDir = $DataDirsForPortal
            DependsOn =  $Depends
            IsDomainAccount = $IsServiceAccountDomainAccount
            IsMSAAccount = $IsServiceAccountMSA
            SetStartupToAutomatic = $True
        }

        ArcGIS_HostNameSettings PortalHostNameSettings
        {
            ComponentName   = "Portal"
            Version         = $Version
            HostName        = $Node.NodeName
            DependsOn       = @('[ArcGIS_Service_Account]Portal_RunAs_Account')
        }
    }
}
