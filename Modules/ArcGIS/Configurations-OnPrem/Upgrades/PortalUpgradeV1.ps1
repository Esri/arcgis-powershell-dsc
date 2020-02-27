Configuration PortalUpgradeV1{
    param(
        [parameter(Mandatory = $true)]
        [System.String]
        $OldVersion,

        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $true)]
        [System.String]
        $PrimaryPortalMachine,
        
        [parameter(Mandatory = $false)]
        [System.String]
        $StandbyMachineName,

        [parameter(Mandatory = $true)]        
        [System.String]
        $InstallerPath,

        [parameter(Mandatory = $false)]
        [System.String]
        $InstallDir,

        [parameter(Mandatory = $false)]
        [System.String]
        $ContentDir,
        
        [parameter(Mandatory = $true)]
        [System.String]
        $Context,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $ServiceAccount,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsServiceAccountDomainAccount = $False,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsServiceAccountMSA = $False,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministratorCredential,

        [parameter(Mandatory = $true)]
        [System.String]
        $ContentDirectoryLocation,
        
        [parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [System.String]
        $ExternalDNSName,

        [parameter(Mandatory = $false)]
        [System.String]
        $InternalLoadBalancer,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsMultiMachinePortal = $False<#,

        [parameter(Mandatory = $false)]
        [System.String]
        $FileShareMachine,

        [parameter(Mandatory = $false)]
        [System.String]
        $FileShareName#>
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.0.0"} 
    Import-DscResource -Name ArcGIS_Install 
    Import-DscResource -Name ArcGIS_License 
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -Name ArcGIS_Portal 
    Import-DscResource -Name ArcGIS_PortalUnregister 
    Import-DscResource -Name ArcGIS_PortalUpgrade 
    Import-DscResource -Name ArcGIS_WaitForComponent
    Import-DscResource -Name ArcGIS_PortalSettings

    Node $AllNodes.NodeName {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }

        $NodeName = $Node.NodeName
        $MachineFQDN = (Get-FQDN $NodeName)
        $PrimaryPortalHostName = (Get-FQDN $PrimaryPortalMachine)
        $StandbyMachine = if($StandbyMachineName){(Get-FQDN $StandbyMachineName)}else{$null}
        $VersionArray = $Version.Split(".")
        $MajorVersion = $VersionArray[1]
        $MinorVersion = if($VersionArray.Length -gt 2){ $VersionArray[2] }else{ 0 }
       
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

        if($MachineFQDN -ieq $PrimaryPortalHostName){
        
            if($IsMultiMachinePortal){
                ArcGIS_PortalUnregister UnregisterStandyPortal
                {
                    PortalEndPoint = $MachineFQDN
                    PrimarySiteAdmin = $SiteAdministratorCredential
                    StandbyMachine = $StandbyMachine
                    Version = $Version
                }
                $Depends += '[ArcGIS_PortalUnregister]UnregisterStandyPortal'
            }
            
            ArcGIS_Install PortalUpgrade
            { 
                Name = "Portal"
                Version = $Version
                Path = $InstallerPath
                Arguments = "/qb USER_NAME=$($ServiceAccount.UserName) PASSWORD=$($ServiceAccount.GetNetworkCredential().Password)";
                Ensure = "Present"
                DependsOn = $Depends
            }
            $Depends += '[ArcGIS_Install]PortalUpgrade'

            if($PortalLicenseFilePath) 
            {
                ArcGIS_License PortalLicense
                {
                    LicenseFilePath = $Node.PortalLicenseFilePath
                    LicensePassword = $Node.PortalLicensePassword
                    Ensure = "Present"
                    Component = 'Portal'
                    DependsOn = $Depends
                }
                $Depends += '[ArcGIS_License]PortalLicense'
            }

            Service Portal_for_ArcGIS_Service
            {
                Name = 'Portal for ArcGIS'
                Credential = $ServiceAccount
                StartupType = 'Automatic'
                State = 'Running'          
                DependsOn = $Depends
            } 
            
            $Depends += '[Service]Portal_for_ArcGIS_Service'
            
            <#$ContentDirectoryLocation = $ContentDirectoryLocation
            if($FileShareMachine -and $FileShareName) 
            {
                #$ContentDirectoryLocation = "\\$($FileShareMachine)\$($FileShareName)\$($ContentDirectoryLocation)"
            }#>    
            
            $DataDirsForPortal = @('HKLM:\SOFTWARE\ESRI\Portal for ArcGIS')
            
            ArcGIS_Service_Account Portal_RunAs_Account
            {
                Name = 'Portal for ArcGIS'
                RunAsAccount = $ServiceAccount
                Ensure = "Present"
                DataDir = $DataDirsForPortal
                DependsOn =  $Depends
                IsDomainAccount = $IsServiceAccountDomainAccount
            }
            $Depends += '[ArcGIS_Service_Account]Portal_RunAs_Account'
    
            if($MajorVersion -gt 5){
                ArcGIS_PortalUpgrade PortalUpgrade
                {
                    PortalAdministrator = $SiteAdministratorCredential 
                    PortalHostName = $MachineFQDN
                    LicenseFilePath = $null
                    DependsOn = $Depends
                }
                $Depends += '[ArcGIS_PortalUpgrade]PortalUpgrade'
            }else{
                ArcGIS_Portal PortalUpgrade
                {
                    Ensure = 'Present'
                    PortalHostName = $MachineFQDN
                    PortalAdministrator = $SiteAdministratorCredential 
                    DependsOn =  $Depends
                    AdminEmail = $SiteAdministratorCredential
                    AdminSecurityQuestionIndex = $ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.SecurityQuestionIndex
                    AdminSecurityAnswer = $ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.SecurityAnswer
                    ContentDirectoryLocation = $ContentDirectoryLocation
                    Join = $False
                    IsHAPortal =  if($IsMultiMachinePortal){$True}else{$False}
                    PeerMachineHostName = ""
                    EnableDebugLogging = $True
                }
                $Depends += "[ArcGIS_Portal]Portal$($Node.NodeName)"

                if($Node.NodeName -ieq $PrimaryPortalMachine){
                    ArcGIS_PortalSettings PortalSettings
                    {
                        PortalHostName          = $MachineFQDN
                        ExternalDNSName         = $ExternalDNSName
                        PortalContext           = $Context
                        PortalEndPoint          = if($InternalLoadBalancer){ $InternalLoadBalancer }else{ if($ExternalDNSHostName){ $ExternalDNSHostName }else{ $MachineFQDN }}
                        PortalEndPointContext   = if($InternalLoadBalancer -or !$ExternalDNSHostName){ 'arcgis' }else{ $Context }
                        PortalEndPointPort      = if($InternalLoadBalancer -or !$ExternalDNSHostName){ 7443 }else{ 443 }
                        PortalAdministrator     = $SiteAdministratorCredential
                        DependsOn               = $Depends
                    }
                    $Depends += "[ArcGIS_PortalSettings]PortalSettings"
                }
            }   
        }elseif($MachineFQDN -ieq $StandbyMachine){
            ArcGIS_WaitForComponent "WaitForUnregisterStandbyPortal"{
                Component = "UnregisterPortal"
                InvokingComponent = "PortalUpgrade"
                ComponentHostName = $PrimaryPortalHostName
                ComponentContext =  "arcgis"
                Ensure = "Present"
                Credential =  $SiteAdministratorCredential
                RetryIntervalSec = 60
                RetryCount = 60
            }

            ArcGIS_Install PortalUninstallStandby
            { 
                Name = "Portal"
                Version = $OldVersion
                Path = $InstallerPath
                Arguments = "/qn INSTALLDIR=$($InstallDir) CONTENTDIR=$($ContentDir)";
                Ensure = "Absent"
                DependsOn = $Depends
            }
            $Depends += '[ArcGIS_Install]PortalUninstallStandby'
            
            $PortalName = (get-CimInstance Win32_Product| Where-Object {$_.Name -match "Portal" -and $_.Vendor -eq 'Environmental Systems Research Institute, Inc.'}).Name
            # This will likely fail if querying a remote machine, need to find a better solution for this.
            if(-not($PortalName -imatch $Version)){
                File DirectoryRemove
                {
                    Ensure = "Absent"  
                    Type = "Directory" 
                    Force = $true
                    DestinationPath = $ContentDir  
                    DependsOn = $Depends
                }
            }

            ArcGIS_Install PortalInstall
            { 
                Name = "Portal"
                Version = $Version
                Path = $InstallerPath
                Arguments = "/qn INSTALLDIR=$($InstallDir) CONTENTDIR=$($ContentDir)"
                Ensure = "Present"
                DependsOn = $Depends
            }
            $Depends += "[ArcGIS_Install]PortalInstall"

            ArcGIS_License PortalLicense
            {
                LicenseFilePath = $Node.PortalLicenseFilePath
                LicensePassword = $Node.PortalLicensePassword
                Ensure = "Present"
                Component = 'Portal'
                DependsOn = $Depends
            }
            $Depends += '[ArcGIS_License]PortalLicense'
            
            Service Portal_for_ArcGIS_Service
            {
                Name = 'Portal for ArcGIS'
                Credential = $ServiceAccount
                StartupType = 'Automatic'
                State = 'Running'          
                DependsOn = $Depends
            }
            $Depends += '[Service]Portal_for_ArcGIS_Service'
            
            $DataDirsForPortal = @('HKLM:\SOFTWARE\ESRI\Portal for ArcGIS')
            
            ArcGIS_Service_Account Portal_RunAs_Account
            {
                Name = 'Portal for ArcGIS'
                RunAsAccount = $ServiceAccount
                Ensure = "Present"
                DataDir = $DataDirsForPortal
                DependsOn = $Depends
                IsDomainAccount = $IsServiceAccountDomainAccount
            }
            $Depends += '[ArcGIS_Service_Account]Portal_RunAs_Account'           
        }        
    }
}