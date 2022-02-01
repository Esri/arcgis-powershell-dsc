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
        $PortalSiteAdministratorCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AdminEmail,

        [Parameter(Mandatory=$False)]
        [System.Byte]
        $AdminSecurityQuestionIndex,
        
        [Parameter(Mandatory=$False)]
        [System.String]
        $AdminSecurityAnswer,

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
        
        [Parameter(Mandatory=$false)]
        [System.Int32]
        $InternalLoadBalancerPort,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsMultiMachinePortal = $False,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $EnableMSILogging = $false<#,

        [parameter(Mandatory = $false)]
        [System.String]
        $FileShareMachine,

        [parameter(Mandatory = $false)]
        [System.String]
        $FileShareName#>
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.3.0"} 
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
        if($MachineFQDN -ieq $PrimaryPortalHostName){
            if($IsMultiMachinePortal){
                ArcGIS_PortalUnregister UnregisterStandyPortal
                {
                    PortalEndPoint = $MachineFQDN
                    PortalAdministrator = $PortalSiteAdministratorCredential
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
                Arguments = Arguments = if($MajorVersion -gt 8){"/qn ACCEPTEULA=YES"}else{"/qn"}
                ServiceCredential = $ServiceAccount
                ServiceCredentialIsDomainAccount =  $IsServiceAccountDomainAccount
                ServiceCredentialIsMSA = $IsServiceAccountMSA
                EnableMSILogging = $EnableMSILogging
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
                IsMSAAccount = $IsServiceAccountMSA
                SetStartupToAutomatic = $True
            }
            $Depends += '[ArcGIS_Service_Account]Portal_RunAs_Account'
    
            if($MajorVersion -gt 5){
                ArcGIS_PortalUpgrade PortalUpgrade
                {
                    PortalAdministrator = $PortalSiteAdministratorCredential 
                    PortalHostName = $MachineFQDN
                    LicenseFilePath = $null
                    Version = $Version
                    DependsOn = $Depends
                }
                $Depends += '[ArcGIS_PortalUpgrade]PortalUpgrade'
            }else{
                ArcGIS_Portal PortalUpgrade
                {
                    Ensure = 'Present'
                    PortalHostName = $MachineFQDN
                    PortalAdministrator = $PortalSiteAdministratorCredential 
                    DependsOn =  $Depends
                    AdminEmail = $AdminEmail
                    AdminSecurityQuestionIndex = $AdminSecurityQuestionIndex
                    AdminSecurityAnswer = $AdminSecurityAnswer
                    ContentDirectoryLocation = $ContentDirectoryLocation
                    Join = $False
                    IsHAPortal =  if($IsMultiMachinePortal){$True}else{$False}
                    PeerMachineHostName = ""
                    EnableDebugLogging = $True
                    EnableEmailSettings = $False
                    EmailSettingsSMTPServerAddress = $null
                    EmailSettingsFrom = $null
                    EmailSettingsLabel = $null
                    EmailSettingsAuthenticationRequired = $false
                    EmailSettingsCredential = $null
                    EmailSettingsSMTPPort = $null
                    EmailSettingsEncryptionMethod = "NONE"
                }
                $Depends += "[ArcGIS_Portal]Portal$($Node.NodeName)"

                if($Node.NodeName -ieq $PrimaryPortalMachine){
                    ArcGIS_PortalSettings PortalSettings
                    {
                        PortalHostName          = $MachineFQDN
                        ExternalDNSName         = $ExternalDNSName
                        PortalContext           = $Context
                        PortalEndPoint          = if($InternalLoadBalancer){ $InternalLoadBalancer }else{ if($ExternalDNSHostName){ $ExternalDNSHostName }else{ (Get-FQDN $MachineFQDN) }}
                        PortalEndPointContext   = if($InternalLoadBalancer -or !$ExternalDNSHostName){ 'arcgis' }else{ $Context }
                        PortalEndPointPort      = if($InternalLoadBalancerPort) { $InternalLoadBalancerPort }elseif(!$ExternalDNSHostName) { 7443 }else { 443 }
                        PortalAdministrator     = $PortalSiteAdministratorCredential
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
                Credential =  $PortalSiteAdministratorCredential
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
            
            Script PortalContentDirectoryRemove
            {
                SetScript = {
                    Remove-Item $using:ContentDir -Recurse
                }
                TestScript = { 
                    -not(Test-Path $using:ContentDir)
                }
                GetScript = { $null }
                DependsOn = $Depends
            }
            $Depends += "[Script]PortalContentDirectoryRemove"

            ArcGIS_Install PortalInstall
            { 
                Name = "Portal"
                Version = $Version
                Path = $InstallerPath
                Arguments = if($MajorVersion -gt 8){"/qn INSTALLDIR=$($InstallDir) CONTENTDIR=$($ContentDir) ACCEPTEULA=YES"}else{"/qn INSTALLDIR=$($InstallDir) CONTENTDIR=$($ContentDir)"}
                Ensure = "Present"
                EnableMSILogging = $EnableMSILogging
                ServiceCredential = $ServiceAccount
                ServiceCredentialIsDomainAccount =  $IsServiceAccountDomainAccount
                ServiceCredentialIsMSA = $IsServiceAccountMSA
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
            
            $DataDirsForPortal = @('HKLM:\SOFTWARE\ESRI\Portal for ArcGIS')
            
            ArcGIS_Service_Account Portal_RunAs_Account
            {
                Name = 'Portal for ArcGIS'
                RunAsAccount = $ServiceAccount
                Ensure = "Present"
                DataDir = $DataDirsForPortal
                DependsOn = $Depends
                IsDomainAccount = $IsServiceAccountDomainAccount
                IsMSAAccount = $IsServiceAccountMSA
                SetStartupToAutomatic = $True
            }
            $Depends += '[ArcGIS_Service_Account]Portal_RunAs_Account'           
        }        
    }
}