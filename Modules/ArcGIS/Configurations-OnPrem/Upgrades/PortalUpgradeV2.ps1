Configuration PortalUpgradeV2{
    param(
        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $true)]        
        [System.String]
        $InstallerPath,

        [parameter(Mandatory = $false)]        
        [System.String]
        $WebStylesInstallerPath,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $ServiceAccount,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsServiceAccountDomainAccount = $False,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsServiceAccountMSA = $False,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $EnableMSILogging = $false
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.2.0"} 
    Import-DscResource -Name ArcGIS_Install 
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -Name ArcGIS_PortalUpgrade 
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
        $VersionArray = $Version.Split(".")
        $MajorVersion = $VersionArray[1]
        $MinorVersion = if($VersionArray.Length -gt 2){ $VersionArray[2] }else{ 0 }

        $Depends = @()
        ArcGIS_Install PortalUpgrade
        { 
            Name = "Portal"
            Version = $Version
            Path = $InstallerPath
            Arguments = if($MajorVersion -gt 8){"/qn ACCEPTEULA=YES"}else{"/qn"}
            ServiceCredential = $ServiceAccount
            ServiceCredentialIsDomainAccount =  $IsServiceAccountDomainAccount
            ServiceCredentialIsMSA = $IsServiceAccountMSA
            EnableMSILogging = $EnableMSILogging
            Ensure = "Present"
            DependsOn = $Depends
        }
        $Depends += '[ArcGIS_Install]PortalUpgrade'

        if((($MajorVersion -eq 7 -and $MinorVersion -eq 1) -or ($MajorVersion -ge 8)) -and $WebStylesInstallerPath){
            ArcGIS_Install "WebStylesInstall"
            { 
                Name = "WebStyles"
                Version = $Version
                Path = $WebStylesInstallerPath
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
    }
}