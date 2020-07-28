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
        $IsServiceAccountMSA = $False
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.1.0"} 
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

        if((($MajorVersion -eq 7 -and $MinorVersion -eq 1) -or ($MajorVersion -ge 8)) -and $WebStylesInstallerPath){
            ArcGIS_Install "WebStylesInstall"
            { 
                Name = "WebStyles"
                Version = $Version
                Path = $WebStylesInstallerPath
                Arguments = "/qb"
                Ensure = "Present"
                DependsOn = $Depends
            }
            $Depends += '[ArcGIS_Install]WebStylesInstall'
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
    }
}