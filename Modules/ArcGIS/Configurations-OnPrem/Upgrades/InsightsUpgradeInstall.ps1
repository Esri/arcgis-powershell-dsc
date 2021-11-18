Configuration InsightsUpgradeInstall{
    param(
        [System.String]
        $Version,

        [System.String]
        $InstallerPath,

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
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.3.0"}
    Import-DscResource -Name ArcGIS_Install
    
    Node $AllNodes.NodeName
    {   
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        ArcGIS_Install InsightsInstall
        {
            Name = "Insights"
            Version = $Version
            Path = $InstallerPath
            Arguments = "/qn ACCEPTEULA=YES"
            ServiceCredential = $ServiceAccount
            ServiceCredentialIsDomainAccount =  $IsServiceAccountDomainAccount
            ServiceCredentialIsMSA = $IsServiceAccountMSA
            EnableMSILogging = $EnableMSILogging
            Ensure = "Present"
        }
    }
}