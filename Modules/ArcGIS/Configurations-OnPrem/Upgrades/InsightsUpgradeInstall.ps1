Configuration InsightsUpgradeInstall{
    param(
        [System.String]
        $Version,

        [System.String]
        $InstallerPath,

        [System.String]
        $PatchesDir,

        [System.Array]
        $PatchInstallOrder = $null,

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
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 3.3.2
    Import-DscResource -Name ArcGIS_Install
    Import-DscResource -Name ArcGIS_InstallPatch
    
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

        if ($PatchesDir) {
            ArcGIS_InstallPatch ServerInstallPatch
            {
                Name = "Insights"
                Version = $Version
                PatchesDir = $PatchesDir
                PatchInstallOrder = $PatchInstallOrder
                Ensure = "Present"
                DependsOn = @("[ArcGIS_Install]InsightsInstall")
            }
        }
    }
}
