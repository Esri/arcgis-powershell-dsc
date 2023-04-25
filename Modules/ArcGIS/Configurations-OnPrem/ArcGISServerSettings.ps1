Configuration ArcGISServerSettings{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServerPrimarySiteAdminCredential,
        
        [Parameter(Mandatory=$false)]
        [System.String]
        $PrimaryServerMachine,

        [Parameter(Mandatory=$false)]
        [System.String]
        $ExternalDNSHostName,

        [Parameter(Mandatory=$false)]
        [System.String]
        $ServerContext,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $DisableServiceDirectory = $False,

        [Parameter(Mandatory=$false)]
        [System.String]
        $SharedKey = $null
    )


    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.1.0 
    Import-DscResource -Name ArcGIS_ServerSettings

    Node $AllNodes.NodeName
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        if($Node.NodeName -ieq $PrimaryServerMachine){
            ArcGIS_ServerSettings ServerSettings
            {
                ServerHostName   = $PrimaryServerMachine
                SiteAdministrator= $ServerPrimarySiteAdminCredential
                ExternalDNSName  = $ExternalDNSHostName
                ServerContext    = $ServerContext
                DisableServiceDirectory = if($DisableServiceDirectory) { $true } else { $false }
                SharedKey = $SharedKey
            }
        }
    }
}
