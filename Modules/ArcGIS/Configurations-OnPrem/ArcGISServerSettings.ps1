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

        [Parameter(Mandatory=$false)]
        [System.String]
        $InternalLoadBalancer
    )


    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 3.3.2
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
                ServerHostName          = Get-FQDN $PrimaryServerMachine
                SiteAdministrator       = $ServerPrimarySiteAdminCredential
                ExternalDNSName         = $ExternalDNSHostName
                ServerContext           = $ServerContext
                ServerEndPoint          = if($InternalLoadBalancer){ $InternalLoadBalancer }else{ if($ExternalDNSHostName){ $ExternalDNSHostName }else{ $null } }
                ServerEndPointPort      = if($InternalLoadBalancer){ 6443 }else{ 443 }
                ServerEndPointContext   = if($InternalLoadBalancer){ 'arcgis' }else{ $ServerContext }
            }
        }
    }
}
