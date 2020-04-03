Configuration ArcGISPortalSettings{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $PortalAdministratorCredential,

        [Parameter(Mandatory=$false)]
        [System.String]
        $PrimaryPortalMachine,
        
        [Parameter(Mandatory=$false)]
        [System.String]
        $ExternalDNSHostName,

        [Parameter(Mandatory=$false)]
        [System.String]
        $PortalContext,

        [Parameter(Mandatory=$false)]
        [System.String]
        $InternalLoadBalancer
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.0.1"}
    Import-DscResource -Name ArcGIS_PortalSettings
    
    Node $AllNodes.NodeName
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        if($Node.NodeName -ieq $PrimaryPortalMachine){
            ArcGIS_PortalSettings PortalSettings
            {
                PortalHostName          = Get-FQDN $PrimaryPortalMachine
                ExternalDNSName         = $ExternalDNSHostName
                PortalContext           = $PortalContext
                PortalEndPoint          = if($InternalLoadBalancer){ $InternalLoadBalancer }else{ if($ExternalDNSHostName){ $ExternalDNSHostName }else{ Get-FQDN $PrimaryPortalMachine }}
                PortalEndPointContext   = if($InternalLoadBalancer -or !$ExternalDNSHostName){ 'arcgis' }else{ $PortalContext }
                PortalEndPointPort      = if($InternalLoadBalancer -or !$ExternalDNSHostName){ 7443 }else{ 443 }
                PortalAdministrator     = $PortalAdministratorCredential
            }
        }
    }
}