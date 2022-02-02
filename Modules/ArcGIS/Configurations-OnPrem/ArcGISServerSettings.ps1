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
        $InternalLoadBalancer,
        
        [Parameter(Mandatory=$false)]
        [System.Int32]
        $InternalLoadBalancerPort,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $IsWorkflowManagerDeployment = $False
    )


    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.3.0"}
    Import-DscResource -Name ArcGIS_ServerSettings

    Node $AllNodes.NodeName
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        $Depends = @()
        if($Node.NodeName -ieq $PrimaryServerMachine){
            ArcGIS_ServerSettings ServerSettings
            {
                ServerHostName          = Get-FQDN $PrimaryServerMachine
                SiteAdministrator       = $ServerPrimarySiteAdminCredential
                ExternalDNSName         = $ExternalDNSHostName
                ServerContext           = $ServerContext
                ServerEndPoint          = if($InternalLoadBalancer){ $InternalLoadBalancer }else{ if($ExternalDNSHostName){ $ExternalDNSHostName }else{ $null } }
                ServerEndPointPort      = if($InternalLoadBalancerPort) { $InternalLoadBalancerPort }elseif(!$ExternalDNSHostName) { 6443 }else { 443 }
                ServerEndPointContext   = if($InternalLoadBalancer){ 'arcgis' }else{ $ServerContext }
                IsWorkflowManagerDeployment = if($IsWorkflowManagerDeployment){ $True }else{ $False }
            }
        }
    }
}