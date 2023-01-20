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
        $InternalLoadBalancer,

        [Parameter(Mandatory=$false)]
        [System.Int32]
        $InternalLoadBalancerPort,

        [System.Boolean]
        $EnableEmailSettings = $False,

        [System.String]
        $EmailSettingsSMTPServerAddress,

        [System.String]
        $EmailSettingsFrom,

        [System.String]
        $EmailSettingsLabel,

        [System.Boolean]
        $EmailSettingsAuthenticationRequired = $False,

        [System.Management.Automation.PSCredential]
        $EmailSettingsCredential,

        [System.Int32]
        $EmailSettingsSMTPPort = 25,

        [ValidateSet("SSL", "TLS", "NONE")]
        [System.String]
        $EmailSettingsEncryptionMethod = "NONE",

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $ADServiceCredential,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $EnableAutomaticAccountCreation,

        [Parameter(Mandatory=$False)]
        [System.String]
        $DefaultRoleForUser,

        [Parameter(Mandatory=$False)]
        [System.String]
        $DefaultUserLicenseTypeIdForUser,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $DisableServiceDirectory,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $DisableAnonymousAccess
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.0.2
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
            $PortalEndpointPort = 443
            if($InternalLoadBalancer -or !$ExternalDNSHostName){
                $PortalEndpointPort = 7443
                if($InternalLoadBalancer){
                    if($InternalLoadBalancerPort){
                        $PortalEndpointPort = $InternalLoadBalancerPort
                    }
                }
            }

            ArcGIS_PortalSettings PortalSettings
            {
                PortalHostName          = $PrimaryPortalMachine
                ExternalDNSName         = $ExternalDNSHostName
                PortalContext           = $PortalContext
                PortalEndPoint          = if($InternalLoadBalancer){ $InternalLoadBalancer }else{ if($ExternalDNSHostName){ $ExternalDNSHostName }else{ Get-FQDN $PrimaryPortalMachine }}
                PortalEndPointContext   = if($InternalLoadBalancer -or !$ExternalDNSHostName){ 'arcgis' }else{ $PortalContext }
                PortalEndPointPort      = $PortalEndpointPort
                PortalAdministrator     = $PortalAdministratorCredential
                ADServiceUser           = $ADServiceCredential
                EnableAutomaticAccountCreation = if($EnableAutomaticAccountCreation) { $true } else { $false }
                DefaultRoleForUser      = $DefaultRoleForUser
                DefaultUserLicenseTypeIdForUser = $DefaultUserLicenseTypeIdForUser
                DisableServiceDirectory = if($DisableServiceDirectory) { $true } else { $false }
                DisableAnonymousAccess  = if($DisableAnonymousAccess) { $true } else { $false }
                EnableEmailSettings     = if($EnableEmailSettings){ $True }else{ $False }
                EmailSettingsSMTPServerAddress = if($EnableEmailSettings){ $EmailSettingsSMTPServerAddress }else{ $null }
                EmailSettingsFrom = if($EnableEmailSettings){ $EmailSettingsFrom }else{ $null }
                EmailSettingsLabel = if($EnableEmailSettings){ $EmailSettingsLabel }else{ $null }
                EmailSettingsAuthenticationRequired = if($EnableEmailSettings){ $EmailSettingsAuthenticationRequired }else{ $false }
                EmailSettingsCredential =if($EnableEmailSettings){ $EmailSettingsCredential }else{ $null }
                EmailSettingsSMTPPort = if($EnableEmailSettings){ $EmailSettingsSMTPPort }else{ $null }
                EmailSettingsEncryptionMethod = if($EnableEmailSettings){ $EmailSettingsEncryptionMethod }else{ "NONE" }
            }
        }
    }
}
