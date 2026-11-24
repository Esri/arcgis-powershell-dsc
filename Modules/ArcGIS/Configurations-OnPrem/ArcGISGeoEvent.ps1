Configuration ArcGISGeoEvent
{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServiceCredential,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ForceServiceCredentialUpdate = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsMSA = $false,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServerPrimarySiteAdminCredential,

        [Parameter(Mandatory=$true)]
        [System.String]
        $Version,

        [Parameter(Mandatory=$false)]
        [System.String]
        $WebSocketContextUrl
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 5.2.0 -Name ArcGIS_Service_Account, ArcGIS_xFirewall, ArcGIS_GeoEvent

    Node $AllNodes.NodeName
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }

        ArcGIS_Service_Account GeoEvent_RunAs_Account
        {
            Name = 'ArcGISGeoEvent'
            RunAsAccount = $ServiceCredential
            ForceRunAsAccountUpdate = $ForceServiceCredentialUpdate
            Ensure = 'Present'
            DataDir = "$env:ProgramData\Esri\GeoEvent"
            IsDomainAccount = $ServiceCredentialIsDomainAccount
            IsMSAAccount = $ServiceCredentialIsMSA
            SetStartupToAutomatic = $True
        }

        ArcGIS_xFirewall GeoEvent_FirewallRules
        {
            Name                  = 'ArcGISGeoEventFirewallRules'
            DisplayName           = 'ArcGIS GeoEvent'
            DisplayGroup          = 'ArcGIS GeoEvent Extension'
            Ensure                = 'Present'
            Access                = 'Allow'
            State                 = 'Enabled'
            Profile               = ('Domain','Private','Public')
            LocalPort             = ('6143','6180','5565','5575')
            Protocol              = 'TCP'
            DependsOn             = '[ArcGIS_Service_Account]GeoEvent_RunAs_Account'
        }

        ArcGIS_GeoEvent ArcGIS_GeoEvent
        {
            ServerHostName      = $Node.NodeName
            Name                = 'ArcGIS GeoEvent'
            Ensure              = 'Present'
            SiteAdministrator   = $ServerPrimarySiteAdminCredential
            WebSocketContextUrl = if([string]::IsNullOrEmpty($WebSocketContextUrl)){ "wss://$(Get-FQDN $Node.NodeName):6143/arcgis" }else{ $WebSocketContextUrl }
            Version             = $Version
            DependsOn           = '[ArcGIS_xFirewall]GeoEvent_FirewallRules'
        }
    }
}