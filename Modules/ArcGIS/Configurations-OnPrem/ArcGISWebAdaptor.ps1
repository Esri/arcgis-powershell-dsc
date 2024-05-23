Configuration ArcGISWebAdaptor
{
    param(
        [Parameter(Mandatory=$True)]
        [System.String]
        $Version,

        [System.Management.Automation.PSCredential]
        $ServerPrimarySiteAdminCredential,

        [System.Management.Automation.PSCredential]
        $PortalAdministratorCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $PrimaryServerMachine,

        [Parameter(Mandatory=$False)]
        [System.String]
        $PrimaryPortalMachine,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ServerRole,

        [System.Boolean]
		$IsJavaWebAdaptor = $False,

        [System.String]
        $JavaWebServerWebAppDirectory,

        [Parameter(Mandatory=$False)]
        [System.String]
        $OverrideHTTPSBinding = $True
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.3.0 
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_IIS_TLS
    Import-DscResource -Name ArcGIS_WebAdaptor

    Node $AllNodes.NodeName
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        $MachineFQDN = Get-FQDN $Node.NodeName

        $Depends = @()

        ArcGIS_xFirewall "WebAdaptorFirewallRules$($Node.NodeName)"
        {
            Name                  = "WebAdaptor-ARR" 
            DisplayName           = "WebAdaptor-ARR" 
            DisplayGroup          = "WebAdaptor-ARR" 
            Ensure                = 'Present'  
            Access                = "Allow" 
            State                 = "Enabled" 
            Profile               = "Public"
            LocalPort             = ("80", "443")                         
            Protocol              = "TCP" 
        }
        $Depends += "[ArcGIS_xFirewall]WebAdaptorFirewallRules$($Node.NodeName)"

        if($IsJavaWebAdaptor){
            Write-Verbose "Java Web Server is assumed to be already configured!"
        }else{
            Service "StartW3SVC$($Node.NodeName)"
            {
                Name = 'W3SVC'
                StartupType = 'Automatic'
                Ensure = 'Present'
                State = 'Running'
                DependsOn = $Depends
            }
            $Depends += "[Service]StartW3SVC$($Node.NodeName)"

            if($OverrideHTTPSBinding){
                $UniqueWebsiteIds = $Node.WebAdaptorConfig.WebSiteId | Select-Object -Unique 
                foreach($WebSiteId in $UniqueWebsiteIds){
                    if($Node.SSLCertificate){
                        ArcGIS_IIS_TLS "WebAdaptorCertificateInstall$($Node.NodeName)$($WebSiteId)"
                        {
                            WebSiteId               = $WebSiteId
                            ExternalDNSName         = $Node.SSLCertificate.CName
                            Ensure                  = 'Present'
                            CertificateFileLocation = $Node.SSLCertificate.Path
                            CertificatePassword     = $Node.SSLCertificate.Password
                            DependsOn               = $Depends
                        }
                    }else{
                        ArcGIS_IIS_TLS "WebAdaptorCertificateInstall$($Node.NodeName)$($WebSiteId)"
                        {
                            WebSiteId       = $WebSiteId
                            ExternalDNSName = $MachineFQDN 
                            Ensure          = 'Present'
                            DependsOn       = $Depends
                        }
                    }
                    $Depends += "[ArcGIS_IIS_TLS]WebAdaptorCertificateInstall$($Node.NodeName)$($WebSiteId)"
                }
            }
        }

        foreach($WA in $Node.WebAdaptorConfig){
            if($WA.Role -ieq "Server" -and $PrimaryServerMachine){
                ArcGIS_WebAdaptor "ConfigureServerWebAdaptor$($Node.NodeName)-$($WA.Context)"
                {
                    Version             = $Version
                    Ensure              = "Present"
                    Component           = if($ServerRole -ieq "NotebookServer"){ 'NotebookServer' }elseif($ServerRole -ieq "MissionServer"){ 'MissionServer' }elseif($ServerRole -ieq "VideoServer"){ 'VideoServer' }else{ 'Server' }
                    HostName            = if($WA.HostName){ $WA.HostName }elseif($Node.SSLCertificate){ $Node.SSLCertificate.CName }else{ $MachineFQDN } 
                    ComponentHostName   = (Get-FQDN $PrimaryServerMachine)
                    Context             = $WA.Context
                    OverwriteFlag       = $False
                    SiteAdministrator   = $ServerPrimarySiteAdminCredential
                    AdminAccessEnabled  = if(@("MissionServer", "NotebookServer", "VideoServer") -iContains  $ServerRole){ $true }else{ $WA.AdminAccessEnabled }
                    IsJavaWebAdaptor    = $IsJavaWebAdaptor
                    JavaWebServerWebAppDirectory = if($IsJavaWebAdaptor){ $JavaWebServerWebAppDirectory }else{ $null }
                    DependsOn           = $Depends
                }
                $Depends += "[ArcGIS_WebAdaptor]ConfigureServerWebAdaptor$($Node.NodeName)-$($WA.Context)"
            }

            if($WA.Role -ieq "Portal" -and $PrimaryPortalMachine){
                ArcGIS_WebAdaptor "ConfigurePortalWebAdaptor$($Node.NodeName)-$($WA.Context)"
                {
                    Version             = $Version
                    Ensure              = "Present"
                    Component           = 'Portal'
                    HostName            = if($WA.HostName){ $WA.HostName }elseif($Node.SSLCertificate){ $Node.SSLCertificate.CName }else{ $MachineFQDN }  
                    ComponentHostName   = (Get-FQDN $PrimaryPortalMachine)
                    Context             = $WA.Context
                    OverwriteFlag       = $False
                    SiteAdministrator   = $PortalAdministratorCredential
                    IsJavaWebAdaptor    = $IsJavaWebAdaptor
                    JavaWebServerWebAppDirectory = if($IsJavaWebAdaptor){ $JavaWebServerWebAppDirectory }else{ $null }
                    DependsOn           = $Depends
                }

                $Depends += "[ArcGIS_WebAdaptor]ConfigurePortalWebAdaptor$($Node.NodeName)-$($WA.Context)"
            }
        }
    }
}
