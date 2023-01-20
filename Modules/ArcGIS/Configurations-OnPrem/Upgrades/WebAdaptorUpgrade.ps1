Configuration WebAdaptorUpgrade{
    param(
        [ValidateSet("ServerWebAdaptor","PortalWebAdaptor")]
        [System.String]
        $WebAdaptorRole,

        [System.String]
        $Component,

        [System.String]
        $Version,

        [System.String]
        $OldVersion,
        
        [System.String]
        $InstallerPath,

        [parameter(Mandatory = $false)]
        [System.String]
        $PatchesDir,

        [parameter(Mandatory = $false)]
        [System.Array]
        $PatchInstallOrder,
        
        [System.String]
        $ComponentHostName,

        [System.Management.Automation.PSCredential]
        $SiteAdministratorCredential,
        
        [System.Int32]
		$WebSiteId = 1,

        [System.Boolean]
        $DownloadPatches = $False,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $EnableMSILogging = $false
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.0.2 
    Import-DscResource -Name ArcGIS_Install
    Import-DscResource -Name ArcGIS_WebAdaptor

    Node $AllNodes.NodeName {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }

        $VersionArray = $Version.Split('.')

        if($WebAdaptorRole -ieq "PortalWebAdaptor"){
            $AdminAccessEnabled = $False
            $Context = $Node.PortalContext
        }
        if($WebAdaptorRole -ieq "ServerWebAdaptor"){
            $AdminAccessEnabled = if($Node.AdminAccessEnabled) { $true } else { $false }
            $Context = $Node.ServerContext
        }

        $Depends = @()

        ArcGIS_Install WebAdaptorUninstall
        { 
            Name = $WebAdaptorRole
            Version = $OldVersion
            WebAdaptorContext = $Context
            Arguments = "WEBSITE_ID=$($WebSiteId)"
            Ensure = "Absent"
        }
        $Depends += '[ArcGIS_Install]WebAdaptorUninstall'

        $WAArguments = "/qn VDIRNAME=$($Context) WEBSITE_ID=$($WebSiteId)"
        if($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 5)){
            $WAArguments += " CONFIGUREIIS=TRUE"
        }

        if($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 8)){
            $WAArguments += " ACCEPTEULA=YES"
        }

        ArcGIS_Install WebAdaptorInstall
        { 
            Name = $WebAdaptorRole
            Version = $Version
            Path = $InstallerPath
            WebAdaptorContext = $Context
            Arguments = $WAArguments
            EnableMSILogging = $EnableMSILogging
            Ensure = "Present"
            DependsOn = $Depends
        }
        $Depends += '[ArcGIS_Install]WebAdaptorInstall'
        
        if($PatchesDir){
            ArcGIS_InstallPatch WebAdaptorInstallPatch
            {
                Name = "WebAdaptor"
                Version = $Version
                DownloadPatches = $DownloadPatches
                PatchesDir = $PatchesDir
                PatchInstallOrder = $PatchInstallOrder
                Ensure = "Present"
                DependsOn = $Depends
            }
            $Depends += '[ArcGIS_InstallPatch]WebAdaptorInstallPatch'
        }

        ArcGIS_WebAdaptor "Configure$($Component)-$($Node.NodeName)"
        {
            Ensure = "Present"
            Component = $Component
            HostName =  if($Node.SSLCertificate){ $Node.SSLCertificate.CName }else{ (Get-FQDN $Node.NodeName) }
            ComponentHostName = (Get-FQDN $ComponentHostName)
            Context = $Context
            OverwriteFlag = $False
            SiteAdministrator = $SiteAdministratorCredential
            AdminAccessEnabled  = $AdminAccessEnabled
            DependsOn = $Depends
        }
    }
}
