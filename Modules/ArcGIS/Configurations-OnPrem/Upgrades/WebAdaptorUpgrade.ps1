Configuration WebAdaptorUpgrade{
    param(
        [ValidateSet("Server","Portal")]
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

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $InstallerIsSelfExtracting = $True,

        [System.Boolean]
        $IsJavaWebAdaptor = $False,

        [System.String]
        $JavaInstallDir,

        [System.String]
        $JavaWebServerWebAppDirectory,

        [System.String]
        $DotnetHostingBundlePath,

        [System.String]
        $WebDeployPath,

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

        [System.Boolean]
        $SkipPatchInstalls = $False,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $EnableMSILogging = $false
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.4.0 -Name ArcGIS_Install, ArcGIS_InstallPatch, ArcGIS_WebAdaptor

    Node $AllNodes.NodeName {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }

        $VersionArray = $Version.Split('.')
        $Depends = $null
        if($IsJavaWebAdaptor){
            $LastWAName = ""
            foreach($WA in $Node.WebAdaptorConfig){
                if($WA.Role -ieq $WebAdaptorRole){
                    $LastWAName = "UnregisterWebAdaptor$($Node.NodeName)-$($WA.Context)"

                    ArcGIS_WebAdaptor $LastWAName
                    {
                        Version             = $OldVersion
                        Ensure              = "Absent"
                        Component           = $Component
                        HostName            = if($Node.SSLCertificate){ $Node.SSLCertificate.CName }else{ (Get-FQDN $Node.NodeName) } 
                        ComponentHostName   = (Get-FQDN $ComponentHostName)
                        Context             = $WA.Context
                        OverwriteFlag       = $False
                        SiteAdministrator   = $SiteAdministratorCredential
                        AdminAccessEnabled  = $WA.AdminAccessEnabled
                        IsJavaWebAdaptor    = $IsJavaWebAdaptor
                        JavaWebServerWebAppDirectory = if($IsJavaWebAdaptor){ $JavaWebServerWebAppDirectory }else{ $null }
                    }
                }
            }
            
            # Uninstall of old Java Web Adaptor handled separately
            
            # Install Java Web Adaptor
            $WAArguments = "/qn ACCEPTEULA=YES"
            if($JavaInstallDir){
                $WAArguments += " INSTALLDIR=`"$($JavaInstallDir)`""
            }

            ArcGIS_Install WebAdaptorJavaInstall
            { 
                Name = "WebAdaptorJava"
                Version = $Version
                Path = $InstallerPath
                Extract = $InstallerIsSelfExtracting
                Arguments = $WAArguments
                EnableMSILogging = $EnableMSILogging
                Ensure = "Present"
                DependsOn  = "[ArcGIS_WebAdaptor]$LastWAName"
            }
            $Depends = @("[ArcGIS_Install]WebAdaptorJavaInstall")

            if ($PatchesDir -and -not($SkipPatchInstalls)) { 
                #TODO - this is not working (Even if the patch is installed, we will have to update the war file manually to get the patch applied)
                ArcGIS_InstallPatch WebAdaptorJavaInstallPatch
                {
                    Name = "WebAdaptorJava"
                    Version = $Version
                    DownloadPatches = $DownloadPatches
                    PatchesDir = $PatchesDir
                    PatchInstallOrder = $PatchInstallOrder
                    Ensure = "Present"
                    DependsOn = $Depends
                }
                $Depends = @("[ArcGIS_InstallPatch]WebAdaptorJavaInstallPatch")
            }
        }else{
            
            foreach($WA in $Node.WebAdaptorConfig){
                if($WA.Role -ieq $WebAdaptorRole){
                    $WAName = "WebAdaptorIIS-$($WA.Role)-$($WA.Context)"
                    ArcGIS_Install "$($WAName)Uninstall"
                    { 
                        Name = $WAName
                        Version = $OldVersion
                        WebAdaptorContext = $WA.Context
                        Arguments = "WEBSITE_ID=$($WA.WebSiteId)"
                        Ensure = "Absent"
                        DependsOn = if($Depends){$Depends}else{$null}
                    }

                    $VersionArray = $Version.Split(".")
                    $WAArguments = "/qn ACCEPTEULA=YES VDIRNAME=$($WA.Context) WEBSITE_ID=$($WA.WebSiteId)"
                    if($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 8)){
                        $WAArguments += " CONFIGUREIIS=TRUE"
                    }
                    
                    $WAName = "WebAdaptorIIS-$($WA.Role)-$($WA.Context)"
                    ArcGIS_Install "$($WAName)Install"
                    {
                        Name = $WAName
                        Version = $Version
                        Path = $InstallerPath
                        Extract = $InstallerIsSelfExtracting
                        Arguments = $WAArguments
                        WebAdaptorContext = $WA.Context
                        WebAdaptorDotnetHostingBundlePath = $DotnetHostingBundlePath
                        WebAdaptorWebDeployPath = $WebDeployPath
                        EnableMSILogging = $EnableMSILogging
                        Ensure = "Present"
                        DependsOn = @("[ArcGIS_Install]$($WAName)Uninstall")
                    }
                    $Depends = @("[ArcGIS_Install]$($WAName)Install")
                }
            }
            if ($PatchesDir -and -not($SkipPatchInstalls)){
                ArcGIS_InstallPatch "WAIISInstallPatch"
                {
                    Name = "WebAdaptorIIS"
                    Version = $Version
                    DownloadPatches = $DownloadPatches
                    PatchesDir = $PatchesDir
                    PatchInstallOrder = $PatchInstallOrder
                    Ensure = "Present"
                    DependsOn = $Depends
                }
                $Depends = @("[ArcGIS_InstallPatch]WAIISInstallPatch")
            }
        }

        foreach($WA in $Node.WebAdaptorConfig){
            if($WA.Role -ieq $WebAdaptorRole){
                ArcGIS_WebAdaptor "ConfigureWebAdaptor$($Node.NodeName)-$($WA.Context)"
                {
                    Version             = $Version
                    Ensure              = "Present"
                    Component           = $Component
                    HostName            = if($Node.SSLCertificate){ $Node.SSLCertificate.CName }else{ (Get-FQDN $Node.NodeName) } 
                    ComponentHostName   = (Get-FQDN $ComponentHostName)
                    Context             = $WA.Context
                    OverwriteFlag       = $False
                    SiteAdministrator   = $SiteAdministratorCredential
                    AdminAccessEnabled  = $WA.AdminAccessEnabled
                    IsJavaWebAdaptor    = $IsJavaWebAdaptor
                    JavaWebServerWebAppDirectory = if($IsJavaWebAdaptor){ $JavaWebServerWebAppDirectory }else{ $null }
                    DependsOn           = $Depends
                }
                $Depends += @("[ArcGIS_WebAdaptor]ConfigureWebAdaptor$($Node.NodeName)-$($WA.Context)")
            }
        }
    }
}