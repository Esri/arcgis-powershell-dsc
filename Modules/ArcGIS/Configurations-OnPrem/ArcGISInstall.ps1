Configuration ArcGISInstall{
    param(
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $ServiceCredential,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsMSA = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $SkipPatchInstalls = $False,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $EnableMSILogging = $false
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 5.1.2 -Name ArcGIS_Install, ArcGIS_InstallMsiPackage, ArcGIS_InstallPatch, ArcGIS_xFirewall, ArcGIS_Tomcat

    Node $AllNodes.NodeName {

        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }

        $HasValidServiceCredential = ($ServiceCredential -and ($ServiceCredential.GetNetworkCredential().Password -ine 'Placeholder'))
        if($HasValidServiceCredential) 
        {
            if(-not($ServiceCredentialIsDomainAccount -or $ServiceCredentialIsMSA)){
                User ArcGIS_RunAsAccount
                {
                    UserName       = $ServiceCredential.UserName
                    Password       = $ServiceCredential
                    FullName       = 'ArcGIS Service Account'
                    Ensure         = 'Present'
                    PasswordChangeRequired = $false
                    PasswordNeverExpires = $true
                }
            }
        }


        $NodeRoleArray = @()
        if($Node.Role -icontains "Server")
        {
            $NodeRoleArray += "Server"
        }
        if($Node.Role -icontains "Portal")
        {
            $NodeRoleArray += "Portal"
        }
        if($Node.Role -icontains "DataStore")
        {
            $NodeRoleArray += "DataStore"
        }
        if($Node.Role -icontains "WebAdaptor")
        {
            $NodeRoleArray += "WebAdaptor"
        }
        if($Node.Role -icontains "Pro")
        {
            $NodeRoleArray += "Pro"
        }
        if($Node.Role -icontains "LicenseManager")
        {
            $NodeRoleArray += "LicenseManager"
        }
        if($Node.Role -icontains "SQLServerClient"){
            $NodeRoleArray += "SQLServerClient"
        }

        for ( $i = 0; $i -lt $NodeRoleArray.Count; $i++ )
        {
            $NodeRole = $NodeRoleArray[$i]
            Switch($NodeRole)
            {
                'Server'
                {
                    $ServerTypeName = if(@("MissionServer", "NotebookServer", "VideoServer","DataPipelinesServer") -iContains $ConfigurationData.ConfigData.ServerRole){ $ConfigurationData.ConfigData.ServerRole }else{ "Server" }

                    $ServerFeatureSet = @()
                    $ServerInstallArguments = "/qn ACCEPTEULA=YES InstallDir=`"$($ConfigurationData.ConfigData.Server.Installer.InstallDir)`""
                    if($ServerTypeName -ieq "Server"){
                        if([version]($ConfigurationData.ConfigData.Version) -ge "11.0"){
                            $EnableDontet = $True
                            if($ConfigurationData.ConfigData.Server.Installer.ContainsKey("EnableDotnetSupport")){
                                $EnableDontet = $ConfigurationData.ConfigData.Server.Installer.EnableDotnetSupport
                            }
                            if(-not($EnableDontet)){
                                $ServerFeatureSet += @("GIS_Server")
                            }
                        } elseif ($ConfigurationData.ConfigData.Version -ieq "10.9.1"){ 
                            $EnableArcMapRuntime = $True
                            if($ConfigurationData.ConfigData.Server.Installer.ContainsKey("EnableArcMapRuntime")){
                                $EnableArcMapRuntime = $ConfigurationData.ConfigData.Server.Installer.EnableArcMapRuntime
                            }
                            $EnableDontet = $True
                            if($ConfigurationData.ConfigData.Server.Installer.ContainsKey("EnableDotnetSupport")){
                                $EnableDontet = $ConfigurationData.ConfigData.Server.Installer.EnableDotnetSupport
                            }

                            if($EnableArcMapRuntime -and $EnableDontet){
                                $ServerInstallArguments += " INSTALLDIR1=`"$($ConfigurationData.ConfigData.Server.Installer.InstallDirPython)`""
                            }elseif($EnableArcMapRuntime -and -not($EnableDontet)){
                                $ServerFeatureSet += @("ArcMap")
                            }elseif($EnableDontet -and -not($EnableArcMapRuntime)){
                                $ServerFeatureSet += @("DotNetSupport")
                            }else{
                                $ServerFeatureSet += @("GIS_Server")
                            }
                        } else {
                            $ServerInstallArguments = "/qn ACCEPTEULA=YES InstallDir=`"$($ConfigurationData.ConfigData.Server.Installer.InstallDir)`" INSTALLDIR1=`"$($ConfigurationData.ConfigData.Server.Installer.InstallDirPython)`""
                        }                        
                        if($ServerFeatureSet.Count -eq 0){
                            $ServerFeatureSet = $null
                        }
                    }                    

                    ArcGIS_Install ServerInstall
                    {
                        Name = $ServerTypeName
                        Version = $ConfigurationData.ConfigData.Version
                        Path = $ConfigurationData.ConfigData.Server.Installer.Path
                        Extract = if($ConfigurationData.ConfigData.Server.Installer.ContainsKey("IsSelfExtracting")){ $ConfigurationData.ConfigData.Server.Installer.IsSelfExtracting }else{ $True }
                        DotnetDesktopRuntimePath = $ConfigurationData.ConfigData.Server.Installer.DotnetDesktopRuntimePath
                        Arguments = $ServerInstallArguments
                        FeatureSet = $ServerFeatureSet
                        ServiceCredential = $ServiceCredential
                        ServiceCredentialIsDomainAccount =  $ServiceCredentialIsDomainAccount
                        ServiceCredentialIsMSA = $ServiceCredentialIsMSA
                        EnableMSILogging = $EnableMSILogging
                        Ensure = "Present"
                    }
                    $ServerDependsOn = @('[ArcGIS_Install]ServerInstall')

                    if($ServerTypeName -ieq "Server" -and $ConfigurationData.ConfigData.Server.Extensions){
                        foreach ($Extension in $ConfigurationData.ConfigData.Server.Extensions.GetEnumerator())
                        {
                            $Arguments = "/qn"
                            $ServerExtensionFeatureSet = @()
                            if($Extension.Value.Features -and $Extension.Value.Features.Count -gt 0){
								if($Extension.Value.Features -icontains "ALL"){
									$ServerExtensionFeatureSet = @( "ALL" )
								}else{
									$Extension.Value.Features | Foreach-Object {
										$ServerExtensionFeatureSet += @( $_ )
									}
								}
                            }

                            ArcGIS_Install "Server$($Extension.Key)InstallExtension"
                            {
                                Name = "Server$($Extension.Key)"
                                Version = $ConfigurationData.ConfigData.Version
                                Path = $Extension.Value.Installer.Path
                                Extract = if($Extension.Value.Installer.ContainsKey("IsSelfExtracting")){ $Extension.Value.Installer.IsSelfExtracting }else{ $True }
                                Arguments = $Arguments
                                FeatureSet = $ServerExtensionFeatureSet
                                EnableMSILogging = $EnableMSILogging
                                Ensure = "Present"
                                DependsOn = $ServerDependsOn
                            }
                            $ServerDependsOn += "[ArcGIS_Install]Server$($Extension.Key)InstallExtension"
                        }
                    }

                    if ($ConfigurationData.ConfigData.Server.Installer.PatchesDir -and -not($SkipPatchInstalls)) {
                        ArcGIS_InstallPatch ServerInstallPatch
                        {
                            Name = $ServerTypeName
                            Version = $ConfigurationData.ConfigData.Version
                            DownloadPatches = if($ConfigurationData.ConfigData.DownloadPatches){ $ConfigurationData.ConfigData.DownloadPatches }else{ $False }
                            PatchesDir = $ConfigurationData.ConfigData.Server.Installer.PatchesDir
                            PatchInstallOrder = $ConfigurationData.ConfigData.Server.Installer.PatchInstallOrder
                            Ensure = "Present"
                            DependsOn = $ServerDependsOn
                        }
                        $ServerDependsOn += "[ArcGIS_InstallPatch]ServerInstallPatch"
                    }

                    if($ConfigurationData.ConfigData.ServerRole -ieq "NotebookServer" -and $ConfigurationData.ConfigData.Server.Installer.NotebookServerSamplesDataPath) 
                    {
                        if(@("10.9.1","11.0","11.1","11.2","11.3") -icontains $ConfigurationData.ConfigData.Version){
                            ArcGIS_Install "NotebookServerSamplesData$($Node.NodeName)"
                            { 
                                Name = "NotebookServerSamplesData"
                                Version = $ConfigurationData.ConfigData.Version
                                Path = $ConfigurationData.ConfigData.Server.Installer.NotebookServerSamplesDataPath
                                Extract = if($ConfigurationData.ConfigData.Server.Installer.ContainsKey("NotebookServerSamplesDataInstallerIsSelfExtracting")){ $ConfigurationData.ConfigData.Server.Installer.NotebookServerSamplesDataInstallerIsSelfExtracting }else{ $True }
                                Arguments = "/qn"
                                ServiceCredential = $ServiceCredential
                                ServiceCredentialIsDomainAccount =  $ServiceCredentialIsDomainAccount
                                ServiceCredentialIsMSA = $ServiceCredentialIsMSA
                                EnableMSILogging = $EnableMSILogging
                                Ensure = "Present"
                                DependsOn = $ServerDependsOn
                            }
                        }
                    }
                    
                    if($ConfigurationData.ConfigData.WorkflowManagerServer) 
                    {
                        ArcGIS_Install WorkflowManagerServerInstall
                        {
                            Name = "WorkflowManagerServer"
                            Version = $ConfigurationData.ConfigData.Version
                            Path = $ConfigurationData.ConfigData.WorkflowManagerServer.Installer.Path
                            Extract = if($ConfigurationData.ConfigData.WorkflowManagerServer.Installer.ContainsKey("IsSelfExtracting")){ $ConfigurationData.ConfigData.WorkflowManagerServer.Installer.IsSelfExtracting }else{ $True }
                            Arguments = "/qn"
                            ServiceCredential = $ServiceCredential
                            ServiceCredentialIsDomainAccount =  $ServiceCredentialIsDomainAccount
                            ServiceCredentialIsMSA = $ServiceCredentialIsMSA
                            EnableMSILogging = $EnableMSILogging
                            Ensure = "Present"
                            DependsOn = $ServerDependsOn
                        }

                        if ($ConfigurationData.ConfigData.WorkflowManagerServer.Installer.PatchesDir -and -not($SkipPatchInstalls)) {
                            ArcGIS_InstallPatch WorkflowManagerServerInstallPatch
                            {
                                Name = "WorkflowManagerServer"
                                Version = $ConfigurationData.ConfigData.Version
                                DownloadPatches = if($ConfigurationData.ConfigData.DownloadPatches){ $ConfigurationData.ConfigData.DownloadPatches }else{ $False }
                                PatchesDir = $ConfigurationData.ConfigData.WorkflowManagerServer.Installer.PatchesDir
                                PatchInstallOrder = $ConfigurationData.ConfigData.WorkflowManagerServer.Installer.PatchInstallOrder
                                Ensure = "Present"
                                DependsOn = @('[ArcGIS_Install]WorkflowManagerServerInstall')
                            }
                        }
                    }

                    if($ConfigurationData.ConfigData.GeoEventServer) 
                    { 
                        ArcGIS_Install GeoEventServerInstall
                        {
                            Name = "GeoEvent"
                            Version = $ConfigurationData.ConfigData.Version
                            Path = $ConfigurationData.ConfigData.GeoEventServer.Installer.Path
                            Extract = if($ConfigurationData.ConfigData.GeoEventServer.Installer.ContainsKey("IsSelfExtracting")){ $ConfigurationData.ConfigData.GeoEventServer.Installer.IsSelfExtracting }else{ $True }
                            Arguments = "/qn"
                            FeatureSet = if($ConfigurationData.ConfigData.GeoEventServer.EnableGeoeventSDK){ @("GeoEvent","SDK") }else{ $null }
                            ServiceCredential = $ServiceCredential
                            ServiceCredentialIsDomainAccount =  $ServiceCredentialIsDomainAccount
                            ServiceCredentialIsMSA = $ServiceCredentialIsMSA
                            EnableMSILogging = $EnableMSILogging
                            Ensure = "Present"
                            DependsOn = $ServerDependsOn
                        }

                        if ($ConfigurationData.ConfigData.GeoEventServer.Installer.PatchesDir -and -not($SkipPatchInstalls)) {
                            ArcGIS_InstallPatch GeoeventServerInstallPatch
                            {
                                Name = "GeoEvent"
                                Version = $ConfigurationData.ConfigData.Version
                                DownloadPatches = if($ConfigurationData.ConfigData.DownloadPatches){ $ConfigurationData.ConfigData.DownloadPatches }else{ $False }
                                PatchesDir = $ConfigurationData.ConfigData.GeoEventServer.Installer.PatchesDir
                                PatchInstallOrder = $ConfigurationData.ConfigData.GeoEventServer.Installer.PatchInstallOrder
                                Ensure = "Present"
                                DependsOn = @('[ArcGIS_Install]GeoEventServerInstall')
                            }
                        }
                    }

                    if($ConfigurationData.ConfigData.RealityServer) 
                    {
                        ArcGIS_Install RealityServerInstall
                        {
                            Name = "RealityServer"
                            Version = $ConfigurationData.ConfigData.Version
                            Path = $ConfigurationData.ConfigData.RealityServer.Installer.Path
                            Extract = if($ConfigurationData.ConfigData.RealityServer.Installer.ContainsKey("IsSelfExtracting")){ $ConfigurationData.ConfigData.RealityServer.Installer.IsSelfExtracting }else{ $True }
                            Arguments = "/qn"
                            ServiceCredential = $ServiceCredential
                            ServiceCredentialIsDomainAccount =  $ServiceCredentialIsDomainAccount
                            ServiceCredentialIsMSA = $ServiceCredentialIsMSA
                            EnableMSILogging = $EnableMSILogging
                            Ensure = "Present"
                            DependsOn = $ServerDependsOn
                        }

                        if ($ConfigurationData.ConfigData.RealityServer.Installer.PatchesDir -and -not($SkipPatchInstalls)) {
                            ArcGIS_InstallPatch RealityServerInstallPatch
                            {
                                Name = "RealityServer"
                                Version = $ConfigurationData.ConfigData.Version
                                DownloadPatches = if($ConfigurationData.ConfigData.DownloadPatches){ $ConfigurationData.ConfigData.DownloadPatches }else{ $False }
                                PatchesDir = $ConfigurationData.ConfigData.RealityServer.Installer.PatchesDir
                                PatchInstallOrder = $ConfigurationData.ConfigData.RealityServer.Installer.PatchInstallOrder
                                Ensure = "Present"
                                DependsOn = @('[ArcGIS_Install]RealityServerInstall')
                            }
                        }
                    }

                    if($ConfigurationData.ConfigData.GeoEnrichmentServer) {
                        ArcGIS_Install GeoEnrichmentServerInstall
                        {
                            Name = "GeoEnrichmentServer"
                            Version = $ConfigurationData.ConfigData.Version
                            Path = $ConfigurationData.ConfigData.GeoEnrichmentServer.Installer.Path
                            Extract = if($ConfigurationData.ConfigData.GeoEnrichmentServer.Installer.ContainsKey("IsSelfExtracting")){ $ConfigurationData.ConfigData.GeoEnrichmentServer.Installer.IsSelfExtracting }else{ $True }
                            DotnetDesktopRuntimePath = $ConfigurationData.ConfigData.GeoEnrichmentServer.Installer.DotnetDesktopRuntimePath
                            Arguments = "/qn"
                            FeatureSet = if($ConfigurationData.ConfigData.GeoEnrichmentServer.Installer.EnableSemanticSearch){ @("SemanticSearch") }else{ $null }
                            ServiceCredential = $ServiceCredential
                            ServiceCredentialIsDomainAccount =  $ServiceCredentialIsDomainAccount
                            ServiceCredentialIsMSA = $ServiceCredentialIsMSA
                            EnableMSILogging = $EnableMSILogging
                            Ensure = "Present"
                            DependsOn = $ServerDependsOn
                        }

                        if ($ConfigurationData.ConfigData.GeoEnrichmentServer.Installer.PatchesDir -and -not($SkipPatchInstalls)) {
                            ArcGIS_InstallPatch GeoEnrichmentServerInstallPatch
                            {
                                Name = "GeoEnrichmentServer"
                                Version = $ConfigurationData.ConfigData.Version
                                DownloadPatches = if($ConfigurationData.ConfigData.DownloadPatches){ $ConfigurationData.ConfigData.DownloadPatches }else{ $False }
                                PatchesDir = $ConfigurationData.ConfigData.GeoEnrichmentServer.Installer.PatchesDir
                                PatchInstallOrder = $ConfigurationData.ConfigData.GeoEnrichmentServer.Installer.PatchInstallOrder
                                Ensure = "Present"
                                DependsOn = @('[ArcGIS_Install]GeoEnrichmentServerInstall')
                            }
                        }
                    }
                }
                'Portal'
                {        
                    $PortalDependsOn = @()
                    ArcGIS_Install "PortalInstall$($Node.NodeName)"
                    { 
                        Name = "Portal"
                        Version = $ConfigurationData.ConfigData.Version
                        Path = $ConfigurationData.ConfigData.Portal.Installer.Path
                        Extract = if($ConfigurationData.ConfigData.Portal.Installer.ContainsKey("IsSelfExtracting")){ $ConfigurationData.ConfigData.Portal.Installer.IsSelfExtracting }else{ $True }
                        Arguments = "/qn ACCEPTEULA=YES INSTALLDIR=`"$($ConfigurationData.ConfigData.Portal.Installer.InstallDir)`" CONTENTDIR=`"$($ConfigurationData.ConfigData.Portal.Installer.ContentDir)`""
                        ServiceCredential = $ServiceCredential
                        ServiceCredentialIsDomainAccount =  $ServiceCredentialIsDomainAccount
                        ServiceCredentialIsMSA = $ServiceCredentialIsMSA
                        EnableMSILogging = $EnableMSILogging
                        Ensure = "Present"
                    }
                    $PortalDependsOn = @("[ArcGIS_Install]PortalInstall$($Node.NodeName)")

                    if($ConfigurationData.ConfigData.Portal.Installer.WebStylesPath){
                        ArcGIS_Install "WebStylesInstall$($Node.NodeName)"
                        { 
                            Name = "WebStyles"
                            Version = $ConfigurationData.ConfigData.Version
                            Path = $ConfigurationData.ConfigData.Portal.Installer.WebStylesPath
                            Extract = if($ConfigurationData.ConfigData.Portal.Installer.ContainsKey("WebStylesInstallerIsSelfExtracting")){ $ConfigurationData.ConfigData.Portal.Installer.WebStylesInstallerIsSelfExtracting }else{ $True }
                            Arguments = "/qn"
                            ServiceCredential = $ServiceCredential
                            ServiceCredentialIsDomainAccount =  $ServiceCredentialIsDomainAccount
                            ServiceCredentialIsMSA = $ServiceCredentialIsMSA
                            EnableMSILogging = $EnableMSILogging
                            Ensure = "Present"
                            DependsOn = $PortalDependsOn
                        }
                        $PortalDependsOn += "[ArcGIS_Install]WebStylesInstall$($Node.NodeName)"
                    }

                    if ($ConfigurationData.ConfigData.Portal.Installer.PatchesDir -and -not($SkipPatchInstalls)) {
                        ArcGIS_InstallPatch PortalInstallPatch
                        {
                            Name = "Portal"
                            Version = $ConfigurationData.ConfigData.Version
                            DownloadPatches = if($ConfigurationData.ConfigData.DownloadPatches){ $ConfigurationData.ConfigData.DownloadPatches }else{ $False }
                            PatchesDir = $ConfigurationData.ConfigData.Portal.Installer.PatchesDir
                            PatchInstallOrder = $ConfigurationData.ConfigData.Portal.Installer.PatchInstallOrder
                            Ensure = "Present"
                            DependsOn = $PortalDependsOn
                        }
                        $PortalDependsOn += "[ArcGIS_InstallPatch]PortalInstallPatch"
                    }
                }
                'DataStore'
                {
                    $Arguments = "/qn ACCEPTEULA=YES InstallDir=`"$($ConfigurationData.ConfigData.DataStore.Installer.InstallDir)`""

                    $DsFeatureSet = $Null
                    if([version]($ConfigurationData.ConfigData.Version) -ge "11.0"){
                        $DsFeatureSet = $Node.DataStoreTypes
                        if($ConfigurationData.ConfigData.DataStore.Installer.InstallAllFeatures){
                            $DsFeatureSet = @("ALL")
                        }
                    }

                    ArcGIS_Install DataStoreInstall
                    { 
                        Name = "DataStore"
                        Version = $ConfigurationData.ConfigData.Version
                        Path = $ConfigurationData.ConfigData.DataStore.Installer.Path
                        Extract = if($ConfigurationData.ConfigData.DataStore.Installer.ContainsKey("IsSelfExtracting")){ $ConfigurationData.ConfigData.DataStore.Installer.IsSelfExtracting }else{ $True }
                        Arguments = $Arguments
                        FeatureSet = $DsFeatureSet
                        ServiceCredential = $ServiceCredential
                        ServiceCredentialIsDomainAccount =  $ServiceCredentialIsDomainAccount
                        ServiceCredentialIsMSA = $ServiceCredentialIsMSA
                        EnableMSILogging = $EnableMSILogging
                        Ensure = "Present"
                    }

                    if ($ConfigurationData.ConfigData.DataStore.Installer.PatchesDir -and -not($SkipPatchInstalls)) {
                        ArcGIS_InstallPatch DataStoreInstallPatch
                        {
                            Name = "DataStore"
                            Version = $ConfigurationData.ConfigData.Version
                            DownloadPatches = if($ConfigurationData.ConfigData.DownloadPatches){ $ConfigurationData.ConfigData.DownloadPatches }else{ $False }
                            PatchesDir = $ConfigurationData.ConfigData.DataStore.Installer.PatchesDir
                            PatchInstallOrder = $ConfigurationData.ConfigData.DataStore.Installer.PatchInstallOrder
                            Ensure = "Present"
                            DependsOn = @("[ArcGIS_Install]DataStoreInstall")
                        }
                    } 
                }
                'WebAdaptor'
                {   
                    $IsJavaWebAdaptor =if($ConfigurationData.ConfigData.WebAdaptor.ContainsKey("IsJavaWebAdaptor")){ $ConfigurationData.ConfigData.WebAdaptor.IsJavaWebAdaptor }else{ $False }
                    if($IsJavaWebAdaptor){
                        $TomcatDependsOn = @()
                        $WAArguments = "/qn ACCEPTEULA=YES"
                        if($ConfigurationData.ConfigData.WebAdaptor.Installer.ContainsKey("InstallDir")){
                            $WAArguments += " INSTALLDIR=`"$($ConfigurationData.ConfigData.WebAdaptor.Installer.InstallDir)`""
                        }
                        if($ConfigurationData.ConfigData.WebAdaptor.Installer.ContainsKey("ApacheTomcat")){
                            $MachineFQDN = Get-FQDN $Node.NodeName
                            $ApacheTomcatConfig = $ConfigurationData.ConfigData.WebAdaptor.Installer.ApacheTomcat

                            # Check if old Tomcat exists, Uninstall old Web Adaptor first
                            if ($ApacheTomcatConfig.ContainsKey("OldVersion") -and $ApacheTomcatConfig.ContainsKey("OldServiceName")){
                                    Write-Verbose "Existing Tomcat configuration found: Version = $($ApacheTomcatConfig.OldVersion), Installed Service Name = $($ApacheTomcatConfig.OldServiceName)."
                                    ArcGIS_Tomcat ApacheTomcatUninstall {
                                        Version                = $ApacheTomcatConfig.OldVersion
                                        Ensure                 = "Absent"
                                        ServiceName            = $ApacheTomcatConfig.OldServiceName
                                    }
                                    $TomcatDependsOn += "[ArcGIS_Tomcat]ApacheTomcatUninstall"
                            }
                            
                            ArcGIS_Tomcat ApacheTomcatInstall
                            {
                                Version = $ApacheTomcatConfig.Version
                                Ensure = "Present"
                                ServiceName = $ApacheTomcatConfig.ServiceName
                                InstallerArchivePath = $ApacheTomcatConfig.Path
                                InstallDirectory = $ApacheTomcatConfig.InstallDir
                                SSLProtocols = $ApacheTomcatConfig.SSLProtocol
                                ExternalDNSName = if($Node.SSLCertificate){$Node.SSLCertificate.CName}else{ $MachineFQDN }
                                CertificateFileLocation = if($Node.SSLCertificate){$Node.SSLCertificate.Path}else{ $null}
                                CertificatePassword = if($Node.SSLCertificate){$Node.SSLCertificate.Password}else{ $null}
                                DependsOn = $TomcatDependsOn # Ensures old Tomcat is removed first
                            }
                            $TomcatDependsOn += "[ArcGIS_Tomcat]ApacheTomcatInstall"
                        }
                        ArcGIS_Install WebAdaptorJavaInstall
                        { 
                            Name = "WebAdaptorJava"
                            Version = $ConfigurationData.ConfigData.Version
                            Path = $ConfigurationData.ConfigData.WebAdaptor.Installer.Path
                            Extract = if($ConfigurationData.ConfigData.WebAdaptor.Installer.ContainsKey("IsSelfExtracting")){ $ConfigurationData.ConfigData.WebAdaptor.Installer.IsSelfExtracting }else{ $True }
                            Arguments = $WAArguments
                            EnableMSILogging = $EnableMSILogging
                            Ensure = "Present"
                            DependsOn = $TomcatDependsOn # Ensures Tomcat is installed first
                        }

                        if ($ConfigurationData.ConfigData.WebAdaptor.Installer.PatchesDir -and -not($SkipPatchInstalls)) { 
                            #TODO - this is not working (Even if the patch is installed, we will have to update the war file manually to get the patch applied)
                            ArcGIS_InstallPatch WebAdaptorJavaInstallPatch
                            {
                                Name = "WebAdaptorJava"
                                Version = $ConfigurationData.ConfigData.Version
                                DownloadPatches = if($ConfigurationData.ConfigData.DownloadPatches){ $ConfigurationData.ConfigData.DownloadPatches }else{ $False }
                                PatchesDir = $ConfigurationData.ConfigData.WebAdaptor.Installer.PatchesDir
                                PatchInstallOrder = $ConfigurationData.ConfigData.WebAdaptor.Installer.PatchInstallOrder
                                Ensure = "Present"
                                DependsOn = @("[ArcGIS_Install]WebAdaptorJavaInstall")
                            }
                        }
                    }
                    else
                    {
                        $WADependsOn = @()
                        foreach($WA in $Node.WebAdaptorConfig){
                            $Context = "arcgis"
                            if($WA.ContainsKey("Context")){
                                $Context = $WA.Context
                            }else{
                                if($WA.Role -ieq "Server"){
                                    $Context = $ConfigurationData.ConfigData.ServerContext
                                }elseif($WA.Role -ieq "Portal"){
                                    $Context = $ConfigurationData.ConfigData.PortalContext
                                }
                            }
                            $WebSiteId = 1
                            if($WA.ContainsKey("WebSiteId")){
                                $WebSiteId = $WA.WebSiteId
                            }else{
                                if($ConfigurationData.ConfigData.WebAdaptor.ContainsKey("WebSiteId")){
                                    $WebsiteId = $ConfigurationData.ConfigData.WebAdaptor.WebSiteId 
                                }
                            }
                            
                            $WAArguments = "/qn ACCEPTEULA=YES VDIRNAME=$($Context) WEBSITE_ID=$($WebSiteId) CONFIGUREIIS=TRUE"
                            
                            $WAName = "WebAdaptorIIS-$($WA.Role)-$($Context)"
                            ArcGIS_Install "$($WAName)Install"
                            {
                                Name = $WAName
                                Version = $ConfigurationData.ConfigData.Version
                                Path = $ConfigurationData.ConfigData.WebAdaptor.Installer.Path
                                Extract = if($ConfigurationData.ConfigData.WebAdaptor.Installer.ContainsKey("IsSelfExtracting")){ $ConfigurationData.ConfigData.WebAdaptor.Installer.IsSelfExtracting }else{ $True }
                                Arguments = $WAArguments
                                WebAdaptorContext = $Context
                                WebAdaptorDotnetHostingBundlePath = if([version]($ConfigurationData.ConfigData.Version) -ge "11.0"){ $ConfigurationData.ConfigData.WebAdaptor.Installer.DotnetHostingBundlePath }else{ $null }
                                WebAdaptorWebDeployPath = if([version]($ConfigurationData.ConfigData.Version) -ge "11.0"){ $ConfigurationData.ConfigData.WebAdaptor.Installer.WebDeployPath }else{ $null }
                                EnableMSILogging = $EnableMSILogging
                                Ensure = "Present"
                            }
                            $WADependsOn = @("[ArcGIS_Install]$($WAName)Install")
                        }

                        if ($ConfigurationData.ConfigData.WebAdaptor.Installer.PatchesDir -and -not($SkipPatchInstalls)) {
                            ArcGIS_InstallPatch "WebAdaptorIIS-InstallPatches"
                            {
                                Name = "WebAdaptorIIS"
                                Version = $ConfigurationData.ConfigData.Version
                                DownloadPatches = if($ConfigurationData.ConfigData.DownloadPatches){ $ConfigurationData.ConfigData.DownloadPatches }else{ $False }
                                PatchesDir = $ConfigurationData.ConfigData.WebAdaptor.Installer.PatchesDir
                                PatchInstallOrder = $ConfigurationData.ConfigData.WebAdaptor.Installer.PatchInstallOrder
                                Ensure = "Present"
                                DependsOn = $WADependsOn
                            }
                        }
                    }
                }
                'SQLServerClient'
                {
                    if($ConfigurationData.ConfigData.SQLServerClient){
                        $TempFolder = "$($env:SystemDrive)\Temp"
                        if(Test-Path $TempFolder){ Remove-Item -Path $TempFolder -Recurse }
                        if(-not(Test-Path $TempFolder)){ New-Item $TempFolder -ItemType directory }

                        foreach($Client in $ConfigurationData.ConfigData.SQLServerClient){
                            $ODBCDriverName = $Client.Name
                            $FileName = Split-Path $Client.InstallerPath -leaf

                            File "SetupCopy$($ODBCDriverName.Replace(' ', '_'))"
                            {
                                Ensure = "Present"
                                Type = "File"
                                SourcePath = $Client.InstallerPath
                                DestinationPath = "$TempFolder\$FileName"  
                            }
                        
                            ArcGIS_InstallMsiPackage "AIMP_$($ODBCDriverName.Replace(' ', '_'))"
                            {
                                Name = $ODBCDriverName
                                Path = $ExecutionContext.InvokeCommand.ExpandString("$TempFolder\$FileName")
                                Ensure = "Present"
                                ProductId = $Client.ProductId
                                Arguments = $Client.Arguments
                                DependsOn = @("[File]SetupCopy$($ODBCDriverName.Replace(' ', '_'))")
                            } 
                        }

                        #if(Test-Path $TempFolder){ Remove-Item -Path $TempFolder -Recurse }
                    }
                }
                'Pro'
                {
                    # Installation Notes: https://pro.arcgis.com/en/pro-app/get-started/arcgis-pro-installation-administration.htm
                    $PortalList = if($ConfigurationData.ConfigData.Pro.PortalList){ $ConfigurationData.ConfigData.Pro.PortalList }else{ "https://arcgis.com" }
                    $Arguments = "/qn ACCEPTEULA=YES PORTAL_LIST=`"$PortalList`" AUTHORIZATION_TYPE=`"$($ConfigurationData.ConfigData.Pro.AuthorizationType)`""

                    # TODO: The SOFTWARE_CLASS does not get added if not supported, should this fail? Currently it uses the default handling mechanism. 
                    if ($ConfigurationData.ConfigData.Pro.SoftwareClass){
                        if (@("viewer","editor","professional") -icontains $ConfigurationData.ConfigData.Pro.SoftwareClass.ToLower()) {
                            $Arguments += " SOFTWARE_CLASS=`"$($ConfigurationData.ConfigData.Pro.SoftwareClass)`""
                        }
                    }

                    if (-not ([string]::IsNullOrEmpty($ConfigurationData.ConfigData.Pro.Installer.InstallDir))){
                        $Arguments += " INSTALLDIR=`"$($ConfigurationData.ConfigData.Pro.Installer.InstallDir)`""
                    }

                    if ($ConfigurationData.ConfigData.Pro.BlockAddIns -match '^[0-5]+$') {
                        $Arguments += " BLOCKADDINS=$($ConfigurationData.ConfigData.Pro.BlockAddIns)" #ensure valid blockaddin value / defauts to allow all addins (0)
                    }

                    if($ConfigurationData.ConfigData.Pro.AuthorizationType -ieq "CONCURRENT_USE"){
                        $Arguments += " ESRI_LICENSE_HOST=`"$($ConfigurationData.ConfigData.Pro.EsriLicenseHost)`"" 
                    }

                    # Pro installed for all users. Per User installs for Pro not supported
                    $Arguments += " ALLUSERS=1"

                    if(-not($ConfigurationData.ConfigData.Pro.ContainsKey("LockAuthSettings")) -or ($ConfigurationData.ConfigData.Pro.ContainsKey("LockAuthSettings") -and -not($ConfigurationData.ConfigData.Pro.LockAuthSettings)) ){
						$Arguments += " LOCK_AUTH_SETTINGS=False"
                    }
					
					if(-not($ConfigurationData.ConfigData.Pro.ContainsKey("EnableEUEI")) -or ($ConfigurationData.ConfigData.Pro.ContainsKey("EnableEUEI") -and -not($ConfigurationData.ConfigData.Pro.EnableEUEI)) ){
						$Arguments += " ENABLEEUEI=0"
                    }
					
					if(-not($ConfigurationData.ConfigData.Pro.ContainsKey("CheckForUpdatesAtStartup")) -or ($ConfigurationData.ConfigData.Pro.ContainsKey("CheckForUpdatesAtStartup") -and -not($ConfigurationData.ConfigData.Pro.CheckForUpdatesAtStartup)) ){
						$Arguments += " CHECKFORUPDATESATSTARTUP=0"
                    }
                    
                    ArcGIS_Install ProInstall{
                        Name = "Pro"
                        Version = $ConfigurationData.ConfigData.ProVersion
                        Path = $ConfigurationData.ConfigData.Pro.Installer.Path
                        DotnetDesktopRuntimePath = if([version]($ConfigurationData.ConfigData.ProVersion) -ge "3.0"){ $ConfigurationData.ConfigData.Pro.Installer.DotnetDesktopRuntimePath }else{ $null }
                        ProEdgeWebView2RuntimePath = if([version]($ConfigurationData.ConfigData.ProVersion) -ge "3.3"){ $ConfigurationData.ConfigData.Pro.Installer.EdgeWebView2RuntimePath }else{ $null }
                        Extract = if($ConfigurationData.ConfigData.Pro.Installer.ContainsKey("IsSelfExtracting")){ $ConfigurationData.ConfigData.Pro.Installer.IsSelfExtracting }else{ $True }
                        Arguments = $Arguments
                        EnableMSILogging = $EnableMSILogging
                        Ensure = "Present"
                    }    
                    
                    $ProDependsOn = @("[ArcGIS_Install]ProInstall")
                    if($ConfigurationData.ConfigData.Pro.Extensions){
                        foreach ($Extension in $ConfigurationData.ConfigData.Pro.Extensions.GetEnumerator()) 
                        {
                            $Arguments = "/qn ALLUSERS=1"
                            $ProExtensionFeatureSet = @()
                            if($Extension.Value.Features -and $Extension.Value.Features.Count -gt 0){
								if($Extension.Value.Features -icontains "ALL"){
									$ProExtensionFeatureSet = @( "ALL" )
								}else{
									$Extension.Value.Features | % {
										$ProExtensionFeatureSet += @( $_ )
									}
								}
                            }else{
                                $ProExtensionFeatureSet = $null
                            }

                            ArcGIS_Install "Pro$($Extension.Key)InstallExtension"
                            {
                                Name = "Pro$($Extension.Key)"
                                Version = $ConfigurationData.ConfigData.ProVersion
                                Path = $Extension.Value.Installer.Path
                                Extract = if($Extension.Value.Installer.ContainsKey("IsSelfExtracting")){ $Extension.Value.Installer.IsSelfExtracting }else{ $True }
                                Arguments = $Arguments
                                FeatureSet = $ProExtensionFeatureSet
                                EnableMSILogging = $EnableMSILogging
                                Ensure = "Present"
                                DependsOn = $ProDependsOn  
                            }
                            $ProDependsOn += "[ArcGIS_Install]Pro$($Extension.Key)InstallExtension"
                        }
                    }

                    if ($ConfigurationData.ConfigData.Pro.Installer.PatchesDir -and -not($SkipPatchInstalls)) {
                        ArcGIS_InstallPatch ProInstallPatch
                        {
                            Name = "Pro"
                            Version = $ConfigurationData.ConfigData.ProVersion
                            DownloadPatches = if($ConfigurationData.ConfigData.DownloadPatches){ $ConfigurationData.ConfigData.DownloadPatches }else{ $False }
                            PatchesDir = $ConfigurationData.ConfigData.Pro.Installer.PatchesDir
                            PatchInstallOrder = $ConfigurationData.ConfigData.Pro.Installer.PatchInstallOrder
                            Ensure = "Present"
                            DependsOn = $ProDependsOn
                        }
                    }
                }
                'LicenseManager'
                {
                    ArcGIS_Install LicenseManagerInstall{
                        Name = "LicenseManager"
                        Version = $ConfigurationData.ConfigData.LicenseManagerVersion
                        Path = $ConfigurationData.ConfigData.LicenseManager.Installer.Path
                        Extract = if($ConfigurationData.ConfigData.LicenseManager.Installer.ContainsKey("IsSelfExtracting")){ $ConfigurationData.ConfigData.LicenseManager.Installer.IsSelfExtracting }else{ $True }
                        Arguments = "/qn ACCEPTEULA=YES INSTALLDIR=`"$($ConfigurationData.ConfigData.LicenseManager.Installer.InstallDir)`""
                        EnableMSILogging = $EnableMSILogging
                        Ensure = "Present"
                    }

                    ArcGIS_xFirewall Server_FirewallRules
                    {
                        Name                  = "ArcGISLicenseManager"
                        DisplayName           = "ArcGIS License Manager"
                        DisplayGroup          = "ArcGIS License Manager"
                        Ensure                = 'Present'
                        Access                = "Allow"
                        State                 = "Enabled"
                        Profile               = ("Domain","Private","Public")
                        LocalPort             = ("27000")
                        Protocol              = "TCP"
                        DependsOn             = @("[ArcGIS_Install]LicenseManagerInstall")
                    }
                }
            }
        }
    }
}