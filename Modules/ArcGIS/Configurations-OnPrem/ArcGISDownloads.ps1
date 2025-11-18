Configuration ArcGISDownloads{
    param(
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $AGOCredential
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 5.0.0 -Name ArcGIS_RemoteFile
    
    Node $AllNodes.NodeName {

        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }

        $Ensure = "Present"
        
        $NodeRoleArray = @()
        if($Node.Role -icontains "Server")
        {
            $NodeRoleArray += "Server"
        }
        if($Node.Role -icontains "Portal")
        {
            $NodeRoleArray += "Portal"
        }
        if(($Node.Role -icontains "Server" -or $Node.Role -icontains "Portal") -and $ConfigurationData.ConfigData.Insights){
            $NodeRoleArray += "Insights"
        }
        if($Node.Role -icontains "DataStore")
        {
            $NodeRoleArray += "DataStore"
        }
        if($Node.Role -icontains "WebAdaptor")
        {
            $NodeRoleArray += "WebAdaptor"
        }
        if($Node.Role -icontains "Desktop")
        {
            $NodeRoleArray += "Desktop"
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
                    if($ConfigurationData.ConfigData.Server.Installer.DotnetDesktopRuntimeDownloadUrl){
                        ArcGIS_RemoteFile "ServerDotnetDesktopRuntimeDownload$($Node.NodeName)"{
                            Source = $ConfigurationData.ConfigData.Server.Installer.DotnetDesktopRuntimeDownloadUrl
                            Destination = $ConfigurationData.ConfigData.Server.Installer.DotnetDesktopRuntimePath 
                            FileSourceType = "Default"
                            Ensure = $Ensure
                        }
                    }

                    ArcGIS_RemoteFile "ServerDownload$($Node.NodeName)"
                    {
                        Source = $ConfigurationData.ConfigData.Server.Installer.Path
                        Destination = $ConfigurationData.ConfigData.Server.Installer.Path
                        FileSourceType = "ArcGISDownloadsAPI"
                        Credential = $AGOCredential
                        ArcGISDownloadAPIFolderPath = "software/arcgis/$($ConfigurationData.ConfigData.Version)"
                        Ensure = $Ensure
                    }
                    $VersionArray = $ConfigurationData.ConfigData.Version.Split(".")
                    if(($VersionArray[0] -gt 11 -or ($VersionArray[0] -eq 11 -and $VersionArray[1] -ge 3)) -and $ConfigurationData.ConfigData.Server.Installer.VolumePaths){
                        foreach($VolumePath in $ConfigurationData.ConfigData.Server.Installer.VolumePaths){
                            $VolumeName = Split-Path $VolumePath -leaf
                            ArcGIS_RemoteFile "ServerVolumeDownload$($VolumeName)"
                            {
                                Source = $VolumePath
                                Destination = $VolumePath
                                FileSourceType = "ArcGISDownloadsAPI"
                                Credential = $AGOCredential
                                ArcGISDownloadAPIFolderPath = "software/arcgis/$($ConfigurationData.ConfigData.Version)"
                                Ensure = $Ensure
                            }
                        }
                    }

                    $ServerTypeName = if(@("MissionServer", "NotebookServer", "VideoServer") -iContains $ConfigurationData.ConfigData.ServerRole){ $ConfigurationData.ConfigData.ServerRole }else{ "Server" }
                    
                    if($ServerTypeName -ieq "Server" -and $ConfigurationData.ConfigData.Server.Extensions){
                        foreach ($Extension in $ConfigurationData.ConfigData.Server.Extensions.GetEnumerator())
                        {
                            ArcGIS_RemoteFile "Server$($Extension.Key)DownloadExtension$($Node.NodeName)"
                            {
                                Source = $Extension.Value.Installer.Path 
                                Destination = $Extension.Value.Installer.Path 
                                FileSourceType = "ArcGISDownloadsAPI"
                                Credential = $AGOCredential
                                ArcGISDownloadAPIFolderPath = "software/arcgis/$($ConfigurationData.ConfigData.Version)"
                                Ensure = $Ensure
                            }
                        }
                    }
                    
                    if($ConfigurationData.ConfigData.ServerRole -ieq "NotebookServer" -and $ConfigurationData.ConfigData.Server.ContainerImagePaths){
                        foreach($ImagePath in $ConfigurationData.ConfigData.Server.ContainerImagePaths){
                            $ImageName = Split-Path $ImagePath -leaf
                            ArcGIS_RemoteFile "NotebookContainerImageDownloads$($ImageName)"
                            {
                                Source = $ImagePath 
                                Destination = $ImagePath
                                FileSourceType = "ArcGISDownloadsAPI"
                                Credential = $AGOCredential
                                ArcGISDownloadAPIFolderPath = "software/arcgis/$($ConfigurationData.ConfigData.Version)"
                                Ensure = $Ensure
                            }
                        }
                    }

                    if($ConfigurationData.ConfigData.ServerRole -ieq "NotebookServer" -and $ConfigurationData.ConfigData.Server.Installer.NotebookServerSamplesDataPath) #TODO
                    {
                        ArcGIS_RemoteFile "NotebookServerSamplesDataDownloads$($Node.NodeName)"
                        {
                            Source = $ConfigurationData.ConfigData.Server.Installer.NotebookServerSamplesDataPath 
                            Destination = $ConfigurationData.ConfigData.Server.Installer.NotebookServerSamplesDataPath 
                            FileSourceType = "ArcGISDownloadsAPI"
                            Credential = $AGOCredential
                            ArcGISDownloadAPIFolderPath = "software/arcgis/$($ConfigurationData.ConfigData.Version)"
                            Ensure = $Ensure
                        }
                    }
                    
                    if($ConfigurationData.ConfigData.WorkflowManagerServer) 
                    {
                        ArcGIS_RemoteFile "WorkflowManagerServerDownload$($Node.NodeName)"
                        {
                            Source = $ConfigurationData.ConfigData.WorkflowManagerServer.Installer.Path 
                            Destination = $ConfigurationData.ConfigData.WorkflowManagerServer.Installer.Path
                            FileSourceType = "ArcGISDownloadsAPI"
                            Credential = $AGOCredential
                            ArcGISDownloadAPIFolderPath = "software/arcgis/$($ConfigurationData.ConfigData.Version)"
                            Ensure = $Ensure
                        }
                    }

                    if($ConfigurationData.ConfigData.GeoEventServer) 
                    { 
                        ArcGIS_RemoteFile "GeoeventDownload$($Node.NodeName)"
                        {
                            Source = $ConfigurationData.ConfigData.GeoEventServer.Installer.Path
                            Destination = $ConfigurationData.ConfigData.GeoEventServer.Installer.Path
                            FileSourceType = "ArcGISDownloadsAPI"
                            Credential = $AGOCredential
                            ArcGISDownloadAPIFolderPath = "software/arcgis/$($ConfigurationData.ConfigData.Version)"
                            Ensure = $Ensure
                        }

                    }
                }
                'Portal'
                {        
                    ArcGIS_RemoteFile "PortalDownload$($Node.NodeName)"
                    {
                        Source = $ConfigurationData.ConfigData.Portal.Installer.Path
                        Destination = $ConfigurationData.ConfigData.Portal.Installer.Path 
                        FileSourceType = "ArcGISDownloadsAPI"
                        Credential = $AGOCredential
                        ArcGISDownloadAPIFolderPath = "software/arcgis/$($ConfigurationData.ConfigData.Version)"
                        Ensure = $Ensure
                    }
                    $VersionArray = $ConfigurationData.ConfigData.Version.Split(".")
                    if(($VersionArray[0] -gt 11 -or ($VersionArray[0] -eq 11 -and $VersionArray[1] -ge 3)) -and $ConfigurationData.ConfigData.Portal.Installer.VolumePaths){
                        foreach($VolumePath in $ConfigurationData.ConfigData.Portal.Installer.VolumePaths){
                            $VolumeName = Split-Path $VolumePath -leaf
                            ArcGIS_RemoteFile "PortalVolumeDownload$($VolumeName)"
                            {
                                Source = $VolumePath
                                Destination = $VolumePath
                                FileSourceType = "ArcGISDownloadsAPI"
                                Credential = $AGOCredential
                                ArcGISDownloadAPIFolderPath = "software/arcgis/$($ConfigurationData.ConfigData.Version)"
                                Ensure = $Ensure
                            }
                        }
                    }

                    if(($VersionArray[0] -gt 10 -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 7) -or $Version -ieq "10.7.1") -and $ConfigurationData.ConfigData.Portal.Installer.WebStylesPath){
                        ArcGIS_RemoteFile "WebStyleDownload$($Node.NodeName)"
                        {
                            Source = $ConfigurationData.ConfigData.Portal.Installer.WebStylesPath
                            Destination = $ConfigurationData.ConfigData.Portal.Installer.WebStylesPath 
                            FileSourceType = "ArcGISDownloadsAPI"
                            Credential = $AGOCredential
                            ArcGISDownloadAPIFolderPath = "software/arcgis/$($ConfigurationData.ConfigData.Version)"
                            Ensure = $Ensure
                        }
                    }

                    if($ConfigurationData.ConfigData.WorkflowManagerWebApp) 
                    {
                        ArcGIS_RemoteFile WorkflowManagerWebAppDownload
                        {
                            Source = $ConfigurationData.ConfigData.WorkflowManagerWebApp.Installer.Path
                            Destination = $ConfigurationData.ConfigData.WorkflowManagerWebApp.Installer.Path 
                            FileSourceType = "ArcGISDownloadsAPI"
                            Credential = $AGOCredential
                            ArcGISDownloadAPIFolderPath = "software/arcgis/$($ConfigurationData.ConfigData.Version)"
                            Ensure = $Ensure
                        }
                    }
                }
                'Insights'
                {
                    ArcGIS_RemoteFile "InsightsDownload$($Node.NodeName)"
                    {
                        Source = $ConfigurationData.ConfigData.Insights.Installer.Path
                        Destination = $ConfigurationData.ConfigData.Insights.Installer.Path 
                        FileSourceType = "ArcGISDownloadsAPI"
                        Credential = $AGOCredential
                        ArcGISDownloadAPIFolderPath = "software/insights/$($ConfigurationData.ConfigData.InsightsVersion)"
                        Ensure = $Ensure
                    }
                }
                'DataStore'
                {
                    ArcGIS_RemoteFile "DataStoreDownload$($Node.NodeName)"
                    {
                        Source = $ConfigurationData.ConfigData.DataStore.Installer.Path
                        Destination = $ConfigurationData.ConfigData.DataStore.Installer.Path 
                        FileSourceType = "ArcGISDownloadsAPI"
                        Credential = $AGOCredential
                        ArcGISDownloadAPIFolderPath ="software/arcgis/$($ConfigurationData.ConfigData.Version)"
                        Ensure = $Ensure
                    }

                    $VersionArray = $ConfigurationData.ConfigData.Version.Split(".")
                    if(($VersionArray[0] -gt 12) -and $ConfigurationData.ConfigData.DataStore.Installer.VolumePaths){
                        foreach($VolumePath in $ConfigurationData.ConfigData.DataStore.Installer.VolumePaths){
                            $VolumeName = Split-Path $VolumePath -leaf
                            ArcGIS_RemoteFile "DataStoreVolumeDownload$($VolumeName)"
                            {
                                Source = $VolumePath
                                Destination = $VolumePath
                                FileSourceType = "ArcGISDownloadsAPI"
                                Credential = $AGOCredential
                                ArcGISDownloadAPIFolderPath = "software/arcgis/$($ConfigurationData.ConfigData.Version)"
                                Ensure = $Ensure
                            }
                        }
                    }
                }
                'WebAdaptor'
                {
                    $IsJavaWebAdaptor =if($ConfigurationData.ConfigData.WebAdaptor.ContainsKey("IsJavaWebAdaptor")){ $ConfigurationData.ConfigData.WebAdaptor.IsJavaWebAdaptor }else{ $False }
                    if($IsJavaWebAdaptor){
                        if($ConfigurationData.ConfigData.WebAdaptor.Installer.ContainsKey("ApacheTomcat") -and $ConfigurationData.ConfigData.WebAdaptor.Installer.ApacheTomcat.ContainsKey("DownloadUrl")){
                            ArcGIS_RemoteFile "ApacheTomcatDownload$($Node.NodeName)"{
                                Source = $ConfigurationData.ConfigData.WebAdaptor.Installer.ApacheTomcat.DownloadUrl
                                Destination = $ConfigurationData.ConfigData.WebAdaptor.Installer.ApacheTomcat.Path 
                                FileSourceType = "Default"
                                Ensure = $Ensure
                            }
                        }
                    }else{
                        if($ConfigurationData.ConfigData.WebAdaptor.Installer.WebDeployDownloadUrl){
                            ArcGIS_RemoteFile "WebDeployDownload$($Node.NodeName)"{
                                Source = $ConfigurationData.ConfigData.WebAdaptor.Installer.WebDeployDownloadUrl
                                Destination = $ConfigurationData.ConfigData.WebAdaptor.Installer.WebDeployPath
                                FileSourceType = "Default"
                                Ensure = $Ensure
                            }
                        }

                        if($ConfigurationData.ConfigData.WebAdaptor.Installer.DotnetHostingBundleDownloadUrl){
                            ArcGIS_RemoteFile "DotnetHostingBundleDownload$($Node.NodeName)"{
                                Source = $ConfigurationData.ConfigData.WebAdaptor.Installer.DotnetHostingBundleDownloadUrl
                                Destination = $ConfigurationData.ConfigData.WebAdaptor.Installer.DotnetHostingBundlePath
                                FileSourceType = "Default"
                                Ensure = $Ensure
                            }
                        }
                    }
                
                    ArcGIS_RemoteFile "WebAdaptorDownload$($Node.NodeName)"
                    {
                        Source = $ConfigurationData.ConfigData.WebAdaptor.Installer.Path
                        Destination = $ConfigurationData.ConfigData.WebAdaptor.Installer.Path 
                        FileSourceType = "ArcGISDownloadsAPI"
                        Credential = $AGOCredential
                        ArcGISDownloadAPIFolderPath = "software/arcgis/$($ConfigurationData.ConfigData.Version)"
                        Ensure = $Ensure
                    }
                }
                'Desktop' {
                    ArcGIS_RemoteFile "DesktopDownload$($Node.NodeName)"
                    {
                        Source = $ConfigurationData.ConfigData.Desktop.Installer.Path
                        Destination = $ConfigurationData.ConfigData.Desktop.Installer.Path 
                        FileSourceType = "ArcGISDownloadsAPI"
                        Credential = $AGOCredential
                        ArcGISDownloadAPIFolderPath = "software/arcgis/$($ConfigurationData.ConfigData.DesktopVersion)"
                        Ensure = $Ensure
                    }
                    if($ConfigurationData.ConfigData.Desktop.Extensions){
                        foreach ($Extension in $ConfigurationData.ConfigData.Desktop.Extensions.GetEnumerator()) 
                        {
                            ArcGIS_RemoteFile "Desktop$($Extension.Key)DownloadExtension$($Node.NodeName)"
                            {
                                Source = $Extension.Value.Installer.Path 
                                Destination = $Extension.Value.Installer.Path 
                                FileSourceType = "ArcGISDownloadsAPI"
                                Credential = $AGOCredential
                                ArcGISDownloadAPIFolderPath = "software/arcgis/$($ConfigurationData.ConfigData.DesktopVersion)"
                                Ensure = $Ensure
                            }
                        }
                    }
                }
                'Pro'
                {
                    if($ConfigurationData.ConfigData.Pro.Installer.DotnetDesktopRuntimeDownloadUrl){
                        ArcGIS_RemoteFile "ProDotnetDesktopRuntimeDownload$($Node.NodeName)"{
                            Source = $ConfigurationData.ConfigData.Pro.Installer.DotnetDesktopRuntimeDownloadUrl
                            Destination = $ConfigurationData.ConfigData.Pro.Installer.DotnetDesktopRuntimePath 
                            FileSourceType = "Default"
                            Ensure = $Ensure
                        }
                    }

                    if($ConfigurationData.ConfigData.Pro.Installer.EdgeWebView2RuntimeDownloadUrl){
                        ArcGIS_RemoteFile "EdgeWebView2RuntimeDownload$($Node.NodeName)"{
                            Source = $ConfigurationData.ConfigData.Pro.Installer.EdgeWebView2RuntimeDownloadUrl
                            Destination = $ConfigurationData.ConfigData.Pro.Installer.EdgeWebView2RuntimePath 
                            FileSourceType = "Default"
                            Ensure = $Ensure
                        }
                    }

                    $ProDownloadFolder = if($ConfigurationData.ConfigData.ProVersion -ieq "3.0.3"){ "3.0" }else{ $ConfigurationData.ConfigData.ProVersion }
                    ArcGIS_RemoteFile "ProDownload$($Node.NodeName)"
                    {
                        Source = $ConfigurationData.ConfigData.Pro.Installer.Path
                        Destination = $ConfigurationData.ConfigData.Pro.Installer.Path 
                        FileSourceType = "ArcGISDownloadsAPI"
                        Credential = $AGOCredential
                        ArcGISDownloadAPIFolderPath = "software/arcgispro/EXEs/$($ProDownloadFolder)"
                        Ensure = $Ensure
                    }
                    if($ConfigurationData.ConfigData.Pro.Extensions){
                        foreach ($Extension in $ConfigurationData.ConfigData.Pro.Extensions.GetEnumerator()) 
                        {
                            ArcGIS_RemoteFile "Pro$($Extension.Key)DownloadExtension$($Node.NodeName)"
                            {
                                Source = $Extension.Value.Installer.Path
                                Destination = $Extension.Value.Installer.Path 
                                FileSourceType = "ArcGISDownloadsAPI"
                                Credential = $AGOCredential
                                ArcGISDownloadAPIFolderPath = "software/arcgispro/EXEs/$($ProDownloadFolder)"
                                Ensure = $Ensure
                            }
                        }
                    }
                }
                'LicenseManager'
                {
                    ArcGIS_RemoteFile "LicenseManagerDownload$($Node.NodeName)"
                    {
                        Source = $ConfigurationData.ConfigData.LicenseManager.Installer.Path
                        Destination = $ConfigurationData.ConfigData.LicenseManager.Installer.Path 
                        FileSourceType = "ArcGISDownloadsAPI"
                        Credential = $AGOCredential
                        ArcGISDownloadAPIFolderPath = "software/ArcGIS_LicenseManager/$($ConfigurationData.ConfigData.LicenseManagerVersion)"
                        Ensure = $Ensure
                    }
                }
            }
        }
    }
}