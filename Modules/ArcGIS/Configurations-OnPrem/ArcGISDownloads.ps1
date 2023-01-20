Configuration ArcGISDownloads{
    param(
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $AGOCredential
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.0.2
    Import-DscResource -Name ArcGIS_RemoteFile

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
        if($Node.Role -icontains "ServerWebAdaptor")
        {
            $NodeRoleArray += "ServerWebAdaptor"
        }
        if($Node.Role -icontains "PortalWebAdaptor")
        {
            $NodeRoleArray += "PortalWebAdaptor"
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
                    ArcGIS_RemoteFile "ServerDownload$($Node.NodeName)"
                    {
                        Source = $ConfigurationData.ConfigData.Server.Installer.Path
                        Destination = $ConfigurationData.ConfigData.Server.Installer.Path
                        FileSourceType = "ArcGISDownloadsAPI"
                        Credential = $AGOCredential
                        ArcGISDownloadAPIFolderPath = "software/arcgis/$($ConfigurationData.ConfigData.Version)"
                        Ensure = $Ensure
                    }

                    $ServerTypeName = if($ConfigurationData.ConfigData.ServerRole -ieq "NotebookServer" -or $ConfigurationData.ConfigData.ServerRole -ieq "MissionServer" ){ $ConfigurationData.ConfigData.ServerRole }else{ "Server" }
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
                    
                    if($ConfigurationData.ConfigData.ServerRole -ieq "NotebookServer" -and $ConfigurationParamsHashtable.ConfigData.Server.ContainerImagePaths){
                        foreach($ImagePath in $ConfigurationParamsHashtable.ConfigData.Server.ContainerImagePaths){
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

                    if($ConfigurationData.ConfigData.ServerRole -ieq "NotebookServer" -and $ConfigurationData.ConfigData.Server.Installer.NotebookServerSamplesDataPath) 
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
                    if(($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 7) -or $Version -ieq "10.7.1") -and $ConfigurationData.ConfigData.Portal.Installer.WebStylesPath){
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
                }
                {($_ -eq "ServerWebAdaptor") -or ($_ -eq "PortalWebAdaptor")}
                {
                    $PortalWebAdaptorSkip = $False
                    if(($Node.Role -icontains 'ServerWebAdaptor') -and ($Node.Role -icontains 'PortalWebAdaptor'))
                    {
                        if($NodeRole -ieq "PortalWebAdaptor")
                        {
                            $PortalWebAdaptorSkip = $True
                        }
                    }
                    
                    if(-not($PortalWebAdaptorSkip))
                    {
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