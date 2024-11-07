Configuration ArcGISUninstall
{
    param(
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $ServiceCredential,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsMSA = $false
    )
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.4.0 -Name ArcGIS_Install,ArcGIS_FileShare
    
    Node $AllNodes.NodeName
    {   
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        if(($Node.Role -icontains "Server" -or $Node.Role -icontains "Portal") -and $ConfigurationData.ConfigData.Insights){
            ArcGIS_Install InsightsUninstall
            {
                Name = "Insights"
                Version = $ConfigurationData.ConfigData.InsightsVersion
                Ensure = "Absent"
            }
        }

        for ( $i = 0; $i -lt $Node.Role.Count; $i++ )
        {        
            $NodeRole = $Node.Role[$i]
            Switch($NodeRole) 
            {
                'Server' {
                    
                    $ServerTypeName = if(@("MissionServer", "NotebookServer", "VideoServer") -iContains $ConfigurationData.ConfigData.ServerRole){ $ConfigurationData.ConfigData.ServerRole }else{ "Server" }
                    
                    if($ServerTypeName -ieq "Server"){
                        if($ConfigurationData.ConfigData.WorkflowManagerServer) 
                        {
                            ArcGIS_Install WorkflowManagerServerUninstall
                            {
                                Name = "WorkflowManagerServer"
                                Version = $ConfigurationData.ConfigData.Version
                                Ensure = "Absent"
                            }
                        }
                        
                        if($ConfigurationData.ConfigData.GeoEventServer) 
                        { 
                            ArcGIS_Install GeoEventServerUninstall{
                                Name = "GeoEvent"
                                Version = $ConfigurationData.ConfigData.Version
                                Ensure = "Absent"
                            }
                        }

                        if($ConfigurationData.ConfigData.Server.Extensions){
                            foreach ($Extension in $ConfigurationData.ConfigData.Server.Extensions.GetEnumerator())
                            {
                                ArcGIS_Install "Server$($Extension.Key)UninstallExtension"
                                {
                                    Name = "Server$($Extension.Key)"
                                    Version = $ConfigurationData.ConfigData.Version
                                    Ensure = "Absent"
                                }
                            }
                        }
                    }
                    
                    $VersionArray = $ConfigurationData.ConfigData.Version.Split(".")
                    if($ServerTypeName -ieq "NotebookServer" -and (@("10.9","10.9.1","11.0","11.1","11.2","11.3") -icontains $ConfigurationData.ConfigData.Version))
                    {
                        ArcGIS_Install "NotebookServerSamplesData$($Node.NodeName)"
                        { 
                            Name = "NotebookServerSamplesData"
                            Version = $ConfigurationData.ConfigData.Version
                            Ensure = "Absent"
                        }
                    }
                    
                    ArcGIS_Install ServerUninstall{
                        Name = $ServerTypeName
                        Version = $ConfigurationData.ConfigData.Version
                        Ensure = "Absent"
                    }

                }
                'Portal' {
                    if($ConfigurationData.ConfigData.WorkflowMangerWebApp) 
                    {
                        ArcGIS_Install WorkflowManagerWebAppUninstall
                        {
                            Name = "WorkflowMangerWebApp"
                            Version = $ConfigurationData.ConfigData.Version
                            Ensure = "Absent"
                        }
                    }

                    ArcGIS_Install "PortalUninstall$($Node.NodeName)"
                    { 
                        Name = "Portal"
                        Version = $ConfigurationData.ConfigData.Version
                        Ensure = "Absent"
                    }

                    $VersionArray = $ConfigurationData.ConfigData.Version.Split(".")
                    if(($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 7) -or $Version -ieq "10.7.1") -and $ConfigurationData.ConfigData.Portal.Installer.WebStylesPath){
                        ArcGIS_Install "WebStylesUninstall$($Node.NodeName)"
                        { 
                            Name = "WebStyles"
                            Version = $ConfigurationData.ConfigData.Version
                            Ensure = "Absent"
                        }
                    }
                }
                'DataStore'{
                    ArcGIS_Install DataStoreUninstall
                    { 
                        Name = "DataStore"
                        Version = $ConfigurationData.ConfigData.Version
                        Ensure = "Absent"
                    }
                }
                'WebAdaptor'{
                    $IsJavaWebAdaptor =if($ConfigurationData.ConfigData.WebAdaptor.ContainsKey("IsJavaWebAdaptor")){ $ConfigurationData.ConfigData.WebAdaptor.IsJavaWebAdaptor }else{ $False }
                    if($IsJavaWebAdaptor){
                        # Uninstall tomcat ?
                        # Remove tomcat service ?
                        ArcGIS_Install WebAdaptorJavaUninstall
                        { 
                            Name = "WebAdaptorJava"
                            Version = $ConfigurationData.ConfigData.Version
                            Ensure = "Absent"
                        }
                    }else{
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

                            $WAName = "WebAdaptorIIS-$($WA.Role)-$($Context)"
                            ArcGIS_Install "$($WAName)Install"
                            {
                                Name = $WAName
                                Version = $ConfigurationData.ConfigData.Version
                                WebAdaptorContext = $Context
                                Arguments = "WEBSITE_ID=$($WebSiteId)"
                                Ensure = "Absent"
                            }
                        }
                    }
                }
                'FileShare'{
                    ArcGIS_FileShare FileShareRemove
                    {
                        FileShareName = $ConfigurationData.ConfigData.FileShareName
                        FileShareLocalPath = $ConfigurationData.ConfigData.FileShareLocalPath
                        Ensure = 'Absent'
                        Credential = $ServiceCredential
                        IsDomainAccount = $ServiceCredentialIsDomainAccount
                        IsMSAAccount = $ServiceCredentialIsMSA
                    }
                }
                'Desktop' {
                    if($ConfigurationData.ConfigData.Desktop.Extensions){
                        foreach ($Extension in $ConfigurationData.ConfigData.Desktop.Extensions.GetEnumerator())
                        {
                            ArcGIS_Install "Desktop$($Extension.Key)UninstallExtension"
                            {
                                Name = "Desktop$($Extension.Key)"
                                Version = $ConfigurationData.ConfigData.DesktopVersion
                                Ensure = "Absent"
                            }
                        }
                    }

                    ArcGIS_Install DesktopUninstall
                    { 
                        Name = "Desktop"
                        Version = $ConfigurationData.ConfigData.DesktopVersion
                        Ensure = "Absent"
                    }
                }
                'Pro' {
                    if($ConfigurationData.ConfigData.Pro.Extensions){
                        foreach ($Extension in $ConfigurationData.ConfigData.Pro.Extensions.GetEnumerator())
                        {
                            ArcGIS_Install "Pro$($Extension.Key)UninstallExtension"
                            {
                                Name = "Pro$($Extension.Key)"
                                Version = $ConfigurationData.ConfigData.ProVersion
                                Ensure = "Absent"
                            }
                        }
                    }

                    ArcGIS_Install ProUninstall{
                        Name = "Pro"
                        Version = $ConfigurationData.ConfigData.ProVersion
                        Ensure = "Absent"
                    }
                }
                'LicenseManager'
                {
                    ArcGIS_Install LicenseManagerUninstall{
                        Name = "LicenseManager"
                        Version = $ConfigurationData.ConfigData.LicenseManagerVersion
                        Ensure = "Absent"
                    }
                }
            }
        }
    }
}
