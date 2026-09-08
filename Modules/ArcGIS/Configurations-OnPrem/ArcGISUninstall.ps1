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
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 5.1.2 -Name ArcGIS_Install,ArcGIS_FileShare, ArcGIS_Tomcat
    
    Node $AllNodes.NodeName
    {   
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        for ( $i = 0; $i -lt $Node.Role.Count; $i++ )
        {        
            $NodeRole = $Node.Role[$i]
            Switch($NodeRole) 
            {
                'Server' {
                    
                    $ServerTypeName = if(@("MissionServer", "NotebookServer", "VideoServer", "DataPipelinesServer") -iContains $ConfigurationData.ConfigData.ServerRole){ $ConfigurationData.ConfigData.ServerRole }else{ "Server" }
                    
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

                        if($ConfigurationData.ConfigData.RealityServer) 
                        { 
                            ArcGIS_Install RealityServerUninstall{
                                Name = "RealityServer"
                                Version = $ConfigurationData.ConfigData.Version
                                Ensure = "Absent"
                            }
                        }

                        if($ConfigurationData.ConfigData.GeoEnrichmentServer) 
                        { 
                            ArcGIS_Install GeoEnrichmentServerUninstall{
                                Name = "GeoEnrichmentServer"
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
                    
                    if($ServerTypeName -ieq "NotebookServer" -and (@("10.9.1","11.0","11.1","11.2","11.3") -icontains $ConfigurationData.ConfigData.Version))
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
                    ArcGIS_Install "PortalUninstall$($Node.NodeName)"
                    { 
                        Name = "Portal"
                        Version = $ConfigurationData.ConfigData.Version
                        Ensure = "Absent"
                    }

                    if($ConfigurationData.ConfigData.Portal.Installer.WebStylesPath){
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
                        $MachineFQDN = Get-FQDN $Node.NodeName
                        if($ConfigurationData.ConfigData.WebAdaptor.Installer.ContainsKey("ApacheTomcat")) {
                            $ApacheTomcatConfig = $ConfigurationData.ConfigData.WebAdaptor.Installer.ApacheTomcat
                            ArcGIS_Tomcat ApacheTomcatUninstall {
                                Version                = $ApacheTomcatConfig.Version
                                Ensure                 = "Absent"
                                ServiceName            = $ApacheTomcatConfig.ServiceName
                                DependsOn              = "[ArcGIS_Install]WebAdaptorJavaUninstall" # Ensures WebAdaptor is uninstalled first
                            }
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
