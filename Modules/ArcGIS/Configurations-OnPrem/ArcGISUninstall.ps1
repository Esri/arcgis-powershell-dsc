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
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.2.0"}
    Import-DscResource -Name ArcGIS_Install
    Import-DscResource -Name ArcGIS_FileShare
    Import-DscResource -Name ArcGIS_InstallMsiPackage
    
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
                    if($ConfigurationData.ConfigData.WorkflowMangerServer) 
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

                    if($ConfigurationData.ConfigData.ServerRole -ieq "NotebookServer" -and $ConfigurationData.ConfigData.Version.Split(".")[1] -gt 8) 
                    {
                        ArcGIS_Install "NotebookServerSamplesData$($Node.NodeName)"
                        { 
                            Name = "NotebookServerSamplesData"
                            Version = $ConfigurationData.ConfigData.Version
                            Ensure = "Absent"
                        }
                    }

                    $ServerTypeName = if($ConfigurationData.ConfigData.ServerRole -ieq "NotebookServer" -or $ConfigurationData.ConfigData.ServerRole -ieq "MissionServer" ){ $ConfigurationData.ConfigData.ServerRole }else{ "Server" }

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

                    $VersionArray = $ConfigurationData.ConfigData.Version.Split(".")
                    $MajorVersion = $VersionArray[1]
                    $MinorVersion = if($VersionArray.Length -gt 2){ $VersionArray[2] }else{ 0 }
                    if((($MajorVersion -eq 7 -and $MinorVersion -eq 1) -or ($MajorVersion -ge 8)) -and $ConfigurationData.ConfigData.Portal.Installer.WebStylesPath){
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
                { 'ServerWebAdaptor' -or 'PortalWebAdaptor' }{
                    
                    $WebAdaptorRole = $NodeRole
                    $WebSiteId = if($ConfigurationData.ConfigData.WebAdaptor.WebSiteId){ $ConfigurationData.ConfigData.WebAdaptor.WebSiteId }else{ 1 }
                    if(($WebAdaptorRole -ieq "PortalWebAdaptor") -and $ConfigurationData.ConfigData.PortalContext){
                        ArcGIS_Install WebAdaptorUninstallPortal
                        { 
                            Name = "PortalWebAdaptor"
                            Version = $ConfigurationData.ConfigData.Version
                            WebAdaptorContext = $ConfigurationData.ConfigData.PortalContext
                            Arguments = "WEBSITE_ID=$($WebSiteId)"
                            Ensure = "Absent"
                        }
                    }

                    if(($WebAdaptorRole -ieq "ServerWebAdaptor") -and $Node.ServerContext){
                        ArcGIS_Install WebAdaptorUninstallServer
                        { 
                            Name = "ServerWebAdaptor"
                            Version = $ConfigurationData.ConfigData.Version
                            WebAdaptorContext = $Node.ServerContext
                            Arguments = "WEBSITE_ID=$($WebSiteId)"
                            Ensure = "Absent"
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
                    ArcGIS_Install DesktopUninstall
                    { 
                        Name = "Desktop"
                        Version = $ConfigurationData.ConfigData.DesktopVersion
                        Ensure = "Absent"
                    }
                }
                'Pro' {
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