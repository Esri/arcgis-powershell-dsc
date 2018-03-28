Configuration ArcGISDisconnectedEnvironment{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS
    Import-DSCResource -Name ArcGIS_Server_DisconnectedEnvironment
    Import-DSCResource -Name ArcGIS_Portal_DisconnectedEnvironment

    $PrimaryServerMachine = ""
    $PrimaryPortalMachine = ""
    $PrimaryDataStore = ""
    $PrimaryBigDataStore = ""
    $PrimaryTileCache = ""
    for ( $i = 0; $i -lt $AllNodes.count; $i++ )
    {

        $Role = $AllNodes[$i].Role
        if($Role -icontains 'Server' -and -not($PrimaryServerMachine))
        {
            $PrimaryServerMachine  = $AllNodes[$i].NodeName
        }

        if($Role -icontains 'Portal' -and -not($PrimaryPortalMachine))
        {
            $PrimaryPortalMachine= $AllNodes[$i].NodeName
        }
        if($Role -icontains 'DataStore')
        {
            $DsTypes = $AllNodes[$i].DataStoreTypes
            if($DsTypes -icontains "Relational" -and -not($PrimaryDataStore))
            {
                $PrimaryDataStore = $AllNodes[$i].NodeName 
            }
            if($DsTypes -icontains "SpatioTemporal" -and -not($PrimaryBigDataStore))
            {
                $PrimaryBigDataStore = $AllNodes[$i].NodeName
            }
            if($DsTypes -icontains "TileCache" -and -not($PrimaryTileCache))
            {
                $PrimaryTileCache = $AllNodes[$i].NodeName
            }
        }
    }

    Node $AllNodes.NodeName
    {
        $MachineFQDN = Get-FQDN $Node.NodeName
        
        $SAPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.Credentials.ServiceAccount.Password -AsPlainText -Force
        $SACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.Credentials.ServiceAccount.UserName, $SAPassword )

        $PSAPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.Password -AsPlainText -Force
        $PSACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.UserName, $PSAPassword )

        $NodeRoleArray = @()
        if($Node.Role -icontains "Server")
        {
            $NodeRoleArray += "Server"
        }
        if($Node.Role -icontains "Portal")
        {
            $NodeRoleArray += "Portal"
        }
        
        for ( $i = 0; $i -lt $NodeRoleArray.Count; $i++ )
        {
            $NodeRole = $NodeRoleArray[$i]
            Switch($NodeRole)
            {
                'Server'{
                    if($ConfigurationData.ConfigData.Server.DisconnectedEnvironment){
                        ArcGIS_Server_DisconnectedEnvironment "DisconnectedEnvironment_$($Node.NodeName)"
                        {
                            Ensure = 'Present'
                            HostName = Get-FQDN $PrimaryServerMachine
                            EnableJsApi = if($ConfigurationData.ConfigData.Server.DisconnectedEnvironment.EnableJsApi) {$true} else {$false}
                            EnableArcGISOnlineMapViewer = if($ConfigurationData.ConfigData.Server.DisconnectedEnvironment.EnableArcGISOnlineMapViewer) {$true} else {$false}
                            SiteAdministrator = $PSACredential
                            DependsOn = $Depends
                        }
                    }
                }
                'Portal'{
                    if($ConfigurationData.ConfigData.Portal.DisconnectedEnvironment)
                    {
                        if ($ConfigurationData.ConfigData.Portal.DisconnectedEnvironment.HelperServices)
                        {
                            $HelperServices = ConvertTo-Json $ConfigurationData.ConfigData.Portal.DisconnectedEnvironment.HelperServices -Depth 4
                        }

                        $LABoundaryLayerFolderPath = $null
                        $LABoundarySubsetFilePath = $null
                        if($ConfigurationData.ConfigData.Portal.DisconnectedEnvironment.LivingAtlas.BoundaryLayerFolderPath){
                            $LABoundaryLayerFolderPath = $ConfigurationData.ConfigData.Portal.DisconnectedEnvironment.LivingAtlas.BoundaryLayerFolderPath
                            if($ConfigurationData.ConfigData.Portal.DisconnectedEnvironment.LivingAtlas.BoundarySubsetFilePath){
                                $LABoundarySubsetFilePath = $ConfigurationData.ConfigData.Portal.DisconnectedEnvironment.LivingAtlas.BoundarySubsetFilePath
                            }
                        }

                        ArcGIS_Portal_DisconnectedEnvironment "DisconnectedEnvironment_$($Node.NodeName)"
                        {
                            Ensure = 'Present'
                            HostName = Get-FQDN $PrimaryPortalMachine
                            SiteAdministrator = $PSACredential
                            DisableExternalContent = if($ConfigurationData.ConfigData.Portal.DisconnectedEnvironment.DisableExternalContent) {$true} else {$false}
                            DisableLivingAtlas = if($ConfigurationData.ConfigData.Portal.DisconnectedEnvironment.LivingAtlas.Disabled) {$true} else {$false}
                            LivingAtlasBoundaryLayerFolderPath = $LABoundaryLayerFolderPath
                            LivingAtlasBoundarySubsetFilePath = $LABoundarySubsetFilePath
                            ConfigJsPath = $ConfigurationData.ConfigData.Portal.DisconnectedEnvironment.ConfigJsPath
                            HelperServices = $HelperServices
                        }
                    }
                }
            }

        }
    }
}