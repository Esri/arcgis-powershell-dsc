Configuration UninstallExtraSetups {
    param(
        [Parameter(Mandatory = $false)]
        [System.String]
        $Version = "12.2",

        [Parameter(Mandatory = $false)]
        [System.String]
        $MachineRoles,

        [Parameter(Mandatory = $false)]
        [System.String]
        $ServerRole,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $DebugMode
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_Install
    
    $MachineRolesArray = $MachineRoles -split ','

    Node localhost
    {
        $FoldersToDelete = @()
        if(-not($MachineRolesArray -iContains "Server") -or $ServerRole -ine "WorkflowManagerServer"){
            ArcGIS_Install WorkflowManagerServerUninstall {
                Name    = "WorkflowManagerServer"
                Version = $Version
                Ensure  = "Absent"
            }

            $FoldersToDelete += @("C:\\ArcGIS\\Server\\WorkflowManager")
        }

        if(-not($MachineRolesArray -iContains "Server") -or $ServerRole -ine "RealityServer"){
            ArcGIS_Install RealityServerUninstall {
                Name    = "RealityServer"
                Version = $Version
                Ensure  = "Absent"
            }

            $FoldersToDelete += @("C:\\ArcGIS\\Server\\RealityServer")
        }

        if(-not($MachineRolesArray -iContains "Server") -or $ServerRole -ine "GeoEventServer"){
            ArcGIS_Install GeoEventServerUninstall {
                Name    = "GeoEvent"
                Version = $Version
                Ensure  = "Absent"
            }
            $FoldersToDelete += @("C:\\ArcGIS\\Server\\GeoEvent")
        }
        
        if(-not($MachineRolesArray -iContains "Server") -or (@("NotebookServer", "MissionServer", "VideoServer","DataPipelinesServer","VelocityServer") -iContains $ServerRole)){
            ArcGIS_Install ServerUninstall {
                Name = "Server"
                Version = $Version
                Ensure = "Absent"
            }

            $FoldersToDelete += @("C:\\ArcGIS\\Server", "C:\\arcgisserver")
        }
            
        if(-not($MachineRolesArray -iContains "Server") -or $ServerRole -ine "MissionServer"){
            ArcGIS_Install MissionServerUninstall {
                Name = "MissionServer"
                Version = $Version
                Ensure = "Absent"
            }

            $FoldersToDelete += @("C:\\ArcGIS\\Mission","C:\\arcgismissionserver")
        }

        if(-not($MachineRolesArray -iContains "Server") -or $ServerRole -ine "VideoServer"){
            ArcGIS_Install VideoServerUninstall {
                Name = "VideoServer"
                Version = $Version
                Ensure = "Absent"
            }

            $FoldersToDelete += @("C:\\ArcGIS\\Video","C:\\arcgisvideoserver")
        }
        

        if(-not($MachineRolesArray -iContains "Server") -or $ServerRole -ine "DataPipelinesServer"){
            ArcGIS_Install DataPipelinesServerUninstall {
                Name = "DataPipelinesServer"
                Version = $Version
                Ensure = "Absent"
            }

            $FoldersToDelete += @("C:\\ArcGIS\\DataPipelines","C:\\datapipelinesserver")
        }
            
        if(-not($MachineRolesArray -iContains "Server") -or $ServerRole -ine "NotebookServer"){
            ArcGIS_Install NotebookServerUninstall {
                Name = "NotebookServer"
                Version = $Version
                Ensure = "Absent"
            }

            $FoldersToDelete += @("C:\\ArcGIS\\NotebookServer", "C:\\arcgisnotebookserver")
        }else{
            $FoldersToDelete += @("C:\\ArcGIS\\Deployment\\Downloads\\NotebookServer")
        }

        if(-not($MachineRolesArray -iContains "Server") -or $ServerRole -ine "VelocityServer"){
            ArcGIS_Install VelocityServerUninstall {
                Name = "VelocityServer"
                Version = $Version
                Ensure = "Absent"
            }

            $FoldersToDelete += @("C:\\ArcGIS\\Velocity","C:\\arcgisvelocity")
        }
        
            
        if(-not($MachineRolesArray -iContains "Portal")){
            ArcGIS_Install WebStylesUninstall
            { 
                Name = "WebStyles"
                Version = $Version
                Ensure = "Absent"
            }

            ArcGIS_Install PortalUninstall
            { 
                Name = "Portal"
                Version = $Version
                Ensure = "Absent"
            }

            $FoldersToDelete += @("C:\\ArcGIS\\Portal","C:\\portalforarcgis")
        }
        
        if (-not($MachineRolesArray -icontains 'DataStore' -or $MachineRolesArray -icontains 'SpatiotemporalDataStore' -or $MachineRolesArray -icontains 'GraphDataStore' -or $MachineRolesArray -icontains 'ObjectDataStore')){
            ArcGIS_Install DataStoreUninstall
            { 
                Name = "DataStore"
                Version = $Version
                Ensure = "Absent"
            }
            $FoldersToDelete += @("C:\\ArcGIS\\DataStore")
        }

        ArcGIS_AzureSetupsManager CleanupDownloadsFolder{
            Version = $Version
            OperationType = 'CleanupDownloadsFolder'
            ComponentNames = if($MachineRolesArray -iContains "Server" -and $ServerRole -ieq "NotebookServer"){ "Server" }else{ "All" }
            ServerRole = $ServerRole
            AdditionalFilesOrFolderToDelete = $FoldersToDelete
        }
    }
}