Configuration UninstallExtraSetups {
    param(
        [Parameter(Mandatory = $false)]
        [System.String]
        $Version = '11.3',

        [Parameter(Mandatory = $false)]
        [System.String]
        $MachineRoles,

        [Parameter(Mandatory = $false)]
        [System.String]
        $ServerRole,

        [Parameter(Mandatory=$false)]
        [System.String]
        $DebugMode
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_Install
    
    $IsDebugMode = $DebugMode -ieq 'true'
    $MachineRolesArray = $MachineRoles -split ','

    Node localhost
    {
        $FoldersToDelete = @("C:\\ArcGIS\\Deployment\\Downloads")
        if($MachineRolesArray -iContains "Server" -and $ServerRole -ieq "NotebookServer"){
            $FoldersToDelete = @("C:\\ArcGIS\\Deployment\\Downloads\\SQLNativeClient","C:\\ArcGIS\\Deployment\\Downloads\\WorkflowManagerServer","C:\\ArcGIS\\Deployment\\Downloads\\GeoEvent","C:\\ArcGIS\\Deployment\\Downloads\\Server", "C:\\ArcGIS\\Deployment\\Downloads\\MissionServer", 
            "C:\\ArcGIS\\Deployment\\Downloads\\VideoServer", "C:\\ArcGIS\\Deployment\\Downloads\\Portal", "C:\\ArcGIS\\Deployment\\Downloads\\WebStyles", "C:\\ArcGIS\\Deployment\\Downloads\\DataStore")
        }
        
        if(-not($MachineRolesArray -iContains "Server") -or $ServerRole -ine "WorkflowManagerServer"){
            ArcGIS_Install WorkflowManagerServerUninstall {
                Name    = "WorkflowManagerServer"
                Version = $Version
                Ensure  = "Absent"
            }

            $FoldersToDelete += @("C:\\ArcGIS\\Server\\WorkflowManager")
        }

        if(-not($MachineRolesArray -iContains "Server") -or $ServerRole -ine "GeoEventServer"){
            ArcGIS_Install GeoEventServerUninstall {
                Name    = "GeoEvent"
                Version = $Version
                Ensure  = "Absent"
            }
            $FoldersToDelete += @("C:\\ArcGIS\\Server\\GeoEvent")
        }
        
        if(-not($MachineRolesArray -iContains "Server") -or (@("NotebookServer", "MissionServer", "VideoServer") -iContains $ServerRole)){
            ArcGIS_Install ServerUninstall {
                Name = "Server"
                Version = $Version
                Ensure = "Absent"
            }

            $FoldersToDelete += @("C:\\ArcGIS\\Server")
        }
            
        if(-not($MachineRolesArray -iContains "Server") -or $ServerRole -ine "MissionServer"){
            ArcGIS_Install MissionServerUninstall {
                Name = "MissionServer"
                Version = $Version
                Ensure = "Absent"
            }

            $FoldersToDelete += @("C:\\ArcGIS\\Mission")
        }

        if(-not($MachineRolesArray -iContains "Server") -or $ServerRole -ine "VideoServer"){
            ArcGIS_Install VideoServerUninstall {
                Name = "VideoServer"
                Version = $Version
                Ensure = "Absent"
            }

            $FoldersToDelete += @("C:\\ArcGIS\\Video")
        }
            
        if(-not($MachineRolesArray -iContains "Server") -or $ServerRole -ine "NotebookServer"){
            ArcGIS_Install NotebookServerUninstall {
                Name = "NotebookServer"
                Version = $Version
                Ensure = "Absent"
            }

            ArcGIS_Install NotebookServerSamplesDataUninstall
            { 
                Name = "NotebookServerSamplesData"
                Version = $Version
                Ensure = "Absent"
            } 

            $FoldersToDelete += @("C:\\ArcGIS\\NotebookServer")
        }else{
            $FoldersToDelete += @("C:\\ArcGIS\\Deployment\\Downloads\\NotebookServerSamplesData", "C:\\ArcGIS\\Deployment\\Downloads\\NotebookServer")
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

            $FoldersToDelete += @("C:\\ArcGIS\\Portal")
        }
        
        if (-not($MachineRolesArray -icontains 'DataStore' -or $MachineRolesArray -icontains 'SpatiotemporalDataStore' -or $MachineRolesArray -icontains 'GraphDataStore' -or $MachineRolesArray -icontains 'ObjectDataStore' -or $MachineRolesArray -icontains 'TileCacheDataStore')){
            ArcGIS_Install DataStoreUninstall
            { 
                Name = "DataStore"
                Version = $Version
                Ensure = "Absent"
            }
            $FoldersToDelete += @("C:\\ArcGIS\\DataStore")
        }
        
        foreach($FolderToDelete in $FoldersToDelete){
            $FileNameResourceName = $FolderToDelete.Replace('\', '_').Replace(':', '_')

            File "RemoveFolder-$FileNameResourceName"
            {
                Ensure = "Absent"
                Type = "Directory"
                DestinationPath	= $FolderToDelete
                Recurse = $true
                Force = $true
            }
        }
    }
}