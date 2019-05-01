Configuration SpatioTemporalDatastoreStart{
    param(
        [System.Management.Automation.PSCredential]
        $PrimarySiteAdmin,

        [System.String]
        $ServerMachineName
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName ArcGIS 
    Import-DscResource -Name ArcGIS_BDSUpgradePost

    Node $AllNodes.NodeName {
        $NodeName = $Node.NodeName
        $ServerMachineHostName = [System.Net.DNS]::GetHostByName($ServerMachineName).HostName
        
        ArcGIS_BDSUpgradePost SpatioTemporalDatastoreStart{
            ServerHostName = $ServerMachineHostName
            SiteAdministrator = $PrimarySiteAdmin
            Ensure = 'Present'
        }
    }
}