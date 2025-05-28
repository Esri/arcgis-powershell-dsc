Configuration ArcGISWebGISDR
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [System.String]
        $Version,

        [Parameter(Mandatory=$true)]
        [System.String]
        $PortalInstallDirectory,

        [Parameter(Mandatory=$true)]
        [ValidateSet('Import', 'Export')]
        [System.String]
        $WebGISDRAction,

        [Parameter(Mandatory=$true)]
        [System.String]
        $WebGISDRPropertiesFilePath,

        [Parameter(Mandatory=$false)]
        [System.Int32]
        $WebGISDRTimeoutInMinutes = 3600,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $RunAsCredential
    )

    Import-DscResource -ModuleName 'ArcGIS' -ModuleVersion 4.5.0 -Name ArcGIS_WebGISDR

    Node $AllNodes.NodeName
    {
        # Install the ArcGIS Web GIS DR role
        ArcGIS_WebGISDR WebGISDR
        {
            Version = $Version
            PortalInstallDirectory = $PortalInstallDirectory
            Action = $WebGISDRAction
            PropertiesFilePath = $WebGISDRPropertiesFilePath
            TimeoutInMinutes = $WebGISDRTimeoutInMinutes
            PSDSCRunAsCredential = $RunAsCredential
        }
    }
}