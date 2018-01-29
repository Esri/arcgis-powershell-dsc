Configuration PortalUpgradeStandbyJoin{
    param(
        [parameter(Mandatory = $true)]
        [System.String]
        $PrimaryPortalMachine,
        
        [parameter(Mandatory = $true)]
        [System.String]
        $Context,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $PrimarySiteAdmin,

        [parameter(Mandatory = $true)]
        [System.String]
        $PrimarySiteAdminEmail,

        [parameter(Mandatory = $true)]
        [System.String]
        $ContentDirectoryLocation,
        
        [parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [System.String]
        $ExternalDNSName<#,

        [parameter(Mandatory = $false)]
        [System.String]
        $FileShareMachine,

        [parameter(Mandatory = $false)]
        [System.String]
        $FileShareName#>
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName ArcGIS 
    Import-DscResource -Name ArcGIS_Install 
    Import-DscResource -Name ArcGIS_License 
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -Name ArcGIS_Portal 
    Import-DscResource -Name ArcGIS_PortalUnregister 
    Import-DscResource -Name ArcGIS_PortalUpgrade 
    Import-DscResource -Name ArcGIS_WaitForComponent

    Node $AllNodes.NodeName {
        $NodeName = $Node.NodeName
        $MachineFQDN = [System.Net.DNS]::GetHostByName($NodeName).HostName
        $PrimaryPortalFQDN = [System.Net.DNS]::GetHostByName($PrimaryPortalMachine).HostName
        #$ContentDirectoryLocation = "\\$($FileShareMachine)\$($FileShareName)\$($ContentDirectoryLocation)"
        
        ArcGIS_Portal "PortalStandBy"
        {
            Ensure = 'Present'
            PortalContext = $Context
            PortalAdministrator = $PrimarySiteAdmin 
            AdminEMail = $PrimarySiteAdminEmail
            AdminSecurityQuestionIndex = 1
            AdminSecurityAnswer = "vanilla"
            ContentDirectoryLocation = $ContentDirectoryLocation
            Join = $true
            IsHAPortal = $true
            ExternalDNSName = $ExternalDNSName
            PortalEndPoint = $MachineFQDN
            PeerMachineHostName = $PrimaryPortalFQDN
            EnableDebugLogging = $True
        }       
    }
}