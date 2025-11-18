Configuration PortalPostUpgrade{

    param(
        [parameter(Mandatory = $true)]
        [System.String]
        $PortalLicenseFileName,

        [Parameter(Mandatory=$false)]
        [System.String]
        $PortalLicenseUserTypeId,
        
        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministratorCredential,
        
        [parameter(Mandatory = $false)]
        [System.String]
        $Version,

        [Parameter(Mandatory=$True)]
        [System.Management.Automation.PSCredential]
        $DeploymentArtifactCredentials,
		
		[Parameter(Mandatory=$false)]
        [System.Boolean]
        $DebugMode		
    )

	Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_PortalUpgrade 

    Node localhost {
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $false
        }

        if($PortalLicenseFileName) {
            $PortalLicenseFileUrl = "$($DeploymentArtifactCredentials.UserName)/$($PortalLicenseFileName)$($DeploymentArtifactCredentials.GetNetworkCredential().Password)"
            Invoke-WebRequest -Verbose:$False -OutFile $PortalLicenseFileName -Uri $PortalLicenseFileUrl -UseBasicParsing -ErrorAction Ignore
        }  

        ArcGIS_PortalUpgrade PortalUpgrade
        {
            PortalAdministrator = $SiteAdministratorCredential 
            PortalHostName = $env:ComputerName
            LicenseFilePath = (Join-Path $(Get-Location).Path $PortalLicenseFileName) 
            Version = $Version
            ImportExternalPublicCertAsRoot = $True
            EnableUpgradeSiteDebug = $DebugMode
        }
    }
}
