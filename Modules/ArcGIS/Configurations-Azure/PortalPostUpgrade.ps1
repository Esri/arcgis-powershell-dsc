Configuration PortalPostUpgrade{

    param(
        [parameter(Mandatory = $true)]
        [System.String]
        $PortalLicenseFileUrl,

        [Parameter(Mandatory=$false)]
        [System.String]
        $PortalLicenseUserTypeId,
        
        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministratorCredential,
        
        [parameter(Mandatory = $false)]
        [System.Boolean]
        $SetOnlyHostNamePropertiesFile,

        [parameter(Mandatory = $false)]
        [System.String]
        $Version,
		
		[Parameter(Mandatory=$false)]
        [System.String]
        $DebugMode		
    )

	function Get-FileNameFromUrl
    {
        param(
            [string]$Url
        )
        $FileName = $Url
        if($FileName) {
            $pos = $FileName.IndexOf('?')
            if($pos -gt 0) { 
                $FileName = $FileName.Substring(0, $pos) 
            } 
            $FileName = $FileName.Substring($FileName.LastIndexOf('/')+1)   
        }     
        $FileName
    }

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_PortalUpgrade 

    $IsDebugMode = $DebugMode -ieq 'true'

    Node localhost {
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $true
        }

        if($PortalLicenseFileUrl) {
			$PortalLicenseFileName = Get-FileNameFromUrl $PortalLicenseFileUrl
			Invoke-WebRequest -OutFile $PortalLicenseFileName -Uri $PortalLicenseFileUrl -UseBasicParsing -ErrorAction Ignore
		} 

        ArcGIS_PortalUpgrade PortalUpgrade
        {
            PortalAdministrator = $SiteAdministratorCredential 
            PortalHostName = $env:ComputerName
            LicenseFilePath = (Join-Path $(Get-Location).Path $PortalLicenseFileName) 
            SetOnlyHostNamePropertiesFile = $SetOnlyHostNamePropertiesFile
            Version = $Version
            ImportExternalPublicCertAsRoot = $True
        }
    }
}
