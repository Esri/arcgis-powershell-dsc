Configuration PortalUpgrade{

    param(
        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

		[parameter(Mandatory = $true)]
        [System.String]
        $PortalInstallerPath,
		
		[parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
        $FileshareMachineCredential,

        [parameter(Mandatory = $true)]
        [System.String]
        $PortalLicenseFileUrl,

        [Parameter(Mandatory=$false)]
        [System.String]
        $PortalLicenseUserType,
        
        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $ServiceCredential,

        [Parameter(Mandatory=$false)]
        [System.String]
        $ServiceCredentialIsDomainAccount = 'false',

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
		$SiteAdministratorCredential,

        [parameter(Mandatory = $false)]
        [System.String]
        $StandbyPortalMachineName,
		
		[Parameter(Mandatory=$false)]
        [System.String]
        $DebugMode		
    )

	function Extract-FileNameFromUrl
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

    Import-DscResource -Name ArcGIS_Install 
    Import-DscResource -Name ArcGIS_License 
	Import-DscResource -name ArcGIS_WindowsService
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -Name ArcGIS_Portal 
    Import-DscResource -Name ArcGIS_PortalUnregister 
    Import-DscResource -Name ArcGIS_PortalUpgrade 

    $IsDebugMode = $DebugMode -ieq 'true'
    $IsServiceCredentialDomainAccount = $ServiceCredentialIsDomainAccount -ieq 'true'

    Node localhost {
        
        $MachineFQDN = Get-FQDN $env:ComputerName
        $VersionArray = $Version.Split(".")
        $MajorVersion = $VersionArray[1]
        if(-Not($IsServiceCredentialDomainAccount)){
            User ArcGIS_RunAsAccount
            {
                UserName = $ServiceCredential.UserName
                Password = $ServiceCredential
                FullName = 'ArcGIS Run As Account'
                Ensure = "Present"
            }
        }

        $Depends = @()

        if($StandbyPortalMachineName){
			$StandbyMachine = Get-FQDN $StandbyPortalMachineName
            ArcGIS_PortalUnregister UnregisterStandyPortal
            {
                PortalEndPoint = $MachineFQDN
                PrimarySiteAdmin = $SiteAdministratorCredential
                StandbyMachine = $StandbyPortalMachineName
				Version = $Version
            }
            $Depends += '[ArcGIS_PortalUnregister]UnregisterStandyPortal'
        } 
		
		$InstallerFileName = Split-Path $PortalInstallerPath -Leaf

		$fPassword = ConvertTo-SecureString $FileshareMachineCredential.GetNetworkCredential().Password -AsPlainText -Force
        $fCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("SiteUpgradeVM\$($FileshareMachineCredential.UserName)", $fPassword )

        $InstallerPathOnMachine = "$env:TEMP\portal\$InstallerFileName"
        
		File DownloadInstallerFromFileShare      
		{            	
			Ensure = "Present"              	
			Type = "File"             	
			SourcePath = $PortalInstallerPath 	
			DestinationPath = $InstallerPathOnMachine    
			Credential = $fCredential     
			DependsOn = $Depends  
		}

        ArcGIS_Install PortalUpgradeInstall
        { 
            Name = "Portal"
            Version = $Version
            Path = $InstallerPathOnMachine
            Arguments = "/qb USER_NAME=$($ServiceCredential.UserName) PASSWORD=$($ServiceCredential.GetNetworkCredential().Password)";
            Ensure = "Present"
            DependsOn = $Depends
        }

		$Depends += '[ArcGIS_Install]PortalUpgradeInstall'
        
		Script RemoveInstaller
		{
			SetScript = 
			{ 
				Remove-Item $using:InstallerPathOnMachine -Force
			}
			TestScript = { -not(Test-Path $using:InstallerPathOnMachine) }
			GetScript = { $null }          
		}
            
        $Depends += '[Script]RemoveInstaller'
        
        if($PortalLicenseFileUrl) {
			$PortalLicenseFileName = Extract-FileNameFromUrl $PortalLicenseFileUrl
			Invoke-WebRequest -OutFile $PortalLicenseFileName -Uri $PortalLicenseFileUrl -UseBasicParsing -ErrorAction Ignore
		}    

        if($PortalLicenseFileName -and ($MajorVersion -lt 7)) 
        {
            ArcGIS_License PortalLicense
            {
                LicenseFilePath = (Join-Path $(Get-Location).Path $PortalLicenseFileName)
                Ensure          = 'Present'
                Component       = 'Portal'
				Force           = $True
				DependsOn       = $Depends
            } 

            $Depends += '[ArcGIS_License]PortalLicense'
        }
		
        ArcGIS_WindowsService Portal_for_ArcGIS_Service
        {
            Name            = 'Portal for ArcGIS'
            Credential      = $ServiceCredential
            StartupType     = 'Automatic'
            State           = 'Running' 
            DependsOn       = $Depends
        }

        $Depends += '[ArcGIS_WindowsService]Portal_for_ArcGIS_Service'
        
        $DataDirsForPortal = @('HKLM:\SOFTWARE\ESRI\Portal for ArcGIS')

        ArcGIS_Service_Account Portal_Service_Account
		{
			Name            = 'Portal for ArcGIS'
            RunAsAccount    = $ServiceCredential
            IsDomainAccount = $IsServiceCredentialDomainAccount
			Ensure          = 'Present'
            DependsOn       = if(-Not($IsServiceCredentialDomainAccount)){@('[User]ArcGIS_RunAsAccount','[ArcGIS_WindowsService]Portal_for_ArcGIS_Service')}else{@('[ArcGIS_WindowsService]Portal_for_ArcGIS_Service')}
            DataDir         = $DataDirsForPortal
        }
        
        $Depends += '[ArcGIS_Service_Account]Portal_Service_Account'
        
        ArcGIS_PortalUpgrade PortalUpgrade
        {
            PortalAdministrator = $SiteAdministratorCredential 
            PortalHostName = $MachineFQDN
            LicenseFilePath = if($MajorVersion -ge 7){ (Join-Path $(Get-Location).Path $PortalLicenseFileName) }else{ $null }
            DependsOn = $Depends
        }
    }
}