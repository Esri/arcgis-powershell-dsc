Configuration PortalStandbyUpgrade{

    param(
        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

		[parameter(Mandatory = $true)]
        [System.String]
        $OldVersion,
		
		[parameter(Mandatory = $true)]
        [System.String]
        $PortalInstallerPath,
		
		[parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
        $FileshareMachineCredential,

        [Parameter(Mandatory=$true)]
        [System.String]
        $PeerMachineName,

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

        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $SiteAdministratorCredential,

        [Parameter(Mandatory=$true)]
        [System.String]
        $PortalEndpoint,

        [Parameter(Mandatory=$false)]
        [System.String]
        $UseCloudStorage,

        [Parameter(Mandatory=$false)]
        [System.String]
        $UseAzureFiles,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $StorageAccountCredential,

        [Parameter(Mandatory=$true)]
        [System.String]
        $FileShareMachineName,

        [Parameter(Mandatory=$false)]
        [System.String]
        $FileShareName = 'fileshare', 
        
        [Parameter(Mandatory=$true)]
        [System.String]
        $ExternalDNSHostName,    
		
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
	Import-DscResource -Name ArcGIS_Portal
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -name ArcGIS_WindowsService
    Import-DscResource -Name ArcGIS_PortalUpgrade

    $FolderName = $ExternalDNSHostName.Substring(0, $ExternalDNSHostName.IndexOf('.')).ToLower()
    $FileShareRootPath = "\\$FileShareMachineName\$FileShareName"
    $ContentStoreLocation = "\\$FileShareMachineName\$FileShareName\$FolderName\portal\content"   
    $IsDebugMode = $DebugMode -ieq 'true'
    $IsServiceCredentialDomainAccount = $ServiceCredentialIsDomainAccount -ieq 'true'
    
    if(($UseCloudStorage -ieq 'True') -and $StorageAccountCredential) 
    {
        $Namespace = $ExternalDNSHostName
        $Pos = $Namespace.IndexOf('.')
        if($Pos -gt 0) { $Namespace = $Namespace.Substring(0, $Pos) }        
        $Namespace = [System.Text.RegularExpressions.Regex]::Replace($Namespace, '[\W]', '') # Sanitize
        $AccountName = $StorageAccountCredential.UserName
		$EndpointSuffix = ''
        $Pos = $StorageAccountCredential.UserName.IndexOf('.blob.')
        if($Pos -gt -1) {
            $AccountName = $StorageAccountCredential.UserName.Substring(0, $Pos)
			$EndpointSuffix = $StorageAccountCredential.UserName.Substring($Pos + 6) # Remove the hostname and .blob. suffix to get the storage endpoint suffix
			$EndpointSuffix = ";EndpointSuffix=$($EndpointSuffix)"
        }

        if($UseAzureFiles -ieq 'True') {
            $AzureFilesEndpoint = $StorageAccountCredential.UserName.Replace('.blob.','.file.')                        
            $FileShareName = $FileShareName.ToLower() # Azure file shares need to be lower case
            $FolderName = $ExternalDNSHostName.Substring(0, $ExternalDNSHostName.IndexOf('.'))
            $ContentStoreLocation = "\\$($AzureFilesEndpoint)\$FileShareName\$FolderName\portal\content"    
        }
        else {
            $AccountKey = $StorageAccountCredential.GetNetworkCredential().Password
            $ContentDirectoryCloudConnectionString = "DefaultEndpointsProtocol=https;AccountName=$($AccountName);AccountKey=$($AccountKey)$($EndpointSuffix)"
		    $ContentDirectoryCloudContainerName = "arcgis-portal-content-$($Namespace)"
        }
    }

    
    Node localhost {
        
        $MachineFQDN = Get-FQDN $env:ComputerName
        $VersionArray = $Version.Split(".")
        $MajorVersion = $VersionArray[1]
        $Depends = @()

        $InstallerFileName = Split-Path $PortalInstallerPath -Leaf
        
        $fPassword = ConvertTo-SecureString $FileshareMachineCredential.GetNetworkCredential().Password -AsPlainText -Force
        $fCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("SiteUpgradeVM\$($FileshareMachineCredential.UserName)", $fPassword )
        
        $InstallerPathOnMachine= "$env:TEMP\portal\$InstallerFileName"

        File DownloadInstallerFromFileShare      
        {            	
            Ensure = "Present"              	
            Type = "File"             	
            SourcePath = $PortalInstallerPath 	
            DestinationPath = $InstallerPathOnMachine    
            Credential = $fCredential     
            DependsOn = $Depends  
        }
        
        if(-Not($IsServiceCredentialDomainAccount)){
            User ArcGIS_RunAsAccount
            {
                UserName = $ServiceCredential.UserName
                Password = $ServiceCredential
                FullName = 'ArcGIS Run As Account'
                Ensure = "Present"
            }
            $Depends += '[User]ArcGIS_RunAsAccount'
        }        

        $InstallDir = "$($env:SystemDrive)\ArcGIS\Portal"
		$ContentDir = "$($env:SystemDrive)\portalforarcgis\content"

       
        ArcGIS_Install PortalUninstallStandby
        { 
            Name = "Portal"
            Version = $OldVersion
            Path = $InstallerPathOnMachine  
            Arguments = "/qn INSTALLDIR=$($InstallDir) CONTENTDIR=$($ContentDir)";
            Ensure = "Absent"
            DependsOn = $Depends
        }
    
        $Depends += '[ArcGIS_Install]PortalUninstallStandby'

        $PortalName = (get-wmiobject Win32_Product| Where-Object {$_.Name -match "Portal" -and $_.Vendor -eq 'Environmental Systems Research Institute, Inc.'}).Name
        if(-not($PortalName -imatch $Version)){
            File DirectoryRemove
            {
                Ensure = "Absent"  
                Type = "Directory" 
                Force = $true
                DestinationPath = $ContentDir  
                DependsOn = $Depends
            }
        }

        if($MajorVersion -ge 7){
            File CreatestandbydbBackupFileRemove
            {
                Ensure = "Absent"  
                Type = "File" 
                Force = $true
                DestinationPath =  "$InstallDir/tools/portalha/createstandbydb.bat.bak"
                DependsOn = $Depends
            }
            $Depends += '[File]CreatestandbydbBackupFileRemove'
        }
            
        ArcGIS_Install PortalUpgradeInstall
        { 
            Name = "Portal"
            Version = $Version
            Path = $InstallerPathOnMachine
            Arguments = "/qn INSTALLDIR=$($InstallDir) CONTENTDIR=$($ContentDir)"
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
			DependsOn       = $Depends
            DataDir         = $DataDirsForPortal
		}

        $Depends += '[ArcGIS_Service_Account]Portal_Service_Account'
        
        ArcGIS_Portal Portal
        {
            Ensure                                = 'Present'
            PortalEndPoint                        = $PortalEndpoint
            PortalContext                         = 'portal'
            LicenseFilePath                       = if($MajorVersion -ge 7){ (Join-Path $(Get-Location).Path $PortalLicenseFileName) } else {$null}
            UserLicenseType                       = if(($MajorVersion -ge 7) -and $PortalLicenseUserType){ $PortalLicenseUserType } else {$null}
            ExternalDNSName                       = $ExternalDNSHostName
            PortalAdministrator                   = $SiteAdministratorCredential 
            DependsOn                             = $Depends
            AdminEmail                            = 'portaladmin@admin.com'
            AdminSecurityQuestionIndex            = 1
            AdminSecurityAnswer                   = 'timbukto'
            Join                                  = $true
            IsHAPortal                            = $true
            PeerMachineHostName                   = $PeerMachineName
            ContentDirectoryLocation              = $ContentStoreLocation
            EnableDebugLogging                    = $IsDebugMode
            LogLevel                              = if($IsDebugMode) { 'DEBUG' } else { 'WARNING' }
            ContentDirectoryCloudConnectionString = $ContentDirectoryCloudConnectionString							
            ContentDirectoryCloudContainerName    = $ContentDirectoryCloudContainerName
        }          
    }
}