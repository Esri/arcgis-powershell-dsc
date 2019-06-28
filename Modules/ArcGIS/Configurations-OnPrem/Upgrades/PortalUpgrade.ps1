Configuration PortalUpgrade{
    param(
        [parameter(Mandatory = $true)]
        [System.String]
        $OldVersion,

        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $true)]
        [System.String]
        $PrimaryPortalMachine,
        
        [parameter(Mandatory = $false)]
        [System.String]
        $StandbyMachineName,

        [parameter(Mandatory = $true)]        
        [System.String]
        $InstallerPath,

        [parameter(Mandatory = $false)]        
        [System.String]
        $WebStylesInstallerPath,

        [parameter(Mandatory = $false)]
        [System.String]
        $InstallDir,

        [parameter(Mandatory = $false)]
        [System.String]
        $ContentDir,

        [parameter(Mandatory = $true)]
        [System.String]
        $PrimaryLicensePath,

        [parameter(Mandatory = $false)]
        [System.String]
        $PrimaryLicensePassword,
        
        [parameter(Mandatory = $false)]
        [System.String]
        $StandbyLicensePath,

        [parameter(Mandatory = $false)]
        [System.String]
        $StandbyLicensePassword,
        
        [parameter(Mandatory = $true)]
        [System.String]
        $Context,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $ServiceAccount,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsSADomainAccount = $False,

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
        $ExternalDNSName,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $IsMultiMachinePortal = $False,

        [System.String]
        $SevenZipInstallerPath = $null,

        [System.String]
        $SevenZipInstallerDir = $null<#,

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
        $PrimaryPortalHostName = [System.Net.DNS]::GetHostByName($PrimaryPortalMachine).HostName
        $StandbyMachine = [System.Net.DNS]::GetHostByName($StandbyMachineName).HostName
        $VersionArray = $Version.Split(".")
        $MajorVersion = $VersionArray[1]
        $MinorVersion = if($VersionArray.Length -gt 2){ $VersionArray[2] }else{ 0 }
       
        $Depends = @()

        if(-not($IsSADomainAccount)){
            User ArcGIS_RunAsAccount
            {
                UserName = $ServiceAccount.UserName
                Password = $ServiceAccount
                FullName = 'ArcGIS Run As Account'
                Ensure = "Present"
            }
            $Depends += '[User]ArcGIS_RunAsAccount'
        }


        if($MachineFQDN -ieq $PrimaryPortalHostName){
        
            if($IsMultiMachinePortal){
    
                ArcGIS_PortalUnregister UnregisterStandyPortal
                {
                    PortalEndPoint = $MachineFQDN
                    PrimarySiteAdmin = $PrimarySiteAdmin
                    StandbyMachine = $StandbyMachine
                    Version = $Version
                }
    
                $Depends += '[ArcGIS_PortalUnregister]UnregisterStandyPortal'
            }
            
            ArcGIS_Install PortalUpgrade
            { 
                Name = "Portal"
                Version = $Version
                Path = $InstallerPath
                Arguments = "/qb USER_NAME=$($ServiceAccount.UserName) PASSWORD=$($ServiceAccount.GetNetworkCredential().Password)";
                Ensure = "Present"
                SevenZipMsiInstallerPath = $SevenZipInstallerPath
                SevenZipInstallDir = $SevenZipInstallerDir
                DependsOn = $Depends
            }
            
            $Depends += '[ArcGIS_Install]PortalUpgrade'

            if((($MajorVersion -eq 7 -and $MinorVersion -eq 1) -or ($MajorVersion -ge 8)) -and $WebStylesInstallerPath){
                ArcGIS_Install "WebStylesInstall"
                { 
                    Name = "WebStyles"
                    Version = $Version
                    Path = $WebStylesInstallerPath
                    Arguments = "/qb"
                    SevenZipMsiInstallerPath = $SevenZipInstallerPath
                    SevenZipInstallDir = $SevenZipInstallerDir
                    Ensure = "Present"
                    DependsOn = $Depends
                }

                $Depends += '[ArcGIS_Install]WebStylesInstall'
            }
            
            if($PrimaryLicensePath -and ($MajorVersion -lt 7)) 
            {
                ArcGIS_License PortalLicense
                {
                    LicenseFilePath = $PrimaryLicensePath
                    Password = $PrimaryLicensePassword
                    Ensure = "Present"
                    Component = 'Portal'
                    DependsOn = $Depends
                }
                $Depends += '[ArcGIS_License]PortalLicense'
            }

            Service Portal_for_ArcGIS_Service
            {
                Name = 'Portal for ArcGIS'
                Credential = $ServiceAccount
                StartupType = 'Automatic'
                State = 'Running'          
                DependsOn = $Depends
            } 
            
            $Depends += '[Service]Portal_for_ArcGIS_Service'
            
            <#$ContentDirectoryLocation = $ContentDirectoryLocation
            if($FileShareMachine -and $FileShareName) 
            {
                #$ContentDirectoryLocation = "\\$($FileShareMachine)\$($FileShareName)\$($ContentDirectoryLocation)"
            }#>    
            
            $DataDirsForPortal = @('HKLM:\SOFTWARE\ESRI\Portal for ArcGIS')
            
            ArcGIS_Service_Account Portal_RunAs_Account
            {
                Name = 'Portal for ArcGIS'
                RunAsAccount = $ServiceAccount
                Ensure = "Present"
                DataDir = $DataDirsForPortal
                DependsOn =  $Depends
                IsDomainAccount = $IsSADomainAccount
            }
            $Depends += '[ArcGIS_Service_Account]Portal_RunAs_Account'
    
            if($MajorVersion -gt 5){
                ArcGIS_PortalUpgrade PortalUpgrade
                {
                    PortalAdministrator = $PrimarySiteAdmin 
                    PortalHostName = $MachineFQDN
                    LicenseFilePath = if($MajorVersion -ge 7){ $PrimaryLicensePath }else{ $null }
                    DependsOn = $Depends
                }
                $Depends += '[ArcGIS_PortalUpgrade]PortalUpgrade'
            }else{
                ArcGIS_Portal PortalUpgrade
                {
                    Ensure = 'Present'
                    PortalEndPoint = $MachineFQDN
                    PortalContext = $Context
                    PortalAdministrator = $PrimarySiteAdmin 
                    DependsOn = $Depends
                    AdminEmail = $PrimarySiteAdminEmail
                    AdminSecurityQuestionIndex = $ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.SecurityQuestionIndex
                    AdminSecurityAnswer = $ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.SecurityAnswer
                    ContentDirectoryLocation = $ContentDirectoryLocation
                    Join = $false
                    IsHAPortal =  if($IsMultiMachinePortal){$True}else{$False}
                    ExternalDNSName = $ExternalDNSName
                    PeerMachineHostName = ""
                    EnableDebugLogging = $True
                    UpgradeReindex = $True
                } 
                $Depends += '[ArcGIS_Portal]PortalUpgrade'
            }   
        }elseif($MachineFQDN -ieq $StandbyMachine){
            
            ArcGIS_WaitForComponent "WaitForUnregisterStandbyPortal"{
                Component = "UnregisterPortal"
                InvokingComponent = "PortalUpgrade"
                ComponentHostName = $PrimaryPortalHostName
                ComponentContext =  "arcgis"
                Ensure = "Present"
                Credential =  $PrimarySiteAdmin
                RetryIntervalSec = 60
                RetryCount = 60
            }

            ArcGIS_Install PortalUninstallStandby
            { 
                Name = "Portal"
                Version = $OldVersion
                Path = $InstallerPath
                Arguments = "/qn INSTALLDIR=$($InstallDir) CONTENTDIR=$($ContentDir)";
                Ensure = "Absent"
                DependsOn = $Depends
            }
            $Depends += '[ArcGIS_Install]PortalUninstallStandby'
            
            $PortalName = (get-wmiobject Win32_Product| Where-Object {$_.Name -match "Portal" -and $_.Vendor -eq 'Environmental Systems Research Institute, Inc.'}).Name
            # This will likely fail if querying a remote machine, need to find a better solution for this.
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

            ArcGIS_Install PortalInstall
            { 
                Name = "Portal"
                Version = $Version
                Path = $InstallerPath
                Arguments = "/qn INSTALLDIR=$($InstallDir) CONTENTDIR=$($ContentDir)"
                Ensure = "Present"
                SevenZipMsiInstallerPath = $SevenZipInstallerPath
                SevenZipInstallDir = $SevenZipInstallerDir
                DependsOn = $Depends
            }
            $Depends += "[ArcGIS_Install]PortalInstall"

            if((($MajorVersion -eq 7 -and $MinorVersion -eq 1) -or ($MajorVersion -ge 8)) -and $WebStylesInstallerPath){
                ArcGIS_Install "WebStylesInstall"
                { 
                    Name = "WebStyles"
                    Version = $Version
                    Path = $WebStylesInstallerPath
                    Arguments = "/qb"
                    SevenZipMsiInstallerPath = $SevenZipInstallerPath
                    SevenZipInstallDir = $SevenZipInstallerDir
                    Ensure = "Present"
                    DependsOn = $Depends
                }

                $Depends += '[ArcGIS_Install]WebStylesInstall'
            }
            
            if($MajorVersion -lt 7){
                ArcGIS_License PortalLicense
                {
                    LicenseFilePath = $StandbyLicensePath
                    Password = $StandbyLicensePassword
                    Ensure = "Present"
                    Component = 'Portal'
                    DependsOn = $Depends
                }
                $Depends += '[ArcGIS_License]PortalLicense'
            }
            
            Service Portal_for_ArcGIS_Service
            {
                Name = 'Portal for ArcGIS'
                Credential = $ServiceAccount
                StartupType = 'Automatic'
                State = 'Running'          
                DependsOn = $Depends
            }
            $Depends += '[Service]Portal_for_ArcGIS_Service'
            
            $DataDirsForPortal = @('HKLM:\SOFTWARE\ESRI\Portal for ArcGIS')
            
            ArcGIS_Service_Account Portal_RunAs_Account
            {
                Name = 'Portal for ArcGIS'
                RunAsAccount = $ServiceAccount
                Ensure = "Present"
                DataDir = $DataDirsForPortal
                DependsOn = $Depends
                IsDomainAccount = $IsSADomainAccount
            }
            $Depends += '[ArcGIS_Service_Account]Portal_RunAs_Account'           
        }        
    }
}