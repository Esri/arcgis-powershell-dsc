Configuration PortalPrimaryUpgrade{

    param(
        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $true)]        
        [System.String]
        $InstallerPath,
        
        [parameter(Mandatory = $true)]
        [System.String]
        $Context,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $ServiceAccount,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $PrimarySiteAdmin,

        [parameter(Mandatory = $true)]
        [System.String]
        $LicensePath,
        
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

        [parameter(Mandatory = $false)]
        [System.String]
        $FileShareMachine,

        [parameter(Mandatory = $false)]
        [System.String]
        $FileShareName
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName ArcGIS 
    Import-DscResource -Name ArcGIS_Install 
    Import-DscResource -Name ArcGIS_License 
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -Name ArcGIS_Portal 

    Node $AllNodes.NodeName {
        $NodeName = $Node.NodeName

        $MachineFQDN = [System.Net.DNS]::GetHostByName($NodeName).HostName
        $StandbyMachine = [System.Net.DNS]::GetHostByName($StandbyMachineName).HostName
        
        $Depends = @()

        User ArcGIS_RunAsAccount
        {
            UserName = $ServiceAccount.UserName
            Password = $ServiceAccount
            FullName = 'ArcGIS Run As Account'
            Ensure = "Present"
        }

        if($IsMultiMachinePortal){
            $PSAUserName = $PrimarySiteAdmin.UserName
            $PSAPassword = $PrimarySiteAdmin.GetNetworkCredential().Password
            Script UnregisterPortal
            {
                GetScript = {
                    $null
                }
                TestScript = 
                {                
                    $Referer = 'http://localhost'
                    $token = Get-PortalToken -PortalHostName $using:MachineFQDN -SiteName 'arcgis' -UserName $using:PSAUserName  `
                        -Password $using:PSAPassword -Referer $Referer
                    
                    $Machines = Invoke-ArcGISWebRequest -Url ("https://$($using:MachineFQDN):7443/arcgis/portaladmin/machines") -HttpFormParameters @{ f = 'json'; token = $token.token; } -Referer $Referer -HttpMethod 'GET'
                    $StandbyFlag = $false
                    ForEach($m in $Machines){
                        if($using:StandbyMachine -ieq $m){
                            $StandbyFlag = $true
                            break;
                        }
                    }

                    -not($StandbyFlag)
                }
                SetScript =
                {
                    $Referer = 'http://localhost'
                    $token = Get-PortalToken -PortalHostName $using:MachineFQDN -SiteName 'arcgis' -UserName $using:PSAUserName  `
                        -Password $using:PSAPassword -Referer $Referer

                    $FormParameters = @{ f = 'json'; token = $Token; machineName = $using:StandbyMachine }
                    Invoke-ArcGISWebRequest -Url ("https://$($using:MachineFQDN):7443/arcgis/portaladmin/machines/unregister") -HttpFormParameters $FormParameters -Referer $Referer -HttpMethod 'POST'
                    
                    Start-Sleep -Seconds 180
                }
            }
        }

        ArcGIS_Install PortalUpgrade
        { 
            Name = "Portal"
            Version = $Version
            Path = $InstallerPath
            Arguments = "/qb USER_NAME=$($ServiceAccount.UserName) PASSWORD=$($ServiceAccount.GetNetworkCredential().Password)";
            Ensure = "Present"
        }

        ArcGIS_License PortalLicense
        {
            LicenseFilePath = $LicensePath
            Ensure = "Present"
            Component = 'Portal'
            DependsOn = '[ArcGIS_Install]PortalUpgrade'
        }

        Service Portal_for_ArcGIS_Service
        {
            Name = 'Portal for ArcGIS'
            Credential = $ServiceAccount
            StartupType = 'Automatic'
            State = 'Running'          
            DependsOn = @('[User]ArcGIS_RunAsAccount')
        } 

        $ContentDirectoryLocation = $ContentDirectoryLocation
        if($FileShareMachine -and $FileShareName) 
        {
            $ContentDirectoryLocation = "\\$($FileShareMachine)\$($FileShareName)\$($ContentDirectoryLocation)"
        }    

        $ServiceAccountsDepends =  @('[User]ArcGIS_RunAsAccount', '[Service]Portal_for_ArcGIS_Service')
        $DataDirsForPortal = @('HKLM:\SOFTWARE\ESRI\Portal for ArcGIS')

        ArcGIS_Service_Account Portal_RunAs_Account
        {
            Name = 'Portal for ArcGIS'
            RunAsAccount = $ServiceAccount
            Ensure = "Present"
            DataDir = $DataDirsForPortal
            DependsOn = $ServiceAccountsDepends
        }

        $Depends += @("[ArcGIS_License]PortalLicense",'[ArcGIS_Service_Account]Portal_RunAs_Account')
        ArcGIS_Portal Portal
        {
            Ensure = 'Present'
            PortalContext = $Context
            PortalAdministrator = $PrimarySiteAdmin 
            DependsOn = $Depends
            AdminEMail = $PrimarySiteAdminEmail
            AdminSecurityQuestionIndex = 1
            AdminSecurityAnswer = "vanilla"
            ContentDirectoryLocation = $ContentDirectoryLocation
            Join = $false
            IsHAPortal =  if($IsMultiMachinePortal){$True}else{$False}
            ExternalDNSName = $ExternalDNSName
            PortalEndPoint = $MachineFQDN
            PeerMachineHostName = ""
            EnableDebugLogging = $True
            UpgradeReindex = $True
        } 

    }

}