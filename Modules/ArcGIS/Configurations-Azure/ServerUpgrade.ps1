Configuration ServerUpgrade{
    param(
        [System.String]
        $Version,

        [System.Management.Automation.PSCredential]
        $ServiceCredential,

        [Parameter(Mandatory=$false)]
        [System.String]
        $ServiceCredentialIsDomainAccount = 'false',

		[System.Management.Automation.PSCredential]
        $FileshareMachineCredential,

        [System.String]
        $ServerInstallerPath,

        [System.String]
        $ServerLicenseFileUrl,

		[System.String]
        $ServerRole,
        
		[Parameter(Mandatory=$false)]
        [System.String]
        $GeoEventServerInstallerPath = "",
		
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
    Import-DscResource -Name ArcGIS_Install 
    Import-DscResource -Name ArcGIS_License 
    Import-DscResource -Name ArcGIS_WindowsService 
    Import-DscResource -Name ArcGIS_ServerUpgrade 
    Import-DscResource -Name ArcGIS_NotebookServerUpgrade 

    $IsDebugMode = $DebugMode -ieq 'true'
    $IsServiceCredentialDomainAccount = $ServiceCredentialIsDomainAccount -ieq 'true'

    Node $AllNodes.NodeName {
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $true
        }

		$NodeName = $Node.NodeName

        $MachineFQDN = Get-FQDN $NodeName
        
        $Depends = @()
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

		$InstallerFileName = Split-Path $ServerInstallerPath -Leaf
		$InstallerPathOnMachine = "$env:TEMP\Server\$InstallerFileName"

		File DownloadInstallerFromFileShare      
		{            	
			Ensure = "Present"              	
			Type = "File"             	
			SourcePath = $ServerInstallerPath 	
			DestinationPath = $InstallerPathOnMachine     
			Credential = $FileshareMachineCredential     
			DependsOn = $Depends  
		}

        $Depends += '[File]DownloadInstallerFromFileShare'

        ArcGIS_WindowsService ArcGIS_GeoEvent_Service_Stop
        {
            Name = 'ArcGISGeoEvent'
            Credential = $ServiceCredential
            StartupType = 'Manual'
            State = 'Stopped'
            DependsOn = $Depends
        }
        $Depends += "[ArcGIS_WindowsService]ArcGIS_GeoEvent_Service_Stop"

        if(Get-Service 'ArcGISGeoEventGateway' -ErrorAction Ignore) 
        {
            ArcGIS_WindowsService ArcGIS_GeoEventGateway_Service
            {
                Name		= 'ArcGISGeoEventGateway'
                Credential  = $ServiceCredential
                StartupType = 'Manual'
                State = 'Stopped'
                DependsOn   = $Depends
            }
            $Depends += "[ArcGIS_WindowsService]ArcGIS_GeoEventGateway_Service"
        }
      
        ArcGIS_Install ServerUpgrade{
            Name = if($ServerRole -ieq "NotebookServer"){ "NotebookServer" }else{ "Server" } 
            Version = $Version
            Path = $InstallerPathOnMachine
            Arguments = "/qb USER_NAME=$($ServiceCredential.UserName) PASSWORD=$($ServiceCredential.GetNetworkCredential().Password)";
            Ensure = "Present"
            DependsOn = $Depends
        }

        $Depends += '[ArcGIS_Install]ServerUpgrade'
        
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
		
        if(-not($ServerRole) -or ($ServerRole -ieq "GeoEventServer")){
            $ServerRole = "GeneralPurposeServer"
        }
        if($ServerRole -ieq "RasterAnalytics" -or $ServerRole -ieq "ImageHosting"){
            $ServerRole = "ImageServer"
        }
        
		## Download license file
		if($ServerLicenseFileUrl) {
			$ServerLicenseFileName = Get-FileNameFromUrl $ServerLicenseFileUrl
			Invoke-WebRequest -OutFile $ServerLicenseFileName -Uri $ServerLicenseFileUrl -UseBasicParsing -ErrorAction Ignore
		}   

		ArcGIS_License ServerLicense
        {
            LicenseFilePath = (Join-Path $(Get-Location).Path $ServerLicenseFileName)
            Ensure = 'Present'
            Component = "Server"
            ServerRole = $ServerRole
            Force = $True
            DependsOn = $Depends
        }

        $Depends += '[ArcGIS_License]ServerLicense'
        
        if($ServerRole -ieq "NotebookServer"){
            #For Notebook Server at the end of install use the Configure app to finish the upgrade process.
            ArcGIS_NotebookServerUpgrade NotebookServerConfigureUpgrade{
                Ensure = "Present"
                Version = $Version
                ServerHostName = $MachineFQDN
                DependsOn = $Depends
            }
        }else{
            ArcGIS_ServerUpgrade ServerConfigureUpgrade{
                Ensure = "Present"
                Version = $Version
                ServerHostName = $MachineFQDN
                DependsOn = $Depends
            }
        }

        #Upgrade GeoEvents
        if($ServerRole -ieq "GeoEvent"){
            $Depends += '[ArcGIS_ServerUpgrade]ServerConfigureUpgrade'
            
            Script ArcGIS_GeoEvent_Service_Stop_for_Upgrade
            {
                TestScript  = {  return $false }
                SetScript   = { 
                    @('ArcGISGeoEvent', 'ArcGISGeoEventGateway') | ForEach-Object{
                        $ServiceName = $_
                        Write-Verbose "Stopping the service '$ServiceName'"    
                        Stop-Service -Name $ServiceName -ErrorAction Ignore    
                        Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Stopped'
                    }
                }
                GetScript   = { return @{} }                  
                DependsOn   = $Depends
            }
            $ServerDependsOn += '[Script]ArcGIS_GeoEvent_Service_Stop_for_Upgrade'

            ArcGIS_Install GeoEventServerUpgrade{
                Name = "GeoEvent"
                Version = $Version
                Path = $GeoEventServerInstallerPath
                Arguments = "/qb PASSWORD=$($ServiceAccount.GetNetworkCredential().Password)";
                Ensure = "Present"
                DependsOn = $Depends
            }

            # ArcGIS_xFirewall GeoEventService_Firewall
            # {
            #     Name                  = "ArcGISGeoEventGateway"
            #     DisplayName           = "ArcGIS GeoEvent Gateway"
            #     DisplayGroup          = "ArcGIS GeoEvent Gateway"
            #     Ensure                = 'Present'
            #     Access                = "Allow"
            #     State                 = "Enabled"
            #     Profile               = ("Domain","Private","Public")
            #     LocalPort             = ("9092")
            #     Protocol              = "TCP"
            #     DependsOn             = $Depends
            # }
            # $Depends += "[ArcGIS_xFirewall]GeoEventService_Firewall"
            
            ArcGIS_WindowsService ArcGIS_GeoEvent_Service_Start
            {
                Name = 'ArcGISGeoEvent'
                Credential = $ServiceCredential
                StartupType = 'Automatic'
                State = 'Running'
                DependsOn = $Depends
            }

            if(Get-Service 'ArcGISGeoEventGateway' -ErrorAction Ignore) 
            {
                ArcGIS_WindowsService ArcGIS_GeoEventGateway_Service
                {
                    Name		= 'ArcGISGeoEventGateway'
                    Credential  = $ServiceCredential
                    StartupType = 'Automatic'
                    State       = 'Running'
                    DependsOn   = $Depends
                }
                $Depends += "[ArcGIS_WindowsService]ArcGIS_GeoEventGateway_Service"
            }
        }
    }
}