Configuration WebProxyConfiguration
{
	param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServiceCredential

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServiceCredentialIsDomainAccount = 'false'

        ,[Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $SiteAdministratorCredential

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $SSLCertificatePassword

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $SSLCertificateFileUrl

        ,[Parameter(Mandatory=$false)]        
        [System.Management.Automation.PSCredential]
        $SelfSignedSSLCertificatePassword
        
        ,[Parameter(Mandatory=$true)]
        [System.String]
        $PortalMachineNames

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $ServerMachineNames

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $WebProxyMachineNames
        
        ,[Parameter(Mandatory=$false)]
        [System.String]
        $PortalEndpoint

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServerEndpoint
                
        ,[Parameter(Mandatory=$true)]
        [System.String]
        $FileShareMachineName

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $ExternalDNSHostName   
        
        ,[Parameter(Mandatory=$false)]
        [System.Int32]
        $OSDiskSize = 0
        
        ,[Parameter(Mandatory=$false)]
        [System.String]
        $EnableDataDisk  

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $FileShareName = 'fileshare' 

        ,[Parameter(Mandatory=$false)]
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
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -name ArcGIS_WindowsService
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_IIS_TLS
    Import-DscResource -Name ArcGIS_ReverseProxy_ARR
    Import-DscResource -Name ArcGIS_Federation
    Import-DscResource -Name ArcGIS_TLSCertificateFileImport
    Import-DscResource -Name ArcGIS_xDisk
    Import-DscResource -Name ArcGIS_Disk
    Import-DscResource -Name ArcGIS_ServerSettings
    Import-DscResource -Name ArcGIS_PortalSettings
        
    $Pos = $PortalMachineNames.IndexOf(',')
    if($Pos -gt -1) {
        $PortalMachineNames = $PortalMachineNames.Substring(0, $Pos) # TEMP 
    }
    $ServerHostNames = ($ServerMachineNames -split ',')
    $ServerMachineName = $ServerHostNames | Select-Object -First 1
    $PortalHostNames = ($PortalMachineNames -split ',')
    $PortalMachineName = $PortalHostNames | Select-Object -First 1
    $IsDebugMode = $DebugMode -ieq 'true'
    $IsServiceCredentialDomainAccount = $ServiceCredentialIsDomainAccount -ieq 'true'

    if($SSLCertificateFileUrl) {
        $SSLCertificateFileName = Get-FileNameFromUrl $SSLCertificateFileUrl
        Invoke-WebRequest -OutFile $SSLCertificateFileName -Uri $SSLCertificateFileUrl -UseBasicParsing -ErrorAction Ignore
    }

    $ipaddress = (Resolve-DnsName -Name $FileShareMachineName -Type A -ErrorAction Ignore | Select-Object -First 1).IPAddress    
    if(-not($ipaddress)) { $ipaddress = $FileShareMachineName }
    $FileShareRootPath = "\\$FileShareMachineName\$FileShareName"    
    $ServerCertificateFileName  = 'SSLCertificateForServer.pfx'
    $ServerCertificateFileLocation = "\\$FileShareMachineName\$FileShareName\Certs\$ServerCertificateFileName"
    $ServerCertificateLocalFilePath =  (Join-Path $env:Temp $ServerCertificateFileName)
    $PortalCertificateFileName  = 'SSLCertificateForPortal.pfx'
    $PortalCertificateFileLocation = "\\$FileShareMachineName\$FileShareName\Certs\$PortalCertificateFileName"
    $PortalCertificateLocalFilePath =  (Join-Path $env:Temp $PortalCertificateFileName)

    $IsLastWebProxyMachine = ($env:ComputerName -ieq (($WebProxyMachineNames -split ',') | Select-Object -Last 1))
    
	Node localhost
	{
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $true
        }
        
        if($OSDiskSize -gt 0) 
        {
            ArcGIS_Disk OSDiskSize
            {
                DriveLetter = ($env:SystemDrive -replace ":" )
                SizeInGB    = $OSDiskSize
            }
        }
        
        if($EnableDataDisk -ieq 'true')
        {
            ArcGIS_xDisk DataDisk
            {
                DiskNumber  =  2
                DriveLetter = 'F'
            }
        }

        $Depends = @()
        $HasValidServiceCredential = ($ServiceCredential -and ($ServiceCredential.GetNetworkCredential().Password -ine 'Placeholder'))
        if($HasValidServiceCredential) 
        {
            if(-Not($IsServiceCredentialDomainAccount)){
                User ArcGIS_RunAsAccount
                {
                    UserName       = $ServiceCredential.UserName
                    Password       = $ServiceCredential
                    FullName       = 'ArcGIS Service Account'
                    Ensure         = 'Present'
                    PasswordChangeRequired = $false
                    PasswordNeverExpires = $true
                }
                $Depends += '[User]ArcGIS_RunAsAccount'
            }

            ArcGIS_xFirewall ReverseProxy_FirewallRules
            {
                Name                  = "IIS-ARR" 
                DisplayName           = "IIS-ARR" 
                DisplayGroup          = "IIS-ARR" 
                Ensure                = 'Present' 
                Access                = "Allow" 
                State                 = "Enabled" 
                Profile               = "Public"
                LocalPort             = ("80", "443")                        
                Protocol              = "TCP" 
            }
            
            Script CopyServerCertificateFileToLocalMachine
            {
                GetScript = {
                    $null
                }
                SetScript = {    
                    Write-Verbose "Copying from $using:ServerCertificateFileLocation to $using:ServerCertificateLocalFilePath"      
                    $PsDrive = New-PsDrive -Name W -Root $using:FileShareRootPath -PSProvider FileSystem                              
                    Copy-Item -Path $using:ServerCertificateFileLocation -Destination $using:ServerCertificateLocalFilePath -Force  
                    if($PsDrive) {
                        Write-Verbose "Removing Temporary Mapped Drive $($PsDrive.Name)"
                        Remove-PsDrive -Name $PsDrive.Name -Force       
                    }       
                }
                TestScript = {   
                    $false
                }
                DependsOn             = $Depends
                PsDscRunAsCredential  = $ServiceCredential # Copy as arcgis account which has access to this share
            }

            ArcGIS_TLSCertificateFileImport ImportServerCertificateFile
            {
                CertificatePath     = $ServerCertificateLocalFilePath
                StoreLocation       = 'LocalMachine'
                StoreName           = 'Root' 
                CertificatePassword = $SelfSignedSSLCertificatePassword 
			    Ensure              = 'Present' 
                DependsOn           = @('[Script]CopyServerCertificateFileToLocalMachine')
            }

            Script CopyPortalCertificateFileToLocalMachine
            {
                GetScript = {
                    $null
                }
                SetScript = {    
                    Write-Verbose "Copying from $using:PortalCertificateFileLocation to $using:PortalCertificateLocalFilePath"      
                    $PsDrive = New-PsDrive -Name W -Root $using:FileShareRootPath -PSProvider FileSystem                              
                    Copy-Item -Path $using:PortalCertificateFileLocation -Destination $using:PortalCertificateLocalFilePath -Force  
                    if($PsDrive) {
                        Write-Verbose "Removing Temporary Mapped Drive $($PsDrive.Name)"
                        Remove-PsDrive -Name $PsDrive.Name -Force       
                    }       
                }
                TestScript = {   
                    $false
                }
                DependsOn             = $Depends
                PsDscRunAsCredential  = $ServiceCredential # Copy as arcgis account which has access to this share
            }

            ArcGIS_TLSCertificateFileImport ImportPortalCertificateFile
            {
                CertificatePath     = $PortalCertificateLocalFilePath
                StoreLocation       = 'LocalMachine'
                StoreName           = 'Root'
                CertificatePassword = $SelfSignedSSLCertificatePassword  
                Ensure              = 'Present' 
                DependsOn           = @('[Script]CopyPortalCertificateFileToLocalMachine')
            }
        }

        ArcGIS_IIS_TLS IISHTTPS
        {
			WebSiteName             = 'Default Web Site'
            Ensure                  = 'Present'
            ExternalDNSName         = $ExternalDNSHostName                        
            CertificateFileLocation = (Join-Path $(Get-Location).Path $SSLCertificateFileName)
            CertificatePassword     = if($SSLCertificatePassword -and ($SSLCertificatePassword.GetNetworkCredential().Password -ine 'Placeholder')) { $SSLCertificatePassword } else { $null }
        }

        ArcGIS_ReverseProxy_ARR WebProxy
		{
			Ensure                      = 'Present'
			ServerSiteName              = 'arcgis'
			PortalSiteName              = 'arcgis'
			ServerHostNames             = $ServerHostNames
			PortalHostNames             = $PortalHostNames
			ExternalDNSName             = $ExternalDNSHostName
			PortalAdministrator         = $SiteAdministratorCredential
			SiteAdministrator           = $SiteAdministratorCredential
			ServerEndPoint              = $ServerEndpoint
			PortalEndPoint              = $PortalEndpoint
			EnableFailedRequestTracking = $IsDebugMode
			EnableGeoEventEndpoints     = $false
			DependsOn                   = @('[ArcGIS_IIS_TLS]IISHTTPS')						
		} 

        if($IsLastWebProxyMachine) 
        {
            ArcGIS_ServerSettings ServerSettings
            {
                ServerContext       = 'server'
                ServerHostName      = $ServerMachineName
                ServerEndPoint      = $ServerEndpoint #ExternalDNSHostName
                ServerEndPointPort  = 6443 #443
                ServerEndPointContext = 'arcgis' #server
                ExternalDNSName     = $ExternalDNSHostName
                SiteAdministrator   = $SiteAdministratorCredential
                DependsOn = @('[ArcGIS_Server]Server','[ArcGIS_ReverseProxy_ARR]WebProxy')
            }

            ArcGIS_PortalSettings PortalSettings
            {
                ExternalDNSName     = $ExternalDNSHostName
                PortalContext       = 'portal'
                PortalHostName      = $PortalMachineName
                PortalEndPoint      = $PortalEndpoint
                PortalEndPointPort    = 7443
                PortalEndPointContext = 'arcgis'
                PortalAdministrator = $SiteAdministratorCredential
                DependsOn = @('[ArcGIS_Portal]Portal','[ArcGIS_ReverseProxy_ARR]WebProxy')
            }
            
            ArcGIS_Federation Federation
            {
                PortalHostName =  (Get-FQDN $PortalMachineName)
                PortalPort = 7443
                PortalContext = 'arcgis'
                ServiceUrlHostName = $ExternalDNSHostName
                ServiceUrlContext = 'server'
                ServiceUrlPort = 443
                ServerSiteAdminUrlHostName = $ServerEndpoint
                ServerSiteAdminUrlPort = 6443
                ServerSiteAdminUrlContext ='arcgis'
                Ensure = "Present"
                RemoteSiteAdministrator = $SiteAdministratorCredential
                SiteAdministrator = $SiteAdministratorCredential
                ServerRole = 'HOSTING_SERVER'
                ServerFunctions = 'GeneralPurposeServer'
                IsMultiTierAzureBaseDeployment = $true
                DependsOn = @('[ArcGIS_PortalSettings]PortalSettings','[ArcGIS_ServerSettings]ServerSettings')
            }
        }

        foreach($ServiceToStop in @('ArcGIS Server', 'Portal for ArcGIS', 'ArcGIS Data Store', 'ArcGISGeoEvent', 'ArcGISGeoEventGateway', 'ArcGIS Notebook Server'))
		{
			if(Get-Service $ServiceToStop -ErrorAction Ignore) 
			{
				ArcGIS_WindowsService "$($ServiceToStop.Replace(' ','_'))_Service"
				{
					Name			= $ServiceToStop
					Credential		= $ServiceCredential
					StartupType		= 'Manual'
					State			= 'Stopped'
					DependsOn		= $Depends
				}
			}
		}
	}
}