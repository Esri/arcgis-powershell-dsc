Configuration ServerConfiguration
{
	param(
        [Parameter(Mandatory=$false)]
        [System.String]
        $Version = '11.1'

        ,[Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServiceCredential

        ,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount

        ,[Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $SiteAdministratorCredential

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServerContext = 'server'

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $UseCloudStorage 

         ,[Parameter(Mandatory=$false)]
        [System.String]
        $UseAzureFiles 

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $StorageAccountCredential
                
        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServerLicenseFileUrl

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $ServerMachineNames

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $PublicKeySSLCertificateFileUrl

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $ServerInternalCertificatePassword

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
        $EnableLogHarvesterPlugin

         ,[Parameter(Mandatory=$false)]
        [System.String]
        $FileShareName = 'fileshare'

        ,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $IsUpdatingCertificates = $False
        
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
	Import-DscResource -Name ArcGIS_License
	Import-DscResource -Name ArcGIS_Server
    Import-DscResource -Name ArcGIS_Server_TLS
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -name ArcGIS_WindowsService
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_xDisk
    Import-DscResource -Name ArcGIS_Disk
    Import-DscResource -Name ArcGIS_LogHarvester
    Import-DscResource -Name ArcGIS_ServerSettings
    
    ##
    ## Download license file and certificate files
    ##
    
    $ServerCertificateFileName  = 'SSLCertificateForServer.pfx'
    $ServerCertificateLocalFilePath =  (Join-Path $env:TEMP $ServerCertificateFileName)
    $ServerCertificateFileLocation = "\\$($FileShareMachineName)\$FileShareName\Certs\$ServerCertificateFileName"

    if($ServerLicenseFileUrl -and ($ServerLicenseFileUrl.Trim().Length -gt 0)) {
        $ServerLicenseFileName = Get-FileNameFromUrl $ServerLicenseFileUrl
        Invoke-WebRequest -OutFile $ServerLicenseFileName -Uri $ServerLicenseFileUrl -UseBasicParsing -ErrorAction Ignore
    }

    if($PublicKeySSLCertificateFileUrl){
		$PublicKeySSLCertificateFileName = Get-FileNameFromUrl $PublicKeySSLCertificateFileUrl
		Invoke-WebRequest -OutFile $PublicKeySSLCertificateFileName -Uri $PublicKeySSLCertificateFileUrl -UseBasicParsing -ErrorAction Ignore
	}
        
    $ServerHostName = ($ServerMachineNames -split ',') | Select-Object -First 1    
    $ipaddress = (Resolve-DnsName -Name $FileShareMachineName -Type A -ErrorAction Ignore | Select-Object -First 1).IPAddress    
    if(-not($ipaddress)) { $ipaddress = $FileShareMachineName }
    $FileShareRootPath = "\\$ipaddress\$FileShareName"
    $FolderName = $ExternalDNSHostName.Substring(0, $ExternalDNSHostName.IndexOf('.')).ToLower()
    $ConfigStoreLocation  = "\\$FileShareMachineName\$FileShareName\$FolderName\$($ServerContext)\config-store"
    $ServerDirsLocation   = "\\$FileShareMachineName\$FileShareName\$FolderName\$($ServerContext)\server-dirs" 

    $Join = ($env:ComputerName -ine $ServerHostName)
    $IsDebugMode = $DebugMode -ieq 'true'
    $IsMultiMachineServer = (($ServerMachineNames -split ',').Length -gt 1)

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
            $ConfigStoreLocation  = "\\$($AzureFilesEndpoint)\$FileShareName\$FolderName\$($ServerContext)\config-store"
            $ServerDirsLocation   = "\\$($AzureFilesEndpoint)\$FileShareName\$FolderName\$($ServerContext)\server-dirs"   
        }
        else {
            $ConfigStoreCloudStorageConnectionString = "NAMESPACE=$($Namespace)$($ServerContext)$($EndpointSuffix);DefaultEndpointsProtocol=https;AccountName=$AccountName"
            $ConfigStoreCloudStorageConnectionSecret = "AccountKey=$($StorageAccountCredential.GetNetworkCredential().Password)"
        }
    }    

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
                
        $HasValidServiceCredential = ($ServiceCredential -and ($ServiceCredential.GetNetworkCredential().Password -ine 'Placeholder'))
        if($HasValidServiceCredential) 
        {
            $ServerDependsOn = @()
            if(-not($IsUpdatingCertificates))
            {
                if(-Not($ServiceCredentialIsDomainAccount)){
                    User ArcGIS_RunAsAccount
                    {
                        UserName       = $ServiceCredential.UserName
                        Password       = $ServiceCredential
                        FullName       = 'ArcGIS Service Account'
                        Ensure         = 'Present'
                        PasswordChangeRequired = $false
                        PasswordNeverExpires = $true
                    }
                    $ServerDependsOn += '[User]ArcGIS_RunAsAccount'
                }

                if($ServerLicenseFileName -and ($ServerLicenseFileName.Trim().Length -gt 0)) 
                {
                    ArcGIS_License ServerLicense
                    {
                        LicenseFilePath = (Join-Path $(Get-Location).Path $ServerLicenseFileName)
                        Ensure          = 'Present'
                        Component       = 'Server'
                    } 
                    $ServerDependsOn += '[ArcGIS_License]ServerLicense'

                    ArcGIS_WindowsService ArcGIS_for_Server_Service
                    {
                        Name            = 'ArcGIS Server'
                        Credential      = $ServiceCredential
                        StartupType     = 'Automatic'
                        State           = 'Running' 
                        DependsOn       = $ServerDependsOn
                    }
                    $ServerDependsOn += '[ArcGIS_WindowsService]ArcGIS_for_Server_Service'

                    ArcGIS_Service_Account Server_Service_Account
                    {
                        Name            = 'ArcGIS Server'
                        RunAsAccount    = $ServiceCredential
                        IsDomainAccount = $ServiceCredentialIsDomainAccount
                        Ensure          = 'Present'
                        DependsOn       = $ServerDependsOn
                    }
                    $ServerDependsOn += '[ArcGIS_Service_Account]Server_Service_Account'
                
                    if($AzureFilesEndpoint -and $StorageAccountCredential -and ($UseAzureFiles -ieq 'True')) 
                    {
                        $filesStorageAccountName = $AzureFilesEndpoint.Substring(0, $AzureFilesEndpoint.IndexOf('.'))
                        $storageAccountKey       = $StorageAccountCredential.GetNetworkCredential().Password
                
                        Script PersistStorageCredentials
                        {
                            TestScript = { 
                                                $result = cmdkey "/list:$using:AzureFilesEndpoint"
                                                $result | ForEach-Object{Write-verbose -Message "cmdkey: $_" -Verbose}
                                                if($result -like '*none*')
                                                {
                                                    return $false
                                                }
                                                return $true
                                            }
                            SetScript = { $result = cmdkey "/add:$using:AzureFilesEndpoint" "/user:$using:filesStorageAccountName" "/pass:$using:storageAccountKey" 
                                            $result | ForEach-Object{Write-verbose -Message "cmdkey: $_" -Verbose}
                                        }
                            GetScript            = { return @{} }                  
                            DependsOn            = $ServerDependsOn
                            PsDscRunAsCredential = $ServiceCredential # This is critical, cmdkey must run as the service account to persist property
                        }
                        $ServerDependsOn += '[Script]PersistStorageCredentials'
                    } 

                    ArcGIS_xFirewall Server_FirewallRules
                    {
                        Name                  = "ArcGISServer"
                        DisplayName           = "ArcGIS for Server"
                        DisplayGroup          = "ArcGIS for Server"
                        Ensure                = 'Present'
                        Access                = "Allow"
                        State                 = "Enabled"
                        Profile               = ("Domain","Private","Public")
                        LocalPort             = ("6080","6443")
                        Protocol              = "TCP"
                    }
                    $ServerDependsOn += '[ArcGIS_xFirewall]Server_FirewallRules'

                    if($IsMultiMachineServer) 
                    {
                        ArcGIS_xFirewall Server_FirewallRules_Internal
                        {
                            Name                  = "ArcGISServerInternal"
                            DisplayName           = "ArcGIS for Server Internal RMI"
                            DisplayGroup          = "ArcGIS for Server"
                            Ensure                = 'Present'
                            Access                = "Allow"
                            State                 = "Enabled"
                            Profile               = ("Domain","Private","Public")
                            LocalPort             = ("4000-4004")
                            Protocol              = "TCP"
                        }
                        $ServerDependsOn += '[ArcGIS_xFirewall]Server_FirewallRules_Internal'
                    }
                    
                    ArcGIS_LogHarvester ServerLogHarvester
                    {
                        ComponentType = "Server"
                        EnableLogHarvesterPlugin = if($EnableLogHarvesterPlugin -ieq 'true'){$true}else{$false}
                        Version = $Version
                        LogFormat = "csv"
                        DependsOn = $ServerDependsOn
                    }

                    $ServerDependsOn += '[ArcGIS_LogHarvester]ServerLogHarvester'

                    ArcGIS_Server Server
                    {
                        Version                                 = $Version
                        Ensure                                  = 'Present'
                        SiteAdministrator                       = $SiteAdministratorCredential
                        ConfigurationStoreLocation              = $ConfigStoreLocation
                        DependsOn                               = $ServerDependsOn
                        ServerDirectoriesRootLocation           = $ServerDirsLocation
                        Join                                    = $Join
                        PeerServerHostName                      = $ServerHostName
                        LogLevel                                = if($IsDebugMode) { 'DEBUG' } else { 'WARNING' }
                        ConfigStoreCloudStorageConnectionString = $ConfigStoreCloudStorageConnectionString
                        ConfigStoreCloudStorageConnectionSecret = $ConfigStoreCloudStorageConnectionSecret
                    }
                    $ServerDependsOn += '[ArcGIS_Server]Server'
                }
            }
            
            if($IsUpdatingCertificates -or ($ServerLicenseFileName -and ($ServerLicenseFileName.Trim().Length -gt 0))){ #On add of new machine or update certificate op
                Script CopyCertificateFileToLocalMachine
                {
                    GetScript = {
                        $null
                    }
                    SetScript = {    
                        Write-Verbose "Copying from $using:ServerCertificateFileLocation to $using:ServerCertificateLocalFilePath"      
                        $PsDrive = New-PsDrive -Name X -Root $using:FileShareRootPath -PSProvider FileSystem                 
                        Write-Verbose "Mapped Drive $($PsDrive.Name) to $using:FileShareRootPath"              
                        Copy-Item -Path $using:ServerCertificateFileLocation -Destination $using:ServerCertificateLocalFilePath -Force  
                        if($PsDrive) {
                            Write-Verbose "Removing Temporary Mapped Drive $($PsDrive.Name)"
                            Remove-PsDrive -Name $PsDrive.Name -Force       
                        }       
                    }
                    TestScript = {   
                        $false
                    }
                    DependsOn             = if(-Not($ServiceCredentialIsDomainAccount) -and -not($IsUpdatingCertificates)){@('[User]ArcGIS_RunAsAccount')}else{@()}
                    PsDscRunAsCredential  = $ServiceCredential # Copy as arcgis account which has access to this share
                }
                $ServerDependsOn += '[Script]CopyCertificateFileToLocalMachine'

                ArcGIS_Server_TLS Server_TLS
                {
                    ServerHostName             = $env:ComputerName
                    SiteAdministrator          = $SiteAdministratorCredential                         
                    WebServerCertificateAlias  = "ApplicationGateway"
                    CertificateFileLocation    = $ServerCertificateLocalFilePath
                    CertificatePassword        = if($ServerInternalCertificatePassword -and ($ServerInternalCertificatePassword.GetNetworkCredential().Password -ine 'Placeholder')) { $ServerInternalCertificatePassword } else { $null }
                    ServerType                 = "GeneralPurposeServer"
                    DependsOn                  = $ServerDependsOn
                    SslRootOrIntermediate	   = if($PublicKeySSLCertificateFileName){ [string]::Concat('[{"Alias":"AppGW-ExternalDNSCerCert","Path":"', (Join-Path $(Get-Location).Path $PublicKeySSLCertificateFileName).Replace('\', '\\'),'"}]') }else{$null}
                }
                $ServerDependsOn += '[ArcGIS_Server_TLS]Server_TLS'
            }

            if($env:ComputerName -ieq $ServerHostName -and (-not($IsUpdatingCertificates) -and ($ServerLicenseFileName -and ($ServerLicenseFileName.Trim().Length -gt 0)))){ #On add of new machine and not on update certificate op, Perform on First machine
                ArcGIS_ServerSettings ServerSettings
                {
                    ServerContext       = $ServerContext
                    ServerHostName      = $ServerHostName
                    ExternalDNSName     = $ExternalDNSHostName
                    SiteAdministrator   = $SiteAdministratorCredential
                    DependsOn = $ServerDependsOn
                }
            }

            if(-not($IsUpdatingCertificates)){
                foreach($ServiceToStop in @('Portal for ArcGIS', 'ArcGIS Data Store', 'ArcGISGeoEvent', 'ArcGISGeoEventGateway', 'ArcGIS Notebook Server', 'ArcGIS Mission Server', 'WorkflowManager'))
                {
                    if(Get-Service $ServiceToStop -ErrorAction Ignore) 
                    {
                        Service "$($ServiceToStop.Replace(' ','_'))_Service"
                        {
                            Name			= $ServiceToStop
                            Credential		= $ServiceCredential
                            StartupType		= 'Manual'
                            State			= 'Stopped'
                            DependsOn		= if(-Not($ServiceCredentialIsDomainAccount)){@('[User]ArcGIS_RunAsAccount')}else{@()}
                        }
                    }
                }
            }
        }
	}
}
