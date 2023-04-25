Configuration ArcGISPortal
{
    param(
        [Parameter(Mandatory=$True)]
        [System.String]
        $Version,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServiceCredential,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ForceServiceCredentialUpdate = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsMSA = $false,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $PortalAdministratorCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $PrimaryPortalMachine,

        [Parameter(Mandatory=$False)]
        [System.String]
        $ContentDirectoryLocation,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AdminEmail,

        [Parameter(Mandatory=$False)]
        [System.String]
		$AdminFullName,

        [Parameter(Mandatory=$False)]
        [System.String]
		$AdminDescription,

        [Parameter(Mandatory=$False)]
        [System.Byte]
        $AdminSecurityQuestionIndex,
        
        [Parameter(Mandatory=$False)]
        [System.String]
        $AdminSecurityAnswer,

        [Parameter(Mandatory=$False)]
        [System.String]
        $LicenseFilePath,

        [Parameter(Mandatory=$False)]
        [System.String]
        $UserLicenseTypeId,

        [Parameter(Mandatory=$False)]
        [ValidateSet("AzureFiles","AzureBlob","AWSS3DynamoDB")]
        [AllowNull()] 
        [System.String]
        $CloudStorageType,

        [System.String]
        $AzureFileShareName,

        [System.String]
        $CloudNamespace,

        [System.String]
        $AWSRegion,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $CloudStorageCredentials,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $EnableHSTS = $False,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $UsesSSL = $False,
        
        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $DebugMode = $False
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.1.0 
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_Portal
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DscResource -Name ArcGIS_WaitForComponent

    if($null -ne $CloudStorageType)
    {
        if($CloudStorageType -ieq 'AWSS3DynamoDB') {
            $ContentDirectoryCloudConnectionString = "NAMESPACE=$($CloudNamespace);REGION=$($AWSRegion);"
            if($null -ne $CloudStorageCredentials){
                $ContentDirectoryCloudConnectionString += "ACCESS_KEY_ID=$($CloudStorageCredentials.UserName);SECRET_KEY=$($CloudStorageCredentials.GetNetworkCredential().Password)"
            }
        }else{
            if($null -ne $CloudStorageCredentials){
                $AccountName = $CloudStorageCredentials.UserName
                $EndpointSuffix = ''
                $Pos = $CloudStorageCredentials.UserName.IndexOf('.blob.')
                if($Pos -gt -1) {
                    $AccountName = $CloudStorageCredentials.UserName.Substring(0, $Pos)
                    $EndpointSuffix = $CloudStorageCredentials.UserName.Substring($Pos + 6) # Remove the hostname and .blob. suffix to get the storage endpoint suffix
                    $EndpointSuffix = ";EndpointSuffix=$($EndpointSuffix)"
                }
        
                if($CloudStorageType -ieq 'AzureFiles') {
                    $AzureFilesEndpoint = if($Pos -gt -1){$CloudStorageCredentials.UserName.Replace('.blob.','.file.')}else{$CloudStorageCredentials.UserName}
                    $AzureFileShareName = $AzureFileShareName.ToLower() # Azure file shares need to be lower case
                    $ContentDirectoryLocation = "\\$($AzureFilesEndpoint)\$AzureFileShareName\$($CloudNamespace)\portal\content"    
                }
                else {
                    $AccountKey = $CloudStorageCredentials.GetNetworkCredential().Password
                    $ContentDirectoryCloudConnectionString = "DefaultEndpointsProtocol=https;AccountName=$($AccountName);AccountKey=$($AccountKey)$($EndpointSuffix)"
                    $ContentDirectoryCloudContainerName = "arcgis-portal-content-$($CloudNamespace)portal"
                }
            }
        }
    }


    Node $AllNodes.NodeName
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        $IsMultiMachinePortal = (($AllNodes | Measure-Object).Count -gt 1)
        
        $Depends = @()
        ArcGIS_xFirewall Portal_FirewallRules
        {
            Name                  = "PortalforArcGIS" 
            DisplayName           = "Portal for ArcGIS" 
            DisplayGroup          = "Portal for ArcGIS" 
            Ensure                = 'Present'
            Access                = "Allow" 
            State                 = "Enabled" 
            Profile               = ("Domain","Private","Public")
            LocalPort             = ("7080","7443","7654")                         
            Protocol              = "TCP" 
        }
        $Depends += @('[ArcGIS_xFirewall]Portal_FirewallRules')
        
        if($IsMultiMachinePortal) 
        {
            ArcGIS_xFirewall Portal_Database_OutBound
            {
                Name                  = "PortalforArcGIS-Outbound" 
                DisplayName           = "Portal for ArcGIS Outbound" 
                DisplayGroup          = "Portal for ArcGIS Outbound" 
                Ensure                = 'Present' 
                Access                = "Allow" 
                State                 = "Enabled" 
                Profile               = ("Domain","Private","Public")
                RemotePort            = ("7120","7220", "7005", "7099", "7199", "5701", "5702", "5703")  # Elastic Search uses 7120,7220 and Postgres uses 7654 for replication, Hazelcast uses 5701 and 5702 (extra 2 ports for situations where unable to get port)
                Direction             = "Outbound"                       
                Protocol              = "TCP" 
            }  
            $Depends += @('[ArcGIS_xFirewall]Portal_Database_OutBound')
            
            ArcGIS_xFirewall Portal_Database_InBound
            {
                Name                  = "PortalforArcGIS-Inbound" 
                DisplayName           = "Portal for ArcGIS Inbound" 
                DisplayGroup          = "Portal for ArcGIS Inbound" 
                Ensure                = 'Present' 
                Access                = "Allow" 
                State                 = "Enabled" 
                Profile               = ("Domain","Private","Public")
                LocalPort             = ("7120","7220","5701", "5702", "5703")  # Elastic Search uses 7120,7220, Hazelcast uses 5701 and 5702
                Protocol              = "TCP" 
            }  
            $Depends += @('[ArcGIS_xFirewall]Portal_Database_InBound')
        }

        $DataDirsForPortal = @('HKLM:\SOFTWARE\ESRI\Portal for ArcGIS')
        if($ContentDirectoryLocation -and (-not($ContentDirectoryLocation.StartsWith('\'))) -and ($CloudStorageType -ne 'AzureFiles'))
        {
            $DataDirsForPortal += $ContentDirectoryLocation
            $DataDirsForPortal += (Split-Path $ContentDirectoryLocation -Parent)

            File ContentDirectoryLocation
            {
                Ensure = "Present"
                DestinationPath = $ContentDirectoryLocation
                Type = 'Directory'
                DependsOn = $Depends
            }  
            $Depends += "[File]ContentDirectoryLocation"
        }

        ArcGIS_Service_Account Portal_RunAs_Account
        {
            Name            = 'Portal for ArcGIS'
            RunAsAccount    = $ServiceCredential
            ForceRunAsAccountUpdate = $ForceServiceCredentialUpdate
            SetStartupToAutomatic = $True
            Ensure          = "Present"
            DataDir         = $DataDirsForPortal
            DependsOn       = $Depends
            IsDomainAccount = $ServiceCredentialIsDomainAccount
            IsMSAAccount    = $ServiceCredentialIsMSA
        }
        
        $Depends += @('[ArcGIS_Service_Account]Portal_RunAs_Account')

        if(-not($ServiceCredentialIsMSA) -and $AzureFilesEndpoint -and $CloudStorageCredentials -and ($CloudStorageType -ieq 'AzureFiles')) 
        {
            $FilesStorageAccountName = $AzureFilesEndpoint.Substring(0, $AzureFilesEndpoint.IndexOf('.'))
            $StorageAccountKey       = $CloudStorageCredentials.GetNetworkCredential().Password
      
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
                SetScript = { 
                                $result = cmdkey "/add:$using:AzureFilesEndpoint" "/user:$using:FilesStorageAccountName" "/pass:$using:StorageAccountKey" 
                                $result | ForEach-Object{Write-verbose -Message "cmdkey: $_" -Verbose}
                            }
                GetScript            = { return @{} }                  
                DependsOn            = $Depends
                PsDscRunAsCredential = $ServiceCredential # This is critical, cmdkey must run as the service account to persist property
            }              
            $Depends += '[Script]PersistStorageCredentials'

            $RootPathOfFileShare = "\\$($AzureFilesEndpoint)\$AzureFileShareName"
            Script CreatePortalContentFolder
            {
                TestScript = { 
                                Test-Path $using:ContentDirectoryLocation
                            }
                SetScript = {                   
                                Write-Verbose "Mount to $using:RootPathOfFileShare"
                                $DriveInfo = New-PSDrive -Name 'Z' -PSProvider FileSystem -Root $using:RootPathOfFileShare
                                if(-not(Test-Path $using:ContentDirectoryLocation)) {
                                    Write-Verbose "Creating folder $using:ContentDirectoryLocation"
                                    New-Item $using:ContentDirectoryLocation -ItemType directory
                                }else {
                                    Write-Verbose "Folder '$using:ContentDirectoryLocation' already exists"
                                }
                            }
                GetScript            = { return @{} }     
                DependsOn            = $Depends
                PsDscRunAsCredential = $ServiceCredential # This is important, only arcgis account has access to the file share on AFS
            }             
            $Depends += '[Script]CreatePortalContentFolder'
        }else{
            Write-Verbose "For MSA we assume these steps have been done independent of the module."
        }

        if($Node.NodeName -ine $PrimaryPortalMachine)
        {
            if($UsesSSL){
                ArcGIS_WaitForComponent "WaitForPortal$($PrimaryPortalMachine)"{
                    Component = "Portal"
                    InvokingComponent = "Portal"
                    ComponentHostName = $PrimaryPortalMachine
                    ComponentContext = "arcgis"
                    Credential = $PortalAdministratorCredential
                    Ensure = "Present"
                    RetryIntervalSec = 60
                    RetryCount = 100
                }
                $Depends += "[ArcGIS_WaitForComponent]WaitForPortal$($PrimaryPortalMachine)"
            }else{
                WaitForAll "WaitForAllPortal$($PrimaryPortalMachine)"{
                    ResourceName = "[ArcGIS_Portal]Portal$($PrimaryPortalMachine)"
                    NodeName = $PrimaryPortalMachine
                    RetryIntervalSec = 60
                    RetryCount = 90
                    DependsOn = $Depends
                }
                $Depends += "[WaitForAll]WaitForAllPortal$($PrimaryPortalMachine)"
            }
        }   
        
        ArcGIS_Portal "Portal$($Node.NodeName)"
        {
            Ensure = 'Present'
            Version = $Version
            PortalHostName = $Node.NodeName
            LicenseFilePath = $LicenseFilePath
            UserLicenseTypeId = $UserLicenseTypeId
            PortalAdministrator = $PortalAdministratorCredential 
            AdminEmail = $AdminEmail
            AdminFullName = $AdminFullName
            AdminDescription = $AdminDescription
            AdminSecurityQuestionIndex = $AdminSecurityQuestionIndex
            AdminSecurityAnswer = $AdminSecurityAnswer
            ContentDirectoryLocation = $ContentDirectoryLocation
            Join = if($Node.NodeName -ine $PrimaryPortalMachine) { $true } else { $false } 
            IsHAPortal = if($IsMultiMachinePortal){ $true } else { $false }
            PeerMachineHostName = if($Node.NodeName -ine $PrimaryPortalMachine) { $PrimaryPortalMachine } else { "" } #add peer machine name
            EnableDebugLogging = if($DebugMode) { $true } else { $false }
            LogLevel = if($DebugMode) { 'DEBUG' } else { 'WARNING' }
            ContentDirectoryCloudConnectionString = $ContentDirectoryCloudConnectionString							
            ContentDirectoryCloudContainerName = $ContentDirectoryCloudContainerName
            DependsOn =  $Depends
        }
        $Depends += "[ArcGIS_Portal]Portal$($Node.NodeName)"
        
        ArcGIS_Portal_TLS ArcGIS_Portal_TLS
        {
            PortalHostName          = $Node.NodeName
            SiteAdministrator       = $PortalAdministratorCredential
            WebServerCertificateAlias =  if($Node.SSLCertificate){$Node.SSLCertificate.CName}else{$null}
            CertificateFileLocation = if($Node.SSLCertificate){$Node.SSLCertificate.Path}else{$null}
            CertificatePassword = if($Node.SSLCertificate){$Node.SSLCertificate.Password}else{$null}
            SslRootOrIntermediate = if($Node.SslRootOrIntermediate){$Node.SslRootOrIntermediate}else{$null}
            EnableHSTS = $EnableHSTS
            DependsOn               = $Depends
        }
    }   
}
