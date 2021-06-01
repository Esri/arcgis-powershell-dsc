Configuration PortalUpgradeStandbyJoinV1{
    param(
        [parameter(Mandatory = $true)]
        [System.String]
        $PrimaryPortalMachine,
        
        [parameter(Mandatory = $true)]
        [System.String]
        $Context,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $PortalSiteAdministratorCredential,

        [parameter(Mandatory = $true)]
        [System.String]
        $ContentDirectoryLocation,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AdminEmail,

        [Parameter(Mandatory=$False)]
        [System.Byte]
        $AdminSecurityQuestionIndex,
        
        [Parameter(Mandatory=$False)]
        [System.String]
        $AdminSecurityAnswer,

        [Parameter(Mandatory=$False)]
        [ValidateSet("AzureFiles","AzureBlob")]
        [AllowNull()] 
        [System.String]
        $CloudStorageType,

        [System.String]
        $AzureFileShareName,

        [System.String]
        $CloudNamespace,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $CloudStorageCredentials
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.2.0"} 
    Import-DscResource -Name ArcGIS_Portal
    Import-DscResource -Name ArcGIS_PortalUpgrade 
    
    if(($null -ne $CloudStorageType) -and $CloudStorageCredentials) 
    {
        $AccountName = $StorageAccountCredential.UserName
		$EndpointSuffix = ''
        $Pos = $StorageAccountCredential.UserName.IndexOf('.blob.')
        if($Pos -gt -1) {
            $AccountName = $StorageAccountCredential.UserName.Substring(0, $Pos)
			$EndpointSuffix = $StorageAccountCredential.UserName.Substring($Pos + 6) # Remove the hostname and .blob. suffix to get the storage endpoint suffix
			$EndpointSuffix = ";EndpointSuffix=$($EndpointSuffix)"
        }

        if($CloudStorageType -ieq 'AzureFiles') {
            $AzureFilesEndpoint = if($Pos -gt -1){$StorageAccountCredential.UserName.Replace('.blob.','.file.')}else{$StorageAccountCredential.UserName}
            $AzureFileShareName = $AzureFileShareName.ToLower() # Azure file shares need to be lower case
            $ContentDirectoryLocation = "\\$($AzureFilesEndpoint)\$AzureFileShareName\$($CloudNamespace)\portal\content"    
        }
        else {
            $AccountKey = $StorageAccountCredential.GetNetworkCredential().Password
            $ContentDirectoryCloudConnectionString = "DefaultEndpointsProtocol=https;AccountName=$($AccountName);AccountKey=$($AccountKey)$($EndpointSuffix)"
		    $ContentDirectoryCloudContainerName = "arcgis-portal-content-$($CloudNamespace)-portal"
        }
    }

    Node $AllNodes.NodeName {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        $NodeName = $Node.NodeName
        $MachineFQDN = (Get-FQDN $NodeName)
        $PrimaryPortalFQDN = (Get-FQDN $PrimaryPortalMachine)
        ArcGIS_Portal "PortalStandByUpgradeJoin"
        {
            Ensure                                  = 'Present'
            PortalHostName                          = $MachineFQDN
            LicenseFilePath                         = $null
            UserLicenseTypeId                       = $null
            PortalAdministrator                     = $PortalSiteAdministratorCredential 
            AdminEmail                              = $AdminEmail
            AdminSecurityQuestionIndex              = $AdminSecurityQuestionIndex
            AdminSecurityAnswer                     = $AdminSecurityAnswer
            ContentDirectoryLocation                = $ContentDirectoryLocation
            Join                                    = $true
            IsHAPortal                              = $true
            PeerMachineHostName                     = $PrimaryPortalFQDN
            EnableDebugLogging                      = $IsDebugMode
            LogLevel                                = if($IsDebugMode) { 'DEBUG' } else { 'WARNING' }
            ContentDirectoryCloudConnectionString   = $ContentDirectoryCloudConnectionString							
            ContentDirectoryCloudContainerName      = $ContentDirectoryCloudContainerName
            EnableEmailSettings                     = $False
            EmailSettingsSMTPServerAddress          = $null
            EmailSettingsFrom                       = $null
            EmailSettingsLabel                      = $null
            EmailSettingsAuthenticationRequired     = $false
            EmailSettingsCredential                 = $null
            EmailSettingsSMTPPort                   = $null
            EmailSettingsEncryptionMethod           = "NONE"
        }
    }
}