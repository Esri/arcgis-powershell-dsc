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
        $CloudStorageCredentials
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 3.3.2 
    Import-DscResource -Name ArcGIS_Portal
    
    if($null -ne $CloudStorageType)
    {
        if($CloudStorageType -ieq 'AWSS3DynamoDB') {
            $ContentDirectoryCloudConnectionString = "NAMESPACE=$($CloudNamespace);REGION=$($AWSRegion);"
            if($null -ne $CloudStorageCredentials){
                $ContentDirectoryCloudConnectionString += "ACCESS_KEY_ID=$($CloudStorageCredentials.UserName);SECRET_KEY=$($CloudStorageCredentials.UserName)"
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
