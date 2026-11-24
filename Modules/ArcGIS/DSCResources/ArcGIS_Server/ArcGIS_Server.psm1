$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.Server.psm1'))

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
        [parameter(Mandatory = $True)]    
        [System.String]
        $Version,

        [parameter(Mandatory = $True)]    
        [System.Boolean]
        $Join,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$SiteAdministrator
	)

	@{}
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
        [parameter(Mandatory = $True)]    
        [System.String]
        $Version,

        [parameter(Mandatory = $True)]    
        [System.Boolean]
        $Join,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$SiteAdministrator,
        
        [parameter(Mandatory = $false)]    
        [System.String]
        $ServerHostName,

        [parameter(Mandatory = $False)]
		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure = 'Present',

        [parameter(Mandatory = $False)]
		[System.String]
		$ConfigurationStoreLocation,
        
        [parameter(Mandatory = $false)]
		[System.String]
        $ServerDirectoriesRootLocation,

        [parameter(Mandatory = $false)]
        [System.String]
        $ServerDirectories,
        
        [parameter(Mandatory = $false)]
		[System.String]
        $ServerLogsLocation = $null,

        [parameter(Mandatory = $false)]
		[System.String]
        $LocalRepositoryPath = $null,

        [parameter(Mandatory = $false)]
        [System.String]
        $PeerServerHostName,
        
        [parameter(Mandatory = $false)]
        [ValidateSet("OFF","SEVERE","WARNING","INFO","FINE","VERBOSE","DEBUG")]
        [System.String]
        [AllowNull()]
		$LogLevel = "WARNING",

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $EnableUsageMetering,

        [parameter(Mandatory = $False)]    
        [System.String]
        [ValidateSet("None","Azure","AWS")]
        $CloudProvider = "None",

        [parameter(Mandatory = $False)]    
        [System.Boolean]
        $IsCloudNativeServer = $False,

        [parameter(Mandatory = $false)]
        [System.String]
        $CloudNamespace,

        [Parameter(Mandatory=$False)]
        [System.String]
        $CloudNativeTags,

        [Parameter(Mandatory=$False)]
        [System.String]
        $CloudNativeLocalDirectory,

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("AccessKey","IAMRole", "None")]
        $AWSCloudAuthenticationType = "None",

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSRegion,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AWSCloudAccessKeyCredential,
        
        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSCloudNativeS3BucketName,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSCloudNativeS3RegionEndpointURL,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSCloudNativeS3RootDir,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSCloudNativeDynamoDBRegionEndpointURL,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSCloudNativeQueueServiceRegionEndpointURL,

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("AccessKey","ServicePrincipal","UserAssignedIdentity", "SASToken", "None")]
        $AzureCloudAuthenticationType = "None",
        
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureCloudServicePrincipalCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudServicePrincipalTenantId,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudServicePrincipalAuthorityHost,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudUserAssignedIdentityClientId,
        
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureCloudStorageAccountCredential,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureCloudNativeStorageAccountCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeStorageAccountContainerName,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeStorageAccountRootDir,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeStorageAccountAccountEndpointUrl,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeStorageAccountRegionEndpointUrl,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureCloudNativeCosmosDBAccountCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeCosmosDBAccountEndpointUrl,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeCosmosDBRegionEndpointUrl,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeCosmosDBAccountDatabaseId,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeCosmosDBAccountSubscriptionId,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeCosmosDBAccountResourceGroupName,

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("Direct","Gateway")]
        $AzureCloudNativeCosmosDBAccountConnectionMode = "Gateway",

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureCloudNativeServiceBusNamespaceCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeServiceBusNamespaceEndpointUrl,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeServiceBusNamespaceRegionEndpointUrl
	)
    
    if($VerbosePreference -ine 'SilentlyContinue') 
    {        
        Write-Verbose ("Site Administrator UserName:- " + $SiteAdministrator.UserName) 
    }

    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    Write-Verbose "Fully Qualified Domain Name :- $FQDN"
    $ServerBaseURL = Get-ArcGISComponentBaseURL -ComponentName "Server" -FQDN $FQDN
	Write-Verbose "Waiting for Server '$($ServerBaseURL)'"
    Test-ArcGISComponentHealth -BaseURL $ServerBaseURL -ComponentName "Server" -Verbose

    if($Ensure -ieq 'Present') {
        $Referer = 'https://localhost' 
        Write-Verbose "Checking for site on '$ServerBaseURL'"
        $siteExists = $false
        $siteExists = Test-ServerSiteCreated -URL $ServerBaseURL -Type "Server" -Referer $Referer -Verbose
        if($siteExists){
            Write-Verbose "ArcGIS Server exists: $($siteExists)"
            try {
                $token = Get-ServerToken -URL $ServerBaseURL -Credential $SiteAdministrator -Referer $Referer 
                if($null -eq $token.token){
                    throw "Unable to retrieve token for administrator."
                }
            }catch {
                Write-Verbose "[WARNING] Get-ServerToken returned:- $_"
            }
        }else{
            Write-Verbose "Unable to detect if site exists."
        }

        if(-not($siteExists)) {
            if($Join) {
                Write-Verbose 'Joining to Server Site'
                Invoke-JoinSite -URL $ServerBaseURL -Credential $SiteAdministrator -Referer $Referer `
                                -ServerType "Server" -PrimaryServerHostName $PeerServerHostName -Verbose
                Write-Verbose 'Joined to Server Site'
            }else{
                 $ServerArgs = @{
                    ServerType = "Server"
                    Version = $Version
                    URL = $ServerBaseURL
                    Credential = $SiteAdministrator
                    ConfigurationStoreLocation = $ConfigurationStoreLocation
                    ServerDirectoriesRootLocation = $ServerDirectoriesRootLocation
                    ServerDirectories = $ServerDirectories
                    LocalRepositoryPath = $LocalRepositoryPath
                    ServerLogsLocation = $ServerLogsLocation
                    LogLevel = $LogLevel
                    CloudProvider = $CloudProvider
                    CloudNamespace = $CloudNamespace
                    AWSCloudAuthenticationType = $AWSCloudAuthenticationType
                    AWSRegion = $AWSRegion
                    AWSCloudAccessKeyCredential = $AWSCloudAccessKeyCredential
                    AzureAuthenticationType = $AzureCloudAuthenticationType
                    AzureServicePrincipalCredential = $AzureCloudServicePrincipalCredential
                    AzureServicePrincipalTenantId = $AzureCloudServicePrincipalTenantId
                    AzureServicePrincipalAuthorityHost = $AzureCloudServicePrincipalAuthorityHost
                    AzureUserAssignedIdentityClientId = $AzureCloudUserAssignedIdentityClientId
                    AzureStorageAccountCredential = if($IsCloudNativeServer){ $AzureCloudNativeStorageAccountCredential}else{ $AzureCloudStorageAccountCredential }
                    # All system directories are in cloud services
                    UseCloudServicesSystemDirectories = $IsCloudNativeServer
                    CloudServiceTags = $CloudNativeTags
                    LocalDirectory = $CloudNativeLocalDirectory
                    AWSS3BucketName = $AWSCloudNativeS3BucketName
                    AWSS3RegionEndpointURL = $AWSCloudNativeS3RegionEndpointURL
                    AWSS3RootDir = $AWSCloudNativeS3RootDir
                    AWSDynamoDBRegionEndpointURL = $AWSCloudNativeDynamoDBRegionEndpointURL
                    AWSQueueServiceRegionEndpointURL = $AWSCloudNativeQueueServiceRegionEndpointURL
                    AzureCosmosDBAccountCredential = $AzureCloudNativeCosmosDBAccountCredential
                    AzureServiceBusNamespaceCredential = $AzureCloudNativeServiceBusNamespaceCredential
                    AzureStorageAccountContainerName = $AzureCloudNativeStorageAccountContainerName
                    AzureStorageAccountRootDir = $AzureCloudNativeStorageAccountRootDir
                    AzureStorageAccountAccountEndpointUrl = $AzureCloudNativeStorageAccountAccountEndpointUrl
                    AzureStorageAccountRegionEndpointUrl = $AzureCloudNativeStorageAccountRegionEndpointUrl
                    AzureCosmosDBAccountEndpointUrl = $AzureCloudNativeCosmosDBAccountEndpointUrl
                    AzureCosmosDBRegionEndpointUrl = $AzureCloudNativeCosmosDBRegionEndpointUrl
                    AzureCosmosDBAccountDatabaseId = $AzureCloudNativeCosmosDBAccountDatabaseId
                    AzureCosmosDBAccountSubscriptionId = $AzureCloudNativeCosmosDBAccountSubscriptionId        
                    AzureCosmosDBAccountResourceGroupName = $AzureCloudNativeCosmosDBAccountResourceGroupName
                    AzureCosmosDBAccountConnectionMode = $AzureCloudNativeCosmosDBAccountConnectionMode
                    AzureServiceBusNamespaceEndpointUrl = $AzureCloudNativeServiceBusNamespaceEndpointUrl
                    AzureServiceBusNamespaceRegionEndpointUrl = $AzureCloudNativeServiceBusNamespaceRegionEndpointUrl
                }

                Invoke-CreateSite @ServerArgs -Verbose
                
            }
            
            Write-Verbose "Waiting for server '$($ServerBaseURL)' health check."
            Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName "Server" -MaxWaitTimeInSeconds 180 
        }else{
            Write-Verbose "Site already exists."
        }

        if(-not($Join)){
        
            #Write-Verbose 'Get Server Token'   
            $token = Get-ServerToken -URL $ServerBaseURL -Credential $SiteAdministrator -Referer $Referer

			Write-Verbose "Ensuring Log Level $LogLevel"	
            $logSettings = Get-LogSettings -URL $ServerBaseURL -Token $token.token -Referer $Referer
            Write-Verbose "Current Log Level:- $($logSettings.settings.logLevel)"

            $CurrentLogDir = ([string]$logSettings.settings.logDir).TrimEnd([char[]]@('\','/'))
            $DesiredLogDir = ([string]$ServerLogsLocation).TrimEnd([char[]]@('\','/'))
        
            if($logSettings.settings.logLevel -ine $LogLevel -or ($logSettings.settings.usageMeteringEnabled -ne $EnableUsageMetering) -or (-not([string]::IsNullOrEmpty($ServerLogsLocation)) -and ($CurrentLogDir -ne $DesiredLogDir)) ) {
                if(-not([string]::IsNullOrEmpty($ServerLogsLocation))){
                    $logSettings.settings.logDir = $ServerLogsLocation
                }
                $logSettings.settings.logLevel = $LogLevel
                $logSettings.settings.usageMeteringEnabled = $EnableUsageMetering
                Write-Verbose "Updating log level to $($logSettings.settings.logLevel), log dir to $($logSettings.settings.logDir) and usageMeteringEnabled to $($logSettings.settings.usageMeteringEnabled)"
                Update-LogSettings -URL $ServerBaseURL -Token $token.token -Referer $Referer -logSettings $logSettings.settings -ServerType "Server"
                Write-Verbose "Updated log level to $($logSettings.settings.logLevel), log dir to $($logSettings.settings.logDir) and usageMeteringEnabled to $($logSettings.settings.usageMeteringEnabled)"
            }
        }
    }
    elseif($Ensure -ieq 'Absent') {
        Write-Verbose 'Deleting Site'
        Invoke-DeleteSite -URL $ServerBaseURL -Credential $SiteAdministrator -Verbose
        Write-Verbose 'Deleted Site'

        Write-Verbose "Deleting contents of $ConfigStoreRootLocation"
        Remove-Item $ConfigurationStoreLocation -Recurse -Force
        Write-Verbose "Deleted contents of $ServerDirectoriesRootLocation"  
        Remove-Item $ServerDirectoriesRootLocation -Recurse -Force
    }
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [parameter(Mandatory = $True)]    
        [System.String]
        $Version,

        [parameter(Mandatory = $True)]    
        [System.Boolean]
        $Join,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$SiteAdministrator,
        
        [parameter(Mandatory = $false)]    
        [System.String]
        $ServerHostName,

        [parameter(Mandatory = $False)]
		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure = 'Present',

        [parameter(Mandatory = $False)]
		[System.String]
		$ConfigurationStoreLocation,
        
        [parameter(Mandatory = $false)]
		[System.String]
        $ServerDirectoriesRootLocation,

        [parameter(Mandatory = $false)]
        [System.String]
        $ServerDirectories,
        
        [parameter(Mandatory = $false)]
		[System.String]
        $ServerLogsLocation = $null,

        [parameter(Mandatory = $false)]
		[System.String]
        $LocalRepositoryPath = $null,

        [parameter(Mandatory = $false)]
        [System.String]
        $PeerServerHostName,
        
        [parameter(Mandatory = $false)]
        [ValidateSet("OFF","SEVERE","WARNING","INFO","FINE","VERBOSE","DEBUG")]
        [System.String]
        [AllowNull()]
		$LogLevel = "WARNING",

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $EnableUsageMetering,

        [parameter(Mandatory = $False)]    
        [System.String]
        [ValidateSet("None","Azure","AWS")]
        $CloudProvider = "None",

        [parameter(Mandatory = $False)]    
        [System.Boolean]
        $IsCloudNativeServer = $False,

        [parameter(Mandatory = $false)]
        [System.String]
        $CloudNamespace,

        [Parameter(Mandatory=$False)]
        [System.String]
        $CloudNativeTags,

        [Parameter(Mandatory=$False)]
        [System.String]
        $CloudNativeLocalDirectory,

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("AccessKey","IAMRole", "None")]
        $AWSCloudAuthenticationType = "None",

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSRegion,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AWSCloudAccessKeyCredential,
        
        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSCloudNativeS3BucketName,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSCloudNativeS3RegionEndpointURL,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSCloudNativeS3RootDir,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSCloudNativeDynamoDBRegionEndpointURL,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSCloudNativeQueueServiceRegionEndpointURL,

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("AccessKey","ServicePrincipal","UserAssignedIdentity", "SASToken", "None")]
        $AzureCloudAuthenticationType = "None",
        
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureCloudServicePrincipalCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudServicePrincipalTenantId,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudServicePrincipalAuthorityHost,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudUserAssignedIdentityClientId,
        
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureCloudStorageAccountCredential,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureCloudNativeStorageAccountCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeStorageAccountContainerName,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeStorageAccountRootDir,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeStorageAccountAccountEndpointUrl,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeStorageAccountRegionEndpointUrl,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureCloudNativeCosmosDBAccountCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeCosmosDBAccountEndpointUrl,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeCosmosDBRegionEndpointUrl,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeCosmosDBAccountDatabaseId,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeCosmosDBAccountSubscriptionId,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeCosmosDBAccountResourceGroupName,

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("Direct","Gateway")]
        $AzureCloudNativeCosmosDBAccountConnectionMode = "Gateway",

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureCloudNativeServiceBusNamespaceCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeServiceBusNamespaceEndpointUrl,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureCloudNativeServiceBusNamespaceRegionEndpointUrl
    )
    
    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    Write-Verbose "Fully Qualified Domain Name :- $FQDN" 
    $Referer = 'https://localhost'
    $ServerBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName "Server" -FQDN $FQDN
    
    $result = $false
    Write-Verbose "Checking for site on '$ServerBaseURL'"
    $result = Test-ServerSiteCreated -URL $ServerBaseURL -Type "Server" -Referer $Referer -Verbose
    if($Ensure -ieq 'Absent') {
        return -not($result)
    }
    if($result){
        Write-Verbose "Server site exists."
        try {
            $token = Get-ServerToken -URL $ServerBaseURL -Credential $SiteAdministrator -Referer $Referer 
            if($null -eq $token.token){
                throw "Unable to retrieve token for administrator."
            }
        }catch {
            Write-Verbose "[WARNING] Get-ServerToken returned:- $_"
        }
    }else{
        Write-Verbose "Unable to detect if Site Exists."
    }

    if($result -and $LogLevel){
        #Write-Verbose "Token $($token.token)"
        $logSettings = Get-LogSettings -URL $ServerBaseURL -Token $token.token -Referer $Referer
        Write-Verbose "Current Log Level $($logSettings.settings.logLevel)"
        if($logSettings.settings.logLevel -ine $LogLevel) {
            Write-Verbose "Current Log Level $($logSettings.settings.logLevel) not set to '$LogLevel'"
            $result = $false
        }

        $CurrentLogDir = ([string]$logSettings.settings.logDir).TrimEnd([char[]]@('\','/'))
        $DesiredLogDir = ([string]$ServerLogsLocation).TrimEnd([char[]]@('\','/'))
        if($result -and -not([string]::IsNullOrEmpty($ServerLogsLocation)) -and ($CurrentLogDir -ne $DesiredLogDir)){
            Write-Verbose "Current Server Log Directory $($logSettings.settings.logDir.TrimEnd("/")) not set to '$($ServerLogsLocation.TrimEnd("/"))'"
            $result = $false
        }
        if($result -and $logSettings.settings.usageMeteringEnabled -ne $EnableUsageMetering) {
            Write-Verbose "Current usageMeteringEnabled not set to $($logSettings.settings.usageMeteringEnabled)"
            $result = $false
        }
    }
    
    $result
}

Export-ModuleMember -Function *-TargetResource