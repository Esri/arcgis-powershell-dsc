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
        [parameter(Mandatory = $true)]
        [System.String]
        $Version,
         
        [parameter(Mandatory = $true)]
        [System.Boolean]
        $Join,

        [parameter(Mandatory = $true)]
        [System.String]
        $ServerType,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,    

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator
    )

    @{}
}

function Set-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(	
        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $true)]
        [System.String]
        $ServerType,

        [parameter(Mandatory = $true)]
        [System.Boolean]
        $Join,

        [parameter(Mandatory = $false)]    
        [System.String]
        $ServerHostName,

        [parameter(Mandatory = $false)]
        [System.String]
        $PeerServerHostName,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,    

        [parameter(Mandatory = $false)]
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

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator,
        
        [parameter(Mandatory = $false)]
        [System.String]
        $LogLevel,

        [parameter(Mandatory = $False)]    
        [System.String]
        [ValidateSet("None","Azure","AWS")]
        $CloudProvider = "None",

        [Parameter(Mandatory=$False)]
        [System.String]
        $CloudNamespace,

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
        $PortalSiteAdministrator
	)
    

    if($VerbosePreference -ine 'SilentlyContinue') 
    {        
        Write-Verbose ("Site Administrator UserName:- " + $SiteAdministrator.UserName) 
    }

    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    Write-Verbose "Server Type:- $ServerType , Fully Qualified Domain Name :- $FQDN"

    $ServerBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName $ServerType -FQDN $FQDN

	Write-Verbose "Waiting for Server '$ServerBaseUrl' to initialize"
    Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName $ServerType -SleepTimeInSeconds 5 -Verbose
    
    if($Ensure -ieq 'Present') {       
        $Referer = 'https://localhost' 
        
        Write-Verbose "Checking for $ServerType site on '$ServerBaseUrl'"
        $siteExists = $false
        $siteExists = Test-ServerSiteCreated -URL $ServerBaseURL -Type $ServerType -Referer $Referer -Verbose
        if($siteExists){
            Write-Verbose "$ServerType site exists: $($siteExists)"
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
            if($Join){
                Write-Verbose 'Joining Site'
                $ServerJoinArgs = @{
                    ServerType = $ServerType
                    Version = $Version
                    URL = $ServerBaseUrl
                    Credential = $SiteAdministrator
                    PrimaryServerHostName = $PeerServerHostName
                    Referer = $Referer
                    PortalSiteAdministrator = $PortalSiteAdministrator
                }

                Invoke-JoinSite @ServerJoinArgs -Verbose
                Write-Verbose 'Joined Site'
            }else{

                $ServerArgs = @{
                    ServerType = $ServerType
                    Version = $Version
                    URL = $ServerBaseUrl
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
                    AzureStorageAccountCredential =  $AzureCloudStorageAccountCredential 
                }
                
                Invoke-CreateSite @ServerArgs -Verbose
            }
            
            if($ServerType -ieq 'VelocityServer'){
                Write-Verbose "Waiting for Velocity Server restart. URL: '$($ServerBaseUrl)'"
                Wait-ForArcGISComponentRestart -BaseURL $ServerBaseUrl -ComponentName $ServerType -Verbose
            }else{
                Write-Verbose "Waiting for Server '$($ServerBaseUrl)'"
                Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName $ServerType -Verbose
            }
        }else{
            Write-Verbose "Site Already Exists."
        }

        if(-not($Join)){
            #Write-Verbose 'Get Server Token'   
            $token = Get-ServerToken -URL $ServerBaseUrl -Credential $SiteAdministrator -Referer $Referer

            Write-Verbose "Ensuring Log Level $LogLevel"	
            $logSettings = Get-LogSettings -URL $ServerBaseUrl -Token $token.token -Referer $Referer
            Write-Verbose "Current Log Level:- $($logSettings.logLevel)"

            $CurrentLogDir = ([string]$logSettings.logDir).TrimEnd([char[]]@('\','/'))
            $DesiredLogDir = ([string]$ServerLogsLocation).TrimEnd([char[]]@('\','/'))

            if(($logSettings.logLevel -ine $LogLevel) -or (-not([string]::IsNullOrEmpty($ServerLogsLocation)) -and ($CurrentLogDir -ne $DesiredLogDir))){
                if(-not([string]::IsNullOrEmpty($ServerLogsLocation))){
                    $logSettings.logDir = $ServerLogsLocation
                }
                $logSettings.logLevel = $LogLevel
                Write-Verbose "Updating log level to $($logSettings.logLevel) and log dir to $($logSettings.logDir)"
                Update-LogSettings -URL $ServerBaseUrl -Token $token.token -Referer $Referer -logSettings $logSettings -ServerType $ServerType
                #Write-Verbose "Updated log level to $($logSettings.settings.logLevel)"
            }
        }
    }
    elseif($Ensure -ieq 'Absent') {
        Write-Verbose 'Deleting Site'
        Invoke-DeleteSite -URL $ServerBaseUrl -Credential $SiteAdministrator
        Write-Verbose 'Site Deleted'
        
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
        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $true)]
        [System.String]
        $ServerType,

        [parameter(Mandatory = $true)]
        [System.Boolean]
        $Join,

        [parameter(Mandatory = $false)]    
        [System.String]
        $ServerHostName,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,    

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

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SiteAdministrator,

        [parameter(Mandatory = $false)]
        [System.String]
        $PeerServerHostName,
        
        [parameter(Mandatory = $false)]
        [System.String]
        $LogLevel,

        [parameter(Mandatory = $False)]    
        [System.String]
        [ValidateSet("None","Azure","AWS")]
        $CloudProvider = "None",

        [Parameter(Mandatory=$False)]
        [System.String]
        $CloudNamespace,

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
        $PortalSiteAdministrator
    )

    $FQDN = if($ServerHostName){ Get-FQDN $ServerHostName }else{ Get-FQDN $env:COMPUTERNAME }
    Write-Verbose "Fully Qualified Domain Name :- $FQDN" 
    $Referer = 'https://localhost'
    $ServerBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName $ServerType -FQDN $FQDN
    $result = $false
    Write-Verbose "Checking for site on '$ServerBaseUrl'"

    $result = Test-ServerSiteCreated -URL $ServerBaseURL -Type $ServerType -Referer $Referer -Verbose
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
        Write-Verbose "Unable to detect if site exists."
    }

    try {        
        
        Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName $ServerType -SleepTimeInSeconds 5 -Verbose
        $token = Get-ServerToken -URL $ServerBaseUrl -Credential $SiteAdministrator -Referer $Referer 
        $result = ($null -ne $token.token)
        if($result){
            Write-Verbose "Site Exists. Was able to retrieve token for PSA"
        }else{
            Write-Verbose "Unable to detect if Site Exists. Was NOT able to retrieve token for PSA"
        }
    }
    catch {
        Write-Verbose "[WARNING]:- $($_)"
    }

    if($result -and $LogLevel){
        $logSettings = Get-LogSettings -URL $ServerBaseUrl -Token $token.token -Referer $Referer 
        Write-Verbose "Current Log Level $($logSettings.logLevel)"
        if($logSettings.logLevel -ine $LogLevel) {
            Write-Verbose "Current Log Level $($logSettings.logLevel) not set to '$LogLevel'"
            $result = $false
        }
        $CurrentLogDir = ([string]$logSettings.logDir).TrimEnd([char[]]@('\','/'))
        $DesiredLogDir = ([string]$ServerLogsLocation).TrimEnd([char[]]@('\','/'))
        if($result -and -not([string]::IsNullOrEmpty($ServerLogsLocation)) -and ($CurrentLogDir -ne $DesiredLogDir)){
            Write-Verbose "Current Server Log Path $($logSettings.logDir) not set to '$ServerLogsLocation'"
            $result = $false
        }
    }

    if($Ensure -ieq 'Present') {
	    $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}

Export-ModuleMember -Function *-TargetResource