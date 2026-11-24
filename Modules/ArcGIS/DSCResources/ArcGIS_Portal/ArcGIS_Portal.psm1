$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.Portal.psm1'))

function Get-TargetResource {
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
        [parameter(Mandatory = $True)]    
        [System.String]
        $Version,

		[parameter(Mandatory = $true)]
        [System.String]
        $PortalHostName
	)

	@{}
}

function Set-TargetResource {
	[CmdletBinding()]
	param
	(
        [parameter(Mandatory = $True)]    
        [System.String]
        $Version,

		[parameter(Mandatory = $True)]
        [System.String]
        $PortalHostName,

		[ValidateSet("Present", "Absent")]
		[System.String]
        $Ensure,
        
        [parameter(Mandatory = $false)]
		[System.String]
		$LicenseFilePath = $null,
        
        [parameter(Mandatory = $false)]
		[System.String]
        $UserLicenseTypeId = $null,

		[System.Management.Automation.PSCredential]
		$PortalAdministrator,

		[System.String]
		$AdminEmail,

        [System.String]
		$AdminFullName,

        [System.String]
		$AdminDescription,

		[System.Management.Automation.PSCredential]
		$AdminSecurityQuestionCredential,

        [System.Boolean]
		$Join,

        [System.Boolean]
		$EnableDebugLogging = $False,

        [System.String]
		$LogLevel = 'WARNING',

        [System.Boolean]
        $IsHAPortal,

        [System.String]
		$PeerMachineHostName,

        [System.String]
        $ContentDirectoryLocation,

        [parameter(Mandatory = $True)]    
        [System.String]
        [ValidateSet("None","Azure","AWS")]
        $CloudProvider = "None",

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("AccessKey","IAMRole", "None")]
        $AWSAuthenticationType = "None",

        [parameter(Mandatory = $false)]
        [System.String]
        $AWSS3ContentBucketName,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSRegion,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AWSAccessKeyCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("AccessKey","ServicePrincipal","UserAssignedIdentity", "SASToken", "None")]
        $AzureAuthenticationType = "None",

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureStorageAccountCredential,

        [parameter(Mandatory = $false)]
        [System.String]
        $AzureContentBlobContainerName,
        
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureServicePrincipalCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureServicePrincipalTenantId,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureServicePrincipalAuthorityHost,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureUserAssignedIdentityClientId,
        
        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $EnableCreateSiteDebug
    )
    
    if ($VerbosePreference -ne 'SilentlyContinue') {        
        Write-Verbose ("PortalAdmin UserName:- " + $PortalAdministrator.UserName) 
    }

    $FQDN = if($PortalHostName){ Get-FQDN $PortalHostName }else{ Get-FQDN $env:COMPUTERNAME }     
    $PortalBaseURL = Get-ArcGISComponentBaseUrl -FQDN $FQDN -ComponentName "Portal"

    if ($EnableDebugLogging) {
        if (-not(Invoke-TestSetLoggingLevel -EnableDebugLogging $True -Verbose)) {
            $RestartRequired = $true
        }
    } else {
        if(-not($IsHAPortal)){
            Write-Verbose "Setup is Single machine Portal"
        }
        if (-not(Invoke-TestSetLoggingLevel -EnableDebugLogging $False -Verbose)) {
            $RestartRequired = $true
        }
    }

    if ($RestartRequired) {
        Restart-ArcGISService -ComponentName 'Portal' -Verbose
    }    
    Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "PortalSharing" -MaxWaitTimeInSeconds 600 -Verbose

    Write-Verbose "Portal at $($PortalBaseURL)"
    if ($Ensure -ieq 'Present') {
        $Referer = 'https://localhost'
        $RestartRequired = $false
        
        $PortalSiteCheck = Test-PortalSiteCreated -URL $PortalBaseURL -Referer $Referer -Verbose
        if($PortalSiteCheck){
            Write-Verbose "Making request to sharing API" 
            $PortalReady = $False
            try {
                Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "PortalSharing" -ThrowErrors $True
                Write-Verbose "Sharing API rest endpoint is available."
                $PortalReady = $True
            }catch {
                Write-Verbose "Sharing API rest endpoint is not available. Error:- $_. Restarting Portal."
                Restart-ArcGISService -ComponentName 'Portal' -Verbose
            }

            if(-not($PortalReady)){
                try{
                    Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "PortalSharing" -MaxWaitTimeInSeconds 600 -Verbose -ThrowErrors $true
                }catch{
                    throw "Portal Site is not healthy. Please check your portal site deployment."
                }
            }
        } else {
            if($Join) {
                $PrimaryMachineFQDN = Get-FQDN $PeerMachineHostName
                Write-Verbose "Joining machine '$($FQDN)' to portal site (Primary - $PrimaryMachineFQDN)"
                Join-PortalSite -URL $PortalBaseURL -Credential $PortalAdministrator -PrimaryMachineHostName $PrimaryMachineFQDN -Verbose
                Write-Verbose "Machine '$($FQDN)' joined to portal site (Primary - $PrimaryMachineFQDN)"   
            } else {
                Write-Verbose "Creating Portal site" 
                $PortalArguments = @{
                    Version = $Version
                    URL = $PortalBaseURL
                    Credential = $PortalAdministrator
                    FullName = $AdminFullName
                    Email = $AdminEmail
                    Description = $AdminDescription
                    AdminSecurityQuestionCredential = $AdminSecurityQuestionCredential
                    LicenseFilePath = $LicenseFilePath
                    UserLicenseTypeId = $UserLicenseTypeId
                    EnableCreateSiteDebug = $EnableCreateSiteDebug
                }

                if($CloudProvider -ieq "None"){
                    $PortalArguments["ContentDirectoryLocation"] = $ContentDirectoryLocation
                }else{
                    $PortalArguments["CloudProvider"] = $CloudProvider
                    if($CloudProvider -ieq "Azure"){
                        $PortalArguments["AzureAuthenticationType"] = $AzureAuthenticationType
                        $PortalArguments["AzureContentBlobContainerName"] = $AzureContentBlobContainerName
                        $PortalArguments["AzureStorageAccountCredential"] = $AzureStorageAccountCredential

                        if($AzureAuthenticationType -ieq "ServicePrincipal"){
                            $PortalArguments["AzureServicePrincipalCredential"] = $AzureServicePrincipalCredential
                            $PortalArguments["AzureServicePrincipalTenantId"] = $AzureServicePrincipalTenantId
                            $PortalArguments["AzureServicePrincipalAuthorityHost"] = $AzureServicePrincipalAuthorityHost
                        }elseif($AzureAuthenticationType -ieq "UserAssignedIdentity"){
                            $PortalArguments["AzureUserAssignedIdentityClientId"] = $AzureUserAssignedIdentityClientId
                        }
                    }elseif($CloudProvider -ieq "AWS"){
                        $PortalArguments["AWSAuthenticationType"] = $AWSAuthenticationType
                        $PortalArguments["AWSS3ContentBucketName"] = $AWSS3ContentBucketName
                        $PortalArguments["AWSRegion"] = $AWSRegion
                        if($AWSAuthenticationType -ieq "AccessKey"){
                            $PortalArguments["AWSAccessKeyCredential"] = $AWSAccessKeyCredential
                        }
                    }
                }

                Invoke-CreatePortalSite @PortalArguments -Verbose
                Write-Verbose 'Portal site created'
            }
        }

        Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "Portal" -Verbose

        $token = Get-PortalToken -URL $PortalBaseURL -Credential $PortalAdministrator -Referer $Referer
        Write-Verbose "Portal site ready. Successfully retrieved token for $($PortalAdministrator.UserName)"

        #Populating Licenses
        if(-not($Join) -and $LicenseFilePath){
            $token = Get-PortalToken -URL $PortalBaseURL -Credential $PortalAdministrator -Referer $Referer -Verbose
            $IsLicensePopulated = Test-LicensePopulated -URL $PortalBaseURL -Token $token.token -Referer $Referer -Verbose  
            if(-not($IsLicensePopulated)){
                Invoke-PopulateLicense -URL $PortalBaseURL -Token $token.token -Referer $Referer -Verbose 
            }
        }

        $token = Get-PortalToken -URL $PortalBaseURL -Credential $PortalAdministrator -Referer $Referer
        $LogSettings = Get-LogSettings -URL $PortalBaseURL -Token $token.token -Referer $Referer 
		if ($LogSettings -and $LogSettings.logLevel) {
			$CurrentLogLevel = $LogSettings.logLevel
			if ($CurrentLogLevel -ne $LogLevel) {
				Write-Verbose "Portal CurrentLogLevel '$CurrentLogLevel' does not match desired value of '$LogLevel'. Updating it"
				$LogSettings.logLevel = $LogLevel
				Update-PortalLogSettings -URL $PortalBaseURL -Token $token.token -Referer $Referer -LogSettings $LogSettings
            }
            else {
				Write-Verbose "Portal CurrentLogLevel '$CurrentLogLevel' matches desired value of '$LogLevel'"
			}
        }
        else {
			Write-Verbose "[WARNING] Unable to retrieve current log settings from portal admin"
		}
    }
    elseif ($Ensure -ieq 'Absent') {
        Write-Warning 'Site Delete not implemented'
    }
}

function Test-TargetResource {
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [parameter(Mandatory = $True)]    
        [System.String]
        $Version,

		[parameter(Mandatory = $True)]
        [System.String]
        $PortalHostName,
        
        [ValidateSet("Present", "Absent")]
		[System.String]
        $Ensure,
        
        [parameter(Mandatory = $false)]
		[System.String]
		$LicenseFilePath = $null,
        
        [parameter(Mandatory = $false)]
		[System.String]
        $UserLicenseTypeId = $null,

		[System.Management.Automation.PSCredential]
		$PortalAdministrator,

		[System.String]
		$AdminEmail,

        [System.String]
		$AdminFullName,

        [System.String]
		$AdminDescription,

        [System.Management.Automation.PSCredential]
		$AdminSecurityQuestionCredential,

        [System.Boolean]
		$Join,

        [System.Boolean]
		$EnableDebugLogging = $False, 

        [System.String]
		$LogLevel = 'WARNING',

        [System.Boolean]
        $IsHAPortal,

        [System.String]
		$PeerMachineHostName,

        [System.String]
        $ContentDirectoryLocation,

        [parameter(Mandatory = $True)]    
        [System.String]
        [ValidateSet("None","Azure","AWS")]
        $CloudProvider = "None",

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("AccessKey","IAMRole", "None")]
        $AWSAuthenticationType = "None",

        [parameter(Mandatory = $false)]
        [System.String]
        $AWSS3ContentBucketName,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AWSRegion,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AWSAccessKeyCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        [ValidateSet("AccessKey","ServicePrincipal","UserAssignedIdentity", "SASToken", "None")]
        $AzureAuthenticationType = "None",

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureStorageAccountCredential,

        [parameter(Mandatory = $false)]
        [System.String]
        $AzureContentBlobContainerName,
        
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AzureServicePrincipalCredential,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureServicePrincipalTenantId,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureServicePrincipalAuthorityHost,

        [Parameter(Mandatory=$False)]
        [System.String]
        $AzureUserAssignedIdentityClientId,
        
        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $EnableCreateSiteDebug
	)

    
    $FQDN = if($PortalHostName){ Get-FQDN $PortalHostName }else{ Get-FQDN $env:COMPUTERNAME }
    $result = $false

    $PortalBaseURL = Get-ArcGISComponentBaseUrl -FQDN $FQDN -ComponentName "Portal"
    $result = Invoke-TestSetLoggingLevel -EnableDebugLogging $EnableDebugLogging -TestOnly $true -Verbose
    if ($result) {
        $Referer = 'https://localhost'
        try{
            $PortalSiteCheck = Test-PortalSiteCreated -URL $PortalBaseURL -Referer $Referer -Verbose
            if($PortalSiteCheck){
                $token = Get-PortalToken -URL $PortalBaseURL -Credential $PortalAdministrator -Referer $Referer
                if (-not($token.token)) {
                    Write-Verbose "Unable to retrive token from portal site"   
                    $result = $false
                } else {
                    Write-Verbose "Portal site already created. Successfully retrieved token for $($PortalAdministrator.UserName)"                        
                }
            }else{
                $result = $false
            }
        }catch{
            Write-Verbose "[WARNING] Unable to detect portal site. Error:- $_"
            $result = $False
        }
    }

    if($result -and -not($Join) -and $LicenseFilePath){
        Write-Verbose "Checking if portal licenses are populated"
        Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "Portal" -Verbose
        $token = Get-PortalToken -URL $PortalBaseURL -Credential $PortalAdministrator -Referer $Referer
        
        $result = Test-LicensePopulated -URL $PortalBaseURL -Token $token.token -Referer $Referer -Verbose  
        if($result){
            Write-Verbose "Portal licenses are populated"
        }else{
            Write-Verbose "Portal licenses are not populated. Will be populated."
        }
    }

    if ($result) {        
        Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "Portal" -Verbose
        $token = Get-PortalToken -URL $PortalBaseURL -Credential $PortalAdministrator -Referer $Referer     
        
        $LogSettings = Get-LogSettings -URL $PortalBaseURL -Token $token.token -Referer $Referer
        $CurrentLogLevel = $LogSettings.logLevel
        if ($CurrentLogLevel -ne $LogLevel) {
            Write-Verbose "Portal CurrentLogLevel '$CurrentLogLevel' does not match desired value of '$LogLevel'"
            $result = $false
        }
        else {
            Write-Verbose "Portal CurrentLogLevel '$CurrentLogLevel' matches desired value of '$LogLevel'"
        }
    }

    if ($Ensure -ieq 'Present') {
	       $result   
    } elseif ($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}

function Invoke-TestSetLoggingLevel {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [System.Boolean]
        $EnableDebugLogging,

        [System.Boolean]
        $TestOnly = $false
    )

    $ExpectedLogLevelFound = $True
    $InstallDir = (Get-ArcGISComponentVersionAndInstallDirectory -ComponentName 'Portal').InstallDir
    $PropertiesFile = Join-Path $InstallDir 'framework\runtime\tomcat\conf\logging.properties'
    @('org.apache.catalina.core.ContainerBase.[Catalina].[localhost].level', '1catalina.org.apache.juli.FileHandler.level', '2localhost.org.apache.juli.FileHandler.level', '3portal.org.apache.juli.FileHandler.level', 'java.util.logging.ConsoleHandler.level') | ForEach-Object {
        $PropertyName = $_
        $DesiredLoggingLevel = $null
        if ($EnableDebugLogging) {
            $DesiredLoggingLevel = 'ALL' 
        }
        else { 
            # Default values for the levels
            if ($PropertyName -eq '3portal.org.apache.juli.FileHandler.level') {
                $DesiredLoggingLevel = 'INFO' 
            }
            elseif ($PropertyName -eq 'java.util.logging.ConsoleHandler.level') {
                $DesiredLoggingLevel = 'FINE'
            }
            else {
                $DesiredLoggingLevel = 'SEVERE'
            }
        }          
            
        $CurrentLoggingLevel = Get-PropertyFromPropertiesFile -PropertiesFilePath $PropertiesFile -PropertyName $PropertyName
        if ($CurrentLoggingLevel -ne $DesiredLoggingLevel) {
            if($TestOnly){
                Write-Verbose "Portal Tomcat CurrentLoggingLevel '$CurrentLoggingLevel' does not match desired value of '$DesiredLoggingLevel' for property '$PropertyName'"
                $ExpectedLogLevelFound = $false
            }else{
                Write-Verbose "Portal Tomcat CurrentLoggingLevel '$CurrentLoggingLevel' does not match desired value of '$DesiredLoggingLevel'. Updating it"
                if (Confirm-PropertyInPropertiesFile -PropertiesFilePath $PropertiesFile -PropertyName $PropertyName -PropertyValue $DesiredLoggingLevel) {
                    Write-Verbose "Portal Tomcat logging level '$PropertyName' changed. Restart needed"
                    $ExpectedLogLevelFound = $false 
                }
            }
        }
        else {
            Write-Verbose "Portal Tomcat CurrentLoggingLevel '$CurrentLoggingLevel' matches desired value of '$DesiredLoggingLevel' for property '$PropertyName'"
        }
    }
    $ExpectedLogLevelFound
}

Export-ModuleMember -Function *-TargetResource
