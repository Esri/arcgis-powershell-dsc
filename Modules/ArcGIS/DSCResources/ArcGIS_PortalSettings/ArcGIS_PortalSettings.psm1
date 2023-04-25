$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$PortalHostName
	)

	$null
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
        [parameter(Mandatory = $true)]
		[System.String]
		$PortalHostName,

		[parameter(Mandatory = $false)]
		[System.String]
		$ExternalDNSName,

		[parameter(Mandatory = $false)]
		[System.String]
		$PortalContext,
        
	    [System.String]
        $PortalEndPoint,
        
        [System.Int32]
        $PortalEndPointPort = 7443,

        [System.String]
        $PortalEndPointContext = 'arcgis',

		[System.Management.Automation.PSCredential]
		$PortalAdministrator,

        [System.Management.Automation.PSCredential]
        $ADServiceUser,

        [System.Boolean]
        $EnableAutomaticAccountCreation,

        [System.String]
        $DefaultRoleForUser,

        [System.String]
        $DefaultUserLicenseTypeIdForUser,

        [System.Boolean]
        $DisableServiceDirectory,

        [System.Boolean]
        $DisableAnonymousAccess,

        [System.Boolean]
        $EnableEmailSettings,

        [System.String]
        $EmailSettingsSMTPServerAddress,

        [System.String]
        $EmailSettingsFrom,

        [System.String]
        $EmailSettingsLabel,

        [System.Boolean]
        $EmailSettingsAuthenticationRequired = $False,

        [System.Management.Automation.PSCredential]
        $EmailSettingsCredential,

        [System.Int32]
        $EmailSettingsSMTPPort = 25,

        [ValidateSet("SSL", "TLS", "NONE")]
        [System.String]
        $EmailSettingsEncryptionMethod = "NONE"
    )

	[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $PortalFQDN = Get-FQDN $PortalHostName
    $Referer = if($ExternalDNSName){"https://$($ExternalDNSName)/$($PortalContext)"}else{"https://localhost"}
    Write-Verbose "Getting Portal Token for user '$($PortalAdministrator.UserName)' from 'https://$($PortalFQDN):7443'"

    $PortalToken = Get-PortalToken -PortalHostName $PortalFQDN -Port 7443 -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
    if(-not($PortalToken.token)) {
        throw "Unable to retrieve Portal Token for '$($PortalAdministrator.UserName)'"
    }else {
		Write-Verbose "Retrieved Portal Token"
	}
    Write-Verbose "Connected to Portal successfully and retrieved token for '$($PortalAdministrator.UserName)'"

	$sysProps = Get-PortalSystemProperties -PortalHostName $PortalFQDN -Token $PortalToken.token -Referer $Referer
	if (-not($sysProps)) {
		$sysProps = @{ }
	}
	$UpdateSystemProperties = $False
    if($ExternalDNSName){
        $ExpectedWebContextUrl = "https://$($ExternalDNSName)/$($PortalContext)"
        if ($sysProps.WebContextURL -ine $ExpectedWebContextUrl) {
            Write-Verbose "Portal System Properties > WebContextUrl is NOT correctly set to '$($ExpectedWebContextUrl)'"
            if (-not($sysProps.WebContextURL)) {
                Add-Member -InputObject $sysProps -MemberType NoteProperty -Name 'WebContextURL' -Value $ExpectedWebContextUrl
            }
            else {
                $sysProps.WebContextURL = $ExpectedWebContextUrl
            }
            $UpdateSystemProperties = $True
        }
        else {
            Write-Verbose "Portal System Properties > WebContextUrl is correctly set to '$($sysProps.WebContextURL)'"
        }
    }

    if($PortalEndPoint){
        # Check if private portal URL is set correctly
        $ExpectedPrivatePortalUrl = if($PortalEndPointPort -ieq 443){ "https://$($PortalEndPoint)/$($PortalEndPointContext)" }else{ "https://$($PortalEndPoint):$($PortalEndPointPort)/$($PortalEndPointContext)" }
        
        if ($sysProps.privatePortalURL -ine $ExpectedPrivatePortalUrl) {
            Write-Verbose "Portal System Properties > privatePortalURL is NOT correctly set to '$($ExpectedPrivatePortalUrl)'"
            if (-not($sysProps.privatePortalURL)) {
                Add-Member -InputObject $sysProps -MemberType NoteProperty -Name 'privatePortalURL' -Value $ExpectedPrivatePortalUrl
            }
            else {
                $sysProps.privatePortalURL = $ExpectedPrivatePortalUrl
            }
            $UpdateSystemProperties = $True			
        }
        else {
            Write-Verbose "Portal System Properties > privatePortalURL is correctly set to '$($sysProps.privatePortalURL)'"
        }
    }
    
    if($UpdateSystemProperties){
        Write-Verbose "Updating Portal System Properties"
        try {
            Wait-ForUrl "https://$($PortalFQDN):7443/arcgis/portaladmin/healthCheck/?f=json" -Verbose
            Wait-ForUrl "https://$($PortalFQDN):7443/arcgis/sharing/rest/generateToken" -Verbose
            Set-PortalSystemProperties -PortalHostName $PortalFQDN -Token $PortalToken.token -Referer $Referer -Properties $sysProps
        } catch {
            Write-Verbose "Error setting Portal System Properties :- $_ .Props - $sysProps"
        }
        Write-Verbose "Updated Portal System Properties."
        
        $MaxWaitTimeInSeconds = 300
        $SleepTimeInSeconds = 10
        $TotalElapsedTimeInSeconds = 0
        Write-Verbose "Waiting for up to $($MaxWaitTimeInSeconds) seconds for portal to restart"
        while(-not($Done) -and ($TotalElapsedTimeInSeconds -lt $MaxWaitTimeInSeconds)){
            try{
                # if available sleep and try again.
                Wait-ForUrl "https://$($PortalFQDN):7443/arcgis/portaladmin/healthCheck/?f=json" -MaxWaitTimeInSeconds 10 -HttpMethod 'GET' -ThrowErrors
                Write-Verbose "Portal web server is still available. Trying again in $($SleepTimeInSeconds) seconds"
                Start-Sleep -Seconds $SleepTimeInSeconds
                $TotalElapsedTimeInSeconds += $SleepTimeInSeconds
            }catch{
                # if error and most likely portal has become unavailable then exit loop
                Write-Verbose "Portal is most likely restarting as result of update of system properties:- $($_)"
                $Done = $true
            }
        }
        
        Write-Verbose "Waiting up to 6 minutes for portaladmin endpoint 'https://$($PortalFQDN):7443/arcgis/portaladmin/' to come back up"
        Wait-ForUrl "https://$($PortalFQDN):7443/arcgis/portaladmin/healthCheck/?f=json" -MaxWaitTimeInSeconds 360 -HttpMethod 'GET' -Verbose
        Write-Verbose "Finished waiting for portaladmin endpoint 'https://$($PortalFQDN):7443/arcgis/portaladmin/' to come back up"    
    }

    Write-Verbose "Getting Portal Token for user '$($PortalAdministrator.UserName)' from 'https://$($PortalFQDN):7443'"
    $token = Get-PortalToken -PortalHostName $PortalFQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
    if (-not($token.token)) {
        throw "Unable to retrieve Portal Token for '$($PortalAdministrator.UserName)'"
    }
    Write-Verbose "Connected to Portal successfully and retrieved token for $($PortalAdministrator.UserName)"
    Write-Verbose "Checking If Portal on HTTPS_Only"
    $PortalSelf = Get-PortalSelfDescription -PortalHostName $PortalFQDN -Token $token.token -Referer $Referer
    if(-not($PortalSelf.allSSL))
    {
        Write-Verbose "Setting Portal to HTTPS_Only"
        $PortalSelfResponse = Set-PortalSelfDescription -PortalHostName $PortalFQDN -Token $token.token -Referer $Referer -Properties @{ allSSL = 'true' }
        Write-Verbose $PortalSelfResponse
    }

    Write-Verbose "Checking if Portal allows anonymous access"
    $PortalSelf = Get-PortalSelfDescription -PortalHostName $PortalFQDN -Token $token.token -Referer $Referer
    if($DisableAnonymousAccess){
        if($PortalSelf.access -ieq 'public'){
            Write-Verbose "Disabling anonymous access"
            $PortalSelfResponse = Set-PortalSelfDescription -PortalHostName $PortalFQDN -Token $token.token -Referer $Referer -Properties @{ access = 'private' }
            Write-Verbose $PortalSelfResponse
        }else{
            Write-Verbose "Anonymous access is Disabled."
        }
    }else{
        if($PortalSelf.access -ieq 'private'){
            Write-Verbose "Enabling anonymous access"
            $PortalSelfResponse = Set-PortalSelfDescription -PortalHostName $PortalFQDN -Token $token.token -Referer $Referer -Properties @{ access = 'public' }
            Write-Verbose $PortalSelfResponse
        }else{
            Write-Verbose "Anonymous access is Enabled." 
        }
    }

    if ($null -ne $ADServiceUser){
        Wait-ForUrl "https://$($PortalFQDN):7443/arcgis/portaladmin/healthCheck/?f=json" -Verbose
        Wait-ForUrl "https://$($PortalFQDN):7443/arcgis/sharing/rest/generateToken" -Verbose
        $token = Get-PortalToken -PortalHostName $PortalFQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
        if (-not($token.token)) {
            throw "Unable to retrieve Portal Token for '$($PortalAdministrator.UserName)'"
        }

        $securityConfig = Get-PortalSecurityConfig -PortalHostName $PortalFQDN -Token $token.token -Referer $Referer
        if ($($securityConfig.userStoreConfig.type) -ne 'WINDOWS') 
        {
            Write-Verbose "UserStore Config Type is set to :-$($securityConfig.userStoreConfig.type). Changing to Active Directory"
            Set-PortalUserStoreConfig -PortalHostName $PortalFQDN -Token $token.token -ADServiceUser $ADServiceUser -Referer $Referer
        } else {
            Write-Verbose "UserStore Config Type is set to :-$($securityConfig.userStoreConfig.type). No Action required"
        }
    }
    
    Wait-ForUrl "https://$($PortalFQDN):7443/arcgis/portaladmin/healthCheck/?f=json" -Verbose
    Wait-ForUrl "https://$($PortalFQDN):7443/arcgis/sharing/rest/generateToken" -Verbose
    if(-not($token)){
        $token = Get-PortalToken -PortalHostName $PortalFQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
    }

    if(-not($securityConfig)){
        $securityConfig = Get-PortalSecurityConfig -PortalHostName $PortalFQDN -Token $token.token -Referer $Referer
    }
    
    $Info = Invoke-ArcGISWebRequest -Url "https://$($PortalFQDN):7443/arcgis/portaladmin/" -HttpFormParameters @{f = 'json'; token = $token.token; } -Referer $Referer -HttpMethod 'GET'
    $VersionArray = "$($Info.version)".Split('.')
    $SecurityPropertiesModifiedCheck = $False
    if(-not([string]::IsNullOrEmpty($DefaultRoleForUser)) -or -not([string]::IsNullOrEmpty($DefaultUserLicenseTypeIdForUser))){
        if($VersionArray[0] -eq 10 -and $VersionArray[1] -lt 8){
            if(-not([string]::IsNullOrEmpty($DefaultRoleForUser))){
                Write-Verbose "Current Default Role for User Setting:- $($securityConfig.defaultRoleForUser)" 
                if ($securityConfig.defaultRoleForUser -ne $DefaultRoleForUser) {
                    $securityConfig.defaultRoleForUser = $DefaultRoleForUser
                    $SecurityPropertiesModifiedCheck = $True
                }else{
                    Write-Verbose "Default Role for User already set to $DefaultRoleForUser"
                }
            }
            
            if(-not([string]::IsNullOrEmpty($DefaultUserLicenseTypeIdForUser))){
                Write-Verbose "Current Default User Type Setting:- $($securityConfig.defaultUserTypeIdForUser)" 
                if ($securityConfig.defaultUserTypeIdForUser -ne $DefaultUserLicenseTypeIdForUser) {
                    $securityConfig.defaultUserTypeIdForUser = $DefaultUserLicenseTypeIdForUser
                    $SecurityPropertiesModifiedCheck = $True
                }else{
                    Write-Verbose "Default User Type already set to $DefaultUserLicenseTypeIdForUser"
                }
            }
        }else{
            $UserDefaultsModified = $False
            
            $userDefaults = (Get-PortalUserDefaults -PortalHostName $PortalFQDN -Token $token.token -Referer $Referer -Verbose)
            
            if(-not([string]::IsNullOrEmpty($DefaultRoleForUser)) ){
                Write-Verbose "Current Default Role for User Setting:- $($userDefaults.role)" 
                if ($userDefaults.role -ne $DefaultRoleForUser) {
                    Write-Verbose "Current Default Role for User does not match. Updating it."
                    if("role" -in $userDefaults.PSobject.Properties.Name){
                        $userDefaults.role = $DefaultRoleForUser
                    }else{
                        Add-Member -InputObject $userDefaults -NotePropertyName 'role' -NotePropertyValue $DefaultRoleForUser
                    }
                    $UserDefaultsModified = $True
                }else{
                    Write-Verbose "Default Role for User already set to $DefaultRoleForUser"
                }
            }

            if(-not([string]::IsNullOrEmpty($DefaultUserLicenseTypeIdForUser))){
                Write-Verbose "Current Default User Type Setting:- $($userDefaults.userLicenseType)" 
                if ($userDefaults.userLicenseType -ne $DefaultUserLicenseTypeIdForUser) {
                    Write-Verbose "Current Default User Type does not match. Updating it."
                    if("userLicenseType" -in $userDefaults.PSobject.Properties.Name){
                        $userDefaults.userLicenseType = $DefaultUserLicenseTypeIdForUser
                    }else{
                        Add-Member -InputObject $userDefaults -NotePropertyName 'userLicenseType' -NotePropertyValue $DefaultUserLicenseTypeIdForUser
                    }
                    $UserDefaultsModified = $True
                }else{
                    Write-Verbose "Default User Type already set to $DefaultUserLicenseTypeIdForUser"
                }
            }

            if($UserDefaultsModified){
                Write-Verbose "Updating Portal User Defaults"
                Set-PortalUserDefaults -PortalHostName $PortalFQDN -Token $token.token -UserDefaultsParameters $userDefaults -Referer $Referer
            }
        }
    }   
        
    $EnableAutoAccountCreationStatus = if ($securityConfig.enableAutomaticAccountCreation -ne $True) { 'disabled' } else { 'enabled' }
    Write-Verbose "Current Automatic Account Creation Setting:- $EnableAutoAccountCreationStatus" 
    if ($securityConfig.enableAutomaticAccountCreation -ne $EnableAutomaticAccountCreation) {
        
        $securityConfig.enableAutomaticAccountCreation = $EnableAutomaticAccountCreation
        $SecurityPropertiesModifiedCheck = $True
    }else{
        Write-Verbose "Automatic Account Creation already $EnableAutoAccountCreationStatus"
    }
    
    $dirStatus = if ($securityConfig.disableServicesDirectory -ne $True) { 'enabled' } else { 'disabled' }
    Write-Verbose "Current Service Directory Setting:- $dirStatus"
    if ($securityConfig.disableServicesDirectory -ne $DisableServiceDirectory) {
        $securityConfig.disableServicesDirectory = $DisableServiceDirectory
        $SecurityPropertiesModifiedCheck = $True
    } else {
        Write-Verbose "Service directory already $dirStatus"
    }

    if($SecurityPropertiesModifiedCheck){
        Write-Verbose "Updating portal security configuration"
        Set-PortalSecurityConfig -PortalHostName $PortalFQDN -Token $token.token -SecurityParameters (ConvertTo-Json $securityConfig -Depth 10) -Referer $Referer -Verbose
    }

    if($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 8) -or $Info.Version -eq "10.8.1"){
        $UpdateEmailSettingsFlag = $False
        try{
            $PortalEmailSettings = Get-PortalEmailSettings -PortalHostName $PortalFQDN -Token $token.token -Referer $Referer
            if(-not($EnableEmailSettings)){
                Write-Verbose "Deleting Portal Email Settings"
                Remove-PortalEmailSettings -PortalHostName $PortalFQDN -Token $token.token -Referer $Referer -Verbose
            }else{
                if(-not($PortalEmailSettings.smtpHost -ieq $EmailSettingsSMTPServerAddress -and $PortalEmailSettings.smtpPort -ieq $EmailSettingsSMTPPort -and $PortalEmailSettings.mailFrom -ieq $EmailSettingsFrom -and $PortalEmailSettings.mailFromLabel -ieq $EmailSettingsLabel -and $PortalEmailSettings.encryptionMethod -ieq $EmailSettingsEncryptionMethod -and $PortalEmailSettings.authRequired -ieq $EmailSettingsAuthenticationRequired -and (($EmailSettingsAuthenticationRequired -ieq $False) -or ($EmailSettingsAuthenticationRequired -ieq $True -and  $PortalEmailSettings.smtpUser -ieq $EmailSettingsCredential.UserName -and $PortalEmailSettings.smtpPass -ieq $EmailSettingsCredential.GetNetworkCredential().Password)))){
                    $UpdateEmailSettingsFlag = $True
                }else{
                    Write-Verbose "Portal Email settings configured correctly."
                }
            }
        }catch{
            if($EnableEmailSettings){
                $UpdateEmailSettingsFlag = $True
            }else{
                Write-Verbose "Portal Email settings configured correctly."
            }
        }

        if($UpdateEmailSettingsFlag){
            Write-Verbose "Updating Portal Email Settings"
            Update-PortalEmailSettings -PortalHostName $PortalFQDN -SMTPServerAddress $EmailSettingsSMTPServerAddress -From $EmailSettingsFrom -Label $EmailSettingsLabel -AuthenticationRequired $EmailSettingsAuthenticationRequired -Credential $EmailSettingsCredential -SMTPPort $EmailSettingsSMTPPort -EncryptionMethod $EmailSettingsEncryptionMethod -Token $token.token -Referer $Referer -Verbose
        }
    }
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [parameter(Mandatory = $false)]
		[System.String]
		$ExternalDNSName,

		[parameter(Mandatory = $false)]
		[System.String]
		$PortalContext,
        
	    [parameter(Mandatory = $true)]
		[System.String]
		$PortalHostName,

		[System.String]
        $PortalEndPoint,
        
        [System.Int32]
        $PortalEndPointPort = 7443,

        [System.String]
        $PortalEndPointContext = 'arcgis',

		[System.Management.Automation.PSCredential]
		$PortalAdministrator,

        [System.Management.Automation.PSCredential]
        $ADServiceUser,

        [System.Boolean]
        $EnableAutomaticAccountCreation,

        [System.String]
        $DefaultRoleForUser,

        [System.String]
        $DefaultUserLicenseTypeIdForUser,

        [System.Boolean]
        $DisableServiceDirectory,

        [System.Boolean]
        $DisableAnonymousAccess,

        [System.Boolean]
        $EnableEmailSettings,

        [System.String]
        $EmailSettingsSMTPServerAddress,

        [System.String]
        $EmailSettingsFrom,

        [System.String]
        $EmailSettingsLabel,

        [System.Boolean]
        $EmailSettingsAuthenticationRequired = $False,

        [System.Management.Automation.PSCredential]
        $EmailSettingsCredential,

        [System.Int32]
        $EmailSettingsSMTPPort = 25,

        [ValidateSet("SSL", "TLS", "NONE")]
        [System.String]
        $EmailSettingsEncryptionMethod = "NONE"
    )

	[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $PortalFQDN = Get-FQDN $PortalHostName
    $Referer = if($ExternalDNSName){"https://$($ExternalDNSName)/$($PortalContext)"}else{"https://localhost"}
	Write-Verbose "Getting Portal Token for user '$($PortalAdministrator.UserName)' from 'https://$($PortalFQDN):7443'"

	$PortalToken = Get-PortalToken -PortalHostName $PortalFQDN -Port 7443 -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
	if(-not($PortalToken.token)) {
		throw "Unable to retrieve Portal Token for '$($PortalAdministrator.UserName)'"
	}else {
		Write-Verbose "Retrieved Portal Token"
	}
	Write-Verbose "Connected to Portal successfully and retrieved token for '$($PortalAdministrator.UserName)'"

	$result = $true
    Write-Verbose "Get System Properties"
    # Check if web context URL is set correctly							
    $sysProps = Get-PortalSystemProperties -PortalHostName $PortalFQDN -Token $PortalToken.token -Referer $Referer
    if($sysProps) {
		Write-Verbose "System Properties:- $(ConvertTo-Json $sysProps -Depth 3 -Compress)"
        if($ExternalDNSName){
            $ExpectedWebContextUrl = "https://$($ExternalDNSName)/$($PortalContext)"	
            if ($sysProps.WebContextURL -ieq $ExpectedWebContextUrl) {
                Write-Verbose "Portal System Properties > WebContextUrl is correctly set to '$($ExpectedWebContextUrl)'"
            } else {
                $result = $false
                Write-Verbose "Portal System Properties > WebContextUrl is NOT correctly set to '$($ExpectedWebContextUrl)'"
            }
        }

        if ($result) {
            if($PortalEndPoint){
                # Check if private portal URL is set correctly
                $ExpectedPrivatePortalUrl = if($PortalEndPointPort -ieq 443){ "https://$($PortalEndPoint)/$($PortalEndPointContext)" }else{ "https://$($PortalEndPoint):$($PortalEndPointPort)/$($PortalEndPointContext)" }
                if ($sysProps.privatePortalURL -ieq $ExpectedPrivatePortalUrl) {						
                    Write-Verbose "Portal System Properties > privatePortalURL is correctly set to '$($ExpectedPrivatePortalUrl)'"
                } else {
                    $result = $false
                    Write-Verbose "Portal System Properties > privatePortalURL is NOT correctly set to '$($ExpectedPrivatePortalUrl)'"
                }
            }
        }
    }else {
        Write-Verbose "System Properties is NULL"
    }

    if ($result){
        try {
            Wait-ForUrl "https://$($PortalFQDN):7443/arcgis/portaladmin/healthCheck/?f=json" -Verbose
            Wait-ForUrl "https://$($PortalFQDN):7443/arcgis/sharing/rest/generateToken" -Verbose
            $token = Get-PortalToken -PortalHostName $PortalFQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer     

            Write-Verbose "Checking If Portal on HTTPS_Only" #Need to check this condition
            $PortalSelf = Get-PortalSelfDescription -PortalHostName $PortalFQDN -Token $token.token -Referer $Referer
            $result = $PortalSelf.allSSL
        }
        catch {
            Write-Verbose "[WARNING]:- Exception:- $($_)"   
            $result = $false
        }
    }
    
    if ($result){
        try {
            Wait-ForUrl "https://$($PortalFQDN):7443/arcgis/portaladmin/healthCheck/?f=json" -Verbose
            Wait-ForUrl "https://$($PortalFQDN):7443/arcgis/sharing/rest/generateToken" -Verbose
            $token = Get-PortalToken -PortalHostName $PortalFQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer

            Write-Verbose "Checking if Portal allows anonymous access"
            $PortalSelf = Get-PortalSelfDescription -PortalHostName $PortalFQDN -Token $token.token -Referer $Referer

            if($DisableAnonymousAccess){
                if($PortalSelf.access -ieq 'public'){
                    Write-Verbose "Anonymous access is not disabled"
                    $result = $false
                }else{
                    Write-Verbose "Anonymous access is disabled."
                }
            }else{
                if($PortalSelf.access -ieq 'private'){
                    Write-Verbose "Anonymous access is not enabled"
                    $result = $false
                }else{
                    Write-Verbose "Anonymous access is enabled." 
                }
            }
        }
        catch {
            Write-Verbose "[WARNING]:- Exception:- $($_)"   
            $result = $false
        }
    }

    Wait-ForUrl "https://$($PortalFQDN):7443/arcgis/portaladmin/healthCheck/?f=json" -Verbose
    Wait-ForUrl "https://$($PortalFQDN):7443/arcgis/sharing/rest/generateToken" -Verbose
    if (-not($token)){
        $token = Get-PortalToken -PortalHostName $PortalFQDN -SiteName 'arcgis' -Credential $PortalAdministrator -Referer $Referer
    }
    if (-not($securityConfig)){
        $securityConfig = Get-PortalSecurityConfig -PortalHostName $PortalFQDN -Token $token.token -Referer $Referer
    }

    if ($ADServiceUser.UserName) {
        if ($($securityConfig.userStoreConfig.type) -ne 'WINDOWS') {
            Write-Verbose "UserStore Config Type is set to :-$($securityConfig.userStoreConfig.type)"
            $result = $false
        } else {
            Write-Verbose "UserStore Config Type is set to :-$($securityConfig.userStoreConfig.type). No Action required"
        }
    }
    
    if ($result) {
        $dirStatus = if ($securityConfig.disableServicesDirectory -ne "true") { 'enabled' } else { 'disabled' }
        Write-Verbose "Current Service Directory Setting:- $dirStatus"
        if ($securityConfig.disableServicesDirectory -ne $DisableServiceDirectory) {
            Write-Verbose "Service directory setting does not match. Updating it."
            $result = $false
        }  
    }

    if ($result) {
        $EnableAutoAccountCreationStatus = if ($securityConfig.enableAutomaticAccountCreation -ne "true") { "disabled" } else { 'enabled' }
        Write-Verbose "Current Automatic Account Creation Setting:- $EnableAutoAccountCreationStatus" 
        if ($securityConfig.enableAutomaticAccountCreation -ne $EnableAutomaticAccountCreation) {
            Write-Verbose "EnableAutomaticAccountCreation setting doesn't match, Updating it."
            $result = $false
        }
    }

	$Info = Invoke-ArcGISWebRequest -Url "https://$($PortalFQDN):7443/arcgis/portaladmin/" -HttpFormParameters @{f = 'json'; token = $token.token; } -Referer $Referer -HttpMethod 'GET'
    $VersionArray = "$($Info.version)".Split('.')
    if($VersionArray[0] -eq 10 -and $VersionArray[1] -lt 8){
        if ($result -and -not([string]::IsNullOrEmpty($DefaultRoleForUser))) {
            Write-Verbose "Current Default Role for User Setting:- $($securityConfig.defaultRoleForUser)"
            if ($securityConfig.defaultRoleForUser -ne $DefaultRoleForUser) {
                Write-Verbose "Current Default Role for User does not match. Updating it."
                $result = $false
            }
        }

        if ($result -and -not([string]::IsNullOrEmpty($DefaultUserLicenseTypeIdForUser))) {
            Write-Verbose "Current Default User Type Setting:- $($securityConfig.defaultUserTypeIdForUser)"
            if ($securityConfig.defaultUserTypeIdForUser -ne $DefaultUserLicenseTypeIdForUser) {
                Write-Verbose "Current Default User Type does not match. Updating it."
                $result = $false
            }
        }
    }else{
        $userDefaults = Get-PortalUserDefaults -PortalHostName $PortalFQDN -Token $token.token -Referer $Referer
        if ($result -and -not([string]::IsNullOrEmpty($DefaultRoleForUser))) {
            Write-Verbose "Current Default Role for User Setting:- $($userDefaults.role)" 
            if ($userDefaults.role -ne $DefaultRoleForUser) {
                Write-Verbose "Current Default Role for User does not match. Updating it."
                $result = $false
            }
        }

        if ($result -and -not([string]::IsNullOrEmpty($DefaultUserLicenseTypeIdForUser))) {
            Write-Verbose "Current Default User Type Setting:- $($userDefaults.userLicenseType)" 
            if ($userDefaults.userLicenseType -ne $DefaultUserLicenseTypeIdForUser) {
                Write-Verbose "Current Default User Type does not match. Updating it."
                $result = $false
            }
        }
    }

    if($result -and ($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 8) -or $Info.Version -eq "10.8.1")){
        Write-Verbose "Checking Portal Email settings."
        try{
            $PortalEmailSettings = Get-PortalEmailSettings -PortalHostName $PortalFQDN -Token $token.token -Referer $Referer
            if(-not($EnableEmailSettings) -or ($EnableEmailSettings -eq $True -and -not($PortalEmailSettings.smtpHost -ieq $EmailSettingsSMTPServerAddress -and $PortalEmailSettings.smtpPort -ieq $EmailSettingsSMTPPort -and $PortalEmailSettings.mailFrom -ieq $EmailSettingsFrom -and $PortalEmailSettings.mailFromLabel -ieq $EmailSettingsLabel -and $PortalEmailSettings.encryptionMethod -ieq $EmailSettingsEncryptionMethod -and $PortalEmailSettings.authRequired -ieq $EmailSettingsAuthenticationRequired -and (($EmailSettingsAuthenticationRequired -ieq $False) -or ($EmailSettingsAuthenticationRequired -ieq $True -and  $PortalEmailSettings.smtpUser -ieq $EmailSettingsCredential.UserName -and $PortalEmailSettings.smtpPass -ieq $EmailSettingsCredential.GetNetworkCredential().Password))))){
                $result = $false
            }else{
                Write-Verbose "Portal Email settings configured correctly."
            }
        }catch{
            if($EnableEmailSettings){
                $result = $false
            }else{
                Write-Verbose "Portal Email settings configured correctly."
            }
        }
    }

	$result
}

function Get-PortalSystemProperties {
    [CmdletBinding()]
    param(        
        [System.String]
		$PortalHostName, 

        [System.String]
		$Token, 

        [System.String]
		$Referer = 'http://localhost'
    )
    
    Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):7443/arcgis/portaladmin/system/properties/") -HttpMethod 'GET' -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer 
}

function Set-PortalSystemProperties {
    [CmdletBinding()]
    param(
        
        [System.String]
		$PortalHostName, 

        [System.String]
		$Token, 

        [System.String]
		$Referer = 'http://localhost',

        $Properties
    )
    
    try {
        Invoke-ArcGISWebRequest -Url("https://$($PortalHostName):7443/arcgis/portaladmin/system/properties/update/") `
                            -HttpFormParameters @{ f = 'json'; token = $Token; properties = (ConvertTo-Json $Properties -Depth 4) } `
                            -Referer $Referer -TimeOutSec 360
    }
    catch {
        Write-Verbose "[WARNING] Request to Set-PortalSystemProperties returned error:- $_"
    }
}

function Get-PortalSecurityConfig {
    [CmdletBinding()]
    param(
        [System.String]
        $PortalHostName,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost'
    )   

    Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):7443/arcgis/portaladmin/security/config") `
                        -HttpFormParameters @{ f = 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET'
}

function Set-PortalSecurityConfig {
    [CmdletBinding()]
    param(
        [System.String]
        $PortalHostName,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost',

        [System.String]
        $SecurityParameters
    )   

    $params = @{ f = 'json'; token = $Token; securityConfig = $SecurityParameters;}
    
    $resp = Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):7443/arcgis/portaladmin/security/config/update") `
                        -HttpFormParameters $params -Referer $Referer -TimeOutSec 100 -Verbose
    if($resp.error -and $resp.error.message){
        throw "[Error] - Set-PortalSecurityConfig Response:- $($resp.error.message)"
    }
}

function Set-PortalUserStoreConfig {
    [CmdletBinding()]
    param(
        [System.String]
        $PortalHostName,
        
        [System.String]
        $Token, 

        [System.String]
        $Referer = 'http://localhost',

        [System.Management.Automation.PSCredential]
        $ADServiceUser
    )

    $userStoreConfig = '{
        "type": "WINDOWS",
        "properties": {
            "userPassword": "' + $($ADServiceUser.GetNetworkCredential().Password) +'",
            "isPasswordEncrypted": "false",
            "user": "' + $($ADServiceUser.UserName.Replace("\","\\")) +'",
            "userFullnameAttribute": "cn",
            "userEmailAttribute": "mail",
            "userGivenNameAttribute": "givenName",
            "userSurnameAttribute": "sn",
            "caseSensitive": "false"
        }
    }'

    $response = Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):7443/arcgis/portaladmin/security/config/updateIdentityStore") `
                                -HttpFormParameters @{ f = 'json'; token = $Token; userStoreConfig = $userStoreConfig; } `
                                -Referer $Referer -TimeOutSec 300 -Verbose
    if ($response.error) {
        throw "Error in Set-PortalUserStoreConfig:- $($response.error)"
    } else {
        Write-Verbose "Response received from Portal Set UserStoreconfig:- $response"
    }
}

function Get-PortalUserDefaults{
    [CmdletBinding()]
    param(
        [System.String]
        $PortalHostName,
        
        [System.String]
        $Token, 

        [System.String]
        $Referer = 'http://localhost'
    )
    
    Invoke-ArcGISWebRequest -Url "https://$($PortalHostName):7443/arcgis/sharing/rest/portals/self/userDefaultSettings" `
                        -HttpFormParameters @{ f = 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET'
}

function Set-PortalUserDefaults{
    [CmdletBinding()]
    param(
        [System.String]
        $PortalHostName,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost',

        $UserDefaultsParameters
    )

	$params = @{ 
                f = 'json'; 
                token = $Token;
                role = $UserDefaultsParameters.role;
                userLicenseType = $UserDefaultsParameters.userLicenseType;
                groups = $UserDefaultsParameters.groups;
                userType = $UserDefaultsParameters.userType;
                apps = $UserDefaultsParameters.apps;
                appBundles = $UserDefaultsParameters.appBundles;
            }
    
    $resp = Invoke-ArcGISWebRequest -Url "https://$($PortalHostName):7443/arcgis/sharing/rest/portals/self/setUserDefaultSettings" -HttpFormParameters $params -Referer $Referer -Verbose
    if($resp.error -and $resp.error.message){
        throw "[Error] - Set-PortalUserDefaults Response:- $($resp.error.message)"
    }
}

function Get-PortalSelfDescription {
    [CmdletBinding()]
    param(        
        [System.String]
        $PortalHostName = 'localhost', 

        [System.String]
        $Token, 

        [System.String]
        $Referer = 'http://localhost'
    )
    
    Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):7443/arcgis/sharing/rest/portals/self/") `
                        -HttpMethod 'GET' -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer 
}

function Set-PortalSelfDescription 
{
    [CmdletBinding()]
    param(
        
        [System.String]
        $PortalHostName,

        [System.String]
        $Token, 

        [System.String]
        $Referer = 'http://localhost',

        $Properties
    )
    
    try {
        $Properties += @{ token = $Token; f = 'json' }
        Invoke-ArcGISWebRequest -Url("https://$($PortalHostName):7443/arcgis/sharing/rest/portals/self/update/") `
                            -HttpFormParameters $Properties -Referer $Referer -TimeOutSec 360
    }
    catch {
        Write-Verbose "[WARNING] Request to Set-PortalSelfDescription returned error:- $_"
    }
}

function Get-PortalEmailSettings
{
    [CmdletBinding()]
    param(
        [System.String]
        $PortalHostName,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost'
    ) 
    
    $resp = Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):7443/arcgis/portaladmin/system/emailSettings") `
                        -HttpFormParameters @{ f = 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET'
						
    if($resp.status -and $resp.status -ieq "error"){
        throw "[Error] - Get-PortalEmailSettings Response:- $($resp.messages)"
    }
	
	$resp 
}

function Update-PortalEmailSettings
{
    [CmdletBinding()]
    param(
        [System.String]
        $PortalHostName,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost',

        [System.String]
        $SMTPServerAddress,

        [System.String]
        $From,

        [System.String]
        $Label,

        [System.Boolean]
        $AuthenticationRequired = $False,

        [System.Management.Automation.PSCredential]
        $Credential,
        
        [System.Int32]
        $SMTPPort = 25,
         
        [System.String]
        $EncryptionMethod
    )

    $emailSettingObject = @{
        smtpServer = $SMTPServerAddress;
        fromEmailAddress = $From;
        fromEmailAddressLabel = $Label;
        authRequired = if($AuthenticationRequired){ "yes" }else{ "no" };
        smtpPort = $SMTPPort;
        encryptionMethod = $EncryptionMethod;
		f = 'json'; 
		token = $Token;
    }

    if($AuthenticationRequired){
        $emailSettingObject.Add("username",$Credential.UserName)
        $emailSettingObject.Add("password",$Credential.GetNetworkCredential().Password)
    }

    $resp = Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):7443/arcgis/portaladmin/system/emailSettings/update") `
                        -HttpFormParameters $emailSettingObject -Referer $Referer -Verbose
    if($resp.error -and $resp.error.message){
        throw "[Error] - Update-PortalEmailSettings Response:- $($resp.error.message)"
    }else{
        if($resp.status -and $resp.status -ieq "success"){
            if ($null -ne $resp.recheckAfterSeconds) {
                Write-Verbose "Sleeping for $($resp.recheckAfterSeconds*2) seconds"
                Start-Sleep -Seconds ($resp.recheckAfterSeconds * 2)
            }
            Write-Verbose "Update-PortalEmailSettings successful."
        }
    }
}

function Remove-PortalEmailSettings
{
    [CmdletBinding()]
    param(
        [System.String]
        $PortalHostName,

        [System.String]
        $Token,

        [System.String]
        $Referer = 'http://localhost'
    )  
    
    $resp = Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):7443/arcgis/portaladmin/system/emailSettings/delete") `
                        -HttpFormParameters @{ f = 'json'; token = $Token; } -Referer $Referer -Verbose
    if($resp.error -and $resp.error.message){
        throw "[Error] - Remove-PortalEmailSettings Response:- $($resp.error.message)"
    }
}

Export-ModuleMember -Function *-TargetResource