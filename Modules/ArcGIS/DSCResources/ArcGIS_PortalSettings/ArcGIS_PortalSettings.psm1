$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.Portal.psm1'))

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$PortalHostName,

        [parameter(Mandatory = $true)]
		[System.String]
		$Version
	)

	@{}
}

function Set-TargetResource
{
	[CmdletBinding()]
	param(
        [parameter(Mandatory = $true)]
        [System.String]
        $PortalHostName,

        [parameter(Mandatory = $true)]
		[System.String]
		$Version,

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

        [parameter(Mandatory = $false)]
        [System.string]                 
        $HttpProxyHost,

        [parameter(Mandatory = $false)]
        [AllowNull()]
        [Nullable[System.UInt32]]               
        $HttpProxyPort,

        [parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]           
        $HttpProxyCredential,

        [parameter(Mandatory = $false)]
        [System.string]                 
        $HttpsProxyHost,

        [parameter(Mandatory = $false)]
        [AllowNull()]
        [Nullable[System.UInt32]]             
        $HttpsProxyPort,

        [parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]           
        $HttpsProxyCredential,

        [parameter(Mandatory = $false)]
        [System.string]                 
        $NonProxyHosts,

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

    $PortalFQDN = Get-FQDN $PortalHostName
    $Referer = if($ExternalDNSName){"https://$($ExternalDNSName)/$($PortalContext)"}else{"https://localhost"}

    $PortalBaseURL = Get-ArcGISComponentBaseUrl -FQDN $PortalFQDN -ComponentName "Portal"
    Write-Verbose "Getting Portal Token for user '$($PortalAdministrator.UserName)' from '$($PortalBaseURL)'"
    $token = Get-PortalToken -URL $PortalBaseURL -Credential $PortalAdministrator -Referer $Referer

    if(-not($token.token)) {
        throw "Unable to retrieve Portal Token for '$($PortalAdministrator.UserName)'"
    }else {
		Write-Verbose "Retrieved Portal Token"
	}
    Write-Verbose "Connected to Portal successfully and retrieved token for '$($PortalAdministrator.UserName)'"

	$sysProps = Get-PortalSystemProperties -URL $PortalBaseURL -Token $token.token -Referer $Referer
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
    # checking forward proxy settings
	if ($HttpProxyHost) {
		if(-not($sysProps.HttpProxyHost)) {
			Add-Member -InputObject $sysProps -MemberType NoteProperty -Name 'httpProxyHost' -Value $HttpProxyHost
		}else{
			$sysProps.HttpProxyHost = $HttpProxyHost
		}
		$UpdateSystemProperties = $true
	}
	elseif ($sysProps.HttpProxyHost) {
        # JSON removed it, so clear it
        $sysProps.PSObject.Properties.Remove('httpProxyHost')
        $UpdateSystemProperties = $true
    }
	if ($HttpProxyPort) {
		if(-not($sysProps.HttpProxyPort)) {
			Add-Member -InputObject $sysProps -MemberType NoteProperty -Name 'httpProxyPort' -Value $HttpProxyPort
		}else{
			$sysProps.HttpProxyPort = $HttpProxyPort
		}
		$UpdateSystemProperties = $true
	}
	elseif ($sysProps.HttpProxyPort) {
        $sysProps.PSObject.Properties.Remove('httpProxyPort')
        $UpdateSystemProperties = $true
    }
	if ($HttpProxyCredential) {
		if(-not($sysProps.HttpProxyUser)) {
			Add-Member -InputObject $sysProps -MemberType NoteProperty -Name 'httpProxyUser' -Value $HttpProxyCredential.UserName
		}else{
			$sysProps.HttpProxyUser = $HttpProxyCredential.UserName
		}
		if(-not($sysProps.HttpProxyPassword)) {
			Add-Member -InputObject $sysProps -MemberType NoteProperty -Name 'httpProxyPassword' -Value $HttpProxyCredential.GetNetworkCredential().Password
		}else{
			$sysProps.HttpProxyPassword = $HttpProxyCredential.GetNetworkCredential().Password
		}
		$UpdateSystemProperties = $true
	}
	elseif ($sysProps.HttpProxyUser -or $sysProps.HttpProxyPassword) {
        $sysProps.PSObject.Properties.Remove('httpProxyUser')
        $sysProps.PSObject.Properties.Remove('httpProxyPassword')
        $UpdateSystemProperties = $true
    }
	# Forward proxy HTTPS Proxy: set or clear
	if ($HttpsProxyHost) {
		if(-not($sysProps.HttpsProxyHost)) {
			Add-Member -InputObject $sysProps -MemberType NoteProperty -Name 'httpsProxyHost' -Value $HttpsProxyHost
		}else{
			$sysProps.HttpsProxyHost = $HttpsProxyHost
		}
		$UpdateSystemProperties = $true
	}
	elseif ($sysProps.HttpsProxyHost) {
        # JSON removed it, so clear it
        $sysProps.PSObject.Properties.Remove('httpsProxyHost')
        $UpdateSystemProperties = $true
    }
	if ($HttpsProxyPort) {
		if(-not($sysProps.HttpsProxyPort)) {
			Add-Member -InputObject $sysProps -MemberType NoteProperty -Name 'httpsProxyPort' -Value $HttpsProxyPort
		}else{
			$sysProps.HttpsProxyPort = $HttpsProxyPort
		}
		$UpdateSystemProperties = $true
	}
	elseif ($sysProps.HttpsProxyPort) {
        $sysProps.PSObject.Properties.Remove('httpsProxyPort')
        $UpdateSystemProperties = $true
    }
	if ($HttpsProxyCredential) {
		if(-not($sysProps.HttpsProxyUser)) {
			Add-Member -InputObject $sysProps -MemberType NoteProperty -Name 'httpsProxyUser' -Value $HttpsProxyCredential.UserName
		}else{
			$sysProps.HttpsProxyUser = $HttpsProxyCredential.UserName
		}
		if(-not($sysProps.HttpsProxyPassword)) {
			Add-Member -InputObject $sysProps -MemberType NoteProperty -Name 'httpsProxyPassword' -Value $HttpsProxyCredential.GetNetworkCredential().Password
		}else{
			$sysProps.HttpsProxyPassword = $HttpsProxyCredential.GetNetworkCredential().Password
		}
		$UpdateSystemProperties = $true
	}
	elseif ($sysProps.HttpsProxyUser -or $sysProps.HttpsProxyPassword) {
        $sysProps.PSObject.Properties.Remove('httpsProxyUser')
        $sysProps.PSObject.Properties.Remove('httpsProxyPassword')
        $UpdateSystemProperties = $true
    }

	if ($NonProxyHosts) {
		if(-not($sysProps.NonProxyHosts)) {
			Add-Member -InputObject $sysProps -MemberType NoteProperty -Name 'nonProxyHosts' -Value $NonProxyHosts
		}else{
			$sysProps.NonProxyHosts = $NonProxyHosts
		}
		$UpdateSystemProperties = $true
	}
	elseif ($sysProps.NonProxyHosts) {
        $sysProps.PSObject.Properties.Remove('nonProxyHosts')
        $UpdateSystemProperties = $true
    }
    
    if($UpdateSystemProperties){
        Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "Portal" -Verbose
        Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "PortalSharing" -Verbose
        
        Write-Verbose "Updating Portal System Properties"
        try {    
            Set-PortalSystemProperties -URL $PortalBaseURL -Token $token.token -Referer $Referer -Properties $sysProps
        } catch {
            Write-Verbose "Error setting Portal System Properties :- $_ .Props - $sysProps"
        }
        Write-Verbose "Updated Portal System Properties."
        
        Wait-ForArcGISComponentRestart -BaseURL $PortalBaseURL -ComponentName "Portal" -RestartComponentName "PortalSharing" -MaxRestartWaitTimeInSeconds 300 -Verbose
    }

    Write-Verbose "Getting Portal Token for user '$($PortalAdministrator.UserName)' from '$($PortalBaseURL)'"
    $token = Get-PortalToken -URL $PortalBaseURL -Credential $PortalAdministrator -Referer $Referer
    if (-not($token.token)) {
        throw "Unable to retrieve Portal Token for '$($PortalAdministrator.UserName)'"
    }
    Write-Verbose "Connected to Portal successfully and retrieved token for $($PortalAdministrator.UserName)"
    Write-Verbose "Checking If Portal on HTTPS_Only"
    $PortalSelf = Get-PortalSelfDescription -URL $PortalBaseURL -Token $token.token -Referer $Referer
    if(-not($PortalSelf.allSSL))
    {
        Write-Verbose "Setting Portal to HTTPS_Only"
        $PortalSelfResponse = Set-PortalSelfDescription -URL $PortalBaseURL -Token $token.token -Referer $Referer -Properties @{ allSSL = 'true' }
        Write-Verbose $PortalSelfResponse
    }

    Write-Verbose "Checking if Portal allows anonymous access"
    $PortalSelf = Get-PortalSelfDescription -URL $PortalBaseURL -Token $token.token -Referer $Referer
    if($DisableAnonymousAccess){
        if($PortalSelf.access -ieq 'public'){
            Write-Verbose "Disabling anonymous access"
            $PortalSelfResponse = Set-PortalSelfDescription -URL $PortalBaseURL -Token $token.token -Referer $Referer -Properties @{ access = 'private' }
            Write-Verbose $PortalSelfResponse
        }else{
            Write-Verbose "Anonymous access is Disabled."
        }
    }else{
        if($PortalSelf.access -ieq 'private'){
            Write-Verbose "Enabling anonymous access"
            $PortalSelfResponse = Set-PortalSelfDescription -URL $PortalBaseURL -Token $token.token -Referer $Referer -Properties @{ access = 'public' }
            Write-Verbose $PortalSelfResponse
        }else{
            Write-Verbose "Anonymous access is Enabled." 
        }
    }

    if ($null -ne $ADServiceUser){
        Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "Portal" -Verbose
        Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "PortalSharing" -Verbose
        
        $token = Get-PortalToken -URL $PortalBaseURL -Credential $PortalAdministrator -Referer $Referer
        if (-not($token.token)) {
            throw "Unable to retrieve Portal Token for '$($PortalAdministrator.UserName)'"
        }

        $securityConfig = Get-PortalSecurityConfig -URL $PortalBaseURL -Token $token.token -Referer $Referer
        if ($($securityConfig.userStoreConfig.type) -ne 'WINDOWS') 
        {
            Write-Verbose "UserStore Config Type is set to :-$($securityConfig.userStoreConfig.type). Changing to Active Directory"
            Set-PortalUserStoreConfig -URL $PortalBaseURL -Token $token.token -ADServiceUser $ADServiceUser -Referer $Referer
        } else {
            Write-Verbose "UserStore Config Type is set to :-$($securityConfig.userStoreConfig.type). No Action required"
        }
    }
    
    Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "Portal" -Verbose
    Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "PortalSharing" -Verbose
    if(-not($token)){
        $token = Get-PortalToken -URL $PortalBaseURL -Credential $PortalAdministrator -Referer $Referer
    }

    if(-not($securityConfig)){
        $securityConfig = Get-PortalSecurityConfig -URL $PortalBaseURL -Token $token.token -Referer $Referer
    }
    
    $SecurityPropertiesModifiedCheck = $False
    if(-not([string]::IsNullOrEmpty($DefaultRoleForUser)) -or -not([string]::IsNullOrEmpty($DefaultUserLicenseTypeIdForUser))){
        $UserDefaultsModified = $False
        $userDefaults = (Get-PortalUserDefaults -URL $PortalBaseURL -Token $token.token -Referer $Referer -Verbose)
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
            Set-PortalUserDefaults -URL $PortalBaseURL -Token $token.token -UserDefaultsParameters $userDefaults -Referer $Referer
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
        Set-PortalSecurityConfig -URL $PortalBaseURL -Token $token.token -SecurityParameters (ConvertTo-Json $securityConfig -Depth 10) -Referer $Referer -Verbose
    }
    
    $UpdateEmailSettingsFlag = $False
    try{
        $PortalEmailSettings = Get-PortalEmailSettings -URL $PortalBaseURL -Token $token.token -Referer $Referer
        if(-not($EnableEmailSettings)){
            Write-Verbose "Deleting Portal Email Settings"
            Remove-PortalEmailSettings -URL $PortalBaseURL -Token $token.token -Referer $Referer -Verbose
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
        Update-PortalEmailSettings -URL $PortalBaseURL -SMTPServerAddress $EmailSettingsSMTPServerAddress -From $EmailSettingsFrom -Label $EmailSettingsLabel -AuthenticationRequired $EmailSettingsAuthenticationRequired -Credential $EmailSettingsCredential -SMTPPort $EmailSettingsSMTPPort -EncryptionMethod $EmailSettingsEncryptionMethod -Token $token.token -Referer $Referer -Verbose
    }
    
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param(
        [parameter(Mandatory = $false)]
        [System.String]
        $ExternalDNSName,

        [parameter(Mandatory = $true)]
		[System.String]
		$Version,

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

        [parameter(Mandatory = $false)]
        [System.string]                 
        $HttpProxyHost,

        [parameter(Mandatory = $false)]
        [AllowNull()]
        [Nullable[System.UInt32]]                    
        $HttpProxyPort,

        [parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]           
        $HttpProxyCredential,

        [parameter(Mandatory = $false)]
        [System.string]                 
        $HttpsProxyHost,

        [parameter(Mandatory = $false)]
        [AllowNull()]
        [Nullable[System.UInt32]]                    
        $HttpsProxyPort,

        [parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]           
        $HttpsProxyCredential,

        [parameter(Mandatory = $false)]
        [System.string]                 
        $NonProxyHosts,

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

    $PortalFQDN = Get-FQDN $PortalHostName
    $Referer = if($ExternalDNSName){"https://$($ExternalDNSName)/$($PortalContext)"}else{"https://localhost"}
	
    $PortalBaseURL = Get-ArcGISComponentBaseUrl -FQDN $PortalFQDN -ComponentName "Portal"
    Write-Verbose "Getting Portal Token for user '$($PortalAdministrator.UserName)' from '$($PortalBaseURL)'"
    $token = Get-PortalToken -URL $PortalBaseURL -Credential $PortalAdministrator -Referer $Referer
	if(-not($token.token)) {
		throw "Unable to retrieve Portal Token for '$($PortalAdministrator.UserName)'"
	}else {
		Write-Verbose "Retrieved Portal Token"
	}
	Write-Verbose "Connected to Portal successfully and retrieved token for '$($PortalAdministrator.UserName)'"

	$result = $true
    Write-Verbose "Get System Properties"
    # Check if web context URL is set correctly							
    $sysProps = Get-PortalSystemProperties -URL $PortalBaseURL -Token $token.token -Referer $Referer
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
        #--- begin proxy test block ---
        $ProtocolSettings = @(
            [PSCustomObject]@{ Prefix = 'Http';  CredentialParam = 'HttpProxyCredential'  },
            [PSCustomObject]@{ Prefix = 'Https'; CredentialParam = 'HttpsProxyCredential' }
        )
        foreach ($Protocol in $ProtocolSettings) {
            $Prefix                 = $Protocol.Prefix
            $ProxyHostParamName     = "${Prefix}ProxyHost"
            $ProxyPortParamName     = "${Prefix}ProxyPort"
            $ProxyCredentialParam   = $Protocol.CredentialParam

            # Grab the parameter values by name
            $ProxyHostValue         = Get-Variable -Name $ProxyHostParamName       -ValueOnly
            $ProxyPortValue         = Get-Variable -Name $ProxyPortParamName       -ValueOnly
            $ProxyCredentialValue   = Get-Variable -Name $ProxyCredentialParam     -ValueOnly

            # Grab the server’s current system properties
            $ServerProxyHost        = $sysProps."${Prefix}ProxyHost"
            $ServerProxyPort        = $sysProps."${Prefix}ProxyPort"
            $ServerProxyUser        = $sysProps."${Prefix}ProxyUser"
            $ServerProxyPassword    = $sysProps."${Prefix}ProxyPassword"

            # If user supplied any proxy info, compare them
            if ($ProxyHostValue -or $ProxyPortValue -or $ProxyCredentialValue) {
                if ($ProxyHostValue -and $ServerProxyHost -ne $ProxyHostValue) {
                    Write-Verbose "$Prefix ProxyHost mismatch (`"$ServerProxyHost`" vs `"$ProxyHostValue`")"
                    $result = $false
                }
                if ($ProxyPortValue -and $ServerProxyPort -ne $ProxyPortValue) {
                    Write-Verbose "$Prefix ProxyPort mismatch (`"$ServerProxyPort`" vs `"$ProxyPortValue`")"
                    $result = $false
                }
                if ($ProxyCredentialValue) {
                    $UserName = $ProxyCredentialValue.UserName
                    $Password = $ProxyCredentialValue.GetNetworkCredential().Password

                    if ($ServerProxyUser -ne $UserName) {
                        Write-Verbose "$Prefix ProxyUser mismatch (`"$ServerProxyUser`" vs `"$UserName`")"
                        $result = $false
                    }
                    if ($ServerProxyPassword -ne $Password) {
                        Write-Verbose "$Prefix ProxyPassword mismatch"
                        $result = $false
                    }
                }
            }
            # Otherwise, if nothing in JSON but server has a value => mismatch
            elseif ($ServerProxyHost -or $ServerProxyPort -or $ServerProxyUser -or $ServerProxyPassword) {
                Write-Verbose "$Prefix proxy present on server but absent in JSON"
                $result = $false
            }

            if (-not $result) { break }
        }

        # NonProxyHosts
        if ($result) {
            if ($NonProxyHosts) {
                if ($sysProps.NonProxyHosts -ne $NonProxyHosts) {
                    Write-Verbose "NonProxyHosts mismatch (`"$($sysProps.NonProxyHosts)`" vs `"$NonProxyHosts`")"
                    $result = $false
                }
            }
            elseif ($sysProps.NonProxyHosts) {
                Write-Verbose "NonProxyHosts present on server but absent in JSON"
                $result = $false
            }
        }

        if ($result){
            Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "Portal" -Verbose
            Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "PortalSharing" -Verbose
            try {
                $token = Get-PortalToken -URL $PortalBaseURL -Credential $PortalAdministrator -Referer $Referer

                Write-Verbose "Checking If Portal on HTTPS_Only" #Need to check this condition
                $PortalSelf = Get-PortalSelfDescription -URL $PortalBaseURL -Token $token.token -Referer $Referer
                $result = $PortalSelf.allSSL
            }
            catch {
                Write-Verbose "[WARNING]:- Exception:- $($_)"   
                $result = $false
            }
        }
    
        if ($result){
            Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "Portal" -Verbose
            Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "PortalSharing" -Verbose
            try {
                $token = Get-PortalToken -URL $PortalBaseURL -Credential $PortalAdministrator -Referer $Referer

                Write-Verbose "Checking if Portal allows anonymous access"
                $PortalSelf = Get-PortalSelfDescription -URL $PortalBaseURL -Token $token.token -Referer $Referer

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

        Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "Portal" -Verbose
        Test-ArcGISComponentHealth -BaseURL $PortalBaseURL -ComponentName "PortalSharing" -Verbose
        if (-not($token)){
            $token = Get-PortalToken -URL $PortalBaseURL -Credential $PortalAdministrator -Referer $Referer
        }
        if (-not($securityConfig)){
            $securityConfig = Get-PortalSecurityConfig -URL $PortalBaseURL -Token $token.token -Referer $Referer
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

        $userDefaults = Get-PortalUserDefaults -URL $PortalBaseURL -Token $token.token -Referer $Referer
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
        
        Write-Verbose "Checking Portal Email settings."
        try{
            $PortalEmailSettings = Get-PortalEmailSettings -URL $PortalBaseURL -Token $token.token -Referer $Referer
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
        

	    $result
    }
}

Export-ModuleMember -Function *-TargetResource