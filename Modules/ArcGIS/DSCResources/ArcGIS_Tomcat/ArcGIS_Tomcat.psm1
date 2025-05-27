function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
        [System.String]
        $ExternalDNSName,

        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [ValidateSet("Present","Absent")]
        [parameter(Mandatory = $True)]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [System.String]
        $ServiceName,

        [System.String]
        $InstallerArchivePath,

        [parameter(Mandatory = $false)]
        [System.String]
        $InstallerArchiveOverrideFolderName,

        [System.String]
        $InstallDirectory,

        [System.String]
        $CertificateFileLocation,

        [System.Management.Automation.PSCredential]
        $CertificatePassword,

        [System.String]
        $SSLProtocols = "TLSv1.3,TLSv1.2"
    )

    $null
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
        [System.String]
        $ExternalDNSName,

        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [ValidateSet("Present","Absent")]
        [parameter(Mandatory = $True)]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [System.String]
        $ServiceName,

        [System.String]
        $InstallerArchivePath,

        [parameter(Mandatory = $false)]
        [System.String]
        $InstallerArchiveOverrideFolderName,

        [System.String]
        $InstallDirectory,

        [System.String]
        $CertificateFileLocation,

        [System.Management.Automation.PSCredential]
        $CertificatePassword,

        [System.String]
        $SSLProtocols = "TLSv1.3,TLSv1.2"
    )

    $HttpPort = 80
    $HttpsPort = 443
    $RestartTomcat = $False
    $ServerXMLNeedsUpdate = $False
    if($Ensure -eq "Present"){
        if(-not(Test-ApacheTomcatInstall -TomcatVersion $Version -InstallDirectory $InstallDirectory -TomcatServiceName $ServiceName)){
            Write-Verbose "Installing Apache Tomcat $($TomcatVersion) - '$ServiceName' service. Removing existing installation if present."
            if(Test-Path $InstallDirectory){
                if(Get-Service $ServiceName -ErrorAction Ignore) {
                    Stop-Service -Name $ServiceName -Force 
                    Write-Verbose 'Stopping the service' 
                    Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Stopped'
                    Write-Verbose 'Stopped the service'
                    
                    $service = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'"
                    $service.delete()
                }
                Remove-Item -Recurse -Path "$InstallDirectory\*" -Force -ErrorAction SilentlyContinue    
            }
            
            Expand-Archive -Path $InstallerArchivePath -DestinationPath $InstallDirectory -Force | Out-Null
    
            if([string]::IsNullOrEmpty($InstallerArchiveOverrideFolderName)){
                $InstallerArchiveOverrideFolderName = "apache-tomcat-$($Version)"
            }
    
            $ArchiveContentPath = Join-Path $InstallDirectory $InstallerArchiveOverrideFolderName
            Move-Item -Path $ArchiveContentPath\* -Destination $InstallDirectory -Force
            Remove-Item -Path $ArchiveContentPath -Force
    
            $WebAppFolder = (Join-Path $InstallDirectory "webapps")
            foreach($FolderNameToDelete in @("manager","host-manager","examples", "docs")){
                $FolderToDeletePath = Join-Path $WebAppFolder $FolderNameToDelete
                if(Test-Path $FolderToDeletePath){
                    Remove-Item -Path $FolderToDeletePath -Force -Recurse
                }
            }
    
            Invoke-StartProcess -ExecPath "$InstallDirectory\\bin\\service.bat" -Arguments "install $ServiceName" -CatalinaHome $InstallDirectory -AddJavaEnvironmentVariables $True -Verbose

            Write-Verbose "Configuring service '$ServiceName' to run under Local System account."
            $scResult = sc.exe config "$ServiceName" obj=LocalSystem
            Write-Verbose "sc.exe config output: $scResult"

            
            Write-Verbose "Setting '$ServiceName' service startup to Automatic"
            Set-Service -Name $ServiceName -StartupType Automatic
    
            $ServerXMLNeedsUpdate = $True
        }
    
        $KeyStoreName = "arcgis.keystore"
        $TomcatConf = (Join-Path $InstallDirectory "conf")
        # Determine the correct server XML file based on Tomcat version
        $TomcatVersionArray = $Version.Split(".")
        $TomcatMajor = [int]$TomcatVersionArray[0]
        $TomcatServerXML = Join-Path $TomcatConf "server.xml"

        $KeyStorePath = Join-Path $TomcatConf $KeyStoreName
        $Base64KeyStorePass = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ExternalDNSName))
        if(-not($ServerXMLNeedsUpdate)){
            $ServerXMLNeedsUpdate = -not( Test-ApacheTomcatServerXML -TomcatServerXML $TomcatServerXML -Base64KeyStorePass $Base64KeyStorePass `
                                        -HttpPort $HttpPort -HttpsPort $HttpsPort -CertificateFileLocation $CertificateFileLocation `
                                        -CertificatePassword $CertificatePassword -SSLProtocols $SSLProtocols  -KeyStorePath $KeyStorePath -TomcatMajorVersion $TomcatMajor )
        }
        
        if($ServerXMLNeedsUpdate){
            # Select the appropriate sample based on version
            if ($TomcatMajor -ge 10) {
                $SampleServerXML = Join-Path $PSScriptRoot "server10.xml"
            }
            else {
                $SampleServerXML = Join-Path $PSScriptRoot "server9.xml"
            }
            Copy-Item -Path $SampleServerXML -Destination $TomcatServerXML -Force
            [xml]$ServerXML = Get-Content $TomcatServerXML
            $Connectors = ($ServerXML.Server.Service | Where-Object { $_.name -ieq "Catalina" }).Connector
            foreach($Connector in $Connectors){
                if($Connector.scheme -ieq "https"){
                    $Connector.SetAttribute("port", $HttpsPort)
                    $Connector.SetAttribute("secure", "true")
                    $Connector.SetAttribute("SSLEnabled", "true")
                    if ($TomcatMajor -ge 10) {
                        # For Tomcat 10: Use nested SSLHostConfig and Certificate elements
                        $SSLHostConfig = $Connector.SelectSingleNode("SSLHostConfig")
                        if (-not $SSLHostConfig) {
                            $SSLHostConfig = $ServerXML.CreateElement("SSLHostConfig")
                            $Connector.AppendChild($SSLHostConfig) | Out-Null
                        }
                        $SSLHostConfig.SetAttribute("hostName", "_default_")
                        $SSLHostConfig.SetAttribute("sslEnabledProtocols", $SSLProtocols)
                
                        $Certificate = $SSLHostConfig.SelectSingleNode("Certificate")
                        if (-not $Certificate) {
                            $Certificate = $ServerXML.CreateElement("Certificate")
                            $SSLHostConfig.AppendChild($Certificate) | Out-Null
                        }
                        $Certificate.SetAttribute("certificateKeystoreFile", $KeyStorePath)
                        $Certificate.SetAttribute("certificateKeystorePassword", $Base64KeyStorePass)
                        $Certificate.SetAttribute("certificateKeystoreType", "pkcs12")
                    } else {
                        # For Tomcat 9: Update Connector attributes directly
                        $Connector.SetAttribute("sslEnabledProtocols", $SSLProtocols);
                        $Connector.SetAttribute("keystoreFile", $KeyStorePath);
                        $Connector.SetAttribute("keystorePass", $Base64KeyStorePass);
                    }
                }else{
                    $Connector.SetAttribute("port", $HttpPort);
                }
            }
            $ServerXML.Save($TomcatServerXML)
            $RestartTomcat = $True
        }
    
        
        $CreateKeyStore =  if(-not(Test-Path $KeyStorePath)){ $True }else{ $False }
        $UserProvidedCertificate = $($CertificateFileLocation -and ($null -ne $CertificatePassword) -and (Test-Path $CertificateFileLocation))
        $CertAliasInKeyStore = $ExternalDNSName
        if($UserProvidedCertificate){
            $CertToInstall = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $CertToInstall.Import($CertificateFileLocation, $CertificatePassword.GetNetworkCredential().Password, 'DefaultKeySet')
            $CertAliasInKeyStore = $CertToInstall.Thumbprint
        }
        
        if(-not($CreateKeyStore)){
            Write-Verbose "Key Store Exists. Testing if the key store accessible and certificate is already in the key store"
            try{
                $CertificateInKeyStore = Invoke-StartProcess -ExecPath "keytool.exe" -Arguments " -list -keystore $KeyStoreName -storepass $Base64KeyStorePass -alias $CertAliasInKeyStore" `
                 -AddJavaEnvironmentVariables $true -WorkingDirectory $TomcatConf -Verbose
                if($CertificateInKeyStore -match "^$CertAliasInKeyStore"){
                    Write-Verbose "Certificate with thumbprint $CertAliasInKeyStore found in the key store."
                }else{
                    Write-Verbose "Certificate does not exist in the key store. Deleting the key store"
                    Remove-Item $KeyStorePath -Force
                    $CreateKeyStore = $True
                }
            }catch{
                Write-Verbose "Key Store is not accessible. Deleting the key store. Error - $_"
                $KeytoolProcess = Get-Process | Where-Object { $_.ProcessName -like "keytool*" }
                <#Do this if a terminating exception happens#>
    
                if ($KeytoolProcess) {
                    Write-Verbose "Keytool process detected, attempting to terminate."
                    Stop-Process -Id $KeytoolProcess.Id -Force -ErrorAction SilentlyContinue
                } else {
                    Write-Verbose "No hanging keytool process detected."
                }
                Remove-Item $KeyStorePath -Force
                $CreateKeyStore = $True
            }
        }   
    
        if($CreateKeyStore){
            Write-Verbose "Creating Key Store"
            try {
                if($UserProvidedCertificate){
                    if (Test-Path $CertificateFileLocation) {
                        Write-Verbose "Certificate file location exists, proceeding with keytool execution."
                    } else {
                        Write-Verbose "Certificate file location not found at $CertificateFileLocation. Exiting process."
                        throw "Certificate file location not found at $CertificateFileLocation."
                    }
                    $srcStorePass = $CertificatePassword.GetNetworkCredential().Password

                    # Create a temporary file to capture keytool output
                    $tempOutput = [System.IO.Path]::GetTempFileName()

                    # Use -RedirectStandardOutput to capture keytool's output
                    Start-Process -FilePath "keytool.exe" `
                    -ArgumentList " -v -list -keystore `"$CertificateFileLocation`" -storepass $srcStorePass" `
                    -NoNewWindow -Wait -RedirectStandardOutput $tempOutput -PassThru

                    # Read the output from the temporary file

                    $output = Get-Content $tempOutput -Raw
                    Remove-Item $tempOutput
                    $CertificateAlias = (($output -split "`r`n") | Where-Object { $_ -match "Alias name: " } | Select-Object -First 1 | ForEach-Object { $_.Split(":")[1].Trim() })
                    Write-Verbose "CERT CertificateAlias IS: $($CertificateAlias)"
                    
                    $Arguments = [System.String]::Join("", @(" -importkeystore -noprompt",
                                    " -srcstoretype pkcs12 -alias `"$CertificateAlias`" -srckeystore `"$CertificateFileLocation`" -srcstorepass `"$srcStorePass`"",
                                    " -deststoretype pkcs12 -destalias `"$CertAliasInKeyStore`" -destkeystore `"$KeyStoreName`" -storepass `"$Base64KeyStorePass`""))
                }else{
                    $Arguments = [System.String]::Join("", @(" -genkeypair -noprompt -keystore `"$KeyStoreName`" -keyalg RSA -keysize 2048 -validity 1825",
                                " -storetype PKCS12 -storepass `"$Base64KeyStorePass`" -alias `"$CertAliasInKeyStore`"",
                                " -dname `"CN=$ExternalDNSName`""))
                }
                $CertificateInKeyStore = Invoke-StartProcess -ExecPath "keytool.exe" -Arguments $Arguments -WorkingDirectory $TomcatConf -AddJavaEnvironmentVariables $true -Verbose
                $RestartTomcat = $True
            }
            catch {
                Write-Verbose "An error occurred during keytool execution: $_"
                # Get process details in case keytool is hanging
                $KeytoolProcess = Get-Process | Where-Object { $_.ProcessName -like "keytool*" }
                <#Do this if a terminating exception happens#>
    
                if ($KeytoolProcess) {
                    Write-Verbose "Keytool process detected, attempting to terminate."
                    Stop-Process -Id $KeytoolProcess.Id -Force -ErrorAction SilentlyContinue
                } else {
                    Write-Verbose "No hanging keytool process detected."
                }
            
                # Optionally retry execution (Uncomment below if retry is needed)
                # Write-Verbose "Retrying keytool execution..."
                # Start-Sleep -Seconds 2
                # Restart the process here if needed
            
                throw "Keytool execution failed. Check logs for details."
            }
        }
    
        if($RestartTomcat){
            Write-Verbose "Stop Service '$ServiceName'"
            Stop-Service -Name $ServiceName -Force 
            Write-Verbose 'Stopping the service' 
            Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Stopped'
            Write-Verbose 'Stopped the service'
            Write-Verbose "Restarting Service '$ServiceName' to pick up property change"
            Start-Service $ServiceName 
            Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Running'
            Write-Verbose "Restarted Service '$ServiceName'"
        }
    } elseif ($Ensure -eq "Absent") {
        Write-Verbose "Ensure Absent: Uninstalling Tomcat Server..."
        Write-Verbose "Attempting to uninstall Tomcat Server version '$Version' with service '$ServiceName'."

        # Check if the Tomcat service exists
        $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($existingService) {
            Write-Verbose "Stopping Tomcat service '$ServiceName'..."
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Write-Verbose "Waiting for service '$ServiceName' to stop..."
            Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Stopped'
            Write-Verbose "Service '$ServiceName' has been stopped."

            # Remove the service using WMI
            $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
            if ($wmiService){
                $pathName = $wmiService.PathName
                if ($pathName -match "^(.*)\\bin\\") {
                    $existingInstallDir = $matches[1]
                    # Trim any extra quotes from the directory path
                    $existingInstallDir = $existingInstallDir.Trim('"')
                    Write-Verbose "Detected existing installation directory: $existingInstallDir"
                }
                $wmiService.delete() | Out-Null
                Write-Verbose "Service '$ServiceName' deleted."
            }
        } else {
            Write-Verbose "Tomcat service '$ServiceName' not found. Skipping service removal."
        }
        # If we detected an existing installation directory, use it for cleanup;
        # Otherwise, fall back to the provided $InstallDirectory.
        Write-Verbose "existingInstallDir is: '$existingInstallDir'."
        $cleanupDir = if ($existingInstallDir) { $existingInstallDir } else { $InstallDirectory }
        if (Test-Path $cleanupDir) {
            Write-Verbose "Cleaning up installation directory '$cleanupDir'."
            Remove-Item -Recurse -Path "$cleanupDir" -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [System.String]
        $ExternalDNSName,

        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [ValidateSet("Present","Absent")]
        [parameter(Mandatory = $True)]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [System.String]
        $ServiceName,

        [System.String]
        $InstallerArchivePath,

        [parameter(Mandatory = $false)]
        [System.String]
        $InstallerArchiveOverrideFolderName,

        [System.String]
        $InstallDirectory,

        [System.String]
        $CertificateFileLocation,

        [System.Management.Automation.PSCredential]
        $CertificatePassword,

        [System.String]
        $SSLProtocols = "TLSv1.3,TLSv1.2"
    )

    $HttpPort = 80
    $HttpsPort = 443

    $result = $True
    if($Ensure -eq "Present") {
        $JAVA_HOME = [environment]::GetEnvironmentVariable("JAVA_HOME","Machine")
        $JRE_HOME = [environment]::GetEnvironmentVariable("JRE_HOME","Machine")
        if (-not((-not([string]::IsNullOrEmpty($JAVA_HOME)) -and (Test-Path -Path "$($JAVA_HOME)")) -or (-not([string]::IsNullOrEmpty($JRE_HOME)) -and (Test-Path -Path "$($JRE_HOME)")))) {
            throw "Java not installed."
        }
        if(Test-ApacheTomcatInstall -TomcatVersion $Version -TomcatServiceName $ServiceName -InstallDirectory $InstallDirectory){
            $TomcatConf = (Join-Path $InstallDirectory "conf")
            $KeyStoreName = "arcgis.keystore"
            $KeyStorePath = Join-Path $TomcatConf $KeyStoreName
            # Determine the correct server XML file based on Tomcat version
            $TomcatVersionArray = $Version.Split(".")
            $TomcatMajor = [int]$TomcatVersionArray[0]
            $TomcatServerXML = Join-Path $TomcatConf "server.xml"
            $Base64KeyStorePass = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ExternalDNSName))
            $result = Test-ApacheTomcatServerXML -TomcatServerXML $TomcatServerXML -Base64KeyStorePass $Base64KeyStorePass `
                            -HttpPort $HttpPort -HttpsPort $HttpsPort -CertificateFileLocation $CertificateFileLocation `
                            -CertificatePassword $CertificatePassword -SSLProtocols $SSLProtocols -KeyStorePath $KeyStorePath -TomcatMajorVersion $TomcatMajor

            if($result){
                if(Test-Path $KeyStorePath){
                    Write-Verbose "Key Store Exists. Testing if the key store accessible and certificate is already in the key store"
                    if($CertificateFileLocation -and ($null -ne $CertificatePassword) -and (Test-Path $CertificateFileLocation)){
                        $CertToInstall = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                        $CertToInstall.Import($CertificateFileLocation, $CertificatePassword.GetNetworkCredential().Password, 'DefaultKeySet')
                        $CertAliasInKeyStore = $CertToInstall.Thumbprint
                    }else{
                        $CertAliasInKeyStore = $ExternalDNSName
                    }
            
                    try{
                        $CertificateInKeyStore = Invoke-StartProcess -ExecPath "keytool.exe" -Arguments " -list -keystore `"$KeyStoreName`" -storepass `"$Base64KeyStorePass`" -alias `"$CertAliasInKeyStore`"" -AddJavaEnvironmentVariables $true -WorkingDirectory $TomcatConf
                        if($CertificateInKeyStore -imatch "^$CertAliasInKeyStore"){
                            Write-Verbose "Certificate with alias $CertAliasInKeyStore found in the key store."
                        }else{
                            $result = $false
                        }
                    }catch{
                        Write-Verbose "Key Store is not accessible. Error - $_"
                        $result = $false
                    }
                }else{
                    Write-Verbose "Key Store does not exist."
                    $result = $false
                }
            }else{
                Write-Verbose "Apache tomcat Server.xml config not as expected."
            }
        }else{
            $result = $False
        }
    }
    elseif ($Ensure -eq "Absent") {
        # For Ensure = "Absent", we check that the Tomcat service is NOT present.
        try {
            $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($existingService) {
                Write-Verbose "Tomcat service '$ServiceName' is present."
                $result = $false  # Resource is not absent, so test fails.
            } else {
                Write-Verbose "Tomcat service '$ServiceName' is absent."
                $result = $true
            }
        } catch {
            Write-Verbose "Error checking for Tomcat service '$ServiceName': $_"
            $result = $false
        }
    }
    return $result
}


function Test-ApacheTomcatInstall
{
    [CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [System.String]
        $TomcatVersion,

        [System.String]
        $InstallDirectory,

        [System.String]
        $TomcatServiceName
    )
    $result = $False
    if(Get-Service $TomcatServiceName -ErrorAction Ignore) {
        $ServiceExePathObj = (Get-CimInstance -ClassName win32_service | Where-Object { $_.Name -imatch $TomcatServiceName})
		if(($ServiceExePathObj | Measure-Object).Count -ge 0){
			$TomcatExePath = ($ServiceExePathObj.PathName -Split ".exe")[0].TrimStart('"') + ".exe"
			Write-Verbose "Apache Tomcat with Service Name $($TomcatServiceName) found. Installed Apache Tomcat Exe Path - $($TomcatExePath). Expected Install Dir - $($InstallDirectory)"
            if((Test-FileInSubPath -Dir $InstallDirectory -File "$TomcatExePath")){
				Write-Verbose "Apache Tomcat with Service Name $($TomcatServiceName) found and installed in $($InstallDirectory)"
				$VersionOutput = Invoke-StartProcess -ExecPath "$InstallDirectory\\bin\\version.bat" -AddJavaEnvironmentVariables $true -CatalinaHome $InstallDirectory -Verbose
				if($VersionOutput -imatch "Server version: Apache Tomcat/$($TomcatVersion)"){
					$result = $True
					Write-Verbose "Apache Tomcat $($TomcatVersion) found and installed in $($InstallDirectory)"
				}
			}else{
				Write-Verbose "Apache Tomcat found installed in $($InstallDirectory) but not version $($TomcatVersion)"
			}
        }else{
            Write-Verbose "Apache Tomcat with service name $($TomcatServiceName) found but not installed in $($InstallDirectory)"
        }
    }else{
        Write-Verbose "Apache Tomcat service $($TomcatServiceName) not found"
    }

    $result
}

function Test-ApacheTomcatServerXML
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [System.String]
        $TomcatServerXML,

        [System.String]
        $KeyStorePath,

        [System.String]
        $Base64KeyStorePass,
        
        [parameter(Mandatory = $false)]
		[System.Int32]
        $HttpPort = 80,

        [parameter(Mandatory = $false)]
		[System.Int32]
        $HttpsPort = 443,

        [System.String]
        $CertificateFileLocation,

        [System.Management.Automation.PSCredential]
        $CertificatePassword,

        [System.Int32]
        $TomcatMajorVersion,

        [System.String]
        $SSLProtocols = "TLSv1.3,TLSv1.2"

    )
 
    $result = $true
    [xml]$ServerXML = Get-Content $TomcatServerXML
    $Connectors = ($ServerXML.Server.Service | Where-Object { $_.name -ieq "Catalina" }).Connector
    $HttpConnector = $Connectors | Where-Object { $_.scheme -eq "http"}
    if(($HttpConnector | Measure-Object).Count -eq 0){
        Write-Verbose "Http Connector not found"
        $result = $false
    }else{
        if($HttpConnector.port -ne $HttpPort){
            Write-Verbose "Http Port $($HttpConnector.port) not set as expected $($HttpPort)"
            $result = $false
        }else{
            Write-Verbose "Http Port $($HttpConnector.port) set as expected"
        }
    }

    $HttpsConnector = $Connectors | Where-Object { $_.scheme -eq "https"}
    if(($HttpsConnector | Measure-Object).Count -eq 0){
        Write-Verbose "Https Connector not found"
        $result = $false
    }else{
        if($HttpsConnector.port -ne $HttpsPort){
            Write-Verbose "Https Port not set as expected $($HttpsConnector.port)"
            $result = $false
        }
        # Test SSL configuration based on Tomcat major version
        if ($TomcatMajorVersion -ge 10) {
            # For Tomcat 10 and above: configuration is within nested SSLHostConfig and Certificate elements
            $SSLHostConfig = $HttpsConnector.SSLHostConfig
            if (-not $SSLHostConfig) {
                Write-Verbose "SSLHostConfig not found."
                $result = $false
            }
            else {
                if ($SSLHostConfig.sslEnabledProtocols -ine $SSLProtocols) {
                    Write-Verbose "SSL Protocols $($SSLHostConfig.sslEnabledProtocols) not set as expected ($SSLProtocols)."
                    $result = $false
                }
            }
            $Certificate = $SSLHostConfig.Certificate
            if (-not $Certificate) {
                Write-Verbose "Certificate element not found under SSLHostConfig."
                $result = $false
            }
            else {
                if ($Certificate.certificateKeystoreFile -ine $KeyStorePath) {
                    Write-Verbose "Keystore file reference $($Certificate.certificateKeystoreFile) not set as expected ($KeyStorePath)."
                    $result = $false
                }
                if ($Certificate.certificateKeystorePassword -ine $Base64KeyStorePass) {
                    Write-Verbose "Keystore password not set as expected."
                    $result = $false
                }
            }
        } else {
            # For Tomcat 9 and below: SSL configuration is directly in the Connector attributes
            if ($HttpsConnector.sslEnabledProtocols -ine $SSLProtocols) {
                Write-Verbose "SSL Protocols $($HttpsConnector.sslEnabledProtocols) not set as expected ($SSLProtocols)."
                $result = $false
            }
            if ($HttpsConnector.keystoreFile -ine $KeyStorePath) {
                Write-Verbose "Keystore file reference $($HttpsConnector.keystoreFile) not set as expected ($KeyStorePath)."
                $result = $false
            }
            if ($HttpsConnector.keystorePass -ine $Base64KeyStorePass) {
                Write-Verbose "Keystore password not set as expected."
                $result = $false
            }
        }
    }

    return $result
}

function Test-FileInSubPath
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [System.IO.DirectoryInfo]
        $Dir,

        [System.IO.FileInfo]
        $File
    )
    $File.FullName.StartsWith($Dir.FullName)
}

function Invoke-StartProcess {
    [CmdletBinding()]
    param(
        [System.String]
        $ExecPath,

        [System.String]
        $Arguments,

        [System.Boolean]
        $AddJavaEnvironmentVariables = $False,

        [Parameter(Mandatory = $false)]
		[System.String]
        $WorkingDirectory,

        [Parameter(Mandatory = $false)]
		[System.String]
        $CatalinaHome = $null
    )
	
    $psi = New-Object System.Diagnostics.ProcessStartInfo
	$psi.EnvironmentVariables["PATH"] = [environment]::GetEnvironmentVariable("PATH","Machine")
    if($AddJavaEnvironmentVariables){
		$JAVA_HOME = [environment]::GetEnvironmentVariable("JAVA_HOME","Machine")
		if($JAVA_HOME){
			$psi.EnvironmentVariables["JAVA_HOME"] = $JAVA_HOME
		}
		$JRE_HOME = [environment]::GetEnvironmentVariable("JRE_HOME","Machine")
		if($JRE_HOME){
			$psi.EnvironmentVariables["JRE_HOME"] = $JRE_HOME
		}
        if($null -ne $CatalinaHome){
			$psi.EnvironmentVariables["CATALINA_HOME"] = $CatalinaHome
        }
    }
    $psi.FileName = $ExecPath
    if($null -ne $WorkingDirectory){
		$psi.WorkingDirectory = $WorkingDirectory
    }
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false #start the process from it's own executable file    
    $psi.RedirectStandardOutput = $true #enable the process to read from standard output
    $psi.RedirectStandardError = $true #enable the process to read from standard error
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.WaitForExit()
    $op = $p.StandardOutput.ReadToEnd()
    Write-Verbose "Exit Code - $($p.ExitCode), Standard Output - $op"
    if($p.ExitCode -eq 0) {                    
        $op
    }else {
        $err = $p.StandardError.ReadToEnd()
        if($err -and $err.Length -gt 0) {
            Write-Verbose $err
        }
        throw "$($ExecPath) failed. Process exit code:- $($p.ExitCode). Error - $($err)"
    }
}


Export-ModuleMember -Function *-TargetResource