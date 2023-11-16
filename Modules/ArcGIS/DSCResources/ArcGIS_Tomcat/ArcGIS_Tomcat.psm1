function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
        [parameter(Mandatory = $true)]
        [System.String]
        $ExternalDNSName,

        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $true)]
        [System.String]
        $ServiceName,

        [parameter(Mandatory = $true)]
        [System.String]
        $InstallerArchivePath,

        [parameter(Mandatory = $false)]
        [System.String]
        $InstallerArchiveOverrideFolderName,

        [parameter(Mandatory = $true)]
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
        [parameter(Mandatory = $true)]
        [System.String]
        $ExternalDNSName,

        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $true)]
        [System.String]
        $ServiceName,

        [parameter(Mandatory = $true)]
        [System.String]
        $InstallerArchivePath,

        [parameter(Mandatory = $false)]
        [System.String]
        $InstallerArchiveOverrideFolderName,

        [parameter(Mandatory = $true)]
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
        
        Write-Verbose "Setting '$ServiceName' service startup to Automatic"
        Set-Service -Name $ServiceName -StartupType Automatic

        $ServerXMLNeedsUpdate = $True
    }

    $KeyStoreName = "arcgis.keystore"
    $TomcatConf = (Join-Path $InstallDirectory "conf")
    $TomcatServerXML = Join-Path $TomcatConf "server.xml"
    $KeyStorePath = Join-Path $TomcatConf $KeyStoreName
    $Base64KeyStorePass = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ExternalDNSName))
    if(-not($ServerXMLNeedsUpdate)){
        $ServerXMLNeedsUpdate = -not( Test-ApacheTomcatServerXML -TomcatServerXML $TomcatServerXML -Base64KeyStorePass $Base64KeyStorePass `
                                    -HttpPort $HttpPort -HttpsPort $HttpsPort -CertificateFileLocation $CertificateFileLocation `
                                    -CertificatePassword $CertificatePassword -SSLProtocols $SSLProtocols  -KeyStorePath $KeyStorePath )
    }
    
    if($ServerXMLNeedsUpdate){
        $SampleServerXML = Join-path $PSScriptRoot "server.xml" 
        Copy-Item -Path $SampleServerXML -Destination $TomcatServerXML -Force
        [xml]$ServerXML = Get-Content $TomcatServerXML
        $Connectors = ($ServerXML.Server.Service | Where-Object { $_.name -ieq "Catalina" }).Connector
        foreach($Connector in $Connectors){
            if($Connector.scheme -ieq "https"){
                $Connector.SetAttribute("port", $HttpsPort);
                $Connector.SetAttribute("sslEnabledProtocols", $SSLProtocols);
                $Connector.SetAttribute("keystoreFile", $KeyStorePath);
                $Connector.SetAttribute("keystorePass", $Base64KeyStorePass);
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
            $CertificateInKeyStore = Invoke-StartProcess -ExecPath "keytool.exe" -Arguments " -list -keystore $KeyStoreName -storepass $Base64KeyStorePass -alias $CertAliasInKeyStore" -AddJavaEnvironmentVariables $true -WorkingDirectory $TomcatConf -Verbose
            if($CertificateInKeyStore -match "^$CertAliasInKeyStore"){
                Write-Verbose "Certificate with thumbprint $CertAliasInKeyStore found in the key store."
            }else{
                Write-Verbose "Certificate does not exist in the key store. Deleting the key store"
                Remove-Item $KeyStorePath -Force
                $CreateKeyStore = $True
            }
        }catch{
            Write-Verbose "Key Store is not accessible. Deleting the key store. Error - $_"
        }
    }   

    if($CreateKeyStore){
        Write-Verbose "Creating Key Store"
        if($UserProvidedCertificate){
            $srcStorePass = $CertificatePassword.GetNetworkCredential().Password
            
            # Get Alias from the certificate
            $Certificate = Invoke-StartProcess -ExecPath "keytool.exe" -Arguments " -v -list -keystore `"$CertificateFileLocation`" -storepass $srcStorePass" -Verbose
            $CertificateAlias = (($Certificate -split "`r`n") | Where-Object { $_ -match "Alias name: " } | Select-Object -First 1 | ForEach-Object { $_.Split(":")[1].Trim() })
            
            $Arguments = [System.String]::Join("", @(" -importkeystore -noprompt",
                            " -srcstoretype pkcs12 -alias `"$CertificateAlias`" -srckeystore `"$CertificateFileLocation`" -srcstorepass `"$srcStorePass`"",
                            " -deststoretype pkcs12 -destalias `"$CertAliasInKeyStore`" -destkeystore `"$KeyStoreName`" -storepass `"$Base64KeyStorePass`""))
            Write-Verbose $Arguments
        }else{
            $Arguments = [System.String]::Join("", @(" -genkeypair -keystore `"$KeyStoreName`" -keyalg RSA -keysize 2048 -validity 1825",
                        " -storetype PKCS12 -storepass `"$Base64KeyStorePass`" -alias `"$CertAliasInKeyStore`"",
                        " -dname `"CN=$ExternalDNSName`""))
        }
        $CertificateInKeyStore = Invoke-StartProcess -ExecPath "keytool.exe" -Arguments $Arguments -WorkingDirectory $TomcatConf -AddJavaEnvironmentVariables $true -Verbose
        $RestartTomcat = $True
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
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [parameter(Mandatory = $true)]
        [System.String]
        $ExternalDNSName,

        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $true)]
        [System.String]
        $ServiceName,

        [parameter(Mandatory = $true)]
        [System.String]
        $InstallerArchivePath,

        [parameter(Mandatory = $false)]
        [System.String]
        $InstallerArchiveOverrideFolderName,

        [parameter(Mandatory = $true)]
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
    $JAVA_HOME = [environment]::GetEnvironmentVariable("JAVA_HOME","Machine")
    $JRE_HOME = [environment]::GetEnvironmentVariable("JRE_HOME","Machine")
    if (-not((-not([string]::IsNullOrEmpty($JAVA_HOME)) -and (Test-Path -Path "$($JAVA_HOME)")) -or (-not([string]::IsNullOrEmpty($JRE_HOME)) -and (Test-Path -Path "$($JRE_HOME)")))) {
        throw "Java not installed."
    }
    if(Test-ApacheTomcatInstall -TomcatVersion $Version -TomcatServiceName $ServiceName -InstallDirectory $InstallDirectory){
        $TomcatConf = (Join-Path $InstallDirectory "conf")
        $KeyStoreName = "arcgis.keystore"
        $KeyStorePath = Join-Path $TomcatConf $KeyStoreName
        $TomcatServerXML = Join-Path $TomcatConf "server.xml"
        $Base64KeyStorePass = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ExternalDNSName))
        $result = Test-ApacheTomcatServerXML -TomcatServerXML $TomcatServerXML -Base64KeyStorePass $Base64KeyStorePass `
                        -HttpPort $HttpPort -HttpsPort $HttpsPort -CertificateFileLocation $CertificateFileLocation `
                        -CertificatePassword $CertificatePassword -SSLProtocols $SSLProtocols -KeyStorePath $KeyStorePath

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

    $result
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
        if($HttpsConnector.sslEnabledProtocols -ine $SSLProtocols){
            Write-Verbose "SSL Protocols $($HttpsConnector.sslEnabledProtocols) not set as expected $($SSLProtocols)"
            $result = $false
        }
        if($HttpsConnector.keystoreFile -ine $KeyStorePath){
            Write-Verbose "Keystore file reference $($HttpsConnector.keystoreFile) not set as expected $($KeyStorePath)"
            $result = $false
        }
        if($HttpsConnector.keystorePass -ine $Base64KeyStorePass){
            Write-Verbose "Keystore password not set as expected"
            $result = $false
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