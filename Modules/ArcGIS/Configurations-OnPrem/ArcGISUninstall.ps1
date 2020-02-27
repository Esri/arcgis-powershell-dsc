Configuration ArcGISUninstall
{
    param(
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $ServiceCredential,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsMSA = $false
    )
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.0.0"}
    Import-DscResource -Name ArcGIS_Install
    Import-DscResource -Name ArcGIS_WebAdaptorInstall
    Import-DscResource -Name ArcGIS_FileShare
    Import-DscResource -Name ArcGIS_InstallMsiPackage
    
    Node $AllNodes.NodeName
    {   
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        for ( $i = 0; $i -lt $Node.Role.Count; $i++ )
        {        
            $NodeRole = $Node.Role[$i]
            Switch($NodeRole) 
            {
                'Server' {
                    if($ConfigurationData.ConfigData.GeoEventServer) 
                    { 
                        ArcGIS_Install GeoEventServerUninstall{
                            Name = "GeoEvent"
                            Version = $ConfigurationData.ConfigData.Version
                            Ensure = "Absent"
                        }
                    }
                    ArcGIS_Install ServerUninstall{
                        Name = if($ConfigurationData.ConfigData.ServerRole -ieq "NotebookServer"){ "NotebookServer" }else{ "Server" }
                        Version = $ConfigurationData.ConfigData.Version
                        Ensure = "Absent"
                    }
                }
                'Portal' {
                    ArcGIS_Install "PortalUninstall$($Node.NodeName)"
                    { 
                        Name = "Portal"
                        Version = $ConfigurationData.ConfigData.Version
                        Ensure = "Absent"
                    }

                    $VersionArray = $ConfigurationData.ConfigData.Version.Split(".")
                    $MajorVersion = $VersionArray[1]
                    $MinorVersion = if($VersionArray.Length -gt 2){ $VersionArray[2] }else{ 0 }
                    if((($MajorVersion -eq 7 -and $MinorVersion -eq 1) -or ($MajorVersion -ge 8)) -and $ConfigurationData.ConfigData.Portal.Installer.WebStylesPath){
                        ArcGIS_Install "WebStylesUninstall$($Node.NodeName)"
                        { 
                            Name = "WebStyles"
                            Version = $ConfigurationData.ConfigData.Version
                            Ensure = "Absent"
                        }
                    }

                }
                'DataStore'{
                    ArcGIS_Install DataStoreUninstall
                    { 
                        Name = "DataStore"
                        Version = $ConfigurationData.ConfigData.Version
                        Ensure = "Absent"
                    }
                }
                { 'ServerWebAdaptor' -or 'PortalWebAdaptor' }{
                    
                    $WebAdaptorRole = $NodeRole

                   if(($WebAdaptorRole -ieq "PortalWebAdaptor") -and $ConfigurationData.ConfigData.PortalContext){
                        ArcGIS_WebAdaptorInstall WebAdaptorUninstallPortal
                        { 
                            Context = $ConfigurationData.ConfigData.PortalContext 
                            Version = $ConfigurationData.ConfigData.Version
                            Ensure = "Absent"
                        } 
                    }

                    if(($WebAdaptorRole -ieq "ServerWebAdaptor") -and $Node.ServerContext){
                        ArcGIS_WebAdaptorInstall WebAdaptorUninstallServer
                        { 
                            Context = $Node.ServerContext
                            Version = $ConfigurationData.ConfigData.Version
                            Ensure = "Absent"
                        } 
                    }
                }
                'FileShare'{
                    ArcGIS_FileShare FileShareRemove
                    {
                        FileShareName = $ConfigurationData.ConfigData.FileShareName
                        FileShareLocalPath = $ConfigurationData.ConfigData.FileShareLocalPath
                        Ensure = 'Absent'
                        Credential = $ServiceCredential
                    }
                }
                'SqlServer'{
                    $InstallerPath = $Node.SQLServerInstallerPath
                    Script SQLServerUninstall
                    {
                        GetScript = {
                            $null
                        }
                        SetScript = {
                            if($using:InstallerPath){
                                $ExtractPath = "$env:SystemDrive\temp\sql"
                                if(Test-Path $ExtractPath){
                                    Remove-Item -Recurse -Force $ExtractPath
                                }
                                & cmd.exe /c "$using:InstallerPath /q /x:$ExtractPath"
                                Write-Verbose "Done Extracting SQL Server"
                                Start-Sleep -Seconds 60
                                if(Test-Path "$ExtractPath\SETUP.exe"){
                                    Write-Verbose "Starting SQL Server Uninstall"
                                    & "$ExtractPath\SETUP.exe" /q /Action=Uninstall /FEATURES=SQL /INSTANCENAME=MSSQLSERVER
                                    Write-Verbose "Server Uninstall Completed"
                                    Remove-Item -Recurse -Force $ExtractPath
                                }else{
                                    Write-Verbose "Something Went Wrong"
                                }
                            }else{
                                #Very Very Crude. Needs a lot of refinement
                                $app = Get-CimInstance -Class Win32_Product | Where-Object {$_.Name -imatch "sql"}
                                $app.Uninstall()
                            }
                        }
                        TestScript = {
                            if (Test-Path "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL") {
                                $False
                            } Else {
                                $True
                            }
                        }
                    }
                }
                'Desktop' {
                    ArcGIS_Install DesktopUninstall
                    { 
                        Name = "Desktop"
                        Version = $ConfigurationData.ConfigData.DesktopVersion
                        Ensure = "Absent"
                    }
                }
                'Pro' {
                    ArcGIS_Install ProUninstall{
                        Name = "Pro"
                        Version = $ConfigurationData.ConfigData.ProVersion
                        Ensure = "Absent"
                    }
                }
                'LicenseManager'
                {
                    ArcGIS_Install LicenseManagerUninstall{
                        Name = "LicenseManager"
                        Version = $ConfigurationData.ConfigData.LicenseManagerVersion
                        Ensure = "Absent"
                    }
                }
            }
        }
    }
}