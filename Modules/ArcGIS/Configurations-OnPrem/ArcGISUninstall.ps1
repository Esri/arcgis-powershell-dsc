Configuration ArcGISUninstall
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DscResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_Install
    Import-DscResource -Name ArcGIS_WebAdaptorInstall
    Import-DscResource -Name ArcGIS_FileShare
    Import-DscResource -Name ArcGIS_InstallMsiPackage
    
    Node $AllNodes.NodeName
    {   
        $SAPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.Credentials.ServiceAccount.Password -AsPlainText -Force
        $SACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.Credentials.ServiceAccount.UserName, $SAPassword )

        $PSAPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.Password -AsPlainText -Force
        $PSACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.UserName, $PSAPassword )
     
        if(-not($ConfigurationData.ConfigData.Credentials.ServiceAccount.IsDomainAccount)){
            User ArcGIS_RunAsAccount
            {
                UserName = $ConfigurationData.ConfigData.Credentials.ServiceAccount.UserName
                Password = $SACredential
                FullName = 'ArcGIS Run As Account'
                Ensure = "Present"
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
                            Path = $ConfigurationData.ConfigData.GeoEventServer.Installer.Path
                            Arguments = "/qb PASSWORD=$($ConfigurationData.ConfigData.Credentials.ServiceAccount.Password)";
                            Ensure = "Absent"
                        }
                    }
                    ArcGIS_Install ServerUninstall{
                        Name = "Server"
                        Version = $ConfigurationData.ConfigData.Version
                        Path = $ConfigurationData.ConfigData.Server.Installer.Path
                        Arguments = "/qn InstallDir=$($ConfigurationData.ConfigData.Server.Installer.InstallDir) INSTALLDIR1=$($ConfigurationData.ConfigData.Server.Installer.InstallDirPython)";
                        Ensure = "Absent"
                    }
                }
                'Portal' {
                    ArcGIS_Install "PortalUninstall$($Node.NodeName)"
                    { 
                        Name = "Portal"
                        Version = $ConfigurationData.ConfigData.Version
                        Path = $ConfigurationData.ConfigData.Portal.Installer.Path
                        Arguments = "/qn INSTALLDIR=$($ConfigurationData.ConfigData.Portal.Installer.InstallDir) CONTENTDIR=$($ConfigurationData.ConfigData.Portal.Installer.ContentDir)";
                        Ensure = "Absent"
                    }
                }
                'DataStore'{
                    ArcGIS_Install DataStoreUninstall
                    { 
                        Name = "DataStore"
                        Version = $ConfigurationData.ConfigData.Version
                        Path = $ConfigurationData.ConfigData.DataStore.Installer.Path
                        Arguments = "/qb InstallDir=$($ConfigurationData.ConfigData.DataStore.Installer.InstallDir)"
                        Ensure = "Absent"
                    }
                }
                { 'ServerWebAdaptor' -or 'PortalWebAdaptor' }{
                    
                    $WebAdaptorRole = $NodeRole

                   if(($WebAdaptorRole -ieq "PortalWebAdaptor") -and $ConfigurationData.ConfigData.PortalContext){
                        ArcGIS_WebAdaptorInstall WebAdaptorUninstallPortal
                        { 
                            Context = $ConfigurationData.ConfigData.PortalContext 
                            Path = $ConfigurationData.ConfigData.WebAdaptor.Installer.Path
                            Arguments = "/qb VDIRNAME=$($ConfigurationData.ConfigData.PortalContext) WEBSITE_ID=1";
                            Ensure = "Absent"
                            Version = $ConfigurationData.ConfigData.Version
                        } 
                    }

                    if(($WebAdaptorRole -ieq "ServerWebAdaptor") -and $ConfigurationData.ConfigData.ServerContext){
                        ArcGIS_WebAdaptorInstall WebAdaptorUninstallServer
                        { 
                            Context = $ConfigurationData.ConfigData.ServerContext 
                            Path = $ConfigurationData.ConfigData.WebAdaptor.Installer.Path
                            Arguments = "/qb VDIRNAME=$($ConfigurationData.ConfigData.ServerContext) WEBSITE_ID=1";
                            Ensure = "Absent"
                            Version = $ConfigurationData.ConfigData.Version
                        } 
                    }
                }
                'FileShare'{
                    ArcGIS_FileShare FileShareRemove
                    {
                        FileShareName = $ConfigurationData.ConfigData.FileShareName
                        FileShareLocalPath = $ConfigurationData.ConfigData.FileShareLocalPath
                        Ensure = 'Absent'
                        Credential = $SACredential
                    }
                }
                'LoadBalancer'{

                    $DCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("$($ConfigurationData.ConfigData.Credentials.ServiceAccount.Domain)\$($ConfigurationData.ConfigData.Credentials.ServiceAccount.UserName)", $SAPassword )
                    
                    $TempFolder = "$($env:SystemDrive)\Temp"

                    if(Test-Path $TempFolder)
                    {
                        Remove-Item -Path $TempFolder -Recurse 
                    }
                    if(-not(Test-Path $TempFolder))
                    {
                        New-Item $TempFolder -ItemType directory            
                    }

                    foreach ($h in $ConfigurationData.ConfigData.LoadBalancer.InstallerPath)
                    {
                        $FileName = Split-Path $h.FilePath -leaf

                        ArcGIS_InstallMsiPackage "AIMP_$($h.Name.Replace(' ', '_'))"
                        {
                            Name = $h.Name
                            Path = $ExecutionContext.InvokeCommand.ExpandString("$TempFolder\$FileName")
                            Ensure = "Absent"
                            ProductId = $h.ProductId
                            Arguments = " /quiet"
                        }
                    }

                    WindowsFeature ARRWebServerUninstall {
                        Ensure = "Absent"
                        Name =  "Web-Server"
                    }
                }
                'SqlServer'{
                    $InstallerPath = $ConfigurationData.ConfigData.SQLServer.SQLServerInstallerPath
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
                                $app = Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -imatch "sql"}
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
            }
        }
    }
}