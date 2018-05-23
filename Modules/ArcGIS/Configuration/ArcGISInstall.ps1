Configuration ArcGISInstall{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_Install
    Import-DscResource -Name ArcGIS_WebAdaptorInstall
    Import-DscResource -Name ArcGIS_InstallMsiPackage

    Node $AllNodes.NodeName {

        $SAPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.Credentials.ServiceAccount.Password -AsPlainText -Force
        $SACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.Credentials.ServiceAccount.UserName, $SAPassword )
     
        if(-not($ConfigurationData.ConfigData.Credentials.ServiceAccount.IsDomainAccount)){
            User ArcGIS_RunAsAccount
            {
                UserName = $ConfigurationData.ConfigData.Credentials.ServiceAccount.UserName
                Password = $SACredential
                FullName = 'ArcGIS Run As Account'
                Ensure = "Present"
                PasswordChangeRequired = $false
                PasswordNeverExpires = $true
            }
        }

        $NodeRoleArray = @()
        if($Node.Role -icontains "FileShare")
        {
            $NodeRoleArray += "FileShare"
        }
        if($Node.Role -icontains "RasterDataStoreItem")
        {
            $NodeRoleArray += "RasterDataStoreItem"
        }
        if($Node.Role -icontains "Server")
        {
            $NodeRoleArray += "Server"
        }
        if($Node.Role -icontains "Portal")
        {
            $NodeRoleArray += "Portal"
        }
        if($Node.Role -icontains "DataStore")
        {
            $NodeRoleArray += "DataStore"
        }
        if($Node.Role -icontains "ServerWebAdaptor")
        {
            $NodeRoleArray += "ServerWebAdaptor"
        }
        if($Node.Role -icontains "PortalWebAdaptor")
        {
            $NodeRoleArray += "PortalWebAdaptor"
        }
        if($Node.Role -icontains "LoadBalancer")
        {
            $NodeRoleArray += "LoadBalancer"
        }

        for ( $i = 0; $i -lt $NodeRoleArray.Count; $i++ )
        {
            $NodeRole = $NodeRoleArray[$i]
            Switch($NodeRole)
            {
                'Server'
                {
                    $HasSQLServer = (($AllNodes | Where-Object { $_.Role -icontains 'SQLServer' }  | Measure-Object).Count -gt 0)

                    ArcGIS_Install ServerInstall
                    {
                        Name = "Server"
                        Version = $ConfigurationData.ConfigData.Version
                        Path = $ConfigurationData.ConfigData.Server.Installer.Path
                        Arguments = "/qn InstallDir=$($ConfigurationData.ConfigData.Server.Installer.InstallDir) INSTALLDIR1=$($ConfigurationData.ConfigData.Server.Installer.InstallDirPython)";
                        Ensure = "Present"
                    }

                    if ($ConfigurationData.ConfigData.Server.Installer.PatchesDir) {
                        ArcGIS_InstallPatch ServerInstallPatch
                        {
                            Name = "Server"
                            Version = $ConfigurationData.ConfigData.Version
                            PatchesDir = $ConfigurationData.ConfigData.Server.Installer.PatchesDir
                            Ensure = "Present"
                        }
                    }

                    if($HasSQLServer)
                    {
                        $SNACInstallerPath = $ConfigurationData.ConfigData.SQLServer.ServerNativeClient11InstallerPath
                        Script SQLNativeClientInstall
                        {
                            GetScript = {
                                $null
                            }
                            TestScript = 
                            {                    
                                $checkClient = Get-ChildItem 'HKLM:\Software\Microsoft\*' -ea SilentlyContinue | Where-object {$_.name -like '*Client*'}
                                if ($checkClient.name.Split('\') -eq 'Microsoft SQL Server Native Client 11.0')
                                {
                                    Write-Verbose 'SQL Native Client 11.0 has been already installed'
                                    $True
                                } else {
                                    Write-Verbose 'Version 11 not present'
                                    $False
                                }
                            }
                            SetScript =
                            {
                                try {
                                    $InstallerPath = $using:SNACInstallerPath
                                    Write-Verbose "Installing Native Client 11 - $InstallerPath"
                                    Start-Process msiexec.exe -Wait -ArgumentList "/qn /i $InstallerPath IACCEPTSQLNCLILICENSETERMS=YES"
                                } Catch {
                                    Write-Verbose 'SQL Native Client 11 was not installed. Manual action required'
                                }
                            }
                        }
                    }

                    if($ConfigurationData.ConfigData.GeoEventServer) 
                    { 
                        ArcGIS_Install GeoEventServerInstall
                        {
                            Name = "GeoEvent"
                            Version = $ConfigurationData.ConfigData.Version
                            Path = $ConfigurationData.ConfigData.GeoEventServer.Installer.Path
                            Arguments = "/qn PASSWORD=$($ConfigurationData.ConfigData.Credentials.ServiceAccount.Password)";
                            Ensure = "Present"
                        }
                    }

                }
                'Portal'
                {                    
                    ArcGIS_Install "PortalInstall$($Node.NodeName)"
                    { 
                        Name = "Portal"
                        Version = $ConfigurationData.ConfigData.Version
                        Path = $ConfigurationData.ConfigData.Portal.Installer.Path
                        Arguments = "/qn INSTALLDIR=$($ConfigurationData.ConfigData.Portal.Installer.InstallDir) CONTENTDIR=$($ConfigurationData.ConfigData.Portal.Installer.ContentDir)";
                        Ensure = "Present"
                    }

                    if ($ConfigurationData.ConfigData.Portal.Installer.PatchesDir) {
                        ArcGIS_InstallPatch PortalInstallPatch
                        {
                            Name = "Portal"
                            Version = $ConfigurationData.ConfigData.Version
                            PatchesDir = $ConfigurationData.ConfigData.Portal.Installer.PatchesDir
                            Ensure = "Present"
                        }
                    } 
                }
                'DataStore'
                {
                    ArcGIS_Install DataStoreInstall
                    { 
                        Name = "DataStore"
                        Version = $ConfigurationData.ConfigData.Version
                        Path = $ConfigurationData.ConfigData.DataStore.Installer.Path
                        Arguments = "/qn InstallDir=$($ConfigurationData.ConfigData.DataStore.Installer.InstallDir)"
                        Ensure = "Present"
                    }

                    if ($ConfigurationData.ConfigData.DataStore.Installer.PatchesDir) {
                        ArcGIS_InstallPatch DataStoreInstallPatch
                        {
                            Name = "DataStore"
                            Version = $ConfigurationData.ConfigData.Version
                            PatchesDir = $ConfigurationData.ConfigData.DataStore.Installer.PatchesDir
                            Ensure = "Present"
                        }
                    } 
                }
                {($_ -eq "ServerWebAdaptor") -or ($_ -eq "PortalWebAdaptor")}
                {
                    $PortalWebAdaptorSkip = $False
                    if(($Node.Role -icontains 'ServerWebAdaptor') -and ($Node.Role -icontains 'PortalWebAdaptor'))
                    {
                        if($NodeRole -ieq "PortalWebAdaptor")
                        {
                            $PortalWebAdaptorSkip = $True
                        }
                    }
                    
                    if(-not($PortalWebAdaptorSkip))
                    {
                        if(($Node.Role -icontains 'PortalWebAdaptor') -and $ConfigurationData.ConfigData.PortalContext)
                        {
                            ArcGIS_WebAdaptorInstall WebAdaptorInstallPortal
                            { 
                                Context = $ConfigurationData.ConfigData.PortalContext 
                                Path = $ConfigurationData.ConfigData.WebAdaptor.Installer.Path
                                Arguments = "/qn VDIRNAME=$($ConfigurationData.ConfigData.PortalContext) WEBSITE_ID=1";
                                Ensure = "Present"
                                Version = $ConfigurationData.ConfigData.Version
                            } 
                        }

                        if(($Node.Role -icontains 'ServerWebAdaptor') -and $ConfigurationData.ConfigData.ServerContext)
                        {
                            ArcGIS_WebAdaptorInstall WebAdaptorInstallServer
                            { 
                                Context = $ConfigurationData.ConfigData.ServerContext 
                                Path = $ConfigurationData.ConfigData.WebAdaptor.Installer.Path
                                Arguments = "/qn VDIRNAME=$($ConfigurationData.ConfigData.ServerContext) WEBSITE_ID=1";
                                Ensure = "Present"
                                Version = $ConfigurationData.ConfigData.Version
                            } 
                        }
                    }

                }
                'LoadBalancer'
                {
                    WindowsFeature ARRWebServer 
                    {
                        Ensure = "Present"
                        Name =  "Web-Server"
                    }
                    
                    $TempFolder = "$($env:SystemDrive)\Temp"

                    if(Test-Path $TempFolder)
                    {
                        Remove-Item -Path $TempFolder -Recurse 
                    }
                    if(-not(Test-Path $TempFolder))
                    {
                        New-Item $TempFolder -ItemType directory            
                    }  

                    Write-Verbose ($ConfigurationData.ConfigData.LoadBalancer.InstallerPath).count

                    foreach ($h in $ConfigurationData.ConfigData.LoadBalancer.InstallerPath)
                    {
                        $FileName = Split-Path $h.FilePath -leaf

                        File "SetupCopy$($h.Name)"
                        {
                            Ensure = "Present"
                            Type = "File"
                            SourcePath = $h.FilePath
                            DestinationPath = "$TempFolder\$FileName"  
                        }

                        ArcGIS_InstallMsiPackage "AIMP_$($h.Name.Replace(' ', '_'))"
                        {
                            Name = $h.Name
                            Path = $ExecutionContext.InvokeCommand.ExpandString("$TempFolder\$FileName")
                            Ensure = "Present"
                            ProductId = $h.ProductId
                            Arguments = " /quiet"
                        }
                    }

                    if(Test-Path $TempFolder)
                    {
                        Remove-Item -Path $TempFolder -Recurse 
                    }
                }
                'SQLExpress'
                {
                    WindowsFeature "NET"
                    {
                        Ensure = "Present"
                        Name = "NET-Framework-Core"
                    }
                    
                    $InstallerPath = $ConfigurationData.ConfigData.SQLServer.SQLServerInstallerPath

                    Script SQLServerInstall
                    {
                        GetScript = {
                            $null
                        }
                        SetScript = {
                            $ExtractPath = "$env:SystemDrive\temp\sql"
                            if(Test-Path $ExtractPath)
                            {
                                Remove-Item -Recurse -Force $ExtractPath
                            }
                            & cmd.exe /c "$using:InstallerPath /q /x:$ExtractPath"
                            Write-Verbose "Done Extracting SQL Server"
                            Start-Sleep -Seconds 60
                            if(Test-Path "$ExtractPath\SETUP.exe")
                            {
                                Write-Verbose "Starting SQL Server Install"
                                & "$ExtractPath\SETUP.exe" /q /IACCEPTSQLSERVERLICENSETERMS /ACTION=Install /FEATURES=SQL /INSTANCENAME=MSSQLSERVER /TCPENABLED=1 /SQLSVCACCOUNT='NT AUTHORITY\SYSTEM' /SQLSYSADMINACCOUNTS='NT AUTHORITY\SYSTEM' /AGTSVCACCOUNT="NT AUTHORITY\Network Service"
                                Write-Verbose "Server Install Completed"
                                Remove-Item -Recurse -Force $ExtractPath
                            }
                            else
                            {
                                Write-Verbose "Something Went Wrong"
                            }
                        }
                        TestScript = {
                            if (Test-Path "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL")
                            {
                                $True
                            } 
                            else 
                            {
                                $False
                            }
                        }
                    }
                }
            }
        }
    }
}