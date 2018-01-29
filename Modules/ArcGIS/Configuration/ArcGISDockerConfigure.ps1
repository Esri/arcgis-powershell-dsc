Configuration ArcGISDockerConfigure
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_Server
    Import-DscResource -Name ArcGIS_WindowsService
    Import-DscResource -Name ArcGIS_Service_Account
    Import-DSCResource -Name ArcGIS_Server_TLS
    
    $PrimaryServerMachine = ""
    for ( $i = 0; $i -lt $AllNodes.count; $i++ )
    {
        $Role = $AllNodes[$i].Role
        if($Role -icontains 'Server' -and -not($PrimaryServerMachine))
        {
            $PrimaryServerMachine  = $AllNodes[$i].NodeName
        }
    }

    Node $AllNodes.NodeName
    { 
        $MachineFQDN = Get-FQDN $Node.NodeName

        $SAPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.Credentials.ServiceAccount.Password -AsPlainText -Force
        $DCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.Credentials.ServiceAccount.UserName, $SAPassword )

        $PSAPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.Password -AsPlainText -Force
        $PSACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.UserName, $PSAPassword )

        #Removes the Requirement for the Ordering inside roles.
        $NodeRoleArray = @()
        if($Node.Role -icontains "Server")
        {
            $NodeRoleArray += "Server"
        }
        
        for ( $i = 0; $i -lt $NodeRoleArray.Count; $i++ )
        {
            $NodeRole = $NodeRoleArray[$i]
            Switch($NodeRole)
            {
                'Server'{
                    $Depends = @()
                    
                    ArcGIS_WindowsService ArcGIS_for_Server_Service
                    {
                        Name = 'ArcGIS Server'
                        Credential = $DCredential
                        StartupType = 'Automatic'
                        State = 'Running'
                    }

                    ArcGIS_Service_Account Server_RunAs_Account
                    {
                        Name = 'ArcGIS Server'
                        RunAsAccount = $DCredential
                        Ensure = 'Present'
                        DependsOn = @('[ArcGIS_WindowsService]ArcGIS_for_Server_Service')
                    }

                    $ConfigStoreLocation =  $ConfigurationData.ConfigData.Server.ConfigStoreLocation
                    $ServerDirectoriesRootLocation = $ConfigurationData.ConfigData.Server.ServerDirectoriesRootLocation

                    File ConfigStoreRootLocation
                    {
                        Type = 'Directory'
                        DestinationPath  = $ConfigStoreLocation
                        Ensure = 'Present'
                        Force = $true
                    }

                    if($Node.NodeName -ine $PrimaryServerMachine)
                    {
                        ArcGIS_WaitForComponent "WaitForServer$($PrimaryServerMachine)"
                        {
                            Component = "Server"
                            ComponentHostName = (Get-FQDN $PrimaryServerMachine)
                            ComponentContext = "arcgis"
                            Ensure = "Present"
                            Credential = $PSACredential
                            RetryIntervalSec = 60
                            RetryCount = 60
                        }
                    }
                    
                    ArcGIS_Server "Server$($Node.NodeName)"
                    {
                        Ensure = 'Present'
                        SiteAdministrator = $PSACredential
                        ConfigurationStoreLocation = $ConfigStoreLocation
                        ServerDirectoriesRootLocation = $ServerDirectoriesRootLocation
                        Join = if($Node.NodeName -ine $PrimaryServerMachine) { $true } else { $false } 
                        PeerServerHostName = Get-FQDN $PrimaryServerMachine
                        DependsOn = if($Node.NodeName -ine $PrimaryServerMachine) { @("[ArcGIS_WaitForComponent]WaitForServer$($PrimaryServerMachine)","[ArcGIS_WaitForFileShare]WaitForFileShare$($Node.NodeName)") } else { @() }
                        LogLevel = if($ConfigurationData.ConfigData.DebugMode) { 'DEBUG' } else { 'WARNING' }
                        SingleClusterMode = if(($AllNodes | Where-Object { $_.Role -icontains 'Server' }  | Measure-Object).Count -gt 0) { $true } else { $false }
                    }

                    
                    if($ConfigurationData.ConfigData.Server.SslCertifcate.Path)
                    {
                        ArcGIS_Server_TLS "Server_TLS_$($Node.NodeName)"
                        {
                            Ensure = 'Present'
                            SiteName = 'arcgis'
                            SiteAdministrator = $PSACredential                         
                            CName = $ConfigurationData.ConfigData.Server.SslCertifcate.Alias
                            RegisterWebAdaptorForCName = $False
                            CertificateFileLocation = $ConfigurationData.ConfigData.Server.SslCertifcate.Path
                            CertificatePassword = $ConfigurationData.ConfigData.Server.SslCertifcate.Password
                            EnableSSL = $True
                            DependsOn =  @("[ArcGIS_Server]Server$($Node.NodeName)") 
                        } 
                    }
                    else
                    {
                        ArcGIS_Server_TLS "Server_TLS_$($Node.NodeName)"
                        {
                            Ensure = 'Present'
                            SiteName = 'arcgis'
                            SiteAdministrator = $PSACredential                         
                            CName = $MachineFQDN
                            RegisterWebAdaptorForCName = $False
                            EnableSSL = $True
                            DependsOn =  @("[ArcGIS_Server]Server$($Node.NodeName)") 
                        } 
                    }
                }
            }
        }
    }
}