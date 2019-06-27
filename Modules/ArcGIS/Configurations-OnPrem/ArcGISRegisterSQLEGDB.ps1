Configuration ArcGISRegisterSQLEGDB{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DSCResource -Name ArcGIS_WaitForSQLServer
    Import-DSCResource -Name ArcGIS_EGDB
    
    Node $AllNodes.NodeName
    {
        $PSAPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.Password -AsPlainText -Force
        $PSACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.Credentials.PrimarySiteAdmin.UserName, $PSAPassword )

        $NodeRoleArray = @()
        if($Node.Role -icontains "Server")
        {
            $NodeRoleArray += "Server"
        }
        if($Node.Role -icontains "SQLServer")
        {
            $NodeRoleArray += "SQLServer"
        }
        for ( $i = 0; $i -lt $NodeRoleArray.Count; $i++ )
        {
            $NodeRole = $NodeRoleArray[$i]
            Switch($NodeRole)
            {
                'Server'{
                    if($Node.NodeName -ieq $PrimaryServerMachine)
                    {
                        ForEach($svr in ($AllNodes | Where-Object { $_.Role -icontains 'SQLServer' }))
                        {
                            
                            $DatabaseServerAdministratorPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.SQLServer.DatabaseAdminUser.Password -AsPlainText -Force
                            $DatabaseServerAdministratorCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.SQLServer.DatabaseAdminUser.UserName, $DatabaseServerAdministratorPassword )

                            if($Node.WMFVersion -gt 4){
                                WaitForAll "WaitForAllSQLServer$($svr.NodeName)"{
                                    ResourceName = "[Script]CreateDatabaseAdminUser"
                                    NodeName = $svr.NodeName
                                    RetryIntervalSec = 60
                                    RetryCount = 60
                                    DependsOn = $Depends
                                }
                                $Depends += "[WaitForAll]WaitForAllSQLServer$($svr.NodeName)"
                            }else{
                                ArcGIS_WaitForSQLServer "WaitForSQLServer$($svr.NodeName)"
                                {
                                    SQLServerMachineName = (Get-FQDN $svr.NodeName)
                                    Ensure = 'Present'
                                    Credential = $DatabaseServerAdministratorCredential
                                    RetryIntervalSec = 60
                                    RetryCount = 60
                                }
                                $Depends += "[WaitForAll]ArcGIS_WaitForSQLServer$($svr.NodeName)"
                            }

                            $SDEUserPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.SQLServer.SDEUser.Password -AsPlainText -Force
                            $SDEUserCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.SQLServer.SDEUser.UserName, $SDEUserPassword )
                            
                            $DatabaseUserPassword = ConvertTo-SecureString $ConfigurationData.ConfigData.SQLServer.DatabaseUser.Password -AsPlainText -Force
                            $DatabaseUserCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($ConfigurationData.ConfigData.SQLServer.DatabaseUser.UserName, $DatabaseUserPassword )

                            $DatabaseServerHostName = (Get-FQDN $svr.NodeName)
                            $DatabaseName = $ConfigurationData.ConfigData.SQLServer.DatabaseName

                            if(($DatabaseOption -ine 'None') -and $DatabaseServerHostName -and $DatabaseName -and $DatabaseServerAdministratorCredential -and $SDEUserCredential -and $DatabaseUserCredential)
                            {
                                ArcGIS_EGDB RegisterEGDB
                                {
                                    DatabaseServer              = $DatabaseServerHostName
                                    DatabaseName                = $DatabaseName
                                    ServerSiteAdministrator     = $PSACredential
                                    DatabaseServerAdministrator = $DatabaseServerAdministratorCredential
                                    SDEUser                     = $SDEUserCredential
                                    DatabaseUser                = $DatabaseUserCredential
                                    IsManaged                   = $ConfigurationData.ConfigData.SQLServer.IsManaged
                                    EnableGeodatabase           = $ConfigurationData.ConfigData.SQLServer.EnableGeodatabase
                                    DatabaseType                = 'SQLServerDatabase'
                                    Ensure                      = 'Present'
                                    DependsOn                   = $Depends
                                }
                                $Depends += "[ArcGIS_EGDB]RegisterEGDB"
                            }
                        }
                    }
                }
                'SqlServer'{
                    ArcGIS_xFirewall Server_FirewallRule_Database
                    {
                            Name                  = "SQL Server Database IN" 
                            DisplayName           = "SQL Server Database 1433" 
                            DisplayGroup          = "SQL Server" 
                            Ensure                = 'Present'
                            Access                = "Allow" 
                            State                 = "Enabled" 
                            Profile               = @("Domain","Private","Public") 
                            LocalPort             = "1433"                         
                            Protocol              = "TCP" 
                            DependsOn             = @('[Script]SQLServerInstall')
                    }

                    Script SetMixedModeAuthentication
                    {
                        GetScript = {
                            $null
                        }
                        TestScript = 
                        {                    
                            $result = $false
                            [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') 
                            $s = new-object ('Microsoft.SqlServer.Management.Smo.Server') "$env:ComputerName" 
                            $result = ($s.Settings.LoginMode -ieq [Microsoft.SqlServer.Management.SMO.ServerLoginMode]::Mixed)
                            $result
                        }
                        SetScript =
                        {
                            [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO')
                            $s = new-object ('Microsoft.SqlServer.Management.Smo.Server') "$env:ComputerName"
                            $s.Settings.LoginMode = [Microsoft.SqlServer.Management.SMO.ServerLoginMode]::Mixed
                            $s.Alter()
                            Stop-Service -Name 'MSSQLSERVER' -Force
                            Start-Sleep -Seconds 5
                            Start-Service -Name 'MSSQLSERVER'
                        }
                        DependsOn = @('[ArcGIS_xFirewall]Server_FirewallRule_Database')
                    }

                    $DatabaseAdminUserName = $ConfigurationData.ConfigData.SQLServer.DatabaseAdminUser.UserName
                    $DatabaseAdminPassword = $ConfigurationData.ConfigData.SQLServer.DatabaseAdminUser.Password

                    Script CreateDatabaseAdminUser
                    {
                        GetScript = {
                            $null
                        }
                        TestScript = 
                        {                    
                            [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') | Out-Null
                            $s = new-object ('Microsoft.SqlServer.Management.Smo.Server') "$env:ComputerName" 
                            (($s.logins).Name -contains $using:DatabaseAdminUserName)    
                        }
                        SetScript =
                        {
                            [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO')
                            $s = new-object ('Microsoft.SqlServer.Management.Smo.Server') "$env:ComputerName"
                            [Microsoft.SqlServer.Management.Smo.Login]$login = New-Object Microsoft.SqlServer.Management.Smo.Login $s,$using:DatabaseAdminUserName
                            $login.LoginType = [Microsoft.SqlServer.Management.Smo.LoginType]::SqlLogin      
                            $login.Create($using:DatabaseAdminPassword)
                            $login.AddToRole("sysadmin")
                            $login.AddToRole("dbcreator")
                            $login.AddToRole("serveradmin")
                            $login.Alter()
                        }
                        DependsOn = @('[Script]SetMixedModeAuthentication')
                    }
                }
            }
        }
    }
}