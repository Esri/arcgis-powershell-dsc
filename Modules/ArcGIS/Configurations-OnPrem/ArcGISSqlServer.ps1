Configuration ArcGISSQLServer
{
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]
        $DatabaseServerAdministratorCredential,

        [Parameter(Mandatory=$true)]
        [System.String]
        $DatabaseServerHostName
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.0.2"}
    Import-DscResource -Name ArcGIS_xFirewall
    
    Node $AllNodes.NodeName
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        if($Node.NodeName -ieq $DatabaseServerHostName){
            ArcGIS_xFirewall Server_FirewallRule_Database
            {
                Name            = "SQL Server Database IN" 
                DisplayName     = "SQL Server Database 1433" 
                DisplayGroup    = "SQL Server" 
                Ensure          = 'Present'
                Access          = "Allow" 
                State           = "Enabled" 
                Profile         = @("Domain","Private","Public") 
                LocalPort       = "1433"                         
                Protocol        = "TCP" 
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

            Script CreateDatabaseAdminUser
            {
                GetScript = {
                    $null
                }
                TestScript = 
                {                
                    $DatabaseAdminUser = $using:DatabaseServerAdministratorCredential
                    [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') | Out-Null
                    $s = new-object ('Microsoft.SqlServer.Management.Smo.Server') "$env:ComputerName" 
                    (($s.logins).Name -contains $DatabaseAdminUser.UserName)    
                }
                SetScript =
                {
                    [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO')
                    $DatabaseAdminUser = $using:DatabaseServerAdministratorCredential
                    $s = new-object ('Microsoft.SqlServer.Management.Smo.Server') "$env:ComputerName"
                    [Microsoft.SqlServer.Management.Smo.Login]$login = New-Object Microsoft.SqlServer.Management.Smo.Login $s,$DatabaseAdminUser.UserName
                    $login.LoginType = [Microsoft.SqlServer.Management.Smo.LoginType]::SqlLogin      
                    $login.Create($DatabaseAdminUser.GetNetworkCredential().Password)
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