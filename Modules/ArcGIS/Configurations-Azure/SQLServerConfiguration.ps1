Configuration SQLServerConfiguration
{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $DatabaseAdminCredential
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_xFirewall

    Node $AllNodes.NodeName
    {       
		LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $true
        }

        $DatabaseAdminUserName = $DatabaseAdminCredential.UserName
        $DatabaseAdminPassword = $DatabaseAdminCredential.GetNetworkCredential().Password

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
		}

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
        }
    }
}
