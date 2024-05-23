Configuration UpgradeVMFileShareConfiguration
{   	
	param(
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $ServiceCredential

        ,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $MachineAdministratorCredential
    )

	Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
	Import-DscResource -Name ArcGIS_xSmbShare

	#$FileShareHostName = $env:ComputerName    
    $FileShareLocalPath = (Join-Path $env:SystemDrive "ArcGIS\Deployment\Downloads")
	$FileShareName = "UpgradeSetups"  
	$IsDebugMode = $DebugMode -ieq 'true'
	
    Node localhost
    {   
		LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $true
        }

		$HasValidServiceCredential = ($ServiceCredential -and ($ServiceCredential.GetNetworkCredential().Password -ine 'Placeholder'))
        if($HasValidServiceCredential) 
        {
			if(-Not($ServiceCredentialIsDomainAccount)){
				User ArcGIS_RunAsAccount
				{
					UserName                = $ServiceCredential.UserName
					Password				= $ServiceCredential
					FullName				= 'ArcGIS Service Account'
					Ensure					= 'Present'
					PasswordChangeRequired  = $false
					PasswordNeverExpires    = $true
				}
			}

			File FileShareLocationPath
			{
				Type						= 'Directory'
				DestinationPath				= $FileShareLocalPath
				Ensure						= 'Present'
				Force						= $true
			}   

			$Accounts = @('NT AUTHORITY\SYSTEM')
			if($ServiceCredential) { $Accounts += $ServiceCredential.GetNetworkCredential().UserName }
			if($MachineAdministratorCredential -and ($MachineAdministratorCredential.GetNetworkCredential().UserName -ine 'Placeholder') -and ($MachineAdministratorCredential.GetNetworkCredential().UserName -ine $ServiceCredential.GetNetworkCredential().UserName)) { $Accounts += $MachineAdministratorCredential.GetNetworkCredential().UserName }

			ArcGIS_xSmbShare FileShare 
			{ 
				Ensure						= 'Present' 
				Name						= $FileShareName
				Path						= $FileShareLocalPath
				FullAccess					= $Accounts
				DependsOn					= if(-Not($ServiceCredentialIsDomainAccount)){@('[User]ArcGIS_RunAsAccount','[File]FileShareLocationPath')}else{@('[File]FileShareLocationPath')}
			}
		}
    }
}
