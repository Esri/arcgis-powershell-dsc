Configuration RemoveStandbyGraphStoreConfiguration
{
    param(
        [Parameter(Mandatory=$true)]
        [System.String]
        $StandbyGraphStoreMachineName
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
    
    Node localhost
	{
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $false
        }

        Script "RemoveStandbyGraphStoreConfiguration"
        {
            GetScript = {
                $null
            }
            TestScript = {
                $false
            }
            SetScript = {
                # Get install location for DataStore
                $RegKey = "HKLM:\SOFTWARE\ESRI\ArcGIS Data Store"
                $DataStoreInstallDirectory = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir.TrimEnd('\')  
                if(-not($DataStoreInstallDirectory -and $DataStoreInstallDirectory.Length -gt 0)){
                    throw "DataStore Install Directory not found in registry."
                }

                $RemoveMachineToolPath = Join-Path $DataStoreInstallDirectory 'tools\removemachine.bat'
                if(-not(Test-Path $RemoveMachineToolPath)){
                    throw "$RemoveMachineToolPath not found"
                }
                
                $Arguments = "$($using:StandbyGraphStoreMachineName) --store graph --prompt no --force true"
                
                Write-Verbose "Remove Machine Tool:- $RemoveMachineToolPath $Arguments"
                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = $RemoveMachineToolPath
                $psi.Arguments = $Arguments
                $psi.UseShellExecute = $false #start the process from it's own executable file    
                $psi.RedirectStandardOutput = $true #enable the process to read from standard output
                $psi.RedirectStandardError = $true #enable the process to read from standard error
                $psi.EnvironmentVariables["AGSDATASTORE"] = [environment]::GetEnvironmentVariable("AGSDATASTORE","Machine")
                
                $p = [System.Diagnostics.Process]::Start($psi)
                $p.WaitForExit()
                $op = $p.StandardOutput.ReadToEnd()
                if($p.ExitCode -eq 0) {                    
                    Write-Host "Remove machine tool executed successfully."
                    # if($op -and $op.Length -gt 0) {
                    #     Write-Verbose "Output:- $op"
                    # }
                    if($op -ccontains 'failed') {
                        throw "Remove machine tool Failed. Output - $op."
                    }
                }else{
                    $err = $p.StandardError.ReadToEnd()
                    Write-Verbose $err
                    if($err -and $err.Length -gt 0) {
                        throw "Remove machine tool Failed. Output - $op. Error - $err"
                    }
                }
            }
        }
    }
}