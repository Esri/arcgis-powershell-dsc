$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
    (
        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $FileShareCredential,

        [parameter(Mandatory = $true)]
        [System.String]
        $FileShareEndpoint,

        [parameter(Mandatory = $true)]
        [System.String]
        $FileShareName,

        [parameter(Mandatory = $true)]
        [System.String]
        $ArcGISWorkspaceLocation,

        [System.Boolean]
        $UseAzureFiles,

        [System.Boolean]
        $IsSingleTier,

        [System.Boolean]
        $Join
    )

    $null
}

function Set-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(	
        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $FileShareCredential,

        [parameter(Mandatory = $true)]
        [System.String]
        $FileShareEndpoint,

        [parameter(Mandatory = $true)]
        [System.String]
        $FileShareName,

        [parameter(Mandatory = $true)]
        [System.String]
        $ArcGISWorkspaceLocation,

        [System.Boolean]
        $UseAzureFiles,

        [System.Boolean]
        $IsSingleTier,

        [System.Boolean]
        $Join
	)
    
    $fsusername = "$($env:COMPUTERNAME)\$($FileShareCredential.GetNetworkCredential().UserName)"
    if($UseAzureFiles -ieq 'True') {
        $AzureFileStrAccountName = $FileShareEndpoint.Substring(0, $FileShareEndpoint.IndexOf('.'))
        $fsusername = "Azure\$AzureFileStrAccountName"
    }
    
    $FSCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $fsusername, $FileShareCredential.Password )

    $FSSharePath = "\\$($FileShareEndpoint)\$FileShareName" 

    if($UseAzureFiles){
        $AvailableDriveLetter = Get-AvailableDriveLetter    
        $connectTestResult = Test-NetConnection -ComputerName "$FileShareEndpoint" -Port 445 #TODO
        Write-Host "connectTestResult - $($connectTestResult.TcpTestSucceeded)"
        
        if ($connectTestResult.TcpTestSucceeded) {
            New-PSDrive -Name $AvailableDriveLetter -PSProvider FileSystem -Root $FSSharePath -Credential $FSCredential -Persist
        } else {
            Write-Error -Message "Unable to reach the Azure storage account via port 445. Check to make sure your organization or ISP is not blocking port 445, or use Azure P2S VPN, Azure S2S VPN, or Express Route to tunnel SMB traffic over a different port."
        }

        $newPath = $ArcGISWorkspaceLocation.Replace($FSSharePath, "$($AvailableDriveLetter):")
        New-Item -Path $newPath -ItemType Directory -Force

        Remove-PSDrive -Name $AvailableDriveLetter
    }

    if(Get-SmbGlobalMapping -LocalPath G: -RemotePath $ArcGISWorkspaceLocation -ErrorAction Ignore){
        Write-Verbose "SMB mapping already exists"
    }else{
        if($IsSingleTier -and -not($Join) -and -not($UseAzureFiles)){
            New-SmbGlobalMapping -RemotePath $ArcGISWorkspaceLocation -Credential $FSCredential -LocalPath G: -Verbose 
        }else{
            New-SmbGlobalMapping -RemotePath $ArcGISWorkspaceLocation -Credential $FSCredential `
            -LocalPath G: -Persistent $true -Verbose
        }
    }

    if(-not($Join) -and -not($UseAzureFiles) -and $IsSingleTier){
        $ServiceName = 'ArcGIS Notebook Server'
        $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
        $InstallDir = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir  
        
        $UserPassFilePath = "$($InstallDir)\NBWorkspaceUser.txt"
        $FSCredential.Password | ConvertFrom-SecureString | Out-File $UserPassFilePath
        $Trigger = New-ScheduledTaskTrigger -AtStartup
        $User = "NT AUTHORITY\SYSTEM" # Specify the account to run the script
        $Arguments = @"
-NoProfile -ExecutionPolicy Bypass -Command "& { New-NotebookWorkspaceSMBGlobalMapping -RemotePath $($ArcGISWorkspaceLocation) -DriveLetter G -Username $($FSCredential.UserName) -WorkspaceUserFilePath '$UserPassFilePath' }"
"@
        $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $Arguments # Specify what program to run and with its parameters
        Register-ScheduledTask -TaskName "NBWorkspaceVMStartupTask" -Trigger $Trigger -User $User -Action $Action -RunLevel Highest -Force -Verbose # Specify the name of the task
        Write-Host "Created VM Startup Task"
    }
}

function Test-TargetResource
{
    [CmdletBinding()]
	[OutputType([System.Boolean])]
	param
    (   
        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $FileShareCredential,

        [parameter(Mandatory = $true)]
        [System.String]
        $FileShareEndpoint,

        [parameter(Mandatory = $true)]
        [System.String]
        $FileShareName,

        [parameter(Mandatory = $true)]
        [System.String]
        $ArcGISWorkspaceLocation,

        [System.Boolean]
        $UseAzureFiles,

        [System.Boolean]
        $IsSingleTier,

        [System.Boolean]
        $Join
    )

    if(Get-SmbGlobalMapping -LocalPath G: -RemotePath $ArcGISWorkspaceLocation -ErrorAction Ignore){
        Write-Verbose "SMB mapping for network location $($ArcGISWorkspaceLocation) already exists"
        return $True
    }else{
        Write-Verbose "SMB mapping for network location $($ArcGISWorkspaceLocation) doesn't exists"
        return $False
    }
    
}

Export-ModuleMember -Function *-TargetResource
