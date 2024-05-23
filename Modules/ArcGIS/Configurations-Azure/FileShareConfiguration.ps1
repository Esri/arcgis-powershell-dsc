Configuration FileShareConfiguration
{
	param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServiceCredential

        ,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $MachineAdministratorCredential

        ,[Parameter(Mandatory=$true)]
        [System.String]
        $ExternalDNSHostName

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $PortalContext
        
        ,[Parameter(Mandatory=$false)]
        [System.Int32]
        $OSDiskSize = 0

         ,[Parameter(Mandatory=$false)]
        [System.String]
        $EnableDataDisk

        ,[Parameter(Mandatory=$false)]
        [System.Int32]
        $DataDiskNumber = 2

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $FileShareName = 'fileshare'

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $IsBaseDeployment 

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $IsNotebookServerDeployment

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $ServerContext

        ,[Parameter(Mandatory=$false)]
        [System.String]
        $DebugMode
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_xDisk
    Import-DscResource -Name ArcGIS_xSmbShare
    Import-DscResource -Name ArcGIS_Disk

    $FolderName = $ExternalDNSHostName.Substring(0, $ExternalDNSHostName.IndexOf('.')).ToLower()
    $FileShareLocalPath = (Join-Path $env:SystemDrive $FileShareName)
    $IsDebugMode = $DebugMode -ieq 'true'

	Node localhost
	{
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $true
        }
        
        if($OSDiskSize -gt 0)
        {
            ArcGIS_Disk OSDiskSize
            {
                DriveLetter = ($env:SystemDrive -replace ":" )
                SizeInGB    = $OSDiskSize
            }
        }

        if($EnableDataDisk -ieq 'true')
        {
            ArcGIS_xDisk DataDisk
            {
                DiskNumber  =  $DataDiskNumber
                DriveLetter = 'F'
            }
        }

        $HasValidServiceCredential = ($ServiceCredential -and ($ServiceCredential.GetNetworkCredential().Password -ine 'Placeholder'))
        if($HasValidServiceCredential) 
        {
            if(-Not($ServiceCredentialIsDomainAccount)){
                User ArcGIS_RunAsAccount
                {
                    UserName       = $ServiceCredential.UserName
                    Password       = $ServiceCredential
                    FullName       = 'ArcGIS Service Account'
                    Ensure         = 'Present'
                    PasswordChangeRequired = $false
                    PasswordNeverExpires = $true
                }
            }

            File FileShareLocationPath
            {
                Type						= 'Directory'
                DestinationPath				= $FileShareLocalPath
                Ensure						= 'Present'
                Force						= $true
            }
            
            if($IsBaseDeployment -ieq 'True'){
                File ContentDirectoryLocationPath
                {
                    Type						= 'Directory'
                    DestinationPath				= (Join-Path $FileShareLocalPath "$FolderName/$($PortalContext)/content")
                    Ensure						= 'Present'
                    Force						= $true
                    DependsOn					= @('[File]FileShareLocationPath')
                }

                $DataStoreBackupsLocalPath = (Join-Path $FileShareLocalPath "$FolderName/datastore/dbbackups")
                File DataStoreBackupsLocationPath
                {
                    Type						= 'Directory'
                    DestinationPath				= $DataStoreBackupsLocalPath
                    Ensure						= 'Present'
                    Force						= $true
                    DependsOn					= @('[File]FileShareLocationPath')
                }        
            }

            if($IsNotebookServerDeployment -ieq 'True'){
                File ArcGISWorkspaceFileShareLocationPath
                {
                    Type						= 'Directory'
                    DestinationPath				= (Join-Path $FileShareLocalPath "$FolderName\$($ServerContext)\server-dirs\arcgisworkspace")
                    Ensure						= 'Present'
                    Force						= $true
                    DependsOn					= @('[File]FileShareLocationPath')
                }
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
                DependsOn					= if(-Not($ServiceCredentialIsDomainAccount)){ @('[User]ArcGIS_RunAsAccount','[File]FileShareLocationPath')}else{ @('[File]FileShareLocationPath')}
            }
        }
	}
}
