function Get-TargetResource
{
    param(
        [Parameter(Mandatory=$True)]
        [System.String]
        $Version,

        [Parameter(Mandatory=$True)]
        [System.String]
        $OperationType,
       
        [Parameter(Mandatory=$True)]
        [System.String]
        $ComponentNames,

        [Parameter(Mandatory=$false)]
        [System.String]
        $ServerRole,

        [Parameter(Mandatory=$false)]
        [System.String]
        $UpgradeSetupsSourceFileSharePath,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $UpgradeSetupsSourceFileShareCredentials,

        [Parameter(Mandatory=$false)]
        [System.Array]
        $AdditionalFilesOrFolderToDelete
    )

    $null

}

function Set-TargetResource
{
    param(
        [Parameter(Mandatory=$True)]
        [System.String]
        $Version,

        [Parameter(Mandatory=$True)]
        [System.String]
        $OperationType,
       
        [Parameter(Mandatory=$True)]
        [System.String]
        $ComponentNames,

        [Parameter(Mandatory=$false)]
        [System.String]
        $ServerRole,

        [Parameter(Mandatory=$false)]
        [System.String]
        $UpgradeSetupsSourceFileSharePath,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $UpgradeSetupsSourceFileShareCredentials,

        [Parameter(Mandatory=$false)]
        [System.Array]
        $AdditionalFilesOrFolderToDelete
    )

    $SetupsStagingFolderPath = "C:\ArcGIS\Deployment\Downloads"
    if($OperationType -ieq "CleanupDownloadsFolder"){
        # Cleanup the downloads folder
        Invoke-DownloadFolderCleanup -ComponentNames $ComponentNames -ServerRole $ServerRole -SetupsStagingFolderPath $SetupsStagingFolderPath -Verbose
    }elseif($OperationType -ieq "DownloadUpgradeSetups"){
        $ComponentNamesArray = $ComponentNames -split ","
        if($ComponentNamesArray.Length -gt 1){
            throw "Multiple components are not supported for this operation."
        }
        
        Invoke-DownloadSetupFromUpgradeVM -Version $Version -ComponentName ($ComponentNames) -ServerRole $ServerRole `
                                    -UpgradeSetupsSourceFileSharePath $UpgradeSetupsSourceFileSharePath -UpgradeSetupsSourceFileShareCredentials $UpgradeSetupsSourceFileShareCredentials `
                                    -SetupsStagingFolderPath $SetupsStagingFolderPath -Verbose
    }else{
        throw "OperationType '$OperationType' is not supported."
    }

    if($AdditionalFilesOrFolderToDelete -ne $null){
        Invoke-AdditionalFolderOrFilesToCleanup -FileOrFolderPaths $AdditionalFilesOrFolderToDelete -Verbose
    }
    
}

function Test-TargetResource
{
    param(
        [Parameter(Mandatory=$True)]
        [System.String]
        $Version,

        [Parameter(Mandatory=$True)]
        [System.String]
        $OperationType,
       
        [Parameter(Mandatory=$True)]
        [System.String]
        $ComponentNames,

        [Parameter(Mandatory=$false)]
        [System.String]
        $ServerRole,

        [Parameter(Mandatory=$false)]
        [System.String]
        $UpgradeSetupsSourceFileSharePath,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $UpgradeSetupsSourceFileShareCredentials,

        [Parameter(Mandatory=$false)]
        [System.Array]
        $AdditionalFilesOrFolderToDelete
    )

    $false
}

function Add-LongPathPrefix {
    param(
        [string]$Path
    )
    if ($Path.Length -gt 259) {
        if (-not $Path.StartsWith("\\\\?\\")) {
            return "\\\\?\\" + $Path
        } else {
            return $Path
        }
     } else {
        return $Path
     }
}

function Invoke-AdditionalFolderOrFilesToCleanup
{
    param(
        [Parameter(Mandatory=$false)]
        [System.Array]
        $FileOrFolderPaths
    )

    foreach($FileOrFolderPath in $FileOrFolderPaths){
        if(Test-Path -Path $FileOrFolderPath) {
            Write-Verbose "Found file/folder: $FileOrFolderPath"
            try {
                # Check if the path is a file or folder
                if (Test-Path -Path $FileOrFolderPath -PathType Leaf) {
                    $FilePathToDelete = Add-LongPathPrefix $FileOrFolderPath
                    Remove-Item -Path $FilePathToDelete -Force 
                    Write-Verbose "Deleted file: $FileOrFolderPath" 
                } elseif (Test-Path -Path $FileOrFolderPath -PathType Container) {
                    $FolderPathToDelete = Add-LongPathPrefix $FileOrFolderPath
                    Remove-Item -Path $FolderPathToDelete -Recurse -Force 
                    Write-Verbose "Deleted file/folder: $FileOrFolderPath" 
                }
            } catch {
                Write-Verbose "[WARNING] Error deleting folder '$($FileOrFolderPath)' - $($_.Exception.Message)"
                # Swallow the error and continue
                # This is to ensure that the script continues even if there are errors in deleting some files/folders
                continue
            }
        } else {
            Write-Verbose "File/Folder not found: $FileOrFolderPath"
        }
    }
}

function  Invoke-DownloadFolderCleanup {
    param(
        [Parameter(Mandatory=$false)]
        [System.String]
        $ComponentNames,

        [Parameter(Mandatory=$false)]
        [System.String]
        $ServerRole,

        [Parameter(Mandatory=$false)]
        [System.String]
        $SetupsStagingFolderPath
    )

    $ComponentNamesArray = $ComponentNames -split ","
    if(Test-Path -Path $SetupsStagingFolderPath) {
        $ExceptionFolders = @()
        if($ComponentNamesArray -icontains "Portal"){
            $ExceptionFolders += @("$($SetupsStagingFolderPath)\Portal","$($SetupsStagingFolderPath)\WebStyles")
        }
        if($ComponentNamesArray -icontains "DataStore"){
            $ExceptionFolders += @("$($SetupsStagingFolderPath)\DataStore")
        }
        if($ComponentNamesArray -icontains "Server"){
            if($ServerRole -ieq "NotebookServer"){
                $ExceptionFolders += @("$($SetupsStagingFolderPath)\NotebookServer","$($SetupsStagingFolderPath)\WebAdaptorIIS")
            }elseif($ServerRole -ieq "MissionServer"){
                $ExceptionFolders += @("$($SetupsStagingFolderPath)\MissionServer")
            }elseif($ServerRole -ieq "VideoServer"){
                $ExceptionFolders += @("$($SetupsStagingFolderPath)\VideoServer")
            }else{
                $ExceptionFolders += @("$($SetupsStagingFolderPath)\Server","$($SetupsStagingFolderPath)\SQLNativeClient")

                if($ServerRole -ieq "GeoEventServer"){
                    $ExceptionFolders += @("$($SetupsStagingFolderPath)\GeoEvent")
                }
                if($ServerRole -ieq "WorkflowManagerServer"){
                    $ExceptionFolders += @("$($SetupsStagingFolderPath)\WorkflowManagerServer")
                }
                $ExceptionFolders += "$($SetupsStagingFolderPath)\Server"
            }
        }

        # Is all is one deploy
        $Subfolders = Get-ChildItem -Path $SetupsStagingFolderPath -Directory
        foreach ($Folder in $Subfolders) {
            $FolderPath = $folder.FullName
    
            # Check if folder exists
            if (Test-Path -Path $FolderPath) {
                Write-Verbose "Found folder: $FolderPath"
                if($FolderPath -in $ExceptionFolders) {
                    Write-Verbose "Skipped deleting folder: $FolderPath"
                } else {
                    try {
                        Remove-Item -Path $FolderPath -Recurse -Force 
                        Write-Verbose "Deleted folder: $FolderPath" 
                    } catch {
                        Write-Verbose "Error deleting folder: $FolderPath. Error: $_"
                        continue
                    }
                }
            } else {
                Write-Verbose "Folder not found: $FolderPath"
            }
        }
    }else{
        Write-Verbose "Folder $DownloadsRoot not found. No cleanup needed."
    }
}
function Invoke-DownloadSetupFromUpgradeVM
{
    param(
        [Parameter(Mandatory=$false)]
        [System.String]
        $Version,    
        
        [Parameter(Mandatory=$false)]
        [System.String]
        $UpgradeVMName,

        [Parameter(Mandatory=$false)]
        [System.String]
        $ComponentName,

        [Parameter(Mandatory=$false)]
        [System.String]
        $ServerRole,

        [Parameter(Mandatory=$false)]
        [System.String]
        $UpgradeSetupsSourceFileSharePath,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $UpgradeSetupsSourceFileShareCredentials,

        [Parameter(Mandatory=$false)]
        [System.String]
        $SetupsStagingFolderPath
    )

    # Make sure the staging path exists
    $StagingPath = "$($SetupsStagingFolderPath)\$($Version)"
    if (-not(Test-Path -Path $StagingPath)) {
        New-Item -Path $StagingPath -ItemType Directory -Force | Out-Null
    }

    # if notebook, check if web adaptor is currently installed, if not then skip the download
    $TempDriveName = "X"
    try{
        if (Get-PSDrive $TempDriveName -ErrorAction SilentlyContinue) {
            Remove-PSDrive -Name $TempDriveName -Force -ErrorAction SilentlyContinue
        } 
        Write-Verbose "Mapping drive '$TempDriveName' to '$($UpgradeSetupsSourceFileSharePath)'"
        $PsDrive = New-PsDrive -Name $TempDriveName -Root $UpgradeSetupsSourceFileSharePath -PSProvider FileSystem -Credential $UpgradeSetupsSourceFileShareCredentials
        Write-Verbose "Mapped drive '$TempDriveName' to '$($UpgradeSetupsSourceFileSharePath)'"
        if($ComponentName -ieq "Portal"){
            # Copy portal setup
            $PortalUpgradeSetupPath = "$($PsDrive.Name):\Portal\PortalforArcGIS.exe"
            $PortalUpgradeSetupDestinationPath = "$($StagingPath)\PortalforArcGIS.exe"
            if(-not(Test-Path -Path $PortalUpgradeSetupDestinationPath)){
                if(-not(Test-Path $PortalUpgradeSetupPath)){
                    throw "Required Portal setup file was not found."
                }
                Copy-Item -Path $PortalUpgradeSetupPath -Destination $PortalUpgradeSetupDestinationPath -Force
                Write-Verbose "Copied Portal setup from '$PortalUpgradeSetupPath' to '$PortalUpgradeSetupDestinationPath'"
            }else{
                Write-Verbose "Portal setup already exists at '$PortalUpgradeSetupDestinationPath'"
            }

            # Copy the portal setup volume
            $PortalUpgradeSetupVolumePath = "$($PsDrive.Name):\Portal\PortalforArcGIS.exe.001"
            $PortalUpgradeSetupVolumeDestinationPath = "$($StagingPath)\PortalforArcGIS.exe.001"
            if(-not(Test-Path -Path $PortalUpgradeSetupVolumeDestinationPath)){
                if(-not(Test-Path $PortalUpgradeSetupVolumePath)){
                    throw "Required Portal setup volume was not found."
                }
                Copy-Item -Path $PortalUpgradeSetupVolumePath -Destination $PortalUpgradeSetupVolumeDestinationPath -Force
                Write-Verbose "Copied Portal setup volume from '$PortalUpgradeSetupVolumePath' to '$PortalUpgradeSetupVolumeDestinationPath'"
            }else{
                Write-Verbose "Portal setup volume already exists at '$PortalUpgradeSetupVolumeDestinationPath'"
            }

            # Copy webstyles
            $WebStylesUpgradeSetupPath = "$($PsDrive.Name):\WebStyles\WebStyles.exe"
            $WebStylesUpgradeSetupDestinationPath = "$($StagingPath)\WebStyles.exe"
            if(-not(Test-Path -Path $WebStylesUpgradeSetupDestinationPath)){
                if(-not(Test-Path $WebStylesUpgradeSetupPath)){
                    throw "Required Web Styles setup file was not found."
                }
                Copy-Item -Path $WebStylesUpgradeSetupPath -Destination $WebStylesUpgradeSetupDestinationPath -Force
                Write-Verbose "Copied Web Styles setup from '$WebStylesUpgradeSetupPath' to '$WebStylesUpgradeSetupDestinationPath'"
            }else{
                Write-Verbose "Web Styles setup already exists at '$WebStylesUpgradeSetupDestinationPath'"
            }
        }elseif($ComponentName -ieq "DataStore"){
            # Copy datastore setup
            $DSUpgradeSetupPath = "$($PsDrive.Name):\DataStore\DataStore.exe"
            $DSUpgradeSetupDestinationPath = "$($StagingPath)\DataStore.exe"
            if(-not(Test-Path -Path $DSUpgradeSetupDestinationPath)){
                if(-not(Test-Path $DSUpgradeSetupPath)){
                    throw "Required DataStore setup file was not found."
                }
                Copy-Item -Path $DSUpgradeSetupPath -Destination $DSUpgradeSetupDestinationPath -Force
                Write-Verbose "Copied DataStore setup from '$DSUpgradeSetupPath' to '$DSUpgradeSetupDestinationPath'"
            }else{
                Write-Verbose "DataStore setup already exists at '$DSUpgradeSetupDestinationPath'"
            }

            $VersionArray = $Version.Split(".")
            if($VersionArray -gt 11){
                # Copy the ds setup volume
                $DSUpgradeSetupVolumePath = "$($PsDrive.Name):\DataStore\DataStore.exe.001"
                $DSUpgradeSetupVolumeDestinationPath = "$($StagingPath)\DataStore.exe.001"
                if(-not(Test-Path -Path $DSUpgradeSetupVolumeDestinationPath)){
                    if(-not(Test-Path $DSUpgradeSetupVolumePath)){
                        throw "Required datastore setup volume was not found."
                    }
                    Copy-Item -Path $DSUpgradeSetupVolumePath -Destination $DSUpgradeSetupVolumeDestinationPath -Force
                    Write-Verbose "Copied Portal setup volume from '$DSUpgradeSetupVolumePath' to '$DSUpgradeSetupVolumeDestinationPath'"
                }else{
                    Write-Verbose "Portal setup volume already exists at '$DSUpgradeSetupVolumeDestinationPath'"
                }
            }
        }elseif($ComponentName -ieq "Server"){
            if($ServerRole -ieq "NotebookServer"){
                # Copy notebook server setup
                $NotebookUpgradeSetupPath = "$($PsDrive.Name):\NotebookServer\NotebookServer.exe"
                $NotebookUpgradeSetupDestinationPath = "$($StagingPath)\NotebookServer.exe"
                if(-not(Test-Path -Path $NotebookUpgradeSetupDestinationPath)){
                    if(-not(Test-Path $NotebookUpgradeSetupPath)){
                        throw "Required Notebook Server setup file was not found."
                    }
                    Copy-Item -Path $NotebookUpgradeSetupPath -Destination $NotebookUpgradeSetupDestinationPath -Force
                    Write-Verbose "Copied Notebook Server setup from '$NotebookUpgradeSetupPath' to '$NotebookUpgradeSetupDestinationPath'"
                }else{
                    Write-Verbose "Notebook Server setup already exists at '$NotebookUpgradeSetupDestinationPath'"
                }

                # TODO: Check if single machine deployment or not
                # Copy WebAdaptor setup
                $WebAdaptorUpgradeSetupPath = "$($PsDrive.Name):\WebAdaptorIIS\WebAdaptorIIS.exe"
                $WebAdaptorUpgradeSetupDestinationPath = "$($StagingPath)\WebAdaptorIIS.exe"
                if(-not(Test-Path -Path $WebAdaptorUpgradeSetupDestinationPath)){
                    if(-not(Test-Path $WebAdaptorUpgradeSetupPath)){
                        throw "Required Web Adaptor setup file was not found."
                    }
                    Copy-Item -Path $WebAdaptorUpgradeSetupPath -Destination $WebAdaptorUpgradeSetupDestinationPath -Force
                    Write-Verbose "Copied Web Adaptor setup from '$WebAdaptorUpgradeSetupPath' to '$WebAdaptorUpgradeSetupDestinationPath'"
                }else{
                    Write-Verbose "Web Adaptor setup already exists at '$WebAdaptorUpgradeSetupDestinationPath'"
                }
                
                $WAAdditionFilesPath = "$($PsDrive.Name):\WebAdaptorIIS\AdditionalFiles"
                if(-not(Test-Path $WAAdditionFilesPath)){
                    throw "Required additional files for Web Adaptor were not found at $WAAdditionFilesPath"
                }

                # Copy WebDeploy setup
                $WebDeployInstallerPath = Get-ChildItem -Path $WAAdditionFilesPath -Filter "*WebDeploy*" -Recurse | Select-Object -ExpandProperty FullName
                if([string]::IsNullOrEmpty($WebDeployInstallerPath)){
                    throw "Required Web Deploy file for Web Adaptor was not found at $WAAdditionFilesPath"
                }
                $WebDeployInstallerDestinationPath = "$($StagingPath)\WebDeploy_amd64_en-US.msi"
                Copy-Item -Path $WebDeployInstallerPath -Destination $WebDeployInstallerDestinationPath -Force -Verbose

                # Copy hosting bundle setup
                $DotnetHostingBundleInstallerPath = Get-ChildItem -Path $WAAdditionFilesPath -Filter "*dotnet-hosting*" -Recurse | Select-Object -ExpandProperty FullName
                if([string]::IsNullOrEmpty($DotnetHostingBundleInstallerPath)){
                    throw "Required dotnet-hosting bundle file for Web Adaptor was not found at $WAAdditionFilesPath"
                }
                $DotnetHostingBundleDestinationPath = "$($StagingPath)\dotnet-hosting-win.exe"
                Copy-Item -Path $DotnetHostingBundleInstallerPath -Destination $DotnetHostingBundleDestinationPath -Force -Verbose

                # Copy notebook container images to the local machine
                $NBAdditionFilesPath = "$($PsDrive.Name):\NotebookServer\AdditionalFiles"
                $NotebookContainerPath = Get-ChildItem -Path $NBAdditionFilesPath -Filter "*arcgis-notebook-python-windows-$($Version)*" -Recurse | Select-Object -ExpandProperty FullName
                if([string]::IsNullOrEmpty($NotebookContainerPath)){
                    Write-Verbose "Required Notebook container image file for Notebook Server was not found at $NBAdditionFilesPath"
                }else{
                    $NotebookContainerDestinationPath = "$($StagingPath)\arcgis-notebook-python-windows-$($Version).tar.gz"
                    Copy-Item -Path $NotebookContainerPath -Destination $NotebookContainerDestinationPath -Force -Verbose
                }

            }elseif($ServerRole -ieq "MissionServer"){
                # Copy mission server setup
                $MissionUpgradeSetupPath = "$($PsDrive.Name):\MissionServer\MissionServer.exe"
                $MissionUpgradeSetupDestinationPath = "$($StagingPath)\MissionServer.exe"
                if(-not(Test-Path -Path $MissionUpgradeSetupDestinationPath)){
                    if(-not(Test-Path $MissionUpgradeSetupPath)){
                        throw "Required Mission Server setup file was not found."
                    }
                    Copy-Item -Path $MissionUpgradeSetupPath -Destination $MissionUpgradeSetupDestinationPath -Force
                    Write-Verbose "Copied Mission Server setup from '$MissionUpgradeSetupPath' to '$MissionUpgradeSetupDestinationPath'"
                }else{
                    Write-Verbose "Mission Server setup already exists at '$MissionUpgradeSetupDestinationPath'"
                }
            }else{
                # Copy Server setup
                $ServerUpgradeSetupPath = "$($PsDrive.Name):\Server\ArcGISforServer.exe"
                $ServerUpgradeSetupDestinationPath = "$($StagingPath)\ArcGISforServer.exe"
                if(-not(Test-Path -Path $ServerUpgradeSetupDestinationPath)){
                    if(-not(Test-Path $ServerUpgradeSetupPath)){
                        throw "Required Server setup file was not found."
                    }
                    Copy-Item -Path $ServerUpgradeSetupPath -Destination $ServerUpgradeSetupDestinationPath -Force
                    Write-Verbose "Copied Server setup from '$ServerUpgradeSetupPath' to '$ServerUpgradeSetupDestinationPath'"
                }else{
                    Write-Verbose "Server setup already exists at '$ServerUpgradeSetupDestinationPath'"
                }
                # Copy the server setup volume
                $ServerUpgradeSetupVolumePath = "$($PsDrive.Name):\Server\ArcGISforServer.exe.001"
                $ServerUpgradeSetupVolumeDestinationPath = "$($StagingPath)\ArcGISforServer.exe.001"
                if(-not(Test-Path -Path $ServerUpgradeSetupVolumeDestinationPath)){
                    if(-not(Test-Path $ServerUpgradeSetupVolumePath)){
                        throw "Required Server setup volume was not found."
                    }
                    Copy-Item -Path $ServerUpgradeSetupVolumePath -Destination $ServerUpgradeSetupVolumeDestinationPath -Force
                    Write-Verbose "Copied Server setup volume from '$ServerUpgradeSetupVolumePath' to '$ServerUpgradeSetupVolumeDestinationPath'"
                }else{
                    Write-Verbose "Server setup volume already exists at '$ServerUpgradeSetupVolumeDestinationPath'"
                }
                if($ServerRole -ieq "GeoEventServer"){
                    # Copy GeoEvent server setup
                    $GeoEventUpgradeSetupPath = "$($PsDrive.Name):\GeoEvent\GeoEvent.exe"
                    $GeoEventUpgradeSetupDestinationPath = "$($StagingPath)\GeoEvent.exe"
                    if(-not(Test-Path -Path $GeoEventUpgradeSetupDestinationPath)){
                        if(-not(Test-Path $GeoEventUpgradeSetupPath)){
                            throw "Required GeoEvent Server setup file was not found."
                        }
                        Copy-Item -Path $GeoEventUpgradeSetupPath -Destination $GeoEventUpgradeSetupDestinationPath -Force
                        Write-Verbose "Copied GeoEvent Server setup from '$GeoEventUpgradeSetupPath' to '$GeoEventUpgradeSetupDestinationPath'"
                    }else{
                        Write-Verbose "GeoEvent Server setup already exists at '$GeoEventUpgradeSetupDestinationPath'"
                    }
                }elseif($ServerRole -ieq "WorkflowManagerServer"){
                    # Copy Workflow Manager server setup
                    $WorkflowManagerServerUpgradeSetupPath = "$($PsDrive.Name):\WorkflowManagerServer\WorkflowManagerServer.exe"
                    $WorkflowManagerServerUpgradeSetupDestinationPath = "$($StagingPath)\WorkflowManagerServer.exe"
                    if(-not(Test-Path -Path $WorkflowManagerServerUpgradeSetupDestinationPath)){
                        if(-not(Test-Path $WorkflowManagerServerUpgradeSetupPath)){
                            throw "Required Workflow Manager Server setup file was not found."
                        }
                        Copy-Item -Path $WorkflowManagerServerUpgradeSetupPath -Destination $WorkflowManagerServerUpgradeSetupDestinationPath -Force
                        Write-Verbose "Copied Workflow Manager Server setup from '$WorkflowManagerServerUpgradeSetupPath' to '$WorkflowManagerServerUpgradeSetupDestinationPath'"
                    }else{
                        Write-Verbose "Workflow Manager Server setup already exists at '$WorkflowManagerServerUpgradeSetupDestinationPath'"
                    }
                }
            }
        }else{
            throw "ComponentName '$ComponentName' is not supported."
        }
    } catch {
        throw "Failed to copy required setups for '$($ComponentName)' from path '$($FileShareRootPath)'. Error: $($_.Exception.Message)"
    } finally {
        # Clean up: Remove the mapped drive when done
        if (Get-PSDrive $TempDriveName -ErrorAction SilentlyContinue) {
            Remove-PSDrive -Name $TempDriveName -Force
            Write-Verbose "Removed PSDrive '$TempDriveName'."
        }
    }
}

Export-ModuleMember -Function *-TargetResource