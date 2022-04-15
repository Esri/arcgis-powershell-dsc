
function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
        [parameter(Mandatory = $True)]
        [ValidateSet("Relational","TileCache","SpatioTemporal")]
        [System.String]
        $DataStoreType,

        [parameter(Mandatory = $True)]
        [ValidateSet("fs","s3","azure")]
        [System.String]
        $BackupType,

        [parameter(Mandatory = $True)]
        [System.String]
        $BackupName,

        [parameter(Mandatory = $True)]
        [System.String]
        $BackupLocation,

        [parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]
        $CloudBackupCredential,

        [parameter(Mandatory = $False)]
        [System.Boolean]
        $IsDefault = $False,
        
        [parameter(Mandatory = $False)]
        [System.Boolean]
        $ForceDefaultRelationalBackupUpdate = $False,

        [parameter(Mandatory = $False)]
        [System.Boolean]
        $ForceCloudCredentialsUpdate = $False
	)
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

	$null
}


function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
        [parameter(Mandatory = $True)]
        [ValidateSet("Relational","TileCache","SpatioTemporal")]
        [System.String]
        $DataStoreType,

        [parameter(Mandatory = $True)]
        [ValidateSet("fs","s3","azure")]
        [System.String]
        $BackupType,

        [parameter(Mandatory = $True)]
        [System.String]
        $BackupName,

        [parameter(Mandatory = $True)]
        [System.String]
        $BackupLocation,

        [parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]
        $CloudBackupCredential,

        [parameter(Mandatory = $False)]
        [System.Boolean]
        $IsDefault = $False,
        
        [parameter(Mandatory = $False)]
        [System.Boolean]
        $ForceDefaultRelationalBackupUpdate = $False,

        [parameter(Mandatory = $False)]
        [System.Boolean]
        $ForceCloudCredentialsUpdate = $False
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    
    $ServiceName = 'ArcGIS Data Store'
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $RegKeyObject = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore)

    $DataStoreInstallDirectory = $RegKeyObject.InstallDir.TrimEnd('\')  
    $RealVersion = $RegKeyObject.RealVersion
    
    Write-Verbose "Version of DataStore is $RealVersion"
    $VersionArray = $RealVersion.Split('.')
    if($VersionArray[1] -lt 6){
        throw "ArcGIS_DataStoreBackup resource doesn't support ArcGIS DataStore 10.5.1 and below"
    }
    
    $UseDescribeDataStore = (($VersionArray[1] -lt 8) -and ($DataStoreType -eq "TileCache")) -or (($RealVersion -ieq "10.6") -and ($DataStoreType -eq "Relational"))
    $AllExistingBackupLocations = Get-DataStoreBackupLocation -DataStoreType $DataStoreType -DataStoreInstallDirectory $DataStoreInstallDirectory `
                                    -UseDescibeDatastore:$UseDescribeDataStore

    $Flag = $False
    if($DataStoreType -eq "Relational"){
        if(($VersionArray[1] -eq 6) -and ($VersionArray[2] -eq 0)){
            if($BackupName -ne "DEFAULT"){
                throw "Backup for Relational DataStore cannot have a backup name other than 'DEFAULT' at $RealVersion"
            }
            if($BackupType -ne "fs"){
                throw "Backup for Relational DataStore can only be a local path or shared file location at $RealVersion"
            }
            if($AllExistingBackupLocations[0].Location -ine $BackupLocation){
                Write-Verbose "Updating default backup location to '$BackupLocation' for $DataStoreType Datastore"
                Invoke-DataStoreConfigureBackupLocationTool -BackupLocationString $BackupLocation `
                                                    -DataStoreInstallDirectory $DataStoreInstallDirectory `
                                                    -DataStoreType $DataStoreType -OperationType "change" -Verbose 
            }
        }else{
            if($IsDefault){
                if($BackupType -ne "fs"){
                    throw "Default back up for Relational DataStore can only be a local path or shared file location at $RealVersion"
                }
                $ExistingBackup = ($AllExistingBackupLocations | Where-Object { $_.IsDefault -ieq $true } | Select-Object -First 1 )
                if($ExistingBackup.Location -ine $BackupLocation){
                    Write-Verbose "Updating default backup location to '$BackupLocation' for $DataStoreType Datastore"
                    Invoke-DataStoreConfigureBackupLocationTool -BackupLocationString $BackupLocation `
                                                        -DataStoreInstallDirectory $DataStoreInstallDirectory `
                                                        -DataStoreType $DataStoreType -OperationType "change" `
                                                        -Verbose -ForceUpdate:$ForceDefaultRelationalBackupUpdate
                }
                if($ExistingBackup.Name -ne $BackupName){
                    Write-Verbose "Updating default backup name to '$BackupName' for $DataStoreType Datastore"
                    $ExpectedBackupLocationString = "type=fs;name=$($BackupName);location=$($BackupLocation)"
                    Invoke-DataStoreConfigureBackupLocationTool -BackupLocationString $ExpectedBackupLocationString `
                                                        -DataStoreInstallDirectory $DataStoreInstallDirectory `
                                                        -DataStoreType $DataStoreType -OperationType "change" -Verbose 
                }
            }else{
                $Flag = $true
            }
        }
    }elseif($DataStoreType -eq "TileCache"){
        if($VersionArray[1] -lt 8){
            if($BackupName -ne "DEFAULT"){
                throw "Backup for Tile Cache DataStore cannot have a backup name other than 'DEFAULT' at $RealVersion"
            }
            if($BackupType -ne "fs"){
                throw "Backup of Tile Cache DataStore to a Cloud Store isn't supported at $RealVersion"
            }
            if($AllExistingBackupLocations[0].Location -ine $BackupLocation){
                Write-Verbose "Updating default backup location to '$BackupLocation' for $DataStoreType Datastore"
                Invoke-DataStoreConfigureBackupLocationTool -BackupLocationString $BackupLocation `
                                                    -DataStoreInstallDirectory $DataStoreInstallDirectory `
                                                    -DataStoreType $DataStoreType -OperationType "change" -Verbose 
            }
        }else{
            $Flag = $true
        }
    }elseif($DataStoreType -eq "SpatioTemporal"){
        $Flag = $true  
    }
      
    if($Flag){
        $ExpectedBackupLocationString = "type=$($BackupType);name=$($BackupName);location=$($BackupLocation)"
        if($BackupType -ne "fs"){
            $EndpointSuffix = $null
            $CloudCredentialUserName = $CloudBackupCredential.UserName
            if($BackupType -ieq "azure"){
                $Pos = $CloudBackupCredential.UserName.IndexOf('.blob.')
                if($Pos -gt -1) 
                {
                    $EndpointSuffix = $CloudCredentialUserName.Substring($Pos + 6)
                    if(($VersionArray[1] -ge 7) -or (($VersionArray[1] -le 6) -and ($EndpointSuffix -ieq "core.windows.net"))){
                        $CloudCredentialUserName = $CloudCredentialUserName.Substring(0, $Pos)
                    }else{
                        throw "Error - Backups to Azure Cloud Storage with endpoint suffix $EndpointSuffix is not supported for ArcGIS Enterprise 10.6.1 and below"
                    }
                }
                else
                {
                    throw "Error - Invalid Backup Azure Blob Storage Account"
                } 
            }

            $ExpectedBackupLocationString += ";username=$($CloudCredentialUserName);password=$($CloudBackupCredential.GetNetworkCredential().Password)"
            if($BackupType -ieq "azure" -and ($null -ne $EndpointSuffix) -and ($VersionArray[1] -ge 7)){
                $ExpectedBackupLocationString += ";endpointsuffix=$EndpointSuffix"
            }
        }

        $ExistingBackup = ($AllExistingBackupLocations | Where-Object { $_.Location -ieq $BackupLocation } | Select-Object -First 1 )
        if($null -ne $ExistingBackup){
            Write-Verbose "Backup with location '$BackupLocation' found for  $DataStoreType Datastore"
            $UpdateBackupLocation = $False
            if(($BackupType -ne "fs") -and $ForceCloudCredentialsUpdate){
                Write-Verbose "Forcing Credentials update for backup with location '$BackupLocation' for $DataStoreType Datastore"
                $UpdateBackupLocation = $true
            }
            if($ExistingBackup.Name -ne $BackupName){
                Write-Verbose "Forcing backup location name update for backup with location '$BackupLocation' for $DataStoreType Datastore"
                $UpdateBackupLocation = $true
            }
            if($UpdateBackupLocation){
                Write-Verbose "Updating Backup with location '$BackupLocation' found for $DataStoreType Datastore"
                Invoke-DataStoreConfigureBackupLocationTool -BackupLocationString $ExpectedBackupLocationString `
                                                    -DataStoreInstallDirectory $DataStoreInstallDirectory `
                                                    -DataStoreType $DataStoreType -OperationType "change" -Verbose 
            }
        }else{
            Write-Verbose "Registering Backup of type '$BackupType', location '$BackupLocation' and name '$BackupName' for  $DataStoreType Datastore "
            Invoke-DataStoreConfigureBackupLocationTool -BackupLocationString $ExpectedBackupLocationString `
                                                -DataStoreInstallDirectory $DataStoreInstallDirectory `
                                                -DataStoreType $DataStoreType -OperationType "register" -Verbose 
        }

        if(($DataStoreType -ne "Relational") -and $IsDefault -and (($null -eq $ExistingBackup) -or (($null -ne $ExistingBackup) -and -not($ExistingBackup.IsDefault)))){
            Write-Verbose "Setting backup with location '$BackupLocation' and name '$BackupName' for $DataStoreType Datastore to default"
            Invoke-DataStoreConfigureBackupLocationTool -BackupLocationString "name=$($BackupName)" `
                                                -DataStoreInstallDirectory $DataStoreInstallDirectory `
                                                -DataStoreType $DataStoreType -OperationType "setdefault" -Verbose 
        }
    }
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [parameter(Mandatory = $True)]
        [ValidateSet("Relational","TileCache","SpatioTemporal")]
        [System.String]
        $DataStoreType,

        [parameter(Mandatory = $True)]
        [ValidateSet("fs","s3","azure")]
        [System.String]
        $BackupType,

        [parameter(Mandatory = $True)]
        [System.String]
        $BackupName,

        [parameter(Mandatory = $True)]
        [System.String]
        $BackupLocation,

        [parameter(Mandatory = $False)]
        [System.Management.Automation.PSCredential]
        $CloudBackupCredential,

        [parameter(Mandatory = $False)]
        [System.Boolean]
        $IsDefault = $False,
        
        [parameter(Mandatory = $False)]
        [System.Boolean]
        $ForceDefaultRelationalBackupUpdate = $False,

        [parameter(Mandatory = $False)]
        [System.Boolean]
        $ForceCloudCredentialsUpdate = $False
    )
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $result = $true
    $ServiceName = 'ArcGIS Data Store'
    $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
    $RegKeyObject = (Get-ItemProperty -Path $RegKey -ErrorAction Ignore)

    $DataStoreInstallDirectory = $RegKeyObject.InstallDir.TrimEnd('\')  
    $RealVersion = $RegKeyObject.RealVersion
    
    Write-Verbose "Version of DataStore is $RealVersion"
    $VersionArray = $RealVersion.Split('.')
    if($VersionArray[1] -lt 6){
        throw "ArcGIS_DataStoreBackup resource doesn't support ArcGIS DataStore 10.5.1 and below"
    }
    
    $UseDescribeDataStore = (($VersionArray[1] -lt 8) -and ($DataStoreType -eq "TileCache")) -or ($RealVersion -ieq "10.6" -and ($DataStoreType -eq "Relational"))
	$AllExistingBackupLocations = Get-DataStoreBackupLocation -DataStoreType $DataStoreType -DataStoreInstallDirectory $DataStoreInstallDirectory `
                                    -UseDescibeDatastore:$UseDescribeDataStore

    if($DataStoreType -eq "Relational"){
        if(($VersionArray[1] -eq 6) -and ($VersionArray[2] -eq 0)){
            if($BackupName -ne "DEFAULT"){
                throw "Backup for Relational DataStore cannot have a backup name other than 'DEFAULT' at $RealVersion"
            }
            if($BackupType -ne "fs"){
                throw "Backup for Relational DataStore can only be a local path or shared file location at $RealVersion"
            }
            if($AllExistingBackupLocations[0].Location -ine $BackupLocation){
                Write-Verbose "Current Default backup location $($ExistingBackup.Location) doesn't match '$BackupLocation' for $DataStoreType Datastore"
                $result = $False
            }
        }else{
            if($IsDefault){
                if($BackupType -ne "fs"){
                    throw "Default back up for Relational DataStore can only be a local path or shared file location at $RealVersion"
                }
                $ExistingBackup = ($AllExistingBackupLocations | Where-Object { $_.IsDefault -ieq $true } | Select-Object -First 1 )
                if($ExistingBackup.Location -ine $BackupLocation){
                    Write-Verbose "Current Default backup location $($ExistingBackup.Location) doesn't match '$BackupLocation' for $DataStoreType Datastore"
                    $result = $False
                }
                
                if($result -and $ExistingBackup.Name -ne $BackupName){
                    Write-Verbose "Current Default backup name $($ExistingBackup.Name) doesn't match '$BackupName' for $DataStoreType Datastore"
                    $result = $False
                }
            }else{
                $Flag = $true
            }
        }
    }elseif($DataStoreType -eq "TileCache"){
        if($VersionArray[1] -lt 8){
            if($BackupName -ne "DEFAULT"){
                throw "Backup for Tile Cache DataStore cannot have a backup name other than 'DEFAULT' at $RealVersion"
            }
            if($BackupType -ne "fs"){
                throw "Backup of Tile Cache DataStore to a Cloud Store isn't supported at $RealVersion"
            }
            if($AllExistingBackupLocations[0].Location -ine $BackupLocation){
                Write-Verbose "Current Default backup location $($ExistingBackup.Location) doesn't match '$BackupLocation' for $DataStoreType Datastore"
                $result = $False
            }
        }else{
            $Flag = $true
        }
    }elseif($DataStoreType -eq "SpatioTemporal"){
        $Flag = $true  
    }

    if($result -and $Flag){
        $ExistingBackup = ($AllExistingBackupLocations | Where-Object { $_.Location -ieq $BackupLocation } | Select-Object -First 1 )
        if($null -ne $ExistingBackup){
            Write-Verbose "Backup with location '$BackupLocation' found for  $DataStoreType Datastore"
            if($BackupType -ne "fs"){
                $EndpointSuffix = $null
                $CloudCredentialUserName = $CloudBackupCredential.UserName
                if($BackupType -ieq "azure"){
                    Write-Verbose "Validating Azure Cloud Storage account Name"
                    $Pos = $CloudBackupCredential.UserName.IndexOf('.blob.')
                    if($Pos -gt -1) 
                    {
                        $EndpointSuffix = $CloudCredentialUserName.Substring($Pos + 6)
                        if(-not(($VersionArray[1] -ge 7) -or (($VersionArray[1] -le 6) -and ($EndpointSuffix -eq "core.windows.net")))){
                            throw "Error - Backups to Azure Cloud Storage with endpoint suffix $EndpointSuffix is not supported for ArcGIS Enterprise 10.6.1 and below"
                        }
                    }
                    else
                    {
                        throw "Error - Invalid Backup Azure Blob Storage Account"
                    } 
                }

                if($ForceCloudCredentialsUpdate){
                    Write-Verbose "Backup cloud credential with location '$BackupLocation' and name '$BackupName' don't match for $DataStoreType Datastore"
                    $result = $False
                }
            }
            if( $result -and $ExistingBackup.Name -ne $BackupName){
                Write-Verbose "Current backup location $($ExistingBackup.Name) doesn't match '$BackupName' for $DataStoreType Datastore"
                $result = $False
            }
        }else{
            Write-Verbose "No Backup of type '$BackupType', location '$BackupLocation' and name '$BackupName' found for  $DataStoreType Datastore"
            $result = $False
        }
        if($result -and ($DataStoreType -ne "Relational") -and $IsDefault -and (($null -eq $ExistingBackup) -or (($null -ne $ExistingBackup) -and -not($ExistingBackup.IsDefault)))){
            Write-Verbose "Backup of type '$BackupType', location '$BackupLocation' and name '$BackupName' isn't default backup for  $DataStoreType Datastore"
            $result = $False
        }
    }
    $result
}

Export-ModuleMember -Function *-TargetResource
