$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

function Get-DataStoreInfo
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,
        
        [System.Management.Automation.PSCredential]
        $ServerSiteAdminCredential, 
        
        [System.String]
        $ServerSiteUrl,
        
        [System.String]
        $Referer
    )

    $WebParams = @{ 
                    f = 'json'
                    username = $ServerSiteAdminCredential.UserName
                    password = $ServerSiteAdminCredential.GetNetworkCredential().Password
                    serverURL = $ServerSiteUrl      
                    dsSettings = '{"features":{"feature.egdb":true,"feature.nosqldb":true,"feature.bigdata":true,"feature.graphstore":true,"feature.ozobjectstore":true}}'
                    getConfigureInfo = 'true'
                }       

   $DataStoreConfigureUrl = $URL.TrimEnd('/') + '/datastoreadmin/configure'  

   Test-ArcGISComponentHealth -BaseURL $URL -ComponentName "DataStore" -MaxWaitTimeInSeconds 180 -SleepTimeInSeconds 5 -Verbose
   
   Invoke-ArcGISWebRequest -Url $DataStoreConfigureUrl -HttpFormParameters $WebParams -Referer $Referer -HttpMethod 'POST' -Verbose 
}


function Get-PITRState
{ 
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $Referer
    )
    
    $result = $null
    $WebParams = @{ 
        f = 'json'
    }

    $DataStoreConfigurePITRUrl = $URL.TrimEnd('/') + '/datastoreadmin/configurePITR'  
    Wait-ForUrl -Url "$($DataStoreConfigurePITRUrl)?f=json" -MaxWaitTimeInSeconds 180 -SleepTimeInSeconds 5 -HttpMethod 'GET' -Verbose
    $Response = Invoke-ArcGISWebRequest -Url $DataStoreConfigurePITRUrl -HttpFormParameters $WebParams -Referer $Referer -TimeOutSec 600 -HttpMethod "GET" -Verbose
    if($Response.status -ieq "success"){
        if($Response.pitrEnabled -ieq $True){
            $result = 'Enabled'
        }else {
            $result = 'Disabled'
        }
    }else{
        throw "[ERROR] Configure PITR web request returned an error."
    }
    
    $result  
}


function Update-PITRState
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $Referer,

        [System.String]
        $PITRState
    )

    $WebParams = @{ 
        f = 'json'
        "enable-pitr" = if ($PITRState -ieq 'Enabled') { "true" }else{ "false" }
    }

    $DataStoreConfigurePITRUrl = $URL.TrimEnd('/') + '/datastoreadmin/configurePITR'
    Wait-ForUrl -Url "$($DataStoreConfigurePITRUrl)?f=json" -MaxWaitTimeInSeconds 180 -SleepTimeInSeconds 5 -HttpMethod 'GET' -Verbose
    $Response = Invoke-ArcGISWebRequest -Url $DataStoreConfigurePITRUrl -HttpFormParameters $WebParams -Referer $Referer -TimeOutSec 600 -Verbose
    if($response.error) {
        Write-Verbose "Error Response - $($response.error | ConvertTo-Json)"
        throw [string]::Format("ERROR: failed. {0}" , $response.error.message)
    }else{
        if($Response.status -ieq "success"){
            Write-Verbose "PITR state changed to $PITRState"
        }else{
            throw "[ERROR] Configure PITR web request returned unknown response $($Response.status)."
        }
    }
}


function Test-DataStoreCertificate
{
    [CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [System.String]
        $CertificateFileLocation,

        [System.String]
        $URL,

        [System.Management.Automation.PSCredential]
        $CertificatePassword
    )

    $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $Cert.Import($CertificateFileLocation, $CertificatePassword.GetNetworkCredential().Password, 32)
    $DataStoreConfigureUrl = $URL.TrimEnd('/') + '/datastoreadmin/configure?f=json'  

    $webRequest = [Net.WebRequest]::Create($DataStoreConfigureUrl)
    $response = $null
    try {
        $response = $webRequest.GetResponse()
    }
    catch {}
    finally {
        if($null -ne $response) {
            $response.Dispose()
        }
    }

    if($null -eq $webRequest.ServicePoint.Certificate) {
        return $false
    }
    
    return $webRequest.ServicePoint.Certificate.GetCertHashString() -ieq $Cert.Thumbprint
}


function Get-DataStoreBackupLocation
{
    [CmdletBinding()]
    param(
        [System.String]
        $DataStoreInstallDirectory,

        [ValidateSet("Relational","TileCache","SpatioTemporal","GraphStore","ObjectStore")]
        [System.String]
        $DataStoreType
    )

    $BackupLocations = [System.Collections.ArrayList]@()
    
    $TypeString = switch ($DataStoreType) {
        "Relational" { "relational" }
        "TileCache" { "tile cache" }
        "GraphStore" { "graph" }
        "ObjectStore" { "object" }
        "SpatioTemporal" { "spatiotemporal" }
        default { throw "Invalid DataStoreType $DataStoreType" }
    }
    
    $locationsString = Invoke-DataStoreConfigureBackupLocationTool -DataStoreInstallDirectory $DataStoreInstallDirectory `
                                                        -DataStoreType $DataStoreType -OperationType "list" -Verbose
    if($locationsString.StartsWith("Backups locations for $($TypeString)")){
        $ConfiguredBackups = $locationsString.Split([System.Environment]::NewLine, [System.StringSplitOptions]::RemoveEmptyEntries)
        for($i = 4; $i -lt $ConfiguredBackups.Length - 1; $i++){ 
            $BackupArray = $ConfiguredBackups[$i].split(" ",[System.StringSplitOptions]::RemoveEmptyEntries)
            $BackupObject = @{
                Name = $BackupArray[0]
                Location = ($BackupArray[2] -replace "\/", "\").TrimEnd("\")
                Type = $BackupArray[1]
                IsDefault = ($BackupArray[3] -eq "true")
            } 
    
            $BackupLocations.Add($BackupObject)
        }
    }
    
    $BackupLocations.ToArray()
}

function Invoke-DataStoreConfigureBackupLocationTool
{
    [CmdletBinding()]
    param(    
        [System.String]
        $BackupLocationString,

        [System.String]
        $RedactedBackupLocationString,

        [System.String]
        $DataStoreInstallDirectory,
        
        [ValidateSet("Relational","TileCache","SpatioTemporal","GraphStore", "ObjectStore")]
        [System.String]
        $DataStoreType,

        [ValidateSet("register","unregister","change","list","setdefault")]
        [System.String]
        $OperationType,

        [switch]
        $ForceUpdate
    )

    $ConfigureBackupToolPath = Join-Path $DataStoreInstallDirectory 'tools\configurebackuplocation.bat'
    if(-not(Test-Path $ConfigureBackupToolPath)){
        throw "$ConfigureBackupToolPath not found"
    }

    $DataStoreTypeAsString = switch ($DataStoreType) {
        "Relational" { "relational" }
        "TileCache" { "tileCache" }
        "GraphStore" { "graph" }
        "ObjectStore" { "object" }
        "SpatioTemporal" { "spatiotemporal" }
        default { throw "Invalid DataStoreType $DataStoreType" }
    }

    $Arguments = "--operation $OperationType --store $DataStoreTypeAsString --prompt no"
    $ArgumentsForLogging = $Arguments
    if($OperationType -ne "list"){
        $Arguments += " --location $BackupLocationString"
        $LocationStringForLogging = if(-not([string]::IsNullOrEmpty($RedactedBackupLocationString))) {
            $RedactedBackupLocationString
        } else {
            $BackupLocationString -replace '(?i)(password=)([^;]+)', '$1xxxxx'
        }
        $ArgumentsForLogging += " --location $LocationStringForLogging"
    }
    if($ForceUpdate){
        $Arguments += " --force true"
        $ArgumentsForLogging += " --force true"
    }
    
    Write-Verbose "Backup Tool:- $ConfigureBackupToolPath $ArgumentsForLogging"
    $op = Invoke-StartProcess -ExecPath $ConfigureBackupToolPath -Arguments $Arguments -EnvVariables @{ "AGSDATASTORE" = $null } -Verbose
    if($op -ccontains 'failed') {
        throw "Configure backup tool failed. Output - $op."
    }
    $op
}

function Test-DataStoreUpgrade
{
    [CmdletBinding()]
    param(
        [System.String]
        $URL,

        [System.String]
        $Referer 
    )

    $result = $true
    $info = Invoke-ArcGISWebRequest -Url "$($URL)/datastoreadmin/configure" -HttpFormParameters @{ f = 'json'}  -Referer $Referer -HttpMethod 'GET' -Verbose 

    if($info.upgrading -and (($info.upgrading -ieq 'outplace') -or ($info.upgrading -ieq 'inplace'))){
        Write-Verbose "Upgrade in progress - $($info.upgrading)"
        $result = $false
    }

    return $result
}

Export-ModuleMember -Function *