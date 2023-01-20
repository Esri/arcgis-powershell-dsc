function Get-FQDN
{    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$MachineName
    )
    if($MachineName -as [ipaddress]){
        $Dns = $MachineName
    }else{
        [bool]$ResolvedDns = $false
        [int]$NumOfDnsResolutionAttempts = 0
        $Dns = $Null
        while((-not $ResolvedDns) -and ($NumOfDnsResolutionAttempts -lt 10))
        {        
            $DnsRecord = $null
            Try {
                if(Get-Command 'Resolve-DnsName' -ErrorAction Ignore) {
                    $DnsRecord = Resolve-DnsName -Name $MachineName -Type ANY -ErrorAction Ignore | Select-Object -First 1
                    if($null -eq $DnsRecord) {
                        $DnsRecord = Resolve-DnsName -Name $MachineName -Type A -ErrorAction Ignore
                    }
                }
                if($null -eq $DnsRecord) {
                    $machine = (Get-CimInstance -Class Win32_ComputerSystem).Name
                    $domain = (Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName $MachineName).DNSDomain
                    $Dns = "$($machine).$($domain)"
                    $ResolvedDns = $true
                }
            }
            Catch {
                Write-Verbose "Error Resolving DNS $($_)"            
            }
            if($null -ne $DnsRecord) {
                [void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.WindowsAzure.ServiceRuntime')
                $UseIP = $false
                if (('Microsoft.WindowsAzure.ServiceRuntime.RoleEnvironment' -as [type]) -and ($null -ne [Microsoft.WindowsAzure.ServiceRuntime.RoleEnvironment]::DeploymentId))
                {
                    $UseIP = $true
                    Write-Verbose "Running on Microsoft Azure Cloud Service VM (Web/Worker) Role. Using IP Address instead of hostnames"
                }
                $Dns = if($UseIP) { $DnsRecord.IPAddress } else { $DnsRecord.Name }
                if($null -ne $Dns -and $Dns.Length -gt 0)
                {
                    $ResolvedDns = $true
                }
                else {
                    Start-Sleep -Seconds 15
                }
            } elseif(-not($ResolvedDns)) {
                Start-Sleep -Seconds 15
            }
            $NumOfDnsResolutionAttempts++
        }
    }
    if(-not $Dns){         
        throw "Unable to resolve DNS for $MachineName"          
    }
    $Dns
}

function Convert-PSObjectToHashtable
{
    param (
        [Parameter(ValueFromPipeline)]
        $InputObject
    )

    process
    {
        if ($null -eq $InputObject) { return $null }

        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string])
        {
            $collection = @(
                foreach ($object in $InputObject) { Convert-PSObjectToHashtable $object }
            )

            Write-Output $collection -NoEnumerate
        }
        elseif ($InputObject -is [psobject])
        {
            $hash = @{}

            foreach ($property in $InputObject.PSObject.Properties)
            {
                $hash[$property.Name] = Convert-PSObjectToHashtable $property.Value
            }

            $hash
        }
        else
        {
            $InputObject
        }
    }
}

Filter timestamp {
    "$(Get-Date -Format G): $_"
}

Function Trace-DSCJob{
    [CmdletBinding()]
    param
    (
        [System.Management.Automation.Job2]
        $Job,

        [System.String]
        $JobName,

        [System.Boolean]
        $DebugMode = $False
    )
    $Done = $false
    $CompletedJobs = New-Object System.Collections.ArrayList
    $PosVerboseMap = @{}
    $PosErrorMap = @{}
    $LogsPath = "$((Get-Item -Path '.\' -Verbose).FullName)\Logs"
    if(!(Test-Path -Path $LogsPath )){
        New-Item -ItemType directory -Path $LogsPath
    }
    while(-not($Done)) {
        if(-Not(($Job.ChildJobs).state -imatch "Running")){
            $Done = $True
        }
        ForEach($j in $Job.ChildJobs){
            $timestamp = (($j.PSBeginTime).toString()).Replace(':','-').Replace('/','-').Replace(' ','-')
            $MachineLogPath = Join-Path $LogsPath $j.Location
            if(!(Test-Path -Path $MachineLogPath)){
                New-Item -ItemType directory -Path $MachineLogPath
            }
            $VerboseLogPath = "$MachineLogPath\$($JobName)-$($timestamp)-Verbose.txt"
            $ErrorLogPath = "$MachineLogPath\$($JobName)-$($timestamp)-Error.txt"

            if(($j.state -imatch "Completed" -or $j.state -imatch "Failed" ) -and -not($CompletedJobs.Contains($j.Name)) ){
                # Add-content $VerboseLogPath -value $j.Verbose
                # if($j.Error){
                #     Add-content $ErrorLogPath -value $j.Error
                # }
                
                $CompletedJobs.add($j.Name)
            }
            $Pos = 0
            if($PosVerboseMap.ContainsKey($j.Name)){
                $Pos = $PosVerboseMap[$j.Name]
            }else{
                $PosVerboseMap.Add($j.Name,$Pos)
            }

            if($Pos -ine $j.Verbose.Count){
                $i = 0  
                foreach($item in $j.Verbose) {
                    if($i -ge $Pos) {
                        $AugmentedVerboseItemWithTimestamp = ($item | timestamp) 
                        if(($item.Message -match "Start  Resource") -or ($item.Message -match "End    Resource")){
                            Write-Host $AugmentedVerboseItemWithTimestamp -foregroundcolor green
                        }else{
                            if($DebugMode -or ($item.Message -match "Start  Test") -or ($item.Message -match "Start  Set") -or ($item.Message -match "End    Test") -or ($item.Message -match "End    Set")){
                                Write-Host $AugmentedVerboseItemWithTimestamp -foregroundcolor yellow
                            }
                        }
                        Add-content $VerboseLogPath -value $AugmentedVerboseItemWithTimestamp
                    }
                    $i++
                }  
                $PosVerboseMap[$j.Name] = $j.Verbose.Count
            }

            $PosError = 0
            if($PosErrorMap.ContainsKey($j.Name)){
                $PosError = $PosErrorMap[$j.Name]
            }else{
                $PosErrorMap.Add($j.Name,$Pos)
            }

            if($PosError -ine $j.Error.Count){
                $i = 0  
                foreach($item in $j.Error) {
                    if($i -ge $PosError) {
                        $AugmentedErrorItemWithTimestamp = ($item | timestamp)
                        Write-Error $AugmentedErrorItemWithTimestamp
                        Add-content $ErrorLogPath -value $AugmentedErrorItemWithTimestamp
                    }
                    $i++
                }  
                $PosErrorMap[$j.Name] = $j.Error.Count
            }
        }
        if(-not($Done)) {                      
            Start-Sleep -Seconds 5
        }
    }

    Write-Information -InformationAction Continue "Logs Directory: $LogsPath"
}

function Invoke-DSCJob {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param(
        [Parameter(Mandatory=$True)]
        [System.String]
        $ConfigurationName,

        [System.String]
        $ConfigurationFolderPath,

        [System.Object]
        $Arguments,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $Credential,
        
        [System.Boolean]
        $DebugMode = $False,

        [System.Boolean]
        $UseWinRMSSL = $False
    )
    
    if(Test-Path ".\$($ConfigurationName)") { Remove-Item ".\$($ConfigurationName)" -Force -ErrorAction Ignore -Recurse }

    Write-Information -InformationAction Continue "Dot Sourcing the Configuration:- $ConfigurationName"
    . "$PSScriptRoot\$($ConfigurationFolderPath)\$($ConfigurationName).ps1" -Verbose:$false

    &$ConfigurationName @Arguments -Verbose
    if(($Arguments.ConfigurationData.AllNodes | Where-Object { $_.Thumbprint -and $_.CertificateFile } | Measure-Object).Count -gt 0){
        Write-Information -InformationAction Continue "Configuring Local Configuration Manager:- $ConfigurationName"
        if($UseWinRMSSL){
            $SessionOptions = New-CimSessionOption -UseSsl
            $EncryptMOFCimSession = New-CimSession -Credential $Credential -SessionOption $SessionOptions -ComputerName $Arguments.ConfigurationData.AllNodes.NodeName
            Set-DscLocalConfigurationManager ".\$($ConfigurationName)" -CimSession $EncryptMOFCimSession -Verbose
        }else{
            Set-DscLocalConfigurationManager ".\$($ConfigurationName)" -Verbose
        }
    }    

    Write-Information -InformationAction Continue "Starting DSC Job:- $ConfigurationName"
    $JobTimer = [System.Diagnostics.Stopwatch]::StartNew()
    $Job = $null
    if($Credential){
        if($UseWinRMSSL){
            $ComputeNameList = @()
            $SessionOptions = New-CimSessionOption -UseSsl
            (Get-ChildItem ".\$($ConfigurationName)\*.mof" -File -exclude @("*.meta.mof") ).Name | ForEach-Object { $ComputeNameList += $_.TrimEnd(".mof") }
            $DeploymentCimSession = New-CimSession -Credential $Credential -SessionOption $sessionOptions -ComputerName $ComputeNameList
            $Job = Start-DscConfiguration -Path ".\$($ConfigurationName)" -Force -Verbose -CimSession $DeploymentCimSession
        }else{
            $Job = Start-DscConfiguration -Path ".\$($ConfigurationName)" -Force -Verbose -Credential $Credential
        }
    }else{
        $Job = Start-DscConfiguration -Path ".\$($ConfigurationName)" -Force -Verbose
    }

    if(Test-Path ".\$($ConfigurationName)") { Remove-Item ".\$($ConfigurationName)" -Force -ErrorAction Ignore -Recurse }

    Trace-DSCJob -Job $Job -JobName $ConfigurationName -DebugMode $DebugMode
    Write-Information -InformationAction Continue "Finished DSC Job:- $ConfigurationName. Time Taken - $($JobTimer.elapsed)"
    Write-Information -InformationAction Continue "$($ConfigurationName) - $($Job.state)"
    $result = if($Job.state -ieq "Completed"){ $True } else{ $False }
    $result 
}

function Invoke-BuildArcGISAzureImage
{
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory=$True)]
        [System.Array]
        $InstallConfigFilePath,

        [Parameter(Mandatory=$false)]
        [System.String]
        $BaseDirectory = "$env:SystemDrive\ArcGIS\Deployment",

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $SkipFilesDownload = $false,

        [Parameter(Mandatory=$false)]
        [ValidateSet("AzureFiles","AzureBlobsManagedIdentity","Default")]
		[System.String]
        $FileSourceType = "Default",

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AFSCredential,

        [Parameter(Mandatory=$false)]
        [System.String]
        $AFSEndpoint,
        
        [switch]
        $DebugSwitch,

        [switch]
        $UseSSL
    )
 
    $DebugMode = if($DebugSwitch){ $true }else{ $False}
    $UseWinRMSSL = if($UseSSL){ $True }else{ $False }

    if(-not(Test-Path $BaseDirectory)) {
        New-Item -Path $BaseDirectory -ItemType 'directory' -Force -ErrorAction Ignore | Out-Null
    }

    $InstallersConfig = ConvertFrom-Json (Get-Content $InstallConfigFilePath -Raw)
    $JobFlag = $False
    if(-not($SkipFilesDownload)){
        $DownloadLocation = Join-Path $BaseDirectory 'Downloads'
        if(-not(Test-Path $DownloadLocation)) {
            New-Item -Path $DownloadLocation -ItemType 'directory' -Force | Out-Null
        }
        $cd = @{
            AllNodes = @(
                @{
                    NodeName = "localhost"
                    PSDscAllowPlainTextPassword = $true
                }
            )
        }

        $DownloadInstallersArgs = @{ 
                                    ConfigurationData = $cd; 
                                    Installers = $InstallersConfig.Installers; 
                                    FileSourceType = $FileSourceType 
                                } 
        if($FileSourceType -ieq "AzureFiles"){
            $DownloadInstallersArgs.AFSCredential = $AFSCredential 
            $DownloadInstallersArgs.AFSEndpoint = $AFSEndpoint 
        }

        $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISDownloadInstallers" -ConfigurationFolderPath "Configurations-AzureImageBuild" -Arguments $DownloadInstallersArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
        if($JobFlag[$JobFlag.Count - 1] -eq $True){
            Write-Information -InformationAction Continue "Downloaded Installer Setups Successfully."
        }
    }else{
        $JobFlag = $True
    }
    
    if($JobFlag[$JobFlag.Count - 1] -eq $True){
        $JobFlag = $False
        $SetupConfigArgs = @{
            Installers = $InstallersConfig.Installers
            WindowsFeatures = $InstallersConfig.WindowsFeatures
        }
        $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISSetupConfiguration" -ConfigurationFolderPath "Configurations-AzureImageBuild" -Arguments $SetupConfigArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
        if($JobFlag[$JobFlag.Count - 1] -eq $True) {
            Write-Information -InformationAction Continue "Installed ArcGIS Setups Successfully. Removing Setup Configuration File."
        }
    }

    $Pro3Installer = ($InstallersConfig.Installers | Where-Object { $_.Name -ieq "ArcGIS Pro" -and $_.Version -ieq "3.0" })
    if(($Pro3Installer | Measure-Object).Count -gt 0)
    {
        $Path = $ExecutionContext.InvokeCommand.ExpandString($Pro3Installer.LocalPath)
        $TempFolder = Join-Path ([System.IO.Path]::GetTempPath()) "Pro3Installer"
        New-Item $TempFolder -ItemType directory            
            
        
        Write-Host "Extracting $Path to $TempFolder"
        $SetupExtractProc = (Start-Process -FilePath $Path -ArgumentList "/s /d $TempFolder" -Wait -NoNewWindow  -Verbose -PassThru)
        if($SetupExtractProc.ExitCode -ne 0){
            throw "Error while extracting setup for 'ArcGIS Pro' at Path '$Path' :- exited with status code $($SetupExtractProc.ExitCode)"
        }else{
            Write-Host 'Done Extracting. Waiting 15 seconds to allow the extractor to close files'
        }
        
        $SetupExe = Get-ChildItem -Path $TempFolder -Filter '*.msi' -Recurse | Select-Object -First 1
        $ExecPath = $SetupExe.FullName
        if(-not($ExecPath) -or (-not(Test-Path $ExecPath))) {
            throw "Neither .exe nor .msi found in extracted contents to install"
        } 
        
        $Pro3InstallArgs = $ExecutionContext.InvokeCommand.ExpandString($Pro3Installer.Arguments)
        $Arguments = "/i `"$ExecPath`" $Pro3InstallArgs"
        $ExecPath = "msiexec"
        
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $ExecPath
        $psi.Arguments = $Arguments
        $psi.UseShellExecute = $false #start the process from it's own executable file    
        $psi.RedirectStandardOutput = $true #enable the process to read from standard output
        $psi.RedirectStandardError = $true #enable the process to read from standard error 
        $p = [System.Diagnostics.Process]::Start($psi)
        $p.WaitForExit()
        $op = $p.StandardOutput.ReadToEnd()
        if($op -and $op.Length -gt 0) {
            Write-Host "Output of execution:- $op"
        }
        $err = $p.StandardError.ReadToEnd()
        if($err -and $err.Length -gt 0) {
            Write-Host $err
        }
        if($p.ExitCode -eq 0) {                    
            Write-Host "Pro Install process finished successfully."
        }else {
            throw "Install failed. Process exit code:- $($p.ExitCode). Error - $err"
        }
    }
    
}

function Invoke-CreateNodeToAdd
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    Param(
        $Node,

        [System.String]
        $TargetComponent,

        [System.String]
        $DataStoreType,

        [System.String]
        $ServerContext,

        [System.String]
        $PortalContext,

        [System.Boolean]
        $WebAdaptorAdminAccessEnabled
    )

    $NodeToAdd = @{ NodeName = $Node.NodeName }
                                
    if($Node.TargetNodeEncryptionCertificateFilePath -and $Node.TargetNodeEncryptionCertificateThumbprint){
        $NodeToAdd["CertificateFile"] = $Node.TargetNodeEncryptionCertificateFilePath
        $NodeToAdd["Thumbprint"] = $Node.TargetNodeEncryptionCertificateThumbprint
    }else{
        $NodeToAdd["PSDscAllowPlainTextPassword"] = $true
    }

    if($Node.SslCertificates -and (($Node.SslCertificates | Where-Object { $_.Target -icontains  $TargetComponent }  | Measure-Object).Count -gt 0) ){
        $SSLCertificate = ($Node.SslCertificates | Where-Object { $_.Target -icontains $TargetComponent }  | Select-Object -First 1)

        if($SSLCertificate.CNameFQDN -and $SSLCertificate.Path){
            $Certificate = @{
                CName = if($SSLCertificate.CNameFQDN){ $SSLCertificate.CNameFQDN }else{ $null }
                Path = if($SSLCertificate.Path){ $SSLCertificate.Path }else{ $null }
                Password = $null
            }

            if($SSLCertificate.Password -or $SSLCertificate.PasswordFilePath){
                $SSLPassword = if($SSLCertificate.PasswordFilePath){ Get-Content $SSLCertificate.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $SSLCertificate.Password -AsPlainText -Force }
                $Certificate["Password"] = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("SSLCertPlaceholder",$SSLPassword)
            }
            $NodeToAdd["SSLCertificate"] = $Certificate
        }

        if(($TargetComponent -ieq "Server" -or $TargetComponent -ieq "Portal") -and $SSLCertificate.SslRootOrIntermediate){
            $NodeToAdd["SslRootOrIntermediate"] = ($SSLCertificate.SslRootOrIntermediate | ConvertTo-Json)
        }
    }    

    if($TargetComponent -ieq "DataStore" -and -not([string]::IsNullOrEmpty($DataStoreType))){ 
        $NodeToAdd.add("DataStoreTypes", @($DataStoreType))
    }

    if($TargetComponent -ieq "WebAdaptor"){
        if($Node.Role -icontains 'ServerWebAdaptor'){
            $NodeToAdd["IsServerWebAdaptorEnabled"] = $True
            $NodeToAdd["ServerContext"] = if($Node.ServerContext){ $Node.ServerContext }else{ $ServerContext }
            $NodeToAdd["AdminAccessEnabled"] = if($Node.AdminAccessEnabled){ $Node.AdminAccessEnabled }else{ $WebAdaptorAdminAccessEnabled }
        }
        if($Node.Role -icontains 'PortalWebAdaptor'){
            $NodeToAdd["IsPortalWebAdaptorEnabled"] = $True
            $NodeToAdd["PortalContext"] = $PortalContext
        }
    }

    $NodeToAdd
}

function Get-DownloadsInstallsConfigurationData
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    Param(
        $ConfigurationParamsJSON
    )
    $InstallConfigurationParamsHashtable = Convert-PSObjectToHashtable $ConfigurationParamsJSON
    $ConfigData = @{
        AllNodes = @() 
        ConfigData = $InstallConfigurationParamsHashtable.ConfigData
    }

    for ( $i = 0; $i -lt $InstallConfigurationParamsHashtable.AllNodes.Count; $i++ ){
        $Node = $InstallConfigurationParamsHashtable.AllNodes[$i]
        $NodeToAdd = @{ NodeName = $Node.NodeName; Role = $Node.Role }
        if($Node.TargetNodeEncryptionCertificateFilePath -and $Node.TargetNodeEncryptionCertificateThumbprint){
            $NodeToAdd["CertificateFile"] = $Node.TargetNodeEncryptionCertificateFilePath
            $NodeToAdd["Thumbprint"] = $Node.TargetNodeEncryptionCertificateThumbprint
        }else{
            $NodeToAdd["PSDscAllowPlainTextPassword"] = $true
        }
        if($Node.Role -icontains 'ServerWebAdaptor'){
            $NodeToAdd["ServerContext"] = if($Node.ServerContext){ $Node.ServerContext }else{ $InstallConfigurationParamsHashtable.ConfigData.ServerContext }
        }
        if($Node.Role -icontains 'DataStore'){
            $NodeToAdd["DataStoreTypes"] = $Node.DataStoreTypes 
        }
        $ConfigData.AllNodes += $NodeToAdd
    }

    if($ConfigData.ConfigData.Credentials){
        $ConfigData.ConfigData.Remove("Credentials")
    }
    if($ConfigData.ConfigData.SslRootOrIntermediate){
        $ConfigData.ConfigData.Remove("SslRootOrIntermediate")
    }
    if($ConfigData.ConfigData.FileShareLocalPath -and ($Mode -ne "Uninstall")){
        $ConfigData.ConfigData.Remove("FileShareLocalPath")
    }
    if($ConfigData.ConfigData.FileShareName -and ($Mode -ne "Uninstall")){
        $ConfigData.ConfigData.Remove("FileShareName")
    }
    if($ConfigData.ConfigData.Server){
        if($ConfigData.ConfigData.Server.LicenseFilePath){
            $ConfigData.ConfigData.Server.Remove("LicenseFilePath")
        }
        if($ConfigData.ConfigData.Server.LicensePassword){
            $ConfigData.ConfigData.Server.Remove("LicensePassword")
        }
        if($ConfigData.ConfigData.Server.ServerDirectoriesRootLocation){
            $ConfigData.ConfigData.Server.Remove("ServerDirectoriesRootLocation")
        }
        if($ConfigData.ConfigData.Server.ServerLogsLocation){
            $ConfigData.ConfigData.Server.Remove("ServerLogLocations")
        }
        if($ConfigData.ConfigData.Server.LocalRepositoryPath){
            $ConfigData.ConfigData.Server.Remove("LocalRepositoryPath")
        }
        if($ConfigData.ConfigData.Server.ServerDirectories){
            $ConfigData.ConfigData.Server.Remove("ServerDirectories")
        }
        if($ConfigData.ConfigData.Server.ConfigStoreLocation){
            $ConfigData.ConfigData.Server.Remove("ConfigStoreLocation")
        }
    }
    if($ConfigData.ConfigData.GeoEventServer){
        if($ConfigData.ConfigData.GeoEventServer.LicenseFilePath){
            $ConfigData.ConfigData.GeoEventServer.Remove("LicenseFilePath")
        }
        if($ConfigData.ConfigData.GeoEventServer.LicensePassword){
            $ConfigData.ConfigData.GeoEventServer.Remove("LicensePassword")
        }
    }
    if($ConfigData.ConfigData.WorkflowManagerServer){
        if($ConfigData.ConfigData.WorkflowManagerServer.LicenseFilePath){
            $ConfigData.ConfigData.WorkflowManagerServer.Remove("LicenseFilePath")
        }
        if($ConfigData.ConfigData.WorkflowManagerServer.LicensePassword){
            $ConfigData.ConfigData.WorkflowManagerServer.Remove("LicensePassword")
        }
    }
    if($ConfigData.ConfigData.Portal){
        if($ConfigData.ConfigData.Portal.LicenseFilePath){
            $ConfigData.ConfigData.Portal.Remove("LicenseFilePath")
        }
        if($ConfigData.ConfigData.Portal.LicensePassword){
            $ConfigData.ConfigData.Portal.Remove("LicensePassword")
        }
        if($ConfigData.ConfigData.Portal.PortalLicenseUserTypeId){
            $ConfigData.ConfigData.Portal.Remove("PortalLicenseUserTypeId")
        }
        if($ConfigData.ConfigData.Portal.ContentDirectoryLocation){
            $ConfigData.ConfigData.Portal.Remove("ContentDirectoryLocation")
        }
    }
    if($ConfigData.ConfigData.DataStore -and $ConfigData.ConfigData.DataStore.ContentDirectoryLocation){
        $ConfigData.ConfigData.DataStore.Remove("ContentDirectoryLocation")
    }
    if($ConfigData.ConfigData.WebAdaptor -and $ConfigData.ConfigData.WebAdaptor.AdminAccessEnabled){
        $ConfigData.ConfigData.WebAdaptor.Remove("AdminAccessEnabled")
    }
    if($ConfigData.ConfigData.Pro -and $ConfigData.ConfigData.Pro.LicenseFilePath){
        $ConfigData.ConfigData.Pro.Remove("LicenseFilePath")
    }
    if($ConfigData.ConfigData.Desktop -and $ConfigData.ConfigData.Desktop.LicenseFilePath){
        $ConfigData.ConfigData.Desktop.Remove("LicenseFilePath")
    }

    return $ConfigData
}

function Invoke-ArcGISConfiguration
{
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory=$True)]
        [System.Array]
        $ConfigurationParametersFile,    

        [ValidateSet("Install","InstallLicense","InstallLicenseConfigure","Uninstall","Upgrade")]
        [Parameter(Position = 1)]
        [System.String]
        $Mode = 'InstallLicenseConfigure',

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $Credential,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $MappedDriveOverrideFlag = $false,
        
        [switch]
        $DebugSwitch,

        [switch]
        $EnableMSILogging,

        [switch]
        $UseSSL
    )
    
    $DebugMode = if($DebugSwitch){ $True }else{ $False } 
    $UseWinRMSSL = if($UseSSL){ $True }else{ $False }
    $EnableMSILoggingMode = if($EnableMSILogging){ $True }else{ $False } 

    if(@("Install","InstallLicense","InstallLicenseConfigure","Uninstall") -icontains $Mode){
        $ConfigurationParamsJSON = $null
        Foreach($cf in $ConfigurationParametersFile){
            if(-not($ConfigurationParamsJSON)){
                $ConfigurationParamsJSON = (ConvertFrom-Json (Get-Content $cf -Raw))
            }
        }
        $ConfigurationParamsHashtable = Convert-PSObjectToHashtable $ConfigurationParamsJSON

        $EnterpriseVersion = $null
        $EnterpriseVersionArray = $null
        if($ConfigurationParamsHashtable.ConfigData.Version){
            $EnterpriseVersion = $ConfigurationParamsHashtable.ConfigData.Version
            $EnterpriseVersionArray = $EnterpriseVersion.Split(".")
            if(-not(($EnterpriseVersionArray[0] -eq 10 -and $EnterpriseVersionArray[1] -ge 7) -or $EnterpriseVersionArray[0] -eq 11)){
                throw "[ERROR] DSC Module only supports ArcGIS Enterprise 10.7.x and later versions."
            }
        }

        $ServiceCredential = $null
        $ServiceCredentialIsDomainAccount = $False
        $ServiceCredentialIsMSA = $False
        $ForceServiceCredentialUpdate = $False
        if($ConfigurationParamsHashtable.ConfigData.Credentials.ServiceAccount){
            $ServiceCredentialIsDomainAccount = if($ConfigurationParamsHashtable.ConfigData.Credentials.ServiceAccount.IsDomainAccount){$ConfigurationParamsHashtable.ConfigData.Credentials.ServiceAccount.IsDomainAccount}else{$False}
            $ServiceCredentialIsMSA = if($ConfigurationParamsHashtable.ConfigData.Credentials.ServiceAccount.IsMSAAccount){$ConfigurationParamsHashtable.ConfigData.Credentials.ServiceAccount.IsMSAAccount}else{$False}
            $ForceServiceCredentialUpdate = if($ConfigurationParamsHashtable.ConfigData.Credentials.ServiceAccount.ForceUpdate){$ConfigurationParamsHashtable.ConfigData.Credentials.ServiceAccount.ForceUpdate}else{$False}
            $SAPassword = ConvertTo-SecureString "PlaceHolder" -AsPlainText -Force
            if(-not($ServiceCredentialIsMSA)){
                $SAPassword = if( $ConfigurationParamsHashtable.ConfigData.Credentials.ServiceAccount.PasswordFilePath ){ Get-Content $ConfigurationParamsHashtable.ConfigData.Credentials.ServiceAccount.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.Credentials.ServiceAccount.Password -AsPlainText -Force }
            }
            $ServiceCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $ConfigurationParamsHashtable.ConfigData.Credentials.ServiceAccount.UserName, $SAPassword )
        }

        $InstallCD = Get-DownloadsInstallsConfigurationData -ConfigurationParamsJSON $ConfigurationParamsJSON

        if($Mode -ine "Uninstall" -and $InstallCD.ConfigData.DownloadSetups){
            $AGOPassword = if( $ConfigurationParamsHashtable.ConfigData.Credentials.AGOCredential.PasswordFilePath ){ Get-Content $ConfigurationParamsHashtable.ConfigData.Credentials.AGOCredential.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.Credentials.AGOCredential.Password -AsPlainText -Force }
            $AGOCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $ConfigurationParamsHashtable.ConfigData.Credentials.AGOCredential.UserName, $AGOPassword )
            $DownloadSetupsArgs = @{
                ConfigurationData = $InstallCD
                AGOCredential = $AGOCredential
            }
            $ConfigurationName = "ArcGISDownloads"
            $JobFlag = Invoke-DSCJob -ConfigurationName $ConfigurationName -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $DownloadSetupsArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
            if($JobFlag[$JobFlag.Count - 1] -ne $True){
                throw "Setup Downloads failed" 
            }
        }

        $InstallArgs = @{
            ConfigurationData = $InstallCD
            ServiceCredential = $ServiceCredential
            ServiceCredentialIsDomainAccount = $ServiceCredentialIsDomainAccount
            ServiceCredentialIsMSA = $ServiceCredentialIsMSA
        }
        
        if(-not($Mode -ieq "Uninstall")){
            $InstallArgs["EnableMSILogging"] = $EnableMSILoggingMode
        }

        $ConfigurationName = if($Mode -ieq "Uninstall"){ "ArcGISUninstall" }else{ "ArcGISInstall" }
        
        $JobFlag = Invoke-DSCJob -ConfigurationName $ConfigurationName -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $InstallArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode

        #License Deployment
        if($JobFlag[$JobFlag.Count - 1] -eq $True -and ($Mode -ieq "InstallLicense" -or $Mode -ieq "InstallLicenseConfigure")){
            $JobFlag = $False
            
            $ServerCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'Server' } | Measure-Object).Count -gt 0)
            $PortalCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'Portal' } | Measure-Object).Count -gt 0)
            $DesktopCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'Desktop' }  | Measure-Object).Count -gt 0)
            $ProCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'Pro' }  | Measure-Object).Count -gt 0)
            $LicenseManagerCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'LicenseManager' } | Measure-Object).Count -gt 0)
            
            $EnterpriseSkipLicenseStep = $true
            if($null -ne $EnterpriseVersionArray -and ($ServerCheck -or $PortalCheck)){
                $EnterpriseSkipLicenseStep = $false
                if(-not($ServerCheck) -and $PortalCheck){
                    $EnterpriseSkipLicenseStep = $true
                }
            }

            $DesktopSkipLicenseStep = $true
            if($ConfigurationParamsHashtable.ConfigData.DesktopVersion -and $DesktopCheck){
                $DesktopSkipLicenseStep = $false
                if($ConfigurationParamsHashtable.ConfigData.Desktop.AuthorizationType -ieq "Float" -and -not($LicenseManagerCheck)){
                    $DesktopSkipLicenseStep = $true
                }
            }

            $ProSkipLicenseStep = $true
            if($ConfigurationParamsHashtable.ConfigData.ProVersion -and $ProCheck){
                $ProSkipLicenseStep = $false
                if(($ConfigurationParamsHashtable.ConfigData.Pro.AuthorizationType -ieq "NAMED_USER") -or 
                ($ConfigurationParamsHashtable.ConfigData.Pro.AuthorizationType -ieq "CONCURRENT_USE" -and -not($LicenseManagerCheck))){
                    $ProSkipLicenseStep = $true
                }
            }
            $LicenseManagerSkipLicenseStep = $true
            if($ConfigurationParamsHashtable.ConfigData.LicenseManagerVersion -and $LicenseManagerCheck -and $ConfigurationParamsHashtable.ConfigData.LicenseManager.LicenseFilePath){
                $LicenseManagerSkipLicenseStep = $false
            }

            if(-not($EnterpriseSkipLicenseStep -and $DesktopSkipLicenseStep -and $ProSkipLicenseStep -and $LicenseManagerSkipLicenseStep)){
                $LicenseCD = @{
                    AllNodes = @() 
                }

                for ( $i = 0; $i -lt $ConfigurationParamsHashtable.AllNodes.count; $i++ ){
                    $Node = $ConfigurationParamsHashtable.AllNodes[$i]
                    $NodeToAdd = @{
                        NodeName = $Node.NodeName;
                        Role = @()
                    }
                    
                    if($Node.TargetNodeEncryptionCertificateFilePath -and $Node.TargetNodeEncryptionCertificateThumbprint){
                        $NodeToAdd["CertificateFile"] = $Node.TargetNodeEncryptionCertificateFilePath
                        $NodeToAdd["Thumbprint"] = $Node.TargetNodeEncryptionCertificateThumbprint
                    }else{
                        $NodeToAdd["PSDscAllowPlainTextPassword"] = $true
                    }
                    
                    $Role = @()
                    if($Node.Role -icontains "Server"){
                        $ServerRole = $null
                        $NodeToAdd.Role += "Server"

                        if($ConfigurationParamsHashtable.ConfigData.ServerRole){   
                            $ServerRole = $ConfigurationParamsHashtable.ConfigData.ServerRole
                            if($ServerRole -ieq "RasterAnalytics" -or $ServerRole -ieq "ImageHosting"){
                                $ServerRole = "ImageServer"
                            }
                        }else{
                            $ServerRole = "GeneralPurposeServer"
                        }
                        $NodeToAdd["ServerRole"] = $ServerRole

                        #Will ignore additional roles if primary role of server is anything else than GeneralPurposeServer
                        if($ServerRole -ieq "GeneralPurposeServer" -and $ConfigurationParamsHashtable.ConfigData.AdditionalServerRoles){
                            $AdditionalServerRoles = @()
                            foreach($AdditionalRole in $ConfigurationParamsHashtable.ConfigData.AdditionalServerRoles){
                                if($AdditionalRole -ieq "RasterAnalytics" -or $AdditionalRole -ieq "ImageHosting"){
                                    $AdditionalServerRoles += "ImageServer"
                                }else{
                                    $AdditionalServerRoles += $AdditionalRole
                                }
                            }
                            $NodeToAdd["AdditionalServerRoles"] = $AdditionalServerRoles
                        }

                        if($ServerRole -ine "GeoEvent" -and  $ServerRole -ine "WorkflowManagerServer"){
                            $ServerLicenseFilePath = $ConfigurationParamsHashtable.ConfigData.Server.LicenseFilePath
                            $ServerLicensePassword = $null
                            if($ConfigurationParamsHashtable.ConfigData.Server.LicensePasswordFilePath){
                                $ServerLicensePassword = (Get-Content $ConfigurationParamsHashtable.ConfigData.Server.LicensePasswordFilePath | ConvertTo-SecureString )
                            }elseif($ConfigurationParamsHashtable.ConfigData.Server.LicensePassword){
                                $ServerLicensePassword = (ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.Server.LicensePassword -AsPlainText -Force)
                            }

                            if($Node.ServerLicenseFilePath)
                            {
                                $ServerLicenseFilePath = $Node.ServerLicenseFilePath
                                $ServerLicensePassword = $null
                                if($Node.ServerLicensePasswordFilePath){
                                    $ServerLicensePassword = (Get-Content $Node.ServerLicensePasswordFilePath | ConvertTo-SecureString )
                                }elseif($Node.ServerLicensePassword){
                                    $ServerLicensePassword = (ConvertTo-SecureString $Node.ServerLicensePassword -AsPlainText -Force)
                                }
                            }
                            
                            $NodeToAdd["ServerLicenseFilePath"] = $ServerLicenseFilePath
                            if($null -ne $ServerLicensePassword){
                                $NodeToAdd["ServerLicensePassword"] = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("PlaceHolder", $ServerLicensePassword)
                            }
                        }

                        if(($ServerRole -ieq "GeoEvent" -or ($ServerRole -ieq "GeneralPurposeServer" -and $ConfigurationParamsHashtable.ConfigData.AdditionalServerRoles -icontains "GeoEvent")) -and $ConfigurationParamsHashtable.ConfigData.GeoEventServer){
                            $GeoeventServerLicenseFilePath =  $ConfigurationParamsHashtable.ConfigData.GeoEventServer.LicenseFilePath
                            $GeoeventServerLicensePassword = $null
                            if($ConfigurationParamsHashtable.ConfigData.GeoEventServer.LicensePasswordFilePath){
                                $GeoeventServerLicensePassword = (Get-Content $ConfigurationParamsHashtable.ConfigData.GeoEventServer.LicensePasswordFilePath | ConvertTo-SecureString )
                            }elseif($ConfigurationParamsHashtable.ConfigData.GeoEventServer.LicensePassword){
                                $GeoeventServerLicensePassword = (ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.GeoEventServer.LicensePassword -AsPlainText -Force)
                            }

                            # Per Node - Geoevent
                            if($Node.GeoeventServerLicenseFilePath)
                            {
                                $GeoeventServerLicenseFilePath = $Node.GeoeventServerLicenseFilePath
                                $GeoeventServerLicensePassword = $null
                                if($Node.GeoeventServerLicensePasswordFilePath){
                                    $GeoeventServerLicensePassword = (Get-Content $Node.GeoeventServerLicensePasswordFilePath | ConvertTo-SecureString )
                                }elseif($Node.ServerLicensePassword){
                                    $GeoeventServerLicensePassword = (ConvertTo-SecureString $Node.GeoeventServerLicensePassword -AsPlainText -Force)
                                }
                            }

                            $NodeToAdd["GeoeventServerLicenseFilePath"] = $GeoeventServerLicenseFilePath
                            if($null -ne $GeoeventServerLicensePassword){
                                $NodeToAdd["GeoeventServerLicensePassword"] = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("PlaceHolder", $GeoeventServerLicensePassword)
                            }
                        }

                        if(($ServerRole -ieq "WorkflowManagerServer" -or ($ServerRole -ieq "GeneralPurposeServer" -and $ConfigurationParamsHashtable.ConfigData.AdditionalServerRoles -icontains "WorkflowManagerServer")) -and $ConfigurationParamsHashtable.ConfigData.WorkflowManagerServer){
                            $WorkflowManagerServerLicenseFilePath =  $ConfigurationParamsHashtable.ConfigData.WorkflowManagerServer.LicenseFilePath
                            $WorkflowManagerServerLicensePassword = $null
                            if($ConfigurationParamsHashtable.ConfigData.WorkflowManagerServer.LicensePasswordFilePath){
                                $WorkflowManagerServerLicensePassword = (Get-Content $ConfigurationParamsHashtable.ConfigData.WorkflowManagerServer.LicensePasswordFilePath | ConvertTo-SecureString )
                            }elseif($ConfigurationParamsHashtable.ConfigData.WorkflowManagerServer.LicensePassword){
                                $WorkflowManagerServerLicensePassword = (ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.WorkflowManagerServer.LicensePassword -AsPlainText -Force)
                            }

                            # Per Node - WorkflowManager
                            if($Node.WorkflowManagerServerLicenseFilePath)
                            {
                                $WorkflowManagerServerLicenseFilePath = $Node.WorkflowManagerServerLicenseFilePath
                                $WorkflowManagerServerLicensePassword = $null
                                if($Node.WorkflowManagerServerLicensePasswordFilePath){
                                    $WorkflowManagerServerLicensePassword = (Get-Content $Node.WorkflowManagerServerLicensePasswordFilePath | ConvertTo-SecureString )
                                }elseif($Node.ServerLicensePassword){
                                    $WorkflowManagerServerLicensePassword = (ConvertTo-SecureString $Node.WorkflowManagerServerLicensePassword -AsPlainText -Force)
                                }
                            }

                            $NodeToAdd["WorkflowManagerServerLicenseFilePath"] = $WorkflowManagerServerLicenseFilePath
                            if($null -ne $WorkflowManagerServerLicensePassword){
                                $NodeToAdd["WorkflowManagerServerLicensePassword"] = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("PlaceHolder", $WorkflowManagerServerLicensePassword)
                            }
                        }
                    }
                    if($Node.Role -icontains "Desktop"){
                        if($ConfigurationParamsHashtable.ConfigData.Desktop.SeatPreference -ieq "Fixed"){
                            $NodeToAdd.Role += "Desktop"
                            $NodeToAdd["DesktopLicenseFilePath"] = $ConfigurationParamsHashtable.ConfigData.Desktop.LicenseFilePath
                        }
                    }
                    if($Node.Role -icontains "Pro"){
                        if($ConfigurationParamsHashtable.ConfigData.Pro.AuthorizationType -ieq "SINGLE_USE"){
                            $NodeToAdd.Role += "Pro"
                            $NodeToAdd["ProLicenseFilePath"] = $ConfigurationParamsHashtable.ConfigData.Pro.LicenseFilePath
                        }
                    }
                    if($Node.Role -icontains "LicenseManager"){
                        $NodeToAdd.Role += "LicenseManager"
                        if($ConfigurationParamsHashtable.ConfigData.LicenseManager -and $ConfigurationParamsHashtable.ConfigData.LicenseManager.LicenseFilePath){
                            $NodeToAdd["LicenseManagerLicenseFilePath"] = $ConfigurationParamsHashtable.ConfigData.LicenseManager.LicenseFilePath
                            $NodeToAdd["LicenseManagerVersion"] = $ConfigurationParamsHashtable.ConfigData.LicenseManagerVersion
                        }
                    }
                    if($NodeToAdd.Role.Count -gt 0){
                        $LicenseCD.AllNodes += $NodeToAdd
                    }
                }
                $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISLicense" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments @{ ConfigurationData = $LicenseCD; ForceLicenseUpdate = if($ConfigurationParamsHashtable.ConfigData.ForceLicenseUpdate){$ConfigurationParamsHashtable.ConfigData.ForceLicenseUpdate }else{ $False } } -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
            }else{
                $JobFlag = $True
            }

            #Configure Deployment
            $SkipConfigureStep = $False
            if(($DesktopCheck -or $ProCheck -or $LicenseManagerCheck) -and -not($ServerCheck -or $PortalCheck)){
                $SkipConfigureStep = $True
            }

            if($JobFlag[$JobFlag.Count - 1] -eq $True -and ($Mode -ieq "InstallLicenseConfigure") -and -not($SkipConfigureStep)){
                $ValidatePortalFileShare = $false
                if($ConfigurationParamsHashtable.ConfigData.Portal){
                    $IsHAPortal = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'Portal' }  | Measure-Object).Count -gt 1)
                    if($IsHAPortal) {
                        if($MappedDriveOverrideFlag) {
                            $ValidatePortalFileShare = $True
                        } else {
                            if($ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount){
                                $ValidatePortalFileShare = $True
                            }else{
                                if($ConfigurationParamsHashtable.ConfigData.Portal.ContentDirectoryLocation.StartsWith('\')) { 
                                    $ValidatePortalFileShare = $True
                                } else {
                                    throw "Config Directory Location path is not a fileshare path"
                                }
                            }
                        }
                    } else {
                        $ValidatePortalFileShare = $True 
                    }
                } else {
                    $ValidatePortalFileShare = $True   
                }

                $ValidateServerFileShare = $false
                $IsHAServer = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'Server' }  | Measure-Object).Count -gt 1)
                if($IsHAServer) {
                    if($MappedDriveOverrideFlag){
                        $ValidateServerFileShare = $True
                    }else{
                        if($ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount){
                            $ValidateServerFileShare = $True
                        }else{
                            if($ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreLocation.StartsWith('\')){
                                $ValidateServerFileShare = $True
                            }else{
                                throw "Config Store Location is not a fileshare path"
                            }
                        }

                        $ValidateServerFileShare = $False
                        if($ConfigurationParamsHashtable.ConfigData.Server.ServerDirectoriesCloudStorageAccount){
                            if($ConfigurationParamsHashtable.ConfigData.Server.ServerDirectoriesCloudStorageAccount.CloudStorageType -ieq "AzureFiles"){
                                $ValidateServerFileShare = $True
                            }else{
                                throw "Unsupported cloud storage account for server directories"
                            }
                        }else{
                            if($ConfigurationParamsHashtable.ConfigData.Server.ServerDirectoriesRootLocation.StartsWith('\')){
                                if($ConfigurationParamsHashtable.ConfigData.Server.ServerDirectories){
                                    foreach($dir in $ConfigurationParamsHashtable.ConfigData.Server.ServerDirectories){
                                        if(-not($dir.physicalPath.StartsWith('\'))){
                                            throw "One or more of Server Directories Location is not a fileshare path"
                                        }
                                    }
                                }
                                $ValidateServerFileShare = $True
                            } else {
                                throw "Server Directories Root Location is not a fileshare path"
                            }
                        }
                    }
                } else {
                    $ValidateServerFileShare = $True 
                }

                if($ValidateServerFileShare -and $ValidatePortalFileShare){
                    $FileShareCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'FileShare'} | Measure-Object).Count -gt 0)
                    $DataStoreCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'DataStore' } | Measure-Object).Count -gt 0)
                    $RelationalDataStoreCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'DataStore' -and $_.DataStoreTypes -icontains "Relational" } | Measure-Object).Count -gt 0)
                    $BigDataStoreCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'DataStore' -and $_.DataStoreTypes -icontains "SpatioTemporal" } | Measure-Object).Count -gt 0)
                    $TileCacheDataStoreCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'DataStore' -and $_.DataStoreTypes -icontains "TileCache"} | Measure-Object).Count -gt 0)
                    $GraphDataStoreCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'DataStore' -and $_.DataStoreTypes -icontains "GraphStore"} | Measure-Object).Count -gt 0)
                    $ObjectDataStoreCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'DataStore' -and $_.DataStoreTypes -icontains "ObjectStore"} | Measure-Object).Count -gt 0)

                    $RasterDataStoreItemCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'RasterDataStoreItem' } | Measure-Object).Count -gt 0)
                    $WebAdaptorCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'ServerWebAdaptor' -or $_.Role -icontains 'PortalWebAdaptor' } | Measure-Object).Count -gt 0)
                    
                    $ServerPrimarySiteAdminCredential = $null 
                    if($ConfigurationParamsHashtable.ConfigData.Server.PrimarySiteAdmin){
                        $ServerPrimarySiteAdminPassword = if( $ConfigurationParamsHashtable.ConfigData.Server.PrimarySiteAdmin.PasswordFilePath ){ Get-Content $ConfigurationParamsHashtable.ConfigData.Server.PrimarySiteAdmin.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.Server.PrimarySiteAdmin.Password -AsPlainText -Force }
                        $ServerPrimarySiteAdminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $ConfigurationParamsHashtable.ConfigData.Server.PrimarySiteAdmin.UserName, $ServerPrimarySiteAdminPassword )
                    }

                    $PortalAdministratorCredential = $null 
                    if($ConfigurationParamsHashtable.ConfigData.Portal.PortalAdministrator){
                        $PortalAdministratorPassword = if($ConfigurationParamsHashtable.ConfigData.Portal.PortalAdministrator.PasswordFilePath ){ Get-Content $ConfigurationParamsHashtable.ConfigData.Portal.PortalAdministrator.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.Portal.PortalAdministrator.Password -AsPlainText -Force }
                        $PortalAdministratorCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $ConfigurationParamsHashtable.ConfigData.Portal.PortalAdministrator.UserName, $PortalAdministratorPassword )
                    }
                    
                    $PrimaryServerMachine = $null
                    $PrimaryPortalMachine = $null
                    $PrimaryDataStore = $null
                    $PrimaryBigDataStore = $null
                    $PrimaryGraphDataStore = $null
                    $PrimaryObjectDataStore = $null
                    $PrimaryTileCache = $null
                    $FileShareMachine = $null

                    $PortalWAExternalHostName = $null
                    $ServerWAExternalHostName = $null

                    $IsServerWAOnSeparateMachine = $False

                    $FileShareCD = @{ AllNodes = @() }
                    $ServerCD =@{ AllNodes = @() }
                    $PortalCD = @{ AllNodes = @() }
                    $WebAdaptorCD = @{ AllNodes = @() }
                    $RelationalDataStoreCD = @{ AllNodes = @() }
                    $BigDataStoreCD = @{ AllNodes = @() }
                    $TileCacheDataStoreCD = @{ AllNodes = @() }
                    $GraphDataStoreCD = @{ AllNodes = @() }
                    $ObjectDataStoreCD = @{ AllNodes = @() }
                    
                    $DataStoreCertificateUpdateCD = @{ AllNodes = @() }

                    $RasterDataStoreItemCD = @{ AllNodes = @() }

                    $PortalWAMachines = @()
                    $ServerWAMachines = @()

                    for ( $i = 0; $i -lt $ConfigurationParamsHashtable.AllNodes.count; $i++ ){
                        $Node = $ConfigurationParamsHashtable.AllNodes[$i]
                        $NodeName = $Node.NodeName
                        
                        if($Node.Role -icontains 'FileShare'){
                            $FileShareNodeToAdd = (Invoke-CreateNodeToAdd -Node $Node -TargetComponent 'FileShare')
                            $FileShareCD.AllNodes += $FileShareNodeToAdd
                            if($null -eq $FileShareMachine){ $FileShareMachine = $FileShareNodeToAdd }
                        }
                        if($Node.Role -icontains 'RasterDataStoreItem'){
                            $RasterDataStoreItemCD.AllNodes += (Invoke-CreateNodeToAdd -Node $Node -TargetComponent 'RasterDataStoreItem')
                        }
                        if($Node.Role -icontains 'Server') {
                            $ServerNodeToAdd = (Invoke-CreateNodeToAdd -Node $Node -TargetComponent 'Server')
                            $ServerCD.AllNodes += $ServerNodeToAdd
                            if($null -eq $PrimaryServerMachine){ $PrimaryServerMachine = $ServerNodeToAdd }
                        }
                        if($Node.Role -icontains 'Portal') {
                            $PortalNodeToAdd = (Invoke-CreateNodeToAdd -Node $Node -TargetComponent 'Portal')
                            $PortalCD.AllNodes += $PortalNodeToAdd
                            if($null -eq $PrimaryPortalMachine){ $PrimaryPortalMachine = $PortalNodeToAdd }
                        }
                        if(($Node.Role -icontains 'ServerWebAdaptor') -or ($Node.Role -icontains 'PortalWebAdaptor')) {
                            $ServerContext = if($ConfigurationParamsHashtable.ConfigData.ServerContext){ $ConfigurationParamsHashtable.ConfigData.ServerContext }else{ $null }
                            $PortalContext = if($ConfigurationParamsHashtable.ConfigData.PortalContext){ $ConfigurationParamsHashtable.ConfigData.PortalContext }else{ $null }
                            $WAAdminAccessEnabled = if($ConfigurationParamsHashtable.ConfigData.WebAdaptor.AdminAccessEnabled){$ConfigurationParamsHashtable.ConfigData.WebAdaptor.AdminAccessEnabled}else{ $False }
                            $WANode = (Invoke-CreateNodeToAdd -Node $Node -TargetComponent 'WebAdaptor' -ServerContext $ServerContext -PortalContext $PortalContext -WebAdaptorAdminAccessEnabled $WAAdminAccessEnabled )

                            if($WANode.IsServerWebAdaptorEnabled){
                                if($WANode.ServerContext -ieq $ConfigurationParamsHashtable.ConfigData.ServerContext){ 
                                    $ServerWAMachines += $WANode.NodeName
                                    if($null -eq $ServerWAExternalHostName){
                                        $ServerWAExternalHostName = if($WANode.SSLCertificate){ $WANode.SSLCertificate.CName }else{ Get-FQDN $WANode.NodeName }
                                    }
                                }
                                if(-not($IsServerWAOnSeparateMachine)){
                                    $IsServerWAOnSeparateMachine = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.NodeName -ine $WANode.NodeName } | Measure-Object).Count -gt 0)
                                }
                                if($ConfigurationParamsHashtable.ConfigData.ServerRole -ieq "NotebookServer" -or $ConfigurationParamsHashtable.ConfigData.ServerRole -ieq "MissionServer"){
                                    $WANode.PSObject.Properties.Remove('AdminAccessEnabled')
                                }
                            }
                            if($WANode.IsPortalWebAdaptorEnabled){
                                $PortalWAMachines += $NodeName.NodeName
                                if($null -eq $PortalWAExternalHostName){
                                    $PortalWAExternalHostName = if($WANode.SSLCertificate){ $WANode.SSLCertificate.CName }else{ Get-FQDN $WANode.NodeName }
                                }
                            }

                            $WebAdaptorCD.AllNodes += $WANode
                        }
                        if($Node.Role -icontains 'DataStore') {
                            $DsTypes = $Node.DataStoreTypes
                            
                            if($DsTypes -icontains "Relational"){
                                $RelationalDataStoreNodeToAdd = (Invoke-CreateNodeToAdd -Node $Node -TargetComponent 'DataStore' -DataStoreType "Relational")
                                $RelationalDataStoreCD.AllNodes += $RelationalDataStoreNodeToAdd
                                if($null -eq $PrimaryDataStore){ $PrimaryDataStore = $RelationalDataStoreNodeToAdd }
                            }
                            if($DsTypes -icontains "SpatioTemporal"){
                                $PrimaryBigDataStoreNodeToAdd = (Invoke-CreateNodeToAdd -Node $Node -TargetComponent 'DataStore' -DataStoreType "SpatioTemporal")
                                $BigDataStoreCD.AllNodes += $PrimaryBigDataStoreNodeToAdd
                                if($null -eq $PrimaryBigDataStore){ $PrimaryBigDataStore = $PrimaryBigDataStoreNodeToAdd }
                            }
                            if($DsTypes -icontains "TileCache"){
                                $PrimaryTileCacheNodeToAdd = (Invoke-CreateNodeToAdd -Node $Node -TargetComponent 'DataStore' -DataStoreType "TileCache")
                                $TileCacheDataStoreCD.AllNodes += $PrimaryTileCacheNodeToAdd
                                if($null -eq $PrimaryTileCache){ $PrimaryTileCache = $PrimaryTileCacheNodeToAdd }
                            }
                            if($DsTypes -icontains "GraphStore"){
                                $PrimaryGraphDataStoreNodeToAdd = (Invoke-CreateNodeToAdd -Node $Node -TargetComponent 'DataStore' -DataStoreType "GraphStore")
                                $GraphDataStoreCD.AllNodes += $PrimaryGraphDataStoreNodeToAdd
                                if($null -eq $GraphDataStore){ $PrimaryGraphDataStore = $PrimaryGraphDataStoreNodeToAdd }
                            }
                            if($DsTypes -icontains "ObjectStore"){
                                $PrimaryObjectDataStoreNodeToAdd = (Invoke-CreateNodeToAdd -Node $Node -TargetComponent 'DataStore' -DataStoreType "ObjectStore")
                                $ObjectDataStoreCD.AllNodes += $PrimaryObjectDataStoreNodeToAdd
                                if($null -eq $ObjectDataStore){ $PrimaryObjectDataStore = $PrimaryObjectDataStoreNodeToAdd }
                            }

                            if($Node.SslCertificates -and (($Node.SslCertificates | Where-Object { $_.Target -icontains 'DataStore' } | Measure-Object).Count -gt 0))
                            {
                                $DataStoreCertificateUpdateCD.AllNodes += (Invoke-CreateNodeToAdd -Node $Node -TargetComponent 'DataStore')
                            }
                        }
                    }
                    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $FileShareCheck){
                        $JobFlag = $False
                        $FilePathsArray = @()
                        if($ConfigurationParamsHashtable.ConfigData.Server){
                            if(-not($ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount)){
                                if($ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreLocation.StartsWith('\')){
                                    $FilePathsArray += $ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreLocation
                                }else{
                                    throw "Config Store Location is not a fileshare path"
                                }
                            }

                            if(-not($ConfigurationParamsHashtable.ConfigData.Server.ServerDirectoriesCloudStorageAccount)){
                                if($ConfigurationParamsHashtable.ConfigData.Server.ServerDirectoriesRootLocation.StartsWith('\')){
                                    $FilePathsArray += $ConfigurationParamsHashtable.ConfigData.Server.ServerDirectoriesRootLocation
                                } else {
                                    throw "Server Directories Root Location is not a fileshare path"
                                }
                            }
                        }

                        if($ConfigurationParamsHashtable.ConfigData.Portal){
                            if(-not($ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount)){
                                if($ConfigurationParamsHashtable.ConfigData.Portal.ContentDirectoryLocation.StartsWith('\')){
                                    $FilePathsArray += $ConfigurationParamsHashtable.ConfigData.Portal.ContentDirectoryLocation
                                }
                            }
                        }

                        $FileShareArgs = @{
                            ConfigurationData = $FileShareCD
                            ServiceCredential = $ServiceCredential
                            ServiceCredentialIsDomainAccount = $ServiceCredentialIsDomainAccount 
                            ServiceCredentialIsMSA = $ServiceCredentialIsMSA 
                            FileShareName = $ConfigurationParamsHashtable.ConfigData.FileShareName
                            FileShareLocalPath = $ConfigurationParamsHashtable.ConfigData.FileShareLocalPath  
                            FilePaths = ($FilePathsArray -join ",")
                        }
                        $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISFileShare" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $FileShareArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
                    }

                    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $ServerCheck){
                        $JobFlag = $False
                        $ServerArgs = @{
                            ConfigurationData = $ServerCD
                            Version = $EnterpriseVersion
                            ServiceCredential = $ServiceCredential
                            ForceServiceCredentialUpdate = $ForceServiceCredentialUpdate
                            ServiceCredentialIsDomainAccount = $ServiceCredentialIsDomainAccount 
                            ServiceCredentialIsMSA = $ServiceCredentialIsMSA 
                            ServerPrimarySiteAdminCredential = $ServerPrimarySiteAdminCredential
                            PrimaryServerMachine = $PrimaryServerMachine.NodeName
                            ConfigStoreLocation = $ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreLocation
                            ServerDirectoriesRootLocation = $ConfigurationParamsHashtable.ConfigData.Server.ServerDirectoriesRootLocation
                            ServerDirectories = if($ConfigurationParamsHashtable.ConfigData.Server.ServerDirectories){$ConfigurationParamsHashtable.ConfigData.Server.ServerDirectories}else{$null}
                            ServerLogsLocation = if($ConfigurationParamsHashtable.ConfigData.Server.ServerLogsLocation){$ConfigurationParamsHashtable.ConfigData.Server.ServerLogsLocation}else{$null}
                            EnableHTTPSOnly = if($ConfigurationParamsHashtable.ConfigData.Server.EnableHTTPSOnly){ $ConfigurationParamsHashtable.ConfigData.Server.EnableHTTPSOnly }else{ $False }
                            EnableHSTS = if($ConfigurationParamsHashtable.ConfigData.Server.EnableHSTS){ $ConfigurationParamsHashtable.ConfigData.Server.EnableHSTS }else{ $False }
                            UsesSSL = $UseSSL
                            DebugMode = $DebugMode
                        }

                        if($ConfigurationParamsHashtable.ConfigData.ServerRole -ieq "NotebookServer" -or $ConfigurationParamsHashtable.ConfigData.ServerRole -ieq "MissionServer"){
                            if($ConfigurationParamsHashtable.ConfigData.Server.ContainerImagePaths){
                                $ServerArgs["ContainerImagePaths"] = $ConfigurationParamsHashtable.ConfigData.Server.ContainerImagePaths
                            }        
                            
                            if((($EnterpriseVersionArray[0] -eq 10 -and  $EnterpriseVersionArray[1] -gt 8) -or ($EnterpriseVersionArray[0] -eq 11))-and $ConfigurationParamsHashtable.ConfigData.Server.Installer.NotebookServerSamplesDataPath){
                                $ServerArgs["ExtractNotebookServerSamplesData"] = $True
                            }                        
                        }else{
                            $ServerArgs["ServerRole"] = $ConfigurationParamsHashtable.ConfigData.ServerRole
                            if($ConfigurationParamsHashtable.ConfigData.ServerRole -ieq "GeneralPurposeServer" -and $ConfigurationParamsHashtable.ConfigData.AdditionalServerRoles){
                                $ServerArgs["AdditionalServerRoles"] = $ConfigurationParamsHashtable.ConfigData.AdditionalServerRoles
                            }

                            $ServerArgs["OpenFirewallPorts"] = ($PortalCheck -or $DataStoreCheck -or $IsServerWAOnSeparateMachine)
                            $ServerArgs["RegisteredDirectories"] = ($ConfigurationParamsHashtable.ConfigData.Server.RegisteredDirectories | ConvertTo-Json)
                            $ServerArgs["LocalRepositoryPath"] = if($ConfigurationParamsHashtable.ConfigData.Server.LocalRepositoryPath){$ConfigurationParamsHashtable.ConfigData.Server.LocalRepositoryPath}else{$null}
                        }

                        if($ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount){
                            $ServerConfigStoreCloudStorageCredentials = $null
                            if($ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.Username -and ($ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.Password -or $ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.PasswordFilePath)){
                                $ServerConfigStoreCloudStorageAccountPassword = if( $ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.PasswordFilePath ){ Get-Content $ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.Password -AsPlainText -Force }
                                $ServerConfigStoreCloudStorageCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.UserName, $ServerConfigStoreCloudStorageAccountPassword )
                            }else{
                                if($ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.CloudStorageType -ne "AWSS3DynamoDB"){
                                    throw "No credentials provided for Cloud Storage for $($ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.CloudStorageType)"
                                }
                            }

                            $ServerArgs["ConfigStoreCloudStorageType"] = $ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.CloudStorageType
                            $ServerArgs["ConfigStoreAzureFileShareName"]  = if($ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.CloudStorageType -ieq "AzureFiles"){ $ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.AzureFileShareName }else{ $null }
                            $ServerArgs["ConfigStoreCloudNamespace"] = $ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.CloudNamespace
                            $ServerArgs["ConfigStoreCloudStorageCredentials"] = $ServerConfigStoreCloudStorageCredentials
                            $ServerArgs["ConfigStoreAWSRegion"] = if($ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.CloudStorageType -ieq "AWSS3DynamoDB"){ $ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.AWSRegion }else{ $null }
                        }

                        if($ConfigurationParamsHashtable.ConfigData.Server.ServerDirectoriesCloudStorageAccount){
                            $ServerDirectoriesCloudStorageCredentials = $null
                            if($ConfigurationParamsHashtable.ConfigData.Server.ServerDirectoriesCloudStorageAccount){
                                $ServerDirectoriesCloudStorageAccountPassword = if( $ConfigurationParamsHashtable.ConfigData.Server.ServerDirectoriesCloudStorageAccount.PasswordFilePath ){ Get-Content $ConfigurationParamsHashtable.ConfigData.Server.ServerDirectoriesCloudStorageAccount.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.Server.ServerDirectoriesCloudStorageAccount.Password -AsPlainText -Force }
                                $ServerDirectoriesCloudStorageCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $ConfigurationParamsHashtable.ConfigData.Server.ServerDirectoriesCloudStorageAccount.UserName, $ServerDirectoriesCloudStorageAccountPassword )
                            }else{
                                throw "No credentials provided for Cloud Storage for $($ConfigurationParamsHashtable.ConfigData.Server.ServerDirectoriesCloudStorageAccount.CloudStorageType)"
                            }

                            $ServerArgs["ServerDirectoriesCloudStorageType"] = $ConfigurationParamsHashtable.ConfigData.Server.ServerDirectoriesCloudStorageAccount.CloudStorageType
                            $ServerArgs["ServerDirectoriesAzureFileShareName"]  = if($ConfigurationParamsHashtable.ConfigData.Server.ServerDirectoriesCloudStorageAccount.CloudStorageType -ieq "AzureFiles"){ $ConfigurationParamsHashtable.ConfigData.Server.ServerDirectoriesCloudStorageAccount.AzureFileShareName }else{ $null }
                            $ServerArgs["ServerDirectoriesCloudNamespace"] = $ConfigurationParamsHashtable.ConfigData.Server.ServerDirectoriesCloudStorageAccount.CloudNamespace
                            $ServerArgs["ServerDirectoriesCloudStorageCredentials"] = $ServerDirectoriesCloudStorageCredentials
                        }

                        $ConfigurationName = "ArcGISServer"
                        if($ConfigurationParamsHashtable.ConfigData.ServerRole -eq "NotebookServer"){
                            $ConfigurationName = "ArcGISNotebookServer"
                        }elseif($ConfigurationParamsHashtable.ConfigData.ServerRole -eq "MissionServer"){
                            $ConfigurationName = "ArcGISMissionServer"
                        }

                        $JobFlag = Invoke-DSCJob -ConfigurationName $ConfigurationName -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $ServerArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
                    }

                    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $ConfigurationParamsHashtable.ConfigData.Server.Databases){
                        foreach($DB in $ConfigurationParamsHashtable.ConfigData.Server.Databases){
                            if($JobFlag[$JobFlag.Count - 1] -eq $True){
                                $DatabaseServerAdministratorCredential = $null
                                if($DB.DatabaseAdminUser){
                                    $DatabaseAdminUserPassword = if( $DB.DatabaseAdminUser.PasswordFilePath ){ Get-Content $DB.DatabaseAdminUser.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $DB.DatabaseAdminUser.Password -AsPlainText -Force }
                                    $DatabaseServerAdministratorCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $DB.DatabaseAdminUser.UserName, $DatabaseAdminUserPassword )
                                }

                                $SDEUserCredential = $null
                                if($DB.SDEUser){
                                    $SDEUserPassword = if( $DB.SDEUser.PasswordFilePath ){ Get-Content $DB.SDEUser.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $DB.SDEUser.Password -AsPlainText -Force }
                                    $SDEUserCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $DB.SDEUser.UserName, $SDEUserPassword )
                                }

                                $DatabaseUserCredential = $null
                                if($DB.DatabaseUser){
                                    $DatabaseUserPassword = if( $DB.DatabaseUser.PasswordFilePath ){ Get-Content $DB.DatabaseUser.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $DB.DatabaseUser.Password -AsPlainText -Force }
                                    $DatabaseUserCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $DB.DatabaseUser.UserName, $DatabaseUserPassword )
                                }

                                if($JobFlag[$JobFlag.Count - 1] -eq $True){
                                    $DBArgs = @{
                                        ConfigurationData = $ServerCD
                                        PrimaryServerMachine = $PrimaryServerMachine.NodeName
                                        ServerPrimarySiteAdminCredential = $ServerPrimarySiteAdminCredential
                                        DatabaseType = $DB.DatabaseType
                                        DatabaseServerHostName = $DB.DatabaseServerHostName
                                        DatabaseName = $DB.DatabaseName
                                        DatabaseServerAdministratorCredential = $DatabaseServerAdministratorCredential
                                        SDEUserCredential = $SDEUserCredential
                                        DatabaseUserCredential = $DatabaseUserCredential
                                        DatabaseIsManaged = $DB.IsManaged
                                        EnableGeodatabase = $DB.EnableGeodatabase
                                    }

                                    $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISRegisterSQLEGDB" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $DBArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
                                }
                            }
                        }
                    }

                    $ServerExternalDNSHostName = $null
                    if($ConfigurationParamsHashtable.ConfigData.Server.ExternalLoadBalancer){
                        $ServerExternalDNSHostName = $ConfigurationParamsHashtable.ConfigData.Server.ExternalLoadBalancer
                    }else{
                        if($null -ne $ServerWAExternalHostName){
                            $ServerExternalDNSHostName = $ServerWAExternalHostName
                        }
                    }

                    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $ServerCheck){
                        $ServerSettingsArgs = @{
                            ConfigurationData = $ServerCD
                            ServerPrimarySiteAdminCredential = $ServerPrimarySiteAdminCredential
                            PrimaryServerMachine = $PrimaryServerMachine.NodeName
                            ExternalDNSHostName = $ServerExternalDNSHostName 
                            ServerContext = $ConfigurationParamsHashtable.ConfigData.ServerContext
                            DisableServiceDirectory = if($ConfigurationParamsHashtable.ConfigData.Server.DisableServiceDirectory){ $true }else{ $false }
                        }
                        $ConfigurationName = "ArcGISServerSettings"
                        if($ConfigurationParamsHashtable.ConfigData.ServerRole -eq "MissionServer"){
                            $ConfigurationName = "ArcGISMissionServerSettings"
                        }elseif($ConfigurationParamsHashtable.ConfigData.ServerRole -eq "NotebookServer"){
                            $ConfigurationName = "ArcGISNotebookServerSettings"
                        }
                        
                        $JobFlag = Invoke-DSCJob -ConfigurationName $ConfigurationName -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $ServerSettingsArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
                    }     

                    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $PortalCheck){
                        $JobFlag = $False
                        $PortalArgs = @{
                            ConfigurationData = $PortalCD
                            Version = $EnterpriseVersion
                            ServiceCredential = $ServiceCredential
                            ForceServiceCredentialUpdate = $ForceServiceCredentialUpdate
                            ServiceCredentialIsDomainAccount = $ServiceCredentialIsDomainAccount 
                            ServiceCredentialIsMSA = $ServiceCredentialIsMSA 
                            PortalAdministratorCredential = $PortalAdministratorCredential
                            PrimaryPortalMachine = $PrimaryPortalMachine.NodeName
                            ContentDirectoryLocation = $ConfigurationParamsHashtable.ConfigData.Portal.ContentDirectoryLocation
                            AdminEmail = $ConfigurationParamsHashtable.ConfigData.Portal.PortalAdministrator.Email
                            AdminSecurityQuestionIndex = $ConfigurationParamsHashtable.ConfigData.Portal.PortalAdministrator.SecurityQuestionIndex
                            AdminSecurityAnswer = $ConfigurationParamsHashtable.ConfigData.Portal.PortalAdministrator.SecurityAnswer
                            LicenseFilePath = if($ConfigurationParamsHashtable.ConfigData.Portal.LicenseFilePath){ $ConfigurationParamsHashtable.ConfigData.Portal.LicenseFilePath }else{ $null }
                            UserLicenseTypeId = if($ConfigurationParamsHashtable.ConfigData.Portal.PortalLicenseUserTypeId){ $ConfigurationParamsHashtable.ConfigData.Portal.PortalLicenseUserTypeId }else{ $null }
                            EnableHSTS = if($ConfigurationParamsHashtable.ConfigData.Portal.EnableHSTS){ $ConfigurationParamsHashtable.ConfigData.Portal.EnableHSTS }else{ $False }
                            UsesSSL = $UseSSL
                            DebugMode = $DebugMode
                        }
                        if($ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount){
                            $PortalCloudStorageCredentials = $null
                            if($ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.Username -and ($ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.Password -or $ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.PasswordFilePath)){
                                $PortalCloudStorageAccountPassword = if( $ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.PasswordFilePath ){ Get-Content $ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.Password -AsPlainText -Force }
                                $PortalCloudStorageCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.UserName, $PortalCloudStorageAccountPassword )
                            }else{
                                if($ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.CloudStorageType -ne "AWSS3DynamoDB"){
                                    throw "No credentials provided for Cloud Storage for $($ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.CloudStorageType)"
                                }
                            }
                            
                            $PortalArgs["CloudStorageType"] = $ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.CloudStorageType
                            $PortalArgs["AzureFileShareName"]  = if($ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.CloudStorageType -ieq "AzureFiles"){ $ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.AzureFileShareName }else{ $null }
                            $PortalArgs["CloudNamespace"] = $ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.CloudNamespace
                            $PortalArgs["CloudStorageCredentials"] = $PortalCloudStorageCredentials
                            $PortalArgs["AWSRegion"] = if($ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.CloudStorageType -ieq "AWSS3DynamoDB"){ $ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.AWSRegion }else{ $null }
                        }

                        $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISPortal" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $PortalArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
                    }

                    $PortalExternalDNSHostName = $null
                    if($PortalCheck){
                        if($ConfigurationParamsHashtable.ConfigData.Portal.ExternalLoadBalancer){
                            $PortalExternalDNSHostName = $ConfigurationParamsHashtable.ConfigData.Portal.ExternalLoadBalancer
                        }else{
                            if($PortalWAExternalHostName){
                                $PortalExternalDNSHostName = $PortalWAExternalHostName 
                            }
                        }
                    }

                    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $PortalCheck){
                        $PortalSettingsArgs = @{
                            ConfigurationData = $PortalCD
                            PrimaryPortalMachine = $PrimaryPortalMachine.NodeName
                            PortalAdministratorCredential = $PortalAdministratorCredential
                            ExternalDNSHostName = $PortalExternalDNSHostName
                            PortalContext = if($null -ne $PortalExternalDNSHostName){ $ConfigurationParamsHashtable.ConfigData.PortalContext }else{ $null }
                            InternalLoadBalancer = if($ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancer){ $ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancer }else{ $null }
                            InternalLoadBalancerPort = if($ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancerPort){ $ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancerPort }else{ $null }
                            EnableAutomaticAccountCreation = if($ConfigurationParamsHashtable.ConfigData.Portal.EnableAutomaticAccountCreation){ $true }else{ $false }
                            DefaultRoleForUser = if($ConfigurationParamsHashtable.ConfigData.Portal.DefaultRoleForUser){ $ConfigurationParamsHashtable.ConfigData.Portal.DefaultRoleForUser }else{ $null }
                            DefaultUserLicenseTypeIdForUser = if($ConfigurationParamsHashtable.ConfigData.Portal.DefaultUserLicenseTypeIdForUser){ $ConfigurationParamsHashtable.ConfigData.Portal.DefaultUserLicenseTypeIdForUser }else{ $null }
                            DisableServiceDirectory = if($ConfigurationParamsHashtable.ConfigData.Portal.DisableServiceDirectory){ $true }else{ $false }
                            DisableAnonymousAccess = if($ConfigurationParamsHashtable.ConfigData.Portal.DisableAnonymousAccess){ $true }else{ $false }
                        }
                        
                        if($ConfigurationParamsHashtable.ConfigData.Credentials.ADServiceUser){
                            $ADServicePassword = if($ConfigurationParamsHashtable.ConfigData.Credentials.ADServiceUser.PasswordFilePath ){ Get-Content $ConfigurationParamsHashtable.ConfigData.Credentials.ADServiceUser.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.Credentials.ADServiceUser.Password -AsPlainText -Force }
                            $ADServiceCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $ConfigurationParamsHashtable.ConfigData.Credentials.ADServiceUser.UserName, $ADServicePassword )
                            $PortalSettingsArgs["ADServiceCredential"] = $ADServiceCredential
                        }

                        $EnterprisePatchVersion = if($EnterpriseVersionArray.Count -eq 3){ $EnterpriseVersionArray[2] }else { 0 }
                        if(($EnterpriseVersionArray[0] -eq 11) -or (($EnterpriseVersionArray[0] -eq 10) -and ($EnterpriseVersionArray[1] -gt 8 -or ($EnterpriseVersionArray[1] -eq 8 -and $EnterprisePatchVersion -eq 1)))){
                            if($ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings){
                                $PortalSettingsArgs["EnableEmailSettings"] = $True
                                $PortalSettingsArgs["EmailSettingsSMTPServerAddress"] = $ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings.SMTPServerAddress
                                $PortalSettingsArgs["EmailSettingsFrom"] = $ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings.From
                                $PortalSettingsArgs["EmailSettingsLabel"] = $ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings.Label
                                $PortalSettingsArgs["EmailSettingsAuthenticationRequired"] = $ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings.AuthenticationRequired
                                if($ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings.AuthenticationRequired){
                                    $EmailSettingsPassword = if( $ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings.PasswordFilePath ){ Get-Content $ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings.Password -AsPlainText -Force }
                                    $EmailSettingsCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings.UserName, $EmailSettingsPassword )
                                    $PortalSettingsArgs["EmailSettingsCredential"] = $EmailSettingsCredential
                                }
                                $PortalSettingsArgs["EmailSettingsSMTPPort"] = $ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings.SMTPPort
                                $PortalSettingsArgs["EmailSettingsEncryptionMethod"] = $ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings.EncryptionMethod
                            }else{
                                $PortalSettingsArgs["EnableEmailSettings"] = $False
                            }
                        }


                        $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISPortalSettings" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $PortalSettingsArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
                    }

                    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $WebAdaptorCheck){
                        $JobFlag = $False
                        $WebAdaptorArgs = @{
                            ConfigurationData           = $WebAdaptorCD
                            ServerPrimarySiteAdminCredential = $ServerPrimarySiteAdminCredential
                            PortalAdministratorCredential = $PortalAdministratorCredential
                            PrimaryServerMachine        = $PrimaryServerMachine.NodeName
                            PrimaryPortalMachine        = $PrimaryPortalMachine.NodeName
                            WebSiteId                   = if($ConfigurationParamsHashtable.ConfigData.WebAdaptor.WebSiteId){ $ConfigurationParamsHashtable.ConfigData.WebAdaptor.WebSiteId }else{ 1 }
                            OverrideHTTPSBinding        = if($ConfigurationParamsHashtable.ConfigData.WebAdaptor.OverrideHTTPSBinding){ $ConfigurationParamsHashtable.ConfigData.WebAdaptor.OverrideHTTPSBinding }else{ $True } 
                        }
                        if($ServerCheck){
                            $WebAdaptorArgs["ServerRole"] = $ConfigurationParamsHashtable.ConfigData.ServerRole
                        }

                        $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISWebAdaptor" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $WebAdaptorArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
                    }
                    
                    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $RelationalDataStoreCheck){
                        $JobFlag = $False
                        $RelationalDataStoreArgs = @{
                            Version = $EnterpriseVersion
                            ConfigurationData = $RelationalDataStoreCD
                            ServiceCredential = $ServiceCredential
                            ForceServiceCredentialUpdate = $ForceServiceCredentialUpdate
                            ServiceCredentialIsDomainAccount = $ServiceCredentialIsDomainAccount 
                            ServiceCredentialIsMSA = $ServiceCredentialIsMSA 
                            PrimaryServerMachine = $PrimaryServerMachine.NodeName
                            ServerPrimarySiteAdminCredential = $ServerPrimarySiteAdminCredential
                            ContentDirectoryLocation = $ConfigurationParamsHashtable.ConfigData.DataStore.ContentDirectoryLocation
                            PrimaryDataStore = $PrimaryDataStore.NodeName
                            EnableFailoverOnPrimaryStop = if($ConfigurationParamsHashtable.ConfigData.DataStore.EnableFailoverOnPrimaryStop){ $ConfigurationParamsHashtable.ConfigData.DataStore.EnableFailoverOnPrimaryStop }else{ $False }
                            EnablePointInTimeRecovery = if($ConfigurationParamsHashtable.ConfigData.DataStore.EnablePointInTimeRecovery){ $ConfigurationParamsHashtable.ConfigData.DataStore.EnablePointInTimeRecovery }else{ $False }
                            UsesSSL = $UseSSL
                            DebugMode = $DebugMode
                        }
                        
                        $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISDataStore" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $RelationalDataStoreArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
                        
                        if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $ConfigurationParamsHashtable.ConfigData.DataStore.Backups -and $ConfigurationParamsHashtable.ConfigData.DataStore.Backups.Relational -and $ConfigurationParamsHashtable.ConfigData.DataStore.Backups.Relational.Count -gt 0){
                            $JobFlag = $False
                            $RelationalDataStoreBackupArgs = @{
                                ConfigurationData = $RelationalDataStoreCD
                                PrimaryDataStore = $PrimaryDataStore.NodeName
                            }
                            $RelationalBackups = @()
                            for ( $i = 0; $i -lt $ConfigurationParamsHashtable.ConfigData.DataStore.Backups.Relational.Count; $i++ ){
                                $BackupObject = $ConfigurationParamsHashtable.ConfigData.DataStore.Backups.Relational[$i]
                                if($BackupObject.IsDefault -and $BackupObject.Type -ne "fs"){
                                    throw "Default back up for Relational DataStore can only be a local path or shared file location at $EnterpriseVersion"
                                }
                            
                                $Backup = @{
                                    Type = $BackupObject.Type
                                    Name = $BackupObject.Name
                                    Location = $BackupObject.Location                                    
                                    IsDefault = if($BackupObject.IsDefault){ $BackupObject.IsDefault }else{ $False }
                                    ForceDefaultRelationalBackupUpdate = if($BackupObject.ForceBackupLocationUpdate){ $BackupObject.ForceBackupLocationUpdate }else{ $False }
                                }

                                if($BackupObject.Type -ine "fs")
                                {
                                    if($BackupObject.CloudStorageAccount){
                                        $Backup["ForceCloudCredentialsUpdate"] = if($BackupObject.CloudStorageAccount.ForceUpdate){ $BackupObject.CloudStorageAccount.ForceUpdate }else{ $False }

                                        if($BackupObject.Type -ieq "azure"){
                                            $Pos = $BackupObject.CloudStorageAccount.UserName.IndexOf('.blob.')
                                            if(-not($Pos -gt -1))
                                            {
                                                throw "Error - Invalid Backup Azure Blob Storage Account"
                                            } 
                                        }

                                        $BackupCloudStorageAccountPassword = if( $BackupObject.CloudStorageAccount.PasswordFilePath ){ Get-Content $BackupObject.CloudStorageAccount.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $BackupObject.CloudStorageAccount.Password -AsPlainText -Force }
                                        $BackupCloudStorageCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $BackupObject.CloudStorageAccount.UserName, $BackupCloudStorageAccountPassword )
                                        $Backup["CloudCredential"] = $BackupCloudStorageCredentials
                                    }else{
                                        throw "No cloud credentials provided for Cloud Backup type $($Backup.Type) and Location $($Backup.Location)"
                                    }
                                }
                                
                                $RelationalBackups += $Backup
                            }
                            $RelationalDataStoreBackupArgs["RelationalBackups"] = $RelationalBackups
                            $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISDataStoreBackup" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $RelationalDataStoreBackupArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
                        }
                    }

                    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $BigDataStoreCheck){
                        $JobFlag = $False
                        $BigDataStoreArgs = @{
                            Version = $EnterpriseVersion
                            ConfigurationData = $BigDataStoreCD
                            ServiceCredential = $ServiceCredential
                            ForceServiceCredentialUpdate = $ForceServiceCredentialUpdate
                            ServiceCredentialIsDomainAccount = $ServiceCredentialIsDomainAccount 
                            ServiceCredentialIsMSA = $ServiceCredentialIsMSA 
                            PrimaryServerMachine = $PrimaryServerMachine.NodeName
                            ServerPrimarySiteAdminCredential = $ServerPrimarySiteAdminCredential
                            ContentDirectoryLocation = $ConfigurationParamsHashtable.ConfigData.DataStore.ContentDirectoryLocation
                            PrimaryBigDataStore = $PrimaryBigDataStore.NodeName
                            UsesSSL = $UseSSL
                            DebugMode = $DebugMode
                        }

                        $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISDataStore" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $BigDataStoreArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode

                        if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $ConfigurationParamsHashtable.ConfigData.DataStore.Backups -and $ConfigurationParamsHashtable.ConfigData.DataStore.Backups.SpatioTemporal -and $ConfigurationParamsHashtable.ConfigData.DataStore.Backups.SpatioTemporal.Count -gt 0){                            
                            $JobFlag = $False
                            $BigDataStoreBackupArgs = @{
                                ConfigurationData = $BigDataStoreCD
                                PrimaryBigDataStore = $PrimaryBigDataStore.NodeName
                            }
                            $SpatioTemporalBackups = @()
                            for ( $i = 0; $i -lt $ConfigurationParamsHashtable.ConfigData.DataStore.Backups.SpatioTemporal.Count; $i++ ){
                                $BackupObject = $ConfigurationParamsHashtable.ConfigData.DataStore.Backups.SpatioTemporal[$i]
                                $Backup = @{
                                    Type = $BackupObject.Type
                                    Name = $BackupObject.Name
                                    Location = $BackupObject.Location                                    
                                    IsDefault = if($BackupObject.IsDefault){ $BackupObject.IsDefault }else{ $False }
                                }

                                if($BackupObject.Type -ine "fs")
                                {
                                    if($BackupObject.CloudStorageAccount){
                                        $Backup["ForceCloudCredentialsUpdate"] = if($BackupObject.CloudStorageAccount.ForceUpdate){ $BackupObject.CloudStorageAccount.ForceUpdate }else{ $False }
                                        
                                        if($BackupObject.Type -ieq "azure"){
                                            $Pos = $BackupObject.CloudStorageAccount.UserName.IndexOf('.blob.')
                                            if(-not($Pos -gt -1))
                                            {
                                                throw "Error - Invalid Backup Azure Blob Storage Account"
                                            }
                                        }

                                        $BackupCloudStorageAccountPassword = if( $BackupObject.CloudStorageAccount.PasswordFilePath ){ Get-Content $BackupObject.CloudStorageAccount.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $BackupObject.CloudStorageAccount.Password -AsPlainText -Force }
                                        $BackupCloudStorageCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $BackupObject.CloudStorageAccount.UserName, $BackupCloudStorageAccountPassword )
                                        $Backup["CloudCredential"] = $BackupCloudStorageCredentials
                                    }else{
                                        throw "No cloud credentials provided for Cloud Backup type $($Backup.Type) and Location $($Backup.Location)"
                                    }
                                }
                                
                                $SpatioTemporalBackups += $Backup
                            }
                            $BigDataStoreBackupArgs["SpatioTemporalBackups"] = $SpatioTemporalBackups
                            $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISDataStoreBackup" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $BigDataStoreBackupArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
                        }
                    }

                    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $TileCacheDataStoreCheck){
                        $JobFlag = $False
                        $TileCacheDataStoreArgs = @{
                            Version = $EnterpriseVersion
                            ConfigurationData = $TileCacheDataStoreCD
                            ServiceCredential = $ServiceCredential
                            ForceServiceCredentialUpdate = $ForceServiceCredentialUpdate
                            ServiceCredentialIsDomainAccount = $ServiceCredentialIsDomainAccount 
                            ServiceCredentialIsMSA = $ServiceCredentialIsMSA 
                            PrimaryServerMachine = $PrimaryServerMachine.NodeName
                            ServerPrimarySiteAdminCredential = $ServerPrimarySiteAdminCredential
                            ContentDirectoryLocation = $ConfigurationParamsHashtable.ConfigData.DataStore.ContentDirectoryLocation
                            PrimaryTileCache = $PrimaryTileCache.NodeName
                            UsesSSL = $UseSSL
                            DebugMode = $DebugMode
                        }

                        $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISDataStore" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $TileCacheDataStoreArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode

                        if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $ConfigurationParamsHashtable.ConfigData.DataStore.Backups -and $ConfigurationParamsHashtable.ConfigData.DataStore.Backups.TileCache -and $ConfigurationParamsHashtable.ConfigData.DataStore.Backups.TileCache.Count -gt 0){
                            $JobFlag = $False
                            $TileCacheDataStoreBackupArgs = @{
                                ConfigurationData = $TileCacheDataStoreCD
                                PrimaryTileCache = $PrimaryTileCache.NodeName
                            }
                            $TileCacheBackups = @()
                            for ( $i = 0; $i -lt $ConfigurationParamsHashtable.ConfigData.DataStore.Backups.TileCache.Count; $i++ ){
                                $BackupObject = $ConfigurationParamsHashtable.ConfigData.DataStore.Backups.TileCache[$i]
                                
                                if($EnterpriseVersionArray[0] -eq 10 -and $EnterpriseVersionArray[1] -eq 7){
                                    if($BackupObject.Name -ne "DEFAULT"){
                                        throw "Backup for Tile Cache DataStore cannot have a backup name other than 'DEFAULT' at $EnterpriseVersion"
                                    }
                                    if($BackupObject.Type -ne "fs"){
                                        throw "Backup of Tile Cache DataStore to a Cloud Store isn't supported at $EnterpriseVersion"
                                    }
                                }

                                $Backup = @{
                                    Type = $BackupObject.Type
                                    Name = $BackupObject.Name
                                    Location = $BackupObject.Location                                    
                                    IsDefault = if($BackupObject.IsDefault){ $BackupObject.IsDefault }else{ $False }
                                }

                                if($BackupObject.Type -ine "fs")
                                {
                                    if($BackupObject.CloudStorageAccount){
                                        $Backup["ForceCloudCredentialsUpdate"] = if($BackupObject.CloudStorageAccount.ForceUpdate){ $BackupObject.CloudStorageAccount.ForceUpdate }else{ $False }

                                        if($BackupObject.Type -ieq "azure"){
                                            $Pos = $BackupObject.CloudStorageAccount.UserName.IndexOf('.blob.')
                                            if(-not($Pos -gt -1))
                                            {
                                                throw "Error - Invalid Backup Azure Blob Storage Account"
                                            } 
                                        }

                                        $BackupCloudStorageAccountPassword = if( $BackupObject.CloudStorageAccount.PasswordFilePath ){ Get-Content $BackupObject.CloudStorageAccount.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $BackupObject.CloudStorageAccount.Password -AsPlainText -Force }
                                        $BackupCloudStorageCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $BackupObject.CloudStorageAccount.UserName, $BackupCloudStorageAccountPassword )
                                        $Backup["CloudCredential"] = $BackupCloudStorageCredentials
                                    }else{
                                        throw "No cloud credentials provided for Cloud Backup type $($Backup.Type) and Location $($Backup.Location)"
                                    }
                                }
                                $TileCacheBackups += $Backup
                            }
                            $TileCacheDataStoreBackupArgs["TileCacheBackups"] = $TileCacheBackups
                            $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISDataStoreBackup" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $TileCacheDataStoreBackupArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
                        }                        
                    }

                    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $GraphDataStoreCheck){
                        $JobFlag = $False
                        $GraphDataStoreArgs = @{
                            Version = $EnterpriseVersion
                            ConfigurationData = $GraphDataStoreCD
                            ServiceCredential = $ServiceCredential
                            ForceServiceCredentialUpdate = $ForceServiceCredentialUpdate
                            ServiceCredentialIsDomainAccount = $ServiceCredentialIsDomainAccount 
                            ServiceCredentialIsMSA = $ServiceCredentialIsMSA 
                            PrimaryServerMachine = $PrimaryServerMachine.NodeName
                            ServerPrimarySiteAdminCredential = $ServerPrimarySiteAdminCredential
                            ContentDirectoryLocation = $ConfigurationParamsHashtable.ConfigData.DataStore.ContentDirectoryLocation
                            PrimaryGraphDataStore = $PrimaryGraphDataStore.NodeName
                            UsesSSL = $UseSSL
                            DebugMode = $DebugMode
                        }

                        $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISDataStore" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $GraphDataStoreArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode

                        if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $ConfigurationParamsHashtable.ConfigData.DataStore.Backups -and $ConfigurationParamsHashtable.ConfigData.DataStore.Backups.GraphStore -and $ConfigurationParamsHashtable.ConfigData.DataStore.Backups.GraphStore.Count -gt 0){                            
                            $JobFlag = $False
                            $GraphStoreBackupArgs = @{
                                ConfigurationData = $GraphDataStoreCD
                                PrimaryGraphStore = $PrimaryGraphDataStore.NodeName
                            }
                            $GraphStoreBackups = @()
                            for ( $i = 0; $i -lt $ConfigurationParamsHashtable.ConfigData.DataStore.Backups.GraphStore.Count; $i++ ){
                                $BackupObject = $ConfigurationParamsHashtable.ConfigData.DataStore.Backups.GraphStore[$i]
                                $Backup = @{
                                    Type = $BackupObject.Type
                                    Name = $BackupObject.Name
                                    Location = $BackupObject.Location                                    
                                    IsDefault = if($BackupObject.IsDefault){ $BackupObject.IsDefault }else{ $False }
                                }

                                if($BackupObject.Type -ine "fs")
                                {
                                    if($BackupObject.CloudStorageAccount){
                                        $Backup["ForceCloudCredentialsUpdate"] = if($BackupObject.CloudStorageAccount.ForceUpdate){ $BackupObject.CloudStorageAccount.ForceUpdate }else{ $False }
                                        
                                        if($BackupObject.Type -ieq "azure"){
                                            $Pos = $BackupObject.CloudStorageAccount.UserName.IndexOf('.blob.')
                                            if(-not($Pos -gt -1))
                                            {
                                                throw "Error - Invalid Backup Azure Blob Storage Account"
                                            }
                                        }

                                        $BackupCloudStorageAccountPassword = if( $BackupObject.CloudStorageAccount.PasswordFilePath ){ Get-Content $BackupObject.CloudStorageAccount.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $BackupObject.CloudStorageAccount.Password -AsPlainText -Force }
                                        $BackupCloudStorageCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $BackupObject.CloudStorageAccount.UserName, $BackupCloudStorageAccountPassword )
                                        $Backup["CloudCredential"] = $BackupCloudStorageCredentials
                                    }else{
                                        throw "No cloud credentials provided for Cloud Backup type $($Backup.Type) and Location $($Backup.Location)"
                                    }
                                }
                                
                                $GraphStoreBackups += $Backup
                            }
                            $GraphStoreBackupArgs["GraphStoreBackups"] = $GraphStoreBackups
                            $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISDataStoreBackup" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $GraphStoreBackupArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
                        }
                    }

                    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $ObjectDataStoreCheck){
                        $JobFlag = $False
                        $ObjectDataStoreArgs = @{
                            Version = $EnterpriseVersion
                            ConfigurationData = $ObjectDataStoreCD
                            ServiceCredential = $ServiceCredential
                            ForceServiceCredentialUpdate = $ForceServiceCredentialUpdate
                            ServiceCredentialIsDomainAccount = $ServiceCredentialIsDomainAccount 
                            ServiceCredentialIsMSA = $ServiceCredentialIsMSA 
                            PrimaryServerMachine = $PrimaryServerMachine.NodeName
                            ServerPrimarySiteAdminCredential = $ServerPrimarySiteAdminCredential
                            ContentDirectoryLocation = $ConfigurationParamsHashtable.ConfigData.DataStore.ContentDirectoryLocation
                            PrimaryObjectDataStore = $PrimaryObjectDataStore.NodeName
                            UsesSSL = $UseSSL
                            DebugMode = $DebugMode
                        }
                        $ObjectStoreMachineCount = ($ObjectDataStoreCD.AllNodes | Where-Object { $_.DataStoreTypes -icontains 'ObjectStore' } | Measure-Object).Count
                        if($ObjectStoreMachineCount -eq 2){
                            throw "Object Store doesn't support two machine configuration."
                        }

                        $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISDataStore" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $ObjectDataStoreArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
                    }

                    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $DataStoreCertificateUpdateCD.AllNodes.Count -gt 0){
                        $JobFlag = $False
                        $ArcGISDataStoreCertificateUpdateArgs = @{
                            ConfigurationData = $DataStoreCertificateUpdateCD
                        }
                        $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISDataStoreCertificateUpdate" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $ArcGISDataStoreCertificateUpdateArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
                    }

                    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $RasterDataStoreItemCheck){
                        $JobFlag = $False
                        $ArcGISRasterDataStoreItemArgs = @{
                            ConfigurationData = $RasterDataStoreItemCD
                            ServiceCredential = $ServiceCredential
                            ServiceCredentialIsDomainAccount = $ServiceCredentialIsDomainAccount 
                            ServiceCredentialIsMSA = $ServiceCredentialIsMSA 
                            ServerPrimarySiteAdminCredential = $ServerPrimarySiteAdminCredential
                            PrimaryServerMachine = $PrimaryServerMachine.NodeName
                            FileShareName = if($ConfigurationParamsHashtable.ConfigData.DataStoreItems.RasterStore.ExternalFileSharePath){$null}else{$ConfigurationParamsHashtable.ConfigData.DataStoreItems.RasterStore.FileShareName}
                            FileShareLocalPath = if($ConfigurationParamsHashtable.ConfigData.DataStoreItems.RasterStore.ExternalFileSharePath){$null}else{$ConfigurationParamsHashtable.ConfigData.DataStoreItems.RasterStore.FileShareLocalPath}
                            ExternalFileSharePath = if($ConfigurationParamsHashtable.ConfigData.DataStoreItems.RasterStore.ExternalFileSharePath){ $ConfigurationParamsHashtable.ConfigData.DataStoreItems.RasterStore.ExternalFileSharePath }else{ $null }
                        }

                        $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISRasterDataStoreItem" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $ArcGISRasterDataStoreItemArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
                    }
                    
                    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $ServerCheck){
                        $RemoteFederation = $PortalServerFederation = $False
                        $RemoteSiteAdministrator = $null
                        if($PortalCheck){
                            $PortalServerFederation = $True
                            $PortalHostName = if($null -ne $ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancer){ $ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancer }else{ if($PrimaryPortalMachine.SSLCertificate){ $PrimaryPortalMachine.SSLCertificate.CName }else{ Get-FQDN $PrimaryPortalMachine.NodeName } }
                            $PortalPort = if($null -ne $ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancerPort){ $ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancerPort }else{ 7443 }
                            $PortalContext = 'arcgis'
                        }elseif($ConfigurationParamsHashtable.ConfigData.Federation){
                            $RemoteFederation = $True
                            $PortalHostName = $ConfigurationParamsHashtable.ConfigData.Federation.PortalHostName
                            $PortalPort = $ConfigurationParamsHashtable.ConfigData.Federation.PortalPort
                            $PortalContext = $ConfigurationParamsHashtable.ConfigData.Federation.PortalContext

                            $RemoteSiteAdministratorPassword = if( $ConfigurationParamsHashtable.ConfigData.Federation.PortalAdministrator.PasswordFilePath ){ Get-Content $ConfigurationParamsHashtable.ConfigData.Federation.PortalAdministrator.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.Federation.PortalAdministrator.Password -AsPlainText -Force }
                            $RemoteSiteAdministrator = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $ConfigurationParamsHashtable.ConfigData.Federation.PortalAdministrator.UserName, $RemoteSiteAdministratorPassword )
                        }

                        if($RemoteFederation -or $PortalServerFederation){
                            $ServerRole = $ConfigurationParamsHashtable.ConfigData.ServerRole
                            $ServerServiceURL = if($null -ne $ServerExternalDNSHostName){ $ServerExternalDNSHostName }else{  if($PrimaryServerMachine.SSLCertificate){ $PrimaryServerMachine.SSLCertificate.CName }else{ Get-FQDN $PrimaryServerMachine.NodeName } }
                            $ServerServiceURLPort = if($null -ne $ServerExternalDNSHostName){ 443 }else{if($ServerRole -ieq 'NotebookServer'){11443}elseif($ServerRole -ieq 'MissionServer'){ 20443 }else{6443}}
                            $ServerServiceURLContext = if($null -ne $ConfigurationParamsHashtable.ConfigData.ServerContext){ $ConfigurationParamsHashtable.ConfigData.ServerContext }else{ 'arcgis' }

                            $ServerSiteAdminURL = if($PrimaryServerMachine.SSLCertificate){ $PrimaryServerMachine.SSLCertificate.CName }else{ Get-FQDN $PrimaryServerMachine.NodeName }
                            $ServerSiteAdminURLPort = if($ServerRole -ieq 'NotebookServer'){11443}elseif($ServerRole -ieq 'MissionServer'){ 20443 }else{ 6443 }
                            if($ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancerPort){
                                $ServerSiteAdminURLPort = $ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancerPort
                            }
                            $ServerSiteAdminURLContext = 'arcgis'

                            if($ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancer){
                                $ServerSiteAdminURL = $ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancer
                                $ServerSiteAdminURLPort = if($ServerRole -ieq 'NotebookServer'){11443}elseif($ServerRole -ieq 'MissionServer'){ 20443 }else{ 6443 }
                                if($ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancerPort){
                                    $ServerSiteAdminURLPort = $ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancerPort
                                }
                                $ServerSiteAdminURLContext = 'arcgis'
                            }else{
                                if($ConfigurationParamsHashtable.ConfigData.WebAdaptor.AdminAccessEnabled -or ($ServerRole -ieq 'NotebookServer')-or ($ServerRole -ieq 'MissionServer')){ 
                                    # Check this for LB when no WAs specified
                                    if($ConfigurationParamsHashtable.ConfigData.Server.ExternalLoadBalancer){
                                        $ServerSiteAdminURL = $ConfigurationParamsHashtable.ConfigData.Server.ExternalLoadBalancer
                                        $ServerSiteAdminURLContext = $ConfigurationParamsHashtable.ConfigData.ServerContext
                                        $ServerSiteAdminURLPort = 443
                                    }else{
                                        if(($null -ne $ServerExternalDNSHostName) <#-and $ServerWAAdminAccessEnabled#>){
                                            $ServerSiteAdminURL = $ServerExternalDNSHostName
                                            $ServerSiteAdminURLContext = $ConfigurationParamsHashtable.ConfigData.ServerContext
                                            $ServerSiteAdminURLPort = 443
                                        }
                                    }
                                }
                            }

                            $ServerFunctions = @()
                            $ServerRole = $ConfigurationParamsHashtable.ConfigData.ServerRole
                            
                            if($ServerRole -ieq "GeneralPurposeServer"){
                                if($ConfigurationParamsHashtable.ConfigData.AdditionalServerRoles){
                                    foreach($AdditionalRole in $ConfigurationParamsHashtable.ConfigData.AdditionalServerRoles){
                                        $ServerFunctions += if($AdditionalRole -ieq "WorkflowManagerServer"){"WorkflowManager"}else{$AdditionalRole}
                                    }
                                }
                            }else{
                                if($ServerRole -ieq "WorkflowManagerServer"){
                                    $ServerRole = "WorkflowManager"
                                }
                                $ServerFunctions += $ServerRole
                            }

                            $FederationArgs = @{
                                ConfigurationData = $ServerCD
                                PrimaryServerMachine = $PrimaryServerMachine.NodeName
                                PortalHostName = $PortalHostName
                                PortalPort = $PortalPort
                                PortalContext = $PortalContext
                                ServerHostName = $ServerServiceURL
                                ServerPort = $ServerServiceURLPort
                                ServerContext = $ServerServiceURLContext
                                ServerSiteAdminUrlHostName = $ServerSiteAdminURL
                                ServerSiteAdminUrlPort = $ServerSiteAdminURLPort
                                ServerSiteAdminUrlContext = $ServerSiteAdminURLContext
                                ServerPrimarySiteAdminCredential = $ServerPrimarySiteAdminCredential
                                RemoteSiteAdministrator = if($RemoteFederation){ $RemoteSiteAdministrator }else{ $PortalAdministratorCredential }
                                IsHostingServer = ($ServerCheck -and $PortalCheck -and $DataStoreCheck) #Check for relational ds only
                                IsFederatedWithRestrictedPublishing = if($ConfigurationParamsHashtable.ConfigData.Federation.RestrictedPublishing){$ConfigurationParamsHashtable.ConfigData.Federation.RestrictedPublishing}else{$False}
                                ServerFunctions = [system.String]::Join(",", $ServerFunctions)
                            }
                            $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISFederation" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $FederationArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
                        }
                    }
                
                    if($JobFlag[$JobFlag.Count - 1] -eq $True){ 
                        if($PortalCheck){
                            $PrimaryPortalCName = if($PrimaryPortalMachine.SSLCertificate){ $PrimaryPortalMachine.SSLCertificate.CName }else{ Get-FQDN $PrimaryPortalMachine.NodeName }
                            $PortalUrl = "$($PrimaryPortalCName):7443/arcgis" 
                            $PortalAdminUrl = "$($PrimaryPortalCName):7443/arcgis"

                            if($ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancer){
                                $PortalEndpointPort = if($ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancerPort){ $ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancerPort }else{ 7443}
                                $PortalUrl = "$($ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancer):$($PortalEndpointPort)/arcgis"
                                $PortalAdminUrl = "$($ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancer):$($PortalEndpointPort)/arcgis"
                            }

                            if($null -ne $PortalExternalDNSHostName){
                                $PortalUrl = "$($PortalExternalDNSHostName)/$($ConfigurationParamsHashtable.ConfigData.PortalContext)"
                                $PortalAdminUrl = "$($PortalExternalDNSHostName)/$($ConfigurationParamsHashtable.ConfigData.PortalContext)"
                            }

                            Write-Information -InformationAction Continue "Portal Admin URL - https://$PortalAdminUrl/portaladmin"
                            Write-Information "Portal URL - https://$PortalUrl/home"    
                        }
                        if($ServerCheck){
                            $PrimaryServerCName = if($PrimaryServerMachine.SSLCertificate){ $PrimaryServerMachine.SSLCertificate.CName }else{ Get-FQDN $PrimaryServerMachine.NodeName }
                            $Port =  if($ServerRole -ieq 'NotebookServer'){11443}elseif($ServerRole -ieq "MissionServer"){20443}else{6443}                            
                            $ServerAdminURL = "$($PrimaryServerCName):$($Port)/arcgis"
                            $ServerManagerURL = "$($PrimaryServerCName):$($Port)/arcgis"
                            $ServerURL = "$($PrimaryServerCName):$($Port)/arcgis"
                            
                            if($ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancer){
                                if($ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancerPort){
                                    $Port = $ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancerPort
                                }
                                $ServerSiteAdminURL = $ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancer
                                $ServerAdminURL = "$($ServerSiteAdminURL):$($Port)/arcgis"
                                $ServerManagerURL = "$($ServerSiteAdminURL):$($Port)/arcgis"
                            }
                            
                            if($null -ne $ServerExternalDNSHostName){
                                $ServerURL = "$($ServerExternalDNSHostName)/$($ConfigurationParamsHashtable.ConfigData.ServerContext)"
                                if($ConfigurationParamsHashtable.ConfigData.WebAdaptor.AdminAccessEnabled){
                                    $ServerAdminURL = "$($ServerExternalDNSHostName)/$($ConfigurationParamsHashtable.ConfigData.ServerContext)"
                                    $ServerManagerURL = "$($ServerExternalDNSHostName)/$($ConfigurationParamsHashtable.ConfigData.ServerContext)"
                                }
                            }

                            Write-Information -InformationAction Continue "Server Admin URL - https://$ServerAdminURL/admin"
                            if(-not($ConfigurationParamsHashtable.ConfigData.ServerRole -in @('MissionServer', 'NotebookServer'))){
                                Write-Information -InformationAction Continue "Server Manager URL - https://$ServerManagerURL/manager"
                            }
                            Write-Information -InformationAction Continue "Server Rest URL - https://$ServerURL/rest"
                        }
                    }
                }else{
                    throw "File directory validations failed for server or portal. Please check and run again."  
                }
            }
        }
    }elseif($Mode -ieq "Upgrade"){
        $HostingConfig = $null

        $OtherConfigs = @()
        
        foreach($cf in $ConfigurationParametersFile){
            $cfJSON = (ConvertFrom-Json (Get-Content $cf -Raw))
            $cfHashtable = Convert-PSObjectToHashtable $cfJSON
            
            $VersionArray = $cfHashtable.ConfigData.Version.Split(".")
            if(-not(($VersionArray[0] -eq 10 -and $VersionArray[1] -ge 7) -or $VersionArray[0] -eq 11)){
                throw "[ERROR] DSC Module only supports upgrades to ArcGIS Enterprise 10.7.x and later versions. Configuration File Name - $cf"
            }

            if(-not($cfHashtable.ConfigData.OldVersion)){
                throw "No Enterprise Version for present installation ('OldVersion') specified for Configuration File Name - $cf"
            }
            
            $HasPortalNodes = ($cfHashtable.AllNodes | Where-Object { $_.Role -icontains 'Portal'} | Measure-Object).Count -gt 0
            $HasServerNodes = ($cfHashtable.AllNodes | Where-Object { $_.Role -icontains 'Server'} | Measure-Object).Count -gt 0
            $HasDataStoreNodes = ($cfHashtable.AllNodes | Where-Object { $_.Role -icontains 'DataStore'} | Measure-Object).Count -gt 0

            if($HasPortalNodes -and $HasDataStoreNodes -and $HasServerNodes){
                $HostingConfig = $cfHashtable
            }else{
                $OtherConfigs += $cfHashtable
            }

            if($HasServerNodes){
                $ServerRole = $null
                if($cfHashtable.ConfigData.ServerRole){
                    $ServerRole = $cfHashtable.ConfigData.ServerRole 
                    if($ServerRole -ieq "RasterAnalytics" -or $ServerRole -ieq "ImageHosting"){
                        $ServerRole = "ImageServer"
                    }
                }else{
                    $ServerRole = "GeneralPurposeServer"
                }
            
                $AdditionalServerRoles = @()
                if($ServerRole -ieq "GeneralPurposeServer" -and $cfHashtable.ConfigData.AdditionalServerRoles){
                    foreach($AdditionalRole in $cf.ConfigData.AdditionalServerRoles){
                        if($AdditionalRole -ieq "RasterAnalytics" -or $AdditionalRole -ieq "ImageHosting"){
                            $AdditionalServerRoles += "ImageServer"
                        }else{
                            $AdditionalServerRoles += $AdditionalRole
                        }
                    }
                }

                if(($ServerRole -ieq "GeoEvent" -or ($ServerRole -ieq "GeneralPurposeServer" -and $AdditionalServerRoles -icontains "GeoEvent")) -and $cfHashtable.ConfigData.GeoEventServer){
                    if($cfHashtable.ConfigData.Version.StartsWith("11.") -and -not($cfHashtable.ConfigData.GeoEventServer.UserBackupConfigFiles)){
                        throw "ArcGIS GeoEvent Server - You have to specify UserBackupConfigFiles as 'true' under GeoEventServer Config Data block of your json config to acknowledge that you understand your geoevent configuration will not be automatically upgraded as a part of this installation and will need to be manually imported after successful completion of the installation."
                    }
                }
            }

            $SetupsDownloadCD = Get-DownloadsInstallsConfigurationData -ConfigurationParamsJSON $cfJSON
            if($SetupsDownloadCD.ConfigData.DownloadSetups){
                $AGOPassword = if( $cfHashtable.ConfigData.Credentials.AGOCredential.PasswordFilePath ){ Get-Content $cfHashtable.ConfigData.Credentials.AGOCredential.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $cfHashtable.ConfigData.Credentials.AGOCredential.Password -AsPlainText -Force }
                $AGOCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $cfHashtable.ConfigData.Credentials.AGOCredential.UserName, $AGOPassword )
                $DownloadSetupsArgs = @{
                    ConfigurationData = $SetupsDownloadCD
                    AGOCredential = $AGOCredential
                }
                $ConfigurationName = "ArcGISDownloads"
                $JobFlag = Invoke-DSCJob -ConfigurationName $ConfigurationName -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $DownloadSetupsArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
                if($JobFlag[$JobFlag.Count - 1] -ne $True){
                    throw "Setup Downloads failed" 
                }
            }
        }

        $JobFlag = $True
        if($null -eq $HostingConfig){
            # Upgrade Non Enterprise Deployment
            if($OtherConfigs.count -gt 1){
                throw "Cannot Upgrade more than one non Enterprise (Server, Portal, DataStore) Deployments at a time only. Pass only one Site at a time!"
            }
            $NonEnterpiseConfig = $OtherConfigs[0]
            if($JobFlag[$JobFlag.Count - 1] -eq $True -and ($NonEnterpiseConfig.AllNodes | Where-Object { $_.Role -icontains 'Portal'} | Measure-Object).Count -gt 0){
                $JobFlag = Invoke-PortalUpgradeScript -PortalConfig $NonEnterpiseConfig -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode -EnableMSILogging $EnableMSILoggingMode   
            }
            if($JobFlag[$JobFlag.Count - 1] -eq $True -and ($NonEnterpiseConfig.AllNodes | Where-Object { $_.Role -icontains 'Server'} | Measure-Object).Count -gt 0){
                $JobFlag = Invoke-ServerUpgradeScript -cf $NonEnterpiseConfig -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode -EnableMSILogging $EnableMSILoggingMode
            }
            if($JobFlag[$JobFlag.Count - 1] -eq $True -and ($NonEnterpiseConfig.AllNodes | Where-Object { $_.Role -icontains 'DataStore'} | Measure-Object).Count -gt 0 -and ($NonEnterpiseConfig.AllNodes | Where-Object { $_.Role -icontains 'Server'} | Measure-Object).Count -gt 0){
                $JobFlag = Invoke-DataStoreUpgradeScript -DSConfig $NonEnterpiseConfig -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode -EnableMSILogging $EnableMSILoggingMode
            }
        }else{
            # Upgrade Enterprise Deployment
            Write-Information -InformationAction Continue "ArcGIS Enterprise Deployment Upgrade"
            $InsightsUpgradeCD = @{ AllNodes = @( ); }
            if($JobFlag -and $HostingConfig.ConfigData.Insights){
                if(-not($HostingConfig.ConfigData.OldInsightsVersion)){
                    throw "No Insights Version ('OldInsightsVersion') for present installation specified"
                }
                for ( $i = 0; $i -lt $HostingConfig.AllNodes.count; $i++ ){
                    $Role = $HostingConfig.AllNodes[$i].Role
                    if($Role -icontains 'Portal' -or $Role -icontains 'Server'){
                        $NodeToAdd = @{ 
                            NodeName = $HostingConfig.AllNodes[$i].NodeName; 
                        }
                        if($Node.TargetNodeEncryptionCertificateFilePath -and $Node.TargetNodeEncryptionCertificateThumbprint){
                            $NodeToAdd["CertificateFile"] = $Node.TargetNodeEncryptionCertificateFilePath
                            $NodeToAdd["Thumbprint"] = $Node.TargetNodeEncryptionCertificateThumbprint
                        }else{
                            $NodeToAdd["PSDscAllowPlainTextPassword"] = $true
                        }
                        $InsightsUpgradeCD.AllNodes += $NodeToAdd
                    }
                }
                
                $UninstallInsightsUpgradeArgs = @{
                    ConfigurationData = $InsightsUpgradeCD
                    Version = $HostingConfig.ConfigData.OldInsightsVersion 
                }
                $JobFlag = Invoke-DSCJob -ConfigurationName "InsightsUpgradeUninstall" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $UninstallInsightsUpgradeArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
                if($JobFlag[$JobFlag.Count - 1] -ne $True){
                    throw "Uninstall of ArcGIS Insights failed while upgrading"
                }
            }
            # Invoke Upgrade Portal
            if($JobFlag[$JobFlag.Count - 1] -eq $True){
                $JobFlag = Invoke-PortalUpgradeScript -PortalConfig $HostingConfig -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode -EnableMSILogging $EnableMSILoggingMode
            }
            # Invoke Upgrade Server
            if($JobFlag[$JobFlag.Count - 1] -eq $True){
                $JobFlag = Invoke-ServerUpgradeScript -cf $HostingConfig -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode -EnableMSILogging $EnableMSILoggingMode
            }
            # Invoke Upgrade DataStore
            if($JobFlag[$JobFlag.Count - 1] -eq $True){
                $JobFlag = Invoke-DataStoreUpgradeScript -DSConfig $HostingConfig -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode -EnableMSILogging $EnableMSILoggingMode
            }
            # Install Insights if present
            if($JobFlag[$JobFlag.Count - 1] -eq $True -and $HostingConfig.ConfigData.Insights){
                $ServiceAccountIsDomainAccount = if($HostingConfig.ConfigData.Credentials.ServiceAccount.IsDomainAccount){$HostingConfig.ConfigData.Credentials.ServiceAccount.IsDomainAccount}else{ $false}
                $ServiceAccountIsMSA = if($HostingConfig.ConfigData.Credentials.ServiceAccount.IsMSAAccount){$HostingConfig.ConfigData.Credentials.ServiceAccount.IsMSAAccount}else{ $false}
                $ServiceAccountPassword = ConvertTo-SecureString "PlaceHolder" -AsPlainText -Force
                if(-not($ServiceAccountIsMSA)){
                    $ServiceAccountPassword = if( $HostingConfig.ConfigData.Credentials.ServiceAccount.PasswordFilePath ){ Get-Content $HostingConfig.ConfigData.Credentials.ServiceAccount.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $HostingConfig.ConfigData.Credentials.ServiceAccount.Password -AsPlainText -Force }
                }
                $ServiceAccountCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $HostingConfig.ConfigData.Credentials.ServiceAccount.UserName, $ServiceAccountPassword )

                $InsightsInstallUpgradeArgs = @{
                    ConfigurationData = $InsightsUpgradeCD
                    Version = $HostingConfig.ConfigData.InsightsVersion
                    InstallerPath = $HostingConfig.ConfigData.Insights.Installer.Path
                    PatchesDir = $HostingConfig.ConfigData.Insights.Installer.PatchesDir
                    PatchInstallOrder = $HostingConfig.ConfigData.Insights.Installer.PatchInstallOrder
                    ServiceAccount = $ServiceAccountCredential
                    IsServiceAccountDomainAccount = $ServiceAccountIsDomainAccount
                    IsServiceAccountMSA = $ServiceAccountIsMSA
                    EnableMSILogging =  $EnableMSILoggingMode
                    DownloadPatches = if($HostingConfig.ConfigData.DownloadPatches){ $HostingConfig.ConfigData.DownloadPatches }else{ $False }
                }

                $JobFlag = Invoke-DSCJob -ConfigurationName "InsightsUpgradeInstall" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $InsightsInstallUpgradeArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
                if($JobFlag[$JobFlag.Count - 1] -ne $True){
                    throw "Uninstall of ArcGIS Insights failed while upgrading"
                }
            }

            #Upgrade Federated Servers
            if($JobFlag[$JobFlag.Count - 1] -and $OtherConfigs.count -gt 0){
                Write-Information -InformationAction Continue "ArcGIS Federated Servers Upgrade"
                for ( $i = 0; $i -lt $OtherConfigs.count; $i++ ){
                    if($JobFlag[$JobFlag.Count - 1] -and ($OtherConfigs[$i].AllNodes | Where-Object { $_.Role -icontains 'Server'} | Measure-Object).Count -gt 0){
                        $JobFlag = Invoke-ServerUpgradeScript -cf $OtherConfigs[$i] -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode -EnableMSILogging $EnableMSILoggingMode
                    }
                }
            }
        }
        
        if($JobFlag[$JobFlag.Count - 1]){
            Write-Information "Upgrade Successful!"
        }else{
            throw "Upgrade Unsuccessful!"
        }
    }
}

function Invoke-PortalUpgradeScript {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory=$true)]
        $PortalConfig,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $Credential,
        
        [System.Boolean]
        $DebugMode = $False,

        [System.Boolean]
        $EnableMSILogging = $False,

        [System.Boolean]
        $UseWinRMSSL = $False
    )
    Write-Information -InformationAction Continue "ArcGIS Portal Upgrade"
    $PortalLicenseFilePath = $PortalConfig.ConfigData.Portal.LicenseFilePath
    $PortalLicensePassword = $null

    if($PortalConfig.ConfigData.Portal.LicensePasswordFilePath){
        $PortalLicensePassword = (Get-Content $PortalConfig.ConfigData.Portal.LicensePasswordFilePath | ConvertTo-SecureString )
    }elseif($PortalConfig.ConfigData.Portal.LicensePassword){
        $PortalLicensePassword = (ConvertTo-SecureString $PortalConfig.ConfigData.Portal.LicensePassword -AsPlainText -Force)
    }
    
    $PrimaryNodeToAdd = $null
    $StandbyNodeToAdd = $null
    $IsMultiMachinePortal = $False
    
    for ( $i = 0; $i -lt $PortalConfig.AllNodes.count; $i++ ){
        $Role = $PortalConfig.AllNodes[$i].Role
        if($Role -icontains 'Portal'){
            $Node = $PortalConfig.AllNodes[$i]

            $NodeToAdd = @{ 
                NodeName = $Node.NodeName; 
            }
            if($Node.TargetNodeEncryptionCertificateFilePath -and $Node.TargetNodeEncryptionCertificateThumbprint){
                $NodeToAdd["CertificateFile"] = $Node.TargetNodeEncryptionCertificateFilePath
                $NodeToAdd["Thumbprint"] = $Node.TargetNodeEncryptionCertificateThumbprint
            }else{
                $NodeToAdd["PSDscAllowPlainTextPassword"] = $true
            }

            $NodeToAdd["PortalLicenseFilePath"] = if($Node.PortalLicenseFilePath){ $Node.PortalLicenseFilePath } else{ $PortalLicenseFilePath } 
            if($Node.PortalLicenseFilePath){
                if($Node.PortalLicensePassword -or $Node.PortalLicensePasswordFilePath){
                    if($Node.PortalLicensePasswordFilePath){
                        $NodeToAdd["PortalLicensePassword"] = (Get-Content $Node.PortalLicensePasswordFilePath | ConvertTo-SecureString )
                    }elseif($Node.PortalLicensePassword){
                        $NodeToAdd["PortalLicensePassword"] = (ConvertTo-SecureString $Node.PortalLicensePassword -AsPlainText -Force)
                    }
                }
            }else{
                if($null -ne $PortalLicensePassword){
                    $NodeToAdd["PortalLicensePassword"] = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("PlaceHolder", $PortalLicensePassword )
                }
            }
            
            if(-not($PrimaryNodeToAdd)){
                $PrimaryNodeToAdd = $NodeToAdd
            }else{
                $StandbyNodeToAdd = $NodeToAdd
                $IsMultiMachinePortal = $True
            }
        }
    }

    $PortalServiceAccountIsDomainAccount = if($PortalConfig.ConfigData.Credentials.ServiceAccount.IsDomainAccount){$PortalConfig.ConfigData.Credentials.ServiceAccount.IsDomainAccount}else{ $false}
    $PortalServiceAccountIsMSA = if($PortalConfig.ConfigData.Credentials.ServiceAccount.IsMSAAccount){$PortalConfig.ConfigData.Credentials.ServiceAccount.IsMSAAccount}else{ $false}
    $PortalServiceAccountPassword = ConvertTo-SecureString "PlaceHolder" -AsPlainText -Force
    if(-not($PortalServiceAccountIsMSA)){
        $PortalServiceAccountPassword = if( $PortalConfig.ConfigData.Credentials.ServiceAccount.PasswordFilePath ){ Get-Content $PortalConfig.ConfigData.Credentials.ServiceAccount.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $PortalConfig.ConfigData.Credentials.ServiceAccount.Password -AsPlainText -Force }
    }
    $PortalServiceAccountCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $PortalConfig.ConfigData.Credentials.ServiceAccount.UserName, $PortalServiceAccountPassword )
    
    $PortalSiteAdministratorPassword = if($PortalConfig.ConfigData.Portal.PortalAdministrator.PasswordFilePath ){ Get-Content $PortalConfig.ConfigData.Portal.PortalAdministrator.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $PortalConfig.ConfigData.Portal.PortalAdministrator.Password -AsPlainText -Force }
    $PortalSiteAdministratorCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $PortalConfig.ConfigData.Portal.PortalAdministrator.UserName, $PortalSiteAdministratorPassword )

    $PortalUpgradeCD = @{ AllNodes = @( $PrimaryNodeToAdd ); }
    if($IsMultiMachinePortal){
        $PortalUpgradeCD.AllNodes += $StandbyNodeToAdd
    }

    $PortalVersion = $PortalConfig.ConfigData.Version
    $VersionArray = $PortalVersion.Split(".")
    $MinorVersion = if($VersionArray.Length -gt 2){ $VersionArray[2] }else{ 0 }

    $PortalUpgradeArgs = @{
        ConfigurationData = $PortalUpgradeCD 
        Version = $PortalVersion
        OldVersion = $PortalConfig.ConfigData.OldVersion
        InstallerPath = $PortalConfig.ConfigData.Portal.Installer.Path
        PatchesDir = $PortalConfig.ConfigData.Portal.Installer.PatchesDir
        PatchInstallOrder = $PortalConfig.ConfigData.Portal.Installer.PatchInstallOrder
        ServiceAccount = $PortalServiceAccountCredential
        IsServiceAccountDomainAccount = $PortalServiceAccountIsDomainAccount
        IsServiceAccountMSA = $PortalServiceAccountIsMSA
        EnableMSILogging =  $EnableMSILoggingMode
        DownloadPatches = if($PortalConfig.ConfigData.DownloadPatches){ $PortalConfig.ConfigData.DownloadPatches }else{ $False }
    }
    if((($VersionArray[0] -eq 11) -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -ge 8) -or ($PortalVersion -ieq "10.7.1")) -and $PortalConfig.ConfigData.Portal.Installer.WebStylesPath){
        $PortalUpgradeArgs.Add("WebStylesInstallerPath",$PortalConfig.ConfigData.Portal.Installer.WebStylesPath)
    }

    $JobFlag = Invoke-DSCJob -ConfigurationName "PortalUpgrade" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $PortalUpgradeArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
    if($JobFlag[$JobFlag.Count - 1] -ne $True){
        throw "Portal Upgrade Install Step Failed"
    }

    if($JobFlag[$JobFlag.Count - 1] -eq $True){
        if($IsMultiMachinePortal){
            $StandbyPortalPostUpgradeCD = @{ AllNodes = @( $StandbyNodeToAdd ); }
            $StandbyPortalPostUpgradeArgs = @{
                ConfigurationData = $StandbyPortalPostUpgradeCD
                PortalSiteAdministratorCredential = $PortalSiteAdministratorCredential 
                SetOnlyHostNamePropertiesFile = $true
                Version = $PortalConfig.ConfigData.Version 
            }
            $JobFlag = Invoke-DSCJob -ConfigurationName "PortalPostUpgrade" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $StandbyPortalPostUpgradeArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
            if($JobFlag[$JobFlag.Count - 1] -ne $True){
                throw "Portal Post Upgrade Step for Standby Portal Machine Failed"
            }
        }
        
        if($JobFlag[$JobFlag.Count - 1] -eq $True){
            $PortalPostUpgradeCD = @{ AllNodes = @( $PrimaryNodeToAdd ); }

            $PortalPostUpgradeArgs = @{
                ConfigurationData = $PortalPostUpgradeCD
                PortalSiteAdministratorCredential = $PortalSiteAdministratorCredential 
                SetOnlyHostNamePropertiesFile = $false
                Version = $PortalConfig.ConfigData.Version
            }

            $JobFlag = Invoke-DSCJob -ConfigurationName "PortalPostUpgrade" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $PortalPostUpgradeArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
            if($JobFlag[$JobFlag.Count - 1] -ne $True){
                throw "Portal Post Upgrade Step for Primary Portal Machine Failed"
            }
        }
    }
    
    
    $HasPortalWANodes = ($PortalConfig.AllNodes | Where-Object { $_.Role -icontains 'PortalWebAdaptor'} | Measure-Object).Count -gt 0
    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $HasPortalWANodes){
        Write-Information -InformationAction Continue "Portal WebAdaptor Upgrade"
        ForEach($WANode in ($PortalConfig.AllNodes | Where-Object {$_.Role -icontains 'PortalWebAdaptor'})){
            $NodeToAdd = (Invoke-CreateNodeToAdd -Node $WANode -TargetComponent 'WebAdaptor' -PortalContext $PortalConfig.ConfigData.PortalContext)
            $WebAdaptorUpgradeArgs = @{
                ConfigurationData = @{ AllNodes = @($NodeToAdd) }
                WebAdaptorRole = "PortalWebAdaptor"
                Component = "Portal"
                Version = $PortalConfig.ConfigData.Version
                OldVersion = $PortalConfig.ConfigData.OldVersion 
                InstallerPath = $PortalConfig.ConfigData.WebAdaptor.Installer.Path 
                PatchesDir = $PortalConfig.ConfigData.WebAdaptor.Installer.PatchesDir
                PatchInstallOrder = $PortalConfig.ConfigData.WebAdaptor.Installer.PatchInstallOrder
                ComponentHostName = $PrimaryNodeToAdd.NodeName
                SiteAdministratorCredential = $PortalSiteAdministratorCredential
                WebSiteId = if($PortalConfig.ConfigData.WebAdaptor.WebSiteId){ $PortalConfig.ConfigData.WebAdaptor.WebSiteId }else{ 1 }
                EnableMSILogging =  $EnableMSILoggingMode
            }

            $JobFlag = Invoke-DSCJob -ConfigurationName "WebAdaptorUpgrade" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $WebAdaptorUpgradeArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
            if($JobFlag[$JobFlag.Count - 1] -ne $True){
                break
            }
        }
        if($JobFlag[$JobFlag.Count - 1] -ne $True){
            throw "Portal WebAdaptors Upgrade Failed"
        }
    }
    
    $JobFlag
}

function Invoke-ServerUpgradeScript {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory=$true)]
        $cf,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $Credential,
        
        [System.Boolean]
        $DebugMode = $False,

        [System.Boolean]
        $EnableMSILogging = $False,

        [System.Boolean]
        $UseWinRMSSL = $False
    )

    Write-Information -InformationAction Continue "ArcGIS Server Upgrades"

    $cfServiceAccountIsDomainAccount =  if($cf.ConfigData.Credentials.ServiceAccount.IsDomainAccount){$cf.ConfigData.Credentials.ServiceAccount.IsDomainAccount}else{ $false}
    $cfServiceAccountIsMSA = if($cf.ConfigData.Credentials.ServiceAccount.IsMSAAccount){$cf.ConfigData.Credentials.ServiceAccount.IsMSAAccount}else{ $false }
    $cfServiceAccountPassword = ConvertTo-SecureString "PlaceHolder" -AsPlainText -Force
    if(-not($cfServiceAccountIsMSA)){
        $cfServiceAccountPassword = if( $cf.ConfigData.Credentials.ServiceAccount.PasswordFilePath ){ Get-Content $cf.ConfigData.Credentials.ServiceAccount.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $cf.ConfigData.Credentials.ServiceAccount.Password -AsPlainText -Force }
    }
    $cfServiceAccountCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $cf.ConfigData.Credentials.ServiceAccount.UserName, $cfServiceAccountPassword )
    
    $cfSiteAdministratorPassword = if($cf.ConfigData.Server.PrimarySiteAdmin.PasswordFilePath ){ Get-Content $cf.ConfigData.Server.PrimarySiteAdmin.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $cf.ConfigData.Server.PrimarySiteAdmin.Password -AsPlainText -Force }
    $cfSiteAdministratorCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $cf.ConfigData.Server.PrimarySiteAdmin.UserName, $cfSiteAdministratorPassword )
    
    $JobFlag = $True
    # Upgrade Servers
    Write-Information -InformationAction Continue "Server Upgrade"
    $cfPrimaryServerMachine = ""

    $ServerRole = $null
    if($cf.ConfigData.ServerRole){
        $ServerRole = $cf.ConfigData.ServerRole 
        if($ServerRole -ieq "RasterAnalytics" -or $ServerRole -ieq "ImageHosting"){
            $ServerRole = "ImageServer"
        }
    }else{
        $ServerRole = "GeneralPurposeServer"
    }

    $AdditionalServerRoles = @()
    if($ServerRole -ieq "GeneralPurposeServer" -and $cf.ConfigData.AdditionalServerRoles){
        foreach($AdditionalRole in $cf.ConfigData.AdditionalServerRoles){
            if($AdditionalRole -ieq "RasterAnalytics" -or $AdditionalRole -ieq "ImageHosting"){
                $AdditionalServerRoles += "ImageServer"
            }else{
                $AdditionalServerRoles += $AdditionalRole
            }
        }
    }

    for ( $i = 0; $i -lt $cf.AllNodes.count; $i++ ){
        $Node = $cf.AllNodes[$i]
        if($Node.Role -icontains 'Server'){
            $ServerMachine = $Node.NodeName
            if(-not($cfPrimaryServerMachine)){
                $cfPrimaryServerMachine = $ServerMachine
            }

            $NodeToAdd = @{
                NodeName = $ServerMachine
            }

            if($Node.TargetNodeEncryptionCertificateFilePath -and $Node.TargetNodeEncryptionCertificateThumbprint){
                $NodeToAdd["CertificateFile"] = $Node.TargetNodeEncryptionCertificateFilePath
                $NodeToAdd["Thumbprint"] = $Node.TargetNodeEncryptionCertificateThumbprint
            }else{
                $NodeToAdd["PSDscAllowPlainTextPassword"] = $true
            }

            $NodeToAdd["ServerRole"] = $ServerRole
            if($ServerRole -ieq "GeneralPurposeServer" -and ($AdditionalServerRoles.Count -gt 0)){
                $NodeToAdd["AdditionalServerRoles"] = $AdditionalServerRoles
            }

            if($ServerRole -ine "GeoEvent" -and $ServerRole -ine "WorkflowManagerServer"){
                $ServerLicenseFilePath = $cf.ConfigData.Server.LicenseFilePath
                $ServerLicensePassword = $null
                if($cf.ConfigData.Server.LicensePasswordFilePath){
                    $ServerLicensePassword = (Get-Content $cf.ConfigData.Server.LicensePasswordFilePath | ConvertTo-SecureString )
                }elseif($cf.ConfigData.Server.LicensePassword){
                    $ServerLicensePassword = (ConvertTo-SecureString $cf.ConfigData.Server.LicensePassword -AsPlainText -Force)
                }

                if($Node.ServerLicenseFilePath){
                    $ServerLicenseFilePath = $Node.ServerLicenseFilePath
                    $ServerLicensePassword = $null
                    if($Node.ServerLicensePasswordFilePath){
                        $ServerLicensePassword = (Get-Content $Node.ServerLicensePasswordFilePath | ConvertTo-SecureString )
                    }elseif($Node.ServerLicensePassword){
                        $ServerLicensePassword = (ConvertTo-SecureString $Node.ServerLicensePassword -AsPlainText -Force)
                    }
                }

                $NodeToAdd["ServerLicenseFilePath"] = $ServerLicenseFilePath
                if($null -ne $NodeServerLicensePassword){
                    $NodeToAdd["ServerLicensePassword"] = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("PlaceHolder", $ServerLicensePassword)
                }
            }
        
            if(($ServerRole -ieq "GeoEvent" -or ($ServerRole -ieq "GeneralPurposeServer" -and $AdditionalServerRoles -icontains "GeoEvent")) -and $cf.ConfigData.GeoEventServer){
                $GeoeventServerLicenseFilePath =  $cf.ConfigData.GeoEventServer.LicenseFilePath
                $GeoeventServerLicensePassword = $null
                if($cf.ConfigData.GeoEventServer.LicensePasswordFilePath){
                    $GeoeventServerLicensePassword = (Get-Content $cf.ConfigData.GeoEventServer.LicensePasswordFilePath | ConvertTo-SecureString )
                }elseif($cf.ConfigData.GeoEventServer.LicensePassword){
                    $GeoeventServerLicensePassword = (ConvertTo-SecureString $cf.ConfigData.GeoEventServer.LicensePassword -AsPlainText -Force)
                }
                # Per Node - Geoevent
                if($Node.GeoeventServerLicenseFilePath)
                {
                    $GeoeventServerLicenseFilePath = $Node.GeoeventServerLicenseFilePath
                    $GeoeventServerLicensePassword = $null
                    if($Node.GeoeventServerLicensePasswordFilePath){
                        $GeoeventServerLicensePassword = (Get-Content $Node.GeoeventServerLicensePasswordFilePath | ConvertTo-SecureString )
                    }elseif($Node.ServerLicensePassword){
                        $GeoeventServerLicensePassword = (ConvertTo-SecureString $Node.GeoeventServerLicensePassword -AsPlainText -Force)
                    }
                }

                $NodeToAdd["GeoeventServerLicenseFilePath"] = $GeoeventServerLicenseFilePath
                if($null -ne $GeoeventServerLicensePassword){
                    $NodeToAdd["GeoeventServerLicensePassword"] = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("PlaceHolder", $GeoeventServerLicensePassword)
                }
            }
        
            if(($ServerRole -ieq "WorkflowManagerServer" -or ($ServerRole -ieq "GeneralPurposeServer" -and $AdditionalServerRoles -icontains "WorkflowManagerServer")) -and $cf.ConfigData.WorkflowManagerServer){
                $WorkflowManagerServerLicenseFilePath =  $cf.ConfigData.WorkflowManagerServer.LicenseFilePath
                $WorkflowManagerServerLicensePassword = $null
                if($cf.ConfigData.WorkflowManagerServer.LicensePasswordFilePath){
                    $WorkflowManagerServerLicensePassword = (Get-Content $cf.ConfigData.WorkflowManagerServer.LicensePasswordFilePath | ConvertTo-SecureString )
                }elseif($cf.ConfigData.WorkflowManagerServer.LicensePassword){
                    $WorkflowManagerServerLicensePassword = (ConvertTo-SecureString $cf.ConfigData.WorkflowManagerServer.LicensePassword -AsPlainText -Force)
                }

                # Per Node - WorkflowManager
                if($Node.WorkflowManagerServerLicenseFilePath)
                {
                    $WorkflowManagerServerLicenseFilePath = $Node.WorkflowManagerServerLicenseFilePath
                    $WorkflowManagerServerLicensePassword = $null
                    if($Node.WorkflowManagerServerLicensePasswordFilePath){
                        $WorkflowManagerServerLicensePassword = (Get-Content $Node.WorkflowManagerServerLicensePasswordFilePath | ConvertTo-SecureString )
                    }elseif($Node.ServerLicensePassword){
                        $WorkflowManagerServerLicensePassword = (ConvertTo-SecureString $Node.WorkflowManagerServerLicensePassword -AsPlainText -Force)
                    }
                }

                $NodeToAdd["WorkflowManagerServerLicenseFilePath"] = $WorkflowManagerServerLicenseFilePath
                if($null -ne $WorkflowManagerServerLicensePassword){
                    $NodeToAdd["WorkflowManagerServerLicensePassword"] = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("PlaceHolder", $WorkflowManagerServerLicensePassword)
                }
            }
            
            $Version = $cf.ConfigData.Version

            $ServerUpgradeArgs = @{
                ConfigurationData = @{ AllNodes = @( $NodeToAdd ) }
                OldVersion = $cf.ConfigData.OldVersion
                Version = $Version
                ServiceAccount = $cfServiceAccountCredential
                IsServiceAccountDomainAccount = $cfServiceAccountIsDomainAccount
                IsServiceAccountMSA = $cfServiceAccountIsMSA
                InstallerPath = $cf.ConfigData.Server.Installer.Path
                PatchesDir = $cf.ConfigData.Server.Installer.PatchesDir
                PatchInstallOrder = $cf.ConfigData.Server.Installer.PatchInstallOrder
                ContainerImagePaths = if($cf.ConfigData.ServerRole -ieq "NotebookServer"){ $cf.ConfigData.Server.ContainerImagePaths }else{ $null }
                InstallDir = $cf.ConfigData.Server.Installer.InstallDir
                NotebookServerSamplesDataPath = if(($cf.ConfigData.ServerRole -ieq "NotebookServer") -and ($cf.ConfigData.Version.Split(".")[1] -gt 8) -and $cf.ConfigData.Server.Installer.NotebookServerSamplesDataPath){ $cf.ConfigData.Server.Installer.NotebookServerSamplesDataPath }else{ $null }
                IsMultiMachineServerSite = ($cf.AllNodes.count -gt 1)
                EnableMSILogging = $EnableMSILogging
                EnableDotnetSupport = if($Version -ieq "10.9.1" -or $Version -eq "11.0"){ if($cf.ConfigData.Server.Installer.ContainsKey("EnableDotnetSupport")){ $cf.ConfigData.Server.Installer.EnableDotnetSupport } else { $True } } else { $False }
                Extensions = if($cf.ConfigData.Server.Extensions){ $cf.ConfigData.Server.Extensions }else{ $null }
                DownloadPatches = if($cf.ConfigData.DownloadPatches){ $cf.ConfigData.DownloadPatches }else{ $False }
            }

            if($Version -ieq "10.9.1"){
                $ServerUpgradeArgs['EnableArcMapRuntime'] = if($cf.ConfigData.Server.Installer.ContainsKey("EnableArcMapRuntime")){ $cf.ConfigData.Server.Installer.EnableArcMapRuntime } else { $True }
            }

            if(($ServerRole -ieq "GeoEvent" -or ($ServerRole -ieq "GeneralPurposeServer" -and $AdditionalServerRoles -icontains "GeoEvent")) -and $cf.ConfigData.GeoEventServer){
                $ServerUpgradeArgs.Add("GeoEventServerInstaller",$cf.ConfigData.GeoEventServer.Installer.Path)
                $ServerUpgradeArgs.Add("GeoEventServerPatchesDir",$cf.ConfigData.GeoEventServer.Installer.PatchesDir)
                $ServerUpgradeArgs.Add("GeoEventServerPatchInstallOrder",$cf.ConfigData.GeoEventServer.Installer.PatchInstallOrder)
                if($cf.ConfigData.Version.StartsWith("11.") -and $cf.ConfigData.GeoEventServer.UserBackupConfigFiles){
                    $ServerUpgradeArgs.Add("GeoEventUserBackupConfigFiles", $True)
                }
            }

            if(($ServerRole -ieq "WorkflowManagerServer" -or ($ServerRole -ieq "GeneralPurposeServer" -and $AdditionalServerRoles -icontains "WorkflowManagerServer")) -and $cf.ConfigData.WorkflowManagerServer){
                $ServerUpgradeArgs.Add("WorkflowManagerServerInstaller",$cf.ConfigData.WorkflowManagerServer.Installer.Path)
                $ServerUpgradeArgs.Add("WorkflowManagerServerPatchesDir",$cf.ConfigData.WorkflowManagerServer.Installer.PatchesDir)
                $ServerUpgradeArgs.Add("WorkflowManagerServerPatchInstallOrder",$cf.ConfigData.WorkflowManagerServer.Installer.PatchInstallOrder)
            }
            
            $JobFlag = Invoke-DSCJob -ConfigurationName "ServerUpgrade" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $ServerUpgradeArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
            if($JobFlag[$JobFlag.Count - 1] -ne $True){
                break
            }
        }   
    }
    if($JobFlag[$JobFlag.Count - 1] -ne $True){
        throw "Server Upgrade Failed"
    }
    
    #Upgrade Server WebAdaptor
    $HasServerWANodes = ($cf.AllNodes | Where-Object { $_.Role -icontains 'ServerWebAdaptor'} | Measure-Object).Count -gt 0
    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $HasServerWANodes){
        Write-Information -InformationAction Continue "Server WebAdaptor Upgrade"
        ForEach($WANode in ($cf.AllNodes | Where-Object {$_.Role -icontains 'ServerWebAdaptor'})){
            $WAAdminAccessEnabled = if($cf.ConfigData.WebAdaptor.AdminAccessEnabled){ $cf.ConfigData.WebAdaptor.AdminAccessEnabled }else{ $False }
            $NodeToAdd = (Invoke-CreateNodeToAdd -Node $WANode -TargetComponent 'WebAdaptor' -ServerContext $cf.ConfigData.ServerContext -WebAdaptorAdminAccessEnabled $WAAdminAccessEnabled)
            $WebAdaptorUpgradeArgs = @{
                ConfigurationData = @{ AllNodes = @($NodeToAdd) }
                WebAdaptorRole = "ServerWebAdaptor"
                Component = if($ServerRole -ieq "NotebookServer"){ 'NotebookServer' }elseif($ServerRole -ieq "MissionServer"){ 'MissionServer' }else{ 'Server' }
                Version = $cf.ConfigData.Version
                OldVersion = $cf.ConfigData.OldVersion 
                InstallerPath = $cf.ConfigData.WebAdaptor.Installer.Path
                PatchesDir = $cf.ConfigData.WebAdaptor.Installer.PatchesDir
                PatchInstallOrder = $cf.ConfigData.WebAdaptor.Installer.PatchInstallOrder
                ComponentHostName = $cfPrimaryServerMachine
                SiteAdministratorCredential = $cfSiteAdministratorCredential
                WebSiteId = if($cf.ConfigData.WebAdaptor.WebSiteId){ $cf.ConfigData.WebAdaptor.WebSiteId }else{ 1 }
                EnableMSILogging = $EnableMSILoggingMode
                DownloadPatches = if($cf.ConfigData.DownloadPatches){ $cf.ConfigData.DownloadPatches }else{ $False }
            }

            $JobFlag = Invoke-DSCJob -ConfigurationName "WebAdaptorUpgrade" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $WebAdaptorUpgradeArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
            
            if($JobFlag[$JobFlag.Count - 1] -ne $True){
                break
            }
        }
        if($JobFlag[$JobFlag.Count - 1] -ne $True){
            throw "Server WebAdaptors Upgrade Failed"
        }
    }

    $JobFlag
}

function Invoke-DataStoreUpgradeScript {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory=$true)]
        $DSConfig,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $Credential,
        
        [System.Boolean]
        $DebugMode = $False,

        [System.Boolean]
        $EnableMSILogging = $False,

        [System.Boolean]
        $UseWinRMSSL = $False
    )
    Write-Information -InformationAction Continue "ArcGIS DataStore Upgrade"
    $PrimaryServerMachine = ""
    for ( $i = 0; $i -lt $DSConfig.AllNodes.count; $i++ ){
        $Role = $DSConfig.AllNodes[$i].Role
        if($Role -icontains 'Server' -and -not($PrimaryServerMachine)){
            $PrimaryServerMachine  = $DSConfig.AllNodes[$i].NodeName
        }
    }

    $DSServiceAccountIsDomainAccount = if($DSConfig.ConfigData.Credentials.ServiceAccount.IsDomainAccount){$DSConfig.ConfigData.Credentials.ServiceAccount.IsDomainAccount}else{ $false}
    $DSServiceAccountIsMSA = if($DSConfig.ConfigData.Credentials.ServiceAccount.IsMSAAccount){$DSConfig.ConfigData.Credentials.ServiceAccount.IsMSAAccount}else{ $false}  
    $DSSAPassword = ConvertTo-SecureString "PlaceHolder" -AsPlainText -Force
    if(-not($DSServiceAccountIsMSA)){
        $DSSAPassword = if( $DSConfig.ConfigData.Credentials.ServiceAccount.PasswordFilePath ){ Get-Content $DSConfig.ConfigData.Credentials.ServiceAccount.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $DSConfig.ConfigData.Credentials.ServiceAccount.Password -AsPlainText -Force }
    }
    $DSServiceAccountCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $DSConfig.ConfigData.Credentials.ServiceAccount.UserName, $DSSAPassword )
    
    $DSPSAPassword = if($DSConfig.ConfigData.Server.PrimarySiteAdmin.PasswordFilePath ){ Get-Content $DSConfig.ConfigData.Server.PrimarySiteAdmin.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $DSConfig.ConfigData.Server.PrimarySiteAdmin.Password -AsPlainText -Force }
    $DSSiteAdministratorCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $DSConfig.ConfigData.Server.PrimarySiteAdmin.UserName, $DSPSAPassword )
    
    $Version = $DSConfig.ConfigData.Version
    Write-Information -InformationAction Continue "DataStore Upgrade to $Version"
    $cd = @{AllNodes = @()}

    $PrimaryDataStore = $null
    $PrimaryDataStoreCD = @{AllNodes = @()}
    $PrimaryTileCache = $null
    $PrimaryTileCacheCD = @{AllNodes = @()}
    $PrimaryBigDataStore = $null
    $PrimaryBigDataStoreCD = @{AllNodes = @()}
    for ( $i = 0; $i -lt $DSConfig.AllNodes.count; $i++ ){
        $DSNode = $DSConfig.AllNodes[$i]
        if($DSNode.Role -icontains 'DataStore'){
            $DsTypes = $DSNode.DataStoreTypes
            $DSNodeName = $DSNode.NodeName
            
            $NodeToAdd = @{
                NodeName = $DSNodeName
            }

            if($DSNode.TargetNodeEncryptionCertificateFilePath -and $DSNode.TargetNodeEncryptionCertificateThumbprint){
                $NodeToAdd["CertificateFile"] = $DSNode.TargetNodeEncryptionCertificateFilePath
                $NodeToAdd["Thumbprint"] = $DSNode.TargetNodeEncryptionCertificateThumbprint
            }else{
                $NodeToAdd["PSDscAllowPlainTextPassword"] = $true
            }
            
            if($DsTypes -icontains "Relational" -and ($null -eq $PrimaryDataStore))
            {
                $PrimaryDataStore = $DSNodeName
                $PrimaryDataStoreCD.AllNodes += $NodeToAdd
            }
            if($DsTypes -icontains "SpatioTemporal" -and ($null -eq $PrimaryBigDataStore))
            {
                $PrimaryBigDataStore = $DSNodeName
                $PrimaryBigDataStoreCD.AllNodes += $NodeToAdd
            }
            if($DsTypes -icontains "TileCache")
            {
                $NodeToAdd["HasMultiMachineTileCache"] = (($DSConfig.AllNodes | Where-Object { $_.DataStoreTypes -icontains 'TileCache' }  | Measure-Object).Count -gt 1)

                if($null -eq $PrimaryTileCache){
                    $PrimaryTileCache = $DSNodeName
                    $PrimaryTileCacheCD.AllNodes += $NodeToAdd
                }
            }
            $cd.AllNodes += $NodeToAdd 
        }
    }

    $JobFlag = $False
    if($DSConfig.ConfigData.DataStore.EnableFailoverOnPrimaryStop){
        $DataStoreUpgradePreInstallArgs = @{
            ConfigurationData = $cd 
            PrimaryDataStore = $PrimaryDataStore   
        }
        $JobFlag = Invoke-DSCJob -ConfigurationName "DataStoreUpgradePreInstall" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $DataStoreUpgradePreInstallArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
        if($JobFlag[$JobFlag.Count - 1] -ne $True){
            throw "Data Store Pre Upgrade Install Step failed."
        }
    }
    
    if(-not($DSConfig.ConfigData.DataStore.EnableFailoverOnPrimaryStop) -or $JobFlag[$JobFlag.Count - 1] -eq $True){
        foreach($DSNd in $cd.AllNodes){
            $UpgradeDataStoreInstallCD = @{AllNodes = @($DSNd)}
            $DataStoreUpgradeInstallArgs = @{
                ConfigurationData = $UpgradeDataStoreInstallCD
                Version = $DSConfig.ConfigData.Version
                ServiceAccount = $DSServiceAccountCredential
                IsServiceAccountDomainAccount = $DSServiceAccountIsDomainAccount
                IsServiceAccountMSA =   $DSServiceAccountIsMSA
                InstallerPath = $DSConfig.ConfigData.DataStore.Installer.Path
                PatchesDir = $DSConfig.ConfigData.DataStore.Installer.PatchesDir
                PatchInstallOrder = $DSConfig.ConfigData.DataStore.Installer.PatchInstallOrder
                InstallDir = $DSConfig.ConfigData.DataStore.Installer.InstallDir
                EnableMSILogging = $EnableMSILoggingMode
                DownloadPatches = if($DSConfig.ConfigData.DownloadPatches){ $DSConfig.ConfigData.DownloadPatches }else{ $False }
            }

            $JobFlag = Invoke-DSCJob -ConfigurationName "DataStoreUpgradeInstall" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $DataStoreUpgradeInstallArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
            if($JobFlag[$JobFlag.Count - 1] -ne $True){
                break
            }
        }
        if($JobFlag[$JobFlag.Count - 1] -ne $True){
            throw "Data Store Upgrade Install Step failed."
        }
    }
    
    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and -not([string]::IsNullOrEmpty($PrimaryDataStore))){
        $DataStoreUpgradeConfigureArgs = @{
            ConfigurationData = $PrimaryDataStoreCD 
            ServerPrimarySiteAdminCredential = $DSSiteAdministratorCredential
            ServerMachineName = $PrimaryServerMachine
            ContentDirectoryLocation = $DSConfig.ConfigData.DataStore.ContentDirectoryLocation 
            InstallDir = $DSConfig.ConfigData.DataStore.Installer.InstallDir 
            Version = $DSConfig.ConfigData.Version
        }

        $JobFlag = Invoke-DSCJob -ConfigurationName "DataStoreUpgradeConfigure" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $DataStoreUpgradeConfigureArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
        if($JobFlag[$JobFlag.Count - 1] -ne $True){
            throw "Relational Data Store Upgrade Configure Step failed."
        }
    }
    
    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and -not([string]::IsNullOrEmpty($PrimaryTileCache)) -and ($PrimaryDataStore -ne $PrimaryTileCache)){
        $DataStoreUpgradeConfigureArgs = @{
            ConfigurationData = $PrimaryTileCacheCD
            ServerPrimarySiteAdminCredential = $DSSiteAdministratorCredential 
            ServerMachineName = $PrimaryServerMachine
            ContentDirectoryLocation = $DSConfig.ConfigData.DataStore.ContentDirectoryLocation 
            InstallDir = $DSConfig.ConfigData.DataStore.Installer.InstallDir 
            Version = $DSConfig.ConfigData.Version
        }
        $JobFlag = Invoke-DSCJob -ConfigurationName "DataStoreUpgradeConfigure" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $DataStoreUpgradeConfigureArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
        if($JobFlag[$JobFlag.Count - 1] -ne $True){
            throw "Tile Cache Data Store Upgrade Configure Step failed."
        }
    }

    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and -not([string]::IsNullOrEmpty($PrimaryBigDataStore)) -and ($PrimaryDataStore -ne $PrimaryTileCache) -and ($PrimaryDataStore -ne $PrimaryBigDataStore)){
        $DataStoreUpgradeConfigureArgs = @{
            ConfigurationData = $PrimaryBigDataStoreCD
            ServerPrimarySiteAdminCredential = $DSSiteAdministratorCredential 
            ServerMachineName = $PrimaryServerMachine
            ContentDirectoryLocation = $DSConfig.ConfigData.DataStore.ContentDirectoryLocation 
            InstallDir = $DSConfig.ConfigData.DataStore.Installer.InstallDir 
            Version = $DSConfig.ConfigData.Version
        }
        $JobFlag = Invoke-DSCJob -ConfigurationName "DataStoreUpgradeConfigure" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $DataStoreUpgradeConfigureArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
        if($JobFlag[$JobFlag.Count - 1] -ne $True){
            throw "Big Data Store Upgrade Configure Step failed."
        }
    }
    $JobFlag
}

function Invoke-PublishWebApp
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [System.String]
        $NodeName,

        [Parameter(Mandatory=$True)]
        [System.String]
        $WebAppName,

        [Parameter(Mandatory=$True)]
        [System.String]
        $SourceDir,
        
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $Credential,

        [switch]
        $UseSSL,
        
        [switch]
        $DebugSwitch
    )

    $DebugMode = if($DebugSwitch){ $True }else{ $False } 
    $UseWinRMSSL = if($UseSSL){ $True }else{ $False }
    $Arguments = @{
        NodeName = $NodeName 
        WebAppName = $WebAppName 
        SourceDir = $SourceDir
    }

    Invoke-DSCJob -ConfigurationName "DeployWebApp" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $Arguments -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
}

function Invoke-PublishGISService
{
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory=$True)]
        [System.String]
        $ConfigurationParametersFile,
        
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $Credential,
        
        [switch]
        $DebugSwitch,

        [switch]
        $UseSSL
    )
    
    $DebugMode = if($DebugSwitch){ $True }else{ $False } 
    $UseWinRMSSL = if($UseSSL){ $True }else{ $False }
    
    $ConfigurationParamsJSON = (ConvertFrom-Json (Get-Content $ConfigurationParametersFile -Raw))
    $cf = Convert-PSObjectToHashtable $ConfigurationParamsJSON

    $NodeToAdd = @{ NodeName = $cf.ServerNode }
                                
    if($cf.TargetNodeEncryptionCertificateFilePath -and $cf.TargetNodeEncryptionCertificateThumbprint){
        $NodeToAdd["CertificateFile"] = $cf.TargetNodeEncryptionCertificateFilePath
        $NodeToAdd["Thumbprint"] = $cf.TargetNodeEncryptionCertificateThumbprint
    }else{
        $NodeToAdd["PSDscAllowPlainTextPassword"] = $true
    }

    $PublisherAccountPassword = if( $cf.PublisherAccountCredential.PasswordFilePath ){ Get-Content $cf.PublisherAccountCredential.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $cf.PublisherAccountCredential.Password -AsPlainText -Force }
    $PublisherAccountCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $cf.PublisherAccountCredential.UserName, $PublisherAccountPassword )
    
    $ConfigData = @{ 
        ConfigurationData = @{ AllNodes = @($NodeToAdd) }
        PublisherAccountCredential = $PublisherAccountCredential
        PortalHostName = $cf.PortalHostName
        PortalPort = $cf.PortalPort
        PortalContext = $cf.PortalContext
        ServerHostName = $cf.ServerHostName
        ServerContext = $cf.ServerContext
        ServerPort = $cf.ServerPort
        GISServices = $cf.GISServices
    }
    $ConfigurationName = "PublishGISService"
    Invoke-DSCJob -ConfigurationName $ConfigurationName -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $ConfigData -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
}

function Wait-ForServiceToReachDesiredState
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.String]
        $ServiceName,

        [Parameter(Mandatory=$true)]
        [System.String]
        $DesiredState,

        [System.Int32]
        $SleepTimeInSeconds=10,

        [System.Int32]
        $MaxSeconds=300,

        [System.Int32]
        $MaxAttempts=-1
    )
    
    $Attempts  = 0
    $Done      = $false
    $startTime = Get-Date

    while ($true)
    {
        if ($Attempts++ -gt 0) {  # to skip the message for first attempt
            Write-Verbose "Checking state of Service '$ServiceName'. Attempt # $Attempts"        
        }    
        
        $Service = Get-Service -Name $ServiceName -ErrorAction Ignore

        $msg = "Service '$ServiceName' not ready."
        if ($Service) {
            $msg  = "Service '$ServiceName' is in '$($Service.Status)' state."
            # exit if done
            if ($Service.Status -ieq $DesiredState) {
                Write-Verbose $msg
                return
            }
        } 

        Write-Verbose $msg       # not there yet, report current state

        # exit on timeout
        if (($MaxSeconds -gt 0) -and ($(Get-Date) - $startTime).TotalSeconds -ge $MaxSeconds) {
            return
        }  

        # exit on number of attempts
        if (($MaxAttempts -gt 0) -and ($Attempts -ge $MaxAttempts)) {
            return
        }

        Write-Verbose "Waiting $SleepTimeInSeconds seconds."
        Start-Sleep -Seconds $SleepTimeInSeconds
    }
}

function Get-ArcGISProductDetails
{
    [CmdletBinding()]
    param(
        [System.String]
        $ProductName
    )
    #Create an instance of the Registry Object and open the HKLM base key
    $RegistryInstance = [microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$env:computername) 
    $ResultsArray = @()
    foreach($UninstallKey in @("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall","SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall") ){
        #Drill down into the Uninstall key using the OpenSubKey Method
        $RegistryKey = $RegistryInstance.OpenSubKey($UninstallKey) 
        #Retrieve an array of string that contain all the subkey names
        $RegistrySubKeys = $RegistryKey.GetSubKeyNames() 
        #Open each Subkey and use GetValue Method to return the required values for each
        foreach($key in $RegistrySubKeys){
            if($key.EndsWith('}')){
                $UninstallSubKey = $RegistryInstance.OpenSubKey($UninstallKey + "\\" + $key ) 
                $Publisher = $UninstallSubKey.GetValue("Publisher")
                $DisplayName = $UninstallSubKey.GetValue("DisplayName")
                if($DisplayName -imatch $ProductName -and $Publisher -ieq "Environmental Systems Research Institute, Inc."){
                    if(($ProductName -ieq "ArcGIS Notebook Server" -and -not($DisplayName -imatch "Samples Data")) `
                        -or ($ProductName -ieq "portal" -and -not($DisplayName -imatch "Web Styles")) `
                        -or ($ProductName -ine "portal" -and $ProductName -ine "ArcGIS Notebook Server") `
                        -or ($ProductName -ieq "ArcGIS Server" -and -not($DisplayName -imatch "Deep Learning Libraries for ArcGIS Server"))){
                        $ResultsArray += New-Object PSObject -Property @{
                            Name = $DisplayName
                            Version = $UninstallSubKey.GetValue("DisplayVersion")
                            InstallLocation = $UninstallSubKey.GetValue("InstallLocation")
                            IdentifyingNumber = $key
                        }
                    }
                }
            }
        } 
    }
    $ResultsArray
}

Export-ModuleMember -Function Get-FQDN, Invoke-ArcGISConfiguration, Invoke-PublishWebApp, `
                                Invoke-BuildArcGISAzureImage, Invoke-PublishGISService, `
                                Get-ArcGISProductDetails, Wait-ForServiceToReachDesiredState
