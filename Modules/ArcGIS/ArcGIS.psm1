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
                                
    if($Node.TargetNodeEncyrptionCertificateFilePath -and $Node.TargetNodeEncyrptionCertificateThumbprint){
        $NodeToAdd["CertificateFile"] = $Node.TargetNodeEncyrptionCertificateFilePath
        $NodeToAdd["Thumbprint"] = $Node.TargetNodeEncyrptionCertificateThumbprint
    }else{
        $NodeToAdd["PSDscAllowPlainTextPassword"] = $true
    }

    if($Node.SslCertificates -and (($Node.SslCertificates | Where-Object { $_.Target -icontains  $TargetComponent }  | Measure-Object).Count -gt 0) ){
        $SSLCertificate = ($Node.SslCertificates | Where-Object { $_.Target -icontains $TargetComponent }  | Select-Object -First 1)
        $SSLPassword = if($SSLCertificate.PasswordFilePath){ Get-Content $SSLCertificate.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $SSLCertificate.Password -AsPlainText -Force }

        $NodeToAdd["SSLCertificate"] =  @{
            Path = $SSLCertificate.Path
            CName = $SSLCertificate.CNameFQDN
            Password = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("SSLCertPlaceholder",$SSLPassword)
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

        $InstallConfigurationParamsHashtable = Convert-PSObjectToHashtable $ConfigurationParamsJSON

        $InstallCD = @{
            AllNodes = @() 
            ConfigData = $InstallConfigurationParamsHashtable.ConfigData
        }

        for ( $i = 0; $i -lt $ConfigurationParamsHashtable.AllNodes.Count; $i++ ){
            $Node = $ConfigurationParamsHashtable.AllNodes[$i]
            $NodeToAdd = @{ NodeName = $Node.NodeName; Role = $Node.Role }
            if($Node.TargetNodeEncyrptionCertificateFilePath -and $Node.TargetNodeEncyrptionCertificateThumbprint){
                $NodeToAdd["CertificateFile"] = $Node.TargetNodeEncyrptionCertificateFilePath
                $NodeToAdd["Thumbprint"] = $Node.TargetNodeEncyrptionCertificateThumbprint
            }else{
                $NodeToAdd["PSDscAllowPlainTextPassword"] = $true
            }
            if($Node.Role -icontains 'ServerWebAdaptor'){
                $NodeToAdd["ServerContext"] = if($Node.ServerContext){ $Node.ServerContext }else{ $ConfigurationParamsHashtable.ConfigData.ServerContext }
            }

            $InstallCD.AllNodes += $NodeToAdd
        }

        if($InstallCD.ConfigData.Credentials){
            $InstallCD.ConfigData.Remove("Credentials")
        }
        if($InstallCD.ConfigData.SslRootOrIntermediate){
            $InstallCD.ConfigData.Remove("SslRootOrIntermediate")
        }
        if($InstallCD.ConfigData.FileShareLocalPath -and ($Mode -ne "Uninstall")){
            $InstallCD.ConfigData.Remove("FileShareLocalPath")
        }
        if($InstallCD.ConfigData.FileShareName -and ($Mode -ne "Uninstall")){
            $InstallCD.ConfigData.Remove("FileShareName")
        }
        if($InstallCD.ConfigData.Server){
            if($InstallCD.ConfigData.Server.LicenseFilePath){
                $InstallCD.ConfigData.Server.Remove("LicenseFilePath")
            }
            if($InstallCD.ConfigData.Server.LicensePassword){
                $InstallCD.ConfigData.Server.Remove("LicensePassword")
            }
            if($InstallCD.ConfigData.Server.ServerDirectoriesRootLocation){
                $InstallCD.ConfigData.Server.Remove("ServerDirectoriesRootLocation")
            }
            if($InstallCD.ConfigData.Server.ServerLogsLocation){
                $InstallCD.ConfigData.Server.Remove("ServerLogLocations")
            }
            if($InstallCD.ConfigData.Server.LocalRepositoryPath){
                $InstallCD.ConfigData.Server.Remove("LocalRepositoryPath")
            }
            if($InstallCD.ConfigData.Server.ServerDirectories){
                $InstallCD.ConfigData.Server.Remove("ServerDirectories")
            }
            if($InstallCD.ConfigData.Server.ConfigStoreLocation){
                $InstallCD.ConfigData.Server.Remove("ConfigStoreLocation")
            }
        }
        if($InstallCD.ConfigData.GeoEventServer){
            if($InstallCD.ConfigData.GeoEventServer.LicenseFilePath){
                $InstallCD.ConfigData.GeoEventServer.Remove("LicenseFilePath")
            }
            if($InstallCD.ConfigData.GeoEventServer.LicensePassword){
                $InstallCD.ConfigData.GeoEventServer.Remove("LicensePassword")
            }
        }
        if($InstallCD.ConfigData.WorkflowManagerServer){
            if($InstallCD.ConfigData.WorkflowManagerServer.LicenseFilePath){
                $InstallCD.ConfigData.WorkflowManagerServer.Remove("LicenseFilePath")
            }
            if($InstallCD.ConfigData.WorkflowManagerServer.LicensePassword){
                $InstallCD.ConfigData.WorkflowManagerServer.Remove("LicensePassword")
            }
        }
        if($InstallCD.ConfigData.Portal){
            if($InstallCD.ConfigData.Portal.LicenseFilePath){
                $InstallCD.ConfigData.Portal.Remove("LicenseFilePath")
            }
            if($InstallCD.ConfigData.Portal.LicensePassword){
                $InstallCD.ConfigData.Portal.Remove("LicensePassword")
            }
            if($InstallCD.ConfigData.Portal.PortalLicenseUserTypeId){
                $InstallCD.ConfigData.Portal.Remove("PortalLicenseUserTypeId")
            }
            if($InstallCD.ConfigData.Portal.ContentDirectoryLocation){
                $InstallCD.ConfigData.Portal.Remove("ContentDirectoryLocation")
            }
        }
        if($InstallCD.ConfigData.DataStore -and $InstallCD.ConfigData.DataStore.ContentDirectoryLocation){
            $InstallCD.ConfigData.DataStore.Remove("ContentDirectoryLocation")
        }
        if($InstallCD.ConfigData.WebAdaptor -and $InstallCD.ConfigData.WebAdaptor.AdminAccessEnabled){
            $InstallCD.ConfigData.WebAdaptor.Remove("AdminAccessEnabled")
        }
        if($InstallCD.ConfigData.Pro -and $InstallCD.ConfigData.Pro.LicenseFilePath){
            $InstallCD.ConfigData.Pro.Remove("LicenseFilePath")
        }
        if($InstallCD.ConfigData.Desktop -and $InstallCD.ConfigData.Desktop.LicenseFilePath){
            $InstallCD.ConfigData.Desktop.Remove("LicenseFilePath")
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

        if($JobFlag[$JobFlag.Count - 1] -eq $True -and ($Mode -ieq "InstallLicense" -or $Mode -ieq "InstallLicenseConfigure")){
            $JobFlag = $False
            
            $ServerCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'Server' } | Measure-Object).Count -gt 0)
            $PortalCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'Portal' } | Measure-Object).Count -gt 0)
            $DesktopCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'Desktop' }  | Measure-Object).Count -gt 0)
            $ProCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'Pro' }  | Measure-Object).Count -gt 0)
            $LicenseManagerCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'LicenseManager' } | Measure-Object).Count -gt 0)
            $EnterpriseMajorVersion = $null

            $EnterpriseSkipLicenseStep = $true
            if($ConfigurationParamsHashtable.ConfigData.Version -and ($ServerCheck -or $PortalCheck)){
                $EnterpriseSkipLicenseStep = $false
                $EnterpriseVersionArray = $ConfigurationParamsHashtable.ConfigData.Version.Split(".")
                $EnterpriseMajorVersion = $EnterpriseVersionArray[1]
                if(($EnterpriseMajorVersion -ge 7) -and -not($ServerCheck) -and $PortalCheck){
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
                    
                    if($Node.TargetNodeEncyrptionCertificateFilePath -and $Node.TargetNodeEncyrptionCertificateThumbprint){
                        $NodeToAdd["CertificateFile"] = $Node.TargetNodeEncyrptionCertificateFilePath
                        $NodeToAdd["Thumbprint"] = $Node.TargetNodeEncyrptionCertificateThumbprint
                    }else{
                        $NodeToAdd["PSDscAllowPlainTextPassword"] = $true
                    }
                    
                    $Role = @()
                    if($Node.Role -icontains "Server"){
                        $ServerRole = $null
                        $ServerLicenseFilePath = $ConfigurationParamsHashtable.ConfigData.Server.LicenseFilePath
                        $ServerLicensePassword = $null
                        
                        if($ConfigurationParamsHashtable.ConfigData.ServerRole)
                        {   
                            $ServerRole = $ConfigurationParamsHashtable.ConfigData.ServerRole
                            if($ServerRole -ieq "RasterAnalytics" -or $ServerRole -ieq "ImageHosting"){
                                $ServerRole = "ImageServer"
                            }
                        }else{
                            $ServerRole = "GeneralPurposeServer"
                        }
                        
                        if($ConfigurationParamsHashtable.ConfigData.Server.LicensePasswordFilePath){
                            $ServerLicensePassword = (Get-Content $ConfigurationParamsHashtable.ConfigData.Server.LicensePasswordFilePath | ConvertTo-SecureString )
                        }elseif($ConfigurationParamsHashtable.ConfigData.Server.LicensePassword){
                            $ServerLicensePassword = (ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.Server.LicensePassword -AsPlainText -Force)
                        }

                        if($ServerRole -ieq "GeoEvent"){
                            $ServerLicenseFilePath =  $ConfigurationParamsHashtable.ConfigData.GeoEventServer.LicenseFilePath
                            $ServerLicensePassword = $null
                            if($ConfigurationParamsHashtable.ConfigData.GeoEventServer.LicensePasswordFilePath){
                                $ServerLicensePassword = (Get-Content $ConfigurationParamsHashtable.ConfigData.GeoEventServer.LicensePasswordFilePath | ConvertTo-SecureString )
                            }elseif($ConfigurationParamsHashtable.ConfigData.GeoEventServer.LicensePassword){
                                $ServerLicensePassword = (ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.GeoEventServer.LicensePassword -AsPlainText -Force)
                            }
                        }

                        if($ServerRole -ieq "WorkflowManagerServer"){
                            $ServerLicenseFilePath =  $ConfigurationParamsHashtable.ConfigData.WorkflowManagerServer.LicenseFilePath
                            $ServerLicensePassword = $null
                            if($ConfigurationParamsHashtable.ConfigData.WorkflowManagerServer.LicensePasswordFilePath){
                                $ServerLicensePassword = (Get-Content $ConfigurationParamsHashtable.ConfigData.WorkflowManagerServer.LicensePasswordFilePath | ConvertTo-SecureString )
                            }elseif($ConfigurationParamsHashtable.ConfigData.WorkflowManagerServer.LicensePassword){
                                $ServerLicensePassword = (ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.WorkflowManagerServer.LicensePassword -AsPlainText -Force)
                            }
                        }
                        
                        if($Node.ServerLicenseFilePath -and ($Node.ServerLicensePassword -or $Node.ServerLicensePasswordFilePath))
                        {
                            $ServerLicenseFilePath = $Node.ServerLicenseFilePath
                            $ServerLicensePassword = $null
                            if($Node.ServerLicensePasswordFilePath){
                                $ServerLicensePassword = (Get-Content $Node.ServerLicensePasswordFilePath | ConvertTo-SecureString )
                            }elseif($Node.ServerLicensePassword){
                                $ServerLicensePassword = (ConvertTo-SecureString $Node.ServerLicensePassword -AsPlainText -Force)
                            }
                        }

                        $NodeToAdd.Role += "Server"
                        $NodeToAdd["ServerRole"] = $ServerRole
                        $NodeToAdd["ServerLicenseFilePath"] = $ServerLicenseFilePath
                        if($null -ne $ServerLicensePassword){
                            $NodeToAdd["ServerLicensePassword"] = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("PlaceHolder", $ServerLicensePassword)
                        }
                    }
                    if($Node.Role -icontains "Portal"){
                        if($EnterpriseMajorVersion -lt 7){
                            $PortalLicenseFilePath = $ConfigurationParamsHashtable.ConfigData.Portal.LicenseFilePath
                            $PortalLicensePassword = $null

                            if($ConfigurationParamsHashtable.ConfigData.Portal.LicensePasswordFilePath){
                                $PortalLicensePassword = (Get-Content $ConfigurationParamsHashtable.ConfigData.Portal.LicensePasswordFilePath | ConvertTo-SecureString )
                            }elseif($ConfigurationParamsHashtable.ConfigData.Portal.LicensePassword){
                                $PortalLicensePassword = (ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.Portal.LicensePassword -AsPlainText -Force)
                            }

                            if($Node.PortalLicenseFilePath -and $Node.PortalLicenseFilePath)
                            {
                                $PortalLicenseFilePath=$Node.PortalLicenseFilePath
                                $PortalLicensePassword = $null
                                if($Node.PortalLicensePasswordFilePath){
                                    $PortalLicensePassword = (Get-Content $Node.PortalLicensePasswordFilePath | ConvertTo-SecureString )
                                }elseif($Node.PortalLicensePassword){
                                    $PortalLicensePassword = (ConvertTo-SecureString $Node.PortalLicensePassword -AsPlainText -Force)
                                }
                            }

                            $NodeToAdd.Role += "Portal"
                            $NodeToAdd["PortalLicenseFilePath"] = $PortalLicenseFilePath
                            if($null -ne $PortalLicensePassword){
                                $NodeToAdd["PortalLicensePassword"] = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("PlaceHolder", $PortalLicensePassword )
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
                            if($ConfigurationParamsHashtable.ConfigData.Portal.ContentDirectoryLocation.StartsWith('\')) { 
                                $ValidatePortalFileShare = $True
                            } else {
                                throw "Config Directory Location path is not a fileshare path"
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
                        if($ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreLocation.StartsWith('\') -and $ConfigurationParamsHashtable.ConfigData.Server.ServerDirectoriesRootLocation.StartsWith('\')){
                            if($ConfigurationParamsHashtable.ConfigData.Server.ServerDirectories){
                                foreach($dir in $ConfigurationParamsHashtable.ConfigData.Server.ServerDirectories){
                                    if(-not($dir.physicalPath.StartsWith('\'))){
                                        throw "One or more of Server Directories Location is not a fileshare path"
                                    }
                                }
                            }
                            $ValidateServerFileShare = $True
                        } else {
                            throw "One or both of Config Store Location and Server Directories Root Location is not a fileshare path"
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
                    
                    $ADServiceCredential = $null
                    if($ConfigurationParamsHashtable.ConfigData.Credentials.ADServiceUser){
                        $ADServicePassword = if($ConfigurationParamsHashtable.ConfigData.Credentials.ADServiceUser.PasswordFilePath ){ Get-Content $ConfigurationParamsHashtable.ConfigData.Credentials.ADServiceUser.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.Credentials.ADServiceUser.Password -AsPlainText -Force }
                        $ADServiceCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $ConfigurationParamsHashtable.ConfigData.Credentials.ADServiceUser.UserName, $ADServicePassword )
                    }
                    
                    $PrimaryServerMachine = $null
                    $PrimaryPortalMachine = $null
                    $PrimaryDataStore = $null
                    $PrimaryBigDataStore = $null
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
                    $DataStoreCertificateUpdateCD = @{ AllNodes = @() }

                    $RasterDataStoreItemCD = @{ AllNodes = @() }

                    $PortalWAMachines = @()
                    $ServerWAMachines = @()

                    for ( $i = 0; $i -lt $ConfigurationParamsHashtable.AllNodes.count; $i++ ){
                        $Node = $ConfigurationParamsHashtable.AllNodes[$i]
                        $NodeName = $Node.NodeName
                        
                        if($Node.Role -icontains 'FileShare'){
                            if($null -eq $FileShareMachine){ $FileShareMachine = $Node }
                            $FileShareCD.AllNodes += (Invoke-CreateNodeToAdd -Node $Node -TargetComponent 'FileShare')
                        }
                        if($Node.Role -icontains 'RasterDataStoreItem'){
                            $RasterDataStoreItemCD.AllNodes += (Invoke-CreateNodeToAdd -Node $Node -TargetComponent 'RasterDataStoreItem')
                        }
                        if($Node.Role -icontains 'Server') {
                            if($null -eq $PrimaryServerMachine){ $PrimaryServerMachine = $Node }
                            $ServerCD.AllNodes += (Invoke-CreateNodeToAdd -Node $Node -TargetComponent 'Server')
                        }
                        if($Node.Role -icontains 'Portal') {
                            if($null -eq $PrimaryPortalMachine){ $PrimaryPortalMachine = $Node }
                            $PortalCD.AllNodes += (Invoke-CreateNodeToAdd -Node $Node -TargetComponent 'Portal')
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
                                if($null -eq $PrimaryDataStore){
                                    $PrimaryDataStore = $Node
                                }
                                $RelationalDataStoreCD.AllNodes += (Invoke-CreateNodeToAdd -Node $Node -TargetComponent 'DataStore' -DataStoreType "Relational")
                            }
                            if($DsTypes -icontains "SpatioTemporal"){
                                if($null -eq $PrimaryBigDataStore){
                                    $PrimaryBigDataStore = $Node
                                }
                                $BigDataStoreCD.AllNodes += (Invoke-CreateNodeToAdd -Node $Node -TargetComponent 'DataStore' -DataStoreType "SpatioTemporal")
                            }
                            if($DsTypes -icontains "TileCache"){
                                if($null -eq $PrimaryTileCache){
                                    $PrimaryTileCache = $Node
                                }
                                $TileCacheDataStoreCD.AllNodes += (Invoke-CreateNodeToAdd -Node $Node -TargetComponent 'DataStore' -DataStoreType "TileCache")
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
                            if($ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreLocation.StartsWith('\') -and $ConfigurationParamsHashtable.ConfigData.Server.ServerDirectoriesRootLocation.StartsWith('\')){
                                $FilePathsArray += $ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreLocation
                                $FilePathsArray += $ConfigurationParamsHashtable.ConfigData.Server.ServerDirectoriesRootLocation
                            }else{
                                throw "One or both of the Config Store Location and Server Directories Root Location is not a file share location"
                            }
                        }
                        if($ConfigurationParamsHashtable.ConfigData.Portal){
                            if($ConfigurationParamsHashtable.ConfigData.Portal.ContentDirectoryLocation.StartsWith('\')){
                                $FilePathsArray += $ConfigurationParamsHashtable.ConfigData.Portal.ContentDirectoryLocation
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

                    $Version = $ConfigurationParamsHashtable.ConfigData.Version
                    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $ServerCheck){
                        $JobFlag = $False
                        $ServerArgs = @{
                            ConfigurationData = $ServerCD
                            Version = $Version
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
                            SslRootOrIntermediate = ($ConfigurationParamsHashtable.ConfigData.SslRootOrIntermediate | ConvertTo-Json)
                            UsesSSL = $UseSSL
                            DebugMode = $DebugMode
                        }

                        if($ConfigurationParamsHashtable.ConfigData.ServerRole -ieq "NotebookServer" -or $ConfigurationParamsHashtable.ConfigData.ServerRole -ieq "MissionServer"){
                            if($ConfigurationParamsHashtable.ConfigData.Server.ContainerImagePaths){
                                $ServerArgs["ContainerImagePaths"] = $ConfigurationParamsHashtable.ConfigData.Server.ContainerImagePaths
                            }        
                            
                            if(($Version.Split(".")[1] -gt 8) -and $ConfigurationParamsHashtable.ConfigData.Server.Installer.NotebookServerSamplesDataPath){
                                $ServerArgs["ExtractNotebookServerSamplesData"] = $True
                            }                        
                        }else{
                            $ServerArgs["ServerRole"] = $ConfigurationParamsHashtable.ConfigData.ServerRole
                            $ServerArgs["OpenFirewallPorts"] = ($PortalCheck -or $DataStoreCheck -or $IsServerWAOnSeparateMachine)
                            $ServerArgs["RegisteredDirectories"] = ($ConfigurationParamsHashtable.ConfigData.Server.RegisteredDirectories | ConvertTo-Json)
                            $ServerArgs["LocalRepositoryPath"] = if($ConfigurationParamsHashtable.ConfigData.Server.LocalRepositoryPath){$ConfigurationParamsHashtable.ConfigData.Server.LocalRepositoryPath}else{$null}
                        }

                        if($ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount){
                            $ServerConfigStoreCloudStorageCredentials = $null
                            if($ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount){
                                $ServerConfigStoreCloudStorageAccountPassword = if( $ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.PasswordFilePath ){ Get-Content $ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.Password -AsPlainText -Force }
                                $ServerConfigStoreCloudStorageCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.UserName, $ServerConfigStoreCloudStorageAccountPassword )
                            }else{
                                throw "No credentials provided for Cloud Storage for $($ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.CloudStorageType)"
                            }

                            $ServerArgs["ConfigStoreCloudStorageType"] = $ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.CloudStorageType
                            $ServerArgs["ConfigStoreAzureFileShareName"]  = if($ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.CloudStorageType -ieq "AzureFiles"){ $ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.AzureFileShareName }else{ $null }
                            $ServerArgs["ConfigStoreCloudNamespace"] = $ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreCloudStorageAccount.CloudNamespace
                            $ServerArgs["ConfigStoreCloudStorageCredentials"] = $ServerConfigStoreCloudStorageCredentials
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

                    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $ServerCheck -and -not(($null -eq $ServerExternalDNSHostName) -and -not($ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancer))){
                        $ServerSettingsArgs = @{
                            ConfigurationData = $ServerCD
                            ServerPrimarySiteAdminCredential = $ServerPrimarySiteAdminCredential
                            PrimaryServerMachine = $PrimaryServerMachine.NodeName
                            ExternalDNSHostName = $ServerExternalDNSHostName 
                            ServerContext = $ConfigurationParamsHashtable.ConfigData.ServerContext
                        }
                        $ConfigurationName = "ArcGISNotebookServerSettings"
                        if($ConfigurationParamsHashtable.ConfigData.ServerRole -eq "MissionServer"){
                            $ConfigurationName = "ArcGISMissionServerSettings"
                        }
                        
                        if($ConfigurationParamsHashtable.ConfigData.ServerRole -ne "NotebookServer" -and $ConfigurationParamsHashtable.ConfigData.ServerRole -ne "MissionServer"){
                            $ConfigurationName = "ArcGISServerSettings"
                            $ServerSettingsArgs["IsWorkflowManagerDeployment"] = if($ConfigurationParamsHashtable.ConfigData.ServerRole -eq "WorkflowManagerServer"){ $True }else{ $False }
                            $ServerSettingsArgs["InternalLoadBalancer"] = if($ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancer){ $ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancer }else{ $null }
                            $ServerSettingsArgs["InternalLoadBalancerPort"] = if($ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancerPort){ $ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancerPort }else{ $null }

                        }

                        $JobFlag = Invoke-DSCJob -ConfigurationName $ConfigurationName -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $ServerSettingsArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
                    }

                    $VersionArray = $Version.Split(".")
                    $MajorVersion = $VersionArray[1]
                    $MinorVersion = if($VersionArray.Count -eq 3){ $VersionArray[2] }else { 0 }

                    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $PortalCheck){
                        $JobFlag = $False
                        $PortalArgs = @{
                            ConfigurationData = $PortalCD
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
                            LicenseFilePath = if($ConfigurationParamsHashtable.ConfigData.Portal.LicenseFilePath -and ($MajorVersion -ge 7)){ $ConfigurationParamsHashtable.ConfigData.Portal.LicenseFilePath }else{ $null }
                            UserLicenseTypeId = if($ConfigurationParamsHashtable.ConfigData.Portal.PortalLicenseUserTypeId -and ($MajorVersion -ge 7)){ $ConfigurationParamsHashtable.ConfigData.Portal.PortalLicenseUserTypeId }else{ $null }
                            ADServiceCredential = $ADServiceCredential
                            EnableAutomaticAccountCreation = if($ConfigurationParamsHashtable.ConfigData.Portal.EnableAutomaticAccountCreation){ $true }else{ $false }
                            DefaultRoleForUser = if($ConfigurationParamsHashtable.ConfigData.Portal.DefaultRoleForUser){ $ConfigurationParamsHashtable.ConfigData.Portal.DefaultRoleForUser }else{ $null }
                            DefaultUserLicenseTypeIdForUser = if($ConfigurationParamsHashtable.ConfigData.Portal.DefaultUserLicenseTypeIdForUser -and ($MajorVersion -ge 7)){ $ConfigurationParamsHashtable.ConfigData.Portal.DefaultUserLicenseTypeIdForUser }else{ $null }
                            DisableServiceDirectory = if($ConfigurationParamsHashtable.ConfigData.Portal.DisableServiceDirectory){ $true }else{ $false }
                            SslRootOrIntermediate = ($ConfigurationParamsHashtable.ConfigData.SslRootOrIntermediate | ConvertTo-Json)
                            UsesSSL = $UseSSL
                            DebugMode = $DebugMode
                        }
                        if($ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount){
                            $PortalCloudStorageCredentials = $null
                            if($ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount){
                                $PortalCloudStorageAccountPassword = if( $ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.PasswordFilePath ){ Get-Content $ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.Password -AsPlainText -Force }
                                $PortalCloudStorageCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.UserName, $PortalCloudStorageAccountPassword )
                            }else{
                                throw "No credentials provided for Cloud Storage for $($ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.CloudStorageType)"
                            }
                            $PortalArgs["CloudStorageType"] = $ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.CloudStorageType
                            $PortalArgs["AzureFileShareName"]  = if($ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.CloudStorageType -ieq "AzureFiles"){ $ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.AzureFileShareName }else{ $null }
                            $PortalArgs["CloudNamespace"] = $ConfigurationParamsHashtable.ConfigData.Portal.PortalContentCloudStorageAccount.CloudNamespace
                            $PortalArgs["CloudStorageCredentials"] = $PortalCloudStorageCredentials
                        }

                        if($MajorVersion -gt 8 -or ($MajorVersion -eq 8 -and $MinorVersion -eq 1)){
                            if($ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings){
                                $PortalArgs["EnableEmailSettings"] = $True
                                $PortalArgs["EmailSettingsSMTPServerAddress"] = $ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings.SMTPServerAddress
                                $PortalArgs["EmailSettingsFrom"] = $ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings.From
                                $PortalArgs["EmailSettingsLabel"] = $ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings.Label
                                $PortalArgs["EmailSettingsAuthenticationRequired"] = $ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings.AuthenticationRequired
                                if($ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings.AuthenticationRequired){
                                    $EmailSettingsPassword = if( $ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings.PasswordFilePath ){ Get-Content $ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings.Password -AsPlainText -Force }
                                    $EmailSettingsCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings.UserName, $EmailSettingsPassword )
                                    $PortalArgs["EmailSettingsCredential"] = $EmailSettingsCredential
                                }
                                $PortalArgs["EmailSettingsSMTPPort"] = $ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings.SMTPPort
                                $PortalArgs["EmailSettingsEncryptionMethod"] = $ConfigurationParamsHashtable.ConfigData.Portal.EmailSettings.EncryptionMethod
                            }else{
                                $PortalArgs["EnableEmailSettings"] = $False
                            }
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

                    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $PortalCheck -and -not(($null -eq $PortalExternalDNSHostName) -and -not($ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancer))){
                        $PortalSettingsArgs = @{
                            ConfigurationData = $PortalCD
                            PrimaryPortalMachine = $PrimaryPortalMachine.NodeName
                            PortalAdministratorCredential = $PortalAdministratorCredential
                            ExternalDNSHostName = $PortalExternalDNSHostName
                            PortalContext = if($null -ne $PortalExternalDNSHostName){ $ConfigurationParamsHashtable.ConfigData.PortalContext }else{ $null }
                            InternalLoadBalancer = if($ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancer){ $ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancer }else{ $null }
                            InternalLoadBalancerPort = if($ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancerPort){ $ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancerPort }else{ $null }
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
                        }
                        if($ServerCheck){
                            $WebAdaptorArgs["ServerRole"] = $ConfigurationParamsHashtable.ConfigData.ServerRole
                        }

                        $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISWebAdaptor" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $WebAdaptorArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
                    }
                    
                    if(($JobFlag[$JobFlag.Count - 1] -eq $True) -and $RelationalDataStoreCheck){
                        $JobFlag = $False
                        $RelationalDataStoreArgs = @{
                            Version = $Version
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
                                if($MajorVersion -eq 6 -and $MinorVersion -eq 0){
                                    if($BackupObject.Name -ne "DEFAULT"){
                                        throw "Backup for Relational DataStore cannot have a backup name other than 'DEFAULT' at $Version"
                                    }
                                    if($BackupObject.Type -ne "fs"){
                                        throw "Backup for Relational DataStore can only be a local path or shared file location at $Version"
                                    }
                                }else{
                                    if($BackupObject.IsDefault -and $BackupObject.Type -ne "fs"){
                                        throw "Default back up for Relational DataStore can only be a local path or shared file location at $Version"
                                    }
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
                                            if($Pos -gt -1) 
                                            {
                                                $EndpointSuffix = $BackupObject.CloudStorageAccount.UserName.Substring($Pos + 6)
                                                if(-not(($MajorVersion -ge 7) -or (($MajorVersion -le 6) -and ($EndpointSuffix -eq "core.windows.net")))){
                                                    throw "Error - Backups to Azure Cloud Storage with endpoint suffix $EndpointSuffix is not supported for ArcGIS Enterprise 10.6.1 and below"
                                                }
                                            }
                                            else
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
                            Version = $Version
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
                                            if($Pos -gt -1) 
                                            {
                                                $EndpointSuffix = $BackupObject.CloudStorageAccount.UserName.Substring($Pos + 6)
                                                if(-not(($MajorVersion -ge 7) -or (($MajorVersion -le 6) -and ($EndpointSuffix -eq "core.windows.net")))){
                                                    throw "Error - Backups to Azure Cloud Storage with endpoint suffix $EndpointSuffix is not supported for ArcGIS Enterprise 10.6.1 and below"
                                                }
                                            }
                                            else
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
                            Version = $Version
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
                                
                                if($MajorVersion -lt 8){
                                    if($BackupObject.Name -ne "DEFAULT"){
                                        throw "Backup for Tile Cache DataStore cannot have a backup name other than 'DEFAULT' at $Version"
                                    }
                                    if($BackupObject.Type -ne "fs"){
                                        throw "Backup of Tile Cache DataStore to a Cloud Store isn't supported at $Version"
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
                                            if($Pos -gt -1) 
                                            {
                                                $EndpointSuffix = $BackupObject.CloudStorageAccount.UserName.Substring($Pos + 6)
                                                if(-not(($MajorVersion -ge 7) -or (($MajorVersion -le 6) -and ($EndpointSuffix -eq "core.windows.net")))){
                                                    throw "Error - Backups to Azure Cloud Storage with endpoint suffix $EndpointSuffix is not supported for ArcGIS Enterprise 10.6.1 and below"
                                                }
                                            }
                                            else
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
                            $PortalHostName = if($null -ne $ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancer){ $ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancer }else{ if($PrimaryPortalMachine.SSLCertificate){ $PrimaryPortalMachine.SSLCertificate.CName }else{Get-FQDN $PrimaryPortalMachine.NodeName} }
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
                            $ServerServiceURL = if($null -ne $ServerExternalDNSHostName){ $ServerExternalDNSHostName }else{  if($PrimaryServerMachine.SSLCertificate){ $PrimaryServerMachine.SSLCertificate.CName }else{Get-FQDN $PrimaryServerMachine.NodeName} }
                            $ServerServiceURLPort = if($null -ne $ServerExternalDNSHostName){ 443 }else{if($ServerRole -ieq 'NotebookServer'){11443}elseif($ServerRole -ieq 'MissionServer'){ 20443 }else{6443}}
                            $ServerServiceURLContext = if($null -ne $ConfigurationParamsHashtable.ConfigData.ServerContext){ $ConfigurationParamsHashtable.ConfigData.ServerContext }else{ 'arcgis' }

                            $ServerSiteAdminURL = if($PrimaryServerMachine.SSLCertificate){ $PrimaryServerMachine.SSLCertificate.CName }else{Get-FQDN $PrimaryServerMachine.NodeName}
                            $ServerSiteAdminURLPort = if($ServerRole -ieq 'NotebookServer'){11443}elseif($ServerRole -ieq 'MissionServer'){ 20443 }elseif($ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancerPort){$ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancerPort}else{ 6443 }
                            $ServerSiteAdminURLContext = 'arcgis'

                            if($ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancer){
                                $ServerSiteAdminURL = $ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancer
                                $ServerSiteAdminURLPort = if($ServerRole -ieq 'NotebookServer'){11443}elseif($ServerRole -ieq 'MissionServer'){ 20443 }elseif($ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancerPort){$ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancerPort}else{ 6443 }
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
                                ServerRole = $ConfigurationParamsHashtable.ConfigData.ServerRole
                            }
                            $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISFederation" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $FederationArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
                        }
                    }
                
                    if($JobFlag[$JobFlag.Count - 1] -eq $True){
                        if($PortalCheck){
                            $PrimaryPortalCName = if($PrimaryPortalMachine.SSLCertificate){ $PrimaryPortalMachine.SSLCertificate.CName }else{ Get-FQDN $PrimaryPortalMachine.NodeName}
                            $PortalUrl = "$($PrimaryPortalCName):7443/arcgis"
                            $PortalAdminUrl = "$($PrimaryPortalCName):7443/arcgis"
                            
                            if($ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancer){
                                $PortalUrl = if($ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancerPort){"$($ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancer):$($ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancerPort)/arcgis"}else{"$($ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancer):7443/arcgis"}
                                $PortalAdminUrl = if($ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancerPort){"$($ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancer):$($ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancerPort)/arcgis"}else{"$($ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancer):7443/arcgis"}
                            }
                            
                            if($null -ne $PortalExternalDNSHostName){
                                $PortalUrl = "$($PortalExternalDNSHostName)/$($ConfigurationParamsHashtable.ConfigData.PortalContext)"
                                $PortalAdminUrl = "$($PortalExternalDNSHostName)/$($ConfigurationParamsHashtable.ConfigData.PortalContext)"
                            }
                            
                            Write-Information -InformationAction Continue "Portal Admin URL - https://$PortalAdminUrl/portaladmin"
                            Write-Information "Portal URL - https://$PortalUrl/home"
                        }
                        if($ServerCheck){
                            $PrimaryServerCName = if($PrimaryServerMachine.SSLCertificate){ $PrimaryServerMachine.SSLCertificate.CName }else{Get-FQDN $PrimaryServerMachine.NodeName}
                            $Port = if($ServerRole -ieq 'NotebookServer'){11443}elseif($ServerRole -ieq "MissionServer"){ 20443 }elseif($ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancerPort){$ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancerPort}else{ 6443 }
                            $ServerAdminURL = "$($PrimaryServerCName):$($Port)/arcgis"
                            $ServerManagerURL = "$($PrimaryServerCName):$($Port)/arcgis"
                            $ServerURL = "$($PrimaryServerCName):$($Port)/arcgis"
                            
                            if($ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancer){
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
            
            if($cfHashtable.ConfigData.Version.Split(".")[1] -le 5){
                throw "[ERROR] DSC Module only supports upgrades to ArcGIS Enterprise 10.6.x and later versions. Configuration File Name - $cf"
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
        }

        $JobFlag = $True
        if($null -eq $HostingConfig){
            # Upgrade Non Enterprise Deployment
            if($OtherConfigs.count -gt 1){
                throw "Cannot Upgrade more than one non Enterprise (Server, Portal, DataStore) Deployments at a time only. Pass only one Site at a time!"
            }
            $NonEnterpiseConfig = $OtherConfigs[0]
            if($JobFlag[$JobFlag.Count - 1] -eq $True -and ($NonEnterpiseConfig.AllNodes | Where-Object { $_.Role -icontains 'Portal'} | Measure-Object).Count -gt 0){
                $JobFlag = Invoke-PortalUpgradeScript -cf $NonEnterpiseConfig -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode -EnableMSILogging $EnableMSILoggingMode   
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
                        if($Node.TargetNodeEncyrptionCertificateFilePath -and $Node.TargetNodeEncyrptionCertificateThumbprint){
                            $NodeToAdd["CertificateFile"] = $Node.TargetNodeEncyrptionCertificateFilePath
                            $NodeToAdd["Thumbprint"] = $Node.TargetNodeEncyrptionCertificateThumbprint
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
                    ServiceAccount = $ServiceAccountCredential
                    IsServiceAccountDomainAccount = $ServiceAccountIsDomainAccount
                    IsServiceAccountMSA = $ServiceAccountIsMSA
                    EnableMSILogging =  $EnableMSILoggingMode
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
            if($Node.TargetNodeEncyrptionCertificateFilePath -and $Node.TargetNodeEncyrptionCertificateThumbprint){
                $NodeToAdd["CertificateFile"] = $Node.TargetNodeEncyrptionCertificateFilePath
                $NodeToAdd["Thumbprint"] = $Node.TargetNodeEncyrptionCertificateThumbprint
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

    $VersionArray = $PortalConfig.ConfigData.Version.Split(".")
    $MajorVersion = $VersionArray[1]
    $MinorVersion = if($VersionArray.Length -gt 2){ $VersionArray[2] }else{ 0 }

    if($MajorVersion -ge 7){
        $PortalUpgradeArgs = @{
            ConfigurationData = $PortalUpgradeCD 
            Version = $PortalConfig.ConfigData.Version
            OldVersion = $PortalConfig.ConfigData.OldVersion
            InstallerPath = $PortalConfig.ConfigData.Portal.Installer.Path
            ServiceAccount = $PortalServiceAccountCredential
            IsServiceAccountDomainAccount = $PortalServiceAccountIsDomainAccount
            IsServiceAccountMSA = $PortalServiceAccountIsMSA
            EnableMSILogging =  $EnableMSILoggingMode
        }
        if((($MajorVersion -eq 7 -and $MinorVersion -eq 1) -or ($MajorVersion -ge 8)) -and $PortalConfig.ConfigData.Portal.Installer.WebStylesPath){
            $PortalUpgradeArgs.Add("WebStylesInstallerPath",$PortalConfig.ConfigData.Portal.Installer.WebStylesPath)
        }

        $JobFlag = Invoke-DSCJob -ConfigurationName "PortalUpgradeV2" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $PortalUpgradeArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
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
                $JobFlag = Invoke-DSCJob -ConfigurationName "PortalPostUpgradeV2" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $StandbyPortalPostUpgradeArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
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

                $JobFlag = Invoke-DSCJob -ConfigurationName "PortalPostUpgradeV2" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $PortalPostUpgradeArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
                if($JobFlag[$JobFlag.Count - 1] -ne $True){
                    throw "Portal Post Upgrade Step for Primary Portal Machine Failed"
                }
            }
        }
    }else{       
        $PortalExternalDNSHostName = $null
        if($ConfigurationParamsHashtable.ConfigData.Portal.ExternalLoadBalancer){
            $PortalExternalDNSHostName = $ConfigurationParamsHashtable.ConfigData.Portal.ExternalLoadBalancer
        }else{
            if(($PortalConfig.AllNodes | Where-Object { ($_.Role -icontains 'PortalWebAdaptor')}  | Measure-Object).Count -gt 0){
                $PortalWAMachineNode = ($PortalConfig.AllNodes | Where-Object { ($_.Role -icontains 'PortalWebAdaptor')} | Select-Object -First 1)
                $PortalExternalDNSHostName = Get-FQDN $PortalWAMachineNode.NodeName
                if(($PortalWAMachineNode.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor'}  | Measure-Object).Count -gt 0)
                {
                    $PortalExternalDNSHostName = ($PortalWAMachineNode.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor' }  | Select-Object -First 1).CNameFQDN
                }
            }
        }

        $PortalUpgradeArgs = @{
            ConfigurationData = $PortalUpgradeCD 
            OldVersion = $PortalConfig.ConfigData.OldVersion
            Version = $PortalConfig.ConfigData.Version
            PrimaryPortalMachine = $PrimaryNodeToAdd.NodeName 
            InstallerPath = $PortalConfig.ConfigData.Portal.Installer.Path
            Context = $PortalConfig.ConfigData.PortalContext
            ServiceAccount = $PortalServiceAccountCredential
            IsServiceAccountDomainAccount = $PortalServiceAccountIsDomainAccount
            IsServiceAccountMSA = $PortalServiceAccountIsMSA
            PortalSiteAdministratorCredential = $PortalSiteAdministratorCredential 
            ContentDirectoryLocation = $PortalConfig.ConfigData.Portal.ContentDirectoryLocation
            ExternalDNSName = $PortalExternalDNSHostName 
            InternalLoadBalancer = if($PortalConfig.ConfigData.Portal.InternalLoadBalancer){ $PortalConfig.ConfigData.Portal.InternalLoadBalancer }else{ $null }
            InternalLoadBalancerPort = if($PortalConfig.ConfigData.Portal.InternalLoadBalancerPort){ $PortalConfig.ConfigData.Portal.InternalLoadBalancer }else{ $null }
            IsMultiMachinePortal = $IsMultiMachinePortal
            AdminEmail = $PortalConfig.ConfigData.Portal.PortalAdministrator.Email
            AdminSecurityQuestionIndex = $PortalConfig.ConfigData.Portal.PortalAdministrator.SecurityQuestionIndex
            AdminSecurityAnswer = $PortalConfig.ConfigData.Portal.PortalAdministrator.SecurityAnswer
            EnableMSILogging =  $EnableMSILoggingMode
        }

        if($IsMultiMachinePortal){
            $PortalUpgradeArgs.Add("StandbyMachineName", $StandbyNodeToAdd.NodeName)
            $PortalUpgradeArgs.Add("InstallDir", $PortalConfig.ConfigData.Portal.Installer.InstallDir)
            $PortalUpgradeArgs.Add("ContentDir", $PortalConfig.ConfigData.Portal.Installer.ContentDir)
        }
        
        $JobFlag = Invoke-DSCJob -ConfigurationName "PortalUpgradeV1" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $PortalUpgradeArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
        if($JobFlag[$JobFlag.Count - 1] -ne $True){
            throw "Portal Upgrade on Primary Machine Failed"
        }

        if($IsMultiMachinePortal -and ($JobFlag[$JobFlag.Count - 1] -eq $True)){
            $PortalUpgradeStandbyArgs = @{
                ConfigurationData = @{ AllNodes = @( $StandbyNodeToAdd ); }
                PrimaryPortalMachine = $PrimaryNodeToAdd.NodeName
                Context = $PortalConfig.ConfigData.PortalContext
                PortalSiteAdministratorCredential = $PortalSiteAdministratorCredential 
                ContentDirectoryLocation = $PortalConfig.ConfigData.Portal.ContentDirectoryLocation
                AdminEmail = $PortalConfig.ConfigData.Portal.PortalAdministrator.Email
                AdminSecurityQuestionIndex = $PortalConfig.ConfigData.Portal.PortalAdministrator.SecurityQuestionIndex
                AdminSecurityAnswer = $PortalConfig.ConfigData.Portal.PortalAdministrator.SecurityAnswer
            }

            if($PortalConfig.ConfigData.Portal.PortalContentCloudStorageAccount){
                $PortalCloudStorageCredentials = $null
                if($PortalConfig.ConfigData.Portal.PortalContentCloudStorageAccount){
                    $PortalCloudStorageAccountPassword = if( $PortalConfig.ConfigData.Portal.PortalContentCloudStorageAccount.PasswordFilePath ){ Get-Content $PortalConfig.ConfigData.Portal.PortalContentCloudStorageAccount.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $PortalConfig.ConfigData.Portal.PortalContentCloudStorageAccount.Password -AsPlainText -Force }
                    $PortalCloudStorageCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $PortalConfig.ConfigData.Portal.PortalContentCloudStorageAccount.UserName, $PortalCloudStorageAccountPassword )
                }else{
                    throw "No credentials provided for Cloud Storage for $($PortalConfig.ConfigData.Portal.PortalContentCloudStorageAccount.CloudStorageType)"
                }
                $PortalUpgradeStandbyArgs["CloudStorageType"] = $PortalConfig.ConfigData.Portal.PortalContentCloudStorageAccount.CloudStorageType
                $PortalUpgradeStandbyArgs["AzureFileShareName"]  = if($PortalConfig.ConfigData.Portal.PortalContentCloudStorageAccount.CloudStorageType -ieq "AzureFiles"){ $PortalConfig.ConfigData.Portal.PortalContentCloudStorageAccount.AzureFileShareName }else{ $null }
                $PortalUpgradeStandbyArgs["CloudNamespace"] = $PortalConfig.ConfigData.Portal.PortalContentCloudStorageAccount.CloudNamespace
                $PortalUpgradeStandbyArgs["CloudStorageCredentials"] = $PortalCloudStorageCredentials
            }

            $JobFlag = Invoke-DSCJob -ConfigurationName "PortalUpgradeStandbyJoinV1" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $PortalUpgradeStandbyArgs -Credential $Credential -UseWinRMSSL $UseWinRMSSL -DebugMode $DebugMode
            if($JobFlag[$JobFlag.Count - 1] -ne $True){
                throw "Portal Upgrade on Secondary Machine Failed"
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

    $cfServiceAccountIsDomainAccount = $cf.ConfigData.Credentials.ServiceAccount.IsDomainAccount
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

    $ServerLicenseFilePath = $cf.ConfigData.Server.LicenseFilePath
    $ServerLicensePassword = $null
    $ServerRole = $null
    if($cf.ConfigData.ServerRole){   
        $ServerRole = $cf.ConfigData.ServerRole 
        if($ServerRole -ieq "RasterAnalytics" -or $ServerRole -ieq "ImageHosting"){
            $ServerRole = "ImageServer"
        }
    }else{
        $ServerRole = "GeneralPurposeServer"
    }

    if($cf.ConfigData.Server.LicensePasswordFilePath){
        $ServerLicensePassword = (Get-Content $cf.ConfigData.Server.LicensePasswordFilePath | ConvertTo-SecureString )
    }elseif($cf.ConfigData.Server.LicensePassword){
        $ServerLicensePassword = (ConvertTo-SecureString $cf.ConfigData.Server.LicensePassword -AsPlainText -Force)
    }

    if($ServerRole -ieq "GeoEvent"){
        $ServerLicenseFilePath =  $cf.ConfigData.GeoEventServer.LicenseFilePath
        $ServerLicensePassword = $null
        if($cf.ConfigData.GeoEventServer.LicensePasswordFilePath){
            $ServerLicensePassword = (Get-Content $cf.ConfigData.GeoEventServer.LicensePasswordFilePath | ConvertTo-SecureString )
        }elseif($cf.ConfigData.GeoEventServer.LicensePassword){
            $ServerLicensePassword = (ConvertTo-SecureString $cf.ConfigData.GeoEventServer.LicensePassword -AsPlainText -Force)
        }
    }

    if($ServerRole -ieq "WorkflowManagerServer"){
        $ServerLicenseFilePath =  $cf.ConfigData.WorkflowManagerServer.LicenseFilePath
        $ServerLicensePassword = $null
        if($cf.ConfigData.WorkflowManagerServer.LicensePasswordFilePath){
            $ServerLicensePassword = (Get-Content $cf.ConfigData.WorkflowManagerServer.LicensePasswordFilePath | ConvertTo-SecureString )
        }elseif($cf.ConfigData.WorkflowManagerServer.LicensePassword){
            $ServerLicensePassword = (ConvertTo-SecureString $cf.ConfigData.WorkflowManagerServer.LicensePassword -AsPlainText -Force)
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

            if($Node.TargetNodeEncyrptionCertificateFilePath -and $Node.TargetNodeEncyrptionCertificateThumbprint){
                $NodeToAdd["CertificateFile"] = $Node.TargetNodeEncyrptionCertificateFilePath
                $NodeToAdd["Thumbprint"] = $Node.TargetNodeEncyrptionCertificateThumbprint
            }else{
                $NodeToAdd["PSDscAllowPlainTextPassword"] = $true
            }
            
            $NodeToAdd["ServerLicenseFilePath"] = if($Node.ServerLicenseFilePath){ $Node.ServerLicenseFilePath }else{ $ServerLicenseFilePath }
            $NodeServerLicensePassword = $null
            if($Node.ServerLicenseFilePath){
                if($Node.ServerLicensePasswordFilePath){
                    $NodeServerLicensePassword = (Get-Content $Node.ServerLicensePasswordFilePath | ConvertTo-SecureString )
                }elseif($Node.ServerLicensePassword){
                    $NodeServerLicensePassword = (ConvertTo-SecureString $Node.ServerLicensePassword -AsPlainText -Force)
                }
            }else{
                if($null -ne $ServerLicensePassword){
                    $NodeServerLicensePassword = $ServerLicensePassword
                }
            }

            if($null -ne $NodeServerLicensePassword){
                $NodeToAdd["ServerLicensePassword"] = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("PlaceHolder", $NodeServerLicensePassword)
            }

            $NodeToAdd["ServerRole"] = $ServerRole

            $ServerUpgradeArgs = @{
                ConfigurationData = @{ AllNodes = @( $NodeToAdd ) }
                OldVersion = $cf.ConfigData.OldVersion
                Version = $cf.ConfigData.Version
                ServiceAccount = $cfServiceAccountCredential
                IsServiceAccountDomainAccount = $cfServiceAccountIsDomainAccount
                IsServiceAccountMSA = $cfServiceAccountIsMSA
                InstallerPath = $cf.ConfigData.Server.Installer.Path
                GeoEventServerInstaller = if($cf.ConfigData.ServerRole -ieq "GeoEvent"){ $cf.ConfigData.GeoEventServer.Installer.Path }else{ $null }
                WorkflowManagerServerInstaller = if($cf.ConfigData.ServerRole -ieq "WorkflowManagerServer"){ $cf.ConfigData.WorkflowManagerServer.Installer.Path }else{ $null }
                ContainerImagePaths = if($cf.ConfigData.ServerRole -ieq "NotebookServer"){ $cf.ConfigData.Server.ContainerImagePaths }else{ $null }
                InstallDir = $cf.ConfigData.Server.Installer.InstallDir
                NotebookServerSamplesDataPath = if(($cf.ConfigData.ServerRole -ieq "NotebookServer") -and ($cf.ConfigData.Version.Split(".")[1] -gt 8) -and $cf.ConfigData.Server.Installer.NotebookServerSamplesDataPath){ $cf.ConfigData.Server.Installer.NotebookServerSamplesDataPath }else{ $null }
                IsMultiMachineServerSite = ($cf.AllNodes.count -gt 1)
                EnableMSILogging = $EnableMSILogging
                EnableArcMapRuntime = if($Version -ieq "10.9.1"){ if($cf.ConfigData.Server.Installer.ContainsKey("EnableArcMapRuntime")){ $cf.ConfigData.Server.Installer.EnableArcMapRuntime }else{ $True } }else{ $False }
                EnableDotnetSupport = if($Version -ieq "10.9.1"){ $cf.ConfigData.Server.Installer.EnableDotnetSupport }else{ $False }
                Extensions = if($cf.ConfigData.Server.Extensions){ $cf.ConfigData.Server.Extensions }else{ $null }
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
                ComponentHostName = $cfPrimaryServerMachine
                SiteAdministratorCredential = $cfSiteAdministratorCredential
                WebSiteId = if($cf.ConfigData.WebAdaptor.WebSiteId){ $cf.ConfigData.WebAdaptor.WebSiteId }else{ 1 }
                EnableMSILogging = $EnableMSILoggingMode
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

    $DSServiceAccountIsDomainAccount = $DSConfig.ConfigData.Credentials.ServiceAccount.IsDomainAccount
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

            if($DSNode.TargetNodeEncyrptionCertificateFilePath -and $DSNode.TargetNodeEncyrptionCertificateThumbprint){
                $NodeToAdd["CertificateFile"] = $DSNode.TargetNodeEncyrptionCertificateFilePath
                $NodeToAdd["Thumbprint"] = $DSNode.TargetNodeEncyrptionCertificateThumbprint
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
                InstallDir = $DSConfig.ConfigData.DataStore.Installer.InstallDir
                EnableMSILogging = $EnableMSILoggingMode
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
                                
    if($cf.TargetNodeEncyrptionCertificateFilePath -and $cf.TargetNodeEncyrptionCertificateThumbprint){
        $NodeToAdd["CertificateFile"] = $cf.TargetNodeEncyrptionCertificateFilePath
        $NodeToAdd["Thumbprint"] = $cf.TargetNodeEncyrptionCertificateThumbprint
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
                        -or ($ProductName -ine "portal" -and $ProductName -ine "ArcGIS Notebook Server")){
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

Export-ModuleMember -Function Get-FQDN, Invoke-ArcGISConfiguration, Invoke-PublishWebApp, Invoke-BuildArcGISAzureImage, Invoke-PublishGISService, Get-ArcGISProductDetails
