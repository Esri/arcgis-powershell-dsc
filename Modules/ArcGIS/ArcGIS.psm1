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
    while(-not($Done)) {
        if(-Not(($Job.ChildJobs).state -imatch "Running")){
            $Done = $True
        }
        ForEach($j in $Job.ChildJobs){
            if(($j.state -imatch "Completed" -or $j.state -imatch "Failed" ) -and -not($CompletedJobs.Contains($j.Name)) ){
                $timestamp = (($j.PSBeginTime).toString()).Replace(':','-').Replace('/','-').Replace(' ','-')
                
                if(!(Test-Path -Path $LogsPath )){
                    New-Item -ItemType directory -Path $LogsPath
                }
                
                $MachineLogPath = Join-Path $LogsPath $j.Location
                if(!(Test-Path -Path $MachineLogPath)){
                    New-Item -ItemType directory -Path $MachineLogPath
                }

                Add-content "$MachineLogPath\$($JobName)-$($timestamp)-Verbose.txt" -value $j.Verbose
                
                if($j.Error){
                    Add-content "$MachineLogPath\$($JobName)-$($timestamp)-Error.txt" -value $j.Error
                }
                
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
                        if($DebugMode){
                            Write-Host $item -foregroundcolor yellow
                        }else{
                            if(($item.Message -match "Start  Test") -or ($item.Message -match "Start  Set") -or ($item.Message -match "End    Test") -or ($item.Message -match "End    Set")){
                                Write-Host $item -foregroundcolor yellow
                            }elseif(($item.Message -match "Start  Resource") -or ($item.Message -match "End    Resource")){
                                Write-Host $item -foregroundcolor green
                            }
                        }
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
                        Write-Error $item
                        #Write-Host "[]$item" -foregroundcolor red
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
        $DebugMode = $False
    )
    
    if(Test-Path ".\$($ConfigurationName)") { Remove-Item ".\$($ConfigurationName)" -Force -ErrorAction Ignore -Recurse }

    Write-Information -InformationAction Continue "Dot Sourcing the Configuration:- $ConfigurationName"
    . "$PSScriptRoot\$($ConfigurationFolderPath)\$($ConfigurationName).ps1" -Verbose:$false

    &$ConfigurationName @Arguments -Verbose

    if(($Arguments.ConfigurationData.AllNodes | Where-Object { $_.Thumbprint -and $_.CertificateFile } | Measure-Object).Count -gt 0){
        Write-Information -InformationAction Continue "Configuring Local Configuration Manager:- $ConfigurationName"
        Set-DscLocalConfigurationManager ".\$($ConfigurationName)" -Verbose
    }    

    Write-Information -InformationAction Continue "Starting DSC Job:- $ConfigurationName"
    $JobTimer = [System.Diagnostics.Stopwatch]::StartNew()
    $Job = if($Credential){ Start-DscConfiguration -Path ".\$($ConfigurationName)" -Force -Verbose -Credential $Credential }else{ Start-DscConfiguration -Path ".\$($ConfigurationName)" -Force -Verbose }
    
    if(Test-Path ".\$($ConfigurationName)") { Remove-Item ".\$($ConfigurationName)" -Force -ErrorAction Ignore -Recurse }

    Trace-DSCJob -Job $Job -JobName $ConfigurationName -DebugMode $DebugMode
    Write-Information -InformationAction Continue "Finished DSC Job:- $ConfigurationName. Time Taken - $($JobTimer.elapsed)"
    Write-Information -InformationAction Continue "$($ConfigurationName) - $($Job.state)"
    $result = if($Job.state -ieq "Completed"){ $True } else{ $False }
    $result 
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
        $DebugMode = $False
    )

    $cfServiceAccountIsDomainAccount = $cf.ConfigData.Credentials.ServiceAccount.IsDomainAccount
    $cfServiceAccountIsMSA = if($cf.ConfigData.Credentials.ServiceAccount.IsMSA){$cf.ConfigData.Credentials.ServiceAccount.IsMSA}else{ $false }
    $cfServiceAccountPassword = if( $cf.ConfigData.Credentials.ServiceAccount.PasswordFilePath ){ Get-Content $cf.ConfigData.Credentials.ServiceAccount.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $cf.ConfigData.Credentials.ServiceAccount.Password -AsPlainText -Force }
    $cfServiceAccountCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $cf.ConfigData.Credentials.ServiceAccount.UserName, $cfServiceAccountPassword )
    
    $cfSiteAdministratorPassword = if($cf.ConfigData.Server.PrimarySiteAdmin.PasswordFilePath ){ Get-Content $cf.ConfigData.Server.PrimarySiteAdmin.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $cf.ConfigData.Server.PrimarySiteAdmin.Password -AsPlainText -Force }
    $cfSiteAdministratorCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $cf.ConfigData.Server.PrimarySiteAdmin.UserName, $cfSiteAdministratorPassword )
    
    $JobFlag = $True

    #ServerWebAdaptorUninstall
    Write-Information -InformationAction Continue "WA Server Uninstall"
    ForEach($WANode in ($cf.AllNodes | Where-Object {$_.Role -icontains 'ServerWebAdaptor'})){
        $NodeToAdd = @{ 
            NodeName = $WANode.NodeName; 
        }
        if($WANode.TargetNodeEncyrptionCertificateFilePath -and $WANode.TargetNodeEncyrptionCertificateThumbprint){
            $NodeToAdd["CertificateFile"] = $WANode.TargetNodeEncyrptionCertificateFilePath
            $NodeToAdd["Thumbprint"] = $WANode.TargetNodeEncyrptionCertificateThumbprint
        }else{
            $NodeToAdd["PSDscAllowPlainTextPassword"] = $true
        }
       
        $WebAdaptorUninstallArgs = @{
            ConfigurationData = @{ AllNodes = @( $NodeToAdd ) }
            Version = $cf.ConfigData.Version 
            InstallerPath = $cf.ConfigData.WebAdaptor.Installer.Path 
            Context = $cf.ConfigData.ServerContext
        }

        $JobFlag = Invoke-DSCJob -ConfigurationName "WebAdaptorUninstall" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $WebAdaptorUninstallArgs -Credential $Credential -DebugMode $DebugMode
        
        if(-not($JobFlag)){
            break
        }
    }


    #UpgradeServers
    if($JobFlag){
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
            $ServerLicensePassword = (Get-Content $cf.ConfigData.Credentials.Server.LicensePasswordFilePath | ConvertTo-SecureString )
        }elseif($cf.ConfigData.Server.LicensePassword){
            $ServerLicensePassword = (ConvertTo-SecureString $cf.ConfigData.Credentials.Server.LicensePassword -AsPlainText -Force)
        }

        if($ServerRole -ieq "GeoEvent"){
            $ServerLicenseFilePath =  $cf.ConfigData.GeoEventServer.LicenseFilePath
            $ServerLicensePassword = $null
            if($cf.ConfigData.GeoEventServer.LicensePasswordFilePath){
                $ServerLicensePassword = (Get-Content $cf.ConfigData.Credentials.GeoEventServer.LicensePasswordFilePath | ConvertTo-SecureString )
            }elseif($cf.ConfigData.GeoEventServer.LicensePassword){
                $ServerLicensePassword = (ConvertTo-SecureString $cf.ConfigData.Credentials.GeoEventServer.LicensePassword -AsPlainText -Force)
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
                if($Node.ServerLicenseFilePath){
                    if($Node.ServerLicensePasswordFilePath){
                        $NodeToAdd["ServerLicensePassword"] =(Get-Content $Node.ServerLicensePasswordFilePath | ConvertTo-SecureString )
                    }elseif($Node.ServerLicensePassword){
                        $NodeToAdd["ServerLicensePassword"] = (ConvertTo-SecureString $Node.ServerLicensePassword -AsPlainText -Force)
                    }
                }else{
                    if($null -ne $ServerLicensePassword){
                        $NodeToAdd["ServerLicensePassword"] = $ServerLicensePassword
                    }
                }
                $NodeToAdd["ServerRole"] = $ServerRole

                $ServerUpgradeArgs = @{
                    ConfigurationData = @{ AllNodes = @( $NodeToAdd ) }
                    Version = $cf.ConfigData.Version
                    ServiceAccount = $cfServiceAccountCredential
                    IsServiceAccountDomainAccount = $cfServiceAccountIsDomainAccount
                    IsServiceAccountMSA = $cfServiceAccountIsMSA
                    InstallerPath = $cf.ConfigData.Server.Installer.Path
                    GeoEventServerInstaller = if($cf.ConfigData.ServerRole -ieq "GeoEvent"){ $cf.ConfigData.GeoEventServer.Installer.Path }else{ $null }
                    ContainerImagePaths = if($cf.ConfigData.ServerRole -ieq "NotebookServer"){ $cf.ConfigData.Server.ContainerImagePaths }else{ $null }
                    InstallDir = $cf.ConfigData.Server.Installer.InstallDir
                }

                $JobFlag = Invoke-DSCJob -ConfigurationName "ServerUpgrade" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $ServerUpgradeArgs -Credential $Credential -DebugMode $DebugMode

                if(-not($JobFlag)){
                    break
                }
            }
        }
        if($JobFlag){
            #UpgradeServerWebAdaptor
            Write-Information -InformationAction Continue "WA Server Install"
            ForEach($WANode in ($cf.AllNodes | Where-Object {$_.Role -icontains 'ServerWebAdaptor'})){
                $WAExternalHostName = if(($WANode.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor'}  | Measure-Object).Count -gt 0){($WANode.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor' }  | Select-Object -First 1).CNameFQDN }else{ Get-FQDN $WANode.NodeName }                
                $NodeToAdd = @{ 
                    NodeName = $WANode.NodeName; 
                    ExternalHostName = $WAExternalHostName
                }
                if($WANode.TargetNodeEncyrptionCertificateFilePath -and $WANode.TargetNodeEncyrptionCertificateThumbprint){
                    $NodeToAdd["CertificateFile"] = $WANode.TargetNodeEncyrptionCertificateFilePath
                    $NodeToAdd["Thumbprint"] = $WANode.TargetNodeEncyrptionCertificateThumbprint
                }else{
                    $NodeToAdd["PSDscAllowPlainTextPassword"] = $true
                }
                
                $WebAdaptorInstallArgs = @{
                    ConfigurationData = @{ AllNodes = @( $NodeToAdd ) }
                    WebAdaptorRole = "ServerWebAdaptor"
                    Version = $cf.ConfigData.Version
                    InstallerPath = $cf.ConfigData.WebAdaptor.Installer.Path
                    Context = $cf.ConfigData.ServerContext
                    ComponentHostName = $cfPrimaryServerMachine
                    SiteAdministratorCredential = $cfSiteAdministratorCredential
                }
                $JobFlag = Invoke-DSCJob -ConfigurationName "WebAdaptorInstall" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $WebAdaptorInstallArgs -Credential $Credential -DebugMode $DebugMode

                if(-not($JobFlag)){
                    break
                }
            }
        }
    }
    $JobFlag
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
        [System.Boolean]
        $UseAzureFiles,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AFSCredential,

        [Parameter(Mandatory=$false)]
        [System.String]
        $AFSEndpoint,
        
        [switch]
        $DebugSwitch  
    )
 
    $DebugMode = if($DebugSwitch){ $true }else{ $False}

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
        $DownloadInstallersArgs = @{ ConfigurationData = $cd } 
        if($UseAzureFiles){
            $DownloadInstallersArgs.Installers = $InstallersConfig.Installers 
            $DownloadInstallersArgs.UseAzureFiles = $true 
            $DownloadInstallersArgs.AFSCredential = $AFSCredential 
            $DownloadInstallersArgs.AFSEndpoint = $AFSEndpoint 
        }

        $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISDownloadInstallers" -ConfigurationFolderPath "Configurations-AzureImageBuild" -Arguments $DownloadInstallersArgs -Credential $Credential -DebugMode $DebugMode
        if($JobFlag){
            Write-Information -InformationAction Continue "Downloaded Installer Setups Successfully."
        }
    }else{
        $JobFlag = $True
    }
    
    if($JobFlag -eq $True){
        $JobFlag = $False
        $SetupConfigArgs = @{
            Installers = $InstallersConfig.Installers
            WindowsFeatures = $InstallersConfig.WindowsFeatures
        }
        $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISSetupConfiguration" -ConfigurationFolderPath "Configurations-AzureImageBuild" -Arguments $SetupConfigArgs -Credential $Credential -DebugMode $DebugMode
        if($JobFlag -eq $True) {
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

    if($TargetComponent -ieq "DataStore"){ Add-Member -InputObject $NodeToAdd -MemberType NoteProperty -Name "DataStoreTypes" -Value  $Node.DataStoreTypes }

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
        $DebugSwitch
    )
    
    $DebugMode = if($DebugSwitch){ $True }else{ $False } 

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
        if($ConfigurationParamsHashtable.ConfigData.Credentials.ServiceAccount){
            $SAPassword = if( $ConfigurationParamsHashtable.ConfigData.Credentials.ServiceAccount.PasswordFilePath ){ Get-Content $ConfigurationParamsHashtable.ConfigData.Credentials.ServiceAccount.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.Credentials.ServiceAccount.Password -AsPlainText -Force }
            $ServiceCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $ConfigurationParamsHashtable.ConfigData.Credentials.ServiceAccount.UserName, $SAPassword )
            $ServiceCredentialIsDomainAccount = $ConfigurationParamsHashtable.ConfigData.Credentials.ServiceAccount.IsDomainAccount
            $ServiceCredentialIsMSA = $ConfigurationParamsHashtable.ConfigData.Credentials.ServiceAccount.IsDomainAccount
        }

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
            
            $ConfigurationName = if($Mode -ieq "Uninstall"){ "ArcGISUninstall" }else{ "ArcGISInstall" }
            
            $JobFlag = Invoke-DSCJob -ConfigurationName $ConfigurationName -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $InstallArgs -Credential $Credential -DebugMode $DebugMode

            if($JobFlag -eq $True -and ($Mode -ieq "InstallLicense" -or $Mode -ieq "InstallLicenseConfigure")){
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
                
                if(-not($EnterpriseSkipLicenseStep -and $DesktopSkipLicenseStep -and $ProSkipLicenseStep)){

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
                            
                            if($ConfigurationData.ConfigData.Server.LicensePasswordFilePath){
                                $ServerLicensePassword = (Get-Content $ConfigurationParamsHashtable.ConfigData.Credentials.Server.LicensePasswordFilePath | ConvertTo-SecureString )
                            }elseif($ConfigurationData.ConfigData.Server.LicensePassword){
                                $ServerLicensePassword = (ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.Credentials.Server.LicensePassword -AsPlainText -Force)
                            }

                            if($ServerRole -ieq "GeoEvent"){
                                $ServerLicenseFilePath =  $ConfigurationParamsHashtable.ConfigData.GeoEventServer.LicenseFilePath
                                $ServerLicensePassword = $null
                                if($ConfigurationData.ConfigData.GeoEventServer.LicensePasswordFilePath){
                                    $ServerLicensePassword = (Get-Content $ConfigurationParamsHashtable.ConfigData.Credentials.GeoEventServer.LicensePasswordFilePath | ConvertTo-SecureString )
                                }elseif($ConfigurationData.ConfigData.GeoEventServer.LicensePassword){
                                    $ServerLicensePassword = (ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.Credentials.GeoEventServer.LicensePassword -AsPlainText -Force)
                                }
                            }
                            
                            if($Node.ServerLicenseFilePath -and $Node.ServerLicensePassword)
                            {
                                $ServerLicenseFilePath=$Node.ServerLicenseFilePath
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
                                    $PortalLicensePassword = (Get-Content $ConfigurationParamsHashtable.ConfigData.Credentials.Portal.LicensePasswordFilePath | ConvertTo-SecureString )
                                }elseif($ConfigurationParamsHashtable.ConfigData.Portal.LicensePassword){
                                    $PortalLicensePassword = (ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.Credentials.Portal.LicensePassword -AsPlainText -Force)
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
                            if($ConfigurationParamsHashtable.ConfigData.Desktop){
                                $NodeToAdd["DesktopLicenseFilePath"] = $ConfigurationParamsHashtable.ConfigData.Desktop.LicenseFilePath
                                $NodeToAdd["DesktopVersion"] = $ConfigurationParamsHashtable.ConfigData.DesktopVersion
                            }
                            if($ConfigurationParamsHashtable.ConfigData.Pro){
                                $NodeToAdd["ProLicenseFilePath"] = $ConfigurationParamsHashtable.ConfigData.Pro.LicenseFilePath
                                $NodeToAdd["ProVersion"] = $ConfigurationParamsHashtable.ConfigData.ProVersion
                            }
                        }
                        if($NodeToAdd.Role.Count -gt 0){
                            $LicenseCD.AllNodes += $NodeToAdd
                        }
                    }
                    $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISLicense" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments @{ ConfigurationData = $LicenseCD; ForceLicenseUpdate = if($ConfigurationParamsHashtable.ConfigData.ForceLicenseUpdate){$ConfigurationParamsHashtable.ConfigData.ForceLicenseUpdate }else{ $False } } -Credential $Credential -DebugMode $DebugMode
                }else{
                    $JobFlag = $True
                }

                $SkipConfigureStep = $False                    
                if(($DesktopCheck -or $ProCheck) -and -not($ServerCheck -or $PortalCheck)){
                    $SkipConfigureStep = $True
                }

                if($JobFlag -eq $True -and ($Mode -ieq "InstallLicenseConfigure") -and -not($SkipConfigureStep)){
                    $FileShareCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'FileShare'} | Measure-Object).Count -gt 0)
                    $DataStoreCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'DataStore' } | Measure-Object).Count -gt 0)
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
                    
                    $CloudStorageCredentials = $null
                    if($ConfigurationParamsHashtable.ConfigData.Credentials.CloudStorageAccount){
                        $CloudStorageAccountPassword = if( $ConfigurationParamsHashtable.ConfigData.Credentials.CloudStorageAccount.PasswordFilePath ){ Get-Content $ConfigurationParamsHashtable.ConfigData.Credentials.CloudStorageAccount.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $ConfigurationParamsHashtable.ConfigData.Credentials.CloudStorageAccount.Password -AsPlainText -Force }
                        $CloudStorageCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $ConfigurationParamsHashtable.ConfigData.Credentials.CloudStorageAccount.UserName, $CloudStorageAccountPassword )
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
                    $DataStoreCD = @{ AllNodes = @() }
                    
                    $RasterDataStoreItemCD = @{ AllNodes = @() }
                    $SQLServerCD = @{ AllNodes = @() }

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
                            if($DsTypes -icontains "Relational" -and ($null -eq $PrimaryDataStore)) { $PrimaryDataStore = $Node }
                            if($DsTypes -icontains "SpatioTemporal" -and ($null -eq $PrimaryBigDataStore)) { $PrimaryBigDataStore = $Node }
                            if($DsTypes -icontains "TileCache" -and ($null -eq $PrimaryTileCache)) { $PrimaryTileCache = $Node }
                            $DataStoreCD.AllNodes += (Invoke-CreateNodeToAdd -Node $Node -TargetComponent 'DataStore')
                        }
                        if($Node.Role -icontains 'SQLServer') {
                            $SQLServerNode = (Invoke-CreateNodeToAdd -Node $Node -TargetComponent 'SQLServer')
                            $SQLServerCD.AllNodes += $SQLServerNode
                        }
                    }
                    if(($JobFlag -eq $True) -and $FileShareCheck){
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
                        $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISFileShare" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $FileShareArgs -Credential $Credential -DebugMode $DebugMode
                    }

                    if(($JobFlag -eq $True) -and $ServerCheck){
                        $JobFlag = $False
                        $ServerArgs = @{
                            ConfigurationData = $ServerCD
                            ServiceCredential = $ServiceCredential
                            ServiceCredentialIsDomainAccount = $ServiceCredentialIsDomainAccount 
                            ServiceCredentialIsMSA = $ServiceCredentialIsMSA 
                            ServerPrimarySiteAdminCredential = $ServerPrimarySiteAdminCredential
                            PrimaryServerMachine = $PrimaryServerMachine.NodeName
                            ConfigStoreLocation = $ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreLocation
                            ServerDirectoriesRootLocation = $ConfigurationParamsHashtable.ConfigData.Server.ServerDirectoriesRootLocation
                            ServerDirectories = if($ConfigurationParamsHashtable.ConfigData.Server.ServerDirectories){$ConfigurationParamsHashtable.ConfigData.Server.ServerDirectories}else{$null}
                            ServerLogsLocation = if($ConfigurationParamsHashtable.ConfigData.Server.ServerLogsLocation){$ConfigurationParamsHashtable.ConfigData.Server.ServerLogsLocation}else{$null}
                            SslRootOrIntermediate = ($ConfigurationParamsHashtable.ConfigData.SslRootOrIntermediate | ConvertTo-Json)
                            DebugMode = $DebugMode
                        }

                        if($ConfigurationParamsHashtable.ConfigData.ServerRole -ieq "NotebookServer" -or $ConfigurationParamsHashtable.ConfigData.ServerRole -ieq "MissionServer"){
                            if($ConfigurationParamsHashtable.ConfigData.Server.ContainerImagePaths){
                                $ServerArgs["ContainerImagePaths"] = $ConfigurationParamsHashtable.ConfigData.Server.ContainerImagePaths
                            }                                
                        }else{
                            $ServerArgs["ServerRole"] = $ConfigurationParamsHashtable.ConfigData.ServerRole
                            $ServerArgs["OpenFirewallPorts"] = ($PortalCheck -or $DataStoreCheck -or $IsServerWAOnSeparateMachine)
                            $ServerArgs["RegisteredDirectories"] = ($ConfigurationParamsHashtable.ConfigData.Server.RegisteredDirectories | ConvertTo-Json)
                            $ServerArgs["LocalRepositoryPath"] = if($ConfigurationParamsHashtable.ConfigData.Server.LocalRepositoryPath){$ConfigurationParamsHashtable.ConfigData.Server.LocalRepositoryPath}else{$null}
                        }

                        if($ConfigurationParamsHashtable.ConfigData.CloudStorageType){
                            $ServerArgs["CloudStorageType"] = $ConfigurationParamsHashtable.ConfigData.CloudStorageType
                            $ServerArgs["AzureFileShareName"]  = if($ConfigurationParamsHashtable.ConfigData.CloudStorageType -ieq "AzureFiles"){ $ConfigurationParamsHashtable.ConfigData.AzureFileShareName }else{ $null }
                            $ServerArgs["CloudNamespace"] = $ConfigurationParamsHashtable.ConfigData.CloudNamespace
                            $ServerArgs["CloudStorageCredentials"] = $CloudStorageCredentials
                        }

                        $ConfigurationName = "ArcGISServer"
                        if($ConfigurationParamsHashtable.ConfigData.ServerRole -eq "NotebookServer"){
                            $ConfigurationName = "ArcGISNotebookServer"
                        }elseif($ConfigurationParamsHashtable.ConfigData.ServerRole -eq "MissionServer"){
                            $ConfigurationName = "ArcGISMissionServer"
                        }

                        $JobFlag = Invoke-DSCJob -ConfigurationName $ConfigurationName -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $ServerArgs -Credential $Credential -DebugMode $DebugMode
                    }

                    if(($JobFlag -eq $True) -and $ConfigurationParamsHashtable.ConfigData.Server.Databases){
                        foreach($DB in $ConfigurationParamsHashtable.ConfigData.Server.Databases){
                            if($JobFlag -eq $True){
                                $DatabaseServerAdministratorCredential = $null
                                if($DB.DatabaseAdminUser){
                                    $DatabaseAdminUserPassword = if( $DB.DatabaseAdminUser.PasswordFilePath ){ Get-Content $DB.DatabaseAdminUser.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $DB.DatabaseAdminUser.Password -AsPlainText -Force }
                                    $DatabaseServerAdministratorCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $DB.DatabaseAdminUser.UserName, $DatabaseAdminUserPassword )
                                }

                                $SDEUserCredential = $null
                                if($DB.SDEUser){
                                    $SDEUserPassword = if( $DB.SDEUser.PasswordFilePath ){ Get-Content $DB.SDEUser.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $DB.Credentials.SDEUser.Password -AsPlainText -Force }
                                    $SDEUserCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $DB.SDEUser.UserName, $SDEUserPassword )
                                }

                                $DatabaseUserCredential = $null
                                if($DB.DatabaseUser){
                                    $DatabaseUserPassword = if( $DB.DatabaseUserCredential.PasswordFilePath ){ Get-Content $DB.DatabaseUserCredential.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $DB.DatabaseUserCredential.Password -AsPlainText -Force }
                                    $DatabaseUserCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $DB.DatabaseUserCredential.UserName, $DatabaseUserPassword )
                                }

                                if((($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'SQLServer' -and $_.NodeName -ieq $DB.DatabaseServerHostName } | Measure-Object).Count -gt 0)){
                                    $SQLServerArgs = @{
                                        ConfigurationData = $SQLServerCD
                                        DatabaseServerHostName = $DB.DatabaseServerHostName
                                        DatabaseServerAdministratorCredential = $DatabaseServerAdministratorCredential
                                    }
                                    
                                    $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISSQLServer" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $SQLServerArgs -Credential $Credential -DebugMode $DebugMode
                                }

                                if($JobFlag -eq $True){
                                    $DBArgs = @{
                                        ConfigurationData = $ServerCD
                                        PrimaryServiceMachine = $PrimaryServerMachine.NodeName
                                        ServerPrimarySiteAdminCredential = $ServerPrimarySiteAdminCredential
                                        DatabaseType = $DB.DatabaseType
                                        DatabaseServerHostName = $DB.DatabaseServerHostName
                                        DatabaseName = $DB.DatabaseName
                                        DatabaseServerAdministratorCredential = $DatabaseServerAdministratorCredential
                                        SDEUserCredential = $SDEUserCredential
                                        DatabaseUserCredential = $DatabaseUserCredential
                                        DatabaseIsManaged = $DB.DatabaseIsManaged
                                        EnableGeodatabase = $DB.EnableGeodatabase
                                    }

                                    $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISRegisterSQLEGDB" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $DBArgs -Credential $Credential -DebugMode $DebugMode
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

                    if(($JobFlag -eq $True) -and $ServerCheck -and -not(($null -eq $ServerExternalDNSHostName) -and -not($ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancer))){
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
                            $ServerSettingsArgs["InternalLoadBalancer"] = if($ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancer){ $ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancer }else{ $null }
                        }

                        $JobFlag = Invoke-DSCJob -ConfigurationName $ConfigurationName -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $ServerSettingsArgs -Credential $Credential -DebugMode $DebugMode
                    }

                    
                    $Version = $ConfigurationParamsHashtable.ConfigData.Version
                    if(($JobFlag -eq $True) -and $PortalCheck){
                        $JobFlag = $False
                        $MajorVersion = $Version.Split(".")[1]
                        $PortalArgs = @{
                            ConfigurationData = $PortalCD
                            ServiceCredential = $ServiceCredential
                            ServiceCredentialIsDomainAccount = $ServiceCredentialIsDomainAccount 
                            ServiceCredentialIsMSA = $ServiceCredentialIsMSA 
                            PortalAdministratorCredential = $PortalAdministratorCredential
                            Version = $Version
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
                            DebugMode = $DebugMode
                        }
                        if($ConfigurationParamsHashtable.ConfigData.CloudStorageType){
                            $PortalArgs["CloudStorageType"] = $ConfigurationParamsHashtable.ConfigData.CloudStorageType
                            $PortalArgs["AzureFileShareName"]  = if($ConfigurationParamsHashtable.ConfigData.CloudStorageType -ieq "AzureFiles"){ $ConfigurationParamsHashtable.ConfigData.AzureFileShareName }else{ $null }
                            $PortalArgs["CloudNamespace"] = $ConfigurationParamsHashtable.ConfigData.CloudNamespace
                            $PortalArgs["CloudStorageCredentials"] = $CloudStorageCredentials
                        }

                        $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISPortal" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $PortalArgs -Credential $Credential -DebugMode $DebugMode
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

                    if(($JobFlag -eq $True) -and $PortalCheck -and -not(($null -eq $PortalExternalDNSHostName) -and -not($ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancer))){
                        $PortalSettingsArgs = @{
                            ConfigurationData = $PortalCD
                            PrimaryPortalMachine = $PrimaryPortalMachine.NodeName
                            PortalAdministratorCredential = $PortalAdministratorCredential
                            ExternalDNSHostName = $PortalExternalDNSHostName
                            PortalContext = if($null -ne $PortalExternalDNSHostName){ $ConfigurationParamsHashtable.ConfigData.PortalContext }else{ $null }
                            InternalLoadBalancer = if($ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancer){ $ConfigurationParamsHashtable.ConfigData.Portal.InternalLoadBalancer }else{ $null }
                        }
                        $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISPortalSettings" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $PortalSettingsArgs -Credential $Credential -DebugMode $DebugMode
                    }

                    if(($JobFlag -eq $True) -and $WebAdaptorCheck){
                        $JobFlag = $False
                        $WebAdaptorArgs = @{
                            ConfigurationData           = $WebAdaptorCD
                            ServerPrimarySiteAdminCredential = $ServerPrimarySiteAdminCredential
                            PortalAdministratorCredential = $PortalAdministratorCredential
                            PrimaryServerMachine        = $PrimaryServerMachine.NodeName
                            PrimaryPortalMachine        = $PrimaryPortalMachine.NodeName
                        }
                        if($ServerCheck){
                            $WebAdaptorArgs["ServerRole"] = $ConfigurationParamsHashtable.ConfigData.ServerRole
                        }

                        $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISWebAdaptor" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $WebAdaptorArgs -Credential $Credential -DebugMode $DebugMode
                    }
                    
                    if(($JobFlag -eq $True) -and $DataStoreCheck){
                        $JobFlag = $False
                        $DataStoreArgs = @{
                            Version = $Version
                            ConfigurationData = $DataStoreCD
                            ServiceCredential = $ServiceCredential
                            ServiceCredentialIsDomainAccount = $ServiceCredentialIsDomainAccount 
                            ServiceCredentialIsMSA = $ServiceCredentialIsMSA 
                            PrimaryServerMachine = $PrimaryServerMachine.NodeName
                            ServerPrimarySiteAdminCredential = $ServerPrimarySiteAdminCredential
                            ContentDirectoryLocation = $ConfigurationParamsHashtable.ConfigData.DataStore.ContentDirectoryLocation
                            PrimaryDataStore = $PrimaryDataStore.NodeName
                            PrimaryBigDataStore = $PrimaryBigDataStore.NodeName
                            PrimaryTileCache = $PrimaryTileCache.NodeName
                            EnableFailoverOnPrimaryStop = if($ConfigurationParamsHashtable.ConfigData.DataStoreItems.DataStore.EnableFailoverOnPrimaryStop){ $ConfigurationParamsHashtable.ConfigData.DataStore.EnableFailoverOnPrimaryStop }else{ $False }
                            DebugMode = $DebugMode
                        }
                        $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISDataStore" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $DataStoreArgs -Credential $Credential -DebugMode $DebugMode
                    }

                    if(($JobFlag -eq $True) -and $RasterDataStoreItemCheck){
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

                        $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISRasterDataStoreItem" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $ArcGISRasterDataStoreItemArgs -Credential $Credential -DebugMode $DebugMode
                    }
                    

                    if(($JobFlag -eq $True) -and $ServerCheck){
                        $RemoteFederation = $PortalServerFederation = $False
                        $RemoteSiteAdministrator = $null
                        if($PortalCheck){
                            $PortalServerFederation = $True
                            $PortalHostName = if($null -ne $PortalExternalDNSHostName){ $PortalExternalDNSHostName }else{ if($PrimaryPortalMachine.SSLCertificate){ $PrimaryPortalMachine.SSLCertificate.CName }else{Get-FQDN $PrimaryPortalMachine.NodeName} }
                            $PortalPort = if($null -ne $PortalExternalDNSHostName){ 443 }else{ 7443 }
                            $PortalContext = if($null -ne $PortalExternalDNSHostName){ $ConfigurationParamsHashtable.ConfigData.PortalContext }else{ 'arcgis' }
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
                            $ServerSiteAdminURLPort = if($ServerRole -ieq 'NotebookServer'){11443}elseif($ServerRole -ieq 'MissionServer'){ 20443 }else{ 6443 }
                            $ServerSiteAdminURLContext = 'arcgis'

                            if($ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancer){
                                $ServerSiteAdminURL = $ConfigurationParamsHashtable.ConfigData.Server.InternalLoadBalancer
                                $ServerSiteAdminURLPort = if($ServerRole -ieq 'NotebookServer'){11443}elseif($ServerRole -ieq 'MissionServer'){ 20443 }else{ 6443 }
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
                            $JobFlag = Invoke-DSCJob -ConfigurationName "ArcGISFederation" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $FederationArgs -Credential $Credential -DebugMode $DebugMode
                        }
                    }
                
                    if($JobFlag -eq $True){ 
                        if($PortalCheck){
                            $PrimaryPortalCName = if($PrimaryPortalMachine.SSLCertificate){ $PrimaryPortalMachine.SSLCertificate.CName }else{ Get-FQDN $PrimaryPortalMachine.NodeName}
                            $PortalUrl = "$($PrimaryPortalCName):7443/arcgis" 
                            if($null -ne $PortalExternalDNSHostName){
                                $PortalUrl = "$($PortalExternalDNSHostName)/$($ConfigurationParamsHashtable.ConfigData.PortalContext)" 
                            }

                            Write-Information -InformationAction Continue "Portal Admin URL - https://$PortalUrl/portaladmin"
                            Write-Information "Portal URL - https://$PortalUrl/home"    
                        }
                        if($ServerCheck){
                            $PrimaryServerCName = if($PrimaryServerMachine.SSLCertificate){ $PrimaryServerMachine.SSLCertificate.CName }else{Get-FQDN $PrimaryServerMachine.NodeName}
                            $Port =  if($ServerRole -ieq 'NotebookServer'){11443}elseif($ServerRole -ieq "MissionServer"){20443}else{6443}
                            $ServerURL = "$($PrimaryServerCName):$($Port)/arcgis"
                            $ServerAdminURL = "$($PrimaryServerCName):$($Port)/arcgis"

                            if($null -ne $ServerExternalDNSHostName){
                                $ServerURL = "$($ServerExternalDNSHostName)/$($ConfigurationParamsHashtable.ConfigData.ServerContext)"
                                if($ConfigurationParamsHashtable.ConfigData.WebAdaptor.AdminAccessEnabled){
                                    $ServerAdminURL = "$($ServerExternalDNSHostName)/$($ConfigurationParamsHashtable.ConfigData.ServerContext)"
                                }
                            }

                            Write-Information -InformationAction Continue "Server Admin URL - https://$ServerAdminURL/admin"
                            if(-not($ConfigurationParamsHashtable.ConfigData.ServerRole -in @('MissionServer', 'NotebookServer'))){
                                Write-Information -InformationAction Continue "Server Manager URL - https://$ServerURL/manager"
                            }
                            Write-Information -InformationAction Continue "Server Rest URL - https://$ServerURL/rest"
                        }
                    }
                }
            }
        }else{
            throw "File directory validations failed for server or portal. Please check and run again."  
        }

    }elseif($Mode -ieq "Upgrade"){
        $HostingConfig = $null

        $OtherConfigs = @()
        
        Foreach($cf in $ConfigurationParametersFile){
            $cfJSON = (ConvertFrom-Json (Get-Content $cf -Raw))
            $cfHashtable = Convert-PSObjectToHashtable $cfJSON
            
            $HasPortalNodes = ($cfHashtable.AllNodes | Where-Object { $_.Role -icontains 'Portal'} | Measure-Object).Count -gt 0
            $HasServerNodes = ($cfHashtable.AllNodes | Where-Object { $_.Role -icontains 'Server'} | Measure-Object).Count -gt 0
            $HasDataStoreNodes = ($cfHashtable.AllNodes | Where-Object { $_.Role -icontains 'DataStore'} | Measure-Object).Count -gt 0

            if(($HasPortalNodes -or $HasDataStoreNodes) -and $HasServerNodes){
                $HostingConfig = $cfHashtable
            }else{
                $OtherConfigs += $cfHashtable
            }
        }
        
        if(-not($HostingConfig)){
            if($OtherConfigs.count -gt 1){
                throw "Cannot Upgrade more than one Unfedrated Sites at a time only. Pass only one Site at a time!"
            }
        }

        $JobFlag = $True
        if($JobFlag -eq $True){
            if($HostingConfig -or (-not($HostingConfig) -and $OtherConfigs)){              
                if(-not($HostingConfig)){
                    $PortalConfig = $OtherConfigs[0]
                }else{
                    $PortalConfig = $HostingConfig
                }

                $PortalLicenseFilePath = $PortalConfig.ConfigData.Portal.LicenseFilePath
                $PortalLicensePassword = $null

                if($PortalConfig.ConfigData.Portal.LicensePasswordFilePath){
                    $PortalLicensePassword = (Get-Content $PortalConfig.ConfigData.Credentials.Portal.LicensePasswordFilePath | ConvertTo-SecureString )
                }elseif($PortalConfig.ConfigData.Portal.LicensePassword){
                    $PortalLicensePassword = (ConvertTo-SecureString $PortalConfig.ConfigData.Credentials.Portal.LicensePassword -AsPlainText -Force)
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

                $PortalServiceAccountIsDomainAccount = $PortalConfig.ConfigData.Credentials.ServiceAccount.IsDomainAccount
                $PortalServiceAccountIsMSA = if($PortalConfig.ConfigData.Credentials.ServiceAccount.IsMSA){$PortalConfig.ConfigData.Credentials.ServiceAccount.IsMSA}else{ $false}
                $PortalServiceAccountPassword = if( $PortalConfig.ConfigData.Credentials.ServiceAccount.PasswordFilePath ){ Get-Content $PortalConfig.ConfigData.Credentials.ServiceAccount.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $PortalConfig.ConfigData.Credentials.ServiceAccount.Password -AsPlainText -Force }
                $PortalServiceAccountCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $PortalConfig.ConfigData.Credentials.ServiceAccount.UserName, $PortalServiceAccountPassword )
                
                $PortalSiteAdministratorPassword = if($PortalConfig.ConfigData.Portal.PortalAdministrator.PasswordFilePath ){ Get-Content $PortalConfig.ConfigData.Portal.PortalAdministrator.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $PortalConfig.ConfigData.Portal.PortalAdministrator.Password -AsPlainText -Force }
                $PortalSiteAdministratorCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $PortalConfig.ConfigData.Portal.PortalAdministrator.UserName, $PortalSiteAdministratorPassword )

                $HasPortalNodes = ($PortalConfig.AllNodes | Where-Object { $_.Role -icontains 'Portal'} | Measure-Object).Count -gt 0
                if($HasPortalNodes){
                    $HasPortalWANodes = ($PortalConfig.AllNodes | Where-Object { $_.Role -icontains 'PortalWebAdaptor'} | Measure-Object).Count -gt 0
                    if($HasPortalWANodes){
                        Write-Information -InformationAction Continue "WebAdaptor Uninstall"
                        ForEach($WANode in ($PortalConfig.AllNodes | Where-Object {$_.Role -icontains 'PortalWebAdaptor'})){
                            $NodeToAdd = @{ 
                                NodeName = $WANode.NodeName; 
                            }
                            if($WANode.TargetNodeEncyrptionCertificateFilePath -and $WANode.TargetNodeEncyrptionCertificateThumbprint){
                                $NodeToAdd["CertificateFile"] = $WANode.TargetNodeEncyrptionCertificateFilePath
                                $NodeToAdd["Thumbprint"] = $WANode.TargetNodeEncyrptionCertificateThumbprint
                            }else{
                                $NodeToAdd["PSDscAllowPlainTextPassword"] = $true
                            }
                            
                            $WebAdaptorUninstallArgs = @{
                                ConfigurationData = @{ AllNodes = @( $NodeToAdd ) }
                                Version = $PortalConfig.ConfigData.Version 
                                InstallerPath = $PortalConfig.ConfigData.WebAdaptor.Installer.Path 
                                Context = $PortalConfig.ConfigData.PortalContext
                            }
                            
                            $JobFlag = Invoke-DSCJob -ConfigurationName "WebAdaptorUninstall" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $WebAdaptorUninstallArgs -Credential $Credential -DebugMode $DebugMode
                        }
                    }

                    if($JobFlag -eq $True){
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
                                InstallerPath = $PortalConfig.ConfigData.Portal.Installer.Path
                                ServiceAccount = $PortalServiceAccountCredential
                                IsServiceAccountDomainAccount = $PortalServiceAccountIsDomainAccount
                                IsServiceAccountMSA = $PortalServiceAccountIsMSA
                            }
                            if((($MajorVersion -eq 7 -and $MinorVersion -eq 1) -or ($MajorVersion -ge 8)) -and $PortalConfig.ConfigData.Portal.Installer.WebStylesPath){
                                $PortalUpgradeArgs.Add("WebStylesInstallerPath",$PortalConfig.ConfigData.Portal.Installer.WebStylesPath)
                            }

                            $JobFlag = Invoke-DSCJob -ConfigurationName "PortalUpgradeV2" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $PortalUpgradeArgs -Credential $Credential -DebugMode $DebugMode

                            if($JobFlag -eq $True){
                                $PortalPostUpgradeCD = @{ AllNodes = @( $PrimaryNodeToAdd ); }

                                $PortalPostUpgradeArgs = @{
                                    ConfigurationData = $PortalPostUpgradeCD
                                    PortalSiteAdministratorCredential = $PortalSiteAdministratorCredential 
                                }

                                $JobFlag = Invoke-DSCJob -ConfigurationName "PortalPostUpgradeV2" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $PortalPostUpgradeArgs -Credential $Credential -DebugMode $DebugMode
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
                                InternalLoadBalancer = if($PortalConfig.ConfigData.Server.InternalLoadBalancer){ $PortalConfig.ConfigData.Server.InternalLoadBalancer }else{ $null }
                                IsMultiMachinePortal = $IsMultiMachinePortal
                                AdminEmail = $PortalConfig.ConfigData.Portal.PortalAdministrator.Email
                                AdminSecurityQuestionIndex = $PortalConfig.ConfigData.Portal.PortalAdministrator.SecurityQuestionIndex
                                AdminSecurityAnswer = $PortalConfig.ConfigData.Portal.PortalAdministrator.SecurityAnswer
                            }

                            if($IsMultiMachinePortal){
                                $PortalUpgradeArgs.Add("StandbyMachineName", $StandbyNodeToAdd.NodeName)
                                $PortalUpgradeArgs.Add("InstallDir", $PortalConfig.ConfigData.Portal.Installer.InstallDir)
                                $PortalUpgradeArgs.Add("ContentDir", $PortalConfig.ConfigData.Portal.Installer.ContentDir)
                            }
                            
                            $JobFlag = Invoke-DSCJob -ConfigurationName "PortalUpgradeV1" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $PortalUpgradeArgs -Credential $Credential -DebugMode $DebugMode

                            if($IsMultiMachinePortal -and ($JobFlag -eq $True)){
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

                                if($PortalConfig.ConfigData.CloudStorageType){
                                    $CloudStorageCredentials = $null
                                    if($PortalConfig.ConfigData.Credentials.CloudStorageAccount){
                                        $CloudStorageAccountPassword = if( $PortalConfig.ConfigData.Credentials.CloudStorageAccount.PasswordFilePath ){ Get-Content $PortalConfig.ConfigData.Credentials.CloudStorageAccount.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $PortalConfig.ConfigData.Credentials.CloudStorageAccount.Password -AsPlainText -Force }
                                        $CloudStorageCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $PortalConfig.ConfigData.Credentials.CloudStorageAccount.UserName, $CloudStorageAccountPassword )
                                    }else{
                                        throw "No credentials provided for Cloud Storage for $($PortalConfig.ConfigData.CloudStorageType)"
                                    }
                                    
                                    $PortalUpgradeStandbyArgs["CloudStorageType"] = $PortalConfig.ConfigData.CloudStorageType
                                    $PortalUpgradeStandbyArgs["AzureFileShareName"]  = if($PortalConfig.ConfigData.CloudStorageType -ieq "AzureFiles"){ $PortalConfig.ConfigData.AzureFileShareName }else{ $null }
                                    $PortalUpgradeStandbyArgs["CloudNamespace"] = $PortalConfig.ConfigData.CloudNamespace
                                    $PortalUpgradeStandbyArgs["CloudStorageCredentials"] = $CloudStorageCredentials
                                }

                                $JobFlag = Invoke-DSCJob -ConfigurationName "PortalUpgradeStandbyJoinV1" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $PortalUpgradeStandbyArgs -Credential $Credential -DebugMode $DebugMode
                            }
                        }

                        if(($JobFlag -eq $True) -and $HasPortalWANodes){
                            Write-Information -InformationAction Continue "WebAdaptor Upgrade"
                            ForEach($WANode in ($PortalConfig.AllNodes | Where-Object {$_.Role -icontains 'PortalWebAdaptor'})){
                                $WAExternalHostName = if(($WANode.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor'}  | Measure-Object).Count -gt 0){($WANode.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor' }  | Select-Object -First 1).CNameFQDN }else{ Get-FQDN $WANode.NodeName }
                                $NodeToAdd = @{ 
                                    NodeName = $WANode.NodeName; 
                                    ExternalHostName = $WAExternalHostName
                                }
                                
                                if($WANode.TargetNodeEncyrptionCertificateFilePath -and $WANode.TargetNodeEncyrptionCertificateThumbprint){
                                    $NodeToAdd["CertificateFile"] = $WANode.TargetNodeEncyrptionCertificateFilePath
                                    $NodeToAdd["Thumbprint"] = $WANode.TargetNodeEncyrptionCertificateThumbprint
                                }else{
                                    $NodeToAdd["PSDscAllowPlainTextPassword"] = $true
                                }

                                $WebAdaptorInstallArgs = @{
                                    ConfigurationData = @{ AllNodes = @($NodeToAdd) }
                                    WebAdaptorRole = "PortalWebAdaptor" 
                                    Version = $PortalConfig.ConfigData.Version
                                    InstallerPath = $PortalConfig.ConfigData.WebAdaptor.Installer.Path 
                                    Context = $PortalConfig.ConfigData.PortalContext 
                                    ComponentHostName = $PrimaryNodeToAdd.NodeName
                                    SiteAdministratorCredential = $PortalSiteAdministratorCredential
                                }

                                $JobFlag = Invoke-DSCJob -ConfigurationName "WebAdaptorInstall" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $WebAdaptorInstallArgs -Credential $Credential -DebugMode $DebugMode
                            }
                        }
                    }
                }
            }

            if(-not($HostingConfig)){
                $ServerConfig = $OtherConfigs[0]
            }else{
                $ServerConfig = $HostingConfig
            }

            $PrimaryServerMachine = ""
            for ( $i = 0; $i -lt $ServerConfig.AllNodes.count; $i++ ){

                $Role = $ServerConfig.AllNodes[$i].Role
                if($Role -icontains 'Server' -and -not($PrimaryServerMachine)){
                    $PrimaryServerMachine  = $ServerConfig.AllNodes[$i].NodeName
                }
            }
            
            if($JobFlag -eq $True){
                if($HostingConfig){
                    Write-Information -InformationAction Continue "Hosting Server Upgrade"
                    if($Credential){
                        $JobFlag = Invoke-ServerUpgradeScript -cf $HostingConfig -Credential $Credential -DebugMode $DebugMode
                    }else{
                        $JobFlag = Invoke-ServerUpgradeScript -cf $HostingConfig -DebugMode $DebugMode
                    }
                }
            }

            if($JobFlag -eq $True){
                if($OtherConfigs){
                    for ( $i = 0; $i -lt $OtherConfigs.count; $i++ ){
                        Write-Information -InformationAction Continue "Other Server Upgrade"
                        if($Credential){
                            $JobFlag = Invoke-ServerUpgradeScript -cf $OtherConfigs[$i] -Credential $Credential -DebugMode $DebugMode
                        }else{
                            $JobFlag = Invoke-ServerUpgradeScript -cf $OtherConfigs[$i] -DebugMode $DebugMode
                        }
                    }
                }
            }
            
            if($JobFlag -eq $True){
                if($HostingConfig -or (-not($HostingConfig) -and $OtherConfigs)){
                    if(-not($HostingConfig)){
                        $DSConfig = $OtherConfigs[0]
                    }else{
                        $DSConfig = $HostingConfig
                    }
                    
                    $DSServiceAccountIsDomainAccount = $DSConfig.ConfigData.Credentials.ServiceAccount.IsDomainAccount
                    $DSServiceAccountIsMSA = if($DSConfig.ConfigData.Credentials.ServiceAccount.IsMSA){$DSConfig.ConfigData.Credentials.ServiceAccount.IsMSA}else{ $false}  
                    $DSSAPassword = if( $DSConfig.ConfigData.Credentials.ServiceAccount.PasswordFilePath ){ Get-Content $DSConfig.ConfigData.Credentials.ServiceAccount.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $DSConfig.ConfigData.Credentials.ServiceAccount.Password -AsPlainText -Force }
                    $DSServiceAccountCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $DSConfig.ConfigData.Credentials.ServiceAccount.UserName, $DSSAPassword )
                    
                    $DSPSAPassword = if($DSConfig.ConfigData.Server.PrimarySiteAdmin.PasswordFilePath ){ Get-Content $DSConfig.ConfigData.Server.PrimarySiteAdmin.PasswordFilePath | ConvertTo-SecureString }else{ ConvertTo-SecureString $DSConfig.ConfigData.Server.PrimarySiteAdmin.Password -AsPlainText -Force }
                    $DSSiteAdministratorCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ( $DSConfig.ConfigData.Server.PrimarySiteAdmin.UserName, $DSPSAPassword )
                    
                    $HasDataStoreNodes = ($DSConfig.AllNodes | Where-Object { $_.Role -icontains 'DataStore'} | Measure-Object).Count -gt 0
                    if($HasDataStoreNodes){
                        $Version = $DSConfig.ConfigData.Version
                        $VersionArray = $Version.split(".")
                        Write-Information -InformationAction Continue "DataStore Upgrade to $Version"
                        if($VersionArray[1] -gt 5){
                            $cd = @{AllNodes = @()}

                            $PrimaryDataStore = $null
                            $PrimaryBigDataStore = @{AllNodes = @()}
                            $PrimaryTileCache = $null
                            $PrimaryDataStoreCD = @{AllNodes = @()}
                            $PrimaryBigDataStoreCD = $null
                            $PrimaryTileCacheCD = @{AllNodes = @()}

                            for ( $i = 0; $i -lt $DSConfig.AllNodes.count; $i++ ){
                                $DSNode = $DSConfig.AllNodes[$i]
                                if($DSNode.Role -icontains 'DataStore'){
                                    $DsTypes = $DSNode.DataStoreTypes

                                    $NodeToAdd = @{
                                        NodeName = $DSNode.NodeName
                                    }

                                    if($DSNode.TargetNodeEncyrptionCertificateFilePath -and $DSNode.TargetNodeEncyrptionCertificateThumbprint){
                                        $NodeToAdd["CertificateFile"] = $DSNode.TargetNodeEncyrptionCertificateFilePath
                                        $NodeToAdd["Thumbprint"] = $DSNode.TargetNodeEncyrptionCertificateThumbprint
                                    }else{
                                        $NodeToAdd["PSDscAllowPlainTextPassword"] = $true
                                    }
                                   
                                    if($DsTypes -icontains "Relational" -and ($null -eq $PrimaryDataStore))
                                    {
                                        $PrimaryDataStore = $DSNode
                                        $PrimaryDataStoreCD.AllNodes += $NodeToAdd
                                    }
                                    if($DsTypes -icontains "SpatioTemporal" -and ($null -eq $PrimaryBigDataStore))
                                    {
                                        $PrimaryBigDataStore = $DSNode
                                        $PrimaryBigDataStoreCD.AllNodes += $NodeToAdd
                                    }
                                    if($DsTypes -icontains "TileCache")
                                    {
                                        $NodeToAdd["HasMultiMachineTileCache"] = (($DSConfig.AllNodes | Where-Object { $_.DataStoreTypes -icontains 'TileCache' }  | Measure-Object).Count -gt 1)

                                        if($null -eq $PrimaryTileCache){
                                            $PrimaryTileCache = $DSNode
                                            $PrimaryTileCacheCD.AllNodes += $NodeToAdd
                                        }
                                    }
                                    $cd.AllNodes += $NodeToAdd 
                                }
                            }

                            $DataStoreUpgradeInstallArgs = @{
                                ConfigurationData = $cd 
                                Version = $DSConfig.ConfigData.Version 
                                ServiceAccount = $DSServiceAccountCredential
                                IsServiceAccountDomainAccount = $DSServiceAccountIsDomainAccount
                                IsServiceAccountMSA =   $DSServiceAccountIsMSA
                                InstallerPath = $DSConfig.ConfigData.DataStore.Installer.Path 
                                InstallDir = $DSConfig.ConfigData.DataStore.Installer.InstallDir
                            }

                            $JobFlag = Invoke-DSCJob -ConfigurationName "DataStoreUpgradeInstall" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $DataStoreUpgradeInstallArgs -Credential $Credential -DebugMode $DebugMode

                            if($JobFlag -and ($null -ne $PrimaryDataStore)){
                                $DataStoreUpgradeConfigureArgs = @{
                                    ConfigurationData = $PrimaryDataStoreCD 
                                    ServerPrimarySiteAdminCredential = $DSSiteAdministratorCredential
                                    ServerMachineName = $PrimaryServerMachine
                                    ContentDirectoryLocation = $DSConfig.ConfigData.DataStore.ContentDirectoryLocation 
                                    InstallDir = $DSConfig.ConfigData.DataStore.Installer.InstallDir 
                                    Version = $DSConfig.ConfigData.Version
                                }

                                $JobFlag = Invoke-DSCJob -ConfigurationName "DataStoreUpgradeConfigure" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $DataStoreUpgradeConfigureArgs -Credential $Credential -DebugMode $DebugMode
                            }

                            if(($JobFlag -eq $True) -and ($null -ne $PrimaryTileCache) -and ($PrimaryDataStore.NodeName -ne $PrimaryTileCache.NodeName)){
                                $DataStoreUpgradeConfigureArgs = @{
                                    ConfigurationData = $PrimaryTileCacheCD
                                    ServerPrimarySiteAdminCredential = $DSSiteAdministratorCredential 
                                    ServerMachineName = $PrimaryServerMachine
                                    ContentDirectoryLocation = $DSConfig.ConfigData.DataStore.ContentDirectoryLocation 
                                    InstallDir = $DSConfig.ConfigData.DataStore.Installer.InstallDir 
                                    Version = $DSConfig.ConfigData.Version
                                }
                                $JobFlag = Invoke-DSCJob -ConfigurationName "DataStoreUpgradeConfigure" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $DataStoreUpgradeConfigureArgs -Credential $Credential -DebugMode $DebugMode
                            }

                            if(($JobFlag -eq $True) -and ($null -ne $PrimaryBigDataStore) -and ($PrimaryDataStore.NodeName -ne $PrimaryTileCache.NodeName) -and ($PrimaryDataStore.NodeName -ne $PrimaryBigDataStore.NodeName)){
                                $DataStoreUpgradeConfigureArgs = @{
                                    ConfigurationData = $PrimaryBigDataStoreCD
                                    ServerPrimarySiteAdminCredential = $DSSiteAdministratorCredential 
                                    ServerMachineName = $PrimaryServerMachine
                                    ContentDirectoryLocation = $DSConfig.ConfigData.DataStore.ContentDirectoryLocation 
                                    InstallDir = $DSConfig.ConfigData.DataStore.Installer.InstallDir 
                                    Version = $DSConfig.ConfigData.Version
                                }
                                $JobFlag = Invoke-DSCJob -ConfigurationName "DataStoreUpgradeConfigure" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $DataStoreUpgradeConfigureArgs -Credential $Credential -DebugMode $DebugMode
                            }
                        }else{
                            $BigDataStoreCD = @{ AllNodes = @() }
                            for ( $i = 0; $i -lt $DSConfig.AllNodes.count; $i++ ){
                                $DSNode = $DSConfig.AllNodes[$i]
                                $Role = $DSNode.Role
                                if($Role -icontains 'DataStore'){
                                    $NodeToAdd = @{
                                        NodeName = $DSNode.NodeName
                                    }
                                    if($DSNode.DataStoreTypes -icontains "TileCache"){
                                        $NodeToAdd["HasMultiMachineTileCache"] = (($DSConfig.AllNodes | Where-Object { $_.DataStoreTypes -icontains 'TileCache' }  | Measure-Object).Count -gt 1)
                                    }

                                    if($DSNode.TargetNodeEncyrptionCertificateFilePath -and $DSNode.TargetNodeEncyrptionCertificateThumbprint){
                                        $NodeToAdd["CertificateFile"] = $DSNode.TargetNodeEncyrptionCertificateFilePath
                                        $NodeToAdd["Thumbprint"] = $DSNode.TargetNodeEncyrptionCertificateThumbprint
                                    }else{
                                        $NodeToAdd["PSDscAllowPlainTextPassword"] = $true
                                    }

                                    $DataStoreUpgradeInstallArgs = @{
                                        ConfigurationData = @{ AllNodes = @($NodeToAdd) }
                                        Version = $DSConfig.ConfigData.Version 
                                        ServiceAccount = $DSServiceAccountCredential 
                                        IsServiceAccountDomainAccount = $DSServiceAccountIsDomainAccount
                                        IsServiceAccountMSA = $DSServiceAccountIsMSA
                                        InstallerPath = $DSConfig.ConfigData.DataStore.Installer.Path 
                                        InstallDir = $DSConfig.ConfigData.DataStore.Installer.InstallDir
                                    }
        
                                    $JobFlag = Invoke-DSCJob -ConfigurationName "DataStoreUpgradeInstall" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $DataStoreUpgradeInstallArgs -Credential $Credential -DebugMode $DebugMode
                                    
                                    if($JobFlag -eq $True){
                                        $DataStoreUpgradeConfigureArgs = @{
                                            ConfigurationData = @{ AllNodes = @($NodeToAdd) }
                                            ServerPrimarySiteAdminCredential = $DSSiteAdministratorCredential 
                                            ServerMachineName = $PrimaryServerMachine
                                            ContentDirectoryLocation = $DSConfig.ConfigData.DataStore.ContentDirectoryLocation 
                                            InstallDir = $DSConfig.ConfigData.DataStore.Installer.InstallDir 
                                            Version = $DSConfig.ConfigData.Version
                                        }

                                        $JobFlag = Invoke-DSCJob -ConfigurationName "DataStoreUpgradeConfigure" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $DataStoreUpgradeConfigureArgs -Credential $Credential -DebugMode $DebugMode
                                    
                                        if($DSNode.DataStoreTypes -icontains "SpatioTemporal"){
                                            $BigDataStoreCD.AllNodes += $NodeToAdd
                                        }
                                        if($JobFlag -eq $True){
                                            break
                                        }
                                    }
                                }
                            }
                            if(($JobFlag -eq $True) -and ($BigDataStoreCD.AllNodes.Count -gt 0)){
                                Write-Information -InformationAction Continue "BigDataStore Upgrade"
                                Foreach($nd in $BigDataStoreMachinesArray){
                                    $SpatioTemporalDatastoreStartArgs = @{
                                        ConfigurationData = $BigDataStoreCD
                                        ServerPrimarySiteAdminCredential = $DSSiteAdministratorCredential 
                                        ServerMachineName = $PrimaryServerMachine 
                                    }

                                    $JobFlag = Invoke-DSCJob -ConfigurationName "SpatioTemporalDatastoreStart" -ConfigurationFolderPath "Configurations-OnPrem\Upgrades" -Arguments $SpatioTemporalDatastoreStartArgs -Credential $Credential -DebugMode $DebugMode

                                    if($JobFlag -eq $True){
                                        break
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
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
        $DebugSwitch
    )

    $DebugMode = if($DebugSwitch){ $True }else{ $False } 

    $Args = @{
        NodeName = $NodeName 
        WebAppName = $WebAppName 
        SourceDir = $SourceDir
    }

    Invoke-DSCJob -ConfigurationName "DeployWebApp" -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $Args -Credential $Credential -DebugMode $DebugMode
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
        $DebugSwitch
    )
    
    $DebugMode = if($DebugSwitch){ $True }else{ $False } 
    
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
        PublisherAccountCredentials = $PublisherAccountCredential
        PortalHostName = $cf.PortalHostName
        PortalPort = $cf.PortalPort
        PortalContext = $cf.PortalContext
        ServerHostName = $cf.ServerHostName
        ServerContext = $cf.ServerContext
        ServerPort = $cf.ServerPort
        GISServices = $cf.GISServices
    }
    $ConfigurationName = "PublishGISService"
    Invoke-DSCJob -ConfigurationName $ConfigurationName -ConfigurationFolderPath "Configurations-OnPrem" -Arguments $ConfigData -Credential $Credential -DebugMode $DebugMode
}

Export-ModuleMember -Function Get-FQDN, Invoke-ArcGISConfiguration, Invoke-PublishWebApp, Invoke-BuildArcGISAzureImage
