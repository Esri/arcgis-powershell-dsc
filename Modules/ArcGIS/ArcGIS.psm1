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
                    if($DnsRecord -eq $null) {
                        $DnsRecord = Resolve-DnsName -Name $MachineName -Type A -ErrorAction Ignore                
                    }
                }
                if($DnsRecord -eq $null) {
                    $machine = (Get-WmiObject -Class Win32_ComputerSystem).Name
                    $domain = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName $MachineName).DNSDomain
                    $Dns = "$($machine).$($domain)"
                    $ResolvedDns = $true
                }
            }
            Catch {
                Write-Verbose "Error Resolving DNS $($_)"            
            }
            if($DnsRecord -ne $null) {
                [void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.WindowsAzure.ServiceRuntime')
                $UseIP = $false
                if (('Microsoft.WindowsAzure.ServiceRuntime.RoleEnvironment' -as [type]) -and ([Microsoft.WindowsAzure.ServiceRuntime.RoleEnvironment]::DeploymentId -ne $null))
                {
                    $UseIP = $true
                    Write-Verbose "Running on Microsoft Azure Cloud Service VM (Web/Worker) Role. Using IP Address instead of hostnames"
                }
                $Dns = if($UseIP) { $DnsRecord.IPAddress } else { $DnsRecord.Name }
                if($Dns -ne $null -and $Dns.Length -gt 0)
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

            Write-Output -NoEnumerate $collection
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
                        Write-Host "[]$item" -foregroundcolor red
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

    Write-Host "Logs Directory: $LogsPath"
}

function Start-DSCJob {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param(
        [Parameter(Mandatory=$True)]
        $ConfigurationName,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $Credential,
        
        [System.Boolean]
        $DebugMode = $False
    )

    Write-Host "Starting DSC Job:- $ConfigurationName"
    $JobTimer = [System.Diagnostics.Stopwatch]::StartNew()
    if($Credential)
    {
        $Job = Start-DscConfiguration -Path ".\$($ConfigurationName)" -Force -Verbose -Credential $Credential
    }
    else
    {
        $Job = Start-DscConfiguration -Path ".\$($ConfigurationName)" -Force -Verbose
    }
    Trace-DSCJob -Job $Job -JobName $ConfigurationName -DebugMode $DebugMode
    Write-Host "Finished DSC Job:- $ConfigurationName. Time Taken - $($JobTimer.elapsed)"
    Write-Host "$($ConfigurationName) - $($Job.state)"
    $result = $False
    if($Job.state -ieq "Completed"){
        $result = $True
    }  
    $result  
}

function Get-ArcGISURL
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $ConfigurationData
    )
    
    $AllNodes = $ConfigurationData.AllNodes
    
    $PrimaryServerMachineNode = ""
    $PrimaryPortalMachineNode = ""
    $PortalContext = $ConfigurationData.ConfigData.PortalContext 
    $ServerContext = $ConfigurationData.ConfigData.ServerContext 

    for ( $i = 0; $i -lt $AllNodes.count; $i++ )
    {
        $Role = $AllNodes[$i].Role
        if($Role -icontains 'Server' -and -not($PrimaryServerMachine))
        {
            $PrimaryServerMachineNode  = $AllNodes[$i]
        }

        if($Role -icontains 'Portal' -and -not($PrimaryPortalMachine))
        {
            $PrimaryPortalMachineNode= $AllNodes[$i]
        }
    }

    if($PrimaryPortalMachineNode)
    {
        $PortalExternalDNSName = Get-FQDN $PrimaryPortalMachineNode.NodeName
        
        if(($PrimaryPortalMachineNode.SslCertificates | Where-Object { $_.Target -icontains 'Portal'}  | Measure-Object).Count -gt 0)
        {
            $PortalExternalDNSName = ($PrimaryPortalMachineNode.SslCertificates | Where-Object { $_.Target -icontains 'Portal' }  | Select-Object -First 1).Alias
        }

        $PortalAdminURL = "https://$($PortalExternalDNSName):7443/arcgis/portaladmin"
        $PortalURL = "https://$($PortalExternalDNSName):7443/arcgis/home"
    }

    if($PrimaryServerMachineNode)
    {
        $ServerExternalDNSName = Get-FQDN $PrimaryServerMachineNode.NodeName
        
        if(($PrimaryServerMachineNode.SslCertificates | Where-Object { $_.Target -icontains 'Server'}  | Measure-Object).Count -gt 0)
        {
            $PortalExternalDNSName = ($PrimaryServerMachineNode.SslCertificates | Where-Object { $_.Target -icontains 'Server' }  | Select-Object -First 1).Alias
        }
        
        $ServerAdminURL = "https://$($ServerExternalDNSName):6443/arcgis/admin"
        $ServerURL = "https://$($ServerExternalDNSName):6443/arcgis/manager"
        $RestURL = "https://$($ServerExternalDNSName):6443/arcgis/rest"
    }

    $HasLoadBalancer = (($AllNodes | Where-Object { $_.Role -icontains 'LoadBalancer' }  | Measure-Object).Count -gt 0)
    if($HasLoadBalancer)
    {
        $LBMachine = ($AllNodes | Where-Object { $_.Role -icontains 'LoadBalancer' }| Sort-Object | Select-Object -First 1)
        $LBExternalDNSName = Get-FQDN $LBMachine.NodeName
        if(($LBMachine.SslCertificates | Where-Object { $_.Target -icontains 'LoadBalancer'}  | Measure-Object).Count -gt 0)
        {
            $SSLCertificate = $LBMachine.SslCertificates | Where-Object { $_.Target -icontains 'LoadBalancer' }  | Select-Object -First 1
            $LBExternalDNSName = $SSLCertificate.Alias
        }
    }
    
    if($ConfigurationData.ConfigData.ExternalLoadBalancer){
        $HasLoadBalancer = $true
        $LBExternalDNSName = $ConfigurationData.ConfigData.ExternalLoadBalancer
    }

    if((($AllNodes | Where-Object { ($_.Role -icontains 'PortalWebAdaptor')}  | Measure-Object).Count -gt 0))
    {
        $PortalWAMachineNode = ($AllNodes | Where-Object { ($_.Role -icontains 'PortalWebAdaptor')} | Select-Object -First 1)
        $PortalExternalDNSName = Get-FQDN $PortalWAMachineNode.NodeName
        if(($PortalWAMachineNode.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor'}  | Measure-Object).Count -gt 0)
        {
            $PortalExternalDNSName = ($PortalWAMachineNode.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor' }  | Select-Object -First 1).Alias
        }

        if($HasLoadBalancer)
        {
            $PortalExternalDNSName = $LBExternalDNSName
        }
    }
    if((($AllNodes | Where-Object { ($_.Role -icontains 'ServerWebAdaptor')}  | Measure-Object).Count -gt 0))
    {
        $ServerWAMachineNode = ($AllNodes | Where-Object { ($_.Role -icontains 'ServerWebAdaptor')} | Select-Object -First 1)
        $ServerWAMachineName = $ServerWAMachineNode.NodeName
        $ServerExternalDNSName = Get-FQDN $ServerWAMachineName
        if(($ServerWAMachineNode.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor'}  | Measure-Object).Count -gt 0)
        {
            $SSLCertificate = $ServerWAMachineNode.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor' }  | Select-Object -First 1
            $ServerExternalDNSName = $SSLCertificate.Alias
        }

        if($HasLoadBalancer){
            $ServerExternalDNSName = $LBExternalDNSName
        }
    }
    
    if($PortalContext)
    {
        $PortalAdminURL = "https://$PortalExternalDNSName/$PortalContext/portaladmin"
        $PortalURL = "https://$PortalExternalDNSName/$PortalContext/home"
    }
    if($ServerContext)
    {
        $ServerAdminURL = "https://$ServerExternalDNSName/$ServerContext/admin"
        $ServerURL = "https://$ServerExternalDNSName/$ServerContext/manager"
        $RestURL = "https://$ServerExternalDNSName/$ServerContext/rest"
    }
    
    if($PrimaryPortalMachineNode)
    {
        Write-Host "Portal Admin URL - $PortalAdminURL"
        Write-Host "Portal URL - $PortalURL"    
    }
    if($PrimaryServerMachineNode)
    {
        Write-Host "Server Admin URL - $ServerAdminURL"
        Write-Host "Server Manager URL - $ServerURL"
        Write-Host "Server Rest URL - $RestURL"
    }
}

function ServerUpgradeScript {
    
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

    $SevenZipInstallerPath = if($cf.ConfigData.SevenZipInstallerPath){$cf.ConfigData.SevenZipInstallerPath}else{$null}
    $SevenZipInstallerDir = if($cf.ConfigData.SevenZipInstallerDir){$cf.ConfigData.SevenZipInstallerDir}else{$null}

    $cfSAPassword = ConvertTo-SecureString $cf.ConfigData.Credentials.ServiceAccount.Password -AsPlainText -Force
    $cfSACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($cf.ConfigData.Credentials.ServiceAccount.UserName, $cfSAPassword )

    $cfPSAPassword = ConvertTo-SecureString $cf.ConfigData.Credentials.PrimarySiteAdmin.Password -AsPlainText -Force
    $cfPSACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($cf.ConfigData.Credentials.PrimarySiteAdmin.UserName, $cfPSAPassword )
    
    $JobFlag = $True

    #ServerWebAdaptorUninstall
    Write-Host "WA Server Uninstall"
    ForEach($WANode in ($cf.AllNodes | Where-Object {$_.Role -icontains 'ServerWebAdaptor'}).NodeName){
        $cd = @{
            AllNodes = @(
                @{
                    NodeName = $WANode
                    PSDscAllowPlainTextPassword = $true
                }
            )
        }    
        if(Test-Path ".\WebAdaptorUninstall") {
            Remove-Item ".\WebAdaptorUninstall" -Force -ErrorAction Ignore -Recurse
        }
        WebAdaptorUninstall -ConfigurationData $cd -Version $cf.ConfigData.Version -InstallerPath $cf.ConfigData.WebAdaptor.Installer.Path -Context $cf.ConfigData.ServerContext  -Verbose
        #Start-DscConfiguration .\WebAdaptorUninstall -Verbose -Wait -Force
        if($Credential){
            $JobFlag = Start-DSCJob -ConfigurationName WebAdaptorUninstall -Credential $Credential -DebugMode $DebugMode
        }else{
            $JobFlag = Start-DSCJob -ConfigurationName WebAdaptorUninstall -DebugMode $DebugMode
        }
        if(-not($JobFlag)){
            break
        }
    }


    #UpgradeServers
    if($JobFlag){
        Write-Host "Server Upgrade"
        $cfPrimaryServerMachine = ""
        for ( $i = 0; $i -lt $cf.AllNodes.count; $i++ ){
            if($cf.AllNodes[$i].Role -icontains 'Server'){
                $ServerMachine = $cf.AllNodes[$i].NodeName
                if(-not($cfPrimaryServerMachine)){
                    $cfPrimaryServerMachine = $ServerMachine
                }
                $cd = @{
                    AllNodes = @(
                        @{
                            NodeName = $ServerMachine
                            PSDscAllowPlainTextPassword = $true
                        }
                    )
                }
                if(Test-Path ".\ServerUpgrade") {
                    Remove-Item ".\ServerUpgrade" -Force -ErrorAction Ignore -Recurse
                }

                $IsSADomainAccount = if($cf.ConfigData.Credentials.ServiceAccount.IsDomainAccount){$True}else{$False}
                $LicenseFilePath = $cf.ConfigData.Server.LicenseFilePath
                $LicensePassword = $null
                if($cf.ConfigData.Server.LicensePassword){
                    $LicensePassword = $cf.ConfigData.Server.LicensePassword
                }
                
                if($cf.ConfigData.GeoEventServer.LicenseFilePath){
                    $LicenseFilePath = $cf.ConfigData.GeoEventServer.LicenseFilePath
                    if($cf.ConfigData.GeoEventServer.LicensePassword){
                        $LicensePassword = $cf.ConfigData.GeoEventServer.LicensePassword
                    }
                }
                
                if($cf.AllNodes[$i].ServerLicensePath -and $cf.AllNodes[$i].ServerLicensePassword){
                    $LicenseFilePath = $cf.AllNodes[$i].ServerLicenseFilePath
                    $LicensePassword = $cf.AllNodes[$i].ServerLicensePassword
                }

                if($cf.ConfigData.ServerRole -ieq "GeoEvent"){
                    ServerUpgrade -ConfigurationData $cd -Version $cf.ConfigData.Version -ServiceAccount $cfSACredential -IsSADomainAccount $IsSADomainAccount -InstallerPath $cf.ConfigData.Server.Installer.Path `
                                -LicensePath $LicenseFilePath -LicensePassword $LicensePassword -ServerRole $cf.ConfigData.ServerRole -GeoEventServerInstaller $cf.ConfigData.GeoEventServer.Installer.Path `
                                -SevenZipInstallerPath $SevenZipInstallerPath -SevenZipInstallerDir $SevenZipInstallerDir -Verbose
                }else{
                    ServerUpgrade -ConfigurationData $cd -Version $cf.ConfigData.Version -ServiceAccount $cfSACredential -IsSADomainAccount $IsSADomainAccount -InstallerPath $cf.ConfigData.Server.Installer.Path `
                                -LicensePath $LicenseFilePath -LicensePassword $LicensePassword -ServerRole $cf.ConfigData.ServerRole `
                                -SevenZipInstallerPath $SevenZipInstallerPath -SevenZipInstallerDir $SevenZipInstallerDir -Verbose    
                }
                
                if($Credential){
                    $JobFlag = Start-DSCJob -ConfigurationName ServerUpgrade -Credential $Credential -DebugMode $DebugMode
                }else{
                    $JobFlag = Start-DSCJob -ConfigurationName ServerUpgrade -DebugMode $DebugMode
                }
                if(-not($JobFlag)){
                    break
                }
            }
        }
        if($JobFlag){
            #UpgradeServerWebAdaptor
            Write-Host "WA Server Install"
            ForEach($WANode in ($cf.AllNodes | Where-Object {$_.Role -icontains 'ServerWebAdaptor'})){
                $WAExternalHostName = if(($WANode.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor'}  | Measure-Object).Count -gt 0){($WANode.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor' }  | Select-Object -First 1).Alias }else{ Get-FQDN $WANode.NodeName }
                $cd = @{
                    AllNodes = @(
                        @{
                            NodeName = $WANode.NodeName
                            ExternalHostName = $WAExternalHostName
                            PSDscAllowPlainTextPassword = $true
                        }
                    )
                }
                if(Test-Path ".\WebAdaptorInstall") {
                    Remove-Item ".\WebAdaptorInstall" -Force -ErrorAction Ignore -Recurse
                }
                WebAdaptorInstall -ConfigurationData $cd -WebAdaptorRole "ServerWebAdaptor" -Version $cf.ConfigData.Version `
                                    -InstallerPath $cf.ConfigData.WebAdaptor.Installer.Path -Context $cf.ConfigData.ServerContext `
                                    -ComponentHostName $cfPrimaryServerMachine -PSACredential $cfPSACredential `
                                    -SevenZipInstallerPath $SevenZipInstallerPath -SevenZipInstallerDir $SevenZipInstallerDir -Verbose
                if($Credential){
                    $JobFlag = Start-DSCJob -ConfigurationName WebAdaptorInstall -Credential $Credential -DebugMode $DebugMode
                }else{
                    $JobFlag = Start-DSCJob -ConfigurationName WebAdaptorInstall -DebugMode $DebugMode
                }
                if(-not($JobFlag)){
                    break
                }
            }
        }
    }
    $JobFlag
}

function Publish-WebApp
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
        $Credential
    )
    
    $ConfigurationName = "DeployWebApp"

    if(Test-Path ".\$ConfigurationName") {
        Remove-Item ".\$ConfigurationName" -Force -ErrorAction Ignore -Recurse
    }

    Write-Host "Dot Sourcing the Configuration:- $ConfigurationName"
    . "$PSScriptRoot\Configurations-OnPrem\$($ConfigurationName).ps1"
    
    Write-Host "Compiling the Configuration:- $ConfigurationName"
    & $ConfigurationName -NodeName $NodeName -WebAppName $WebAppName -SourceDir $SourceDir

    if($Credential){
        Start-DSCJob -ConfigurationName $ConfigurationName -Credential $Credential -DebugMode $DebugMode
    }else{
        Start-DSCJob -ConfigurationName $ConfigurationName -DebugMode $DebugMode
    }

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
    
    $DebugMode = $False

    if($DebugSwitch){
        $DebugMode = $true
    }

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
        Write-Host "Dot Sourcing the Configuration:- ArcGISDownloadInstallers"
        . "$PSScriptRoot\Configurations-AzureImageBuild\ArcGISDownloadInstallers.ps1" -Verbose:$false
        Write-Host "Compiling the Configuration:- ArcGISDownloadInstallers"
        if($UseAzureFiles){
            $cd = @{
                AllNodes = @(
                    @{
                        NodeName = "localhost"
                        PSDscAllowPlainTextPassword = $true
                    }
                )
            }
            ArcGISDownloadInstallers -Installers $InstallersConfig.Installers -UseAzureFiles $true -AFSCredential $AFSCredential -AFSEndpoint $AFSEndpoint -ConfigurationData $cd
        }else{
            ArcGISDownloadInstallers -Installers $InstallersConfig.Installers
        }
        
        if($Credential){
            $JobFlag = Start-DSCJob -ConfigurationName ArcGISDownloadInstallers -Credential $Credential -DebugMode $DebugMode
        }else{
            $JobFlag = Start-DSCJob -ConfigurationName ArcGISDownloadInstallers -DebugMode $DebugMode
        }
    }else{
        $JobFlag = $True
    }
    
    if($JobFlag -eq $True){
        if(-not($SkipFilesDownload)){
            Write-Host "Downloaded Installer Setups Successfully. Removing Download Installer Configuration File."
            if(Test-Path ".\ArcGISDownloadInstallers") {
                Remove-Item ".\ArcGISDownloadInstallers" -Force -ErrorAction Ignore -Recurse
            }
        }

        Write-Host "Dot Sourcing the Configuration:- ArcGISSetupConfiguration"
        . "$PSScriptRoot\Configurations-AzureImageBuild\ArcGISSetupConfiguration.ps1" -Verbose:$false

        $JobFlag = $False
        Write-Host "Compiling the Configuration:- ArcGISSetupConfiguration"
        ArcGISSetupConfiguration -Installers $InstallersConfig.Installers -WindowsFeatures $InstallersConfig.WindowsFeatures
        $JobFlag = Start-DSCJob -ConfigurationName ArcGISSetupConfiguration -DebugMode $DebugMode
        if($JobFlag -eq $True -and (Test-Path ".\ArcGISSetupConfiguration")) {
            Write-Host "Installed ArcGIS Setups Successfully. Removing Setup Configuration File."
            Remove-Item ".\ArcGISSetupConfiguration" -Force -ErrorAction Ignore -Recurse
        }
    }
}

function Configure-ArcGIS
{
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory=$True)]
        [System.Array]
        $ConfigurationParametersFile,    

        [ValidateSet("Install","InstallLicense","InstallLicenseConfigure","Uninstall","Upgrade","PublishGISService")]
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
    
    $DebugMode = $False

    if($DebugSwitch){
        $DebugMode = $true
    }

    if($Mode -ieq "Install" -or $Mode -ieq "InstallLicense" -or $Mode -ieq "InstallLicenseConfigure" -or $Mode -ieq "Uninstall" -or $Mode -ieq "PublishGISService"){

        Foreach($cf in $ConfigurationParametersFile){
            if(-not($ConfigurationParamsJSON)){
                $ConfigurationParamsJSON = (ConvertFrom-Json (Get-Content $cf -Raw))
            }
        }
        $ConfigurationParamsHashtable = Convert-PSObjectToHashtable $ConfigurationParamsJSON
        for ( $i = 0; $i -lt $ConfigurationParamsHashtable.AllNodes.count; $i++ ){
            if ($Credential)
            {
                $WMFVersion = Invoke-Command -ComputerName $ConfigurationParamsHashtable.AllNodes[$i].NodeName -ScriptBlock { $PSVersionTable.PSVersion.Major } -Credential $Credential 
            } else {
                $WMFVersion = Invoke-Command -ComputerName $ConfigurationParamsHashtable.AllNodes[$i].NodeName -ScriptBlock { $PSVersionTable.PSVersion.Major }
            }
            $ConfigurationParamsHashtable.AllNodes[$i].WMFVersion = [int]$WMFVersion.ToString()
        }
        
        $CommonNodeToAddForPlainText = @{
            NodeName = "*"
            PSDscAllowPlainTextPassword = $true
        }
       
        $ConfigurationParamsHashtable.AllNodes += $CommonNodeToAddForPlainText 

        if($Mode -ieq "Install" -or $Mode -ieq "InstallLicense" -or $Mode -ieq "InstallLicenseConfigure"){ 
            $ValidatePortalFileShare = $false
            if($ConfigurationParamsHashtable.ConfigData.Portal){
                $IsHAPortal = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'Portal' }  | Measure-Object).Count -gt 1)
                if($IsHAPortal)
                {
                    if($MappedDriveOverrideFlag)
                    {
                        $ValidatePortalFileShare = $True
                    }
                    else
                    {
                        if($ConfigurationParamsHashtable.ConfigData.Portal.ContentDirectoryLocation.StartsWith('\'))
                        {
                            $ValidatePortalFileShare = $True
                        }
                        else
                        {
                            throw "Config Directory Location path is not a fileshare path"
                        }
                    }
                }else{
                    $ValidatePortalFileShare = $True 
                }
            }else{
                $ValidatePortalFileShare = $True   
            }

            $ValidateServerFileShare = $false
            $IsHAServer = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'Server' }  | Measure-Object).Count -gt 1)
            if($IsHAServer)
            {
                if($MappedDriveOverrideFlag)
                {
                    $ValidateServerFileShare = $True
                }
                else
                {
                    if($ConfigurationParamsHashtable.ConfigData.Server.ConfigStoreLocation.StartsWith('\') -and $ConfigurationParamsHashtable.ConfigData.Server.ServerDirectoriesRootLocation.StartsWith('\'))
                    {
                        $ValidateServerFileShare = $True
                    }
                    else
                    {
                        throw "One or both of Config Store Location and Server Directories Root Location is not a fileshare path"
                    }
                }
            }
            else
            {
                $ValidateServerFileShare = $True 
            }

            if($ValidateServerFileShare -and $ValidatePortalFileShare){
                $JobFlag = $False

                Write-Host "Dot Sourcing the Configuration:- ArcGISInstall"
                . "$PSScriptRoot\Configurations-OnPrem\ArcGISInstall.ps1" -Verbose:$false

                Write-Host "Compiling the Configuration:- ArcGISInstall"
                ArcGISInstall -ConfigurationData $ConfigurationParamsHashtable

                if($Credential){
                    $JobFlag = Start-DSCJob -ConfigurationName ArcGISInstall -Credential $Credential -DebugMode $DebugMode
                }else{
                    $JobFlag = Start-DSCJob -ConfigurationName ArcGISInstall -DebugMode $DebugMode
                }

                if(Test-Path ".\ArcGISInstall") {
                    Remove-Item ".\ArcGISInstall" -Force -ErrorAction Ignore -Recurse
                }

                if($JobFlag -eq $True -and ($Mode -ieq "InstallLicense" -or $Mode -ieq "InstallLicenseConfigure")){
                    $JobFlag = $False
                    
                    $ServerCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'Server' } | Measure-Object).Count -gt 0)
                    $PortalCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'Portal' } | Measure-Object).Count -gt 0)
                    $DesktopCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'Desktop' }  | Measure-Object).Count -gt 0)
                    $ProCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'Pro' }  | Measure-Object).Count -gt 0)
                    $LicenseManagerCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'LicenseManager' } | Measure-Object).Count -gt 0)

                    $EnterpriseSkipLicenseStep = $false
                    if($ConfigurationParamsHashtable.ConfigData.Version){
                        $EnterpriseVersionArray = $ConfigurationParamsHashtable.ConfigData.Version.Split(".")
                        $EnterpriseMajorVersion = $EnterpriseVersionArray[1]
                        if(($EnterpriseMajorVersion -ge 7) -and -not($ServerCheck) -and $PortalCheck){
                            $EnterpriseSkipLicenseStep = $true
                        }
                    }

                    $DesktopSkipLicenseStep = $false
                    if($ConfigurationParamsHashtable.ConfigData.DesktopVersion){
                        if($DesktopCheck -and ($ConfigurationParamsHashtable.ConfigData.Desktop.AuthorizationType -ieq "Float" -and -not($LicenseManagerCheck))){
                            $DesktopSkipLicenseStep = $true
                        }
                    }

                    $ProSkipLicenseStep = $false
                    if($ConfigurationParamsHashtable.ConfigData.ProVersion){
                        if($ProCheck -and (($ConfigurationParamsHashtable.ConfigData.Pro.AuthorizationType -ieq "NAMED_USER") -or 
                        ($ConfigurationParamsHashtable.ConfigData.Pro.AuthorizationType -ieq "CONCURRENT_USE" -and -not($LicenseManagerCheck)))){
                            $ProSkipLicenseStep = $true
                        }
                    }
                    
                    if(-not($EnterpriseSkipLicenseStep -and $DesktopSkipLicenseStep -and $ProSkipLicenseStep)){
                        Write-Host "Dot Sourcing the Configuration:- ArcGISLicense"
                        . "$PSScriptRoot\Configurations-OnPrem\ArcGISLicense.ps1" -Verbose:$false

                        Write-Host "Compiling the Configuration:- ArcGISLicense"
                        ArcGISLicense -ConfigurationData $ConfigurationParamsHashtable
                        
                        if($Credential){
                            $JobFlag = Start-DSCJob -ConfigurationName ArcGISLicense -Credential $Credential -DebugMode $DebugMode
                        }else{
                            $JobFlag = Start-DSCJob -ConfigurationName ArcGISLicense -DebugMode $DebugMode
                        }

                        if(Test-Path ".\ArcGISLicense") {
                            Remove-Item ".\ArcGISLicense" -Force -ErrorAction Ignore -Recurse
                        }
                    }else{
                        $JobFlag = $True
                    }

                    $SkipConfigureStep = $False                    
                    if(($DesktopCheck -or $ProCheck) -and -not($ServerCheck -or $PortalCheck)){
                        $SkipConfigureStep = $True
                    }

                    if($JobFlag -eq $True -and ($Mode -ieq "InstallLicenseConfigure") -and -not($SkipConfigureStep)){
                        
                        $JobFlag = $False
                    
                        Write-Host "Dot Sourcing the Configuration:- ArcGISConfigure"
                        . "$PSScriptRoot\Configurations-OnPrem\ArcGISConfigure.ps1" -Verbose:$false

                        Write-Host "Compiling the Configuration:- ArcGISConfigure"
                        ArcGISConfigure -ConfigurationData $ConfigurationParamsHashtable
                        
                        if($Credential){
                            $JobFlag = Start-DSCJob -ConfigurationName ArcGISConfigure -Credential $Credential -DebugMode $DebugMode
                        }else{
                            $JobFlag = Start-DSCJob -ConfigurationName ArcGISConfigure -DebugMode $DebugMode
                        }

                        if(Test-Path ".\ArcGISConfigure") {
                            Remove-Item ".\ArcGISConfigure" -Force -ErrorAction Ignore -Recurse
                        }

                        if($JobFlag -eq $True){
                            $RemoteFederation = if($ConfigurationParamsHashtable.ConfigData.Federation){$true}else{$false}
                            $PortalServerFederation = $False
                            if(-not($RemoteFederation))
                            {
                                $ServerCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'Server' }  | Measure-Object).Count -gt 0)
                                $PortalCheck = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'Portal' }  | Measure-Object).Count -gt 0)
                                if($ServerCheck -and $PortalCheck)
                                {
                                    $PortalServerFederation = $True
                                }
                            }

                            if($RemoteFederation -or $PortalServerFederation){
                                Write-Host "Dot Sourcing the Configuration:- ArcGISFederation"
                                . "$PSScriptRoot\Configurations-OnPrem\ArcGISFederation.ps1" -Verbose:$false
                                
                                Write-Host "Compiling the Configuration:- ArcGISFederation"
                                ArcGISFederation -ConfigurationData $ConfigurationParamsHashtable 
                                
                                if($Credential){
                                    $JobFlag = Start-DSCJob -ConfigurationName ArcGISFederation -Credential $Credential -DebugMode $DebugMode
                                }else{
                                    
                                    $JobFlag = Start-DSCJob -ConfigurationName ArcGISFederation -DebugMode $DebugMode
                                }

                                if(Test-Path ".\ArcGISFederation") {
                                    Remove-Item ".\ArcGISFederation" -Force -ErrorAction Ignore -Recurse
                                }
                            }
                        }
                    
                        if($JobFlag -eq $True){ 
                            Get-ArcGISURL $ConfigurationParamsHashtable
                        }
                    }
                }
            }else{
                throw "File directory validations failed for server or portal. Please check and run again."  
            }
        }elseif(($Mode -ieq "Uninstall") -or ($Mode -ieq "PublishGISService")){
            if($Mode -ieq "Uninstall"){
                $ConfigurationName = "ArcGISUninstall"
            }elseif($Mode -ieq "PublishGISService"){
                $ConfigurationName = "PublishGISService"
            }
            if(Test-Path ".\$ConfigurationName") {
                Remove-Item ".\$ConfigurationName" -Force -ErrorAction Ignore -Recurse
            }    

            Write-Host "Dot Sourcing the Configuration:- $ConfigurationName"
            . "$PSScriptRoot\Configurations-OnPrem\$ConfigurationName.ps1" -Verbose:$false

            Write-Host "Compiling the Configuration:- $ConfigurationName"
            & $ConfigurationName -ConfigurationData $ConfigurationParamsHashtable
            
            if($Credential){
                Start-DSCJob -ConfigurationName $ConfigurationName -Credential $Credential -DebugMode $DebugMode
            }else{
                Start-DSCJob -ConfigurationName $ConfigurationName -DebugMode $DebugMode
            }
        }
    }elseif($Mode -ieq "Upgrade"){
        Write-Host "Dot Sourcing the Configuration:- WebAdaptorUninstall"
        . "$PSScriptRoot\Configurations-OnPrem\Upgrades\WebAdaptorUninstall.ps1" -Verbose:$false

        Write-Host "Dot Sourcing the Configuration:- WebAdaptorInstall"
        . "$PSScriptRoot\Configurations-OnPrem\Upgrades\WebAdaptorInstall.ps1" -Verbose:$false

        Write-Host "Dot Sourcing the Configuration:- PortalUpgrade"
        . "$PSScriptRoot\Configurations-OnPrem\Upgrades\PortalUpgrade.ps1" -Verbose:$false

        Write-Host "Dot Sourcing the Configuration:- PortalUpgradeStandbyJoin"
        . "$PSScriptRoot\Configurations-OnPrem\Upgrades\PortalUpgradeStandbyJoin.ps1" -Verbose:$false

        Write-Host "Dot Sourcing the Configuration:- ServerUpgrade"
        . "$PSScriptRoot\Configurations-OnPrem\Upgrades\ServerUpgrade.ps1" -Verbose:$false

        Write-Host "Dot Sourcing the Configuration:- DataStoreUpgradeInstall"
        . "$PSScriptRoot\Configurations-OnPrem\Upgrades\DataStoreUpgradeInstall.ps1" -Verbose:$false

        Write-Host "Dot Sourcing the Configuration:- DataStoreUpgradeConfigure"
        . "$PSScriptRoot\Configurations-OnPrem\Upgrades\DataStoreUpgradeConfigure.ps1" -Verbose:$false

        Write-Host "Dot Sourcing the Configuration:- SpatioTemporalDatastoreStart"
        . "$PSScriptRoot\Configurations-OnPrem\Upgrades\SpatioTemporalDatastoreStart.ps1" -Verbose:$false

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
                
                $SevenZipInstallerPath = if($PortalConfig.ConfigData.SevenZipInstallerPath){$PortalConfig.ConfigData.SevenZipInstallerPath}else{$null}
                $SevenZipInstallerDir = if($PortalConfig.ConfigData.SevenZipInstallerDir){$PortalConfig.ConfigData.SevenZipInstallerDir}else{$null}
                $PrimaryPortalMachine = ""
                $PrimaryPortalMachineNode = $null
                $StandByPortalMachine = ""
                $StandByPortalMachineNode = $null
                $IsMultiMachinePortal = $False
                
                for ( $i = 0; $i -lt $HostingConfig.AllNodes.count; $i++ ){
                    $Role = $PortalConfig.AllNodes[$i].Role
                    if($Role -icontains 'Portal'){
                        if(-not($PrimaryPortalMachine)){
                            $PrimaryPortalMachineNode = $PortalConfig.AllNodes[$i]
                            $PrimaryPortalMachine = $PrimaryPortalMachineNode.NodeName
                        }else{
                            $StandByPortalMachineNode = $PortalConfig.AllNodes[$i]
                            $StandByPortalMachine = $StandByPortalMachineNode.NodeName
                            $IsMultiMachinePortal = $True
                        }
                    }
                }

                $PortalSAPassword = ConvertTo-SecureString $PortalConfig.ConfigData.Credentials.ServiceAccount.Password -AsPlainText -Force
                $PortalSACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($PortalConfig.ConfigData.Credentials.ServiceAccount.UserName, $PortalSAPassword )
                $PortalIsSADomainAccount = if($PortalConfig.ConfigData.Credentials.ServiceAccount.IsDomainAccount){$True}else{$False}
                $PortalPSAPassword = ConvertTo-SecureString $PortalConfig.ConfigData.Credentials.PrimarySiteAdmin.Password -AsPlainText -Force
                $PortalPSACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($PortalConfig.ConfigData.Credentials.PrimarySiteAdmin.UserName, $PortalPSAPassword )
                
                $HasPortalNodes = ($PortalConfig.AllNodes | Where-Object { $_.Role -icontains 'Portal'} | Measure-Object).Count -gt 0
                if($HasPortalNodes){
                    $HasPortalWANodes = ($PortalConfig.AllNodes | Where-Object { $_.Role -icontains 'PortalWebAdaptor'} | Measure-Object).Count -gt 0
                    if($HasPortalWANodes){
                        Write-Host "WebAdaptor Uninstall"
                        ForEach($WANode in ($PortalConfig.AllNodes | Where-Object {$_.Role -icontains 'PortalWebAdaptor'}).NodeName){
                            $cd = @{
                                AllNodes = @(
                                    @{
                                        NodeName = $WANode
                                        PSDscAllowPlainTextPassword = $true
                                    }
                                )
                            }
                            if(Test-Path ".\WebAdaptorUninstall") {
                                Remove-Item ".\WebAdaptorUninstall" -Force -ErrorAction Ignore -Recurse
                            }
                            
                            Write-Host "Compiling the Configuration:- Web Adaptor Uninstall for Portal"
                            WebAdaptorUninstall -ConfigurationData $cd -Version $PortalConfig.ConfigData.Version -InstallerPath $PortalConfig.ConfigData.WebAdaptor.Installer.Path -Context $PortalConfig.ConfigData.PortalContext -Verbose

                            if($Credential){
                                $JobFlag = Start-DSCJob -ConfigurationName WebAdaptorUninstall -Credential $Credential -DebugMode $DebugMode
                            }else{
                                $JobFlag = Start-DSCJob -ConfigurationName WebAdaptorUninstall -DebugMode $DebugMode
                            }
                        }
                    }

                    if($JobFlag -eq $True){
                        if($PortalConfig.ConfigData.ExternalLoadBalancer){
                            $ExternalDNSName = $PortalConfig.ConfigData.ExternalLoadBalancer
                        }else{
                            if(($PortalConfig.AllNodes | Where-Object { ($_.Role -icontains 'PortalWebAdaptor')}  | Measure-Object).Count -gt 0){
                                $PortalWAMachineNode = ($PortalConfig.AllNodes | Where-Object { ($_.Role -icontains 'PortalWebAdaptor')} | Select-Object -First 1)
                                $ExternalDNSName = Get-FQDN $PortalWAMachineNode.NodeName
                                if(($PortalWAMachineNode.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor'}  | Measure-Object).Count -gt 0)
                                {
                                    $ExternalDNSName = ($PortalWAMachineNode.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor' }  | Select-Object -First 1).Alias
                                }

                                if(($PortalConfig.AllNodes | Where-Object { $_.Role -icontains 'LoadBalancer' } | Measure-Object).Count -gt 0){
                                    $LoadbalancerNode = ($PortalConfig.AllNodes | Where-Object { ($_.Role -icontains 'LoadBalancer')} | Select-Object -First 1)
                                    $ExternalDNSName = Get-FQDN $LoadbalancerNode.NodeName
                                    if(($LoadbalancerNode.SslCertificates | Where-Object { $_.Target -icontains 'LoadBalancer'}  | Measure-Object).Count -gt 0)
                                    {
                                        $ExternalDNSName = ($LoadbalancerNode.SslCertificates | Where-Object { $_.Target -icontains 'LoadBalancer' }  | Select-Object -First 1).Alias
                                    }
                                }
                            }else{
                                $ExternalDNSName = Get-FQDN $PrimaryPortalMachine
                                if(($PrimaryPortalMachineNode.SslCertificates | Where-Object { $_.Target -icontains 'Portal'}  | Measure-Object).Count -gt 0)
                                {
                                    $ExternalDNSName = ($PrimaryPortalMachineNode.SslCertificates | Where-Object { $_.Target -icontains 'Portal' }  | Select-Object -First 1).Alias
                                }
                            }
                        }

                        $VersionArray = $PortalConfig.ConfigData.Version.Split(".")
                        $MajorVersion = $VersionArray[1]
                        $MinorVersion = if($VersionArray.Length -gt 2){ $VersionArray[2] }else{ 0 }
                        
                        $LicenseFilePath = $PortalConfig.ConfigData.Portal.LicenseFilePath
                        $LicensePassword = $null
                        if($PortalConfig.ConfigData.Server.LicensePassword)
                        {
                            $LicensePassword = $PortalConfig.ConfigData.Portal.LicensePassword
                        }

                        $PrimaryLicenseFilePath = $LicenseFilePath
                        $PrimaryLicensePassword = $LicensePassword
                        if($PrimaryPortalMachineNode.PortalLicenseFilePath -and $PrimaryPortalMachineNode.PortalLicensePassword)
                        {
                            $PrimaryLicenseFilePath = $PrimaryPortalMachineNode.PortalLicenseFilePath
                            $PrimaryLicensePassword = $PrimaryPortalMachineNode.PortalLicensePassword
                        }

                        Write-Host "Portal Upgrade"
                        if($IsMultiMachinePortal){
                            $cd = @{
                                AllNodes = @(
                                    @{
                                        NodeName = $PrimaryPortalMachine
                                        PSDscAllowPlainTextPassword = $true
                                    },
                                    @{
                                        NodeName = $StandByPortalMachine
                                        PSDscAllowPlainTextPassword = $true
                                    }
                                );
                            }
                            
                            $StandbyLicenseFilePath = $LicenseFilePath
                            $StandbyLicensePassword = $LicensePassword
                            if($StandByPortalMachineNode.PortalLicenseFilePath -and $StandByPortalMachineNode.PortalLicensePassword)
                            {
                                $StandbyLicenseFilePath = $StandByPortalMachineNode.PortalLicenseFilePath
                                $StandbyLicensePassword = $StandByPortalMachineNode.PortalLicensePassword
                            }

                            $PortalUpgradeArgs = @{
                                ConfigurationData = $cd 
                                OldVersion = $PortalConfig.ConfigData.OldVersion
                                Version = $PortalConfig.ConfigData.Version
                                PrimaryPortalMachine = $PrimaryPortalMachine 
                                StandbyMachineName =  $StandByPortalMachine
                                InstallerPath = $PortalConfig.ConfigData.Portal.Installer.Path
                                InstallDir = $PortalConfig.ConfigData.Portal.Installer.InstallDir 
                                ContentDir = $PortalConfig.ConfigData.Portal.Installer.ContentDir
                                PrimaryLicensePath = $PrimaryLicenseFilePath
                                PrimaryLicensePassword = $PrimaryLicensePassword
                                StandbyLicensePath = $StandbyLicenseFilePath
                                StandbyLicensePassword = $StandbyLicensePassword 
                                Context = $PortalConfig.ConfigData.PortalContext
                                ServiceAccount = $PortalSACredential
                                IsSADomainAccount = $PortalIsSADomainAccount
                                PrimarySiteAdmin = $PortalPSACredential 
                                PrimarySiteAdminEmail = $PortalConfig.ConfigData.Credentials.PrimarySiteAdmin.Email 
                                ContentDirectoryLocation = $PortalConfig.ConfigData.Portal.ContentDirectoryLocation
                                ExternalDNSName = $ExternalDNSName 
                                IsMultiMachinePortal = $IsMultiMachinePortal
                                SevenZipInstallerPath = $SevenZipInstallerPath
                                SevenZipInstallerDir = $SevenZipInstallerDir
                            }
                        }else{
                            $cd = @{
                                AllNodes = @(
                                    @{
                                        NodeName = $PrimaryPortalMachine
                                        PSDscAllowPlainTextPassword = $true
                                    }
                                )
                            }
                            
                            $PortalUpgradeArgs = @{
                                ConfigurationData = $cd 
                                OldVersion = $PortalConfig.ConfigData.OldVersion
                                Version = $PortalConfig.ConfigData.Version 
                                PrimaryPortalMachine = $PrimaryPortalMachine
                                InstallerPath = $PortalConfig.ConfigData.Portal.Installer.Path
                                PrimaryLicensePath = $PrimaryLicenseFilePath
                                PrimaryLicensePassword = $PrimaryLicensePassword
                                Context = $PortalConfig.ConfigData.PortalContext
                                ServiceAccount = $PortalSACredential
                                IsSADomainAccount = $PortalIsSADomainAccount
                                PrimarySiteAdmin = $PortalPSACredential 
                                PrimarySiteAdminEmail = $PortalConfig.ConfigData.Credentials.PrimarySiteAdmin.Email 
                                ContentDirectoryLocation = $PortalConfig.ConfigData.Portal.ContentDirectoryLocation
                                ExternalDNSName = $ExternalDNSName 
                                IsMultiMachinePortal = $False
                                SevenZipInstallerPath = $SevenZipInstallerPath
                                SevenZipInstallerDir = $SevenZipInstallerDir
                            }
                        }
                        if((($MajorVersion -eq 7 -and $MinorVersion -eq 1) -or ($MajorVersion -ge 8)) -and $PortalConfig.ConfigData.Portal.Installer.WebStylesPath){
                            $PortalUpgradeArgs.Add("WebStylesInstallerPath",$PortalConfig.ConfigData.Portal.Installer.WebStylesPath)
                        }

                        if(Test-Path ".\PortalUpgrade") {
                            Remove-Item ".\PortalUpgrade" -Force -ErrorAction Ignore -Recurse
                        }
                        PortalUpgrade @PortalUpgradeArgs -Verbose
                        if($Credential){
                            $JobFlag = Start-DSCJob -ConfigurationName PortalUpgrade -Credential $Credential -DebugMode $DebugMode
                        }else{
                            $JobFlag = Start-DSCJob -ConfigurationName PortalUpgrade -DebugMode $DebugMode
                        }


                        if($IsMultiMachinePortal -and ($JobFlag -eq $True)){
                            $cd = @{
                                AllNodes = @(
                                    @{
                                        NodeName = $StandByPortalMachine
                                        PSDscAllowPlainTextPassword = $true
                                    }
                                );
                            }

                            $StandbyLicenseFilePath = $LicenseFilePath
                            if($StandByPortalMachineNode.PortalLicenseFilePath)
                            {
                                $StandbyLicenseFilePath = $StandByPortalMachineNode.PortalLicenseFilePath
                            }
                        
                            $PortalUpgradeStandbyArgs = @{
                                ConfigurationData = $cd 
                                Version = $PortalConfig.ConfigData.Version 
                                PrimaryPortalMachine = $PrimaryPortalMachine 
                                Context = $PortalConfig.ConfigData.PortalContext
                                PrimarySiteAdmin = $PortalPSACredential 
                                PrimarySiteAdminEmail = $PortalConfig.ConfigData.Credentials.PrimarySiteAdmin.Email 
                                ContentDirectoryLocation = $PortalConfig.ConfigData.Portal.ContentDirectoryLocation
                                ExternalDNSName = $ExternalDNSName
                                LicenseFilePath = $StandbyLicenseFilePath
                                UserLicenseType = if($PortalConfig.ConfigData.Portal.PortalLicenseUserType){ $PortalConfig.ConfigData.Portal.PortalLicenseUserType }else{ $null }
                            }

                            if((($MajorVersion -eq 7 -and $MinorVersion -eq 1) -or ($MajorVersion -ge 8)) -and $PortalConfig.ConfigData.Portal.Installer.WebStylesPath){
                                $PortalUpgradeStandbyArgs.Add("WebStylesInstallerPath",$PortalConfig.ConfigData.Portal.Installer.WebStylesPath)
                            }

                            PortalUpgradeStandbyJoin @PortalUpgradeStandbyArgs -Verbose
                            if($Credential){
                                $JobFlag = Start-DSCJob -ConfigurationName PortalUpgradeStandbyJoin -Credential $Credential -DebugMode $DebugMode
                            }else{
                                $JobFlag = Start-DSCJob -ConfigurationName PortalUpgradeStandbyJoin -DebugMode $DebugMode
                            }
                        }

                        if(($JobFlag -eq $True) -and $HasPortalWANodes){
                            Write-Host "WebAdaptor Upgrade"
                            ForEach($WANode in ($PortalConfig.AllNodes | Where-Object {$_.Role -icontains 'PortalWebAdaptor'})){
                                $WAExternalHostName = if(($WANode.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor'}  | Measure-Object).Count -gt 0){($WANode.SslCertificates | Where-Object { $_.Target -icontains 'WebAdaptor' }  | Select-Object -First 1).Alias }else{ Get-FQDN $WANode.NodeName }
                                $cd = @{
                                    AllNodes = @(
                                        @{
                                            NodeName = $WANode.NodeName
                                            ExternalHostName = $WAExternalHostName
                                            PSDscAllowPlainTextPassword = $true
                                        }
                                    )
                                }    
                                if(Test-Path ".\WebAdaptorInstall") {
                                    Remove-Item ".\WebAdaptorInstall" -Force -ErrorAction Ignore -Recurse
                                }    
                                WebAdaptorInstall -ConfigurationData $cd -WebAdaptorRole "PortalWebAdaptor" -Version $PortalConfig.ConfigData.Version `
                                                    -InstallerPath $PortalConfig.ConfigData.WebAdaptor.Installer.Path -Context $PortalConfig.ConfigData.PortalContext `
                                                    -ComponentHostName $PrimaryPortalMachine -PSACredential $PortalPSACredential `
                                                    -SevenZipInstallerPath $SevenZipInstallerPath -SevenZipInstallerDir $SevenZipInstallerDir -Verbose
                                if($Credential){
                                    $JobFlag = Start-DSCJob -ConfigurationName WebAdaptorInstall -Credential $Credential -DebugMode $DebugMode
                                }else{
                                    $JobFlag = Start-DSCJob -ConfigurationName WebAdaptorInstall -DebugMode $DebugMode
                                }
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
                    Write-Host "Hosting Server Upgrade"
                    if($Credential){
                        $JobFlag = ServerUpgradeScript -cf $HostingConfig -Credential $Credential -DebugMode $DebugMode
                    }else{
                        $JobFlag = ServerUpgradeScript -cf $HostingConfig -DebugMode $DebugMode
                    }
                }
            }

            if($JobFlag -eq $True){
                if($OtherConfigs){
                    for ( $i = 0; $i -lt $OtherConfigs.count; $i++ ){
                        Write-Host "Other Server Upgrade"
                        if($Credential){
                            $JobFlag = ServerUpgradeScript -cf $OtherConfigs[$i] -Credential $Credential -DebugMode $DebugMode
                        }else{
                            $JobFlag = ServerUpgradeScript -cf $OtherConfigs[$i] -DebugMode $DebugMode
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

                    $SevenZipInstallerPath = if($DSConfig.ConfigData.SevenZipInstallerPath){$DSConfig.ConfigData.SevenZipInstallerPath}else{$null}
                    $SevenZipInstallerDir = if($DSConfig.ConfigData.SevenZipInstallerDir){$DSConfig.ConfigData.SevenZipInstallerDir}else{$null}
                    
                    $DSSAPassword = ConvertTo-SecureString $DSConfig.ConfigData.Credentials.ServiceAccount.Password -AsPlainText -Force
                    $DSSACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($DSConfig.ConfigData.Credentials.ServiceAccount.UserName, $DSSAPassword )

                    $DSPSAPassword = ConvertTo-SecureString $DSConfig.ConfigData.Credentials.PrimarySiteAdmin.Password -AsPlainText -Force
                    $DSPSACredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($DSConfig.ConfigData.Credentials.PrimarySiteAdmin.UserName, $DSPSAPassword )
                    
                    $HasDataStoreNodes = ($DSConfig.AllNodes | Where-Object { $_.Role -icontains 'DataStore'} | Measure-Object).Count -gt 0
                    if($HasDataStoreNodes){
                        $Version = $DSConfig.ConfigData.Version
                        $VersionArray = $Version.split(".")
                        Write-Host "DataStore Upgrade to $Version"
                        if($VersionArray[1] -gt 5){
                            $cd = @{
                                AllNodes = @(
                                    @{
                                        NodeName = "*"
                                        PSDscAllowPlainTextPassword = $true
                                    }
                                )
                            }

                            for ( $i = 0; $i -lt $DSConfig.AllNodes.count; $i++ ){
                                $DSNode = $DSConfig.AllNodes[$i].NodeName
                                if($DSConfig.AllNodes[$i].Role -icontains 'DataStore'){
                                    $NodeToAdd = @{
                                        NodeName = $DSNode
                                    }
                                    $cd.AllNodes += $NodeToAdd 
                                }
                            }

                            if(Test-Path ".\DataStoreUpgradeInstall") {
                                Remove-Item ".\DataStoreUpgradeInstall" -Force -ErrorAction Ignore -Recurse
                            }

                            DataStoreUpgradeInstall -ConfigurationData $cd -Version $DSConfig.ConfigData.Version -ServiceAccount $DSSACredential `
                                -InstallerPath $DSConfig.ConfigData.DataStore.Installer.Path -InstallDir $DSConfig.ConfigData.DataStore.Installer.InstallDir `
                                -SevenZipInstallerPath $SevenZipInstallerPath -SevenZipInstallerDir $SevenZipInstallerDir -Verbose
                            if($Credential){
                                $JobFlag = Start-DSCJob -ConfigurationName DataStoreUpgradeInstall -Credential $Credential -DebugMode $DebugMode
                            }else{
                                $JobFlag = Start-DSCJob -ConfigurationName DataStoreUpgradeInstall -DebugMode $DebugMode
                            }

                            $PrimaryDataStore = ""
                            $PrimaryBigDataStore = ""
                            $PrimaryTileCache = ""
                            for ( $i = 0; $i -lt $DSConfig.AllNodes.count; $i++ )
                            {
                                $Role = $DSConfig.AllNodes[$i].Role
                                if($Role -icontains 'DataStore')
                                {
                                    $DsTypes = $DSConfig.AllNodes[$i].DataStoreTypes
                                    if($DsTypes -icontains "Relational" -and -not($PrimaryDataStore))
                                    {
                                        $PrimaryDataStore = $DSConfig.AllNodes[$i].NodeName 
                                    }
                                    if($DsTypes -icontains "SpatioTemporal" -and -not($PrimaryBigDataStore))
                                    {
                                        $PrimaryBigDataStore =$DSConfig.AllNodes[$i].NodeName
                                    }
                                    if($DsTypes -icontains "TileCache" -and -not($PrimaryTileCache))
                                    {
                                        $PrimaryTileCache = $DSConfig.AllNodes[$i].NodeName
                                    }
                                }
                            }

                            if($JobFlag -and $PrimaryDataStore){
                                $cd = @{
                                    AllNodes = @(
                                        @{
                                            NodeName = $PrimaryDataStore
                                            PSDscAllowPlainTextPassword = $true
                                        }
                                    )
                                }
                                if(Test-Path ".\DataStoreUpgradeConfigure") {
                                    Remove-Item ".\DataStoreUpgradeConfigure" -Force -ErrorAction Ignore -Recurse
                                }
                                DataStoreUpgradeConfigure -ConfigurationData $cd -PrimarySiteAdmin $DSPSACredential -ServerMachineName $PrimaryServerMachine `
                                    -ContentDirectoryLocation $DSConfig.ConfigData.DataStore.ContentDirectoryLocation -InstallDir $DSConfig.ConfigData.DataStore.Installer.InstallDir -Verbose
                                if($Credential){
                                    $JobFlag = Start-DSCJob -ConfigurationName DataStoreUpgradeConfigure -Credential $Credential -DebugMode $DebugMode
                                }else{
                                    $JobFlag = Start-DSCJob -ConfigurationName DataStoreUpgradeConfigure -DebugMode $DebugMode
                                }
                            }

                            if(($JobFlag -eq $True) -and $PrimaryTileCache -and ($PrimaryDataStore -ne $PrimaryTileCache)){
                                $cd = @{
                                    AllNodes = @(
                                        @{
                                            NodeName = $PrimaryTileCache
                                            PSDscAllowPlainTextPassword = $true
                                        }
                                    )
                                }
                                if(Test-Path ".\DataStoreUpgradeConfigure") {
                                    Remove-Item ".\DataStoreUpgradeConfigure" -Force -ErrorAction Ignore -Recurse
                                }
                                DataStoreUpgradeConfigure -ConfigurationData $cd -PrimarySiteAdmin $DSPSACredential -ServerMachineName $PrimaryServerMachine `
                                    -ContentDirectoryLocation $DSConfig.ConfigData.DataStore.ContentDirectoryLocation -InstallDir $DSConfig.ConfigData.DataStore.Installer.InstallDir -Verbose
                                if($Credential){
                                    $JobFlag = Start-DSCJob -ConfigurationName DataStoreUpgradeConfigure -Credential $Credential -DebugMode $DebugMode
                                }else{
                                    $JobFlag = Start-DSCJob -ConfigurationName DataStoreUpgradeConfigure -DebugMode $DebugMode
                                }
                            }

                            if(($JobFlag -eq $True) -and $PrimaryBigDataStore -and ($PrimaryDataStore -ne $PrimaryTileCache) -and ($PrimaryDataStore -ne $PrimaryBigDataStore)){
                                $cd = @{
                                    AllNodes = @(
                                        @{
                                            NodeName = $PrimaryBigDataStore
                                            PSDscAllowPlainTextPassword = $true
                                        }
                                    )
                                }
                                if(Test-Path ".\DataStoreUpgradeConfigure") {
                                    Remove-Item ".\DataStoreUpgradeConfigure" -Force -ErrorAction Ignore -Recurse
                                }
                                DataStoreUpgradeConfigure -ConfigurationData $cd -PrimarySiteAdmin $DSPSACredential -ServerMachineName $PrimaryServerMachine `
                                    -ContentDirectoryLocation $DSConfig.ConfigData.DataStore.ContentDirectoryLocation -InstallDir $DSConfig.ConfigData.DataStore.Installer.InstallDir -Verbose
                                if($Credential){
                                    $JobFlag = Start-DSCJob -ConfigurationName DataStoreUpgradeConfigure -Credential $Credential -DebugMode $DebugMode
                                }else{
                                    $JobFlag = Start-DSCJob -ConfigurationName DataStoreUpgradeConfigure -DebugMode $DebugMode
                                }
                            }                    

                        }else{
                            $BigDataStoreMachinesArray = @()
                            for ( $i = 0; $i -lt $DSConfig.AllNodes.count; $i++ ){
                                $Role = $DSConfig.AllNodes[$i].Role
                                $DSNode = $DSConfig.AllNodes[$i].NodeName
                                if($Role -icontains 'DataStore'){
                                    $cd = @{
                                        AllNodes = @(
                                            @{
                                                NodeName = $DSNode
                                                PSDscAllowPlainTextPassword = $true
                                            }
                                        )
                                    }
                                    if(Test-Path ".\DataStoreUpgradeInstall") {
                                        Remove-Item ".\DataStoreUpgradeInstall" -Force -ErrorAction Ignore -Recurse
                                    }
                                
                                    DataStoreUpgradeInstall -ConfigurationData $cd -Version $DSConfig.ConfigData.Version -ServiceAccount $DSSACredential `
                                        -InstallerPath $DSConfig.ConfigData.DataStore.Installer.Path `
                                        -SevenZipInstallerPath $SevenZipInstallerPath -SevenZipInstallerDir $SevenZipInstallerDir -Verbose
                                    if($Credential){
                                        $JobFlag = Start-DSCJob -ConfigurationName DataStoreUpgradeInstall -Credential $Credential -DebugMode $DebugMode
                                    }else{
                                        $JobFlag = Start-DSCJob -ConfigurationName DataStoreUpgradeInstall -DebugMode $DebugMode
                                    }

                                    if(Test-Path ".\DataStoreUpgradeConfigure") {
                                        Remove-Item ".\DataStoreUpgradeConfigure" -Force -ErrorAction Ignore -Recurse
                                    }
                                    if($JobFlag -eq $True){
                                        DataStoreUpgradeConfigure -ConfigurationData $cd -PrimarySiteAdmin $DSPSACredential -ServerMachineName $PrimaryServerMachine `
                                            -ContentDirectoryLocation $DSConfig.ConfigData.DataStore.ContentDirectoryLocation -InstallDir $DSConfig.ConfigData.DataStore.Installer.InstallDir -Verbose
                                        if($Credential){
                                            $JobFlag = Start-DSCJob -ConfigurationName DataStoreUpgradeConfigure -Credential $Credential -DebugMode $DebugMode
                                        }else{
                                            $JobFlag = Start-DSCJob -ConfigurationName DataStoreUpgradeConfigure -DebugMode $DebugMode
                                        }
                                    }
                                    if($DSConfig.AllNodes[$i].DataStoreTypes -icontains "SpatioTemporal"){
                                        $BigDataStoreMachinesArray += $DSNode
                                    }
                                    if($JobFlag -eq $True){
                                        break
                                    }
                                }
                            }
                            if(($JobFlag -eq $True) -and $BigDataStoreMachinesArray){
                                Write-Host "BigDataStore Upgrade"
                                Foreach($nd in $BigDataStoreMachinesArray){
                                    $cd = @{
                                        AllNodes = @(
                                            @{
                                                NodeName = $nd
                                                PSDscAllowPlainTextPassword = $true
                                            }
                                        )
                                    }
                                    if(Test-Path ".\SpatioTemporalDatastoreStart") {
                                        Remove-Item ".\SpatioTemporalDatastoreStart" -Force -ErrorAction Ignore -Recurse
                                    }
                                    SpatioTemporalDatastoreStart -NodeName $nd -PrimarySiteAdmin $DSPSACredential -ServerMachineName $PrimaryServerMachine -ConfigurationData $cd -Verbose
                                    if($Credential){
                                        $JobFlag = Start-DSCJob -ConfigurationName SpatioTemporalDatastoreStart -Credential $Credential -DebugMode $DebugMode
                                    }else{
                                        $JobFlag = Start-DSCJob -ConfigurationName SpatioTemporalDatastoreStart -DebugMode $DebugMode
                                    }
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
   
Export-ModuleMember -Function Get-FQDN, Configure-ArcGIS, Publish-WebApp, Invoke-BuildArcGISAzureImage