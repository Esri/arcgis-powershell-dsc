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

function ConvertPSObjectToHashtable
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
                foreach ($object in $InputObject) { ConvertPSObjectToHashtable $object }
            )

            Write-Output -NoEnumerate $collection
        }
        elseif ($InputObject -is [psobject])
        {
            $hash = @{}

            foreach ($property in $InputObject.PSObject.Properties)
            {
                $hash[$property.Name] = ConvertPSObjectToHashtable $property.Value
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
    
    $HasSSLCertificatesPerNode = $true
    for ( $i = 0; $i -lt $AllNodes.count; $i++ )
    {
        if($HasSSLCertificatesPerNode -and -not($AllNodes[$i].SslCertifcate)){
            $Roles = $AllNodes[$i].Role
            if((@("Server", "Portal", "ServerWebAdaptor","PortalWebAdaptor", "LoadBalancer") | ?{$Roles -contains $_}).Count -gt 1)
            {
                $HasSSLCertificatesPerNode = $False
            }                
        }
    }
    
    $PrimaryServerMachine = ""
    $PrimaryPortalMachine = ""
    $PortalContext = $ConfigurationData.ConfigData.PortalContext 
    $ServerContext = $ConfigurationData.ConfigData.ServerContext 

    for ( $i = 0; $i -lt $AllNodes.count; $i++ )
    {
        $Role = $AllNodes[$i].Role
        if($Role -icontains 'Server' -and -not($PrimaryServerMachine))
        {
            $PrimaryServerMachine  = $AllNodes[$i]
            $PrimaryServerMachineName  = $PrimaryServerMachine.NodeName
        }

        if($Role -icontains 'Portal' -and -not($PrimaryPortalMachine))
        {
            $PrimaryPortalMachine= $AllNodes[$i]
            $PrimaryPortalMachineName = $PrimaryPortalMachine.NodeName
        }
    }

    if($PrimaryPortalMachine)
    {
        $PortalExternalDNSName = Get-FQDN $PrimaryPortalMachineName
        
        if($HasSSLCertificatesPerNode)
        {
            $PortalExternalDNSName = $PrimaryPortalMachine.SslCertifcate.Path
        }
        else
        { 
            if($ConfigurationData.ConfigData.Portal.SslCertifcate)
            {
                $PortalExternalDNSName = $ConfigurationData.ConfigData.Portal.SslCertifcate.Alias
            }  
        }

        $PortalAdminURL = "https://$($PortalExternalDNSName):7443/arcgis/portaladmin"
        $PortalURL = "https://$($PortalExternalDNSName):7443/arcgis/home"
    }

    if($PrimaryServerMachine)
    {
        $ServerExternalDNSName = Get-FQDN $PrimaryServerMachineName
        
        if($HasSSLCertificatesPerNode)
        {
            $ServerExternalDNSName = $PrimaryServerMachine.SslCertifcate.Path
        }
        else
        { 
            if($ConfigurationData.ConfigData.Portal.SslCertifcate)
            {
                $ServerExternalDNSName = $ConfigurationData.ConfigData.Server.SslCertifcate.Alias
            } 
        }

        $ServerAdminURL = "https://$($ServerExternalDNSName):6443/arcgis/admin"
        $ServerURL = "https://$($ServerExternalDNSName):6443/arcgis/manager"
        $RestURL = "https://$($ServerExternalDNSName):6443/arcgis/rest"
    }

    $HasLoadBalancer = (($AllNodes | Where-Object { $_.Role -icontains 'LoadBalancer' }  | Measure-Object).Count -gt 0)
    if($HasLoadBalancer)
    {
        $LBMachine = ($AllNodes | Where-Object { $_.Role -icontains 'LoadBalancer' }| Sort-Object | Select-Object -First 1)
        $ExternalDNSName = Get-FQDN $LBMachine.NodeName
        
        $ServerExternalDNSName = $ExternalDNSName
        $PortalExternalDNSName = $ExternalDNSName

        if($HasSSLCertificatesPerNode)
        {
            $ServerExternalDNSName = $LBMachine.SslCertifcate.Alias
            $PortalExternalDNSName = $LBMachine.SslCertifcate.Alias
        }
        else
        {
            if($ConfigurationData.ConfigData.Portal.SslCertifcate)
            {
                $ServerExternalDNSName = $ConfigurationData.ConfigData.Portal.SslCertifcate.Alias
                $PortalExternalDNSName = $ConfigurationData.ConfigData.Portal.SslCertifcate.Alias
            }
            elseif($ConfigurationData.ConfigData.Server.SslCertifcate)
            {
                $ServerExternalDNSName = $ConfigurationData.ConfigData.Server.SslCertifcate.Alias
                $PortalExternalDNSName = $ConfigurationData.ConfigData.Server.SslCertifcate.Alias
            }
        }        
    }
    else
    {
        if((($AllNodes | Where-Object { ($_.Role -icontains 'PortalWebAdaptor')}  | Measure-Object).Count -gt 0))
        {
            $PortalWAMachine = ($AllNodes | Where-Object { ($_.Role -icontains 'PortalWebAdaptor') }| Select-Object -First 1)
            $PortalExternalDNSName =  Get-FQDN $PortalWAMachine.NodeName
            
            if($HasSSLCertificatesPerNode)
            {
                $PortalExternalDNSName = $PortalWAMachine.SslCertifcate.Alias
            }
            else 
            {
                if($ConfigurationData.ConfigData.Portal.SslCertifcate)
                {
                    $PortalExternalDNSName = $ConfigurationData.ConfigData.Portal.SslCertifcate.Alias
                }
            }
        }
        if((($AllNodes | Where-Object { ($_.Role -icontains 'ServerWebAdaptor')}  | Measure-Object).Count -gt 0))
        {
            $ServerWAMachine = ($AllNodes | Where-Object { ($_.Role -icontains 'ServerWebAdaptor') }| Select-Object -First 1)
            $ServerExternalDNSName = Get-FQDN $ServerWAMachine.NodeName
            if($HasSSLCertificatesPerNode)
            {
                $ServerExternalDNSName = $ServerWAMachine.SslCertifcate.Alias
            }
            else 
            {
                if($ConfigurationData.ConfigData.Server.SslCertifcate)
                {
                    $ServerExternalDNSName = $ConfigurationData.ConfigData.Server.SslCertifcate.Alias
                }
            }
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
    
    if($PrimaryPortalMachine)
    {
        Write-Host "Portal Admin URL - $PortalAdminURL"
        Write-Host "Portal URL - $PortalURL"    
    }
    if($PrimaryServerMachine)
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
                                -LicensePath $LicenseFilePath -LicensePassword $LicensePassword -ServerRole $cf.ConfigData.ServerRole -GeoEventServerInstaller $cf.ConfigData.GeoEventServer.Installer.Path -Verbose
                }else{
                    ServerUpgrade -ConfigurationData $cd -Version $cf.ConfigData.Version -ServiceAccount $cfSACredential -IsSADomainAccount $IsSADomainAccount -InstallerPath $cf.ConfigData.Server.Installer.Path `
                                -LicensePath $LicenseFilePath -LicensePassword $LicensePassword -ServerRole $cf.ConfigData.ServerRole -Verbose    
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
            ForEach($WANode in ($cf.AllNodes | Where-Object {$_.Role -icontains 'ServerWebAdaptor'}).NodeName){
                $cd = @{
                    AllNodes = @(
                        @{
                            NodeName = $WANode
                            PSDscAllowPlainTextPassword = $true
                        }
                    )
                }
                if(Test-Path ".\WebAdaptorInstall") {
                    Remove-Item ".\WebAdaptorInstall" -Force -ErrorAction Ignore -Recurse
                }
                WebAdaptorInstall -ConfigurationData $cd -WebAdaptorRole "ServerWebAdaptor" -PreRequisiteWindowsFeatures $cf.ConfigData.WebAdaptor.PreRequisiteWindowsFeatures -Version $cf.ConfigData.Version `
                                -InstallerPath $cf.ConfigData.WebAdaptor.Installer.Path -Context $cf.ConfigData.ServerContext -ComponentHostName $cfPrimaryServerMachine `
                                -PSACredential $cfPSACredential -Verbose
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
    . "$PSScriptRoot\Configuration\$($ConfigurationName).ps1"
    
    Write-Host "Compiling the Configuration:- $ConfigurationName"
    & $ConfigurationName -NodeName $NodeName -WebAppName $WebAppName -SourceDir $SourceDir

    if($Credential){
        Start-DSCJob -ConfigurationName $ConfigurationName -Credential $Credential -DebugMode $DebugMode
    }else{
        Start-DSCJob -ConfigurationName $ConfigurationName -DebugMode $DebugMode
    }

}

function Configure-ArcGIS
{
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory=$True)]
        [System.Array]
        $ConfigurationParametersFile,    

        [ValidateSet("Install","Uninstall","Upgrade","PublishGISService")]
        [Parameter(Position = 1)]
        [System.String]
        $Mode = 'Install',

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

    if($Mode -ieq "Install" -or $Mode -ieq "Uninstall" -or $Mode -ieq "PublishGISService"){

        Foreach($cf in $ConfigurationParametersFile){
            if(-not($ConfigurationParamsJSON)){
                $ConfigurationParamsJSON = (ConvertFrom-Json (Get-Content $cf -Raw))
            }
        }
        $ConfigurationParamsHashtable = ConvertPSObjectToHashtable $ConfigurationParamsJSON
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

        if($Mode -ieq "Install"){ 

            $ValidateFileShare = $False
         
            $IsHAPortal = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'Portal' }  | Measure-Object).Count -gt 1)
            $IsHAServer = (($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'Server' }  | Measure-Object).Count -gt 1)

            if($IsHAPortal -or $IsHAServer){
                if((($ConfigurationParamsHashtable.AllNodes | Where-Object { $_.Role -icontains 'FileShare' }  | Measure-Object).Count -gt 0)){
                    $ValidateFileShare = $True
                }else{
                    if($MappedDriveOverrideFlag){
                        $ValidateFileShare = $False
                    }else{
                        $ValidateFileShare = $False
                    }
                }
            }else{
                $ValidateFileShare = $True
            }

            if($ValidateFileShare){
                $JobFlag = $False

                Write-Host "Dot Sourcing the Configuration:- ArcGISInstall"
                . "$PSScriptRoot\Configuration\ArcGISInstall.ps1" -Verbose:$false

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

                if($JobFlag){
                    
                    $JobFlag = $False

                    Write-Host "Dot Sourcing the Configuration:- ArcGISLicense"
                    . "$PSScriptRoot\Configuration\ArcGISLicense.ps1" -Verbose:$false

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
                    
                    if($JobFlag){
                        
                        $JobFlag = $False
                    
                        Write-Host "Dot Sourcing the Configuration:- ArcGISConfigure"
                        . "$PSScriptRoot\Configuration\ArcGISConfigure.ps1" -Verbose:$false

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
                    
                        if($JobFlag){ 
                            Get-ArcGISURL $ConfigurationParamsHashtable
                        }
                    }
                }
            }else{
                throw "FileShare not present required for HA Setup!"  
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
            . "$PSScriptRoot\Configuration\$ConfigurationName.ps1" -Verbose:$false

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
        . "$PSScriptRoot\Configuration\Upgrades\WebAdaptorUninstall.ps1" -Verbose:$false

        Write-Host "Dot Sourcing the Configuration:- WebAdaptorInstall"
        . "$PSScriptRoot\Configuration\Upgrades\WebAdaptorInstall.ps1" -Verbose:$false

        Write-Host "Dot Sourcing the Configuration:- PortalUpgrade"
        . "$PSScriptRoot\Configuration\Upgrades\PortalUpgrade.ps1" -Verbose:$false

        Write-Host "Dot Sourcing the Configuration:- PortalUpgradeStandbyJoin"
        . "$PSScriptRoot\Configuration\Upgrades\PortalUpgradeStandbyJoin.ps1" -Verbose:$false

        Write-Host "Dot Sourcing the Configuration:- ServerUpgrade"
        . "$PSScriptRoot\Configuration\Upgrades\ServerUpgrade.ps1" -Verbose:$false

        Write-Host "Dot Sourcing the Configuration:- DataStoreUpgradeInstall"
        . "$PSScriptRoot\Configuration\Upgrades\DataStoreUpgradeInstall.ps1" -Verbose:$false

        Write-Host "Dot Sourcing the Configuration:- DataStoreUpgradeConfigure"
        . "$PSScriptRoot\Configuration\Upgrades\DataStoreUpgradeConfigure.ps1" -Verbose:$false

        Write-Host "Dot Sourcing the Configuration:- SpatioTemporalDatastoreStart"
        . "$PSScriptRoot\Configuration\Upgrades\SpatioTemporalDatastoreStart.ps1" -Verbose:$false

        

        $HostingConfig = $null

        $OtherConfigs = @()

        Foreach($cf in $ConfigurationParametersFile){
            $cfJSON = (ConvertFrom-Json (Get-Content $cf -Raw))
            $cfHashtable = ConvertPSObjectToHashtable $cfJSON
            
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
        if($JobFlag){
            if($HostingConfig -or (-not($HostingConfig) -and $OtherConfigs)){
                if(-not($HostingConfig)){
                    $PortalConfig = $OtherConfigs[0]
                }else{
                    $PortalConfig = $HostingConfig
                }
                
                $PrimaryPortalMachine = ""
                $PrimaryPortal = $null
                $StandByPortalMachine = ""
                $StandByPortal = $null
                $IsMultiMachinePortal = $False
                
                for ( $i = 0; $i -lt $HostingConfig.AllNodes.count; $i++ ){
                    $Role = $PortalConfig.AllNodes[$i].Role
                    if($Role -icontains 'Portal'){
                        if(-not($PrimaryPortalMachine)){
                            $PrimaryPortal = $PortalConfig.AllNodes[$i]
                            $PrimaryPortalMachine = $PrimaryPortal.NodeName
                        }else{
                            $StandByPortal = $PortalConfig.AllNodes[$i]
                            $StandByPortalMachine = $StandByPortal.NodeName
                            $IsMultiMachinePortal = $True
                        }
                    }
                }

                #$FileShareMachine = ($PortalConfig.AllNodes | Where-Object { $_.Role -icontains 'FileShare' }).NodeName

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

                    if($JobFlag){
                        $HasLoadBalancer = (($PortalConfig.AllNodes | Where-Object { $_.Role -icontains 'LoadBalancer' }  | Measure-Object).Count -gt 0)
                        $ExternalDNSName = [System.Net.DNS]::GetHostByName($PrimaryPortalMachine).HostName
                        if($PortalConfig.ConfigData.Portal.SslCertifcate){
                            $ExternalDNSName = $PortalConfig.ConfigData.Portal.SslCertifcate.Alias
                        }else{
                            if($HasLoadBalancer){
                                $LBMachine = ($PortalConfig.AllNodes | Where-Object { $_.Role -icontains 'LoadBalancer' }| Sort-Object | Select-Object -First 1).NodeName
                                $ExternalDNSName = [System.Net.DNS]::GetHostByName($LBMachine).HostName
                            }else{
                                if((($PortalConfig.AllNodes | Where-Object { ($_.Role -icontains 'PortalWebAdaptor')}  | Measure-Object).Count -gt 0) -and $PortalConfig.ConfigData.PortalContext){
                                    $PortalWAMachine = ($PortalConfig.AllNodes | Where-Object { ($_.Role -icontains 'PortalWebAdaptor') }| Select-Object -First 1).NodeName
                                    $ExternalDNSName = [System.Net.DNS]::GetHostByName($PortalWAMachine).HostName
                                }
                            }
                        }
                        
                        $LicenseFilePath = $PortalConfig.ConfigData.Portal.LicenseFilePath
                        $LicensePassword = $null
                        if($PortalConfig.ConfigData.Server.LicensePassword)
                        {
                            $LicensePassword = $PortalConfig.ConfigData.Portal.LicensePassword
                        }

                        $PrimaryLicenseFilePath = $LicenseFilePath
                        $PrimaryLicensePassword = $LicensePassword
                        if($PrimaryPortal.PortalLicenseFilePath -and $PrimaryPortal.PortalLicensePassword)
                        {
                            $PrimaryLicenseFilePath = $PrimaryPortal.PortalLicenseFilePath
                            $PrimaryLicensePassword = $PrimaryPortal.PortalLicensePassword
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
                            if($StandbyPortal.PortalLicenseFilePath -and $StandbyPortal.PortalLicensePassword)
                            {
                                $StandbyLicenseFilePath = $StandbyPortal.PortalLicenseFilePath
                                $StandbyLicensePassword = $StandbyPortal.PortalLicensePassword
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
                                <#FileShareMachine = $FileShareMachine
                                FileShareName = $PortalConfig.ConfigData.FileShareName#>
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
                            
                            if($FileShareMachine -and $ConfigurationData.ConfigData.FileShareName){
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
                                    <#FileShareMachine = $FileShareMachine
                                    FileShareName = $PortalConfig.ConfigData.FileShareName #>
                                    
                                }
                            }else{
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
                                }
                            }
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


                        if($IsMultiMachinePortal -and $JobFlag){
                            $cd = @{
                                AllNodes = @(
                                    @{
                                        NodeName = $StandByPortalMachine
                                        PSDscAllowPlainTextPassword = $true
                                    }
                                );
                            }
                            $PortalUpgradeStandbyArgs = @{
                                ConfigurationData = $cd 
                                PrimaryPortalMachine = $PrimaryPortalMachine 
                                Context = $PortalConfig.ConfigData.PortalContext
                                PrimarySiteAdmin = $PortalPSACredential 
                                PrimarySiteAdminEmail = $PortalConfig.ConfigData.Credentials.PrimarySiteAdmin.Email 
                                ContentDirectoryLocation = $PortalConfig.ConfigData.Portal.ContentDirectoryLocation
                                ExternalDNSName = $ExternalDNSName 
                                <#FileShareMachine = $FileShareMachine
                                FileShareName = $PortalConfig.ConfigData.FileShareName#>
                            }

                            PortalUpgradeStandbyJoin @PortalUpgradeStandbyArgs -Verbose
                            if($Credential){
                                $JobFlag = Start-DSCJob -ConfigurationName PortalUpgradeStandbyJoin -Credential $Credential -DebugMode $DebugMode
                            }else{
                                $JobFlag = Start-DSCJob -ConfigurationName PortalUpgradeStandbyJoin -DebugMode $DebugMode
                            }
                        }

                        if($JobFlag -and $HasPortalWANodes){
                            Write-Host "WebAdaptor Upgrade"
                            ForEach($WANode in ($PortalConfig.AllNodes | Where-Object {$_.Role -icontains 'PortalWebAdaptor'}).NodeName){
                                $cd = @{
                                    AllNodes = @(
                                        @{
                                            NodeName = $WANode
                                            PSDscAllowPlainTextPassword = $true
                                        }
                                    )
                                }    
                                if(Test-Path ".\WebAdaptorInstall") {
                                    Remove-Item ".\WebAdaptorInstall" -Force -ErrorAction Ignore -Recurse
                                }    
                                WebAdaptorInstall -ConfigurationData $cd -WebAdaptorRole "PortalWebAdaptor" -PreRequisiteWindowsFeatures $PortalConfig.ConfigData.WebAdaptor.PreRequisiteWindowsFeatures -Version $PortalConfig.ConfigData.Version `
                                                -InstallerPath $PortalConfig.ConfigData.WebAdaptor.Installer.Path -Context $PortalConfig.ConfigData.PortalContext -ComponentHostName $PrimaryPortalMachine `
                                                -PSACredential $PortalPSACredential -Verbose
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
            
            if($JobFlag){
                if($HostingConfig){
                    Write-Host "Hosting Server Upgrade"
                    if($Credential){
                        $JobFlag = ServerUpgradeScript -cf $HostingConfig -Credential $Credential -DebugMode $DebugMode
                    }else{
                        $JobFlag = ServerUpgradeScript -cf $HostingConfig -DebugMode $DebugMode
                    }
                }
            }

            if($JobFlag){
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
            
            if($JobFlag){
                if($HostingConfig -or (-not($HostingConfig) -and $OtherConfigs)){
                    if(-not($HostingConfig)){
                        $DSConfig = $OtherConfigs[0]
                    }else{
                        $DSConfig = $HostingConfig
                    }

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
                                $NodeToAdd = @{
                                    NodeName = $DSNode
                                }
                                $cd.AllNodes += $NodeToAdd 
                            }

                            if(Test-Path ".\DataStoreUpgradeInstall") {
                                Remove-Item ".\DataStoreUpgradeInstall" -Force -ErrorAction Ignore -Recurse
                            }

                            DataStoreUpgradeInstall -ConfigurationData $cd -Version $DSConfig.ConfigData.Version -ServiceAccount $DSSACredential `
                                -InstallerPath $DSConfig.ConfigData.DataStore.Installer.Path -InstallDir $DSConfig.ConfigData.DataStore.Installer.InstallDir -Verbose
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

                            if($JobFlag -and $PrimaryTileCache -and ($PrimaryDataStore -ne $PrimaryTileCache)){
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

                            if($JobFlag -and $PrimaryBigDataStore -and ($PrimaryDataStore -ne $PrimaryTileCache) -and ($PrimaryDataStore -ne $PrimaryBigDataStore)){
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
                                        -InstallerPath $DSConfig.ConfigData.DataStore.Installer.Path  -Verbose
                                    if($Credential){
                                        $JobFlag = Start-DSCJob -ConfigurationName DataStoreUpgradeInstall -Credential $Credential -DebugMode $DebugMode
                                    }else{
                                        $JobFlag = Start-DSCJob -ConfigurationName DataStoreUpgradeInstall -DebugMode $DebugMode
                                    }

                                    if(Test-Path ".\DataStoreUpgradeConfigure") {
                                        Remove-Item ".\DataStoreUpgradeConfigure" -Force -ErrorAction Ignore -Recurse
                                    }
                                    if($JobFlag){
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
                                    if($JobFlag){
                                        break
                                    }
                                }
                            }
                            if($JobFlag -and $BigDataStoreMachinesArray){
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
                                    if($JobFlag){
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
   
Export-ModuleMember -Function Get-FQDN, Configure-ArcGIS, Publish-WebApp