$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

<#
    .SYNOPSIS
        Makes a request to Harvest ArcGIS Enterprise Component logs in a standardized format using Log Harvestor Plugin
    .PARAMETER HostName
        Optional Host Name or IP of the Machine on which the component has been installed and is to be configured.
    .PARAMETER ComponentType
        ArcGIS Enterprise Component Name for which the Logs need to be harvested (Valid Value - Server)
    .PARAMETER EnableLogHarvesterPlugin
        Boolean to indicate whether to enable or disable the Log Harvestor Plugin for ArcGIS Enterprise Component
    .PARAMETER LogOutputFolder
        File Path on Local machine where harevested logs will be persisted
#>
function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
    (
        [parameter(Mandatory = $false)]    
        [System.String]
        $HostName,

        [ValidateSet("Server")]
        [parameter(Mandatory = $true)]    
        [System.String]
        $ComponentType,

        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $true)]    
        [System.Boolean]
        $EnableLogHarvesterPlugin,

        [parameter(Mandatory = $False)]
		[System.String]
		$LogOutputFolder = "C:\\ArcGIS\\ServerLogs",

        [ValidateSet("csv", "json")]
        [parameter(Mandatory = $False)]
		[System.String]
		$LogFormat = "csv"
    )
    $null
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
    (
        [parameter(Mandatory = $false)]    
        [System.String]
        $HostName,

        [ValidateSet("Server")]
        [parameter(Mandatory = $true)]    
        [System.String]
        $ComponentType,

        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $true)]    
        [System.Boolean]
        $EnableLogHarvesterPlugin,

        [parameter(Mandatory = $False)]
		[System.String]
		$LogOutputFolder = "C:\\ArcGIS\\ServerLogs",

        [ValidateSet("csv", "json")]
        [parameter(Mandatory = $False)]
		[System.String]
		$LogFormat = "csv"
    )
    
    $ServiceName = $null
    if($ComponentType -eq "Server"){
        Write-Verbose "Configuring Server Log Harvester Plugin"
        $ServiceName = 'ArcGIS Server'
        $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
        $InstallDir =(Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir 
        $NodeAgentFilePath = Join-Path $InstallDir 'framework\etc\NodeAgentExt.xml'
        $MajorVersion = $Version.Split(".")[0]
        $UsesLog4j = ($Version -ine "10.9.1" -and $MajorVersion -le 10)
        if($EnableLogHarvesterPlugin){
            $ServerObserverFolderPath = Join-Path $InstallDir 'framework\lib\server\observers'
            $SampleXMLFile = if($UsesLog4j){'LogHarvesterSample.xml'}else{'LogHarvesterSample2.xml'}
            $LogXMLFilePath = Join-Path $PSScriptRoot $SampleXMLFile
            [xml]$xml = Get-Content $LogXMLFilePath
            $DestXMLFileName = if($UsesLog4j){'log4j.xml'}else{ 'log4j2.xml'}
            $Log4jxmlFilePath = Join-Path $ServerObserverFolderPath $DestXMLFileName
            if($UsesLog4j){
                (($xml.configuration.appender | Where-Object { $_.name -eq "file-services-logs" }).param | Where-Object { $_.name -eq "file" }).value = ( $LogOutputFolder.trimend('\') + "\\services.log" )
                (($xml.configuration.appender | Where-Object { $_.name -eq "file-server-logs" }).param | Where-Object { $_.name -eq "file" }).value = ( $LogOutputFolder.trimend('\') + "\\server.log" )
            }else{
                ($xml.Configuration.Properties.Property | Where-Object { $_.name -eq "log.dir" })."#text" = $LogOutputFolder.trimend('\')
                ($xml.Configuration.Properties.Property | Where-Object { $_.name -eq "log.format" })."#text" =  $LogFormat 
            }
            $xml.Save($Log4jxmlFilePath)
            $Log4jXMLZipPath = (Join-Path $ServerObserverFolderPath 'log4j-xml.zip')
            Compress-Archive -LiteralPath $Log4jxmlFilePath -CompressionLevel Optimal -DestinationPath $Log4jXMLZipPath -Force
            $Log4jXMLJarPath = (Join-Path $ServerObserverFolderPath 'log4j-xml.jar')
            if(Test-Path $Log4jXMLJarPath){
                Write-Verbose 'Stopping the service' 
                Stop-Service -Name $ServiceName -Force -ErrorAction Ignore
                Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Stopped'
                Write-Verbose 'Stopped the service'
                Start-Sleep -Seconds 5
            }
            Write-Verbose "Updating Log4j Jar"
            Move-Item -Path $Log4jXMLZipPath -Destination $Log4jXMLJarPath -Force
            Remove-Item $Log4jxmlFilePath -Force
            #Enable Log Handlers JSON File
            Write-Verbose "Updating Log Handlers JSON File"
            $logHandlersDisabledJsonFilePath = (Join-Path $InstallDir "framework\etc\log-handlers.json.disabled")
            if(Test-Path $logHandlersDisabledJsonFilePath){
                $logHandlersEnabledJsonFilePath = (Join-Path $InstallDir "framework\etc\log-handlers.json")
                Move-Item -Path $logHandlersDisabledJsonFilePath -Destination $logHandlersEnabledJsonFilePath -Force
                # $destpath = (Join-Path $InstallDir "framework\etc\log-handlers.json")
                # $temp = Get-Content $destpath -raw | ConvertFrom-Json
                # $tempArray = @()
                # $temp.logHandlers = $temp.logHandlers | Where-Object { $_.enabled -eq $True } | ForEach-Object { $tempArray += $_ }
                # $temp.logHandlers = $tempArray
                # $temp | ConvertTo-Json  | set-content $destpath
            }
            #Enable Log Harvester Plugin
            Write-Verbose "Updating Log Harvester Node Agent Plugin"
            if(Test-Path $NodeAgentFilePath){
                $NodeAgentFile = New-Object System.Xml.XmlDocument
                $NodeAgentFile.Load($NodeAgentFilePath)
                [System.XML.XMLElement]$elem = $NodeAgentFile.CreateElement("Plugin");
                $elem.SetAttribute("class","com.esri.arcgis.discovery.logharvester.LogHarvesterPlugin")
                [System.XML.XMLElement]$elemInner = $NodeAgentFile.CreateElement("Property")
                $elemInner.SetAttribute("name","PeriodicInterval")
                $elemInner.InnerText = "1"
                $elem.AppendChild($elemInner)
                $NodeAgentFile.NodeAgent.Plugins.AppendChild($elem)
                $NodeAgentFile.Save($NodeAgentFilePath)
            }
            Write-Verbose "Finished Configuring Server Log Harvester Plugin"
        }else{
            Write-Verbose "Disabling Server Log Harvester Plugin"
            $ServerObserverFolderPath = Join-Path $InstallDir 'framework\lib\server\observers'
            Remove-Item (Join-Path $ServerObserverFolderPath 'log4j-xml.jar') -Force
            $logHandlersJsonFilePath = (Join-Path $InstallDir "framework\etc\log-handlers.json")
            if(Test-Path $logHandlersJsonFilePath){
                Rename-Item -Path $logHandlersJsonFilePath -NewName "log-handlers.json.disabled"
            }
            if(Test-Path $NodeAgentFilePath){
                $NodeAgentFile = New-Object System.Xml.XmlDocument
                $NodeAgentFile.Load($NodeAgentFilePath)
                $NodeToDelete = $NodeAgentFile.NodeAgent.Plugins.Plugin | Where-Object { $_.class -eq "com.esri.arcgis.discovery.logharvester.LogHarvesterPlugin" }
                $NodeAgentFile.NodeAgent.Plugins.RemoveChild($NodeToDelete)
                $NodeAgentFile.Save($NodeAgentFilePath)
            }
            Write-Verbose "Disabled Server Log Harvester Plugin"
        }
    }
    
    if(-not($UsesLog4j)){
        [Environment]::SetEnvironmentVariable("ARCGIS_LOG_APPENDER", "agol", 'Machine')
    }

    #Restart Component
    Restart-ArcGISService -ServiceName $ServiceName -Verbose

    if($ComponentType -eq "Server"){
        $FQDN = if($HostName){ Get-FQDN $HostName }else{ Get-FQDN $env:COMPUTERNAME }
        Write-Verbose "Waiting for Server 'https://$($FQDN):6443/arcgis/admin' to initialize"
        Wait-ForUrl "https://$($FQDN):6443/arcgis/admin" -HttpMethod 'GET'
    }
}

function Test-TargetResource
{
    [CmdletBinding()]
	[OutputType([System.Boolean])]
	param
    (
        [parameter(Mandatory = $false)]    
        [System.String]
        $HostName,

        [ValidateSet("Server")]
        [parameter(Mandatory = $true)]    
        [System.String]
        $ComponentType,

        [parameter(Mandatory = $true)]
        [System.String]
        $Version,

        [parameter(Mandatory = $true)]    
        [System.Boolean]
        $EnableLogHarvesterPlugin,

        [parameter(Mandatory = $False)]
		[System.String]
		$LogOutputFolder = "C:\\ArcGIS\\ServerLogs",

        [ValidateSet("csv", "json")]
        [parameter(Mandatory = $False)]
		[System.String]
		$LogFormat = "csv"
    )

    $result = $true
    if($ComponentType -eq "Server"){
        $ServiceName = 'ArcGIS Server'
        $RegKey = Get-EsriRegistryKeyForService -ServiceName $ServiceName
        $InstallDir =(Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir 
        if($EnableLogHarvesterPlugin){
            if(-not (Get-NodeAgentServerLogHarvestorPresent -InstallDir $InstallDir)){
                Write-Verbose "Log Harvestor Plugin is not Enabled. Needs to be Enabled"
                $result = $false
            }
        }
        else
        {
            if(Get-NodeAgentServerLogHarvestorPresent -InstallDir $InstallDir){
                Write-Verbose "Log Harvestor Plugin is Enabled. Needs to be Disabled"
                $result = $false
            }
        }
    }

    $result       
}



function Get-NodeAgentServerLogHarvestorPresent
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [System.String]
        $InstallDir       
    )
 
    $Enabled = $false
    $File = Join-Path $InstallDir 'framework\etc\NodeAgentExt.xml'
    if(Test-Path $File){
        [xml]$xml = Get-Content $File
        if((($xml.NodeAgent.Plugins.Plugin | Where-Object { $_.class -ieq 'com.esri.arcgis.discovery.logharvester.LogHarvesterPlugin'}).Length -gt 0) -or `
                ($xml.NodeAgent.Plugins.Plugin.class -ieq 'com.esri.arcgis.discovery.logharvester.LogHarvesterPlugin'))
        {
            Write-Verbose "Log Harvester elements exist in $File"
            $Enabled = $true
        }
    }

    $Enabled

}


Export-ModuleMember -Function *-TargetResource
