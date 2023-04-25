Configuration ArcGISSetupConfiguration
{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Installers,

        [Parameter(Mandatory=$false)]
        [String[]]
        $WindowsFeatures,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Absent','Present')]
        [ValidateNotNullOrEmpty()]
        [String]$Ensure = 'Present'
    )

    Import-DscResource -Name ArcGIS_Install
    Import-DscResource -Name ArcGIS_InstallPatch
    Import-DscResource -Name ArcGIS_xWindowsUpdate
    Import-DscResource -Name ArcGIS_InstallMsiPackage

    Node $env:ComputerName
    {
        $Depends = @()

	    LocalConfigurationManager
        {
		    ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $false
        }

        Registry CloudPlatform
        {
          Ensure      = "Present"
          Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\ESRI\License11.1"
          ValueName   = "CLOUD_PLATFORM"
          ValueData   = "AZURE"
        }
        $Depends += "[Registry]CloudPlatform"

        Registry VolumeShadowcopyService
        {
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\BCDRAGENT"
            ValueName   = "USEVSSCOPYBACKUP"
            ValueData   = "TRUE"
        }
        $Depends += "[Registry]VolumeShadowcopyService"

        Script SetAutomaticPageFileManagement
        {
            GetScript = { }
            SetScript = { Get-CimInstance -ClassName Win32_ComputerSystem | Set-CimInstance -Property @{ AutomaticManagedPageFile = $false } -ErrorAction Stop }
            TestScript = { (Get-CimInstance Win32_computersystem).AutomaticManagedPagefile }
        }
        $Depends += "[Script]SetAutomaticPageFileManagement"

        $ProImage = $false
        if($Installers.Length -eq 3){
            foreach($Installer in $Installers){
                if($Installer.Name -ieq "ArcGIS Pro"){
                    $ProImage = $true
                }
            }
        }
        
        if(-not($ProImage)){
            #region Windows Features
            if($WindowsFeatures -and ($WindowsFeatures.Length -gt 0)) 
            {
                for($i = 0; $i -lt $WindowsFeatures.Length; $i++) {
                    $WindowsFeature = $WindowsFeatures[$i]

                    WindowsFeature "WF_$($WindowsFeature)"
                    {
                        Ensure =  $Ensure
                        Name = $WindowsFeature
                        IncludeAllSubFeature = if($i -gt 0) { $true } else { $false }
                        DependsOn = $Depends
                    }

                    $Depends += "[WindowsFeature]WF_$($WindowsFeature)"
                }
            }
        }
        
        $FilesToDelete = @()
        for($i = 0; $i -lt $Installers.Length; $i++)
        {
            $Installer = $Installers[$i]
            if($Installer.LocalPath -and $Installer.Name)
            {
                if($Installer.IsMsi -and -not($Installer.RemotePath.EndsWith('exe')))
                {
                    if($Installer.RemotePath.EndsWith('msu')) # Is a windows update package?
                    {
                        ArcGIS_xWindowsUpdate "xWU_$($Installer.Name.Replace(' ', '_'))"
                        {
                            Ensure = $Ensure
                            Path = (Join-Path $ExecutionContext.InvokeCommand.ExpandString($Installer.LocalPath) $Installer.RemotePath)
                            Id = $Installer.ProductId
                            DependsOn = $Depends
                        }
                        $Depends += "[ArcGIS_xWindowsUpdate]xWU_$($Installer.Name.Replace(' ', '_'))"
                    }
                    else
                    {
                        ArcGIS_InstallMsiPackage "AIMP_$($Installer.Name.Replace(' ', '_'))"
                        {
                            Name = $Installer.Name
                            Path = (Join-Path $ExecutionContext.InvokeCommand.ExpandString($Installer.LocalPath) $Installer.RemotePath)
                            Ensure = $Ensure
                            ProductId = $Installer.ProductId
                            Arguments = $ExecutionContext.InvokeCommand.ExpandString($Installer.Arguments)
                            DependsOn = $Depends
                        }
                        $Depends += "[ArcGIS_InstallMsiPackage]AIMP_$($Installer.Name.Replace(' ', '_'))"
                    }
                }
                else
                {
                    if(-not($Installer.Name -eq "ArcGIS Pro" -and $Installer.Version -eq '3.0')){
                        ArcGIS_Install "AI_$($Installer.Name.Replace(' ', '_'))"
                        {
                            Name = $Installer.Name
                            Path = (Join-Path $ExecutionContext.InvokeCommand.ExpandString($Installer.LocalPath) $Installer.RemotePath)
                            Version = "00"
                            Ensure = $Ensure
                            ProductId = $Installer.ProductId
                            Arguments = $ExecutionContext.InvokeCommand.ExpandString($Installer.Arguments)
                            DependsOn = $Depends
                        }
                        $Depends += "[ArcGIS_Install]AI_$($Installer.Name.Replace(' ', '_'))"

                        if(($Installer.Patches).Length -gt 0) {
                            ArcGIS_InstallPatch "$($Installer.Name)InstallPatch"
                            {
                                Name = $Installer.Name
                                Version = "00"
                                ProductId = $Installer.ProductId
                                PatchesDir = (Join-Path $ExecutionContext.InvokeCommand.ExpandString($Installer.LocalPath) "Patches")
                                PatchInstallOrder = $Installer.Patches
                                Ensure = "Present"
                            }
                        }
                    }
                }
                if(-not($ProImage)){
                    if(@("ArcGIS for Server","Portal for ArcGIS","DataStore","Notebook Server","Mission Server") -Contains $Installer.Name){
                        $InstallationDirectory = $ExecutionContext.InvokeCommand.ExpandString($($Installer.Arguments).Split(" ")[1].split("=")[1].Replace('\\','\').Replace('"',""))
                        $FilesToDelete += (Join-Path $InstallationDirectory "framework/etc/arcgis-framework.properties")
                        if($Installer.Name -ieq "ArcGIS for Server" -or $Installer.Name -ieq "Notebook Server" -or $Installer.Name -ieq "Mission Server"){
                            $FilesToDelete += (Join-Path $InstallationDirectory "framework/etc/certificates/arcgis.keystore")
                            $FilesToDelete += (Join-Path $InstallationDirectory "framework/etc/certificates/keystorepass.dat")
                        }
                    }
                }
            }
        }
        
        if(-not($ProImage)){
            #### Install the IIS features
            foreach($pr in @("Web-Scripting-Tools"))
            {
                WindowsFeature "WF_$($pr)"
                {
                    Ensure =  $Ensure
                    Name = $pr
                    IncludeAllSubFeature = $true
                    DependsOn = $Depends
                }
                $Depends += "[WindowsFeature]WF_$($pr)"
            }

            foreach($pr in @("Web-Mgmt-Service", "Web-ISAPI-Ext", "Web-ISAPI-Filter", 
                                "Web-Filtering","Web-Windows-Auth",
                                "Web-Static-Content","Web-Asp-Net45","Web-Net-Ext45"))
            {
                WindowsFeature "WF_$($pr)"
                {
                    Ensure =  $Ensure
                    Name = $pr
                    IncludeAllSubFeature = $true
                    DependsOn = $Depends
                }
                $Depends += "[WindowsFeature]WF_$($pr)"
            }

            $ServiceToStopList = @('ArcGIS Server','Portal for ArcGIS','ArcGIS Data Store')

            if($Installers.Name -icontains "GeoEvent"){
                $ServiceToStopList += "ArcGISGeoEventGateway"
                $ServiceToStopList += "ArcGISGeoEvent"
            } 
            if($Installers.Name -icontains "Notebook Server"){
                $ServiceToStopList += "ArcGIS Notebook Server"
            }
            if($Installers.Name -icontains "Mission Server"){
                $ServiceToStopList += "ArcGIS Mission Server"
            }
            if($Installers.Name -icontains "Workflow Manager Server"){
                $ServiceToStopList += "WorkflowManager"
            }

            $ServiceToStopList | ForEach-Object{
                Service "StopService-$($_.Replace(' ', '_'))"
                {
                    Name        = $_
                    StartupType = "Manual"
                    State       = "Stopped"
                    DependsOn   = $Depends
                }
                $Depends += "[Service]StopService-$($_.Replace(' ', '_'))"
            }

            $FilesToDelete | ForEach-Object {
                $FileNameResourceName = $_.Replace('\', '_').Replace(':', '_')
                File "RemoveFile-$FileNameResourceName"
                {
                    Ensure          = "Absent"
                    Type            = "File"
                    DestinationPath = $_
                    DependsOn       = $Depends
                }
                $Depends += "[File]RemoveFile-$FileNameResourceName"
            }
        }
    }
}
