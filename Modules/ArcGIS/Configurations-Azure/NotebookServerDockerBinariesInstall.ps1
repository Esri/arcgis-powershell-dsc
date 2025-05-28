Configuration NotebookServerDockerBinariesInstall
{
    param(
        [Parameter(Mandatory=$false)]
        [System.String]
        $Version = "11.5"

        ,[Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Context
        
        ,[Parameter(Mandatory=$false)]
        [System.String]
        $DockerEngineBinariesArchiveUrl

        ,[Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $ServiceCredential

        ,[Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration 
    Import-DSCResource -ModuleName ArcGIS
    Import-DscResource -Name ArcGIS_PendingReboot
    Import-DscResource -Name ArcGIS_NotebookPostInstall
    Import-DscResource -Name ArcGIS_NotebookServerDockerEngine

    Node localhost
	{
        LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $True
        }

        WindowsFeature containers
        {
            Name  = 'Containers'
            Ensure = 'Present'
        }
        
        ArcGIS_PendingReboot PendingReboot
        {
            Name = 'PendingReboot'
            DependsOn = @("[WindowsFeature]containers")
        }
        
        ArcGIS_NotebookServerDockerEngine InstallDockerEngine
        {
            SiteName = $Context
            DockerEngineBinariesArchiveUrl = $DockerEngineBinariesArchiveUrl
            ServiceCredentialUsername = $ServiceCredential.UserName
            ForceUpdate = $False
            DependsOn = @("[ArcGIS_PendingReboot]PendingReboot")
        }

        ArcGIS_PendingReboot PendingRebootAfterDockerInstall
        {
            Name = 'PendingRebootAfterDockerInstall'
            DependsOn = @("[ArcGIS_NotebookServerDockerEngine]InstallDockerEngine")
        }

        $NBAdditionFilesPath = "C:\\ArcGIS\\Deployment\\Downloads\\NotebookServer\\AdditionalFiles"
        if(Test-Path $NBAdditionFilesPath){
            $containerPath = Get-ChildItem -Path $NBAdditionFilesPath -Filter "*arcgis-notebook-python-windows-$($Version)*" -Recurse | Select-Object -ExpandProperty FullName
            if(-not([string]::IsNullOrEmpty($containerPath))){
                ArcGIS_NotebookPostInstall NotebookPostInstall {
                    SiteName            = $Context
                    ContainerImagePaths = @($containerPath) # Add the path to the container images
                    ExtractSamples      = $false
                    DependsOn           = @("[ArcGIS_PendingReboot]PendingRebootAfterDockerInstall")
                    PsDscRunAsCredential  = $ServiceCredential # Copy as arcgis account which has access to this share
                }
            }
        }
    }
}