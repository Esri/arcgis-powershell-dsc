Configuration ArcGISDownloadInstallers
{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Installers,

        [Parameter(Mandatory=$true)]
        [System.Boolean]
        $UseAzureFiles,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AFSCredential,

        [Parameter(Mandatory=$false)]
        [System.String]
        $AFSEndpoint,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Absent','Present')] 
        [ValidateNotNullOrEmpty()]
        [string]$Ensure = 'Present'
    )
    
    Import-DscResource -Name ArcGIS_RemoteFile

    Node localhost
    {
	    LocalConfigurationManager
        {
			ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'    
            RebootNodeIfNeeded = $true
        }

        foreach($Installer in $Installers)
        {
            if($Installer.RemotePath -and $Installer.LocalPath -and $Installer.Name) 
            {
                ArcGIS_RemoteFile $Installer.Name.Replace(' ', '_')
                {
                    Url = $Installer.RemotePath
                    DestinationPath = $ExecutionContext.InvokeCommand.ExpandString($Installer.LocalPath) 
                    UseAzureFiles = if($UseAzureFiles){ $true }else{ $false }
                    AFSEndpoint = if($UseAzureFiles){ $AFSEndpoint }else{ $null }
                    AFSCredential = if($UseAzureFiles){ $AFSCredential }else{ $null }         
                    Ensure = $Ensure
                }
            }
        }
    }
}