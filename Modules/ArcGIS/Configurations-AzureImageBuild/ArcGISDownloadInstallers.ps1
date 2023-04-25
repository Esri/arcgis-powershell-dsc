Configuration ArcGISDownloadInstallers
{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Installers,

        [Parameter(Mandatory=$true)]
        [ValidateSet("AzureFiles","AzureBlobsManagedIdentity","Default")]
		[System.String]
        $FileSourceType,

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
                    Source = $Installer.RemotePath
                    Destination = (Join-Path $ExecutionContext.InvokeCommand.ExpandString($Installer.LocalPath) $Installer.RemotePath)
                    FileSourceType = $FileSourceType
                    AzureFilesEndpoint = if($FileSourceType -ieq "AzureFiles"){ $AFSEndpoint }else{ $null }
                    Credential = if($FileSourceType -ieq "AzureFiles"){ $AFSCredential }else{ $null }         
                    Ensure = $Ensure
                }

                if((($Installer.Patches).Length -gt 0)) {
                    foreach($patch in $Installer.Patches){
                        $PatchFileName = Split-Path $patch -leaf
                        ArcGIS_RemoteFile "$($Installer.Name.Replace(' ', '_'))_$($PatchFileName.Replace(' ', '_'))"
                        {
                            Source = $PatchFileName
                            Destination = (Join-Path (Join-Path $ExecutionContext.InvokeCommand.ExpandString($Installer.LocalPath) "Patches") $PatchFileName)
                            FileSourceType = $FileSourceType
                            AzureFilesEndpoint = if($FileSourceType -ieq "AzureFiles"){ $AFSEndpoint }else{ $null }
                            Credential = if($FileSourceType -ieq "AzureFiles"){ $AFSCredential }else{ $null }         
                            Ensure = $Ensure
                        }
                    }
                }

                if(($Installer.AdditionalFiles).Length -gt 0) {
                    foreach($AdditionalFile in $Installer.AdditionalFiles){
                        $AdditionalFileName = Split-Path $AdditionalFile -leaf
                        ArcGIS_RemoteFile "$($Installer.Name.Replace(' ', '_'))_$($AdditionalFileName.Replace(' ', '_'))"
                        {
                            Source = $AdditionalFileName
                            Destination = (Join-Path (Join-Path $ExecutionContext.InvokeCommand.ExpandString($Installer.LocalPath) "AdditionalFiles") $AdditionalFileName)
                            FileSourceType = $FileSourceType
                            AzureFilesEndpoint = if($FileSourceType -ieq "AzureFiles"){ $AFSEndpoint }else{ $null }
                            Credential = if($FileSourceType -ieq "AzureFiles"){ $AFSCredential }else{ $null }         
                            Ensure = $Ensure
                        }
                    }
                }
            }
        }
    }
}
