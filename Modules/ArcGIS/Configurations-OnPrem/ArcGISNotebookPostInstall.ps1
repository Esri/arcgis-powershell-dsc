Configuration ArcGISNotebookPostInstall
{
    param(
        [Parameter(Mandatory=$true)]
        [System.String]
        $Version,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServiceCredential,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsMSA = $false,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $ServerPrimarySiteAdminCredential,

        [Parameter(Mandatory=$false)]
        [System.Array]
        $ContainerImagePaths,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ExtractSamples = $false
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 5.2.0 -Name ArcGIS_NotebookPostInstall

    Node $AllNodes.NodeName
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }

        $HasContainerImages = ($ContainerImagePaths.Count -gt 0)
        $ShouldExtractSamples = ((@('10.9.1','11.0','11.1','11.2','11.3') -icontains $Version) -and $ExtractSamples -and -not($ServiceCredentialIsMSA))

        if($HasContainerImages -or $ShouldExtractSamples){
            if([version]$Version -ge '12.2'){
                ArcGIS_NotebookPostInstall "NotebookPostInstall$($Node.NodeName)"
                {
                    SiteName            = 'arcgis'
                    Version             = $Version
                    ContainerImagePaths = if($HasContainerImages){$ContainerImagePaths}else{$null}
                    ExtractSamples      = $false
                    SiteAdministrator   = $ServerPrimarySiteAdminCredential
                }
            }elseif($ServiceCredentialIsMSA){
                ArcGIS_NotebookPostInstall "NotebookPostInstall$($Node.NodeName)"
                {
                    SiteName            = 'arcgis'
                    Version             = $Version
                    ContainerImagePaths = if($HasContainerImages){$ContainerImagePaths}else{$null}
                    ExtractSamples      = $ShouldExtractSamples
                }
            }else{
                ArcGIS_NotebookPostInstall "NotebookPostInstall$($Node.NodeName)"
                {
                    SiteName             = 'arcgis'
                    Version              = $Version
                    ContainerImagePaths  = if($HasContainerImages){$ContainerImagePaths}else{$null}
                    ExtractSamples       = $ShouldExtractSamples
                    PsDscRunAsCredential = $ServiceCredential
                }
            }
        }
    }
}