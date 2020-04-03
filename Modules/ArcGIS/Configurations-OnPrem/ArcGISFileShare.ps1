Configuration ArcGISFileShare
{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServiceCredential,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsMSA = $false,

        [Parameter(Mandatory=$true)]
        [System.String]
        $FileShareName,

        [Parameter(Mandatory=$true)]
        [System.String]
        $FileShareLocalPath,

        [Parameter(Mandatory=$False)]
        [System.String]
        $FilePaths
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DSCResource -ModuleName @{ModuleName="ArcGIS";ModuleVersion="3.0.1"}
    Import-DscResource -Name ArcGIS_xFirewall
    Import-DscResource -Name ArcGIS_FileShare

    Node $AllNodes.NodeName 
    {   
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        ArcGIS_FileShare FileShare
        {
            FileShareName = $FileShareName
            FileShareLocalPath = $FileShareLocalPath
            Ensure = 'Present'
            Credential = $ServiceCredential
            FilePaths = if($FilePaths -and ($FilePaths -ne "")){ $FilePaths }else{ $null }
            IsDomainAccount = $ServiceCredentialIsDomainAccount
        }        
    }
}