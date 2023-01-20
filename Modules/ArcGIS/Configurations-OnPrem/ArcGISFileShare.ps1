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
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.0.2
    Import-DscResource -Name ArcGIS_FileShare

    Node $AllNodes.NodeName 
    {   
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }

        $DependsOn = @()
        if($null -ne $ServiceCredential){
            if(-not($ServiceCredentialIsDomainAccount) -and -not($ServiceCredentialIsMSA)){
                User ArcGIS_RunAsAccount
                {
                    UserName = $ServiceCredential.UserName
                    Password = $ServiceCredential
                    FullName = 'ArcGIS Run As Account'
                    Ensure = "Present"
                    PasswordChangeRequired = $false
                    PasswordNeverExpires = $true
                }
                $DependsOn += '[User]ArcGIS_RunAsAccount'
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
            IsMSAAccount = $ServiceCredentialIsMSA
            DependsOn = $DependsOn
        }        
    }
}
