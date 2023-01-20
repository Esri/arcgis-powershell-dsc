Configuration ArcGISRegisterSQLEGDB{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]    
        [System.String]
        $PrimaryServerMachine,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServerPrimarySiteAdminCredential,

        [Parameter(Mandatory=$true)]
        [ValidateSet("AzureSQLDatabase","SQLServerDatabase","AzurePostgreSQLDatabase","AzureMISQLDatabase")]
        [System.String]
        $DatabaseType,

        [Parameter(Mandatory=$False)]
        [System.String]
        $DatabaseServerHostName,
        
        [Parameter(Mandatory=$False)]
        [System.String]
        $DatabaseName,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $DatabaseServerAdministratorCredential,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $SDEUserCredential,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $DatabaseUserCredential,

        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $DatabaseIsManaged = $False,
        
        [Parameter(Mandatory=$False)]
        [System.Boolean]
        $EnableGeodatabase = $False
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 4.0.2
    Import-DSCResource -Name ArcGIS_EGDB
    
    Node $AllNodes.NodeName
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }
        
        if($Node.NodeName -ieq $PrimaryServerMachine){
            ArcGIS_EGDB "RegisterEGDB-$DatabaseServerHostName"
            {
                DatabaseServer              = $DatabaseServerHostName
                DatabaseName                = $DatabaseName
                ServerSiteAdministrator     = $ServerPrimarySiteAdminCredential
                DatabaseServerAdministrator = $DatabaseServerAdministratorCredential
                SDEUser                     = $SDEUserCredential
                DatabaseUser                = $DatabaseUserCredential
                IsManaged                   = $DatabaseIsManaged
                EnableGeodatabase           = $EnableGeodatabase
                DatabaseType                = $DatabaseType
                Ensure                      = 'Present'
            }
        }
    }
}
