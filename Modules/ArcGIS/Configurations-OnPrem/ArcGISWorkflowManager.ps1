Configuration ArcGISWorkflowManager
{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $ServiceCredential,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ForceServiceCredentialUpdate = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsDomainAccount = $false,

        [Parameter(Mandatory=$false)]
        [System.Boolean]
        $ServiceCredentialIsMSA = $false,

        [Parameter(Mandatory=$true)]
        [System.String]
        $Version
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ArcGIS -ModuleVersion 5.2.0 -Name ArcGIS_Service_Account, ArcGIS_xFirewall

    Node $AllNodes.NodeName
    {
        if($Node.Thumbprint){
            LocalConfigurationManager
            {
                CertificateId = $Node.Thumbprint
            }
        }

        ArcGIS_Service_Account WorkflowManager_RunAs_Account
        {
            Name = 'WorkflowManager'
            RunAsAccount = $ServiceCredential
            ForceRunAsAccountUpdate = $ForceServiceCredentialUpdate
            Ensure = 'Present'
            DataDir = "$env:ProgramData\Esri\workflowmanager"
            IsDomainAccount = $ServiceCredentialIsDomainAccount
            IsMSAAccount = $ServiceCredentialIsMSA
            SetStartupToAutomatic = $True
        }

        ArcGIS_xFirewall WorkflowManagerServer_FirewallRules
        {
            Name                  = 'ArcGISWorkflowManagerServerFirewallRules'
            DisplayName           = 'ArcGIS Workflow Manager Server'
            DisplayGroup          = 'ArcGIS Workflow Manager Server Extension'
            Ensure                = 'Present'
            Access                = 'Allow'
            State                 = 'Enabled'
            Profile               = ('Domain','Private','Public')
            LocalPort             = ('13443')
            Protocol              = 'TCP'
            DependsOn             = '[ArcGIS_Service_Account]WorkflowManager_RunAs_Account'
        }

        if(($AllNodes | Measure-Object).Count -gt 1){
            $WfmPorts = @('9830', '9820', '9840', '9880')
            if([version]$Version -ge '11.3'){
                $WfmPorts = @('13820', '13830', '13840', '9880')
            }

            ArcGIS_xFirewall WorkflowManagerServer_FirewallRules_MultiMachine_OutBound
            {
                Name                  = 'ArcGISWorkflowManagerServerFirewallRulesClusterOutbound'
                DisplayName           = 'ArcGIS WorkflowManagerServer Extension Cluster Outbound'
                DisplayGroup          = 'ArcGIS WorkflowManagerServer Extension'
                Ensure                = 'Present'
                Access                = 'Allow'
                State                 = 'Enabled'
                Profile               = ('Domain','Private','Public')
                RemotePort            = $WfmPorts
                Protocol              = 'TCP'
                Direction             = 'Outbound'
                DependsOn             = '[ArcGIS_xFirewall]WorkflowManagerServer_FirewallRules'
            }

            ArcGIS_xFirewall WorkflowManagerServer_FirewallRules_MultiMachine_InBound
            {
                Name                  = 'ArcGISWorkflowManagerServerFirewallRulesClusterInbound'
                DisplayName           = 'ArcGIS WorkflowManagerServer Extension Cluster Inbound'
                DisplayGroup          = 'ArcGIS WorkflowManagerServer Extension'
                Ensure                = 'Present'
                Access                = 'Allow'
                State                 = 'Enabled'
                Profile               = ('Domain','Private','Public')
                LocalPort             = $WfmPorts
                Protocol              = 'TCP'
                Direction             = 'Inbound'
                DependsOn             = '[ArcGIS_xFirewall]WorkflowManagerServer_FirewallRules_MultiMachine_OutBound'
            }
        }
    }
}