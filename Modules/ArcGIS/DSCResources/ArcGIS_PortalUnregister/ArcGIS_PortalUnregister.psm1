$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.Portal.psm1'))

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
        $PortalEndPoint,
            
		[System.Management.Automation.PSCredential]
        $PortalAdministrator,
        
        [parameter(Mandatory = $true)]
        [System.String]
        $StandbyMachine,

        [parameter(Mandatory = $true)]
        [System.String]
        $Version
	)

    @{}
}

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
	param
	(
        [parameter(Mandatory = $true)]
		[System.String]
        $PortalEndPoint,
            
		[System.Management.Automation.PSCredential]
        $PortalAdministrator,
        
        [parameter(Mandatory = $true)]
        [System.String]
        $StandbyMachine,

        [parameter(Mandatory = $true)]
        [System.String]
        $Version
    )
    
    
	$result = $false
	$result = Test-Install -Name "Portal" -Version $Version
    if(-not($result)){
		$Referer = 'https://localhost'
        $PortalBaseURL = $PortalEndPoint.TrimEnd("/") + "/arcgis"
		$token = Get-PortalToken -URL $PortalBaseURL -Credential $PortalAdministrator -Referer $Referer
        $StandbyMachineHostName = Get-FQDN $StandbyMachine
        $StandbyFlag = Test-MachineInPortalSite -URL $PortalBaseURL -Credential $PortalAdministrator -Token $token.token -MachineFQDN $StandbyMachineHostName
		$result = -not($StandbyFlag)
	}

	$result
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
        [parameter(Mandatory = $true)]
		[System.String]
        $PortalEndPoint,
            
		[System.Management.Automation.PSCredential]
        $PortalAdministrator,
        
        [parameter(Mandatory = $true)]
        [System.String]
        $StandbyMachine,

        [parameter(Mandatory = $true)]
        [System.String]
        $Version
	)



    $Referer = 'https://localhost'
    $PortalBaseURL = $PortalEndPoint.TrimEnd("/") + "/arcgis"
    $token = Get-PortalToken -URL $PortalBaseURL -Credential $PortalAdministrator -Referer $Referer
        
    Write-Verbose "Unregistering $StandbyMachine Portal"
    $StandbyMachineHostName = Get-FQDN $StandbyMachine
    $StandbyMachine = ((Get-MachinesInPortalSite -URL $PortalBaseURL -Token $token.token -Referer $Referer) | Where-Object { $_.machineName -ieq $StandbyMachineHostName } | Select-Object -First 1)
    Unregister-PortalSiteMachine -URL $PortalBaseURL -Token $token.token -Referer $Referer -MachineFQDN $StandbyMachine.machineName -Verbose
}

Export-ModuleMember -Function *-TargetResource
