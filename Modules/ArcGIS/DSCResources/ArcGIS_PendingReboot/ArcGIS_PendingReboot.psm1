<#
    .SYNOPSIS
        Fork of Pending Reboot dsc resource of ComputerManagementDsc Module. Sets the current state of the pending reboot.
    .PARAMETER Name
        Specifies the name of this pending reboot check.
    .PARAMETER SkipComponentBasedServicing
        Specifies whether to skip reboots triggered by the Component-Based Servicing component.
    .PARAMETER SkipWindowsUpdate
        Specifies whether to skip reboots triggered by Windows Update.
    .PARAMETER SkipPendingFileRename
        Specifies whether to skip pending file rename reboots.
    .PARAMETER SkipPendingComputerRename
        Specifies whether to skip reboots triggered by a pending computer rename.
    .PARAMETER SkipCcmClientSDK
        Specifies whether to skip reboots triggered by the ConfigMgr client. Defaults to True.
    
#>

# Import Localization Strings
$script:localizedData = ConvertFrom-StringData @'
GettingPendingRebootStateMessage = Getting the Pending Reboot State for '{0}'. (PR0001)
TestingPendingRebootStateMessage = Testing the Pending Reboot State for '{0}'. (PR0002)
RebootRequiredMessage = {0} reboot required. (PR0003)
RebootNotRequiredMessage = {0} reboot is not required. (PR0004)
RebootRequiredButSkippedMessage = {0} reboot required, but is skipped. (PR0005)
SettingPendingRebootStateMessage = Setting the Pending Reboot State for '{0}' to reboot required. (PR0006)
QueryCcmClientUtilitiesFailedMessage = Unable to query CIM Class CCM_ClientUtilities because '{0}'. (PR0007)
'@

# A list of reboot triggers that will be checked when determining if reboot is required.
$script:rebootTriggers = @(
        @{
            Name        = 'ComponentBasedServicing'
            Description = 'Component based servicing'
        },
        @{
            Name        = 'WindowsUpdate'
            Description = 'Windows Update'
        },
        @{
            Name        = 'PendingFileRename'
            Description = 'Pending file rename'
        },
        @{
            Name        = 'PendingComputerRename'
            Description = 'Pending computer rename'
        },
        @{
            Name        = 'CcmClientSDK'
            Description = 'ConfigMgr'
        }
    )

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name
    )

    Write-Verbose -Message ($script:localizedData.GettingPendingRebootStateMessage -f $Name)

    return Get-PendingRebootState @PSBoundParameters
}

function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter()]
        [System.Boolean]
        $SkipComponentBasedServicing,

        [Parameter()]
        [System.Boolean]
        $SkipWindowsUpdate,

        [Parameter()]
        [System.Boolean]
        $SkipPendingFileRename,

        [Parameter()]
        [System.Boolean]
        $SkipPendingComputerRename,

        [Parameter()]
        [System.Boolean]
        $SkipCcmClientSDK = $true
    )

    Write-Verbose -Message ($script:localizedData.SettingPendingRebootStateMessage -f $Name)

    $currentStatus = Get-PendingRebootState @PSBoundParameters

    if ($currentStatus.RebootRequired)
    {
        $global:DSCMachineStatus = 1
    }
}

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter()]
        [System.Boolean]
        $SkipComponentBasedServicing,

        [Parameter()]
        [System.Boolean]
        $SkipWindowsUpdate,

        [Parameter()]
        [System.Boolean]
        $SkipPendingFileRename,

        [Parameter()]
        [System.Boolean]
        $SkipPendingComputerRename,

        [Parameter()]
        [System.Boolean]
        $SkipCcmClientSDK = $true
    )

    Write-Verbose -Message ($script:localizedData.TestingPendingRebootStateMessage -f $Name)

    $currentStatus = Get-PendingRebootState @PSBoundParameters

    return (-not $currentStatus.RebootRequired)
}

<#
    .SYNOPSIS
        Returns a hash table containing the current state of the pending reboot
        triggers.
    .PARAMETER Name
        Specifies the name of this pending reboot check.
    .PARAMETER SkipComponentBasedServicing
        Specifies whether to skip reboots triggered by the Component-Based Servicing component.
    .PARAMETER SkipWindowsUpdate
        Specifies whether to skip reboots triggered by Windows Update.
    .PARAMETER SkipPendingFileRename
        Specifies whether to skip pending file rename reboots.
    .PARAMETER SkipPendingComputerRename
        Specifies whether to skip reboots triggered by a pending computer rename.
    .PARAMETER SkipCcmClientSDK
        Specifies whether to skip reboots triggered by the ConfigMgr client. Defaults to True.
#>
function Get-PendingRebootHashTable
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter()]
        [System.Boolean]
        $SkipComponentBasedServicing,

        [Parameter()]
        [System.Boolean]
        $SkipWindowsUpdate,

        [Parameter()]
        [System.Boolean]
        $SkipPendingFileRename,

        [Parameter()]
        [System.Boolean]
        $SkipPendingComputerRename,

        [Parameter()]
        [System.Boolean]
        $SkipCcmClientSDK = $true
    )

    # The list of registry keys that will be used to determine if a reboot is required
    $rebootRegistryKeys = @{
        ComponentBasedServicing = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\'
        WindowsUpdate           = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\'
        PendingFileRename       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\'
        ActiveComputerName      = 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName'
        PendingComputerName     = 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName'
    }

    $componentBasedServicingKeys = (Get-ChildItem -Path $rebootRegistryKeys.ComponentBasedServicing).Name

    if ($componentBasedServicingKeys)
    {
        $componentBasedServicing = $componentBasedServicingKeys.Split('\') -contains 'RebootPending'
    }
    else
    {
        $componentBasedServicing = $false
    }

    $windowsUpdateKeys = (Get-ChildItem -Path $rebootRegistryKeys.WindowsUpdate).Name

    if ($windowsUpdateKeys)
    {
        $windowsUpdate = $windowsUpdateKeys.Split('\') -contains 'RebootRequired'
    }
    else
    {
        $windowsUpdate = $false
    }

    $pendingFileRename = (Get-ItemProperty -Path $rebootRegistryKeys.PendingFileRename).PendingFileRenameOperations.Length -gt 0
    $activeComputerName = (Get-ItemProperty -Path $rebootRegistryKeys.ActiveComputerName).ComputerName
    $pendingComputerName = (Get-ItemProperty -Path $rebootRegistryKeys.PendingComputerName).ComputerName
    $pendingComputerRename = $activeComputerName -ne $pendingComputerName

    if ($SkipCcmClientSDK)
    {
        $ccmClientSDK = $false
    }
    else
    {
        $invokeCimMethodParameters = @{
            NameSpace   = 'ROOT\ccm\ClientSDK'
            ClassName   = 'CCM_ClientUtilities'
            Name        = 'DetermineIfRebootPending'
            ErrorAction = 'Stop'
        }

        try
        {
            $ccmClientSDK = Invoke-CimMethod @invokeCimMethodParameters
        }
        catch
        {
            Write-Warning -Message ($script:localizedData.QueryCcmClientUtilitiesFailedMessage -f $_)
        }

        $ccmClientSDK = ($ccmClientSDK.ReturnValue -eq 0) -and ($ccmClientSDK.IsHardRebootPending -or $ccmClientSDK.RebootPending)
    }

    return @{
        Name                        = $Name
        SkipComponentBasedServicing = $SkipComponentBasedServicing
        ComponentBasedServicing     = $componentBasedServicing
        SkipWindowsUpdate           = $SkipWindowsUpdate
        WindowsUpdate               = $windowsUpdate
        SkipPendingFileRename       = $SkipPendingFileRename
        PendingFileRename           = $pendingFileRename
        SkipPendingComputerRename   = $SkipPendingComputerRename
        PendingComputerRename       = $pendingComputerRename
        SkipCcmClientSDK            = $SkipCcmClientSDK
        CcmClientSDK                = $ccmClientSDK
    }
}

<#
    .SYNOPSIS
        Returns the current state of the pending reboot by assessing the result provided
        in a pending reboot hash table.
    .PARAMETER Name
        Specifies the name of this pending reboot check.
    .PARAMETER SkipComponentBasedServicing
        Specifies whether to skip reboots triggered by the Component-Based Servicing component.
    .PARAMETER SkipWindowsUpdate
        Specifies whether to skip reboots triggered by Windows Update.
    .PARAMETER SkipPendingFileRename
        Specifies whether to skip pending file rename reboots.
    .PARAMETER SkipPendingComputerRename
        Specifies whether to skip reboots triggered by a pending computer rename.
    .PARAMETER SkipCcmClientSDK
        Specifies whether to skip reboots triggered by the ConfigMgr client. Defaults to True.
#>
function Get-PendingRebootState
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter()]
        [System.Boolean]
        $SkipComponentBasedServicing,

        [Parameter()]
        [System.Boolean]
        $SkipWindowsUpdate,

        [Parameter()]
        [System.Boolean]
        $SkipPendingFileRename,

        [Parameter()]
        [System.Boolean]
        $SkipPendingComputerRename,

        [Parameter()]
        [System.Boolean]
        $SkipCcmClientSDK = $true
    )

    $pendingRebootState = Get-PendingRebootHashTable @PSBoundParameters
    $rebootRequired = $false

    foreach ($rebootTrigger in $script:rebootTriggers)
    {
        $skipTriggerName = 'Skip{0}' -f $rebootTrigger.Name
        $skipTrigger = $pendingRebootState.$skipTriggerName

        if ($skipTrigger)
        {
            Write-Verbose -Message ($script:localizedData.RebootRequiredButSkippedMessage -f $rebootTrigger.Description)
        }
        else
        {
            if ($pendingRebootState.$($rebootTrigger.Name))
            {
                Write-Verbose -Message ($script:localizedData.RebootRequiredMessage -f $rebootTrigger.Description)
                $rebootRequired = $true
            }
            else
            {
                Write-Verbose -Message ($script:localizedData.RebootNotRequiredMessage -f $rebootTrigger.Description)
            }
        }
    }

    $pendingRebootState += @{
        RebootRequired = $rebootRequired
    }

    return $pendingRebootState
}

Export-ModuleMember -Function *-TargetResource