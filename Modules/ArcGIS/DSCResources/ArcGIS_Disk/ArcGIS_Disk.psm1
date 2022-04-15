#
# ArcGIS_Disk: DSC resource to resize the OS (System) Disk Drive
#

function Get-TargetResource
{
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory)]
        [string] $DriveLetter
    )

    $null
}

function Set-TargetResource
{
    param
    (
        [parameter(Mandatory)]
        [string] $DriveLetter,

        [uint32] $SizeInGB
    )
        
    Write-Verbose "Drive Letter:- $DriveLetter"
    $CurrentSizeInBytes = (Get-Partition -DriveLetter $DriveLetter).Size
    $DesiredSizeInBytes = $SizeInGB * 1024 * 1024 * 1024
    $MaxSize = ((Get-PartitionSupportedSize -DriveLetter $DriveLetter).sizeMax * 1)
    Write-Verbose "Desired Size:- $DesiredSizeInBytes Max Size:- $MaxSize"    
    $NewSize = [System.Math]::Min($MaxSize, $DesiredSizeInBytes)
    Write-Verbose "Desired Size:- $DesiredSizeInBytes Max Size:- $MaxSize New Size:- $NewSize" 
	$NewSize = [System.Math]::Min($NewSize, 4396837486080) # Max of 4 TB	
    Write-Verbose "Desired Size:- $DesiredSizeInBytes Max Size:- $MaxSize New Size:- $NewSize" 
    if($CurrentSizeInBytes -lt $NewSize){        
        Write-Verbose "Desired Size '$DesiredSizeInBytes' is more than current size '$CurrentSizeInBytes'. MaxSize for partition is '$MaxSize'. Resizing partition to new size '$NewSize'"
        Resize-Partition -DriveLetter $DriveLetter -Size $NewSize -ErrorAction SilentlyContinue # TODO:- capture error in error variable and log it at a minimum
    }else {
        Write-Verbose "Desired Size '$DesiredSizeInBytes' is equal or less than current size '$CurrentSizeInBytes'. MaxSize for partition is '$MaxSize'."
    }
}

function Test-TargetResource
{
	[OutputType([System.Boolean])]
    param
    (
        [parameter(Mandatory)]
        [string] $DriveLetter,

        [uint32] $SizeInGB
    )

    $result = $true
    Write-Verbose "Drive Letter:- $DriveLetter"
    $CurrentSizeInBytes = (Get-Partition -DriveLetter $DriveLetter).Size
    $DesiredSizeInBytes = $SizeInGB * 1024 * 1024 * 1024
    $MaxSize = ((Get-PartitionSupportedSize -DriveLetter $DriveLetter).sizeMax * 1)
    Write-Verbose "Desired Size:- $DesiredSizeInBytes Max Size:- $MaxSize"   
    $NewSize = [System.Math]::Min($MaxSize, $DesiredSizeInBytes)
    Write-Verbose "Desired Size:- $DesiredSizeInBytes Max Size:- $MaxSize New Size:- $NewSize" 
    if($CurrentSizeInBytes -lt $NewSize){
        Write-Verbose "Desired Size '$DesiredSizeInBytes' is more than current size '$CurrentSizeInBytes'. MaxSize for partition is '$MaxSize'."
        $result = $false
    }else {
        Write-Verbose "Desired Size '$DesiredSizeInBytes' is equal or less than current size '$CurrentSizeInBytes'. MaxSize for partition is '$MaxSize'."
    }
    $result
}


Export-ModuleMember -Function *-TargetResource
