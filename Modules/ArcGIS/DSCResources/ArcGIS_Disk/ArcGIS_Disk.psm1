#
# ArcGIS_Disk: DSC resource to resize the Disk drives to maximum size.
#

function Get-TargetResource
{
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $HostName
    )

    @{}
}

function Set-TargetResource
{
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $HostName
    )
        
    Write-Verbose "Allocating maximum disk size if has the desired size of disks is not maximum on host '$HostName'"
    $Disks = Get-DiskLetterAndSizes
    foreach ($Disk in $Disks.GetEnumerator())
    {
        $DriveLetter = $Disk.Key
        $DiskNumber = $Disk.Value
        Set-DiskMaxSizeAllocated -DriveLetter $DriveLetter -DriveNumber $DiskNumber -Verbose
    }
}

function Test-TargetResource
{
	[OutputType([System.Boolean])]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $HostName
    )

    Write-Verbose "Checking if the disks has the desired size on host '$HostName'"
    $result = $true
    $Disks = Get-DiskLetterAndSizes
    foreach ($Disk in $Disks.GetEnumerator())
    {
	    $result = $result -and (Test-DiskMaxSizeAllocated -DriveLetter $Disk.Key -Verbose)
    }

    return $result
}

function Set-DiskMaxSizeAllocated
{
    [OutputType([System.Boolean])]
    param
    (
        [parameter(Mandatory = $true)]
        [string] $DriveLetter,

        [parameter(Mandatory = $true)]
        [int] $DriveNumber
    )

    $Partition = Get-Partition -DriveLetter $DriveLetter -ErrorAction Ignore
    if($Partition){
        $CurrentSizeInBytes = $Partition.Size
        $MaxSize = Get-PartitionMaxSize -Partition $Partition
        Write-Verbose "Drive Letter:- '$DriveLetter', Max Size in bytes:- '$MaxSize'"
        if(($MaxSize - $CurrentSizeInBytes) -ge 1MB){
            Write-Verbose "Max Size '$MaxSize' of Disk '$DriveLetter' is more than current size '$CurrentSizeInBytes'. Resizing partition to new size '$MaxSize'"
            Resize-Partition -DriveLetter $DriveLetter -Size $MaxSize -ErrorAction Stop
        }else {
            Write-Verbose "Disk '$DriveLetter' has less than 1 MiB available for growth (current size '$CurrentSizeInBytes', maximum size '$MaxSize'). Skipping resize."
        }
    }else{
        Write-Verbose "Drive Letter:- '$DriveLetter' is not allocated. Allocating disk '$DriveLetter'."
        
        $Disk = Get-Disk -Number $DriveNumber -ErrorAction Stop
        if ($disk.IsOffline -eq $true)
        {
            Write-Verbose 'Setting disk Online'
            $disk | Set-Disk -IsOffline $false
        }

        if ($disk.IsReadOnly -eq $true)
        {
            Write-Verbose 'Setting disk to not ReadOnly'
            $disk | Set-Disk -IsReadOnly $false
        }

        if ($disk.PartitionStyle -eq "RAW")
        {
            Write-Verbose -Message "Initializing disk number '$($DriveNumber)'..."
            $Disk = $Disk | Initialize-Disk -PartitionStyle GPT -PassThru
            $Partition = $Disk | New-Partition -DriveLetter $DriveLetter -UseMaximumSize
            Start-Sleep -Seconds 5
            $Partition | Format-Volume -FileSystem NTFS -Confirm:$false 
            Write-Verbose -Message "Successfully initialized disk number '$($DriveNumber)'."
        }
    }

    return (Test-DiskMaxSizeAllocated -DriveLetter $DriveLetter)
}


function Test-DiskMaxSizeAllocated
{
    [OutputType([System.Boolean])]
    param
    (
        [parameter(Mandatory)]
        [string] $DriveLetter
    )

    $result = $false
    $Partition = Get-Partition -DriveLetter $DriveLetter -ErrorAction Ignore
    if($Partition){
        $CurrentSizeInBytes = $Partition.Size
        $MaxSize = Get-PartitionMaxSize -Partition $Partition
        Write-Verbose "Drive Letter:- '$DriveLetter', Max Size in bytes:- '$MaxSize'"
        if(($MaxSize - $CurrentSizeInBytes) -ge 1MB){
            Write-Verbose "Max Size '$MaxSize' of Disk '$DriveLetter' is more than current size '$CurrentSizeInBytes'."
        }else {
            Write-Verbose "Disk '$DriveLetter' has less than 1 MiB available for growth (current size '$CurrentSizeInBytes', maximum size '$MaxSize'). No resize required."
            $result = $True
        }
    }else{
        Write-Verbose "Drive Letter:- '$DriveLetter' is not allocated."
    }
    return $result
}


function Get-PartitionMaxSize
{
    param
    (
        [parameter(Mandatory = $true)]
        [System.Object] $Partition
    )

    try
    {
        $SupportedSize = Get-PartitionSupportedSize -DiskNumber $Partition.DiskNumber -PartitionNumber $Partition.PartitionNumber -ErrorAction Stop
    }
    catch
    {
        throw "Unable to determine the maximum size of drive '$($Partition.DriveLetter)' (disk $($Partition.DiskNumber), partition $($Partition.PartitionNumber)). Get-PartitionSupportedSize failed: $($_.Exception.Message)"
    }

    if ($null -eq $SupportedSize.SizeMax -or $SupportedSize.SizeMax -le 0 -or $SupportedSize.SizeMax -lt $Partition.Size)
    {
        throw "Invalid maximum size returned for drive '$($Partition.DriveLetter)' (disk $($Partition.DiskNumber), partition $($Partition.PartitionNumber)): '$($SupportedSize.SizeMax)'. Current size: '$($Partition.Size)'."
    }

    return $SupportedSize.SizeMax
}


function Get-DiskLetterAndSizes
{
    $AssignedDriverLetters = @()
    $DisksToAllocate = @()
    $Disks = Get-Disk
    $DisksResult = @{}
    foreach($Disk in $Disks)
    {
        $Partitions = Get-Partition -DiskNumber $Disk.Number -ErrorAction Ignore
        if($Partitions)
        {
            foreach($Partition in $Partitions){
                $DriveLetter = $Partition.DriveLetter
                if($DriveLetter)
                {
                    # Update all assigned disks 
                    $AssignedDriverLetters += $DriveLetter
                    $DisksResult[$DriveLetter] =  $Disk.Number
                }
            }
        }else{
            $DisksToAllocate += $Disk
        }
    }

     # Allocate all unallocated disks and assign drive letters
     foreach($Disk in $DisksToAllocate){
        $i = 0
        if($Disk.PartitionStyle -ieq 'RAW'){
            $DriveLetter = [char]([int][char]'F' + $i)
            $DriveLetter = $DriveLetter.ToString()
            while($AssignedDriverLetters -contains $DriveLetter){
                $i++
                $DriveLetter = [char]([int][char]'F' + $i)
                $DriveLetter = $DriveLetter.ToString()
            }
            $DisksResult[$DriveLetter] =  $Disk.Number
            $AssignedDriverLetters += $DriveLetter
        }else{
            Write-Verbose "Skipping disk $($Disk.Number) as partition style is $($Disk.PartitionStyle)"
        }
    }
    return $DisksResult
}



Export-ModuleMember -Function *-TargetResource
