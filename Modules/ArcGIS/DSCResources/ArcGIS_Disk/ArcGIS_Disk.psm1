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

    $null
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
        $MaxSize = ((Get-PartitionSupportedSize -DriveLetter $DriveLetter).sizeMax * 1)
        Write-Verbose "Drive Letter:- '$DriveLetter', Max Size in bytes:- '$MaxSize'"
        if($CurrentSizeInBytes -lt $MaxSize){
            Write-Verbose "Max Size '$MaxSize' of Disk '$DriveLetter' is more than current size '$CurrentSizeInBytes'. Resizing partition to new size '$MaxSize'"
            Resize-Partition -DriveLetter $DriveLetter -Size $MaxSize -ErrorAction SilentlyContinue # TODO:- capture error in error variable and log it at a minimum
        }else {
            Write-Verbose "Max Size '$MaxSize' of Disk '$DriveLetter' is equal to current size '$CurrentSizeInBytes'."
        }
    }else{
        Write-Verbose "Drive Letter:- '$DriveLetter' is not allocated. Allocating disk '$DriveLetter'."
        
        $Disk = Get-Disk -Number $DiskNumber
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
            Write-Verbose -Message "Initializing disk number '$($DiskNumber)'..."
            $disk | Initialize-Disk -PartitionStyle GPT -PassThru
            $partition = $disk | New-Partition -DriveLetter $DriveLetter -UseMaximumSize
            Start-Sleep -Seconds 5
            $Partition | Format-Volume -FileSystem NTFS -Confirm:$false 
            Write-Verbose -Message "Successfully initialized disk number '$($DiskNumber)'."
        }
    }
    return $result
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
        $MaxSize = ((Get-PartitionSupportedSize -DriveLetter $DriveLetter).sizeMax * 1)
        Write-Verbose "Drive Letter:- '$DriveLetter', Max Size in bytes:- '$MaxSize'"
        if($CurrentSizeInBytes -lt $MaxSize){
            Write-Verbose "Max Size '$MaxSize' of Disk '$DriveLetter' is more than current size '$CurrentSizeInBytes'."
        }else {
            Write-Verbose "Max Size '$MaxSize' of Disk '$DriveLetter' is equal to current size '$CurrentSizeInBytes'."
            $result = $True
        }
    }else{
        Write-Verbose "Drive Letter:- '$DriveLetter' is not allocated."
    }
    return $result
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
