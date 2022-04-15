<#
    .SYNOPSIS
        Makes a request to the download a file from remote file storage server.
    .PARAMETER Url
        Fully qualified url of the remote file to be downloaded.
    .PARAMETER DestinationPath
        File path on the Local machine where the image will be downloaded too.
    .PARAMETER FileSourceType
        Remote file storage Authentication type. Supported values - AzureFiles, AzureBlobsManagedIdentity, Default
    .PARAMETER AFSCredential
        Credential to use when Azure Files if being used as remote file storage server
    .PARAMETER AFSEndpoint
        End point of Azure Files if being used as remote file storage server
    .PARAMETER Ensure
        Ensure makes sure that a remote file exists on the local machine. Take the values Present or Absent. 
        - "Present" ensures that a remote file exists on the local machine.
        - "Absent" ensures that a remote file doesn't exists on the local machine.
#>

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Url,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("AzureFiles","AzureBlobsManagedIdentity","Default")]
		[System.String]
        $FileSourceType
	)
	
	$null	
}


function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Url,

		[System.String]
        $DestinationPath,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("AzureFiles","AzureBlobsManagedIdentity","Default")]
		[System.String]
        $FileSourceType,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AFSCredential,

        [Parameter(Mandatory=$false)]
        [System.String]
        $AFSEndpoint,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)

    if(-not($DestinationPath)) {
        throw 'Destination Path not provided'
    }

    if($Ensure -ieq 'Present') {
        $DestinationFolder = Split-Path $DestinationPath -Parent	
        if(-not(Test-Path $DestinationFolder)){
            Write-Verbose "Creating Directory $DestinationFolder"
            New-Item $DestinationFolder -ItemType directory
        }	      
          
        if($FileSourceType -ieq "AzureFiles"){
            $AvailableDriveLetter = AvailableDriveLetter
            New-PSDrive -Name $AvailableDriveLetter -PSProvider FileSystem -Root $AFSEndpoint -Credential $AFSCredential -Persist
            $FileSharePath = "$($AvailableDriveLetter):\\$($url)"
            Write-Verbose "Copying file $FileSharePath to $DestinationPath"
            Copy-Item -Path $FileSharePath -Destination $DestinationPath -Force
            Remove-PSDrive -Name $AvailableDriveLetter
        }else{
            if($url.StartsWith('http', [System.StringComparison]::InvariantCultureIgnoreCase)) {
                Write-Verbose "Downloading file $url to $DestinationPath"
                Invoke-DownloadFile -RemoteFileUrl $url -DestinationFilePath $DestinationPath `
                                    -IsUsingAzureBlobManagedIndentity ($FileSourceType -ieq "AzureBlobsManagedIdentity") -Verbose
            }else{
                Write-Verbose "Copying file $url to $DestinationPath"
                Copy-Item -Path $url -Destination $DestinationPath -Force
            }
        }
    }
    elseif($Ensure -ieq 'Absent') {        
        if($DestinationPath  -and  (Test-Path $DestinationPath))
        {
            Remove-Item -Path $DestinationPath -Force
        }
    }	

}
function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Url,

		[System.String]
        $DestinationPath,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("AzureFiles","AzureBlobsManagedIdentity","Default")]
		[System.String]
        $FileSourceType,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $AFSCredential,

        [Parameter(Mandatory=$false)]
        [System.String]
        $AFSEndpoint,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)

	
	$result = $false
	if($DestinationPath -and (Test-Path $DestinationPath))
    {
        $result = $true
    }    
	if($Ensure -ieq 'Present') {
        if($result) {
            if($url.StartsWith('http', [System.StringComparison]::InvariantCultureIgnoreCase)) {
                # File Exists locally. Check the remote location
                Write-Verbose 'File Exists locally. Check if the remote URL has Changed using Last-Modified Header'
                $HasRemoteFileChanged = $true
                $response = $null
                try { 
                    if($FileSourceType -ieq "AzureBlobsManagedIdentity"){
                        $ManagedIdentityAccessToken = Get-ManagedIdentityAccessToken -Verbose
                        $Headers = @{
                                Authorization = "Bearer $ManagedIdentityAccessToken"
                                "x-ms-version" = "2017-11-09"
                            }
                        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -Headers $Headers -TimeoutSec 15 -Method Head -ErrorAction Ignore
                    }else{
                        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -UseDefaultCredentials -TimeoutSec 15 -Method Head -ErrorAction Ignore 
                    }
                }
                catch{ 
                    $HasRemoteFileChanged = $false 
                }
                if($response) {
                    [DateTime]$RemoteFileLastModTime = $response.Headers['Last-Modified']                    
                    if($RemoteFileLastModTime -le (Get-Item -Path $DestinationPath).CreationTime) {
                        $HasRemoteFileChanged = $false
                    }                    
                }
                if($HasRemoteFileChanged) {
                    # File has changed - needs to be downloaded again
                    $result = $false
                }
            } else {
                if($FileSourceType -eq "Default"){
                    if((Get-Item -Path $Url).LastWriteTime -gt (Get-Item -Path $DestinationPath).CreationTime) {
                        # File has changed - needs to be copied again
                        $result = $false
                    }
                }else{
                    $result = $false
                }
            }
        }
        $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }	
}

function AvailableDriveLetter
{
    param (
        [char]
        $ExcludedLetter
    )
    $Letter = [int][char]'C'
    $i = @()
    #getting all the used Drive letters reported by the Operating System
    $(Get-PSDrive -PSProvider filesystem) | ForEach-Object{$i += $_.name}
    #Adding the excluded letter
    $i+=$ExcludedLetter
    while($i -contains $([char]$Letter)){$Letter++}
    return $([char]$Letter)
}

function Get-ManagedIdentityAccessToken
{
    $response = Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fstorage.azure.com%2F' -UseBasicParsing -Method GET -Headers @{Metadata="true"}
    $content = $response.Content | ConvertFrom-Json
    $ArmToken = $content.access_token
    return $ArmToken
}

function Invoke-DownloadFile
{
    param (
        [System.String]
        $RemoteFileUrl,
        
        [System.String]
        $DestinationFilePath,

        [System.Boolean]
        $IsUsingAzureBlobManagedIndentity
    )
    try {
        $wc = New-Object System.Net.WebClient;
        if($IsUsingAzureBlobManagedIndentity){
            $ManagedIdentityAccessToken = Get-ManagedIdentityAccessToken -Verbose
            $wc.Headers.Add('Authorization', "Bearer $ManagedIdentityAccessToken")
            $wc.Headers.Add("x-ms-version", "2017-11-09")
        }
        $wc.DownloadFile($RemoteFileUrl, $DestinationFilePath)        
    }
    catch {
        throw "Error downloading remote file. Error - $_"
    }
}

Export-ModuleMember -Function *-TargetResource

