$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.Portal.psm1'))

<#
    .SYNOPSIS
        Makes a request to the download a file from remote file storage server.
    .PARAMETER Source
        Can be fully qualified Url of the remote file to be downloaded or filepath to copy from a mounted share.
    .PARAMETER Destination
        File path on the Local machine where the image will be downloaded too.
    .PARAMETER FileSourceType
        Remote file storage Authentication type. Supported values - AzureFiles, AzureBlobsManagedIdentity, ArcGISDownloadsAPI, Default
    .PARAMETER Credential
        Credential to fetch ArcGIS Online Credential if being used as remote file storage server or to fetch Azure Files if being used as remote file storage server
    .PARAMETER AzureFilesEndpoint
        End point of Azure Files if being used as remote file storage server
    .PARAMETER ArcGISDownloadAPIFolderPath
        ArcGIS Downloads API Folder Version Path
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
		$Source,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("AzureFiles","AzureBlobsManagedIdentity","ArcGISDownloadsAPI","AzureSASUri","Default")]
		[System.String]
        $FileSourceType
	)
	
	@{}
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Source,

		[System.String]
        $Destination,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("AzureFiles","AzureBlobsManagedIdentity","ArcGISDownloadsAPI", "AzureSASUri","Default")]
		[System.String]
        $FileSourceType,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory=$false)]
        [System.String]
        $AzureFilesEndpoint,

        [Parameter(Mandatory=$false)]
        [System.String]
        $ArcGISDownloadAPIFolderPath,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)

    if(-not($Destination)) {
        throw 'Destination Path not provided'
    }

    if($Ensure -ieq 'Present') {
        $DestinationFolder = Split-Path $Destination -Parent	
        if(-not(Test-Path $DestinationFolder)){
            Write-Verbose "Creating Directory $DestinationFolder"
            New-Item $DestinationFolder -ItemType directory
        }	      
          
        if($FileSourceType -ieq "AzureFiles"){
            $AvailableDriveLetter = Get-AvailableDriveLetter
            New-PSDrive -Name $AvailableDriveLetter -PSProvider FileSystem -Root $AzureFilesEndpoint -Credential $Credential -Persist
            $FileSharePath = "$($AvailableDriveLetter):\\$($Source)"
            Write-Verbose "Copying file $FileSharePath to $Destination"
            Copy-Item -Path $FileSharePath -Destination $Destination -Force
            Remove-PSDrive -Name $AvailableDriveLetter
        }else{
            if($FileSourceType -ieq "ArcGISDownloadsAPI" -or $Source.StartsWith('http', [System.StringComparison]::InvariantCultureIgnoreCase)){
                $DownloadUrl = $Source 
				if($FileSourceType -ieq "ArcGISDownloadsAPI"){
					$DownloadUrl = (Get-ArcGISDownloadAPIUrl -FileName $Source -ArcGISDownloadAPIFolderPath $ArcGISDownloadAPIFolderPath `
										-ArcGISOnlineCredential $Credential -Verbose)
				}
                
                Write-Verbose "Downloading file to $Destination"
                Get-RemoteFile -RemoteFileUrl $DownloadUrl -DestinationFilePath $Destination `
                                    -IsUsingAzureBlobManagedIndentity ($FileSourceType -ieq "AzureBlobsManagedIdentity") -Verbose
            }elseif($FileSourceType -ieq "AzureSASUri"){
                $DownloadUrl ="$($Credential.UserName.TrimEnd('\'))/$($Source)$($Credential.GetNetworkCredential().Password)"
                Write-Verbose "Downloading file to $Destination"
                Get-RemoteFile -RemoteFileUrl $DownloadUrl -DestinationFilePath $Destination -Verbose
            }
            else{
                Write-Verbose "Copying file $Source to $Destination"
                Copy-Item -Path $Source -Destination $Destination -Force
            }
        }
    }
    elseif($Ensure -ieq 'Absent') {        
        if($Destination  -and  (Test-Path $Destination))
        {
            Remove-Item -Path $Destination -Force
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
		$Source,

        [System.String]
        $Destination,

        [Parameter(Mandatory=$true)]
        [ValidateSet("AzureFiles","AzureBlobsManagedIdentity","ArcGISDownloadsAPI","AzureSASUri","Default")]
		[System.String]
        $FileSourceType,
        
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory=$false)]
        [System.String]
        $AzureFilesEndpoint,

        [Parameter(Mandatory=$false)]
        [System.String]
        $ArcGISDownloadAPIFolderPath,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)
	$result = $false
	if($Destination -and (Test-Path $Destination))
    {
        $result = $true
    }
	if($Ensure -ieq 'Present') {
        if($result) {
			if($FileSourceType -ieq "ArcGISDownloadsAPI" -or $Source.StartsWith('http', [System.StringComparison]::InvariantCultureIgnoreCase) -or $FileSourceType -ieq "AzureSASUri"){
                Write-Verbose 'File Exists locally. Check if the remote URL has Changed using Last-Modified Header'
                $HasRemoteFileChanged = $true
                $DownloadUrl = $Source
                if($FileSourceType -ieq "ArcGISDownloadsAPI"){
                    $DownloadUrl = (Get-ArcGISDownloadAPIUrl -FileName $Source -ArcGISDownloadAPIFolderPath $ArcGISDownloadAPIFolderPath `
                                        -ArcGISOnlineCredential $Credential -Verbose)
                }
                if($FileSourceType -ieq "AzureSASUri"){
                    $DownloadUrl ="$($Credential.UserName.TrimEnd('\'))/$($Source)$($Credential.GetNetworkCredential().Password)"
                }

                $Request = [System.Net.HttpWebRequest]::CreateHttp($DownloadUrl)
                $response = $null
                try { 
                    $Request.Method = 'HEAD'
                    $Request.Timeout = 20000
                    if($FileSourceType -ieq "AzureBlobsManagedIdentity"){
                        $ManagedIdentityAccessToken = Get-AzureManagedIdentityStorageAccessToken -Verbose
                        $Request.Headers.Add("Authorization","Bearer $ManagedIdentityAccessToken")
                        $Request.Headers.Add("x-ms-version","2017-11-09")
                    }
                    $response = $Request.GetResponse();
                }
                catch{ 
                    Write-Verbose "[WARNING] - $_"
                }
                if($response) {
                    [DateTime]$RemoteFileLastModTime = $response.Headers['Last-Modified']
                    if($RemoteFileLastModTime -le (Get-Item -Path $Destination).CreationTime) {
                        $HasRemoteFileChanged = $false
                    }
                    $response.Dispose()                    
                }
                if($HasRemoteFileChanged) {
                    # File has changed - needs to be downloaded again
                    $result = $false
                }
            } else {
                if($FileSourceType -eq "Default"){
                    if((Get-Item -Path $Source).LastWriteTime -gt (Get-Item -Path $Destination).CreationTime) {
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

function Get-ArcGISDownloadAPIUrl
{
    param(
        [System.String]
        $FileName,
       
        [System.String]
        $ArcGISDownloadAPIFolderPath,

        [System.Management.Automation.PSCredential]
        $ArcGISOnlineCredential
    )

    $DownloadFileName = Split-Path $FileName -leaf
    $token = Get-PortalToken -Credential $ArcGISOnlineCredential -URL "https://www.arcgis.com" -Client "referer" -Expiration 600 -Referer "referer"
    $HttpFormParameters = @{Referer = 'referer'; folder = $ArcGISDownloadAPIFolderPath; token = $Token.token}
    $DownloadAPIUrl = "https://downloads.arcgis.com/dms/rest/download/secured/$($DownloadFileName)"
    $response = Invoke-ArcGISWebRequest -Url $DownloadAPIUrl -HttpFormParameters $HttpFormParameters -Referer $null -HttpMethod "GET" -verbose
    if($response) {
        if($response.code -eq 200){
            return $response.url
        }else{
            throw "ERROR - $($response.message)"
        }
    }else {
        throw "ERROR - Response from $Url is NULL"
    }
}

Export-ModuleMember -Function *-TargetResource