$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

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
        [ValidateSet("AzureFiles","AzureBlobsManagedIdentity","ArcGISDownloadsAPI","Default")]
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
		$Source,

		[System.String]
        $Destination,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("AzureFiles","AzureBlobsManagedIdentity","ArcGISDownloadsAPI","Default")]
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
                Invoke-DownloadFile -RemoteFileUrl $DownloadUrl -DestinationFilePath $Destination `
                                    -IsUsingAzureBlobManagedIndentity ($FileSourceType -ieq "AzureBlobsManagedIdentity") -Verbose
            }else{
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
        [ValidateSet("AzureFiles","AzureBlobsManagedIdentity","ArcGISDownloadsAPI","Default")]
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
	[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	$result = $false
	if($Destination -and (Test-Path $Destination))
    {
        $result = $true
    }
	if($Ensure -ieq 'Present') {
        if($result) {
			if($FileSourceType -ieq "ArcGISDownloadsAPI" -or $Source.StartsWith('http', [System.StringComparison]::InvariantCultureIgnoreCase)){
                Write-Verbose 'File Exists locally. Check if the remote URL has Changed using Last-Modified Header'
                $HasRemoteFileChanged = $true
                $response = $null
                try { 
                    $DownloadUrl = $Source
                    if($FileSourceType -ieq "ArcGISDownloadsAPI"){
                        $DownloadUrl = (Get-ArcGISDownloadAPIUrl -FileName $Source -ArcGISDownloadAPIFolderPath $ArcGISDownloadAPIFolderPath `
                                            -ArcGISOnlineCredential $Credential -Verbose)
                    }

                    $Request = [System.Net.HttpWebRequest]::CreateHttp($DownloadUrl)
                    $Request.Method = 'HEAD'
                    if($FileSourceType -ieq "AzureBlobsManagedIdentity"){
                        $ManagedIdentityAccessToken = Get-ManagedIdentityAccessToken -Verbose
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


function Get-ManagedIdentityAccessToken
{
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add('Metadata', "true")
    $response = $wc.DownloadString('http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fstorage.azure.com%2F')
    $wc.Dispose()
    return ($response | ConvertFrom-Json).access_token
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
        $response = $wc.DownloadFile($RemoteFileUrl, $DestinationFilePath)
        $wc.Dispose()
        $response
    }
    catch {
        throw "Error downloading remote file. Error - $_"
    }
}
function Get-AGOToken
{
    param(
        [System.Management.Automation.PSCredential]
        $ArcGISOnlineCredential
    )

    try {
        $AGOToken = Invoke-ArcGISWebRequest -Url "https://www.arcgis.com/sharing/rest/generateToken" -HttpFormParameters @{ username = $ArcGISOnlineCredential.UserName; password = $ArcGISOnlineCredential.GetNetworkCredential().Password; client = 'referer'; referer = 'referer'; expiration = 600; f = 'json' } -Referer $Referer -TimeOutSec 45
        if($AGOToken.error){
            Write-Verbose "Error Response - $($token.error)"
            throw [string]::Format("ERROR: Unable to get Token - {0}" , $token.error.message)
        }
        return $AGOToken
    } catch {
        throw "[ERROR]:- AGO at $url did not return a token - $_"
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
    $token = Get-AGOToken -ArcGISOnlineCredential $ArcGISOnlineCredential -Verbose
    $HttpFormParameters = @{Referer = 'referer'; folder = $ArcGISDownloadAPIFolderPath; token = $Token.token}
    $HttpBody = ConvertTo-HttpBody $HttpFormParameters
    $UrlWithQueryString = "https://downloads.arcgis.com/dms/rest/download/secured/$($DownloadFileName)"
    if($UrlWithQueryString.IndexOf('?') -lt 0) {
        $UrlWithQueryString += '?'
    }else {
        $UrlWithQueryString += '&'
    }
    $UrlWithQueryString += $HttpBody
    $wc = New-Object System.Net.WebClient
    $res = $wc.DownloadString($UrlWithQueryString)
    $wc.Dispose()
    if($res) {
        $response = $res | ConvertFrom-Json
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