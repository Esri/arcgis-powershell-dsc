
function Download-File($url, $targetFile)
{
   try {
        Start-BitsTransfer -Source $url -Destination $targetFile
   }
   catch {
       # Exception could happen if the bits service is not running 
       $uri = New-Object "System.Uri" "$url"
       $request = [System.Net.HttpWebRequest]::Create($uri)
       $request.set_Timeout(15000) #15 second timeout
       $response = $request.GetResponse()
       if(-not ($responseContentLength -lt 1024))
       {
          $totalLength = [System.Math]::Floor($response.get_ContentLength()/1024)
       }
       else
       {
          $totalLength = [System.Math]::Floor(1024/1024)
       }

       $responseStream = $response.GetResponseStream()
       $targetStream = New-Object -TypeName System.IO.FileStream -ArgumentList $targetFile, Create
       $buffer = new-object byte[] 10KB
       $count = $responseStream.Read($buffer,0,$buffer.length)
       $downloadedBytes = $count
       while ($count -gt 0)
       {
           $targetStream.Write($buffer, 0, $count)
           $count = $responseStream.Read($buffer,0,$buffer.length)
           $downloadedBytes = $downloadedBytes + $count
       }

       #Write-Progress -activity "Finished downloading file '$($url.split('/') | Select -Last 1)'"

       $targetStream.Flush()
       $targetStream.Close()
       $targetStream.Dispose()
       $responseStream.Dispose()
   }
}

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Url
	)
	
	$returnValue = @{
		Url = $Url
	}

	$returnValue	
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

		[System.Boolean]
		$Force,

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
          if($url.StartsWith('http', [System.StringComparison]::InvariantCultureIgnoreCase)) {
              Write-Verbose "Downloading file $url to $DestinationPath"
              Download-File -url $url -targetFile $DestinationPath
          }else {
              Write-Verbose "Copying file $url to $DestinationPath"
              Copy-Item -Path $url -Destination $DestinationPath -Force
          }
    }
    elseif($Ensure -ieq 'Absent') {        
        if($DestinationPath  -and  (Test-Path $DestinationPath))
        {
            Remove-Item -Path $DestinationPath -Force:$Force
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

		[System.Boolean]
		$Force,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)

	
	$result = $false
	if($DestinationPath  -and  (Test-Path $DestinationPath))
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
                        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -UseDefaultCredentials -TimeoutSec 15 -Method Head -ErrorAction Ignore 
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

                    if((Get-Item -Path $Url).LastWriteTime -gt (Get-Item -Path $DestinationPath).CreationTime) {
                        # File has changed - needs to be copied again
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


Export-ModuleMember -Function *-TargetResource

