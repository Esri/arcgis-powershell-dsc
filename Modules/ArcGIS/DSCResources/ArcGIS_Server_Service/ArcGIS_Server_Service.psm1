function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$ServerHostName,

        [parameter(Mandatory = $true)]
		[System.String]
		$PathToSourceFile
	)
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false
    
	$null
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
        [ValidateNotNullorEmpty()]
		$ServerHostName = 'localhost',

        [parameter(Mandatory = $false)]
		[System.String]
		$ServiceName,

        [parameter(Mandatory = $false)]
		[System.String]
		$ServiceType,

        [parameter(Mandatory = $false)]
		[System.String]
		$Folder,

        [parameter(Mandatory = $false)]
		[uint32]
		$Port = 6443,

        [parameter(Mandatory = $false)]
		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure = 'Present',

        [parameter(Mandatory = $false)]
		[ValidateSet("STARTED","STOPPED")]
		[System.String]
		$State,

        [parameter(Mandatory = $false)]
        [System.String]
		$ServerContext = 'arcgis',

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$PublisherAccount,       

        [parameter(Mandatory = $true)]
		[System.String]
        [ValidateNotNullorEmpty()]
		$PathToSourceFile,

        [parameter(Mandatory = $false)]
		[System.String]
        $PathToItemInfoFile,
        
        [System.String]
        [ValidateNotNullorEmpty()]
		$PortalHostName,

        [parameter(Mandatory = $false)]
		[uint32]
        $PortalPort,
        
        [parameter(Mandatory = $false)]
        [System.String]
		$PortalContext

    )
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    if(-not(Test-Path $PathToSourceFile)){
        Write-Verbose "File $PathToSourceFile not found or inaccessible"
    }
    
    if(-not($ServiceName) -or (-not($ServiceType))){
        # if Service details is not provided, then read from name of source file
        $FileName = (Get-Item $PathToSourceFile).BaseName
        $Splits = $FileName -split '__'
        $ServiceName = $Splits | Select-Object -First 1
        $ServiceType = if($Splits.Length -gt 1) { $Splits[$Splits.Length - 1] } else { 'MapServer' }
    }

    $result = $false
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    $Referer = 'http://localhost'

    $Scheme = if($Port -eq 6080 -or $Port -eq 80) { 'http' } else { 'https' }
    $ServerEndPoint = "$($Scheme)://$($ServerHostname):$Port"
    $Url = "$ServerEndPoint/$ServerContext/admin"
    Wait-ForUrl -Url $Url -MaxWaitTimeInSeconds 180
    $token = Get-ServerToken -ServerEndPoint $ServerEndPoint -ServerSiteName $ServerContext -Credential $PublisherAccount -Referer $Referer
    
    Write-Verbose "Check for existence of ServiceName:- $ServiceName ServiceType:- $ServiceType Folder:- $Folder"
    $ServiceNameToCompare = if($Folder) { "$Folder/$ServiceName" } else { $ServiceName }
    $CatalogEndpoint = "$($ServerEndPoint)/$ServerContext/rest/services/$($Folder)"   
    $resp = Invoke-ArcGISWebRequest -Url $CatalogEndpoint -HttpFormParameters @{ f='json'; token = $token.token} -Referer $Referer    
    $ServiceExists = ($resp.services | Where-Object { $_.name -eq $ServiceNameToCompare -and $_.type -eq $ServiceType } | Measure-Object).Count -gt 0
    if($ServiceExists) {
        Write-Verbose "Service with name '$ServiceName' of type '$ServiceType' exists in folder '$($Folder)'"
        $result = $true
    }else {
        Write-Verbose "Service with name '$ServiceName' of type '$ServiceType' not found in folder '$($Folder)'"
    }

    if($result -and $State){        
        $statusUrl = "$($ServerEndPoint)/$ServerContext/admin/services/$($ServiceNameToCompare).$($ServiceType)/status"
        Write-Verbose "Checking current state of service"
        $resp = Invoke-ArcGISWebRequest -Url $statusUrl -HttpFormParameters @{ f='json'; token = $token.token} -Referer $Referer    
        if($State -ine $resp.realTimeState) {
            Write-Verbose "The realTimeState of the service $($resp.realTimeState) does not match expected value of $($State)"
            $result = $false
        }else {
            Write-Verbose "The realTimeState of the service $($resp.realTimeState) matches expected value of $($State)"
        }
    }

    if($result -and $PathToItemInfoFile) {
        if(-not(Test-Path $PathToItemInfoFile)){
            Write-Verbose "File $PathToItemInfoFile not found or inaccessible"
        }        
        $itemInfoUrl = "$($ServerEndPoint)/$ServerContext/admin/services/$($ServiceNameToCompare).$($ServiceType)/iteminfo"
        Write-Verbose "Checking iteminfo on the service at $itemInfoUrl"
        $resp = Invoke-ArcGISWebRequest -Url $itemInfoUrl -HttpFormParameters @{ f='json'; token = $token.token} -Referer $Referer    
        if($resp.description -and ($resp.description.Length -gt 0)) {
            Write-Verbose "Service already has an item info defined"
        }else {
            Write-Verbose "Service does not have an item info"
            $result = $false            
        }
    }

    if($Ensure -ieq 'Present') {
	       $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
		[System.String]
		$ServerHostName = 'localhost',

        [parameter(Mandatory = $false)]
		[System.String]
		$ServiceName,

        [parameter(Mandatory = $false)]
		[System.String]
		$ServiceType,

        [parameter(Mandatory = $false)]
		[System.String]
		$Folder,

        [parameter(Mandatory = $false)]
		[uint32]
		$Port = 6443,

        [parameter(Mandatory = $false)]
		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure = 'Present',

        [parameter(Mandatory = $false)]
		[ValidateSet("STARTED","STOPPED")]
		[System.String]
		$State,

        [parameter(Mandatory = $false)]
        [System.String]
		$ServerContext = 'arcgis',

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$PublisherAccount,       

        [parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
		[System.String]
		$PathToSourceFile,

        [parameter(Mandatory = $false)]
		[System.String]
		$PathToItemInfoFile,
        
        [parameter(Mandatory = $false)]
        [System.String]
        $PortalHostName,

        [parameter(Mandatory = $false)]
		[uint32]
        $PortalPort,
        
        [parameter(Mandatory = $false)]
        [System.String]
		$PortalContext
	)

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    if(-not(Test-Path $PathToSourceFile)){
        Write-Verbose "File $PathToSourceFile not found or inaccessible"
    }
    
    if(-not($ServiceName) -or (-not($ServiceType))){
        # if Service details is not provided, then read from name of source file
        $FileName = (Get-Item $PathToSourceFile).BaseName
        $Splits = $FileName -split '__'
        $ServiceName = $Splits | Select-Object -First 1
        $ServiceType = if($Splits.Length -gt 1) { $Splits[$Splits.Length - 1] } else { 'MapServer' }
    }
        
    $Referer = 'http://localhost'

    $Scheme = if($Port -eq 6080 -or $Port -eq 80) { 'http' } else { 'https' }
    $ServerEndPoint = "$($Scheme)://$($ServerHostname):$Port"
    Write-Verbose $ServerEndPoint
    $token = Get-ServerToken -ServerEndPoint $ServerEndPoint -ServerSiteName $ServerContext -Credential $PublisherAccount -Referer $Referer
        
    Write-Verbose "Check for existence of ServiceName:- $ServiceName ServiceType:- $ServiceType Folder:- $Folder"
    $ServiceNameToCompare = if($Folder) { "$Folder/$ServiceName" } else { $ServiceName }
    $CatalogEndpoint = "$($ServerEndPoint)/$ServerContext/rest/services/$($Folder)"   
    $resp = Invoke-ArcGISWebRequest -Url $CatalogEndpoint -HttpFormParameters @{ f='json'; token = $token.token} -Referer $Referer    
    Write-Verbose "[DEBUG] Services:- $(ConvertTo-Json $resp.services -Compress -Depth 5)"
    $ServiceExists = ($resp.services | Where-Object { $_.name -eq $ServiceNameToCompare -and $_.type -eq $ServiceType } | Measure-Object).Count -gt 0
        
    if($Ensure -ieq 'Present') {        
             
        if($ServiceExists) 
        {
            Write-Verbose "Service with name '$ServiceName' of type '$ServiceType' already exists in folder '$($Folder)'"            
        }else {            
            $ServicePath = if($Folder) { "$($Folder)/$($ServiceName)/$ServiceType" } else { "$($ServiceName)/$ServiceType" }
            $SourceFile = Get-Item $PathToSourceFile
            if($SourceFile.Extension -ieq '.sd') {
                Write-Verbose "Publishing service '$ServiceName' of type '$ServiceType' to '$ServicePath'"
                $stoken = ""
                if($PortalHostName -and $PortalPort -and $PortalContext){
                    $stoken = Get-PortalToken -PortalHostName $PortalHostName -SiteName $PortalContext -Credential $PublisherAccount -Referer $Referer -Port $PortalPort
                }
                Publish-ArcGISService -ServerHostName $ServerHostName -ServerContext $ServerContext -Token $token.token -Referer $Referer -SDFilePath $PathToSourceFile -ServicePath $ServicePath -Port $Port -PortalToken $stoken.token
            }else {
                $CreateServiceUrl = if($Folder) { "$($ServerEndPoint)/$ServerContext/admin/services/$Folder/createService" } else { "$($ServerEndPoint)/$ServerContext/admin/services/createService" }
                $service = (Get-Content $PathToSourceFile -Raw)
                Write-Verbose "Creating service '$ServiceName' of type '$ServiceType' using URL:- '$CreateServiceUrl'"
                $resp = Invoke-ArcGISWebRequest -Url $CreateServiceUrl -HttpFormParameters @{ f='json'; service = $service; token = $token.token } -Referer $Referer -HttpMethod 'POST' -LogResponse -TimeOutSec 240
                Write-Verbose "Response from create service:- $(ConvertTo-Json $resp -Compress -Depth 5)"
            }
        } 

        if($PathToItemInfoFile) {
            if(-not(Test-Path $PathToItemInfoFile)){
                Write-Verbose "File $PathToItemInfoFile not found or inaccessible"
            }
            $itemInfoUrl = "$($ServerEndPoint)/$ServerContext/admin/services/$($ServiceNameToCompare).$($ServiceType)/iteminfo"
            Write-Verbose "Checking iteminfo on the service at $itemInfoUrl"
            $resp = Invoke-ArcGISWebRequest -Url $itemInfoUrl -HttpFormParameters @{ f='json'; token = $token.token} -Referer $Referer    
            if($resp.description -and ($resp.description.Length -gt 0)) {
                Write-Verbose "Service already has an item info defined"
            }else {                
                $itemInfoUploadUrl = "$itemInfoUrl/upload"
                Write-Verbose "Service does not have an item info. Uploading from $PathToItemInfoFile using $itemInfoUploadUrl"
                $uploadResponse = UploadFile -url $itemInfoUploadUrl -requestUri $itemInfoUploadUrl -filePath $PathToItemInfoFile -fileContentType 'application/text' -formParams @{ f='json'; token = $token.token; folder = [System.IO.Path]::GetFileNameWithoutExtension($PathToItemInfoFile) } -Referer $Referer -fileParameterName 'file'                           
                Write-Verbose "Upload response:-  $(ConvertTo-Json $uploadResponse -Depth 3 -Compress)"
            }
        }
        
        $statusUrl = "$($ServerEndPoint)/$ServerContext/admin/services/$($ServiceNameToCompare).$($ServiceType)/status"
        Write-Verbose "Retrieve service status from $statusUrl"
        $resp = Invoke-ArcGISWebRequest -Url $statusUrl -HttpFormParameters @{ f='json'; token = $token.token} -Referer $Referer   
        if($resp) {
            Write-Verbose "Status Response:- $(ConvertTo-Json $resp -Depth 5 -Compress)" 
        }else {
            Write-Verbose "[WARNING] Status Response returned NULL"
        }
        if($State -ine $resp.realTimeState) {
            Write-Verbose "The realTimeState of the service '$($resp.realTimeState)' does not match expected value of $($State)"
            if($State -ieq 'STOPPED') {
                $stopUrl = "$($ServerEndPoint)/$ServerContext/admin/services/$($ServiceNameToCompare).$($ServiceType)/stop"
                Write-Verbose "Stopping service with operation $stopUrl"
                Invoke-ArcGISWebRequest -Url $stopUrl -HttpFormParameters @{ f='json'; token = $token.token} -Referer $Referer -TimeOutSec 120   
            }
            elseif($State -ieq 'STARTED') {
                $startUrl = "$($ServerEndPoint)/$ServerContext/admin/services/$($ServiceNameToCompare).$($ServiceType)/start"
                Write-Verbose "Starting service with operation $startUrl" 
                try {
                    Invoke-ArcGISWebRequest -Url $startUrl -HttpFormParameters @{ f='json'; token = $token.token} -Referer $Referer -TimeOutSec 600 
                }catch{
                    Write-Verbose "[{WARNING] Error starting service. Error:- $_"
                }
            }
        }      
    }
    elseif($Ensure -ieq 'Absent') {
        if(-not($ServiceExists)) 
        {
            Write-Verbose "Service with name '$ServiceName' of type '$ServiceType' does not exist in folder '$($Folder)'"            
        }else {
            $DeleteServiceUrl = if($Folder) { "$($ServerEndPoint)/$ServerContext/admin/services/$Folder/$($ServiceName).$($ServiceType)/delete" } else { "$($ServerEndPoint)/$ServerContext/admin/services/$($ServiceName).$($ServiceType)/delete" }
            Write-Verbose "Deleting service '$ServiceName' of type '$ServiceType' in folder '$Folder' using URL:- '$DeleteServiceUrl'"
            Invoke-ArcGISWebRequest -Url $DeleteServiceUrl -HttpFormParameters @{ f='json'; service = $service; token = $token.token } -Referer $Referer -HttpMethod 'POST' -LogResponse
        }
    }
}

function Get-ArcGISPublishJobStatus
{
    [CmdletBinding()]
    param(
    [System.String]
        [Parameter(Mandatory=$true)]
        $ServerHostName,

        [System.String]
        [Parameter(Mandatory=$false)]
        $ServerContext = 'arcgis',

        [System.String]
        [Parameter(Mandatory=$true)]
        $Token,

        [System.String]
        [Parameter(Mandatory=$false)]
        $Referer = 'http://localhost',

        [System.String]
        [Parameter(Mandatory=$true)]
        $JobId,
        
        [parameter(Mandatory = $false)]
		[uint32]
		$Port = 6443
    )
    $Scheme = if($Port -eq 6080 -or $Port -eq 80) { 'http' } else { 'https' }
   Invoke-ArcGISWebRequest -Url ("$($Scheme)://$($ServerHostName):$Port/$ServerContext" + '/rest/services/System/PublishingTools/GPServer/Publish%20Service%20Definition/jobs/' + $JobId) -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer
}

function Wait-ArcGISServicePublishJob
{
    [CmdletBinding()]
    param(    
        [System.String]
        [Parameter(Mandatory=$true)]
        $ServerHostName,

        [System.String]
        [Parameter(Mandatory=$false)]
        $ServerContext = 'arcgis',

        [System.String]
        [Parameter(Mandatory=$true)]
        $Token,

        [System.String]
        [Parameter(Mandatory=$false)]
        $Referer = 'http://localhost',

        [System.String]
        [Parameter(Mandatory=$false)]
        $JobId,

        [System.Int32]
        [Parameter(Mandatory=$false)]
        $MaxWaitTimeInSeconds = 300,

        [System.Int32]
        [Parameter(Mandatory=$false)]
        $SleepTimeInSeconds = 5,
        
        [parameter(Mandatory = $false)]
		[uint32]
		$Port = 6443
    )    

    $TimeElapsed = 0
    $Done = $false
    while(-not($Done) -and ($TimeElapsed -lt $MaxWaitTimeInSeconds)) {
        $JobStatus = Get-ArcGISPublishJobStatus -ServerHostName $ServerHostName -ServerContext $ServerContext -Token $Token -Referer $Referer -JobId $JobId -Port $Port
        if($JobStatus.status -ieq 'error') {
            throw "Unable to get publish job status for Service $ServicePath "  + ($JobStatus.messages.description -join " ")
        }
        if(($JobStatus.jobStatus -eq 'esriJobSucceeded') -or ($JobStatus.jobStatus -eq 'esriJobFailed')) {                    
            $Done = $true
            if($JobStatus.jobStatus -eq 'esriJobSucceeded'){
                Write-Verbose "Service '$ServicePath 'Published successfully"
            }else{
                throw "Service failed to publish. Last Job Status $($JobStatus.messages.description -join ' ')"
            }
        }
        else {
            Start-Sleep -Seconds $SleepTimeInSeconds
            $TimeElapsed += $SleepTimeInSeconds
        }
    }
    $Done
}

function Publish-ArcGISService
{
    [CmdletBinding()]
    param(    
        [System.String]
        [Parameter(Mandatory=$true)]
        $ServerHostName,

        [System.String]
        [Parameter(Mandatory=$false)]
        $ServerContext = 'arcgis',

        [System.String]
        [Parameter(Mandatory=$true)]
        $Token,

        [System.String]
        [Parameter(Mandatory=$false)]
        $Referer = 'http://localhost',

        [System.String]
        [Parameter(Mandatory=$true)]
        $SDFilePath,

        [System.String]
        [Parameter(Mandatory=$false)]
        $ServicePath,

        [System.Int32]
        [Parameter(Mandatory=$false)]
        $MaxWaitTimeInSeconds = 300,

        [System.Int32]
        [Parameter(Mandatory=$false)]
        $SleepTimeInSeconds = 5,

        [switch]
        $UploadOnly,
        
        [parameter(Mandatory = $false)]
		[uint32]
        $Port = 6443,
        
        [System.String]
        [Parameter(Mandatory=$true)]
        $PortalToken
    )       
    
    $Scheme = if($Port -eq 6080 -or $Port -eq 80) { 'http' } else { 'https' }
    $UploadItemUrl ="$($Scheme)://$($ServerHostName):$Port/$ServerContext" + '/admin/uploads/upload'

    $items = Get-ArcGISUploads -ServerHostName $ServerHostName -ServerContext $ServerContext -Token $Token -Referer $Referer -Port $Port
    $itemFileName = Split-Path -Path $SDFilePath -Leaf
    $item = $items.items | Where-Object { $_.itemName -ieq $itemFileName } | Select-Object -First 1
    if(-not($item))
    {
        Write-Verbose "Item does not exist - uploading file $SDFilePath"
        $item = UploadFile -requestUri $UploadItemUrl -url $UploadItemUrl -filePath $SDFilePath -fileContentType 'application/octet-stream' -formParams @{ token = $Token;  f = 'json' } -Referer $Referer -fileParameterName 'itemFile'
        if($item.status -ieq 'error'){
            throw "Failed to upload item before publishing ServicePath. " + ($item.messages -join " ")
        }else{
            $item = $item.item
            Write-Verbose "Uploaded item successfully $($item.itemID)"
        }
    }
    else {
        Write-Verbose "Item already exists with ID $($item.itemID)"
    }

    if(-not($UploadOnly)) 
    {
        if($PortalToken){
            $job = Submit-ArcGISPublishJob -ServerHostName $ServerHostName -ServerContext $ServerContext -Token $PortalToken -Referer $Referer -ItemId $item.itemID -Port $Port    
        }else{
            $job = Submit-ArcGISPublishJob -ServerHostName $ServerHostName -ServerContext $ServerContext -Token $Token -Referer $Referer -ItemId $item.itemID -Port $Port
        }
        Write-Verbose "[DEBUG] Job:- $(ConvertTo-Json $job -Compress -Depth 5)"
        if($job.error) {
            $ErrorFlag = $true
            throw ("Failed to submit publish job for Service $ServicePath " + ("$($job.error.code) - " -join $job.error.message ))
        }
        if($job.status -ieq 'error') {
            $ErrorFlag = $true
            throw "Failed to submit publish job for Service $ServicePath " + ($job.messages -join " ")
        }
        if($MaxWaitTimeInSeconds -gt 0) {
            $Done = $false
            try {
                if(-not($ErrorFlag)){
                    $Done = Wait-ArcGISServicePublishJob -ServerHostName $ServerHostName -ServerContext $ServerContext -Token $Token -Referer $Referer -JobId $job.jobId -MaxWaitTimeInSeconds $MaxWaitTimeInSeconds -SleepTimeInSeconds $SleepTimeInSeconds -Port $Port
                }
            }
            finally {
                $deleteResult = Delete-ArcGISUploadedItem -ServerHostName $ServerHostName -ServerContext $ServerContext -Token $Token -Referer $Referer -ItemId $item.itemID -Port $Port
                #if($deleteResult.status -ieq 'error') {
                #    Write-Verbose "Deleting the uploaded item $($item.itemID) did not succeeed. Error:- $($deleteResult.messages -join ' ')"
                #}
            }
            if(-not($Done)) {
                throw "Service publishing for $ServicePath failed to complete in expected time"
            }
        }

        @{ jobId = $job.jobId; itemId = $item.itemID; servicePath = $ServicePath }
    }
}

function Delete-ArcGISUploadedItem
{
    [CmdletBinding()]
    param(
    [System.String]
        [Parameter(Mandatory=$true)]
        $ServerHostName,

        [System.String]
        [Parameter(Mandatory=$false)]
        $ServerContext = 'arcgis',

        [System.String]
        [Parameter(Mandatory=$true)]
        $Token,

        [System.String]
        [Parameter(Mandatory=$false)]
        $Referer = 'http://localhost',

        [System.String]
        [Parameter(Mandatory=$true)]
        $ItemId,
        
        [parameter(Mandatory = $false)]
		[uint32]
		$Port = 6443
    )

   $Scheme = if($Port -eq 6080 -or $Port -eq 80) { 'http' } else { 'https' }
   Invoke-ArcGISWebRequest -Url ("$($Scheme)://$($ServerHostName):$Port/$ServerContext" + '/admin/uploads/' + $ItemId + '/delete') -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer   
}

function Get-ArcGISUploads
{
    param(
    [System.String]
        [Parameter(Mandatory=$true)]
        $ServerHostName,

        [System.String]
        [Parameter(Mandatory=$false)]
        $ServerContext = 'arcgis',

        [System.String]
        [Parameter(Mandatory=$true)]
        $Token,

        [System.String]
        [Parameter(Mandatory=$false)]
        $Referer = 'http://localhost',
        
        [parameter(Mandatory = $false)]
		[uint32]
		$Port = 6443
    )
    $Scheme = if($Port -eq 6080 -or $Port -eq 80) { 'http' } else { 'https' }
    Invoke-ArcGISWebRequest -Url ("$($Scheme)://$($ServerHostName):$Port/$ServerContext" + '/admin/uploads') -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer
}

function Submit-ArcGISPublishJob
{
    [CmdletBinding()]
    param(
    [System.String]
        [Parameter(Mandatory=$true)]
        $ServerHostName,

        [System.String]
        [Parameter(Mandatory=$false)]
        $ServerContext = 'arcgis',

        [System.String]
        [Parameter(Mandatory=$true)]
        $Token,

        [System.String]
        [Parameter(Mandatory=$false)]
        $Referer = 'http://localhost',

        [System.String]
        [Parameter(Mandatory=$true)]
        $ItemId,
        
        [parameter(Mandatory = $false)]
		[uint32]
		$Port = 6443
    )
    $Scheme = if($Port -eq 6080 -or $Port -eq 80) { 'http' } else { 'https' }
    Invoke-ArcGISWebRequest -Url ("$($Scheme)://$($ServerHostName):$Port/$ServerContext" + '/rest/services/System/PublishingTools/GPServer/Publish%20Service%20Definition/submitJob') `
                            -HttpFormParameters @{ f = 'json'; token = $Token; in_sdp_id = $ItemId } -Referer $Referer
}

function UploadFile([Uri]$url, [string]$requestUri, [string]$filePath, [string]$fileParameterName, [string]$fileContentType, $formParams, $Referer) 
{    
    $endPoint = $url.AbsoluteUri 
    
    [System.Net.WebRequest]$webRequest = [System.Net.WebRequest]::Create($endPoint)
    $webRequest.ServicePoint.Expect100Continue = $false
    $webRequest.Method = "POST"    
    if($Referer) {
        $webRequest.Referer = $Referer
    }

    $boundary = [System.Guid]::NewGuid().ToString()
    $header = "--{0}" -f $boundary
    $footer = "--{0}--" -f $boundary
    $webRequest.ContentType = "multipart/form-data; boundary={0}" -f $boundary

    [System.IO.Stream]$reqStream = $webRequest.GetRequestStream()    

    $enc = [System.Text.Encoding]::GetEncoding("UTF-8")
    $headerPlusNewLine = $header + [System.Environment]::NewLine
    [byte[]]$headerBytes = $enc.GetBytes($headerPlusNewLine)
    [void]$reqStream.Write($headerBytes,0, $headerBytes.Length)

    [System.IO.FileInfo]$fileInfo = New-Object "System.IO.FileInfo" -ArgumentList $filePath   

    #### File Header ####
    $fileHeader = "Content-Disposition: form-data; name=""{0}""; filename=""{1}""" -f $fileParameterName, $fileInfo.Name
    $fileHeader = $fileHeader + [System.Environment]::NewLine
    [byte[]]$fileHeaderBytes = $enc.GetBytes($fileHeader)
    [void]$reqStream.Write($fileHeaderBytes,0, $fileHeaderBytes.Length)
    
    #### File Content Type ####
    [string]$fileContentTypeStr = "Content-Type: {0}" -f $fileContentType;
    $fileContentTypeStr = $fileContentTypeStr + [System.Environment]::NewLine + [System.Environment]::NewLine
    [byte[]]$fileContentTypeBytes = $enc.GetBytes($fileContentTypeStr)
    [void]$reqStream.Write($fileContentTypeBytes,0, $fileContentTypeBytes.Length)    
    
    #### File #####
    [System.IO.FileStream]$fileStream = New-Object 'System.IO.FileStream' -ArgumentList @($filePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
    $fileStream.CopyTo($reqStream)
    $fileStream.Flush()
    $fileStream.Close()

    #### Use StreamWrite to write remaining form parameters ####
    [System.IO.StreamWriter]$streamWriter = New-Object 'System.IO.StreamWriter' -ArgumentList $reqStream
        
    [void]$streamWriter.WriteLine("")
    
    foreach($formParam in $formParams.GetEnumerator()) {
        [void]$streamWriter.WriteLine($header)
        [void]$streamWriter.WriteLine(("Content-Disposition: form-data; name=""{0}""" -f $formParam.Name))
        [void]$streamWriter.WriteLine("")
        [void]$streamWriter.WriteLine($formParam.Value)
    }     
    [void]$streamWriter.WriteLine($footer)
    $streamWriter.Flush()  
     
    $resp = $webRequest.GetResponse()
    $rs = $resp.GetResponseStream()
    [System.IO.StreamReader]$sr = New-Object System.IO.StreamReader -argumentList $rs
    $res = $sr.ReadToEnd()
    $response = $res | ConvertFrom-Json
    $response
}

Export-ModuleMember -Function *-TargetResource