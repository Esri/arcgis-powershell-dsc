$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

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
   
    $token = ""
	if($PortalHostName -and $PortalPort -and $PortalContext){
		$token = Get-PortalToken -PortalHostName $PortalHostName -SiteName $PortalContext -Credential $PublisherAccount -Referer $Referer -Port $PortalPort
	}else{
		$token = Get-ServerToken -ServerEndPoint $ServerEndPoint -ServerSiteName $ServerContext -Credential $PublisherAccount -Referer $Referer
	}
    
    Write-Verbose "Check for existence of ServiceName:- $ServiceName ServiceType:- $ServiceType Folder:- $Folder"
    $ServiceNameToCompare = if($Folder) { "$Folder/$ServiceName" } else { $ServiceName }
    $CatalogEndpoint = "$($ServerEndPoint)/$ServerContext/rest/services/$($Folder)"   
    $resp = Invoke-ArcGISWebRequest -Url $CatalogEndpoint -HttpFormParameters @{ f='json'; token = $token.token} -Referer $Referer    
    $ServiceExists = ($resp.services | Where-Object { $_.name -eq $ServiceNameToCompare -and $_.type -eq $ServiceType } | Measure-Object).Count -gt 0
    if($ServiceExists) {
        Write-Verbose "Service with name '$ServiceName' of type '$ServiceType' exists in folder '$($Folder)'"
        if($SourceFile.Extension -ne '.sd'){
            Write-Verbose 'Update Service Properties'
            $ServicePropertiesToCheck = Convert-PSObjectToHashtable $(ConvertFrom-Json (Get-Content $PathToSourceFile -Raw))
            $ServicePropertiesFromServer =  Convert-PSObjectToHashtable $(ConvertFrom-Json (ConvertTo-Json (Get-ServiceProperties -ServerHostName $ServerHostName -ServerContext $ServerContext -Token $token.token -Referer $Referer -Port $Port -ServiceName $ServiceNameToCompare -ServiceType $ServiceType -Verbose)))
            if(($ServicePropertiesFromServer | ConvertTo-Json -Compress) -ne ($ServicePropertiesToCheck | ConvertTo-Json -Compress)){
                Write-Verbose "Service properties have changed, updating them."
                $result = $False
            }else{
                Write-Verbose "Service properties are the same, nothing needs to change."
                $result = $true
            }
        }else{
            $result = $true
        }
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
	
	$token = ""
	if($PortalHostName -and $PortalPort -and $PortalContext){
		$token = Get-PortalToken -PortalHostName $PortalHostName -SiteName $PortalContext -Credential $PublisherAccount -Referer $Referer -Port $PortalPort
	}else{
		$token = Get-ServerToken -ServerEndPoint $ServerEndPoint -ServerSiteName $ServerContext -Credential $PublisherAccount -Referer $Referer
	}
    
	Write-Verbose "Check for existence of ServiceName:- $ServiceName ServiceType:- $ServiceType Folder:- $Folder"
    $ServiceNameToCompare = if($Folder) { "$Folder/$ServiceName" } else { $ServiceName }
    $CatalogEndpoint = "$($ServerEndPoint)/$ServerContext/rest/services/$($Folder)"   
    $resp = Invoke-ArcGISWebRequest -Url $CatalogEndpoint -HttpFormParameters @{ f='json'; token = $token.token} -Referer $Referer    
    Write-Verbose "[DEBUG] Services:- $(ConvertTo-Json $resp.services -Compress -Depth 5)"
    $ServiceExists = ($resp.services | Where-Object { $_.name -eq $ServiceNameToCompare -and $_.type -eq $ServiceType } | Measure-Object).Count -gt 0
        
    if($Ensure -ieq 'Present') 
    {        
        if($ServiceExists) 
        {
            Write-Verbose "Service with name '$ServiceName' of type '$ServiceType' already exists in folder '$($Folder)'"   
            if($SourceFile.Extension -ne '.sd') {
                $ServicePropertiesToCheck = Convert-PSObjectToHashtable $(ConvertFrom-Json (Get-Content $PathToSourceFile -Raw))
                $ServicePropertiesFromServer =  Convert-PSObjectToHashtable $(ConvertFrom-Json (ConvertTo-Json (Get-ServiceProperties -ServerHostName $ServerHostName -ServerContext $ServerContext -Token $token.token -Referer $Referer -Port $Port -ServiceName $ServiceNameToCompare -ServiceType $ServiceType -Verbose)))

                if(($ServicePropertiesFromServer | ConvertTo-Json -Compress) -ne ($ServicePropertiesToCheck | ConvertTo-Json -Compress)){
                    Write-Verbose 'Updating Service Properties'
                    Update-ServiceProperties -ServerHostName $ServerHostName -ServerContext $ServerContext -Token $token.token -Referer $Referer -Port $Port -ServiceProperties (Get-Content $PathToSourceFile -Raw) -ServiceName $ServiceNameToCompare -ServiceType $ServiceType -Verbose
                    # Wait until Service update completes.
                    Write-Verbose "Waiting for Url '$ServerUrl/$SiteName/admin' to respond"
                    Wait-ForUrl -Url "$ServerUrl/$SiteName/admin/" -SleepTimeInSeconds 15 -MaxWaitTimeInSeconds 90 
                }
            }         
        }else {    
            if(-not([string]::IsNullOrEmpty($Folder))){ 
				if(-not(Test-ArcGISServerFolder -Folder $Folder -ServerHostName $ServerHostName -ServerContext $ServerContext -Token $token.token -Referer $Referer -Port $Port -Verbose)){
                    Invoke-CreateArcGISServerFolder -Folder $Folder -ServerHostName $ServerHostName -ServerContext $ServerContext -Token $token.token -Referer $Referer -Port $Port -Verbose
                }
            }

            $ServicePath = if($Folder) { "$($Folder)/$($ServiceName)/$ServiceType" } else { "$($ServiceName)/$ServiceType" }
            $SourceFile = Get-Item $PathToSourceFile
            if($SourceFile.Extension -ieq '.sd') {
                Write-Verbose "Publishing service '$ServiceName' of type '$ServiceType' to '$ServicePath'"
                Publish-ArcGISService -ServerHostName $ServerHostName -ServerContext $ServerContext -Token $token.token -Referer $Referer -SDFilePath $PathToSourceFile -ServicePath $ServicePath -Port $Port -Verbose
            }else {
                $CreateServiceUrl = if($Folder) { "$($ServerEndPoint)/$ServerContext/admin/services/$Folder/createService" } else { "$($ServerEndPoint)/$ServerContext/admin/services/createService" }
                $service = (Get-Content $PathToSourceFile -Raw)
                Write-Verbose "Creating service '$ServiceName' of type '$ServiceType' using URL:- '$CreateServiceUrl'"
                $resp = Invoke-ArcGISWebRequest -Url $CreateServiceUrl -HttpFormParameters @{ f='json'; service = $service; token = $token.token } -Referer $Referer -HttpMethod 'POST' -Verbose -TimeOutSec 240
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
                $uploadResponse = ((Invoke-UploadFile -url $itemInfoUploadUrl -filePath $PathToItemInfoFile -fileContentType 'application/text' -fileParameterName 'file' `
                -Referer $Referer -formParams @{ f='json'; token = $token.token; folder = [System.IO.Path]::GetFileNameWithoutExtension($PathToItemInfoFile) } -Verbose)  | ConvertFrom-Json)
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
            Invoke-ArcGISWebRequest -Url $DeleteServiceUrl -HttpFormParameters @{ f='json'; service = $service; token = $token.token } -Referer $Referer -HttpMethod 'POST' -Verbose
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
    [OutputType([System.Boolean])]
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

function Test-ArcGISServerFolder
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
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
        $Port = 6443,
        [System.String]
        [Parameter(Mandatory=$true)]
        $Folder
    )
	$Result = $False
    $Scheme = if($Port -eq 6080 -or $Port -eq 80) { 'http' } else { 'https' }
	$response = Invoke-ArcGISWebRequest -Url ("$($Scheme)://$($ServerHostName):$Port/$($ServerContext)/admin/services/") -HttpFormParameters @{ f = 'json'; token = $Token; folderName = $Folder } -Referer $Referer -HttpMethod 'GET'
	$Result = $response.folders -icontains $Folder
    if($Result){
        Write-Verbose "Folder $($Folder) exists!"
    }else{
        Write-Verbose "Folder $($Folder) doesn't exists!"
    }
	$Result
}

function Invoke-CreateArcGISServerFolder
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
        
        [parameter(Mandatory = $false)]
		[uint32]
        $Port = 6443,
		
        [System.String]
        [Parameter(Mandatory=$true)]
        $Folder
    )
	Write-Verbose "Creating Folder $Folder"
    $Scheme = if($Port -eq 6080 -or $Port -eq 80) { 'http' } else { 'https' }
    Invoke-ArcGISWebRequest -Url ("$($Scheme)://$($ServerHostName):$Port/$ServerContext" + '/admin/services/createFolder') -HttpFormParameters @{ f = 'json'; token = $Token; folderName = $Folder } -Referer $Referer
}

function Publish-ArcGISService
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
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
        $Port = 6443
    )       
    
    $Scheme = if($Port -eq 6080 -or $Port -eq 80) { 'http' } else { 'https' }
    $UploadItemUrl ="$($Scheme)://$($ServerHostName):$($Port)/$($ServerContext)/admin/uploads/upload"

    $items = Get-ArcGISUploads -ServerHostName $ServerHostName -ServerContext $ServerContext -Token $Token -Referer $Referer -Port $Port
    $itemFileName = Split-Path -Path $SDFilePath -Leaf
    $item = $items.items | Where-Object { $_.itemName -ieq $itemFileName } | Select-Object -First 1
    if(-not($item))
    {
        Write-Verbose "Item does not exist - uploading file $SDFilePath"
		$item = ((Invoke-UploadFile -url $UploadItemUrl -filePath $SDFilePath -fileContentType 'application/octet-stream' -fileParameterName 'itemFile' `
                -Referer $Referer -formParams @{ token = $Token;  f = 'json' } -Verbose) | ConvertFrom-Json)
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
		$ServiceConfiguration = $(Get-ServiceConfiguration -ServerHostName $ServerHostName -ServerContext $ServerContext -Token $Token -Referer $Referer -ItemId $item.itemID -Port $Port -Verbose)
		$ServiceConfiguration.folderName = $Folder
		$job = (Submit-ArcGISPublishJob -ServerHostName $ServerHostName -ServerContext $ServerContext -Token $Token -Referer $Referer -ItemId $item.itemID -Port $Port -ServiceConfiguration $ServiceConfiguration -Verbose)
        
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
                $deleteResult = Invoke-DeleteArcGISUploadedItem -ServerHostName $ServerHostName -ServerContext $ServerContext -Token $Token -Referer $Referer -ItemId $item.itemID -Port $Port
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

function Invoke-DeleteArcGISUploadedItem
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

function Get-ServiceConfiguration
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
    Invoke-ArcGISWebRequest -Url "$($Scheme)://$($ServerHostName):$($Port)/$($ServerContext)/admin/uploads/$($ItemId)/serviceconfiguration.json"  `
                            -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer -HttpMethod "GET"

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
        $Port = 6443,
        
        $ServiceConfiguration
    )
	$Scheme = if($Port -eq 6080 -or $Port -eq 80) { 'http' } else { 'https' }
    Invoke-ArcGISWebRequest -Url "$($Scheme)://$($ServerHostName):$($Port)/$($ServerContext)/rest/services/System/PublishingTools/GPServer/Publish%20Service%20Definition/submitJob" `
                            -HttpFormParameters @{ f = 'json'; token = $Token; in_sdp_id = $ItemId; in_config_overwrite = (ConvertTo-Json $ServiceConfiguration -depth 10 -compress) } -Referer $Referer -Verbose
}


function Get-ServiceProperties
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

        [parameter(Mandatory = $false)]
		[uint32]
        $Port = 6443,

        [System.String]
        [Parameter(Mandatory=$false)]
        $ServiceName,

        [System.String]
        [Parameter(Mandatory=$false)]
        $ServiceType
    ) 

    $Scheme = if($Port -eq 6080 -or $Port -eq 80) { 'http' } else { 'https' }
    $GetServicePropertiesUrl = "$($Scheme)://$($ServerHostName):$($Port)/$($ServerContext)/admin/services/$ServiceName.$ServiceType"
    Write-Verbose "Url:- $GetServicePropertiesUrl"

    try {
        $response = Invoke-ArcGISWebRequest -Url $GetServicePropertiesUrl -HttpFormParameters @{ f= 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET' -TimeOutSec 30
        Confirm-ResponseStatus $response -Url $GetServicePropertiesUrl
        $response 
    }
    catch{
        Write-Verbose "[EXCEPTION] ArcGIS_Server_Service Get-SystemServiceProperties Error:- $_"
        $null
    }
}

function Update-ServiceProperties
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

        [parameter(Mandatory = $false)]
		[uint32]
        $Port = 6443,

        [System.String]
        [Parameter(Mandatory=$false)]
        $ServiceName,

        [System.String]
        [Parameter(Mandatory=$false)]
        $ServiceType,

        # service prop json obj
        $ServiceProperties
    ) 

    if(-not($ServiceProperties)) {
        throw "Service Properties parameter is not provided"
    }
    $Scheme = if($Port -eq 6080 -or $Port -eq 80) { 'http' } else { 'https' }
    $UpdateServicePropertiesUrl = "$($Scheme)://$($ServerHostName):$($Port)/$($ServerContext)/admin/services/$ServiceName.$ServiceType/edit"
    $props = @{ f= 'json'; token = $Token; service = $ServiceProperties; runAsync='true' }

    try{
        $response = Invoke-ArcGISWebRequest -Url $UpdateServicePropertiesUrl -HttpFormParameters $props -Referer $Referer -TimeOutSec 300
        Confirm-ResponseStatus $response -Url $UpdateServicePropertiesUrl
        $response
    }catch{
        Write-Verbose "[EXCEPTION] ArcGIS_Server_Service Invoke-UpdateSystemServiceProperties Error:- $_"
        $null
    }
}

Export-ModuleMember -Function *-TargetResource
