function ConvertTo-HttpBody($props)
{
    [string]$str = ''
    foreach($prop in $props.Keys){                
        $key = [System.Web.HttpUtility]::UrlEncode($prop)
        $value = [System.Web.HttpUtility]::UrlEncode($props[$prop])
        $str += "$key=$value&"
    }
    if($str.Length -gt 0) {
        $str = $str.Substring(0, $str.Length - 1)
    }
    $str
}

function Confirm-ResponseStatus($Response, $Url)
{
  $parentFunc = (Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name

  if (!$Response) { 
    throw [string]::Format("ERROR: {0} response is NULL.URL:- {1}", $parentFunc, $Url)
  }
  if ($Response.status -and ($Response.status -ieq "error")) { 
    throw [string]::Format("ERROR: {0} failed. {1}" , $parentFunc,($Response.messages -join " "))
  }
  if ($Response.error) { 
    throw [string]::Format("ERROR: {0} failed. {1}" , $parentFunc,$Response.error.messages)
  }
}

function Wait-ForUrl
{
    [CmdletBinding()]
    param
    (
		[Parameter(Position = 0, Mandatory=$true)]
        [System.String]
		$Url, 

        [System.Int32]
		$MaxWaitTimeInSeconds = 150, 

        [System.Int32]
		$SleepTimeInSeconds = 5,

        [System.Boolean]
		$ThrowErrors,

        [System.String]
		$HttpMethod = 'GET',

        [System.Int32]
	    $MaximumRedirection=5,

		[System.Int32]
	    $RequestTimeoutInSeconds=15,
        
        [System.Boolean]
        $IsWebAdaptor
    )

    [bool]$Done = $false
    $WaitForError = $null
    Write-Verbose "Waiting for Url $Url"

    # for server and portal generate token
    if($Url -ilike "*/generateToken"){
        $ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($Url)
        $ServicePoint.CloseConnectionGroup("")
    }

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    while((-not($Done)) -and ($stopwatch.Elapsed.TotalSeconds -lt $MaxWaitTimeInSeconds)) {
	    try {
			if($HttpMethod -ieq 'GET') {
				[System.Net.HttpWebRequest]$webRequest = [System.Net.WebRequest]::Create($Url)
				$webRequest.Timeout  = ($RequestTimeoutInSeconds * 1000)
                $webRequest.AllowAutoRedirect = $MaximumRedirection -gt -1
                $webRequest.MaximumAutomaticRedirections = [System.Math]::Max(1, $MaximumRedirection)
                if($IsWebAdaptor){
                    $webRequest.Headers.Add('accept-language','en-US') 
                }
                $resp = $null
                try {
                    $resp = $webRequest.GetResponse()
                    $Done = $true
                }catch [System.Net.WebException] {
                    # Handle Protocol Errors (404, 500, etc.)
                    $resp = $_.Exception.Response
                    if ($null -ne $resp) {
                        $statusCode = [int]$resp.StatusCode
                        Write-Warning "Server returned error: $statusCode"
                    }
                }
                finally {
                    # This ensures the response is disposed of, freeing up the network connection
                    if ($null -ne $resp) {
                        $resp.Dispose()
                    }
                }
			}
			else {
				$resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -UseDefaultCredentials -ErrorAction Ignore -TimeoutSec $RequestTimeoutInSeconds -Method $HttpMethod -DisableKeepAlive -MaximumRedirection $MaximumRedirection
				if($resp) {
					if(($resp.StatusCode -eq 200) -and $resp.Content) { 
						$Done = $true
						Write-Verbose "Url is ready : $Url"
					}else{
                        $WaitForError = "[Warning]:- Response:- $($resp.Content)"
						Write-Verbose $WaitForError
					}
				}else {
                    $WaitForError = "[Warning]:- Response from $Url was NULL"
					Write-Verbose $WaitForError
				}
			}
        }
        catch {
            $WaitForError = "[Warning]:- $($_)"
            Write-Verbose $WaitForError
        }
        if(-not($Done)) {
            Start-Sleep -Seconds $SleepTimeInSeconds
        }
    }
    $stopwatch.Stop()
    if($ThrowErrors -and -not($Done)){
        throw "[ERROR] Wait-ForUrl for $Url failed after waiting for $MaxWaitTimeInSeconds seconds -  $WaitForError"
    }
}

function Invoke-UploadFile
{   
    [CmdletBinding()]
    param
    (
		[System.String]
        $url, 
        
        [System.String]
        $filePath, 

        [System.String]
        $fileContentType, 
        
        $formParams,

        $httpHeaders,

        [System.String]
        $Referer,

        [System.String]
        $fileParameterName = 'file',

        [System.String]
        $fileName
    )


    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} # Allow self-signed certificates
    [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    [System.Net.WebRequest]$webRequest = [System.Net.WebRequest]::Create($url)
    $webRequest.ServicePoint.Expect100Continue = $false
    $webRequest.Method = "POST"
    $webRequest.Referer = $Referer
    $webRequest.Timeout = 86400000;
    
    if(-not($fileName) -or $fileName.Length -lt 1){
        $fileName = (Get-Item -Path $filePath).Name
    }

    if($httpHeaders){
        foreach($httpHeader in $httpHeaders.GetEnumerator())
        {
            if('Referer' -ine $httpHeader.Name) {
                $webRequest.Headers.Add($httpHeader.Name, $httpHeader.Value)
            }
        }
    }

    $boundary = [System.Guid]::NewGuid().ToString()
    $header = "--{0}" -f $boundary
    $footer = "--{0}--" -f $boundary
    $webRequest.ContentType = "multipart/form-data; boundary={0}" -f $boundary

    $enc = [System.Text.Encoding]::GetEncoding("UTF-8")
    $headerPlusNewLine = $header + [System.Environment]::NewLine
    [byte[]]$headerBytes = $enc.GetBytes($headerPlusNewLine)

    [System.IO.Stream]$reqStream = $null
    [System.IO.StreamWriter]$streamWriter = $null
    try {
        $reqStream = $webRequest.GetRequestStream()

        #### Use StreamWriter to write form parameters ####
        $streamWriter = New-Object 'System.IO.StreamWriter' -ArgumentList $reqStream
        foreach($formParam in $formParams.GetEnumerator()) {
            [void]$streamWriter.WriteLine($header)
            [void]$streamWriter.WriteLine(("Content-Disposition: form-data; name=""{0}""" -f $formParam.Name))
            [void]$streamWriter.WriteLine("")
            [void]$streamWriter.WriteLine($formParam.Value)
        }
        $streamWriter.Flush()

        [void]$reqStream.Write($headerBytes,0, $headerBytes.Length)

        #### File Header ####
        $fileHeader = "Content-Disposition: form-data; name=""{0}""; filename=""{1}""" -f $fileParameterName, $fileName
        $fileHeader = $fileHeader + [System.Environment]::NewLine
        [byte[]]$fileHeaderBytes = $enc.GetBytes($fileHeader)
        [void]$reqStream.Write($fileHeaderBytes,0, $fileHeaderBytes.Length)

        #### File Content Type ####
        [string]$fileContentTypeStr = "Content-Type: {0}" -f $fileContentType
        $fileContentTypeStr = $fileContentTypeStr + [System.Environment]::NewLine + [System.Environment]::NewLine
        [byte[]]$fileContentTypeBytes = $enc.GetBytes($fileContentTypeStr)
        [void]$reqStream.Write($fileContentTypeBytes,0, $fileContentTypeBytes.Length)

        #### File #####
        [System.IO.FileStream]$fileStream = $null
        try {
            $fileStream = New-Object 'System.IO.FileStream' -ArgumentList @($filePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
            $fileStream.CopyTo($reqStream)
        }
        finally {
            if($null -ne $fileStream) {
                $fileStream.Dispose()
            }
        }

        [void]$streamWriter.WriteLine("")
        [void]$streamWriter.WriteLine($footer)
        $streamWriter.Flush()
    }
    finally {
        if($null -ne $streamWriter) {
            $streamWriter.Dispose()
        }
        elseif($null -ne $reqStream) {
            $reqStream.Dispose()
        }
    }
    
    $resp = $null
    $rs = $null
    $sr = $null
	try {
		$resp =  $webRequest.GetResponse()    
    }catch {
        Write-Verbose "[WARNING] $url returned an error $_"
	}
    try {
        if($resp) {
            $rs = $resp.GetResponseStream()
            $sr = New-Object System.IO.StreamReader -ArgumentList $rs
            $sr.ReadToEnd()
        } else {
            $null
        }
    }
    finally {
        if($null -ne $sr) {
            $sr.Dispose()
        }
        if($null -ne $rs) {
            $rs.Dispose()
        }
        if($null -ne $resp) {
            $resp.Dispose()
        }
    }
}

function Get-ArcGISComponentVersionAndInstallDirectory{
    param(
        [System.String]
        $ComponentName,

        [System.String]
        $ServiceName
    )
    
    if([string]::IsNullOrEmpty($ServiceName)){
        $ServiceName = Get-ArcGISServiceName -ComponentName $ComponentName
    }

    $RegKey = if($ServiceName -ieq 'ArcGIS Server'){ 'ArcGIS_SXS_Server' }else{ $ServiceName }
    $RegValue = (Get-ItemProperty -Path "HKLM:\SOFTWARE\ESRI\$RegKey" -ErrorAction Ignore)
    return @{
        RealVersion = $RegValue.RealVersion
        InstallDir = $RegValue.InstallDir
    }
}

function Invoke-ArcGISWebRequest
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.String]
		$Url, 

        [Parameter(Mandatory=$true)]
        $HttpFormParameters,
        
        [Parameter(Mandatory=$false)]
        [System.String]
		$Referer = 'https://localhost',

        [Parameter(Mandatory=$false)]
        [System.Int32]
		$TimeOutSec = 30,

        [Parameter(Mandatory=$false)]
        [System.String]
		$HttpMethod = 'Post'
    )

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} # Allow self-signed certificates
	[System.Net.ServicePointManager]::DefaultConnectionLimit = 1024
	[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    
    $HttpBody = (ConvertTo-HttpBody $HttpFormParameters)
    if($HttpMethod -ieq 'GET') {
        $UrlWithQueryString = $Url
        if(-not([string]::IsNullOrEmpty($HttpBody))){
            if($UrlWithQueryString.IndexOf('?') -lt 0) {
                $UrlWithQueryString += '?'
            }else {
                $UrlWithQueryString += '&'
            }
            $UrlWithQueryString += $HttpBody
        }

        $wc = New-Object System.Net.WebClient
        if($Referer) {
            $wc.Headers.Add('Referer', $Referer)
        }
        try {
            $res = $wc.DownloadString($UrlWithQueryString)
            Write-Verbose "Response:- $res"
            if($res) {
                $response = $res | ConvertFrom-Json
                $response
            }else {
                Write-Verbose "Response from $Url is NULL"
            }
        }
        catch [System.Net.WebException] {
            # Catch the specific WebException
            Write-Verbose "HTTP Request Failed!"
            Write-Verbose "Status: $($_.Exception.Message)"
            if ($wc.Headers.Count -gt 0) {
                foreach ($key in $wc.Headers.AllKeys) {
                    Write-Verbose "$key : $($wc.Headers[$key])"
                }
            }

            # Check if the server actually sent a response object back
            if ($_.Exception.Response) {
                # Extract the response stream
                $responseStream = $_.Exception.Response.GetResponseStream()
                
                # Read the stream using a StreamReader
                $reader = New-Object System.IO.StreamReader($responseStream)
                $responseBody = $reader.ReadToEnd()
                
                Write-Verbose "Server Response Body ---$responseBody"
                
                # Always clean up your streams to free up resources!
                $reader.Close()
                $responseStream.Close()
            }
            throw $_
        }
        catch {
            # Catch any other unexpected errors (e.g., typos in the URL, network disconnected)
            throw "An unexpected error occurred: $_"
        }
        finally {
            $wc.Dispose()
        }
     }else {
        $Headers = @{
            'Content-type'='application/x-www-form-urlencoded'
            'Content-Length' = $HttpBody.Length
            'Accept' = 'text/plain,text/html,application/json'     
            'Referer' = $Referer             
        }
        try {
            $res = Invoke-WebRequest -Method $HttpMethod -Uri $Url -Body $HttpBody -Headers $Headers -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing -TimeoutSec $TimeOutSec
            Write-Verbose "Response:- $($res.Content)"
            if($res -and $res.Content) {
                $response = $res.Content | ConvertFrom-Json
                $response  
            }else { 
                throw "Response returned NULL"
            }
        }
        catch {
            # Catch any other unexpected errors (e.g., typos in the URL, network disconnected)
            throw "Request to $Url failed. An unexpected error occurred: $_"
        }
    }
}

function Get-PropertyFromPropertiesFile
{
    [CmdletBinding()]
    param(
        [string]
        $PropertiesFilePath,

        [string]
        $PropertyName
    )
    
    $PropertyValue = $null
    if(Test-Path $PropertiesFilePath) {
        Get-Content $PropertiesFilePath | ForEach-Object {
            if($_ -and $_.StartsWith($PropertyName)){
                $Splits = $_.Split('=')
                if($Splits.Length -gt 1){
                    $PropertyValue = $Splits[1].Trim()
                }
            }
        }
    }
    $PropertyValue
}

function Set-PropertyFromPropertiesFile
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [System.String]
        $PropertiesFilePath,

        [System.String]
        $PropertyName,

        [System.String]
        $PropertyValue
    )      

    $Changed = $false       
    $Lines = @()
    $Exists = $false
    $Commented = $false
    $CommentedProperty = '#' + $PropertyName
    if(Test-Path $PropertiesFilePath) {
       
        Get-Content $PropertiesFilePath | ForEach-Object {
            $Line = $_
            if($_ -and $_.StartsWith($PropertyName)){
                $Line = "$($PropertyName)=$($PropertyValue)"
                $Splits = $_.Split('=')
                if(($Splits.Length -gt 1) -and ($Splits[1].Trim() -ieq $PropertyValue)){
                    $Exists = $true
                    Write-Verbose "Property entry for '$PropertyName' already exists in $PropertiesFilePath  and matches expected value '$PropertyValue'"
                }
            }
            elseif($_ -and $_.StartsWith($CommentedProperty)){
                Write-Verbose "Uncomment existing property entry for '$PropertyName'"
                $Lines += "$($PropertyName)=$($PropertyValue)"
                $Commented = $true
            }
            else {
                $Lines += $Line
            }
        }
        if(-not($Exists) -and (-not($Commented))) { 
            Write-Verbose "Adding entry $PropertyName = $PropertyValue to $PropertiesFilePath"
            $Lines += "$($PropertyName)=$($PropertyValue)" 
			$Lines += [System.Environment]::NewLine # Add a newline            
        }
    }else{
        $Lines += "$($PropertyName)=$($PropertyValue)"
    }
    if(-not($Exists) -or $Commented) {        
		Write-Verbose "Updating file $PropertiesFilePath"
		Set-Content -Path $PropertiesFilePath -Value $Lines -Force 
		$Changed = $true
    }
    Write-Verbose "Changed applied:- $Changed"
    $Changed
}

function Confirm-PropertyInPropertiesFile
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [System.String]
        $PropertiesFilePath,

        [System.String]
        $PropertyName,

        [System.String]
        $PropertyValue
    )  

    $CurrentValue = Get-PropertyFromPropertiesFile -PropertiesFilePath $PropertiesFilePath -PropertyName $PropertyName
    if($CurrentValue -ne $PropertyValue)
    {
        Write-Verbose "Current Value for '$PropertyName' is '$CurrentValue'. Expected value is '$PropertyValue'. Changing it"
        Set-PropertyFromPropertiesFile -PropertiesFilePath $PropertiesFilePath -PropertyName $PropertyName -PropertyValue $PropertyValue -Verbose        
    }else {
        Write-Verbose "Current Value for '$PropertyName' is '$CurrentValue' and matches expected value. No change needed"
        $false
    }
}

function Get-NodeAgentAmazonElementsPresent
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [System.String]
        $InstallDir
    )

    $Enabled = $false
    $File = Join-Path $InstallDir 'framework\etc\NodeAgentExt.xml'
    if(Test-Path $File){
        [xml]$xml = Get-Content $File
        if((Select-Xml -Xml $xml -XPath "//NodeAgent/Observers/Observer[@platform='amazon']").Length -gt 0 -or (Select-Xml -Xml $xml -XPath "//NodeAgent/Plugins/Plugin[@platform='amazon']").Length -gt 0){
            Write-Verbose "Amazon elements exist in $File"
            $Enabled = $true
        }
    }

    $Enabled
}

function Remove-NodeAgentAmazonElements
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [System.String]
        $InstallDir  
    )

    $Changed = $false
    $File = Join-Path $InstallDir 'framework\etc\NodeAgentExt.xml'
    if(Test-Path $File){
        [xml]$xml = Get-Content $File
        if((Select-Xml -Xml $xml -XPath "//NodeAgent/Observers/Observer[@platform='amazon']").Length -gt 0){
            $amazonObserverNode = $xml.NodeAgent.Observers.SelectSingleNode("//Observer[@platform='amazon']")
            if($null -ne $amazonObserverNode){
                Write-Verbose "Amazon Observer exists in $File. Removing it"
                $amazonObserverNode.ParentNode.RemoveChild($amazonObserverNode) | Out-Null
                $Changed = $true
            }
        }
        if((Select-Xml -Xml $xml -XPath "//NodeAgent/Plugins/Plugin[@platform='amazon']").Length -gt 0){
            $amazonPluginNode = $xml.NodeAgent.Plugins.SelectSingleNode("//Plugin[@platform='amazon']")
            if($null -ne $amazonPluginNode){
                Write-Verbose "Amazon plugin exists in $File. Removing it"
                $amazonPluginNode.ParentNode.RemoveChild($amazonPluginNode) | Out-Null
                $Changed = $true
            }
        }
        if($Changed) {
            $xml.Save($File)
        }
    }

    $Changed
}

function Add-HostMapping
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        $hostname, 
        $ipaddress
    )
    $returnValue = $false
    if((-not($hostname)) -or (-not($ipaddress))){ return $returnValue }

    $file = "$env:SystemRoot\System32\drivers\etc\hosts"
    $contents = Get-Content $file 
    $exists = $false
    foreach($content in $contents){
        if($content -and (-not($content.StartsWith('#'))) -and ($content.StartsWith($hostname)))
        {
            $exists = $true
        }
    }    
    if($exists){
        Write-Verbose "Entry '$hostname  $ipaddress' already exists in $file"
    }else{
        Write-Verbose "Adding entry '$hostname`t`t$ipaddress' to $file"
        Add-Content -Value "" -Path $file -Force  # Add a new line
        Add-Content -Value "$hostname`t`t$ipaddress`t`t# $hostname" -Path $file -Force
    }
    $returnValue
}

function Get-ConfiguredHostName
{
    [CmdletBinding()]
    param(
        [string]$InstallDir
    )

    $File = Join-Path $InstallDir 'framework\etc\hostname.properties'
    $HostName = $null
    if(Test-Path $File) {
        Get-Content $File | ForEach-Object {
            if($_ -and $_.StartsWith('hostname')){
                $Splits = $_.Split('=')
                if($Splits.Length -gt 1){
                    $HostName = $Splits[1].Trim()
                }
            }
        }
    }
    $HostName
}

function Set-ConfiguredHostName
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [string]$InstallDir,

        [Parameter(Mandatory=$true)]
        [string]$HostName
    )

    $Changed = $false
    $File = Join-Path $InstallDir 'framework\etc\hostname.properties'    
    $Lines = @()
    $Exists = $false
    if(Test-Path $File) {
        Get-Content $File | ForEach-Object {
            $Line = $_
            if($_ -and $_.StartsWith('hostname')){
                $Line = "hostname=$($HostName)"
                $Splits = $_.Split('=')
                if(($Splits.Length -gt 1) -and ($Splits[1].Trim() -ieq $HostName)){
                    $Exists = $true
                    Write-Verbose "Host entry for $HostName already exists"
                }
            }else {
                $Lines += $Line
            }
        }
        if(-not($Exists)) { $Lines += "hostname=$($HostName)" }
    }else{
        $Lines += "hostname=$($HostName)"
    }
    if(-not($Exists)) {
        Write-Verbose "Adding entry $HostName to $File"
        $Changed = $true
        Set-Content -Path $File -Value $Lines
    }
    $Changed
}


function Get-ConfiguredHostIdentifier
{
    [CmdletBinding()]
    param(
        [string]$InstallDir
    )

    $File = Join-Path $InstallDir 'framework\etc\hostidentifier.properties'
    $HostIdentifier = $null
    if(Test-Path $File) {
        Get-Content $File | ForEach-Object {
            if($_ -and $_.StartsWith('hostidentifier')){
                $Splits = $_.Split('=')
                if($Splits.Length -gt 1){
                    $HostIdentifier = $Splits[1].Trim()
                }
            }
        }
    }
    $HostIdentifier
}

function Get-ConfiguredHostIdentifierType
{
    [CmdletBinding()]
    param(
        [string]$InstallDir
    )

    $File = Join-Path $InstallDir 'framework\etc\hostidentifier.properties'
    $HostIdentifier = $null
    if(Test-Path $File) {
        Get-Content $File | ForEach-Object {
            if($_ -and $_.StartsWith('preferredidentifier')){
                $Splits = $_.Split('=')
                if($Splits.Length -gt 1){
                    $HostIdentifier = $Splits[1].Trim()
                }
            }
        }
    }
    $HostIdentifier
}

function Set-ConfiguredHostIdentifier
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [string]$InstallDir,

        [Parameter(Mandatory=$true)]
        [string]$HostIdentifier,

        [ValidateSet('hostname','ip')]
        [string]$HostIdentifierType = 'hostname'
    )

    $Changed = $false
    $File = Join-Path $InstallDir 'framework\etc\hostidentifier.properties'    
    $Lines = @()
    $HostIdExists = $false
    $HostIdTypeExists = $false
    $HostIdChanged = $true
    $HostIdTypeChanged = $true
    if(Test-Path $File) {
        Get-Content $File | ForEach-Object {
            $Line = $_            
            if($Line -and ($Line.StartsWith('hostidentifier') -or $Line.StartsWith('#hostidentifier'))) {                
                $Line = "hostidentifier=$($HostIdentifier)"
                if(-not($_.StartsWith('#'))) {
                    $Splits = $_.Split('=')
                    if(($Splits.Length -gt 1) -and ($Splits[1].Trim() -ieq $HostIdentifier)){
                        $HostIdChanged = $false
                        Write-Verbose "Host entry for $HostIdentifier already exists"                    
                    }
                }
                $HostIdExists = $true
            }
            elseif($Line -and ($Line.StartsWith('preferredidentifier') -or $Line.StartsWith('#preferredidentifier'))) {
                $Line = "preferredidentifier=$($HostIdentifierType)"
                if(-not($_.StartsWith('#'))) {
                    $Splits = $_.Split('=')
                    if(($Splits.Length -gt 1) -and ($Splits[1].Trim() -ieq $HostIdentifierType)){
                        $HostIdTypeChanged = $false
                        Write-Verbose "Host identifier type entry for $HostIdentifierType already exists"
                    }
                }
                $HostIdTypeExists = $true
            }
            $Lines += $Line
        }
        if(-not($HostIdExists)) { $Lines += "hostidentifier=$($HostIdentifier)" }
        if(-not($HostIdTypeExists)) { $Lines += "preferredidentifier=$($HostIdentifierType)" }
    }else{
        $Lines += "hostidentifier=$($HostName)"
        $Lines += "preferredidentifier=$($HostIdentifierType)" 
    }
    if((-not($HostIdExists)) -or (-not($HostIdTypeExists)) -or $HostIdChanged -or $HostIdTypeChanged) {
        Write-Verbose "Adding/modifying entry $HostIdentifier or identifier type $HostIdentifierType to $File"
        $Changed = $true
        Set-Content -Path $File -Value $Lines
    }
    $Changed
}

function Get-ArcGISProductName
{
    [CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Name,

		[parameter(Mandatory = $false)]
		[System.String]
		$Version
    )

    $VersionedProductNames = @(
        'Web Styles',
        'WebStyles',
        'ServerDataInteroperability',
        'ServerDataReviewer',
        'ServerWorkflowManagerClassic',
        'ServerMappingChartingSolution'
    )
    if($VersionedProductNames -icontains $Name -and [string]::IsNullOrWhiteSpace($Version)){
        throw "A Version is required to resolve the product name '$Name'."
    }

    $ProductName = $Name
    if($Name -ieq 'Portal' -or $Name -ieq 'Portal for ArcGIS'){
        $ProductName = 'Portal for ArcGIS'
    }elseif($Name -ieq 'LicenseManager' -or $Name -ieq 'ArcGIS License Manager'){
        $ProductName = 'ArcGIS License Manager'
    }elseif($Name -ieq 'Pro' -or $Name -ieq "ArcGIS Pro"){
        $ProductName = 'ArcGIS Pro'
    }elseif($Name -ieq "Web Styles" -or $Name -ieq 'WebStyles'){
        $ProductName = "Portal for ArcGIS $($Version) Web Styles"
    }elseif($Name -ieq 'DataStore'){
        $ProductName = 'ArcGIS Data Store'
    }elseif($Name -ieq "ArcGIS for Server" -or $Name -ieq 'Server'){
        $ProductName = 'ArcGIS Server'
    }elseif($Name -ieq 'ServerDeepLearningLibraries'){
        $ProductName = 'Deep Learning Libraries for ArcGIS Server'
    }elseif($Name -ieq 'ProDeepLearningLibraries'){
        $ProductName = 'Deep Learning Libraries for ArcGIS Pro'
    }elseif($Name -ieq "Mission Server" -or $Name -ieq 'MissionServer'){
        $ProductName = 'ArcGIS Mission Server'
    }elseif($Name -ieq "Notebook Server" -or $Name -ieq 'NotebookServer'){
        $ProductName = 'ArcGIS Notebook Server'
    }elseif($Name -ieq "Video Server" -or $Name -ieq 'VideoServer'){
        $ProductName = 'ArcGIS Video Server'
    }elseif($Name -ieq 'Geoevent'){
        $ProductName = 'ArcGIS Geoevent Server'
    }elseif($Name -ieq "Workflow Manager Server" -or $Name -ieq 'WorkflowManagerServer'){
        $ProductName = 'ArcGIS Workflow Manager Server'
    }elseif($Name -ieq "WebAdaptorIIS"){
        $ProductName = 'ArcGIS Web Adaptor (IIS)'
    }elseif($Name -ieq "WebAdaptorJava"){
        $ProductName = 'ArcGIS Web Adaptor (Java Platform)'
    }elseif($Name -ieq 'NotebookServerSamplesData'){
        $ProductName = 'ArcGIS Notebook Server Samples Data'
    }elseif($Name -ieq 'ServerDataInteroperability'){
        $ProductName = "ArcGIS Data Interoperability $Version for Server"
    }elseif($Name -ieq 'ProDataInteroperability'){
        $ProductName = "Data Interoperability for ArcGIS Pro"
    }elseif($Name -ieq 'ServerDataReviewer'){
        $ProductName = "ArcGIS Data Reviewer $Version for Server"
    }elseif($Name -ieq 'ServerWorkflowManagerClassic'){
        $ProductName = "ArcGIS Workflow Manager (Classic) $Version Server"    
    }elseif($Name -ieq 'ServerMappingChartingSolution'){
        $ProductName = "Mapping and Charting Solutions $Version for Server"
    }elseif($Name -ieq 'GeoenrichmentServer'){
        $ProductName = "GeoEnrichmentServer"
    }elseif($Name -ieq 'DataPipelinesServer'){
        $ProductName = "ArcGIS Data Pipelines Server"
    }elseif($Name -ieq 'RealityServer'){
        $ProductName = "ArcGIS Reality Server Runtime"
    }elseif($Name -ieq 'Monitor'){
        $ProductName = "ArcGIS Monitor Server"
    }elseif($Name -ieq 'MonitorAgent'){
        $ProductName = "ArcGIS Monitor Agent"
    }
    
    $ProductName
}

function Get-ComponentCode
{
       [CmdletBinding()]
       param
       (
        [ValidateSet("Server","Portal","DataStore","GeoEvent","NotebookServer","MissionServer","WorkflowManagerServer","Monitor", "MonitorAgent","WebStyles", "WebAdaptorIIS", "WebAdaptorJava","Pro","LicenseManager","NotebookServerSamplesData","ServerDataInteroperability","ProDataInteroperability","ServerDataReviewer","ServerWorkflowManagerClassic","ProWorkflowMangerClassic","ServerMappingChartingSolution","VideoServer","ServerDeepLearningLibraries","ProDeepLearningLibraries","GeoenrichmentServer","DataPipelinesServer","RealityServer")]
        [parameter(Mandatory = $true)]
        [System.String]
        $ComponentName,

        [ValidateSet("3.2","3.3","3.4","3.5","3.6","3.7","2018.0","2018.1","2019.0","2019.1","2019.2","2020.0","2020.1","2021.0","2022.0","2021.1","2022.1","2023.0","2024.0","2024.1","2025.0","2025.0.1","2025.1","2025.1.1","10.9.1","11.0","11.1","11.2","11.3","11.4","11.5","12.0","12.1")]
        [parameter(Mandatory = $true)]
        [System.String]
        $Version
    )

    $ProductCodes = @{
        Server = @{          
            '10.9.1' = 'E4A5FD24-5C61-4846-B084-C7AD4BB1CF19'
            '11.0' = 'A14CF942-415B-461C-BE3C-5B37E34BC6AE'
            '11.1' = '0F6C2D4F-9D41-4D25-A8AF-51E328D7CD8F'
            '11.2' = '4130E39E-FD8C-4DE0-AE91-AFEC71063B2D'
            '11.3' = 'BFADF38F-B9D3-40E6-AFD5-7DA1DA5BD349'
            '11.4' = 'C5CF7CE9-7501-4ECC-9C48-A7DD5A259AE2'
            '11.5' = 'BBFCF183-6CB3-409F-A855-21D48C5F079B'
            '12.0' = '97DB2F11-2C92-41DF-9C6D-F71648CD2AC9'
            '12.1' = '93056F2C-C97C-4958-B79E-92E9873F8C61'
        }
        Portal = @{      
            '10.9.1' = 'B5C5195E-2446-45F9-B49E-CC0E1C358E7C'
            '11.0' = 'EB809599-C650-486A-85C6-D37618754AE4'
            '11.1' = 'BED48866-C615-4790-AD87-01F114C1A999'
            '11.2' = 'F03C23C1-1F2C-42D0-85C4-38F49B710035'
            '11.3' = '6B72E29F-B27F-452E-8FCF-C2CFB9417891'
            '11.4' = 'CFB543E4-7FB7-4F9D-BD1F-483347B142DF'
            '11.5' = '366A0EAF-7974-4EA3-9A43-74D76FB77C47'
            '12.0' = 'C898DDF9-D6BE-45DF-9A10-3263660BB39F'
            '12.1' = 'B089C99B-8570-40E1-88C0-EF86CA36E536'
        }
        WebStyles = @{ 
            '10.9.1' = '2E63599E-08C2-4401-8FD7-95AAA64EA087'
            '11.0' = 'CCA0635D-E306-4C42-AB81-F4032D731397'
            '11.1' = '67EDD399-CBD8-48C8-8B72-D79FBBBD79B2'
            '11.2' = '0508DE8B-B6B2-42AD-B955-77451C3ACB60'
            '11.3' = 'A477F9A0-A5E5-4BBF-8042-8503DE8AAEC5'
            '11.4' = '2C941605-135F-4501-AD91-21ECA70977ED'
            '11.5' = '58668668-FCF9-400D-B3DF-24A3E0417C00'
            '12.0' = 'A31A5861-3957-46E3-9166-56D297C0309E'
            '12.1' = '44120188-FA74-4E39-8691-68C7C4C9A25C'
        }
        DataStore = @{             
            '10.9.1' = '30BB3697-7815-406B-8F0C-EAAFB723AA97'
            '11.0' = 'ABCEFF81-861D-482A-A20E-8542814C03BD'
            '11.1' = '391B3A39-0951-43E3-991D-82C82CA6E4A4'
            '11.2' = 'FE7F4A14-4D96-4B31-8937-BA19C0A92DDB'
            '11.3' = 'E4FC0BED-0F94-49D4-9AF5-BBA64AED3787'
            '11.4' = '4AC2C588-DFDC-449E-8DFF-3701C3C3824A'
            '11.5' = '622B3833-6239-4857-96D5-4294D1E85F94'
            '12.0' = 'E62C9D19-53FE-45C2-B9C5-C86C7C703B8F'
            '12.1' = '0D10FFF3-8380-4E15-952E-DC031EB3940D'
        }        
        GeoEvent = @{             
            '10.9.1' = 'F5C3D729-0B74-419D-9154-D05C63606A94'
            '11.0' = '98B0A1CC-5CE4-4311-85DD-46ABD08232C5'
            '11.1' = '475EA5B0-E454-4870-BB1F-AB81EDDEC2A7'
            '11.2' = '7CBB01F9-90D3-42A6-99A8-70E773B5E8C5'
            '11.3' = '3F9DC5C6-E832-46A9-AC27-26F48C02DBDC'
            '11.4' = '4CEDE889-6698-4083-B221-7499B7A32D39'
            '11.5' = 'C8BA52B6-38E6-484E-BEC6-61A28EBC6CB8'
            '12.0' = '92BEF07A-3250-4276-BCDE-1D66F26160CE'
            '12.1' = 'C57000DE-175A-4305-B948-94B53A6E3B86'
        }
        NotebookServer = @{
            '10.9.1' = '39DA210D-DE33-4223-8268-F81D2674B501'
            '11.0' = '62777D3B-5F08-4945-8EA2-C2B518D88AEA'
            '11.1' = 'B449287C-6C2B-4D83-BD27-B416A2171FD5'
            '11.2' = '7CF68441-8657-48C3-93C2-DB2DC3EFA9E5'
            '11.3' = 'FA4C02E7-1BFB-4895-AE47-24CBCE443304'
            '11.4' = 'A853CA10-4978-4882-8629-571FBA02618D'
            '11.5' = 'C9AB6062-B63C-4745-AB1F-2532D594379F'
            '12.0' = '42B859BB-95D1-4778-B2A7-991F3DD812E1'
            '12.1' = 'E3307F5C-C424-45A9-8B2D-8950B9700B74'
        }
        NotebookServerSamplesData = @{
            '10.9.1' = '02AB631F-4427-4426-B515-8895F9315D22'
            '11.0' = '2F9BC4EA-B2D9-43C6-98CA-06A9DDFB6A63'
            '11.1' = 'A8752FEB-3783-44FC-AC1D-A9DACA94822E'
            '11.2' = '3A9E12F6-7D4B-4DA2-BA2C-C9D0E900CF94'
            '11.3' = 'B26B2E98-9D10-48EF-A980-F11672CF766F'
        }
        MissionServer = @{
            '10.9.1' = '2BE7F20D-572A-4D3E-B989-DC9BDFFB75AA'
            '11.0' = 'A0E25148-B33D-442F-9EE4-B35AEC2DEA6D'
            '11.1' = 'C8723ED4-272B-43B5-88D6-98F484DFFF09'
            '11.2' = '5721BCA3-D4BB-42D3-A719-787D0B11F478'
            '11.3' = '6A92CAEF-653B-47F0-885D-A82CA38B4C58'
            '11.4' = '3338445A-81E9-421C-A331-BA1BFBE8A8DE'
            '11.5' = 'F0FEE17E-2CB7-4C42-B091-5E8AC7945666'
            '12.0' = '16AF7BDF-E692-4490-A3F6-1F41812CF155'
            '12.1' = 'E116D18B-4CB4-4E16-8EA5-CDD2CCA67DF4'
        }
        VideoServer = @{
            '11.2' = 'D68D1CBB-990B-4F5B-916A-A7B89EE33716'
            '11.3' = '401FBD2C-0D81-4D3B-8BCF-8D08C8F18EC9'
            '11.4' = '016CE7D6-3D42-4D1A-8AEE-4846433173D1'
            '11.5' = 'BCA8F7A7-9A65-4E66-A007-83C0D3EF73A6'
            '12.0' = 'A08F57C3-0681-4D57-AEE8-51BB55ABA32D'
            '12.1' = '691DD84E-B01A-4341-888B-6B941F671E6E'
        }
        WorkflowManagerServer = @{
            '10.9.1' = '9EF4FCC5-64EE-4719-B050-41E5AB85857B'
            '11.0' = '1B27C0F2-81E9-4F1F-9506-46F937605674'
            '11.1' = 'BCCADE20-4363-4D62-AE55-BB51329210CF'
            '11.2' = '434D85E9-9CFB-4683-9FFF-5C38CDEBD676'
            '11.3' = 'A5AC0A8B-A7A2-45DD-8EDC-7A4F762A4192'
            '11.4' = '455C44DE-39C6-4D9F-BC13-48F7626492E8'
            '11.5' = 'A5C18498-DEF3-44DD-8DE6-8E6C1653CC66'
            '12.0' = '3E93DBCD-2ECB-4E88-BD1E-3456D5FAD070'
            '12.1' = 'CF66FDBC-FBF0-4593-8222-172328452A77'
        }
        
        Monitor = @{
            '2025.0' = '99F8BE63-2E0F-40D8-9059-350E727360A7'
            '2025.0.1' = '7E3F85BA-A4EB-4FBE-B242-0F5F60AF9E29'
            '2025.1' = 'BF2BC66A-BD09-4473-8936-E45DE550E261'
        }
        MonitorAgent = @{
            '2025.1.1' = '443C4796-53B6-44C3-8776-DDD6A203C173'
            '2025.1' = '8CDE3732-1F56-4B12-ADDE-DCEACE78F26A'
            '2025.0.1' = '7ED078BC-816A-4D5A-BD82-4E4503A4BF03'
            '2025.0' = 'C703CED4-F325-4F95-8A36-1578F2EEF3B4'
        }
        LicenseManager = @{
            '2018.0' = 'CFF43ACB-9B0C-4725-B489-7F969F5B90AB'
            '2018.1' = 'E1C26E47-C6AB-4120-A3DE-2FA0F723C876'
            '2019.0' = 'CB1E78B5-9914-45C6-8227-D55F4CD5EA6F'
            '2019.1' = 'BA3C546E-6FAC-405C-B2C9-30BC6E26A7A9'
            '2019.2' = '77F1D4EB-0225-4626-BB9E-7FCB4B0309E5'
            '2020.0' = 'EEE800C6-930D-4DA4-A61A-0B1735AF2478'
            '2020.1' = '3C9B5AFE-057B-47B3-83A6-D348ABAC3E14'
            '2021.0' = '9DDD72DA-75D2-4FB0-BC19-25F8B53254FF'
            '2021.1' = 'DA36A877-1BF2-4E28-9CE3-D3A07FB645A3'
            '2022.0' = 'A3AC9C93-E045-4CAE-AAE4-F62A8E669E02'
            '2022.1' = '96804860-2C2F-4448-AE47-76CB160AD043'
            '2023.0' = 'C5E546F7-5E07-4AAB-A367-15FF52D0C683'
            '2024.0' = 'D9D91CDE-048A-47B5-AFE7-FB397DAF87D9'
            '2024.1' = '2BCB59D3-E25C-4F17-8C94-121A12B68A6C'
            '2025.0' = '6D41720D-070B-4023-B58A-74F507FC4AD7'
            '2025.1' = '7917E829-F495-4FDE-8213-F59B49D51545'
        }
        Pro = @{
            '3.2' = '76DFAD3E-96C5-4544-A6B4-3774DBF88B4E'
            '3.3' = 'B43BC6C2-05D2-460B-AEE4-D15A9CA7B55E'
            '3.4' = 'F6FDD729-EC3F-4361-A98E-B592EEF0D445'
            '3.5' = '6AB7A2E6-6E45-4A2D-8E88-6B0856B4CB48'
            '3.6' = '302EF432-616C-4281-94F6-D53E290D0F77'
            '3.7' = 'E56D931B-27A0-4C1D-87F8-AFCDCD21A653'
        }
        WebAdaptorIIS = @{
            '10.9.1' = @('BC399DA9-62A6-4978-9B75-32F46D3737F7', 'F48C3ABF-AF5F-4326-9876-E748DB244DB7','AC4AD5BF-E0B4-4EE6-838E-93EE66D986EF', 'F96ECEFD-2015-4275-B15D-363F53407390','21B1638E-47E7-4147-B739-EB341F99986F', '78ABEA6E-4832-4087-B7BB-04746D1E83E8','A624163D-A110-4959-BD82-98CB7CE6ECBE', '7A6E0537-43A2-4925-8F8A-E19715B21392','4AE1AE3D-2471-4393-B0D9-ECB4D1368EB9', 'C72DE321-E19C-4737-9513-AE39B1A32953','49F98C43-955D-4BD8-A585-07BA45D72D0A', '5DD68937-54F9-4015-A8DA-4602AFCA8986','D3C16E17-DAB1-4025-A029-46C7598DCA4A', 'A2CBD39F-C2DE-4983-9C70-7F108B52F402','CA174887-E7C6-4DE9-8797-72CBD7FC4B1C', 'B658575F-82ED-49BE-980C-D4A5089FCA7A','CBEE526A-29B6-46FE-B7F8-B930A785CFF8', '76618450-9F2C-4FCC-9CDA-01A61F9E1953','17591EF3-221C-4DD1-B773-6C9617925B5F','566920BF-1EF3-4E62-B2BF-029475E35AAB','4A3B27C6-7CB1-4DE8-BCB1-221B9A23E2E1')
            '11.0' = @('FCC01D4A-1159-41FC-BDB4-4B4E05B3436F','920A1EFA-D4DC-4C6D-895A-93FDD1EDE394','258F0D35-985B-4104-BCC4-B8F9A4BB89B4','7B128234-C3D8-4274-917F-BC0BCE90887F','CD160BB2-3AA9-42CE-8BA0-4BFF906E81DE','BBBD3910-2CBB-4418-B5CE-FB349E1E74F0','594D4267-E702-4BA8-9DF4-DB91DCF94B3E','D2538F6E-E852-4BE0-9D20-61730D977410','BAB5BA8A-DE70-4F79-9926-D6849C218BF2','E37D4B50-05EC-4128-AC65-10E299693A3C','2BD1FC31-CFB0-488A-83B3-BEC066423FAA','AA378242-0C2C-4CC2-9E33-B44E0F92577C','F00D0401-C60F-4AB1-BCF2-ADA00DF40AA9','5AE7F499-C7A3-4477-BBED-3D8B21FF6322','5147A262-75C3-4CAE-BCF0-09D9EBBF4A24','7D3F3C7C-A40D-42EC-BA38-E04E6B3CFA16','36305F97-388A-4427-AF76-C4BA8BC2A3DC','BB3F184D-C512-4544-8A7D-76A1F600AEC2','A4CEFD65-D3DF-4992-AC4A-2CED8894F0BF','36B75654-E4C2-4FF3-B9F7-0D202D1ECAC8','0E14FDF9-3D6C-48E4-B362-B248B61FC971')
            '11.1' = @('E2F2DE02-86AC-42EE-B90D-544206717C9E','A4082192-FA68-4150-8EB7-ACCF12F634C4','7A467DB0-DE13-40A6-9213-7F336C28456E','4C3342AC-45D7-417A-8DFC-54604649A97C','8B8A2734-BEC8-476F-B99D-3E13C9F0BAA8','62FCD139-C853-4944-809C-967835510785','65E3E662-67D0-4608-A522-5C10C59CA2DC','614E9ADA-CE81-44DB-BB04-C2A0E02C6458','83F624D7-ED01-48A1-8E3A-6CEDD4CDEBF2','F2D7F6E9-DB46-4B39-994A-FCA32EA5CF15','4A6C5251-C1E3-4ADD-A442-773C110701E6','E09C05F7-8E85-4402-A1A8-C53B6926D0CD','5E664C01-5D5B-4CAA-A03F-145B69FFF6EA','DC9156D0-13CE-4981-B0EB-3C55B1997632','3A5F0EB2-B721-4E5F-9576-47F02A5F77F6','09AFD321-FD2A-4D22-AEEB-C858E0691386','B14810D6-F62D-4581-BBDB-80B739A504DB','8A2CE94A-6340-4AA4-AE83-62A4FA8C5AC2','90E8E4D4-DDE0-4743-AA83-CBDD1827F307','7C10E922-35BD-4A1B-87B0-6346AF5D1462','1EA1484D-962A-4923-9CD1-BC074031E25F')
            '11.2' = @('3F2DF3A0-0EB7-4DED-BA7F-A33B7B106252','CAB137C6-98F0-4569-9484-719632E81CF6','899B1E0C-4675-4E52-BFBC-4FFF69DBAF8E','4DE50EC3-6CB8-4EE5-B634-1AE53499F6D4','A0ABE60F-0E01-4D84-A08B-EE34EFF96584','066DEFEE-E71D-42F5-859E-225825268720','53A32CFB-A012-4546-9A7F-09E489442A0A','34AD67CC-2BA2-4EAA-B2A5-777036B0104E','08CF83CB-FC1E-4F7C-8960-96C7D8A0B733','D3803AB3-1C2F-4AD9-80EB-901685912599','6671DEEE-CEE8-4FBD-B2DC-430F268225AF','F92DED6B-B2B4-4E4F-A65B-ACE4973C0A9A','6EDAB5E0-FD24-4427-82BE-134DB0FF9D37','EFA6EC36-1A4B-481D-8A2E-C3B9098179F1','CB1CA2A3-D209-462D-947A-AE5DCAACDC54','D8D5A0CB-3F4F-4863-8EB2-6D24C0D0F093','AE62DBD4-44A1-4E67-BAAC-4A5B2AC8830E','8C323710-4026-4A8C-8DCF-5EFF6EE3F39B','3232DC1F-00C3-4247-B354-FA022F1504C0','3D0E95E1-BDA7-47BF-A967-3E889D3C79D9','151724F6-2228-4A46-B710-88A6BAFEDCB4')
            '11.3' = @('6D1FDF29-5DAB-4816-9CDE-15CF663E3BDD','9DA66832-790E-4A08-90D8-3305D2C4F2A2','E3DF9FCC-2078-4816-B195-EE30D1C74086','87C9FEB8-73A7-436A-861E-74C3A3D7805B','3D881639-2227-4E9E-9380-C55991C92D3F','7FB27776-2537-456E-BF4D-6E90B1050E16','013D126B-0E28-4070-B57D-1C7128511E09','F2D44D27-A3EB-4892-A260-7FF8D90AE3ED','AC6ECF31-E1D9-4A08-B7E2-9BF4EA138BFD','D2B275D6-F12D-4AB1-B0E3-7E72E42309F6','8AC70A2E-6E62-47C1-8DAE-63481CF7E570','1C94E9C9-8FE0-4647-B679-1C99721D8E5A','36E80F76-A84A-4C2E-9087-F6B6FC60B8F0','442DAF3B-289D-45AC-855D-CD1AF79AD046','2F5AE3DF-9918-4BB3-ADAC-D6A02681E8C5','B2775E94-5176-42F2-9161-C52EFD7BFFD5','614151D0-B8AE-4D85-83B3-70AFA3961E1A','C9DD2778-546E-4E27-AEC1-C51BCA198172','BF09767E-0CB7-4DAF-9ABE-400EE03CB9D6','72587C29-AB2F-42F4-AB8B-A54325CA7A71','1FA8B39E-07B5-4EAE-BABD-1B121131FEB2','CFE37EEE-9148-4A1D-904C-05EBD63345DA','2C774E47-A888-4F31-8425-781628500874','2F923C43-6CF5-44B7-A21F-AFDE607C417D','112A5C83-2207-4B94-9829-7433E8B82A7E','2EE1C0D5-4631-47B3-B77E-CA5062732BA4','0D125A07-D3FE-4388-870A-0CAC77280683','0155E162-901D-41DF-A260-AA8E6C833D9A','20F7ABC9-CC0F-47DD-B3FB-AA3D70140F1D','407A2E2C-F8D7-4900-9F68-442774F9DD9E','E86311FF-9990-48CD-A04C-B3404FA5B395','2CF5D03B-AD63-4BB4-A3C6-7FD1D595F810','8F2FCF64-7190-45B8-8DC4-4DAB5ED83425','8673E73F-83A3-4C29-8BAB-516394436BC0','6B41E749-D67F-4975-A858-7EEB32532C12','E953DD69-8BA7-4653-AFEE-622E42B77AE1','457B6C44-9A92-4F31-A071-359E8F000A70','44FE2519-ABD7-4557-BD59-A1717928C539','0B7987AB-85E2-480C-B245-D4BECE95E8EB','D5985070-E78C-4B9A-8075-929EE77AC4B0','F5D192C7-104E-4524-9DE0-36B34216B999','65B4454A-4C0E-4DF0-BC32-18552466B306','8AE7199B-D50C-48AD-BB82-1C289443C4C1','0FDDEF60-6FA8-4DA7-9E05-A8CC4A1C1C9B','033430AD-8978-459F-8CDA-2FD49B67752B','85BD45E5-25CB-4FED-BBAE-2AA34286E556','E46DBEB4-628D-4DC6-BC13-32F42B6EF5F6','D976C4CB-B3B6-43C9-87E9-F27E2BE826AE','91869554-E02E-4AB1-956F-AC1B54AF2158','A88F3595-7DC9-455C-813D-66C6C687A9D1','44CAC131-3CA6-44A1-AFBD-3E083365D5F0')
            '11.4' = @('A1EEF9DE-E054-461A-BAB8-EE7FF8C8C6E6', '37A3BCC2-9A76-4D87-AC2A-993582ECF891','51D04E2F-9196-43DC-950E-173EED1290D4', '5C9B7DA6-01DC-425E-BA94-427DDE199959','D7BDB359-3BCE-4153-A570-7948C6097FF4', '6827D461-6440-4C74-9F83-7D7BF9F57F93', '47AA6E11-0D24-47C1-99E6-9C0F4B318FFF', 'BC0F76E2-9583-4E66-8CA6-FD343F329B31','A99CDDFA-B1A0-4924-A659-61E4E1BBCB83', 'B00814E3-1EBC-41AC-A632-8D0494885AE2','BECA4DB4-7080-4504-96F9-861884FB3FBA', '356E98BB-0E15-4FBD-9AAE-81FC15213B7F','51875907-8D8B-46B4-A694-519FDB8F9907', 'E85450CF-E7A9-4281-9C2A-3CC8CDA952A9','703152AA-069F-46AB-9080-404463A073E4', 'E514597B-CDE7-460D-9FD1-04B9B786DB23','0ED2A3FD-4B6B-4006-B10C-9F45F1D90CFC', '75A1143F-82EC-42D1-9081-30901CF73614','D86A7B19-67FA-4EA3-86EE-A210F618B274', 'AF997D9E-270C-4CB9-88B5-EFF0FE3F930B','718DE748-4F62-4A16-862D-670564FF79ED', '9AD6E83D-DC7B-47FD-AC52-3B3DD1FDA07D','000B3034-FA23-46E6-A5A5-FD13EB302F5F', 'C79C1A34-2364-4DCB-BA6B-BA6D22A919D9','2479729B-3FFA-41C3-A2C6-4D992782A243', 'C0FA8EE3-5230-400B-B80E-2F6950D606A4','66FD8F46-B3CF-4C1F-9B04-B5894FD41A75', 'C87ACC53-FC3D-4527-AB2C-D5FBB41A1F34','8976EB40-82E0-4583-A255-EEB30EC86161', '743EDE64-11F6-46BF-85E7-A64ADE4CA7F0','7C841837-FDDE-493E-BCC1-2E8514AFE146', 'ABFAD895-1F0D-4D50-AFF2-DAD9303FA2A0','CBE7BA7E-0A46-4AEF-AC5D-E7A7C7986701', 'B61D5494-BD5F-4583-9564-AEA33C2DA6E3','C190AA6A-46A8-4068-840C-125FA21918BB', 'C5174467-893B-4D38-ABD9-1FA9CB2FB1AD','42C04A4F-7E12-4E37-8143-C8CDBD7E1DE4', '22732FD0-C451-4284-B35A-D040B5A16FEC','46FA248B-A29F-42CA-AC41-201F675BD9F3', 'ACD97940-DA22-4761-8962-8E531EE0EC0A','98671F19-A3DC-4310-970A-E74C8950E3A5', '478AABC4-FCD7-4956-9421-F2AE705245DF','E64B3CED-3FFE-4B21-AFD6-CBC400707329', '15BAD677-D80E-48A6-84D9-ED1F1C002816','C630E05F-7208-447C-86CE-FEF27E2DDE1C', 'D721DFD5-9DF9-4F8A-BD45-D61E2D719F91','FCEF4ECC-D7A8-4192-8E47-7A22221A70D2', '57244572-CDD1-4079-B5E7-526CB411109D','4A38BCCB-3CBB-47CC-BF03-F4B6178280E6', '9608A7E2-D821-4CFF-A8EA-9D9C27A6585C','EB8847FE-9A77-4933-8D0E-874F0F7399C2')
            '11.5' = @('B87FD5D1-7ED0-424B-8A79-CE4B231CF085','A944DC16-D9B0-4FEC-AAFB-9CC9D5D45414','CACEC5F2-E484-40E5-BC3E-D82A19554E40','EC659D96-A962-4F04-AF02-42CDD3CC8C6A','7D357A92-E949-4322-95D5-6EB58640C078','4782E831-37C1-4B83-B975-9D0E0F373135','CC3694A7-F3EC-4358-9F06-DD1D2EBC4B1D','BD0A6A4E-4B75-48E9-8ABF-9774E7960CAB','43E50FE3-F1E4-416C-924D-9604296C2090','276501DB-F08D-4489-BF02-D12430E7BB5C','BE613B94-61AF-4B48-A0CA-DDCB134CE9CA','F3D1F822-9CE3-46CE-8ACA-8CFD737F6604','155FF541-DB93-49F4-BB01-B5495F707807','5A969923-9741-4FA9-81AB-13B776DFF16E','BFBAA84A-008F-493F-B6D3-EC12AD4C57BD','72A84420-32D8-462F-968B-92F25B02D73C','F048814A-3140-461F-A399-13F234344AF0','ADD92D5D-540E-4532-AB53-DA19D76FFBE2','E594184E-A395-49AB-860F-6EA29C50423F','F2C56B3D-BA68-413F-9916-C2CDCEDD9C7E','7ADDF6BE-4277-4814-A31C-DF36D0ADE5E3','362763DC-B9B5-46E8-80AB-17C082646B2A','A3B15EFA-172D-40EF-B5B9-382777992697','83C7DEB5-C160-4520-9F45-1B2C1A55B5C0','A0B36D8D-9551-4EDA-974E-9ED1CEC5151A','AAD36199-6837-4865-8692-02BA825874B7','DD14E295-6798-407E-A5A0-870C8341577E','E25BD1CE-3A98-4833-B021-E5F1FB613F21','5118D9DB-543E-45EA-AE06-08A0A67143A1','DCBFF94C-763C-4F36-A10C-2AFD9A335334','DD063BF3-0D8E-4E58-B295-C48827E13893','59062D7E-E4E7-4567-9634-4E51F42D6BCA','C26ABB80-29AF-4328-834E-A3C0ECF298B4','0654FE83-95A5-481E-B5B2-61A3FEDFA5C4','77EE6E4F-5A1D-4DBB-9688-027DA4DF3BAB','2558441D-97F6-419A-9AF9-A0F4D56C1AC4','468A6A59-C347-4B59-952F-697390488CE3','003BAC29-91FE-4185-A90B-945F82847E67','817458AC-05F3-4A68-AD26-A6E894EAECD5','5C2E1A0C-B17C-4CA0-B230-4934C4AD11CF','CE3DAA74-A08E-46B1-B963-8552A486F9C2','2EBA8AD2-0DA0-4143-B878-9FD1303635A3','CD758D69-D265-4053-A62F-AF4525F61BD5','709E6312-B1F0-48A6-8347-5186CDF5AD07','2CB5A7D6-51DA-4CD1-ADF9-4F7036E8D36B','9A94211B-33E6-4311-9B0D-3CD1BBCEE423','73E65AC0-BE55-4BDC-8586-9CC9634C692D','513D8FE8-4999-4D9C-98A4-03F9EBC5B50C','777F527D-2D43-4430-8E8F-A93B71FA1C4D','C74184F9-8D73-4F9A-8C47-187F28B9A92A','6FA4997E-158E-4A9B-A093-7473A259500E')
            '12.0' = @('BB194DE8-F519-4660-837F-B6AAA3650DEB','2F6059F3-08E0-45D6-B75E-D99A26F46923','7C748A51-F096-4886-B7DB-A8F1D09AF36B','A6571CB2-ED32-4406-99DE-1115CC67A159','532FC0CE-63C1-4AC0-823E-C11DEBCB014D','135DE6D2-F950-4502-8A3F-207590E63385','A7B6D59B-E59C-4799-9793-1E062FE57C4C','4C04F842-BF8B-4789-8FDC-092767AC09A7','49530C4D-F9E1-4AB1-9386-0ADA92BBE99B','1FF4D167-C240-48BC-961A-F819EB364283','AE371E47-D666-41D7-ABD2-06304FAC2CE1','CC85E3D7-FBEB-417A-B94B-83721721144D','319AFA39-5272-4944-A4DA-FACFB484737B','1B923CCF-53C3-49BF-99D0-B8A0D4AFF648','B023628D-AC80-425B-A052-BCD26AD5A547','3650EF99-D4A5-4A8F-AA28-09935A66EBFA','0033A180-F240-422A-B1A7-9F4FEDD8B20E','FF312ADC-BDEB-4AF7-9B27-CE849400D4CB','FF480938-7A92-438E-B634-E46B747FA4AA','D965B597-02B4-4BAD-B7B5-2C8780BEDCAC','C259A6BB-BF51-4793-A77B-359B5A9D274E','B0868301-627D-4A6B-A301-5C9FC120418E','578A334A-F1D4-4846-B6FE-9B6087FC4DC1','8E07BB12-EC11-4477-AC15-EB93A39AA736','25689A35-9378-4A80-B5C9-CB5723732D0F','6F484488-A8EA-4483-9700-EA173C86DE5F','F89A57CE-6340-4549-8893-85B86A3315C9','01BB8344-7A5D-4204-B046-B8FC5B1EB1AF','C829C6CE-2239-4B9F-97ED-8B93CE13006E','B294CD04-C562-4C42-A3D0-A3F353F58352','B0D9C28E-26A2-4362-9FE3-1504BF92C204','C3FE2DBA-83B6-40B4-954E-4733FF7F4C0C','07F81319-C8A9-4A73-87FE-6C3FFEEE187A','4CC28D62-8260-4537-9E6D-578432579EA6','11517C11-A569-42DF-A109-35ED8A383215','8501FB6A-2543-4857-8C68-F59EB83A5F14','09542E0F-0313-4249-9970-7CEB90902D2A','095279E6-82B0-4915-93C1-B0B3F7491BB5','B698BDD0-DC3E-41B0-B1D5-566B522EDD4F','DCE0A9CB-20E5-46F7-8A89-DA9DAC1658EF','1AF687D6-A15F-4AC1-A5B8-202BEF43AA92','D38DC6CD-7D57-477E-B5B4-CB3A704654C8','0CCFF04D-8F0A-45FC-B326-A6A3D2E828B0','BF863CEF-1BE9-40F6-976B-680D502F9C0F','9BC57233-80DA-4EAD-96D1-ED07FDCD602B','C68E9488-FD2B-426D-B431-48EACEF2D8CE','58EB33C9-5156-406D-81EE-B9B20603FEAA','4D4A68E7-56E0-43E0-94DF-B18CBAB9E205','4350A88A-9027-40C1-91CA-0D9235BE4042','1F78C428-AC73-4858-A4D2-FCEB3123F156','B2E5F1AB-51EB-492D-BF61-A43002F7F8D2')
            '12.1' = @('3EBF5B44-4B62-4E7D-ADF8-2F1BE4419867','10E702C4-5461-45C2-9BF7-0E4861D4CB15','CFEF5F3A-9B91-4124-8863-C724282F3DD1','37E9E565-596E-4C47-8319-A57E404988A0','6F91314C-BC9A-4AF9-94B7-1F12FB68BB09','B978AEF5-56CC-4D75-A8A5-72369B307F0C','4B83513E-4505-436C-A0ED-6AAAE100CEB6','2A880BAB-A224-4EDC-A575-713C89FFE307','7B13AAB0-EA92-43B7-B911-143C020946C0','909A3A6D-E97B-4C18-9E28-4BC670868EB4','53ED8318-CBCB-4E58-8BD4-757DF2F72514','2A394041-E353-478A-9C95-427537B383BF','53DB779D-9705-4C83-A09B-E047171BC780','F8252420-C71B-476D-B190-E291159087FB','C334CDA9-D6E6-4E10-BFD9-D3E69D815F20','E6BE03C5-E4C9-4E4D-B1D1-481FBF0DE00D','73C3EA6E-07E6-484C-8B37-9999498F2E6D','3782A1E6-DADF-4629-A8C1-897D0D7C4D2C','3CC697B6-50CD-4DB0-A775-91A50E601ABE','51262449-468F-4F31-AE23-58CFA276BCF6','18F949CD-2887-482D-BE7F-11E0797AFB1F','D917129E-84D7-4965-8C1C-6647FC3C390D','6DC057CC-279C-4B2D-83A2-C6A882D5FC7E','BAF5DFA6-930F-4726-B9F2-41E2D8BDA98F','A54A42A1-3DF1-49FC-809B-A3CFB97C563C','08869055-8E45-47D1-BE1A-E0E7EE21D139','9A6D4A47-09D6-43E3-A66E-397599052291','88EF3E0B-744A-4D12-AA78-51C97A785B25','B8EBCC18-FDD7-454B-A1A2-DC1BA36C1D72','DC686101-411F-424D-BBBA-63ADED7880AE','3FFA65CF-5696-4726-9F68-F8CF4B616434','B2E56531-2941-4614-AD12-91F0B2DD07FB','181C90B1-BDDD-4DA3-BD45-5D8BC3603D41','95A27070-2B74-4DE6-9A1D-C02FB0AB2D49','264541CF-FDAF-410C-9D64-0E745A2CBF30','448D6332-B41F-4A9D-852B-484FFE5875EC','B9EC1A0B-E377-4EE5-99F5-2B93E13A6D9F','7060272F-2AEB-4569-9E90-2DAD0D3C520B','B2594ED6-2F00-4DB0-932B-D04D422DAF36','71ECBE5D-7995-48DE-833A-2E05535550F8','0E70B283-6622-4E05-889C-6952678CBDDE','799C961D-A5FF-4F8F-AABE-27F654D13339','5DDEEFB0-0C4C-483D-8AD3-0425981D4B97','4C4C8FA0-1DDA-4E17-8A8E-6B4D3E12BED7','DFE77477-1106-4784-91C3-7DA5436CC8B3','A73584A8-8AF4-4C5A-A3B9-4CACCCF0E5ED','C58E3698-6DF3-419C-A1D6-0F9A90114805','2E7F4E14-11A2-4963-A24D-949107B404C2','5C560E1E-6266-41F8-B76F-B1296A48815F','E664E225-7F7D-4B03-9218-0F64AFD57E95','B0E93D95-F062-40F5-8863-0FA4863C0033','852703F7-78E1-4F00-BCC0-FF98D8A39E7B','01B6CA84-23DF-47BD-8093-7536AC0C9776')
        }
        WebAdaptorJava = @{
            '10.9.1' = 'B9138950-F155-4754-9510-678B2B523A35'
            '11.0' = '05060E31-277F-49DA-B284-A0F16D60949A'
            '11.1' = '9D76C3E5-4F36-4E65-94E8-AC3D45E0722D'
            '11.2' = 'C737C573-7676-462F-B612-3150F8FE4F8E'
            '11.3' = 'ACFAB233-F0D1-4494-AB0E-F018B7137CFB'
            '11.4' = '9A118830-2B2E-407F-AC52-0EC479AD8234'
            '11.5' = 'F56388CB-22AF-429E-A878-81CC8F072217'
            '12.0' = '74A17026-AB8D-45DD-949F-5A05F8AF0B39'
            '12.1' = 'E78D347D-E22D-40DE-B182-E4A9A78FB97C'
        }
        ServerDataInteroperability = @{
            '10.9.1' = '26A934BC-212C-4F90-8DFF-9900437D303B'
            '11.0' = '338D8E88-3791-4578-A9DC-82D83CF0806B'
            '11.1' = '4D7379B9-E6B5-4B5C-A8CC-82DE30EA9329'
            '11.2' = '58AE1C52-2096-4708-8B38-196E866E845B'
            '11.3' = 'AF003EED-0B32-49DC-8D40-914AA03B4A39'
            '11.4' = 'B51EA33A-50A0-4A3A-93D3-7996D5857118'
            '11.5' = 'C70F9A21-95A4-4908-BA87-FDCD8F2F26EB'
            '12.0' = '9E052075-3EFB-4565-9186-D263F0A69A54'
            '12.1' = 'D7633151-A3F5-497D-8D88-160262735F43'
        }
        ProDataInteroperability = @{
            '3.2' = '7FFFFCBC-0C97-4B5A-9A5D-74A79D0C43AF'
            '3.3' = '37F59181-A898-46C4-BBFC-B209FED50428'
            '3.4' = '7F066F83-DA01-44F2-9666-6EFA801CCB3D'
            '3.5' = '50DC0AD9-A7DB-4093-ADD1-78A12841873D'
            '3.6' = 'C1BC0512-8B35-4229-AB23-373509FEBAFC'
            '3.7' = '1AB8880E-529C-4438-9B1F-269648AD825A'
        }
        ServerDataReviewer = @{
            '10.9.1' = '907233F9-A534-4483-AB2A-1EA0E7328BE3'
        }
        ServerWorkflowManagerClassic = @{
            '10.9.1' = '71FDEA4A-4411-42AC-930C-B65453A48E07'
        }
        #ServerMappingChartingSolution is now known as ArcGIS Maritime for Server
        ServerMappingChartingSolution = @{
            '10.9.1' = 'D461F83B-0FFB-4AB0-92FE-F82DA370E5F3'
            '11.0' = '12F0B974-5A37-4902-8CFA-C28C2938A7C2'
            '11.1' = '9082A706-E68B-46E2-B22F-0A9E0975055C'
            '11.2' = '96982D34-F3DA-43F4-9168-97B778E25111'
            '11.3' = '7FF70DEB-9D1B-4FB2-915A-9B4C1B1225F9'
            '11.4' = '08BBEF38-3483-4111-871D-D2AFE7D2054E'
            '11.5' = '589C31AD-BF06-479D-999D-790D83BA52E3'
            '12.0' = 'C81ECAAA-4FCA-4721-91F1-6E113E320871'
            '12.1' = 'D3939715-2ADB-414F-B2E4-A3DADD159C69'
        }
        ServerDeepLearningLibraries = @{
            '11.0' = '23FC1804-7B41-4271-8734-8C78C9B8CEF9' 
            '11.1' = '55A9B498-55AD-4AB9-812F-E29303FC14FE' 
            '11.2' = 'A21D9C29-93F6-47FF-B1E3-C5735BAAE028'
            '11.3' = '1AD2A68A-312B-40B1-8191-A77E2A62F09F'
            '11.4' = '595FAC0C-2BA5-4F58-A818-BE987D5C131A'
            '11.5' = 'AC41FE87-D271-49B9-8918-ABA9ADB06F30'
            '12.0' = '9284C916-FDFD-4F16-856D-AD1B797467B2'
            '12.1' = '9C38A28D-70CA-4A3F-8C3D-CD80BF815233'
        }
        ProDeepLearningLibraries = @{
            '3.2' = '713C97D1-F666-4EFE-A370-718646B23459'
            '3.3' = '24CFF061-D968-45CF-8CAB-D9E818A4318F'
            '3.4' = '6C9433E9-AEA5-4C85-8183-1B4BBF9C47F1'
            '3.5' = '0354AE95-2315-47B6-A8C4-2B694220785A'
            '3.6' = 'AAB2647E-C7EE-4FFB-81D2-54BF1F070941'
            '3.7' = '3E61D7ED-F500-4E1C-8772-97D45DDC4A08'
        }
        RealityServer = @{
            '12.0' = 'CC32EDFF-F1D4-4232-8494-BC87BBC6F146'
            '12.1' = '192D2EE4-71D4-4A91-8D74-D1E18926F1BC'
        }
        DataPipelinesServer = @{
            '12.0' = 'C12E5DB8-9886-4089-89FB-652E6CAFE043'
            '12.1' = '47592468-38F3-4920-A2E1-C60B898933EF'
        }
        GeoenrichmentServer = @{
            '11.3' = 'B2755F3D-5798-417D-AD2B-B30382E38D45'
            '11.4' = '51A3704E-8952-40BB-862D-434EC6394661'
            '11.5' = 'E8221CA6-05A1-4D4F-8BE2-43CB5E22FD9A'
            '12.0' = '4C13A8B7-0E7F-4077-A755-3E28358E363D'
            '12.1' = 'E893462F-32E2-427C-B558-0AC852F2C8E1'
        }
    }
    $ProductCodes[$ComponentName][$Version]    
} 

Function Test-Install{
    [CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
        [parameter(Mandatory = $true)]
		[System.String]
		$Name,

		[parameter(Mandatory = $false)]
		[System.String]
        $Version,
        
        [parameter(Mandatory = $false)]
		[System.String]
        $ProductId
    )
    
    $result = $false
    $resultSetFlag = $false
    $ProdId = $null

    if(-not([string]::IsNullOrEmpty($ProductId))){
        if(-not([string]::IsNullOrEmpty($Version))){
            $ProdIdObject = Get-ComponentCode -ComponentName $Name -Version $Version
            if($Name -ieq "WebAdaptorIIS"){
                if($ProdIdObject -icontains $ProductId){
                    $ProdId = $ProductId
                }else{
                    Write-Verbose "Given product Id doesn't match the product id for the version specified for Component $Name"
                    $result = $false
                    $resultSetFlag = $True
                }
            }else{
                if($ProdIdObject -ieq $ProductId){
                    $ProdId = $ProductId
                }else{
                    Write-Verbose "Given product Id doesn't match the product id for the version specified for Component $Name"
                    $result = $false
                    $resultSetFlag = $True
                }
            }
        }else{
            $ProdId = $ProductId
        }
    }else{
        if(-not([string]::IsNullOrEmpty($Version))){
            if($Name -ieq "WebAdaptorIIS"){
                throw "Product Id is required for Component $Name"
            }else{
                $ProdId = Get-ComponentCode -ComponentName $Name -Version $Version
            }
        }else{
            throw "Product Id or Version is required for Component $Name"
        }
    }

    if($null -eq $ProdId){
        $result = $false
    }else{
        if(-not($resultSetFlag)){    
            if(-not($ProdId.StartsWith('{'))){
                $ProdId = '{' + $ProdId
            }
            if(-not($ProdId.EndsWith('}'))){
                $ProdId = $ProdId + '}'
            }
            $PathToCheck = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$($ProdId)"
            Write-Verbose "Testing Presence for Component '$Name' with Path $PathToCheck"
            if (Test-Path $PathToCheck -ErrorAction Ignore){
                Write-Verbose "Found Component $Name with Product Id $ProdId"
                $result = $true
            }
            if(-not($result)){
                $PathToCheck = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$($ProdId)"
                Write-Verbose "Testing Presence for Component '$Name' with Path $PathToCheck"
                if (Test-Path $PathToCheck -ErrorAction Ignore){
                    Write-Verbose "Found Component $Name with Product Id $ProdId"
                    $result = $true
                }
            }
        }
    }
    
    $result
}

function Convert-PSObjectToHashtable
{
    param (
        [System.Object]
        $InputObject
    )

    process
    {
        if ($null -eq $InputObject) { return $null }

        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string])
        {
            $collection = @(
                foreach ($object in $InputObject) { Convert-PSObjectToHashtable $object }
            )

            Write-Output -InputObject $collection -NoEnumerate
        }
        elseif ($InputObject -is [psobject])
        {
            $hash = @{}

            foreach ($property in $InputObject.PSObject.Properties)
            {
                $hash[$property.Name] = Convert-PSObjectToHashtable $property.Value
            }

            $hash
        }
        else
        {
            $InputObject
        }
    }
}

function Get-AvailableDriveLetter
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


function Get-ArcGISComponentBaseUrl{
    
    [CmdletBinding()]
    [OutputType([System.Int32])]
    param (
        [System.String]
        $FQDN = "localhost",

        [System.String]
        $ComponentName,

        [System.Int32]
        $Port = -1,

        [System.String]
        $Context = "arcgis"
    )

    if($Port -lt 0){
        $Port = Get-ArcGISEnterpriseComponentPort -ComponentName $ComponentName 
    }

    $BaseURL = "https://$($FQDN):$($Port)/$($Context)"
    if($Port -eq 443){
        $BaseURL = "https://$($FQDN)/$($Context)"
    }
    return $BaseURL
}

function Test-ArcGISComponentHealth{
    
    [CmdletBinding()]
    [OutputType([System.Int32])]
    param (
        [System.String]
        $BaseURL,

        [System.String]
        $ComponentName,

        [System.Int32]
		$MaxWaitTimeInSeconds = 150, 

        [System.Int32]
		$SleepTimeInSeconds = 5,

        [System.Boolean]
		$ThrowErrors,

        [System.String]
		$HttpMethod = 'GET',

        [System.Int32]
	    $MaximumRedirection=5,

		[System.Int32]
	    $RequestTimeoutInSeconds=15,
        
        [System.Boolean]
        $IsWebAdaptor
    )

    $HealthCheckURL = $BaseURL
    $AdditionalHealthCheckURL = $null
    switch ($ComponentName) {
        'Portal' { 
            # This only returns valid status when the site is created
            $HealthCheckURL = "$($BaseURL)/portaladmin/healthCheck?f=json"
            break 
        }
        'PortalAdmin' { 
            $HealthCheckURL = "$($BaseURL)/portaladmin/?f=json"
            break 
        }
        'PortalSharing' { 
            $HealthCheckURL = "$($BaseURL)/sharing/rest/info?f=json" 
            break
        }
        {@('Server','MissionServer','NotebookServer','VideoServer','DataPipelinesServer') -icontains $_} { 
            $HealthCheckURL = "$($BaseURL)/rest/info/healthcheck?f=json"
            $AdditionalHealthCheckURL = "$($BaseURL)/admin" # Only for admin?/hea
            break
        }
        'ServerAdmin' { 
            $HealthCheckURL = "$($BaseURL)/admin" # Only for admin?
            break
        }
        'DataStore' { 
            $HealthCheckURL = "$($BaseURL)/datastoreadmin/configure?f=json"
            break 
        }
        'GeoEvent' {  $HealthCheckURL = "$($BaseURL)/rest"; break }
        'Monitor' {  $HealthCheckURL = "$($BaseURL)/rest/info/healthcheck?f=json"; break }
        default { $HealthCheckURL = $BaseURL }
    }
    
    Wait-ForUrl -Url $HealthCheckURL -MaxWaitTimeInSeconds $MaxWaitTimeInSeconds -SleepTimeInSeconds $SleepTimeInSeconds -HttpMethod $HttpMethod -MaximumRedirection $MaximumRedirection -RequestTimeoutInSeconds $RequestTimeoutInSeconds -ThrowErrors $ThrowErrors -IsWebAdaptor $IsWebAdaptor -Verbose
    if(-not([string]::IsNullOrEmpty($AdditionalHealthCheckURL))){
        Wait-ForUrl -Url $AdditionalHealthCheckURL -MaxWaitTimeInSeconds $MaxWaitTimeInSeconds -SleepTimeInSeconds $SleepTimeInSeconds -HttpMethod $HttpMethod -MaximumRedirection $MaximumRedirection -RequestTimeoutInSeconds $RequestTimeoutInSeconds -ThrowErrors $ThrowErrors -IsWebAdaptor $IsWebAdaptor -Verbose
    }
}

function Wait-RecheckAfterSeconds {
    param(
        [int] $Seconds,
        [int] $Multiplier = 2
    )
    if($Seconds -gt 0){
        $sleep = $Seconds * $Multiplier
        Write-Verbose "Sleeping for $sleep seconds"
        Start-Sleep -Seconds $sleep
    }
}


function Invoke-StartProcess
{
    [CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$ExecPath,

		[parameter(Mandatory = $false)]
		[System.String]
        $Arguments,

        [parameter(Mandatory = $false)]
		[hashtable]
        $EnvVariables,

        [Parameter(Mandatory = $false)]
		[System.String]
        $WorkingDirectory,

        [Parameter(Mandatory = $false)]
		[System.Int32]
        $TimeOutInMinutes = -1
    )

    Write-Verbose "Running $ExecPath"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $ExecPath
    
    if(-not([string]::IsNullOrEmpty($WorkingDirectory))){
		$psi.WorkingDirectory = $WorkingDirectory
    }

    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false #start the process from it's own executable file    
    $psi.RedirectStandardOutput = $true #enable the process to read from standard output
    $psi.RedirectStandardError = $true #enable the process to read from standard error 
    if($EnvVariables -and $EnvVariables.Count -gt 0){
        foreach ($key in $EnvVariables.Keys) {
            if($null -eq $EnvVariables[$key]){
                $psi.EnvironmentVariables[$key] = [environment]::GetEnvironmentVariable($key,"Machine")
            }else{
                $psi.EnvironmentVariables[$key] = $EnvVariables[$key]
            }
        }
    }

    $p = [System.Diagnostics.Process]::Start($psi)
    if($TimeOutInMinutes -gt 0){
        $TimeoutInMilliseconds = $TimeoutInMinutes * 60 * 1000
        $p.WaitForExit($TimeoutInMilliseconds)
        if(-not $p.HasExited) {
            $p.Kill()
            throw "$($ExecPath) timed out after $($TimeoutInMinutes) minutes."
        }
    }else{
        $p.WaitForExit()
    }
    
    $op = $p.StandardOutput.ReadToEnd()
    $result = $null
    if($p.ExitCode -eq 0) {                    
        Write-Verbose "$ExecPath run successful."
        $result = $op
    }else{
        $err = $p.StandardError.ReadToEnd()
        Write-Verbose $err
        $ExceptionString= "$ExecPath run failed. Output - $($op). Process exit code:- $($p.ExitCode)."
        if($err -and $err.Length -gt 0) {
            throw "$($ExceptionString) Error - $($err)"
        }else{
            throw $ExceptionString
        }
    }
    $result
}

function Get-WindowsServiceRunAsInfo
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $Name
    )

    $Service = Get-CimInstance Win32_Service -Filter "Name='$Name'" | Select-Object -First 1
    if($null -eq $Service){
        throw "Service '$Name' not found. Please check and try again."
    }

    $RunAsAccount = $Service.StartName
    if($RunAsAccount -and $RunAsAccount.StartsWith('.\')){
        $RunAsAccount = $RunAsAccount.Substring(2)
        Write-Verbose "Removing the machine prefix for the current RunAsAccount to $RunAsAccount"
    }

    [PSCustomObject]@{
        Service      = $Service
        RunAsAccount = $RunAsAccount
    }
}

function Get-RemoteFile
{
    param (
        [System.String]
        $RemoteFileUrl,
        
        [System.String]
        $DestinationFilePath,

        [System.Boolean]
        $IsUsingAzureBlobManagedIndentity
    )
    
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} # Allow self-signed certificates
    [System.Net.ServicePointManager]::DefaultConnectionLimit = 1024
    [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    $wc = New-Object System.Net.WebClient
    try {
        if($IsUsingAzureBlobManagedIndentity){
            $ManagedIdentityAccessToken = Get-AzureManagedIdentityStorageAccessToken -Verbose
            $wc.Headers.Add('Authorization', "Bearer $ManagedIdentityAccessToken")
            $wc.Headers.Add("x-ms-version", "2017-11-09")
        }
        $wc.DownloadFile($RemoteFileUrl, $DestinationFilePath)
    }
    catch {
        throw "Error downloading remote file. Error - $_"
    }
    finally {
        $wc.Dispose()
    }
}

function Get-AzureManagedIdentityStorageAccessToken
{
    $wc = New-Object System.Net.WebClient
    try {
        $wc.Headers.Add('Metadata', "true")
        $response = $wc.DownloadString('http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fstorage.azure.com%2F')
        return ($response | ConvertFrom-Json).access_token
    }catch {
        throw "Error getting managed identity token for storage account access. Error - $_"
    }
    finally {
        $wc.Dispose()
    }
}

Export-ModuleMember -Function @(
    'Invoke-ArcGISWebRequest'
    'Invoke-UploadFile'
    'Wait-ForUrl'
    'Confirm-ResponseStatus'
    'Confirm-PropertyInPropertiesFile'
    'Get-PropertyFromPropertiesFile'
    'Set-PropertyFromPropertiesFile'
    'Get-NodeAgentAmazonElementsPresent'
    'Remove-NodeAgentAmazonElements'
    'Add-HostMapping'
    'Get-ConfiguredHostIdentifier'
    'Set-ConfiguredHostIdentifier'
    'Get-ConfiguredHostName'
    'Set-ConfiguredHostName'
    'Get-ConfiguredHostIdentifierType'
    'Get-ComponentCode'
    'Get-ArcGISProductName'
    'Test-Install'
    'Convert-PSObjectToHashtable'
    'Restart-ArcGISService'
    'Get-AvailableDriveLetter'
    'Test-ArcGISComponentHealth'
    'Get-ArcGISComponentBaseUrl'
    'Wait-RecheckAfterSeconds'
    'Invoke-StartProcess'
    'Get-ArcGISComponentVersionAndInstallDirectory'
    'Get-WindowsServiceRunAsInfo'
    'Get-RemoteFile'
    'Get-AzureManagedIdentityStorageAccessToken'
)