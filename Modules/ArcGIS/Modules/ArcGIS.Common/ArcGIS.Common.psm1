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


function Get-ServerToken 
{
    [CmdletBinding()]
    param(
		[Parameter(Mandatory=$true)]
        [System.String]
		$ServerEndPoint, 

		[Parameter(Mandatory=$false)]
        [System.String]
        $ServerSiteName = 'arcgis', 
        
        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$Credential,

		[Parameter(Mandatory=$true)]
        [System.String]
		$Referer, 

        [System.Int32]
        $Expiration=1000,

        [System.Int32]
        $MaxAttempts = 10
    )
    $url = ($ServerEndPoint.TrimEnd('/') + "/$ServerSiteName/admin/generateToken")
    $ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($url)
    $ServicePoint.CloseConnectionGroup("")
    $token = $null
    $Done = $false
	$NumAttempts = 0
	while(-not($Done) -and ($NumAttempts -lt $MaxAttempts)) {
		try {
			$token = Invoke-ArcGISWebRequest -Url $url -HttpFormParameters @{ username = $Credential.GetNetworkCredential().UserName; password = $Credential.GetNetworkCredential().Password; client = 'referer'; referer = $Referer; expiration = $Expiration; f = 'json' } -Referer $Referer -TimeOutSec 45 
		}
		catch {
			Write-Verbose "[WARNING]:- Server at $url did not return a token on attempt $($NumAttempts + 1). Retry after 15 seconds"
		}
		if($token) {
			Write-Verbose "Retrieved server token successfully"
			$Done = $true
		}else {
			Start-Sleep -Seconds 15
			$NumAttempts = $NumAttempts + 1
		}
	}
    $token
}


function Get-PortalToken 
{
    [CmdletBinding()]
    param(
		[Parameter(Mandatory=$true)]		
        [System.String]
		$PortalHostName, 

		[Parameter(Mandatory=$false)]
        [System.String]
		$SiteName = 'arcgis', 

		[parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$Credential,

		[Parameter(Mandatory=$true)]
        [System.String]
		$Referer,

        [Parameter(Mandatory=$false)]
        [System.Int32]
		$Port = 7443,

        [System.Int32]
        $MaxAttempts = 10
    )
    $url = ("https://$($PortalHostName):$($Port)/$SiteName/sharing/rest/generateToken")
    $ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($url)
    $ServicePoint.CloseConnectionGroup("")
    $token = $null
    $Done = $false
	$NumAttempts = 0
	while(-not($Done) -and ($NumAttempts -lt $MaxAttempts)) {
		try {
            $token = Invoke-ArcGISWebRequest -Url $url -HttpFormParameters @{ username = $Credential.UserName; password = $Credential.GetNetworkCredential().Password; referer = $Referer; f = 'json' } -Referer $Referer
            if($token.error){
                Write-Verbose "Error Response - $($token.error)"
                throw [string]::Format("ERROR: Unable to get Portal Token - {0}" , $token.error.message)
            }
		} catch {
            $token = $null
			Write-Verbose "[WARNING]:- Portal at $url did not return a token on attempt $($NumAttempts + 1). Retry after 15 seconds"
		}
		if($token) {
			Write-Verbose "Retrieved portal token successfully"
			$Done = $true
		}else {
			Start-Sleep -Seconds 15
			$NumAttempts = $NumAttempts + 1
		}
    }
    $token
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

        [switch]
		$ThrowErrors,

        [System.String]
		$HttpMethod = 'GET',

        [System.Int32]
	    $MaximumRedirection=5,

		[System.Int32]
	    $RequestTimeoutInSeconds=15,
        
        [switch]
        $IsWebAdaptor
    )

    [bool]$Done = $false
    [int]$TotalElapsedTimeInSeconds = 0
    $WaitForError = $null
    Write-Verbose "Waiting for Url $Url"
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    while((-not($Done)) -and ($TotalElapsedTimeInSeconds -lt $MaxWaitTimeInSeconds)) {
	    try {
			if($HttpMethod -ieq 'GET') {
				[System.Net.HttpWebRequest]$webRequest = [System.Net.WebRequest]::Create($Url)
				$webRequest.Timeout  = ($RequestTimeoutInSeconds * 1000)
                $webRequest.AllowAutoRedirect = $MaximumRedirection -gt -1
                $webRequest.MaximumAutomaticRedirections = [System.Math]::Max(1, $MaximumRedirection)
                if($IsWebAdaptor){
                    $webRequest.Headers.Add('accept-language','en-US') 
                }
				$resp = $webRequest.GetResponse()
				Write-Verbose "Url is $($resp.StatusCode)"
                $Done = $true
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
            $TotalElapsedTimeInSeconds += $SleepTimeInSeconds
        }
    }
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
    [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
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

    [System.IO.Stream]$reqStream = $webRequest.GetRequestStream()   

    $enc = [System.Text.Encoding]::GetEncoding("UTF-8")
    $headerPlusNewLine = $header + [System.Environment]::NewLine
    [byte[]]$headerBytes = $enc.GetBytes($headerPlusNewLine)

    
    #### Use StreamWriter to write form parameters ####
    [System.IO.StreamWriter]$streamWriter = New-Object 'System.IO.StreamWriter' -ArgumentList $reqStream
    foreach($formParam in $formParams.GetEnumerator()) {
        [void]$streamWriter.WriteLine($header)
        [void]$streamWriter.WriteLine(("Content-Disposition: form-data; name=""{0}""" -f $formParam.Name))
        [void]$streamWriter.WriteLine("")
        [void]$streamWriter.WriteLine($formParam.Value)
    }
    $streamWriter.Flush()     

    [void]$reqStream.Write($headerBytes,0, $headerBytes.Length)

    [System.IO.FileInfo]$fileInfo = New-Object "System.IO.FileInfo" -ArgumentList $filePath   

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
    [System.IO.FileStream]$fileStream = New-Object 'System.IO.FileStream' -ArgumentList @($filePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
    $fileStream.CopyTo($reqStream)
    $fileStream.Flush()
    $fileStream.Close()

    [void]$streamWriter.WriteLine("")        
    [void]$streamWriter.WriteLine($footer)
    $streamWriter.Flush()
    
    $resp = $null
	try {
		$resp =  $webRequest.GetResponse()    
    }catch {
        Write-Verbose "[WARNING] $url returned an error $_"
	}
    if($resp) {
		$rs = $resp.GetResponseStream()
        [System.IO.StreamReader]$sr = New-Object System.IO.StreamReader -argumentList $rs
        $sr.ReadToEnd()
    }else {
        $null
    }
}

function Get-EsriRegistryKeyForService([string]$ServiceName)
{
    $RegKey = $ServiceName
    if($ServiceName -ieq 'ArcGIS Server')
    {
        $RegKey = 'ArcGIS_SXS_Server'
    }
    "HKLM:\SOFTWARE\ESRI\$RegKey"
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
		$Referer = 'http://localhost',

        [Parameter(Mandatory=$false)]
        [System.Int32]
		$TimeOutSec = 30,

        [Parameter(Mandatory=$false)]
        [System.String]
		$HttpMethod = 'Post'
    )

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} # Allow self-signed certificates
	[System.Net.ServicePointManager]::DefaultConnectionLimit = 1024
	[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    $HttpBody = ConvertTo-HttpBody $HttpFormParameters
    $Headers = @{'Content-type'='application/x-www-form-urlencoded'
                    'Content-Length' = $HttpBody.Length
                    'Accept' = 'text/plain'     
                    'Referer' = $Referer             
                }
    if($HttpMethod -ieq 'GET') {
        $UrlWithQueryString = $Url
        if($UrlWithQueryString.IndexOf('?') -lt 0) {
            $UrlWithQueryString += '?'
        }else {
            $UrlWithQueryString += '&'
        }
        $UrlWithQueryString += $HttpBody
        $wc = New-Object System.Net.WebClient
        if($Referer) {
            $wc.Headers.Add('Referer', $Referer)
        }
        $res = $wc.DownloadString($UrlWithQueryString)
		Write-Verbose "Response:- $res"
		if($res) {
			$response = $res | ConvertFrom-Json
			$response
		}else {
			Write-Verbose "Response from $Url is NULL"
		}
     }else {
        $Headers = @{'Content-type'='application/x-www-form-urlencoded'
                'Content-Length' = $HttpBody.Length
                'Accept' = 'text/plain'     
                'Referer' = $Referer             
            }        
        $res = Invoke-WebRequest -Method $HttpMethod -Uri $Url -Body $HttpBody -Headers $Headers -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing -TimeoutSec $TimeOutSec   
        if($res -and $res.Content) {          
			Write-Verbose "Response:- $($res.Content)"
			$response = $res.Content | ConvertFrom-Json
            $response  
        }else { 
            throw "Request to $Url failed. Response returned NULL"
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

		[parameter(Mandatory = $true)]
		[System.String]
		$Version
    )

    $VersionArray = $Version.Split(".")

    $ProductName = $Name
    if($Name -ieq 'Portal' -or $Name -ieq 'Portal for ArcGIS'){
        $ProductName = 'Portal for ArcGIS'
    }elseif($Name -ieq 'LicenseManager' -or $Name -ieq 'ArcGIS License Manager'){
        $ProductName = 'ArcGIS License Manager'
    }elseif($Name -ieq 'Pro' -or $Name -ieq "ArcGIS Pro"){
        $ProductName = 'ArcGIS Pro'
    }elseif($Name -ieq 'Desktop' -or $Name -ieq "ArcGIS Desktop"){
        $ProductName = 'ArcGIS Desktop'
    }elseif($Name -ieq "Web Styles" -or $Name -ieq 'WebStyles'){
        $ProductName = "Portal for ArcGIS $($Version) Web Styles"
    }elseif($Name -ieq 'DataStore'){
        $ProductName = 'ArcGIS Data Store'
    }elseif($Name -ieq "ArcGIS for Server" -or $Name -ieq 'Server'){
        $ProductName = 'ArcGIS Server'
    }elseif($Name -ieq 'ServerDeepLearningLibraries'){
        $ProductName = 'Deep Learning Libraries for ArcGIS Server'
    }elseif($Name -ieq "Mission Server" -or $Name -ieq 'MissionServer'){
        $ProductName = 'ArcGIS Mission Server'
    }elseif($Name -ieq "Notebook Server" -or $Name -ieq 'NotebookServer'){
        $ProductName = 'ArcGIS Notebook Server'
    }elseif($Name -ieq 'Geoevent'){
        $ProductName = 'ArcGIS Geoevent Server'
    }elseif($Name -ieq "Workflow Manager Server" -or $Name -ieq 'WorkflowManagerServer'){
        $ProductName = 'ArcGIS Workflow Manager Server'
    }elseif($Name -ieq "Workflow Manager WebApp" -or $Name -ieq 'WorkflowManagerWebApp'){
        $ProductName = 'ArcGIS Workflow Manager WebApp'
    }elseif($Name -ieq "WebAdaptor" -or $Name -ieq 'ServerWebAdaptor' -or $Name -ieq 'PortalWebAdaptor'){
        $ProductName = 'ArcGIS Web Adaptor'
    }elseif($Name -ieq 'NotebookServerSamplesData'){
        $ProductName = 'ArcGIS Notebook Server Samples Data'
    }elseif($Name -ieq 'Insights'){
        $ProductName = 'ArcGIS Insights'
    }elseif($Name -ieq 'ServerDataInteroperability'){
        $ProductName = "ArcGIS Data Interoperability $Version for Server"
    }elseif($Name -ieq 'DesktopDataInteroperability'){
        $ProductName = "ArcGIS Data Interoperability $Version for Desktop"
    }elseif($Name -ieq 'ProDataInteroperability'){
        $ProductName = "Data Interoperability for ArcGIS Pro"
    }elseif($Name -ieq 'ServerDataReviewer'){
        $ProductName = "ArcGIS Data Reviewer $Version for Server"
    }elseif($Name -ieq 'DesktopDataReviewer'){
        $ProductName = "ArcGIS Data Reviewer $Version for Desktop"
    }elseif($Name -ieq 'ServerWorkflowManagerClassic'){
        if($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 8) -or $Version -ieq "10.8.1"){
            $ProductName = "ArcGIS Workflow Manager (Classic) $Version Server"
        }else{
            $ProductName = "ArcGIS Workflow Manager $Version for Server"
        }
    }elseif($Name -ieq 'DesktopWorkflowManagerClassic'){
        if($VersionArray[0] -eq 11 -or ($VersionArray[0] -eq 10 -and $VersionArray[1] -gt 8) -or $Version -ieq "10.8.1"){
            $ProductName = "ArcGIS Workflow Manager (Classic) $Version Desktop"
        }else{
            $ProductName = "ArcGIS Workflow Manager $Version for Desktop"
        }
    }elseif($Name -ieq 'ServerLocationReferencing'){
        $ProductName = "ArcGIS Location Referencing $Version for Server"
    }elseif($Name -ieq 'DesktopLocationReferencing'){
        $ProductName = "ArcGIS Location Referencing $Version for Desktop"
    }elseif($Name -ieq 'ServerMappingChartingSolution'){
        $ProductName = "Mapping and Charting Solutions $Version for Server"
    }elseif($Name -ieq 'DesktopMappingChartingSolution'){
        $ProductName = "Mapping and Charting Solutions $Version for Desktop"
    }elseif($Name -ieq 'DesktopBackgroundGP64Bit'){
        $ProductName = "ArcGIS Desktop Background Geoprocessing $Version (64-bit)"
    }
    
    $ProductName
}

function Get-ComponentCode
{
       [CmdletBinding()]
       param
       (
        [ValidateSet("Server","Portal","DataStore","GeoEvent","NotebookServer","MissionServer","WorkflowManagerServer", "WorkflowManagerWebApp","Monitor","WebStyles", "WebAdaptor","Desktop","Pro","LicenseManager","NotebookServerSamplesData","Insights","ServerDataInteroperability","DesktopDataInteroperability","ProDataInteroperability","ServerDataReviewer","DesktopDataReviewer","ServerWorkflowManagerClassic","DesktopWorkflowManagerClassic","ProWorkflowMangerClassic", "ServerLocationReferencing","DesktopLocationReferencing","ServerMappingChartingSolution","DesktopMappingChartingSolution","DesktopBackgroundGP64Bit")]
        [parameter(Mandatory = $true)]
        [System.String]
        $ComponentName,

        [ValidateSet("2.0","2.1","2.2","2.3","2.4","2.5","2.6","2.7","2.8","2.9","3.0","3.0.3","10.4","10.4.1","10.5","10.5.1","10.6","10.6.1","10.7","10.7.1","10.8","10.8.1","10.8.2","10.9","10.9.1","2018.0","2018.1","2019.0","2019.1","2019.2","2020.0","2020.1","2020.2","2020.3","2021.0","2022.0","3.4","3.4.1","2021.1","2021.1.1","2021.2.1", "2021.2", "2021.3.1", "2021.3","2022.1","2022.1.1","2022.2","2022.3","11.0")]
        [parameter(Mandatory = $true)]
        [System.String]
        $Version
    )

    $ProductCodes = @{
        Server = @{          
            '10.4' = '687897C7-4795-4B17-8AD0-CB8C364778AD'
            '10.4.1' = '88A617EF-89AC-418E-92E1-926908C4D50F'
            '10.5' = 'CD87013B-6559-4804-89F6-B6F1A7B31CBC'
            '10.5.1' = '40CC6E89-93A4-4D87-A3FB-11413C218D2C'
            '10.6' = '07606F78-D997-43AE-A9DC-0738D91E8D02'
            '10.6.1' = 'F62B418D-E9E4-41CE-9E02-167BE4276105'
            '10.7' = '98D5572E-C435-4841-A747-B4C72A8F76BB'
            '10.7.1' = '08E03E6F-95D3-4D33-A171-E0DC996E08E3'
            '10.8' = '458BF5FF-2DF8-426B-AEBC-BE4C47DB6B54'
            '10.8.1' = 'E9B85E31-4C31-4528-996B-F06E213F8BB3'
            '10.9' = '32A62D8E-BE72-4B28-AA0E-FE546D827240'
            '10.9.1' = 'E4A5FD24-5C61-4846-B084-C7AD4BB1CF19'
            '11.0' = 'A14CF942-415B-461C-BE3C-5B37E34BC6AE'
        }
        Portal = @{      
            '10.4' = 'FA6FCD2D-114C-4C04-A8DF-C2E43979560E'
            '10.4.1' = '31373E04-9B5A-4CD7-B668-0B1DE7F0D45F'
            '10.5' = '43EF63C6-957B-4DA7-A222-6904053BF222'
            '10.5.1' = 'C7E44FBE-DFA6-4A95-8779-B6C40F3947B7'
            '10.6' = 'FFE4808A-1AD2-41A6-B5AD-2BA312BE6AAA'
            '10.6.1' = 'ECC6B3B9-A875-4AE3-9C03-8664EB38EED9'
            '10.7' = '6A640642-4D74-4A2F-8350-92B6371378C5'
            '10.7.1' = '7FDEEE00-6641-4E27-A54E-82ACCCE14D00'
            '10.8' = '7D432555-69F9-4945-8EE7-FC4503A94D6A'
            '10.8.1' = '0803DE56-BAE9-49F5-A120-BA249BD924E2'
            '10.9' = '46FDB40E-6489-42CE-88D6-D35DFC5CABAF'
            '10.9.1' = 'B5C5195E-2446-45F9-B49E-CC0E1C358E7C'
            '11.0' = 'EB809599-C650-486A-85C6-D37618754AE4'
        }
        WebStyles = @{ 
            '10.7.1' = 'B2E42A8D-1EE9-4610-9932-D0FCFD06D2AF'
            '10.8' = 'EF31CB36-2EB4-4FD3-A451-AC12FD22A582'
            '10.8.1' = '7748EA55-04FF-45E2-98EC-C78095AC25AA'
            '10.9' = '0A229482-5C33-4E93-AB5B-614ED0CAFBE7'
            '10.9.1' = '2E63599E-08C2-4401-8FD7-95AAA64EA087'
            '11.0' = 'CCA0635D-E306-4C42-AB81-F4032D731397'
        }
        DataStore = @{             
            '10.4' = 'C351BC6D-BF25-487D-99AB-C963D590A8E8'
            '10.4.1' = 'A944E0A7-D268-41CA-B96E-8434457B051B'
            '10.5' = '5EA81114-6FA7-4B4C-BD72-D1C882088AAC'
            '10.5.1' = '75276C83-E88C-43F6-B481-100DA4D64F71'
            '10.6' = '846636C1-53BB-459D-B66D-524F79E40396'
            '10.6.1' = '53160721-93D8-48F8-9EDD-038794AE756E'
            '10.7' = '2B19AB45-1A17-45CD-8001-0608E8D72447'
            '10.7.1' = '112E5FD0-9DD2-45DA-ACD5-A21AA45F67E2'
            '10.8' = '2018A7D8-CBE8-4BCF-AF0E-C9AAFB4C9B6D'
            '10.8.1' = '45E1C306-B1AB-4AE5-8435-818F0F9F8821'
            '10.9' = '7A7D3A39-DBC0-48E8-B2C2-3466A84FE89E'
            '10.9.1' = '30BB3697-7815-406B-8F0C-EAAFB723AA97'
            '11.0' = 'ABCEFF81-861D-482A-A20E-8542814C03BD'
        }        
        GeoEvent = @{             
            '10.4' = '188191AE-5A83-49E8-88CB-1F1DB05F030D'
            '10.4.1' = 'D71379AF-A72B-4B10-A7BA-64BC6AF6841B'
            '10.5' = '4375BD31-BD98-4166-84D9-E944D77103E8'
            '10.5.1' = 'F11BBE3B-B78F-4E5D-AE45-E3B29063335F'
            '10.6' = '723742C8-6633-4C85-87AC-503507FE222B'
            '10.6.1' = 'D0586C08-E589-4942-BC9B-E83B2E8B95C2'
            '10.7' = '7430C9C3-7D96-429E-9F47-04938A1DC37E'
            '10.7.1' = '3AE4EE62-B5ED-45CB-8917-F761B9335F33'
            '10.8' = '10F38ED5-B9A1-4F0C-B8E2-06AD1365814C'
            '10.8.1' = 'C98F8E6F-A6D0-479A-B80E-C173996DD70B'
            '10.9' = 'B73748C3-DD75-4376-B4DA-D52C59121A10'
            '10.9.1' = 'F5C3D729-0B74-419D-9154-D05C63606A94'
            '11.0' = '98B0A1CC-5CE4-4311-85DD-46ABD08232C5'
        }
        NotebookServer = @{
            '10.7' = '3721E3C6-6302-4C74-ACA4-5F50B1E1FE3A'
            '10.7.1' = 'F6DF77B9-F35E-4877-A7B1-63E1918B4E19'
            '10.8' = 'B1DB581E-E66C-4E58-B9E3-50A4D6CB5982'
            '10.8.1' = '55DE1B3D-DDFB-4906-81F2-B573BAC25018'
            '10.9' = '9D0291C2-D01E-4411-A2D8-BB42740C9ECC'
            '10.9.1' = '39DA210D-DE33-4223-8268-F81D2674B501'
            '11.0' = '62777D3B-5F08-4945-8EA2-C2B518D88AEA'
        }
        NotebookServerSamplesData = @{
            '10.9' = 'C2ECEE9C-961A-4EAF-9BD4-9FB0EBCFA535'
            '10.9.1' = '02AB631F-4427-4426-B515-8895F9315D22'
            '11.0' = '2F9BC4EA-B2D9-43C6-98CA-06A9DDFB6A63'
        }
        MissionServer = @{
            '10.8' = 'A1A58B32-2ADF-4EAD-AC84-BE97318CA569'
            '10.8.1' = '26F574C6-C9F8-487C-977A-A906AAA60136'
            '10.9' = '94280A6F-6501-42CE-A627-FCE20B01A9D7'
            '10.9.1' = '2BE7F20D-572A-4D3E-B989-DC9BDFFB75AA'
            '11.0' = 'A0E25148-B33D-442F-9EE4-B35AEC2DEA6D'
        }
        WorkflowManagerServer = @{
            '10.8.1' = 'C0F0FCAB-2B65-4B8E-8614-531690B7CF9C'
            '10.9' = '80C5D637-B20F-4D11-882C-33C17918EF0E'
            '10.9.1' = '9EF4FCC5-64EE-4719-B050-41E5AB85857B'
            '11.0' = '1B27C0F2-81E9-4F1F-9506-46F937605674'
        }
        WorkflowManagerWebApp = @{
            '10.8.1' = '96A58AC8-C040-4E4A-A118-BE963BF1A8CF'
            '10.9' = '28F45C9F-9581-4F82-9377-5B165D0D8580'
        }
        Monitor = @{
            '10.7' = '0497042F-0CBB-40C0-8F62-F1922B90E12E'
            '10.7.1' = 'FF811F17-42F9-4539-A879-FC8EDB9D6C46'
            '10.8' = '98AA3E79-18C5-4D51-9477-C844C6EBC6F3'
            '10.8.1' = 'F2E2767F-B7FB-43DD-A682-31544DF29D48'
        }
        Desktop = @{
            '10.4' = '72E7DF0D-FFEE-43CE-A5FA-43DFC25DC087'
            '10.4.1' = 'CB0C9578-75CB-45E5-BD81-A600BA33B0C3'
            '10.5' = '76B58799-3448-4DE4-BA71-0FDFAA2A2E9A'
            '10.5.1' = '4740FC57-60FE-45BB-B513-3309F6B73183'
            '10.6' = 'F8206086-367E-44E4-9E24-92E9E057A63D'
            '10.6.1' = 'FA2E2CBC-0697-4C71-913E-8C65B5A611E8'
            '10.7' = 'BFB4F32E-38DF-4E8F-8180-C99FC9A14BBE'
            '10.7.1' = '69262D87-3697-492B-ABED-765DDC15118B'
            '10.8' = '3DB5C522-636F-4FC2-9C38-298DBEBFD0BC'
            '10.8.1' = '7C4FF945-CE6A-415E-8EB9-2B61B0B35DCD'
            '10.8.2' = '791AB03F-1AF2-43FE-8F5D-8FDC9509D7CF'
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
        }
        Pro = @{
            '2.0' = '28A4967F-DE0D-4076-B62D-A1A9EA62FF0A'
            '2.1' = '0368352A-8996-4E80-B9A1-B1BA43FAE6E6'
            '2.2' = 'B5E1FB35-5E9D-4B40-ABA5-20F29A186889'
            '2.3' = '9CB8A8C5-202D-4580-AF55-E09803BA1959'
            '2.4' = 'E3B1CE52-A1E6-4386-95C4-5AB450EF57BD'
            '2.5' = '0D695F82-EB12-4430-A241-20226042FD40'	
            '2.6' = '612674FE-4B64-4254-A9AD-C31568C89EA4'
            '2.7' = 'FBBB144A-B4BE-49A0-95C4-1007E3A42FA5'
            '2.8' = '26C745E6-B3C1-467B-9523-727D1803EE07'
            '2.9' = 'AD53732E-507C-4A7F-B451-BE7EA01D0832'
            '3.0' = 'FE78CD1B-4B17-4634-BBF7-3A597FFFAA69'
            '3.0.3' = '690B606E-8A38-4CB9-B088-241F60A86072'
        }
        WebAdaptor = @{
            '10.4' = @('B83D9E06-B57C-4B26-BF7A-004BE10AB2D5','E2C783F3-6F85-4B49-BFCD-6D6A57A2CFCE','901578F9-BC82-498D-A008-EC3F53F6C943','E3849BEC-6CAF-463F-8EFA-169116A32554','EE889E4F-85C7-4B8A-9DAA-5103C9E14FD6','89D96D88-CC2F-4E9B-84DD-5C976A4741EE','0913DB77-F27B-4FDE-9F51-01BB97BBEBB9','99B6A03C-D208-4E2E-B374-BA7972334396','A0F3D072-0CD1-43D7-AFDA-8F47B15C217C','0FE26871-21C3-4561-B52E-A8FED5C8E821','1D1F3C15-F368-44AF-9728-6CF031D478AF','CE5EC52D-B54D-4381-9F6E-2C08F7721620','E71AEC5B-25F0-47E5-B52C-847A1B779E48','5DA1F056-A3F1-46D5-8F2E-74E72F85B51B','1EB3D37A-902A-43E2-9EAA-1B43BA10C369','839FFEB7-76B5-4CBB-A05E-E2276FC3421D','594E1C33-1C6D-49B4-A83F-2A780193B75F','34330B0C-34CD-4DCF-A68D-FDE7A1834659','42A96EC7-7CA9-4F68-B946-E9BF84713605','A1A8DAE4-B6F9-446F-8F6A-487F1E07A434','3BF277C6-6A88-4F72-A08C-54F1E45F44E5')
            '10.4.1' = @('F53FEE2B-54DD-4A6F-8545-6865F4FBF6DC','475ACDE5-D140-4F10-9006-C804CA93D2EF','0547D7D8-7188-4103-9387-A99FE15215AF','25DFAFFF-07CE-42A2-B157-541D7980A3DA','771998A8-A440-4F5F-B55A-0FE2C594208B','C120DC32-DBEA-4CB1-94E4-F50A7EE09F5C','3294151B-CA4C-4A89-BBC7-DCE521D8A327','E04FB941-248D-4806-9871-04DB306EEA91','66CD667D-440D-4CF1-9ECB-C6C77A7A0520','7938463B-E744-4332-8617-39E91B10FC15','C22C2AF5-D58E-4A4D-85DF-E3A38C83F37A','9AF62D15-755B-43DE-878A-DBA23D33B28A','D4F22207-C5FA-49B0-9466-9E4D37435882','C8ADE9B2-3BC8-4417-97D0-785BA0CD86D9','C85A40C5-00B9-4CDE-9299-397BFD5A2EAF','E0BD73FB-4028-4A5D-9A24-9FA0BD614D4B','83CF76EC-F959-46B3-9067-F59B2A846D2F','F7D6BD55-8D07-4A57-8284-ADACE0F567D8','C56A0E47-D4E1-4762-9BAF-07A19A154EE6','09AC608B-7CE4-4280-9F4E-F2988A58428D','5695B2B6-A25E-4013-B5F8-30686FDDFE0D')
            '10.5' = @('87B4BD93-A5E5-469E-9224-8A289C6B2F10','604CF558-B7E1-4271-8543-75E260080DFA','9666ABD8-8485-4383-B3DD-4D1598F582A3','58264BBA-5F61-41D9-839A-00B6C2C66A63','5988C905-772F-4F62-8339-1796C38674B7','ADD5FF4F-EB57-4460-BD33-D55562AE6FA7','3294151B-CA4C-4A89-BBC7-DCE521D8A327','EF65064A-96C8-4EA1-B76D-B9BCC97EF76A','6B2FA0A8-6F2C-4359-B7A4-D2F9FD63EE97','ACF59C57-A613-44CC-A927-1D8C2B280516','2E5E4CDE-9964-4B40-A1F1-843C62AC789E','2901A5D3-C16D-4993-A306-86261B0430B1','AC910B51-6077-4055-B042-D72CA0D23D69','8F36D583-35F0-43F2-8F8F-5B696F87183A','37C2CAE2-4A81-4289-B318-93D63C63AA47','CC345B69-1E26-4C56-B640-92BCBADBDF06','F0FAE80D-0C51-4D9D-A79B-057396A2456D','5BA355D1-D9B6-4CA0-B1C6-694377084464','25118D44-AD2D-423F-85F0-5D730A2691B7','D4855344-CEE0-47A3-BD50-D7E2A674D04E','9CD66AA3-F0DA-46CC-A5DD-0BB5B23499AD')
            '10.5.1' = @('0A9DA130-E764-485F-8C1A-AD78B04AA7A4','B8A6A873-ED78-47CE-A9B4-AB3192C47604','7DEAE915-5FAC-4534-853D-B4FC968DBDEB','AC10F3CF-A5C1-44B0-8271-27F26D323D14','5F748B0C-3FB6-42FF-A82D-C1573D3C1469','428DE39D-BF23-42B5-A70E-F5DD5DD21C2C','98B1DE9B-0ECF-4CAA-A29A-B89B2E8F38F1','4876508B-31CF-4328-BE11-FFF1B07A3923','D803A89F-4762-4EFD-8219-55F4C3047EDE','4A5F404B-391F-4D13-9EE4-5B9AC434FD5A','99FFFA13-2A40-4AA4-AAC1-9891F2515DB1','2B04DE60-3E79-4B44-9A93-40CAC72DE2FB','D595C9E2-BBA0-4708-A871-1166CD0CFB61','50825C57-5040-436D-B64C-A53FFB897E9D','5D750A11-BC80-45CE-B0DD-33BA8A5D8224','60390703-9077-4DDE-8BB1-A025AB0FE75B','BF75DC6C-F1A5-4A3C-A6A6-76BCB5DB5881','96B29B2F-888A-4C2B-B8C3-97E9A7849F2F','7FDD9158-2E93-4E12-A249-CD9D5445C527','A868CBAC-D9A2-41A7-8A5B-069AB63FEC7B','83462AE4-27BB-4B63-9E3E-F435BD03BB12')
            '10.6' = @('4FB9D475-9A23-478D-B9F7-05EBA2073FC7','38DBD944-7F0E-48EB-9DCB-98A0567FB062','8214B9D8-49D9-43DB-8632-AE2BAD4B21E9','B3FD1FE3-4851-4657-9754-73876D4CB265','88CDE5E9-23B8-4077-9E69-9CD3715BE805','E7630CBC-96DE-4665-9C2A-D682CFFD5B0E','E2601F84-D2E5-4DD4-B0EC-6AED75CB77D9','75FB755F-AF36-484E-98A8-FADA56574D25','AA32D01D-27CD-4842-90CF-F22C1BD6309B','CF126207-4C89-44AA-8783-9BAA2BA5F106','9F8694BE-613F-4195-AA42-B849E84D059A','2C3BE00F-57BE-4D0B-81BC-3378D823CF0E','EAC54B65-D6BC-41DC-8C82-5E99D7FD4271','76C17CB6-106C-41F8-89BA-41C086E69238','4493EB64-CAE0-439F-8FA6-897677D5A6C8','0C59A27D-B4B6-4A23-8873-897B870F6E2B','B46B6E63-D8E1-4EA4-9A9B-D98DFAA6644D','89E6330E-6139-4F4B-BA9F-ACD59065230D','238E647E-53DF-4B8B-B436-ADA5004065DE','30EF8944-904A-45D3-96D4-7DF3B0FE01D5','06012CC0-5C12-4499-B5CC-99E9D547A2FD')
            '10.6.1' = @('1B4E7470-72F4-4169-92B9-EF1BDF8AE4AF','3FA8B44E-E0E3-4245-A662-6B81E1E75048','8D6EE2C0-A393-49CD-A048-1D9FD435D7B8','6C05375F-78A5-4DF7-A157-C2A6E0D7BAD2','1F1EEC9F-80D5-48DD-B8BC-EB3D0404D9AD','2CA5FC7F-1165-4870-9C16-004ACC848435','E23D8BB8-0FEB-4316-8E09-80772FD1B5E0','C67E73AB-8278-49C9-9CA8-A714E20B8124','E527C0BD-E026-46D8-9461-2A7EEFBDA35A','D5DF4279-E3FF-4261-AB85-93F8BDE90D8D','8D439456-493A-4B48-A542-492AABD9CF7D','D61CE1AE-2DB8-4D46-AC7F-3BEAB7C29A59','9B07A4CE-58C6-4689-B37B-EFF565712CF2','C97C2CEF-F939-496E-8CB7-8756856CBBC6','59079961-A0BA-48DD-9B07-45437FCBC42A','5372DAF1-7EB6-4822-843E-0B2F7A7B052B','D807F4E9-0F87-4B3C-8F93-456251226187','7BEB71AD-3958-41FB-8EC3-64DBE4775760','286D4CB5-777E-4AA1-B2EB-D6A3A4212107','37F3B528-915F-4528-949B-F199E4B3B4AA','6FEB4C76-14AC-4A70-BE45-6CBAED529CAF')
            '10.7' = @('F343B520-F769-4D93-86D2-663168AC6975','58A76431-E1A9-4D11-BB89-0D12C6E77C78','E7B9D4A3-4E55-49F8-B34C-CA8745FFD894','D89709DB-8B6D-431A-95D4-FFEB69C474D5','858283F5-B9E9-4688-BF3C-BD3F3FD169D8','DE2BA579-D2F0-4068-9C52-8AC24022F13D','48405A7D-CFA4-4F6F-BB8C-B36A22E99B07','BEC99E10-7AB1-4B90-9C81-D2CBFCAD4239','C0C178B9-EBC6-46C5-B009-186661E9AEA3','0D5F9D8E-B221-4C74-87C3-13050F906A94','52EC0A7A-9BBA-4F47-9C52-2E1D1D09D9B4','6CF9C794-AEC2-45EF-A11A-83938F01A1E9','F36AF2F5-2E37-409B-9E71-D2D2B1D4A22F','4F54A93E-2F0F-4515-99AA-83BF88961D5F','A04ACEF7-4E22-4F4F-8608-9FD335572C6F','0D562427-2AB5-46C6-998E-4C33D642DE10','8C15E459-D24F-46E0-B945-CD4812A040AC','24821676-BD09-49CA-95B4-591BBE86118A','3C4D06FD-8194-4062-AB04-E87003CBE908','71044157-41F9-4AEC-B6B1-834FBA256135','C4ECCD46-EC43-4C44-8147-916649A2BA1B')
            '10.7.1' = @('5ECEF84F-592C-47D1-B7C5-9F3D7E2AB7CE','5F1D01EA-296E-4226-A704-6A90E2916782','7368D3C8-F13B-4786-AE38-B51952F43867','2C838C64-DF81-4A64-8618-072AD30D51C1','D4054E1B-C75C-4F69-BBB7-DBE77250F345','C2C75F23-3E15-43E4-A902-673569F3F0DF','F633A04F-D08B-4EBF-B746-00ADA0334CE3','7D13D8C5-751F-44B1-BEAE-C9EB8E13FDF8','ACAA0479-B7C5-44A1-B5FD-34A018EA2137','E0343824-0C94-4A6C-96F7-AA5E1D8F8437','8D108926-DC71-493D-B2C9-8BAE04DD9047','A19DF635-25F0-4371-AC42-A4EECAF8BD75','78F54FC8-C530-4D7E-91CC-48B9BC364535','CEFB5C80-707B-471A-B8BF-5EC333F1A8B2','BE892BB6-842B-4A18-A0B7-E89C5AAAD1A3','A11006D2-3C1A-4D56-917D-4417D3341ADD','763E3951-E827-492B-8E86-F526F251083E','57C506AE-3BB7-4936-9154-7A2744735456','4E2BA3D3-EFD2-4FCE-91C0-1D15457F8F08','1BBB3C99-8EF5-4225-B5DD-799E50582BF7','F6E99E06-B303-4965-9566-2F21EE7FD130')
            '10.8' = @('D6059C27-7199-4A94-806B-6C40EFD02828','E77ED9CA-7DC8-45FC-A8BB-57AD2096EF8A','068CA630-558A-4C4A-983F-ECF5F8183FC9','F168EBD1-CEDA-469B-89E4-E79C85253CB6','96229607-EC9D-4805-AF94-E1AC47676586','D89375FD-6CAC-4204-8761-22F51B39E6A1','BABA485F-681E-4B5D-95EF-54CC738F4A0C','AEFE7DEE-1EEE-4F99-BCA7-2193B86C7058','FC4B3333-7AEB-46C6-AD90-E071A18D653F','119C0DB0-02B8-442C-B3F5-999D99C9D42F','89946E15-3E27-4F13-946F-30205F18D34B','5B21D9CD-DDC8-4768-88F6-3C0633E7B97E','C0752042-FAAC-4A94-B5A4-918BE46B7595','751ED05E-63BF-407C-9039-C72F33CC73D4','720EDDD5-B0FD-4E53-8F80-0F328EA8ABE0','5FBFC270-1AEE-4E41-B7A2-47F7C742EF95','A46D3ECC-39D2-459C-9BC3-1C780CA5BCF1','CAE80A6F-8046-47CE-B3F6-D2ACEDDDA99A','0B5C6775-B1D2-4D41-B233-FC2CDC913FEE','278663A9-7CA3-40D5-84EA-CA7A9CABACB6','9452D085-0F4F-4869-B8B4-D660B4DD8692')
            '10.8.1' = @('9695EF78-A2A8-4383-AFBF-627C55FE31DC','56F26E70-2C61-45BC-A624-E100175086F7','996B7BC1-3AF4-4633-AF5F-F7BE67448F51','0FB565D2-7C0E-4723-B086-C67443ADE5FD','246A7BFA-BE78-4031-A36D-F7BB95FFC5E2','7D3E447C-3DB7-488D-AB11-C84A02476FF5','1B5B7A25-F639-44F8-987B-6CD8F88967BE','4242D730-262E-45E0-8E1F-9060F03452C3','7CF4D730-F1D6-4D01-B750-D1BA7E55C3CC','179DB6A6-DFE4-4AF1-92D5-2FDDD831A783','0F67B656-1ED6-4C87-9DB3-DA51ABEE40C0','86F8D877-87EA-4296-9D48-64D7AE94330B','80FEB406-8086-42FE-B14B-C45A96B36894','5990ACD0-4A80-4115-BFAE-F8DEB498A7C0','12E78447-5AD7-41DB-82E5-BEDAAE7242C0','25A1ECD8-4FAA-4271-9586-6FD94549365D','221CCAE0-DA79-4C5E-ABCA-396E827334B1','508FBAA8-FD44-4998-B797-1666BD41D804','23EB5093-17EE-45A0-AE9F-C96B6456C15F','BEB8559D-6843-4EED-A2ED-7BA9325EF482','A12D63AE-3DE9-45A0-8799-F2BFF29A1665')
            '10.9' = @('1FD4759C-6858-42AD-A1DC-6DA0C3B1D28C','E3CBD7DB-60AE-45F3-B281-F9556781E602','D712233D-C35F-4A04-A7E8-6D3F00A40544','D5EBAE28-7A5C-41E7-A04F-A1AAFF75C8AC','2F798220-41AF-4D8D-B425-98095F3DC287','06B94095-F4F9-4434-8358-2E84965B6301','F2C06411-06A3-4617-8577-7975BD6CC32E','10C21BB5-7E8C-47F6-AB6E-AC62300EA034','B0D3E289-039D-470C-A9DC-1EB9713B2458','35838A3A-D572-4B2B-8C83-4F8A99324F92','CEEC063C-D280-490E-B795-373E7DE6266A','4CB4458D-C08A-4DE8-9D0B-45C4E0B849F9','83605278-1596-4C33-8484-CF2BD4C07587','A2AE04B5-879C-4E0A-B237-D642D8BBE3C7','38E1E357-BA81-4135-A11A-51FBC9C858DC','947676E2-B5A6-49CB-A5AA-DFEB54D8F064','8E838EF7-0B7D-4E2A-AF21-4639AC6E5492','37913C5B-A6BA-4F1D-B12F-AD505B91D05A','1C9C9C3C-CE4D-4F42-8A3B-78ECA6C57B8E','0C000BEA-E770-4138-A707-CCB02E64469A','D5CEFB24-D0FD-4C73-8685-205222E08C12')
            '10.9.1' = @('BC399DA9-62A6-4978-9B75-32F46D3737F7', 'F48C3ABF-AF5F-4326-9876-E748DB244DB7','AC4AD5BF-E0B4-4EE6-838E-93EE66D986EF', 'F96ECEFD-2015-4275-B15D-363F53407390','21B1638E-47E7-4147-B739-EB341F99986F', '78ABEA6E-4832-4087-B7BB-04746D1E83E8','A624163D-A110-4959-BD82-98CB7CE6ECBE', '7A6E0537-43A2-4925-8F8A-E19715B21392','4AE1AE3D-2471-4393-B0D9-ECB4D1368EB9', 'C72DE321-E19C-4737-9513-AE39B1A32953','49F98C43-955D-4BD8-A585-07BA45D72D0A', '5DD68937-54F9-4015-A8DA-4602AFCA8986','D3C16E17-DAB1-4025-A029-46C7598DCA4A', 'A2CBD39F-C2DE-4983-9C70-7F108B52F402','CA174887-E7C6-4DE9-8797-72CBD7FC4B1C', 'B658575F-82ED-49BE-980C-D4A5089FCA7A','CBEE526A-29B6-46FE-B7F8-B930A785CFF8', '76618450-9F2C-4FCC-9CDA-01A61F9E1953','17591EF3-221C-4DD1-B773-6C9617925B5F','566920BF-1EF3-4E62-B2BF-029475E35AAB','4A3B27C6-7CB1-4DE8-BCB1-221B9A23E2E1')
            '11.0' = @('FCC01D4A-1159-41FC-BDB4-4B4E05B3436F','920A1EFA-D4DC-4C6D-895A-93FDD1EDE394','258F0D35-985B-4104-BCC4-B8F9A4BB89B4','7B128234-C3D8-4274-917F-BC0BCE90887F','CD160BB2-3AA9-42CE-8BA0-4BFF906E81DE','BBBD3910-2CBB-4418-B5CE-FB349E1E74F0','594D4267-E702-4BA8-9DF4-DB91DCF94B3E','D2538F6E-E852-4BE0-9D20-61730D977410','BAB5BA8A-DE70-4F79-9926-D6849C218BF2','E37D4B50-05EC-4128-AC65-10E299693A3C','2BD1FC31-CFB0-488A-83B3-BEC066423FAA','AA378242-0C2C-4CC2-9E33-B44E0F92577C','F00D0401-C60F-4AB1-BCF2-ADA00DF40AA9','5AE7F499-C7A3-4477-BBED-3D8B21FF6322','5147A262-75C3-4CAE-BCF0-09D9EBBF4A24','7D3F3C7C-A40D-42EC-BA38-E04E6B3CFA16','36305F97-388A-4427-AF76-C4BA8BC2A3DC','BB3F184D-C512-4544-8A7D-76A1F600AEC2','A4CEFD65-D3DF-4992-AC4A-2CED8894F0BF','36B75654-E4C2-4FF3-B9F7-0D202D1ECAC8','0E14FDF9-3D6C-48E4-B362-B248B61FC971')
        }
        Insights = @{
            '3.4' = '4230C365-8713-4A13-93BA-6016BE47ECAE'
            '3.4.1' = 'F3B91D92-3DD8-4F0B-B43B-6F9DA2C1830A'
            '2020.1' = '5293D733-7F85-48C8-90A2-7506E51773DB'
            '2020.2' = 'A51F92FD-3A9D-467C-B29F-74759CB85E0A'
            '2020.3' = 'A423A99B-D785-49F9-B91B-E39457B6B6D5'
            '2021.1' = '6C55A753-1D58-4BD6-BD2E-7D57433F835E'
            '2021.1.1' = '67E5DAD3-A014-44D7-9CF1-35AF8C7117D4'
            '2021.2' = 'E7C79A1B-DB5E-48A9-846B-B648FCAD7A12'
            '2021.2.1' = '749A02F9-D417-449A-9AF5-1D116E080790'
            '2021.3' = '64066B1D-7BF6-42DD-98F1-03D5146EC890'
            '2021.3.1' = '2EFCCCED-8C84-4A76-B2B7-4680195E9FD4'
            '2022.1' = '76A44AB1-68B5-4762-8C1C-5CBD97AC5E2C'
            '2022.1.1' = '33B5B7A9-448D-4DEA-92C0-F8046E685553'
            '2022.2' = 'E1B018A2-C615-4CDA-AC51-8F1EDE8492AF'
            '2022.3' = '09230105-BBD4-401B-AB77-3E221BAD668F'
        }
        ServerDataInteroperability = @{
            '10.6' = 'D603B058-F1BA-4DD4-92E0-8F9498FCB16C'
            '10.6.1' = 'E653824F-7C0E-4F02-8383-EDF801126E99'
            '10.7' = 'F826D109-412C-4A3C-9496-8335132856D7'
            '10.7.1' = '0950170A-DC28-410C-B475-A2056E446501'
            '10.8' = 'CF608831-5C85-4896-B601-C873E7D9B25A'
            '10.8.1' = 'DD893054-9F88-474C-95D4-F169F29DC7F0'
            '10.9' = '1C69B559-2141-4230-868C-F1915D9B70A4'
            '10.9.1' = '26A934BC-212C-4F90-8DFF-9900437D303B'
            '11.0' = '338D8E88-3791-4578-A9DC-82D83CF0806B'
        }
        DesktopDataInteroperability = @{
            '10.6' = 'DD635BA7-E87B-4FD6-9315-3AD9873E1961'
            '10.6.1' = 'EA280AEA-FA8A-45C1-9EF7-C82B9642C82C'
            '10.7' = 'FB0D5A51-C4EE-42CE-BAF0-96ADD1E87AF9'
            '10.7.1' = '41C39820-FF98-4F7B-B0B0-2DB851B20A64'
            '10.8' = 'C598BA10-D8C5-4627-A480-1D2C7A60D0FD'
            '10.8.1' = 'F429D9C3-FD0E-4525-BE0A-617A1FB59326'
            '10.8.2' = 'DBA13F17-67C9-42C4-920C-24A25BA49698'
        }
        ProDataInteroperability = @{
            '2.0' = '90104667-B575-4F77-AD95-2A8EC7FB2304'
            '2.1' = '104DD66D-557A-4004-9A93-9C418E40DE94'
            '2.2' = 'FB89E9BB-C18C-4902-8E3C-22C97DF64385'
            '2.3' = 'B3F8426F-F9E6-406E-9D73-EB7351F1391C'
            '2.4' = '15EEA5E7-AF9A-44FF-AB61-5EC64BF722A6'
            '2.5' = '8EB6B440-9C8E-4739-A4FD-1B7438A14499'	
            '2.6' = '9F366C17-E615-4C55-85E9-F646C4A30A0B'
            '2.7' = 'A9BD7866-71EE-4FCB-9AB8-FE03BEA78C32'
            '2.8' = '918560B6-96AE-4002-987D-41DE7706F879'
            '2.9' = 'DE8B6635-C3F9-4566-B0C9-F0A90C17E5A1'
            '3.0' = '3AFB366C-9CA0-483B-A773-680216789FE6'
            '3.0.3' = '78E79722-2A97-4CA9-A3FF-B45D3DD7D7FA'
        }
        ServerDataReviewer = @{
            '10.6' = '1659E374-3210-48F9-856F-7AC959D2EB6F'
            '10.6.1' = '0E158FA1-3021-46E7-8C8A-042AA4350D36'
            '10.7' = 'CC95AED9-06A0-4394-ADE4-2305C108C6FD'
            '10.7.1' = '2B0CC75F-AD24-4F85-878D-37408E9A4297'
            '10.8' = 'E3112732-C0A4-43AF-8C02-E500CDAF10FF'
            '10.8.1' = '11325011-C503-4C8D-AA14-A26816FF56DE'
            '10.9' = '746D3948-2EF3-41F0-AD53-5D7739420A5D'
            '10.9.1' = '907233F9-A534-4483-AB2A-1EA0E7328BE3'
        }
        DesktopDataReviewer = @{
            '10.6' = 'CD2D4B77-5B9A-4CCB-9F7D-8AFF3B7CAEE4'
            '10.6.1' = 'B2660BD2-9CA7-4946-907E-0B3BCDB783F3'
            '10.7' = '780F7310-19D5-432F-820F-11430E357A3B'
            '10.7.1' = '715D6D96-D3BE-44A9-A400-5E204EDB7CBB'
            '10.8' = 'F22C3DB5-0374-4227-807D-A5AC12BFEEBC'
            '10.8.1' = '1A5448B7-AACD-42D2-B58E-953D6F6D247D'
            '10.8.2' = '2DAD85A3-E0B6-4948-B0E2-433D572CAC73'
        }
        ServerWorkflowManagerClassic = @{
            '10.6' = 'F0553C08-337E-4C10-AD64-F2E8A5457483'
            '10.6.1' = '816E8417-B450-4449-A660-1B98A4665FF7'
            '10.7' = 'FBF6F647-730E-40C6-97A2-B309127EFAEE'
            '10.7.1' = '2CCB468C-1534-4A70-8DBB-79083A01E0E5'
            '10.8' = 'A32F405C-5DFD-4470-92C6-CFC10514E1C0'
            '10.8.1' = '605F940D-4166-464E-BC7E-6DFCE61D9B59'
            '10.9' = 'DAEB8424-B81E-4B2B-A810-F55CD9E824C3'
            '10.9.1' = '71FDEA4A-4411-42AC-930C-B65453A48E07'
        }
        DesktopWorkflowManagerClassic = @{
            '10.6' = 'CB6C6444-6F6B-4FF1-8BFC-46D528D59C50'
            '10.6.1' = '0C05EC3A-31E3-4530-B89F-FD51FB4822FB'
            '10.7' = '2DD96926-CA3A-4F22-BC37-9396D6AF0994'
            '10.7.1' = 'FCC76F40-4B99-420B-854F-C0EE4D528090'
            '10.8' = '952B019D-51A5-4FF9-99F1-0B78108F1AD3'
            '10.8.1' = '0D449C48-01C1-4BB4-BFB1-DC478AB0BE37'
            '10.8.2' = '4A933372-8984-4A17-B4C5-16B2BA05246D'
        }
        ServerLocationReferencing = @{
            '10.6' = '21313BBC-BD85-4C6E-A014-E411DAD7B9FB'
            '10.6.1' = '30744A19-F755-4E5D-BBB5-0793AA1D5D95'
            '10.7' = 'E426CC35-3A0A-4592-88C1-BDABDCFBC474'
            '10.7.1' = 'F085B6FD-56FC-4DD4-A173-626538B590B0'
            '10.8' = '112A6F66-24F3-4EE3-AC9B-99699B090FA5'
            '10.8.1' = '917DAA9D-4CF1-4B02-9A3F-E5A602B69001'
        }
        DesktopLocationReferencing = @{
            '10.6' = '7D10A45E-61B3-4D11-89DC-1319A82B6229'
            '10.6.1' = '23CCEE36-BA62-402C-8093-0307FE5D71E3'
            '10.7' = 'D761218F-38F7-4789-8F7C-EC938490AFD5'
            '10.7.1' = '84776953-163A-4F6E-B452-80F2CBA95378'
            '10.8' = 'B70B2469-9CB6-46BB-B68D-E6F9DD93E076'
            '10.8.1' = '505F351D-546C-456A-99E0-100C8849BAF5'
            '10.8.2' = '481FE031-95FA-4F9E-8C2C-38172B92FD9B'
        }
        ServerMappingChartingSolution = @{
            '10.6' = '99AEF0E8-F02E-4D39-81EE-61069DFF4A8B'
            '10.6.1' = 'A4473561-043A-4424-BF2C-2ED0B7ED5528'
            '10.7' = '54B88944-4E07-4C9E-9269-EB3B5FEC5005'
            '10.7.1' = '63A22C38-5333-45D6-9BF6-19D079973934'
            '10.8' = '814ABE31-0CC8-4FF5-B4AC-805792AFA5DF'
            '10.8.1' = 'A05B2B55-6D79-4BDD-9953-5BC209D572C7'
            '10.9' = 'DA940082-21CA-4B95-A84B-C4FA1FADBA48'
            '10.9.1' = 'D461F83B-0FFB-4AB0-92FE-F82DA370E5F3'
            '11.0' = '12F0B974-5A37-4902-8CFA-C28C2938A7C2'
        }
        DesktopMappingChartingSolution = @{
            '10.6' = '5B03CF31-A5D5-47E4-A90F-9DB96B347542'
            '10.6.1' = '72E6AC26-6738-4C28-8627-4535D18DAE9E'
            '10.7' = '1644CA9F-0AD6-4655-B269-23A439C76812'
            '10.7.1' = 'CC64068F-E062-4FA2-95DB-ABAB75A98948'
            '10.8' = '3244667E-C4CC-46DA-8C2E-0891C765EB44'
            '10.8.1' = 'CA93D266-9313-4F55-8CEC-4BBD50552A7A'
            '10.8.2' = '5032F46D-CCC9-4E22-8871-289BDC1FD2A3'
        }
        DesktopBackgroundGP64Bit = @{
            '10.6' = 'D9A37390-98EF-4DDD-BD1E-06BBADFE8CE6'
            '10.6.1' = 'E02F36E6-2ED8-47A9-A6D2-C7C9AEFDE364'
            '10.7' = 'F4A727FC-1E11-4380-8171-5E4FF508E6CB'
            '10.7.1' = '39E26603-505E-4CE3-ABC6-5721CADF41D3'
            '10.8' = 'C28E8BF1-8707-40D3-A048-15C965475A09'
            '10.8.1' = '1EBC0FD8-8A64-4E8C-9565-F9784A3B96D2'
            '10.8.2' = 'DE0069B6-F646-49BB-82EC-8E29F5CE8937'
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
            if($Name -ieq "WebAdaptor"){
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
            if($Name -ieq "WebAdaptor"){
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
                $result = $true
            }
            if(-not($result)){
                $PathToCheck = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$($ProdId)"
                Write-Verbose "Testing Presence for Component '$Name' with Path $PathToCheck"
                if (Test-Path $PathToCheck -ErrorAction Ignore){
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

function Get-DataStoreBackupLocation
{
    [CmdletBinding()]
    param(
        [System.String]
        $DataStoreInstallDirectory,

        [ValidateSet("Relational","TileCache","SpatioTemporal","GraphStore")]
        [System.String]
        $DataStoreType,

        [switch]
        $UseDescibeDatastore
    )

    $BackupLocations = [System.Collections.ArrayList]@()
    
    $TypeString = if($DataStoreType -ieq "Relational"){ "relational" }elseif($DataStoreType -ieq "TileCache"){ "tile cache" }elseif($DataStoreType -ieq "GraphStore"){ "graph" }else{ "spatiotemporal" }
    if($UseDescibeDatastore){
        $op = Invoke-DescribeDataStore -DataStoreInstallDirectory $DataStoreInstallDirectory -Verbose
        if($null -ne $op ){
            $DatastoreInfo = $op -split 'Information for' | Where-Object { $_.Trim().StartsWith($TypeString) } | Select-Object -First 1
            $location = (($DatastoreInfo -split [System.Environment]::NewLine) | Where-Object { $_.StartsWith('Backup location') } | Select-Object -First 1)
            if($location) {
                $pos = $location.LastIndexOf('.')
                if($pos -gt -1) {
                    # The output of backup location is a filepath of this format //something/like/this
                    # To be able to make a comparison with the DatabaseBackupsDirectory param (\\something\like\that) replace forward slash with backslash
                    $location = ($location.Substring($pos + 1) -replace "\/", "\")
                }
                if($location -eq "null") {
                    $location = ""
                }
            }
            $BackupObject = @{
                Location = $location.TrimEnd("\")
                Type = "fs"; 
                IsDefault = $True
                Name = "DEFAULT"
            }
            $BackupLocations.Add($BackupObject)
        }else{
            throw "[ERROR] Invoke-DescribeDataStore returned null."
        }
    }else{
        $locationsString = Invoke-DataStoreConfigureBackupLocationTool -DataStoreInstallDirectory $DataStoreInstallDirectory `
                                                            -DataStoreType $DataStoreType -OperationType "list" -Verbose
        if($locationsString.StartsWith("Backups locations for $($TypeString)")){
            $ConfiguredBackups = $locationsString.Split([System.Environment]::NewLine, [System.StringSplitOptions]::RemoveEmptyEntries)
            for($i = 4; $i -lt $ConfiguredBackups.Length - 1; $i++){ 
                $BackupArray = $ConfiguredBackups[$i].split(" ",[System.StringSplitOptions]::RemoveEmptyEntries)
                $BackupObject = @{
                    Name = $BackupArray[0]
                    Location = ($BackupArray[2] -replace "\/", "\").TrimEnd("\")
                    Type = $BackupArray[1]
                    IsDefault = ($BackupArray[3] -eq "true")
                } 
        
                $BackupLocations.Add($BackupObject)
            }
        }
    }
    $BackupLocations.ToArray()
}

function Invoke-DescribeDataStore
{
    [CmdletBinding()]
    param(
        [System.String]
        $DataStoreInstallDirectory
    )

    $DescribeDatastoreToolPath = Join-Path $DataStoreInstallDirectory 'tools\describedatastore.bat'
    if(-not(Test-Path $DescribeDatastoreToolPath -PathType Leaf)){
        throw "$DescribeDatastoreToolPath not found"
    }

    $Attempts  = 1
    $MaxAttempts = 3
    $SleepTimeInSeconds = 30
    while ($true)
    {
        Write-Verbose "Invoking Describe Datastore. Attempt # $Attempts"    
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $DescribeDatastoreToolPath
        $psi.Arguments = $Arguments
        $psi.UseShellExecute = $false #start the process from it's own executable file    
        $psi.RedirectStandardOutput = $true #enable the process to read from standard output
        $psi.RedirectStandardError = $true #enable the process to read from standard error
        $psi.EnvironmentVariables["AGSDATASTORE"] = [environment]::GetEnvironmentVariable("AGSDATASTORE","Machine")
    
        $p = [System.Diagnostics.Process]::Start($psi)
        $p.WaitForExit()
        $result = $null
        $op = $p.StandardOutput.ReadToEnd()
        if($p.ExitCode -eq 0) {
            $result = $op
            return $result
        }else{
            $err = $p.StandardError.ReadToEnd()
            Write-Verbose "[ERROR] Attempt # $Attempts - $err"
            if($Attempts -le $MaxAttempts){
                $Attempts += 1
                Write-Verbose "Trying Again. Waiting $SleepTimeInSeconds seconds. "
                if($err -imatch "ArcGIS Data Store service is not running"){
                    $ServiceName = 'ArcGIS Data Store'
                    Write-Verbose "Started Service '$ServiceName'"
                    Start-Service $ServiceName 
                    Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Running'
                    Write-Verbose "Started Service '$ServiceName'"
                }
                Start-Sleep -Seconds $SleepTimeInSeconds
            }else{
                if($err -and $err.Length -gt 0) {
                    throw "ArcGIS Data Store 'describedatastore.bat' tool failed. Output - $op. Error - $err"
                }
                break
            }
        }
    }
}

function Invoke-DataStoreConfigureBackupLocationTool
{
    [CmdletBinding()]
    param(    
        [System.String]
        $BackupLocationString,

        [System.String]
        $DataStoreInstallDirectory,
        
        [ValidateSet("Relational","TileCache","SpatioTemporal","GraphStore")]
        [System.String]
        $DataStoreType,

        [ValidateSet("register","unregister","change","list","setdefault")]
        [System.String]
        $OperationType,

        [switch]
        $ForceUpdate
    )

    $ConfigureBackupToolPath = Join-Path $DataStoreInstallDirectory 'tools\configurebackuplocation.bat'
    if(-not(Test-Path $ConfigureBackupToolPath)){
        throw "$ConfigureBackupToolPath not found"
    }

    $DataStoreTypeAsString = if($DataStoreType -ieq "Relational"){ "relational" }elseif($DataStoreType -ieq "TileCache"){ "tileCache" }elseif($DataStoreType -ieq "GraphStore"){ "graph" }else{ "spatiotemporal" }
    $Arguments = "--operation $OperationType --store $DataStoreTypeAsString --prompt no"
    if($OperationType -ne "list"){
        $Arguments += " --location $BackupLocationString"
    }
    if($ForceUpdate){
        $Arguments += " --force true"
    }
    
    Write-Verbose "Backup Tool:- $ConfigureBackupToolPath $Arguments"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $ConfigureBackupToolPath
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false #start the process from it's own executable file    
    $psi.RedirectStandardOutput = $true #enable the process to read from standard output
    $psi.RedirectStandardError = $true #enable the process to read from standard error
    $psi.EnvironmentVariables["AGSDATASTORE"] = [environment]::GetEnvironmentVariable("AGSDATASTORE","Machine")
    
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.WaitForExit()
    $op = $p.StandardOutput.ReadToEnd()
    if($p.ExitCode -eq 0) {                    
        Write-Host "Backup location tool executed successfully."
        # if($op -and $op.Length -gt 0) {
        #     Write-Verbose "Output of execution:- $op"
        # }
        if($op -ccontains 'failed') {
            throw "Configure Backup Tool Failed. Output - $op."
        }
    }else{
        $err = $p.StandardError.ReadToEnd()
        Write-Verbose $err
        if($err -and $err.Length -gt 0) {
            throw "Configure Backup Tool Failed. Output - $op. Error - $err"
        }
    }
    $op
}

function Restart-ArcGISService
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServiceName
    )

    try {
        Write-Verbose "Restarting Service $ServiceName"
        Stop-Service -Name $ServiceName -Force -ErrorAction Ignore
        Write-Verbose 'Stopping the service' 
        Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Stopped'
        Write-Verbose 'Stopped the service'
    }catch {
        Write-Verbose "[WARNING] Stopping Service $_"
    }

    try {
        Write-Verbose 'Starting the service'
        Start-Service -Name $ServiceName -ErrorAction Ignore        
        Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Running'
        Write-Verbose "Restarted Service $ServiceName"
    }catch {
        Write-Verbose "[WARNING] Starting Service $_"
    }
}

Export-ModuleMember -Function @(
    'Invoke-ArcGISWebRequest'
    'ConvertTo-HttpBody'
    'Invoke-UploadFile'
    'Wait-ForUrl'
    'Confirm-ResponseStatus'
    'Get-ServerToken'
    'Get-PortalToken'
    'Get-EsriRegistryKeyForService'
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
    'Get-DataStoreBackupLocation'
    'Invoke-DataStoreConfigureBackupLocationTool'
    'Invoke-DescribeDataStore'
    'Restart-ArcGISService'
)