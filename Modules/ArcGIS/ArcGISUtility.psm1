function To-HttpBody($props)
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
			$token = Invoke-ArcGISWebRequest -Url $url -HttpFormParameters @{ username = $Credential.UserName; password = $Credential.GetNetworkCredential().Password; referer = $Referer; f = 'json' } -Referer $Referer -LogResponse  
		}
		catch {
			Write-Verbose "[WARNING]:- Portal at $url did not return a token on attempt $($NumAttempts + 1). Retry after 15 seconds"
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

function Check-ResponseStatus($Response, $Url)
{
  $parentFunc = (Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name

  if (!$Response) { 
    throw [string]::Format("ERROR: {0} response is NULL.URL:- {1}", $parentFunc, $Url)
  }
  if ($Response.status -and ($Response.status -ieq "error")) { 
    throw [string]::Format("ERROR: {0} failed. {1}" , $parentFunc,($Response.messages -join " "))
  }
}  

function Get-LastModifiedDateForRemoteFile
{
	[CmdletBinding()]
	param(
		[System.String]$Url
	)
    $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -UseDefaultCredentials -TimeoutSec 15 -Method Head -ErrorAction Ignore
    if($response) {
        return [DateTime]$response.Headers['Last-Modified']
    }else {
        return [DateTime]::MaxValue
    }
}

function Wait-ForServiceToReachDesiredState
{
 [CmdletBinding()]
 param(
	[Parameter(Mandatory=$true)]
    [System.String]
	$ServiceName,

	[Parameter(Mandatory=$true)]
    [System.String]
	$DesiredState,

    [System.Int32]
	$SleepTimeInSeconds=10,

    [System.Int32]
	$MaxSeconds=300,

    [System.Int32]
	$MaxAttempts=-1
  )
    
  $Attempts  = 0
  $Done      = $false
  $startTime = Get-Date

  while ($true)
  {
    if ($Attempts++ -gt 0) {  # to skip the message for first attempt
      Write-Verbose "Checking state of Service '$ServiceName'. Attempt # $Attempts"        
    }    
    
    $Service = Get-Service -Name $ServiceName -ErrorAction Ignore

    $msg = "Service '$ServiceName' not ready."
    if ($Service) {
      $msg  = "Service '$ServiceName' is in '$($Service.Status)' state."
      # exit if done
      if ($Service.Status -ieq $DesiredState) {
        Write-Verbose $msg
        return
      }
    } 

    Write-Verbose $msg       # not there yet, report current state

    # exit on timeout
    if (($MaxSeconds -gt 0) -and ($(Get-Date) - $startTime).TotalSeconds -ge $MaxSeconds) {
      return
    }  

    # exit on number of attempts
    if (($MaxAttempts -gt 0) -and ($Attempts -ge $MaxAttempts)) {
      return
    }

    Write-Verbose "Waiting $SleepTimeInSeconds seconds."
    Sleep -Seconds $SleepTimeInSeconds
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
		$LogFailures,

        [System.String]
		$HttpMethod = 'GET',

        [System.Int32]
	    $MaximumRedirection=5,

		[System.Int32]
	    $RequestTimeoutInSeconds=15
    )

    [bool]$Done = $false
    [int]$TotalElapsedTimeInSeconds = 0
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
						Write-Verbose "[Warning]:- Response:- $($resp.Content)"
					}
				}else {
					Write-Verbose "[Warning]:- Response from $Url was NULL"
				}
			}
        }
        catch {
            Write-Verbose "[Warning]:- $($_)"
        }
        if(-not($Done)) {
            Sleep -Seconds $SleepTimeInSeconds
            $TotalElapsedTimeInSeconds += $SleepTimeInSeconds
        }
    }
}

function Upload-File([string]$url, [string]$filePath, [string]$fileContentType, $formParams, $httpHeaders, $Referer, [string]$fileParameterName = 'file', [string]$fileName) 
{   
    [System.Net.WebRequest]$webRequest = [System.Net.WebRequest]::Create($url)
    $webRequest.ServicePoint.Expect100Continue = $false
    $webRequest.Method = "POST"
    $webRequest.Referer = $Referer
    $webRequest.Timeout = 5400000;

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

function License-Software
{
    [CmdletBinding()]
    param
    (
		[string]
        $Product, 
        
        [string]
		$LicenseFilePath, 
        
        [string]
        $Password, 
        
		[string]
		$Version, 

		[string]
		$StdOutputLogFilePath, 

		[string]
        $StdErrLogFilePath,
        
        [System.Boolean]
        $IsSingleUse
    )

    $SoftwareAuthExePath = "$env:SystemDrive\Program Files\Common Files\ArcGIS\bin\SoftwareAuthorization.exe"
    if($Product -ieq 'Desktop' -or $Product -ieq 'Pro') {
        $SoftwareAuthExePath = "$env:SystemDrive\Program Files (x86)\Common Files\ArcGIS\bin\SoftwareAuthorization.exe"
        if($IsSingleUse){
            if($Product -ieq 'Desktop'){
                $SoftwareAuthExePath = "$env:SystemDrive\Program Files (x86)\Common Files\ArcGIS\bin\softwareauthorization.exe"
            }elseif($Product -ieq 'Pro'){
                $InstallLocation = (get-wmiobject Win32_Product| Where-Object {$_.Name -match "Pro" -and $_.Vendor -eq 'Environmental Systems Research Institute, Inc.'}).InstallLocation
                $SoftwareAuthExePath = "$($InstallLocation)bin\SoftwareAuthorizationPro.exe"
            }
        }else{
            $LMInstallLocation = (get-wmiobject Win32_Product| Where-Object {$_.Name -match "License Manager" -and $_.Vendor -eq 'Environmental Systems Research Institute, Inc.'}).InstallLocation
            if($LMInstallLocation){
                $SoftwareAuthExePath = "$($LMInstallLocation)bin\SoftwareAuthorizationLS.exe"
            }
        }
    }
    Write-Verbose "Licensing Product [$Product] using Software Authorization Utility at $SoftwareAuthExePath" -Verbose
    
    $Params = '-s -ver {0} -lif "{1}"' -f $Version,$licenseFilePath
    if($Password){
        $Params = '-s -ver {0} -lif "{1}" -password {2}' -f $Version,$licenseFilePath,$Password
    }
    Write-Verbose "[Running Command] $SoftwareAuthExePath $Params" -Verbose
    
    if($StdOutputLogFilePath) {
        [bool]$Done = $false
        [int]$AttemptNumber = 1
        $err = $null
        while(-not($Done) -and ($AttemptNumber -le 10)) {
            Start-Process -FilePath $SoftwareAuthExePath -ArgumentList $Params -Wait -RedirectStandardOutput $StdOutputLogFilePath -RedirectStandardError $StdErrLogFilePath
            [string]$LicenseFileOutput = Get-Content $StdOutputLogFilePath
            if($LicenseFileOutput -and (($LicenseFileOutput.IndexOf('Error') -gt -1) -or ($LicenseFileOutput.IndexOf('(null)') -gt -1))) {
                $err = "[ERROR] - Attempt $AttemptNumber - Licensing for Product [$Product] failed. Software Authorization Utility returned $LicenseFileOutput"
                Write-Verbose $err
                Start-Sleep -Seconds (Get-Random -Maximum 61 -Minimum 30)
            }else{
                $Done = $True
                $err = $null
            }
            $AttemptNumber += 1
        }
        if($err -ne $null){
            throw $err
        }
	}
    else {
        Start-Process -FilePath $SoftwareAuthExePath -ArgumentList $Params
    }
    if($Product -ieq 'Desktop' -or $Product -ieq 'Pro') {
        Write-Verbose "Sleeping for 2 Minutes to finish Licensing"
        Start-Sleep -Seconds 120
    }
    Write-Verbose "Finished Licensing Product [$Product]" -Verbose
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
		$HttpMethod = 'Post',

		[Parameter(Mandatory=$false)]
		[switch]
		$LogResponse
    )

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} # Allow self-signed certificates
	[System.Net.ServicePointManager]::DefaultConnectionLimit = 1024
	[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    $HttpBody = To-HttpBody $HttpFormParameters
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
		if($LogResponse) { 
			Write-Verbose "Response:- $res"
		}
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
			if($LogResponse) { 
				Write-Verbose "Response:- $($res.Content)"
			}
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

function Ensure-PropertyInPropertiesFile
{
    [CmdletBinding()]
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

function Add-HostMapping
{
    [CmdletBinding()]
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


function Get-WebAdaptorsForPortal {
    [CmdletBinding()]
    param(
		[System.String]
		$PortalHostName = 'localhost', 

        [System.String]
		$SiteName = 'arcgis', 

        [System.Int32]
		$Port = 7443,
		
        [System.String]
		$Token, 

        [System.String]
		$Referer = 'http://localhost'
    )
    $GetWebAdaptorsUrl = "https://$($PortalHostName):$($Port)/$($SiteName)" + "/portaladmin/system/webadaptors"
    try{
		Invoke-ArcGISWebRequest -Url $GetWebAdaptorsUrl -HttpFormParameters @{ token = $Token; f = 'json' } -Referer $Referer -TimeoutSec 240 -HttpMethod 'GET'    
	}catch{
		Write-Verbose "[WARNING] Get-WebAdaptorsForPortal request to $($GetWebAdaptorsUrl) did not succeed. Error:- $_"
		$null
	}   
}

function Register-WebAdaptorForPortal {
    [CmdletBinding()]
    param(
        [System.String]
		$PortalHostName = 'localhost', 

        [System.String]
		$SiteName = 'arcgis', 

        [System.Int32]
		$Port = 7443,
		
        [System.String]
		$Token, 

        [System.String]
		$Referer = 'http://localhost', 

        [System.String]
		$WebAdaptorUrl, 

        [System.String]
		$MachineName, 

        [System.Int32]
		$HttpPort = 80, 

		[System.Int32]
		$HttpsPort = 443
    )
    [System.String]$RegisterWebAdaptorsUrl = ("https://$($PortalHostName):$($Port)/$($SiteName)" + "/portaladmin/system/webadaptors/register")
	Write-Verbose "Register Web Adaptor URL:- $RegisterWebAdaptorsUrl"
    $WebParams = @{ token = $Token
                    f = 'json'
                    webAdaptorURL = $WebAdaptorUrl
                    machineName = $MachineName
                    httpPort = $HttpPort.ToString()
                    httpsPort = $HttpsPort.ToString()
                  }
	try {
		Invoke-ArcGISWebRequest -Url $RegisterWebAdaptorsUrl -HttpFormParameters $WebParams -Referer $Referer -TimeoutSec 240 -ErrorAction Ignore
	}
	catch {
		Write-Verbose "[WARNING] Register-WebAdaptorForPortal returned an error. Error:- $_"
	}
}

function UnRegister-WebAdaptorForPortal {
    [CmdletBinding()]
    param(
        [System.String]
		$PortalHostName = 'localhost', 

        [System.String]
		$SiteName = 'arcgis', 

        [System.Int32]
		$Port = 7443,
		
        [System.String]
		$Token, 

        [System.String]
		$Referer = 'http://localhost',
		 
        [System.String]
		$WebAdaptorId
    )
    
    $UnRegisterWebAdaptorsUrl = "https://$($PortalHostName):$($Port)/$($SiteName)/portaladmin/system/webadaptors/$WebAdaptorId/unregister"
    try {
        Invoke-ArcGISWebRequest -Url $UnRegisterWebAdaptorsUrl -HttpFormParameters  @{ f = 'json'; token = $Token } -Referer $Referer -TimeoutSec 300  
    }catch{
        Write-Verbose "[WARNING] UnRegister-WebAdaptorForPortal on $UnRegisterWebAdaptorsUrl failed with error $($_)"
    }    
}

function Get-PortalSystemProperties {
    [CmdletBinding()]
    param(        
        [System.String]
		$PortalHostName = 'localhost', 

        [System.String]
		$SiteName = 'arcgis', 

        [System.Int32]
		$Port = 7443,

        [System.String]
		$Token, 

        [System.String]
		$Referer = 'http://localhost'
    )
    
    Invoke-ArcGISWebRequest -Url ("https://$($PortalHostName):$($Port)/$($SiteName)" + '/portaladmin/system/properties/') -HttpMethod 'GET' -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer 
}

function Set-PortalSystemProperties {
    [CmdletBinding()]
    param(
        
        [System.String]
		$PortalHostName = 'localhost', 

        [System.String]
		$SiteName = 'arcgis', 

        [System.Int32]
		$Port = 7443,

        [System.String]
		$Token, 

        [System.String]
		$Referer = 'http://localhost',

        $Properties
    )
    
    try {
        Invoke-ArcGISWebRequest -Url("https://$($PortalHostName):$($Port)/$($SiteName)" + '/portaladmin/system/properties/update/') -HttpFormParameters @{ f = 'json'; token = $Token; properties = (ConvertTo-Json $Properties -Depth 4) } -Referer $Referer -TimeOutSec 360
    }
    catch {
        Write-Verbose "[WARNING] Request to Set-PortalSystemProperties returned error:- $_"
    }
}


function Test-WCPPWAPortalProperties
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
	param(
		[System.String]
		$PortalHostName,
		
		[System.String]		
		$ExternalDNSName,
		
		[System.String]
		$PortalEndPoint,

		[System.String]
		$PortalContext,

		[System.String]
        $Token,

        [System.String]
		$Referer,

        [switch]
        $IsCallingResourcePortal 
    )

    $result = $false
    Write-Verbose "Get System Properties"
    # Check if web context URL is set correctly							
    $sysProps = Get-PortalSystemProperties -PortalHostName $PortalHostName -SiteName 'arcgis' -Token $Token -Referer $Referer
    if($sysProps) {
		Write-Verbose "System Properties:- $(ConvertTo-Json $sysProps -Depth 3 -Compress)"
        if($ExternalDNSName){
            $ExpectedWebContextUrl = "https://$($ExternalDNSName)/$($PortalContext)"	
            if ($sysProps.WebContextURL -ieq $ExpectedWebContextUrl) {
                $result = $true
                Write-Verbose "Portal System Properties > WebContextUrl is correctly set to '$($ExpectedWebContextUrl)'"
            }
            else {
                Write-Verbose "Portal System Properties > WebContextUrl is NOT correctly set to '$($ExpectedWebContextUrl)'"
            }
        }

        if ($result -and $PortalEndPoint) {
            if (-not($PortalEndPoint -as [ipaddress])) {
                $PortalEndPoint = Get-FQDN $PortalEndPoint
            }
            # Check if private portal URL is set correctly
            $ExpectedPrivatePortalUrl = "https://$($PortalEndPoint):7443/arcgis"
            if(-not($IsCallingResourcePortal) -and -not($PortalEndPoint -as [ipaddress]))
            { 
                $ExpectedPrivatePortalUrl = "https://$($ExternalDNSName)/$($PortalContext)"
            }

            if ($sysProps.privatePortalURL -ieq $ExpectedPrivatePortalUrl) {						
                Write-Verbose "Portal System Properties > privatePortalURL is correctly set to '$($ExpectedPrivatePortalUrl)'"
            }
            else {
                $result = $false
                Write-Verbose "Portal System Properties > privatePortalURL is NOT correctly set to '$($ExpectedPrivatePortalUrl)'"
            }
        }
        
        if ($result -and $ExternalDNSName) {
            $ExpectedUrl = "https://$ExternalDNSName/$PortalContext"
            $webadaptorConfigs = Get-WebAdaptorsForPortal -PortalHostName $PortalHostName -SiteName 'arcgis' -Token $Token -Referer $Referer
            $result = $false
            $webadaptorConfigs.webAdaptors | Where-Object { $_.httpPort -eq 80 -and $_.httpsPort -eq 443 } | ForEach-Object {
                if ($_.webAdaptorURL -ieq $ExpectedUrl) {
                    Write-Verbose "WebAdaptor URL $($_.webAdaptorURL) matches $ExpectedUrl"
                    $result = $True
                }
            }
        }
    }else {
        Write-Verbose "System Properties is NULL"
    }
    $result
}

function Set-WCPPWAPortalProperties
{
	[CmdletBinding()]
	param(
		[System.String]
		$PortalHostName,
		
		[System.String]		
		$ExternalDNSName,
		
		[System.String]
		$PortalEndPoint,

		[System.String]
		$PortalContext,

		[System.String]
		$Token,

        [System.String]
        $Referer,
        
        [switch]
        $IsCallingResourcePortal
	)
	
	$FQDN = Get-FQDN $PortalHostName
	
	$sysProps = Get-PortalSystemProperties -PortalHostName $FQDN -SiteName 'arcgis' -Token $Token -Referer $Referer
	if (-not($sysProps)) {
		$sysProps = @{ }
	}
	
    if($ExternalDNSName){
        $ExpectedWebContextUrl = "https://$($ExternalDNSName)/$($PortalContext)"
        if ($sysProps.WebContextURL -ine $ExpectedWebContextUrl) {
            Write-Verbose "Portal System Properties > WebContextUrl is NOT correctly set to '$($ExpectedWebContextUrl)'"
            if (-not($sysProps.WebContextURL)) {
                Add-Member -InputObject $sysProps -MemberType NoteProperty -Name 'WebContextURL' -Value $ExpectedWebContextUrl
            }
            else {
                $sysProps.WebContextURL = $ExpectedWebContextUrl
            }			
        }
        else {
            Write-Verbose "Portal System Properties > WebContextUrl is correctly set to '$($sysProps.WebContextURL)'"
        }
    }

    if (-not($PortalEndPoint -as [ipaddress])) {
        $PortalEndPoint = Get-FQDN $PortalEndPoint
    }
    # Check if private portal URL is set correctly
    $ExpectedPrivatePortalUrl = "https://$($PortalEndPoint):7443/arcgis"
    if(-not($IsCallingResourcePortal) -and -not($PortalEndPoint -as [ipaddress]))
    { 
        $ExpectedPrivatePortalUrl = "https://$($ExternalDNSName)/$($PortalContext)"
    }
    
    if ($sysProps.privatePortalURL -ine $ExpectedPrivatePortalUrl) {
        Write-Verbose "Portal System Properties > privatePortalURL is NOT correctly set to '$($ExpectedPrivatePortalUrl)'"
        if (-not($sysProps.privatePortalURL)) {
            Add-Member -InputObject $sysProps -MemberType NoteProperty -Name 'privatePortalURL' -Value $ExpectedPrivatePortalUrl
        }
        else {
            $sysProps.privatePortalURL = $ExpectedPrivatePortalUrl
        }			
    }
    else {
        Write-Verbose "Portal System Properties > privatePortalURL is correctly set to '$($sysProps.privatePortalURL)'"
    }
    
    Write-Verbose "Updating Portal System Properties"
    try {
        Wait-ForUrl -Url "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET'
        Set-PortalSystemProperties -PortalHostName $FQDN -SiteName 'arcgis' -Token $Token -Referer $Referer -Properties $sysProps
    } catch {
        Write-Verbose "Error setting Portal System Properties :- $_"
        Write-Verbose "Request: Set-PortalSystemProperties -PortalHostName $FQDN -SiteName 'arcgis' -Token $Token -Referer $Referer -Properties $sysProps"
    }
    Write-Verbose "Waiting 5 minutes for web server to apply changes before polling for endpoint being available" 
    Start-Sleep -Seconds 300 # Add a 5 minute wait to allow the web server to go down
    Write-Verbose "Updated Portal System Properties. Waiting for portaladmin endpoint 'https://$($FQDN):7443/arcgis/portaladmin/' to come back up"
    Wait-ForUrl -Url "https://$($FQDN):7443/arcgis/portaladmin/" -MaxWaitTimeInSeconds 300 -HttpMethod 'GET' -LogFailures
    Write-Verbose "Finished waiting for portaladmin endpoint 'https://$($FQDN):7443/arcgis/portaladmin/' to come back up"
    
    if ($ExternalDNSName){
        $WebAdaptorUrl = "https://$($ExternalDNSName)/$($PortalContext)"
        $WebAdaptorsForPortal = Get-WebAdaptorsForPortal -PortalHostName $FQDN -SiteName 'arcgis' -Token $Token -Referer $Referer
        Write-Verbose "Current number of WebAdaptors on Portal:- $($WebAdaptorsForPortal.webAdaptors.Length)"
        $AlreadyExists = $false
        $WebAdaptorsForPortal.webAdaptors | Where-Object { $_.httpPort -eq 80 -and $_.httpsPort -eq 443 } | ForEach-Object {
            if ($_.webAdaptorURL -ine $WebAdaptorUrl) {
                Write-Verbose "Unregister Web Adaptor with Url $WebAdaptorUrl"
                UnRegister-WebAdaptorForPortal -PortalHostName $FQDN -SiteName 'arcgis' -Token $Token -Referer $Referer -WebAdaptorId $_.id             
            } 
            else {
                Write-Verbose "Webadaptor with require properties URL $($_.webAdaptorURL) and Name $($_.machineName) already exists"
                $AlreadyExists = $true
            }
        }

        if(-not($AlreadyExists)) {
            
            #Register the PortalEndPoint as a (dummy) web adaptor for Portal
            Write-Verbose "Registering the ExternalDNSName Endpoint with Url $WebAdaptorUrl and MachineName $PortalEndPoint as a Web Adaptor for Portal"
            try{
                Wait-ForUrl -Url "https://$($FQDN):7443/arcgis/portaladmin/" -HttpMethod 'GET'
                $registerResponse = Register-WebAdaptorForPortal -PortalHostName $FQDN -SiteName 'arcgis' -Token $Token -Referer $Referer -WebAdaptorUrl $WebAdaptorUrl `
                                                                -MachineName $ExternalDNSName -HttpPort 80 -HttpsPort 443
            } catch {
                Write-Verbose "Error registering Webadaptor for Portal :- $_"    
                Write-Verbose "Request: Register-WebAdaptorForPortal -PortalHostName $FQDN -SiteName 'arcgis' -Token $Token -Referer $Referer -WebAdaptorUrl $WebAdaptorUrl -MachineName $ExternalDNSName -HttpPort 80 -HttpsPort 443"
            }

            if($registerResponse) {												
                Write-Verbose "Register WebAdaptor Response:- $(ConvertTo-Json -Depth 5 $registerResponse -Compress)"
            }else { 
                Write-Verbose "Register WebAdaptor Response is null indicating a stopped web server" 
                Start-Sleep -Seconds 180 # Wait for Portal admin to stop/start asynchronously
                Write-Verbose "Waiting for portaladmin endpoint to come back up"
                Wait-ForUrl -Url "https://$($FQDN):7443/arcgis/portaladmin/" -MaxWaitTimeInSeconds 300 -HttpMethod 'GET' 
            }

            $WebAdaptorsForPortal = Get-WebAdaptorsForPortal -PortalHostName $FQDN -SiteName 'arcgis' -Token $Token -Referer $Referer
            if($WebAdaptorsForPortal) {												
                Write-Verbose "WebAdaptors Response:- $(ConvertTo-Json -Depth 5 $WebAdaptorsForPortal -Compress)"
            }else { 
                Write-Verbose "WebAdaptors Response is null indicating a stopped web server" 
                Start-Sleep -Seconds 180 # Wait for Portal to stop/start asynchronously
                Write-Verbose "Waiting for portaladmin endpoint to come back up"
                Wait-ForUrl -Url "https://$($FQDN):7443/arcgis/portaladmin/" -MaxWaitTimeInSeconds 180 -HttpMethod 'GET' 
            }
            Write-Verbose "Number of Registered Web Adaptors: $($WebAdaptorsForPortal.webAdaptors.Length)"
            $VerifyWebAdaptor = $WebAdaptorsForPortal.webAdaptors | Where-Object { $_.webAdaptorURL -ieq $WebAdaptorUrl -and $_.httpPort -eq 80 -and $_.httpsPort -eq 443 }
            if(-not($VerifyWebAdaptor)) {
                Write-Verbose "[WARNING] Unable to verify the web adaptor that was just registered for $($WebAdaptorUrl)"
            }   
        }
    }
}

function Get-ServerSystemProperties
{
    [CmdletBinding()]
    param(        
        [System.String]
		$ServerHostName, 

        [System.String]
		$ContextName = 'arcgis', 

		[System.Int32]
		$AdminEndpointHttpsPort = 6443,

        [System.String]
		$Token, 

        [System.String]
		$Referer
    )
    
    Invoke-ArcGISWebRequest -Url ("https://$($ServerHostName):$($AdminEndpointHttpsPort)/$($ContextName)" + '/admin/system/properties/') -HttpMethod 'Get' -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer 
}

function Set-ServerSystemProperties
{
    [CmdletBinding()]
    param(
        
        [System.String]
		$ServerHostName, 

        [System.String]
		$ContextName = 'arcgis', 

		[System.Int32]
		$AdminEndpointHttpsPort = 6443,

        [System.String]
		$Token, 

        [System.String]
		$Referer,

        $Properties
    )
    
    try {
        Invoke-ArcGISWebRequest -Url("https://$($ServerHostName):$($AdminEndpointHttpsPort)/$($ContextName)" + '/admin/system/properties/update/') -HttpFormParameters @{ f = 'json'; token = $Token; properties = (ConvertTo-Json $Properties -Depth 4) } -Referer $Referer -TimeOutSec 180
    }catch {
        Write-Verbose "[WARNING] Request to Set-ServerSystemProperties returned error:- $_"
    }
}

function Get-WebAdaptorsConfigForServer
{
    [CmdletBinding()]
    param(
      [System.String]
	  $ServerUrl,

      [System.String]
	  $SiteName, 
      
	  [System.String]
	  $Token, 

      [System.String]
	  $Referer
    )

    $GetWebAdaptorsUrl = $ServerUrl.TrimEnd('/') + "/$SiteName/admin/system/webadaptors"  
    Invoke-ArcGISWebRequest -Url $GetWebAdaptorsUrl -HttpFormParameters  @{ f= 'json'; token = $Token } -Referer $Referer -TimeoutSec 30    
}

function Register-WebAdaptorForServer 
{
    [CmdletBinding()]
    param(
        [System.String]
		$ServerUrl, 

        [System.String]
		$SiteName, 

        [System.String]
		$Token, 

        [System.String]
		$Referer, 

        [System.String]
		$WebAdaptorUrl, 

        [System.String]
		$MachineName, 

        [System.Int32]
		$HttpPort = 80, 

        [System.Int32]
		$HttpsPort = 443
    )

    [System.String]$RegisterWebAdaptorsUrl = $ServerUrl.TrimEnd('/') + "/$SiteName/admin/system/webadaptors/register"  
    $WebParams = @{ token = $Token
                    f = 'json'
                    webAdaptorURL = $WebAdaptorUrl
                    machineName = $MachineName
                    httpPort = $HttpPort.ToString()
                    httpsPort = $HttpsPort.ToString()
                    isAdminEnabled = 'true'
                  }
    Invoke-ArcGISWebRequest -Url $RegisterWebAdaptorsUrl -HttpFormParameters $WebParams -Referer $Referer       
}

function Test-WAWCServerProperties{
    [CmdletBinding()]
	param(
		[System.String]
        $ServerHostName,
        
        [System.String]
        $ServerContext,
    	
		[System.String]		
		$ExternalDNSName,
		
		[System.String]
		$ServerEndPoint,

		[System.String]
		$Token, 

        [System.String]
		$Referer
	)

    $FQDN = Get-FQDN $ServerHostName
	
	$result = $true
    if($result){
		$serverSysProps = Get-ServerSystemProperties -ServerHostName $FQDN -Token $Token -Referer $Referer	
		if($serverSysProps) {
			Write-Verbose "System Properties:- $(ConvertTo-Json $serverSysProps -Depth 3 -Compress)"
		}else {
			Write-Verbose "System Properties is NULL"
		}
		$ExpectedServerWebContextUrl = "https://$($ExternalDNSName)/$($ServerContext)"	
		if($serverSysProps.WebContextURL -ieq $ExpectedServerWebContextUrl) {
			Write-Verbose "Server System Properties > WebContextUrl is correctly set to '$($ExpectedServerWebContextUrl)'"
		}else{
			$result = $false
			Write-Verbose "Server System Properties > WebContextUrl is NOT correctly set to '$($ExpectedServerWebContextUrl)'"
		}
	}

	if($result) {
		$WebAdaptorsForServer = Get-WebAdaptorsConfigForServer -ServerUrl "https://$($FQDN):6443" -SiteName 'arcgis' `
																-Token $Token -Referer $Referer
		$WebAdaptorUrl = "https://$($ServerEndPoint):6443/arcgis" # "https://$($ServerEndPoint)/$ServerSiteName"
		$ExistingWebAdaptor = $WebAdaptorsForServer.webAdaptors | Where-Object { $_.webAdaptorURL -ieq $WebAdaptorUrl }

		if(-not($ExistingWebAdaptor)) {
			$result = $false
			Write-Verbose "Web Adaptor for url '$WebAdaptorUrl' is not set"
		}
	}
    $result
}

function Set-WAWCServerProperties{
    [CmdletBinding()]
	param(
		[System.String]
		$ServerHostName,
        
        [System.String]
        $ServerContext,
		
		[System.String]		
		$ExternalDNSName,
		
		[System.String]
		$ServerEndPoint,

		[System.String]
		$Token, 

        [System.String]
		$Referer
	)

    $ServerFQDN = Get-FQDN $ServerHostName
   
    $WebAdaptorsForServer = Get-WebAdaptorsConfigForServer -ServerUrl "https://$($ServerFQDN):6443" -SiteName 'arcgis' `
                                                            -Token $Token -Referer $Referer
    $WebAdaptorUrl = "https://$($ServerEndPoint):6443/arcgis" # "https://$($ServerEndPoint)/$ServerSiteName"
    $ExistingWebAdaptor = $WebAdaptorsForServer.webAdaptors | Where-Object { $_.webAdaptorURL -ieq $WebAdaptorUrl }

    if(-not($ExistingWebAdaptor)) {
        #Register the ServerEndpoint as a (dummy) web adaptor for server				
        Write-Verbose 'Registering the Server Endpoint as a Web Adaptor for Server'
        Write-Verbose "Register https://$($ServerEndPoint):6443/arcgis as web adaptor" # "Register https://$($ServerEndPoint)/$ServerSiteName as web adaptor" 
        Register-WebAdaptorForServer -ServerUrl "https://$($ServerFQDN):6443" -Token $Token -Referer $Referer -SiteName 'arcgis' `
                                        -WebAdaptorUrl $WebAdaptorUrl -MachineName $ServerEndPoint -HttpPort 80 -HttpsPort 443
        Write-Verbose 'Finished Registering the ServerEndPoint as a Web Adaptor for Server'

        $WebAdaptorsForServer = Get-WebAdaptorsConfigForServer -ServerUrl "https://$($ServerFQDN):6443" -SiteName 'arcgis' `
                                                            -Token $Token -Referer $Referer
        $VerifyWebAdaptor = $WebAdaptorsForServer.webAdaptors | Where-Object { $_.webAdaptorURL -ieq $WebAdaptorUrl }
        if(-not($VerifyWebAdaptor)) {
            Write-Verbose "[WARNING] Unable to verify the web adaptor that was just registered for $ServerEndPoint with URL $WebAdaptorUrl"
        }
    }
    else{
        Write-Verbose "Web Adaptor for $ServerEndPoint with URL $WebAdaptorUrl already exists on the Server"
    }
    
	$serverSysProps = Get-ServerSystemProperties -ServerHostName $ServerFQDN -Token $Token -Referer $Referer	
	if($serverSysProps) {
		Write-Verbose "System Properties:- $(ConvertTo-Json $serverSysProps -Depth 3 -Compress)"
	}else {
		Write-Verbose "System Properties is NULL"
	}
	$ExpectedServerWebContextUrl = "https://$($ExternalDNSName)/$($ServerContext)"	
	if($serverSysProps.WebContextURL -ieq $ExpectedServerWebContextUrl) {
		Write-Verbose "Server System Properties > WebContextUrl is correctly set to '$($ExpectedServerWebContextUrl)'"
	}else{
		$result = $false
		Write-Verbose "Server System Properties > WebContextUrl is NOT correctly set to '$($ExpectedServerWebContextUrl)'"
		if(-not($serverSysProps.WebContextURL)) {
			Add-Member -InputObject $serverSysProps -MemberType NoteProperty -Name 'WebContextURL' -Value $ExpectedServerWebContextUrl
		}else{
			$serverSysProps.WebContextURL = $ExpectedServerWebContextUrl
		}	
		Write-Verbose "Updating Server System Properties to set WebContextUrl to $ExpectedServerWebContextUrl"
		Set-ServerSystemProperties -ServerHostName $ServerFQDN -Token $Token -Referer $Referer -Properties $serverSysProps
		Write-Verbose "Updated Server System Properties to set WebContextUrl to $ExpectedServerWebContextUrl"
	}
}

function Get-ComponentCode
{
       [CmdletBinding()]
       param
       (
        [ValidateSet("Server","Portal","DataStore","GeoEvent","NotebookServer","Monitor","WebStyles","Desktop","Pro","LicenseManager")]
        [parameter(Mandatory = $true)]
        [System.String]
        $ComponentName,

        [ValidateSet("2.0","2.1","2.2","2.3","2.4","10.4","10.4.1","10.5","10.5.1","10.6","10.6.1","10.7","10.7.1","2018.0","2018.1","2019.0")]
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
        }
        WebStyles = @{ 
            '10.7.1' = 'B2E42A8D-1EE9-4610-9932-D0FCFD06D2AF'
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
        }
        NotebookServer = @{
            '10.7' = '3721E3C6-6302-4C74-ACA4-5F50B1E1FE3A'
            '10.7.1' = 'F6DF77B9-F35E-4877-A7B1-63E1918B4E19'
        }
        Monitor = @{
            '10.7' = '0497042F-0CBB-40C0-8F62-F1922B90E12E'
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
        }
        LicenseManager = @{
            '2018.0' = '1914B5D6-02C2-4CA3-9CAB-EE76358228CF'
            '2018.1' = 'E1C26E47-C6AB-4120-A3DE-2FA0F723C876'
            '2019.0' = '23696ED6-78BA-44A8-B4C7-1BC979131533'
        }
        Pro = @{
            '2.0' = '28A4967F-DE0D-4076-B62D-A1A9EA62FF0A'
            '2.1' = '0368352A-8996-4E80-B9A1-B1BA43FAE6E6'
            '2.2' = 'A23CF244-D194-4471-97B4-37D448D2DE76'
            '2.3' = '9CB8A8C5-202D-4580-AF55-E09803BA1959'
            '2.4' = '78D498E7-1791-4796-9A4F-6BFAD51C09B5'
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
    $ProdId = $ProductId
    if(-not($ProductId)){
        if($Version){
            $ProdId = Get-ComponentCode -ComponentName $Name -Version $Version
        }else{
            Throw "Product Id or Version is required for Component $Name"
        }
    }
    
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

    $result
}



# http://www.andreasnick.com/85-reading-out-an-msp-product-code-with-powershell.html
<# 
.SYNOPSIS 
    Get the Patch Code from an Microsoft Installer Patch MSP
.DESCRIPTION 
    Get a Patch Code from an Microsoft Installer Patch MSP (Andreas Nick 2015)
.NOTES 
    $NULL for an error
.LINK
.RETURNVALUE
  [String] Product Code
.PARAMETER
  [IO.FileInfo] Path to the msp file
#>
function Get-MSPqfeID {
    param (
        [IO.FileInfo] $patchnamepath
          
    )
    try {
        $wi = New-Object -com WindowsInstaller.Installer
        $mspdb = $wi.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $Null, $wi, $($patchnamepath.FullName, 32))
        $su = $mspdb.GetType().InvokeMember("SummaryInformation", "GetProperty", $Null, $mspdb, $Null)
        #$pc = $su.GetType().InvokeMember("PropertyCount", "GetProperty", $Null, $su, $Null)

        [String] $qfeID = $su.GetType().InvokeMember("Property", "GetProperty", $Null, $su, 3)
        return $qfeID
    }
    catch {
        Write-Output $_.Exception.Message
        return $NULL
    }
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

            Write-Output -NoEnumerate $collection
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

Export-ModuleMember -Function Invoke-ArcGISWebRequest,License-Software,To-HttpBody,Upload-File,Wait-ForUrl,Get-LastModifiedDateForRemoteFile,Check-ResponseStatus `
                                ,Get-ServerToken,Get-PortalToken,Wait-ForServiceToReachDesiredState,Get-EsriRegistryKeyForService,Ensure-PropertyInPropertiesFile `
                                ,Get-PropertyFromPropertiesFile,Set-PropertyFromPropertiesFile,Add-HostMapping,Get-ConfiguredHostIdentifier,Set-ConfiguredHostIdentifier `
                                ,Get-ConfiguredHostName,Set-ConfiguredHostName,Get-ConfiguredHostIdentifierType,Get-ComponentCode,Test-Install,Get-MSPqfeID `
                                ,Convert-PSObjectToHashtable,Set-PortalSystemProperties,Get-PortalSystemProperties,UnRegister-WebAdaptorForPortal,Register-WebAdaptorForPortal `
                                ,Get-WebAdaptorsForPortal,Set-WCPPWAPortalProperties,Test-WCPPWAPortalProperties,Test-WAWCServerProperties, Set-WAWCServerProperties