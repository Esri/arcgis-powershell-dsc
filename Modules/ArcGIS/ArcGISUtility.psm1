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

        [System.Int32]$Expiration=1000
    )
            
    Invoke-ArcGISWebRequest -Url ($ServerEndPoint.TrimEnd('/') + "/$ServerSiteName/admin/generateToken") -HttpFormParameters @{ username = $Credential.UserName; password = $Credential.GetNetworkCredential().Password; client = 'referer'; referer = $Referer; expiration = $Expiration; f = 'json' } -Referer $Referer -TimeOutSec 30 
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
		$Port = 7443
    )
       
    Invoke-ArcGISWebRequest -Url "https://$($PortalHostName):$($Port)/$SiteName/sharing/rest/generateToken" -HttpFormParameters @{ username = $Credential.UserName; password = $Credential.GetNetworkCredential().Password; referer = $Referer; f = 'json' } -Referer $Referer -LogResponse  
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
    Start-Sleep -Seconds $SleepTimeInSeconds
  }
}

function Wait-ForUrl
{
    [CmdletBinding()]
    param
    (
		[Parameter(Mandatory=$true)]
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
	    $MaximumRedirection=5
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
				$webRequest.Timeout  = (15 * 1000)
                $webRequest.AllowAutoRedirect = $MaximumRedirection -gt -1
                $webRequest.MaximumAutomaticRedirections = [System.Math]::Max(1, $MaximumRedirection)
				$resp = $webRequest.GetResponse()
				$Done = $true
			}
			else {
				$resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -UseDefaultCredentials -ErrorAction Ignore -TimeoutSec 15 -Method $HttpMethod -DisableKeepAlive -MaximumRedirection $MaximumRedirection
				if($resp) {
					if(($resp.StatusCode -eq 200)-and $resp.Content) { 
						$Done = $true
						Write-Verbose "Url is ready : $Url"
					}else{
						Write-Verbose "[Warning]:- Response:- $($resp.Content)"
					}
				}
			}
        }
        catch {
            Write-Verbose "[Warning]:- $($_)"
        }
        if(-not $Done) {
            Start-Sleep -Seconds $SleepTimeInSeconds
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
		$Arguments, 

		[string]
		$StdOutputLogFilePath, 

		[string]
		$StdErrLogFilePath
    )

    $SoftwareAuthExePath = "$env:SystemDrive\Program Files\Common Files\ArcGIS\bin\SoftwareAuthorization.exe"
    if($Product -ieq 'Desktop' -or $Product -ieq 'Pro') {
        $SoftwareAuthExePath = "$env:SystemDrive\Program Files (x86)\Common Files\ArcGIS\bin\SoftwareAuthorization.exe"
    }
    Write-Verbose "Licensing Product [$Product] using Software Authorization Utility at $SoftwareAuthExePath" -Verbose
    
    $Params = " $Arguments -lif $licenseFilePath"
    if($Password){
        $Params += " -password $Password" 
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
        $res = Invoke-WebRequest -Method $HttpMethod -Uri $Url -Body $HttpBody -Headers $Headers -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing  -TimeoutSec $TimeOutSec   
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

function Get-ComponentCode
{
       [CmdletBinding()]
       param
       (
        [ValidateSet("Server","Portal","DataStore","GeoEvent","EnterpriseBuilder")]
        [parameter(Mandatory = $true)]
        [System.String]
              $ComponentName,

        [ValidateSet("10.4","10.4.1","10.5","10.5.1","10.6","10.6.1")]
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
        }
        Portal = @{      
            '10.4' = 'FA6FCD2D-114C-4C04-A8DF-C2E43979560E'
            '10.4.1' = '31373E04-9B5A-4CD7-B668-0B1DE7F0D45F'
            '10.5' = '43EF63C6-957B-4DA7-A222-6904053BF222'
            '10.5.1' = 'C7E44FBE-DFA6-4A95-8779-B6C40F3947B7'
            '10.6' = 'FFE4808A-1AD2-41A6-B5AD-2BA312BE6AAA'
            '10.6.1' = 'ECC6B3B9-A875-4AE3-9C03-8664EB38EED9'
        }
        DataStore = @{             
            '10.4' = 'C351BC6D-BF25-487D-99AB-C963D590A8E8'
            '10.4.1' = 'A944E0A7-D268-41CA-B96E-8434457B051B'
            '10.5' = '5EA81114-6FA7-4B4C-BD72-D1C882088AAC'
            '10.5.1' = '75276C83-E88C-43F6-B481-100DA4D64F71'
            '10.6' = '846636C1-53BB-459D-B66D-524F79E40396'
            '10.6.1' = '53160721-93D8-48F8-9EDD-038794AE756E'
        }        
        GeoEvent = @{             
            '10.4' = '188191AE-5A83-49E8-88CB-1F1DB05F030D'
            '10.4.1' = 'D71379AF-A72B-4B10-A7BA-64BC6AF6841B'
            '10.5' = '4375BD31-BD98-4166-84D9-E944D77103E8'
            '10.5.1' = 'F11BBE3B-B78F-4E5D-AE45-E3B29063335F'
            '10.6' = '723742C8-6633-4C85-87AC-503507FE222B'
            '10.6.1' = 'D0586C08-E589-4942-BC9B-E83B2E8B95C2'
        }
        EnterpriseBuilder = @{
            '10.5.1' = '9A57125F-B38F-421F-9C57-F6039BEF2713'
            '10.6' = '9A57125F-B38F-421F-9C57-F6039BEF2713'
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

Export-ModuleMember -Function Invoke-ArcGISWebRequest,License-Software,To-HttpBody,Upload-File,Wait-ForUrl,Get-LastModifiedDateForRemoteFile,Check-ResponseStatus `
                                ,Get-ServerToken,Get-PortalToken,Wait-ForServiceToReachDesiredState,Get-EsriRegistryKeyForService,Ensure-PropertyInPropertiesFile `
                                ,Get-PropertyFromPropertiesFile,Set-PropertyFromPropertiesFile,Add-HostMapping,Get-ConfiguredHostIdentifier,Set-ConfiguredHostIdentifier `
                                ,Get-ConfiguredHostName,Set-ConfiguredHostName,Get-ConfiguredHostIdentifierType,Get-ComponentCode,Test-Install,Get-MSPqfeID