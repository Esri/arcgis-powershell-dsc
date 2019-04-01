function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$SiteName
	)
	
	$returnValue = @{
		SiteName = $SiteName
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
		$SiteName,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

        [parameter(Mandatory = $true)]
		[System.String]
		$ServerHostName,

        [uint32]
        $RetryIntervalSec  = 30,

        [uint32]
        $RetryCount  = 10
	)    

    $Referer = 'http://localhost'
    $ServerUrl = "https://$($ServerHostName):6443"
	$NumCount = 0
	$Done     = $false
	while ((-not $Done) -and ($NumCount++ -le $RetryIntervalSec)) 
	{
        try {
            Write-Verbose "Checking for site on '$ServerUrl'"
            $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer
            $Done = ($token.token -ne $null)
        }catch {
            Write-Verbose "[WARNING] Check returned error:- $_"
        }
        if(-not($Done)) {
            Start-Sleep -Seconds $RetryIntervalSec
        }else {
            Write-Verbose "Site on '$ServerUrl' is ready"
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
		$SiteName,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

        [parameter(Mandatory = $true)]
		[System.String]
		$ServerHostName,

        [uint32]
        $RetryIntervalSec  = 30,

        [uint32]
        $RetryCount  = 10
	)
    
    $Referer = 'http://localhost'
    $ServerUrl = "https://$($ServerHostName):6443"
    $result = $false
    try {        
        Write-Verbose "Checking for site on '$ServerUrl'"
        [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
        $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer
        $result = ($token.token -ne $null)
        if($result){
            Write-Verbose "Site Exists. Was able to retrieve token for PSA"
        }else{
            Write-Verbose "Unable to detect if Site Exists. Was NOT able to retrieve token for PSA"
        }
    }
    catch {
        Write-Verbose "[WARNING]:- $($_)"
    }
    $result
}

