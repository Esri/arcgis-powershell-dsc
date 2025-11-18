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

	    [System.String]
		$ServerEndPoint,

		[System.Management.Automation.PSCredential]
		$SiteAdministrator
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
		$ServerHostName,

        [parameter(Mandatory = $false)]
        [Int32]
        $SocMaximumHeapSize,

		[System.Management.Automation.PSCredential]
		$SiteAdministrator
    )
    
	[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	$ServerFQDN = Get-FQDN $ServerHostName
	$ServerHttpsUrl = "https://$($ServerFQDN):6443" 
    $Referer = $ServerHttpsUrl
	
	Write-Verbose "Getting Server Token for user '$($SiteAdministrator.UserName)' from '$ServerHttpsUrl'"

	$serverToken = Get-ServerToken -ServerEndPoint $ServerHttpsUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer
    if(-not($serverToken.token)) {
        Write-Verbose "Get Server Token Response:- $serverToken"
        throw "Unable to retrieve Server Token for '$($SiteAdministrator.UserName)'"
    }
	Write-Verbose "Connected to Server successfully and retrieved token for '$($SiteAdministrator.UserName)'"

	# Push SocMaximumHeapSize if user asked for it
	if($SocMaximumHeapSize -gt 0){

		$MachineName = $ServerFQDN
		$AllMachines = Get-Machines -ServerURL $ServerHttpsUrl -Token $serverToken.token -Referer $Referer
		if(-not($AllMachines.machines | Where-Object { $_.machineName -ieq $MachineName })) {
			$MachineName = $env:COMPUTERNAME
			if(-not($AllMachines.machines | Where-Object { $_.machineName -ieq $MachineName })){
				throw "Not able to find machine in site with either hostname $MachineName or fully qualified domain name $ServerFQDN"
			}
		}

		# Fetch current machineDetails
		$machineDetails = Get-MachineDetails `
            -ServerURL   $ServerHttpsUrl `
            -Token       $serverToken.token `
            -Referer     $Referer `
            -MachineName $MachineName
		
		# If property doesn't exist, add it, otherwise overwrite
		if (-not $machineDetails.PSObject.Properties.Match('socMaxHeapSize')) {
			Add-Member -InputObject $machineDetails `
                       -MemberType NoteProperty `
                       -Name 'socMaxHeapSize' `
                       -Value $SocMaximumHeapSize
		}
		else {
			$machineDetails.socMaxHeapSize = $SocMaximumHeapSize
		}
		Write-Verbose "Setting SocMaximumHeapSize to $SocMaximumHeapSize on machine $ServerHostName"

		# Push it back via edit endpoint helper
        Update-SocMaxHeapSize `
            -ServerURL         $ServerHttpsUrl `
            -Token             $serverToken.token `
            -MachineName       $MachineName `
            -Referer           $Referer `
            -MachineProperties $machineDetails
	}

	Write-Verbose "Waiting for Url 'https://$($ServerFQDN):6443/arcgis/rest/info/healthCheck' to respond"
	Wait-ForUrl -Url "https://$($ServerFQDN):6443/arcgis/rest/info/healthCheck?f=json" -SleepTimeInSeconds 10 -MaxWaitTimeInSeconds 150 -HttpMethod 'GET' -Verbose
}

function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	( 
        [parameter(Mandatory = $true)]
		[System.String]
		$ServerHostName,

        [parameter(Mandatory = $false)]
        [Int32]
        $SocMaximumHeapSize,

		[System.Management.Automation.PSCredential]
		$SiteAdministrator
    )

	[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
	$ServerFQDN = Get-FQDN $ServerHostName
    $ServerHttpsUrl = "https://$($ServerFQDN):6443" 
    $Referer = $ServerHttpsUrl	
    Write-Verbose "Getting Server Token for user '$($SiteAdministrator.UserName)' from 'https://$($ServerFQDN):6443'"

    $serverToken = Get-ServerToken -ServerEndPoint $ServerHttpsUrl -ServerSiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer
    if(-not($serverToken.token)) {
        Write-Verbose "Get Server Token Response:- $serverToken"
        throw "Unable to retrieve Server Token for '$($SiteAdministrator.UserName)'"
    }
    Write-Verbose "Connected to Server successfully and retrieved token for '$($SiteAdministrator.UserName)'"
	$result = $true
	
	if($result -and $SocMaximumHeapSize -gt 0){

		$MachineName = $ServerFQDN
		$AllMachines = Get-Machines -ServerURL $ServerHttpsUrl -Token $serverToken.token -Referer $Referer
		if(-not($AllMachines.machines | Where-Object { $_.machineName -ieq $MachineName })) {
			$MachineName = $env:COMPUTERNAME
			if(-not($AllMachines.machines | Where-Object { $_.machineName -ieq $MachineName })){
				throw "Not able to find machine in site with either hostname $MachineName or fully qualified domain name $ServerFQDN"
			}
		}
		# pull the machineDetails
        $machineDetails = Get-MachineDetails `
            -ServerURL $ServerHttpsUrl `
            -Token   $serverToken.token `
            -Referer $Referer `
            -MachineName $MachineName

		# if the property is missing, or doesn't match the user-supplied value, fail
		if (
            -not $machineDetails.PSObject.Properties.Match('socMaxHeapSize') -or
            $machineDetails.socMaxHeapSize -ne $SocMaximumHeapSize
        ) {
            Write-Verbose "SocMaximumHeapSize mismatch: expected $SocMaximumHeapSize, actual $($machineDetails.socMaxHeapSize)"
            $result = $false
        }
        else {
            Write-Verbose "SocMaximumHeapSize is already set to $SocMaximumHeapSize"
        }
	}

	$result    
}

function Get-MachineDetails
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerURL, 
        
        [System.String]
        $Token, 
        
        [System.String]
        $Referer, 
        
        [System.String]
        $MachineName
    )
    $GetMachineDetailsUrl  = $ServerURL.TrimEnd("/") + "/arcgis/admin/machines/$MachineName/"
    return Invoke-ArcGISWebRequest -Url $GetMachineDetailsUrl -HttpFormParameters @{ f= 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET' -TimeoutSec 150
}
function Get-Machines
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerURL, 
        
        [System.String]
        $Token, 
        
        [System.String]
        $Referer
    )
    $GetMachinesUrl  = $ServerURL.TrimEnd("/") + "/arcgis/admin/machines/"
    Invoke-ArcGISWebRequest -Url $GetMachinesUrl -HttpFormParameters @{ f= 'json'; token = $Token; } -Referer $Referer -HttpMethod 'GET' -TimeoutSec 150
}

function Update-SocMaxHeapSize
{
    [CmdletBinding()]
    param(
        [System.String]
        $ServerURL, 
        
        [System.String]
        $Token, 
        
        [System.String]
        $MachineName,

        [System.String]
        $Referer, 
        
        $MachineProperties,
        
        [System.Int32]
        $MaxAttempts = 5,

        [System.Int32]
        $SleepTimeInSecondsBetweenAttempts = 30
    )

    $Url  = $ServerURL.TrimEnd("/") + "/arcgis/admin/machines/$MachineName/edit"
    $MachineProperties.psobject.properties | Foreach-Object -begin {$h=@{}} -process {$h."$($_.Name)" = $_.Value} -end {$h} # convert PSCustomObject to hashtable
    
    if($ServerURL -imatch "6443"){
        $h.ports = $null
    }

    $h.f = 'json'
    $h.token = $Token
    [bool]$Done = $false
    [int]$Attempt = 1
    while(-not($Done) -and $Attempt -le $MaxAttempts) 
    {
        $AttemptStr = ''
        if($Attempt -gt 1) {
            $AttemptStr = "Attempt # $Attempt"              
        }
        Write-Verbose "Update SocMaxHeapSize $AttemptStr"
        try {    
            $response = Invoke-ArcGISWebRequest -Url $Url -HttpFormParameters $h -Referer $Referer -TimeOutSec 150 -Verbose
            if($response.status -ieq 'success'){
                Write-Verbose "Update Web Server SocMaxHeapSize Successful! Server will Restart now."
                $Done = $true
            }else{
                if(($response.status -ieq 'error') -and $response.messages){
                    Write-Verbose "[WARNING]:- $($response.messages -join ',')"
                }else{
                    Write-Verbose "[WARNING]:- $($response | ConvertTo-Json -Depth 10)"
                }
            }
        }
        catch
        {                
            if($Attempt -ge $MaxAttempts) {
                Write-Verbose "[WARNING] Update failed after $MaxAttempts. Last Response:- $($_)"
                #throw "Update failed after $MaxAttempts. Error:- $($_)"
            }
        }
        if(-not($Done)){
            Start-Sleep -Seconds $SleepTimeInSecondsBetweenAttempts
        }
        
        $Attempt++
    }
    $response
}

Export-ModuleMember -Function *-TargetResource
