$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the ArcGIS Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Common' `
            -ChildPath 'ArcGIS.Common.psm1'))

Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'ArcGIS.Client' `
            -ChildPath 'ArcGIS.Client.Server.psm1'))

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(   
        [parameter(Mandatory = $true)]
		[System.String]
		$ServerHostName,

	    [System.Management.Automation.PSCredential]
		$SiteAdministrator
	)

	@{}
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
    
	$ServerFQDN = Get-FQDN $ServerHostName
	Write-Verbose "Fully Qualified Domain Name :- $ServerFQDN"
   	$ServerBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName "Server" -FQDN $ServerFQDN
    $Referer = $ServerBaseUrl
	
	Write-Verbose "Getting Server Token for user '$($SiteAdministrator.UserName)' from '$ServerBaseUrl'"
	$serverToken = Get-ServerToken -URL $ServerBaseUrl -Credential $SiteAdministrator -Referer $Referer
    if(-not($serverToken.token)) {
        Write-Verbose "Get Server Token Response:- $serverToken"
        throw "Unable to retrieve Server Token for '$($SiteAdministrator.UserName)'"
    }
	Write-Verbose "Connected to Server successfully and retrieved token for '$($SiteAdministrator.UserName)'"

	# Push SocMaximumHeapSize if user asked for it
	if($SocMaximumHeapSize -gt 0){
        Update-MachineProperties `
                            -URL            $ServerBaseUrl `
                            -Token          $serverToken.token `
                            -Referer        $Referer `
                            -MachineName    $ServerFQDN `
                            -SocMaxHeapSize $SocMaximumHeapSize -Verbose

        # Restart the ArcGIS Server service
        # after updating the machine properties before checking the health of the server
        Restart-ArcGISService -ComponentName "Server" -Verbose
	}

    Write-Verbose "Waiting for Url '$($ServerBaseUrl)'"
	Test-ArcGISComponentHealth -BaseURL $ServerBaseUrl -ComponentName "Server" -SleepTimeInSeconds 10 -MaxWaitTimeInSeconds 150 -Verbose
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

	$ServerFQDN = Get-FQDN $ServerHostName
    Write-Verbose "Fully Qualified Domain Name :- $ServerFQDN"
    $ServerBaseUrl = Get-ArcGISComponentBaseUrl -ComponentName "Server" -FQDN $ServerFQDN
    $Referer = $ServerBaseUrl
	
	Write-Verbose "Getting Server Token for user '$($SiteAdministrator.UserName)' from '$ServerBaseUrl'"

    $serverToken = Get-ServerToken -URL $ServerBaseUrl -Credential $SiteAdministrator -Referer $Referer
    if(-not($serverToken.token)) {
        Write-Verbose "Get Server Token Response:- $serverToken"
        throw "Unable to retrieve Server Token for '$($SiteAdministrator.UserName)'"
    }
    Write-Verbose "Connected to Server successfully and retrieved token for '$($SiteAdministrator.UserName)'"
	$result = $true
	
	if($result -and $SocMaximumHeapSize -gt 0){
        $machineDetails = Get-MachineProperties `
                            -URL $ServerBaseUrl `
                            -Token $serverToken.token `
                            -Referer $Referer `
                            -MachineName $ServerFQDN

		# if the property is missing, or doesn't match the user-supplied value, fail
		if(-not($machineDetails.PSObject.Properties.Match('socMaxHeapSize')) -or $machineDetails.socMaxHeapSize -ne $SocMaximumHeapSize){
            Write-Verbose "SocMaximumHeapSize needs to be updated. Expected - $SocMaximumHeapSize, Current - $($machineDetails.socMaxHeapSize)"
            $result = $false
        }
        else {
            Write-Verbose "SocMaximumHeapSize is already set to $SocMaximumHeapSize"
        }
	}

	$result    
}

Export-ModuleMember -Function *-TargetResource
