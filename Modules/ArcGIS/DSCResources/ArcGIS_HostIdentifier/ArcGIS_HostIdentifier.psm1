

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
        [ValidateSet("ArcGIS Server","Portal for ArcGIS", "ArcGIS Data Store")]
		[System.String]
		$Name
    )
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

	$null
}


function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
        [ValidateSet("ArcGIS Server","Portal for ArcGIS", "ArcGIS Data Store")]
		[System.String]
		$Name,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
    )
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    if($Name -ieq 'ArcGIS Server')
    {
        if($Ensure -ieq 'Present') {
        
            $RegKey = Get-EsriRegistryKeyForService -ServiceName $Name
            $InstallDir =(Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir 
            $SiteName = 'arcgis'
            $FQDN = Get-FQDN $env:COMPUTERNAME    
            Write-Verbose "Fully Qualified Domain Name :- $FQDN"   

            $configuredHostName = Get-ConfiguredHostName -InstallDir $InstallDir
            Write-Verbose "Configured host name:- $configuredHostName"
            if($configuredHostName -ine $FQDN){
                Write-Verbose "Configured Host Name $configuredHostName is not equal to $($FQDN). Setting it"

                $ServiceName = $Name
			    try {
				    Write-Verbose "Restarting Service '$ServiceName'"
				    Stop-Service -Name $ServiceName -Force -ErrorAction Ignore
				    Write-Verbose 'Stopping the service' 
				    Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Stopped'
				    Write-Verbose 'Stopped the service'
			    }catch {
                    Write-Verbose "[WARNING] Stopping Service $_"
                }

                if(Set-ConfiguredHostName -InstallDir $InstallDir -HostName $FQDN) { 
                    Write-Verbose "Updated the hostname successfully"
                }

                try {
				    Write-Verbose 'Starting the service'
				    Start-Service -Name $ServiceName -ErrorAction Ignore        
				    Wait-ForServiceToReachDesiredState -ServiceName $ServiceName -DesiredState 'Running'
				    Write-Verbose "Restarted Service $ServiceName"
			    }catch {
                    Write-Verbose "[WARNING] Starting Service $_"
                }

			    Write-Verbose "Waiting for Server 'https://$($FQDN):6443/arcgis/admin' to initialize"
                Wait-ForUrl "https://$($FQDN):6443/$SiteName/admin" -HttpMethod 'GET'
            }   


            Write-Verbose "Waiting for Server 'https://$($FQDN):6443/arcgis/admin' to initialize"
            Wait-ForUrl "https://$($FQDN):6443/$SiteName/admin" -HttpMethod 'GET'

            $Referer = 'http://localhost'
            $ServerUrl = 'https://localhost:6443'            
            $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName $SiteName -Credential $SiteAdministrator -Referer $Referer
            $machines = Get-MachinesInSite -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer
            $hasMachine = $machines.machines | Where-Object { $_.machineName -ieq $FQDN }
            if(-not($hasMachine)) {
                Write-Verbose "Machine '$FQDN' not found in Site"
                $currentName = ($machines.machines | Select-Object -First 1).machineName
                Write-Verbose "Renaming Machine '$currentName' to '$FQDN'"
                Rename-MachineInSite -ServerURL $ServerUrl -SiteName $SiteName -Referer $Referer -Token $token.token -MachineName $currentName -NewMachineName $FQDN              
                Write-Verbose "Renamed Machine '$currentName' to '$FQDN'"

                Write-Verbose "Staring machine via admin API"
                Start-ArcGISServerMachine -ServerHostName 'localhost' -ServerPort 6443 -SiteName $SiteName -Token $token.token -MachineName $FQDN -Referer $Referer
            } else {
                Write-Verbose "Machine '$FQDN' found in Site"
            }  
            
        }else{
            Write-Warning 'Absent not implemented'
        }
    }else {
        Write-Warning 'Updating Host Identifier only implemented for "ArcGIS Server"'
    }
}


function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
        [ValidateSet("ArcGIS Server","Portal for ArcGIS", "ArcGIS Data Store")]
		[System.String]
		$Name,

        [parameter(Mandatory = $true)]
		[System.Management.Automation.PSCredential]
		$SiteAdministrator,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
    )
    
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    $result = $true
    if($Name -ieq 'ArcGIS Server')
    {
        $RegKey = Get-EsriRegistryKeyForService -ServiceName $Name
        $InstallDir =(Get-ItemProperty -Path $RegKey -ErrorAction Ignore).InstallDir    
        $FQDN = Get-FQDN $env:COMPUTERNAME    
        Write-Verbose "Fully Qualified Domain Name :- $FQDN"

        $configuredHostName = Get-ConfiguredHostName -InstallDir $InstallDir
        Write-Verbose "Configured host name:- $configuredHostName"
        if($configuredHostName -ine $FQDN){
            Write-Verbose "Configured Host Name $configuredHostName is not equal to $($FQDN)"
            $result = $false
        }   

        if($result) {
            $Referer = 'http://localhost'
            $ServerUrl = 'https://localhost:6443'
            $SiteName = 'arcgis'
            $token = Get-ServerToken -ServerEndPoint $ServerUrl -ServerSiteName $SiteName -Credential $SiteAdministrator -Referer $Referer
            $machines = Get-MachinesInSite -ServerURL $ServerUrl -SiteName $SiteName -Token $token.token -Referer $Referer
            $hasMachine = $machines.machines | Where-Object { $_.machineName -ieq $FQDN }
            if(-not($hasMachine)) {
                Write-Verbose "Machine '$FQDN' not found in Site"
                $result = $false                
            } else {
                Write-Verbose "Machine '$FQDN' found in Site"
            }     
        }

    }else {
        Write-Warning 'Updating Host identifier only implemented for "ArcGIS Server"'
    }
    
    if($Ensure -ieq 'Present') {
	    $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}

function Get-MachinesInSite
{
    [CmdletBinding()]
    param(
        [string]
        $ServerURL = 'https://localhost:6443', 

        [string]
        $SiteName = 'arcgis', 

        [string]
        $Token, 
        
        [string]
        $Referer = 'http://localhost'
    )
    $GetMachinesUrl  = $ServerURL.TrimEnd("/") + "/$SiteName/admin/machines/"
    Invoke-ArcGISWebRequest -Url $GetMachinesUrl -HttpFormParameters @{ f= 'json'; token = $Token  } -Referer $Referer -TimeOutSec 150 -HttpMethod POST
}

function Rename-MachineInSite
{
    [CmdletBinding()]
    param(
        [string]
        $ServerURL = 'https://localhost:6443', 

        [string]
        $SiteName = 'arcgis', 

        [string]
        $Token, 

        [string]
        $MachineName, 

        [string]
        $NewMachineName, 
        
        [string]
        $Referer = 'http://localhost'
    )
    $UpdateMachineUrl  = $ServerURL.TrimEnd("/") + "/$SiteName/admin/machines/rename"
    Invoke-ArcGISWebRequest -Url $UpdateMachineUrl -HttpFormParameters @{ f= 'json'; token = $Token; machineName = $MachineName; newMachineName = $NewMachineName  } -Referer $Referer -TimeOutSec 150 -HttpMethod POST
}

function Start-ArcGISServerMachine
{
    [CmdletBinding()]
    param(
    [System.String]
        [Parameter(Mandatory=$true)]
        $ServerHostName,

        [int]
        [Parameter(Mandatory=$true)]
        $ServerPort,

        [System.String]
        [Parameter(Mandatory=$false)]
        $SiteName = 'arcgis',

        [System.String]
        [Parameter(Mandatory=$true)]
        $Token,

        [System.String]
        [Parameter(Mandatory=$true)]
        $MachineName,

        [System.String]
        [Parameter(Mandatory=$false)]
        $Referer = 'http://localhost'
    )
    Invoke-ArcGISWebRequest -Url ("https://$($ServerHostName):$($ServerPort)/$SiteName" + '/admin/machines/' + $MachineName + '/start') -HttpFormParameters @{ f = 'json'; token = $Token } -Referer $Referer -TimeOutSec 150
}

Export-ModuleMember -Function *-TargetResource

