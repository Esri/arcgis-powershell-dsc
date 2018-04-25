<#
    .SYNOPSIS
        Configures a WebAdaptor
    .PARAMETER Ensure
        Take the values Present or Absent. 
        - "Present" ensures that WebAdaptor is Configured.
        - "Absent" ensures that WebAdaptor is unconfigured - Not Implemented.
    .PARAMETER Component
        Sets the type of WebAdaptor to be installed - Server or Portal
    .PARAMETER HostName
        Host Name of the Machine on which the WebAdaptor is Installed
    .PARAMETER ComponentHostName
        Host Name of the Server or Portal to be configured with the WebAdaptor
    .PARAMETER Context
        Context with which the WebAdaptor is to be Configured, same as the one with which it was installed.
    .PARAMETER OverwriteFlag
        Boolean to indicate whether overwrite of the webadaptor settings already configured should take place or not.
    .PARAMETER AdminAccessEnabled
        Boolean to indicate whether Admin Access to Sever Admin API and Manager is enabled or not. Default - True
#>

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [ValidateSet("Server","Portal")]
        [System.String]
        $Component,

        [parameter(Mandatory = $true)]
		[System.String]
		$HostName,

		[parameter(Mandatory = $true)]
		[System.String]
		$ComponentHostName,

        [parameter(Mandatory = $true)]
        [System.String]
        $Context,

        [parameter(Mandatory = $true)]
        [System.Boolean]
        $OverwriteFlag = $false,

        [System.Management.Automation.PSCredential]
		$SiteAdministrator,
        
        [System.Boolean]
        $AdminAccessEnabled = $true
    )
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    $null 
}
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [ValidateSet("Server","Portal")]
        [System.String]
        $Component,

        [parameter(Mandatory = $true)]
		[System.String]
		$HostName,

		[parameter(Mandatory = $true)]
		[System.String]
		$ComponentHostName,

        [parameter(Mandatory = $true)]
        [System.String]
        $Context,

        [parameter(Mandatory = $true)]
        [System.Boolean]
        $OverwriteFlag = $false,

        [System.Management.Automation.PSCredential]
        $SiteAdministrator,
        
        [System.Boolean]
        $AdminAccessEnabled = $true
    )

    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    if($Ensure -ieq 'Present') {
        try
        {
            $ExecPath = Join-Path ${env:CommonProgramFiles(x86)} '\ArcGIS\WebAdaptor\IIS\Tools\ConfigureWebAdaptor.exe'
            $Arguments = ""
            if($Component -ieq 'Server') {
                
                $AdminAccessString = "false"
                if($AdminAccessEnabled){
                    $AdminAccessString = "true"
                }

                $SiteURL = "https://$($ComponentHostName):6443"
                $WAUrl = "http://$($HostName)/$($Context)/webadaptor"
                Write-Verbose $WAUrl
                $SiteUrlCheck = "$($SiteURL)/arcgis/rest/info?f=json"
                Wait-ForUrl $SiteUrlCheck -HttpMethod 'GET'
                $Arguments = "/m server /w $WAUrl /g $SiteURL /u $($SiteAdministrator.UserName) /p $($SiteAdministrator.GetNetworkCredential().Password) /a $AdminAccessString"
            }
            elseif($Component -ieq 'Portal'){
                $SiteURL = "https://$($ComponentHostName):7443"
                $WAUrl = "https://$($HostName)/$($Context)/webadaptor"
                Write-Verbose $WAUrl
                $SiteUrlCheck = "$($SiteURL)/arcgis/sharing/rest/info?f=json"
                Wait-ForUrl $SiteUrlCheck -HttpMethod 'GET'
                $Arguments = "/m portal /w $WAUrl /g $SiteURL /u $($SiteAdministrator.UserName) /p $($SiteAdministrator.GetNetworkCredential().Password)"
            }
            Write-Verbose "Executing $ExecPath with arguments $Arguments"
            Write-Verbose "$ExecPath $Arguments"
            #Start-Process -FilePath $ExecPath -ArgumentList $Arguments -Wait

            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $ExecPath
            $psi.Arguments = $Arguments
            $psi.UseShellExecute = $false #start the process from it's own executable file    
            $psi.RedirectStandardOutput = $true #enable the process to read from standard output
            $psi.RedirectStandardError = $true #enable the process to read from standard error
            
            $p = [System.Diagnostics.Process]::Start($psi)
            $p.WaitForExit()
            $op = $p.StandardOutput.ReadToEnd()
            if($op -and $op.Length -gt 0) {
                Write-Verbose "Output of execution:- $op"
                if($op.StartsWith("ERROR")){
                    throw $op
                }
            }
            $err = $p.StandardError.ReadToEnd()
            if($err -and $err.Length -gt 0) {
                Write-Verbose $err
                throw $err
            }
        }catch{
            Write-Verbose "[WARNING]:- Error:- $_"
            if($Component -ieq 'Portal'){
                $PortalFQDN = Get-FQDN $ComponentHostName #->SiteURL
                try{
                    $dnsName = Resolve-DnsName -Name $HostName -Type ANY
                }catch{
                    $dnsName = [System.Net.Dns]::GetHostAddresses($HostName)
                }
                $MachineIP = ($dnsName | Select-Object -First 1).IPAddress 
                $Referer = "http://localhost"
                $WebAdaptorUrl = "https://$($HostName)/$($Context)"
                
                $token = Get-PortalToken -PortalHostName $PortalFQDN -SiteName 'arcgis' -Credential $SiteAdministrator -Referer $Referer		    

                $WebAdaptorsForPortal = Get-WebAdaptorsForPortal -PortalHostName $PortalFQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer
				Write-Verbose "Current number of WebAdaptors on Portal:- $($WebAdaptorsForPortal.webAdaptors.Length)"
                $AlreadyExists = $false
                $WebAdaptorId = ""
				$WebAdaptorsForPortal.webAdaptors | Where-Object { $_.httpPort -eq 80 -and $_.httpsPort -eq 443 } | ForEach-Object {
                    if($_.webAdaptorURL -ieq  $WebAdaptorUrl) {
                        Write-Verbose "Webadaptor with require properties URL $($_.webAdaptorURL) and Name $($_.machineName) already exists"
                        $AlreadyExists = $true
                        $WebAdaptorId = $_.id
                        #break
                    }
				}
                
                if(-not($AlreadyExists)) {        
					#Register the ExternalDNSName and PortalEndPoint as a web adaptor for Portal
					Write-Verbose "Registering the ExternalDNSName Endpoint with Url $WebAdaptorUrl and MachineName $ExternalDNSName as a Web Adaptor for Portal"
					Register-WebAdaptorForPortal -PortalHostName $PortalFQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer `
                                                                        -WebAdaptorUrl $WebAdaptorUrl -MachineName $HostName -MachineIP $MachineIP -HttpPort 80 -HttpsPort 443
                    
                    Write-Verbose "Waiting 3 minutes for web server to apply changes before polling for endpoint being available"
                    Start-Sleep -Seconds 180 # Add a 3 minute wait to allow the web server to go down
                    Write-Verbose "Updated Web Adaptors which causes a web server restart. Waiting for portaladmin endpoint 'https://$($PortalFQDN):7443/arcgis/portaladmin/' to come back up"
                    Wait-ForUrl -Url "https://$($PortalFQDN):7443/arcgis/portaladmin/" -MaxWaitTimeInSeconds 360 -HttpMethod 'GET' -LogFailures
                    Write-Verbose "Finished waiting for portaladmin endpoint 'https://$($PortalFQDN):7443/arcgis/portaladmin/' to come back up"
                    
                    $WebAdaptorsForPortal = Get-WebAdaptorsForPortal -PortalHostName $PortalFQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer
				    $WebAdaptorsForPortal.webAdaptors | Where-Object { $_.httpPort -eq 80 -and $_.httpsPort -eq 443 } | ForEach-Object {
                        if($_.webAdaptorURL -ieq  $WebAdaptorUrl) {
                            $WebAdaptorId = $_.id
                        }
                    }    
                }
                
                try{
                    Write-Verbose "Configuring WebAdaptor on Machine"

                    $PortalSiteUrl = "https://$($PortalFQDN):7443"
                    Wait-ForUrl "$PortalSiteUrl/arcgis/portaladmin/" -HttpMethod 'POST'
                    $PortalMachines = Get-PortalMachines -PortalHostName $PortalFQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer
                    
                    $pspath = "$env:SystemDrive\inetpub\wwwroot\$($Context)\WebAdaptor.config"
                    $WAConfigFile = New-Object System.Xml.XmlDocument
                    $WAConfigFile.Load($pspath)
                    $SharedK = Get-SharedKey -PortalHostName $PortalFQDN -SiteName 'arcgis' -Token $token.token -Referer $Referer
                    
                    if($WAConfigFile.SelectSingleNode("//Config/Portal/SharedKey")){
                        $nd = $WAConfigFile.SelectSingleNode("//Config/Portal/SharedKey")
                        $nd.InnerText = $SharedK
                    }else{
                        [System.XML.XMLElement]$SharedKey = $WAConfigFile.CreateElement("SharedKey");
                        $SharedKey.InnerText = $SharedK
                        $WAConfigFile.SelectSingleNode("//Config/Portal").AppendChild($SharedKey)
                    }

                    if($WAConfigFile.SelectSingleNode("//Config/Portal/Id")){
                        $nd = $WAConfigFile.SelectSingleNode("//Config/Portal/Id")
                        $nd.InnerText = $WebAdaptorId
                    }else{
                        [System.XML.XMLElement]$Id = $WAConfigFile.CreateElement("Id");
                        $Id.InnerText = $WebAdaptorId
                        $WAConfigFile.SelectSingleNode("//Config/Portal").AppendChild($Id)
                    }
                    
                    if($WAConfigFile.SelectSingleNode("//Config/Portal/HttpPort")){
                        $nd = $WAConfigFile.SelectSingleNode("//Config/Portal/HttpPort")
                        $nd.InnerText = "7080"
                    }else{
                        [System.XML.XMLElement]$HttpPort = $WAConfigFile.CreateElement("HttpPort");
                        $HttpPort.InnerText = "7080"
                        $WAConfigFile.SelectSingleNode("//Config/Portal").AppendChild($HttpPort)
                    }

                    if($WAConfigFile.SelectSingleNode("//Config/Portal/HttpsPort")){
                        $nd = $WAConfigFile.SelectSingleNode("//Config/Portal/HttpsPort")
                        $nd.InnerText = "7443"
                    }else{
                        [System.XML.XMLElement]$HttpsPort = $WAConfigFile.CreateElement("HttpsPort");
                        $HttpsPort.InnerText =  "7443"
                        $WAConfigFile.SelectSingleNode("//Config/Portal").AppendChild($HttpsPort)
                    }

                    if($WAConfigFile.SelectSingleNode("//Config/Portal/URL")){
                        $nd = $WAConfigFile.SelectSingleNode("//Config/Portal/URL")
                        $nd.InnerText = $PortalSiteUrl
                    }else{
                        [System.XML.XMLElement]$URL = $WAConfigFile.CreateElement("URL");      
                        $URL.InnerText = $PortalSiteUrl         
                        $WAConfigFile.SelectSingleNode("//Config/Portal").AppendChild($URL)
                    }

                    if($WAConfigFile.SelectSingleNode("//Config/Portal/PortalNodes") -and $WAConfigFile.SelectSingleNode("//Config/Portal/PortalNodes").HasChildNodes){
                        Write-Verbose "Portal Nodes Node exists"
                    }else{
                        [System.XML.XMLElement]$PortalNodes = $WAConfigFile.CreateElement("PortalNodes");
                        $WAConfigFile.SelectSingleNode("//Config/Portal").AppendChild($PortalNodes)
                    }
  
                    ForEach($PMachine in $PortalMachines){
                        #$nd = $WAConfigFile.SelectSingleNode("//Config/Portal/Id")
                        #$nd.InnerText = $WebAdaptorId

                        $node = $WAConfigFile.Config.Portal.PortalNodes.ChildNodes | where {$_.'#text' -eq $PMachine}
                        if(-not($node)){
                            [System.XML.XMLElement]$elem = $WAConfigFile.CreateElement("Node");
                            $elem.InnerText = $PMachine
                            $WAConfigFile.SelectSingleNode("//Config/Portal/PortalNodes").AppendChild($elem)
                        }
                    }

                    $WAConfigFile.Save($pspath)

                    # Recycle the application pool
                    Import-Module WebAdministration
                    $pool = (Get-Item "IIS:\Sites\Default Web Site\$Context"| Select-Object applicationPool).applicationPool
                    Restart-WebAppPool $pool
                    Write-Verbose "WebAppPool Recycled. Sleeping for a minute for it to comeback up."
                    Start-Sleep -Seconds 60
                }catch{
                    Write-Verbose "[WARNING]:- Some Error Occured: $_"
                }
            }
        }
    }else{
        Write-Verbose "Absent Not Implemented Yet!"
    }
}
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [ValidateSet("Server","Portal")]
        [System.String]
        $Component,

        [parameter(Mandatory = $true)]
		[System.String]
		$HostName,

		[parameter(Mandatory = $true)]
		[System.String]
		$ComponentHostName,

        [parameter(Mandatory = $true)]
        [System.String]
        $Context,

        [parameter(Mandatory = $true)]
        [System.Boolean]
        $OverwriteFlag = $false,

        [System.Management.Automation.PSCredential]
		$SiteAdministrator,
        
        [System.Boolean]
        $AdminAccessEnabled = $true
    )
    [System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    Import-Module $PSScriptRoot\..\..\ArcGISUtility.psm1 -Verbose:$false

    $WAInstalls = (get-wmiobject Win32_Product| Where-Object {$_.Name -match 'Web Adaptor' -and $_.Vendor -eq 'Environmental Systems Research Institute, Inc.'})
    $result = $false
    foreach($wa in $WAInstalls){
        if($wa.InstallLocation -match "\\$($Context)\\"){
            $WAConfigPath = Join-Path $wa.InstallLocation 'WebAdaptor.config'
            [xml]$WAConfig = Get-Content $WAConfigPath
            $ServerSiteURL = "https://$($ComponentHostName):6443"
            $PortalSiteUrl = "https://$($ComponentHostName):7443"
            if(($Component -ieq "Server") -and ($WAConfig.Config.GISServer.SiteURL -like $ServerSiteURL)){
                if($OverwriteFlag){
                    $result = $false
                }else{
                    if (URLAvailable("https://$Hostname/$Context/admin")){
                        if(-not($AdminAccessEnabled)){
                            $result = $false
                        }else{
                            $result = $true
                        } 
                    }else{
                        if($AdminAccessEnabled){
                            $result = $false
                        }else{
                            $result = $true
                        } 
                    }
                }
            }elseif(($Component -ieq "Portal") -and ($WAConfig.Config.Portal.URL -like $PortalSiteUrl)){
                if($OverwriteFlag){
                  $result =  $false
                }else{
                   $result =  $true
                }
            }else{
                $result = $false
            }
            break
        }
    } 
    $result
}

function URLAvailable([string]$Url){
    # fixed (all status codes except 200 will throw an error)
    Write-Verbose "Checking URLAvailable : $Url"

    try{
        $HTTP_Response_Available = Invoke-WebRequest -Uri $Url -Method GET -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing
        $HTTP_Status_Available = [int]$HTTP_Response_Available.StatusCode
    }catch [System.Net.WebException]{
        $HTTP_Status_Available = [int]$_.Exception.HTTP_Response_Available.StatusCode #every status code except 200
    }finally{
        $temp = $HTTP_Response_Available.Close 
    }
    if ($HTTP_Status_Available -eq 200){
        $result =  $true
    }else{
        $result = $false
    }
    $result
}

function Get-WebAdaptorsForPortal
{
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

	Invoke-ArcGISWebRequest -HttpMethod "GET" -Url ("https://$($PortalHostName):$($Port)/$($SiteName)" + "/portaladmin/system/webadaptors") -HttpFormParameters @{ token = $Token; f = 'json' } -Referer $Referer -LogResponse   
}

function Get-PortalMachines
{
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

    $MachineNames = @()
    $Machines = Invoke-ArcGISWebRequest -HttpMethod "GET" -Url ("https://$($PortalHostName):$($Port)/$($SiteName)" + "/portaladmin/machines") -HttpFormParameters @{ token = $Token; f = 'json' } -Referer $Referer -LogResponse
    $Machines.machines | ForEach-Object {
       $MachineNames += $_.machineName
    }

    $MachineNames
}

function Get-SharedKey
{
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

    $SharedKey = Invoke-ArcGISWebRequest -HttpMethod "GET" -Url ("https://$($PortalHostName):$($Port)/$($SiteName)" + "/portaladmin/system/webadaptors/config") -HttpFormParameters @{ token = $Token; f = 'json' } -Referer $Referer
    $SharedKey.sharedKey
}

function Register-WebAdaptorForPortal 
{
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
        
        [System.String]
		$MachineIP, 

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
                    machineIP = $MachineIP
                    httpPort = $HttpPort.ToString()
                    httpsPort = $HttpsPort.ToString()
                  }
	try {
		Invoke-ArcGISWebRequest -Url $RegisterWebAdaptorsUrl -HttpFormParameters $WebParams -Referer $Referer -TimeoutSec 360 -ErrorAction Ignore
	}
	catch {
		Write-Verbose "[WARNING] Register-WebAdaptorForPortal returned an error. Error:- $_"
	}
}

Export-ModuleMember -Function *-TargetResource


