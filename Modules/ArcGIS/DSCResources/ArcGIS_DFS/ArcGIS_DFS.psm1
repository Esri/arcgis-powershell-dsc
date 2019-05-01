function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$DomainName
	)

	$null
}

$script:ImpersonationUtils = Add-Type -Namespace Esri -Name Impersonation -MemberDefinition @"
   // http://msdn.microsoft.com/en-us/library/aa378184.aspx
   [DllImport("advapi32.dll", SetLastError = true)]
   public static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

   // http://msdn.microsoft.com/en-us/library/aa379317.aspx
   [DllImport("advapi32.dll", SetLastError=true)]
   public static extern bool RevertToSelf();
"@ -passthru

function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$DomainName,

        [parameter(Mandatory = $true)]
		[System.String]
		$FileSharePath,

		[parameter(Mandatory = $true)]
		[System.String]
		$FileShareName,

        [parameter(Mandatory = $true)]
		[System.String]
		$ReplicationGroupName,

        [parameter(Mandatory = $false)]
		[System.Management.Automation.PSCredential]
		$AdminCredentials,

        [parameter(Mandatory = $true)]
		[System.String[]]
		$ReplicationNodeNames,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)

    if($Ensure -ieq 'Present') 
    {
        Import-Module $pshome\modules\dfsn\DFSN | Out-Null
                
        if($AdminCredentials) {
             [IntPtr]$userToken = [Security.Principal.WindowsIdentity]::GetCurrent().Token
            if(!$ImpersonationUtils::LogonUser( 
                $AdminCredentials.GetNetworkCredential().UserName, 
                $AdminCredentials.GetNetworkCredential().Domain, 
                $AdminCredentials.GetNetworkCredential().Password, 2, 0, [ref]$userToken)
            ) {
                throw (new-object System.ComponentModel.Win32Exception( [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() ) )
            }        

            $Identity = New-Object Security.Principal.WindowsIdentity $userToken
            if($Identity) {
                Write-Verbose "About to impersonate User $($Identity.Name)"
                $UserContext = $Identity.Impersonate()
                Write-Verbose "Successfully impersonated User $($Identity.Name)"
            }else {
                Write-Verbose "Unable to create identity object from token"
            }
        }

        $path = "\\$DomainName\$FileShareName"
        $node = $env:COMPUTERNAME
        $TargetPath = "\\$node\$FileShareName" 
        if(-not(Get-DfsnRoot | Where-Object { $_.Path -ieq $path })) {
            Write-Verbose "New DfsnRoot for $node with target path $TargetPath and Path $path"
            New-DfsnRoot -TargetPath $TargetPath -Type DomainV2 -Path $path -Verbose -GrantAdminAccounts '\\esriazure\esriadmin' 
        }
        else {
            Write-Verbose "DfsnRoot for $node already exists with target path $TargetPath and Path $path"
        }     
        
        Import-Module $pshome\modules\dfsr\DFSR | Out-Null

        if(-not(Get-DfsReplicationGroup -GroupName $ReplicationGroupName -DomainName $DomainName)){
            Write-Verbose "Replication Group '$ReplicationGroupName' for Domain '$DomainName' does not exist. Creating it"
            New-DfsReplicationGroup -GroupName $ReplicationGroupName -DomainName $DomainName 
        }else {
            Write-Verbose "Replication Group '$ReplicationGroupName' for Domain '$DomainName' already exists"
        }
       
        if(-not(Get-DfsReplicatedFolder -GroupName $ReplicationGroupName -FolderName $FileShareName -DomainName $DomainName)){
            Write-Verbose "Replication Folder '$FileShareName' in Group '$ReplicationGroupName' for Domain '$DomainName' does not exist. Creating it"
            New-DfsReplicatedFolder -GroupName $ReplicationGroupName -FolderName $FileShareName -DomainName $DomainName 
        }else{
            Write-Verbose "Replication Folder '$FileShareName' in Group '$ReplicationGroupName' for Domain '$DomainName' already exists"
        }

        if(-not(Get-DfsrMember -GroupName $ReplicationGroupName -ComputerName $node -DomainName $DomainName)){
            Write-Verbose "Node $node is not a member of the replication group '$ReplicationGroupName'. Adding it"
            Add-DfsrMember -GroupName $ReplicationGroupName -ComputerName $node -DomainName $DomainName 
        }else{
            Write-Verbose "Node $node is already a member of the replication group '$ReplicationGroupName'"
        }

        $Primary = $ReplicationNodeNames | Sort-Object | Select-Object -First 1
        $Secondary = $ReplicationNodeNames | Sort-Object | Select-Object -Last 1
        $IsPrimary = ($Primary -ieq $node)
        if($IsPrimary) {
            Write-Verbose "Node $node is the Primary. Setting Membership" 
            Set-DfsrMembership -GroupName $ReplicationGroupName -FolderName $FileShareName -ContentPath $FileSharePath -ComputerName $Primary -DomainName $DomainName -PrimaryMember $true -Force  
            
        }else{            
            if($Primary -ine $Secondary){
                Write-Verbose "Node $node is the Secondary. Adding Connection" 
                Add-DfsrConnection -GroupName $ReplicationGroupName -SourceComputerName $Primary -DestinationComputerName $Secondary -DomainName $DomainName  

                Write-Verbose "Set Membership"
                Set-DfsrMembership -GroupName $ReplicationGroupName -FolderName $FileShareName -ContentPath $FileSharePath -ComputerName $Secondary -DomainName $DomainName -Force 
           }
        }    
        
        if($UserContext) {
            #Write-Verbose "Undo Impersonation"
            try {
                $UserContext.Undo();
                $UserContext.Dispose();
            }catch{}
        }   

    }else{
        Write-Warning 'Absent not implemented'
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
		$DomainName,

        [parameter(Mandatory = $true)]
		[System.String]
		$FileSharePath,

		[parameter(Mandatory = $true)]
		[System.String]
		$FileShareName,

        [parameter(Mandatory = $true)]
		[System.String]
		$ReplicationGroupName,

        [parameter(Mandatory = $false)]
		[System.Management.Automation.PSCredential]
		$AdminCredentials,

        [parameter(Mandatory = $true)]
		[System.String[]]
		$ReplicationNodeNames,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure
	)

    $result = $false
    
    if(Get-DfsReplicationGroup -GroupName $ReplicationGroupName -DomainName $DomainName){
        Write-Verbose "Replication Group '$ReplicationGroupName' for Domain '$DomainName' already exists"
        $result = $true
    }else {
        Write-Verbose "Replication Group '$ReplicationGroupName' for Domain '$DomainName' does not exist"
    }
       
    if($result) {
        if(-not(Get-DfsReplicatedFolder -GroupName $ReplicationGroupName -FolderName $FileShareName -DomainName $DomainName)){
            Write-Verbose "Replication Folder '$FileShareName' in Group '$ReplicationGroupName' for Domain '$DomainName' does not exist." 
            $result = $false            
        }else{
            Write-Verbose "Replication Folder '$FileShareName' in Group '$ReplicationGroupName' for Domain '$DomainName' already exists"
            $result = $true
        }
    }

    $node = $env:COMPUTERNAME
    if($result) {
        if(-not(Get-DfsrMember -GroupName $ReplicationGroupName -ComputerName $node -DomainName $DomainName)){
            Write-Verbose "Node $node is not a member of the replication group '$ReplicationGroupName'." 
            $result = $false           
        }else{
            Write-Verbose "Node $node is already a member of the replication group '$ReplicationGroupName'"
            $result = $true
        }
    }

    if($result) {
        $Primary = $ReplicationNodeNames | Sort-Object | Select-Object -First 1
        $Secondary = $ReplicationNodeNames | Sort-Object | Select-Object -Last 1 
    
        $IsPrimary = ($Primary -ieq $node)
        if($IsPrimary) {
            Write-Verbose "Node $node should be the Primary" 
            if((Get-DfsrMembership -GroupName $ReplicationGroupName -ComputerName $env:COMPUTERNAME -DomainName $DomainName).PrimaryMember){
                Write-Verbose "Node $node is the primary"
                $result = $true                  
            }else { 
                Write-Verbose "Node $node is NOT the primary as required"
                $result = $false
            }
            if($result) {   
                if((Get-DfsrMembership -GroupName $ReplicationGroupName -ComputerName $env:COMPUTERNAME -DomainName $DomainName).ContentPath -ieq $FileSharePath){
                    Write-Verbose "Content Path on Node $node is as expected"
                    $result = $true 
                }else { 
                    Write-Verbose "Content Path on Node $node is NOT as expected"
                    $result = $false
                }
            }
        }else{            
            if($Primary -ine $Secondary){
                Write-Verbose "Node $node is the Secondary" 
                if((Get-DfsrMembership -GroupName $ReplicationGroupName -ComputerName $env:COMPUTERNAME -DomainName $DomainName).PrimaryMember){
                    Write-Verbose "Node $node is the Primary. It should not be"
                    $result = $false  
                }
                
                if($result) {       
                    if((Get-DfsrMembership -GroupName $ReplicationGroupName -ComputerName $env:COMPUTERNAME -DomainName $DomainName).ContentPath -ine $FileSharePath){
                        $result = $false
                    }

                    if($result) {
                        if(-not(Get-DfsrConnection -GroupName $ReplicationGroupName -SourceComputerName $Primary -DestinationComputerName $Secondary -DomainName $DomainName)){
                            Write-Verbose "Connection between replication partners $Primary and $Secondary does not exist"
                            $result = $false 
                        }
                    }
                }
            }
        } 
    }


    if($Ensure -ieq 'Present') {
	       $result   
    }
    elseif($Ensure -ieq 'Absent') {        
        (-not($result))
    }
}


Export-ModuleMember -Function *-TargetResource

