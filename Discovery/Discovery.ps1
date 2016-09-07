function Get-HuntTargets {
<#
.SYNOPSIS

	Build a target list from IP range or Active Directory Domain or OU lookup and formats output for use with PSHunt.
	Use this to perform reconnaisance prior to scanning systems with PSHunt or for general asset discovery and tracking.

	Project: PSHunt
	Author: Chris Gerritz (Twitter @gerritzc Github @singlethreaded)
	License: Apache License 2.0
	Required Dependencies: RSAT
							Expand-IPList
	Optional Dependencies: None
 
.DESCRIPTION
 
	Get-HuntTargets builds a target list by enumerating an IP address range or querying active directory using Get-ADComputer. 
	Uses Expand-IPList to interpret IP ranges or CIDR blocks. Performs Invoke-PortScan, Forward/Reverse DNS lookups, and formats the output for use with PSHunt. 

 
.PARAMETER IPRange

	Specifies the IP address range. The range provided can be in the form of a single IP address, a low-high range, or a CIDR range. Comma-delimited ranges may can be provided.

.PARAMETER CustomList

	An array of DNS Names or IP Addresses.  Can be pipelined in.
 
.PARAMETER Domain

	Specifies a Domain or Domain Controller to query for Computer Objects.  You can find a domain controller by doing the following:

	# Current Local System's Domain:
	C:\PS> Get-ADDomainController 

	# A Remote Domain (use the root domain name as the server address)
	C:\PS> Get-ADDomainController -Server Galactica.int -Credential $creds

.PARAMETER OUs

	Array of OUs to drill into using distinguished name syntax.  Default is all Computer Objects.
	 
.EXAMPLE

	C:\PS> Get-HuntTargets 74.125.228.0/29
	 
	Description
	-----------
	Returns a detailed list of live hosts specified by the CIDR range.
 
.EXAMPLE

	C:\PS> Get-HuntTargets '74.125.228.1,74.125.228.4-74.125.228.6'
	 
	Description
	-----------
	Returns a detailed list of live hosts specified by the comma seperated IP and IP range.

.EXAMPLE

	PS C:\> Get-HuntTargets -Domain galactica.int -OUs "OU=Flight Deck,DC=galactica,DC=int" -Credential $Creds

	Description
	-----------
	Returns the hostnames of computer objects found in the specified Organizational Unit on domain galactica.int

#>

    Param (
		[Parameter(	Position = 0, 
					Mandatory = $false,
					ValueFromPipeline=$false)]
        [String]
        $IpRange,
		
		[Parameter(	Mandatory = $false,
					ValueFromPipeline=$true)]
		[Alias("CustomList")]
        [String[]]
        $ComputerName,
		
		[Parameter(Mandatory = $false)]
        [String]
        $Domain,
		
		[Parameter(Mandatory = $false)]
        [String[]]
        $OUs,
		
		[Parameter(Mandatory = $false)]
		[Switch]
		$DiscoverOS,
		
		[Parameter(	Mandatory=$false)]
        [int]$ThrottleLimit=64,
	
		[Parameter(	Mandatory=$false)]
        [System.Management.Automation.PSCredential]
		$Credential	
    )

    BEGIN {
		
		$DiscoveryPorts = 22,80,135,139,443,445,1025,3389,5985,49152
				
		
		# Parse IP List, CIDR, etc. into array of IPs
		if ($IpRange) {
			Write-Verbose "Parsing IPRanges: $IpRange"
			$IPs = Expand-IPList $IpRange
			if ($IPs) {
				$Targets = $IPs
			} else {
				Write-Warning "Syntax Error with IpRange.  Try again."
				return
			}
		}
		
		# Query Domain
		if ($Domain) {
			Write-Verbose "Querying Domain $Domain"
			$Props = 'OperatingSystem','OperatingSystemServicePack','OperatingSystemVersion','Enabled','Created'
			
			if ($OUs) {
				$OUs | Foreach-Object {
					$OU = [String]$_
					Write-Verbose "Querying Organizational Unit (OU): <$OU> for all Windows-based Computer objects"
					try {
						# Query each OU
						
						$DomainComputers += Get-ADComputer -Filter '(Enabled -eq $True) -AND (OperatingSystem -like "*Windows*")' -Properties $Props -SearchBase $OU -Server $Domain -Credential $Credential
						<# 
							Created                    : 8/14/2016 6:46:53 PM
							DistinguishedName          : CN=WIN7-32-1,OU=Vyper,DC=galactica,DC=int
							DNSHostName                : WIN7-32-1.galactica.int
							Enabled                    : True
							Name                       : WIN7-32-1
							ObjectClass                : computer
							ObjectGUID                 : a490ee71-04e3-43b1-b45f-8b37d79e2c10
							OperatingSystem            : Windows 7 Enterprise
							OperatingSystemServicePack : Service Pack 1
							OperatingSystemVersion     : 6.1 (7601)
							SamAccountName             : WIN7-32-1$
							SID                        : S-1-5-21-1031827263-1101308967-1021258693-1110
							UserPrincipalName          :
						#>
						
					} catch {
						Write-Warning "ERROR: Bad OU:  $OU"
					}
				}
				# Add the DNSHostName of each unique computer object object to our target list
				$Targets += $DomainComputers | Sort-Object SID -Unique | Foreach-Object { $_.DNSHostname }
				
			} else {
				try {
					# Query the Domain for all computer Objects
					Write-Verbose "Querying Domain <$Domain> for all Windows-based Computer objects"
					$DomainComputers = Get-ADComputer -Filter '(Enabled -eq $True) -AND (OperatingSystem -like "*Windows*")' -Properties $Props -Server $Domain -Credential $Credential
				} catch {
					Write-Warning "ERROR: Well that didn't work"
				}
				# Add the DNSHostName of each unique computer object object to our target list
				$Targets += $DomainComputers | Foreach-Object { $_.DNSHostname }	
			}
			Write-Verbose "Domain Query complete.  $($Targets.Count) computer objects were registered in Active Directory"
		}
		
		$TargetCount = 0
	}
	
	PROCESS {

		# Check Custom List for proper format
		if ($ComputerName) {
			Write-Verbose "Adding Custom List to TargetList"
			$Targets += $ComputerName
		}
		
	}
	
	END {
	
		# Perform threaded portscan of targets
		Write-Verbose "Running discovery scan on $($Targets.Count) hosts"
		$PortScanResults = Invoke-HuntPortScan -ComputerName $Targets -Ports $DiscoveryPorts -ThrottleLimit $ThrottleLimit -Randomize
		<#
			ComputerName  : 192.168.8.112
			ICMP          : True
			Latency       : 0
			DNS           : win2k8r2.galactica.int
			IP            : 192.168.8.112
			IPAddressList : 192.168.8.112
			TCP22         : False
			TCP80         : False
			TCP135        : True
			TCP139        : True
			TCP443        : False
			TCP445        : True
			TCP1025       : False
			TCP3389       : True
			TCP5985       : True
			TCP49152      : False
		#>
		Write-Verbose "Scan results recieved.  Formating TargetList..."
		Foreach ($hostscan in $PortScanResults) {
			
			# Rearrange ports into it's own object
			$PortResults = New-Object PSObject
			$hostscan.PSObject.Properties | where { $_.Name -match "TCP" } | Foreach-Object {
				$PortResults | Add-Member -MemberType NoteProperty -Name $_.Name -Value $_.Value
				$hostscan.PSObject.Properties.Remove($_.Name)
			}
			$hostscan | Add-Member -MemberType NoteProperty -Name 'Ports' -Value $PortResults
			
			# Set Alive or not by checking success of portscans and ICMP (i.e. check all the boolean values)
			$hostscan | Add-Member -MemberType NoteProperty -Name 'StaleDNSEntry' -Value $false
			if ( $hostscan.PSObject.Properties | where { $_.TypeNameOfValue -eq "System.Boolean" } | where { $_.Value -eq $True } ) {
				$hostscan | Add-Member -MemberType NoteProperty -Name 'Alive' -Value $true
			} else {
				$hostscan | Add-Member -MemberType NoteProperty -Name 'Alive' -Value $false
				if ($hostscan.IPAddressList -AND ($hostscan.IPAddressList -notcontains $hostscan.IP)) {
					$hostscan.StaleDNSEntry = $true
				}
			}
			
			# Check for existance (alive or in DNS / Active Directory)
			if ( $hostscan.Alive -OR $hostscan.IPAddressList -OR ($hostscan.IP -AND $hostscan.DNS) ) {
				$hostscan | Add-Member -MemberType NoteProperty -Name 'Exists' -Value $true
			} else {
				$hostscan | Add-Member -MemberType NoteProperty -Name 'Exists' -Value $false
			}
			
			# Check available execution methods
			$ExecutionMethods = New-Object PSObject -Property @{
				WMI = $false
				Schtasks = $false
				PsExec = $false
				PSRemoting = $false
			}
			if ($hostscan.Ports.TCP135) {
				$ExecutionMethods.WMI = $True
			}
			if (($hostscan.Ports.TCP139) -OR ($hostscan.Ports.TCP135)) {
				$ExecutionMethods.Schtasks = $True
				$ExecutionMethods.PsExec = $True
			}
			if ($hostscan.Ports.TCP5985) {
				$ExecutionMethods.PSRemoting = $True
			}
			$hostscan | Add-Member -MemberType NoteProperty -Name 'ExecutionMethods' -Value $ExecutionMethods
			
			if ($a[0].ExecutionMethods.PSObject.Properties | where { $_.Value -eq $true }) {
				# If accessible, add to accessible host count
				$TargetCount += 1
			}
			
			# Operating System and any Domain Attributes we collected
			$hostscan | Add-Member -MemberType NoteProperty -Name 'OperatingSystem' -Value $Null 
			if ($Domain) {
				
				if ($DomainComputers.DNSHostName -contains $hostscan.dns) {
				
					$DomainProps = $DomainComputers | where { $_.DNSHostName -eq $hostscan.dns}
					
					if ($DomainProps) {
						$hostscan.OperatingSystem = $DomainProps.OperatingSystem
						$hostscan | Add-Member -MemberType NoteProperty -Name 'DistinguishedName' -Value $DomainProps.DistinguishedName
						$hostscan | Add-Member -MemberType NoteProperty -Name 'Created' -Value $DomainProps.Created
					}
				}
			}
			
			# Discover OS
			if ( ($DiscoverOS) -AND ($hostscan.OperatingSystem -eq $null) ) {
				# Discover OS
				if ($ExecutionMethods.WMI) {
					try {
						$hostscan.OperatingSystem = Get-WmiObject -Computer $hostscan.ComputerName -Class Win32_OperatingSystem -ErrorAction Stop | Select -ExpandProperty Caption
					} catch {
						Write-Warning "Could not reach $($hostscan.ComputerName) on WMI. Error: $_"
					}
				} 
			}
			
		}
		
		Write-Verbose "Enumeration Complete.  $TargetCount of $($Targets.Count) hosts are accessible"
		$PortScanResults
		
	}
}


function Invoke-HuntPortScan {
<#
.SYNOPSIS

	Conducts Multithreaded Port Scans, DNS lookups, and ICMP scans of a network to enumerate systems that are alive and remotely administerable.
	Invoke-HuntPortScan is optimized for large scale discovery of state and a small number of key remote admin services.  If you want to scan systems against a large number of ports, try PowerSploit's Invoke-PortScan.

	The optimal number of threads may vary in your environment.  
	Note: Memory consuption will add up at about 1-2MB per thread/runspace. 

	Project: PSHunt
	Author: Chris Gerritz (Twitter @gerritzc Github @singlethreaded)
	License: BSD 3-clause license
	Required Dependencies: None
	Optional Dependencies: None

	Original function authored by: 
	Svendsen Tech.
	Copyright (c) 2015, Joakim Svendsen
	All rights reserved.
	Runspace "framework" borrowed and adapted from Zachary Loeber's work.

	BSD 3-clause license. http://www.opensource.org/licenses/BSD-3-Clause

	Original Homepage/documentation:
	http://www.powershelladmin.com/wiki/Port_scan_subnets_with_PSnmap_for_PowerShell


.PARAMETER ComputerName
	List of IP or DNS/NetBIOS names

.PARAMETER PORTS
	Port or ports to check.

.PARAMETER NoDNS
	Do not perform DNS Reverse lookup.

.PARAMETER ThrottleLimit
	Number of concurrent threads. Default: 32.  As Hosts are scanned in randomized order, you can crank the threads to 100+ for optimal performance on a large network.

.PARAMETER Randomize
	Randomize the order of hosts scanned (helpful on large geographically distributed networks)

.PARAMETER HideProgress
	Do not display progress with Write-Progress

.PARAMETER Timeout
	Timeout in seconds for each thread. Default = 30.  Don't set too low, there is wierdness with threading that aren't directly intuitive - could cause problems.

.PARAMETER PortConnectTimeoutMs
	Port connect timeout in milliseconds. 5 seconds as a default for LAN scans. Increase for mobile/slow WAN.

.EXAMPLE

	PS C:\> Invoke-HuntPortScan -ComputerName 192.168.8.112 -Port 22,80,135,139,443,445,3389,5985
	
			ComputerName  : 192.168.8.112
			ICMP          : True
			Latency       : 0
			DNS           : win2k8r2.galactica.int
			IP            : 192.168.8.112
			IPAddressList : 192.168.8.112
			TCP22         : False
			TCP80         : False
			TCP135        : True
			TCP139        : True
			TCP443        : False
			TCP445        : True
			TCP3389       : True
			TCP5985       : True

			
.EXAMPLE

	PS C:\> $ScanResults = Invoke-HuntPortScan -Cn 192.168.1.1, synology, ubuntuvm, vista64esxi -Port 22,3389,80,443
	PS C:\> $ScanResults | Where { $_.TCP22 } | Format-Table -AutoSize

#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[ValidateNotNullOrEmpty()]
		[Alias('PSComputerName', 'Cn')]
		[string[]] 
		$ComputerName,
		
        [int[]] 
		$Ports = @(22,80,135,139,443,445,1025,3389,5985,49152),

        [switch] 
		$NoDNS,

        [int] 
		$ThrottleLimit = 64,
		
		[switch]
		$Randomize,
		
        [switch] 
		$HideProgress,

        [int] 
		$Timeout = 30,

        [int] 
		$PortConnectTimeoutMs = 5000
    )

	BEGIN {
	
	
		$MyEAP = 'Stop'
		$ErrorActionPreference = $MyEAP
		$StartTime = Get-Date
		if ($NoDNS) {
			$Dns = $False
		} else {
			$Dns = $True
		}
		
		$IPv4Regex = '(?:(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)\.){3}(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)'

		$PortData = [HashTable]::Synchronized(@{})
		
		$RunspaceTimers = [HashTable]::Synchronized(@{})
		$Runspaces = New-Object -TypeName System.Collections.ArrayList
		$RunspaceCounter = 0
		
		Write-Verbose -Message 'Creating initial session state.'
		$ISS = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
		$ISS.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList 'RunspaceTimers', $RunspaceTimers, ''))
		$ISS.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList 'PortData', $PortData, ''))
		
		Write-Verbose -Message 'Creating runspace pool.'
		$RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit, $ISS, $Host)
		$RunspacePool.ApartmentState = 'STA'
		$RunspacePool.Open()	
		
		
		## SCRIPTBLOCK
		$ScriptBlock = {
			[CmdletBinding()]
			param(
				[int] $ID,
				[string] $Computer,
				[int] $Port,
				[switch] $Dns,
				[switch] $ICMP,
				[int] $PortConnectTimeout
			)
			# Get the start time.
			$RunspaceTimers.$ID = Get-Date
			
			# The objects returned here are passed to the pipeline...
			if (-not $PortData.ContainsKey($Computer))
			{
				$PortData[$Computer] = New-Object -TypeName PSObject -Property @{ 
					ComputerName = $Computer
				}
			}
			
			# ICMP Scan
			if ($ICMP) {
				$PortData[$Computer] | Add-Member -MemberType NoteProperty -Name ICMP -Value $false -Force
				$PortData[$Computer] | Add-Member -MemberType NoteProperty -Name Latency -Value $null -Force
				try {
					$ping = Test-Connection -ComputerName $Computer -Count 1
					if ($ping) {
						$PortData[$Computer].ICMP = $True
						$PortData[$Computer].Latency = $ping.ResponseTime
						Write-Verbose "${Computer}: ICMP Ping to $Computer succeeded with Latency $($ping.ResponseTime)"
					} else {
						Write-Verbose "${Computer}: ICMP Ping to $Computer failed"
					}
				} catch {
					Write-Verbose "${Computer}: ICMP Ping to $Computer failed"
				}
			}

			# DNS or Reverse DNS Lookup
			if ($Dns)
			{
				$PortData[$Computer] | Add-Member -MemberType NoteProperty -Name 'DNS' -Value $null
				$PortData[$Computer] | Add-Member -MemberType NoteProperty -Name 'IP' -Value $null
				$PortData[$Computer] | Add-Member -MemberType NoteProperty -Name 'IPAddressList' -Value $null
				
				if ( ($Computer -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") -AND ($Computer -ne "127.0.0.1") ) {
					# $Computer is an IP - Do reverse lookup for hostname
					Write-Verbose "${Computer}: Resolving DNS for $Computer via Reverse Lookup"
					$PortData[$Computer].IP = $Computer
					try {
						$resolved = [System.Net.Dns]::GetHostEntry($Computer)
					} catch {
						# $Status = "WARNING: Could not resolve Hostname from IP"
						Write-Warning "${Computer}: WARNING: Could not resolve Hostname from IP"
					}
					$PortData[$Computer].DNS = $resolved.HostName
					$PortData[$Computer].IPAddressList= $resolved.AddressList.IPAddressToString
					
				} 
				elseif ($Computer -ne $null) {
					# $Computer is hostname - Resolve IP from hostname
					Write-Verbose "${Computer}: Resolving IP for $Computer via DNS Lookup"
					try {
						$resolved = [System.Net.Dns]::GetHostEntry($Computer)
					} catch {
						# $Status = "FAILURE: Could not resolve IP from Hostname"
						Write-Warning "${Computer}: FAILURE: Could not resolve IP from Hostname"
					}
					$PortData[$Computer].DNS = $resolved.HostName
					$PortData[$Computer].IPAddressList = $resolved.AddressList.IPAddressToString
					if ($resolved.AddressList.count -gt 1) {
						# Add first IPv4 address to IPAddress field
						$resolved.AddressList | where { $_.AddressFamily -eq "InterNetwork" } | foreach-Object { 
							$PortData[$Computer].IP = $_.IPAddressToString
							break 
						}
					} else {
						$PortData[$Computer].IP = $resolved.AddressList.IPAddressToString
					}
				}
				Write-Verbose "${Computer}: DNS resolution Complete on $Computer RESULTS: $($PortData[$Computer].DNS) ($($PortData[$Computer].IP)) # of IPs: $($PortData[$Computer].IPAddressList.Count)"
							
			} # end of if $Dns
			
			# Port Scan
			if ($Port) {
				#Write-Verbose -Message "Processing ${Computer}, TCP Port $Port in thread."
				$MySock, $IASyncResult, $Result = $Null, $Null, $Null
				$MySock = New-Object Net.Sockets.TcpClient
				$IASyncResult = [IAsyncResult] $MySock.BeginConnect($Computer, $Port, $null, $null)
				$Result = $IAsyncResult.AsyncWaitHandle.WaitOne($PortConnectTimeout, $true)
				if ($MySock.Connected)
				{
					$MySock.Close()
					$MySock.Dispose()
					$MySock = $Null
					Write-Verbose "${Computer}: TCP Port $Port is OPEN"
					$PortData[$Computer] | Add-Member -MemberType NoteProperty -Name "TCP$Port" -Value $True
				}
				else
				{
					$MySock.Close()
					$MySock.Dispose()
					$MySock = $Null
					Write-Verbose "${Computer}: TCP Port $Port is CLOSED"
					$PortData[$Computer] | Add-Member -MemberType NoteProperty -Name "TCP$Port" -Value $False
				}
			} # end Port
			
			# Emit object to pipeline!
			#$o
		} # end of script block that's run for each host/port/DNS

		## FUNCTIONS
		function Randomize-List {
		   Param(
			 [array]$InputList
		   )
		   return $InputList | Get-Random -Count $InputList.Count;
		}

		function Get-Result {
			[CmdletBinding()]
			param(
				[switch] $Wait
			)
			do
			{
				$More = $false
				foreach ($Runspace in $Runspaces) {
					$StartTime = $RunspaceTimers[$Runspace.ID]
					if ($Runspace.Handle.IsCompleted)
					{
						#Write-Verbose -Message ('Thread done for {0}' -f $Runspace.IObject)
						$Runspace.PowerShell.EndInvoke($Runspace.Handle)
						$Runspace.PowerShell.Dispose()
						$Runspace.PowerShell = $null
						$Runspace.Handle = $null
					}
					elseif ($Runspace.Handle -ne $null)
					{
						$More = $true
					}
					if ($Timeout -and $StartTime)
					{
						if ((New-TimeSpan -Start $StartTime).TotalSeconds -ge $Timeout -and $Runspace.PowerShell) {
							Write-Warning -Message ('Thread Timeout on {0} while performing {1}' -f $Runspace.IObject,$Runspace.Task)
							$Runspace.PowerShell.Dispose()
							$Runspace.PowerShell = $null
							$Runspace.Handle = $null
						}
					}
				}
				if ($More -and $PSBoundParameters['Wait'])
				{
					Start-Sleep -Milliseconds 100
				}
				foreach ($Thread in $Runspaces.Clone())
				{
					if (-not $Thread.Handle) {
						Write-Verbose -Message ('Removing {0} ({1}) from runspaces' -f $Thread.IObject,$Thread.Task)
						$Runspaces.Remove($Thread)
					}
				}
				if (-not $HideProgress)
				{
					$PercentComplete = ($RunspaceCounter - $Runspaces.Count) / $RunspaceCounter
					$ProgressSplatting = @{
						Activity = 'Discovery Scan'
						Status = 'Processing: {0} of {1} ({3:P0}) jobs complete. Using {2} threads' -f ($RunspaceCounter - $Runspaces.Count), $RunspaceCounter, $ThrottleLimit, $PercentComplete
						PercentComplete = $PercentComplete * 100
					}
					Write-Progress @ProgressSplatting
				}
			}
			while ($More -and $PSBoundParameters['Wait'])
		} # end of Get-Result
	  
		$StartTime = Get-Date
	}

	PROCESS {
		if ($Randomize) {
			# Randomize systems so it's not all against one subnet (only helpful on larger, distributed networks)
			 $Targets = Randomize-List -InputList $ComputerName		
		} else {
			$Targets = $ComputerName	
		}

		Write-Verbose "Scanning $($ComputerName.Count) hosts"
		
		foreach ($Computer in $Targets) {
			
			# Starting DNS thread if switch was specified.
			if ($Dns) {
				++$RunspaceCounter
				$psCMD = [System.Management.Automation.PowerShell]::Create().AddScript($ScriptBlock)
				[void] $psCMD.AddParameter('ID', $RunspaceCounter)
				[void] $psCMD.AddParameter('Computer', $Computer)
				[void] $PSCMD.AddParameter('Port', $Null)
				[void] $PSCMD.AddParameter('Dns', $true)
				[void] $PSCMD.AddParameter('ICMP', $null)
				[void] $psCMD.AddParameter('Verbose', $VerbosePreference)
				$psCMD.RunspacePool = $RunspacePool
				Write-Verbose -Message "Starting $Computer DNS thread"
				[void]$Runspaces.Add(@{
					Handle = $psCMD.BeginInvoke()
					PowerShell = $psCMD
					IObject = $Computer
					Task = 'DNS'
					ID = $RunspaceCounter
				})
			}
			
			# Starting ICMP Ping thread
			++$RunspaceCounter
			$psCMD = [System.Management.Automation.PowerShell]::Create().AddScript($ScriptBlock)
			[void] $psCMD.AddParameter('ID', $RunspaceCounter)
			[void] $psCMD.AddParameter('Computer', $Computer) #
			[void] $PSCMD.AddParameter('Port', $Null)
			[void] $PSCMD.AddParameter('Dns', $Null)
			[void] $PSCMD.AddParameter('ICMP', $true)
			[void] $psCMD.AddParameter('Verbose', $VerbosePreference)
			$psCMD.RunspacePool = $RunspacePool
			Write-Verbose -Message "Starting $Computer ping thread" #
			[void]$Runspaces.Add(@{
				Handle = $psCMD.BeginInvoke()
				PowerShell = $psCMD
				IObject = $Computer 
				Task = 'ICMP'
				ID = $RunspaceCounter
			})
			
			# Starting one thread for each port.
			foreach ($p in $Ports)
			{
				#Start-Sleep -Milliseconds 25
				$RunspaceCounter++
				$psCMD = [System.Management.Automation.PowerShell]::Create().AddScript($ScriptBlock)
				[void] $psCMD.AddParameter('ID', $RunspaceCounter)
					[void] $psCMD.AddParameter('Computer', $Computer)
					[void] $psCMD.AddParameter('Port', $p)
					[void] $psCMD.AddParameter('Dns', $Null)
					[void] $PSCMD.AddParameter('ICMP', $null)
					[void] $psCMD.AddParameter('PortConnectTimeout', $PortConnectTimeoutMs)
					[void] $psCMD.AddParameter('Verbose', $VerbosePreference)
					$psCMD.RunspacePool = $RunspacePool
				Write-Verbose -Message "Starting $Computer, TCP$p"
				[void]$Runspaces.Add(@{
					Handle = $psCMD.BeginInvoke()
					PowerShell = $psCMD
					IObject = $Computer
					Task = "TCP$p"
					ID = $RunspaceCounter
				})
			}
			#Get-Result
		}
	
	}
	
	END {
	
	    #Get-Result
		Get-Result -Wait
		if (-not $HideProgress)
		{
			Write-Progress -Activity 'Discovery Scan' -Status 'Done' -Completed
		}
		
		$TimeLapsed = New-TimeSpan -Start $StartTime
		$Message = “Scan against {0} hosts completed in {1:hh\:mm\:ss} +{1:fff}ms. Closing runspace pool.” -f $($ComputerName.Count),$TimeLapsed
		Write-Verbose -Message $Message
		
		$RunspacePool.Close()
		$RunspacePool.Dispose()
		
		[hashtable[]] $Script:ExportProperties = @{ Name = 'ComputerName'; Expression = { $_.Name } }
		$Script:ExportProperties += @{ Name = 'ICMP'; Expression = { $_.Value.ICMP } }
		$Script:ExportProperties += @{ Name = 'Latency'; Expression = { $_.Value.Latency } }
		if ($Dns)
		{
			$Script:ExportProperties += @{ Name = 'DNS'; Expression = { $_.Value.DNS } }
			$Script:ExportProperties += @{ Name = 'IP'; Expression = { $_.Value.IP } }
			$Script:ExportProperties += @{ Name = 'IPAddressList'; Expression = { $_.Value.IPAddressList } }
		}
		foreach ($p in $Ports | Sort-Object)
		{
			$Script:ExportProperties += @{ Name = "TCP$p"; Expression = [ScriptBlock]::Create("`$_.Value.'TCP$p'") }
		}
		
		# Return final data to pipeline
		$PortData.GetEnumerator() | Sort-Object -Property @{ 
			Expression ={ 
				if ($_.Name -match "\A$IPv4Regex\z") { 
					# Sort by IP Address Octet
					($_.Name.Split('.') | ForEach-Object { '{0:D3}' -f [int] $_ }) -join '.' 
				} else { 
					# Sort by hostname
					$_.Name 
				} 
			}
		} | Select-Object -Property $Script:ExportProperties
		
		# Run Garbage Collection as this function tends to consume a lot of memory if using a high number of threads
		[System.GC]::Collect()
	}
}


function Test-TCPPort {
	Param(	
		[Parameter(	Position=0, 
					Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[string]$ComputerName,

		[Parameter(	Position=1,
					Mandatory=$true)]			
		[int]$Port=445

	)

	$MySocket = $Null
	$IASyncResult = $Null
	$Result = $Null	
	$PortConnectTimeout = 5000
	
	$MySock = New-Object System.Net.Sockets.TcpClient
	$IASyncResult = [IAsyncResult] $MySock.BeginConnect($ComputerName, $Port, $null, $null)
	$Result = $IAsyncResult.AsyncWaitHandle.WaitOne($PortConnectTimeout, $true)
	if ($MySock.Connected) {
		$MySock.Close()
		$MySock.Dispose()
		$MySock = $Null
		Write-Verbose "${Computer}: TCP Port $Port is OPEN"
		return $True
	}
	else {
		$MySock.Close()
		$MySock.Dispose()
		$MySock = $Null
		Write-Verbose "${Computer}: TCP Port $Port is CLOSED"
		return $False
	}
}


function Test-TCPPorts {
	Param(	
		[Parameter(	Position=0, 
					Mandatory=$true,
					ValueFromPipeline=$True)]
		[ValidateNotNullorEmpty()]
		[string[]]$ComputerName,

		[Parameter(	Position=1,
					Mandatory=$true)]			
		[int[]]$Ports=445,
		
		[int]
		$PortConnectTimeout = 5000
	)

	BEGIN {
		
		function Invoke-TCPConnect {
			Param( 
				[String]$Computer,
				[Int]$Port
			)
			
			$MySocket = $Null
			$IASyncResult = $Null
			$Result = $Null	
			
			$MySock = New-Object System.Net.Sockets.TcpClient
			$IASyncResult = [IAsyncResult] $MySock.BeginConnect($Computer, $Port, $null, $null)
			$Result = $IAsyncResult.AsyncWaitHandle.WaitOne($PortConnectTimeout, $true)
			if ($MySock.Connected) {
				$MySock.Close()
				$MySock.Dispose()
				$MySock = $Null
				Write-Verbose "${Computer}: TCP Port $Port is OPEN"
				return $True
			}
			else {
				$MySock.Close()
				$MySock.Dispose()
				$MySock = $Null
				Write-Verbose "${Computer}: TCP Port $Port is CLOSED"
				return $False
			}		
		}
		
		
	}
	
	PROCESS {
		foreach ($computer in $ComputerName) {
			Write-Verbose "[$Computer] Attempting TCP Connect scan on ports: ($Port)"
			$Comp = New-Object -TypeName PSObject -Property @{
				ComputerName = $computer
			}
			foreach ($port in $Ports) {
				$result = Invoke-TCPConnect $computer $port
				$Comp | Add-Member -Type NoteProperty -Name "TCP$port" -Value $result
			}
			Write-Output $Comp
		}
	}
	
	END {
	
	}
}


# IP parsing function from PowersSploit (Parse-IPList).
function Expand-IPList ([String] $IpRange)
{

	function IPtoInt
	{
		Param([String] $IpString)
	
		$Hexstr = ""
		$Octets = $IpString.Split(".")
		foreach ($Octet in $Octets) {
				$Hexstr += "{0:X2}" -f [Int] $Octet
		}
		return [Convert]::ToInt64($Hexstr, 16)
	}

	function InttoIP
	{
		Param([Int64] $IpInt)
		$Hexstr = $IpInt.ToString("X8")
		$IpStr = ""
		for ($i=0; $i -lt 8; $i += 2) {
				$IpStr += [Convert]::ToInt64($Hexstr.SubString($i,2), 16)
				$IpStr += '.'
		}
		return $IpStr.TrimEnd('.')
	}

	$Ip = [System.Net.IPAddress]::Parse("127.0.0.1")

	foreach ($Str in $IpRange.Split(","))
	{
		$Item = $Str.Trim()
		$Result = ""
		$IpRegex = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
	
		# First, validate the input
		switch -regex ($Item)
		{
			"^$IpRegex/\d{1,2}$"
			{
				$Result = "cidrRange"
				break
			}
			"^$IpRegex-$IpRegex$"
			{
				$Result = "range"
				break
			}
			"^$IpRegex$"
			{
				$Result = "single"
				break
			}
			default
			{
				Write-Warning "Inproper input"
				return
			}
		}
	
		#Now, start processing the IP addresses
		switch ($Result)
		{
			"cidrRange"
			{
				$CidrRange = $Item.Split("/")
				$Network = $CidrRange[0]
				$Mask = $CidrRange[1]
			
				if (!([System.Net.IPAddress]::TryParse($Network, [ref] $Ip))) { Write-Warning "Invalid IP address supplied!"; return}
				if (($Mask -lt 0) -or ($Mask -gt 30)) { Write-Warning "Invalid network mask! Acceptable values are 0-30"; return}
			
				$BinaryIP = [Convert]::ToString((IPtoInt $Network),2).PadLeft(32,'0')
				#Generate lower limit (Excluding network address)
				$Lower = $BinaryIP.Substring(0, $Mask) + "0" * ((32-$Mask)-1) + "1"
				#Generate upperr limit (Excluding broadcast address)
				$Upper = $BinaryIP.Substring(0, $Mask) + "1" * ((32-$Mask)-1) + "0"
				$LowerInt = [Convert]::ToInt64($Lower, 2)
				$UpperInt = [Convert]::ToInt64($Upper, 2)
				for ($i = $LowerInt; $i -le $UpperInt; $i++) { InttoIP $i }
			}
			"range"
			{
				$Range = $item.Split("-")
			
				if ([System.Net.IPAddress]::TryParse($Range[0],[ref]$Ip)) { $Temp1 = $Ip }
				else { Write-Warning "Invalid IP address supplied!"; return }
			
				if ([System.Net.IPAddress]::TryParse($Range[1],[ref]$Ip)) { $Temp2 = $Ip }
				else { Write-Warning "Invalid IP address supplied!"; return }
			
				$Left = (IPtoInt $Temp1.ToString())
				$Right = (IPtoInt $Temp2.ToString())
			
				if ($Right -gt $Left) {
					for ($i = $Left; $i -le $Right; $i++) { InttoIP $i }
				}
				else { Write-Warning "Invalid IP range. The right portion must be greater than the left portion."; return}
			
				break
			}
			"single"
			{
				if ([System.Net.IPAddress]::TryParse($Item,[ref]$Ip)) { $Ip.IPAddressToString }
				else { Write-Warning "Invalid IP address supplied!"; return }
				break
			}
			default
			{
				Write-Warning "An error occured."
				return
			}
		}
	}

}   

# ipcalc utility from Joakim Svendsen.
function Invoke-PSipcalc 
{
<#
.SYNOPSIS

	Provides detailed network information. Accepts CIDR notation and IP / subnet mask.
	Inspired by the utility "ipcalc" on Linux.

	Svendsen Tech.
	Copyright (c) 2015, Joakim Svendsen
	All rights reserved.

	BSD 3-clause license. http://www.opensource.org/licenses/BSD-3-Clause

.PARAMETER NetworkAddress
	CIDR notation network address, or using subnet mask. Examples: '192.168.0.1/24', '10.20.30.40/255.255.0.0'.

.PARAMETER Contains
	Causes PSipcalc to return a boolean value for whether the specified IP is in the specified network. Includes network address and broadcast address.

.PARAMETER Enumerate
	Enumerates all IPs in subnet (potentially resource-expensive). Ignored if you use -Contains.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True)]
		[string[]] $NetworkAddress,
		
		[Parameter(Mandatory=$false)]
        [string] $Contains,
		
		[Parameter(Mandatory=$false)]
        [switch] $Enumerate
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    # This is a regex I made to match an IPv4 address precisely ( http://www.powershelladmin.com/wiki/PowerShell_regex_to_accurately_match_IPv4_address_%280-255_only%29 )
    $IPv4Regex = '(?:(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)\.){3}(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)'

    function Convert-IPToBinary
    {
        param(
            [string] $IP
        )
        $IP = $IP.Trim()
        if ($IP -match "\A${IPv4Regex}\z")
        {
            try
            {
                return ($IP.Split('.') | ForEach-Object { [System.Convert]::ToString([byte] $_, 2).PadLeft(8, '0') }) -join ''
            }
            catch
            {
                Write-Warning -Message "Error converting '$IP' to a binary string: $_"
                return $Null
            }
        }
        else
        {
            Write-Warning -Message "Invalid IP detected: '$IP'."
            return $Null
        }
    }

    function Convert-BinaryToIP
    {
        param(
            [string] $Binary
        )
        $Binary = $Binary -replace '\s+'
        if ($Binary.Length % 8)
        {
            Write-Warning -Message "Binary string '$Binary' is not evenly divisible by 8."
            return $Null
        }
        [int] $NumberOfBytes = $Binary.Length / 8
        $Bytes = @(foreach ($i in 0..($NumberOfBytes-1))
        {
            try
            {
                #$Bytes += # skipping this and collecting "outside" seems to make it like 10 % faster
                [System.Convert]::ToByte($Binary.Substring(($i * 8), 8), 2)
            }
            catch
            {
                Write-Warning -Message "Error converting '$Binary' to bytes. `$i was $i."
                return $Null
            }
        })
        return $Bytes -join '.'
    }

    function Get-ProperCIDR
    {
        param(
            [string] $CIDRString
        )
        $CIDRString = $CIDRString.Trim()
        $o = '' | Select-Object -Property IP, NetworkLength
        if ($CIDRString -match "\A(?<IP>${IPv4Regex})\s*/\s*(?<NetworkLength>\d{1,2})\z")
        {
            # Could have validated the CIDR in the regex, but this is more informative.
            if ([int] $Matches['NetworkLength'] -lt 0 -or [int] $Matches['NetworkLength'] -gt 32)
            {
                Write-Warning "Network length out of range (0-32) in CIDR string: '$CIDRString'."
                return
            }
            $o.IP = $Matches['IP']
            $o.NetworkLength = $Matches['NetworkLength']
        }
        elseif ($CIDRString -match "\A(?<IP>${IPv4Regex})[\s/]+(?<SubnetMask>${IPv4Regex})\z")
        {
            $o.IP = $Matches['IP']
            $SubnetMask = $Matches['SubnetMask']
            if (-not ($BinarySubnetMask = Convert-IPToBinary $SubnetMask))
            {
                return # warning displayed by Convert-IPToBinary, nothing here
            }
            # Some validation of the binary form of the subnet mask, 
            # to check that there aren't ones after a zero has occurred (invalid subnet mask).
            # Strip all leading ones, which means you either eat 32 1s and go to the end (255.255.255.255),
            # or you hit a 0, and if there's a 1 after that, we've got a broken subnet mask, amirite.
            if ((($BinarySubnetMask) -replace '\A1+') -match '1')
            {
                Write-Warning -Message "Invalid subnet mask in CIDR string '$CIDRString'. Subnet mask: '$SubnetMask'."
                return
            }
            $o.NetworkLength = [regex]::Matches($BinarySubnetMask, '1').Count
        }
        else
        {
            Write-Warning -Message "Invalid CIDR string: '${CIDRString}'. Valid examples: '192.168.1.0/24', '10.0.0.0/255.0.0.0'."
            return
        }
        # Check if the IP is all ones or all zeroes (not allowed: http://www.cisco.com/c/en/us/support/docs/ip/routing-information-protocol-rip/13788-3.html )
        if ($o.IP -match '\A(?:(?:1\.){3}1|(?:0\.){3}0)\z')
        {
            Write-Warning "Invalid IP detected in CIDR string '${CIDRString}': '$($o.IP)'. An IP can not be all ones or all zeroes."
            return
        }
        return $o
    }

    function Get-IPRange
    {
        param(
            [string] $StartBinary,
            [string] $EndBinary
        )
        [int64] $StartInt = [System.Convert]::ToInt64($StartBinary, 2)
        [int64] $EndInt = [System.Convert]::ToInt64($EndBinary, 2)
        for ($BinaryIP = $StartInt; $BinaryIP -le $EndInt; $BinaryIP++)
        {
            Convert-BinaryToIP ([System.Convert]::ToString($BinaryIP, 2).PadLeft(32, '0'))
        }
    }

    function Test-IPIsInNetwork {
        param(
            [string] $IP,
            [string] $StartBinary,
            [string] $EndBinary
        )
        $TestIPBinary = Convert-IPToBinary $IP
        [int64] $TestIPInt64 = [System.Convert]::ToInt64($TestIPBinary, 2)
        [int64] $StartInt64 = [System.Convert]::ToInt64($StartBinary, 2)
        [int64] $EndInt64 = [System.Convert]::ToInt64($EndBinary, 2)
        if ($TestIPInt64 -ge $StartInt64 -and $TestIPInt64 -le $EndInt64)
        {
            return $True
        }
        else
        {
            return $False
        }
    }

    function Get-NetworkInformationFromProperCIDR
    {
        param(
            [psobject] $CIDRObject
        )
        $o = '' | Select-Object -Property IP, NetworkLength, SubnetMask, NetworkAddress, HostMin, HostMax, 
            Broadcast, UsableHosts, TotalHosts, IPEnumerated, BinaryIP, BinarySubnetMask, BinaryNetworkAddress,
            BinaryBroadcast
        $o.IP = [string] $CIDRObject.IP
        $o.BinaryIP = Convert-IPToBinary $o.IP
        $o.NetworkLength = [int32] $CIDRObject.NetworkLength
        $o.SubnetMask = Convert-BinaryToIP ('1' * $o.NetworkLength).PadRight(32, '0')
        $o.BinarySubnetMask = ('1' * $o.NetworkLength).PadRight(32, '0')
        $o.BinaryNetworkAddress = $o.BinaryIP.SubString(0, $o.NetworkLength).PadRight(32, '0')
        if ($Contains)
        {
            if ($Contains -match "\A${IPv4Regex}\z")
            {
                # Passing in IP to test, start binary and end binary.
                return Test-IPIsInNetwork $Contains $o.BinaryNetworkAddress $o.BinaryNetworkAddress.SubString(0, $o.NetworkLength).PadRight(32, '1')
            }
            else
            {
                Write-Error "Invalid IPv4 address specified with -Contains"
                return
            }
        }
        $o.NetworkAddress = Convert-BinaryToIP $o.BinaryNetworkAddress
        if ($o.NetworkLength -eq 32 -or $o.NetworkLength -eq 31)
        {
            $o.HostMin = $o.IP
        }
        else
        {
            $o.HostMin = Convert-BinaryToIP ([System.Convert]::ToString(([System.Convert]::ToInt64($o.BinaryNetworkAddress, 2) + 1), 2)).PadLeft(32, '0')
        }
        #$o.HostMax = Convert-BinaryToIP ([System.Convert]::ToString((([System.Convert]::ToInt64($o.BinaryNetworkAddress.SubString(0, $o.NetworkLength)).PadRight(32, '1'), 2) - 1), 2).PadLeft(32, '0'))
        #$o.HostMax = 
        [string] $BinaryBroadcastIP = $o.BinaryNetworkAddress.SubString(0, $o.NetworkLength).PadRight(32, '1') # this gives broadcast... need minus one.
        $o.BinaryBroadcast = $BinaryBroadcastIP
        [int64] $DecimalHostMax = [System.Convert]::ToInt64($BinaryBroadcastIP, 2) - 1
        [string] $BinaryHostMax = [System.Convert]::ToString($DecimalHostMax, 2).PadLeft(32, '0')
        $o.HostMax = Convert-BinaryToIP $BinaryHostMax
        $o.TotalHosts = [int64][System.Convert]::ToString(([System.Convert]::ToInt64($BinaryBroadcastIP, 2) - [System.Convert]::ToInt64($o.BinaryNetworkAddress, 2) + 1))
        $o.UsableHosts = $o.TotalHosts - 2
        # ugh, exceptions for network lengths from 30..32
        if ($o.NetworkLength -eq 32)
        {
            $o.Broadcast = $Null
            $o.UsableHosts = [int64] 1
            $o.TotalHosts = [int64] 1
            $o.HostMax = $o.IP
        }
        elseif ($o.NetworkLength -eq 31)
        {
            $o.Broadcast = $Null
            $o.UsableHosts = [int64] 2
            $o.TotalHosts = [int64] 2
            # Override the earlier set value for this (bloody exceptions).
            [int64] $DecimalHostMax2 = [System.Convert]::ToInt64($BinaryBroadcastIP, 2) # not minus one here like for the others
            [string] $BinaryHostMax2 = [System.Convert]::ToString($DecimalHostMax2, 2).PadLeft(32, '0')
            $o.HostMax = Convert-BinaryToIP $BinaryHostMax2
        }
        elseif ($o.NetworkLength -eq 30)
        {
            $o.UsableHosts = [int64] 2
            $o.TotalHosts = [int64] 4
            $o.Broadcast = Convert-BinaryToIP $BinaryBroadcastIP
        }
        else
        {
            $o.Broadcast = Convert-BinaryToIP $BinaryBroadcastIP
        }
        if ($Enumerate)
        {
            $IPRange = @(Get-IPRange $o.BinaryNetworkAddress $o.BinaryNetworkAddress.SubString(0, $o.NetworkLength).PadRight(32, '1'))
            if ((31, 32) -notcontains $o.NetworkLength )
            {
                $IPRange = $IPRange[1..($IPRange.Count-1)] # remove first element
                $IPRange = $IPRange[0..($IPRange.Count-2)] # remove last element
            }
            $o.IPEnumerated = $IPRange
        }
        else {
            $o.IPEnumerated = @()
        }
        return $o
    }
    $NetworkAddress | ForEach-Object { Get-ProperCIDR -CIDRString $_ } | ForEach-Object { Get-NetworkInformationFromProperCIDR -CIDRObject $_ }
}

