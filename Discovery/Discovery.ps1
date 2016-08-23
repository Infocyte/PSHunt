function Get-HuntTargets {
<#
.SYNOPSIS

Build a target list from IP range or Active directory lookup.

Project: PSHunt
Author: Chris Gerritz (Twitter @gerritzc Github @singlethreaded)
License: Apache License 2.0
Required Dependencies: RSAT
Optional Dependencies: None
 
.DESCRIPTION

 reverse DNS lookup scan on a range of IP addresses.
 
Get-HuntTargets builds a target list by enumerating an IP address range or querying active directory. 
The target list performs Forward/Reverse DNS lookups, Queries AD, and formats the output for use with PSHunt. 
Use this to perform reconnaisance prior to scanning systems with PSHunt or for general asset discovery and tracking.
 
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

PS C:\> Write-Output "74.125.228.1,74.125.228.0/29" | Get-HuntTargets

Description
-----------
Returns the hostnames of the IP addresses piped from another source.

#>

    Param (
		[Parameter(	Position = 0, 
					Mandatory = $false,
					ValueFromPipeline=$false)]
        [String]
        $IpRange,
		
		[Parameter(	Mandatory = $false)]
		[Alias("CustomList")]
        [String[]]
        $ComputerName,
		
		[Parameter(Mandatory = $false)]
        [String]
        $Domain,
		
		[Parameter(Mandatory = $false)]
        [String[]]
        $OUs,
		
		[Parameter(	Mandatory=$false)]
        [int]$ThrottleLimit=32,
	
		[Parameter(	Mandatory=$false)]
        [System.Management.Automation.PSCredential]
		$Credential	
    )

    BEGIN {
		
		$DiscoveryPorts = 22,80,135,139,443,445,1025,3389,5985,49152
		
		
		# Parsing function taken from PowersSploit.  Thanks Matthew Graeber!
        function Parse-IPList ([String] $IpRange)
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
		
		
		# Parse IP List, CIDR, etc. into array of IPs
		if ($IpRange) {
			Write-Verbose "Parsing IPRanges: $IpRange"
			$IPs = Parse-IPList $IpRange
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
		$PortScanResults = Invoke-HuntPortScan -ComputerName $Targets -Ports $DiscoveryPorts -ThrottleLimit $ThrottleLimit -DNS -Randomize
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
			if ($hostscan.TCP135) {
				$ExecutionMethods.WMI = $True
			}
			if (($hostscan.TCP139) -OR ($hostscan.TCP135)) {
				$ExecutionMethods.Schtasks = $True
				$ExecutionMethods.PsExec = $True
			}
			if ($hostscan.TCP5985) {
				$ExecutionMethods.PSRemoting = $True
			}
			$hostscan | Add-Member -MemberType NoteProperty -Name 'ExecutionMethods' -Value $ExecutionMethods
			
			# Add any Domain Attributes that we know about. 
			if ($Domain) {
				$hostscan | Add-Member -MemberType NoteProperty -Name 'OperatingSystem' -Value $Null
				if ($DomainComputers.DNSHostName -contains $hostscan.dns) {
				
					$DomainProps = $DomainComputers | where { $_.DNSHostName -eq $hostscan.dns}
					
					if ($DomainProps) {
						$hostscan.OperatingSystem = $DomainProps.OperatingSystem
						$hostscan | Add-Member -MemberType NoteProperty -Name 'DistinguishedName' -Value $DomainProps.DistinguishedName
						$hostscan | Add-Member -MemberType NoteProperty -Name 'Created' -Value $DomainProps.Created
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

.PARAMETER DNS
	Perform a DNS lookup.

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

	PS C:\> Invoke-HuntPortScan -ComputerName 192.168.8.112 -Port 22,80,135,139,443,445,3389,5985 -Dns
	
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

	PS C:\> $ScanResults = Invoke-HuntPortScan -Cn 192.168.1.1, synology, ubuntuvm, vista64esxi -Port 22,3389,80,443 -DNS
	PS C:\> $ScanResults | Where { $_.TCP22 } | Format-Table -AutoSize

#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[ValidateNotNullOrEmpty()]
		[Alias('PSComputerName', 'Cn')]
		[string[]] 
		$ComputerName,
		
        [int[]] 
		$Ports = @(22,80,135,139,443,445,1025,3389,5985,49152),

        [switch] 
		$Dns,

        [int] 
		$ThrottleLimit = 32,
		
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
				
				if ($Computer -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") {
					# $Computer is an IP - Do reverse lookup for hostname
					Write-Verbose "${Computer}: Resolving DNS for $Computer via Reverse Lookup"
					$PortData[$Computer].IP = $Computer
					try {
						$resolved = [System.Net.Dns]::GetHostEntry($Computer)
						$PortData[$Computer].DNS = $resolved.HostName
						$PortData[$Computer].IPAddressList= $resolved.AddressList.IPAddressToString
					} catch {
						# $Status = "WARNING: Could not resolve Hostname from IP"
						Write-Verbose "${Computer}: WARNING: Could not resolve Hostname from IP"
					}
				} elseif ($Computer -ne $null) {
					# $Computer is DNS name - Resolve IP from hostname
					Write-Verbose "${Computer}: Resolving IP for $Computer via DNS Lookup"
					$PortData[$Computer].DNS = $Computer
					try {
						$resolved = [System.Net.Dns]::GetHostEntry($Computer)
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
					} catch {
						# $Status = "FAILURE: Could not resolve IP from Hostname"
						Write-Verbose "${Computer}: FAILURE: Could not resolve IP from Hostname"
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
			if ($PSBoundParameters['Dns']) {
				++$RunspaceCounter
				$psCMD = [System.Management.Automation.PowerShell]::Create().AddScript($ScriptBlock)
				[void] $psCMD.AddParameter('ID', $RunspaceCounter)
				[void] $psCMD.AddParameter('Computer', $Computer)
				[void] $PSCMD.AddParameter('Port', $Null)
				[void] $PSCMD.AddParameter('Dns', $Dns)
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

	try{
		$tcp=new-object System.Net.Sockets.TcpClient
		$tcp.connect($ComputerName,$Port)
		return $true
	}
	catch{
		return $false
	}
	finally {
		$tcp.close()
	}
}


function Test-TCPPorts {
	Param(	
		[Parameter(	Position=0, 
					Mandatory=$true)]
		[string]$ComputerName,

		[Parameter(	Position=1,
					Mandatory=$false)]		
		[int[]]$Ports=@(445)
		)
	BEGIN {
	
		$ScriptBlock = {
			Param(	
				[string]$ComputerName,		
				[int]$Port
			)

			try {
				$tcp=new-object System.Net.Sockets.TcpClient
				$tcp.connect($ComputerName,$Port)
				return $true
			}
			catch{
				return $false
			}
			finally {
				$tcp.close()
			}
		}	
			
		Write-Verbose "Scanning TCP ports: $Ports"	
		$Jobs = @()		
		$TestResults = New-Object PSObject -property @{
			Target = $ComputerName
		}
	}
	PROCESS {
		foreach ($port in $Ports) {
			$portname = "TCP$port"
			
			
			# Run each port in a parallel background job.
			$Jobs += Start-Job -Name $Portname -scriptblock $ScriptBlock -ArgumentList $ComputerName,$port
		}
	}
	END {
		# Wait for jobs
		if ($PSBoundParameters['Debug']) { $jobs }	
		Write-Verbose "Waiting for $($Jobs.count) tests to complete"
		$null = $Jobs | Wait-Job -Timeout 5
		$Jobs | foreach {
			$JobResults = Receive-Job $_
			Write-Verbose "Received Job Result $JobResults for $($_.name)"
			$TestResults | Add-Member -type NoteProperty -name $_.name -value $JobResults
		}
		if ($PSBoundParameters['Debug']) { $jobs }
		# Stop and remove all jobs  
		$null = $Jobs | stop-job
		$null = $Jobs | remove-job
		
		$TestResults
	}
}


# PortScan from PowerSloit
function Invoke-Portscan
{
<#
.SYNOPSIS

Simple portscan module

PowerSploit Function: Invoke-Portscan
Author: Rich Lundeen (http://webstersProdigy.net)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Does a simple port scan using regular sockets, based (pretty) loosely on nmap

.NOTES

version .13

.PARAMETER Hosts

Include these comma seperated hosts (supports IPv4 CIDR notation) or pipe them in

.PARAMETER HostFile

Input hosts from file rather than commandline

.PARAMETER ExcludeHosts

Exclude these comma seperated hosts

.PARAMETER Ports

Include these comma seperated ports (can also be a range like 80-90)

.PARAMETER PortFile

Input ports from a file

.PARAMETER TopPorts

Include the x top ports - only goes to 1000, default is top 50

.PARAMETER ExcludedPorts

Exclude these comma seperated ports

.PARAMETER SkipDiscovery

Treat all hosts as online, skip host discovery

.PARAMETER PingOnly

Ping scan only (disable port scan)

.PARAMETER DiscoveryPorts

Comma separated ports used for host discovery. -1 is a ping

.PARAMETER Threads

number of max threads for the thread pool (per host)

.PARAMETER nHosts

number of hosts to concurrently scan

.PARAMETER Timeout

Timeout time on a connection in miliseconds before port is declared filtered

.PARAMETER SleepTimer

Wait before thread checking, in miliseconds

.PARAMETER SyncFreq

How often (in terms of hosts) to sync threads and flush output

.PARAMETER T

[0-5] shortcut performance options. Default is 3. higher is more aggressive. Sets (nhosts, threads,timeout)
    5 {$nHosts=30;  $Threads = 1000; $Timeout = 750  }
    4 {$nHosts=25;  $Threads = 1000; $Timeout = 1200 }
    3 {$nHosts=20;  $Threads = 100;  $Timeout = 2500 }
    2 {$nHosts=15;  $Threads = 32;   $Timeout = 3000 }
    1 {$nHosts=10;  $Threads = 32;   $Timeout = 5000 }

.PARAMETER GrepOut

Greppable output file

.PARAMETER XmlOut

output XML file

.PARAMETER ReadableOut

output file in 'readable' format

.PARAMETER AllformatsOut

output in readable (.nmap), xml (.xml), and greppable (.gnmap) formats

.PARAMETER noProgressMeter

Suppresses the progress meter

.PARAMETER quiet

supresses returned output and don't store hosts in memory - useful for very large scans

.PARAMETER ForceOverwrite

Force Overwrite if output Files exist. Otherwise it throws exception

.EXAMPLE

C:\PS> Invoke-Portscan -Hosts "webstersprodigy.net,google.com,microsoft.com" -TopPorts 50

Description
-----------
Scans the top 50 ports for hosts found for webstersprodigy.net,google.com, and microsoft.com

.EXAMPLE

C:\PS> echo webstersprodigy.net | Invoke-Portscan -oG test.gnmap -f -ports "80,443,8080"

Description
-----------
Does a portscan of "webstersprodigy.net", and writes a greppable output file

.EXAMPLE

C:\PS> Invoke-Portscan -Hosts 192.168.1.1/24 -T 4 -TopPorts 25 -oA localnet

Description
-----------
Scans the top 20 ports for hosts found in the 192.168.1.1/24 range, outputs all file formats

.LINK

http://webstersprodigy.net
#>

    [CmdletBinding()]Param (
        #Host, Ports
        [Parameter(ParameterSetName="cmdHosts",

                   ValueFromPipeline=$True,
                   Mandatory = $True)]
                   [String[]] $Hosts,

        [Parameter(ParameterSetName="fHosts",
                   Mandatory = $True)]
                   [Alias("iL")]
                   [String]  $HostFile,

        [Parameter(Mandatory = $False)]
                   [Alias("exclude")]
                   [String] $ExcludeHosts,

        [Parameter(Mandatory = $False)]
                   [Alias("p")]
                   [String] $Ports,

        [Parameter(Mandatory = $False)]
                   [Alias("iP")]
                   [String] $PortFile,

        [Parameter(Mandatory = $False)]
                   [String] $TopPorts,

        [Parameter(Mandatory = $False)]
                   [Alias("xPorts")]
                   [String] $ExcludedPorts,

        #Host Discovery
        [Parameter(Mandatory = $False)]
                   [Alias("Pn")]
                   [Switch] $SkipDiscovery,

        [Parameter(Mandatory = $False)]
                   [Alias("sn")]
                   [Switch] $PingOnly,

        [Parameter(Mandatory = $False)]
                   [Alias("PS")]
                   [string] $DiscoveryPorts = "-1,445,80,443",

        #Timing and Performance
        [Parameter(Mandatory = $False)]
                   [int] $Threads = 100,

        [Parameter(Mandatory = $False)]
                   [int] $nHosts = 25,

        [Parameter(Mandatory = $False)]
                   [int] $Timeout = 2000,

        [Parameter(Mandatory = $False)]
                   [int] $SleepTimer = 500,

        [Parameter(Mandatory = $False)]
                   [int] $SyncFreq = 1024,

        [Parameter(Mandatory = $False)]
                   [int] $T,

        #Output
        [Parameter(Mandatory = $False)]
                   [Alias("oG")]
                   [String] $GrepOut,

        [Parameter(Mandatory = $False)]
                   [Alias("oX")]
                   [String] $XmlOut,

        [Parameter(Mandatory = $False)]
                   [Alias("oN")]
                   [String] $ReadableOut,

        [Parameter(Mandatory = $False)]
                   [Alias("oA")]
                   [String] $AllformatsOut,

        [Parameter(Mandatory = $False)]
                   [Switch] $noProgressMeter,

        [Parameter(Mandatory = $False)]
                   [Alias("q")]
                   [Switch] $quiet,

        [Parameter(Mandatory = $False)]
                   [Alias("F")]
                   [Switch] $ForceOverwrite

        #TODO add script parameter
        #TODO add resume parameter
    )

    PROCESS {

        Set-StrictMode -Version 2.0

        $version = .13
        $hostList = New-Object System.Collections.ArrayList
        $portList = New-Object System.Collections.ArrayList
        $hostPortList = New-Object System.Collections.ArrayList

        $scannedHostList = @()

        function Parse-Hosts
        {
            Param (
                [Parameter(Mandatory = $True)] [String] $Hosts
            )

            [String[]] $iHosts = $Hosts.Split(",")

            foreach($iHost in $iHosts)
            {
                $iHost = $iHost.Replace(" ", "")

                if(!$iHost)
                {
                    continue
                }

                if($iHost.contains("/"))
                {
                    $netPart = $iHost.split("/")[0]
                    [uint32]$maskPart = $iHost.split("/")[1]

                    $address = [System.Net.IPAddress]::Parse($netPart)

                    if ($maskPart -ge $address.GetAddressBytes().Length * 8)
                    {
                        throw "Bad host mask"
                    }

                    $numhosts = [System.math]::Pow(2,(($address.GetAddressBytes().Length *8) - $maskPart))

                    $startaddress = $address.GetAddressBytes()
                    [array]::Reverse($startaddress)

                    $startaddress = [System.BitConverter]::ToUInt32($startaddress, 0)
                    [uint32]$startMask = ([System.math]::Pow(2, $maskPart)-1) * ([System.Math]::Pow(2,(32 - $maskPart)))
                    $startAddress = $startAddress -band $startMask

                    #in powershell 2.0 there are 4 0 bytes padded, so the [0..3] is necessary
                    $startAddress = [System.BitConverter]::GetBytes($startaddress)[0..3]
                    [array]::Reverse($startaddress)

                    $address = [System.Net.IPAddress] [byte[]] $startAddress

                    $hostList.Add($address.IPAddressToString)

                    for ($i=0; $i -lt $numhosts-1; $i++)
                    {

                        $nextAddress =  $address.GetAddressBytes()
                        [array]::Reverse($nextAddress)
                        $nextAddress =  [System.BitConverter]::ToUInt32($nextAddress, 0)
                        $nextAddress ++
                        $nextAddress = [System.BitConverter]::GetBytes($nextAddress)[0..3]
                        [array]::Reverse($nextAddress)

                        $address = [System.Net.IPAddress] [byte[]] $nextAddress
                        $hostList.Add($address.IPAddressToString)

                    }

                }
                else
                {
                    $hostList.Add($iHost)
                }
            }
        }

        function Parse-ILHosts
        {
           Param (
                [Parameter(Mandatory = $True)] [String] $HostFile
            )

            Get-Content $HostFile | ForEach-Object {
                Parse-Hosts $_
            }
        }

        function Exclude-Hosts
        {
            Param (
                [Parameter(Mandatory = $True)] [String] $excludeHosts
            )

            [String[]] $iHosts = $excludeHosts.Split(",")

            foreach($iHost in $iHosts)
            {
                $iHost = $iHost.Replace(" ", "")
                $hostList.Remove($iHost)
            }
        }

        function Get-TopPort
        {
            Param (
                [Parameter(Mandatory = $True)]
                [ValidateRange(1,1000)]
                [int] $numPorts
            )

            #list of top 1000 ports from nmap from Jun 2013
            [int[]] $topPortList = @(80,23,443,21,3389,110,445,139,143,53,135,3306,8080,22
                        1723,111,995,993,5900,1025,1720,548,113,81,6001,179,1026,2000,8443,
                        8000,32768,554,26,1433,49152,2001,515,8008,49154,1027,5666,646,5000,
                        5631,631,49153,8081,2049,88,79,5800,106,2121,1110,49155,6000,513,
                        990,5357,49156,543,544,5101,144,7,389,8009,9999,5009,7070,5190,3000,
                        5432,1900,3986,13,1029,9,5051,6646,49157,1028,873,1755,2717,4899,9100,
                        119,37,1000,3001,5001,82,10010,1030,9090,2107,1024,2103,6004,1801,
                        5050,19,8031,1041,255,1048,1049,1053,1054,1056,1064,3703,17,808,3689,
                        1031,1044,1071,5901,100,9102,2869,4001,5120,8010,9000,2105,636,1038,
                        2601,1,7000,1066,1069,625,311,280,254,4000,1761,5003,2002,1998,2005,
                        1032,1050,6112,1521,2161,6002,2401,902,4045,787,7937,1058,2383,1033,
                        1040,1059,50000,5555,1494,3,593,2301,3268,7938,1022,1234,1035,1036,1037,
                        1074,8002,9001,464,497,1935,2003,6666,6543,24,1352,3269,1111,407,500,
                        20,2006,1034,1218,3260,15000,4444,264,33,2004,1042,42510,999,3052,1023,
                        222,1068,888,7100,1717,992,2008,7001,2007,8082,512,1043,2009,5801,1700,
                        7019,50001,4662,2065,42,2602,3333,9535,5100,2604,4002,5002,1047,1051,1052,
                        1055,1060,1062,1311,3283,4443,5225,5226,6059,6789,8089,8651,8652,8701,9415,
                        9593,9594,9595,16992,16993,20828,23502,32769,33354,35500,52869,55555,55600,
                        64623,64680,65000,65389,1067,13782,366,5902,9050,85,1002,5500,1863,1864,
                        5431,8085,10243,45100,49999,51103,49,90,6667,1503,6881,27000,340,1500,8021,
                        2222,5566,8088,8899,9071,5102,6005,9101,163,5679,146,648,1666,83,3476,5004,
                        5214,8001,8083,8084,9207,14238,30,912,12345,2030,2605,6,541,4,1248,3005,8007,
                        306,880,2500,1086,1088,2525,4242,8291,9009,52822,900,6101,2809,7200,211,800,
                        987,1083,12000,705,711,20005,6969,13783,1045,1046,1061,1063,1070,1072,1073,
                        1075,1077,1078,1079,1081,1082,1085,1093,1094,1096,1098,1099,1100,1104,1106,
                        1107,1108,1148,1169,1272,1310,1687,1718,1783,1840,2100,2119,2135,2144,2160,
                        2190,2260,2381,2399,2492,2607,2718,2811,2875,3017,3031,3071,3211,3300,3301,
                        3323,3325,3351,3404,3551,3580,3659,3766,3784,3801,3827,3998,4003,4126,4129,
                        4449,5222,5269,5633,5718,5810,5825,5877,5910,5911,5925,5959,5960,5961,5962,
                        5987,5988,5989,6123,6129,6156,6389,6580,6901,7106,7625,7777,7778,7911,8086,
                        8181,8222,8333,8400,8402,8600,8649,8873,8994,9002,9011,9080,9220,9290,9485,
                        9500,9502,9503,9618,9900,9968,10002,10012,10024,10025,10566,10616,10617,10621,
                        10626,10628,10629,11110,13456,14442,15002,15003,15660,16001,16016,16018,17988,
                        19101,19801,19842,20000,20031,20221,20222,21571,22939,24800,25734,27715,28201,
                        30000,30718,31038,32781,32782,33899,34571,34572,34573,40193,48080,49158,49159,
                        49160,50003,50006,50800,57294,58080,60020,63331,65129,691,212,1001,1999,2020,
                        2998,6003,7002,50002,32,2033,3372,99,425,749,5903,43,458,5405,6106,6502,7007,
                        13722,1087,1089,1124,1152,1183,1186,1247,1296,1334,1580,1782,2126,2179,2191,2251,
                        2522,3011,3030,3077,3261,3493,3546,3737,3828,3871,3880,3918,3995,4006,4111,4446,
                        5054,5200,5280,5298,5822,5859,5904,5915,5922,5963,7103,7402,7435,7443,7512,8011,
                        8090,8100,8180,8254,8500,8654,9091,9110,9666,9877,9943,9944,9998,10004,10778,15742,
                        16012,18988,19283,19315,19780,24444,27352,27353,27355,32784,49163,49165,49175,
                        50389,50636,51493,55055,56738,61532,61900,62078,1021,9040,666,700,84,545,1112,
                        1524,2040,4321,5802,38292,49400,1084,1600,2048,2111,3006,6547,6699,9111,16080,
                        555,667,720,801,1443,1533,2106,5560,6007,1090,1091,1114,1117,1119,1122,1131,1138,
                        1151,1175,1199,1201,1271,1862,2323,2393,2394,2608,2725,2909,3003,3168,3221,3322,
                        3324,3390,3517,3527,3800,3809,3814,3826,3869,3878,3889,3905,3914,3920,3945,3971,
                        4004,4005,4279,4445,4550,4567,4848,4900,5033,5080,5087,5221,5440,5544,5678,5730,
                        5811,5815,5850,5862,5906,5907,5950,5952,6025,6510,6565,6567,6689,6692,6779,6792,
                        6839,7025,7496,7676,7800,7920,7921,7999,8022,8042,8045,8093,8099,8200,8290,8292,
                        8300,8383,9003,9081,9099,9200,9418,9575,9878,9898,9917,10003,10180,10215,11111,
                        12174,12265,14441,15004,16000,16113,17877,18040,18101,19350,25735,26214,27356,
                        30951,32783,32785,40911,41511,44176,44501,49161,49167,49176,50300,50500,52673,
                        52848,54045,54328,55056,56737,57797,60443,70,417,714,722,777,981,1009,2022,4224,
                        4998,6346,301,524,668,765,2041,5999,10082,259,1007,1417,1434,1984,2038,2068,4343,
                        6009,7004,44443,109,687,726,911,1461,2035,4125,6006,7201,9103,125,481,683,903,
                        1011,1455,2013,2043,2047,6668,6669,256,406,843,2042,2045,5998,9929,31337,44442,
                        1092,1095,1102,1105,1113,1121,1123,1126,1130,1132,1137,1141,1145,1147,1149,1154,
                        1164,1165,1166,1174,1185,1187,1192,1198,1213,1216,1217,1233,1236,1244,1259,1277,
                        1287,1300,1301,1309,1322,1328,1556,1641,1688,1719,1721,1805,1812,1839,1875,1914,
                        1971,1972,1974,2099,2170,2196,2200,2288,2366,2382,2557,2800,2910,2920,2968,3007,
                        3013,3050,3119,3304,3307,3376,3400,3410,3514,3684,3697,3700,3824,3846,3848,3859,
                        3863,3870,3872,3888,3907,3916,3931,3941,3957,3963,3968,3969,3972,3990,3993,3994,
                        4009,4040,4080,4096,4143,4147,4200,4252,4430,4555,4600,4658,4875,4949,5040,5063,
                        5074,5151,5212,5223,5242,5279,5339,5353,5501,5807,5812,5818,5823,5868,5869,5899,
                        5905,5909,5914,5918,5938,5940,5968,5981,6051,6060,6068,6203,6247,6500,6504,6520,
                        6550,6600)
            $numPorts--
            $portList.AddRange($topPortList[0..$numPorts])
        }

        function Parse-Ports
        {
            Param (
                [Parameter(Mandatory = $True)] [String] $Ports,
                [Parameter(Mandatory = $True)] $pList
            )

            foreach ($pRange in $Ports.Split(","))
            {

                #-1 is a special case for ping
                if ($pRange -eq "-1")
                {
                    $pList.Add([int]$pRange)
                }
                elseif ($pRange.Contains("-"))
                {
                    [int[]] $range = $pRange.Split("-")
                    if ($range.Count -ne 2 -or $pRange.Split("-")[0] -eq "" -or $pRange.split("-")[1] -eq "")
                    {
                        throw "Invalid port range"
                    }

                    $pList.AddRange($range[0]..$range[1])
                }
                else
                {
                    $pList.Add([int]$pRange)
                }

            }
            foreach ($p in $pList)
            {
                if ($p -lt -1 -or $p -gt 65535)
                {
                    throw "Port $p out of range"
                }
            }
         }

        function Parse-IpPorts
        {
           Param (
                [Parameter(Mandatory = $True)] [String] $PortFile
            )

            Get-Content $PortFile | ForEach-Object {
                Parse-Ports -Ports $_ -pList $portList
            }
        }

        function Remove-Ports
        {
            Param (
                [Parameter(Mandatory = $True)] [string] $ExcludedPorts
            )

            [int[]] $ExcludedPorts = $ExcludedPorts.Split(",")

            foreach ($x in $ExcludedPorts)
            {
                $portList.Remove($x)
            }
        }

        function Write-PortscanOut
        {
            Param (
                [Parameter(Mandatory = $True, ParameterSetName="Comment")] [string] $comment,
                [Parameter(Mandatory = $True, ParameterSetName="HostOut")] [string] $outhost,
                [Parameter(Mandatory = $True, ParameterSetName="HostOut")] [bool] $isUp,
                [Parameter(Mandatory = $True, ParameterSetName="HostOut")] $openPorts,
                [Parameter(Mandatory = $True, ParameterSetName="HostOut")] $closedPorts,
                [Parameter(Mandatory = $True, ParameterSetName="HostOut")] $filteredPorts,
                [Parameter()] [bool] $SkipDiscovery,
                [Parameter()] [System.IO.StreamWriter] $grepStream,
                [Parameter()] [System.Xml.XmlWriter] $xmlStream,
                [Parameter()] [System.IO.StreamWriter] $readableStream

            )
            switch ($PSCmdlet.ParameterSetName)
            {
                "Comment"
                {

                    Write-Verbose $comment

                    if ($grepStream) {
                        $grepStream.WriteLine("# " + $comment)
                    }
                    if ($xmlStream) {
                        $xmlStream.WriteComment($comment)
                    }
                    if ($readableStream) {
                        $readableStream.WriteLine($comment)
                    }
                }
                "HostOut"
                {
                    $oPort = [string]::join(",", $openPorts.ToArray())
                    $cPort = [string]::join(",", $closedPorts.ToArray())
                    $fPort = [string]::join(",", $filteredPorts.ToArray())

                    if ($grepStream) {
                       #for grepstream use tabs - can be ugly, but easier for regex
                       if ($isUp -and !$SkipDiscovery) {
                            $grepStream.writeline("Host: $outhost`tStatus: Up")
                        }
                        if ($isUp -or $SkipDiscovery) {
                            if ($oPort -ne "") {
                                $grepStream.writeline("Host: $outhost`tOpen Ports: $oPort")
                            }
                            if ($cPort -ne "") {
                                $grepStream.writeline("Host: $outhost`tClosed Ports: $cPort")
                            }
                            if ($fPort -ne "") {
                                $grepStream.writeline("Host: $outhost`tFiltered Ports: $fPort")
                            }
                        }
                        elseif (!$SkipDiscovery) {
                            $grepStream.writeline("Host: $outhost`tStatus: Down")
                        }
                    }
                    if ($xmlStream) {
                        $xmlStream.WriteStartElement("Host")

                        $xmlStream.WriteAttributeString("id", $outhost)
                        if (!$SkipDiscovery) {
                            if ($isUp) {
                                $xmlStream.WriteAttributeString("Status", "Up")
                             }
                             else {
                                $xmlStream.WriteAttributeString("Status", "Downs")
                             }
                        }

                        $xmlStream.WriteStartElement("Ports")
                        foreach($p in $openPorts) {
                            $xmlStream.writestartElement("Port")
                            $xmlStream.WriteAttributeString("id", [string]$p)
                            $xmlStream.WriteAttributeString("state", "open")
                            $xmlStream.WriteEndElement()

                        }
                        foreach ($p in $closedPorts) {
                            $xmlStream.writestartElement("Port")
                            $xmlStream.WriteAttributeString("id", [string]$p)
                            $xmlStream.WriteAttributeString("state", "closed")
                            $xmlStream.WriteEndElement()
                        }
                        foreach ($p in $filteredPorts) {
                            $xmlStream.writestartElement("Port")
                            $xmlStream.WriteAttributeString("id", [string]$p)
                            $xmlStream.WriteAttributeString("state", "filtered")
                            $xmlStream.WriteEndElement()
                        }

                        $xmlStream.WriteEndElement()
                        $xmlStream.WriteEndElement()
                    }
                    if ($readableStream) {
                        $readableStream.writeline("Porscan.ps1 scan report for $outhost")
                        if ($isUp) {
                            $readableStream.writeline("Host is up")
                        }

                        if ($isUp -or $SkipDiscovery) {

                            $readableStream.writeline(("{0,-10}{1,0}" -f "PORT", "STATE"))

                            [int[]]$allports = $openPorts + $closedPorts + $filteredPorts
                            foreach($p in ($allports| Sort-Object))
                            {
                                if ($openPorts.Contains($p)) {
                                    $readableStream.writeline(("{0,-10}{1,0}" -f $p, "open"))
                                }
                                elseif ($closedPorts.Contains($p)) {
                                    $readableStream.writeline(("{0,-10}{1,0}" -f $p, "closed"))
                                }
                                elseif ($filteredPorts.Contains($p)) {
                                    $readableStream.writeline(("{0,-10}{1,0}" -f $p, "filtered"))
                                }
                            }

                        }
                        elseif(!$SkipDiscovery) {
                            $readableStream.writeline("Host is Down")
                        }
                        $readableStream.writeline("")
                    }
                }
            }
        }

        #function for Powershell v2.0 to work
        function Convert-SwitchtoBool
        {
            Param (
                [Parameter(Mandatory = $True)] $switchValue
            )
            If ($switchValue) {
                return $True
            }
            return $False
        }

        try
        {

            [bool] $SkipDiscovery = Convert-SwitchtoBool ($SkipDiscovery)
            [bool] $PingOnly = Convert-SwitchtoBool ($PingOnly)
            [bool] $quiet  = Convert-SwitchtoBool ($quiet)
            [bool] $ForceOverwrite  = Convert-SwitchtoBool ($ForceOverwrite)

            #########
            #parse arguments
            #########

            [Environment]::CurrentDirectory=(Get-Location -PSProvider FileSystem).ProviderPath

            if ($PsCmdlet.ParameterSetName -eq "cmdHosts")
            {
                foreach($h in $Hosts)
                {
                    Parse-Hosts($h) | Out-Null
                }
            }
            else
            {
                Parse-ILHosts($HostFile) | Out-Null
            }
            if($ExcludeHosts)
            {
                Exclude-Hosts($ExcludeHosts)
            }
            if (($TopPorts -and $Ports) -or ($TopPorts -and $PortFile))
            {
                throw "Cannot set topPorts with other specific ports"
            }
            if($Ports)
            {
                Parse-Ports -Ports $Ports -pList $portList | Out-Null
            }
            if($PortFile)
            {
                Parse-IpPorts($PortFile) | Out-Null
            }
            if($portList.Count -eq 0)
            {
                if ($TopPorts)
                {
                    Get-TopPort($TopPorts) | Out-Null
                }
                else
                {
                    #if the ports still aren't set, give the deftault, top 50 ports
                    Get-TopPort(50) | Out-Null
                }
            }
            if ($ExcludedPorts)
            {
                Remove-Ports -ExcludedPorts $ExcludedPorts | Out-Null
            }

            if($T)
            {
                switch ($T)
                {
                    5 {$nHosts=30;  $Threads = 1000; $Timeout = 750 }
                    4 {$nHosts=25;  $Threads = 1000; $Timeout = 1200 }
                    3 {$nHosts=20;  $Threads = 100;  $Timeout = 2500 }
                    2 {$nHosts=15;  $Threads = 32;   $Timeout = 3000 }
                    1 {$nHosts=10;  $Threads = 32;   $Timeout = 5000 }
                    default {
                        throw "Invalid T parameter"
                    }
                }
            }

            $grepStream = $null
            $xmlStream = $null
            $readableStream = $null

            if($AllformatsOut)
            {
                if ($GrepOut -or $XmlOut -or $ReadableOut) {
                     Write-Warning "Both -oA specified with other output... going to ignore -oG/-oN/-oX"
                }
                $GrepOut = $AllformatsOut + ".gnmap"
                $XmlOut = $AllformatsOut + ".xml"
                $ReadableOut = $AllformatsOut + ".nmap"
            }
            if ($GrepOut) {
                if (!$ForceOverwrite -and (Test-Path $GrepOut)) {
                    throw "Error: $AllformatsOut already exists. Either delete the file or specify the -f flag"
                }
                $grepStream = [System.IO.StreamWriter] $GrepOut
            }
            if ($ReadableOut) {
                if (!$ForceOverwrite -and (Test-Path $ReadableOut)) {
                    throw "Error: $ReadableOut already exists. Either delete the file or specify the -f flag"
                }
                $readableStream = [System.IO.StreamWriter] $ReadableOut
            }
            if ($XmlOut) {
                if (!$ForceOverwrite -and (Test-Path $XmlOut)) {
                    throw "Error: $XmlOut already exists. Either delete the file or specify the -f flag"
                }

                $xmlStream =   [System.xml.xmlwriter]::Create([string]$XmlOut)
                $xmlStream.WriteStartDocument()
                $xmlStream.WriteStartElement("Portscanrun")
                $xmlStream.WriteAttributeString("version", $version)

            }

            Parse-Ports -Ports $DiscoveryPorts -pList $hostPortList | Out-Null

            $startdate = Get-Date
            $myInvocationLine = $PSCmdlet.MyInvocation.Line
            $startMsg = "Invoke-Portscan.ps1 v$version scan initiated $startdate as: $myInvocationLine"

            #TODO deal with output
            Write-PortscanOut -comment $startMsg -grepStream $grepStream -xmlStream $xmlStream -readableStream $readableStream

            #converting back from int array gives some argument error checking
            $sPortList = [string]::join(",", $portList)
            $sHostPortList = [string]::join(",", $hostPortList)

            ########
            #Port Scan Code - run on a per host basis
            ########
            $portScanCode = {
                param (
                    [Parameter( Mandatory = $True)] [string] $thost,
                    [Parameter( Mandatory = $True)][bool] $SkipDiscovery,
                    [Parameter( Mandatory = $True)][bool] $PingOnly,
                    [Parameter( Mandatory = $True)][int] $Timeout,
                    [Parameter( Mandatory = $True)] $PortList,
                    [Parameter( Mandatory = $True)] $hostPortList,
                    [Parameter( Mandatory = $True)][int] $maxthreads)
                Process
                {
                $openPorts = New-Object System.Collections.ArrayList
                $closedPorts = New-Object System.Collections.ArrayList
                $filteredPorts = New-Object System.Collections.ArrayList

                $sockets = @{}
                $timeouts = New-Object Hashtable

                #set maximum $async threads
                $fThreads = New-Object int
                $aThreads = New-Object int
                [System.Threading.ThreadPool]::GetMaxThreads([ref]$fThreads, [ref]$aThreads) | Out-Null
                [System.Threading.ThreadPool]::SetMaxThreads($fthreads,$maxthreads) | Out-Null

                function New-ScriptBlockCallback {
                    param(
                        [parameter(Mandatory=$true)]
                        [ValidateNotNullOrEmpty()]
                        [scriptblock]$Callback
                    )

                    #taken from http://www.nivot.org/blog/post/2009/10/09/PowerShell20AsynchronousCallbacksFromNET
                    if (-not ("CallbackEventBridge" -as [type])) {
                        Add-Type @"
                            using System;

                            public sealed class CallbackEventBridge
                            {
                                public event AsyncCallback CallbackComplete = delegate { };

                                private CallbackEventBridge() {}

                                private void CallbackInternal(IAsyncResult result)
                                {
                                    CallbackComplete(result);
                                }

                                public AsyncCallback Callback
                                {
                                    get { return new AsyncCallback(CallbackInternal); }
                                }

                                public static CallbackEventBridge Create()
                                {
                                    return new CallbackEventBridge();
                                }
                            }
"@
                    }

                    $bridge = [CallbackEventBridge]::Create()
                    Register-ObjectEvent -InputObject $bridge -EventName CallbackComplete -Action $Callback | Out-Null

                    $bridge.Callback

                }

                function Test-Port {

                    Param (
                        [Parameter(Mandatory = $True)] [String] $h,
                        [Parameter(Mandatory = $True)] [int] $p,
                        [Parameter(Mandatory = $True)] [int] $timeout
                    )

                    try {
                        $pAddress = [System.Net.IPAddress]::Parse($h)
                        $sockets[$p] = new-object System.Net.Sockets.TcpClient $pAddress.AddressFamily

                    }
                    catch {
                        #we're assuming this is a host name
                        $sockets[$p] = new-object System.Net.Sockets.TcpClient
                    }

                    
                    $scriptBlockAsString = @"

                        #somewhat of a race condition with the timeout, but I don't think it matters
                        if ( `$sockets[$p] -ne `$NULL)
                        {
                            if (!`$timeouts[$p].Disposed) {
                                `$timeouts[$p].Dispose()
                            }

                            `$status = `$sockets[$p].Connected;
                            if (`$status -eq `$True)
                            {
                                #write-host "$p is open"
                                `$openPorts.Add($p)
                            }
                            else
                            {
                                #write-host "$p is closed"
                                `$closedPorts.Add($p)

                            }
                            `$sockets[$p].Close();

                            `$sockets.Remove($p)
                        }
"@
                    $timeoutCallback = @"
                        #write-host "$p is filtered"
                        `$sockets[$p].Close()
                        if (!`$timeouts[$p].Disposed) {
                            `$timeouts[$p].Dispose()
                            `$filteredPorts.Add($p)
                        }
                        `$sockets.Remove($p)
"@

                    $timeoutCallback = [scriptblock]::Create($timeoutCallback)

                    $timeouts[$p] = New-Object System.Timers.Timer
                    Register-ObjectEvent -InputObject $timeouts[$p] -EventName Elapsed -Action $timeoutCallback | Out-Null
                    $timeouts[$p].Interval = $timeout
                    $timeouts[$p].Enabled = $true

                    $myscriptblock = [scriptblock]::Create($scriptBlockAsString)
                    $x = $sockets[$p].beginConnect($h, $p,(New-ScriptBlockCallback($myscriptblock)) , $null)

                }

                function PortScan-Alive
                {
                    Param (
                        [Parameter(Mandatory = $True)] [String] $h
                    )

                    Try
                    {

                        #ping
                        if ($hostPortList.Contains(-1))
                        {
                            $ping = new-object System.Net.NetworkInformation.Ping
                            $pResult = $ping.send($h)
                            if ($pResult.Status -eq "Success")
                            {
                                return $True
                            }
                        }
                        foreach($Port in $hostPortList)
                        {
                            if ($Port -ne -1)
                            {
                                Test-Port -h $h -p $Port -timeout $Timeout
                            }
                        }

                        do {
                            Start-Sleep -Milli 100
                            if (($openPorts.Count -gt 0) -or ($closedPorts.Count -gt 0)) {
                                return $True
                            }
                        }
                        While ($sockets.Count -gt 0)

                    }
                    Catch
                    {
                        Write-Error "Exception trying to host scan $h"
                        Write-Error $_.Exception.Message;
                    }

                    return $False
                }

                function Portscan-Port
                {
                    Param (
                        [Parameter(Mandatory = $True)] [String] $h
                    )

                    [string[]]$Ports = @()

                    foreach($Port in $Portlist)
                    {
                        Try
                        {
                            Test-Port -h $h -p $Port -timeout $Timeout
                        }
                        Catch
                        {
                            Write-Error "Exception trying to scan $h port $Port"
                            Write-Error $_.Exception.Message;
                        }
                    }
                }
                [bool] $hostResult = $False

                if(!$SkipDiscovery)
                {
                    [bool] $hostResult = PortScan-Alive $thost
                    $openPorts.clear()
                    $closedPorts.clear()
                    $filteredPorts.Clear()
                }
                if((!$PingOnly) -and ($hostResult -or $SkipDiscovery))
                {
                    Portscan-Port $thost
                }
                while ($sockets.Count -gt 0) {
                    Start-Sleep -Milli 500
                }

                return @($hostResult, $openPorts, $closedPorts, $filteredPorts)
                }
            }

            # the outer loop is to flush the loop.
            # Otherwise Get-Job | Wait-Job could clog, etc

            [int]$saveIteration = 0
            [int]$computersDone=0
            [int]$upHosts=0
            while (($saveIteration * $SyncFreq) -lt $hostList.Count)
            {

                Get-Job | Remove-Job -Force
                $sIndex = ($saveIteration*$SyncFreq)
                $eIndex = (($saveIteration+1)*$SyncFreq)-1

                foreach ($iHost in $hostList[$sIndex..$eIndex])
                {
                    $ctr = @(Get-Job -state Running)
                    while ($ctr.Count -ge $nHosts)
                    {
                        Start-Sleep -Milliseconds $SleepTimer
                        $ctr = @(Get-Job -state Running)
                    }

                    $computersDone++
                    if(!$noProgressMeter)
                    {
                        Write-Progress -status "Port Scanning" -Activity $startMsg -CurrentOperation "starting computer $computersDone"  -PercentComplete ($computersDone / $hostList.Count * 100)
                    }

                    Start-Job -ScriptBlock $portScanCode -Name $iHost -ArgumentList @($iHost, $SkipDiscovery, $PingOnly, $Timeout, $portList, $hostPortList, $Threads)  | Out-Null
                }

                Get-Job | Wait-Job | Out-Null

                foreach ($job in Get-Job)
                {
                    $jobOut = @(Receive-Job $job)
                    [bool]$hostUp = $jobOut[0]
                    $jobName = $job.Name

                    $openPorts = $jobOut[1]
                    $closedPorts = $jobOut[2]
                    $filteredPorts = $jobOut[3]

                    if($hostUp) {
                        $upHosts ++
                    }

                    if (!$quiet)
                    {
                        $hostDate = Get-Date
                        $hostObj = New-Object System.Object
                        $hostObj | Add-Member -MemberType Noteproperty -Name Hostname -Value $jobName

                        $hostObj | Add-Member -MemberType Noteproperty -Name alive -Value $hostUp
                        $hostObj | Add-Member -MemberType Noteproperty -Name openPorts -Value $openPorts
                        $hostObj | Add-Member -MemberType Noteproperty -Name closedPorts -Value $closedPorts
                        $hostObj | Add-Member -MemberType Noteproperty -Name filteredPorts -Value $filteredPorts
                        $hostObj | Add-Member -MemberType NoteProperty -Name finishTime -Value $hostDate

                        $scannedHostList += $hostobj
                    }

                    Write-PortscanOut -outhost $jobName -isUp $hostUp -openPorts $openPorts -closedPorts $closedPorts -filteredPorts $filteredPorts -grepStream $grepStream -xmlStream $xmlStream -readableStream $readableStream -SkipDiscovery $SkipDiscovery
                }

                if ($grepStream) {
                    $grepStream.flush()
                }
                if ($xmlStream) {
                    $xmlStream.flush()
                }
                if($readableStream) {
                    $readableStream.flush()
                }

                $saveIteration ++
            }

            $enddate = Get-Date
            $totaltime = ($enddate - $startdate).TotalSeconds
            $endMsg = "Port scan complete at $enddate ($totaltime seconds)"
            if (!$SkipDiscovery) {
                $endMsg += ", $upHosts hosts are up"
            }

            Write-PortscanOut -comment $endMsg -grepStream $grepStream -xmlStream $xmlStream -readableStream $readableStream

            if($grepStream) {
                $grepStream.Close()
            }
            if ($xmlStream) {
                $xmlStream.Close()
            }
            if($readableStream) {
                $readableStream.Close()
            }

            return $scannedHostList

        }
        Catch
        {
            Write-Error $_.Exception.Message;
        }
    }
}

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
        [Parameter(Mandatory=$True)][string[]] $NetworkAddress,
        [string] $Contains,
        [switch] $Enumerate
    )

    # PowerShell ipcalc clone: PSipcalc.
    # Copyright (c), 2015, Svendsen Tech
    # All rights reserved.

    ## Author: Joakim Svendsen

    # BSD 3-clause license.

    # Original release 2015-07-13 (ish) v1.0 (or whatever...)
    # 2015-07-16: v1.2. Standardized the TotalHosts and UsableHosts properties to always be of the type int64.
    # Formely TotalHosts was a string, except for network lengths of 30-32, when it was an int32. UsableHosts used to be int32.

    # 2015-07-15: Added -Contains and fixed some comment bugs(!) plus commented a bit more and made minor tweaks. v1.1, I guess.

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

# Parsing function taken from PowersSploit.  Thanks Matthew Graeber!
function Parse-IPList ([String] $IpRange)
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
