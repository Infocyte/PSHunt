function Invoke-HuntSurvey {
<#
.SYNOPSIS
 
	Transfers and Executes a script or executable on a remote computer using various execution options.

.DESCRIPTION
	
	Transfers and Executes a script or executable on a remote computer using various execution options.
	Wraps Start-Remote Process and adds remote connectivity tests, threading, and transport of the script to be executed.
	
.NOTES

	Project: PSHunt
	Author: Chris Gerritz (Github @singlethreaded) (Twitter @gerritzc)
	Company: Infocyte, Inc.
	License: Apache License 2.0
    Required Dependencies: 	Start-RemoteTask
							Invoke-PsExec
    Optional Dependencies: 	None

.PARAMETER Targets
	IP Address or Hostnames of targets.  Can be pipelined from a targets array or file.

.PARAMETER Task
 	Name of powershell script to transfer and execute.  Default is <scriptpath>\Surveys\Survey.ps1.
	
.PARAMETER TaskArgs
	Command Line arguements to Task (input a single string)

.PARAMETER DATADIR
	Directory for host logs and receiving results.  Created by this script, filled up by Get-HuntRemoteTaskResults
	Default = "$pwd\DATADIR"
	
.PARAMETER ExecutionType
	Select method of remote execution { WMI | Schtasks | PsExec | PSRemoting | Auto }: 
		1.  WMI - Execute via WMI Process Call Create (TCP 135 + Dynamic Port)
		2.  Schtasks - Execute via Scheduled Task (TCP 445 or 139)
		3.  PsExec - Execute via PSExec (TCP 445 or 139)
		4.  PSRemoting - Use Invoke-Command via Powershell Remoting TCP 5985 (or TCP 5986 for SSL)
		6.  Auto - Query host for accessible ports and attempt execution with available protocols.  Order Preference: PSRemoting > WMI > PsExec > Schtasks
				
.PARAMETER TaskName
	Name of scheduled task (if schtasks is selected).  Default=pshunttask

.PARAMETER Credential
	Credentials to remote targets.
	
.EXAMPLE
	PS > Invoke-HuntRemoteTask.ps1 Workstation1.infocyte.com -Task .\surveys\Survey.ps1 -ExecutionType PsExec

.EXAMPLE
	PS > $Targets = "192.168.1.101","192.168.1.102","192.168.1.103"
	PS > $Targets | Invoke-HuntRemoteTask.ps1 -Task (Resolve-Path .\surveys\Survey.ps1) -ExecutionType WMI
	
.EXAMPLE
	PS > $Creds = Get-Credential galactica.int\scanSvcAcct
	PS > Get-Content .\galactica_targets.txt | Invoke-RemoteTask.ps1 -Task (Resolve-Path .\surveys\Survey.ps1) -ExecutionType Auto -Credential $Creds

#>
	[CmdletBinding()]
	Param(	
			[Parameter(	Position=0, 
						Mandatory=$false, 
						ValueFromPipeline=$True,
						HelpMessage='Hostname, IP Address, or FQDN')]
			[ValidateNotNullOrEmpty()]
			[String[]]
			$ComputerName="$env:COMPUTERNAME",

			[parameter(	Position=1, 
						Mandatory=$false,
						HelpMessage='Must be a valid .ps1')]
			[ValidateScript({ (Test-Path $_) -AND ($_ -like "*.ps1") })]	
			[String]
			$SurveyPath = "$PSScriptRoot\..\Surveys\Survey.ps1",

			[Parameter(	Mandatory=$False)]
			[String]
			$ScriptArgs='',
			
			[parameter(Mandatory=$False,
				HelpMessage='Your DATA directory')]
			[String]$DATADIR="$pwd\DATADIR",
			
			[parameter(	Mandatory=$False,
				HelpMessage="Supported execution types are: WMI, Schtasks, PsExec, PSRemoting.  Or set it to Auto.")]
			[ValidateSet('Auto', 'WMI', 'Schtasks', 'PsExec','PSRemoting')]
			[String]
			$ExecutionType='WMI',

			[Parameter(	Mandatory=$False)]
			[ValidateNotNullOrEmpty()]
			[String]
			$TaskName='pshunttask',
			
			[Parameter(	Mandatory=$False)]
			[System.Management.Automation.PSCredential]
			$Credential
		)

	BEGIN {
		
		function Write-Log {
			Param(	
				[string]$Target, 
				[String]$LogPath, 
				[string]$Msg, 
				[int]$n
			)
			$Time = get-date -format "yyyy-MM-dd hh:mm:ss:ms"
			if ($Msg -match "ERROR") {
				Write-Warning "($n): $Msg"	
			} else {
				Write-Verbose "($n): $Msg"	
			}
			"$Time, $Target, " + $Msg | Out-File -Encoding 'ASCII' -Append $LogPath
		}

		
		# Generate Random filename (random but will start with 'ps' and end in .ps1)
		[string] $RemoteFilename = 'ps' + [System.Guid]::NewGuid().ToString().Substring(2) + $SurveyPath.Substring($SurveyPath.LastIndexOf('.'))
		
		$date = get-date -uformat "%Y%m%d"	
		
		# Prep log for new scan		
		if (-NOT (Test-Path $PSScriptRoot\..\log)) { $null = New-Item $PSScriptRoot\..\log -Force }
		$LogPath = "$(Resolve-Path $PSScriptRoot\..\log\)\HuntLog.log"
		
		# Create Data Directories
		if (-NOT (Test-Path $DATADIR)) { $null = New-Item $DATADIR -Force}
		if (-NOT (Test-Path "$DATADIR\$date")) { $null = New-Item "$DATADIR\$date" -Force}
		
		$n = 0
	}

	PROCESS {

        $HostCount = $ComputerName.count
        $datetime = (Get-Date).ToString()
        Write-Verbose "STARTING NEW SURVEY ($HostCount systems) - $datetime - Using Task $SurveyPath via Execution Type $ExecutionType"

		foreach ($Target in $ComputerName) {
			if ( ($Target -eq $null) -OR ($Target -eq "") ) { continue }
			
			$n += 1
			
			#  Making local output directory
			$TargetDATADIR = "$DATADIR\$date\$Target"
			if (-NOT (Test-Path $TargetDATADIR)) { $null = New-Item $TargetDATADIR }
			
			# Setting remote folder paths and UNC path
			$RemotePath = 'C:\Windows\temp'
			$RemoteScript = "$RemotePath\$RemoteFilename"
			$RemoteUNCPath = "\\$Target\C$\Windows\temp"
			
			# Kick this thing off
			$Msg = "Executing $SurveyPath on $Target via $ExecutionType as $RemoteUNCPath\$RemoteFilename"
            Write-Log $Target $LogPath "Executing $SurveyPath on $Target via $ExecutionType as $RemoteUNCPath\$RemoteFilename." $n

			Write-Progress -activity "Deploying Surveys" -status "Percent Complete: " -PercentComplete (($n / $HostCount)  * 100) -CurrentOperation "($n of $HostCount): Surveying $Target"

			#region TEST =====================
			
			Switch ($ExecutionType) {
				'Auto' {
			
					$Ports = 135,139,445,1025,5985,49152
					Write-Verbose "($n): Auto - Scanning all relevant ports to determine execution options"
					
					$TestResults = Test-TCPPorts -Target $Target -Ports $Ports
					
					#Write-Debug "$TestResults"

					if ($TestResults.TCP5985) {
						$ExecutionType = 'PSRemoting'
					}
					elseif ( ($TestResults.TCP135) -AND (($TestResults.TCP445) -OR ($TestResults.TCP139)) -AND (($TestResults.TCP49152) -OR ($TestResults.TCP1025)) ) {
						$ExecutionType = 'WMI'
					}
					elseif ( ($TestResults.TCP445) -OR ($TestResults.TCP139) ) {
						$ExecutionType = 'PSExec'
						#$ExecutionType = 'Schtasks'
					}
					else {
						Write-Log $Target $LogPath "ERROR: Auto check failed.  $Target did not respond to any port scans! Host may be unavailable." $n
						continue						
					}
					Write-Log $Target $LogPath "Setting ExecutionType (Auto) to $ExecutionType" $n
					
				}
				'PSRemoting' {
					# TEST: PSRemoting Ports
					Write-Verbose 'Performing PSRemoting connection tests to TCP 5985'
					if (!(Test-TCPPort $Target 5985)) {
						Write-Log $Target $LogPath "ERROR: PSRemoting Check failed. Could not reach $Target on TCP port 5985!" $n
						continue
					}
				
				}
				'WMI' {
					# TEST: WMI Ports
					if ( (Test-TCPPort $Target 445) -OR (Test-TCPPort $Target 139) ) {
						#Write-Debug "($n): Test-TCPPort scan of Port 445 or 139 was successful!"
					
						if ( (Test-TCPPort $Target 49152) -OR (Test-TCPPort $Target 1025) ) {
						
							Write-Debug "($n): Test-TCPPort scan of Dynamic Port 49152 or 1025 was successful!"
						
						} else {	
							Write-Log $Target $LogPath 'ERROR: Dynamic Ports (49152+/1025+) not responding, WMI might fail if it cannot reach dynamic ports' $n
						}	
					} else {
						Write-Log $Target $LogPath "ERROR: WMI check failed.  Could not reach $Target on TCP port 445 or 139!" $n
						continue
					}
				}
				'Schtasks' { 
					# TEST: Schtasks Ports
					if ( (Test-TCPPort $Target 445) -OR (Test-TCPPort $Target 139) ) {
					
						# Write-Debug "($n): Test-TCPPort scan of Port 445 or 139 was successful"	
					
					} else {
						Write-Log $Target $LogPath "ERROR: Schtasks check failed. Could not reach $Target on TCP port 445 or 139!" $n
						continue
					}
				}
				'PsExec' { 
					# TEST: PsExec Ports
					if ( (Test-TCPPort $Target 445) -OR (Test-TCPPort $Target 139) ) {
						Write-Debug "($n): Test-TCPPort scan of Port 445 or 139 was successful"
					} else {
						Write-Log $Target $LogPath "ERROR: PsExec check failed. Could not reach $Target on TCP port 445 or 139!" $n
						continue
					}					
				}
			}
		
			#endregion Test
			
			#region TRANSPORT ===================
			
			try {
				# Sending scripts to target	using SMB transport for WMI and Schtasks execution
				Write-Verbose "Copying $SurveyPath to: $RemoteUNCPath\$RemoteFilename"
				$RemoteDisk = New-PSDrive -Name "RD" -PSProvider "FileSystem" -Root $RemoteUNCPath\ -Credential $credential
				$null = Copy-Item -Path $SurveyPath -Destination RD:\$RemoteFilename -Force
				
			} catch [System.UnauthorizedAccessException] {
				# Access Denied
				Write-Log $Target $LogPath "ERROR: Unauthorized Access on transfer of $SurveyPath to $RemoteUNCPath\$RemoteFilename." $n
				continue
			} catch {
				Write-Log $Target $LogPath "ERROR: Failed to transfer $SurveyPath to $RemoteUNCPath\$RemoteFilename.  Error Message: $($_.Exception.Message)" $n
				continue
			} finally {
				Remove-PSDrive -name RD -PSProvider FileSystem -ea 0
			}
			
			#endregion TRANSPORT
			
			#region EXECUTE
			
			
			Switch ($ExecutionType) {
				'WMI' { 		
					Write-Verbose "Executing $RemotePath\$RemoteFilename using WMI"
					$Result = Start-RemoteProcess -ComputerName $Target -PSScript $RemoteScript -ExecutionType WMI -Credential $Credential

					#If WMI fails, try PsExec (auto)
					if (($result -eq $False) -AND ($ExecutionType -eq "Auto") ) {
						# WMI Fallback Method: Scheduled Task
						Write-Verbose "($n): FALLBACK: WMI Failed, Falling back to PsExec"
						$Result = Start-RemoteProcess -ComputerName $Target -PSScript $RemoteScript -TaskName $TaskName -ExecutionType PsExec -Credential $Credential 	
                    } elseif ($result -eq $False) {
                        
					}
				}
				'Schtasks' { 			
					Write-Verbose "Executing $RemotePath\$RemoteFilename with Schtasks"
					$Result = Start-RemoteProcess -ComputerName $Target -PSScript $RemoteScript -ExecutionType Schtasks -TaskName $TaskName -Credential $Credential 	
					# Verbose output
					#if ($PSBoundParameters['verbose']) { Start-Sleep 0.5; schtasks /query /s $Target /tn $TaskName /v }
					#write-verbose "to query whether done type: schtasks /query /s $Target /tn $TaskName /v"						
				}
				'PSExec' { 
					Write-Verbose "Executing $RemotePath\$RemoteFilename with PSExec"
					$Result = Start-RemoteProcess -ComputerName $Target -PSScript $RemoteScript -ExecutionType PsExec -Credential $Credential 		
				}
				'PSRemoting' {
					Write-Verbose "Executing $RemotePath\$RemoteFilename PSRemoting's Invoke-Command"
					$Result = Start-RemoteProcess -ComputerName $Target -PSScript $RemoteScript -ExecutionType PSRemoting -Credential $Credential

				}
			}
			Write-Log $Target $LogPath "Task executed with result: $result" $n
			#endregion Execute
		}
	}

	END {
		# End scan
		$datetime = (Get-Date).ToString()
        Write-Progress -activity "Deploying Surveys" -Complete
        Write-Verbose "SURVEY COMPLETE ($HostCount systems) - $datetime - Using Task $SurveyPath via Execution Type $ExecutionType"
	}
}

function Get-HuntSurveyResults {
<#
.SYNOPSIS
	Pickup results from remote host and cleanup

	Project: PSHunt
	Author: Chris Gerritz (Github @singlethreaded) (Twitter @gerritzc)
	Company: Infocyte, Inc.
	License: Apache License 2.0
	Required Dependencies: None
	Optional Dependencies: None
	
.DESCRIPTION 
		Companion to Invoke-RemoteTask
		Used to pickup results from Execute-RemoteTask survey.
		
.NOTES

 
.EXAMPLE

#>
	[CmdletBinding()]
	Param(	
			[Parameter( Position=0, 
						Mandatory=$false, 
						ValueFromPipeline=$True,
				HelpMessage='Target NetBios Hostname, IP Address, or FQDN')]
			[ValidateNotNullOrEmpty()]
			[string[]]
			$ComputerName="$env:COMPUTERNAME",
	
			[Parameter(Mandatory=$false,
							HelpMessage='Like this: "C:\Windows\temp\SurveyResults.xml"')]
			[ValidateNotNullOrEmpty()]
			[string]
			$RemotePath='C:\Windows\temp\SurveyResults.xml',

			[parameter(Mandatory=$False,
				HelpMessage='Your DATA directory')]
			[ValidateScript({ 
				# Test if path is container (OPDATA folder) 
				Test-Path -PathType container -Path $_ })]
			[string]$DATADIR="$pwd\DATADIR",
			
			[Parameter(Mandatory=$False)]
			[ValidateNotNullOrEmpty()]
			[string]
			$TaskName='pshunttask',
			
			[Parameter(	Mandatory=$false)]
			[System.Management.Automation.PSCredential]
			$Credential
			)

	BEGIN {
		#$ErrorActionPreference = "Continue"
		#$DebugActionPreference = "Continue"
		
		#region FUNCTIONS:
		
		function Remove-ScheduledTask ($Target, $TaskName, [Switch]$Force) {	
			# Delete remote task if present
			if ($Credential.UserName -ne $null) {
				Write-Verbose "Using specified credentials: " + $Credential.Username.ToString()
				$Result = schtasks /query /s $Target /tn $TaskName /U ($Credential.Username) /P ($Credential.GetNetworkCredential().password) 2>&1
			} else {
				$Result = schtasks /query /s $Target /tn $TaskName 2>&1
			}
			
			if ($Results -match 'ERROR: The network address is invalid') {
				Write-Debug "$Results"
				return "ERROR: The network address is invalid"
			}
			elseif ($Results -match 'ERROR: The system cannot find the file specified') {
				Write-Debug "$Results"
				return 'ERROR: The system cannot find the file specified'		
			}
			elseif ($Results -match 'Running') {
				Write-Debug "$Results"
				if (!$Force) {
					return "WAIT: Task still Running"
				}
			} 
			else {
				Write-Debug "$Results"
				return $Results
			}
			
			Write-Verbose "Deleting scheduled task on $Target"
			if ($Credential.UserName -ne $null) {
				Write-Verbose "Using specified credentials: " + $Credential.Username.ToString()
				$Result = schtasks /delete /s $Target /tn $TaskName /U ($Credential.Username) /P ($Credential.GetNetworkCredential().password) 2>&1
			} else {
				$Result = schtasks /delete /s $Target /tn $TaskName 2>&1
			}
			Write-Debug "$Results"
			
			return "SUCCESS: Task Removed from $Target"
		}  

		function Write-Log {
			Param(	
				[string]$Target, 
				[String]$LogPath, 
				[string]$Msg, 
				[int]$n
			)
			$Time = get-date -format "yyyy-MM-dd hh:mm:ss:ms"
			if ($Msg -match "ERROR") {
				Write-Warning "($n): $Msg"	
			} else {
				Write-Verbose "($n): $Msg"	
			}
			"$Time, $Target, " + $Msg | Out-File -Encoding 'ASCII' -Append $LogPath
		}

		
		#endregion Functions
			
		$date = get-date -uformat "%Y%m%d"	
		$ResultsFileName = Split-Path $RemotePath -Leaf
		
		# Prep log		
		if (-NOT (Test-Path $PSScriptRoot\..\log)) { $null = New-Item $PSScriptRoot\..\log -Force }
		$LogPath = "$(Resolve-Path $PSScriptRoot\..\log\)\HuntLog.log"
		
		# Create Data Directories if not already made
		if (-NOT (Test-Path $DATADIR)) { $null = New-Item $DATADIR -Force}
		if (-NOT (Test-Path "$DATADIR\$date")) { $null = New-Item "$DATADIR\$date" -Force}
	
		$n = 0
	}

	PROCESS {

        $HostCount = $ComputerName.count
        $datetime = (Get-Date).ToString()
        Write-Verbose "STARTING SURVEY RESULT RECOVERY ($HostCount systems) - $datetime - Recovering $ResultsFileName"

		foreach ($target in $ComputerName) {
			if ( ($Target -eq $null) -OR ($Target -eq "") ) { continue }
			
			$n += 1
			$pickuptime = get-date -format "hhmm"
			$RemoteUNCPath = "\\$Target\$($RemotePath.Chars(0))$\$($RemotePath.Substring($RemotePath.IndexOf(':')+2))"
			$TargetDATADIR = "$DATADIR\$date\$Target"

			Write-Verbose "($n): Recovering $ResultsFileName from $target. Local Target Datadir: $TargetDATADIR"
			Write-Progress -activity "Recovering Survey Results" -status "Percent Complete: " -PercentComplete (($n / $HostCount)  * 100) -CurrentOperation "($n of $HostCount): Recovering $ResultsFileName from $Target"

			
			#region TEST
			
			#  Check local output directory
			if (!(Test-Path $TargetDATADIR)) {
				Write-Log $Target $LogPath "ERROR: $TargetDATADIR does not exists. $Target may not have been scanned. Exiting" $n
				continue
			}
			
			if ( (Test-TCPPort $target 445) -OR (Test-TCPPort $target 139) ) {
				
			} else {
				Write-Log $Target $LogPath "ERROR: $target did not respond on port 445 or 139" $n
				continue
			}
			#endregion Test

			#region PICKUP
			
			try {
				Write-Debug "($n): Transfering $RemoteUNCPath to $TargetDATADIR\$pickuptime-$ResultsFileName"
				$RemoteDisk = New-PSDrive -Name "RD" -PSProvider FileSystem -Root (Split-Path $RemoteUNCPath -Parent) -Credential $credential
				if (Test-Path RD:\$ResultsFileName) {
					$null = Move-Item -Path RD:\$ResultsFileName -Destination $TargetDATADIR\$pickuptime-$ResultsFileName -Force
					Write-Log $Target $LogPath "SUCCESS[Get-HuntSurveyResults]: Recovered $RemoteUNCPath to $TargetDATADIR\$pickuptime-$ResultsFileName" $n				
				} else {
					# Survey Results not present
					Write-Log $Target $LogPath "FAILURE[Get-HuntSurveyResults]: $RemoteUNCPath was not found" $n		
				}				
			} catch [System.UnauthorizedAccessException] {
				# Access Denied
				Write-Log $Target $LogPath "ERROR: Unauthorized Access transfering $RemoteUNCPath to $TargetDATADIR" $n
				$null = Remove-PSDrive -name RD -PSProvider FileSystem
				continue
			} catch {
				Write-Log $Target $LogPath "ERROR: Failed transfering $RemoteUNCPath to $TargetDATADIR.  Error Message: $($_.Exception.Message)" $n
				$null = Remove-PSDrive -name RD -PSProvider FileSystem
				continue
			} 
				
			
			#endregion Pickup
			
			#region CLEANUP
			
			# Delete Scheduled Task
			# $null = Remove-ScheduledTask $Target $TaskName

			<#
			$TimeOut = 180
			$Date = Get-Date
			While ($isRunning) {
				$Results = Remove-ScheduledTask $Target $TaskName
				if ( ($Results -match "Running") -AND (((Get-Date) - $Date).TotalSeconds -lt $TimeOut) {
					Start-Sleep -s 5
				} else {
					$isRunning = $False
				}
			}
			#>
			
			# Cleanup Task
			$filter = [regex]"ps\w{6}-\w{4}-\w{4}-\w{4}-\w{12}[.]ps1$"
			Write-Verbose "($n): Cleaning survey off $Target using a regex filter"
			try {
				$null = Get-ChildItem RD:\ | where { $_.name -match $filter } | Remove-Item
			} catch {				
				Write-Debug "$($_.Exception.Message)"
			} finally {
				$null = Remove-PSDrive -name RD -PSProvider FileSystem
			}
			#endregion Cleanup

        Write-Output (Resolve-Path $TargetDATADIR\$pickuptime-$ResultsFileName)
		}
	}

	END {
		# End scan
		$datetime = (Get-Date).ToString()
        Write-Progress -activity "Recovering Survey Results" -Complete
        Write-Verbose "COMPLETED SURVEY RESULT RECOVERY ($HostCount systems) - $datetime - $RemotePath has been picked up"
		
	}
}
		
