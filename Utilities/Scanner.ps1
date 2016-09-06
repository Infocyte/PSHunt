function Invoke-HuntScanner {
<#
.SYNOPSIS

	Conducts Multithreaded Scans of the desired scan.  Scans are defined in functions stored in $PSModulePath\Scanners\

	The optimal number of threads may vary in your environment.  
	Note: Memory consuption will add up at about 1-2MB per thread/runspace. 

	Project: PSHunt
	Author: Chris Gerritz (Github @singlethreaded) (Twitter @gerritzc)
	Company: Infocyte, Inc.
	License: Apache License 2.0
	Required Dependencies: None
	Optional Dependencies: None

.DESCRIPTION

	A Scan executes functions against a remote system to collect a small amount of information.  
	Scans are defining as scriptblock functions that accept the following inputs and outputs.

	INPUTS: 
	- String Array of ComputerNames or IPs (of remote system)
	- PSCredential
	- Any user defined args

	OUTPUT:
	- PSObject (will be assigned to ScanData[$computer])

	
.NOTES
	When defining a Scan:
	- Do not use Write-Host or anything else you shouldn't be using in a normal cmdlet or powershell function
	- Verbose statements will print
	- Debug the Scan by calling it with the -Debug parameter.  Errors will be lost when ran using Invoke-HuntScanner
	
	
.PARAMETER ComputerName
	List of IP or DNS/NetBIOS names

.PARAMETER ScanPath
	Creates a scriptblock from a Scan.  You can choose which scan to use from the scanners folder and even define your own by using the template.
	
.PARAMETER ArgumentList
	Arguments for the scan function

.PARAMETER ThrottleLimit
	Number of concurrent threads. Default: 32.  For synchronous or Network I/O bound tasks, crank the threads to 100+ for optimal performance.

.PARAMETER Randomize
	Randomize the order of hosts scanned (helpful on large geographically distributed networks)

.PARAMETER HideProgress
	Do not display progress with Write-Progress

.PARAMETER Timeout
	Timeout in seconds for each thread. Default = 30.  Don't set too low, there is wierdness with threading that aren't directly intuitive - could cause problems.

.PARAMETER Credential
	Credentials of remote system.

.EXAMPLE

	PS C:\> $ScanPath = "C:\Users\Chris\Documents\GitHub\PSHunt\Scanners\SB_OSInfo.ps1"
	PS C:\> $Target = "cic.galactica.int", "localhost", "Win2k8R2"
	PS C:\> $Credential = Get-Credential galactica\adama
	PS C:\> Invoke-HuntScanner -ComputerName $Target -ScanPath $ScanPath -Credential $Credential -verbose
			
.EXAMPLE

	PS C:\> $ScanPath = "C:\Users\Chris\Documents\GitHub\PSHunt\Scanners\SB_OSInfo.ps1"
	PS C:\> $ScanArgs = @($True, "AnotherArg")
	PS C:\> $Target = "cic.galactica.int", "localhost", "Win2k8R2"
	PS C:\> $Credential = Get-Credential galactica\adama
	PS C:\> Invoke-HuntScanner -ComputerName $Target -ScanPath $ScanPath -ArgumentList $ScanArgs -Credential $Credential -verbose
	

#>
	Param(	
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[ValidateNotNullOrEmpty()]
		[Alias('PSComputerName')]
		[string[]] 
		$ComputerName,
		
		[Parameter(Mandatory=$true)]
		[ValidateScript({ Test-Path $_ })]
		[String]
		$ScanPath,
		
		[String[]]
		$ArgumentList,

        [int] 
		$ThrottleLimit = 32,
		
		[switch]
		$Randomize,
		
        [switch] 
		$HideProgress,

        [int] 
		$Timeout = 30,
		
		[Parameter(	Mandatory=$false)]
		[System.Management.Automation.PSCredential]
		$Credential
	)
	
	BEGIN {
	
		# Set up threads
		$MyEAP = 'Stop'
		$ErrorActionPreference = $MyEAP
		$StartTime = Get-Date

		$ScanData = [HashTable]::Synchronized(@{})
		
		$RunspaceTimers = [HashTable]::Synchronized(@{})
		$Runspaces = New-Object -TypeName System.Collections.ArrayList
		$RunspaceCounter = 0
		
		Write-Verbose -Message 'Creating initial session state.'
		$ISS = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
		$ISS.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList 'RunspaceTimers', $RunspaceTimers, ''))
		$ISS.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList 'ScanData', $ScanData, ''))
		
		Write-Verbose -Message 'Creating runspace pool.'
		$RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit, $ISS, $Host)
		$RunspacePool.ApartmentState = 'STA'
		$RunspacePool.Open()	

		# Create ScriptBlock from selected Scan
		$SBText = Get-Content $ScanPath
		$ScriptBlock = [ScriptBlock]::Create($SBText)
		Write-Verbose "ScriptBlock created from $ScanPath"
		
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
						Activity = 'Threaded Scan'
						Status = 'Processing: {0} of {1} ({3:P0}) jobs complete. Using {2} threads' -f ($RunspaceCounter - $Runspaces.Count), $RunspaceCounter, $ThrottleLimit, $PercentComplete
						PercentComplete = $PercentComplete * 100
					}
					Write-Progress @ProgressSplatting
				}
			}
			while ($More -and $PSBoundParameters['Wait'])
		} # end of Get-Result
	  
		$StartTime = Get-Date
		$AllTargets = @()
	}

	PROCESS {
		if ($Randomize) {
			# Randomize systems so it's not all against one subnet (only helpful on larger, distributed networks)
			 $Targets = Randomize-List -InputList $ComputerName		
		} else {
			$Targets = $ComputerName	
		}
		$AllTargets += $Targets
		
		Write-Verbose "Scanning $($ComputerName.Count) hosts using $ThrottleLimit threads"
		Write-Verbose "$ScanPath"
		
		foreach ($Computer in $Targets) {
			
			# Adding ScriptBlock Job to runspace
			++$RunspaceCounter
			$psCMD = [System.Management.Automation.PowerShell]::Create().AddScript($ScriptBlock)
			[void] $psCMD.AddParameter('ID', $RunspaceCounter)
			[void] $psCMD.AddParameter('Computer', $Computer)
			[void] $psCMD.AddParameter('Credential', $Credential)
			[void] $psCMD.AddParameter('Verbose', $VerbosePreference)
			Foreach ($argument in $ArgumentList) {
				[void] $PSCMD.AddParameter($argument)
			}

			$psCMD.RunspacePool = $RunspacePool
			Write-Verbose -Message "Adding job for $Computer"
			[void]$Runspaces.Add(@{
				Handle = $psCMD.BeginInvoke()
				PowerShell = $psCMD
				IObject = $Computer
				Task = 'Custom'
				ID = $RunspaceCounter
			})
		} # End foreach Targets
	} #End Process
	
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
		
		# Sort and write results to pipeline
		$AllTargets | Sort-Object -Property @{ 
			# Sort results by ComputerName
			Expression ={ 
				if ($_.Name -match "\A$IPv4Regex\z") { 
					# Sort by IP Address Octet
					($_.Name.Split('.') | ForEach-Object { '{0:D3}' -f [int] $_ }) -join '.' 
				} else { 
					# Sort by hostname
					$_.Name 
				} 
			}
		} | ForEach-Object {
			Write-Output $ScanData[$_]
		}

		# Run Garbage Collection as this function tends to consume a lot of memory if using a high number of threads
		[System.GC]::Collect()
	}
}


function New-HuntScan {
	# Generate a HuntScan template file
	
$BeginScript = @"
<#
.SYNOPSIS

	<Scan Template - Put a Short Description Here>
	
	Scan is formated to run multi-threaded with Invoke-HuntScanner.

	Project: PSHunt
	Author: Chris Gerritz (Twitter @gerritzc Github @singlethreaded)
	Company: Infocyte, Inc.
	License: Apache license 2.0
	Required Dependencies: Invoke-HuntScanner
	Optional Dependencies: None
	
.NOTES

	Debug without Invoke-HuntScanner using the debug parameter.  Like this:
	
	PS > $Cred = Get-Credential galactica\adama
	PS > .\SB_OSInfo.ps1 -Computer cic.galactica.int -Credential $Cred -verbose -debug

.PARAMETER ComputerName
	IP or DNS/NetBIOS name of remote system
	
.PARAMETER Credential
	Credential of remote system
	
.EXAMPLE		
	PS C:\> $ScanPath = "C:\Users\Chris\Documents\GitHub\PSHunt\Scanners\Scan_RegistryValue.ps1"
	PS C:\> $Targets = "cic.galactica.int", "localhost", "Win2k8R2"
	PS C:\> $Credential = Get-Credential galactica\adama
	
	PS C:\> Invoke-HuntScanner -ComputerName $Targets -ScanPath $ScanPath -ArgumentList $ScanArgs -Credential $Credential -verbose
	
#>
[CmdletBinding()]
param(
	[int] $ID=0,
	[string] $Computer,
	[System.Management.Automation.PSCredential] $Credential
)

<#
	HuntScanner Variables in each thread from Invoke-HuntScanner:
	$RunspaceTimers
	$ScanData
#> 

# Test
if ($PSBoundParameters['Debug']) {
	# For debugging the scriptblock independant of Invoke-HuntScanner
	$ScanData = [HashTable]::Synchronized(@{})
} else {
	# Get the start time.
	$RunspaceTimers.$ID = Get-Date
}

# Add computer to ScanData Object
if (-not $ScanData.ContainsKey($Computer)) {
	$ScanData[$Computer] = New-Object -TypeName PSObject -Property @{ 
		ComputerName = $Computer
		Errors = @()
	}
}


#########################################
# Start Scan Function 						
# Define script here
# Inputs: 	$ComputerName
#			$Credential
#			+ any user defined inputs ($Args)
# Outputs: 	Add output to $ScanData[$Computer] as a new member (NoteProperty) rather than pipeline:
# 			Example: $ScanData[$Computer] | Add-Member -MemberType NoteProperty -Name 'OS' -Value $OS
#########################################

# Uniquely define a new GUID for every defined scan
"@
	

$NewSigline = '$ScanSignature = "' + "$(New-GUID)" + '"'

$EndScript = @"


$ScanData[$Computer] | Add-Member -MemberType NoteProperty -Name 'Test' -Value $True

#########################################
# End Scan Function 							
#########################################

if ($PSBoundParameters['Debug']) {
	# Return ScanData if Debuging script outside Invoke-HuntScanner
	return $ScanData[$computer]
}
"@

$Script = $BeginScript + $NewSigLine + $EndScript
$Script | Out-File Scan_Template.ps1
Write-Verbose "Exported scan template to $pwd\Scan_Template.ps1"
Write-Verbose "Now define your scan and import it using Import-HuntScan"
}

function Add-HuntScan {

}

function Remove-HuntScan {

}

function Get-HuntScan {

}


