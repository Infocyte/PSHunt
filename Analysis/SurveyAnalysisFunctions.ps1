<#
.SYNOPSIS

Wrapper for Get-VTReport.  Checks the VTSubmissionLog for cached entries and formats results into 
one line of CSV.  Additionally, if not a private key it requests VTReports at 4 reports per minute 
per the public key speed limit. 

Author: Chris Gerritz (Github @singlethreaded) (Twitter @gerritzc)
License: BSD 3-Clause
Required Dependencies: VirusTotal.psm1
Optional Dependencies: None

.DESCRIPTION

.PARAMETER Hashes

Specifies the hashes to request VTReports on.

.PARAMETER APIKey

VirusTotal API Key

.PARAMETER PrivateKey

Specifies whether the key is private (removes submission speed limit)

.EXAMPLE

$Process.SHA1 | Get-HuntVTStatus -APIKey 'cb83aa5543b1...'

#>

#region Analysis Cmdlets

function Initialize-HuntReputation {
	Param([Switch]$Reload)
# Load Reputation Data into global lookup hashtables 
	
	function _Import-FileReputation {
		Param(
			[String]$csvpath
		)
		$NullHash = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
		$start = Get-Date
		$hashlist = @{}
		try { $CSV = import-csv $csvpath 
		} catch { 
			Write-Warning Could not get reputation from $Path
			exit 
		}
		$TotalItems = $CSV.count
		$n = 1
		Foreach ($line in $CSV) { 
			# process the line
			$hash = $line.SHA1
			if (($hash -ne "") -AND ($hash -ne $NullHash) -AND (-not $hashlist.ContainsKey($hash)) ) {
				$hashlist.Add($hash, $line.Status)		
			}
			if ($n%1000 -eq 0) {
				Write-Progress -Activity "Importing Reputation" -percentcomplete "-1" -status "$n hashes added to Hashtable"
			}
			$n += 1
		}
		$timetaken = ((Get-Date) - $start).totalseconds
		Write-Progress -Activity "Importing Reputation" -percentcomplete "-1" -status "$n hashes added to Hashtable in $timetaken" -Completed
		Write-Verbose "$n hashes added to Hashtable in $timetaken seconds"
		<#
		$reader = [System.IO.File]::OpenText($path)
		
		# Test list
		try {
			$line = $reader.ReadLine()
			if (($line -notlike "#TYPE*") -AND ($line -notlike '"Name",*')) {
				Write-Error "Error: $path is not a readable helix list"
				$reader.Close()
				exit
			}
		} catch {
			$reader.Close()
			Write-Error "Error: Could not read from file: $path"
			exit
		} 
		
		while ($line = $reader.ReadLine()) {
			if ( ($line -eq $null) -OR ($line -like "#TYPE*") -OR ($line -like '"Name",*') ) { continue }
			
			# process the line
			$sha1 = $line.split(",")[3].Trim('"')
			$obj = New-Object PSObject -Property @{
				Name		= $line.split(",")[0].Trim('"')
				PathName	= $line.split(",")[1].Trim('"')
				Notes		= $line.split(",")[6].Trim('"')
			}
			if (($sha1 -ne "") -AND ($sha1 -ne $NullHash) -AND (-not $hashlist.ContainsKey($sha1)) ) {
				$hashlist.Add($sha1, $obj)
			}
		}
		$reader.Close()
		#>
		
		return $hashlist
	}
		
	function _Import-NIST {
	Param(
		[Parameter(Position=0, Mandatory=$True)]
		[ValidateScript({ Test-Path $_ -PathType Leaf -Include *.txt })]	
		[String]$path
	) 
		$NullHash = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
		$start = Get-Date
		$hashlist = New-Object Hashtable 2000000
		try {
			$reader = [System.IO.File]::OpenText($path)
		} catch {
			Write-Warning "Could not open $Path"
		}

		$n = 0
		$line = $reader.readline()
		if ( ($line -match "^[0-9a-zA-Z]{40}") -OR ($line -match "^[0-9a-zA-Z]{32}") -OR ($line -match "^[0-9a-zA-Z]{64}")) {
			$hashlist.Add($line, $true)
			$n += 1
		} else {
			Write-Warning "File is not a list of hashes, $line is not a hash";
			exit 
		}
		
		while ($line = $reader.ReadLine()) {
			if ( ($line -eq $null) -OR ($line -eq $NullHash) ) { continue }	 
			if ( -not $hashlist.ContainsKey($line) ) {
				$hashlist.Add($line, $null)
			}
			$n += 1
			if ($n%1000 -eq 0) {
				Write-Progress -Activity "Reading from NIST" -percentcomplete "-1" -status "$n hashes added to Hashtable"
			}
		}
		$timetaken = ((Get-Date) - $start).totalseconds
		Write-Progress -Activity "Reading from NIST" -percentcomplete "-1" -status "$n hashes added to Hashtable in $timetaken" -Completed
		Write-Verbose "$n hashes added to Hashtable in $timetaken seconds"
		$reader.Close()
		return $hashlist
	}

	function _Import-URLReputation {
		Param(
			[String]$csvpath
		)
		$start = Get-Date
		$hashlist = @{}
		try { $CSV = import-csv $csvpath 
		} catch { 
			Write-Warning Could not get reputation from $Path
			exit 
		}
		$TotalItems = $CSV.count
		$n = 1
		Foreach ($line in $CSV) { 
			# process the line
			$URL = $line.URL
			if (($URL -ne "") -AND ($URL -ne $Null) -AND (-not $hashlist.ContainsKey($URL)) ) {
				$hashlist.Add($URL, $line.Status)		
			}
			if ($n%1000 -eq 0) {
				Write-Progress -Activity "Importing Reputation" -percentcomplete "-1" -status "$n IPs added to Hashtable"
			}
			$n += 1
		}
		$timetaken = ((Get-Date) - $start).totalseconds
		Write-Progress -Activity "Importing Reputation" -percentcomplete "-1" -status "$n IPs added to Hashtable in $timetaken" -Completed
		Write-Verbose "$n IPs added to Hashtable in $timetaken seconds"
		
		return $hashlist
	}
		
	# Load ReputationData
	
	$NISTPath = Resolve-Path $PSScriptRoot\..\ReputationData\NIST_SHA1.txt
	$FileReputationPath = Resolve-Path $PSScriptRoot\..\ReputationData\Files.csv
	$URLReputationPath = Resolve-Path $PSScriptRoot\..\ReputationData\URL_IP.csv
	$PipesReputationPath = Resolve-Path $PSScriptRoot\..\ReputationData\Pipes.csv
	
	if (!$Global:NIST) {
		$Message = "Loading NIST Database - {0:N2} MB" -f ((Get-ItemProperty -path $NistPath).length/1000000)
		Write-Verbose $Message 
		$Global:NIST = _Import-NIST $NISTPath
	} 
	if ( ($Reload) -OR (!$Global:FileReputation) ) {
		$Message = "Loading FileReputation - {0:N2} MB" -f ((Get-ItemProperty -path $FileReputationPath).length/1000000)
		Write-Verbose $Message 
		$Global:FileReputation = _Import-FileReputation $FileReputationPath
	}
	if ( ($Reload) -OR (!$Global:URLReputation) ) {
		$Message = "Loading URLReputation - {0:N2} MB" -f ((Get-ItemProperty -path $URLReputationPath).length/1000000)
		Write-Verbose $Message 
		$Global:URLReputation = _Import-URLReputation $URLReputationPath
	}
	<#
	if (!$Global:PipesReputation) {
		$Global:PipesReputation = _Import-URLReputation $PipesReputationPath
	}	
	#>
	return 
}

function Update-HuntObject {
<#
.SYNOPSIS 	
	Used to analyze output from the psHunt Survey (survey.ps1) HostObject.

	Author: Chris Gerritz (Github @singlethreaded) (Twitter @gerritzc)
	License: BSD 3-Clause
	Required Dependencies: 	SurveyAnalysis.ps1
							VirusTotal.psm1
	Optional Dependencies: 	None

.DESCRIPTION 
	
.PARAMETER HostObjects
	Path to HostObject (Array)

.PARAMETER Baseline
	Output a CSV of the HostObject for inclusion in whitelist.  Default = False

.PARAMETER Reprocess
	Reprocess an already processed hostobject. Default = False
				
.EXAMPLE
	PS > gci .\DATADIR -recurse | Update-HostObject
	
#>
[CmdletBinding()]  
Param(
	[Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True,
		HelpMessage="List of Paths to HostObjects")]
	[ValidateScript({ Test-Path $_ -PathType Leaf -Include *.xml })]	
	[alias("PathNames")]
	[string[]]$HostObjects,

	[Parameter(Mandatory=$False)]
	[switch]$VirusTotal,
	
	[Parameter(Mandatory=$False)]
	[switch]$Reprocess
)
		
	BEGIN {

		$version = 0.7 # version needs to match the survey & hostobject version
		$SurveyFileName = "HostSurvey.xml"
		$HostObjectType = 'psHunt_HostObject'
		$datestamp = get-date -uformat "%D"
		$Hashtype = "SHA1"
		$NullHash = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"

		#region Functions:

		function _Merge-HashTable($htold, $htnew) {
			$keys = $htold.getenumerator() | foreach-object {$_.key}
			$keys | foreach-object {
				$key = $_
				if ($htnew.containskey($key))
				{
					$htold.remove($key)
				}
			}
			$htnew = $htold + $htnew
			return $htnew
		}

		# Check Files against hash reputation
		function _Compare-Hash ($InputList) {
			foreach ($item in $InputList) {
				if ($item) {
					$item | Add-Member -type NoteProperty -Name Status -Value "Unknown" -Force
				} else {
					continue
				}
				#Begin Checks
				if ( ($item.SHA1 -ne $Null) -AND ($item.SHA1 -ne "")) {
									
					#Check Hash against file reputation lists
					if ($Global:FileReputation.Contains($item.SHA1)) {
						$item.Status = $Global:FileReputation[$item.SHA1]
						continue
					}
					elseif ($Global:NIST.Contains($item.SHA1)) {
						#query NIST database
						$item.Status = "Good"
						continue
					}
				}
				
			} #End Foreach
		}
		
		# Process Connections against IP Reputation
		function _Compare-Connection ($Netstat) {
			foreach ($cnx in $Netstat) { 
				# Assign process's check
				$cnx | Add-Member -type NoteProperty -name Status -value "Unknown" -Force
				if ($item.Dst_Address) {
					# Check IP/URL
					if ($Global:URLReputation.Contains($Item.Dst_Address)) {
						$item.Status = $Global:URLReputation[$item.Dst_Address]
					}
				}
			}
		}

		#endregion Functions



		# Import Reputation Lists ==============
		
		
		if (!$Global:FileReputation) {
			Write-Verbose "Initializing Reputation Data"
			Initialize-HuntReputation
		} else {
			Write-Verbose "Reputation Data already initialized"
		}
		$Unknowns = @{}
		
		$n = 0
		$total = $HostObjects.count
		Write-Verbose "Test: $total"
	}
	PROCESS {
		$total = $HostObjects.count
		foreach ($PathName in $HostObjects) {
			<#
			# Check inputs:
			if (($PathName -notlike "*.xml") -OR !(Test-Path $PathName)) { 
				Write-Verbose "$PathName does not exist or is not an xml file"
				break 
			}
			if (Test-Path -pathtype Container -Path $PathName) {Write-Verbose 'Path to Survey HostObject is a container';break}
			#>
			
			$n += 1
			Write-Progress -Activity "Processing HostObjects" -percentcomplete "$n/$total" -status "Processing HostObject $n of $total"
			Write-Verbose "($n): Processing $PathName"		
			

			# Import host Objects
			Write-Verbose "Importing $PathName"
			$HostObject = Import-Clixml $PathName
			
			# Check psHunt_HostObject type and version
			if ( ($HostObject.ObjectType -ne $HostObjectType) -OR ($HostObject.Version -ne $version) ) {
				Write-Verbose "($n): Not a $HostObjectType with version: $version. Skipping"
				break
			}
			
			#Test if already processed
			if ($Reprocess -OR (!$HostObject.processed)) {

				# process ProcessList
				Write-Verbose "Processing ProcessList..."
				$null = _Compare-Hash $HostObject.ProcessList
				
				Foreach ($item in $HostObject.ProcessList) {
					# Items that cannot be checked but should be there (Idle Process, System, etc):
					if ( ($item.ProcessId -eq 0) -OR ($item.ProcessId -eq 4) ) {
						$item.Status = "Good"
					}
					elseif ( ($item.ParentProcessId -eq 4) -AND ($item.SHA1 -eq $null) ) {
						#Check smss.exe and anything else spawned off System
						$item.Status = "Good"						
					}
					elseif ( ($item.Name -eq 'audiodg.exe') -AND ($item.PathName -eq $null) ) {
						#Check audiodg
						$item.Status = "Good"						
					}
				}
				
				# process ModuleList
				Write-Verbose "Processing loaded DLLs..." 
				$null = _Compare-Hash $HostObject.ModuleList
				
				# process DriverList
				Write-Verbose "Processing Drivers..."
				$null = _Compare-Hash $HostObject.DriverList
				
				# Process Autoruns
				Write-Verbose "Processing Autoruns..."
				$null = _Compare-Hash $HostObject.Autoruns
				
				# Process NetStat
				Write-Verbose "Processing connections..."
				$null = _Compare-Connection $HostObject.NetStat
 
				$HostObject.Processed = $true	
				$HostObject.DateProcessed = Get-Date
				
				Write-Verbose "Updating $PathName"
				$HostObject | Export-CLIXML "$PathName"  -Encoding "UTF8" -Force
				
				# Add Unknowns:
				($HostObject.ProcessList | where {$_.Status -eq "UNKNOWN"}).SHA1 + 
					($HostObject.ModuleList | where {$_.Status -eq "UNKNOWN"}).SHA1 + 
					($HostObject.DriverList | where {$_.Status -eq "UNKNOWN"}).SHA1 + 
					($HostObject.Autoruns | where {$_.Status -eq "UNKNOWN"}).SHA1 | % {
					try {
						$Unknowns.Add($_,0)
					} catch {}
				}
				
			} else {
				Write-Verbose "HostObject has already been processed, skipping"
			}
		}
	}
	END {
		if ($VirusTotal) { 
			$unknowns.Keys | Get-HuntVTStatus
		}
		write-verbose "Processing Complete"
		return $Unknowns.Keys

	}
}

function Get-HuntVTStatus {
	<#
	.SYNOPSIS

	Wrapper for Get-VTReport.  Checks the VTSubmissionLog for cached entries and formats results into 
	one line of CSV.  Additionally, if not a private key it requests VTReports at 4 reports per minute 
	per the public key limit. 

	Author: Chris Gerritz (Github @singlethreaded) (Twitter @gerritzc)
	License: BSD 3-Clause
	Required Dependencies: VirusTotal.psm1
	Optional Dependencies: None

	.DESCRIPTION

	.PARAMETER Hashes

	Specifies the hashes to request VTReports on.

	.PARAMETER APIKey

	VirusTotal API Key.  Fill this in with your key as a default if you don't want to keep putting it in the commandline.

	.PARAMETER PrivateKey

	Specifies whether the key is private (removes submission speed limit)

	.EXAMPLE

	$Process.SHA1 | Get-HuntVTStatus -APIKey 'cb83aa5543b1...'

	#>
	
	[CmdletBinding()]
	Param(	
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
		[String[]]$Hashes,
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[string]$FileReputationPath="$PSScriptRoot\..\ReputationData\Files.csv",
		
		[Parameter(Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[String]$APIKey,
		
		[Switch]$PrivateKey
	)

	BEGIN {

		$Format = @(
			"MD5"
			"SHA1"
			"SHA256"
			"Status"
			"DateAdded"
			"Notes"
		)
		$NullHash = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
		$today = get-date -format d	
		$StatusUnknown = "Unknown"
		$StatusGood = "Good"
		$StatusSuspicious = "Suspicious"
		$StatusBad = "Bad"
		if ($FileReputationPath -match "^\\..\\ReputationData") {
			$FileReputationPath = "$pwd\ReputationData\Files.csv"
		}
		
		$VTCache = Import-CSV $FileReputationPath
		
		$n = 0
		$Total = $Hashes.count
	}
	PROCESS {
		foreach ($hash in $Hashes) {
			$n += 1
			
			if (!$hash) {
				Write-Verbose "($n) Hash is null, skipping"
				continue
			}
			Switch -regex ($hash) {
				"^[0-9a-zA-Z]{32}" {
					$HashType = "MD5"
					}
				"^[0-9a-zA-Z]{40}" {
					$HashType = "SHA1"
					}
				"^[0-9a-zA-Z]{64}" {
					$HashType = "SHA256"
					}
				Default { 
					Write-Warning "($n): ERROR - Incorrect hash format (MD5, SHA1, SHA256): $hash"
					continue 
					Write-Warning "continue didn't work"
					}
			}		
				
			# Check VTSubmissionLog first
			if ( ($VTCache.$HashType) -contains $Hash ) {
				Write-Verbose "Report for $Hash already in FileReputation"
				continue
			} else {
				Write-Verbose "($n): Requesting VT Report for $Hash"
				$Report = Get-VTReport -VTApiKey $APIKey -hash $Hash
				if (!$Report) { 
					Write-Warning "($n): ERROR - Could not get report for hash $hash"
					continue 
				}			
			}

			$Result = New-Object PSObject -Property @{
				MD5			= $Report.md5.ToUpper()
				SHA1		= $Report.sha1.ToUpper()
				SHA256		= $Report.sha256.ToUpper()
				Status		= $StatusUnknown
				DateAdded 	= $today
				Notes		= $null
			}
			if ($Report.response_code -ne 0) {
				if ($Report.positives -gt 2) {
					Write-Verbose "[*] Found a BAD one! Positive Match on $($Report.positives)"
					Write-Verbose $Report
					$Notes = "VT $($Report.positives.ToString()) "
					$Notes += ($Report.scans | Out-String -stream | Select-String "True").ToString().Trim()
					$Result.Status = $StatusBad
					$Result.Notes = $Notes
					
				} elseif ($Report.positives -gt 0) {
					Write-Verbose "[*] Found a SUSPICIOUS one! Positive Match on $($Report.positives)"
					Write-Verbose $Report
					$Notes = "VT $($Report.positives.ToString()) "
					$Notes += ($Report.scans | Out-String -stream | Select-String "True").ToString().Trim()
					$Result.Status = $StatusSuspicious
					$Result.Notes = $Notes
								
				} else {
					Write-Verbose "File Clean!"
					$Notes = "VT Report Clean"
					$Result.Status = $StatusGood
					$Result.Notes = $Notes
				
				}
			} else {
				Write-Verbose "Hash UNKNOWN!  Never been submitted to VT"
			}
			Write-Verbose "Appending new VTReport record to $OutFile"
			$null = $Result | Select $Format | Export-Csv $FileReputationPath -NoTypeInformation -Encoding "UTF8" -Append
			Write-Output $Result | Select $Format 

			
			# Public API Key is restricted to 4 requests per minute
			if (!$PrivateKey) {
				Start-Sleep 15
			}
		}
	}
	END {
		if ($Global:FileReputation) {
			Write-Verbose "Re-Initializing Reputation Data"
			Initialize-HuntReputation -Reload
		}
	}
}

function Group-HuntObjects {
<#
.SYNOPSIS 	
	Group psHunt Survey (survey.ps1) HostObjects into a single Object with unique processes, modules, drivers, etc.  
	
	Author: Chris Gerritz (Github @singlethreaded) (Twitter @gerritzc)
	License: BSD 3-Clause
	Required Dependencies: 	SurveyAnalysis.ps1
							VirusTotal.psm1
	Optional Dependencies: 	None

.DESCRIPTION 
	
.PARAMETER HostObjects
	Path to HostObject (Array)
				
.EXAMPLE
	PS > gci .\DATADIR -recurse | Group-HostObjects
	
#>
[CmdletBinding()]  
Param(
	[Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True,
		HelpMessage="List of Paths to HostObjects")]
	[ValidateScript({ Test-Path $_ -PathType Leaf -Include *.xml })]	
	[alias("PathNames")]
	[string[]]$HostObjects,

	[parameter(Mandatory=$False,
		HelpMessage='Your DATA directory')]
	[ValidateScript({ 
		# Test if path is container (OPDATA folder) 
		Test-Path -PathType container -Path $_ })]
	[string]$DATADIR="$pwd\DATADIR",
	
	[Parameter(Mandatory=$False)]
	[String]$OutFile="GroupedObject"
)
		
	BEGIN {
        
        $ErrorActionPreference = "Stop"

		$version = 0.7 # version needs to match the survey & hostobject version
		$SurveyFileName = "HostSurvey.xml"
		$HostObjectType = 'psHunt_HostObject'
		$datestamp = get-date -format "yyyyMMdd"
		$Hashtype = "SHA1"
		$NullHash = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
		
		$Format = @(
			"MD5"
			"SHA1"
			"SHA256"
			"Status"
			"DateAdded"
			"Notes"
		)

        if ( -NOT (Test-Path $DATADIR)) {
            $null = mkdir $DATADIR
        }
		
		# Creating BaseObject arrays
		$ProcessList = @()	
		$ModuleList = @()
		$DriverList = @()
		$AutorunList = @()
		$MemoryInjectList = @()
		$AccountList = @()
		$Connections = @()
		$InstalledPrograms = @()
		$OSHashList = @{}
		$ScanMetaData = @()
		$HostList = @()

		# Build GroupedObject
		$n = 0
		$nh = $HostObjects.count

	}
	PROCESS {
		Foreach ($Path in $HostObjects) {
			# Import host Objects
			$n += 1
			Write-Verbose "($n of $nh): Parsing $Path into GroupedObject"	
			Write-Progress -Activity "Grouping HostObjects" -percentcomplete "-1" -status "Processing HostObject $n of $nh"
			try { 
                $HostObject = Import-Clixml $Path
	        } catch {
                Write-Error "Error: Could not import HostObject: $Path"
                continue
            }		
			# Sanity Checks
			if ($HostObject.Version -ne $version) {
				Write-Error "$_ (Version $HostObject.Version) is not compatible with this function (should be version $version). Skipping HostObject."
				continue 
			}
			if ($HostObject.ObjectType -ne $HostObjectType) { 
				Write-Error "$_ is not compatible with this Analyzer (should be a $HostObjectType). Skipping."
				continue 			
			}
			if (!$HostObject.Processed) { 
				Write-Warning "$_ has not been processed. Processing now."
                Update-HuntObject $Path -Reprocess
                $HostObject = Import-Clixml $Path
			}
			
			# HostList
            if ($HostList -notcontains $HostObject.HostName) {
                $HostList += $HostObject.HostName
            }
			
			# Processes
            Write-Verbose "Normalizing ProcessList from $($HostObject.HostName)"
			Foreach ($item in $HostObject.ProcessList) {
				$hash = $item.SHA1
				if (($hash -eq $null) -OR ($hash -eq "") -OR ($hash -eq $NullHash) ) {
					continue
				}
				if ($ProcessList.SHA1 -contains $hash) {
					$ProcessList | where { $_.SHA1 -eq $hash} | % {
						Write-Verbose "$($_.Name) ($Hash) already exists - adding to occurances" 
                        $_.Occurances +=1 
                        if ($_.Hosts -notcontains $HostObject.Hostname) { 
                            $_.Hosts += $HostObject.HostName 
                        }
						continue
					}
				} else {
					Write-Verbose "Adding $Hash from $_ to Normalized ProcessList"
					$item | Add-Member -type NoteProperty -name Hosts -value @($HostObject.HostName) -Force
					$item | Add-Member -type NoteProperty -name Occurances -value 1 -Force
					$ProcessList += $item					
				}
			}
			
			#Modules
			Foreach ($item in $HostObject.ModuleList) {
				$hash = $item.SHA1
				if (($hash -eq $null) -OR ($hash -eq "") -OR ($hash -eq $NullHash) ) {
					continue
				}
				
				if ($ModuleList.SHA1 -contains $hash) {
					$ModuleList | where { $_.SHA1 -eq $hash} | % {
						$_.Occurances += 1 
                        if ($_.Hosts -notcontains $HostObject.Hostname) { 
                            $_.Hosts += $HostObject.HostName 
                        }
						continue
					}
				} else {
					$item | Add-Member -type NoteProperty -name Hosts -value @($HostObject.HostName) -Force
					$item | Add-Member -type NoteProperty -name Occurances -value 1 -Force
					$ModuleList += $item					
				}
			}
			
            # BROKE
			#Drivers
			Foreach ($item in $HostObject.DriverList) {
				$hash = $item.SHA1
				if (($hash -eq $null) -OR ($hash -eq "") -OR ($hash -eq $NullHash) ) {
					continue
				}
				
				if ($DriverList.SHA1 -contains $hash) {
					$DriverList | where { $_.SHA1 -eq $hash} | % {
						$_.Occurances +=1 
                        if ($_.Hosts -notcontains $HostObject.Hostname) { 
                            $_.Hosts += $HostObject.HostName 
                        }
						continue
					}
				} else {
					$item | Add-Member -type NoteProperty -name Hosts -value @($HostObject.HostName) -Force
					$item | Add-Member -type NoteProperty -name Occurances -value 1 -Force
					$DriverList += $item					
				}
			}

			#Autoruns
			Foreach ($item in $HostObject.Autoruns) {
				$hash = $item.SHA1
				if (($hash -eq $null) -OR ($hash -eq "") -OR ($hash -eq $NullHash) ) {
					continue
				}
				
				if ($AutorunList.SHA1 -contains $hash) {
					$AutorunList | where { $_.SHA1 -eq $hash} | % {
						$_.Occurances +=1 
                        if ($_.Hosts -notcontains $HostObject.Hostname) { 
                            $_.Hosts += $HostObject.HostName 
                        }
						continue
					}
				} else {
					$item | Add-Member -type NoteProperty -name Hosts -value @($HostObject.HostName) -Force
					$item | Add-Member -type NoteProperty -name Occurances -value 1 -Force
					$AutorunList += $item					
				}
			}

			#InstalledApps
			Foreach ($item in $HostObject.InstalledApps) {
				$App = $item.DisplayName
				if (($App -eq $null) -OR ($App -eq "")) {
					continue
				}
				if ($InstalledPrograms.Name -contains $App) {
					$InstalledPrograms | where { $_ -eq $App} | % {
						$_.Occurances +=1
						continue
					}
				} else {
					$newApp = New-Object PSObject -Property @{
						Name			= $App
                        Publisher       = $item.Publisher
                        Version         = $item.DisplayVersion
						Occurances		= 1
					}
					$InstalledPrograms += $newApp				
				}
			}
			
			# Memory Injects
			$HostObject.InjectedModules | where { $_.PE -eq $true } | % {
				$_ | Add-Member -type NoteProperty -name HostName -value $HostObject.HostName -Force
				$MemoryInjects += $_
			}
			
			$HostObject.NetStat | where {($_.Protocol -eq 'TCP') -AND ($_.State -eq "ESTABLISHED") -AND ( $_.Src_Address -ne $_.Dst_Address ) } | % {
				$_ | Add-Member -type NoteProperty -name HostName -value $HostObject.HostName -Force
				$Connections += $_
			}
			
		
			# Add unique account logins
			foreach ($account in $HostObject.Accounts.LoginHistory) { 
				if (($account.Name -ne "") -AND ($account.Name -notmatch "NT AUTHORITY") -AND ($account.Privileges -match "Administrator") ) {
                    if ($AccountList.UserSID -contains $account.UserSID) {
                        
                        $AccountList | where { $_.UserSID -eq $account.UserSID } | % {
                            if ($_.Hosts -notcontains $HostObject.Hostname) { 
                                $_.Hosts += $HostObject.HostName
                                $_.Occurances += 1
                            }
						}
                    } else {
                        $newAccount = New-Object PSObject -Property @{
						    User			= $account.Name
                            UserSID         = $account.UserSID
						    Occurances		= 1
                            Hosts           = @($HostObject.HostName)
                        }
                        $AccountList += $newAccount
                    }

				}
			}
			
			# Add OS Information
			try {

                if ($OSHashList -notcontains $HostObject.HostInfo.OS) {
                    $OSHashList.Add($HostObject.HostInfo.OS, 1)
                } else {
                    $OSHashList[$HostObject.HostInfo.OS] += 1
                }
			} catch {
			    Write-Debug "Oh shiza OSHASHLIST"
			}

			# Add Scan time stats
			$ScanMetaData += @{
				Hostname 	= $HostObject.HostName
				RunTime 	= $HostObject.RunTime
				}
		}
	}	

	END {
        
		# Build GroupedObject 
		$GroupedObject = New-Object PSObject -Property @{
			Opfolder			= $DATADIR
			Date				= (Get-Date)
			Hosts				= $HostList
			OSStats				= $OSHashList
			ProcessList			= $ProcessList
			ModuleList			= $ModuleList
			DriverList			= $DriverList
			Connections			= $Connections
			InstalledPrograms	= $InstalledPrograms
			Accounts			= $AccountList
			AutorunList			= $AutorunList
			MemoryInjects		= $MemoryInjects
			ScanMetaData		= $ScanMetaData
		}
		# Export GroupedObject
        [String]$ExportFile = "$DATADIR\$OutFile-$datestamp.xml"
		$GroupedObject | Export-CLIXML $ExportFile -encoding 'UTF8' -Force
		Write-Progress -Activity "Grouping HostObjects" -percentcomplete "-1" -status "$n HostObjects grouped" -Completed
		Write-Verbose "$n HostObjects grouped in $timetaken seconds and exported to $ExportFile"
		return $GroupedObject
	}
}

#endregion

#region Internal  Helper Functions

#endregion


# Test

#gci C:\Users\Chris\Documents\GitHub\PSHunt\Surveys -recurse -Include *.xml | Group-HuntObjects -debug -verbose

