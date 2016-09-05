<#
.SYNOPSIS

	This scan uses WMI to check the value of a specific registry key as defined by two arguments:
	$KeyName = "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters"
	$KeyValue = "NullSessionPipes"
	$ScanArgs = @($KeyName, $KeyValue)
	
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
	PS > .\Scan_OSInfo.ps1 -Computer cic.galactica.int -Credential $Cred -verbose -debug

.PARAMETER ComputerName
	IP or DNS/NetBIOS name of remote system
	
.PARAMETER Credential
	Credential of remote system
	
.PARAMETER KeyName
	The registry key you wish to query
	
.PARAMETER KeyValue
	The KeyValue Name you wish to query

.EXAMPLE 

	PS C:\> $KeyName = 'HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters',
	PS C:\> $KeyValue = 'NullSessionPipes'
	PS C:\> $ScanArgs = @($KeyName, $KeyValue)
	
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
# DO NOT EDIT ABOVE THIS COMMENT BLOCK
#########################################

# Uniquely define a new GUID for every defined scan
$ScanSignature = "a9d92e6e-eff5-4fbd-82b1-03498582741b"

# Arguments
$KeyName = [String]$args[0]
$KeyValue = [String]$args[1]
	
# (No need to change the stuff below this, the two params above are all that are needed)
$HiveName = $KeyName.Split(":")[0]
$KeyNameSplit = $KeyName.Split(":")[1].Substring(1)
Switch ($HiveName) {
	"HKCR" { $Hive = 2147483648 }
	"HKEY_CLASSES_ROOT" { $Hive = 2147483648 } 
	"HKCU" { $Hive  = 2147483649 }
	"HKEY_CURRENT_USER" { $Hive  = 2147483649 }
	"HKLM" { $Hive  = 2147483650 }
	"HKEY_LOCAL_MACHINE" { $Hive  = 2147483650 }
	"HKUS" { $Hive  = 2147483651 }
	"HKEY_USERS" { $Hive  = 2147483651 }
	"HKCC" { $Hive  = 2147483653 }
	"HKEY_CURRENT_CONFIG" { $Hive  = 2147483653 }
}
try {
	Write-Verbose "[$Computer] Getting PSVersion"
	$Reg = Get-Wmiobject -list "StdRegProv" -namespace root\default -Computername $Computer -Credential $Credential -ea stop
	$Result = $Reg.GetStringValue($Hive,$KeyNameSplit,$KeyValue).svalue
} catch {
	$msg = "Could not get string value of $KeyValue from $Target $HiveName" + ":\$KeyName via WMI"	
	Write-Warning $msg
	$PSVersion = $null
	$ScanData[$Computer].Errors += $_.Exception
}
$ScanData[$Computer] | Add-Member -MemberType NoteProperty -Name $KeyValue -Value $Result


#########################################
# End Scan Function 		
# DO NOT EDIT BELOW THIS COMMENT BLOCK 						
#########################################

if ($PSBoundParameters['Debug']) {
	# Return ScanData if Debuging script outside Invoke-HuntScanner
	return $ScanData[$computer]
}
