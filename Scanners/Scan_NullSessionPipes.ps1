<#
.SYNOPSIS

	This scan uses WMI to check for exempted null session pipes.  
	Null Session Pipes key will sometimes be set on machines compromised by malware that use SMB / Named Pipe lateral C2.
	
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
	
	
	False Positives: Some SQL servers and legacy applications can use these as well
	
	Legacy NullSessionPipes:
	In operating systems earlier than Windows Server 2003 with Service Pack 1 (SP1), these named pipes were allowed anonymous access by default. 
	In later operating systems, these pipes must be explicitly added if needed.
	
	COMNAP
	COMNODE
	SQL\QUERY
	SPOOLSS
	LLSRPC
	Netlogon
	Lsarpc
	Samr
	browser

.PARAMETER ComputerName
	IP or DNS/NetBIOS name of remote system
	
.PARAMETER Credential
	Credential of remote system
	
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
$ScanSignature = "6dea3f9b-f39e-47ff-acff-e24dc89132d3"


# Get NullSessionPipes registry key
$KeyName = 'HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters'
$KeyValue1 = 'NullSessionPipes'
$KeyValue2 = 'NullSessionShares'
$KeyValue3 = 'RestrictNullSessAccess'

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
	$Result1 = $Reg.GetStringValue($Hive,$KeyNameSplit,$KeyValue).svalue
	$Result2 = $Reg.GetStringValue($Hive,$KeyNameSplit,$KeyValue2).svalue
	$Result3 = $Reg.GetStringValue($Hive,$KeyNameSplit,$KeyValue3).svalue
} catch {
	$msg = "Could not get string value of $KeyValue from $Target $HiveName" + ":\$KeyName via WMI"	
	Write-Warning $msg
	$ScanData[$Computer].Errors += $_.Exception
}
$ScanData[$Computer] | Add-Member -MemberType NoteProperty -Name $KeyValue1 -Value $Result1
$ScanData[$Computer] | Add-Member -MemberType NoteProperty -Name $KeyValue2 -Value $Result2
$ScanData[$Computer] | Add-Member -MemberType NoteProperty -Name $KeyValue2 -Value $Result3


#########################################
# End Scan Function
# DO NOT EDIT BELOW THIS COMMENT BLOCK 							
#########################################

if ($PSBoundParameters['Debug']) {
	# Return ScanData if Debuging script outside Invoke-HuntScanner
	return $ScanData[$computer]
}