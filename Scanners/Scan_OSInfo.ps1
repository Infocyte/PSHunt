<#
.SYNOPSIS

	This scan uses WMI to get Operating System information and Powershell Version.
	
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
# DO NOT EDIT ABOVE THIS COMMENT BLOCK
#########################################

# Uniquely define a new GUID for every defined scan
$ScanSignature = "b183358c-2778-482e-9705-7e0effd44092"

# OS Info
try {
	Write-Verbose "[$Computer]: Getting OS Information from $computer via WMI with credentials $($Credential.Username)"
	$OS = Get-wmiobject -Class Win32_OperatingSystem -Property Caption,Version,OSArchitecture -Computer $Computer -Credential $Credential -ea stop | Select Caption, Version, OSArchitecture
} catch {
	Write-Warning "ERROR[$Computer]: Could not get OS Information via WMI."
	$ScanData[$Computer].Errors += $_.Exception
	$OS = New-Object PSObject -Property {
		Caption = $null
		OSArchitecture = $null
		Version = $null
	}
}
$ScanData[$Computer] | Add-Member -MemberType NoteProperty -Name 'OS' -Value $OS


# Get Powershell Version
$KeyName = 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine'
$KeyValue = 'PowerShellVersion'
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
	$PSVersion = $Reg.GetStringValue($Hive,$KeyNameSplit,$KeyValue).svalue
} catch {
	$msg = "Could not get string value of $KeyValue from $Target $HiveName" + ":\$KeyName via WMI"	
	Write-Warning $msg
	$PSVersion = $null
	$ScanData[$Computer].Errors += $_.Exception
}
$ScanData[$Computer] | Add-Member -MemberType NoteProperty -Name 'PSVersion' -Value $PSVersion

#########################################
# End Scan Function 			
# DO NOT EDIT BELOW THIS COMMENT BLOCK 					
#########################################

if ($PSBoundParameters['Debug']) {
	# Return ScanData if Debuging script outside Invoke-HuntScanner
	return $ScanData[$computer]
}