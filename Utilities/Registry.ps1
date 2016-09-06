# TODO: Update with another method that takes Credentials - WMI is kind of aweful.
function Get-RemoteRegistryValue {
<#
		$HKCR = 2147483648 #HKEY_CLASSES_ROOT
		$HKEY_CLASSES_ROOT = 2147483648 #HKEY_CLASSES_ROOT
		$HKCU = 2147483649 #HKEY_CURRENT_USER
		$HKEY_CURRENT_USER = 2147483649 #HKEY_CURRENT_USER
		$HKLM = 2147483650 #HKEY_LOCAL_MACHINE
		$HKEY_LOCAL_MACHINE = 2147483650 #HKEY_LOCAL_MACHINE
		$HKUS = 2147483651 #HKEY_USERS
		$HKEY_USERS = 2147483651 #HKEY_USERS
		$HKCC = 2147483653 #HKEY_CURRENT_CONFIG
		$HKEY_CURRENT_CONFIG = 2147483653 #HKEY_CURRENT_CONFIG
		
		$KeyName = 'SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine'
		$KeyValue = 'PowerShellVersion'
#>
Param(
	[Parameter(	Position=0, 
				Mandatory=$true)]
	[string]$ComputerName,
	
	[Parameter(	Position=1, 
				Mandatory=$true)]
	[string]$HiveName, 
	
	[Parameter(	Position=2, 
				Mandatory=$true)]
	[string]$KeyName, 
	
	[Parameter(	Position=3, 
				Mandatory=$false)]
	[string]$KeyValue,
	
	[System.Management.Automation.PSCredential]
	$Credential
)

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

	 	$Reg = Get-Wmiobject -list "StdRegProv" -namespace root\default -Computername $ComputerName -Credential $Credential
		
	} catch {
		Write-Warning "Could not connect to $Target Registry Provider"
		return "ERROR: Could not connect to $Target Registry Provider"
	}
	
	try {
		$Value = $Reg.GetStringValue($HiveName,$KeyName,$KeyValue).svalue
		Write-Output $Value
	} catch {
		Write-Warning "Could not get string value of $KeyValue from $Target $HiveName :\$KeyName"
		return "ERROR: Could not get string value of $KeyValue from $Target $HiveName :\$KeyName"		
	}
	
	<#
	# $reg = [wmiclass]'\\$Target\root\default:StdRegprov'
	$key = "SOFTWARE\Microsoft\Windows\CurrentVersion"
	$value = "CommonFilesDir"
	$reg.GetStringValue($HKLM, $key, $value)  ## REG_SZ

	$value = "ProgramFilesPath"
	$reg.GetExpandedStringValue($HKLM, $key, $value)  ## REG_EXPAND_SZ

	$key = "SOFTWARE\Microsoft\Windows\CurrentVersion\BITS"
	$value = "LogFileMinMemory"
	$reg.GetDwordValue($HKLM, $key, $value)  ## REG_DWORD
	#>
	
	<#
	#$Hive = [Microsoft.Win32.RegistryHive]'LocalMachine';
	$Hive = [Microsoft.Win32.RegistryHive]$HiveName
	$regKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($Hive,$Target);
	$ref = $regKey.OpenSubKey($KeyName);
	$Value = $ref.GetValue($KeyValue)
	return $Value
	#>
	
}


function Invoke-RegQuery {
	Param(
		[Parameter(	Position=0, 
					Mandatory=$true)]
		[string]$Target,
		
		[Parameter(	Position=1, 
					Mandatory=$true)]
		[string]$KeyName, 
		
		[Parameter(	Position=2, 
					Mandatory=$false)]
		[string]$KeyValue,
		
		[System.Management.Automation.PSCredential]
		$Credential
	)

	Write-Verbose "Performing remote registry query"
	try {
	
		$RegQuery = reg query \\$Target\$KeyName /v $KeyValue 2>$null | Select-String "$KeyValue"
		
		if ($?) { 
			$parsedquery = $RegQuery.tostring() #.split()[12]
			return $parsedquery 
		} else { 
			throw $error[0].Exception 
		}
	} catch {
		return "ERROR[Invoke-RegQuery]: Query Failed"
	}
	
}