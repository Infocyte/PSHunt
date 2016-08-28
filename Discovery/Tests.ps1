
function Get-RemoteArchitecture {
	Param(	
		[Parameter(	Position=0, 
					Mandatory=$true)]
		[string]$ComputerName,
		
		[Parameter(	Mandatory=$false)]
		[System.Management.Automation.PSCredential]
		$Credential,
		
		[switch]$WMI=$true
	)
	
	if ( ($ComputerName -match "localhost") -OR ($ComputerName -eq $Env:COMPUTERNAME) ) {
		# Determine local Archiecture
		switch ([intptr]::size)
			{
				4 {	$Architecture = "32-bit"} 
				8 {	$Architecture = "64-bit"}
			}	
		return $Architecture
	}

	# Test Remote Architecture
	if ($WMI) {
		Write-Verbose "Testing Remote architecture using WMI"
		# Use WMI Query (Port 135/Dynamic)
		$ArchQuery = (Get-WMIObject -Computer $ComputerName -Class Win32_OperatingSystem -property OSArchitecture -Credential $Credential).OSArchitecture

	} else {
		Write-Verbose "Testing Remote architecture using Reg Query"
		# Use Registry Query (Port 445/139)
		$Hive = [Microsoft.Win32.RegistryHive]"LocalMachine"
		$KeyName = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
		$KeyValue = 'PROCESSOR_ARCHITECTURE'
		
		# Open Key
		$ArchQuery = Get-RemoteRegistryValue $ComputerName $Hive $KeyName $KeyValue
	}
	return $ArchQuery
		
}

# TODO: Update to accept credentials on the registry guy
function Get-RemotePowershellVersion {
	Param(
		[string]$ComputerName
	)
	$Hive = [Microsoft.Win32.RegistryHive]"LocalMachine"
	$KeyName = 'SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine'
	$KeyValue = 'PowerShellVersion'

	# Open Key
	$Value = Get-RemoteRegistryValue $ComputerName $Hive $KeyName $KeyValue
	return $Value
}

function Get-RemoteOperatingSystem {
	Param(	
		[Parameter(	Position=0, 
					Mandatory=$true)]
		[string]$ComputerName,
		
		[Parameter(	Mandatory=$false)]
		[System.Management.Automation.PSCredential]
		$Credential
	)
	
	try {
		$OS = Get-wmiobject -Computer $ComputerName -Class Win32_OperatingSystem -Property Caption,Version,OSArchitecture -Credential $credential -ea stop | Select Caption, Version, OSArchitecture
	} catch {
		Write-Debug "$_"
		$OS = New-Object PSObject -Property @{
			Caption 		= "FAIL"
			OSArchitecture	= "FAIL"
			Version			= "FAIL"
		}
	}#End Try
	return $OS
}


