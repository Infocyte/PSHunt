function Test-TCPPort {
Param(	
	[Parameter(	Position=0, 
				Mandatory=$true)]
	[ValidateNotNullorEmpty()]
	[string]$Target,

	[Parameter(	Position=1,
				Mandatory=$true)]			
	[int]$Port=445

)

	try{
		$tcp=new-object System.Net.Sockets.TcpClient
		$tcp.connect($Target,$Port)
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
		[string]$Target,

		[Parameter(	Position=1,
					Mandatory=$true)]		
		[int[]]$Ports=@(445)
		)
	BEGIN {
	
		$ScriptBlock = {
			Param(	
				[string]$Target,		
				[int]$Port
			)

			try {
				$tcp=new-object System.Net.Sockets.TcpClient
				$tcp.connect($Target,$Port)
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
			Target = $Target
		}
	}
	PROCESS {
		foreach ($port in $Ports) {
			$portname = "TCP$port"
			Write-Verbose $Portname
			
			# Run each port in a parallel background job.
			$Jobs += Start-Job -Name $Portname -scriptblock $ScriptBlock -ArgumentList $Target,$port
		}
	}
	END {
		# Wait for jobs
		if ($PSBoundParameters['Debug']) { $jobs }	
		Write-Debug "Waiting for $($Jobs.count) tests to complete"
		$Jobs | Wait-Job -Timeout 5 | where {$_.State -eq "Completed"} | foreach {
			$JobResults = Receive-Job $_
			Write-Verbose "Received Job Result $JobResults for $_.name"
			$TestResults | Add-Member -type NoteProperty -name $_.name -value $JobResults
		}
	
		# Stop and remove all jobs  
		$null = $Jobs | stop-job
		$null = $Jobs | remove-job
		
		$TestResults
	}
}

function Get-RemoteArchitecture {
	Param(	
		[Parameter(	Position=0, 
					Mandatory=$true)]
		[string]$Target,
		
		[Parameter(	Mandatory=$false)]
		[System.Management.Automation.PSCredential]
		$Credential,
		
		[switch]$WMI
	)
	
	<#	
	# Determine local Archiecture
	if ($target -eq "localhost") {
		switch ([intptr]::size)
			{
				4 {	$Architecture = "32-bit"} 
				8 {	$Architecture = "64-bit"}
			}	
		return $Architecture
	}
	#>

	# Test Remote Architecture
	if ($WMI) {
		Write-Verbose "Testing Remote architecture using WMI"
		# Use WMI Query (Port 135/Dynamic)
		$ArchQuery = (Get-WMIObject -Computer $Target -Class Win32_OperatingSystem -property OSArchitecture -Credential $Credential).OSArchitecture
		

	} else {
		Write-Verbose "Testing Remote architecture using Reg Query"
		# Use Registry Query (Port 445/139)
		$Hive = [Microsoft.Win32.RegistryHive]"LocalMachine"
		$KeyName = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
		$KeyValue = 'PROCESSOR_ARCHITECTURE'
		
		# Open Key
		$ArchQuery = Get-RemoteRegistryValue $Target $Hive $KeyName $KeyValue
	}
	return $ArchQuery
		
}

# TODO: Update to accept credentials on the registry guy
function Get-RemotePowershellVersion {
	Param(
		[string]$Target
	)
	$Hive = [Microsoft.Win32.RegistryHive]"LocalMachine"
	$KeyName = 'SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine'
	$KeyValue = 'PowerShellVersion'

	# Open Key
	$Value = Get-RemoteRegistryValue $Target $Hive $KeyName $KeyValue
	return $Value
}

function Get-RemoteOperatingSystem {
	Param(	
		[Parameter(	Position=0, 
					Mandatory=$true)]
		[string]$Target,
		
		[Parameter(	Mandatory=$false)]
		[System.Management.Automation.PSCredential]
		$Credential
	)
	
	try {
		$OS = Get-wmiobject -Computer $Target -Class Win32_OperatingSystem -Property Caption,Version,OSArchitecture -Credential $credential -ea stop | Select Caption, Version, OSArchitecture
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
