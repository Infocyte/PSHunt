Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\.."
$ErrorActionPreference = "Continue"
Remove-Module PSHunt
Import-Module PSHunt -Force -ErrorAction Stop
. $ModuleRoot\misc\misc.ps1

$VerbosePreference = "Continue"

# Test Discovery
Write-Host "Testing Expand-IPList with 192.168.1.1/30"
Expand-IPList 192.168.1.12/29
$x = @("192.168.1.9", "192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14")
if ($a[3] -eq (Expand-IPList 192.168.1.12/29)[3]) {
	Write-Host "Expand-IPList: Success"
}else {
	Write-Warning "Expand-IPList: FAIL"
}

Write-Host "Testing Test-TCPPort against localhost port 445"
$port = Test-TCPPort -ComputerName 127.0.0.1 -Port 445
if ($port) { 
	Write-Host "Test-TCPPort: Success" 
} else { 
	Write-Warning "Test-TCPPort: Fail"
}
Write-Host "Testing mutli-port Test-TCPPorts against localhost ports 135,139,445"
Test-TCPPorts -ComputerName 127.0.0.1 -Ports 135,139,445
if ($port) { 
	Write-Host "Test-TCPPort: Success" 
} else { 
	Write-Warning "Test-TCPPort: Fail"
}

Write-Host "Testing Get-HuntTargets"
$Targets = Get-HuntTargets 127.0.0.1 -DiscoverOS 
$Targets
if ($port) { 
	Write-Host "Test-TCPPort: Success" 
} else { 
	Write-Warning "Test-TCPPort: Fail"
}
