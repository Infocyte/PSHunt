Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\.."
$ErrorActionPreference = "Continue"
Remove-Module PSHunt
Import-Module PSHunt -Force -ErrorAction Stop
. $ModuleRoot\misc\misc.ps1

$VerbosePreference = "Continue"

#Test SurveyDeployment
Write-Host "Testing Start-RemoteProcess with WMI"
Start-RemoteProcess -ComputerName 127.0.0.1 -Command "C:\windows\system32\calc.exe" -ExecutionType WMI
Write-Host "Testing Start-RemoteProcess with PSExec"
Start-RemoteProcess -ComputerName 127.0.0.1 -Command "C:\windows\system32\calc.exe" -ExecutionType PSExec
Write-Host "Testing Start-RemoteProcess with Schtasks"
Start-RemoteProcess -ComputerName 127.0.0.1 -Command "C:\windows\system32\calc.exe" -ExecutionType Schtasks
Write-Host "Testing Start-RemoteProcess with PSRemoting"
Start-RemoteProcess -ComputerName 127.0.0.1 -Command "C:\windows\system32\calc.exe" -ExecutionType PSRemoting
sleep 2
taskkill /FI "IMAGENAME eq calc*" /f

Invoke-HuntSurvey -ComputerName 127.0.0.1
$proc = Get-WmiObject -Class win32_process -Filter "name='powershell.exe'" | where { $_.CommandLine -match "ps1" }
if ($proc) {
	Write-Host "Survey is running on localhost"
	$proc
	sleep 30
} else {
	Write-Warning "Survey failed to run on localhost"
	return
}

$stillRunning = $true
Write-Host -ForegroundColor magenta "waiting on survey..."
while ($stillRunning) {
	$proc = Get-WmiObject -Class win32_process -Filter "name='powershell.exe'" | where { $_.CommandLine -match "ps1" }
	if ($proc) {
		Start-Sleep 5
		Write-Host -ForegroundColor magenta "." -NoNewline
	} else {
		$stillRunning = $false
	}
}

Get-HuntSurveyResults -ComputerName 127.0.0.1 


