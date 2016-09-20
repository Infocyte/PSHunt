Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\.."
$ErrorActionPreference = "Continue"
Remove-Module PSHunt
Import-Module PSHunt -Force -ErrorAction Stop
. $ModuleRoot\misc\misc.ps1

$VerbosePreference = "Continue"

dir .\

#region Test FileAnalysis
$TestBinary = "C:\Windows\System32\calc.exe"
if (Test-Path $TestBinary) {
	Write-Host -ForegroundColor Gray "Testing File Analysis functions with $TestBinary"
} else {
	Write-Warning "Test Binary not available at $TestBinary"
	break
}
	
Write-Host -ForegroundColor Gray -ForgroundColor "Grey" "Testing Get-Hashes"
$Hashes = Get-Hashes -Path $TestBinary -Type All
$Hashes | ft -auto
Write-Host -ForegroundColor Gray "Testing Get-Entropy"
$Entropy = Get-Entropy -FilePath $TestBinary
Write-Host "$TestBinary ($($Hashes.MD5)) has entropy of $Entropy"

Write-Host -ForegroundColor Gray "Testing Invoke-Sigcheck"
Invoke-Sigcheck $TestBinary
sleep 1

Write-Host -ForegroundColor Gray "Testing Convert-BinaryToString"
$a = Convert-BinaryToString -FilePath C:\windows\System32\calc.exe
Write-Host $a[0..20]
Start-Sleep 1

Write-Host -ForegroundColor Gray "Testing Convert-StringToBinary"
Convert-StringToBinary -InputString $a -FilePath .\test.exe
sleep 1
if (Test-Path .\test.exe) {
	Write-Host "Convert-StringToBinary Test: SUCCESS"
	$TestPath = Resolve-Path .\test.exe
	$Hashes2 = Get-Hashes -Path $TestPath -Type All
	$Hashes2
	$Entropy2 = Get-Entropy -FilePath $TestPath
	if ($Hashes.SHA1 -eq $Hashes2.SHA1) {
		Write-Host "Converted file's hashes check: Success"
	} else {
		Write-Warning "Converted file's hashes check: Fail"
	}
	if ($Entropy -eq $Entropy2) {
		Write-Host "Converted file's entropy check: Success"
	} else {
		Write-Warning "Converted file's entropy check: Fail"
	}
} else {
	Write-Warning "Convert-StringToBinary Test: FAIL"
	$TestPath = $TestBinary
}
Start-Sleep 1

Write-Host -ForegroundColor Gray "Testing Get-Strings"
$Strings = Get-Strings -Path $TestPath
$Strings[0..20]
Start-Sleep 1
Remove-Item $TestPath
