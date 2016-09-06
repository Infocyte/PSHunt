# PSHunt Test
$ErrorActionPreference = "Continue"
$VerbosePreference = "Continue"
$Binary = "C:\windows\System32\calc.exe"
$VTAPIKey = ""

if (Test-Path $Binary) {
	Write-Host "Testing Binary manipulation with $Binary"
	Write-Host "Testing Get-Hashes"
	$Hashes = Get-Hashes $Binary -Type All
	$Hashes
	Write-Host "Testing Get-Entropy"
	$Entropy = Get-Entropy $Binary
	Write-Host "$Binary ($($Hashes.MD5)) has entropy of $Entropy"

	Write-Host "Testing Invoke-Sigcheck"	
	Invoke-Sigcheck $Binary
	
	Write-Host "Testing Convert-BinaryToString"
	$a = Convert-BinaryToString -FilePath C:\windows\System32\calc.exe
	Write-Host $a[0..20]
	Write-Host "Testing Convert-StringToBinary"
	Convert-StringToBinary -InputString $a -FilePath .\test.exe
	.\test.exe
	$Hashes2 = Get-Hashes .\test.exe -Type All
	$Hashes2
	$Entropy2 = Get-Entropy .\test.exe
	if ($Hashes.SHA1 -eq $Hashes2.SHA1) {
		Write-Host "Hashes Compare: Success"
	} else {
		Write-Error "Hashes Compare: Fail"
	}
	if ($Entropy -eq $Entropy2) {
		Write-Host "Entropy Compare: Success"
	} else {
		Write-Error "Entropy Compare: Fail"
	}
	Start-Sleep 2
	taskkill /IM calc.exe /F
	Write-Host "Testing Get-Strings"
	$Strings = Get-Strings -Path .\test.exe
	$Strings[0..20]
}

# Test Discovery
Parse-IPList 192.168.1.1/30
Test-TCPPort          
Test-TCPPorts      
Get-HuntTargets 
Invoke-HuntPortScan 


# Test Deployment
Get-HuntSurveyResults 
Invoke-HuntSurvey
Invoke-HuntScanner
Start-RemoteProcess

# Test Analysis
Initialize-HuntReputation

Write-Host "Testing Get-VTReport"
Get-VTReport -hash $Hashes.SHA1 -VTAPIKey $VTAPIKey
Write-Host "Testing Get-HuntVTStatus"
Get-HuntVTStatus -Hashes $Hashes.SHA1 -VTAPIKey $VTAPIKey

Write-Host "Testing Update-HuntObject"
Update-HuntObject

Write-Host "Testing Group-HuntObjects "
Group-HuntObjects        
