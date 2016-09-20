Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\.."
$ErrorActionPreference = "Continue"
Remove-Module PSHunt
Import-Module PSHunt -Force -ErrorAction Stop
. $ModuleRoot\misc\misc.ps1

$VerbosePreference = "Continue"


#Test SurveyAnalysis
Initialize-HuntReputation

Write-Host "Testing Get-VTReport"
Get-VTReport -hash $Hashes.SHA1 -VTAPIKey $VTAPIKey
Write-Host "Testing Get-HuntVTStatus"
Get-HuntVTStatus -Hashes $Hashes.SHA1 -VTAPIKey $VTAPIKey

Write-Host "Testing Update-HuntObject"
Update-HuntObject

Write-Host "Testing Group-HuntObjects "
Group-HuntObjects    
