Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\.."
$ErrorActionPreference = "Continue"
Remove-Module PSHunt
Import-Module PSHunt -Force -ErrorAction Stop
. $ModuleRoot\misc\misc.ps1

$VerbosePreference = "Continue"

# Test Scanner
Invoke-HuntScanner -ComputerName 127.0.0.1
