# Read in all ps1 files expect those in the Lib and Survey folder
Get-ChildItem $PSScriptRoot |
    ? {$_.PSIsContainer -and ($_.Name -notmatch "Lib|Surveys|Scanners|Test|ReputationData|Misc")} |
    % {Get-ChildItem "$($_.FullName)\*" -Filter '*.ps1'} |
    % {
		Import-Module $_.FullName
	}
Import-Module $PSScriptRoot\Lib\Posh-VirusTotal\Posh-VirusTotal.psm1
Import-Module $PSScriptRoot\Lib\PSReflect\PSReflect.psm1

