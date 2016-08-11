# Read in all ps1 files expect those in the Lib and Survey folder
Get-ChildItem $PSScriptRoot |
    ? {$_.PSIsContainer -and ($_.Name -ne 'Lib') -and ($_.Name -ne 'Surveys') -and ($_.Name -ne 'ReputationData') -and ($_.Name -ne 'Misc')} |
    % {Get-ChildItem "$($_.FullName)\*" -Include '*.ps1'} |
    % {. $_.FullName}