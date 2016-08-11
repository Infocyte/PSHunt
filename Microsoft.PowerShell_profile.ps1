$a = (Get-Host).UI.RawUI
$a.BackgroundColor = "black"
$a.ForegroundColor = "green"
$b = $a.BufferSize
$b.Width = 2000
$b.Height = 9000
$a.BufferSize = $b
$b = $a.WindowSize
$b.Width = 120
$b.Height = 32
$a.WindowSize = $b
$a.WindowTitle = "PSHunt - Powershell Threat Hunting Module"
#$PsDefaultParameterValues.add("Get-Help:ShowWindow",$True)  # <- this is cool, use it to make help display as a popup
#Clear-Host