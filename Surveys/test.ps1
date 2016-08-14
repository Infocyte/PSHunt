$ScriptPath = $MyInvocation.MyCommand.Path
iex calc.exe
"Success" | Out-file C:\Users\public\Desktop\Success.txt
Start-Sleep 3
taskkill /IM calc.exe /F
if (!($?)){ taskkill /IM calculator.exe /F } # For Win10... they renamed calc?
iex Notepad.exe
Start-Sleep 3
taskkill /IM notepad.exe /F
del C:\Users\public\Desktop\Success.txt
if (($ScriptPath) -AND ($ScriptDir -match "^C:\\Windows\\Temp*")) { 
	Remove-Item $ScriptPath
	#have to do this or it sometimes freezes
	[System.Diagnostics.Process]::GetCurrentProcess().Kill()
}