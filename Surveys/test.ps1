iex calc.exe
"Success" | Out-file C:\Users\infocyte\Desktop\Success.txt
Start-Sleep 3
taskkill /IM calc.exe /F
iex Notepad.exe
Start-Sleep 3
taskkill /IM notepad.exe /F
del C:\Users\infocyte\Desktop\Success.txt