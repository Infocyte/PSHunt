<#
.SYNOPSIS 
	 
	LogSurvey.ps1 is used to collect all logs from a live windows host. 

	Author: Chris Gerritz (Github @singlethreaded) (Twitter @gerritzc)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None	
		
#>
Param(
		[switch]$UseTime,
		[datetime]$StartTime,
		[datetime]$EndTime,	
		[string]$ScriptPath="C:\window\temp",		
		[string]$OutFileName="LogResults.xml"
	)

# =======Variables:

	$ErrorActionPreference  = "Stop"
	# $ErrorActionPreference  = "ContinueSilently"	

	# Set Time window for eventlogs, firewall logs, etc.
	#$StartTime 	= (get-date -year 2013 -month 05 -day 31 -Hour 12 -Minute 0 -Second 32)
	#$EndTime 	= (get-date -year 2013 -month 05 -day 31 -Hour 23 -Minute 0 -Second 32)
	#$UseTime 	= $false
	
function Get-USBHistory {
	# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR
	# Windows XP: $env:windir\setupapi.log
	# Win7: $env:windir\INF\setupapi.dev.log and env:windir\INF\setupapi.app.log.

	#find all of the devices that have been plugged in (Vender &: Product info) (Unique Ids)
	#$DeviceInfo = gci -ea 0 -recurse "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" | where { $_.PSPath -match ".*Disk&Ven[^\\]*$" }  | select PSChildName
	#$UniqueIds = gci -ea 0 -recurse "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" | where { $_.PSParentPath -match ".*Disk&Ven[^\\]*$" }  | select PSChildName
	
	$setupapilog = gc -ea 0 $env:windir\INF\setupapi.dev.log | Select-String "Device Install" -Context 10 | where { $_ -match "USB" }
	$setupapilog += gc -ea 0 $env:windir\INF\setupapi.app.log | Select-String -context 3 "USB" | where { $_ -match "USB" }
	$USBSTOR = gci -ea 0 -recurse "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" | where { $_.PSParentPath -match ".*Disk&Ven[^\\]*$" } | Select Name
	$USB = gci -ea 0 -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USB" | foreach { gci $_.pspath | foreach {Get-ItemProperty $_.pspath } } | Select DeviceDesc

	$USBHistory = new-Object PSObject -Property @{
		setupapilog		= $setupapilog
		USBSTOR			= $USBSTOR
		USB				= $USB
	}
	return $USBHistory
}

function Get-IEHistory {            
	# Internet Explorer History
	# Location: C:\Users\<user name>\AppData\Local\Microsoft\Windows\History
		
	# IE Typed URLs
	# Location: HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\TypedUrls
		
	# Internet Explorer Temp Folder (IE Cache)
	# Location: C:\Users\<user name>\AppData\Local\Microsoft\Windows\Temporary Internet Files

	# IE Cookies
	# Location: C:\Users\<user name>\AppData\Roaming\Microsoft\Windows\Cookies	
	
	$Cookies = gc -ea 0 -Force "C:\Users\*\AppData\Roaming\Microsoft\Windows\Cookies\*" | Select-String -SimpleMatch "/" | Select Line
	$TypedURLs = get-itemproperty -Path "HKCU:\Software\Microsoft\Internet Explorer\TypedUrls"
	
	
	$shell = New-Object -ComObject Shell.Application            
	$hist = $shell.NameSpace(34)            
	$folder = $hist.Self            
	$Visits = @()
	
	$hist.Items() | foreach {	
		$_.GetFolder.Items() | foreach {            
			$site = $_
			if ($site.IsFolder) {            
				$pageFolder  = $site.GetFolder            
				$pageFolder.Items() | foreach {           
				    $Visits += New-Object -TypeName PSObject -Property @{            
						Site = $($site.Name)            
						URL = $($pageFolder.GetDetailsOf($_,0))            
						Date = $( $pageFolder.GetDetailsOf($_,2))    
					}
				}  #End Foreach
			} #Endif            
		}  #End Foreach
	} #End Foreach
	
	$IEHistory = New-Object -TypeName PSObject -Property @{
		Visits 		= $Visits
		TypedURLs 	= $TypedURLs
		Cookies 	= $Cookies
	}
	return $IEHistory
} # End Get-IEHistory

function Get-EventLogs ([bool]$time=$false, [datetime]$start=$null,[datetime]$end=$null) {
#	-Source <string>
#	-Message <string>
#	 -Entrytype Information,Error,Warning,FailureAudit,SuccessAudit

	# Surveying Event Logs
#	wevtutil qe application /c:50 /rd:true /f:text
#	wevtutil qe security /c:100 /rd:true /f:text
#	wevtutil qe system /c:50 /rd:true /f:text

#Security EventIDs:
# 4776	The domain controller attempted to validate the credentials for an account.
# 4777	The domain controller failed to validate the credentials for an account.
# 4741	A computer account was created.
# 4742	A computer account was changed.
# 4720	A user account was created.
# 4738	A user account was changed.
# 4740	A user account was locked out.
# 4624	 An account was successfully logged on.
# 4625	 An account failed to log on.
# 4723	An attempt was made to change an account's password.
# 4724	An attempt was made to reset an account's password.
# 5712	 A Remote Procedure Call (RPC) was attempted.
# 4688	A new process has been created.
# 4739	Domain Policy was changed.
# 4782	 The password hash an account was accessed.
# 4649	A replay attack was detected.
# 5140	 A network share object was accessed
# 4698	A scheduled task was created.
# 4699	A scheduled task was deleted.
# 4702	A scheduled task was updated.
# 4657	A registry value was modified.
# 4946	 A change has been made to Windows Firewall exception list. A rule was added.
# 4947	 A change has been made to Windows Firewall exception list. A rule was modified.
# 4948	 A change has been made to Windows Firewall exception list. A rule was deleted.
# 4949	 Windows Firewall settings were restored to the default values.
# 4950	 A Windows Firewall setting has changed.
# 4672	Special privileges assigned to new logon.
# 4673	A privileged service was called.
# 5024	The Windows Firewall Service has started successfully.
# 5025	The Windows Firewall Service has been stopped.
# 4608	Windows is starting up.
# 4697	A service was installed in the system.
# LogName='System';
# StartTime=$StartTime
# Event ID 552
# Event ID 20000
# Event ID 4001

	$EventID=4625,4720,4738,4740,4723,4724,5712,4782,4649,4698,4699,4702,4657,4946,4947,4948,4950,4697,5025,5024,4608,552,20000,4001

#	$StartTime = (get-date -year 2013 -month 05 -day 31 -Hour 12 -Minute 0 -Second 32)
#	$StopTime = (get-date -year 2013 -month 05 -day 31 -Hour 23 -Minute 0 -Second 32)
#	(get-date -year 2013 -month 05 -day 31 -Hour 23 -Minute 0 -Second 32)
	
	if ($time -eq $true) {
		$EventLogs = Get-WinEvent -MaxEvents 1000 -FilterHashTable @{LogName='Security','System','Application'; StartTime=$start; EndTime=$end;} | Select-Object LogName,TimeCreated,LevelDisplayName,ProviderName,ID,Message
	} else {
		$EventLogs = Get-WinEvent -MaxEvents 50 -FilterHashTable @{LogName='Security','System','Application'; ID=$EventID} | Select-Object LogName,TimeCreated,LevelDisplayName,ProviderName,ID,Message
	}
	
	Return $EventLogs
} # End Get-EventLogs

function Get-OldestLog {
	$Oldest = @()
	$Oldest +=  Get-WinEvent -Oldest -MaxEvents 1 -FilterHashTable @{LogName='Application'} | Select LogName,Id,TimeCreated
	$Oldest +=  Get-WinEvent -Oldest -MaxEvents 1 -FilterHashTable @{LogName='Security'} | Select LogName,Id,TimeCreated
	$Oldest +=  Get-WinEvent -Oldest -MaxEvents 1 -FilterHashTable @{LogName='System'} | Select LogName,Id,TimeCreated
	return $Oldest
}
 
function Get-LogPaths {
	$date = (get-date).date.AddDays(-7)
	$LogPaths = gci -ea 0 -recurse -Include *.log,*.dat -Force C:\ | where-object {$_.lastwritetime -ge $date} | Select FullName, Length, CreationTime, LastWriteTime
	return $LogPaths
}

function Get-FirewallLogs { 
	#	Getting todays domain firewall hits '
	# domainfw.log, publicfw.log, privatefw.log, pfirewall.log, pfirewall.log 
	
	# firewall hits (windows defaults to not log)
	return Get-Content -ea 0 $env:windir\system32\LogFiles\Firewall\*.log | Select-String "ALLOW TCP" | out-string
}

function Get-AVLogs {
	
	
	return $AVLogs
}

function Get-Prefetch {
	# Survey Prefetch  
	return gci -ea 0 -force $env:windir\Prefetch | select creationtime,length,name
} # End Get-Prefetch
	
function Get-ExecutableList ([bool]$time=$false, [datetime]$start=$null,[datetime]$end=$null) {
	# Surveying File System for recently created executable files
	if ($time -eq $false) {
		$start = (get-date) - (new-timespan -days 10)
		$end = (get-date)
	} 
		
	$files += gci -ea 0 -recurse -include *.exe,*.dll,*.sys,*.bat,*.cmd,*.ps1,*.vbs,*.js -Force $env:TEMP | where-object {($_.creationtime -ge $start) -AND ($_.creationtime -lt $end)} | Select FullName, Length, CreationTime
	$files += gci -ea 0  -recurse -include *.exe,*.dll,*.sys,*.bat,*.cmd,*.ps1,*.vbs,*.js -Force $env:TMP | where-object {($_.creationtime -ge $start) -AND ($_.creationtime -lt $end)} | Select FullName, Length, CreationTime
	$files += gci -ea 0  -recurse -include *.exe,*.dll,*.sys,*.bat,*.cmd,*.ps1,*.vbs,*.js -Force $env:windir\System32 | where-object {($_.creationtime -ge $start) -AND ($_.creationtime -lt $end)} | Select FullName, Length, CreationTime
	$files += gci -ea 0  -recurse -include *.exe,*.dll,*.sys,*.bat,*.cmd,*.ps1,*.vbs,*.js -Force C:\Users\*\AppData | where-object {($_.creationtime -ge $start) -AND ($_.creationtime -lt $end)} | Select FullName, Length, CreationTime	
	#	$dir = Get-ChildItem * -recurse -Force -include *.exe,*.dll,*.sys,*.bat,*.ps1 | Select-Object FullName, Attributes, CreationTime,LastAccessTime,LastWriteTime,Length

	return $files
} # End Get-FileList


##################     MAIN     ##################
# Variables:

$Start = $StartTime.ToShortDateString()
$End = $EndTime.ToShortDateString()

# Test Powershell versions
try {
	$PSVersion = $psversiontable.PSVersion
	$DotNetVersion = gci 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' | sort pschildname -des | select -fi 1 -exp pschildname
	
	# Windows PowerShell 2.0 needs to be installed on Windows Server 2008 and Windows Vista only. It is already installed on Windows Server 2008 R2 and Windows 7.
	# In Windows Vista SP2 and Windows Server 2008 SP2 the integrated version of the .NET Framework is version 3.0; 
	# in Windows 7 and Windows Server 2008 R2, the integrated version of the .NET Framework is version 3.5 SP1
} catch {
	Write-Host "Script not compatible with Powershell 1.0" > SurveyOut.txt
	return 0
}#End Try

# Gather logs and export individual files:
<#
	Get-USBHistory | Export-clixml $ScriptPath\out_USBHistory.xml -encoding "UTF8"
	Get-IEHistory | Export-clixml $ScriptPath\out_IEHistory.xml -encoding "UTF8"
	Get-EventLogs $UseTime $StartTime $EndTime | Export-clixml $ScriptPath\out_EventLogs.xml -encoding "UTF8"
	Get-OldestLog | Export-csv $ScriptPath\out_OldestLog.csv
	Get-LogPaths | Export-csv $ScriptPath\out_LogPaths.csv
	Get-FirewallLogs | Out-File $ScriptPath\out_FirewallLogs.txt -encoding "UTF8"
	Get-AVLogs | Out-File $ScriptPath\out_AVLogs.txt -encoding "UTF8"
	Get-Prefetch | Export-csv $ScriptPath\out_Prefetch.csv
	Get-ExecutableList $UseTime $StartTime $EndTime | Export-csv $ScriptPath\out_ExecutableList.csv
#>

# Gather logs and export single object:
$LogObject = New-Object PSObject -Property @{
	Firewall			= Get-FirewallLogs
	Events				= Get-EventLogs $UseTime $StartTime $EndTime 
	Oldest				= Get-OldestLog 
	Prefetch			= Get-Prefetch
	USBHistory			= Get-USBHistory
	IEHistory			= Get-IEHistory
	AV					= Get-AVLogs
	Executables 		= Get-ExecutableList $UseTime $StartTime $EndTime
	LogPaths			= Get-LogPaths
} 


$LogObject | Export-clixml $ScriptPath\$OutFileName -encoding "UTF8"
<#
# Compress XML
# &"$ScriptPath\kzip.exe" /q /y /s3 $SurveyOut".zip" $ScriptPath\$SurveyOut
if (Test-Path $ScriptPath\7za.exe) {
	&"$ScriptPath\7za.exe" a -y $ScriptPath\HistoryObj.7z $ScriptPath\HistoryObj.xml
	&"$ScriptPath\7za.exe" a -y $ScriptPath\out_History.7z $ScriptPath\out_*
}
#>