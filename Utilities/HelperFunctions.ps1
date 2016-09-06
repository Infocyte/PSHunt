
function Write-Log {
	Param(	
		[string]$Target, 
		[String]$LogPath, 
		[string]$Msg, 
		[int]$n
	)
	$Time = get-date -format "yyyy-MM-dd hh:mm:ss:ms"
	if ($Msg -match "ERROR") {
		Write-Warning "($n): $Msg"	
	} else {
		Write-Verbose "($n): $Msg"	
	}
	"$Time, $Target, " + $Msg | Out-File -Encoding 'ASCII' -Append $LogPath
}
