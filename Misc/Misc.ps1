function Convert-BinaryToString {
    [CmdletBinding()]
    param ( [Parameter(Position=0, Mandatory=$True)]
			[ValidateNotNullOrEmpty()]
			[string] 
			$FilePath
    )
	# $Content = Get-Content -Path $FilePath -Encoding Byte
	# $Base64 = [System.Convert]::ToBase64String($Content)
	# $Base64 | Out-File $FilePath.txt
	# http://trevorsullivan.net/2012/07/24/powershell-embed-binary-data-in-your-script/
	
    try {
        $ByteArray = [System.IO.File]::ReadAllBytes($FilePath);
    } catch {
        throw "Failed to read file. Please ensure that you have permission to the file, and that the file path is correct.";
    }

    if ($ByteArray) {
        $Base64String = [System.Convert]::ToBase64String($ByteArray);
    } else {
        throw '$ByteArray is $null.';
    }

    Write-Output -InputObject $Base64String;
}

function Convert-StringToBinary {
    [CmdletBinding()]
    param (	[Parameter(Position=0, Mandatory=$True)]
			[ValidateNotNullOrEmpty()]
			[string] $InputString,
			
			[ValidateNotNullOrEmpty()]
			[string] $FilePath = ('{0}\{1}' -f $env:TEMP, [System.Guid]::NewGuid().ToString())
    )
	# $TargetFile = Convert-StringToBinary -InputString $NewExe -FilePath C:\temp\new.exe;
	# Start-Process -FilePath $TargetFile.FullName;
	# http://trevorsullivan.net/2012/07/24/powershell-embed-binary-data-in-your-script/
	
    try {
        if ($InputString.Length -ge 1) {
            $ByteArray = [System.Convert]::FromBase64String($InputString);
            [System.IO.File]::WriteAllBytes($FilePath, $ByteArray);
        }
    } catch {
        throw ('Failed to create file from Base64 string: {0}' -f $FilePath);
    }

    Write-Output -InputObject (Get-Item -Path $FilePath);
}

function Invoke-DownloadFile {
# Need this in Powershell V2, otherwise us Invoke-WebRequest (aka wget)
# Return true if file downloaded, otherwise false/null
	Param(
		[Parameter(Position=0, Mandatory=$True)]
		[String]$Url,
		[Parameter(Position=1, Mandatory=$True)]
		[String]$Path
	)
	$wc = New-Object System.Net.WebClient
	
	# GetSystemWebProxy method reads the current user's Internet Explorer (IE) proxy settings. 
	$proxy = [System.Net.WebRequest]::GetSystemWebProxy()
	# Check if there is a proxy.  Explicitly Authenticated proxies are not yet supported.
	
	$wc.Proxy = $proxy
	$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
	# $proxyAddr = (get-itemproperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyServer
	# $wc.proxy.Address = $proxyAddr
	
	try {
		$wc.DownloadFile($Url,$Path)
		return $true
	} 
	catch {
		Write-Warning "Could not download file from $Url -> $Path"
		return $false
	} 
	finally {
		$wc.Dispose()
	}
}

function Merge-HashTable($htold, $htnew) {
	$keys = $htold.getenumerator() | foreach-object {$_.key}
	$keys | foreach-object {
		$key = $_
		if ($htnew.containskey($key))
		{
			$htold.remove($key)
		}
	}
	$htnew = $htold + $htnew
	return $htnew
}

