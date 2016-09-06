function Get-Strings
{
<#
.SYNOPSIS

Gets strings from a file.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

The Get-Strings cmdlet returns strings (Unicode and/or Ascii) from a file. This cmdlet is useful for dumping strings from binary file and was designed to replicate the functionality of strings.exe from Sysinternals.

.PARAMETER Path

Specifies the path to an item.

.PARAMETER Encoding

Specifies the file encoding. The default value returns both Unicode and Ascii.

.PARAMETER MinimumLength

Specifies the minimum length string to return. The default string length is 3.

.EXAMPLE

Get-Strings C:\Windows\System32\calc.exe

Description
-----------
Dump Unicode and Ascii strings of calc.exe.

.EXAMPLE

Get-ChildItem C:\Windows\System32\*.dll | Get-Strings -MinimumLength 12 -Encoding Ascii

Description
-----------
Dumps Ascii strings of at least length 12 of every dll located in C:\Windows\System32.
#>

    Param
    (
        [Parameter(Position = 1, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_ -PathType 'Leaf'})]
        [String[]]
        [Alias('PSPath')]
        $Path,

        [ValidateSet('Default','Ascii','Unicode')]
        [String]
        $Encoding = 'Default',

        [UInt32]
        $MinimumLength = 3
    )

    BEGIN
    {
        $FileContents = ''
    }
    PROCESS
    {
        foreach ($File in $Path)
        {
            if ($Encoding -eq 'Unicode' -or $Encoding -eq 'Default')
            {
                $UnicodeFileContents = Get-Content -Encoding 'Unicode' $File
                $UnicodeRegex = [Regex] "[\u0020-\u007E]{$MinimumLength,}"
                $Results += $UnicodeRegex.Matches($UnicodeFileContents)
            }
            
            if ($Encoding -eq 'Ascii' -or $Encoding -eq 'Default')
            {
                $AsciiFileContents = Get-Content -Encoding 'UTF7' $File
                $AsciiRegex = [Regex] "[\x20-\x7E]{$MinimumLength,}"
                $Results = $AsciiRegex.Matches($AsciiFileContents)
            }

            $Results | ForEach-Object { Write-Output $_.Value }
        }
    }
    END {}
}

function Get-Entropy
{
<#
.SYNOPSIS

Calculates the entropy of a file or byte array.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.PARAMETER ByteArray

Specifies the byte array containing the data from which entropy will be calculated.

.PARAMETER FilePath

Specifies the path to the input file from which entropy will be calculated.

.EXAMPLE

Get-Entropy -FilePath C:\Windows\System32\kernel32.dll

.EXAMPLE

ls C:\Windows\System32\*.dll | % { Get-Entropy -FilePath $_ }

.EXAMPLE

C:\PS>$RandArray = New-Object Byte[](10000)
C:\PS>foreach ($Offset in 0..9999) { $RandArray[$Offset] = [Byte] (Get-Random -Min 0 -Max 256) }
C:\PS>$RandArray | Get-Entropy

Description
-----------
Calculates the entropy of a large array containing random bytes.

.EXAMPLE

0..255 | Get-Entropy

Description
-----------
Calculates the entropy of 0-255. This should equal exactly 8.

.OUTPUTS

System.Double

Get-Entropy outputs a double representing the entropy of the byte array.
#>

    [CmdletBinding()] Param (
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $True, ParameterSetName = 'Bytes')]
        [ValidateNotNullOrEmpty()]
        [Byte[]]
        $ByteArray,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'File')]
        [ValidateNotNullOrEmpty()]
        [IO.FileInfo]
        $FilePath
    )

    BEGIN
    {
        $FrequencyTable = @{}
        $ByteArrayLength = 0
    }

    PROCESS
    {
        if ($PsCmdlet.ParameterSetName -eq 'File')
        {
            $ByteArray = [IO.File]::ReadAllBytes($FilePath.FullName)
        }

        foreach ($Byte in $ByteArray)
        {
            $FrequencyTable[$Byte]++
            $ByteArrayLength++
        }
    }

    END
    {
        $Entropy = 0.0

        foreach ($Byte in 0..255)
        {
            $ByteProbability = ([Double] $FrequencyTable[[Byte]$Byte]) / $ByteArrayLength
            if ($ByteProbability -gt 0)
            {
                $Entropy += -$ByteProbability * [Math]::Log($ByteProbability, 2)
            }
        }

        Write-Output $Entropy
    }
}

function Invoke-Sigcheck {
<#
.SYNOPSIS

Wrapper for SysInternals Sigcheck.

	Author: Chris Gerritz (Github @singlethreaded) (Twitter @gerritzc)
	License: Apache License 2.0
	Required Dependencies: None
	Optional Dependencies: None

.DESCRIPTION

Wrapper for SysInternals Sigcheck.  Executes SysInternals Sigcheck and parses output into a powershell object.

#>
	Param(
		[Parameter(Position=0, Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[string] $FilePath,
		
		[string] $SigcheckPath="C:\Windows\temp\sigcheck.exe",
		
		[switch] $GetHashes
	)
	
	# Hardcode Hash (TODO: impliment more better authentication mechanism, maybe a signature check for MS)
	if ((Get-WmiObject -class win32_operatingsystem -Property OSArchitecture).OSArchitecture -match "64") {	
		$SigcheckURL = "http://live.sysinternals.com/sigcheck64.exe"
		$SigcheckHash = "860CECD4BF4AFEAC0F6CCCA4BECFEBD0ABF06913197FC98AB2AE715F382F45BF"
	} else {
		$SigcheckURL = "http://live.sysinternals.com/sigcheck.exe"
		$SigcheckHash = "92A9500E9AF8F2FBE77FB63CAF67BD6CC4CC110FA475ADFD88AED789FB515E6A"
	}
	
	# Download Autoruns if not in the target directory & verify it's actually right sigcheck
	# $(get-AuthenticodeSignature myfile.exe).SignerCertificate.Subject <-- PS 3.0+
	if ( (Test-Path $SigcheckPath) -AND ((Get-Hashes $SigcheckPath).SHA256 -eq $SigcheckHash) ) {
	
	} else {
		$wc = New-Object System.Net.WebClient
		
		# Check if there is a proxy.  Explicitly Authenticated proxies are not yet supported.
		if (Get-Item "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\proxyserver" -ea 0) {
			$proxyAddr = (get-itemproperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyServer
			$proxy = new-object System.Net.WebProxy
			$proxy.Address = $proxyAddr
			$proxy.useDefaultCredentials = $true
			$wc.proxy = $proxy
		}
		try {
			$wc.DownloadFile($SigcheckURL,$SigcheckPath)
		} 
		catch {
			Write-Warning "Could not download sigcheck from Microsoft"
			return $null
		} 
		finally {
			$wc.Dispose()
		}
	}
	
<#
	Path            : c:\windows\temp\autorunsc.exe
	Verified        : Signed
	Date            : 12:43 PM 7/6/2016
	Publisher       : Microsoft Corporation
	Company         : Sysinternals - www.sysinternals.com
	Description     : Autostart program viewer
	Product         : Sysinternals autoruns
	Product Version : 13.61
	File Version    : 13.61
	Machine Type    : 64-bit
	Binary Version  : 13.61.0.0
	Original Name   : autoruns.exe
	Internal Name   : Sysinternals Autoruns
	Copyright       : Copyright (C) 2002-2016 Mark Russinovich
	Comments        : n/a
	Entropy         : 5.966
	MD5             : 3DB29814EA5A2091425200B58E25BA15
	SHA1            : E33A2A83324731F8F808B2B1E1F5D4A90A9B9C33
	PESHA1          : B4DC9B4C6C053ED5D41ADB85DCDC8C8651D478FC
	PESHA256        : 6C7E61FE0FBE73E959AA78A40810ACD1DB3B308D9466AA6A4ACD9B0356B55B5B
	SHA256          : D86C508440EB2938639006D0D021ADE7554ABB2D1CFAA88C1EE1EE324BF65EC7
	IMP             : FA51BDCED359B24C8FCE5C35F417A9AF
#>
	
	if ($GetHashes) {
		Write-Verbose "Verifying Digital Signatures via sigcheck.exe -accepteula -nobanner -c -h -a $FilePath"
		$Signature = (&"$SigcheckPath" -accepteula -nobanner -c -a -h $FilePath) | ConvertFrom-CSV | Select -ExcludeProperty PESHA1,PESHA256,IMP | where { 
			$_.Path -ne "No matching files were found." } 
		
	} else {
		Write-Verbose "Verifying Digital Signatures via sigcheck.exe -accepteula -nobanner -c -a $FilePath"
		$Signature = (&"$SigcheckPath" -accepteula -nobanner -c -a $FilePath) | ConvertFrom-CSV | Select -ExcludeProperty PESHA1,PESHA256,IMP | where {
			$_.Path -ne "No matching files were found." } 
		
	}

	return $Signature
}

function Get-Hashes {
<#
.SYNOPSIS 
	Returns a MD5, SHA1, and SHA256 hashes of a file. 
	Return is formated as uppercase HEX without byte group delimiters.
	
.NOTES
	Project: PSHunt
	Author: Chris Gerritz (Github @singlethreaded) (Twitter @gerritzc)
	License: Apache License 2.0
	Required Dependencies: 	None
	Optional Dependencies: 	None
	
.PARAMETER Path
	FilePath to be hashed.  Can be pipelined.

.PARAMETER Type
	Type of hashes to be used.  Defaults to 'all' which is MD5, SHA1, and SHA256
	
.EXAMPLE
	PS > Get-Hash C:\Windows\System32\cmd.exe
	
#>	
	Param(
	    [Parameter(
			Position=0,
			ValueFromPipeline = $true,
			ValueFromPipelineByPropertyName = $true
			)]
		[Alias("FullName")]
		[String]$Path,

		[Parameter(Position=1)]
        [ValidateSet('MD5','SHA1','SHA256','All')]
		[string[]]$Type = @('ALL')
	) 

	BEGIN {
		# Initialize Cryptoproviders
		if (-NOT $Global:CryptoProvider) {
			try { $MD5CryptoProvider = new-object -TypeName system.security.cryptography.MD5CryptoServiceProvider } catch { $MD5CryptoProvider = $null }
			try { $SHA1CryptoProvider = new-object -TypeName system.security.cryptography.SHA1CryptoServiceProvider } catch { $SHA1CryptoProvider = $null }
			try { $SHA256CryptoProvider = new-object -TypeName system.security.cryptography.SHA256CryptoServiceProvider } catch { $SHA256CryptoProvider = $null }
			
			$Global:CryptoProvider = New-Object PSObject -Property @{
				MD5CryptoProvider = $MD5CryptoProvider
				SHA1CryptoProvider = $SHA1CryptoProvider
				SHA256CryptoProvider = $SHA256CryptoProvider
			}	
		}
	}
	
	PROCESS {
		
		try {
			$inputBytes = [System.IO.File]::ReadAllBytes($Path);
		} catch {
			Write-Warning "Hash Error: Could not read file $Path"
			return $null
		}
		
		$Results = New-Object PSObject -Property @{
			Path = $Path
			MD5 = $null
			SHA1 = $null
			SHA256 = $null
		}
		
		Switch ($Type) {
			All {
				try {
					$Hash = [System.BitConverter]::ToString($Global:CryptoProvider.MD5CryptoProvider.ComputeHash($inputBytes))
					$result = $Hash.Replace('-','').ToUpper()
				} catch {
					Write-Warning "Hash Error: Could not compute Hash $Path with MD5CryptoProvider"
					$result = $null
				}
				$Results.MD5 = $result
				
				try {
					$Hash = [System.BitConverter]::ToString($Global:CryptoProvider.SHA1CryptoProvider.ComputeHash($inputBytes))
					$result = $Hash.Replace('-','').ToUpper()
				} catch {
					Write-Warning "Hash Error: Could not compute Hash $Path with SHA1CryptoProvider"
					$result = $null
				}
				$Results.SHA1 = $result
				
				try {
					$Hash = [System.BitConverter]::ToString($Global:CryptoProvider.SHA256CryptoProvider.ComputeHash($inputBytes))
					$result = $Hash.Replace('-','').ToUpper()
				} catch {
					Write-Warning "Hash Error: Could not compute Hash $Path with SHA256CryptoProvider"
					$result = $null
				}
				$Results.SHA256 = $result
				break;
			}
			MD5 { 
				try {
					$Hash = [System.BitConverter]::ToString($Global:CryptoProvider.MD5CryptoProvider.ComputeHash($inputBytes))
					$result = $Hash.Replace('-','').ToUpper()
				} catch {
					Write-Warning "Hash Error: Could not compute Hash $Path with MD5CryptoProvider"
					$result = $null
				}
				$Results.MD5 = $result			
			}
			SHA1 {
				Write-Verbose "Type: SHA1"
				try {
					$Hash = [System.BitConverter]::ToString($Global:CryptoProvider.SHA1CryptoProvider.ComputeHash($inputBytes))
					$result = $Hash.Replace('-','').ToUpper()
				} catch {
					Write-Warning "Hash Error: Could not compute Hash $Path with SHA1CryptoProvider"
					$result = $null
				}
				$Results.SHA1 = $result
			}
			SHA256 {
				try {
					$Hash = [System.BitConverter]::ToString($Global:CryptoProvider.SHA256CryptoProvider.ComputeHash($inputBytes))
					$result = $Hash.Replace('-','').ToUpper()
				} catch {
					Write-Warning "Hash Error: Could not compute Hash $Path with SHA256CryptoProvider"
					$result = $null
				}
				$Results.SHA256 = $result
			}
		}

		Write-Output $Results
	}
	
	END {}
}
