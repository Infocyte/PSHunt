function Get-Hash {
	Param(
    [System.IO.FileInfo] $file = $(Throw 'Usage: Get-Hash [System.IO.FileInfo]'), 
    [String] $hashType = 'sha256'
	)

  $stream = $null;  
  [string] $result = $null;
  $hashAlgorithm = [System.Security.Cryptography.HashAlgorithm]::Create($hashType )
  $stream = $file.OpenRead();
  $hashByteArray = $hashAlgorithm.ComputeHash($stream);
  $stream.Close();

  trap
  {
    if ($stream -ne $null) { $stream.Close(); }
    break;
  }

  # Convert the hash to Hex
  $hashByteArray | foreach { $result += $_.ToString("X2") }
  return $result
}

function Get-Bytes([String] $str) {
    $bytes = New-Object Byte[] ($str.Length * 2)
    #[System.Buffer]::BlockCopy($str.ToCharArray(), 0, $bytes, 0, $bytes.Length)
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($str)
    return $bytes
}

function Get-VTReport {
    [CmdletBinding()]
    Param( 
    [Parameter(Mandatory=$true)][ValidateNotNull()]
	[String] $VTApiKey,
    
	[Parameter(ParameterSetName="hash", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
	[String] $hash,
    
	[Parameter(ParameterSetName="file", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
	[System.IO.FileInfo] $file,
    
	[Parameter(ParameterSetName="uri", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
	[Uri] $uri,
    
	[Parameter(ParameterSetName="ipaddress", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
	[String] $ip,
    
	[Parameter(ParameterSetName="domain", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)
	][String] $domain
    )
    Begin {
        $fileUri = 'https://www.virustotal.com/vtapi/v2/file/report'
        $UriUri = 'https://www.virustotal.com/vtapi/v2/url/report'
        $IPUri = 'http://www.virustotal.com/vtapi/v2/ip-address/report'
        $DomainUri = 'http://www.virustotal.com/vtapi/v2/domain/report'
    }
    Process {
        [String] $h = $null
        [String] $u = $null
        [String] $method = $null
        $body = @{}

        switch ($PSCmdlet.ParameterSetName) {
        "file" { 
            $h = Get-Hash -file $file
            Write-Verbose -Message ("FileHash:" + $h)
            $u = $fileUri
            $method = 'POST'
            $body = @{ resource = $h; apikey = $VTApiKey}
            }
        "hash" {            
            $u = $fileUri
            $method = 'POST'
            $body = @{ resource = $hash; apikey = $VTApiKey}
            }
        "uri" {
            $u = $UriUri
            $method = 'POST'
            $body = @{ url = $uri; apikey = $VTApiKey}
            }
        "ipaddress" {
            $u = $IPUri
            $method = 'GET'
            $body = @{ ip = $ip; apikey = $VTApiKey}
        }
        "domain" {            
            $u = $DomainUri
            $method = 'GET'
            $body = @{ domain = $domain; apikey = $VTApiKey}}
        }        

        return Invoke-RestMethod -Method $method -Uri $u -Body $body
    }    
}

function Invoke-VTScan {
    [CmdletBinding()]
    Param( 
		[Parameter(Mandatory=$true)]
		[ValidateNotNull()]
		[String] $VTApiKey,
    
		[Parameter(ParameterSetName="file", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[System.IO.FileInfo] $file,
		
		[Parameter(ParameterSetName="uri", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[Uri] $uri
    )
    Begin {
        $fileUri = 'https://www.virustotal.com/vtapi/v2/file/scan'
        $UriUri = 'https://www.virustotal.com/vtapi/v2/url/scan'
        [byte[]]$CRLF = 13, 10
    }
    Process {
        [String] $h = $null
        [String] $u = $null
        [String] $method = $null
        $body = New-Object System.IO.MemoryStream

        switch ($PSCmdlet.ParameterSetName) {
        "file" { 
            $u = $fileUri
            $method = 'POST'
            $boundary = [Guid]::NewGuid().ToString().Replace('-','')
            $ContentType = 'multipart/form-data; boundary=' + $boundary
            $b2 = Get-Bytes ('--' + $boundary)
            $body.Write($b2, 0, $b2.Length)
            $body.Write($CRLF, 0, $CRLF.Length)
            
            $b = (Get-Bytes ('Content-Disposition: form-data; name="apikey"'))
            $body.Write($b, 0, $b.Length)

            $body.Write($CRLF, 0, $CRLF.Length)
            $body.Write($CRLF, 0, $CRLF.Length)
            
            $b = (Get-Bytes $VTApiKey)
            $body.Write($b, 0, $b.Length)

            $body.Write($CRLF, 0, $CRLF.Length)
            $body.Write($b2, 0, $b2.Length)
            $body.Write($CRLF, 0, $CRLF.Length)
            
            $b = (Get-Bytes ('Content-Disposition: form-data; name="file"; filename="' + $file.Name + '";'))
            $body.Write($b, 0, $b.Length)
            $body.Write($CRLF, 0, $CRLF.Length)            
            $b = (Get-Bytes 'Content-Type:application/octet-stream')
            $body.Write($b, 0, $b.Length)
            
            $body.Write($CRLF, 0, $CRLF.Length)
            $body.Write($CRLF, 0, $CRLF.Length)
            
            $b = [System.IO.File]::ReadAllBytes($file.FullName)
            $body.Write($b, 0, $b.Length)

            $body.Write($CRLF, 0, $CRLF.Length)
            $body.Write($b2, 0, $b2.Length)
            
            $b = (Get-Bytes '--')
            $body.Write($b, 0, $b.Length)
            
            $body.Write($CRLF, 0, $CRLF.Length)
            
                
            Invoke-RestMethod -Method $method -Uri $u -ContentType $ContentType -Body $body.ToArray()
            }
        "uri" {
            $h = $uri
            $u = $UriUri
            $method = 'POST'
            $body = @{ url = $uri; apikey = $VTApiKey}
            Invoke-RestMethod -Method $method -Uri $u -Body $body
            }            
        }                        
    }    
}

function New-VTComment {
    [CmdletBinding()]
    Param( 
    [Parameter(Mandatory=$true)][ValidateNotNull()][String] $VTApiKey,
    [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String] $hash,
    [Parameter(Mandatory=$true)][ValidateNotNull()][String] $Comment
    )

    Process {
        $u = 'https://www.virustotal.com/vtapi/v2/comments/put'
        $method = 'POST'
        $body = @{ resource = $hash; apikey = $VTApiKey; comment = $Comment}

        return Invoke-RestMethod -Method $method -Uri $u -Body $body
    }    
}

function Invoke-VTRescan {
 [CmdletBinding()]
    Param( 
    [Parameter(Mandatory=$true)][ValidateNotNull()][String] $VTApiKey,
    [Parameter(Mandatory=$true, ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String] $hash
    )
    Process {
        $u = 'https://www.virustotal.com/vtapi/v2/file/rescan'
        $method = 'POST'
        $body = @{ resource = $hash; apikey = $VTApiKey}
        return Invoke-RestMethod -Method $method -Uri $u -Body $body
    }    
}