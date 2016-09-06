# Posh-VirusTotal impliments the VirusTotal API directly... too complicated.  This wraps Posh-VirusTotal and abstracts complexity.
function Get-VTReport {
    [CmdletBinding()]
    Param( 
		[Parameter(Mandatory=$false)]
		[String] $ApiKey,
		
		[Parameter(ParameterSetName="hash", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[String] $Hash,
		
		[Parameter(ParameterSetName="file", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[ValidateScript({Test-Path $_ -PathType Leaf})]
		[String] $Path,
		
		[Parameter(ParameterSetName="uri", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[String] $Uri,
		
		[Parameter(ParameterSetName="ipaddress", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[String] $Ip,
		
		[Parameter(ParameterSetName="domain", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)
		][String] $Domain,

		# Proxy	
		[Parameter(Mandatory=$false)]
		[string]$CertificateThumbprint,
			
		[Parameter(Mandatory=$false)]
		[string]$Proxy,

		[Parameter(Mandatory=$false)]
		[Management.Automation.PSCredential]$ProxyCredential,

		[Parameter(Mandatory=$false)]
		[Switch]$ProxyUseDefaultCredentials
    )
    Begin {
		
		if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey)) {
            throw 'ERROR: No VirusTotal API Key has been specified or set.'
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey)) {
            $APIKey = $Global:VTAPIKey
        }
		
    }
    Process {
		
		$Params =  @{}
        $Params.add('APIKey', $ApiKey)
		
		# Set up proxy if provided.
		if ($Proxy) {
	        $Params.add('Proxy', $Proxy)
			if ($ProxyCredential) { 
				$Params.Add('ProxyCredential', $ProxyCredential) 
			} 
			else {
				$Params.add('ProxyUseDefaultCredentials',$ProxyUseDefaultCredentials)
			}
			if ($CertificateThumbprint) { 
				$Params.add('CertificateThumbprint', $CertificateThumbprint)
			}
		}
		
        switch ($PSCmdlet.ParameterSetName) {
			"file" { 
				$p = Resolve-Path -Path $Path | select -ExpandProperty Path
				$hashes = Get-Hashes -Path $p -Type SHA1
				Write-Verbose "Submitting hash ($($hashes.SHA1)) of $p"
				$Params.Add('Resource', $hashes.SHA1)
				
				$Result = Get-VTFileReport @Params
			}
			"hash" {
				$Params.Add('Resource', $hash)
				$Result = Get-VTFileReport @Params
			}
			"uri" {
				$Params.Add('Resource', $uri)
				$Params.Add('Scan', $false)
				$Result = Get-VTURLReport @Params
			}
			"ipaddress" {
				$ip1 = $null
				$isAddress = [System.Net.IPAddress]::tryparse($ip,[ref] $ip1)
				if ($isAddress) {
					$Params.Add('IPAddress', $ip)
					$Result = Get-VTIPReport @Params
				} else {
					throw "ERROR: IP is not an IPv4 Address"
				}
				
			}
			"domain" {
				$Params.Add('Domain', $domain)
				$Result = Get-VTDomainReport @Params
			}
        }        
		
        return $Result
    }    
}

function Invoke-VTScan {
    [CmdletBinding()]
    Param( 
		[Parameter(Mandatory=$false)]
		[String] $ApiKey,
    
		[Parameter(ParameterSetName="file", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[ValidateScript({Test-Path $_ -PathType Leaf})]
		[String] $Path,
		
		[Parameter(ParameterSetName="uri", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[String] $uri,
		
		# Proxy
		[Parameter(Mandatory=$false)]
		[string]$Proxy,

		[Parameter(Mandatory=$false)]
		[Management.Automation.PSCredential]$ProxyCredential,

		[Parameter(Mandatory=$false)]
		[Switch]$ProxyUseDefaultCredentials
    )
    Begin {

		if (!(Test-Path variable:Global:VTApiKey ) -and !($APIKey)) {
            throw 'ERROR: No VirusTotal API Key has been specified or set.'
        }
        elseif ((Test-Path variable:Global:VTApiKey ) -and !($APIKey)) {
            $APIKey = $Global:VTApiKey
        }
		
    }
    Process {
		$Params =  @{}
        $Params.add('APIKey', $ApiKey)
		
		# Set up proxy if provided.
		if ($Proxy) {
	        $Params.add('Proxy', $Proxy)
			if ($ProxyCredential) { 
				$Params.Add('ProxyCredential', $ProxyCredential) 
			} 
			else {
				$Params.add('ProxyUseDefaultCredentials',$ProxyUseDefaultCredentials)
			}
			if ($CertificateThumbprint) { 
				$Params.add('CertificateThumbprint', $CertificateThumbprint)
			}
		}
		
        switch ($PSCmdlet.ParameterSetName) {
        "file" { 
			$p = Resolve-Path -Path $Path | select -ExpandProperty Path
			$Params.add('File', $p)
			$Result = Submit-VTFile @Params
            }
        "uri" {
            $h = $uri	
			$Params.add('URL', $uri)
			$Result = Submit-VTURL @Params
            }            
        }

		return $Result
    }    
}

