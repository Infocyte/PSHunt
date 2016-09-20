
#  .ExternalHelp Posh-VirusTotal.Help.xml
function Set-VTAPIKey
{
    [CmdletBinding()]
    Param
    (
        # VirusToral API Key.
        [Parameter(Mandatory=$true)]
        [string]$APIKey,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [securestring]$MasterPassword
    )

    Begin
    {
    }
    Process
    {
        $Global:VTAPIKey = $APIKey
        $SecureKeyString = ConvertTo-SecureString -String $APIKey -AsPlainText -Force

        # Generate a random secure Salt
        $SaltBytes = New-Object byte[] 32
        $RNG = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $RNG.GetBytes($SaltBytes)

        $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList 'user', $MasterPassword

        # Derive Key, IV and Salt from Key
        $Rfc2898Deriver = New-Object System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList $Credentials.GetNetworkCredential().Password, $SaltBytes
        $KeyBytes  = $Rfc2898Deriver.GetBytes(32)

        $EncryptedString = $SecureKeyString | ConvertFrom-SecureString -key $KeyBytes


        $FolderName = 'Posh-VirusTotal'
        $ConfigName = 'api.key'
        $saltname   = 'salt.rnd'

        (Test-Path -Path "$($env:AppData)\$FolderName")
        if (!(Test-Path -Path "$($env:AppData)\$FolderName"))
        {
            Write-Verbose -Message 'Seems this is the first time the config has been set.'
            Write-Verbose -Message "Creating folder $("$($env:AppData)\$FolderName")"
            New-Item -ItemType directory -Path "$($env:AppData)\$FolderName" | Out-Null
        }
        
        Write-Verbose -Message "Saving the information to configuration file $("$($env:AppData)\$FolderName\$ConfigName")"
        "$($EncryptedString)"  | Set-Content  "$($env:AppData)\$FolderName\$ConfigName" -Force

        # Saving salt in to the file.
        Set-Content -Value $SaltBytes -Encoding Byte -Path "$($env:AppData)\$FolderName\$saltname" -Force
    }
    End
    {
    }
}

#  .ExternalHelp Posh-VirusTotal.Help.xml
function Read-VTAPIKey
{
    [CmdletBinding()]

    Param
    (

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [securestring]$MasterPassword
    )

    Begin
    {
        # Test if configuration file exists.
        if (!(Test-Path "$($env:AppData)\Posh-VirusTotal\api.key"))
        {
            throw 'Configuration has not been set, Set-VTAPIKey to configure the API Keys.'
        }
    }
    Process
    {
        Write-Verbose -Message "Reading key from $($env:AppData)\Posh-VirusTotal\api.key."
        $ConfigFileContent = Get-Content -Path "$($env:AppData)\Posh-VirusTotal\api.key"
        Write-Debug -Message "Secure string is $($ConfigFileContent)"
        $SaltBytes = Get-Content -Encoding Byte -Path "$($env:AppData)\Posh-VirusTotal\salt.rnd" 
        $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList 'user', $MasterPassword

        # Derive Key, IV and Salt from Key
        $Rfc2898Deriver = New-Object System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList $Credentials.GetNetworkCredential().Password, $SaltBytes
        $KeyBytes  = $Rfc2898Deriver.GetBytes(32)

        $SecString = ConvertTo-SecureString -Key $KeyBytes $ConfigFileContent

        # Decrypt the secure string.
        $SecureStringToBSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecString)
        $APIKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto($SecureStringToBSTR)

        # Set session variable with the key.
        Write-Verbose -Message "Setting key $($APIKey) to variable for use by other commands."
        $Global:VTAPIKey = $APIKey
        Write-Verbose -Message 'Key has been set.'
    }
    End
    {
    }
}

#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTIPReport
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # IP Address to scan for.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [string]$IPAddress,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            throw 'No VirusTotal API Key has been specified or set.'
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }
    }
    Process
    {

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Body = @{'ip'= $IPAddress; 'apikey'= $APIKey}

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $IPReport = Invoke-RestMethod @Params
        
        $ErrorActionPreference = $OldEAP
        
        if ($RESTError)
        {
            if ($RESTError.Message.Contains('403'))
            {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*')
            {
                throw 'API key rate has been reached.'
            }
            else
            {
                throw $RESTError
            }
        }

        $IPReport.pstypenames.insert(0,'VirusTotal.IP.Report')
        $IPReport
        
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTDomainReport
{
    [CmdletBinding(DefaultParametersetName = 'Direct')]
    Param
    (
        # Domain to scan.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [string]$Domain,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/domain/report'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            throw 'No VirusTotal API Key has been specified or set.'
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }
    }
    Process
    {
        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Body = @{'domain'= $Domain; 'apikey'= $APIKey}

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        
        $DomainReport = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP
        
        if ($RESTError)
        {
            if ($RESTError.Message.Contains('403'))
            {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*')
            {
                throw 'API key rate has been reached.'
            }
            else
            {
                throw $RESTError
            }
        }

        $DomainReport.pstypenames.insert(0,'VirusTotal.Domain.Report')
        $DomainReport
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTFileReport
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # File MD5 Checksum, File SHA1 Checksum, File SHA256 Checksum or ScanID to query.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [ValidateCount(1,4)]
        [string[]]$Resource,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/report'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            throw 'No VirusTotal API Key has been specified or set.'
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }
    }
    Process
    {
        $QueryResources =  $Resource -join ','

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Body =  @{'resource'= $QueryResources; 'apikey'= $APIKey}

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }


        $ReportResult =Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP
        
        if ($RESTError)
        {
            if ($RESTError.Message.Contains('403'))
            {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*')
            {
                throw 'API key rate has been reached.'
            }
            else
            {
                throw $RESTError
            }
        }

        foreach ($FileReport in $ReportResult)
        {
            $FileReport.pstypenames.insert(0,'VirusTotal.File.Report')
            $FileReport
        }
        
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTURLReport
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # URL or ScanID to query.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [ValidateCount(1,4)]
        [string[]]$Resource,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$APIKey,

        # Automatically submit the URL for analysis if no report is found for it in VirusTotal.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [switch]$Scan,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/url/report'
        
        if ($Scan)
        {
            $scanurl = 1
        }
        else
        {
            $scanurl = 0
        }

        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            throw 'No VirusTotal API Key has been specified or set.'
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }
    }
    Process
    {
        $QueryResources =  $Resource -join ','

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Body = @{'resource'= $QueryResources; 'apikey'= $APIKey; 'scan'=$scanurl}


        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $ReportResult = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP
        
        if ($RESTError)
        {
            if ($RESTError.Message.Contains('403'))
            {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*')
            {
                throw 'API key rate has been reached.'
            }
            else
            {
                throw $RESTError
            }
        }

        foreach ($URLReport in $ReportResult)
        {
            $URLReport.pstypenames.insert(0,'VirusTotal.URL.Report')
            $URLReport
        }
        
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Submit-VTURL
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # URL or ScanID to query.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [ValidateCount(1,4)]
        [string[]]$URL,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$APIKey,

        # Automatically submit the URL for analysis if no report is found for it in VirusTotal.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$false)]
        [switch]$Scan,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/url/scan'
        if ($Scan)
        {
            $scanurl = 1
        }
        else
        {
            $scanurl = 0
        }

        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            throw 'No VirusTotal API Key has been specified or set.'
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }
    }
    Process
    {
        $URLList =  $URL -join "`n"
        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        
        $Body =  @{'url'= $URLList; 'apikey'= $APIKey}

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Post')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $SubmitedList = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP
        
        if ($RESTError)
        {
            if ($RESTError.Message.Contains('403'))
            {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*')
            {
                throw 'API key rate has been reached.'
            }
            else
            {
                throw $RESTError
            }
        }

        foreach($submited in $SubmitedList)
        {
            $submited.pstypenames.insert(0,'VirusTotal.URL.Submission')
            $submited
        }
      
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Submit-VTFile
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # URL or ScanID to query.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$File,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin
    {
        $URI = 'http://www.virustotal.com/vtapi/v2/file/scan'

        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            Write-Error 'No VirusTotal API Key has been specified or set.'
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }
    }
    Process
    {
        $fileinfo = Get-ItemProperty -Path $File

        # Check the file size
        if ($fileinfo.length -gt 64mb)
        {
            Write-Error 'VirusTotal has a limit of 64MB per file submited' -ErrorAction Stop
        }
   
        $req = [System.Net.WebRequest]::Create('http://www.virustotal.com/vtapi/v2/file/scan')
        #$req.Headers = $headers
        $req.Method = 'POST'
        $req.AllowWriteStreamBuffering = $true
        $req.SendChunked = $false
        $req.KeepAlive = $true

        # Set the Proxy values.
        if ($PSCmdlet.ParameterSetName -eq 'Proxy')
        {
            $ProxyObject = New-Object System.Net.WebProxy
            $ProxyObject.Address = [uri]$Proxy

            if ($ProxyUseDefaultCredentials)
            {
                $ProxyObject.UseDefaultCredentials = $ProxyUseDefaultCredentials
            }

            if ($ProxyCredential)
            {
                $ProxyObject.Credentials = $ProxyCredential.GetNetworkCredential()
            }

            $req.Proxy = $ProxyObject
        }

        # Set the proper headers.
        $headers = New-Object -TypeName System.Net.WebHeaderCollection

        # Prep the POST Headers for the message
        $headers.add('apikey',$apikey)
        $boundary = '----------------------------' + [DateTime]::Now.Ticks.ToString('x')
        $req.ContentType = 'multipart/form-data; boundary=' + $boundary
        [byte[]]$boundarybytes = [System.Text.Encoding]::ASCII.GetBytes("`r`n--" + $boundary + "`r`n")
        [string]$formdataTemplate = "`r`n--" + $boundary + "`r`nContent-Disposition: form-data; name=`"{0}`";`r`n`r`n{1}"
        [string]$formitem = [string]::Format($formdataTemplate, 'apikey', $apikey)
        [byte[]]$formitembytes = [System.Text.Encoding]::UTF8.GetBytes($formitem)
        [string]$headerTemplate = "Content-Disposition: form-data; name=`"{0}`"; filename=`"{1}`"`r`nContent-Type: application/octet-stream`r`n`r`n"
        [string]$header = [string]::Format($headerTemplate, 'file', (get-item $file).name)
        [byte[]]$headerbytes = [System.Text.Encoding]::UTF8.GetBytes($header)
        [string]$footerTemplate = "Content-Disposition: form-data; name=`"Upload`"`r`n`r`nSubmit Query`r`n" + $boundary + '--'
        [byte[]]$footerBytes = [System.Text.Encoding]::UTF8.GetBytes($footerTemplate)


        # Read the file and format the message
        $stream = $req.GetRequestStream()
        $rdr = new-object System.IO.FileStream($fileinfo.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        [byte[]]$buffer = new-object byte[] $rdr.Length
        [int]$total = [int]$count = 0
        $stream.Write($formitembytes, 0, $formitembytes.Length)
        $stream.Write($boundarybytes, 0, $boundarybytes.Length)
        $stream.Write($headerbytes, 0,$headerbytes.Length)
        $count = $rdr.Read($buffer, 0, $buffer.Length)
        do{
            $stream.Write($buffer, 0, $count)
            $count = $rdr.Read($buffer, 0, $buffer.Length)
        }while ($count > 0)
        $stream.Write($boundarybytes, 0, $boundarybytes.Length)
        $stream.Write($footerBytes, 0, $footerBytes.Length)
        $stream.close()

        Try
        {
            # Upload the file
            $response = $req.GetResponse()

            # Read the response
            $respstream = $response.GetResponseStream()
            $sr = new-object System.IO.StreamReader $respstream
            $result = $sr.ReadToEnd()
            ConvertFrom-Json $result
        }
        Catch [Net.WebException]
        {
            if ($Error[0].ToString() -like '*403*')
            {
                Write-Error 'API key is not valid.'
            }
            elseif ($Error[0].ToString() -like '*204*')
            {
                Write-Error 'API key rate has been reached.'
            }
        }
    }
    End
    {
    }
}

#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-PoshVTVersion
 {
     [CmdletBinding()]
     [OutputType([pscustomobject])]
     Param
     ()
 
     Begin
     {
        $currentversion = ''
        $installed = Get-Module -Name 'Posh-VirusTotal' 
     }
     Process
     {
        $webClient = New-Object System.Net.WebClient
        Try
        {
            $current = Invoke-Expression  $webClient.DownloadString('https://raw.github.com/darkoperator/Posh-VirusTotal/master/Posh-VirusTotal.psd1')
            $currentversion = $current.moduleversion
        }
        Catch
        {
            Write-Warning 'Could not retrieve the current version.'
        }
        $majorver,$minorver = $currentversion.split('.')

        if ($majorver -gt $installed.Version.Major)
        {
            Write-Warning 'You are running an outdated version of the module.'
        }
        elseif ($minorver -gt $installed.Version.Minor)
        {
            Write-Warning 'You are running an outdated version of the module.'
        } 
        
        $props = @{
            InstalledVersion = "$($installed.Version)"
            CurrentVersion   = $currentversion
        }
        New-Object -TypeName psobject -Property $props
     }
     End
     {
          
     }
 }

#  .ExternalHelp Posh-VirusTotal.Help.xml
 function Get-VTAPIKeyInfo
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin
    {
        $URI = 'http://www.virustotal.com/vtapi/v2/key/details'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            throw 'No VirusTotal API Key has been specified or set.'
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }
    }
    Process
    {

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Body = @{'apikey'= $APIKey}

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $IPReport = Invoke-RestMethod @Params
        
        $ErrorActionPreference = $OldEAP
        
        if ($RESTError)
        {
            if ($RESTError.Message.Contains('403'))
            {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*')
            {
                throw 'API key rate has been reached.'
            }
            else
            {
                throw $RESTError
            }
        }

        $IPReport.pstypenames.insert(0,'VirusTotal.IP.Report')
        $IPReport
        
    }
    End
    {
    }
}


# Private API
###############


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTSpecialURL
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # VirusToral Private API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin
    {
        
        $URI = 'https://www.virustotal.com/vtapi/v2/file/scan/upload_url'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            throw 'No VirusTotal API Key has been specified or set.'
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private')
        {
            throw 'The key provided is not a Private API Key'
        }
        Write-Verbose 'Key verifies as a Private API Key.'
    }
    Process
    {

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Body = @{'apikey' = $APIKey}

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }
        
        $IPReport = Invoke-RestMethod $Params

        $ErrorActionPreference = $OldEAP
        
        if ($RESTError)
        {
            if ($RESTError.Message.Contains('403'))
            {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*')
            {
                throw 'API key rate has been reached.'
            }
            else
            {
                throw $RESTError
            }
        }

        $IPReport.pstypenames.insert(0,'VirusTotal.SpecialUploadURL')
        $IPReport
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTFileComment
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # File MD5, SHA1 or SHA256 Checksum to get comments from.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [string]$Resource,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/comments/get'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            Write-Error 'No VirusTotal API Key has been specified or set.'
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private')
        {
            throw 'The key provided is not a Private API Key'
        }
        Write-Verbose 'Key verifies as a Private API Key.'

        $Body = @{'apikey'= $APIKey}
    }
    Process
    {

        $Body.add('resource',$Resource)

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Response = Invoke-RestMethod @Params
        
        $ErrorActionPreference = $OldEAP
        if ($RESTError)
        {
            if ($RESTError.Message.Contains('403'))
            {
                Write-Error 'API key is not valid.' -ErrorAction Stop
            }
            elseif ($RESTError.Message -like '*204*')
            {
                Write-Error 'API key rate has been reached.' -ErrorAction Stop
            }
            else
            {
                Write-Error $RESTError
            }
        }
        $Response.pstypenames.insert(0,'VirusTotal.Comment')
        $Response

    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Set-VTFileComment
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # File MD5, SHA1 or SHA256 Checksum to comment on.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [string]$Resource,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Comment,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/comments/put'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            throw 'No VirusTotal API Key has been specified or set.'
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private')
        {
            throw 'The key provided is not a Private API Key'
        }
        Write-Verbose 'Key verifies as a Private API Key.'

        $Body = @{'apikey'= $APIKey}
    }
    Process
    {

        $Body.add('resource',$Resource)

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Post')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Response = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP
        if ($RESTError)
        {
            if ($RESTError.Message.Contains('403'))
            {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*')
            {
                throw 'API key rate has been reached.'
            }
            else
            {
                throw $RESTError
            }
        }
        $Response.pstypenames.insert(0,'VirusTotal.Comment')
        $Response

    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Set-VTFileRescan
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # File MD5 Checksum, File SHA1 Checksum, File SHA256 Checksum or ScanID to query.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [string]$Resource,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$APIKey,

        # Date in which the rescan should be performed. If not specified the rescan will be performed immediately.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$false)]
        [datetime]$Date,

        # Period in days in which the file should be rescanned.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$false)]
        [int32]$Period,

        # Used in conjunction with period to specify the number of times the file should be rescanned.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$false)]
        [int32]$Repeat,

        # An URL where a POST notification should be sent when the rescan finishes.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$false)]
        [string]$NotifyURL,

        # Indicates if POST notifications should be sent only if the scan results differ from the previous one.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$false)]
        [bool]$NotifyChanges,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/rescan'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            Write-Error 'No VirusTotal API Key has been specified or set.'
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }

        $Body = @{'apikey'= $APIKey}

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private')
        {
            throw 'The key provided is not a Private API Key'
        }
        Write-Verbose 'Key verifies as a Private API Key.'
    }
    Process
    {
        $Body.add('resource',$Resource)
        if ($Date)
        {
            $Body.add('date', ($Date.ToString('yyyyMMddhhmmss')))
        }

        if ($Period)
        {
            $Body.add('period', $Period)
        }

        if ($Repeat)
        {
            $Body.add('repeat', $Repeat)
        }

        if ($NotifyURL)
        {
            $Body.add('notify_url', $NotifyURL)
        }

        if ($NotifyChanges)
        {
            $Body.add('notify_changes_only', $NotifyChanges)
        }

        $Body.add('resource',$Resource)
        
        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Post')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Response = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP
        if ($RESTError)
        {
            if ($RESTError.Message.Contains('403'))
            {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*')
            {
                throw 'API key rate has been reached.'
            }
            else
            {
                throw $RESTError
            }
        }

        $Response.pstypenames.insert(0,'VirusTotal.ReScan')
        $Response
        
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Remove-VTFileRescan
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # File MD5 Checksum, File SHA1 Checksum, File SHA256 Checksum or ScanID to remove rescan.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [string]$Resource,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/rescan/delete'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            Write-Error 'No VirusTotal API Key has been specified or set.'
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }

        $Body = @{'apikey'= $APIKey}

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private')
        {
            throw 'The key provided is not a Private API Key'
        }
        Write-Verbose 'Key verifies as a Private API Key.'

    }
    Process
    {

        $Body.add('resource',$Resource)

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Post')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }
        
        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        
        $Response = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP

        if ($RESTError)
        {
            if ($RESTError.Message.Contains('403'))
            {
                Write-Error 'API key is not valid.' -ErrorAction Stop
            }
            elseif ($RESTError.Message -like '*204*')
            {
                Write-Error 'API key rate has been reached.' -ErrorAction Stop
            }
            else
            {
                Write-Error $RESTError
            }
        }

        $Response.pstypenames.insert(0,'VirusTotal.ReScan')
        $Response

    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTFileScanReport
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # File MD5 Checksum, File SHA1 Checksum, File SHA256 Checksum or ScanID of the scan.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [string]$Resource,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$APIKey,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$false)]
        [switch]$AllInfo,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/report'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            throw 'No VirusTotal API Key has been specified or set.'
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }

        $Body = @{'apikey'= $APIKey}

        if ($AllInfo)
        {
            $Body.Add('allinfo',1)
        }

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private')
        {
            throw 'The key provided is not a Private API Key'
        }
        Write-Verbose 'Key verified as a Private API Key.'
    }
    Process
    {

        $Body.add('resource',$Resource)
        
        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        $Response = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP
        
        if ($RESTError)
        {
            if ($RESTError.Message.Contains('403'))
            {
                Write-Error 'API key is not valid.' -ErrorAction Stop
            }
            elseif ($RESTError.Message -like '*204*')
            {
                Write-Error 'API key rate has been reached.' -ErrorAction Stop
            }
            else
            {
                Write-Error $RESTError
            }
        }
        $Response.pstypenames.insert(0,'VirusTotal.Scan.Report')
        $Response

    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTFileBehaviourReport
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # File MD5 Checksum, File SHA1 Checksum or File SHA256 Checksum of file.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [string]$Resource,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$APIKey,

        # File name and path to save Behaviour report as a Cuckoo JSON Dump.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Report,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials

    
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/behaviour'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            throw 'No VirusTotal API Key has been specified or set.'
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private')
        {
            throw 'The key provided is not a Private API Key'
        }
        Write-Verbose 'Key verified as a Private API Key.'

        $Body = @{'apikey'= $APIKey}
    }
    Process
    {

        $Body.add('hash',$Resource)

        $ReportFullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Report)
        
        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('Outfile', $ReportFullPath)

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }
        
        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        Write-Verbose "Saving report to $($ReportFullPath)."

        $bahaviour_report = Invoke-WebRequest @Params

        $ErrorActionPreference = $OldEAP
        if ($RESTError)
        {
            if ($RESTError.Message.Contains('403'))
            {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*')
            {
                throw 'API key rate has been reached.'
            }
            else
            {
                throw $RESTError
            }
        }
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTFileSample
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # File MD5 Checksum, File SHA1 Checksum or File SHA256 Checksum of file.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [string]$Resource,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$APIKey,

        # File name and path to save sample.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position = 1)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position = 1)]
        [string]$File,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/download'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            Write-Error 'No VirusTotal API Key has been specified or set.'
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private')
        {
            throw 'The key provided is not a Private API Key'
        }
        Write-Verbose 'Key verified as a Private API Key.'

        $Body = @{'apikey'= $APIKey}
    }
    Process
    {

        $Body.add('hash',$Resource)

        $SampleFullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($File)

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('OutFile', $SampleFullPath)

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        Write-Verbose "Saving report to $($SampleFullPath)."

        $SampleResponse = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP

        if ($RESTError)
        {
            if ($RESTError.Message.Contains('403'))
            {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*')
            {
                throw 'API key rate has been reached.'
            }
            else
            {
                throw $RESTError
            }
        }
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Get-VTFileNetworkTraffic
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # File MD5 Checksum, File SHA1 Checksum or File SHA256 Checksum.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [string]$Hash,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$APIKey,

        # File name and path to save Network Traffic in PCAP format.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position = 1)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position = 1)]
        [string]$File,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials

    
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/network-traffic'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            throw 'No VirusTotal API Key has been specified or set.'
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }

        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private')
        {
            throw 'The key provided is not a Private API Key'
        }
        Write-Verbose 'Key verified as a Private API Key.'

        $Body = @{'apikey'= $APIKey}
    }
    Process
    {

        $Body.add('hash',$Resource)

        $NTFullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($File)

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')
        $Params.Add('OutFile', $NTFullPath)

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'

        

        Write-Verbose "Saving file to $($NTFullPath)."

        $NTResponse = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP

        if ($RESTError)
        {
            if ($RESTError.Message.Contains('403'))
            {
                throw 'API key is not valid.'
            }
            elseif ($RESTError.Message -like '*204*')
            {
                throw 'API key rate has been reached.'
            }
            else
            {
                throw $RESTError
            }
        }
    }
    End
    {
    }
}


#  .ExternalHelp Posh-VirusTotal.Help.xml
function Search-VTAdvancedReversed
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # A search modifier compliant file search query..
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [string]$Query,

        # VirusToral API Key.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$APIKey,

        # The offset value returned by a previously issued identical query.
        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [int]$OffSet,

        [Parameter(ParameterSetName = 'Direct',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$false,
            ValueFromPipelineByPropertyName=$false)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy,
 
        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(ParameterSetName = 'Proxy',
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Switch]$ProxyUseDefaultCredentials
    
    )

    Begin
    {
        $URI = 'https://www.virustotal.com/vtapi/v2/file/search'
        if (!(Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            Write-Error 'No VirusTotal API Key has been specified or set.'
        }
        elseif ((Test-Path variable:Global:VTAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:VTAPIKey
        }

        $Body = @{'apikey' = $APIKey
                'query' = $Query}
        # If an offset is provided apply it.
        if ($OffSet)
        {
            $Body.Add('offset',$OffSet)
        }
        
        Write-Verbose 'Verifying the API Key.'
        $KeyInfo = Get-VTAPIKeyInfo -APIKey $APIKey
        if ($KeyInfo.type -ne 'private')
        {
            throw 'The key provided is not a Private API Key'
        }
        Write-Verbose 'Key verifies as a Private API Key.'

    }
    Process
    {
        
        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',$URI)
        $Params.Add('ErrorVariable', 'RESTError')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }

        $OldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        
        $Response = Invoke-RestMethod @Params

        $ErrorActionPreference = $OldEAP

        if ($RESTError)
        {
            if ($RESTError.Message.Contains('403'))
            {
                Write-Error 'API key is not valid.' -ErrorAction Stop
            }
            elseif ($RESTError.Message -like '*204*')
            {
                Write-Error 'API key rate has been reached.' -ErrorAction Stop
            }
            else
            {
                Write-Error $RESTError[0]
            }
        }

        $Response.pstypenames.insert(0,'VirusTotal.Search')
        $Response

    }
    End
    {
    }
}
