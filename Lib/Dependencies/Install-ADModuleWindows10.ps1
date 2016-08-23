#requires -RunAsAdministrator

<#-----------------------------------------------------------------------------
Ashley McGlone, Microsoft Premier Field Engineer
http://aka.ms/goateepfe
February 2016
Install-ADModule
For Windows 10 performs the following tasks:
- Downloads and installs Windows 10 RSAT for the appropriate system architecture
- Enables the RSAT AD PowerShell feature
- Updates help for the AD module
- Displays validation output
-------------------------------------------------------------------------------
LEGAL DISCLAIMER
This Sample Code is provided for the purpose of illustration only and is not
intended to be used in a production environment.  THIS SAMPLE CODE AND ANY
RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a
nonexclusive, royalty-free right to use and modify the Sample Code and to
reproduce and distribute the object code form of the Sample Code, provided
that You agree: (i) to not use Our name, logo, or trademarks to market Your
software product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your software product in which the Sample Code is embedded;
and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and
against any claims or lawsuits, including attorneys’ fees, that arise or result
from the use or distribution of the Sample Code.
 
This posting is provided "AS IS" with no warranties, and confers no rights. Use
of included script samples are subject to the terms specified
at http://www.microsoft.com/info/cpyright.htm.
-----------------------------------------------------------------------------#>


<#
.SYNOPSIS
Installs the AD PowerShell module from RSAT for Windows 10
.DESCRIPTION
Performs the following tasks:
- Downloads and installs Windows 10 RSAT for the appropriate system architecture
- Enables the RSAT AD PowerShell feature
- Updates help for the AD module
- Displays validation output
.NOTES
Requires an elevated PowerShell host.

Requires an internet connection to download the RSAT install.

The RSAT hotfix download (<100MB) will be stored in the Downloads
folder of the user running the script.

Checks the following before taking action:
- Is the system running Windows 10?
- Is the RSAT already installed?
- Is the AD PowerShell feature already enabled?
.PARAMETER Test
Switch parameter to validate the install. Performs the following:
- Displays the RSAT update file that was downloaded.
- Confirms the hotfix is installed.
- Displays help for Get-ADDomain.
- Run the cmdlets Get-ADDomain.
.EXAMPLE
Install-ADModule -Verbose
.EXAMPLE
Install-ADModule -Test -Verbose
#>
Function Install-ADModule {
    [CmdletBinding()]
    Param(
        [switch]$Test = $false
    )

    If ((Get-CimInstance Win32_OperatingSystem).Caption -like "*Windows 10*") {
        Write-Verbose '---This system is running Windows 10'
    } Else {
        Write-Warning '---This system is not running Windows 10'
        break
    }

    If (Get-HotFix -Id KB2693643 -ErrorAction SilentlyContinue) {

        Write-Verbose '---RSAT for Windows 10 is already installed'

    } Else {

        Write-Verbose '---Downloading RSAT for Windows 10'

        If ((Get-CimInstance Win32_ComputerSystem).SystemType -like "x64*") {
            $dl = 'WindowsTH-KB2693643-x64.msu'
        } Else {
            $dl = 'WindowsTH-KB2693643-x86.msu'
        }
        Write-Verbose "---Hotfix file is $dl"

        Write-Verbose "---$(Get-Date)"
        #Download file sample
        #https://gallery.technet.microsoft.com/scriptcenter/files-from-websites-4a181ff3
        $BaseURL = 'https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/'
        $URL = $BaseURL + $dl
        $Destination = Join-Path -Path $HOME -ChildPath "Downloads\$dl"
        $WebClient = New-Object System.Net.WebClient
        $WebClient.DownloadFile($URL,$Destination)
        $WebClient.Dispose()

        Write-Verbose '---Installing RSAT for Windows 10'
        Write-Verbose "---$(Get-Date)"
        # http://stackoverflow.com/questions/21112244/apply-service-packs-msu-file-update-using-powershell-scripts-on-local-server
        wusa.exe $Destination /quiet /norestart /log:$home\Documents\RSAT.log

        # wusa.exe returns immediately. Loop until install complete.
        do {
            Write-Host "." -NoNewline
            Start-Sleep -Seconds 3
        } until (Get-HotFix -Id KB2693643 -ErrorAction SilentlyContinue)
        Write-Host "."
        Write-Verbose "---$(Get-Date)"
    }

    # The latest versions of the RSAT automatically enable all RSAT features
    If ((Get-WindowsOptionalFeature -Online -FeatureName `
        RSATClient-Roles-AD-Powershell -ErrorAction SilentlyContinue).State `
        -eq 'Enabled') {

        Write-Verbose '---RSAT AD PowerShell already enabled'

    } Else {

        Write-Verbose '---Enabling RSAT AD PowerShell'
        Enable-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-Powershell

    }

    Write-Verbose '---Downloading help for AD PowerShell'
    Update-Help -Module ActiveDirectory -Verbose -Force

    Write-Verbose '---ActiveDirectory PowerShell module install complete.'

    # Verify
    If ($Test) {
        Write-Verbose '---Validating AD PowerShell install'
        dir (Join-Path -Path $HOME -ChildPath Downloads\*msu)
        Get-HotFix -Id KB2693643
        Get-Help Get-ADDomain
        Get-ADDomain
    }
}

Get-Help Install-ADModule -Full

Install-ADModule -Verbose

#Install-ADModule -Test -Verbose

break

<#
# Remove
wusa.exe /uninstall /kb:2693643 /quiet /norestart /log:$home\RSAT.log
#>
