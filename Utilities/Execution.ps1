function Start-RemoteProcess {
<#
.SYNOPSIS
 
	Executes a command on a remote computer using various execution options.

	Project: PSHunt
	Author: Chris Gerritz (Github @singlethreaded) (Twitter @gerritzc)
	Company: Infocyte, Inc.
	License: Apache License 2.0
	Required Dependencies: None
	Optional Dependencies: None

.DESCRIPTION
  
	Executes a command on a remote host using WMI, Schtasks, PSExec, or PSRemoting
   
.PARAMETER ComputerName
			
	IP Address or Hostname of target system

.PARAMETER Command
 	Command line to execute 
	Note: syntax can be squirly depending on execution type... not well tested
	
.PARAMETER PSScript
 	Name of script or executable to execute.  
	
.PARAMETER ExecutionType
	Select method of remote execution { WMI | Schtasks | PSExec | PSRemoting }: 
		1.  WMI - Execute via WMI (TCP 135 + Dynamic Port)
		2.  Schtasks - Execute via Scheduled Task (TCP 445 or 139)
		3.  PSExec - Execute via PSExec (TCP 445 or 139)
		4.  PSRemoting - Use Invoke-Command via Powershell Remoting TCP 5985
				
.PARAMETER TaskName
	Name of scheduled task (if schtasks is selected).
  
 .PARAMETER Credentials
	Credentials of remote system.

#>
    [CmdletBinding()]
    Param
    (		
		[parameter(	Mandatory=$false,
					ValueFromPipeline=$true)]
        [string]$ComputerName="$env:COMPUTERNAME",
		
		[parameter(Mandatory=$false)]
        [string]$Command,
		
        [parameter(Mandatory=$false)]
        [string]$PSScript,		

	    [parameter(	Mandatory=$False,
					HelpMessage="Supported execution types are: WMI, Schtasks, PSExec, PSRemoting")]
		[ValidateSet('WMI', 'Schtasks', 'PSExec','PSRemoting')]
		[String]$ExecutionType='WMI',
		
        [parameter(	Mandatory=$false)]	
		[string]$TaskName = 'pshunttask',
		
		[Parameter(	Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

		$ErrorActionPreference = "Stop"
		
		Switch ($ExecutionType) {
			'WMI' {		
				if ($PSScript) {
					$TaskToRun = "Powershell.exe -ExecutionPolicy bypass -NoProfile -WindowStyle Hidden -File $PSScript"	
					#$TaskToRun = "Powershell.exe -ExecutionPolicy bypass -NoProfile -WindowStyle Hidden -Command { iex $PSScript }"	
				}
				elseif ($Command) {
					$TaskToRun = $Command
				}
				
				Write-Verbose "[Start-RemoteProcess]: Running $TaskToRun via Invoke-WMIMethod on $ComputerName"
				try {
					$Result = Invoke-WmiMethod -ComputerName $ComputerName -Credential $Credential -Class Win32_process -Name Create -ArgumentList $TaskToRun
					if ( ($?) -AND ($Result.ReturnValue -eq 0)) { 
                        $Result = "SUCCESS[Start-RemoteProcess]: Process started on $ComputerName with PID $($Result.ProcessID)" 
                    } else {
                        Switch ($Result.ReturnValue) {
                            0 {$resultTxt = "SUCCESS"}
                            2 {$resultTxt = "Access denied"}
                            3 {$resultTxt = "Insufficient privilege"}
                            8 {$resultTxt = "Unknown failure"}
                            9 {$resultTxt = "Path not found"}
                            21 {$resultTxt = "Invalid parameter"}
                            default { 
                                $resultTxt = "$($Error[0].Exception.Message)"
                            }
                        }  
						Write-Debug "Using \$? error handling on WMI"
                        Write-Warning "ERROR[Start-RemoteProcess]: $resultTxt on $ComputerName when running command $taskToRun"
                        throw $resultTxt
                    } 
				} catch [System.UnauthorizedAccessException] {
					# Access is denied
					Write-Debug "UnauthorizedAccessException error thrown"
					return "ERROR[Start-RemoteProcess]: Access Denied to $ComputerName with Result: $resultTxt"
				} catch [System.Runtime.InteropServices.COMException] {
					# The RPC server is unavailable
					Write-Debug "COMException error thrown"
					return "ERROR[Start-RemoteProcess]: The RPC server is unavailable on $ComputerName with Result: $resultTxt"
				} catch {
					# General Exception
					Write-Debug "General or unknown error thrown"
					return "ERROR[Start-RemoteProcess]: WMI Failure on $ComputerName with Result: $resultTxt"
				}
			}
			'Schtasks' { 			
				# Set up a scheduled task for an arbitrary time, then execute it manually.
				if ($PSScript) {
					$TaskToRun = "Powershell.exe -ExecutionPolicy bypass -NoProfile -File $PSScript" 
				}
				elseif ($Command) {
					$TaskToRun = $Command
				}
				Write-Verbose "[Start-RemoteProcess] Executing $TaskToRun via Scheduled Task on $ComputerName"
				if ($Credential.UserName -ne $null) {
					$Username = ($Credential.GetNetworkCredential().Username) 
					$Domain = ($Credential.GetNetworkCredential().Domain) 
					if (!$Domain) {
						$Domain = $ComputerName
					}
					$Result = schtasks /create /RU SYSTEM /s $Computername /U "$Domain\$Username" /P $Credential.GetNetworkCredential().password /tn $TaskName /tr $TaskToRun /sc once /st 23:59 /F 2>&1
				} else {
					$Result = schtasks /create /RU SYSTEM /s $Computername /tn $TaskName /tr $TaskToRun /sc once /st 23:59 /F 2>&1
				}
				if (!($?) -OR ($Result -match "Error") ) {
					Write-Warning "ERROR[Start-RemoteProcess]: Could not scheduled task on $Computername with result: $Result" 
					return "ERROR[Start-RemoteProcess]: Could not schedule task on $Computername with result: $Result" 
				} else {
					Write-Verbose "[Start-RemoteProcess] Created task with result: $Result"
				}

				Write-Verbose "[Start-RemoteProcess] Running $TaskName on $ComputerName"
				if ($Credential.UserName -ne $null) {
					# Write-Verbose "Using specified credentials: $($($Credential.Username).ToString())"
					$Result = schtasks /run /s $Computername /tn $TaskName /U ($Credential.GetNetworkCredential().Username) /P ($Credential.GetNetworkCredential().password) 2>&1
				} else {
					$Result = schtasks /run /s $Computername /tn $TaskName 2>&1
				}
				if (!($?) -OR ($Result -match "Error") ) {
					Write-Warning "ERROR[Start-RemoteProcess]: Error while running scheduled task on $Computername with result: $Result" 
					return "ERROR[Start-RemoteProcess]: Could not run scheduled task on $Computername with result: $Result" 
				} else {
					Write-Verbose "[Start-RemoteProcess] $Result"
				}
				
				# Deleting the task while running was causing problems...
				Start-Sleep -s 1
				Write-Verbose "[Start-RemoteProcess] Deleting Scheduled Task $TaskName"
				if ($Credential.UserName -ne $null) {
					$Result = schtasks /Delete /s $Computername /tn $TaskName /U ($Credential.GetNetworkCredential().Username) /P ($Credential.GetNetworkCredential().password) /F 2>&1
				} else {
					$Result = schtasks /Delete /s $Computername /tn $TaskName /F 2>&1
				}
				
				if (!($?) -OR ($Result -match "Error") ) {
					Write-Warning "ERROR[Start-RemoteProcess]: Error while disabling scheduled task on $Computername with result: $Result"  
				} else {
					Write-Verbose "[Start-RemoteProcess] Deleted task with result: $Result"
				}

				# Spaces in file paths can be used by using two sets of quotes, one
				# set for CMD.EXE and one for SchTasks.exe.  The outer quotes for CMD
				# need to be double quotes; the inner quotes can be single quotes or
				# escaped double quotes:
				# SCHTASKS /Create /tr "'c:\program files\internet explorer\iexplorer.exe' 'c:\log data\today.xml'" ...
			}
			'PSExec' {
				# Method: PSExec
				if ($PSScript) {
					$TaskToRun = "cmd.exe /c Powershell.exe -Exec bypass -NoProfile -File $PSScript"
				}
				elseif ($Command) {
					$TaskToRun = $Command
				}
				Write-Debug "[Start-RemoteProcess] Running $TaskToRun via PSExec on $ComputerName"
				
				try {
					$Result = Invoke-PsExec -ComputerName $ComputerName -Command $TaskToRun -Credential $Credential
				} catch {
					Write-Warning "ERROR[Start-RemoteProcess]: Invoke-PsExec on $ComputerName running $TaskToRun.  Error: $Result"
					return "ERROR[Start-RemoteProcess]: Invoke-PsExec on $ComputerName running $TaskToRun.  Error: $Result"
				}
			
				<#
				if ($Credential.UserName -ne $null) {
					Write-Verbose "Using specified credentials: " + $Credential.Username.ToString()
					
					$result = &"$PSExecPath" \\$ComputerName -s -u ($Credential.Username) -p ($Credential.GetNetworkCredential().password) -accepteula -h -n 3 -d cmd /c $Command 2>&1
				} else {
					$result = &"$PSExecPath" \\$ComputerName -s -accepteula -h -n 3 -d cmd /c $Command 2>&1
				}
				#>
				
			}
			'PSRemoting' {
				# Method: PSRemoting
				
				if ($PSScript) {
					$cmd = "iex $PSScript"
				}
				elseif ($Command) {
					$cmd = $Command
				}
				$sb = [ScriptBlock]::Create($cmd)
				Write-Verbose "[Start-RemoteProcess] Executing via PSRemoting's Invoke-Command: $cmd"
				
				# Invoke-Command isn't working against localhost with ComputerName param
				
				if (($ComputerName -eq $env:ComputerName) -OR ($ComputerName -match 'localhost') -OR ($ComputerName -eq '127.0.0.1') ) {
					try {	
						Write-Debug "Launching local job against localhost"
						$Job = Start-Job -ScriptBlock $sb -Credential $Credential
						Start-Sleep -Milliseconds 100
						if ( ($Job.State -eq 'Error') -OR ($Job.State -eq 'Failed') ) {
							Throw "ERROR[Start-RemoteProcess]: Starting ScriptBlock with Start-Job"
						}					
					} catch {
						Write-Warning "ERROR[Start-RemoteProcess]: PSRemoting command $Command failed on $ComputerName with $Credential with Error: $($Job.Error)"
						return "ERROR[Start-RemoteProcess]: PSRemoting command $Command failed on $ComputerName with $Credential with Error: $($Job.Error)"
					}
				} else {
					try {
						if ($Credential) {
							$Job = Invoke-Command -ComputerName $ComputerName -ScriptBlock $sb -asJob -Credential $Credential
						} else {
							$Job = Invoke-Command -ComputerName $ComputerName -ScriptBlock $sb -asJob				
						}

						Start-Sleep -Milliseconds 100
						if ( ($Job.State -eq 'Error') -OR ($Job.State -eq 'Failed') ) {
							Throw "ERROR[Start-RemoteProcess]: Starting ScriptBlock with Invoke-Command"
						}					
					} catch {
						Write-Warning "ERROR[Start-RemoteProcess]: PSRemoting command $Command failed on $ComputerName with creds ($Credential) with Error: $($Job.Error)"
						return "ERROR[Start-RemoteProcess]: PSRemoting command $Command failed on $ComputerName with creds ($Credential) with Error: $($Job.Error)"
					}
				}
			}
		}
		# Don't track jobs
		# $null = Get-Job | Remove-Job
		
		return "SUCCESS: Execution Complete on $ComputerName"
}

function Invoke-PsExec {
<#
	.SYNOPSIS

		This function is a rough port of Metasploit's psexec functionality.
		It utilizes Windows API calls to open up the service manager on
		a remote machine, creates/run a service to run a command, and then 
		cleans everything up.

		Adapted from @harmjoy's Invoke-PSExec which came from MSF's version (see links).
		I removed some of the stuff we didn't need in PSHunt and added the ability to 
		impersonate an account for remote execution to off domain systems.

		Project: PSHunt
		Author: Chris Gerritz (Github @singlethreaded) (Twitter @gerritzc)
		Original Author: @harmj0y
		Company: Infocyte, Inc.
		License: BSD 3-Clause
		Required Dependencies: None
		Optional Dependencies: None

	.PARAMETER ComputerName

		ComputerName to run the command on.

	.PARAMETER Command

		Binary path (or Windows command) to execute.

	.PARAMETER ServiceName

		The name of the service to create, defaults to "PSHuntSvc"

	.EXAMPLE

		PS C:\> Invoke-PsExec -ComputerName 192.168.50.200 -Command "net user backdoor password123 /delete"

		Deletes a user named backdoor on the 192.168.50.200 host.

	.EXAMPLE

		PS C:\> Invoke-PsExec -ComputerName 192.168.50.200 -Credentials (Get-Credential) -Command "cmd /c Powershell.exe -File C:\Windows\Temp\survey.ps1" -ServiceName pshuntsvc

		Runs the powershell script C:\Windows\Temp\survey.ps1 using a temporary service called "pshuntsvc"
		Advapi32:CreateServiceA is being difficult so I could only get powershell scripts to work with cmd /c powershell.exe.  
		I might fix this later but for now it works.

	.LINK
	
		https://github.com/HarmJ0y/Misc-PowerShell/blob/master/Invoke-PsExec.ps1
		https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/smb/psexec.rb
		https://github.com/rapid7/metasploit-framework/blob/master/tools/psexec.rb
#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] 
		[String]
		$ComputerName,

		[Parameter(Mandatory = $True)]
		[ValidateNotNullOrEmpty()]
		[String]
		$Command,

		[String]
		$ServiceName = "PSHuntSvc",

		[System.Management.Automation.PSCredential]
		$Credential
	)

	$ErrorActionPreference = "Stop"

	#  http://stackingcode.com/blog/2011/10/27/quick-random-string
	function Local:Get-RandomString 
	{
		param (
			[int]$Length = 12
		)
		$set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray()
		$result = ""
		for ($x = 0; $x -lt $Length; $x++) {
			$result += $set | Get-Random
		}
		$result
	}

	# from http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html
	function Local:Get-DelegateType
	{
		Param
		(
			[OutputType([Type])]
					
			[Parameter( Position = 0)]
			[Type[]]
			$Parameters = (New-Object Type[](0)),
					
			[Parameter( Position = 1 )]
			[Type]
			$ReturnType = [Void]
		)

		$Domain = [AppDomain]::CurrentDomain
		$DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
		$AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
		$TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
		$ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
		$ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
		$MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
		$MethodBuilder.SetImplementationFlags('Runtime, Managed')
				
		Write-Output $TypeBuilder.CreateType()
	}

	# from http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html
	function Local:Get-ProcAddress
	{
		Param
		(
			[OutputType([IntPtr])]
				
			[Parameter( Position = 0, Mandatory = $True )]
			[String]
			$Module,
					
			[Parameter( Position = 1, Mandatory = $True )]
			[String]
			$Procedure
		)

		# Get a reference to System.dll in the GAC
		$SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
			Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
		$UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
		# Get a reference to the GetModuleHandle and GetProcAddress methods
		$GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
		$GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
		# Get a handle to the module specified
		$Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
		$tmpPtr = New-Object IntPtr
		$HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
				
		# Return the address of the function
		Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
	}


	# Declare/setup all the needed API function
	# adapted heavily from http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html 
	$CloseServiceHandleAddr = Get-ProcAddress Advapi32.dll CloseServiceHandle
	$CloseServiceHandleDelegate = Get-DelegateType @( [IntPtr] ) ([Int])
	$CloseServiceHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseServiceHandleAddr, $CloseServiceHandleDelegate)    

	$OpenSCManagerAAddr = Get-ProcAddress Advapi32.dll OpenSCManagerA
	$OpenSCManagerADelegate = Get-DelegateType @( [String], [String], [Int]) ([IntPtr])
	$OpenSCManagerA = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenSCManagerAAddr, $OpenSCManagerADelegate)
			
	$OpenServiceAAddr = Get-ProcAddress Advapi32.dll OpenServiceA
	$OpenServiceADelegate = Get-DelegateType @( [IntPtr], [String], [Int]) ([IntPtr])
	$OpenServiceA = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenServiceAAddr, $OpenServiceADelegate)
		  
	$CreateServiceAAddr = Get-ProcAddress Advapi32.dll CreateServiceA
	$CreateServiceADelegate = Get-DelegateType @( [IntPtr], [String], [String], [Int], [Int], [Int], [Int], [String], [String], [Int], [Int], [Int], [Int]) ([IntPtr])
	$CreateServiceA = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateServiceAAddr, $CreateServiceADelegate)

	$StartServiceAAddr = Get-ProcAddress Advapi32.dll StartServiceA
	$StartServiceADelegate = Get-DelegateType @( [IntPtr], [Int], [String]) ([IntPtr])
	$StartServiceA = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StartServiceAAddr, $StartServiceADelegate)

	$DeleteServiceAddr = Get-ProcAddress Advapi32.dll DeleteService
	$DeleteServiceDelegate = Get-DelegateType @( [IntPtr] ) ([IntPtr])
	$DeleteService = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DeleteServiceAddr, $DeleteServiceDelegate)

	$GetLastErrorAddr = Get-ProcAddress Kernel32.dll GetLastError
	$GetLastErrorDelegate = Get-DelegateType @() ([Int])
	$GetLastError = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetLastErrorAddr, $GetLastErrorDelegate)

	$LogonUserAddr = Get-ProcAddress Advapi32.dll LogonUserA
	$LogonUserDelegate = Get-DelegateType @( [String], [String], [String], [Int], [Int], [IntPtr].MakeByRefType() ) ([BOOL])
	$LogonUser = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LogonUserAddr, $LogonUserDelegate)

	$ImpersonateLoggedOnUserAddr = Get-ProcAddress Advapi32.dll ImpersonateLoggedOnUser 
	$ImpersonateLoggedOnUserDelegate = Get-DelegateType @( [IntPtr] ) ([BOOL])
	$ImpersonateLoggedOnUser  = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateLoggedOnUserAddr, $ImpersonateLoggedOnUserDelegate)

	$RevertToSelfAddr = Get-ProcAddress Advapi32.dll RevertToSelf 
	$RevertToSelfDelegate = Get-DelegateType @() ([Void])
	$RevertToSelf   = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($RevertToSelfAddr, $RevertToSelfDelegate)


	if ($Credential) {
		# Step 0 - LogonUser to create a user token with new username/pass, then force this thread to impersonate it.
		# https://msdn.microsoft.com/en-us/library/windows/desktop/aa378184(v=vs.85).aspx
		# LOGON32_LOGON_NEW_CREDENTIALS = 9
        Write-Debug "Using Credentials"
        if (!$Credential.GetNetworkCredential().Domain) {
            # Go with non-domain name
            $Domain = $ComputerName
        } else {
            $Domain = $Credential.GetNetworkCredential().Domain
        }
        
        #$hToken = New-Object System.IntPtr 
        $hToken = [IntPtr]::Zero
		$val = $LogonUser.Invoke($cred.GetNetworkCredential().Username, $Domain, $Credential.GetNetworkCredential().Password, 9, 3, [ref]$hToken)
		if ($val -AND ($val -ne 0)) {
			# Impersonate user on current thread
            Write-Verbose "Impersonating $($cred.GetNetworkCredential().Username), Domain: $Domain"
			$val = $ImpersonateLoggedOnUser.Invoke($hToken)
		}
		else {
			# error codes - http://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx
			$err = $GetLastError.Invoke()
			Write-Warning "[!] User Impersonation failed, LastError: $err"
			# breathe for a second
			Start-Sleep -s 1
		}
				
	}
			
	# Step 1 - OpenSCManager()
	# 0xF003F = SC_MANAGER_ALL_ACCESS
	#   http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
	# "[*] Opening service manager"
	$ManagerHandle = $OpenSCManagerA.Invoke("\\$ComputerName", "ServicesActive", 0xF003F)
	Write-Debug "[*] Service manager handle: $ManagerHandle"

	# if we get a non-zero handle back, everything was successful
	if ($ManagerHandle -and ($ManagerHandle -ne 0)){

		# Step 2 - CreateService()
		# 0xF003F = SC_MANAGER_ALL_ACCESS
		# 0x10 = SERVICE_WIN32_OWN_PROCESS
		# 0x3 = SERVICE_DEMAND_START
		# 0x1 = SERVICE_ERROR_NORMAL
		# "[*] Creating new service: '$ServiceName'"
		$ServiceHandle = $CreateServiceA.Invoke($ManagerHandle, $ServiceName, $ServiceName, 0xF003F, 0x10, 0x3, 0x1, $Command, $null, $null, $null, $null, $null)
		Write-Debug "[*] CreateServiceA Handle: $ServiceHandle"

		if ($ServiceHandle -and ($ServiceHandle -ne 0)){

			Write-Debug "[*] Service successfully created"

			# Step 3 - CloseServiceHandle() for the service handle
			# "[*] Closing service handle"
			$t = $CloseServiceHandle.Invoke($ServiceHandle)

			# Step 4 - OpenService()
			# "[*] Opening the service '$ServiceName'"
			$ServiceHandle = $OpenServiceA.Invoke($ManagerHandle, $ServiceName, 0xF003F)
			Write-Debug "[*] OpenServiceA handle: $ServiceHandle"

			if ($ServiceHandle -and ($ServiceHandle -ne 0)){

				# Step 5 - StartService()
				# "[*] Starting the service"
                $val = $StartServiceA.Invoke($ServiceHandle, $null, $null)
			

				# if we successfully started the service, let it breathe and then delete it
				if ($val -ne 0){
					Write-Debug "[*] Remote Service successfully started"
					# breathe for a second
					Start-Sleep -s 1
				}
				else{
					# error codes - http://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx
					$err = $GetLastError.Invoke()
					if ($err -eq 1053){
						#Write-Warning "[*] Command didn't respond to start"
					}
					else{
						Write-Warning "[!] StartService failed, LastError: $err"
						#"[!] StartService failed, LastError: $err"
					}
					# breathe for a second
					Start-Sleep -s 1
				}

				# start cleanup
				# Step 6 - DeleteService()
				# "[*] Deleting the service '$ServiceName'"
				$val = $DeleteService.invoke($ServiceHandle)
						
				if ($val -eq 0){
					# error codes - http://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx
					$err = $GetLastError.Invoke()
					Write-Warning "[!] DeleteService failed, LastError: $err"
				}
				else{
					Write-Debug "[*] Service successfully deleted"
				}
						
				# Step 7 - CloseServiceHandle() for the service handle 
				# "[*] Closing the service handle"
				$val = $CloseServiceHandle.Invoke($ServiceHandle)
				Write-Debug "[*] Service handle closed off"

			}
			else{
				# error codes - http://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx
				$err = $GetLastError.Invoke()
				Write-Warning "[!] OpenServiceA failed, LastError: $err"
				#"[!] OpenServiceA failed, LastError: $err"
			}
		}
		else {
			# error codes - http://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx
			$err = $GetLastError.Invoke()
			Write-Warning "[!] CreateService failed, LastError: $err"
			#"[!] CreateService failed, LastError: $err"
		}

		# final cleanup - close off the manager handle
		# "[*] Closing the manager handle"
		$t = $CloseServiceHandle.Invoke($ManagerHandle)
	}
	else{
		# error codes - http://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx
		$err = $GetLastError.Invoke()
		Write-Warning "[!] OpenSCManager failed, LastError: $err"
		#"[!] OpenSCManager failed, LastError: $err"
	}
			
	$RevertToSelf.Invoke()
} # End Invoke-PSExec

# Experimental w/ PSReflect
function Invoke-PsExec2 {
<#
	.SYNOPSIS

		This function is a rough port of Metasploit's psexec functionality.
		It utilizes Windows API calls to open up the service manager on
		a remote machine, creates/run a service to run a command, and then 
		cleans everything up.

		Adapted from @harmjoy's Invoke-PSExec which came from MSF's version (see links).
		I removed some of the stuff we didn't need in PSHunt and added the ability to 
		impersonate an account for remote execution to off domain systems.

		Project: PSHunt
		Author: Chris Gerritz (Github @singlethreaded) (Twitter @gerritzc)
		Original Author: @harmj0y
		Company: Infocyte, Inc.
		License: BSD 3-Clause
		Required Dependencies: PSReflect
		Optional Dependencies: None

	.PARAMETER ComputerName

		ComputerName to run the command on.

	.PARAMETER Command

		Binary path (or Windows command) to execute.

	.PARAMETER ServiceName

		The name of the service to create, defaults to "PSHuntSvc"

	.EXAMPLE

		PS C:\> Invoke-PsExec -ComputerName 192.168.50.200 -Command "net user backdoor password123 /delete"

		Deletes a user named backdoor on the 192.168.50.200 host.

	.EXAMPLE

		PS C:\> Invoke-PsExec -ComputerName 192.168.50.200 -Credentials (Get-Credential) -Command "cmd /c Powershell.exe -File C:\Windows\Temp\survey.ps1" -ServiceName pshuntsvc

		Runs the powershell script C:\Windows\Temp\survey.ps1 using a temporary service called "pshuntsvc"
		Advapi32:CreateServiceA is being difficult so I could only get powershell scripts to work with cmd /c powershell.exe.  
		I might fix this later but for now it works.

	.LINK
	
		https://github.com/HarmJ0y/Misc-PowerShell/blob/master/Invoke-PsExec.ps1
		https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/smb/psexec.rb
		https://github.com/rapid7/metasploit-framework/blob/master/tools/psexec.rb
#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)] 
		[String]
		$ComputerName,

		[Parameter(Mandatory = $True)]
		[ValidateNotNullOrEmpty()]
		[String]
		$Command,

		[String]
		$ServiceName = "PSHuntSvc",

		[System.Management.Automation.PSCredential]
		$Credential
	)

	$Mod = New-InMemoryModule -ModuleName PSExec

        $FunctionDefinitions = @(
		    (func kernel32 GetLastError ([Int]) @()),
            (func advapi32 OpenSCManagerA ([IntPtr]) @( [String], [String], [Int])  -SetLastError),	
            (func advapi32 OpenServiceA ([IntPtr]) @([IntPtr], [String], [Int]) -SetLastError),
            (func advapi32 CreateServiceA ([IntPtr]) @( [IntPtr], [String], [String], [Int], [Int], [Int], [Int], [String], [String], [Int], [Int], [Int], [Int]) -SetLastError),
            (func advapi32 StartServiceA ([IntPtr]) @( [IntPtr], [Int], [String]) -SetLastError),
            (func advapi32 DeleteService ([IntPtr]) @( [IntPtr] ) -SetLastError),
			(func advapi32 LogonUserA ([Bool]) @( [String], [String], [String], [Int], [Int], [IntPtr].MakeByRefType() ) -SetLastError),
			(func advapi32 ImpersonateLoggedOnUser ([Bool]) @( [IntPtr] ) -SetLastError),
			(func advapi32 RevertToSelf ([Void]) @() -SetLastError),
			(func advapi32 CloseServiceHandle ([Int]) @([IntPtr]) -SetLastError)
        )

        $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32PSExec'
        $Kernel32 = $Types['kernel32']
		$Advapi32 = $Types['advapi32']
 

	if ($Credential) {
        Write-Verbose "Using Credentials"
        if (!$Credential.GetNetworkCredential().Domain) {
            # Go with non-domain name
            $Domain = $ComputerName
        } else {
            $Domain = $Credential.GetNetworkCredential().Domain
        }
		
		# Step 0 - LogonUser to create a user token with new username/pass, then force this thread to impersonate it.
		# https://msdn.microsoft.com/en-us/library/windows/desktop/aa378184(v=vs.85).aspx
		# LOGON32_LOGON_NEW_CREDENTIALS = 9        
        $hToken = [IntPtr]::Zero
		$val = $Advapi32::LogonUserA($cred.GetNetworkCredential().Username, $Domain, $Credential.GetNetworkCredential().Password, 9, 3, [ref]$hToken)
		# breathe for a second
		if ($val -AND ($val -ne 0)) {
			# Impersonate user on current thread
            Write-Verbose "Impersonating $($cred.GetNetworkCredential().Username), Domain: $Domain"
			$val = $Advapi32::ImpersonateLoggedOnUser($hToken)
			if (!$val) {
				$err = $Kernel32::GetLastError()
				Write-Warning "[!] User Impersonation failed, LastError: $err"
				return
			}
		}
		else {
			# error codes - http://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx
			$err = $Kernel32::GetLastError()
			Write-Warning "[!] User Impersonation failed, LastError: $err"
			return
		}	
	}
		
	# Step 1 - OpenSCManager()
	# 0xF003F = SC_MANAGER_ALL_ACCESS
	#   http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
	Write-Verbose "[*] Opening service manager"
	$ManagerHandle = $Advapi32::OpenSCManagerA("\\$ComputerName", "ServicesActive", 0xF003F)
	Write-Verbose "[*] Service manager handle: $ManagerHandle"
	if (!$ManagerHandle -OR ($ManagerHandle -eq 0)){
		$err = $Kernel32::GetLastError()
		Write-Warning "Failed to open Service Manager.  Error: $err"
		#return
	}
	
	# Step 2 - CreateService()
	# 0xF003F = SC_MANAGER_ALL_ACCESS
	# 0x10 = SERVICE_WIN32_OWN_PROCESS
	# 0x3 = SERVICE_DEMAND_START
	# 0x1 = SERVICE_ERROR_NORMAL
	Write-Verbose "[*] Creating new service: '$ServiceName'"
	$ServiceHandle = $Advapi32::CreateServiceA($ManagerHandle, $ServiceName, $ServiceName, 0xF003F, 0x10, 0x3, 0x1, $Command, $null, $null, $null, $null, $null)
	Write-Verbose "[*] CreateServiceA Handle: $ServiceHandle"
	if (!$ServiceHandle -OR ($ServiceHandle -eq 0)){
		# error codes - http://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx
		$err = $Kernel32::GetLastError()
		Write-Warning "[!] CreateService failed, LastError: $err"
		#return
	}
	
	# Step 3 - CloseServiceHandle() for the service handle
	Write-Verbose "[*] Closing service handle"
	$t = $Advapi32::CloseServiceHandle($ServiceHandle)
	Start-Sleep -s 1
	
	# Step 4 - OpenService()
	Write-Verbose "[*] Opening the service '$ServiceName'"	
	$ServiceHandle = $Advapi32::OpenServiceA($ManagerHandle, $ServiceName, 0xF003F)
	Write-Verbose "[*] OpenServiceA handle: $ServiceHandle"
	if ($ServiceHandle -and ($ServiceHandle -ne 0)){
		$err = $Kernel32::GetLastError()
		Write-Warning "[!] OpenServiceA failed, LastError: $err"
	}
	
	# Step 5 - StartService()
	Write-Verbose "[*] Starting the service"
	$val = $Advapi32::StartServiceA($ServiceHandle, $null, $null)
	Start-Sleep -s 1
	if ($val -eq 0){
		$err = $Kernel32::GetLastError()
		if ($err -eq 1053){
			Write-Warning "[*] Command didn't respond to start"
		} else {
			Write-Warning "[!] StartServiceA failed, LastError: $err"
		}
	}
	
	# start cleanup
	# Step 6 - DeleteService()
	Write-Verbose "[*] Deleting the service '$ServiceName'"
	$val = $Advapi32::DeleteService($ServiceHandle)
			
					
	# Step 7 - CloseServiceHandle() for the service handle 
	Write-Verbose "[*] Closing the service handle"
	$val = $Advapi32::CloseServiceHandle($ServiceHandle)
	Write-Debug "[*] Service handle closed off"

	# final cleanup - close off the manager handle
	Write-Verbose "[*] Closing the manager handle"
	$t = $Advapi32::CloseServiceHandle($ManagerHandle)

	$Advapi32::RevertToSelf()

} # End Invoke-PSExec
	


