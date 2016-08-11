function Invoke-ThreadedFunction
{
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String[]]$ComputerName,
        
		[Parameter(Position = 1, Mandatory = $True)]
        [System.Management.Automation.ScriptBlock]$ScriptBlock,
        
		[Parameter(Position = 2)]
		[Hashtable]$ScriptParameters,
        
		[Int]$Threads = 20,
        
		[Int]$Timeout = 60
    )
    
    begin
    {
        
        if ($PSBoundParameters['Debug'])
        {
            $DebugPreference = 'Continue'
        }
        
        Write-Verbose "[*] Total number of hosts: $($ComputerName.count)"
        
        # Adapted from:
        #   http://powershell.org/wp/forums/topic/invpke-parallel-need-help-to-clone-the-current-runspace/
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $SessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()
        
        # threading adapted from
        # https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1#L407
        #   Thanks Carlos!
        # create a pool of maxThread runspaces
        $Pool = [runspacefactory]::CreateRunspacePool(1, $Threads, $SessionState, $Host)
        $Pool.Open()
        
		#$OFS = "`r`n"
        #$Code = [ScriptBlock]::Create($(Get-Content $Command))
        #Remove-Variable OFS
		
        $Jobs = @()
        $PS = @()
        $Wait = @()
        
        $Counter = 0
    }
    
    process
    {
        
        ForEach ($Computer in $ComputerName)
        {
            
            # make sure we get a server name
            if ($Computer -ne '')
            {
                
                While ($($Pool.GetAvailableRunspaces()) -le 0)
                {
                    Start-Sleep -MilliSeconds 100
                }
                
                # create a "powershell pipeline runner"
                $PS += [powershell]::create()
                $PS[$Counter].runspacepool = $Pool
                
                # add the script block + arguments
                $Null = $PS[$Counter].AddScript($ScriptBlock).AddParameter('ComputerName', $Computer)
                if ($ScriptParameters)
                {
                    ForEach ($Param in $ScriptParameters.GetEnumerator())
                    {
                        $Null = $PS[$Counter].AddParameter($Param.Name, $Param.Value)
                    }
                }
                
                # start job
                $Jobs += $PS[$Counter].BeginInvoke();
                
                # store wait handles for WaitForAll call
                $Wait += $Jobs[$Counter].AsyncWaitHandle
            }
            $Counter = $Counter + 1
        }
    }
    
    end
    {
        
        Write-Verbose "Waiting for scanning threads to finish..."
        $WaitTimeout = Get-Date
        
        # set a 60 second timeout for the scanning threads
        while ( $($Jobs | Where-Object { $_.IsCompleted -eq $False }).count -gt 0 )
        {
		
			 
			if ( $($($(Get-Date) - $WaitTimeout).totalSeconds) -gt $Timeout ) {
				
			}
            Start-Sleep -MilliSeconds 100
        }
        
        # end async call
        for ($y = 0; $y -lt $Counter; $y++)
        {
            
            try
            {
                # complete async job
                $PS[$y].EndInvoke($Jobs[$y])
                
            }
            catch
            {
                Write-Warning "error: $_"
            }
            finally
            {
                $PS[$y].Dispose()
            }
        }
        
        $Pool.Dispose()
        Write-Verbose "All threads completed!"
    }
}