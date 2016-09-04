# PSHunt

PSHunt is a Powershell Threat Hunting Module designed to scan remote endpoints* for indicators of compromise or survey them for more comprehensive information related to state of those systems (active processes, autostarts, configurations, and/or logs).  

PSHunt began as the precurser to Infocyte's commercial product, [Infocyte HUNT](http://www.infocyte.com/products), and is now being open sourced for the benefit of the DFIR community.

[Read More](https://good-hunting.ghost.io/2016/09/01/pshunt-powershell-threat-hunting-project/)

*Currently just Windows

#### PSHunt Structure

PSHunt is divided into several modules, functions, and folders.  The below gives an outline of the grouping of these functions and upcoming posts will describe how how to use them with examples and screenshots.

##### Discovery

Discovery functions and cmdlets are used to identify hosts on the network and build a target list that can be ingested by the scanners and survey deployment cmdlets. 
`Get-HuntTargets` `Invoke-HuntPortScan`

##### Scanners

Scans are modular queries that take in a remote ComputerName argument and output a Powershell object.  The utility `Invoke-HuntScan` is used to initiate the selected scan against your target list.
`Scan_OSInfo.ps1`

##### Surveys

Surveys are scripts that are deployed to remote hosts to collect comprehensive information from the host.  Running locally allows the scripts to dig deeper into the operating system than what remote WMI or registry queries normally allow.
`Survey.ps1`
`SurveyLogs.ps1`

##### Utilities

Utility functions provide the base functionality for deployment and execution of surveys and scans.  
`Invoke-HuntSurvey` `Get-HuntSurveyResults` `Invoke-HuntScanner`

##### Analysis

There are two types of analysis functions:

* **Survey Analysis**

 Survey Analysis functions provide the framework for analysing and displaying survey and scan results.
 
 `Initialize-HuntReputation` `Update-HuntObject` `Group-HuntObject`
 
* **File Analysis** 
File Analysis functions are a set of utilities to analyze files and malware.

 `Get-Entropy` `Get-VTReport` `Get-Hashes`


##### Libraries (Lib)

Libraries are 3rd party tools that have been incorporated to enable additional analysis or are other projects (i.e. Posh-VirusTotal) that are utilized by the framework.
`7zip` `Posh-VirusTotal`

##### Reputation Lists

Reputation lists include hashes from the NIST NSRL Database, baselined virtual machines provided by Infocyte, and also is updated with any VirusTotal submission made using PSHunt's `Get-VTReport`.  These lists are loaded into a global memory variable by `Initialize-HuntReputation` and is compared against by `Update-HuntObject`.


### Project Logistics

PSHunt will be maintained on [Infocyte's Github Repo](https://github.com/Infocyte/PSHunt).  I'll continue to manage the code base, fix bugs, and add new features as time allows.  I welcome comments and suggests, bug identification, and code commits.  Feel free to use the code in your own projects and cmdlets as well.  Most of the code is under the Apache License 2.0 which is pretty liberal but I ask that attribution remain.  Some code that was pulled from or inspired by other projects like Powersploit are under the same licenses the original code was in (mostly BSD 3-Clause).

####  Attributions
I have learned from and, in some cases, borrowed code from other Powershell security gurus within the community. Those individuals include the below mentioned and a few others who will have attribution within applicable function documentation:

###### Jared Atkinson *(@jaredcatkinson)* 
* **Blog**: http://www.invoke-ir.com
###### Matt Graeber *(@mattifestation)* 
* **Blog**: http://www.exploit-monday.com
###### Chris Campbell *(@obscuresec)* 
* **Blog**: http://obscuresecurity.blogspot.com
###### Joe Bialek *(@clymb3r)* 
* **Blog**: https://clymb3r.wordpress.com
