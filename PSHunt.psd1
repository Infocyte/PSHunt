@{
# Script module or binary module file associated with this manifest.
ModuleToProcess = 'PSHunt.psm1'

# Version number of this module.
ModuleVersion = '0.7.0.0'

# ID used to uniquely identify this module
GUID = '3d8e67d5-1542-40da-8e6a-b5e9af0e3f1f'

# Author of this module
Author = @('Chris Gerritz', 'Russ Morris')

# Company or vendor of this module
CompanyName = 'Infocyte, Inc.'

# Copyright statement for this module
Copyright = 'Apache License 2.0 unless explicitly noted otherwise'

# Description of the functionality provided by this module
Description = 'Threat Hunting Module'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '4.0'

# Assemblies that must be loaded prior to importing this module
RequiredAssemblies = @()

# Format files (.ps1xml) to be loaded when importing this module
FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
NestedModules = @( 	'lib\Posh-VirusTotal\Posh-VirusTotal.psm1',
					'lib\PSReflect\PSReflect.psm1'  )

# Functions to export from this module
FunctionsToExport = @(	
	'Get-HuntTargets',
	'Invoke-HuntPortScan',
	'Expand-IPList',
	'Invoke-PSipcalc ',
	'Start-RemoteProcess',
	'Invoke-HuntScanner',
	'Invoke-HuntSurvey',
	'Get-HuntSurveyResults',
	'Initialize-HuntReputation',
	'Update-HuntObject',
	'Get-HuntVTStatus',
	'Group-HuntObjects',
	'Test-TCPPort',
	'Test-TCPPorts',
	'Get-Strings',
	'Get-Entropy',
	'Invoke-Sigcheck',
	'Get-Hashes',
	'Convert-BinaryToString',
	'Convert-StringToBinary',
	'Get-VTReport',
	'Invoke-VTScan'
)

# Cmdlets to export from this module
CmdletsToExport = ''

# Variables to export from this module
VariablesToExport = ''

# Aliases to export from this module
AliasesToExport = ''

# List of all modules packaged with this module.
ModuleList = @()

PrivateData = @{

	# Tags applied to this module. These help with module discovery in online galleries.
	Tags = @('security','threat hunting','hunt','incident response','dfir')

	# A URL to the license for this module.
	LicenseUri = 'http://www.apache.org/licenses/LICENSE-2.0.html'

	# A URL to the main website for this project.
	ProjectUri = 'https://github.com/Infocyte/PSHunt'
}
}
