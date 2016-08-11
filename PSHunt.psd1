@{
# Script module or binary module file associated with this manifest.
ModuleToProcess = 'psHunt.psm1'

# Version number of this module.
ModuleVersion = '0.7.0.0'

# ID used to uniquely identify this module
GUID = '3d8e67d5-1542-40da-8e6a-b5e9af0e3f1f'

# Author of this module
Author = 'Chris Gerritz', 'Russ Morris'

# Company or vendor of this module
CompanyName = 'Infocyte, Inc.'

# Copyright statement for this module
Copyright = 'BSD 3-Clause unless explicitly noted otherwise'

# Description of the functionality provided by this module
Description = 'Threat Hunting Module'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '4.0'

# Assemblies that must be loaded prior to importing this module
RequiredAssemblies = @()

# Format files (.ps1xml) to be loaded when importing this module
FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
NestedModules = @()

# Functions to export from this module
FunctionsToExport = @(	'Start-RemoteProcess',
						'Invoke-DownloadFile',
						'Convert-BinaryToString',
						'Convert-StringToBinary',
						'Get-RemoteRegistryValue',
						'Invoke-HuntSurvey',
						'Get-HuntSurveyResults',
						'Test-TCPPort',
						'Test-TCPPorts',
						'Get-RemoteArchitecture',
						'Get-RemotePowershellVersion',
						'Get-RemoteOperatingSystem',
						'Get-Strings',
						'Get-Entropy',
						'Invoke-Sigcheck',
						'Get-Hashes',
						'Initialize-HuntReputation',
						'Update-HuntObject',
						'Get-HuntVTStatus',
						'Group-HuntObjects',
						'Get-VTReport',
						'Invoke-VTScan',
						'New-VTComment',
						'Invoke-VTRescan'
					)

# Cmdlets to export from this module
CmdletsToExport = ''

# Variables to export from this module
VariablesToExport = ''

# Aliases to export from this module
AliasesToExport = ''

# List of all modules packaged with this module.
ModuleList = @()
}
