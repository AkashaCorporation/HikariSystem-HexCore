#---------------------------------------------------------------------------------------------
#  Copyright (c) Akasha Corporation. All rights reserved.
#  Licensed under the MIT License. See License.txt in the project root for license information.
#---------------------------------------------------------------------------------------------

[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)]
	[string]$OutDir
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$source = Join-Path $scriptRoot 'fixtures\issue30-hidden-function.asm'
$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'

if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
	throw "Fixture source is missing: $source"
}
if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
	throw "vswhere.exe is missing: $vswhere"
}

$installation = & $vswhere -latest -products * -version '[17.0,18.0)' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -format json |
	ConvertFrom-Json |
	Select-Object -First 1
if (-not $installation) {
	throw 'Visual Studio 2022 C++ x64 tools are required for this fixture.'
}

$devCmd = Join-Path $installation.installationPath 'Common7\Tools\VsDevCmd.bat'
if (-not (Test-Path -LiteralPath $devCmd -PathType Leaf)) {
	throw "VsDevCmd.bat is missing: $devCmd"
}

$resolvedOutDir = [IO.Path]::GetFullPath($OutDir)
New-Item -ItemType Directory -Path $resolvedOutDir -Force | Out-Null
$objectPath = Join-Path $resolvedOutDir 'issue30-hidden-function.obj'
$binaryPath = Join-Path $resolvedOutDir 'issue30-hidden-function.exe'
$mapPath = Join-Path $resolvedOutDir 'issue30-hidden-function.map'

$compile = @(
	'call', ('"{0}"' -f $devCmd), '-no_logo', '-arch=x64', '-host_arch=x64', '>', 'nul', '&&',
	'ml64', '/nologo', '/c', ('/Fo"{0}"' -f $objectPath), ('"{0}"' -f $source), '&&',
	'link', '/nologo', ('/out:"{0}"' -f $binaryPath), '/entry:entrypoint', '/subsystem:console',
	'/machine:x64', '/nodefaultlib', '/incremental:no', '/debug:none', '/opt:noref', '/opt:noicf',
	'/fixed', '/dynamicbase:no', '/nxcompat', '/brepro', '/filealign:512', ('/map:"{0}"' -f $mapPath),
	('"{0}"' -f $objectPath)
) -join ' '

& cmd.exe /d /s /c $compile
if ($LASTEXITCODE -ne 0) {
	throw "Fixture build failed with exit code $LASTEXITCODE"
}

$bytes = [IO.File]::ReadAllBytes($binaryPath)
if ($bytes.Length -lt 512 -or [Text.Encoding]::ASCII.GetString($bytes, 0, 2) -ne 'MZ') {
	throw 'Fixture is not a valid PE image.'
}

$peOffset = [BitConverter]::ToUInt32($bytes, 0x3c)
if ([Text.Encoding]::ASCII.GetString($bytes, $peOffset, 4) -ne "PE`0`0") {
	throw 'Fixture PE signature is missing.'
}

$coffOffset = $peOffset + 4
$sectionCount = [BitConverter]::ToUInt16($bytes, $coffOffset + 2)
$pointerToSymbols = [BitConverter]::ToUInt32($bytes, $coffOffset + 8)
$symbolCount = [BitConverter]::ToUInt32($bytes, $coffOffset + 12)
$optionalSize = [BitConverter]::ToUInt16($bytes, $coffOffset + 16)
$optionalOffset = $coffOffset + 20
$magic = [BitConverter]::ToUInt16($bytes, $optionalOffset)
if ($magic -ne 0x20b) {
	throw "Fixture optional-header magic is not PE32+: 0x$($magic.ToString('x'))"
}

$imageBase = [BitConverter]::ToUInt64($bytes, $optionalOffset + 24)
$dataDirectoryOffset = $optionalOffset + 112
$exportSize = [BitConverter]::ToUInt32($bytes, $dataDirectoryOffset + 4)
$exceptionSize = [BitConverter]::ToUInt32($bytes, $dataDirectoryOffset + 3 * 8 + 4)
$sectionTable = $optionalOffset + $optionalSize
$text = $null
for ($index = 0; $index -lt $sectionCount; $index++) {
	$offset = $sectionTable + $index * 40
	$name = [Text.Encoding]::ASCII.GetString($bytes, $offset, 8).Trim([char]0)
	if ($name -eq '.text') {
		$text = [pscustomobject]@{
			virtualSize = [BitConverter]::ToUInt32($bytes, $offset + 8)
			virtualAddress = [BitConverter]::ToUInt32($bytes, $offset + 12)
			rawSize = [BitConverter]::ToUInt32($bytes, $offset + 16)
			rawAddress = [BitConverter]::ToUInt32($bytes, $offset + 20)
		}
		break
	}
}
if (-not $text) {
	throw 'Fixture .text section is missing.'
}

$hiddenOffset = 0x37
$hiddenBytes = [byte[]](0x41,0x31,0xd2,0x8d,0x44,0x51,0x07,0x45,0x85,0xc0,0x41,0x0f,0x45,0xc0,0xc3)
$adjacentBytes = [byte[]](0x48,0x83,0xc0,0x7f,0xc3)
$hiddenRaw = [int]$text.rawAddress + $hiddenOffset
for ($index = 0; $index -lt $hiddenBytes.Length; $index++) {
	if ($bytes[$hiddenRaw + $index] -ne $hiddenBytes[$index]) {
		throw "Hidden function byte mismatch at +0x$($index.ToString('x'))"
	}
}
for ($index = 0; $index -lt $adjacentBytes.Length; $index++) {
	if ($bytes[$hiddenRaw + $hiddenBytes.Length + $index] -ne $adjacentBytes[$index]) {
		throw "Adjacent control byte mismatch at +0x$($index.ToString('x'))"
	}
}
if ($pointerToSymbols -ne 0 -or $symbolCount -ne 0) {
	throw 'Fixture unexpectedly retains a COFF symbol table.'
}
if ($exportSize -ne 0 -or $exceptionSize -ne 0) {
	throw 'Fixture unexpectedly contains exports or an exception/.pdata directory.'
}

$binarySha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $binaryPath).Hash.ToLowerInvariant()
$sourceSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash.ToLowerInvariant()
$sha256 = [Security.Cryptography.SHA256]::Create()
try {
	$hiddenDigest = $sha256.ComputeHash($hiddenBytes)
} finally {
	$sha256.Dispose()
}
$hiddenSha256 = -join ($hiddenDigest | ForEach-Object { $_.ToString('x2') })
$hiddenRva = [uint64]$text.virtualAddress + $hiddenOffset
$hiddenVa = $imageBase + $hiddenRva
$adjacentRva = $hiddenRva + [uint64]$hiddenBytes.Length
$manifest = [ordered]@{
	schemaVersion = 1
	fixture = 'issue30-hidden-function-pe64'
	generatedAt = (Get-Date).ToUniversalTime().ToString('o')
	binary = [ordered]@{
		path = $binaryPath
		sha256 = $binarySha256
		bytes = $bytes.Length
		format = 'PE32+'
		architecture = 'x86_64'
		imageBase = ('0x{0:x}' -f $imageBase)
	}
	source = [ordered]@{ path = $source; sha256 = $sourceSha256 }
	toolchain = [ordered]@{
		visualStudio = $installation.installationVersion
		installationPath = $installation.installationPath
	}
	contract = [ordered]@{
		textRva = ('0x{0:x}' -f [uint64]$text.virtualAddress)
		hiddenFunctionRva = ('0x{0:x}' -f $hiddenRva)
		hiddenFunctionVa = ('0x{0:x}' -f $hiddenVa)
		hiddenFunctionSize = $hiddenBytes.Length
		hiddenFunctionSha256 = $hiddenSha256
		adjacentControlRva = ('0x{0:x}' -f $adjacentRva)
		adjacentControlSize = $adjacentBytes.Length
		coffSymbols = 0
		exportDirectorySize = 0
		exceptionDirectorySize = 0
	}
}
$manifestPath = Join-Path $resolvedOutDir 'issue30-hidden-function.manifest.json'
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8

[pscustomobject]@{
	binary = $binaryPath
	binarySha256 = $binarySha256
	hiddenFunctionVa = ('0x{0:x}' -f $hiddenVa)
	hiddenFunctionSize = $hiddenBytes.Length
	manifest = $manifestPath
} | ConvertTo-Json -Compress
