param(
    [string]$FirstRoot = (Join-Path $PSScriptRoot 'build'),
    [string]$SecondRoot = (Join-Path $PSScriptRoot 'build-repeat'),
    [string]$LlvmPdbUtil = 'C:\Users\Mazum\Desktop\caps\llvm-build\build-mlir\bin\llvm-pdbutil.exe'
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $LlvmPdbUtil)) { throw 'llvm-pdbutil.exe not found' }
$FirstRoot = (Resolve-Path -LiteralPath $FirstRoot).Path
$SecondRoot = (Resolve-Path -LiteralPath $SecondRoot).Path
$first = Get-Content -Raw -LiteralPath (Join-Path $FirstRoot 'build-manifest.json') | ConvertFrom-Json
$second = Get-Content -Raw -LiteralPath (Join-Path $SecondRoot 'build-manifest.json') | ConvertFrom-Json
if ($first.schemaVersion -ne 2 -or $second.schemaVersion -ne 2) { throw 'Both build manifests must use schemaVersion 2' }
if ($first.corpusId -ne $second.corpusId) { throw 'Build matrix corpus identities differ' }
if ($first.entries.Count -ne $second.entries.Count) { throw 'Build matrix entry counts differ' }
if (@($first.entries.id | Sort-Object -Unique).Count -ne $first.entries.Count -or @($second.entries.id | Sort-Object -Unique).Count -ne $second.entries.Count) { throw 'Build manifest entry ids must be unique' }
$sourceSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $PSScriptRoot 'semantic_benchmark.c')).Hash.ToLowerInvariant()
$groundTruthSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $PSScriptRoot 'ground_truth.json')).Hash.ToLowerInvariant()

$results = @()
foreach ($entry in $first.entries) {
    $repeat = $second.entries | Where-Object id -eq $entry.id
    if (-not $repeat) { throw "Missing repeat entry $($entry.id)" }
	if ($entry.sourceSha256 -ne $sourceSha256 -or $repeat.sourceSha256 -ne $sourceSha256 -or $entry.groundTruthSha256 -ne $groundTruthSha256 -or $repeat.groundTruthSha256 -ne $groundTruthSha256) { throw "Source identity failed for $($entry.id)" }
	foreach ($field in @('compiler', 'compilerSha256', 'compilerBannerSha256', 'vcvarsSha256', 'dumpbinSha256', 'configurationSha256', 'architecture', 'optimization', 'symbols')) {
		if (-not $entry.$field -or $entry.$field -ne $repeat.$field) { throw "Toolchain/configuration identity $field differs for $($entry.id)" }
	}
    $binaryEqual = $entry.binarySha256 -eq $repeat.binarySha256
    if (-not $binaryEqual) { throw "Binary determinism failed for $($entry.id)" }
    $pdbSemanticEqual = $true
    $firstPdbSemanticSha256 = $null
    $secondPdbSemanticSha256 = $null
    if ($entry.pdbPath -and $repeat.pdbPath) {
        # Module 1 is the source object (module 0 is the linker-generated EXP).
        # Compare source files and symbols for that module plus the global PDB
        # identity; CRT type-stream insertion order is physically unstable but
        # not part of this corpus's source-known semantic contract.
        $firstDump = (& $LlvmPdbUtil dump -summary -modi=1 -files -symbols $entry.pdbPath 2>&1 | Out-String)
        $secondDump = (& $LlvmPdbUtil dump -summary -modi=1 -files -symbols $repeat.pdbPath 2>&1 | Out-String)
        $normalize = {
            param([string]$text)
			$normalized = $text.Replace($SecondRoot, '<BUILD_ROOT>').Replace($FirstRoot, '<BUILD_ROOT>')
			$normalized = $normalized.Replace('\', '/').Replace("`r`n", "`n")
			$normalized = [regex]::Replace($normalized, 'debug stream: \d+', 'debug stream: <INDEX>')
			$normalized = [regex]::Replace($normalized, '(pdb file ni|src file ni):? \d+', '$1: <INDEX>')
			$normalized = [regex]::Replace($normalized, '\[size = \d+\]', '[size = <SIZE>]')
			$normalized = [regex]::Replace($normalized, '(?m)^\s*\d+ \| ', '  <OFFSET> | ')
			$normalized.Trim()
        }
        $firstNormalized = & $normalize $firstDump
        $secondNormalized = & $normalize $secondDump
		$sha = [Security.Cryptography.SHA256]::Create()
        $firstPdbSemanticSha256 = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($firstNormalized)) | ForEach-Object { $_.ToString('x2') })
        $secondPdbSemanticSha256 = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($secondNormalized)) | ForEach-Object { $_.ToString('x2') })
		$sha.Dispose()
        $pdbSemanticEqual = $firstPdbSemanticSha256 -eq $secondPdbSemanticSha256
        if (-not $pdbSemanticEqual) { throw "PDB semantic determinism failed for $($entry.id)" }
    }
    $results += [ordered]@{
        id = $entry.id
		configurationSha256 = $entry.configurationSha256
		compilerSha256 = $entry.compilerSha256
        binarySha256 = $entry.binarySha256
        binaryByteIdentical = $binaryEqual
        pdbPhysicalSha256 = $entry.pdbSha256
        repeatPdbPhysicalSha256 = $repeat.pdbSha256
        pdbSemanticSha256 = $firstPdbSemanticSha256
        pdbSemanticIdentical = $pdbSemanticEqual
    }
}

$report = [ordered]@{
    schemaVersion = 1
    corpusId = $first.corpusId
    binaryByteIdentical = @($results | Where-Object binaryByteIdentical).Count
    pdbSemanticIdentical = @($results | Where-Object pdbSemanticIdentical).Count
    total = $results.Count
    entries = $results
}
$output = Join-Path $FirstRoot 'repeat-verification.json'
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $output -Encoding utf8
Write-Output "Repeat verification passed: $($results.Count)/$($results.Count) binaries and semantic PDBs ($output)"
