param(
    [string]$GhidraRoot = 'C:\Users\Mazum\Desktop\ghidra_12.1.2_PUBLIC_20260605\ghidra_12.1.2_PUBLIC',
    [string]$WorkRoot = (Join-Path $PSScriptRoot 'work'),
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$expectedRevision = 'c0f584bf229fffba61b36431f3ce30c0c3e4e682'
$properties = Get-Content -LiteralPath (Join-Path $GhidraRoot 'Ghidra\application.properties')
$version = (($properties | Select-String '^application.version=').Line -split '=', 2)[1]
$revision = (($properties | Select-String '^application.revision.ghidra=').Line -split '=', 2)[1]
if ($version -ne '12.1.2' -or $revision -ne $expectedRevision) { throw "Unexpected Ghidra identity $version/$revision" }
$analyze = Join-Path $GhidraRoot 'support\analyzeHeadless.bat'
$bsim = Join-Path $GhidraRoot 'support\bsim.bat'
foreach ($tool in @($analyze, $bsim)) { if (-not (Test-Path -LiteralPath $tool)) { throw "Missing tool $tool" } }

$resolvedWork = [IO.Path]::GetFullPath($WorkRoot)
$allowedRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'work'))
if ($resolvedWork -ne $allowedRoot -and -not $resolvedWork.StartsWith($allowedRoot + [IO.Path]::DirectorySeparatorChar)) {
    throw "WorkRoot must remain under $allowedRoot"
}
if ($Force -and (Test-Path -LiteralPath $resolvedWork)) { Remove-Item -LiteralPath $resolvedWork -Recurse -Force }
$inputRoot = Join-Path $resolvedWork 'input'
$projectRoot = Join-Path $resolvedWork 'project'
$signatureRoot = Join-Path $resolvedWork 'signatures'
$databaseRoot = Join-Path $resolvedWork 'database'
$queryRoot = Join-Path $resolvedWork 'queries'
foreach ($dir in @($inputRoot, $projectRoot, $signatureRoot, $databaseRoot, $queryRoot)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

$manifestPath = Join-Path $PSScriptRoot '..\corpus\build\build-manifest.json'
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
foreach ($entry in $manifest.entries) {
    $source = [IO.Path]::GetFullPath($entry.binaryPath)
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash.ToLowerInvariant() -ne $entry.binarySha256) { throw "$($entry.id) hash drift" }
    Copy-Item -LiteralPath $source -Destination (Join-Path $inputRoot "$($entry.id).dll") -Force
}

$projectName = 'HexCoreSemanticAtlas'
if (-not (Test-Path -LiteralPath (Join-Path $projectRoot "$projectName.gpr"))) {
    & $analyze $projectRoot $projectName -import $inputRoot -recursive -overwrite -analysisTimeoutPerFile 300
    if ($LASTEXITCODE -ne 0) { throw "Ghidra import failed with $LASTEXITCODE" }
}

$databasePath = (Join-Path $databaseRoot 'semantic-atlas').Replace('\', '/')
$databaseUrl = if ($databasePath -match '^([A-Za-z]):/(.*)$') { "file:/$($Matches[1]):/$($Matches[2])" } else { "file:$databasePath" }
if (-not (Get-ChildItem -LiteralPath $databaseRoot -File -ErrorAction SilentlyContinue)) {
    & $bsim createdatabase $databaseUrl medium_nosize
    if ($LASTEXITCODE -ne 0) { throw "BSim database creation failed with $LASTEXITCODE" }
}

$projectUrlPath = $projectRoot.Replace('\', '/')
$projectUrl = if ($projectUrlPath -match '^([A-Za-z]):/(.*)$') { "ghidra:/$($Matches[1]):/$($Matches[2])/$projectName" } else { "ghidra:/$projectUrlPath/$projectName" }
if (-not (Get-ChildItem -LiteralPath $signatureRoot -File -ErrorAction SilentlyContinue | Select-Object -First 1)) {
    & $bsim generatesigs $projectUrl $signatureRoot --bsim $databaseUrl
    if ($LASTEXITCODE -ne 0) { throw "BSim signature generation failed with $LASTEXITCODE" }
    & $bsim commitsigs $databaseUrl $signatureRoot
    if ($LASTEXITCODE -ne 0) { throw "BSim signature commit failed with $LASTEXITCODE" }
}

foreach ($entry in $manifest.entries) {
    $program = "$($entry.id).dll"
    $output = Join-Path $queryRoot "$($entry.id).json"
    & $analyze $projectRoot "$projectName/input" -process $program -noanalysis -scriptPath $PSScriptRoot -postScript QueryFunctionAtlas.java $databaseUrl $output 0.0 32
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $output)) { throw "BSim query failed for $program" }
}

$runManifest = [ordered]@{
    schemaVersion = 1
    ghidraVersion = $version
    ghidraRevision = $revision
    databaseTemplate = 'medium_nosize'
    corpusManifestSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $manifestPath).Hash.ToLowerInvariant()
    queryFiles = @(Get-ChildItem -LiteralPath $queryRoot -Filter '*.json' -File | Sort-Object Name | ForEach-Object {
        [ordered]@{ path = $_.Name; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant() }
    })
}
$runManifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $resolvedWork 'run-manifest.json') -Encoding utf8
Write-Output "BSim completed: $($runManifest.queryFiles.Count) query files in $queryRoot"
