param(
    [string]$OutputRoot = (Join-Path $PSScriptRoot 'build'),
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'vswhere.exe not found' }
$vsRoot = (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath).Trim()
if (-not $vsRoot) { throw 'Visual Studio C++ toolchain not found' }
$vcvars = Join-Path $vsRoot 'VC\Auxiliary\Build\vcvarsall.bat'
$clang = 'C:\Program Files\LLVM\bin\clang-cl.exe'
if (-not (Test-Path -LiteralPath $clang)) { throw 'clang-cl.exe not found' }
$source = Join-Path $PSScriptRoot 'semantic_benchmark.c'
$groundTruth = Join-Path $PSScriptRoot 'ground_truth.json'
New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$OutputRoot = (Resolve-Path -LiteralPath $OutputRoot).Path
$manifestPath = Join-Path $OutputRoot 'build-manifest.json'
$priorManifest = if (Test-Path -LiteralPath $manifestPath) { Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json } else { $null }
$sourceSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash.ToLowerInvariant()
$groundTruthSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $groundTruth).Hash.ToLowerInvariant()
$vcvarsSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $vcvars).Hash.ToLowerInvariant()
$expectedExports = @((Get-Content -Raw -LiteralPath $groundTruth | ConvertFrom-Json).functions.PSObject.Properties.Name | Sort-Object)

$matrix = @()
$compilers = @(
    @{ id = 'msvc'; command = 'cl.exe' },
    @{ id = 'clangcl'; command = $clang }
)
$architectures = @('x86', 'x64')
$optimizations = @(
    @{ id = 'O0'; flags = '/Od' },
    @{ id = 'O2'; flags = '/O2' }
)
$symbols = @(
    @{ id = 'debug'; compile = '/Zi'; link = '/DEBUG' },
    @{ id = 'stripped'; compile = ''; link = '' }
)

foreach ($compiler in $compilers) {
    foreach ($architecture in $architectures) {
        foreach ($optimization in $optimizations) {
            foreach ($symbol in $symbols) {
                $id = "$($compiler.id)-$architecture-$($optimization.id)-$($symbol.id)"
                $outDir = Join-Path $OutputRoot $id
                New-Item -ItemType Directory -Force -Path $outDir | Out-Null
                $binary = Join-Path $outDir 'semantic_benchmark.dll'
                $pdb = Join-Path $outDir 'semantic_benchmark.pdb'
                $object = Join-Path $outDir 'semantic_benchmark.obj'
				$binaryExisted = Test-Path -LiteralPath $binary
				if ($Force) {
					foreach ($artifactName in @('semantic_benchmark.dll', 'semantic_benchmark.pdb', 'semantic_benchmark.obj', 'semantic_benchmark.lib', 'semantic_benchmark.exp', 'semantic_benchmark.ilk', 'compile.pdb')) {
						$artifactPath = Join-Path $outDir $artifactName
						if (Test-Path -LiteralPath $artifactPath) { Remove-Item -LiteralPath $artifactPath -Force }
					}
				}
                $compilerCommand = if ($compiler.command -match '\s') { '"' + $compiler.command + '"' } else { $compiler.command }
                $targetFlag = if ($compiler.id -eq 'clangcl') {
                    if ($architecture -eq 'x86') { '--target=i686-pc-windows-msvc' } else { '--target=x86_64-pc-windows-msvc' }
                } else { '' }
                $deterministicFlag = if ($compiler.id -eq 'msvc') { '/experimental:deterministic' } else { '' }
                $pathMapFlag = if ($compiler.id -eq 'msvc') { "/pathmap:$OutputRoot=." } else { "/clang:-ffile-prefix-map=$OutputRoot=." }
                $compileArgs = @('/nologo', '/LD', '/MD', '/Brepro', $deterministicFlag, $pathMapFlag, '/std:c17', '/W3', $targetFlag, $optimization.flags, $symbol.compile, '/D_CRT_SECURE_NO_WARNINGS', "/Fd:$outDir\compile.pdb", "/Fo$object", "`"$source`"", "/Fe$binary") | Where-Object { $_ }
                $linkArgs = @('/link', '/Brepro', $symbol.link, "/PDB:$pdb", '/PDBALTPATH:semantic_benchmark.pdb', 'ntdll.lib', 'advapi32.lib', 'kernel32.lib') | Where-Object { $_ }
                $commandLine = "$compilerCommand $($compileArgs -join ' ') $($linkArgs -join ' ')"
                if (-not (Test-Path -LiteralPath $binary)) {
                    $cmd = "call `"$vcvars`" $architecture >nul && $commandLine"
                    $savedPreference = $ErrorActionPreference
                    $ErrorActionPreference = 'Continue'
                    $buildOutput = & cmd.exe /d /s /c $cmd 2>&1
                    $buildExitCode = $LASTEXITCODE
                    $ErrorActionPreference = $savedPreference
                    if ($buildExitCode -ne 0 -or -not (Test-Path -LiteralPath $binary)) {
                        throw "Build $id failed:`n$($buildOutput -join [Environment]::NewLine)"
                    }
                }

                $bannerCommand = if ($compiler.id -eq 'clangcl') { '"' + $clang + '" --version' } else { 'cl.exe /nologo /Bv /?' }
				$bannerFile = Join-Path $OutputRoot ".compiler-banner-$PID-$architecture.txt"
				try {
					& cmd.exe /d /s /c "call `"$vcvars`" $architecture >nul && $bannerCommand >`"$bannerFile`" 2>&1"
					$bannerExitCode = $LASTEXITCODE
					$bannerRaw = (Get-Content -Raw -LiteralPath $bannerFile).Trim()
				} finally {
					if (Test-Path -LiteralPath $bannerFile) { Remove-Item -LiteralPath $bannerFile -Force }
				}
				if ($bannerExitCode -ne 0) { throw "$id compiler identity command failed with $bannerExitCode" }
				$banner = if ($compiler.id -eq 'msvc') { (($bannerRaw -split "`r?`n" | Select-Object -First 10) -join "`n").Trim() } else { $bannerRaw.Replace("`r`n", "`n") }
                if ($compiler.id -eq 'clangcl' -and $banner -notmatch 'clang version') { throw "$id did not prove ClangCL identity" }
                if ($compiler.id -eq 'msvc' -and $banner -notmatch 'cl\.exe:.*\d+\.\d+') { throw "$id did not prove MSVC identity" }
				$bannerBytes = [Text.Encoding]::UTF8.GetBytes($banner.Replace("`r`n", "`n"))
				$bannerHasher = [Security.Cryptography.SHA256]::Create()
				$compilerBannerSha256 = -join ($bannerHasher.ComputeHash($bannerBytes) | ForEach-Object { $_.ToString('x2') })
				$bannerHasher.Dispose()

                $dumpbin = (& cmd.exe /d /s /c "call `"$vcvars`" $architecture >nul && where dumpbin.exe" 2>$null | Select-Object -First 1).Trim()
                $exportsRaw = & $dumpbin /nologo /exports $binary 2>&1
                $exports = @()
                foreach ($line in $exportsRaw) {
                    if ($line -match '^\s+\d+\s+[0-9A-Fa-f]+\s+([0-9A-Fa-f]+)\s+(bench_[A-Za-z0-9_]+)') {
                        $exports += [ordered]@{ name = $Matches[2]; rva = "0x$($Matches[1].ToLowerInvariant())" }
                    }
                }
                if ($exports.Count -ne 14) { throw "$id exported $($exports.Count) benchmark functions, expected 14" }
				$compilerPath = if ($compiler.id -eq 'clangcl') {
					$clang
				} else {
					(& cmd.exe /d /s /c "call `"$vcvars`" $architecture >nul && where cl.exe" 2>$null | Select-Object -First 1).Trim()
				}
				$compilerSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $compilerPath).Hash.ToLowerInvariant()
				$dumpbinSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $dumpbin).Hash.ToLowerInvariant()
				$actualExports = @($exports.name | Sort-Object)
				if ((Compare-Object -ReferenceObject $expectedExports -DifferenceObject $actualExports).Count -ne 0) {
					throw "$id exports do not match the ground-truth function universe"
				}
				$configurationDocument = [ordered]@{
					compiler = $compiler.id
					compilerSha256 = $compilerSha256
					compilerBannerSha256 = $compilerBannerSha256
					vcvarsSha256 = $vcvarsSha256
					dumpbinSha256 = $dumpbinSha256
					architecture = $architecture
					optimization = $optimization.id
					symbols = $symbol.id
					commandLine = $commandLine.Replace($OutputRoot, '<BUILD_ROOT>')
					sourceSha256 = $sourceSha256
					groundTruthSha256 = $groundTruthSha256
				}
				$configurationBytes = [Text.Encoding]::UTF8.GetBytes(($configurationDocument | ConvertTo-Json -Compress -Depth 8))
				$configurationHasher = [Security.Cryptography.SHA256]::Create()
				$configurationSha256 = -join ($configurationHasher.ComputeHash($configurationBytes) | ForEach-Object { $_.ToString('x2') })
				$configurationHasher.Dispose()

                $entry = [ordered]@{
                    id = $id
                    compiler = $compiler.id
                    compilerPath = $compilerPath
                    compilerBanner = $banner
					compilerBannerSha256 = $compilerBannerSha256
                    architecture = $architecture
                    optimization = $optimization.id
                    symbols = $symbol.id
                    commandLine = $commandLine
					compilerArguments = @($compileArgs)
					linkerArguments = @($linkArgs)
					compilerSha256 = $compilerSha256
					vcvarsPath = $vcvars
					vcvarsSha256 = $vcvarsSha256
					dumpbinPath = $dumpbin
					dumpbinSha256 = $dumpbinSha256
					configurationSha256 = $configurationSha256
                    sourceSha256 = $sourceSha256
                    groundTruthSha256 = $groundTruthSha256
                    binaryPath = $binary
                    binarySha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $binary).Hash.ToLowerInvariant()
                    pdbPath = if (Test-Path -LiteralPath $pdb) { $pdb } else { $null }
                    pdbSha256 = if (Test-Path -LiteralPath $pdb) { (Get-FileHash -Algorithm SHA256 -LiteralPath $pdb).Hash.ToLowerInvariant() } else { $null }
                    exports = $exports | Sort-Object name
                }
				if ($binaryExisted -and -not $Force) {
					$prior = @($priorManifest.entries | Where-Object id -eq $id)
					if ($prior.Count -ne 1 -or $prior[0].configurationSha256 -ne $configurationSha256 -or
						$prior[0].binarySha256 -ne $entry.binarySha256 -or $prior[0].compilerSha256 -ne $compilerSha256 -or $prior[0].compilerBannerSha256 -ne $compilerBannerSha256 -or
						$prior[0].sourceSha256 -ne $sourceSha256 -or $prior[0].groundTruthSha256 -ne $groundTruthSha256) {
						throw "Refusing unproven reuse for $id; rerun with -Force to rebuild it"
					}
				}
                $matrix += $entry
            }
        }
    }
}

$manifest = [ordered]@{
    schemaVersion = 2
    corpusId = 'hexcore-semantic-benchmark-v1'
    generatedAt = (Get-Date).ToUniversalTime().ToString('o')
    visualStudioRoot = $vsRoot
    entries = $matrix
}
$manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifestPath -Encoding utf8
Write-Output "Built $($matrix.Count) verified corpus variants: $manifestPath"
