param([string]$OutputRoot = (Join-Path $PSScriptRoot 'build'), [switch]$Force)
$ErrorActionPreference = 'Stop'
$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$vsRoot = (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath).Trim()
if (-not $vsRoot) { throw 'Visual Studio C++ toolchain not found' }
$vcvars = Join-Path $vsRoot 'VC\Auxiliary\Build\vcvarsall.bat'
$clang = 'C:\Program Files\LLVM\bin\clang-cl.exe'
if (-not (Test-Path -LiteralPath $clang)) { throw 'clang-cl.exe not found' }
$source = Join-Path $PSScriptRoot 'semantic_parity.cpp'
New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
$sourceSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash.ToLowerInvariant()
$expected = @((Select-String -LiteralPath $source -Pattern '^// HXGT (\{.+\})$').Matches | ForEach-Object { ($_.Groups[1].Value | ConvertFrom-Json).function } | Sort-Object)
$entries = @()
foreach ($compiler in @(@{id='msvc';exe='cl.exe'},@{id='clangcl';exe=$clang})) {
  foreach ($arch in @('x86','x64')) { foreach ($opt in @(@{id='O0';flag='/Od'},@{id='O2';flag='/O2'})) { foreach ($symbols in @('debug','stripped')) {
    $id="$($compiler.id)-$arch-$($opt.id)-$symbols"; $dir=Join-Path $OutputRoot $id; New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $dll=Join-Path $dir 'semantic_parity.dll'; $pdb=Join-Path $dir 'semantic_parity.pdb'; $obj=Join-Path $dir 'semantic_parity.obj'
    if ($Force) { Get-ChildItem -LiteralPath $dir -File | Remove-Item -Force }
    $target = if ($compiler.id -eq 'clangcl') { if($arch -eq 'x86'){'--target=i686-pc-windows-msvc'}else{'--target=x86_64-pc-windows-msvc'} } else { '' }
    $debugCompile=if($symbols -eq 'debug'){'/Zi'}else{''}; $debugLink=if($symbols -eq 'debug'){'/DEBUG'}else{''}
    $exe=if($compiler.exe -match '\s'){ '"'+$compiler.exe+'"' }else{$compiler.exe}
    $compile=@('/nologo','/LD','/MD','/Brepro','/EHsc','/std:c++20',$target,$opt.flag,$debugCompile,"/Fd:$dir\compile.pdb","/Fo$obj","`"$source`"","/Fe$dll")|Where-Object{$_}
    $link=@('/link','/Brepro',$debugLink,"/PDB:$pdb",'/PDBALTPATH:semantic_parity.pdb')|Where-Object{$_}
    $command="$exe $($compile -join ' ') $($link -join ' ')"
    if (-not (Test-Path -LiteralPath $dll)) { $out = & cmd.exe /d /s /c "call `"$vcvars`" $arch >nul && $command" 2>&1; if ($LASTEXITCODE -ne 0) { throw "Build $id failed:`n$($out -join "`n")" } }
    $dumpbin=(& cmd.exe /d /s /c "call `"$vcvars`" $arch >nul && where dumpbin.exe" | Select-Object -First 1).Trim()
    $raw=& $dumpbin /nologo /exports $dll 2>&1; $exports=@()
    foreach($line in $raw){if($line-match '^\s+\d+\s+[0-9A-Fa-f]+\s+([0-9A-Fa-f]+)\s+(\S+)'){ $decorated=$Matches[2];$logical=$decorated -replace '^[@_]','' -replace '@@?\d+$','';if($expected -contains $logical){$exports+=[ordered]@{name=$logical;decoratedName=$decorated;rva="0x$($Matches[1].ToLowerInvariant())"}}}}
    $actual = @($exports.name | Sort-Object -Unique); if ((Compare-Object $expected $actual).Count -ne 0) { throw "$id export mismatch expected=$($expected.Count) actual=$($actual.Count): $($actual -join ',')" }
    $entries += [ordered]@{id=$id;compiler=$compiler.id;architecture=$arch;optimization=$opt.id;symbols=$symbols;commandLine=$command;sourceSha256=$sourceSha256;binaryPath=$dll;binarySha256=(Get-FileHash $dll -Algorithm SHA256).Hash.ToLowerInvariant();pdbPath=if(Test-Path $pdb){$pdb}else{$null};pdbSha256=if(Test-Path $pdb){(Get-FileHash $pdb -Algorithm SHA256).Hash.ToLowerInvariant()}else{$null};exports=$exports|Sort-Object name}
  }}}
}
$manifest=[ordered]@{schemaVersion=1;corpusId='hexcore-semantic-parity-v1';sourcePath=$source;sourceSha256=$sourceSha256;entries=$entries}
$manifestPath=Join-Path $OutputRoot 'build-manifest.json';$manifest|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $manifestPath -Encoding utf8
$tsx = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\hexcore-hql\node_modules\tsx\dist\cli.mjs'))
& node.exe $tsx (Join-Path $PSScriptRoot 'generate_ground_truth.ts') $manifestPath
if ($LASTEXITCODE -ne 0) { throw 'Ground-truth generation failed' }
Write-Output "Built $($entries.Count) semantic parity binaries: $manifestPath"
