$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath($PSScriptRoot);$wslRoot='/mnt/c'+$root.Substring(2).Replace('\','/')
New-Item -ItemType Directory -Force (Join-Path $root 'build')|Out-Null
$command="set -eu; cd '$wslRoot'; gcc -shared -fPIC -O2 -g -fno-omit-frame-pointer -Wl,--build-id=sha1 -o build/libelf_semantic_dwarf.so elf_semantic.c; cp build/libelf_semantic_dwarf.so build/libelf_semantic_btf.so; LLVM_OBJCOPY=objcopy pahole -J build/libelf_semantic_btf.so; cp build/libelf_semantic_dwarf.so build/libelf_semantic_stripped.so; strip --strip-debug build/libelf_semantic_stripped.so"
& wsl.exe -d kali-linux -u root -e sh -lc $command
if ($LASTEXITCODE -ne 0) { throw 'ELF semantic build failed' }
$artifacts=@('libelf_semantic_dwarf.so','libelf_semantic_btf.so','libelf_semantic_stripped.so')|ForEach-Object{$file=Join-Path $root "build\$_";[ordered]@{name=$_;path=$file;sha256=(Get-FileHash $file -Algorithm SHA256).Hash.ToLowerInvariant()}}
$manifest=[ordered]@{schemaVersion=1;sourceSha256=(Get-FileHash (Join-Path $root 'elf_semantic.c') -Algorithm SHA256).Hash.ToLowerInvariant();compiler='gcc';compilerVersion=(& wsl.exe -d kali-linux -u root -e sh -lc 'gcc -dumpfullversion').Trim();paholeVersion=((& wsl.exe -d kali-linux -u root -e sh -lc 'pahole --version')-join' ').Trim();artifacts=$artifacts}
$manifest|ConvertTo-Json -Depth 6|Set-Content (Join-Path $root 'build\manifest.json') -Encoding utf8
Write-Output "Built DWARF/BTF/stripped ELF corpus"
