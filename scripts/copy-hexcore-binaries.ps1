# Script para copiar binários nativos do HexCore para modo dev
# Executa após npm install para garantir que os módulos nativos sejam encontrados

Write-Host "=== Copiando binários nativos HexCore ===" -ForegroundColor Cyan

$extensions = @(
    @{name="hexcore-capstone"; binary="hexcore_capstone.node"},
    @{name="hexcore-unicorn"; binary="hexcore_unicorn.node"}, 
    @{name="hexcore-llvm-mc"; binary="hexcore_llvm_mc.node"}
)

foreach ($ext in $extensions) {
    $extName = $ext.name
    $binaryName = $ext.binary
    
    # Fonte: prebuilds usa hífen
    $source = "extensions/$extName/prebuilds/win32-x64/$extName.node"
    
    # Destino 1: build/Release (onde index.js procura)
    $buildDir = "extensions/$extName/build/Release"
    if (!(Test-Path $buildDir)) {
        New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
    }
    $dest1 = "$buildDir/$binaryName"
    
    # Destino 2: raiz (fallback)
    $dest2 = "extensions/$extName/$binaryName"
    
    if (Test-Path $source) {
        Copy-Item $source $dest1 -Force
        Copy-Item $source $dest2 -Force
        Write-Host "[OK] $binaryName copiado (build + raiz)" -ForegroundColor Green
    } else {
        Write-Host "[ERRO] $source não encontrado!" -ForegroundColor Red
    }
}

# Copiar unicorn.dll para os lugares corretos
$unicornDll = "extensions/hexcore-unicorn/prebuilds/win32-x64/unicorn.dll"
$unicornDest1 = "extensions/hexcore-unicorn/unicorn.dll"
$unicornDest2 = "extensions/hexcore-unicorn/deps/unicorn/unicorn.dll"
$unicornDest3 = "extensions/hexcore-unicorn/build/Release/unicorn.dll"

if (Test-Path $unicornDll) {
    Copy-Item $unicornDll $unicornDest1 -Force
    Copy-Item $unicornDll $unicornDest2 -Force
    
    $buildDir = "extensions/hexcore-unicorn/build/Release"
    if (!(Test-Path $buildDir)) {
        New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
    }
    Copy-Item $unicornDll $unicornDest3 -Force
    
    Write-Host "[OK] unicorn.dll copiado (raiz + deps + build)" -ForegroundColor Green
} else {
    Write-Host "[AVISO] unicorn.dll não encontrado" -ForegroundColor Yellow
}

Write-Host "`nBinários copiados com sucesso!" -ForegroundColor Cyan
