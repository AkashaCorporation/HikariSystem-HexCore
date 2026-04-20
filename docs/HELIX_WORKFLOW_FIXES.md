# Correções Necessárias no Workflow Helix

## Problema

O repo HexCore-Helix tem esta estrutura:
```
HexCore-Helix/
  engine/CMakeLists.txt    <- C++ engine aqui
  crates/                  <- Rust workspace
  package.json             <- NAPI-RS na raiz
```

O workflow faz checkout em `path: engine`, criando:
```
workspace/
  engine/                  <- repo inteiro
    engine/CMakeLists.txt  <- C++ engine aqui
    crates/
    package.json
```

## Mudanças Necessárias

### 1. Mudar path do checkout
```yaml
- name: Checkout Helix Repository
  uses: actions/checkout@v6
  with:
    repository: LXrdKnowkill/hexcore-helix
    path: helix-repo  # era: engine
```

### 2. Ajustar download de deps
```yaml
- name: Download Helix LLVM/MLIR Deps
  if: steps.cache-helix-deps.outputs.cache-hit != 'true'
  run: |
    $tag = "v0.2.0"
    $asset = "helix-llvm-mlir-deps-win32-x64.zip"
    $url = "https://github.com/LXrdKnowkill/hexcore-helix/releases/download/$tag/$asset"
    Write-Host "Downloading Helix LLVM/MLIR deps from $url ..."
    Invoke-WebRequest -Uri $url -OutFile $asset
    Expand-Archive -Path $asset -DestinationPath helix-repo/engine/deps/llvm-mlir -Force
    Remove-Item $asset
```

### 3. Ajustar build do C++ engine
```yaml
- name: Build C++ Engine
  working-directory: helix-repo/engine
  run: |
    if (Test-Path "CMakeLists.txt") {
      cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
        -DLLVM_DIR="${{ github.workspace }}/helix-repo/engine/deps/llvm-mlir/lib/cmake/llvm" `
        -DMLIR_DIR="${{ github.workspace }}/helix-repo/engine/deps/llvm-mlir/lib/cmake/mlir"
      cmake --build build --config Release
    } else {
      Write-Host "No CMakeLists.txt — skipping C++ build"
    }
```

### 4. Ajustar install dependencies
```yaml
- name: Install Dependencies
  working-directory: helix-repo
  run: npm ci --ignore-scripts
```

### 5. Ajustar build NAPI-RS
```yaml
- name: Build NAPI-RS Module
  working-directory: helix-repo
  env:
    LLVM_DIR: ${{ github.workspace }}/helix-repo/engine/deps/llvm-mlir
    MLIR_DIR: ${{ github.workspace }}/helix-repo/engine/deps/llvm-mlir
  run: npm run build
```

### 6. Ajustar leitura de versão
```yaml
- name: Read Engine Version
  id: engine-version
  working-directory: helix-repo
  run: |
    $version = node -p "require('./package.json').version"
    "version=$version" >> $env:GITHUB_OUTPUT
```

### 7. Ajustar localização do .node
```yaml
- name: Locate and Pack NAPI-RS Binary
  id: pack-napi
  working-directory: helix-repo
  run: |
    $version = "${{ steps.engine-version.outputs.version }}"
    $binaryName = node -p "require('./package.json').napi.binaryName"
    $nodeFile = "$binaryName.win32-x64-msvc.node"
    $candidates = @(
      "$nodeFile",
      "crates/hexcore-helix/$nodeFile"
    )
    # ... resto igual
```

### 8. Ajustar cache key
```yaml
- name: Cache Helix LLVM/MLIR Deps
  id: cache-helix-deps
  uses: actions/cache@v4
  with:
    path: helix-repo/engine/deps/llvm-mlir
    key: helix-llvm-mlir-win32-x64-${{ hashFiles('helix-repo/crates/hexcore-helix/Cargo.toml') }}
```

## Resumo

Trocar todas as ocorrências de:
- `path: engine` → `path: helix-repo`
- `working-directory: engine` → `working-directory: helix-repo` (exceto build C++)
- `working-directory: engine` (build C++) → `working-directory: helix-repo/engine`
- Paths absolutos: `engine/` → `helix-repo/`
