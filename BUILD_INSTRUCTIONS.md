# HexCore - Instruções de Build Rápido

Este guia te ajuda a compilar o HexCore rapidamente após fazer `git pull`.

## Pré-requisitos (só precisa instalar uma vez)
- Node.js 22.21.1
- Python 3.11
- Visual Studio 2022 Build Tools
- node-gyp global: `npm install -g node-gyp`

## Build Rápido (após git pull)

### 1. Copiar binários nativos HexCore PRIMEIRO
```powershell
.\scripts\copy-hexcore-binaries.ps1
```

**IMPORTANTE**: Faça isso ANTES do `npm install`! Os binários `.node` já vêm pré-compilados no repositório dentro de `prebuilds/win32-x64/`. Este script copia eles para onde o npm install espera encontrá-los.

### 2. Instalar dependências
```powershell
npm install
```

**IMPORTANTE**: Quando aparecer "Entering npm script environment", digite `exit` e pressione Enter.

### 3. Instalar dependências das extensões markdown
```powershell
npm install --prefix extensions/markdown-language-features
npm install --prefix extensions/markdown-math
npm install --prefix extensions/simple-browser
npm install --prefix extensions/json-language-features/server
npm install --prefix extensions/css-language-features/server
npm install --prefix extensions/html-language-features/server
npm install --prefix .vscode/extensions/vscode-selfhost-test-provider
```

### 4. Compilar módulos nativos do core
```powershell
cd node_modules/@vscode/sqlite3
node-gyp rebuild
cd ../../..

cd node_modules/@vscode/spdlog
node-gyp rebuild
cd ../../..
```

### 5. Instalar ripgrep
```powershell
npm run postinstall --prefix node_modules/@vscode/ripgrep
```

### 6. Compilar o projeto
```powershell
npm run compile
```

### 7. Rodar o HexCore
```powershell
.\scripts\code.bat
```

## Script Automatizado

Ou use este script PowerShell que faz tudo automaticamente:

```powershell
# Salve como: build-hexcore-quick.ps1
Write-Host "=== HexCore Quick Build ===" -ForegroundColor Cyan

# 1. Copy HexCore binaries FIRST
Write-Host "`n[1/7] Copying HexCore native binaries..." -ForegroundColor Yellow
.\scripts\copy-hexcore-binaries.ps1

# 2. npm install (você precisa digitar 'exit' quando aparecer o prompt)
Write-Host "`n[2/7] Installing dependencies..." -ForegroundColor Yellow
npm install

# 3. Extensões markdown
Write-Host "`n[3/7] Installing markdown extensions..." -ForegroundColor Yellow
npm install --prefix extensions/markdown-language-features --silent
npm install --prefix extensions/markdown-math --silent
npm install --prefix extensions/simple-browser --silent
npm install --prefix extensions/json-language-features/server --silent
npm install --prefix extensions/css-language-features/server --silent
npm install --prefix extensions/html-language-features/server --silent
npm install --prefix .vscode/extensions/vscode-selfhost-test-provider --silent

# 4. Módulos nativos core
Write-Host "`n[4/7] Building native modules..." -ForegroundColor Yellow
Push-Location node_modules/@vscode/sqlite3
node-gyp rebuild | Out-Null
Pop-Location

Push-Location node_modules/@vscode/spdlog
node-gyp rebuild | Out-Null
Pop-Location

# 5. Ripgrep
Write-Host "`n[5/7] Installing ripgrep..." -ForegroundColor Yellow
npm run postinstall --prefix node_modules/@vscode/ripgrep

# 6. Compile
Write-Host "`n[6/7] Compiling project..." -ForegroundColor Yellow
npm run compile

# 7. Done
Write-Host "`n[7/7] Build complete!" -ForegroundColor Green
Write-Host "`nRun with: .\scripts\code.bat" -ForegroundColor Cyan
```

Execute com:
```powershell
powershell -ExecutionPolicy Bypass -File build-hexcore-quick.ps1
```

## Troubleshooting

### Erro: "Cannot find module hexcore-unicorn"
```powershell
.\scripts\copy-hexcore-binaries.ps1
```

### Erro: "Cannot find module hexcore-capstone"  
```powershell
.\scripts\copy-hexcore-binaries.ps1
```

### Erro: "Cannot find module spdlog.node"
```powershell
cd node_modules/@vscode/spdlog
node-gyp rebuild
cd ../../..
```

### Tela em branco ao abrir
Falta compilar. Execute:
```powershell
npm run compile
```
