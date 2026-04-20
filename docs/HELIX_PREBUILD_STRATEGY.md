# HexCore Helix — Prebuild Strategy for Beta.2

> **Data**: 2026-03-12  
> **Contexto**: Integração do Helix (NAPI-RS + LLVM/MLIR) no workflow de prebuilds da HexCore

---

## Situação Atual

- ✅ Helix funciona localmente (`.node` de 12 MB já compilado)
- ✅ LLVM 18 + MLIR instalado em `C:\Users\Mazum\Desktop\caps\llvm-build\build-mlir` (4.5 GB)
- ❌ Nenhuma release no repo standalone com `.node` pré-compilado
- ❌ Nenhum zip de deps LLVM/MLIR pré-compiladas
- ⚠️ Build do zero leva 2-4 horas (LLVM + engine C++ + NAPI)

---

## Estratégia para Beta.2

### Fase 1: Release Manual (Imediato)

**Você faz localmente:**

1. **Criar zip de deps LLVM/MLIR**
   ```batch
   cd C:\Users\Mazum\Desktop\caps
   .\create-llvm-deps-zip.bat
   ```
   
   Gera: `llvm-18-mlir-win32-x64.zip` (~500-800 MB estimado)
   
   Contém:
   - `lib/*.lib` (440 libs LLVM/MLIR)
   - `lib/cmake/` (configs CMake)
   - `include/` (headers LLVM/MLIR)

2. **Copiar o `.node` já compilado**
   ```batch
   copy C:\Users\Mazum\Desktop\HexCore-Helix-Original\HexCore-Helix\crates\hexcore-helix\hexcore-helix.win32-x64-msvc.node C:\Users\Mazum\Desktop\
   ```

3. **Criar release no repo standalone**
   ```bash
   # No repo LXrdKnowkill/HexCore-Helix
   gh release create v0.5.0 \
     --title "v0.5.0 — Entry Block Crash Fix" \
     --notes "See CHANGELOG.md" \
     hexcore-helix.win32-x64-msvc.node \
     llvm-18-mlir-win32-x64.zip
   ```

### Fase 2: Adaptar Install Script

**Modificar `scripts/hexcore-native-install.js`:**

```javascript
// Detectar NAPI-RS via campo "napi" no package.json
function isNapiRsPackage(pkgJson) {
  return pkgJson.napi && pkgJson.napi.binaryName;
}

// Baixar .node direto da release do GitHub
async function downloadNapiPrebuilt(pkgName, version, platform, arch) {
  const repo = getRepoFromPackageName(pkgName); // e.g., "LXrdKnowkill/HexCore-Helix"
  const binaryName = pkgJson.napi.binaryName; // "hexcore-helix"
  const filename = `${binaryName}.${platform}-${arch}-msvc.node`;
  const url = `https://github.com/${repo}/releases/download/v${version}/${filename}`;
  
  // Download e coloca em crates/hexcore-helix/ (ou raiz do pacote)
  await downloadFile(url, path.join(pkgDir, filename));
}
```

### Fase 3: Workflow CI (Longo Prazo)

**Adicionar job no `hexcore-native-prebuilds.yml`:**

```yaml
helix-win32-x64:
  runs-on: windows-latest
  steps:
    - uses: actions/checkout@v4
      with:
        repository: LXrdKnowkill/HexCore-Helix
        path: HexCore-Helix
    
    - name: Download LLVM Deps
      run: |
        gh release download llvm-deps --pattern "llvm-18-mlir-win32-x64.zip" --repo LXrdKnowkill/HexCore-Helix
        7z x llvm-18-mlir-win32-x64.zip -oC:\llvm-18
    
    - name: Setup Rust
      uses: dtolnay/rust-toolchain@stable
      with:
        targets: x86_64-pc-windows-msvc
    
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: 22
    
    - name: Install NAPI-RS CLI
      run: npm install -g @napi-rs/cli
    
    - name: Build C++ Engine
      env:
        LLVM_DIR: C:\llvm-18\lib\cmake\llvm
      run: |
        cd HexCore-Helix\engine
        cmake -B build -G "Visual Studio 17 2022" -A x64
        cmake --build build --config Release
    
    - name: Build NAPI Module
      env:
        LLVM_DIR: C:\llvm-18\lib\cmake\llvm
      run: |
        cd HexCore-Helix
        npm run build
    
    - name: Create Release
      env:
        GITHUB_TOKEN: ${{ secrets.HEXCORE_RELEASE_TOKEN }}
      run: |
        cd HexCore-Helix
        gh release create v${{ github.ref_name }} --repo LXrdKnowkill/HexCore-Helix \
          crates/hexcore-helix/hexcore-helix.win32-x64-msvc.node
```

---

## Checklist de Implementação

### Você (Manual)

- [ ] Executar `create-llvm-deps-zip.bat`
- [ ] Verificar tamanho do zip (deve ser 500-800 MB)
- [ ] Copiar `hexcore-helix.win32-x64-msvc.node` para área de trabalho
- [ ] Criar release `v0.5.0` no repo `LXrdKnowkill/HexCore-Helix` com:
  - `hexcore-helix.win32-x64-msvc.node`
  - `llvm-18-mlir-win32-x64.zip`

### Kiro (Automático)

- [ ] Adaptar `hexcore-native-install.js` para detectar NAPI-RS
- [ ] Adicionar campo `napi` no `package.json` do Helix (se ainda não tiver)
- [ ] Adicionar job `helix-win32-x64` no `hexcore-native-prebuilds.yml`
- [ ] Testar install script localmente
- [ ] Commit e push

---

## Estrutura do ZIP de Deps

```
llvm-18-mlir-win32-x64.zip
├── lib/
│   ├── LLVM*.lib (440 arquivos, ~1.5 GB)
│   ├── MLIR*.lib
│   └── cmake/
│       ├── llvm/
│       └── mlir/
└── include/
    ├── llvm/
    └── mlir/
```

**Tamanho estimado:** 500-800 MB comprimido, 2 GB descomprimido

---

## Alternativas Consideradas

### ❌ Opção A: Build LLVM do Zero no CI
- **Tempo:** 2-4 horas por build
- **Custo:** Alto (minutos de runner)
- **Viabilidade:** Inviável para cada PR/release

### ❌ Opção B: Cache de LLVM no CI
- **Tempo:** ~30 min primeira vez, ~5 min depois
- **Problema:** Cache expira após 7 dias, precisa rebuild frequente
- **Viabilidade:** Possível mas frágil

### ✅ Opção C: Deps Pré-compiladas (Escolhida)
- **Tempo:** ~5 min (download + build engine + NAPI)
- **Custo:** Baixo (storage no GitHub)
- **Viabilidade:** Alta, mesmo padrão do Remill/Rellic

---

## Próximos Passos

1. **Hoje (você):** Criar zip + release manual
2. **Amanhã (Kiro):** Adaptar install script + workflow
3. **Beta.2:** Helix funciona via `npm install` sem build local
4. **Futuro:** Adicionar Linux/macOS (mesma estratégia)

---

## Notas Técnicas

### Por que não subir o build-mlir inteiro?

- **Tamanho:** 4.5 GB (inviável para GitHub Releases, limite 2 GB por arquivo)
- **Desnecessário:** 90% são arquivos intermediários de build (`.obj`, `.pdb`, etc.)
- **Solução:** Extrair apenas libs + headers + cmake configs = ~500-800 MB

### Por que não usar `install-llvm-action`?

- **Problema:** Instala LLVM pré-compilado sem MLIR ou com MLIR incompleto
- **Alternativa:** Funciona para projetos simples, mas Helix precisa de 80+ libs MLIR específicas
- **Solução:** Deps customizadas garantem compatibilidade exata

### Compatibilidade de Versão

- **LLVM 18.1.8** (usado no build local)
- **MSVC 2022** (Visual Studio 17)
- **Rust stable** (1.75+)
- **Node.js 22+**

Qualquer mudança nessas versões pode quebrar o linking. O zip de deps congela a versão exata.

---

**Status:** Pronto para execução. Aguardando criação do zip e release manual.
