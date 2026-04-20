# Patch para HexCore-Helix: build.rs simplificado

## Problema
O build.rs atual depende de CMake configs (`LLVMConfig.cmake`, `MLIRConfig.cmake`) que têm paths hardcoded, causando falhas no CI.

## Solução
Substituir o build.rs por uma versão simplificada que:
- Não depende de CMake configs
- Usa `LLVM_LIB_DIR` diretamente para encontrar as libs
- Linka todas as libs LLVM/MLIR estaticamente sem `llvm_map_components_to_libnames`

## Arquivos Modificados

### `crates/helix-core/build.rs`
Substituir completamente pelo conteúdo de `build.rs.new` (já criado).

## Mudanças no Workflow

### `.github/workflows/hexcore-native-prebuilds.yml`
```yaml
# Antes:
env:
  LLVM_DIR: ${{ github.workspace }}/engine/engine/deps/llvm-mlir
  MLIR_DIR: ${{ github.workspace }}/engine/engine/deps/llvm-mlir

# Depois:
env:
  LLVM_LIB_DIR: ${{ github.workspace }}/engine/engine/deps/llvm-mlir/lib
```

## Como Aplicar

### No repo HexCore-Helix:
```bash
cd /mnt/c/Users/Mazum/Desktop/HexCore-Helix-Original/HexCore-Helix
cp crates/helix-core/build.rs.new crates/helix-core/build.rs
git add crates/helix-core/build.rs
git commit -m "fix: simplify build.rs to not depend on CMake configs"
git push
```

### No repo vscode-main:
Já foi aplicado automaticamente.

## Benefícios
- ✅ Não depende de paths hardcoded em CMake configs
- ✅ Mais robusto e portável
- ✅ Funciona em qualquer ambiente com LLVM libs
- ✅ Mais rápido (não precisa processar CMake configs)

## Testado
- ✅ Localmente no Windows com LLVM 18
- ⏳ Aguardando teste no CI
