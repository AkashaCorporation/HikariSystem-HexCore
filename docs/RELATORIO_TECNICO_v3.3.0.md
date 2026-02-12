# Relatório Técnico — HexCore v3.3.0

**Data:** 2026-02-12
**Autor:** Bianca Niarim Kiryashikova
**Branch:** `akasha-main-sync`
**Status:** Mergeado em `stable` via PR #10 e PR #11

---

## Resumo Executivo

A versão 3.3.0 do HikariSystem HexCore introduz:

1. **Rewrite completo do better-sqlite3** — migrado de vendor dump para wrapper N-API puro
2. **Unicorn Engine 1.2.0** — bump de versão com novos testes (breakpoints, shared memory, snapshots)
3. **3 novas extensões** — hexcore-ioc, hexcore-minidump, hexcore-disassembler (melhorias)
4. **Infraestrutura CI** — workflow de prebuilds nativos, preflight checks, job templates
5. **Power de documentação** — `hexcore-native-engines` para padronizar wrappers N-API

---

## 1. Rewrite do better-sqlite3

### Problema
O `hexcore-better-sqlite3` era um vendor dump do pacote npm `better-sqlite3` com dependências runtime
(`bindings`, `node-gyp-build`) e estrutura monolítica incompatível com o padrão HexCore.

### Solução
Reescrita completa como wrapper N-API seguindo o padrão das outras engines (Capstone, Unicorn, LLVM MC):

- **C++ nativo**: `main.cpp`, `sqlite3_wrapper.cpp`, `sqlite3_wrapper.h`
- **Classes**: `DatabaseWrapper` e `StatementWrapper` com N-API ObjectWrap
- **API completa**: `exec()`, `prepare()`, `run()`, `get()`, `all()`, `pragma()`, `close()`
- **Features**: safe integers (BigInt), raw mode, expand mode, named/positional binding
- **Zero deps runtime**: loading via fallback chain (prebuilds → Release → Debug)
- **Compatibilidade**: `hexcore-ioc` continua funcionando sem alterações

### Arquivos Principais
- `extensions/hexcore-better-sqlite3/src/sqlite3_wrapper.cpp` — 580 linhas, implementação completa
- `extensions/hexcore-better-sqlite3/src/sqlite3_wrapper.h` — header com DatabaseWrapper + StatementWrapper
- `extensions/hexcore-better-sqlite3/src/main.cpp` — entry point N-API
- `extensions/hexcore-better-sqlite3/binding.gyp` — build config multi-plataforma
- `extensions/hexcore-better-sqlite3/index.js` — fallback loading + JS layer
- `extensions/hexcore-better-sqlite3/package.json` — v2.0.0, zero runtime deps

### Testes
- Smoke test em `test/test.js` validando CRUD, prepared statements, pragma, transactions
- Teste de integração com `hexcore-ioc` confirmando compatibilidade

---

## 2. Unicorn Engine 1.2.0

### Mudanças
- Bump de versão: 1.0.0 → 1.2.0 (standalone e monorepo)
- Novos testes: `test_bps.js` (breakpoints), `test_shared_mem.js`, `test_snapshot.js`
- Melhorias no wrapper C++ (`unicorn_wrapper.cpp`, `unicorn_wrapper.h`)
- Atualização do `index.d.ts` com novos tipos

### Release
- Release `v1.2.0` criada automaticamente no repo standalone via workflow
- Asset: `hexcore-unicorn-v1.2.0-napi-v8-win32-x64.tar.gz` (6.22 MB)

---

## 3. Novas Extensões

### hexcore-ioc (Indicators of Compromise)
- Extrator de IOCs (IPs, URLs, hashes, emails, domínios) de arquivos binários
- Usa `hexcore-better-sqlite3` para persistência de matches
- Gerador de relatórios Markdown

### hexcore-minidump
- Parser de arquivos Windows Minidump (.dmp)
- Streams suportados: ThreadList, ThreadInfoList, ModuleList, MemoryInfoList, Memory64List, SystemInfo
- Fix aplicado: offsets de thread context corrigidos (PR #11)
- Fix aplicado: guard de affinity corrigido para validar `sizeOfEntry`

### hexcore-disassembler (melhorias)
- Pipeline de automação (`automationPipelineRunner.ts`)
- Constant sanity checker
- Formula builder para análise de padrões
- Pipeline profiles configuráveis
- Schema JSON para jobs de automação

### hexcore-strings (melhorias)
- Stack string detector (`stackStringDetector.ts`)
- XOR scanner (`xorScanner.ts`)

---

## 4. Infraestrutura CI/CD

### Workflows Atualizados
- `hexcore-build.yml` — build geral com preflight checks
- `hexcore-installer.yml` — geração de .exe Windows
- `hexcore-native-prebuilds.yml` — build de prebuilds para todas as engines nativas

### Novos Scripts
- `scripts/verify-hexcore-preflight.cjs` — validação pré-build (activationEvents, etc.)
- `scripts/patch-vsce-npm.js` — patch para compatibilidade vsce
- `scripts/build-hexcore-win.ps1` — build script Windows atualizado

### Preflight Checks
- Toda extensão com `"main"` deve ter `"activationEvents"` no package.json
- Validação automática no CI antes do build

---

## 5. Bugs Corrigidos

| Bug | Arquivo | Fix |
|-----|---------|-----|
| Thread context offsets invertidos | `streamParsers.ts` | `contextSize` → offset +40, `contextRva` → offset +44 |
| Affinity guard incorreto | `streamParsers.ts` | Adicionado check `sizeOfEntry >= 64` |
| package-lock.json dessincronizado | `better-sqlite3/package-lock.json` | Regenerado com `npm install --package-lock-only` |
| activationEvents ausente | `better-sqlite3/package.json` | Adicionado `"activationEvents": []` |

---

## 6. Métricas

- **Arquivos alterados:** 82
- **Linhas adicionadas:** ~33.000+
- **Linhas removidas:** ~2.100+
- **PRs mergeados:** 2 (#10, #11)
- **Prebuilds gerados:** 4 engines (Capstone, Unicorn, LLVM MC, better-sqlite3)
- **Tempo de CI:** ~6 min (prebuilds), ~10 min (installer)

---

## 7. Limitações Conhecidas

- Build de prebuilds apenas para Windows (win32-x64) — Linux/macOS pendente
- Workflow de prebuilds no repo privado consome minutos pagos (2x multiplicador Windows)
- Check "Prevent package-lock.json changes" herdado do VS Code upstream — pode ser desabilitado
- Check de collaborator tenta acessar `microsoft/vscode` — irrelevante para o fork

---

## 8. Próximos Passos

1. Configurar `HEXCORE_RELEASE_TOKEN` com permissão `Contents: Read and write`
2. Adicionar runners Linux ao workflow de prebuilds
3. Desabilitar workflows herdados do VS Code que não se aplicam
4. Testar build completa do HexCore com as novas extensões
5. Atualizar versão do produto para 3.3.0 no `product.json`
