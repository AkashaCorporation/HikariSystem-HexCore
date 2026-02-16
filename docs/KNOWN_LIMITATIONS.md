# Known Limitations — HexCore v3.5.1

Limitações conhecidas e workarounds para a versão atual.

---

## Build & CI

### 1. Prebuilds apenas para Windows (win32-x64)
- **Status:** Limitação ativa
- **Impacto:** Linux e macOS não têm prebuilds pré-compilados
- **Workaround:** Nessas plataformas, `hexcore-native-install.js` faz fallback para `node-gyp rebuild`
- **Solução futura:** Adicionar runners Linux/macOS ao workflow `hexcore-native-prebuilds.yml`

### 2. GitHub Actions — Minutos pagos em repo privado
- **Status:** Limitação ativa
- **Impacto:** Project-Akasha (privado) consome minutos do plano Free (2.000/mês)
- **Detalhes:** Windows runners têm multiplicador 2x. Workflow de prebuilds (~6 min) = ~12 min do plano
- **Workaround:** Rodar workflows no HikariSystem-HexCore (público, minutos ilimitados)
- **Solução futura:** Mover workflow de prebuilds para o repo público

### 3. Check "Prevent package-lock.json changes" falha em PRs
- **Status:** Limitação herdada do VS Code upstream
- **Impacto:** PRs que alteram package-lock.json mostram check falhando
- **Detalhes:** O workflow tenta verificar permissões no repo `microsoft/vscode` (403)
- **Workaround:** O check não é blocking — pode mergear mesmo com falha
- **Solução futura:** Desabilitar ou adaptar o workflow para o fork HexCore

### 4. Check de collaborator tenta acessar microsoft/vscode
- **Status:** Limitação herdada
- **Impacto:** Erro 403 nos logs do CI (cosmético, não bloqueia)
- **Detalhes:** `octokit/request-action` faz GET em `/repos/microsoft/vscode/collaborators/`
- **Workaround:** Ignorar
- **Solução futura:** Remover ou adaptar o workflow

---

## Extensões Nativas

### 5. better-sqlite3 — lib/ layer mantida por compatibilidade
- **Status:** Decisão de design
- **Impacto:** A pasta `lib/` com `database.js`, `methods/` etc. é mantida para compatibilidade
- **Detalhes:** O padrão HexCore proíbe `lib/` como diretório JS intermediário, mas o better-sqlite3
  precisa dele para manter a API `new Database()` com transactions, aggregates, etc.
- **Workaround:** Aceito como exceção documentada
- **Solução futura:** Migrar funcionalidades de `lib/` para o wrapper C++ gradualmente

### 6. Unicorn — DLL dinâmica necessária no Windows
- **Status:** Limitação da engine
- **Impacto:** `unicorn.dll` precisa estar no PATH ou no diretório do binário
- **Detalhes:** Diferente das outras engines que usam libs estáticas
- **Workaround:** `index.js` adiciona `deps/unicorn/` ao PATH automaticamente
- **Solução futura:** Nenhuma — é característica da engine Unicorn

### 7. LLVM MC — Asset de deps precisa ser baixado separadamente
- **Status:** Limitação ativa
- **Impacto:** O workflow de prebuilds tem step especial para baixar `llvm-win32-x64.zip`
- **Detalhes:** As libs LLVM são grandes demais para incluir no repo
- **Workaround:** Step condicional no workflow faz download automático
- **Solução futura:** Nenhuma necessária — funciona bem

---

## Plataforma

### 8. HexCore congelado na base VS Code 3.2.2
- **Status:** Limitação temporária
- **Impacto:** Não é possível atualizar para VS Code 3.3.0+ upstream
- **Detalhes:** Erro de build ao tentar atualizar a base do VS Code
- **Workaround:** Manter na base 3.2.2 e aplicar patches HexCore por cima
- **Solução futura:** Investigar e resolver o erro de build do upstream 3.3.0

### 9. Electron 39.2.7 — Versão fixa
- **Status:** Limitação de compatibilidade
- **Impacto:** Não atualizar Electron sem testar todas as extensões nativas
- **Detalhes:** Mudança de Electron pode quebrar N-API bindings
- **Workaround:** Manter versão fixa, testar antes de atualizar
- **Solução futura:** Testar com Electron mais recente quando estabilizar

---

## Segurança

### 10. HEXCORE_RELEASE_TOKEN — Permissões mínimas
- **Status:** Configuração necessária
- **Impacto:** Sem o token, prebuilds não são publicados como releases
- **Detalhes:** Token precisa de `Contents: Read and write` nos 4 repos standalone
- **Nota:** NÃO usar `Codespaces` — usar `Contents`

---

## Documentação

### 11. POWER.md — Seção de migração do better-sqlite3 desatualizada
- **Status:** Cosmético
- **Impacto:** O POWER.md ainda descreve o better-sqlite3 como "precisa migração"
- **Detalhes:** A migração já foi concluída na v3.3.0
- **Solução:** Atualizar POWER.md para refletir o estado atual

---

## Debugger & Emulação

### 12. Debugger — Sem comandos headless (pipeline impossível)
- **Status:** Limitação ativa
- **Impacto:** O debugger/emulador NÃO pode ser usado no pipeline de automação
- **Detalhes:** Todos os 10 comandos do hexcore-debugger usam UI interativa (`showOpenDialog`, `showInputBox`, `showQuickPick`). A engine por baixo (`debugEngine.ts`, `unicornWrapper.ts`) é 100% programática, mas não há wrappers headless expostos como comandos VS Code
- **Workaround:** Nenhum — requer implementação de novos comandos headless
- **Solução futura:** Criar variantes headless: `emulateHeadless`, `stepHeadless`, `readMemoryHeadless`, `setBreakpointHeadless`, `snapshotHeadless`

### 13. Debugger — ARM64 ELF incompleto no DebugEngine
- **Status:** ~~Limitação ativa~~ **Resolvido em v3.5.1**
- **Resolução:** Todos os 5 métodos ARM64 implementados:
  - `setupArm64Stack()` — configura LR=0xDEAD0000, alinhamento 16-byte do SP
  - `initializeElfProcessStack()` — monta argc/argv/envp via X0/X1/X2 (register-based)
  - `installSyscallHandler()` — intercepta SVC #0 (intno===2), X8=syscall number
  - `updateEmulationRegisters()` — mapeia x0-x15, fp, sp, pc, nzcv
  - `popReturnAddress()` — lê LR (X30) em vez de pop da stack
  - 20+ syscalls ARM64: write(64), exit(93), exit_group(94), brk(214), mmap(222), etc.

### 14. Debugger — ELF estáticos não interceptam libc
- **Status:** Limitação de design
- **Impacto:** Binários ELF statically-linked não têm PLT stubs, então `LinuxApiHooks` não consegue interceptar chamadas libc (printf, malloc, etc.)
- **Detalhes:** O hook system funciona substituindo endereços na PLT. Sem PLT, apenas interceptação direta de syscalls funciona (e só para x86/x64 via `int 0x80`/`syscall`)
- **Workaround:** Para binários estáticos, depender apenas de syscall hooking
- **Solução futura:** Implementar pattern matching para detectar funções libc inlined em binários estáticos

---

## Disassembler & Análise

### 15. buildFormula — Apenas x86/x64
- **Status:** ~~Limitação ativa~~ **Resolvido em v3.5.1**
- **Resolução:** formulaBuilder agora suporta ARM64 e ARM32:
  - Registradores: x0-x30, w0-w30, sp, lr, fp, xzr, wzr, pc (ARM64) + r0-r15 (ARM32)
  - 15 mnemonics ARM: movz, movk, movn, mul, madd, msub, neg, eor, orr, and, lsl, lsr, asr, mla, mvn
  - Suporte a 3 operandos (add x0, x1, x2) e prefixo # em imediatos

### 16. Sem extensão ELF Analyzer
- **Status:** Lacuna de funcionalidade
- **Impacto:** `hexcore-peanalyzer` analisa headers/imports/exports/sections de PE, mas não existe equivalente para ELF
- **Detalhes:** O disassembler tem um parser ELF interno (`elfParser.ts`) mas ele não é exposto como comando headless de análise estrutural. Informações como segments, symbols, dynamic linking, RELRO, stack canary, NX não são extraídas de forma estruturada
- **Workaround:** Usar `hexcore.filetype.detect` para identificação básica e `hexcore.disasm.analyzeAll` para descoberta de funções
- **Solução futura:** Criar extensão `hexcore-elfanalyzer` com comandos headless equivalentes ao peanalyzer

---

## Extensões — Funcionalidades Faltantes

### 17. Base64 — Sem modo headless
- **Status:** Limitação ativa
- **Impacto:** `hexcore.base64.decode` sempre abre um relatório markdown no editor, não pode ser usado no pipeline
- **Workaround:** Nenhum para pipeline. Decodificação manual via editor
- **Solução futura:** Adicionar `hexcore.base64.decodeHeadless` que aceita `output` e escreve resultado em arquivo

### 18. Hex Viewer — Sem dump headless
- **Status:** Limitação ativa
- **Impacto:** Não é possível extrair dados hexadecimais programaticamente via pipeline
- **Detalhes:** Todos os comandos do hex viewer (openHexView, searchHex, copyAs*, addBookmark, applyTemplate) requerem a webview aberta. Bookmarks não são persistidos entre sessões. `applyTemplate` não tem biblioteca de templates built-in
- **Workaround:** Nenhum para pipeline
- **Solução futura:** Adicionar `hexcore.hexview.dumpHeadless` e `hexcore.hexview.searchHeadless`

### 19. Strings XOR — Apenas 1 byte
- **Status:** Limitação ativa
- **Impacto:** `hexcore.strings.extractAdvanced` brute-força apenas chaves XOR de 1 byte (0x01-0xFF)
- **Detalhes:** Malware moderno frequentemente usa XOR com chaves multi-byte (4, 8, 16+ bytes), rolling XOR, ou XOR com incremento. Nenhuma dessas variantes é detectada
- **Workaround:** Análise manual de padrões XOR multi-byte
- **Solução futura:** Implementar detecção de XOR multi-byte (2, 4, 8, 16 bytes), rolling XOR, e XOR com incremento

### 20. Prebuilds — Apenas win32-x64
- **Status:** Limitação ativa (duplica #1 com mais contexto)
- **Impacto:** Linux e macOS não têm prebuilds, afetando instalação e CI
- **Detalhes:** Todos os 5 engines nativos (Capstone, Unicorn, Remill, LLVM MC, better-sqlite3) só têm prebuilds para Windows x64. Em outras plataformas, `prebuild-install` falha e o fallback para `node-gyp rebuild` requer toolchain C++ completo (CMake, LLVM headers para Remill)
- **Workaround:** `node-gyp rebuild` com dependências instaladas
- **Solução futura:** Adicionar runners Linux (ubuntu-latest) e macOS (macos-latest) ao workflow de prebuilds
