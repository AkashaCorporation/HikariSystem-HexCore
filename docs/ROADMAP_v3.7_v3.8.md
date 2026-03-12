# HexCore Roadmap — v3.7 & v3.8

> **Data**: 2026-02-22
> **Autor**: Mazum + Kiro
> **Contexto**: Baseado nos relatórios do Kiro-CLI (Callfuscated HTB Insane challenge), backlog existente, e decisões de arquitetura.

---

## Decisões Estratégicas

### ❌ Sleigh — PARKED → DROPPED
O Sleigh (lifting-bits/sleigh) foi removido do roadmap. Motivos:
- Capstone já cobre disassembly multi-arch com qualidade
- Remill já cobre IR lifting (machine code → LLVM IR)
- Sleigh produziria P-Code, uma IR alternativa sem ecossistema de otimização
- LLVM IR é infinitamente mais útil: plugamos Rellic, LLVM passes, e futuramente Souper
- Manter dois lifters seria retrabalho sem ganho real

### ✅ Souper — v3.8
O Souper (Google) é um superoptimizer de LLVM IR que usa SMT solvers (Z3) para encontrar sequências equivalentes mais simples. Resolve o problema de obfuscação de forma elegante:
```
Capstone → Remill → Souper → Rellic = decompilação limpa mesmo em binários insane
```

---

## v3.7 — "Dynamic Intelligence"

> **Tema**: Emulação robusta, PRNG real, otimização de IR, e análise avançada de VMs.
> **Estimativa**: 2-3 semanas
> **Origem**: Relatórios Kiro-CLI (Callfuscated), backlog items #6, #28, #29, #30

### Prioridade 1 — Crítico (Bloqueante)

#### 1.1 Permissive Memory Mapping (`emulateFullHeadless`)
- **O quê**: Flag `permissiveMemoryMapping: boolean` (default: false)
- **Por quê**: VMs self-modifying fazem jump pra .rodata/.data — UC_ERR_FETCH_PROT crash
- **Onde**: `extensions/hexcore-debugger/src/debugEngine.ts` (mapeamento ELF segments)
- **Onde**: `extensions/hexcore-debugger/src/pe32Worker.js` (mapeamento PE sections)
- **Onde**: `extensions/hexcore-debugger/src/x64ElfWorker.js` (mapeamento ELF x64)
- **Impacto**: Teria economizado 3+ horas no Callfuscated
- **Esforço**: 1-2 dias
- **Backlog**: Novo item (derivado do relatório Kiro-CLI)

#### 1.2 glibc PRNG Implementation
- **O quê**: Classe `GlibcPRNG` com 344-state LCG, integrada nos PLT hooks
- **Por quê**: `rand()` retorna 0 (stub) — quebra validação de 50%+ dos crackmes
- **Onde**: `extensions/hexcore-debugger/src/debugEngine.ts` (novo módulo PRNG)
- **Interface**: `prngMode: 'glibc' | 'msvcrt' | 'stub'` (default: 'stub')
- **Inclui**: `srand(seed)` captura o seed, `rand()` retorna sequência correta
- **Esforço**: 3-5 dias
- **Backlog**: Item #6 (PRNG Analysis Helper) — parcialmente resolvido

#### 1.3 MSVCRT PRNG Implementation
- **O quê**: Classe `MsvcrtPRNG` com LCG simples (seed * 214013 + 2531011)
- **Por quê**: Crackmes Windows usam `rand()` do MSVCRT
- **Onde**: Mesmo módulo PRNG do item 1.2
- **Esforço**: 1 dia (trivial comparado ao glibc)

### Prioridade 2 — Alto (Qualidade)

#### 2.1 Rellic IR Optimization Pipeline
- **O quê**: Passes de otimização no LLVM IR antes do Rellic processar
- **Passes**: Dead Code Elimination (DCE), Constant Folding, Junk Instruction Filtering
- **Por quê**: Rellic gera pseudo-C inutilizável com obfuscação pesada (centenas de ADDs junk)
- **Onde**: `extensions/hexcore-rellic/src/rellic_decompile_pipeline.cpp` (C++ LLVM passes)
- **Onde**: `extensions/hexcore-disassembler/src/rellicWrapper.ts` (flag `optimizeIR`)
- **Interface**: `optimizeIR: boolean` (default: true), `optimizationPasses: string[]`
- **Esforço**: 1-2 semanas
- **Nota CHANGELOG**: Cumpre a promessa "Real Clang AST-based decompilation passes planned for v3.7"

#### 2.2 Junk Instruction Filtering (Disassembler)
- **O quê**: Filtro de instruções junk no disassembler (call/pop pairs, add/sub zero, nop sleds)
- **Por quê**: 66% das instruções no Callfuscated eram junk — poluem análise
- **Onde**: `extensions/hexcore-disassembler/src/disassemblerEngine.ts`
- **Interface**: `filterJunk: boolean` no `analyzeAll` e `disassembleAtHeadless`
- **Esforço**: 2-3 dias

#### 2.3 Memory Dump During Emulation
- **O quê**: Dump de ranges de memória arbitrários durante execução
- **Por quê**: Inspecionar estado de VM sem scripts customizados
- **Onde**: `extensions/hexcore-debugger/src/debugEngine.ts`
- **Interface**: `memoryDumps: Array<{ address: string, size: number, trigger: 'breakpoint' | 'end' }>`
- **Esforço**: 2-3 dias
- **Backlog**: Item #29 (Headless Breakpoint Snapshots & Dumps) — parcialmente resolvido

#### 2.4 Runtime Memory Disassembly (mmap regions)
- **O quê**: Dump de memória dinâmica (mmap'd) e disassembly imediato
- **Por quê**: VMs decriptam handlers em runtime — análise estática não alcança
- **Onde**: `extensions/hexcore-debugger/src/debugEngine.ts` + `disassemblerEngine.ts`
- **Esforço**: 3-4 dias
- **Backlog**: Item #28

### Prioridade 3 — Médio (Nice to Have)

#### 3.1 VM Detection & Analysis Heuristics
- **O quê**: Detecção automática de dispatchers, operand stacks, handler tables
- **Heurísticas**: Múltiplos `cmp eax, N` + jumps, `[rbp+rax*4-offset]` patterns, junk ratio
- **Onde**: `extensions/hexcore-disassembler/src/disassemblerEngine.ts`
- **Interface**: `detectVM: boolean` no `analyzeAll`
- **Output**: `vmDetected`, `vmType`, `dispatcher`, `opcodeCount`, `stackArrays`
- **Esforço**: 3-5 dias
- **Backlog**: Item #30

#### 3.2 Side-Channel Analysis Framework
- **O quê**: Coleta de métricas durante emulação (instruction count per BB, memory access patterns, branch stats)
- **Onde**: `extensions/hexcore-debugger/src/debugEngine.ts`
- **Interface**: `collectSideChannels: boolean` no `emulateFullHeadless`
- **Esforço**: 3-5 dias

#### 3.3 Breakpoint Auto-Snapshot
- **O quê**: Breakpoints que automaticamente tiram snapshot (registradores + stack + memória) antes de continuar
- **Por quê**: "Roda tudo e vê no final" não serve pra análise de VMs
- **Onde**: `extensions/hexcore-debugger/src/debugEngine.ts`
- **Interface**: Expandir `breakpoints: []` no `emulateFullHeadless` com `autoSnapshot: true`
- **Esforço**: 2-3 dias
- **Backlog**: Item #29

### Extras v3.7

#### E1. README — Adicionar Rellic
- **O quê**: Rellic não está listado no README principal
- **Esforço**: 30 min

#### E2. Souper Pipeline Hook (Preparação v3.8)
- **O quê**: Deixar um hook no pipeline Remill→Rellic onde o Souper vai se encaixar
- **Onde**: `extensions/hexcore-disassembler/src/rellicWrapper.ts`
- **Design**: `optimizerStep: 'none' | 'llvm-passes' | 'souper'` (default: 'llvm-passes' na v3.7)
- **Esforço**: 1 dia

#### E3. PRNG Analysis Helper (Backlog #6)
- **O quê**: Detectar padrões de PRNG no disassembly (srand, rand()%N) e anotar no flow
- **Por quê**: Complementa o PRNG real (1.2/1.3) com análise estática
- **Onde**: `extensions/hexcore-disassembler/src/disassemblerEngine.ts`
- **Esforço**: 2-3 dias

---

## v3.8 — "Superoptimizer"

> **Tema**: Souper integration — LLVM IR superoptimization via SMT solvers.
> **Estimativa**: 3-4 semanas
> **Pré-requisito**: v3.7 completa (IR optimization pipeline funcional)

### 4.1 hexcore-souper N-API Wrapper
- **O quê**: Nova engine nativa wrapping Google Souper
- **Build**: LLVM 18 + Z3 (já temos ambos do Rellic/Remill)
- **API**: `superoptimize(irText: string): string` — recebe LLVM IR, retorna IR otimizado
- **Standalone repo**: `hexcore-souper` (mesmo padrão dos outros engines)
- **Esforço**: 2-3 semanas (build system + wrapper + testes)

### 4.2 Pipeline Integration
- **O quê**: Plugar Souper no pipeline Remill→Rellic
- **Flow**: `Capstone → Remill (lift) → Souper (optimize) → Rellic (decompile)`
- **Onde**: `extensions/hexcore-disassembler/src/rellicWrapper.ts`
- **Interface**: `optimizerStep: 'souper'` ativa o superoptimizer
- **Esforço**: 3-5 dias

### 4.3 Souper Headless Command
- **O quê**: `hexcore.souper.optimize` — otimiza LLVM IR via pipeline
- **Contract**: `{ file, output, quiet }` (padrão headless)
- **Esforço**: 1-2 dias

### 4.4 Prebuild Pipeline
- **O quê**: Adicionar hexcore-souper ao `hexcore-native-prebuilds.yml`
- **Esforço**: 1 dia

---

## Backlog Status Após v3.7

| Item | Descrição | Status |
|------|-----------|--------|
| #6 | PRNG Analysis Helper | `DONE` (v3.7) |
| #10 | Guided Reverse Mode | `PENDING` (v4.0) |
| #11 | Formula-to-Script Export | `PENDING` (v3.8+) |
| #28 | Runtime Memory Disassembly | `DONE` (v3.7) |
| #29 | Headless Breakpoint Snapshots | `DONE` (v3.7) |
| #30 | VM Pattern Heuristics | `DONE` (v3.7) |
| #31 | Zero-Copy IPC SharedArrayBuffer | `PENDING` (v4.0) |
| #32 | Basic Symbolic Execution | `PENDING` (v4.0+) |
| Sleigh | hexcore-sleigh | `DROPPED` |

---

## Ordem de Implementação Sugerida (v3.7)

```
Semana 1:
  1.1 permissiveMemoryMapping (1-2 dias)
  1.2 glibc PRNG (3-5 dias)
  1.3 MSVCRT PRNG (1 dia)
  E1  README Rellic (30 min)

Semana 2:
  2.2 Junk Instruction Filtering (2-3 dias)
  2.3 Memory Dump During Emulation (2-3 dias)
  2.4 Runtime Memory Disassembly (3-4 dias)

Semana 3:
  2.1 Rellic IR Optimization Pipeline (1-2 semanas — pode estender)
  3.1 VM Detection Heuristics (3-5 dias)
  3.2 Side-Channel Analysis (3-5 dias)
  3.3 Breakpoint Auto-Snapshot (2-3 dias)
  E2  Souper Pipeline Hook (1 dia)
  E3  PRNG Analysis Helper (2-3 dias)
```

---

## Feature Matrix Atualizada

| Feature | v3.6 | v3.7 | v3.8 |
|---------|------|------|------|
| Permissive Memory Mapping | ❌ | ✅ | ✅ |
| glibc PRNG | ❌ | ✅ | ✅ |
| MSVCRT PRNG | ❌ | ✅ | ✅ |
| Rellic IR Optimization | ❌ | ✅ | ✅ |
| Junk Instruction Filter | ❌ | ✅ | ✅ |
| Memory Dump (emulation) | ❌ | ✅ | ✅ |
| Runtime Memory Disassembly | ❌ | ✅ | ✅ |
| VM Detection Heuristics | ❌ | ✅ | ✅ |
| Side-Channel Analysis | ❌ | ✅ | ✅ |
| Breakpoint Auto-Snapshot | ❌ | ✅ | ✅ |
| Souper Superoptimizer | ❌ | ❌ | ✅ |
| Souper Pipeline Integration | ❌ | Hook | ✅ |

---

**Próximo passo**: Criar specs individuais (requirements → design → tasks) para cada feature da v3.7, começando pelo `permissiveMemoryMapping` que é o mais rápido e impactante.
