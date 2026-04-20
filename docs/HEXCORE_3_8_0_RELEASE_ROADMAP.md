# HexCore 3.8.0 — Release Roadmap

**Status base:** 3.8.0-nightly, todo o trabalho core entregue.
**Objetivo:** verificar entrega + shippar stable com consciência clara dos gaps conhecidos.
**Filosofia:** "ship working, polish in follow-ups" — ship 3.8.0 com o que está sólido, deixar comunidade/3.9.0 cycle atacar resíduos.

---

## Fase 1 — Verificação cross-corpora (1-2h)

Antes de qualquer commit, rodar benchmark no `.node` atual pra garantir zero regressão. O `.node` já tem DWARF/PDB/ET_REL + todos os fixes de hoje.

### Gate 1.1 — Regression battery nos 5 corpora

Rodar `helix_tool.exe` em `.ll` files conhecidos e comparar line count contra baselines:

| Corpus | Função sample | Baseline (Apr 18) | Verificar | Tolerância |
|---|---|---|---|---|
| Kernel Mali | `kbase_jit_allocate` | 176L | ≥ 174L | ±2 |
| Kernel Mali | `kbase_context_mmap` | 184L | ≥ 180L | ±5 |
| Kernel Mali | `kbase_csf_queue_register` | 26L | ≥ 25L | ±1 |
| SOTR | `HealthData-read` | 52L | ≥ 50L | ±2 |
| SOTR | `RPC-Die-caller` | 349L | ≥ 345L | ±5 |
| Malware Defeat | main-entry | 12L | = 12L | 0 |
| LARA | `BattleConductorCore` | 15L | = 15L | 0 |
| LARA | `SetHealth` | 15L | ±1 | ±1 |
| gta-sa | `sub_5EC502_playerinfo-process` | 11L | = 11L | 0 |

**Se alguma função vier FORA da tolerância** → investigar antes de shippar. Não é release-blocker necessariamente, mas documentar na release notes.

### Gate 1.2 — DWARF pipeline funcional no `mali_kbase.ko`

Abrir HexCore, regen `fresh-helix-souper-*` sobre Intigriti folder. Confirmar logs:
- `[dwarf] Loaded 792 structs, 3864 functions, 1633 boundaries`
- `[helix-struct] Extracted function name from IR: kbase_jit_allocate`
- `[helix-struct] Applied N renames (X fields, Y params)` (N ≥ 10 pra `kbase_jit_allocate`)

No `.A.c`:
- Header com struct layouts (`struct kbase_context (51160 bytes) {...}`)
- Params renomeados (`kctx, info, ignore_pressure_limit`)
- Field offsets resolvidos (`v->jit_active_head`, `v->usage_id`, etc.)

### Gate 1.3 — PDB feeder funcional (opcional)

Se você tiver algum PE+PDB disponível além do Malware Defeat (SOTR tem PDB? gta-sa?):
- Abrir HexCore e liftar uma função
- Console: `[pdbLoader] parsed N function boundaries from <path>.pdb`
- `[pathfinder] PDB supplemented .pdata: +M function boundaries`

Se só tiver o Malware Defeat → pula este gate, `.node` já validou localmente.

### Gate 1.4 — Build limpo

```bash
# TS compilation
cd C:/Users/Mazum/Desktop/vscode-main/extensions/hexcore-disassembler
npx tsc -p ./
# Expect: zero errors, zero output

# Engine rebuild
cd C:/Users/Mazum/Desktop/HexCore-Helix-Original/HexCore-Helix
./rebuild_engine.bat
# Expect: [5/5] Linking CXX executable helix_tool.exe

# NAPI rebuild
LLVM_LIB_DIR="C:/Users/Mazum/Desktop/caps/llvm-build/build-mlir/lib" npm run build
# Expect: Finished release profile
```

---

## Fase 2 — Consistência documental (30 min)

### Gate 2.1 — Cross-check dos 4 docs

Os 4 docs precisam estar consistentes:

| Doc | O que verificar |
|---|---|
| `vscode-main/CHANGELOG.md` | Heading `## [3.8.0-nightly]` com seções Pathfinder/DWARF/Remill/Azoth/Waves |
| `vscode-main/docs/HexCore.3.8.0.md` | Milestone 1 (1.1-1.8), 4.2 marcadas DONE; Milestone 7 Backlog aberto |
| `vscode-main/docs/FEATURE_BACKLOG.md` | Snapshot atualizado pra 2026-04-19; #31 DONE |
| `vscode-main/docs/HEXCORE_V38_WISHLIST.md` | Header com Status Update W1-W5 deferred |

Todas as 4 já foram atualizadas nessa sessão. Fazer quick review visual.

### Gate 2.2 — Release notes preview

Redigir 1 parágrafo curto de release notes que VOCÊ publicaria no GitHub release. Deve mencionar:
- Destaques (Pathfinder + Helix 0.9.0 + Azoth + DWARF feeder)
- Known limitations (batch decompile, type specifier, HQL signatures, W1-W5 deferred)
- Migration notes (se tiver — provavelmente não tem)
- Agradecimentos

**Template pra começar:**

```
## HexCore 3.8.0 — "Souper Era + Pathfinder + Project Azoth"

HexCore 3.8.0 ships the Pathfinder CFG pre-lift engine, Helix decompiler v0.9.0
with DWARF/PDB metadata ingestion, Project Azoth clean-room dynamic analysis
framework (replaces Qiling, Apache-2.0), Perseus zero-copy IPC for Unicorn hooks,
the refcount audit scanner v0.1 (4 bounty-bug patterns), 55 YARA anti-analysis
rules, and the first Windows N-API build of Google Souper with Z3 SMT.

Highlights:
- `kbase_jit_allocate` (mali_kbase.ko): 13L → 287L with real parameter names
  (`kctx, info, ignore_pressure_limit`) and field names (`jit_active_head,
   jit_pool_head, usage_id, deferred_pages_list, reclaim`).
- Pathfinder + Remill FIX-025: 134 BBs survive end-to-end (vs 7 pre-v3.8.0).
- Project Azoth: 5/5 Parity Gates, 22,921 API calls captured on v3 malware.
- Perseus SAB: 1.34× Unicorn hook throughput, 100% vs ~35% delivery.

Known limitations (planned for 3.8.1 / 3.9.0):
- Batch decompile (N functions in one job)
- Type specifier propagation at engine level (struct types in signatures)
- PDB TPI parser (struct types from PDB)
- Wishlist W1-W5 (xref headless, IAT resolution, TLS callbacks dedicated,
   emulate-from-address, XOR brute force headless) deferred
- Refcount audit Pattern D (needs dataflow CFG)
- Kernel anti-debug indicators (DR0-7, MSR, CR access)

Thanks to Anthropic Claude and Google Gemini for pair-programming sessions
during v3.8.0 development.
```

---

## Fase 3 — Polish opcional (2-3h se tempo permitir)

**NÃO é bloqueante.** Se você quiser shippar HOJE, pula direto pra Fase 4.

Mas se quiser fechar 2-3 itens de polish que aumentam confiança:

### Polish 3.1 — Batch decompile MVP (~1h)

Wrapper TS simples que pega um array de IR strings (ou lê `.ll` de uma pasta) e chama `decompileIR` em loop, concatenando outputs em 1 `.c` único com `// === function_N ===` separadores.

Valor: fecha promessa pro bug bounty workflow (auditar 209 funções em 1 job). Nome sugerido: `hexcore.helix.decompileBatch`.

### Polish 3.2 — Engine-level type specifier integration (~2h)

Expor `structInfo` como attr no `CFuncDecl` no CAstBuilder. No `CAstPrinter`, quando emitindo param signature, checar se a param tem struct type em `structInfo.functions[name].params[i].type` e emitir `struct kbase_context *` em vez de `int64_t`.

Valor: fecha o gap de type specifier que a gente viu hoje. Sem isso, header da função fica `int64_t kctx` em vez de `struct kbase_context *kctx`.

### Polish 3.3 — Commit + push de tudo uncommitted (~30 min)

vscode-main tem muito trabalho uncommitted (1734 linhas CHANGELOG + extensões várias). Organizar em commits lógicos:

```
commit 1: feat(helix-3.8.0): Pathfinder DWARF + PDB + ET_REL metadata feeder
commit 2: feat(helix-3.8.0): struct rename pipeline end-to-end + symtab range-aware lookup
commit 3: docs(helix-3.8.0): consolidate CHANGELOG + update HexCore.3.8.0.md + FEATURE_BACKLOG + WISHLIST
commit 4: fix(remill-fork): remove uncommitted FIX-027 regression
```

**Se pular polish 3.3** → release ficará sem referência git clara; não recomendado.

---

## Fase 4 — Release gate (decisão go/no-go)

### Checklist final antes de taggear

- [ ] Fase 1 todos os gates passaram ou documentados
- [ ] Fase 2 docs consistentes
- [ ] Fase 3 polish feito ou explicitamente saltado
- [ ] Release notes escritas
- [ ] `git status` em vscode-main: limpo ou justificado
- [ ] `git status` em HexCore-Helix-Original: limpo ou justificado
- [ ] Standalone hexcore-remill: já v0.4.0 commitado + pushed ✓
- [ ] Standalone hexcore-souper: ver se precisa bump
- [ ] Standalone hexcore-elixir (Azoth): ver se precisa tag v1.0.0

### Decisão

**Se TODOS os checks passaram** → Fase 5.
**Se 1-2 checks falharam** → documentar como known limitations, Fase 5 mesmo assim.
**Se 3+ checks falharam** → criar `v3.8.0-rc1` tag, deixa bake 3-5 dias, volta ao checklist.

---

## Fase 5 — Ship (1h)

### 5.1 — Tag commits principais

```bash
# vscode-main
cd C:/Users/Mazum/Desktop/vscode-main
# Substitui "3.8.0-nightly" por "3.8.0" no CHANGELOG
# Rename tag
git tag -a v3.8.0 -m "HexCore 3.8.0 — Souper Era + Pathfinder + Project Azoth"
git push origin v3.8.0

# HexCore-Helix-Original (se aplicável — engine shipou embutido)
cd C:/Users/Mazum/Desktop/HexCore-Helix-Original/HexCore-Helix
git tag -a helix-v0.9.0 -m "Helix 0.9.0 — Waves 1-12 + DWARF feeder pipeline"
git push origin helix-v0.9.0
```

### 5.2 — GitHub release

Criar release pelo `gh`:

```bash
cd C:/Users/Mazum/Desktop/vscode-main
gh release create v3.8.0 \
  --title "HexCore 3.8.0 — Souper Era + Pathfinder + Project Azoth" \
  --notes-file release-notes-3.8.0.md
```

Onde `release-notes-3.8.0.md` é o texto da Fase 2.2.

### 5.3 — Standalone repos sync (se aplicável)

Se os standalone repos receberam changes:
- hexcore-remill: já em v0.4.0 pushed
- hexcore-souper: tag se teve mudança
- hexcore-elixir: tag v1.0.0 se Azoth é release-ready standalone

### 5.4 — Social / anúncio

Opcional: post curto no X/Twitter / LinkedIn / Discord da sua comunidade. Formato sugerido:

```
HexCore 3.8.0 is out 🔥

Ships:
- Pathfinder CFG engine (2-3× more BBs than stock Remill)
- Helix decompiler v0.9.0 with DWARF/PDB type recovery
- Project Azoth — clean-room Apache-2.0 dynamic analysis (replaces Qiling)
- Perseus zero-copy IPC (1.34× Unicorn throughput)
- Refcount audit scanner (4 bounty-bug patterns)
- Souper superoptimizer first Windows N-API build

Paper: [link]
Download: [link]
Known limitations: [link release notes]
```

---

## Fase 6 — Post-ship (primeira semana)

- Monitorar issues GitHub / Discord por bug reports
- Se crash reports → priorizar patch 3.8.1
- Se output quality complaints → priorizar based on freq
- Se comunidade achar regressão → acknowledge + 3.8.1 patch

**Não travar em perfection.** O objetivo do shipping é unblock o próximo ciclo (3.9.0) onde features realmente grandes (batch decompile, engine-level types, HQL anti-analysis signatures, kernel driver signatures JSON) são roadmap'd.

---

## Timeline estimada

| Fase | Tempo | Dia |
|---|---|---|
| 1 — Verificação | 1-2h | hoje |
| 2 — Docs consistency | 30min | hoje |
| 3 — Polish (opcional) | 0-3h | hoje ou amanhã |
| 4 — Release gate | 10min decisão | hoje ou amanhã |
| 5 — Ship | 1h | Apr 20-21 |
| 6 — Post-ship watch | ongoing | Apr 22+ |

**Janela ideal:** ship antes do hackathon começar (Apr 21) para que vocês entrem com 3.8.0 stable no portfólio. Ou depois do hackathon se preferir atenção focada lá primeiro.

---

## Gaps explícitos pra próxima versão (3.8.1 / 3.9.0)

Registrar aqui pra não esquecer:

**3.8.1 (patch releases, conforme bugs aparecerem):**
- Type specifier engine-level (hoje é text-level post-processor)
- VFS / PE relocations / GetProcAddress / NT syscalls do Azoth
- Bugs encontrados pela comunidade

**3.9.0 (next major):**
- Batch decompile (N funções em 1 job)
- PDB TPI parser (types de PDB, símetrico ao DWARF)
- Refcount audit Pattern D (dataflow CFG-aware)
- Kernel driver signatures JSON (ntoskrnl + Linux kernel)
- Kernel anti-debug indicators (DR0-7, MSR, CR)
- HQL anti-analysis signatures (4 JSON specs + command)
- W1-W5 wishlist items como comandos headless dedicados
- SAILR-style ISD/ISC goto-aware structuring (Wave 13)
- State machine visualization (Milestone 4.4)

---

## TL;DR minha recomendação

1. **Fase 1 hoje** (1-2h): benchmark + DWARF smoke test
2. **Fase 2 hoje** (30min): docs review
3. **Fase 3 polish**: se tiver tempo, SÓ fazer 3.3 (commits organizados). Pula 3.1 e 3.2 pra 3.9.0
4. **Fase 4 decide**: 90% chance todos os checks passam
5. **Fase 5 ship** até Apr 21 pro hackathon ou Apr 22-23 depois

Ship é hoje ou amanhã. O core está sólido.
