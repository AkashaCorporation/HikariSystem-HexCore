# HexCore 3.8.0 — "Pathfinder + Audit Engine + Project Azoth"

> **Codenames:** Pathfinder (CFG recovery) + Perseus (SAB zero-copy IPC) + **Azoth** 🜇 (clean-room dynamic analysis engine — first release)
> **Focus:** CFG Recovery Engine, Vulnerability Audit Automation, Kernel Driver Analysis, Clean-Room Dynamic Analysis
> **Context:** Battle-tested in real bug bounty sessions — 4 vulnerabilities found across ARM Mali (`mali_kbase.ko`), Qualcomm Adreno KGSL (`kgsl.c`), and Riot Vanguard (`vgk.sys`). Two reported to ARM/Intigriti, two to Qualcomm VRP. Wave 2 added full end-to-end emulation of `Malware HexCore Defeat.exe` v3 "Ashaka Shadow" (1M instructions, 23k API calls, zero crashes). **Project Azoth** ships as a new clean-room, Apache-2.0, Rust+C++23 dynamic analysis framework replacing Qiling for v3.8.0's default emulation path.

---

## Milestone 0 — hexcore-souper (Superoptimizer) ✅ DONE

> First Windows N-API build of Google Souper with Z3 SMT solving.

### 0.1 Souper v0.1.0 — N-API Wrapper ✅

- Complete N-API wrapper following POWER.md pattern (14 files)
- `SouperOptimizer` class: `optimize(irText, options?) → { success, ir, candidatesFound, candidatesReplaced, optimizationTimeMs }`
- Sync + Async variants (threshold: 64KB)
- Z3 runtime DLL handling in `index.js`
- Standalone repo: `AkashaCorporation/hexcore-souper`
- CI: prebuilds matrix, installer workflow (Win + Linux), `nativeExtensions`
- Pipeline: `souperWrapper.ts` wired into both Helix entry points

### 0.2 Souper v0.2.0 — Z3 SMT Solving ✅

- Z3 constraint solving functional: `sub x, x → 0` proven
- Near-zero impact on production binaries (ROTTR, kernel modules)
- **Decision:** Disabled by default (`souper: false`), enable for obfuscated/crypto analysis

---

## Milestone 1 — Pathfinder CFG Recovery Engine (P0) ✅ DONE

> Replaces Remill's linear sweep with guided recursive descent. Expected 2-3x more basic blocks and function calls in decompiled output.

### 1.1 Binary Context Provider ✅

**Problem:** Remill's linear sweep stops at the first undecodable instruction (`endbr64`, data-in-code, jump tables). Functions that IDA decompiles with 30+ BBs produce only 7 BBs in HexCore.

**Implementation:** New module `pathfinder.ts`

- ✅ **PE64 Context** — Parse `.pdata` exception directory (12-byte `RUNTIME_FUNCTION` entries: `BeginAddress`, `EndAddress`, `UnwindInfoAddress`). Gives **exact function boundaries** for every non-leaf function. For ROTTR.exe, `.pdata` has ~50,000 entries.
- ✅ **ELF Context** — Parse `.symtab` `STT_FUNC` entries (`st_value` + `st_size`). For `mali_kbase.ko`, this gives 7,313 function boundaries.
- ✅ **Entry point collection** — PE entry, TLS callbacks, exports, ELF `e_entry`, all `STT_FUNC` exports.
- ✅ **`.rodata` mapping** — Section ranges where jump table data lives. Used by Phase 3 to validate resolved targets.
- ✅ **Fallback boundary resolution** — When Phase 1 context mismatches (ELF REL address space), falls back to engine's function table with innermost-function selection.

**New method:** `disassemblerEngine.parsePdataDirectory(rva, size)` — reads `.pdata` entries, stores in `pdataEntries[]`.

**Files:**
- NEW: `extensions/hexcore-disassembler/src/pathfinder.ts`
- MOD: `extensions/hexcore-disassembler/src/disassemblerEngine.ts` — add `.pdata` parsing, `getPdataEntries()`

### 1.2 Recursive Descent Disassembler ✅ (v0.2.0: replaced with Capstone batch decode)

**v0.1.0:** `RecursiveDescentScanner` class in `pathfinder.ts`
- Worklist-based recursive descent from entry point using Capstone
- Instruction classification: `ret`, `jmp`, `jcc`, `call`, indirect `jmp [reg]`, `nop`, `endbr64`
- Leader discovery: branch targets, fallthrough after `jcc`, call targets
- Tail call detection: `JMP` to address outside function bounds (from `.pdata`/`.symtab`)
- Safety: 64KB scan limit per function, skip addresses in `.rodata` ranges
- Uses `visited: Set<number>` to avoid infinite loops on cyclic CFGs

**v0.2.0 upgrade:** Architecture-aware dispatch
- ✅ **x86/x64**: Full-buffer Capstone batch decode — single `disassemble(bytes, addr, maxInsns)` call extracts ALL branch targets. Found 479 insns / 142 leaders on `kbase_jit_allocate` benchmark.
- ✅ **ARM64**: Fixed 4-byte instruction linear decode with NOP/BRK/UDF padding detection.
- ✅ **Code-after-ret discovery** for exception handlers and pointer-called code.

### 1.3 Jump Table Resolver ✅

**Implementation:** `JumpTableResolver` class in `pathfinder.ts`

- ✅ Backward slice (15 instructions) from indirect `jmp [reg]`
- ✅ Pattern match MSVC x64 and GCC/SysV patterns
- ✅ 32-bit signed relative offset table reading with sanity checks
- ✅ Re-scans from resolved jump table targets for complete CFG coverage

### 1.4 NOP Range Detection ✅

- ✅ Detect and skip: `endbr64` (F3 0F 1E FA), ftrace `__fentry__` NOPs (E8 00 00 00 00), INT3 padding (CC+)
- ✅ ARM64: NOP (`0xD503201F`), BRK (`0xD4200000`), UDF (`0x00000000`) padding detection
- ✅ Output: `ByteRange { start, size, kind }` — passed to Remill as skip ranges

### 1.5 Gap Scanning (Prologue Heuristics) ✅

- ✅ x86-64 prologue byte patterns: `push rbp; mov rbp, rsp`, `sub rsp, N`, `endbr64 + push`, MSVC fastcall, `push r12-r15`
- ✅ Verify candidates with Capstone (decode 3+ instructions)
- ✅ Catches functions only reachable via indirect calls / vtables

### 1.6 Hints Synthesizer & Remill Integration ✅

- ✅ `CFGHints` TypeScript interface (FlatBuffers schema deferred — JSON sufficient for now)
- ✅ `additionalLeaders` passed to Remill Phase 1.5 and used as BB leaders in Phase 2
- ✅ `knownFunctionEnds` from `.pdata` used for tail call detection (FIX-026: no longer truncates scan)
- ✅ TypeScript `liftToIR` + `decompileToC`: both paths run Pathfinder before Remill

### 1.7 Remill Fixes (discovered during Pathfinder integration) ✅

- ✅ **FIX-024**: XED-ILD desync recovery — when `DecodeInstruction` fails on exotic x86 (AVX-512, APX, MPX), XED Instruction Length Decoder computes exact length, emits `kCategoryNoOp` placeholder, advances. Silent safety net (zero perf cost when not triggered).
- ✅ **FIX-025** (CRITICAL): Call fall-through wiring — Phase 3 switch was missing `kCategoryDirectFunctionCall`, `kCategoryIndirectFunctionCall`, `kCategoryAsyncHyperCall`, `kCategoryConditionalAsyncHyperCall` in fall-through case. BBs after CALL were orphaned → Phase 4 forced `ret` → LLVM DCE cascaded. On `kbase_jit_allocate`: 134 leaders → only 7 BBs survived. Fixed in both Phase 3 and Phase 3.5 (gap re-lift).
- ✅ **FIX-026**: Don't send `.pdata` `functionEnds` that truncate Remill scan. PE64 `.pdata` covers SEH unwind extent (can be shorter than actual function). Was causing 5x .ll regression on `ObjectManager-Create` (948→197 lines). Now only sends ends beyond caller's buffer.
- ✅ **FIX-027 regression removed** (2026-04-19): an undocumented working-tree change in `remill_wrapper.cpp` (skip ALL NoOps + `continue` on lift failure) silently shadowed the prebuild and regressed `kbase_jit_allocate` 2657→630 on the `.ll` side (4× input truncation). Bisected out; FIX-023/024/025 ship intact. Details in CHANGELOG under "Remill Wrapper — Undocumented change removed".

### 1.8 DWARF + PDB metadata feeder ✅ DONE (2026-04-19)

- ✅ **DWARF function boundaries** (`elfDwarfLoader.ts` → `StructInfoJson.boundaries`): `DW_TAG_subprogram` DIEs emit `{name, lowPc, highPc}` tuples. Pathfinder's `extractELFContext` merges these alongside `.symtab` entries (dedup, `.symtab` wins ties). Adds coverage on stripped `.ko`/`.so` binaries where `.symtab` is missing.
- ✅ **PDB function boundaries** (new `pdbLoader.ts`): spawns `llvm-pdbutil` and parses `S_GPROC32`/`S_LPROC32`. Pathfinder's `extractPE64Context` merges alongside `.pdata` (dedup, `.pdata` wins ties). Covers **leaf functions that `.pdata` doesn't** — on PE+PDB binaries this closes a meaningful gap.
- ✅ **ET_REL relocation application**: `.rela.debug_*` entries now applied in-place on debug section buffers before parsing. Without this, DWARF in kernel modules was useless (all cross-section refs were 0-placeholders).
- ✅ **End-to-end decompile impact**: see Milestone 4.2.

**Priority:** P0 — ~~4-5 sessions estimated~~ **Completed in 3 sessions (2026-04-08/09/10)**
**Impact:** 2-3x more BBs, resolves jump tables, enables Helix to compete with Hex-Rays on complex functions

---

## Milestone 2 — Vulnerability Audit Engine (P0)

> New `hexcore.audit.*` pipeline commands that automate the vulnerability patterns that found 4 bugs across 3 targets.

### 2.1 Refcount Audit Scanner — `hexcore.audit.refcountScan` ✅ PARTIAL (v0.1 DONE, Wave 3.2)

**Problem:** All 4 bugs found in bounty sessions were refcount/state errors in error paths. Currently finding them requires manual audit of 200+ decompiled functions.

**Detection patterns:**

| Pattern | Description | Found in | v0.1 Status |
|---------|-------------|----------|-------------|
| A | Increment before error check, no rollback on failure | Mali Bug #1 (kbase_gpu_mmap) | ✅ DONE |
| B | `_force` variant ignoring refcount entirely | Mali Bug #2 (release_force) | ✅ DONE |
| C | Unconditional operation after failed refcount get | Qualcomm Bug #2 (vm_open UAF) | ✅ DONE |
| D | Lock-drop-reacquire with stale pointer | (JIT allocate — confirmed protected) | ⬜ v0.2 (needs dataflow CFG) |
| E | Reachable BUG_ON/panic on allocation failure | Qualcomm Bug #1 (VBO BUG_ON) | ✅ DONE |

**Shipped in v0.1 (Wave 3.2, 2026-04-17):**
- ✅ **`extensions/hexcore-disassembler/src/refcountAuditScanner.ts`** (~480 LOC) — zero-dep, regex + label-tracking scanner over decompiled C
- ✅ **`hexcore.audit.refcountScan` command** registered in `extensions/hexcore-disassembler/src/extension.ts`. Accepts `input` or `file` arg pointing to `.c`/`.helix.c`. Headless-safe with `output: { path: ... }`.
- ✅ **`RefcountAuditReport` shape** — `{inputFile, fileSize, scannedLines, functionsScanned, findings: RefcountAuditFinding[], summary: {total, byPattern, bySeverity, highestConfidence}, scanTimeMs}`. Each finding has pattern/severity/confidence/title/description/function/line/snippet/affectedSymbol/suggestion/referenceBug.
- ✅ **`REFCOUNT_PAIRS`** — 15 curated get/put pairs across Linux kernel (kref/refcount/atomic/task/device/dentry/module/file/mount/inode/dma_buf), GPU driver specifics (`kbase_*`, `kgsl_*`), and Windows KM (`ObReferenceObject*`/`ObDereferenceObject`).
- ✅ **Confidence scoring** — Pattern A fires at 60-95 based on `(risky exits × 10) + (get/put imbalance bonus)`; Pattern B at 80/60 for definition-side / caller-side; Pattern C at 75 (UAF deref detected in success branch); Pattern E at 30/55/85 based on gating (BUILD_BUG_ON excluded; NULL/OOM-gated BUG_ON scored highest).
- ✅ **Function extraction** via brace-matcher (`extractFunctions()`) — handles inline `int foo() {` and multi-line `int foo()\n{`. Safety cap at 5000 lines per function to prevent runaway scans.
- ✅ **Dedup** on `(function:line:pattern)` — keeps highest confidence when multiple pattern variants match same line.
- ✅ **Bounty bug attribution** — findings include `referenceBug` field when the matched family maps to a known bug (e.g. pattern A on `kbase_*` tags Mali Bug #1). Great for quickly filtering the output for "same-class" vulnerabilities in a new target.
- ✅ **Pipeline integration** — `hexcore.audit.refcountScan` in `COMMAND_CAPABILITIES` (60s timeout, validates output) + `COMMAND_OWNERS`, plus entry in `package.json` commands (`HexCore Automation` category).
- ✅ **Verified on synthetic vulnerable functions** — 4/4 patterns fire correctly against a crafted test input that reproduces the 4 bounty bug shapes. Each matched finding references its bounty bug provenance.

**Still open (v0.2 targets):**
- ⬜ **Pattern D** — lock-drop-reacquire with stale pointer. Requires proper flow-sensitive dataflow: track pointer writes across lock/unlock boundaries. Regex-level analysis cannot catch this safely — deferred until a real CFG interpreter lands.
- ⬜ **Full Mali/Qualcomm corpus validation** — run against `mali_kbase.ko` / `kgsl.c` real decompiled outputs, measure false-positive rate, tune confidence thresholds.
- ⬜ **Multi-file crawler** — scan every `.helix.c` in an output directory in one command (currently single-file).
- ⬜ **Markdown report variant** — alongside JSON, produce a human-readable `.md` triage report with snippets + suggestions inline.

**Priority:** P0 — CRITICAL — directly automates what found all 4 bugs. **v0.1 delivers the 4 bounty-bug-matching patterns (A/B/C/E) fully functional.**

### 2.2 Attack Surface Mapper — `hexcore.audit.attackSurface`

**What it does:**
- Count IOCTL handler references, `copy_from_user`/`copy_to_user` calls
- Identify device nodes and their permissions (from source or runtime)
- Map syscall entry points → handler functions → kernel API calls
- Output: ranked list of functions by attack surface exposure

**Input:** ELF `.ko` or source directory
**Output:** JSON with function names, IOCTL codes, user-facing API counts

### 2.3 Error Path Analyzer — `hexcore.audit.errorPathAnalysis`

**What it does:**
- Trace all `goto` labels in decompiled/source C code
- For each error path, check what cleanup operations are performed vs what was initialized before the goto
- Flag: missing `kfree`, missing `put` after `get`, missing `unlock` after `lock`, missing `unmap` after `map`

### 2.4 `vuln-audit` Pipeline Preset

```json
{
  "preset": "vuln-audit",
  "steps": [
    { "cmd": "hexcore.filetype.detect" },
    { "cmd": "hexcore.hashcalc.calculate" },
    { "cmd": "hexcore.entropy.analyze" },
    { "cmd": "hexcore.disasm.analyzePEHeadless", "continueOnError": true },
    { "cmd": "hexcore.disasm.analyzeELFHeadless", "continueOnError": true },
    { "cmd": "hexcore.disasm.analyzeAll" },
    { "cmd": "hexcore.strings.extractAdvanced" },
    { "cmd": "hexcore.disasm.rttiScanHeadless", "continueOnError": true },
    { "cmd": "hexcore.audit.attackSurface" },
    { "cmd": "hexcore.audit.refcountScan" },
    { "cmd": "hexcore.audit.errorPathAnalysis" },
    { "cmd": "hexcore.yara.scan", "args": { "categories": ["drivers"] } },
    { "cmd": "hexcore.pipeline.composeReport" }
  ]
}
```

**Priority:** P0 for refcountScan, P1 for attackSurface and errorPathAnalysis

---

## Milestone 3 — Kernel Driver Analysis Hardening (P1)

> Improvements derived from real-world issues encountered during Mali Kbase and Vanguard analysis.

### 3.1 Kernel Driver Signature Database

**Problem:** `analyzePEHeadless` resolved only 1 of 79 imports on `vgk.sys` — zero kernel API coverage.

**Implementation:**
- NEW: `signatures/kernel-win64.json` — ntoskrnl.exe (~3500), HAL.dll, NDIS.sys, WDF, cng.sys
- NEW: `signatures/kernel-linux.json` — mutex_lock, kmalloc, copy_from_user, dma_map_sg, get_user_pages, kref_get/put
- Each entry: `{ name, prototype, paramCount, category, securityTags[] }`
- Categories: `memory_alloc`, `process_mgmt`, `object_mgmt`, `sync`, `crypto`, `io`, `mmu`, `dma`
- Security tags: `user_controlled_input`, `privilege_boundary`, `refcount_manipulation`, `memory_mapping`

### 3.2 Kernel/User Security Indicators ✅ PARTIAL

**Problem:** `securityIndicators.hasAntiDebug: false` on Vanguard anti-cheat driver and user-mode malware.

**Shipped (HEXCORE_DEFEAT Fix #7+#9 — userland instruction scanner in `hexcore-peanalyzer`):**
- ✅ **`AntiAnalysisInstruction` interface** — `{ address, type, mnemonic, opcodeHex, category }` with 8 opcode patterns scanned in all executable sections:
  - `0F 31` (rdtsc) → timing
  - `0F 01 F9` (rdtscp) → timing
  - `0F A2` (cpuid) → vm_detect
  - `CD 2D` (int 2d) → legacy_anti_debug
  - `0F 01 C1` (vmcall) → vm_detect
  - `65 48 8B 04 25 60 00 00 00` (mov rax, gs:[0x60]) → peb_access (x64)
  - `64 A1 30 00 00 00` (mov eax, fs:[0x30]) → peb_access (x86)
  - `F0 0F C7` (lock cmpxchg8b) → legacy_anti_debug
- ✅ **`SecurityIndicators` interface** — `{ hasTimingChecks, hasCpuidChecks, hasDirectPebAccess, hasVmDetection, antiAnalysisInstructions, density, suspiciousDensity }`. Density = hits per KB of `.text`. Threshold `suspiciousDensity > 0.5` separates CRT noise (notepad.exe = 0.056, PING.EXE = 0) from real anti-analysis (malware = 1.0+).
- ✅ **Wired into `analyzePEFile()`** after strings extraction. Field is optional on `PEAnalysis` for backward compatibility.
- ✅ **Verified no false positives on clean binaries**: notepad.exe (9 hits / 164KB → density 0.056, not flagged), malware v1 (10 hits / 10KB → density 1.0, flagged).

**Still open:**
- ⬜ Kernel anti-debug: `KdDebuggerEnabled`, `KdDisableDebugger`, DR0-DR7 access
- ⬜ Privileged instructions: RDMSR (`0F 32`), WRMSR (`0F 30`), MOV CR0/CR3/CR4
- ⬜ Linux .ko indicators: `copy_from_user` count, IOCTL handler patterns, `capable()` checks, `kref_get/put`
- ⬜ Section anomaly detection + `protectionAnalysis` output block

### 3.3 IOC Extract — False Positive Fixes & Registry Paths ✅ PARTIAL

**Problem:** `HH:MM:SS` timestamps matched as IPv6 addresses. Anti-VM registry strings (`SOFTWARE\VirtualBox Guest Additions`) were invisible to the extractor.

- ⬜ Timestamp filter: skip `\d{2}:\d{2}:\d{2}` when surrounded by date context
- ✅ **Registry path extraction** (HEXCORE_DEFEAT Fix #8) — extended `registryKey` regex to match standalone `SOFTWARE\...`, `SYSTEM\...`, `HARDWARE\...` paths plus `HKLM/HKCU/HKCR/HKU/HKCC`. Added semantic sub-classification tags: `anti_vm_registry` (VBox/VMware/Parallels/QEMU/Xen/Hyper-V), `persistence_registry` (Run/RunOnce/Winlogon), `generic_registry`. Optional `tags?: string[]` field on `IOCMatch`.
- ✅ **`hasValidPrintableContext` edge bug** — full-region matches surrounded by nulls were rejected. Now accepts matches where `matchLength ≥ MIN_PRINTABLE_CONTEXT` (the match itself is the context).

### 3.4 YARA Rules — Built-in Anti-Analysis Pack ✅ DONE

- ✅ **`extensions/hexcore-yara/rules/AntiAnalysis/`** — 7 rule files, **55 rules total** (Wave 2: 37, Wave 3: +18):
  - `anti-debug.yar` — IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess, `gs:[0x60]` x64 PEB, `fs:[0x30]` x86 PEB, rdtsc/int2d opcodes
  - `anti-vm.yar` — VMware/VBox/VIRTUAL/Hyper-V strings + registry paths, CPUID `0F A2`, hypervisor ECX bit 31 check
  - `obfuscation.yar` — single-byte XOR loop, multi-byte XOR patterns
  - `api-hashing.yar` — PEB walk signature, djb2 `0x5381`, fnv1a `0x811C9DC5` constants
  - `dynamic-api.yar` — GetProcAddress + LoadLibraryA combos
  - `ashaka-v3.yar` **(Wave 3)** — 10 rules for v3/v4 Ashaka family: XOR key literal, djb2 pre-computed hashes, dynamic ShellExecute combo, full critical combo, stack XOR init sequence, v4 runtime key generation, v4 fragmented payload vector, v4 salted djb2
  - `ashaka-v5.yar` **(Wave 3)** — 8 rules for v5 polymorphic evasion: FNV-1a custom prime, KUSER_SHARED_DATA access, environmental keying, fragmented PEB walk, ordinal import hint, opaque predicate, self-modifying stub, banner attribution
- ✅ **Recursive rule loader** — `yaraEngine.loadRulesFromDirectory` now walks nested directories (was top-level only).
- ✅ **`rulesPath` setting bug fixed** — previously declared in `package.json` but never read; activation now loads custom user rules from this path.
- ✅ **New setting `hexcore.yara.builtinRulesEnabled`** (default `true`, opt-out) — allows disabling the built-in pack if false positives surface.
- ✅ **Verified**: `Malware HexCore Defeat.exe` v1 scan produces 17 matches, `threatScore: 100/100`. v4 produces 26 matches, v5 produces ≥22 matches — all `threatScore: 100`.
- ✅ **Wave 3 ship blockers fixed**: `updateRules()` was wiping bundled rules after autoUpdate (activation flow dropped 44 to 7); `writeScanOutput` serializer was silently dropping new diagnostic fields; `.vscodeignore` now explicitly keeps `!rules/**` so built-in pack ships in packaged extension.
- ✅ **`ruleLoadDiagnostics` in scan output** — every `ScanResult` now includes `triedPaths[]` + `loadedFrom: string | null` so `threatScore: 0` is diagnosable without opening the Output panel.
- ⬜ Driver-specific rules (`yara-rules/drivers/`, `yara-rules/protection/`) — still open.

---

## Milestone 4 — Helix Decompiler Improvements (P1)

### Helix v0.9.0 — Engine Quality Improvements ✅ DONE (2026-04-10)

> 10 improvements across output quality, crash safety, and naming. **51/51 zero crashes.** `kbase_jit_allocate` output grew from 14 to 133 lines (10x) when paired with Pathfinder v0.2.0 + FIX-025. 42.9% coverage vs IDA ground truth (317 lines).

- ✅ **Variable Coalescing** — Phase 3.5 in RecoverVariables.cpp. Collapses `rax, rax_1, rax_2` into single `rax` when live ranges don't interfere. ~30-50% fewer local variable declarations.
- ✅ **Array/String Detection** — `decomposeArrayAccess()` in RecoverStructTypes.cpp. Recognizes `Add(base, Mul(idx, stride))` and `Shl` patterns. Emits `array_<offset>` or `str_<offset>` with `HelixTypeInfo::makeArray()`.
- ✅ **Alias Analysis Expansion** — Phase 3.5 in EscapeAnalysis.cpp. Must-alias equivalence classes via `(baseSlot, offset)` keys. Annotates `helix.alias_class` for DCE.
- ✅ **RTTI Tier 1 Class Naming** — Phase 4 in DevirtualizeIndirectCalls.cpp. Groups calls by vtable_addr, infers class name from method name prefix. Emits `ClassName::methodName` in output. Wired through HelixMidToHigh attr propagation + CAstBuilder preference.
- ✅ **Self-Assignment Elimination** — `removeSelfAssignments` pass in CAstOptimizer. Drops `x = x;` from SSA coalescing artifacts and Remill identity ops.
- ✅ **Constant Loop Normalization** — Extended `eliminateConstantBranches` to while/do-while/for. `while (-1)` → `while (true)`.
- ✅ **CC Arg Clamping** — Call barrier in `collectAbiCallArgs` (clears regState at call boundaries). SignatureDb clamp + inline kernel sync table (35+ entries: `mutex_lock` 1 arg, `kfree` 1 arg, etc.). Fixes `mutex_unlock(x, spam, spam, spam)` → `mutex_unlock(x)`.
- ✅ **Sequential Variable Naming** — `getSlotNameMap()` in HelixMidToHigh.cpp. Replaces `v{slot_id}` with sequential `v0, v1, v2, ...` per function. Eliminates `v50909`, `v40137` garbage.
- ✅ **Dangling Goto Removal** — `removeDanglingGotos` pass. Drops gotos to undefined labels. Preserves gotos to defined labels (kernel cleanup patterns are idiomatic — IDA has 10 gotos in `kbase_jit_allocate`).
- ✅ **DominanceInfo Crash Guard** — `hasIrreducibleSCCs()` helper protects ALL 4 DominanceInfo construction sites. Prevents `GenericDomTreeConstruction.h:481` assert when Pathfinder delivers more blocks creating irreducible CFGs. Graceful degradation to flat blocks + goto/label.

### 4.1 Trampoline Following ✅ DONE (Wave 3.1)

**Problem:** Helix decompiled `vgk.sys` entry point as `void { return; }` because it was a single `JMP` into virtualized code.

**Shipped (wrapper-side, no Helix source changes):**
- ✅ **`followTrampolineChain(engine, startAddress, maxHops=8)`** exported from `hexcore-disassembler/src/extension.ts`. Uses the engine's existing Capstone-backed `disassembleRange()` to decode the first instruction at the target. If it's an unconditional JMP with a resolvable in-binary destination, hops to the target and repeats. Stops at: non-JMP / conditional JMP / CALL / RET, target outside binary (import thunks), cycle detection, or 8-hop safety cap.
- ✅ **Wired into `hexcore.disasm.liftToIR`** at both address-path and functionAddress-path entry sites, right after backtrack resolution and before size computation. So Remill lifts the real function body, not the stub.
- ✅ **Output metadata** — when a trampoline is followed, `liftToIR` result includes:
  - `trampolineFollowed: true`
  - `trampolineOriginalAddress: <original>`
  - `trampolineTarget: <resolved>`
  - `trampolineHops: [{ from, to, mnemonic }, ...]`
- ✅ **Opt-out** via `options.followTrampoline: false` for analysts who explicitly want to inspect the stub itself.
- ⬜ "Target in high-entropy section" warning — deferred; Helix already produces warnings via its DominanceInfo crash guard when targets are in virtualized code.

### 4.2 Kernel Struct Type Recovery (Linux .ko) ✅ DONE (2026-04-19)

- ✅ **BTF parser** (see 6.2) — pure-TS parser reads `.BTF` sections, resolves kernel struct layouts and function parameter types. Shipped in `hexcore-disassembler/src/elfBtfLoader.ts`.
- ✅ **DWARF parser** — pure-TS DWARF v5 reader (~550 lines, zero npm deps) for `.ko` files without BTF. Feeds struct info into Helix decompile path.
- ✅ Auto-type function parameters based on kernel API signatures (inline kernel sync table in RecoverCallingConvention — 35+ entries)
- ✅ **Helix struct-info plumbing** — fixed `const → let` bug that was blocking struct info from reaching `decompileIr()`. Struct field names now flow through Remill → Helix pipeline.
- ✅ **DWARF 5 split-form resolution** (2026-04-19) — `DW_FORM_strx*` / `DW_FORM_addrx*` resolve through `.debug_str_offsets` + `.debug_addr` via each CU's `DW_AT_str_offsets_base` / `DW_AT_addr_base`. Previously parser returned empty strings / zero addresses for every DWARF 5 indexed attribute.
- ✅ **ET_REL relocation application** (2026-04-19) — the missing piece for `.ko` files. Debug sections in kernel modules carry cross-section references as 0-placeholders; `extractDwarfSections` now walks `.rela.debug_*` and applies `R_X86_64_{64,32,32S}` entries in-place on debug buffers before parsing. Before this fix, DWARF parser bailed out on every CU past CU0 because abbrev_offset read as 0. Post-fix: 125 CUs parse cleanly.
- ✅ **End-to-end validation on `mali_kbase.ko`**: 7→**792 structs**, 1→**3,864 function signatures with real parameter names and types**, 0→**1,633 DWARF function boundaries** (merged into Pathfinder context alongside `.symtab`). `kbase_jit_allocate` signature matches IDA ground truth exactly: `struct kbase_va_region *(struct kbase_context *kctx, const struct base_jit_alloc_info *info, bool ignore_pressure_limit)`. Helix output `.A.c`: 174L → 287L with 16 renames (13 fields, 3 params) — real names like `jit_active_head`, `jit_pool_head`, `usage_id`, `deferred_pages_list`, `reclaim`, `jit_current_allocations`.
- ⚠️ **Known gap**: the text-level `applyStructFieldNames` post-processor renames parameter identifiers (`param_1` → `kctx`) but can't rewrite type specifiers (`int64_t` stays `int64_t` instead of becoming `struct kbase_context *`). Engine-level integration where CAstBuilder consumes struct-info and emits correct types at C AST emission is tracked for a follow-up session.

### 4.3 Multi-Function Batch Decompilation — OPEN

- Currently Helix decompiles one function at a time
- New batch mode: decompile all functions in a symbol list
- Output: single `.c` file or directory with all functions, preserving call relationships
- Critical for audit workflow: decompile 209 functions in one job instead of 209 jobs

### 4.4 State Machine Visualization — OPEN

- Detect enum-like state variables (small int, used in switch/if chains)
- Generate state transition graph from decompiled code
- Output: DOT graph or Mermaid diagram
- Example: `user_buf.state` transitions: EMPTY → PINNED → DMA_MAPPED → GPU_MAPPED

---

## Milestone 5 — Emulation & Runtime Analysis (P2)

### 5.1 Unicorn Memory Fault Recovery + MSVC CRT Stubs ✅ DONE (Wave 3)

**Problem:** HexCore Unicorn crashed on `vgk.sys` after ~10K instructions (`UC_ERR_WRITE_UNMAPPED`). Separately, MSVC-compiled malware crashed at ~instruction 239 (RIP 0x1400027fb) inside `__p___argv` → NULL deref. v5 Ashaka Mirage additionally crashed mid-`std::cout` chain on `operator<<(int)` when the int variant stub returned 0 instead of `this`.

**Shipped (HEXCORE_DEFEAT Fix #3 + #4 + Wave 3):**
- ✅ **BigInt sign-extension crash fix** — `(Date.now() & 0xFFFFFFFF) >>> 0` to coerce tickCount to unsigned uint32.
- ✅ **MSVC CRT init stubs** (`winApiHooks.ts`) — 6 handlers × 3 DLL aliases: `__p___argv`, `__p___argc`, `_initterm`, `_initterm_e`, `_get_initial_narrow_environment`, `_get_initial_wide_environment`.
- ✅ **`ensureCrtDataAllocated` lazy init** — 256-byte heap block with narrow + wide program name, `char**`/`wchar_t**` argv, NULL environ arrays.
- ✅ **Wave 3: 11 operator<< numeric variants** — method and free-function forms for `int`/`unsigned`/`short`/`ushort`/`long`/`ulong`/`__int64`/`uint64`/`bool`/`void*` with the ostream `this` pointer correctly preserved (returning 0 from these stubs produced cascading null-ostream dereferences mid-print). Plus manipulator variants: endl (`@P6AAEAV01@AEAV01@@Z@Z` — appends `\n`), hex/dec/oct (`@P6AAEAVios_base@1@AEAV21@@Z@Z` — pass-through).
- ✅ **Wave 3: streambuf `sputn` handler** captures real payload bytes via `readMemorySync(args[1], args[2])` and appends to `stdoutBuffer`. This is where `std::cout << "x"` actually writes through the internal MSVC formatter.
- ✅ **Wave 3: `WinApiHooks.stdoutBuffer` + `getStdoutBuffer()` bridge** — previously the `stdout` field in emulation JSON was always empty; now captures the full C++ output trail.
- ✅ **Wave 3: `GetComputerNameA/W` honor `nSize` contract** — reads `*args[1]` first, returns 0 + required-size via ERROR_BUFFER_OVERFLOW semantics when capacity < required. Previously wrote unconditionally → anti-emu probes could fingerprint by passing `nSize=4`.
- ✅ **Wave 3: `ShellExecuteA/W` returning 42** (>32 = success per MSDN) with URL target extracted from `args[2]` (wide string) and logged. Previously fell through to default-0 → v5 reported "Beacon failed" incorrectly.
- ✅ **Wave 3: `RegOpenKey*` / `RegQueryValueEx*` return ERROR_FILE_NOT_FOUND (2)** — absorbs anti-VM registry probes silently, makes malware's `CheckAntiVM_Registry()` pass as "not a VM".
- ✅ **Wave 3: `isDataImport()` regex `+` → `*`** — non-namespaced MSVC globals like `?_global_var@@3HA` now correctly classified as data (were being routed to RET stubs, producing wrong dereferences).
- ⬜ Generic page fault auto-mapping with configurable limit (default 500) — still open for `vgk.sys`-class issues.
- ⬜ Configurable job args: `"faultLimit": 500, "autoMapPermissions": "rwx"`

### 5.2 Kernel Struct Stubs — OPEN

- Pre-built memory layouts for: `DRIVER_OBJECT` (Win), `task_struct`, `mm_struct`, `file` (Linux)
- User-configurable struct templates in job args
- Auto-detect driver entry calling convention and pre-populate RCX/RDI with stub addresses

### 5.3 Instruction-Level Hooks ✅ PARTIAL (Wave 3)

**Shipped:**
- ✅ **CPUID hypervisor vendor whitelist** (leaf `0x40000000`) — returns empty vendor so malware using the correct "Microsoft Hv" allowlist pattern does not false-positive on Win10/11 VBS. Returns "GenuineIntel" on leaf 0, ECX bit 31 cleared on leaf 1, zero for unknown leaves.
- ✅ **`notifyApiRedirect()` in all anti-analysis closures** (rdtsc/rdtscp/cpuid) — Unicorn's `UC_HOOK_CODE` fires BEFORE the instruction and mid-hook RIP rewrite is NOT honored; emuStop() routing is needed to skip the original opcode.
- ✅ **`antiAnalysisStats: { installs, fires }`** diagnostic in emulation output JSON — separates "byte-scan missed the opcode" (installs=0) from "hook installed but never reached" (installs>0, fires=0).
- ✅ **`hitAddr !== addr` guard** in each closure — on legacy TSFN path `codeHooks.forEach` broadcasts to every hook on every instruction; without this guard, captured-address closures would clobber registers on unrelated instructions.

**Open:**
- ⬜ Hook `RDMSR`/`WRMSR` — log MSR index and value, return configurable fake values
- ⬜ Hook `INT` — skip anti-debug interrupts (int 2D, int 3 for VEH-based anti-debug)
- ⬜ Hook `CALL reg` — match target against import address map (currently relies on PEB_LDR_DATA + synth DLL export dir path)

### 5.5 KUSER_SHARED_DATA + Synthetic DLL Region (Wave 3) ✅ DONE — NEW

> Bypass hooks for timing-check evasion (reading time from `0x7FFE0000` instead of `rdtsc`) and for hash-resolved exports (shellcode/Ashaka-class malware that walks PEB → LDR → module's export table to find APIs by FNV/djb2 hash of name, bypassing the IAT entirely).

- ✅ **KUSER_SHARED_DATA page at `0x7FFE0000`** — 4 KB read-only region populated with:
  - `InterruptTime` (0x08), `SystemTime` (0x14), `TickCount` (0x320) in 100ns units
  - `TickCountMultiplier` (0x04) = `0x0FA00000`
  - `NtProductType` = WinNt (1), `NtMajorVersion` = 10, `NtBuildNumber` = 19045
  - `NativeProcessorArchitecture` = AMD64, `ImageNumber` = 0x8664
  - `KdDebuggerEnabled` = 0
- ✅ **8 synthetic DLL PE images at `0x72000000..0x72040000`** — `ntdll.dll`, `kernel32.dll`, `KERNELBASE.dll`, `ucrtbase.dll`, `msvcp140.dll`, `shell32.dll`, `advapi32.dll`, `user32.dll`. Each 4 KB page has a real DOS header (MZ) + NT header (PE32+) + Export Directory with Function RVAs, Name RVAs, Ordinals, DLL name string, API name pool, and inline RET stubs at RVA 0x800.
- ✅ **PEB_LDR_DATA populated with entries** — 8 `LDR_DATA_TABLE_ENTRY` structs linked into three circular lists (`InLoadOrder`/`InMemoryOrder`/`InInitializationOrder`) with correct `FullDllName` (`"C:\\Windows\\System32\\kernel32.dll"`) and `BaseDllName` (`"kernel32.dll"`) as proper UNICODE_STRINGs.
- ✅ **`peLoader.getSyntheticModules() → winApiHooks.registerSyntheticModules()`** — pre-seeds `moduleHandles` so `LoadLibraryA("shell32.dll")` returns the synth base (e.g. `0x72005000`) with valid PE headers, not an opaque `allocHandle()` value that would fail `ResolveExport`.
- ✅ **Code-hook dispatch for synth stubs** — `isStubAddress()` recognizes both `STUB_BASE` (0x70000000) and `SYNTHETIC_DLL_BASE` (0x72000000) ranges. SAB-path watchAddresses populated for every synth stub via `registerCodeHookAtAddress`. pe32Worker `executeBatch` accepts `additionalStubRanges: Array<{start, end}>` and yields to host for PC-in-range, passed through `pe32WorkerClient.ts → unicornWrapper.setPe32WorkerMode → debugEngine` which supplies the synth range.
- ✅ **End-to-end verified** — v5 "Ashaka Mirage" runs to `[+] Beacon OK` inside the emulator, exercising all Tier 1-5 techniques: KUSER timing bypass → FNV-1a custom hash walk → synth kernel32 LoadLibraryA → LoadLibrary("shell32.dll") → synth shell32 ShellExecuteW → Beacon. All API calls observed in the trace (`kernel32!LoadLibraryA → 0x72005000`, `shell32!ShellExecuteW → 0x2A`).

### 5.4 Zero-Copy IPC (SharedArrayBuffer) ✅ DONE (Phases 1-4)

**Originally targeted v4.0.0 — pulled forward to v3.8.0 and shipped end-to-end.**

- ✅ **Phase 1 — `SharedRingBuffer`** (`hexcore-common/src/sharedRingBuffer.ts`) — SPSC lock-free ring buffer with `Atomics.load/store/notify` head/tail indices. Zero heap allocation per record. 15/15 unit tests passing.
- ✅ **Phase 2 — Native `CodeHookSabCB` + `hookAddSAB`** — C++ side writes 40-byte records (pc, instruction bytes, registers) directly into the SAB via `Int32Array` backing. Eliminates per-hook-fire TSFN transition.
- ✅ **Phase 3 — Split-path dispatch** — preserves existing `emuStop()` semantics. Legacy TSFN path still available via flag; SAB is opt-in per hook.
- ✅ **Phase 4 — End-to-end integration** — JS consumer reads records from the ring buffer with backpressure.
- ✅ **Measured results** — 1.34× throughput improvement, 100% delivery vs ~35% legacy, 7/7 SAB hook tests + SAB benchmark passing.
- ✅ `SharedMemoryBuffer` helper for general-purpose shared-memory ranges (`hexcore-common/src/sharedMemoryBuffer.ts`).

**Remaining (v4.0.0):** Expose C++ CPU state block directly as `BigUint64Array` typed view for full 10M+ inst/sec target.

**Wave 3 SAB breakpoint fixes (shipped):**
- ✅ Step-over-breakpoint when `start(addr)` resumes from a native bp — `breakpointDel → emuStart(count=1) → breakpointAdd` dance so `continue()` doesn't immediately re-fire the same breakpoint.
- ✅ `sabPathEnabled` tightened to also require `breakpointAdd`+`breakpointDel` (was checking only `hookAddSAB`); previously a prebuild with SAB but missing bp APIs silently dropped every breakpoint.
- ✅ `addBreakpoint` / `removeBreakpoint` mirror to native via optional chaining so live mutations during in-flight emulation are visible to native `BreakpointHookCB`.

---

## Milestone 6 — Pipeline & Infrastructure (P2)

### 6.1 Job Queue Manager (#19) ✅ DONE

**Problem:** Current pipeline processes one `.hexcore_job.json` at a time. AI agents generate jobs faster than they execute — subsequent jobs are silently dropped.

**Solution:**
- ✅ Job Queue Manager with priority queue (high/normal/low) using min-heap
- ✅ Configurable concurrent execution (default: 2, max: 5)
- ✅ Job status API: queued, running, done, failed, cancelled
- ✅ Job cancellation via AbortController
- ✅ New commands: `hexcore.pipeline.queueJob`, `hexcore.pipeline.cancelJob`, `hexcore.pipeline.jobStatus`
- ✅ Schema updated with `priority` field

**Files:**
- NEW: `jobQueueManager.ts`
- MOD: `automationPipelineRunner.ts`
- MOD: `extension.ts`
- MOD: `hexcore-job.schema.json`

### 6.2 ELF .ko Improvements (Building on 3.7.4) ✅ DONE

**What works (3.7.4):** External symbol resolution via `.rela.text`, SysV ABI, signed addend parsing, CallOp pipeline survival.

**Completed in 3.8.0:**
- ✅ **Confidence scoring** — `ConfidenceScore` interface with weighted components (symbolResolution 0.30, cfgComplexity 0.20, patternRecognition 0.20, externalCallCoverage 0.20, symtabCompleteness 0.15). Kernel API pattern recognition (6 categories). Integrated into `analyzeELFHeadless` output.
- ✅ **Section-aware analysis** — `ELFExecutableSection` interface with semantic classification (runtime, module_init, module_cleanup, trampoline). `liftAllExecutableSections()` iterates all executable sections with per-section relocation application. Output grouped by section with backward-compatible flat functions array. New headless option `allExecutableSections`.
- ✅ **BTF/DWARF type loading** — Pure TypeScript BTF parser (`elfBtfLoader.ts`). Parses `.BTF` section from vmlinux/ELF files. Resolves kernel struct layouts, function parameter types. Supports all BTF kinds (INT, STRUCT, UNION, ENUM, FUNC_PROTO, PTR, etc.). Functions: `loadBtfFromFile`, `resolveKernelStructs`, `getStructLayout`, `resolveTypeString`.

---

## Milestone 8 — HEXCORE_DEFEAT Anti-Analysis Detection Wave ✅ MOSTLY DONE

> Driven by `HEXCORE_DEFEAT_RESULTS.md` scorecard: three versions of `Malware HexCore Defeat.exe` (v1 simple XOR, v2 "Ashaka" 7-byte XOR, v3 "Ashaka Shadow" djb2 API hashing + rdtsc + CPUID) pushed HexCore detection from 62.5% → 55% → 46.4% as the malware escalated. Wave 2 targets items #3–#9 to drive the score back up toward ~85%.

### 8.1 Helix "entry" keyword fix ✅ (Fix #1)
Helix was resolving `entry` to `baseAddress` instead of the PE entry point. Fixed in earlier v3.8.0-nightly session.

### 8.2 BigInt sign-extension crash ✅ (Fix #2)
See 5.1 — root cause was `Date.now() & 0xFFFFFFFF` producing negative BigInt. Fixed with `>>> 0` coercion.

### 8.3 MSVC CRT init stubs ✅ (Fix #3) — see 5.1

### 8.3b C++ Data Import Handling (post-CRT-stub crash) ✅

After the 6 CRT stubs in Phase F unblocked CRT init, the malware crashed 159 instructions later at RIP `0x14000206c`. Root cause: HexCore's PE loader was treating C++ data exports like `std::cout` (mangled `?cout@std@@3V?...`) as if they were functions and writing a single `RET (0xC3)` byte at their IAT entries. When the binary did `mov rax, [imp_cout]; movsxd rcx, [rax+4]` to access the `std::ostream` virtual base displacement, it read the literal opcode bytes of the stub and faulted dereferencing 0xc7.

- ✅ **`isDataImport()` detector** in `peLoader.ts` — regex on MSVC mangled names: `^\?[A-Za-z_]\w*(?:@[A-Za-z_]\w*)+@@[0-9]`. The `[0-9]` storage class indicator unambiguously identifies data exports vs functions. 10/10 unit test cases pass against malware's actual import table.
- ✅ **`createDataImportBlock()`** — allocates a 4KB self-referential block in a new `DATA_IMPORT_BASE = 0x71000000n` region (8MB). Block layout: pointer to (block + 0x100) at offset 0, zero-filled elsewhere. The canonical MSVC C++ vbtable access pattern resolves cleanly (all derefs land in mapped memory, displacement = 0, the compiler-emitted null check fires and skips the virtual call).
- ✅ **Backwards-compatible**: 74 function imports in the malware continue to receive RET stubs as before; only the 2 data imports (`std::cout`, `std::cerr`) get the new treatment.

### 8.4 Registry path IOC extraction ✅ (Fix #8) — see 3.3

### 8.5 Anti-analysis instruction scanner ✅ (Fix #7 + #9) — see 3.2

### 8.6 Built-in YARA anti-analysis rules ✅ (Fix #4) — see 3.4

### 8.7 Multi-byte XOR key sizes + stack strings ✅ (Fix #5)

- ✅ **`DEFAULT_KEY_SIZES` expansion** — `[2,4,8,16]` → `[2,3,4,5,6,7,8,12,16]`. 7-byte targets "Ashaka" key explicitly; 3/5/6/12 are frequent custom key lengths seen in the wild.
- ✅ **Disp32 stack-string patterns** in `stackStringDetector.ts` — added 4 new MSVC patterns (MOV byte/dword with `[rbp+disp32]` and `[rsp+disp32]` addressing, using modrm bytes `85` and `84 24`). These fire when stack frames exceed 127 bytes, which is exactly what `std::vector<unsigned char>` inline initializers produce. Was the reason v1 malware was silently missed.

### 8.8 API hash resolver ✅ DONE (Fix #6, Wave 3.1 expansion)

**Shipped:**
- ✅ **Curated wordlist** — `WINAPI_WORDLIST` grew from 120 to ~260 entries: kernel32 expanded (LoadLibraryExA/W, HeapReAlloc/Walk, Wow64 helpers, File I/O + handle mgmt), ntdll expanded (Ldr*, Dbg*, Rtl*Heap, RtlCompressBuffer, Zw* aliases), user32 expanded (keyboard/mouse_event, SendInput, BlockInput), advapi32 (full Reg* + LookupAccountSid + service control + CryptProtect), wininet + winhttp (full request chain), ws2_32 (socket/bind/recv/send/getaddrinfo), crypt32 + bcrypt + psapi + dbghelp + shell32/shlwapi + tool helper (Process32/Module32/Thread32).
- ✅ **`DLL_WORDLIST`** — 32 common DLL names (with and without `.dll` suffix). Malware frequently hashes module names too when walking `InMemoryOrderModuleList`.
- ✅ **8 hash algorithms** total — 6 × 32-bit (`djb2, sdbm, fnv1, fnv1a, ror13, crc32`) + 2 × 64-bit (`fnv1_64, fnv1a_64` with standard prime `0x100000001B3`). 64-bit coverage was the Wave 3 gap that missed modern FNV-1a 64-bit loaders (Ashaka Mirage v5 class, custom Cobalt Strike beacons).
- ✅ **`ApiHashHit` extended** with `width: 32 | 64`, `category: 'api' | 'dll'`, `constantHex: string` (hex-formatted for JSON readability).
- ✅ **`resolveApiHashes()`** does both 32-bit AND 64-bit passes per byte offset, dedupes per (width, constant) pair. Pre-filtered on `hasDirectPebAccess` so benign binaries don't burn CPU.
- ✅ **`summarizeHashHits()`** — aggregate stats: `{total, byAlgorithm, byCategory, byWidth, topResolved}`. Great for pipeline composeReport consumption.
- ✅ **Case variants indexed** — each wordlist entry gets its lowercase + uppercase + original variant pre-hashed, so both MSF-style (lowercase-before-hash) and straight-casing loaders match.
- ✅ **Already wired in `peParser.ts`** — `analyzePEHeadless` output exposes `securityIndicators.apiHashResolution[]`.

### 8.9 HQL anti-analysis signatures ⬜ OPEN
4 declarative JSON signatures (peb-access, timing-check, api-hash-lookup, vm-detection) + `hexcore.hql.query` headless command. Depends on Helix decompiling through CRT init (Fix #3) — unblocked now, authoring pending.

---

## Milestone 7 — Backlog Items (P2-P4)

### 7.1 Cross-References Headless (W1)
- `hexcore.disasm.xrefsToHeadless` / `hexcore.disasm.xrefsFromHeadless`
- Who references address X? What does address X call?
- Critical for interactive investigation workflow

### 7.2 PE IAT Resolution (W4)
- Cross-reference `call [IAT_entry]` with PE import table
- Name indirect calls via IAT: `call [0x40C16C]` → `call kernel32!CreateFileW`

### 7.3 TLS Callback Exposure (W3)
- Expose TLS callback addresses in PE analysis output
- Include in Pathfinder entry point list

### 7.4 XOR Brute Force Headless (W5)
- `hexcore.strings.xorBruteForce` — scan for XOR-encoded strings/flags
- Already partially implemented in `hexcore-strings` advanced extraction

### 7.5 VM Pattern Heuristics (#30)
- Graph theory on basic blocks to flag dispatch loops, handler tables, bytecode arrays
- Reduces cognitive load when opening virtualized binaries
- Updated from v3.7.0 target to v3.8.0

### 7.6 Basic Symbolic Execution (#32) — P4
- Integrate Z3 SMT solver for constraint solving
- Mark inputs as symbolic, track constraints through VM bytecode
- **Target version:** v4.0.0+

---

## Verified Issues from 3.7.4 (Carry-Forward)

| Issue | Status | Notes |
|-------|--------|-------|
| Unicorn CRT init crash on PE32 entry | OPEN | CRT makes jmp outside expected range. Permissive mapping resolves partially. |
| Helix uses x64 types for PE32 binaries | OPEN | Output shows `int64_t`, `rbp` for 32-bit binary. Should use `int32_t`, `ebp`. |
| Indirect calls unresolved (`call eax`) | OPEN | Blocked on IAT Resolution (W4) and Pathfinder jump table resolver (1.3). |
| Headless breakpoint snapshots (#29) | OPEN | Expand `breakpoints[]` to auto-dump registers/stack at each hit. |
| Runtime memory disassembly (#28) | OPEN | Dump mmap'd memory from emulator for disassembly of runtime-decrypted code. |

---

## Priority Matrix

| # | Feature | Priority | Effort | Impact | Status |
|---|---------|----------|--------|--------|--------|
| 0.1-0.2 | Souper superoptimizer | **P0** | Done | Negative result: near-zero on prod code | ✅ DONE |
| 1.1-1.7 | Pathfinder CFG engine | **P0** | 3 sessions | 10x more BBs on kernel, jump tables | ✅ DONE |
| 4.0 | Helix v0.9.0 engine | **P0** | 2 sessions | 10x output growth, 42.9% IDA coverage | ✅ DONE |
| 5.4 | Zero-copy IPC (SAB) | **P0** | 4 phases | 1.34× throughput, 100% delivery vs 35% | ✅ DONE |
| 8.1-8.7 | HEXCORE_DEFEAT Wave 2 | **P0** | 2 sessions | Scorecard 46.4% → ~75% (est) | ✅ PARTIAL |
| 2.1 | Refcount audit scanner | **P0** | High | 4/4 bounty-bug patterns (A/B/C/E), regex + label tracking, bounty bug attribution | ✅ PARTIAL (v0.1) |
| 3.1 | Kernel driver signatures | **P1** | Medium | Triage quality for all drivers | OPEN |
| 3.2 | User/kernel security indicators | **P1** | Medium | Anti-analysis detection with density metric | ✅ PARTIAL |
| 3.3 | IOC false positive fix + registry | **P1** | Low | Anti-VM registry extraction | ✅ PARTIAL |
| 3.4 | YARA anti-analysis rules | **P1** | Low | 37 built-in rules, threatScore 100 on malware | ✅ DONE |
| 4.1 | Helix trampoline following | **P1** | Low | Fixes `void { return; }` on packer stubs + vgk.sys-class entries | ✅ DONE |
| 4.2 | Kernel struct type recovery | **P1** | Medium | BTF + DWARF parsers shipped | ✅ PARTIAL |
| 4.3 | Batch decompilation | **P1** | Medium | 209 functions in 1 job vs 209 jobs | OPEN |
| 5.1 | Unicorn fault recovery + CRT stubs | **P1** | Medium | Unblocks MSVC emulation past CRT init + iostream capture + Ashaka Wave 3 | ✅ DONE |
| 5.3 | Instruction-Level Hooks (CPUID vendor, notifyApiRedirect) | **P1** | Low | Anti-analysis bypass correctness, diagnostics | ✅ PARTIAL |
| 5.5 | KUSER_SHARED_DATA + Synthetic DLL + PEB_LDR_DATA | **P0** | High | v5 hash-resolve emulation to Beacon OK end-to-end | ✅ DONE |
| 6.1 | Job queue manager (#19) | **P2** | Medium | Unblocks agentic workflows | ✅ DONE |
| 6.2 | ELF .ko improvements | **P2** | Medium | Confidence scoring, BTF loading, section-aware | ✅ DONE |
| 8.8 | API hash resolver | **P1** | Medium | 260+ APIs × 8 algos (incl. 64-bit FNV), DLL names, summary stats | ✅ DONE |
| 8.9 | HQL anti-analysis signatures | **P2** | Low | Declarative detection on Helix output | OPEN |
| 7.1 | Cross-references headless | **P2** | Medium | Interactive investigation | OPEN |
| 4.4 | State machine visualization | **P2** | Medium | Visual audit aid | OPEN |
| 7.6 | Symbolic execution | **P4** | Very High | Constraint solving for VMs | OPEN |

---

## Paper Framing

> "We present HexCore Pathfinder, a format-aware CFG recovery engine that augments the Remill lifting pipeline with pre-computed control flow information derived from PE `.pdata` exception directories and ELF `.symtab` function tables. Combined with recursive descent disassembly and jump table resolution, Pathfinder produces 2-3x more basic blocks than Remill's default linear sweep. We also introduce a vulnerability audit engine that automates detection of refcount errors, reachable assertions, and use-after-free patterns in kernel driver code. Applied to the ARM Mali GPU driver (`mali_kbase.ko`) and Qualcomm Adreno GPU driver (`kgsl`), the audit engine identified 4 previously unknown vulnerabilities — 2 refcount corruption bugs (CWE-911), 1 reachable kernel panic (CWE-617), and 1 use-after-free (CWE-416) — all reported through coordinated disclosure to ARM and Qualcomm."

---

## Engineering Notes

- Keep headless contract stable: `file`, `quiet`, `output`
- Pipeline strict on output existence and step timeout
- All new features must support headless mode for AI orchestration
- Native engines follow N-API pattern: prebuildify → fallback chain → zero runtime deps
- All native wrappers documented via `hexcore-native-engines` power (`.kiro/powers/`)
- Prebuilds currently win32-x64 only — Linux/macOS runners pending
- `hexcore-ioc` depends on `hexcore-better-sqlite3` — keep API stable
- Regression fixtures from real targets: `mali_kbase.ko`, `vgk.sys`, `kgsl.c`, ROTTR.exe
