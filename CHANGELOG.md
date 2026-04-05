# Changelog

All notable changes to the HikariSystem HexCore project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.7.4-nightly] - 2026-04-04 - "Remill Refinement + mali_kbase Siege"

> **Remill IR Quality + Pipeline Reliability + Session Persistence + Analysis Hardening + ELF ET_REL Full Resolution + SysV Calling Convention** — LLVM IR quality improvements, autoBacktrack hardening, persistent session database, section-filtered strings, ftrace/CET preamble detection, ELF ET_REL external symbol resolution, and HQL session integration. Battle-tested against `mali_kbase.ko` (45MB, 7313 functions, Arm Mali GPU driver) — external kernel calls (`mutex_lock`, `dma_sync_sg_for_device`, `_dev_warn`, etc.) now appear in decompiled output with correct SysV calling convention.

### Remill Wrapper — External Symbol Resolution (Phase 5.6) — NEW

- **`setExternalSymbols(map)` NAPI Method** — New method accepts a `{ address: symbolName }` map from the TypeScript layer before lifting. The C++ Phase 5.6 injects `declare ptr @mutex_lock(...)` etc. directly into the LLVM Module, ensuring external dependencies survive optimization passes and DCE.
- **Phase 5.6: Resolve External CALLI Targets** — After all optimization passes, walks the LLVM Module and: (1) matches `callTargets` from Phase 3 against the external symbol map, (2) scans all CALLI `CallInst` for constant i64 targets matching fake addresses, (3) declares ALL external symbols in the module as a safety net. Fixes the 2/7 functions where Phase 4.5 `calliTargets` pointer staleness caused zero declares.
- **Target OS from Binary Format** — `liftToIR` now detects the binary format (ELF → `linux`, PE → `windows`) and passes the correct OS to Remill instead of using `process.platform`. Fixes `target triple = "x86_64-unknown-windows-msvc-coff"` for ELF files lifted on Windows hosts. The Remill lifter is recreated when the target OS changes.

### Helix Decompiler — SysV Calling Convention — NEW

- **`RecoverCallingConventionPass` ABI Auto-Detection** — The pass now reads `llvm.target_triple` from the MLIR module attribute. Triples containing `linux`, `elf`, `gnu`, `freebsd`, `openbsd`, or `darwin` select SysV ABI (RDI, RSI, RDX, RCX, R8, R9). Falls back to Win64 (RCX, RDX, R8, R9) for Windows triples or when no triple is present. Previously hardcoded to Win64.
- **Header reflects ABI** — Decompiled output shows `/* sysv */` for Linux binaries, `/* win64 */` for Windows PE. Parameter numbering matches the correct ABI: `param_1` = RDI for SysV, `param_1` = RCX for Win64.

### Helix Decompiler — P0 CallOp Pipeline Survival — NEW

- **CallOp Dialect Conversion Fix** — `applyPartialConversion` in `HelixLowToMid` and `HelixMidToHigh` was skipping all operations inside `low::FuncOp` regions because `FuncOp` was marked as `addLegalOp`. The MLIR conversion framework treats legal ops as "done" and never recurses into their bodies. Added manual post-conversion walks in both passes that collect surviving `low::CallOp` / `mid::CallOp` and convert them in-place. Previously: zero calls survived the pipeline for `.ko` files. Now: all calls propagate through Low → Mid → High.
- **Target Triple Preservation** — `mlir::translateLLVMIRToModule` does NOT carry over the LLVM `target triple` as an MLIR attribute. The pipeline now captures the triple from `llvm::Module::getTargetTriple()` before `std::move` and sets it as `llvm.target_triple` on the MLIR `ModuleOp`. This enables downstream passes (RecoverCallingConvention, collectCallArgs) to detect the correct ABI.
- **P0 Debug Instrumentation** — `CallOpCountInstrumentation` (PassInstrumentation) added to `Pipeline.cpp`. Traces `low.call`, `mid.call`, `high.call` counts BEFORE and AFTER every pass in the pipeline. Output goes to stderr as `[P0-TRACE]` lines. Also logs per-phase CallOp counts in `EliminateDeadCode` and per-pattern conversion in `HelixLowToMid`.

### Helix Decompiler — External Symbol Resolution via AddressOf — NEW

- **`llvm.mlir.addressof` Symbol Extraction** — For ET_REL (.ko) files, the fresh Remill lifter emits external calls as `ptrtoint(@symbol_name)`, which becomes `llvm.ptrtoint(llvm.mlir.addressof @symbol)` in MLIR. The `convertSemantic::CALL` handler now looks through `PtrToIntOp → AddressOfOp` to extract the symbol name directly. Previously: all external calls appeared as `__indirect_call(...)`. Now: `_dev_warn(...)`, `dma_sync_sg_for_device(...)`, `mutex_lock(...)` appear with their real kernel API names.
- **`resolveCallTargets` Phase 3** — Added a fallback phase in `SignatureDb.cpp` that walks remaining nameless `CallOp`s and resolves them via `AddressOfOp` when address-based lookup fails. This catches calls where the `__hxreloc__` addresses don't match (rebased vs real addresses) but the LLVM IR still references the symbol by name.

### Disassembler — FIX-011 Hardening

- **Signed Addend Parsing** — `r_addend` in ELF RELA entries is now read as signed int64 via `BigInt.asIntN(64, ...)`. Previously, `Number(readU64(...))` converted `-4` (0xFFFFFFFFFFFFFFFC) to `1.844e+19`, causing displacement overflow and zero relocations patched. Fixes all 97-section `.ko` files.
- **Resolved Target Map** — The `symbolMap` now stores both the fake base address (0x7FFF0000+) AND the resolved target address (`fakeAddr + addend + 4`) that the Remill lifter actually computes. Ensures IR text replacement matches regardless of addend variations.
- **Hybrid Post-Processing** — Two-strategy approach: Strategy A does regex replacement of `@sub_<fakeHex>` patterns in IR text. Strategy B uses `liftResult.callTargets[]` (populated by Remill Phase 3) to match fake addresses against the symbol map, adding declares even when no text patterns match.
- **Kernel Infrastructure Filter** — 17 kernel trampoline symbols (`__fentry__`, `__x86_return_thunk`, `__cfi_check`, `__x86_indirect_thunk_{rax..r15}`) are excluded from relocation patching to avoid polluting the IR with NOPs.

### Disassembler — Pipeline Capability Map

- **6 New Pipeline Commands** — `hexcore.disasm.extractStrings`, `hexcore.disasm.getSessionDbPath`, `hexcore.disasm.renameFunction`, `hexcore.disasm.renameVariable`, `hexcore.disasm.retypeFunction`, `hexcore.disasm.retypeVariable`, `hexcore.disasm.setBookmark` added to `COMMAND_CAPABILITIES` and `COMMAND_OWNERS`. Session mutation commands use `validateOutput: false`.
- **`getSessionDbPath` Headless Support** — Now accepts `output.path` and writes `{ "dbPath": "...", "error": "..." }` to file. Reports diagnostic error when session store is unavailable.

### hexcore-better-sqlite3 — Prebuild Loader Fix

- **Multi-Name Prebuild Resolution** — `index.js` now tries `hexcore-better-sqlite3.node` (prebuildify hyphen), `hexcore_better_sqlite3.node` (underscore), and `node.napi.node` (generic) before falling back to build paths. Fixes session store initialization failure where the prebuild file existed but the loader looked for the wrong filename.

### hexcore-better-sqlite3 — Session Store Loader Fix

- **`loadNativeModule` Pattern** — `sessionStore.ts` now uses `loadNativeModule` with candidate paths (same pattern as capstone/remill/helix wrappers) instead of bare `require('hexcore-better-sqlite3')`. Fixes module resolution in the VS Code extension host where `node_modules` symlinks don't exist.

### Helix Worker Thread — Flag Propagation Fix

- **`useCastLayer` + `skipOptimization` in Worker** — `decompileIrAsync` (used for IR > 64KB) now forwards engine flags to the worker thread. Previously, the worker created a fresh `HelixEngine` without applying `setUseCastLayer(true)` or `setSkipOptimization(true)`, causing PE files to work (small IR → sync path) but ELF to fail (large IR → async path, flags lost).

### HQL Extension

- **`engines` field** — Added `"engines": { "vscode": "^1.97.0" }` to `package.json` (fixes extension host load error).
- **FlatBuffer adapter fixes** — `readStr()` handles `Uint8Array` return from newer `flatbuffers` versions. Schema vtable offset constants preserved for future use.

### Remill Wrapper — IR Quality

- **Selective SSE Semantic Inlining** — SSE/FP semantic functions (MINSS, MAXSS, MULSS, ADDSS, SUBSS, DIVSS, SQRTSS, COMISS, CVTPS2PD, XORPS, and 30+ more) are now **always inlined** regardless of the `inlineSemantics` flag. After inlining, LLVM optimization passes reduce them to native IR: `MINSS` → `fcmp olt` + `select`, `MULSS` → `fmul`, `SQRTSS` → `@llvm.sqrt.f32`. Non-SSE semantics stay as named calls for Helix pattern-matching.
- **LLVM Intrinsic Lowering (Phase 5.4)** — `@llvm.ctpop` → `@__popcnt{N}`, `@llvm.ctlz` → `@__clz{N}`, `@llvm.cttz` → `@__ctz{N}`, `@llvm.bswap` → `@__bswap{N}`. Replaces opaque LLVM intrinsics with named external calls that the Helix decompiler can emit as readable library calls. Skips non-integer (vector) intrinsics.
- **State Register Naming (Phase 5.3)** — GEPs on the State pointer (arg 0) are annotated with register names (`&RAX`, `&XMM0`). Loads from State are named after their register (`RAX`, `XMM0`). Implicit parameter detection: registers loaded before any store in the entry block are reported in `result.implicitParams[]`.
- **Third Optimization Round (Phase 5.5)** — Added `InstCombine` → `SimplifyCFG` → `ADCE` after the existing two rounds. Catches dead branches and constant conditions left over from semantic inlining and intrinsic lowering.
- **`inlineSemantics` Option** — New `LiftOptions.inlineSemantics` field (default: `false`). When `true`, ALL semantic helper functions are inlined (aggressive mode). When `false`, only SSE/FP semantics are inlined (selective mode). Exposed in the N-API `liftBytes` options and async worker.

### Disassembler — autoBacktrack Fixes

- **autoBacktrack for `functionAddress` Branch** — The `liftToIR` command had autoBacktrack only in the `options.file` code path. The `functionAddress` path (used by pipeline jobs) skipped backtracking entirely. Now both branches call `findFunctionStartForAddress` when `autoBacktrack` is enabled.
- **`forceProbe` Parameter** — `findFunctionStartForAddress(address, forceProbe)` accepts a new `forceProbe` flag. When `true`, skips function table lookups (steps 1+2) and goes directly to Capstone fallback + byte scanner. Prevents false "already a function start" from `analyzeAll` misdetections.
- **Improved Byte-Level Boundary Scanner** — Scan range increased from 16KB to 64KB. Now detects three boundary types: INT3 padding (`CC CC`), NOP padding (`90 90`), and `ret` + prologue (`C3` followed by optional padding then a prologue byte). Prologue recognition covers REX prefixes (`48`, `4C`, `40`, `41`, `44`, `45`), push variants (`50`–`57`), and other x64 function entry patterns.
- **Backtrack Metadata** — `liftToIR` results now include `backtracked: boolean` and `originalAddress: number` when the start address was adjusted by autoBacktrack.

### Helix Decompiler — C AST Layer (Phase 4)

- **C AST Architecture** — New standalone C AST layer replaces monolithic PseudoCEmitter (5,200 LOC) with a clean 3-stage pipeline: `CAstBuilder` (3,125 LOC) → `CAstOptimizer` (2,400+ LOC) → `CAstPrinter` (486 LOC). Mutable tree semantics (not MLIR SSA) enabling proper tree-rewriting optimizations. Namespace `helix::cast`, 9 headers, 5 source files, ~6,000 LOC total.
- **`--use-cast-layer` Feature Flag** — New CLI flag enables the C AST pipeline. Without the flag, PseudoCEmitter (default) is used. Wired through: `helix_tool.cpp` → C API (`helix_engine_set_use_cast_layer`) → `Engine` → `Pipeline::emitPseudoC()`.
- **Node Hierarchy** — 31 AST node types: 12 expressions (`CIntLitExpr`, `CVarRefExpr`, `CBinaryExpr`, `CUnaryExpr`, `CCastExpr`, `CCallExpr`, `CTernaryExpr`, `CSubscriptExpr`, `CFieldAccessExpr`, `CFloatLitExpr`, `CStringLitExpr`, `CAddrLitExpr`), 15 statements, 4 declarations. LLVM-style RTTI via `NodeKind` enum + `classof()`. CRTP visitor template (`CAstVisitor<Derived>`).
- **CAstBuilder — 4-Tier Op Coverage** — Handles all HelixHigh ops (29), HelixMid ops (11), HelixLow ops (26 expression + 15 statement), LLVM dialect ops (47 including FP: `fadd`, `fsub`, `fmul`, `fdiv`, `fcmp`, `fpext`, `sitofp`, vector: `extractelement`, `shufflevector`, `insertelement`), and arith dialect ops (19). Fallback: unrecognized ops → diagnostic comment.
- **CAstBuilder — Remill Intrinsic Resolution** — `__remill_read_memory_f32(state, addr)` → `*(float*)addr`, `__remill_write_memory_*` → pass-through state, `__remill_flag_computation_*` / `__remill_undefined_*` → `0` (infrastructure). LLVM calls as statements now emit with correct arguments (fixes `__popcnt8()` missing args).
- **CAstBuilder — Win64 ABI** — Parameter inference (RCX→param_1, RDX→param_2, R8→param_3, R9→param_4, XMM0-3→float params), `param_1→this` heuristic (struct base ≥3 uses), stack offset mapping, copy propagation with 5-hop transitive resolution and cycle detection.
- **14-Pass AST Optimizer** — Tree-rewriting passes in fixed order:
  1. `removePrologueEpilogue` — Strip `rbp=rsp`, `rsp=rsp±N`, callee-saved register saves
  2. `eliminateInfrastructure` — Remove `_promoted_*`, `_spill_*`, `__*flag*`, RSP bookkeeping
  3. `eliminateNullPtrStores` — Remove `*(type)(void*)0 = ...` (unresolved State GEPs)
  4. `eliminateDeadStores` — Backward liveness analysis with call/deref/field safety guards
  5. `propagateCopies` — Single-use synthetic temporary inlining with `cloneExpr()` deep-copy
  6. `canonicalizeXorPatterns` — `x ^ -1` → `!x` (boolean) / `~x` (bitwise), Remill flag idioms
  7. `recoverStructFieldAccess` — `*(ptr + N)` → `ptr->field_0xN`
  8. `simplifyExpressions` — 12+ algebraic rules: `*&x→x`, `!!x→x`, `x+0→x`, `x*-1→-x`, `!(==)→!=`, shift-combine, constant folding
  9. `synthesizeCompoundAssign` — Structural equality matching for `*x = *x + 1 → (*x)++`, `ptr->f = ptr->f OP y → ptr->f OP= y`
  10. `eliminateConstantBranches` — `if(0){A}else{B}` → B, `if(1){A}else{B}` → A
  11. `removeEmptyIfStatements` — Dead NaN guards from MINSS/MAXSS lowering
  12. `cleanupFloatZeros` — `(int64_t)(void*)0` → `0.0f` in float context, `block_argN` → `0.0f`
  13. `collapseMinMaxPatterns` — `if(a < b){x=a}` → `x = min(a, b)`, `if(a > b){x=a}` → `x = max(a, b)`
  14. `removeDeadCodeAfterReturn` — Strip unreachable statements after return/break/continue/goto
- **CAstPrinter** — Visitor-based C code emitter with C operator precedence (13 levels), smart parenthesization, hex literals for |value| > 256, 4-space indentation, struct declaration support.

### Helix Decompiler — State Struct GEP Resolution

- **XMM Register Recognition** — `RemillToHelixLow` RegisterTracker Strategy 3 extended to recognize State struct paths: `gep %state, 0, 0, 1, N` → XMM registers (XMM0-XMM15, 128-bit), `gep %state, 0, 0, 2, N` → ArithFlags (CF, PF, AF, ZF, SF, DF, OF, 8-bit). Existing GPR path (`gep %state, 0, 0, 6, N`) unchanged.
- **Chained GEP Resolution** — Second scan pass resolves multi-level GEP chains: `gep __VEC_BASE, N` → XMM{N}, `gep __FLAGS_BASE, N` → flag name. Sub-GEPs within known XMM registers inherit the register name.
- **Float Type Propagation** — XMM/YMM variable declarations typed as `float` instead of `int64_t`. RegReadOp/RegWriteOp for XMM registers produce/consume `float` type. Eliminates `int64_t xmm0` → `float xmm0`.
- **FP Flag Warning Suppression** — Flag synthesis warnings for floating-point condition codes (`b`, `nb`, `be`, `nbe`, `p`, `np`) silenced. These failures are expected from SSE UCOMISS/COMISS lowering.
- **Liveness Resilience for ELF ET_REL (FIX-013)** — `Liveness.cpp` no longer asserts on escaped SSA uses from unresolved ELF relocations. When a use leaves its parent region (common in `.ko` kernel modules where calls point to relocation stubs at address 0), the use is marked as external and the decompiler continues with reduced confidence instead of crashing. Affected functions emit `// Issues: Unresolved relocations detected (ELF ET_REL)` in the output header.

### Disassembler — ELF Relocation Processing & autoBacktrack

- **ELF `.rela.text` Processing (FIX-011)** — For ELF ET_REL files (kernel modules `.ko`, relocatable objects `.o`), the disassembler now parses `.rela.text` / `.rel.text` relocation entries and resolves external symbol names via `.symtab` + `.strtab`. Supported relocation types: `R_X86_64_PLT32`, `R_X86_64_PC32`, `R_X86_64_GOTPCREL`. The `liftToIR` command pre-patches the byte buffer with fake addresses for each external symbol, lifts normally, then post-processes the IR to replace fake addresses with named declarations (`declare ptr @mutex_lock(...)`). Eliminates `call sub_0` for all external calls in kernel modules. Tested target: `mali_kbase.ko` (7313 functions, Arm Mali GPU driver).
- **autoBacktrack `forceProbe` Mode** — `findFunctionStartForAddress(addr, forceProbe=true)` skips function table lookups and goes directly to Capstone + byte-level prologue scanning. The `liftToIR` command uses `forceProbe` by default when `autoBacktrack` is enabled, preventing false "already a function start" results from `analyzeAll` misdetections.
- **Improved Boundary Scanner** — Scan range increased from 16KB to 64KB. Now detects three boundary types: INT3 padding (`CC CC`), NOP padding (`90 90`), and `ret` + prologue (`C3` followed by optional padding then a prologue byte). Covers REX prefixes, push variants, and other x64 function entry patterns.
- **autoBacktrack for `functionAddress` Branch** — The `liftToIR` pipeline path that uses `functionAddress` now correctly applies autoBacktrack. Previously only the `file` + `address` code path had backtracking.
- **Backtrack Metadata** — `liftToIR` results include `backtracked: boolean` and `originalAddress: number` when the start address was adjusted.

### Session Persistence (FIX-008 + FIX-009) — NEW

- **`.hexcore_session.db`** — New SQLite-backed persistent session store (via `hexcore-better-sqlite3`, WAL mode). Auto-created next to the binary on first load. Keyed by SHA-256 of the binary — reopening the same binary restores all session data instantly.
- **7-Table Schema** — `session_meta` (binary hash, version), `functions` (renames, return types, calling conventions), `variables` (per-function renames/retypes), `fields` (struct field names/types), `comments`, `bookmarks`, `analyze_cache` (persists `analyzeAll` function table across sessions).
- **Analyze Cache** — `analyzeAll()` saves discovered functions to the session DB. Next run restores from cache before scanning, making re-analysis near-instant for previously analyzed binaries.
- **Legacy Migration** — On first load, imports existing `.hexcore-annotations.json` comments into the session DB automatically.
- **New Commands** — `hexcore.disasm.renameVariable`, `hexcore.disasm.retypeVariable`, `hexcore.disasm.retypeFunction`, `hexcore.disasm.setBookmark`, `hexcore.disasm.getSessionDbPath`. All support both interactive (UI input box) and headless (pipeline JSON args) modes.

### HQL Session Integration — NEW

- **`SessionDbReader`** — New read-only SQLite accessor in `hexcore-hql/src/adapter/sessionDb.ts`. Opens the disassembler's session DB in WAL read-only mode for concurrent access.
- **`hydrateHAST(buffer, session?)`** — HAST FlatBuffer hydrator now accepts an optional `SessionDbReader`. When provided, analyst-defined function names, return types, and variable renames/retypes are applied to the `CFunctionDecl` nodes before the HQL matcher runs.

### Disassembler — autoBacktrack Hardening (FIX-001)

- **Function Table Containment (Always Active)** — `findFunctionStartForAddress` now checks if the target address falls within a known function's range even when `forceProbe=true`. Previously, `forceProbe` skipped the function table entirely.
- **Capstone Backward Disassembly** — New step 4 in the backtrack pipeline: tries disassembling from `addr-1` through `addr-16`, checking which instruction sequence lands exactly on the target address. Requires ≥3 consecutive valid instructions. Works for dense code (D lang, optimized) without CC/90 padding.
- **Extended Prologue Recognition** — Byte scanner now recognizes: `mov [rsp+8], rcx` (fastcall save), `mov [rsp+10h], rdx` (2nd arg save), `endbr64` (F3 0F 1E FA).

### Disassembler — Section-Filtered String Extraction (FIX-003)

- **`findStrings(sections?, minLength?)`** — String extraction now accepts optional PE section names (e.g. `[".rdata", ".data"]`) and minimum length. When specified, only those byte ranges are scanned. Eliminates 99% noise from `.text` on large binaries.
- **New `hexcore.disasm.extractStrings` Command** — Headless pipeline command: `{ "args": { "sections": [".rdata"], "minLength": 5, "maxStrings": 10000 } }`.

### Disassembler — ftrace Preamble Skip (FIX-015)

- **NOP Sled Detection** — `scanForFunctionPrologs` recognizes multi-byte NOP sequences (0F 1F, 66 0F 1F) as ftrace `__pfx_` preambles. When a sled ≥8 bytes is found followed by `endbr64` or `push rbp`, the function is registered at the real prologue.
- **CET-Enabled Binary Support** — `endbr64` + `push rbp`/`sub rsp` recognized as valid function prologue. Covers `-fcf-protection=full`.

### Disassembler — ELF ET_REL Detection (FIX-014)

- **ET_REL Warning** — Loading an ELF relocatable (e_type=1, `.ko`, `.o`) emits a warning. `FileInfo.isRelocatable` flag + `elfWarning` in headless results.

### Disassembler — Instruction Alignment Verification (IMP-001)

- **`verifyInstructionAlignment(targetAddress)`** — Disassembles backwards from a known good region to verify the target is on an instruction boundary. Returns `{ aligned: false, suggestedAddress }` when mid-instruction. Integrated into `disassembleAtHeadless`.

### Disassembler — XRef Performance

- **XRef Storage: O(N) → O(1) Lookup** — Cross-references changed from `XRef[]` + `.filter()` to `Map<number, XRef[]>` + `.get()`. `findCrossReferences(address)` is now O(1).

### Disassembler — Deep PE Analysis with Windows API Signatures (P1) — NEW

- **Windows API Signature Database (`peApiDatabase.ts`)** — 180+ Windows API type signatures covering kernel32, ntdll, advapi32, ws2_32, wininet, winhttp, user32, shell32, crypt32, bcrypt, ole32, urlmon, gdi32. Each entry includes: full C prototype (return type, parameter names and types), **API category** (file_io, memory, process, thread, injection, network, crypto, registry, hook, etc.), and **security tags** (shellcode, keylogger, ransomware, c2, anti_debug, persistence, dropper, exfiltration, etc.). Automatic A/W/Ex suffix stripping for O(1) lookup.
- **Enhanced PE Data Directory Parsing** — New parsing for 5 additional PE data directories:
  - **TLS Directory** — Parses TLS callback array (common anti-debug technique). Reports callback count and addresses. Emits warning when callbacks are detected.
  - **Debug Directory** — Parses CodeView (RSDS) entries to extract PDB path and GUID. Supports multiple debug entries per binary.
  - **Delay Import Directory** — Walks delay-load DLL descriptors, resolves function names from INT table. Full name/hint/address resolution.
  - **CLR Runtime Header** — Detects .NET assemblies, extracts runtime version, metadata size, entry point token, native/32-bit flags.
  - **Resource/Security/Reloc/LoadConfig** — Size reporting for remaining data directories.
- **`hexcore.disasm.analyzePEHeadless` Command** — Comprehensive headless PE analysis returning: typed imports with full C prototypes, category-based security summary, security indicators (hasInjectionAPIs, hasAntiDebug, hasKeylogger, hasDynamicLoading, hasPersistence, isDotNet, hasTLSCallbacks, isSigned), data directories (TLS, Debug, Delay Import, CLR), sections, and exports. Pipeline-compatible with `$step[N]` referencing.
- **Import Category Summary** — Groups all imported APIs by functional category with aggregated security tags. Provides instant behavioral profiling: "this binary uses 12 injection APIs, 8 network APIs, and 5 crypto APIs".
- **Import Tree — API Signature Tooltips** — Hovering any import function in the sidebar now shows the full C prototype, API category, and security tags. Icons are color-coded: **red** = injection/keylogger/shellcode, **orange** = network/crypto, **yellow** = anti-debug/evasion, **blue** = normal.
- **Pipeline Integration** — `hexcore.disasm.analyzePEHeadless` registered in COMMAND_CAPABILITIES and COMMAND_OWNERS for automation pipeline use.

### Base64 Decoder — Confidence Scoring Engine (P2) — NEW

- **Shannon Entropy Analysis** — Calculates per-string entropy in bits/byte. Real base64 data has entropy ~5.5-6.0; false positives (API names, alphabet strings) have lower entropy (~3.0-4.0). Entropy is reported in results and used as a scoring factor.
- **8-Factor Confidence Scoring** — Each Base64 candidate receives a 0-100 confidence score based on:
  1. **String length** — Longer strings score higher (+15 for ≥100 chars, -10 for <24)
  2. **Shannon entropy** — High entropy = more likely real (+15 for ≥5.5 bits/byte)
  3. **Padding validation** — Correct `=` padding present (+8)
  4. **Character distribution** — Chi-squared uniformity analysis across Base64 alphabet
  5. **Decoded content quality** — Printable ASCII ratio (+12 for >90%)
  6. **Decoded patterns** — JSON/XML/URL/path detection in decoded output (+5)
  7. **Null byte penalty** — High null ratio penalized (-8 for >30%)
  8. **Context filter** — Windows API names, alphabet sequences, code identifiers (-25)
- **Context-Aware False Positive Filters** — Eliminates common false positives:
  - CamelCase Windows API names (`CreateFileA`, `VirtualAllocEx`, `InitializeCriticalSectionEx`)
  - NT native API patterns (`NtQueryInformationProcess`, `RtlDecompressBuffer`)
  - Pure alphabet sequences (`abcdefghijklmnopqrstuvwxyz`)
  - C++ namespaces, snake_case identifiers, dotted names
  - URLs, pure hex strings, GUIDs
  - Low character diversity (repeated patterns like `AAAAAAAA`)
  - All-alphabetic strings with no digits or `+/` characters
- **Confidence Categories** — `high_confidence` (≥75), `medium_confidence` (≥50), `possible` (≥30). Matches below 30 are filtered out entirely.
- **Enhanced Headless API** — New `minConfidence` parameter (default 30) and `category` filter. Returns breakdown by category, average confidence score, and per-match scoring reasons.
- **Report Overhaul** — Interactive report now shows matches grouped by confidence category with entropy, confidence score, and expandable scoring breakdown per match.

### Disassembler — Deep ELF Section Analyzer (P4) — NEW

- **ELF Program Headers** — All program headers parsed with type names (PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_GNU_STACK, PT_GNU_RELRO, PT_TLS, etc.), permissions, virtual/physical addresses, file/memory sizes, and alignment. PT_INTERP extracts the interpreter path (e.g., `/lib64/ld-linux-x86-64.so.2`).
- **Full Symbol Table** — ALL symbols from `.symtab` and `.dynsym` with complete metadata: name, value, size, **binding** (LOCAL/GLOBAL/WEAK), **type** (NOTYPE/OBJECT/FUNC/SECTION/FILE/TLS/GNU_IFUNC), **visibility** (DEFAULT/HIDDEN/PROTECTED/INTERNAL), section name, and import/export classification. Up to 16,384 symbols per table.
- **Relocations (Human-Readable)** — ALL relocation entries from every `.rela.*`/`.rel.*` section with type names (R_X86_64_PC32, R_X86_64_PLT32, R_X86_64_GOTPCREL, R_AARCH64_CALL26, etc.), resolved symbol names, addends, and source section. Supports x86_64 (12 types), AArch64 (6 types) relocation naming. Up to 65,536 entries per section.
- **Dynamic Entries** — ALL entries from `.dynamic` section with tag names (DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH, DT_INIT, DT_FINI, DT_GNU_HASH, DT_FLAGS_1, etc.). String values resolved for DT_NEEDED (library names), DT_SONAME, DT_RPATH, DT_RUNPATH.
- **Kernel Module Info (.ko)** — For ET_REL files, parses `.modinfo` section extracting: module name, version, description, author, license, srcversion, vermagic, depends (comma-separated dependencies), intree flag, retpoline flag, and parameter descriptions.
- **`hexcore.disasm.analyzeELFHeadless` Command** — Comprehensive headless ELF analysis returning: file info, sections, program headers, symbol statistics (total/functions/objects/imports/exports/local/global/weak), full symbol table, relocations grouped by section, dynamic entries, needed libraries, module info (for .ko), interpreter path, and SONAME. Pipeline-compatible.
- **Symbol Statistics** — Automatic categorization: counts functions, objects, imports, exports, local/global/weak bindings. Instant profile of binary composition.

### Helix Decompiler — Variable Rename Propagation in Body (P3) — NEW

- **C AST Variable Rename Walk (VSCode Side)** — Session DB variable renames (`renameVariable`) are now passed to the Helix engine via `setVariableRename(oldName, newName)` BEFORE decompilation. The engine walks all `CVarRefExpr` nodes in the C AST and substitutes names surgically, eliminating the fragile string-based replacement. This prevents false matches on substrings, struct field names, and comments.
- **`collectSessionVariableRenames()` Helper** — Reads all variable renames from the session DB for the target function (with ±16 byte address tolerance for patchable entries). Returns `{oldName, newName}[]` pairs passed to `HelixWrapper.decompileIr()`.
- **HelixWrapper P3 Integration** — New `setVariableRename(old, new)`, `clearVariableRenames()` on `HelixEngineInstance`. `supportsVariableRenames()` feature detection. Renames forwarded to worker thread via `workerData` for async decompilation. Renames cleared after each decompile call.
- **Graceful Fallback** — When the native module doesn't support `setVariableRename` (older `.node` build), `applySessionRenames` falls back to the existing string-based regex replacement. Zero behavior change for users who haven't rebuilt Helix.
- **Belt-and-Suspenders Fix** — String-based regex rename in `applySessionRenames` now ALWAYS runs regardless of engine support. If the C++ AST walk already renamed the variable, the regex finds nothing and is a no-op. If the AST walk missed it (C AST layer off, name mismatch), the regex catches it. Prevents rename regression.
- **Requires Helix C++ Side**: `Engine.h/cpp` (rename map + setter), `CApi.cpp` (C API export `helix_engine_set_variable_rename`), `ffi.rs` (NAPI-RS FFI), `CAstOptimizer.cpp` (new rename walk pass after optimizer, before printer).

### Remill Wrapper — Native endbr64/ftrace Handling in DoLift (FIX-023)

- **Synthetic NOP for endbr64/endbr32** — When `DecodeInstruction()` fails on CET instructions (F3 0F 1E FA / F3 0F 1E FB), the Phase 1 scanner now creates a synthetic `DecodedInst` with `category = kCategoryNoOp` and `size = 4` instead of stopping the scan. Phase 3 recognizes these synthetic NOPs and skips `LiftIntoBlock()` for them. The lifter now continues through `endbr64` preambles natively without the TypeScript FIX-017 skip (which is kept as a safety net for older .node builds).
- **Synthetic NOP for `call __fentry__`** — Same treatment for `E8 00 00 00 00` (ftrace NOP sled with unresolved displacement). Creates a synthetic 5-byte `kCategoryNoOp`. Eliminates the need for TypeScript-side byte skipping in kernel modules.
- **Impact**: The Remill scanner now correctly decodes through the full `endbr64 + call __fentry__ + push rbp + mov rbp, rsp` preamble without stopping. Combined with FIX-018 (section disambiguation), all 7 mali_kbase.ko functions lift with correct code bytes from the first instruction.
- **Requires Remill .node rebuild** (`npx node-gyp rebuild`).

### Disassembler — Backtrack Validation with Capstone Linear Sweep (FIX-022c)

- **Linear Sweep Validation** — After `findFunctionStartForAddress` returns a backtrack candidate, `validateBacktrackCandidate()` decodes instructions linearly from the candidate to the original address using Capstone. If the sweep encounters a `RET`, `INT3` padding (CC CC), unconditional `JMP` to outside the range, or a decode failure before reaching the original address, the candidate belongs to a **different function** and the backtrack is rejected. Replaces the fixed distance limit (256/4096 bytes) with a semantically correct validation.
- **Impact**: Fixes the UpdatePosition-full regression on ROTTR (108-byte backtrack crossed a `ret` boundary into an adjacent function). All 7 previously regressed functions are now either restored or improved. Zero regressions across PE64 (ROTTR) and ET_REL (mali_kbase.ko) test binaries.
- **Cost**: ~30-50 Capstone decode calls per backtrack validation (submillisecond). Only runs when autoBacktrack is enabled and the candidate differs from the original address.

### Disassembler — autoBacktrack Regression Fix for PE (FIX-022)

- **forceProbe Conditional on File Type** — `findFunctionStartForAddress` was called with `forceProbe=true` in both `liftToIR` code paths, which skips the function table and always does byte-level prologue scanning. For PE64 binaries (ROTTR), this caused the scanner to backtrack too far (108-1755 bytes) into **adjacent functions**, collapsing 19-23 basic blocks down to 1. Now uses `forceProbe=false` for PE files (consults function table first), and `forceProbe=true` only for ET_REL (.ko) where the function table may have misdetected entries. Fixes NpcDamage (50→7→restored), UpdatePosition (42→10→restored), BoneTransform (22→10→restored) regressions on ROTTR.

### Remill Wrapper — Kernel Module Lifting Improvements (FIX-019/020/021)

- **Return Thunk Recognition (FIX-019)** — Phase 1 (pre-decode) and Phase 3 (CFG wiring) now recognize `__x86_return_thunk`, `__x86_indirect_thunk_*`, and `__x86_return_thunk_safe` as function returns instead of jumps. In Spectre-mitigated kernels, `ret` is replaced by `jmp __x86_return_thunk` (retpoline). Without this fix, the lifter treats the thunk jump as an unconditional branch to an external target, leaving the block without a proper return terminator and causing the scanner to continue past the function boundary. Now emits `ret` in the LLVM IR for these blocks, preventing code bleed into adjacent functions. Affects all kernel modules compiled with `-mretpoline`.
- **Branch Target Resolution via Relocation Map (FIX-020)** — Phase 1 leader discovery now consults the `externalSymbols_` map when evaluating jump targets. In ET_REL files, branch targets that resolve to known kernel symbols (e.g., `__x86_return_thunk`) are handled at the symbol level rather than the address level, preventing false leader insertion for external trampolines.
- **Internal Call Target Tracking (FIX-021)** — `callTargets` in `LiftResult` now includes BOTH external AND internal call targets (previously only external). The TypeScript `liftToIR` command separates them: internal targets (within `.text` range, not in symbolMap) are reported as `internalCallTargets[]` in the result for downstream recursive lifting. Example: `kbase_jit_allocate` calling `find_reasonable_region` (internal helper at 0x142a0) — now visible in the result for future multi-function lifting.
- **Requires Remill .node rebuild** — FIX-019 and FIX-020 are C++ changes in `remill_wrapper.cpp`. The TypeScript FIX-021 is active immediately. Full effect requires rebuilding the hexcore-remill native module.

### Disassembler — ET_REL Section Disambiguation (FIX-018)

- **Code Section Priority in addressToOffset** — For ET_REL (relocatable) ELF files, multiple sections have `virtualAddress=0` (e.g., `__bug_table`, `.text`, `.rodata`, `.data`, `.debug_info` — all start at VA 0). The `addressToOffset()` function used a first-match strategy, so `__bug_table` (which comes before `.text` in the section list) would intercept addresses meant for `.text`. This caused `getBytes(0x3A20)` to return bug table data instead of function code, producing garbage semantics (ADD/OR byte ops on AL/CL registers). Now uses two-pass matching: Pass 1 prioritizes `isCode || isExecutable` sections, Pass 2 falls back to any matching section for data addresses.
- **Impact**: ALL 7 mali_kbase functions were affected. `kbase_jit_allocate` returned 67 garbage semantics; with the fix, it should return 400+ real instructions with branches, calls, and control flow.

### Disassembler — CET/ftrace Preamble Skip (FIX-017)

- **endbr64 + __fentry__ Skip** — Linux kernel modules compiled with `-fcf-protection` and `-pg` start every function with `endbr64` (F3 0F 1E FA) + `call __fentry__` (E8 00 00 00 00) — a 9-byte preamble that Remill's amd64 semantics module cannot decode. Without skipping, the lifter falls into byte-by-byte decoding, producing ADD/OR byte operations instead of real instructions. The `liftToIR` command now detects and skips this preamble, advancing `startAddress` by 9 bytes to the real `push rbp; mov rbp, rsp` prologue.
- **Supported Patterns**: `endbr64` (F3 0F 1E FA), `endbr32` (F3 0F 1E FB), `call +0` ftrace NOP (E8 00 00 00 00), multi-byte NOP sled (66 0F 1F ...).
- **Impact**: `kbase_jit_allocate` goes from 67 garbage semantics (ADD/OR byte ops) to real x86-64 instructions with branches, calls, and control flow.

### Disassembler — Buffer Size Fallback Fix (FIX-016)

- **Smart Function Sizing** — `liftToIR` fallback buffer size changed from **256 bytes** to intelligent sizing. Priority chain: (1) explicit `options.size`, (2) `options.count * 15` clamped to symbol table size, (3) `getRecommendedLiftSize()` from ELF/PE symbol table, (4) 4096-byte fallback. Fixes functions like `kbase_jit_allocate` (2121 bytes) being truncated to 74 semantics — now lifts the full function with 400+ semantics, 20+ basic blocks, and 40+ external calls.
- **`getSymbolSizeAt(address)`** — New engine method that resolves function size from: (1) function table (`analyzeAll`), (2) ELF `.symtab`/`.dynsym` `st_size` field (from P4 enhanced parsing), (3) gap to next function in sorted address list. Returns 0 if unknown.
- **`getRecommendedLiftSize(address, fallback)`** — Returns `symbolSize + 16` (padding for alignment/epilogue) if symbol size is known, otherwise the fallback value.
- **Count+Symbol Max** — When `count` is provided, `size = max(count*15, symbolTableSize)`. Ensures the buffer is at least as large as the real function even when count underestimates. Example: `count=300` gives `4500` bytes, but if the symbol table says the function is `5000` bytes, `5000` is used.
- **All 4 code paths fixed** — Both `liftToIR` (Remill) and `rellic.decompile` (Rellic) commands, both `address` and `functionAddress` branches.

### Disassembler — Duplicate Declare Fix (FIX-011b)

- **Deduplicate External Symbol Declarations** — The `liftToIR` FIX-011 post-processor emitted `declare ptr @vunmap(...)` both inline (Strategy A text replacement) and in the external symbols block (Strategy B annotation), causing `error: invalid redefinition of function` in the LLVM parser. Now scans the IR for existing `declare` statements before injecting the annotation block, filtering out already-declared symbols. Affected: `mali_kbase.ko` with `count >= 1000` (symbols `vunmap`, `kbase_is_page_migration_enabled`, `_raw_spin_unlock`, `_raw_spin_lock`, etc.).
- **Empty Block Guard** — When all external symbols are already declared inline, the annotation block (`; --- External symbols ---`) is not injected at all, keeping the IR clean.

### Pipeline & Integration Fixes

- **Full Static Pipeline Upgraded** — Default `full-static` pipeline profile now uses `hexcore.disasm.analyzePEHeadless` (v3.7.5 deep analysis with typed imports, API signatures, security indicators) instead of legacy `hexcore.peanalyzer.analyze`. Import table is always present in pipeline output.
- **PE Analyzer Fallback** — When the standalone `hexcore-peanalyzer` extension returns empty imports (RVA resolution failure for some binaries), it now falls back to `hexcore.disasm.analyzePEHeadless` to fill the import table via the disassembler engine's IAT/ILT walker.
- **Documentation Updated** — `HEXCORE_AUTOMATION.md` and `HEXCORE_JOB_TEMPLATES.md` updated with new command names, descriptions, and aliases (`hexcore.pe.deep`, `hexcore.elf.deep`).

### Engine Versions

| Engine | Version | Changes |
|--------|---------|---------|
| hexcore-remill | 0.2.0 | +SSE selective inlining, intrinsic lowering, register naming, 3rd opt round |
| hexcore-capstone | 1.3.4 | (unchanged) |
| hexcore-unicorn | 1.2.3 | (unchanged) |
| hexcore-helix | 0.8.0-nightly | +C AST layer, 14-pass optimizer, State GEP resolution, XMM float typing |
| hexcore-llvm-mc | 1.0.1 | (unchanged) |
| hexcore-better-sqlite3 | 2.0.0 | (unchanged) |
| hexcore-disassembler | 1.4.0 | +PE API sigs, ELF deep analysis, analyzePE/ELFHeadless, P3 rename wiring |
| hexcore-base64 | 2.0.0 | +Confidence scoring engine, context filters, entropy analysis |

### Known Issues

- **Residual `(int64_t)(void*)0` in Non-Float Context** — Some State GEPs that don't resolve to named registers still appear as null pointer dereferences. The `eliminateNullPtrStores` pass removes most of these, but values used as expression operands (not assignment targets) may survive. Full fix requires deeper State struct analysis in RemillToHelixLow.
- **`block_argN` Variables** — MLIR block arguments from `select`/phi nodes appear as unresolved `block_arg0` in some control flow paths. The `cleanupFloatZeros` pass replaces these with `0.0f` in float context, but non-float contexts still show the raw name.
- **Type Propagation Incomplete** — All non-XMM variables still typed as `int64_t`. Struct pointer types (`Entity*`), field types (`float` for health values), and return types require deeper type inference passes planned for v1.0.

---

## [3.7.3] - 2026-03-26 - "Field-Tested Fortification"

> **29-Item Engineering Overhaul** — Consolidated all findings from the ROTTR.exe reverse engineering session (PE64, ~1.4GB), code reviews of hexcore-capstone and hexcore-unicorn, POWER.md compliance audit, and community feedback (Issue #18). This release resolves the only known P0 crash, hardens every native engine, introduces function boundary detection, and adds four new headless commands for the automation pipeline.

### Critical Fixes

- **[P0] Helix Liveness.cpp Assertion Crash (BUG-HELIX-001)** — Fixed `StructureControlFlow::detectEscapingValues` to also scan **block arguments** (MLIR phi values), not just operation results. Block arguments defined inside a loop body with uses outside the region were silently missed, causing a fatal `"Use leaves the current parent region"` assertion during the HelixLow→HelixHigh pass pipeline. Affects functions with deep loops, backward branches to entry blocks, and heavy SIMD code paths.
- **Unicorn DLL Missing in Packaged Build (BUG-UNI-008)** — The `.exe` build was missing `unicorn.dll` because `prebuild-install` only fetches the `.node` file, the DLL is gitignored, and the install script silently skipped the copy. Fixed across 4 points: (1) `hexcore-native-install.js` now downloads the DLL from GitHub Release if absent, (2) `.vscodeignore` force-includes runtime DLLs, (3) prebuild workflow uploads DLL as release asset, (4) installer workflow has a verification step with fallback download.

### Native Engine Fixes — hexcore-capstone

- **Async Worker Error Swallowing (BUG-CAP-001)** — `DisasmAsyncWorker::Execute()` now calls `SetError()` instead of silently storing errors in a member variable. Promises correctly reject with descriptive messages.
- **Detached ArrayBuffer Guard (BUG-CAP-004)** — Added `IsDetached()` check before dereferencing TypedArray buffers in `Disasm()` and `DisasmAsync()` paths.
- **C++17 Cross-Platform (BUG-CAP-005)** — Added `CLANG_CXX_LANGUAGE_STANDARD: c++17` for Mac and `/std:c++17` for Windows in `binding.gyp`.
- **target_name POWER.md Compliance (BUG-CAP-007)** — Renamed `capstone_native` → `hexcore_capstone` in binding.gyp, main.cpp, and index.js. Legacy name kept as fallback for transition.
- **Exception Contradiction (BUG-CAP-008)** — Aligned Mac/Windows exception settings with `NAPI_DISABLE_CPP_EXCEPTIONS`.
- **Unhandled Architecture Detail (BUG-CAP-003)** — `DetailToObject()` now returns `archSpecific: null` with a warning string for architectures without detail parsing (TMS320C64X, M680X, EVM, WASM, BPF).
- **BigInt Addresses (FEAT-CAP-009)** — Instruction `address` field now emits BigInt for 64-bit safety. Backward-compatible `addressAsNumber` field added. Base address accepts both BigInt and Number.
- **Sync/Async Duplication (BUG-CAP-006)** — Documented as TODO for future refactor.

### Native Engine Fixes — hexcore-unicorn

- **GetRegisterSize Lookup Table (BUG-UNI-002)** — Full per-register size lookup for x86/x64 (200+ registers including GPR 8/16/32/64-bit, XMM 128-bit, YMM 256-bit, ZMM 512-bit, FP, MMX, segment, control/debug), ARM64 (B/H/S/D/Q/X/W registers), and ARM32. `RegRead` now returns correctly-sized buffers; `RegWrite` accepts Buffer for wide registers.
- **MemMap 32-bit Truncation (BUG-UNI-003)** — All `Uint32Value()` calls for memory sizes replaced with BigInt-aware parsing. Enables mapping regions > 4GB.
- **StateRestore Memory Cleanup (BUG-UNI-004)** — `StateRestore()` now calls `uc_mem_unmap()` on all existing regions before remapping from snapshot. Eliminates stale region persistence and UC_ERR_MAP regressions.
- **StateSave Data Loss (BUG-UNI-005)** — When `uc_mem_read` fails, the buffer is still stored (zeroed) and an `error` field is added to the region object for consumer diagnostics.
- **Auto-Map Limit (BUG-UNI-006)** — `InvalidMemHookCB` now enforces `MAX_AUTO_MAPS = 1000` with an atomic counter. Prevents address space exhaustion from malicious binaries. Counter resets on `EmuStart`, `EmuStartAsync`, and `StateRestore`.
- **CodeHook Sequence Numbers (BUG-UNI-007)** — `CodeHookCB` now stamps an atomic `sequenceNumber` on each callback, enabling JS consumers to detect out-of-order delivery from `NonBlockingCall`.

### Compliance

- **Copyright Headers (BUG-CAP-002 + BUG-UNI-001)** — Replaced `Copyright (c) Microsoft Corporation` with `Copyright (c) HikariSystem` in 7 source files across Capstone and Unicorn (both monorepo and standalone repos).

### Added — Function Boundary Detection (Fase 2)

- **Native Prologue Scanner (FEAT-CAP-010)** — New `detectFunctions()` async method on the Capstone wrapper. C++ worker scans entire code buffers for prologue patterns (x86/x64: `push rbp`, `endbr64`, `sub rsp`; ARM64: `stp x29,x30`; ARM32: `push {regs,lr}`; MIPS: `addiu sp`) and collects call targets. Returns `FunctionBoundary[]` with start/end, confidence score, detection method, and thunk flag.
- **Auto-Backtrack (FEAT-DISASM-004)** — `disassembleAtHeadless` and `helix.decompile` (via `liftToIR`) now auto-detect function boundaries. When an address lands mid-function, the system scans backward to find the real function start. Disable with `"autoBacktrack": false`.
- **Decompiler Stub Elimination (BUG-HELIX-002)** — Consequence of auto-backtrack: Helix no longer decompiles partial stubs when given mid-function addresses.

### Added — Helix Decompiler Quality (Fase 3)

- **optimizeIR Flag (BUG-HELIX-003)** — Full pipeline implementation from C++ Engine → C API → Rust FFI → NAPI-RS → TS wrapper. `helix.decompile` headless now accepts `"optimizeIR": false` to skip Tier 2.5 optimization passes (magic division recovery, devirtualization).
- **Confidence Score Penalties (FEAT-HELIX-004)** — `PseudoCEmitter::analyzeFunction` now penalizes: stub functions with < 5 statements (-40 points), short functions < 10 statements (-15), and undecomposed native opcode calls (-3 each, max -30). Scores reflect actual output quality.
- **x64 Opcode Decomposition (FEAT-HELIX-005)** — 30+ native x64 opcodes now emit C expressions instead of raw opcode function calls: SSE conversions (`CVTPS2PD` → `(double)`), memory moves (`MOVSD_MEM` → `*(double*)addr`), min/max (`MINSS` → `fminf()`), sign extension (`CWDE` → `(int32_t)(int16_t)`), SSE arithmetic (`MULSS` → `*`), and more.

### Added — Pipeline & Analysis (Fase 4)

- **Batch String Search (FEAT-DISASM-001)** — `searchStringHeadless` now accepts `{ queries: ["health", "ammo", ...] }` for batch mode. Reduces 25-step jobs to a single step. Results include per-query `query` field.
- **PE Section Filter (FEAT-STRINGS-001)** — String extraction prioritizes sections: `.rdata` (60%) > `.data` (20%) > `.rsrc` (10%) > `.text` (10%). Eliminates 99% noise from `.text` section. Results annotated with `section` field.
- **minLength Default (FEAT-STRINGS-002)** — Default minimum string length increased from 4 to 6 characters.
- **Pipeline Step Referencing (FEAT-PIPE-001)** — Job steps can reference previous outputs: `"$step[0].output"`, `"$step[prev].result.fieldName"`. Supports recursive object traversal and clear error messages for forward references.

### Added — New Headless Commands (Fase 5 + Issue #18)

- **RTTI Scan (FEAT-DISASM-002)** — `hexcore.disasm.rttiScanHeadless`: scans PE binaries for `.?AV` RTTI type descriptors, extracts class names with decorated/undecorated forms. Aliases: `rttiScan`, `scanRtti`.
- **AOB Scan (FEAT-DISASM-003)** — `hexcore.disasm.searchBytesHeadless`: byte pattern search with `??` wildcard support in virtual address space. Supports space-separated and compact hex formats. Aliases: `searchBytes`, `aobScan`.
- **Memory Pattern Search ([#18](https://github.com/AkashaCorporation/HikariSystem-HexCore/issues/18))** — `hexcore.debug.searchMemoryHeadless`: pattern search across emulated RAM during keepAlive sessions. Supports hex (with wildcards), ASCII, and UTF-16 patterns. Region filtering: `all`, `heap`, `stack`, or explicit ranges. Aliases: `searchMemory`, `unicorn.searchMemory`. *Requested by [@YasminePayload](https://github.com/YasminePayload).*

### Engine Versions

| Engine | Version | Changes |
|--------|---------|---------|
| hexcore-capstone | 1.3.4 | +detectFunctions, BigInt, SetError, target_name, C++17 |
| hexcore-unicorn | 1.2.3 | +RegisterSize lookup, MemMap BigInt, StateRestore, autoMap limit |
| hexcore-helix | 0.7.1 | +optimizeIR flag, confidence scoring, opcode decomposition, Liveness fix |
| hexcore-remill | 0.2.0 | (unchanged) |
| hexcore-llvm-mc | 1.0.1 | (unchanged) |
| hexcore-better-sqlite3 | 2.0.0 | (unchanged) |

---

## [3.7.2] - 2026-03-22 - "Headless Hardening + Runtime Convergence"

> **Stabilization & Architecture Release** — Focused convergence release ahead of the `3.8.0` Helix-first transition. `v3.7.2` hardens the automation-first HexCore stack across three fronts: (1) wrapper fidelity for Capstone and LLVM MC, (2) worker/runtime stability for Unicorn-backed debugger flows, and (3) first-round Remill/Helix precision fixes so LLVM IR and decompiler output stop lying in high-impact control-flow cases.

### Added

- **Richer Headless Debugger Metadata** — Headless debugger outputs now expose `executionBackend` and, on faulted runs, structured `faultInfo` to make worker-vs-in-process mode and unmapped-memory failures visible to operators and pipeline jobs.
- **`permissiveMemoryMapping` in `emulateHeadless`** — The lighter headless emulation entry point now accepts `permissiveMemoryMapping`, allowing more aggressive PE/x64 runtime experiments without forcing the full emulation command surface.
- **Expanded PE/CRT Runtime Contracts** — Added or strengthened WinAPI/CRT hook coverage used by real PE64 samples, including `GetSystemTimeAsFileTime`, `GetSystemInfo`, `GetNativeSystemInfo`, `GetCommandLineA/W`, `GetStartupInfoA/W`, `K32GetProcessMemoryInfo`, `psapi!GetProcessMemoryInfo`, `_get_wide_winmain_command_line`, `WideCharToMultiByte`, `MultiByteToWideChar`, and `__stdio_common_vsprintf_s`.
- **Wave 2 Runtime Diagnostics Notes** — Added dedicated runtime findings and updated automation/job-template docs covering `executionBackend`, `faultInfo`, `permissiveMemoryMapping`, trace-loop jobs, and breakpoint-loop jobs.
- **Remill LLVM Optimization Pass Pipeline (Phase 5.5)** — The Remill wrapper now runs a curated sequence of LLVM passes on lifted IR before output: SROA → mem2reg → EarlyCSE → InstCombine → SimplifyCFG → DCE → ADCE → DSE → InstCombine → SimplifyCFG. A double-round of InstCombine + SimplifyCFG catches opportunities exposed by dead store elimination. Eliminates flag computation intrinsics, redundant State store/load sequences, and trampolim blocks. IR size reduced by ~55% on reference functions. Enabled by default via `optimizeIR: true`.
- **Remill Boundary Detection (`LiftOptions`)** — New configurable limits prevent the wrapper from generating oversized IR for large functions: `maxInstructions` (default: 2000), `maxBasicBlocks` (default: 500), `maxBytes` (default: 32KB). Result includes `truncated`, `nextAddress`, and `truncationReason` for chunked lifting support.
- **Remill CALL Target Recording** — Phase 1 pre-decode now detects direct and indirect function calls, records external call targets in `LiftResult.callTargets[]`, and creates proper basic block boundaries at CALL fall-through addresses.
- **Remill SSA Value Naming (Phase 6)** — All unnamed LLVM values and basic blocks receive explicit names (`%v0`, `%v1`, `%bb_0`, ...) before IR printing, eliminating SSA numbering parse failures in downstream `.ll` consumers.
- **Remill `LiftOptions` JS API** — `liftBytes()` now accepts an optional third argument: `{ maxInstructions, maxBasicBlocks, maxBytes, splitAtCalls, optimizeIR }`. All options have sensible defaults and are backward-compatible.
- **Helix Smart Parenthesization** — The Pseudo-C emitter now uses a full C operator precedence table (15 levels) to decide when parentheses are needed. Binary expressions like `(rbp - 0x31)` are emitted as `rbp - 0x31`; nested arithmetic like `(a + (b * c))` becomes `a + b * c`. All 50+ expression handlers across HelixHigh, HelixMid, HelixLow, LLVM, and Arith dialects were updated.
- **Helix Vtable Pattern Recovery** — Indirect calls through vtable offsets (e.g., `CALL [RAX+0x18]`) are now detected during HelixLow-to-Mid conversion. The vtable offset is propagated as an attribute through the 3-tier pipeline (Low→Mid→High) and emitted as `obj->vfunc_0x18(args)`. Fixes a regression from v0.6.0 where the Mid tier lost target expression info.
- **Helix PC Alloca Detection** — Robust fallback for PC register tracking when the Remill IR uses a GEP into the State struct (not a plain alloca) for `%PC`. The engine detects the PC pointer by matching the first `store entryAddr` and tracks all subsequent stores to the same pointer. Includes a per-block SSA evaluation cache that prevents address drift from mutated `trackedValues`.
- **Helix Label Deduplication & Goto Elimination** — Labels at the same address now receive unique suffixes (`loc_1405d3e75`, `loc_1405d3e75_2`). A new Phase 4.6 in StructureControlFlow removes trivial gotos that jump to the immediately following block (natural fallthroughs).
- **Helix Memory CMP/TEST Dereference** — When Remill semantics indicate a memory-source operand (`CMP [addr], imm` / `TEST [addr], imm`), the engine now emits a `MemReadOp` to load the value before comparing. Fixes `if (0x142dde25a != 0)` (always-true address comparison) → `if (*0x142dde25a != 0)` (correct value comparison).

### Changed

- **Capstone Async Option Parity** — The async disassembly path now replays the supported native handle options instead of effectively preserving only `DETAIL`, bringing the wrapper closer to real engine behavior.
- **LLVM MC Wrapper Surface** — The product wrapper now exposes more of the native assembly surface, including CPU/features knobs and clearer trust boundaries around `assembleMultiple`.
- **Disassembler Function Discovery** — Indirect memory operands are no longer accepted as if they were real direct branch/call targets, eliminating large classes of fake discovered functions.
- **Worker Lifecycle Alignment** — ARM64, x64 ELF, and PE32 worker clients now share a more consistent startup/ready/error/cleanup model, including stronger startup diagnostics and better system-Node fallback behavior.
- **Headless Documentation Refresh** — `HEXCORE_AUTOMATION.md` and `HEXCORE_JOB_TEMPLATES.md` were refreshed to reflect the real Wave 2 debugger surface and current Helix-first workflow.
- **`hexcore-remill` version** — Bumped to `0.2.0`. Default lifting behavior now applies LLVM optimization passes and boundary limits automatically. Reference function `sub_1405d3e00` (7,500 bytes, 235 blocks) dropped from ~16,700 lines to ~7,500 lines of IR. Helix output for the same function went from 60+ blocks with unresolved gotos to a clean 24-line function at 100% confidence.

### Fixed

- **Ghost Function Pollution in Deep Analysis** — Fixed a high-impact function-discovery bug where indirect targets such as `[rip + 0x10]` were misread as real addresses, producing hundreds of zero-byte or tiny fake functions like `sub_10`, `sub_18`, and `sub_20`.
- **ARM64 Worker Startup Failure** — Fixed the `ARM64 worker not started` failure mode by hardening worker bootstrap, readiness checks, and startup error reporting.
- **Repeated-Run `UC_ERR_MAP` Regressions** — Debugger sessions now clean previous emulation state before remapping, preventing duplicate-map failures when rerunning headless jobs back to back.
- **PE64 RIP / Register Desynchronization** — Fixed stale register snapshots and x64 program-counter truncation in the PE worker path so `currentAddress`, `rip`, and headless register dumps stay coherent after execution.
- **Snapshot / Restore Metadata Drift** — Restoring a snapshot now restores both machine state and HexCore-side execution metadata, preventing mismatches between registers, `currentAddress`, and `instructionsExecuted`.
- **PE x64 TEB / GS Runtime Gaps** — Fixed Windows x64 emulation gaps around `GS_BASE`, TEB, TLS-vector, and TLS-data setup so real PE64 targets can execute substantially deeper before hitting bogus unmapped-memory faults.
- **PE Import Stub Dispatch** — Fixed the PE worker batch/stub dispatch argument ordering bug that prevented import-hook paths from activating reliably in worker mode.
- **`setBreakpointHeadless` Output Contract** — The headless breakpoint command now writes its declared output file correctly instead of succeeding without producing the expected artifact.
- **Remill Conditional Branch Lowering** — Fixed a major lowering bug where lifted conditional branches could collapse into `br i1 true`; the wrapper now uses real branch state instead of placeholder always-taken control flow.
- **Remill `NEXT_PC` Propagation** — Fixed unsafe `%NEXT_PC` inheritance across conditional predecessors, improving PC/NEXT-PC stamping at basic-block boundaries in lifted LLVM IR.
- **Helix MLIR Stability** — Fixed a fatal MLIR liveness assertion caused by values escaping newly structured regions, allowing previously crashing decompilation cases to complete and produce output again.
- **Helix Indirect Call Honesty** — Unresolved indirect-call rendering was improved so Helix stops pretending obviously internal branch targets are clean direct calls. The instruction address is no longer used as a fake callee address (`__indirect_1405d3e0f` → `__indirect_call`); vtable calls show `obj->vfunc_0xNN()` instead.
- **Helix PC Address Tracking** — Fixed all decompiled instructions showing the same address (`// 0x1405d3e75` everywhere) due to SSA re-evaluation of `load NEXT_PC` seeing mutated `trackedValues`. Each instruction now carries its correct unique binary address.
- **Helix `loc_irr_*` Labels** — Irreducible control flow labels changed from meaningless counters (`loc_irr_100`, `loc_irr_103`) to hex addresses from the binary (`loc_1405d3e75`, `loc_1405d42a8`).
- **Helix VarRefOp / UndefOp / RetOp Emission** — Fixed `/* unhandled: helix_high.var.ref */` appearing as statements, `/* undef */` in expressions, and missing `helix_low.ret` handler.
- **Remill Prebuild Loading Priority** — Discovered that `index.js` loads prebuilds before `build/Release/`, silently ignoring newly compiled `.node` files. Resolved by ensuring the build output is copied to the prebuild directory.
- **Remill SSA Numbering Errors** — Multi-block lifting inserted instructions into different blocks out of creation order and the strip phase removed referenced values, producing `expected to be numbered '%894' or greater` parse errors. Fixed by explicit value naming in Phase 6.
- **Remill Missing CALL Fall-Through Leaders** — Function call instructions did not create basic block boundaries at their fall-through addresses, causing CALL instructions to be merged into larger blocks instead of properly splitting the CFG.

### Architecture Notes

- `v3.7.2` is the stabilization bridge into `v3.8.0`, not the full IPC redesign. Shared-memory / zero-copy IPC groundwork improved, but backlog item `#31` is not fully implemented in this release.
- Real-world runtime validation improved substantially on both ARM64 and PE64 targets. Representative Wave 2 validation now survives repeated-run, snapshot/restore, and long PE64 worker sessions that previously failed early.
- Standalone native repos were advanced in parallel with the monorepo work:
  - `hexcore-capstone` `1.3.3`
  - `hexcore-llvm-mc` `1.0.1`
  - `hexcore-unicorn` `1.2.2`
  - `hexcore-remill` `0.2.0` — LLVM optimization passes, boundary detection, SSA fix
  - `hexcore-helix` `0.7.0` — Smart parens, vtable recovery, PC tracking, label dedup, memory CMP dereference
- The Remill LLVM pass pipeline uses the New Pass Manager (LLVM 18.1.8). All required libraries (`LLVMPasses`, `LLVMScalarOpts`, `LLVMInstCombine`, `LLVMAnalysis`, `LLVMTransformUtils`) were already present in deps — no new dependencies added. The `.node` binary grew from ~10.6 MB to ~17 MB due to linking the pass infrastructure.
- The pass pipeline is a prerequisite for the Souper superoptimizer planned in v3.8.0. Souper works best on pre-cleaned IR; the passes remove the obvious noise so Souper can focus on non-trivial optimizations.
- `optimizeIR: false` is the recommended escape hatch for malware analysis scenarios where DCE/ADCE might remove intentional junk code that analysts need to study.
- Standalone `hexcore-remill` published at `AkashaCorporation/hexcore-remill` v0.2.0.

### Notes

- Rellic remains transitional and deprecated. Helix is the strategic decompiler direction going into `v3.8.0`.
- `v3.8.0` remains the release where larger decompiler architecture work, including Souper-era changes and final Rellic removal, is expected to mature.

---

## [3.7.1] - 2026-03-18 - "Dynamic Intelligence + XOR Massive Update"

> **Feature Release** — Two major feature sets shipped together as the first stable release since v3.7.0-beta.2. (1) Dynamic Intelligence: robust emulation (permissive memory mapping, faithful glibc/MSVCRT PRNG), advanced disassembly analysis (junk filtering, VM detection, PRNG pattern detection), runtime memory inspection (dumps, breakpoint auto-snapshots, side-channel analysis, dumpAndDisassemble), Rellic IR optimization passes with Souper hook for v3.8, and conditional pipeline branching (`onResult`). (2) XOR Massive Update: complete overhaul of the `hexcore-strings` deobfuscation engine from 3 scanners to 9, with centralized scoring, PE section awareness, and 19 new property-based tests. All features maintain full backward compatibility. Rellic marked deprecated — removal planned for v3.8.0.

### Added — Dynamic Intelligence

- **Permissive Memory Mapping** — `permissiveMemoryMapping: true` in `emulateFullHeadless` maps all PE sections and ELF segments with RWX permissions, allowing self-modifying VMs to execute from .rodata/.data without UC_ERR_FETCH_PROT. Supported in DebugEngine, PE32 Worker, and x64 ELF Worker.
- **glibc PRNG** — `prngMode: 'glibc'` provides faithful 344-state TYPE_3 algorithm. `srand(seed)` initializes the 31-word state table using LCG `16807 * state[i-1] % 2147483647`. `rand()` returns `(state[i-31] + state[i-3]) >>> 1`. Matches native glibc output for any seed.
- **MSVCRT PRNG** — `prngMode: 'msvcrt'` provides faithful LCG: `seed = seed * 214013 + 2531011`, returns `(seed >> 16) & 0x7FFF`. Matches native MSVCRT output for any seed.
- **PRNG Stub Preservation** — `prngMode: 'stub'` (default) returns 0 for all `rand()` calls, preserving backward compatibility. Invalid mode values fall back to stub with warning.
- **Memory Dumps** — `memoryDumps` array in `emulateFullHeadless` captures arbitrary memory ranges at breakpoints or end of execution. Each dump includes address, size, and base64-encoded data.
- **Breakpoint Auto-Snapshots** — `breakpointConfigs` with `autoSnapshot: true` automatically captures registers, stack, and optional memory ranges when breakpoints are hit, then continues execution.
- **Side-Channel Analysis** — `collectSideChannels: true` installs instrumentation hooks collecting instruction counts per basic block, memory access patterns, and branch statistics via `SideChannelData`.
- **Runtime Memory Disassembly** — `dumpAndDisassemble(address, size)` combines memory reading and Capstone disassembly for analyzing runtime-decrypted VM handlers and shellcode.
- **DisassemblerEngine `loadBuffer()`** — Accept raw buffer with base address for disassembly without file on disk.
- **Junk Instruction Filtering** — `filterJunk: true` in `analyzeAll` and `disassembleAtHeadless` detects and removes 7 junk patterns: call/pop (callfuscation), add/sub zero, nop sleds, push/pop same reg, xchg same reg, mov same reg, identity LEA. Reports `junkCount` and `junkRatio`.
- **VM Detection Heuristics** — `detectVM: true` in `analyzeAll` identifies dispatcher patterns (3+ cmp/jcc chains), handler tables (indirect jumps via `[reg*scale+base]`), and operand stacks (`[reg+reg*scale-offset]`). Reports `vmDetected`, `vmType`, `dispatcher`, `opcodeCount`, `stackArrays`, `junkRatio`.
- **PRNG Pattern Detection** — `detectPRNG: true` in `analyzeAll` scans for srand/rand/random/srandom call sites, extracts seed values via 5-instruction lookback on argument registers. Reports `prngDetected`, `seedSource`, `seedValue`, `randCallCount`, `callSites`.
- **Rellic `optimizationPasses`** — New parameter `optimizationPasses: string[]` allows specifying LLVM passes (`'dce'`, `'constfold'`, `'simplifycfg'`) before Rellic decompilation. Default `optimizerStep` is `'llvm-passes'` (DCE + ConstFold).
- **Souper Pipeline Hook** — `optimizerStep: 'souper'` logs "not yet implemented" and falls through to decompilation. Architecture ready for v3.8 Souper superoptimizer integration.
- **Pipeline `onResult` Conditional Branching** (GitHub Issue #16) — New `onResult` field in pipeline steps evaluates step output and controls flow. Operators: `contains`, `equals`, `not`, `gt`, `lt`, `regex`. Actions: `skip` (skip N steps), `goto` (jump to step index), `abort` (stop pipeline), `log` (log and continue). Loop protection: max 100 iterations.
- **`normalizeStep()` onResult Validation** — Validates `onResult` fields during step normalization, rejecting invalid operators/actions with descriptive errors.
- **`evaluateOnResult()` / `applyOnResultAction()`** — Exported functions for onResult evaluation and action application, enabling property-based testing.
- **24 Property-Based Tests (Dynamic Intelligence)** — Comprehensive PBT suite across 7 test files covering PRNG oracle properties, permissive mapping toggle, junk filter metamorphic properties, VM detection heuristics, PRNG detection, onResult evaluation/action/normalization, and loop protection.

### Added — XOR Massive Update (`hexcore-strings`)

- **Scoring Engine (`scoringEngine.ts`)** — Centralized string quality scoring replacing per-module `scoreRun` functions. Weights: printability (0.4), English frequency (0.3), bigrams (0.15), length (0.15), spaces (0.1). New bonuses: URL (+0.15), Windows path (+0.10), registry key (+0.10). Penalties: all-digits (0.3×), repeated characters (0.5×). Exports `scoreString`, `scoreStringDetailed`, `ScoringOptions`, `ScoreBreakdown`.
- **PE Section Parser (`peSectionParser.ts`)** — Parses PE headers (MZ → e_lfanew → PE signature → COFF → section table) to map file offsets to section names (.text, .data, .rdata, .rsrc, etc.). Exports `parsePESections`, `getSectionForOffset`, `PESectionMap`, `PESectionInfo`. Gracefully handles non-PE buffers.
- **Known-Plaintext Attack (`knownPlaintextAttack.ts`)** — Derives XOR keys by XOR-ing known plaintext patterns against ciphertext at every offset. Built-in `MALWARE_PATTERNS`: `http://`, `https://`, `MZ`, `This program`, `.exe`, `.dll`, `.sys`, `cmd.exe`, `powershell`, `HKEY_`, `SOFTWARE\`, null-padding. Extends partial keys via frequency analysis. Discards keys producing <30% printable bytes. Supports `customPlaintextPatterns` option.
- **Composite Cipher (`compositeCipher.ts`)** — Detects ADD (byte subtraction), SUB (byte addition), and ROT-N (alphabetic rotation, N=1–25) obfuscation. Tests all 255 key values for ADD/SUB and all 25 rotations for ROT. Reports operation type and key value in results.
- **Wide String XOR (`wideStringXor.ts`)** — Detects XOR-obfuscated UTF-16LE strings by checking for alternating null bytes after decoding. Converts UTF-16LE → UTF-8 for display. Tests single-byte and multi-byte XOR on word-aligned pairs. Uses `ignoreNullBytes: true` in scoring.
- **Positional XOR (`positionalXor.ts`)** — Two derivation modes: counter-linear (`decoded[i] = buffer[i] ^ ((base + i * step) & 0xFF)`, base 0x00–0xFF, step 1–8) and block-rotate (key of N bytes rotated every M bytes, keySizes [2,4,8], blockSizes [16,32,64,128,256]). Quick-check on first 256 bytes discards candidates with <5% printable.
- **Rolling XOR Extended (`rollingXorExt.ts`)** — Rolling XOR with window size 1–4: `decoded[i] = buffer[i] ^ XOR(buffer[i-1]...buffer[i-N])`. Tests 256 seed values for the first byte. Quick-check on 256 bytes per seed×window combination. Reports `windowSize` in results.
- **Layered XOR (`layeredXor.ts`)** — Cascaded multi-layer XOR decoding (up to 3 layers). After each layer, computes entropy per 256-byte block; if high-entropy regions (>7.0) are adjacent to low-entropy regions (<4.0), applies a second layer. Time-bounded at 2× single-layer cost via `performance.now()`. Reports full `layerKeys` sequence.
- **Kasiski Detector (`kasiskiDetector.ts`)** — Detects Vigenère-style key lengths via Kasiski Examination (repeated 3+ byte sequences, GCD of distances) with Index of Coincidence fallback (IC > 0.05 threshold). Supports configurable `maxKeyLength` (default 64). Used by `multiByteXor.ts` for dynamic key size candidates.
- **9-Scanner Orchestrator Pipeline** — `extension.ts` now runs scanners in sequence: xorBruteForce → multiByteXor → knownPlaintext → compositeCipher → wideString → positional → rollingExt → layered → stackStrings. PE pre-scan reads first 2KB to parse sections and prioritize .data/.rdata/.rsrc. Global dedup via unified `seen` set. Cap: 5000 results total, 2000 per scanner.
- **PE Section Attribution** — Each result now includes optional `section` field (e.g., `.data`, `.rdata`) when the result offset falls within a known PE section.
- **Individual Scanner Toggle Options** — New options on `hexcore.strings.extractAdvanced`: `enableKnownPlaintext`, `enableCompositeCipher`, `enableWideString`, `enablePositionalXor`, `enableRollingExt`, `enableLayeredXor`. All default to `true`.
- **`targetSections` Option** — Restricts scanning to specific PE sections (e.g., `[".data", ".rdata"]`). Results outside target sections are discarded.
- **`customPlaintextPatterns` Option** — Adds user-defined byte patterns to the known-plaintext attack in addition to built-in `MALWARE_PATTERNS`.
- **Updated Report Generator (`reportGenerator.ts`)** — Statistical summary at top (result count + average confidence per method). Separate sections for each new method: XOR-wide, XOR-layered, XOR-counter, XOR-block-rotate, XOR-rolling-ext, ADD, SUB, ROT, XOR-known-plaintext. "Section" column in tables when PE sections are available. XOR-layered rows show full key sequence. XOR-known-plaintext rows indicate originating pattern.
- **19 Property-Based Tests (XOR)** — PBT suite covering: ADD/SUB round-trip (P1), ROT round-trip (P2), layered XOR round-trip (P3), positional XOR round-trip (P4), rolling XOR extended round-trip (P5), multi-byte XOR arbitrary key round-trip (P6), wide string detection round-trip (P7), known-plaintext key recovery (P8), known-plaintext discard threshold (P9), Kasiski key length detection (P10), scoring bonus detection (P11), scoring repetition penalty (P12), wide string null byte scoring (P13), scoring backward compatibility (P14), result metadata completeness (P15), uniform key discard (P16), result count cap (P17), method enable/disable filtering (P18), PE section target filtering (P19).

### Changed

- **Debugger version** — `hexcore-debugger` bumped to `2.2.0`.
- **Disassembler version** — `hexcore-disassembler` bumped to `1.5.0`.
- **`hexcore-strings` version** — Bumped to `1.3.0`.
- **Pipeline runner** — `for` loop converted to `while` with manual index for `onResult` branching support.
- **`MAX_LOOP_ITERATIONS`** — Exported constant (100) for pipeline loop protection.
- **Rellic marked deprecated** — All documentation updated to indicate Rellic removal in v3.8.0. Use Helix instead.
- **`multiByteXor.ts`** — Scoring replaced by centralized `scoreString` from `scoringEngine.ts`. Frequency assumptions expanded from `[0x00, 0x20]` to `[0x00, 0x20, 0x65, 0xFF, 0x90, 0xCC]`. Kasiski integration for dynamic key size candidates. Uniform key discard (all bytes equal).

### Architecture Notes

- No native engines were modified in v3.7.1 — all changes are TypeScript-only.
- PRNG implementations are pure TypeScript, no native dependencies.
- Junk filtering, VM detection, and PRNG detection are pure functions operating on `Instruction[]` arrays.
- `onResult` evaluation reads step output from JSON files generated by headless commands.
- Souper hook is a no-op placeholder — actual integration requires LLVM/Souper native work in v3.8.
- All XOR scanner modules are pure functions with no VS Code API dependencies, enabling direct unit and property testing.
- Backward compatibility preserved: existing `hexcore.strings.extractAdvanced` calls without new options behave identically to v1.2.0.

### Backlog Items Resolved

| Item | Description |
|------|-------------|
| #6 | PRNG Analysis Helper (static detection) |
| #16 | Pipeline Conditional Branching (onResult) |
| #28 | Runtime Memory Disassembly (dumpAndDisassemble) |
| #29 | Memory Dumps + Breakpoint Auto-Snapshots |
| #30 | VM Detection Heuristics |

---

## [3.7.0-beta.2] - 2026-03-12 - "Helix Build Integration"

> **Build & Packaging Release** — Helix MLIR decompiler engine fully integrated into the CI/CD pipeline. Native prebuild fetch, `nativeExtensions` registration, and installer workflow updated for both Windows and Linux. Rellic marked deprecated in favor of Helix. Documentation updated across all automation and template docs.

### Added

- **Helix in `nativeExtensions` array** — `hexcore-helix` added to `build/lib/extensions.ts` `nativeExtensions` list. This routes the extension through `packageNativeLocalExtensionsStream` (bypasses `vsce npm list --production` check that fails on native-only extensions without declared npm dependencies).
- **Helix prebuild fetch (Windows)** — Added `cd ../hexcore-helix && node ../../scripts/hexcore-native-install.js` to the "Fetch HexCore Native Prebuilds" step in `hexcore-installer.yml`. Downloads `hexcore-helix.win32-x64-msvc.node` from the standalone repo release.
- **Helix prebuild fetch (Linux)** — Added dedicated "Fetch HexCore Helix Prebuilds (Linux)" step with `continue-on-error: true` (same pattern as Remill/Rellic Linux steps — Linux prebuilds may not exist yet).
- **`tsconfig.json` paths mapping** — Added `"hexcore-helix": ["../hexcore-helix"]` to `extensions/hexcore-disassembler/tsconfig.json` paths (done in beta.1 prep, confirmed working).

### Changed

- **Rellic marked deprecated** — `hexcore-rellic` is now deprecated in favor of `hexcore-helix`. Rellic remains functional but Helix produces substantially better output (structured control flow, named parameters, confidence scoring). All templates updated to prefer Helix commands.
- **Automation docs updated** — `HEXCORE_AUTOMATION.md` version bumped to v3.7.0-beta.2. Rellic commands annotated as deprecated. Helix commands already documented in beta.1.
- **Job templates updated** — `HEXCORE_JOB_TEMPLATES.md` version bumped to v3.7.0-beta.2. Full Static Analysis and CTF Reverse templates now use `hexcore.helix.decompile` instead of `hexcore.rellic.decompile`.
- **Command aliases updated** — `hexcore.decompile` now resolves to `hexcore.helix.decompile` (was `hexcore.rellic.decompile`). `hexcore.decompile.ir` now resolves to `hexcore.helix.decompileIR`.

### Architecture Notes

- Helix uses NAPI-RS (not node-gyp like other engines). The `.node` file naming convention is `hexcore-helix.win32-x64-msvc.node` (differs from the `hexcore_engine.win32-x64.node` pattern of Capstone/Unicorn/Remill/Rellic).
- Helix standalone repo: `hexcore-helix` under the Helxi org.
- 6 native engines total: Capstone, Unicorn, LLVM MC, Remill, Rellic (deprecated), Helix.

---

## [3.7.0-beta.1] - 2026-03-11 - "Helix MLIR Stability (Beta Part 1)"

> **Stability & Bug-Fix Release** — Critical crash fixes in the Helix MLIR decompilation engine. Functions with loop-at-entry patterns (backward branches to the entry block) no longer crash the extension host. Calling convention recovery is now crash-free on all IR patterns. PE32 emulation gotchas documented.

### Fixed

- **Helix: Entry block predecessor crash (LLVM `abort()`)** — Extension host crashed with `Entry block to function must not have predecessors!` + `LLVM ERROR: Broken module found, compilation aborted!` when decompiling functions whose Remill-lifted IR had backward branches to the entry block (loop-at-entry pattern). Root cause: `parseIR()` internally calls `llvm::UpgradeDebugInfo()` which calls `llvm::verifyModule(FatalErrors=true)` before returning — crashing before any sanitization could run. Fix: replaced `llvm::parseIR()` with direct `LLParser::Run(UpgradeDebugInfo=false)` in `Pipeline::parseLLVMIR()`, then applies entry block sanitization (insert new empty entry block with unconditional branch). Functions like `0x140001728` from `partial_encryption.exe` (SIMD + loop) now decompile successfully.

- **Helix: `RecoverCallingConvention` crash on large/unusual IR** — `DominanceInfo::getNode()` in MLIR 18.x crashes on certain IR patterns (massive single-block functions, nested regions). Root cause was `collectAbiCallArgs` → `findLatestRegWriteOnDomChain` → `domInfo.getNode()`. Fix: removed `DominanceInfo` entirely from `RecoverCallingConvention`. ABI argument recovery now uses block scan + predecessor search exclusively (`findLatestRegWriteInPredecessors` with configurable depth). HTB VVM challenge `05-banner.ll` (5973-line, 3-block function) now decompiles at 100% confidence.

- **PE32 emulation: `UC_ERR_MAP (code 11)` on repeated calls** — Calling `hexcore.debug.emulateFullHeadless` multiple times without `hexcore.debug.disposeHeadless` between attempts caused duplicate memory region mapping (Unicorn rejects re-mapping existing regions). Fix: always call `disposeHeadless` before starting a new emulation session.

- **PE32 emulation: `UC_ERR_READ_UNMAPPED (code 6)` on PE32 binaries** — Stack pointer (ESP) initialized to `0x800eeffc` but no stack memory region was mapped. `permissiveMemoryMapping` does not create a stack — it only controls section permission flags. Workaround: use multi-step approach (`emulateHeadless` + `setRegisterHeadless` to redirect ESP to an already-mapped heap region such as `0x5f00000`).

### Notes

- Helix engine `.node`: `hexcore-helix.win32-x64-msvc.node` rebuilt (11,878,400 bytes).
- Helix engine library: `helix_engine.lib` rebuilt (43,056,284 bytes).
- `helix_tool.exe` rebuilt and tested against `logic_1728.ll` — crash-free.
- All previous Remill 1–7 test suite files pass without regressions.
- `hexcore.helix.decompileIR` is the correct pipeline command for decompiling pre-lifted `.ll` files (not `hexcore.helix.decompile`).

---

## [3.6.0] - 2026-02-21 - "Decompiler & Deep Analysis"

> **Major Feature Release** — Rellic decompiler (experimental), disassembleAt headless command, emulateFullHeadless PE32 crash fix, searchString xref fix, and full pipeline integration for decompilation workflows.

### Added

- **Rellic Decompiler (Experimental)** — New native N-API engine (`hexcore-rellic`) that decompiles LLVM IR to pseudo-C with mnemonic annotations. Walks Remill-lifted IR directly and generates annotated C output with register variables, basic blocks, arithmetic, comparisons, branches, memory operations, and SSE/FP instructions. Supports 30+ x86/x64 mnemonic handlers (MOV, ADD, SUB, CMP, JMP, XOR, OR, SHL, SHR, LEA, INC, DEC, IMUL, MOVD, MOVSX, ADDSS, SUBSS, MULSS, MOVSS_MEM, CVTDQ2PS, NOP, and all conditional jumps). Built on LLVM 18 + Clang 18 + Z3.
- **`hexcore.rellic.decompile`** — Single-shot pipeline command: lifts machine code via Remill then decompiles to pseudo-C in one step.
- **`hexcore.rellic.decompileIR`** — Decompile pre-lifted LLVM IR text to pseudo-C.
- **`hexcore.rellic.decompileUI`** — Interactive decompile panel with editor integration.
- **`hexcore.disasm.disassembleAtHeadless`** — Disassemble N instructions starting at a given virtual address. Full headless handler with address parsing, instruction fetching, JSON output.
- **`hexcore.disasm.liftToIR`** — Lift machine code to LLVM IR via Remill engine (pipeline-safe).
- **Remill `cleanIR()` post-processing** — Strips Remill-specific metadata, normalizes function declarations, and cleans memory intrinsics for Rellic pipeline compatibility.
- **Deep Reverse Engineering job template** — New automation template: disassemble → lift IR → decompile → strings → base64 → report.
- **PE32 Worker process isolation** — Dedicated Worker for PE32 emulation with IPC message protocol, preventing Extension Host crashes from native segfaults.

### Fixed

- **`emulateFullHeadless` PE32 crash** — Extension Host crashed instantly and entered restart loop when running emulateFullHeadless on PE32 binaries. Root cause: native segfault in Unicorn engine propagated to Extension Host process. Fix: Worker process isolation (same pattern as x64 ELF and ARM64).
- **`searchStringHeadless` empty references** — `searchStringReferences()` returned `references: []` because it only scanned `this.instructions` array. Fix: implemented `scanTextSectionForStringRefs()` that scans full .text section bytes.
- **Rellic `demangleRemillSemantic()` off-by-one** — `_ZN12_GLOBAL__N_1` prefix is 17 chars, old code used `substr(0, 18)`. Fixed to use `prefix.size()`.

### Changed

- **Native prebuilds workflow** — Promoted `hexcore-rellic` from experimental job to main prebuild matrix. Rellic now builds alongside Capstone, Unicorn, LLVM MC, Remill, and better-sqlite3.
- **Pipeline capability map** — Added `liftToIR`, `rellic.decompile`, `rellic.decompileIR`, `disassembleAtHeadless` to `COMMAND_CAPABILITIES`, `COMMAND_OWNERS`, and `COMMAND_ALIASES`.
- **Full Static Analysis template** — Added `rellic.decompile` step with `continueOnError: true`.
- **CTF Reverse Engineering template** — Added `rellic.decompile` step for automated decompilation.

### Architecture Notes

- Rellic is marked **Experimental** — generates low-level IR-style pseudo-C, not readable high-level C. Best for automated pattern matching and batch analysis. Real Clang AST-based decompilation passes planned for v3.7.
- Rellic requires x86/x64 binaries only (same as Remill).
- Must use same LLVM version as hexcore-remill (LLVM 18) to avoid symbol conflicts.

---

## [3.5.4] - 2026-02-19 - "Stability & Isolation"

> **Bugfix, Stability, & Validation Release** — x64 ELF emulation crash fix via worker process isolation, intelligent IPC string memory synchronization, advanced custom VM CTF challenge validation, and memory region size correction.

### Fixed

- **Worker/Host Memory Desync** — Fixed a critical issue where the Node.js `x64ElfWorker` would dynamically modify the heap (e.g., decrypting strings) but the Host's HexCore instance couldn't read those strings when evaluating API hooks like `__printf_chk`.
- **Smart Memory Sync** — Implemented "Smart Sync" in `unicornWrapper.ts`. Before every API hook execution, HexCore instantly synchronizes 1024 bytes around argument pointers (`RDI`, `RSI`, `RDX`, `RCX`) from the Worker to the Host.
- **RSP Stack Synchronization** — Fixed a bug where `popReturnAddressSync` read stale Host stack memory instead of real stack written by the Worker. RSP is now continuously synced prior to hook validation.
- **x64 ELF emuStart crash (STATUS_HEAP_CORRUPTION)** — Unicorn's x64 ELF emulation caused `0xC0000374` heap corruption in the Electron extension host. Fix: x64 ELF emulation now runs in a dedicated child process (`x64ElfWorker.js`) communicating via JSON-RPC.
- **Unicorn `memRegions()` size calculation** — Fixed `end` field from Unicorn being inclusive instead of exclusive. Size is now `end - begin + 1n`.
- **Entropy Analyzer** — Fixed webview not updating and missing "Open File" button.

### Added

- **`getline` API Hook** — Implemented a robust `getline` hook in `linuxApiHooks.ts` utilizing `this.memoryManager.heapAlloc` to dynamically allocate and fetch inputs from `stdinBuffer`.
- **`__printf_chk` String Mapping** — Extended the `__printf_chk` hook to properly serialize its string formatting logic and propagate to the headless pipeline's `stdout`.
- **CTF Validation** — Verified that HexCore effortlessly executes over 19,000 instructions from advanced custom VM challenges, gracefully bypassing `ptrace` anti-dbg checks and evaluating dozens of sub-VM loops in headless automation mode.
- **x64 ELF Worker Client & Worker** — Standalone Node.js process and IPC client handling Unicorn state.
- **Debugger headless emulation commands** — 5 new pipeline-safe commands: `emulateFullHeadless`, `writeMemoryHeadless`, `setRegisterHeadless`, `setStdinHeadless`, `disposeHeadless`.

### Fixed

- **x64 ELF emuStart crash (STATUS_HEAP_CORRUPTION)** — Unicorn's x64 ELF emulation caused `0xC0000374` heap corruption in the Electron extension host process. Root cause: Unicorn's internal memory management conflicts with Electron's V8 heap. Fix: replicated the ARM64 worker pattern — x64 ELF emulation now runs in a dedicated child process (`x64ElfWorker.js`) communicating via JSON-RPC over IPC. The worker spawns automatically when `setElfSyncMode(true)` is called for x64 architecture, migrating all Unicorn state (memory regions, register values) to the isolated process.
- **Unicorn `memRegions()` size calculation** — `end` field from Unicorn is **inclusive** (last valid byte), so region size must be `end - begin + 1`, not `end - begin`. The off-by-one caused `UC_ERR_ARG` (code 15) during worker state migration because Unicorn rejected unaligned sizes (e.g., 4095 instead of 4096 for a page). Fixed in `setElfSyncMode` migration loop.
- **`getMemoryRegions()` display size** — cosmetic fix in 3 code paths (ARM64 worker, x64 ELF worker, in-process) to use `end - begin + 1n` for correct region size display.
- **Entropy Analyzer webview not updating on second run** — CSP `nonce-${nonce}` doesn't work in VS Code sidebar webviews. Changed to `'unsafe-inline'` (same fix as PE Analyzer). Also added re-send of cached analysis data when webview is recreated.
- **Entropy Analyzer missing "Open File" button** — added file picker button to toolbar, bypassing `getActiveFileUri()` logic.

### Added

- **x64 ELF Worker Client** (`x64ElfWorkerClient.ts`) — IPC client that manages the child process lifecycle. Supports: `initialize`, `mapMemory`, `memWrite`, `memRead`, `regWrite`, `regRead`, `emuStart`, `emuStop`, `memRegions`, `contextSave`, `contextRestore`, `addHook`, `dispose`. BigInt values serialized with `BI:` prefix for JSON transport.
- **x64 ELF Worker** (`x64ElfWorker.js`) — standalone Node.js process that loads `hexcore-unicorn` and executes Unicorn operations in isolation. Handles all emulation lifecycle including hook callbacks via IPC.
- **Debugger headless emulation commands** — 5 new pipeline-safe commands: `emulateFullHeadless`, `writeMemoryHeadless`, `setRegisterHeadless`, `setStdinHeadless`, `disposeHeadless`. All registered in `COMMAND_CAPABILITIES`, `COMMAND_OWNERS`, and `COMMAND_ALIASES`.

### Removed

- **ARM64 heartbeat DIAG** — removed diagnostic `setTimeout` heartbeat logging from `startEmulation` (was temporary crash detection aid, no longer needed).
- **DIAG code in extension.ts** — removed diagnostic instrumentation from debugger extension entry point.

### Backlog Items Resolved

| Item | Description |
|------|-------------|
| N/A | x64 ELF worker process isolation (crash fix) |
| N/A | memRegions size calculation fix (UC_ERR_ARG) |
| N/A | Entropy analyzer webview + Open File button |

## [3.5.3] - 2026-02-18 - "Quality & Polish"

> **Maintenance Release** — Developer experience improvements, Issue #8 resolution, and documentation overhaul.

### Fixed

- **Preinstall robustness** — `build/npm/preinstall.ts` `installHeaders()` now uses `--ignore-scripts` flag, 60-second timeout, and clear error messages when `npm ci` fails in `build/npm/gyp/`. Prevents the interactive shell hang reported in Issue #8.
- **Report Composer outDir resolution** — `composeReport` now resolves the reports directory from: (1) explicit `reportsDir` argument, (2) `output.path` parent directory (pipeline outDir), (3) default `hexcore-reports/`. Previously it was hardcoded to `hexcore-reports/` which failed when the pipeline used a custom `outDir`.

### Added

- **CONTRIBUTING.md** — Complete contributor guide with prerequisites, quick start, project structure, test instructions, extension creation guide, code style reference, native engine development notes, and PR process.

### Improved

- **DEVELOPMENT.md** — Added "Important Notes" section at top with `VSCODE_SKIP_NODE_VERSION_CHECK` requirement, prebuild auto-download clarification, and preinstall troubleshooting.

### Issue #8 Resolution

All 5 items from @YasminePayload's build process report are now resolved. Full credit to **@YasminePayload** for the incredibly detailed bug report that directly improved HexCore's build system reliability and developer experience.

| Item | Description | Fixed In |
|------|-------------|----------|
| #1 | Interactive shell blocks npm install | v3.5.3 |
| #2 | Native module binary naming mismatch | v3.4.2 |
| #3 | Missing build/Release directory | v3.4.2 |
| #4 | Unicorn DLL multi-location requirement | v3.4.2 |
| #5 | No development build documentation | v3.5.3 |
| #6 | Debugger extension crash | v3.5.1 |

## [3.5.2] - 2026-02-17 - "Pipeline Maturity"

> **Feature Release** — Full pipeline maturity: every analytical capability in HexCore is now accessible programmatically. New ELF Analyzer, Report Composer, multi-byte XOR deobfuscation, and headless commands for Debugger, Base64, and Hex Viewer.

### Added

- **Debugger Headless — Snapshot & Restore** — `hexcore.debug.snapshotHeadless` and `hexcore.debug.restoreSnapshotHeadless` commands for pipeline-driven emulation state management.
- **API/Lib Call Trace** — `TraceManager` captures API/libc calls with arguments, return values, and PC addresses during emulation. New `TraceTreeProvider` panel for real-time visualization. `hexcore.debug.exportTraceHeadless` for pipeline export.
- **ELF Analyzer** (`hexcore-elfanalyzer`) — New extension for structural analysis of ELF binaries. TypeScript-pure parser supporting ELF32/ELF64, section/segment/symbol parsing, dynamic linking info, and security mitigations (RELRO, Stack Canary, NX, PIE). Commands: `hexcore.elfanalyzer.analyze`, `hexcore.elfanalyzer.analyzeActive`.
- **Report Composer** (`hexcore-report-composer`) — New extension that aggregates pipeline outputs from `hexcore-reports/` directory into a unified Markdown report with table of contents, evidence links, and analyst notes. Command: `hexcore.pipeline.composeReport`.
- **Base64 Headless** — `hexcore.base64.decodeHeadless` command for pipeline-driven Base64 string extraction from binary files.
- **Multi-byte XOR Deobfuscation** — Extended `hexcore.strings.extractAdvanced` with multi-byte XOR keys (2, 4, 8, 16 bytes), rolling XOR, and XOR with increment detection. Frequency analysis-based key recovery.
- **Hex Viewer Headless** — `hexcore.hexview.dumpHeadless` for programmatic hex dump extraction and `hexcore.hexview.searchHeadless` for pattern search with streaming (64KB chunks + overlap).
- **Pipeline Capability Registration** — All 9 new headless commands registered in `COMMAND_CAPABILITIES`, `COMMAND_OWNERS`, and `COMMAND_ALIASES` maps. 3 convenience aliases added.

### Backlog Items Resolved

| Item | Description |
|------|-------------|
| #21 | Debugger Headless Commands (snapshot/restore/trace) |
| #7b | API/Lib Call Trace Snippets in Debugger |
| #9 | Report Composer |
| #23 | ELF Analyzer Extension |
| #24 | Base64 Headless Mode |
| #25 | Multi-byte XOR Deobfuscation |
| #27 | Hex Viewer Headless Commands |

### New Headless Commands

| Command | Extension |
|---------|-----------|
| `hexcore.debug.snapshotHeadless` | hexcore-debugger |
| `hexcore.debug.restoreSnapshotHeadless` | hexcore-debugger |
| `hexcore.debug.exportTraceHeadless` | hexcore-debugger |
| `hexcore.elfanalyzer.analyze` | hexcore-elfanalyzer |
| `hexcore.base64.decodeHeadless` | hexcore-base64 |
| `hexcore.hexview.dumpHeadless` | hexcore-hexviewer |
| `hexcore.hexview.searchHeadless` | hexcore-hexviewer |
| `hexcore.pipeline.composeReport` | hexcore-report-composer |

## [3.5.1] - 2026-02-16 - "ARM64 Fix"

> **Bugfix Release** — Complete ARM/ARM64 support across disassembler, debugger, strings, and formula engines. Previously, ARM64 binaries were effectively unreadable. Tested against HTB Insane-level ARM64 ELF: 72 functions discovered (was 1).

### Fixed

- **Capstone ARM64 instruction classification** — `isCall`, `isRet`, `isJump`, `isConditional` flags now correctly detect ARM64 branch instructions: `blr`/`blraa`/`blrab`, `bx lr`/`retaa`/`retab`/`pop {pc}`, dot-notation (`b.eq`, `b.ne`), `cbz`/`cbnz`/`tbz`/`tbnz`, `br`, and ARM32 conditional branches (`beq`, `bne`, `bhi`, etc.).
- **STP x29,x30 encoding mask** — prolog scanner mask was `0xFFFF83FF` (included imm7 bits), changed to `0xFC407FFF` to match any addressing mode and offset.
- **Trampoline/thunk following** — `analyzeFunction` now follows unconditional jump targets as new functions (entry point trampolines like `b #target` were previously dead-ends).
- **Race condition in recursive analysis** — `analyzeFunction` fired off child BL target analysis without `await`, causing floating promises. Functions discovered via calls were missing from reports. Now properly awaits all child targets before returning.

### Added

- **ARM64/ARM32 function prolog scanning** — `scanForFunctionPrologs` detects STP x29,x30 (any addressing mode), SUB SP,SP, PACIASP (ARM64), PUSH {lr}/STR LR,[SP] (ARM32).
- **ARM64 function end detection** — architecture-aware: ARM64 NOP (`0xD503201F`), ARM32 NOP, UDF padding, and ARM prolog boundaries.
- **ARM64/ARM32 fallback disassembly** — `decodeARM64Fallback` (NOP, RET, BL, B, B.cond, CBZ/CBNZ, STP, LDP, BLR, BR) and `decodeARM32Fallback` (NOP, BX LR, POP {pc}, BL, B, PUSH).
- **ARM64 stack string detection** — `stackStringDetector` scans for STRB/STR opcodes with SP/FP base register, backward search for MOVZ loading ASCII values.
- **ARM64 DebugEngine** (5 methods):
  - `setupArm64Stack()` — LR=0xDEAD0000 sentinel, 16-byte SP alignment
  - `initializeElfProcessStack()` — argc/argv/envp via X0/X1/X2 (register-based)
  - `installSyscallHandler()` — SVC #0 interception (intno===2), X8=syscall number
  - `updateEmulationRegisters()` — x0-x15, fp, sp, pc, nzcv mapping
  - `popReturnAddress()` — reads LR (X30) instead of stack pop
  - 20+ ARM64 Linux syscalls: write(64), exit(93), exit_group(94), brk(214), mmap(222), openat(56), close(57), fstat(80), ioctl(29), readlinkat(78), etc.
- **ARM64 formulaBuilder** — register recognition (x0-x30, w0-w30, sp, lr, fp, xzr, wzr, pc, r0-r15), `#` prefix handling, 15 ARM mnemonics (movz, movk, movn, mul, madd, msub, neg, eor, orr, and, lsl, lsr, asr, mla, mvn), 3-operand instruction form support.

### Backlog Items Resolved

| Item | Description |
|------|-------------|
| #22 | ARM64 DebugEngine Completion |
| #26 | buildFormula ARM64 Register Support |

## [3.5.0] - 2026-02-15 - "Fortification"

> **Security & Stability Release** — Full codebase audit across all 18 HexCore extensions. CSP hardening, memory safety, input validation, and crash prevention.

### Security

- **CSP nonce-based script injection** — hexviewer and peanalyzer webviews now use `nonce-<random>` instead of `'unsafe-inline'` to prevent XSS attacks.
- **ReDoS prevention** — base64 scanner regex bounded to `{20,4096}` (was unbounded `{20,}`).
- **Output path validation** — hashcalc and filetype `output.path` restricted to workspace or user home directory, preventing arbitrary file writes.
- **File size limit** — disassembler engine rejects files >512MB before `readFileSync` to prevent OOM crashes.

### Fixed

- **Unicorn hook memory leaks** — replaced raw `new`/`delete` with `std::unique_ptr` RAII in 5 hook callback allocations (`unicorn_wrapper.cpp`).
- **Strings offset carryover bug** — fixed incorrect offset calculation in chunked extraction that caused reported offsets to drift.
- **Base64 streaming** — replaced `readFileSync` with chunked streaming (1MB chunks + 4KB overlap) to handle large files without loading entire file into memory.
- **Remill crash prevention** — added try/catch in C++ `DoLift` and `LiftBytesWorker::Execute` (was aborting process due to `NAPI_DISABLE_CPP_EXCEPTIONS`).
- **Remill semantics path resolution** — `GetModuleHandleA` now tries both `hexcore_remill.node` and `hexcore-remill.node` naming conventions.
- **Capstone ARM/ARM64 sync/async detail parity** — sync path now includes `mem`, `shift`, `vectorIndex`, `subtracted`, `ext`, `vas` fields matching async output.
- **Capstone error handling** — `numInsns == 0` with `CS_ERR_OK` is now treated as valid (empty input), added null guard on `cs_free`.

### Changed

- **Truncation warnings** — hexviewer search results (50 limit) and peanalyzer suspicious strings (20 limit) now show "Showing X of Y" when truncated.
- **Native module naming** — all 4 engines (Capstone, Remill, Unicorn, LLVM MC) now try both underscore and hyphen naming conventions for prebuilds.
- **`.vscodeignore` hardening** — added `!prebuilds/**` force-include to Capstone, Unicorn, LLVM MC, and better-sqlite3 to ensure prebuilds survive packaging.

### npm Packages Published

| Package | Version |
|---------|---------|
| hexcore-capstone | 1.3.2 |
| hexcore-remill | 0.1.1 |
| hexcore-unicorn | 1.2.0 |
| hexcore-llvm-mc | 1.0.0 |
| hexcore-better-sqlite3 | 2.0.0 |

## [3.4.1] - 2026-02-14

> **Fix Release** — hexcore-remill packaging fix: promoted from experimental to production engine in CI/CD pipeline.

### Fixed
- **hexcore-remill not included in packaged builds** — the native module worked in dev mode but was missing from the installer output. Added to `nativeExtensions` in build system.
- **Prebuild workflow** — moved hexcore-remill from experimental matrix to main prebuild matrix alongside Capstone, Unicorn, LLVM MC, and better-sqlite3.
- **Semantics packaging** — added dedicated semantics tarball (`remill-semantics-win32-x64.tar.gz`) to prebuild workflow for LLVM IR .bc files required at runtime.
- **Installer workflow** — added hexcore-remill prebuild fetch + semantics download for Windows and Linux builds.

### Changed
- Experimental prebuild matrix now only contains hexcore-rellic (future).
- Updated GitHub Actions versions in experimental job (v4 → v6).
- `docs/FEATURE_BACKLOG.md` — hexcore-remill moved from "Future Engines (Research)" to Infrastructure (#20).

## [3.4.0] - 2026-02-13 - "IR Horizon"

> **Feature Release** — Remill IR Lifting engine, N-API wrapper for machine code → LLVM IR translation, improved disassembler error handling, and native prebuild CI expansion.

### Added

#### hexcore-remill v0.1.0 (NEW)
- **Remill N-API wrapper** — lifts machine code to LLVM IR via the Remill library (Trail of Bits).
- **Static linking** — 168 static libs (LLVM 18, XED, glog, gflags, Remill) compiled with `/MT` via clang-cl x64.
- **API surface** — `liftToIR(buffer, arch, address)`, `getSupportedArchitectures()`, `getVersion()`.
- **Architecture support** — x86, x86_64 (amd64), aarch32, aarch64, sparc32, sparc64.
- **Build tooling** — `_rebuild_mt.py` (full /MT rebuild), `_write_gyp.py` (auto-generate binding.gyp from deps), `_pack_deps.py` (deps zip for CI), `_copy_to_standalone.py` (standalone repo sync).
- **Standalone repo** — [hexcore-remill](https://github.com/LXrdKnowkill/hexcore-remill) with prebuild releases and CI integration.
- **16/16 tests passing** — arch listing, version check, x86/x64 lifting, error handling, edge cases.

#### hexcore-disassembler: Remill IR Lifting Integration
- **`hexcore.disasm.liftToIR` command** — lift selected address range to LLVM IR from the disassembler UI.
- **`remillWrapper.ts`** — TypeScript wrapper with `liftToIR()`, `isAvailable()`, `getSupportedArchitectures()`, `getVersion()`.
- **`archMapper.ts`** — maps HexCore `ArchitectureConfig` to Remill architecture strings.
- **`buildIRHeader()`** — generates metadata header (file, arch, address range, timestamp) for IR output.
- **VA-aware address resolution** — uses loaded file's base address and buffer size for bounds checking.
- **Improved error messages** — shows loaded file name, base address, and buffer size when address resolution fails.
- **`isFileLoaded()` guard** — prevents confusing errors when no file is loaded.
- **Headless API** — `hexcore.disasm.liftToIR` registered as headless-capable with `file`, `address`, `size`, `output` contract.
- **Engine status** — "Capstone + LLVM MC + Remill" shown in status bar when all three engines are available.

### Changed
- Extension version bumps:
  - `hexcore-disassembler`: `1.3.0` -> `1.4.0`
- Native prebuilds CI (`hexcore-native-prebuilds.yml`) updated with Remill engine in main matrix.
- `docs/FEATURE_BACKLOG.md` updated with Infrastructure entries #12–#19.
- `docs/RUNBOOK_NATIVE_PREBUILDS.md` updated with Remill build instructions.
- `powers/hexcore-native-engines/POWER.md` updated with Remill wrapper documentation.

### Fixed
- **liftToIR address resolution** — was failing when user tested with addresses from a different binary than the one loaded. Now shows clear error with loaded file context.
- **Remill `GetSemanticsDir()` build conflict** — resolved `windows.h` / Sleigh `CHAR` macro collision in `remill_wrapper.cpp`.

## [3.3.0] - 2026-02-10 - "Deep Analysis"

> **Feature Release** — Windows Minidump forensic analysis, XOR brute-force deobfuscation, stack string detection, deep headless disassembly, and IOC SQLite backend.

### Added

#### hexcore-minidump v1.0.0 (NEW)
- **MDMP binary parser** — pure TypeScript implementation for Windows Minidump files (.dmp/.mdmp).
- **Stream parsing** — ThreadListStream, ThreadInfoListStream, ModuleListStream, MemoryInfoListStream, MemoryListStream, Memory64ListStream, SystemInfoStream.
- **Threat heuristics** — RWX memory region detection (shellcode indicators), non-system DLL identification, recently-created thread flagging, non-image thread start address detection.
- **4 headless commands** — `hexcore.minidump.parse`, `.threads`, `.modules`, `.memory` with JSON/Markdown output.
- **Pipeline integration** — all 4 commands registered as headless-capable with appropriate timeouts.

#### hexcore-strings v1.2.0 (UPGRADE)
- **XOR brute-force scanner** — single-byte key deobfuscation (0x01–0xFF) with quick-reject, printable run extraction, and English frequency confidence scoring.
- **Stack string detector** — x86/x64 opcode pattern matching for MOV-to-stack sequences (C6 45, C6 44 24, C7 45, C7 44 24), displacement-ordered reconstruction.
- **New command** — `hexcore.strings.extractAdvanced` for combined standard + deobfuscated extraction.
- **Report upgrade** — deobfuscated strings section with XOR key, confidence percentages, and instruction counts.

#### hexcore-ioc v1.1.0 (NEW)
- **IOC Extraction Engine** — automatic extraction of 11 IOC categories from binaries: IPv4/IPv6, URLs, domains, emails, file paths, registry keys, named pipes, mutexes, user agents, and crypto wallets.
- **Binary-aware noise reduction** — printable context validation rejects ghost matches from opcode byte sequences (e.g., `E8 2E 63 6F 6D` → `.com`), domain TLD whitelisting, and Set-based deduplication.
- **UTF-16LE dual-pass** — decodes Windows wide strings before regex matching for complete coverage.
- **Threat assessment** — automated severity tagging: suspicious URLs (raw IP hosts, C2 paths), persistence registry keys, ransomware wallet indicators.
- **SQLite persistence backend** — dual-mode storage (memory/sqlite) for IOC match deduplication via `hexcore-better-sqlite3`.
- **Auto-mode switching** — transparent upgrade to SQLite when file size ≥ 64 MB or match count ≥ 20,000.
- **Graceful fallback** — if `better-sqlite3` isn't available, automatically degrades to in-memory mode.
- **Headless pipeline support** — `hexcore.ioc.extract` registered as headless-safe with `file`, `output`, `quiet` contract.

#### hexcore-disassembler — Deep Headless Commands
- **`hexcore.disasm.searchStringHeadless`** — programmatic string xref search without UI prompts.
- **`hexcore.disasm.exportASMHeadless`** — assembly export to file without save dialog, single-function or all-functions mode.
- **`analyzeAll` instruction-level export** — `includeInstructions: true` flag enables per-function instruction listing (capped at 200), xref arrays, and string entries.
- **`maxFunctions` default raised** — 1000 → 5000 for large binary analysis.

#### hexcore-better-sqlite3 v1.0.0 (NEW)
- **SQLite wrapper** — deterministic prebuild packaging for `better-sqlite3@11.9.1`.
- **N-API v8** — prebuilt native addon for win32-x64.

### Changed
- Extension version bumps:
  - `hexcore-strings`: `1.1.0` -> `1.2.0`
  - `hexcore-ioc`: `1.0.0` -> `1.1.0`
- Pipeline capability map expanded with 8 new entries (5 Minidump + 1 Advanced Strings + 2 Deep Headless).
- GitHub Actions workflows updated to include IOC, YARA, minidump, and better-sqlite3 in build/installer pipelines.

## [3.2.2] - 2026-02-10 - "Pipeline Stabilization Hotfix"

> **Hotfix Release** — command registration consistency for packaged builds, YARA headless pipeline support, and entropy analyzer refactor.

### Added

#### hexcore-yara v2.1.0
- **Headless command contract** for `hexcore.yara.scan` with `file`, `quiet`, and `output` options.
- **Pipeline-safe exports** for YARA scan output in JSON or Markdown formats.
- **Expanded activation coverage** for all contributed commands and YARA views to avoid packaged-build activation gaps.

#### hexcore-entropy v1.1.0
- **Modular architecture** split into:
  - `types.ts` (contracts)
  - `entropyAnalyzer.ts` (streaming engine + entropy math)
  - `graphGenerator.ts` (ASCII graph)
  - `reportGenerator.ts` (report output)
  - `extension.ts` (command orchestration)
- **Sampling support** via `sampleRatio` option for large-file quick analysis.
- **Future crypto hook** via `cryptoSignals` (preview field, conservative stub for now).

### Fixed
- **Pipeline capability map** now includes:
  - `hexcore.yara.scan` (headless)
  - `hexcore.pipeline.listCapabilities` (headless)
- **Pipeline command args compatibility**:
  - `hexcore.pipeline.listCapabilities` now accepts `output.path` in runner options format.
- **Packaged-build "Command not found" reliability issues** addressed by expanding `activationEvents` coverage in:
  - `hexcore-yara`
  - `hexcore-debugger`
  - `hexcore-disassembler`
  - `hexcore-hexviewer`
- **Entropy large-file stability** improved with streaming/chunked analysis and adaptive block sizing.

### Changed
- Extension version bumps:
  - `hexcore-disassembler`: `1.2.0` -> `1.3.0`
  - `hexcore-yara`: `2.0.0` -> `2.1.0`
  - `hexcore-entropy`: `1.0.0` -> `1.1.0`
  - `hexcore-debugger`: `2.0.0` -> `2.0.1`
  - `hexcore-hexviewer`: `1.2.0` -> `1.2.1`
- Updated docs:
  - `docs/HEXCORE_AUTOMATION.md`
  - `README.md`
  - `.agent/skills/hexcore/SKILL.md`
  - `HEXCORE_AUDIT.md`

## [3.2.1] - 2026-02-09 - "Defender's Eye"

> **Stable Release** — YARA engine rewrite with Microsoft DefenderYara integration,
> constant decoder tooltip, pipeline automation UX, and GitHub Pages site.

### Added

#### hexcore-yara v2.0.0: DefenderYara Integration
- **Real YARA rule parser** — hex patterns (with wildcards `??`), text patterns (nocase/wide/ascii), regex patterns, and weighted conditions
- **DefenderYara integration** — index 76,000+ Microsoft Defender signatures from local `DefenderYara-main` directory
- **On-demand category loading** — load Trojan, Backdoor, Ransom, Exploit, etc. individually without flooding memory
- **Smart essentials loader** — `loadDefenderEssentials()` loads the top 11 threat categories for quick scans
- **Threat scoring** — 0-100 score with severity mapping: 🔴 Critical (Trojan, Ransom, Backdoor) / 🟠 High (Exploit, PWS, Worm) / 🟡 Medium (HackTool, Spyware) / 🟢 Low/Info
- **Threat Report** — formatted output in Output Channel with score bar, category breakdown, match offsets
- **Auto-detect DefenderYara** — scans common paths (Desktop, Downloads) on startup
- **New commands**:
  - `hexcore.yara.quickScan` — load essentials + scan in one click
  - `hexcore.yara.loadDefender` — select DefenderYara folder and index
  - `hexcore.yara.loadCategory` — QuickPick multi-select for specific categories
  - `hexcore.yara.threatReport` — show last scan's threat report
- **Dynamic Rules Tree** — sidebar shows DefenderYara categories with rule counts and loaded/pending status
- **Results Tree** — threat score header, grouped by category, severity icons with theme colors

#### hexcore-disassembler: Constant Decoder Tooltip
- **Hover tooltip** on any immediate value in the disassembly webview
- **Representations**: Hex, Unsigned, Signed32, Signed64, Binary, ASCII, Float32
- **Dark-themed** tooltip with copy buttons per representation
- **Placeholder-based regex** — prevents HTML corruption when multiple regex passes highlight operands

#### hexcore-disassembler: Pipeline Automation UX
- **`hexcore.pipeline.listCapabilities`** — lists all pipeline commands with HEADLESS/INTERACTIVE status, aliases, timeouts, and owning extensions
- **Workspace-aware banner** — pipeline runner logs workspace root, job file, target, output dir, step count, and timestamp

### Changed
- `hexcore-yara/yaraEngine.ts` — complete rewrite from simple string matching to real YARA parser with hex pattern matching engine
- `hexcore-yara/extension.ts` — 8 commands (was 4), progress bars, auto-detect DefenderYara, threat report formatting
- `hexcore-yara/resultsTree.ts` — threat score header, category grouping, severity-colored icons
- `hexcore-yara/rulesTree.ts` — dynamic categories from DefenderYara catalog, stats header
- `hexcore-yara/package.json` — bumped to v2.0.0, 4 new commands, `defenderYaraPath` config setting
- `.gitignore` — added hexcore-keystone (legacy), unicorn/llvm-mc build artifacts, `.hexcore_job.json`, wiki/

### Removed
- `extensions/hexcore-keystone/` — 50MB of legacy build artifacts removed from tracking (superseded by LLVM MC)

### Infrastructure
- **GitHub Pages** — landing page at https://lxrdknowkill.github.io/HikariSystem-HexCore/
- Dark theme cybersecurity design with animated threat score demo
- Features, extensions table, engine cards, pipeline code block, install steps

## [3.2.0-preview] - 2026-02-08 - "Linux Awakening"

> **Preview Release** - Major update introducing Linux ELF emulation, headless automation pipeline,
> and sweeping improvements across all analysis extensions. Tested against real CTF binaries (HTB).

### Added

#### hexcore-debugger v2.1.0: Full Linux ELF Emulation
- **PIE binary support** - Automatic detection of ET_DYN (Position Independent Executables) with conventional base address (`0x555555554000` for x64, `0x56555000` for x86)
- **PLT/GOT resolution** - Parse `.rela.plt` (JUMP_SLOT) and `.rela.dyn` (GLOB_DAT) relocations, create API stubs, patch GOT entries for full import interception
- **Direct GOT call support** - Handle modern `-fno-plt` style binaries that use `call [rip+GOT]` instead of PLT stubs
- **40+ Linux API hooks** with System V AMD64 ABI argument reading (RDI, RSI, RDX, RCX, R8, R9):
  - I/O: `puts`, `printf`, `fprintf`, `sprintf`, `snprintf`, `write`, `read`
  - String: `strlen`, `strcpy`, `strncpy`, `strcmp`, `strncmp`, `strstr`, `strchr`, `strrchr`, `strtok`
  - Memory: `memcpy`, `memset`, `memcmp`, `memmove`
  - Heap: `malloc`, `calloc`, `realloc`, `free`
  - Conversion: `strtol`, `strtoul`, `atoi`, `atol`
  - Process: `exit`, `abort`, `getpid`, `getuid`, `getenv`, `__libc_start_main`
  - Time: `time`, `gettimeofday`, `clock_gettime`, `sleep`, `usleep`
  - File stubs: `fopen`, `fclose`, `fread`, `fwrite`, `fseek`, `ftell`
  - Security: `__stack_chk_fail`
- **Linux syscall handler** - Intercept `syscall` instruction for: read, write, close, mmap, brk, getpid, getuid, arch_prctl, exit, exit_group
- **TLS/FS_BASE setup** - Automatic Thread Local Storage with stack canary at `fs:[0x28]` for GCC `-fstack-protector` binaries
- **`__libc_start_main` -> `main()` redirect** - Skip CRT init, jump directly to `main()` with argc/argv/envp
- **stdin emulation** - Configurable input buffer for `scanf`, `read(0)`, `getchar`, `fgets` with format specifier parsing (`%d`, `%s`, `%x`, `%c`, `%u`)
- **API redirect loop** - Transparent handling of multiple API calls during `continue()` with safety limit
- **New modules**: `linuxApiHooks.ts`, `elfLoader.ts`, `peLoader.ts`, `memoryManager.ts`, `winApiHooks.ts`
- **New commands**: `hexcore.debug.setStdin` for ELF stdin input, `hexcore.debug.unicornStatus` for engine diagnostics

#### hexcore-debugger: Emulation Engine Fixes
- **Fixed step stalling** - Removed `stepMode` flag, use Unicorn native `count=1` for reliable single-step
- **Fixed continue with breakpoint** - `isFirstInstruction` flag + `notifyApiRedirect()` prevents stub corruption
- **Fixed RIP=0x0 on continue** - `.rela.dyn` (GLOB_DAT) parsing ensures direct GOT calls are intercepted
- **Fixed isRunning state** - `getEmulationState()` correctly reports `isRunning=true` after load with new `isReady` field
- **RIP sync after emuStop** - `syncCurrentAddress()` reads actual RIP from Unicorn registers
- **`fs_base`/`gs_base` register support** in `setRegister()` for TLS segment access
- **`arch_prctl` syscall** now actually sets FS/GS base (was no-op before)

#### hexcore-disassembler v1.2.0: ELF Deep Analysis & Headless Mode
- **PIE detection** - Detect `ET_DYN` ELF type, auto-select base address
- **PLT/GOT parsing** - Resolve import function addresses via `.rela.plt`
- **Section/symbol address adjustment** for PIE base offset
- **PIE characteristic flag** - File info shows `['ELF', 'PIE']`
- **Headless `analyzeAll`** - Deep analysis with JSON/MD output for automation
- **Function summary export** - Address, name, size, instruction count, callers/callees

#### Automation Pipeline System (NEW)
- **Pipeline Runner** (`automationPipelineRunner.ts`) - Execute `.hexcore_job.json` job files with step-by-step headless execution
- **Command**: `hexcore.pipeline.runJob` - Run automation jobs manually or auto-trigger on file creation
- **Workspace watcher** - Auto-detects `.hexcore_job.json` in workspace
- **Step controls** - Per-step timeout, error handling, output validation
- **Status tracking** - `hexcore-pipeline.status.json` and `hexcore-pipeline.log` output
- **Extension preflight** - Auto-activates extensions before pipeline steps

#### All Analysis Extensions: Headless Mode
Every analysis tool now supports headless execution via standardized parameters:

| Extension | Command | Headless Parameters |
|-----------|---------|-------------------|
| **File Type** | `hexcore.filetype.detect` | `file`, `output`, `quiet` |
| **Hash Calculator** | `hexcore.hashcalc.calculate` | `file`, `algorithms`, `output`, `quiet` |
| **Entropy** | `hexcore.entropy.analyze` | `file`, `blockSize`, `output`, `quiet` |
| **Strings** | `hexcore.strings.extract` | `file`, `minLength`, `maxStrings`, `output`, `quiet` |
| **PE Analyzer** | `hexcore.peanalyzer.analyze` | `file`, `output`, `quiet` |
| **Disassembler** | `hexcore.disasm.analyzeAll` | `file`, `output`, `quiet` |

- All commands support JSON and Markdown output formats
- Backward-compatible aliases: `hexcore.hash.file`, `hexcore.hash.calculate`, `hexcore.pe.analyze`, `hexcore.disasm.open`

#### SKILL.md: Complete Technical API Documentation
- Full emulator memory layout with addresses (STUB_BASE, TEB, PEB, heap, stack, TLS)
- Complete DebugEngine, PE Loader, ELF Loader, Memory Manager API reference
- 25+ Windows API hooks table, 40+ Linux API hooks table, 12 syscall handlers
- Unicorn Wrapper API with all methods and types
- WebView message protocol and troubleshooting guides

### Changed
- `elfLoader.ts` completely rewritten with PIE support, PLT stub creation, and dual `.rela.plt`/`.rela.dyn` GOT patching
- `unicornWrapper.ts` overhauled with API redirect loop, state sync, and `EmulationState.isReady` field
- `debugEngine.ts` updated with ELF loading flow, TLS setup, stdin buffer, and state management
- `disassemblerEngine.ts` updated with inline PE/ELF parsing, function prolog scan, and string xrefs
- `capstoneWrapper.ts` improved with instruction type analysis (call/jump/ret/conditional detection)
- `llvmMcWrapper.ts` improved with multi-arch assembly support and NOP padding
- All analysis extensions refactored with consistent headless APIs

### Known Issues (Preview)
- Deep stepping (~400+ steps) may encounter `UC_ERR_FETCH_PROT` on some code paths
- File I/O hooks (`fopen`, `fread`, etc.) are stubs returning error codes
- No dynamic linker emulation (imports resolved statically via GOT patching)
- `.hexcore_job.json` is auto-generated by AI agents - not committed to repository

## [3.1.1] - 2026-02-03 - "Stability Pass"

### Added
- Native engine availability diagnostics for Disassembler and Debugger (Capstone/LLVM MC/Unicorn).
- Shared native module loader in `hexcore-common` with consistent error reporting.
- Postinstall native prebuild installer (`scripts/hexcore-native-install.js`) and Windows prebuild workflow.
- `engines.vscode` metadata for native engine packages to prevent extension host load errors.
- Function selector in the large disassembly editor for quick navigation.

### Fixed
- Disassembler PE analysis now passes file path (not buffer) and awaits results so Sections/Imports/Exports render.
- Large disassembly editor navigation now selects the containing function for a target address.
- Default function selection prefers entry point or first non-empty function instead of empty stubs.

### Changed
- Hardened native engine loading paths for Capstone/LLVM MC/Unicorn to improve portability.

## [3.1.0] - 2026-02-01 - "Integration"

### Added

#### hexcore-debugger: Unicorn Emulation Mode
- CPU emulation support via Unicorn Engine
- Multi-architecture emulation (x86, x64, ARM, ARM64, MIPS, RISC-V)
- Commands: emulate, step, continue, breakpoints
- Memory read/write and register manipulation
- Snapshot save/restore for state management
- Auto-detection of PE/ELF architecture and entry points

#### hexcore-disassembler: LLVM-MC Patching
- Inline assembly patching with LLVM MC backend
- Patch instructions with automatic NOP padding
- NOP instruction replacement
- Assemble single/multiple instructions
- Save patched files to disk
- Intel/AT&T syntax toggle for x86

#### hexcore-llvm-mc: New Native Module
- LLVM 18.1.8 MC-based assembler (replaces Keystone)
- Full multi-arch support: X86, ARM, ARM64, MIPS, RISC-V, PowerPC, SPARC, SystemZ, Hexagon, WebAssembly, BPF, LoongArch
- N-API bindings with async assembly support
- Plug-and-play (no external LLVM installation required)

## [3.0.0] - 2026-01-31 - "Trinity"

### Added - New Engines

#### hexcore-unicorn v1.0.0
- **Complete Unicorn Engine bindings** using N-API
- CPU emulation for all architectures: x86, x86-64, ARM, ARM64, MIPS, SPARC, PowerPC, M68K, RISC-V
- Memory operations: map, read, write, unmap, protect, regions
- Register operations: read, write, batch operations
- **Async emulation** with Promise support (`emuStartAsync`)
- Hook system: code execution, memory access (read/write/fetch), interrupts
- Context save/restore for snapshotting
- ThreadSafeFunction for JavaScript callbacks from native hooks
- **29/29 tests passing**
- Author: **Bih** [(ThreatBih)](https://github.com/ThreatBiih)

#### hexcore-keystone v1.0.0
- **Automated Keystone assembler** bindings
- Auto-generates architecture definition files (no manual configuration)
- X86/X64 assembly support (Intel, AT&T, NASM syntax)
- Async assembly support (`asmAsync`)
- Automatic build system with CMake
- **Legacy mode**: Based on LLVM 3.8 (stable but dated)

### Updated

#### hexcore-capstone v1.3.0
- **Standalone package** with async disassembly (`disasmAsync`)
- Dual module support: ESM (`index.mjs`) + CommonJS (`index.js`)
- Complete TypeScript definitions with JSDoc
- Extended architecture support (Capstone v5)
- Support for detail mode across all architectures

---

## [2.0.0] - Previous Release

- HexCore UI Overhaul & IDA-Style Graph View (CFG)
- Multi-arch disassembler integration
- Capstone N-API binding
- New analysis tools

[3.5.2]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v3.5.2
[3.5.1]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v3.5.1
[3.5.0]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v3.5.0
[3.4.1]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v3.4.1
[3.4.0]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v3.4.0
[3.3.0]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v3.3.0
[3.2.2]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v3.2.2
[3.2.1]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v3.2.1
[3.2.0-preview]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v3.2.0-preview
[3.1.1]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v3.1.1
[3.1.0]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v3.1.0
[3.0.0]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v3.0.0
[2.0.0]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v2.0.0
