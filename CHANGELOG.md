# Changelog

All notable changes to the HikariSystem HexCore project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
