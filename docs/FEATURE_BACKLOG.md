# HexCore Feature Backlog

> **Date**: 2026-02-17
> **Scope**: Improve reverse workflow quality, reproducibility and teaching value.
> **Source**: Analysis of real CTF usage (Wayback, virtually.mad challenges).

## Status Legend
- `DONE`: implemented and merged
- `IN_PROGRESS`: partially implemented
- `PENDING`: not implemented yet

## Current Snapshot (2026-02-19 — v3.5.4 "Stability & Isolation")
- P0 delivered: **5/5** (`#1`, `#2`, `#3`, `#4`, `#5`)
- P1 delivered: **4/5** (`#7a`, `#8`, `#7b`, `#9`)
- P2 delivered: **2/4** (`#24`, `#27`)
- Infrastructure delivered: **8/8** (`#12`, `#13`, `#14`, `#15`, `#16`, `#17`, `#18`, `#20`)
- Future Engines delivered: **0/2** (hexcore-rellic `NEXT` — planned for v3.6.0)
- Pipeline hardening added beyond original backlog:
  - `.hexcore_job.json` schema validation
  - `hexcore.pipeline.validateJob`
  - `hexcore.pipeline.validateWorkspace`
  - `hexcore.pipeline.doctor`
  - step retries (`retryCount`, `retryDelayMs`)
- v3.5.0 additions:
  - Full codebase security audit ("Fortification")
  - Capstone sync/async ARM/ARM64 detail parity (1.3.2)
  - Native module naming mismatch fix (underscore vs hyphen)
  - Remill promoted from experimental to production pipeline
- v3.5.1 additions:
  - ARM64 instruction classification fix in Capstone wrapper (isCall, isRet, isJump, isConditional)
  - ARM64/ARM32 function prolog scanning (STP x29,x30 / SUB SP,SP / PACIASP / PUSH {lr})
  - ARM64 trampoline/thunk following in recursive function analysis
  - ARM64 fallback disassembly (decodeARM64Fallback, decodeARM32Fallback)
  - ARM64 stack string detection (STRB, STR w/ SP/FP base)
  - ARM64 DebugEngine: 5 methods + 20 syscalls (#22 DONE)
  - ARM64 formulaBuilder: registers + 15 mnemonics (#26 DONE)
  - Race condition fix: analyzeFunction now awaits child BL targets
- v3.5.2 additions:
  - Debugger Headless: snapshotHeadless, restoreSnapshotHeadless (#21 DONE)
  - API/Lib Call Trace: TraceManager, TraceTreeProvider, exportTraceHeadless (#7b DONE)
  - ELF Analyzer: hexcore-elfanalyzer with ELF32/ELF64 parser and security mitigations (#23 DONE)
  - Report Composer: hexcore-report-composer for pipeline report aggregation (#9 DONE)
  - Base64 Headless: decodeHeadless command (#24 DONE)
  - Multi-byte XOR Deobfuscation: 2/4/8/16-byte keys, rolling XOR, XOR with increment (#25 DONE)
  - Hex Viewer Headless: dumpHeadless, searchHeadless with streaming (#27 DONE)
  - Pipeline Capability Registration: 9 new headless commands in COMMAND_CAPABILITIES
- v3.5.3 additions:
  - Preinstall robustness fix: --ignore-scripts, 60s timeout, clear error messages (Issue #8 #1)
  - CONTRIBUTING.md: complete contributor guide (Issue #8 #5)
  - DEVELOPMENT.md: added Important Notes section with troubleshooting
  - Issue #8 fully resolved (all 6 items closed)
- v3.5.4 additions:
  - x64 ELF worker process isolation: prevents STATUS_HEAP_CORRUPTION (0xC0000374) crash
  - Unicorn memRegions size fix: end is inclusive, size = end - begin + 1
  - getMemoryRegions display size cosmetic fix (3 code paths)
  - Debugger headless emulation commands: emulateFullHeadless, writeMemoryHeadless, setRegisterHeadless, setStdinHeadless, disposeHeadless
  - Entropy analyzer webview CSP fix + Open File button
  - ARM64 heartbeat DIAG removed, extension.ts DIAG cleanup

---

## P0 — Must Have

### 1. Immediate Constant Decoder in Disassembly
- **Status**: `DONE`
- **Problem**: Easy to misread constants from asm (example: `0x540be400`).
- **Feature**: Show hex + unsigned decimal + signed decimal in hover/panel.
- **Acceptance**:
  - Clicking an immediate shows all numeric forms.
  - Quick copy button for each representation.
- **Target**: v3.2.1

### 2. Expression Evaluator for Instruction Math
- **Status**: `DONE`
- **Problem**: Analysts manually compute formulas from instruction chains.
- **Feature**: "Build Formula" from selected instructions (`imul`/`add`/`sub`/`lea`).
- **Acceptance**:
  - Select sequence, get normalized expression preview.
  - Export expression to JSON/MD report.
- **Target**: v3.3.0

### 3. Workspace-Aware Pipeline UX
- **Status**: `DONE`
- **Problem**: Job executes in wrong workspace and confuses operators.
- **Feature**: Explicit banner "running from workspace X / job Y" before run.
- **Acceptance**:
  - Status/log always include workspace root path.
  - Command palette run shows resolved job file before execution.
- **Target**: v3.2.1

### 4. Command Capability Introspection
- **Status**: `DONE`
- **Problem**: Unclear which commands are headless-safe.
- **Feature**: `hexcore.pipeline.listCapabilities` command.
- **Acceptance**:
  - Outputs command, aliases, headless=true/false, timeout, required extension.
- **Target**: v3.2.1

### 5. Built-in Run Profile Presets
- **Status**: `DONE`
- **Problem**: Manual JSON tuning each time.
- **Feature**: Presets: quick triage / full static / ctf reverse.
- **Acceptance**:
  - Generates `.hexcore_job.json` template from preset.
  - User can save as profile per workspace.
- **Target**: v3.3.0

---

## P1 — High Value

### 6. PRNG Analysis Helper
- **Status**: `PENDING`
- **Feature**: Detect common libc PRNG patterns (`srand`, `rand()%N`) and annotate flow.
- **Acceptance**:
  - Notes candidate seed sources (`time`, `localtime` fields).
  - Links callsites in disassembly tree.
- **Target**: v3.4.0+ (benefits from Remill/Rellic decompilation)

### 7a. XOR Deobfuscation & Stack String Detection (Strings)
- **Status**: `DONE`
- **Feature**: Advanced string extraction with XOR brute-force scanning and stack-string reconstruction.
- **Acceptance**:
  - `hexcore.strings.extractAdvanced` command with XOR + stack string modes.
  - XOR scanner tries single-byte keys (0x01–0xFF) and reports decoded strings.
  - Stack string detector identifies `mov byte [rbp-N]` patterns and reconstructs strings.
- **Target**: v3.3.0

### 7b. API/Lib Call Trace Snippets in Debugger
- **Status**: `DONE` (v3.5.2)
- **Feature**: Optional trace for libc calls (`time`, `localtime`, `srand`, `rand`).
- **Acceptance**:
  - Trace panel with args + return values.
  - Export trace JSON.
- **Target**: v3.4.0+

### 8. Constant Sanity Checker
- **Status**: `DONE`
- **Feature**: Warn when a decoded immediate mismatch appears in comments/docs.
- **Acceptance**:
  - `hexcore.disasm.checkConstants` validates inline comments and optional notes file against instruction immediates.
  - Single decimal literal annotations are normalized and checked against immediate literal value.
  - Export report as JSON/Markdown for pipeline usage.
- **Target**: v3.3.0

### 9. Report Composer
- **Status**: `DONE` (v3.5.2)
- **Feature**: Merge pipeline outputs + analyst notes into one final report.
- **Acceptance**:
  - Single MD export with evidence links.
- **Target**: v3.4.0+

---

## P2 — Nice to Have

### 10. Guided Reverse Mode (Teaching)
- **Status**: `PENDING`
- **Feature**: Step-by-step checklist UI with checkpoints.
- **Acceptance**:
  - Checkpoints: identify entry, find seed logic, validate key path, decrypt output.
- **Target**: v4.0.0

### 11. Formula-to-Script Export
- **Status**: `PENDING`
- **Feature**: Generate Python/C snippet from extracted expression.
- **Acceptance**:
  - One-click export with placeholders + test harness.
- **Target**: v3.4.0+ (near-automatic with Rellic decompilation)

---

## Infrastructure — Native Engines & Tooling

### 12. Capstone N-API Bindings (hexcore-capstone)
- **Status**: `DONE`
- **Feature**: Modern N-API wrapper for Capstone disassembler engine.
- **Acceptance**:
  - Multi-arch support: x86, x64, ARM, ARM64, MIPS, PPC, SPARC, M68K, RISC-V.
  - Async disassembly API.
  - Prebuild pipeline with `prebuildify` (win32-x64).
  - Fallback loading chain: prebuilds → Release → Debug.
- **Target**: v3.0.0

### 13. Unicorn N-API Bindings (hexcore-unicorn)
- **Status**: `DONE`
- **Feature**: Modern N-API wrapper for Unicorn CPU emulator engine.
- **Acceptance**:
  - Multi-arch emulation: x86, x64, ARM, ARM64, MIPS, SPARC, PPC, RISC-V.
  - Breakpoints, shared memory, snapshot/restore APIs.
  - Prebuild pipeline (win32-x64).
- **Version**: 1.2.1
- **Target**: v3.3.0

### 14. LLVM MC N-API Bindings (hexcore-llvm-mc)
- **Status**: `DONE`
- **Feature**: LLVM MC-based assembler bindings for Node.js.
- **Acceptance**:
  - Multi-arch assembly: x86, x64, ARM, ARM64, MIPS, RISC-V, PPC, SPARC.
  - Used by disassembler for patch/assemble workflow.
  - Prebuild pipeline (win32-x64).
- **Target**: v3.2.0

### 15. better-sqlite3 N-API Rewrite (hexcore-better-sqlite3)
- **Status**: `DONE`
- **Feature**: Complete rewrite of better-sqlite3 as pure N-API wrapper (zero runtime deps).
- **Acceptance**:
  - Full API: `exec()`, `prepare()`, `run()`, `get()`, `all()`, `pragma()`, `close()`.
  - Safe integers (BigInt), raw mode, expand mode, named/positional binding.
  - Zero runtime dependencies (no `bindings`, no `node-gyp-build`).
  - Backward compatible with `hexcore-ioc`.
  - Prebuild pipeline (win32-x64).
- **Version**: 2.0.0
- **Target**: v3.3.0

### 16. IOC Extractor (hexcore-ioc)
- **Status**: `DONE`
- **Feature**: Automatic extraction of Indicators of Compromise from binary files.
- **Acceptance**:
  - Extracts IPs, URLs, hashes, emails, domains from binaries.
  - Persists matches using `hexcore-better-sqlite3`.
  - Generates Markdown reports.
  - Context menu integration.
- **Target**: v3.3.0

### 17. Minidump Parser (hexcore-minidump)
- **Status**: `DONE`
- **Feature**: Windows Minidump (.dmp) analysis with stream parsing.
- **Acceptance**:
  - Streams: ThreadList, ThreadInfoList, ModuleList, MemoryInfoList, Memory64List, SystemInfo.
  - Thread context parsing with correct offsets.
  - Module list with version info.
  - Memory region enumeration.
- **Target**: v3.3.0

### 18. Native Prebuilds CI/CD Pipeline
- **Status**: `DONE`
- **Feature**: Automated prebuild generation for all native engines.
- **Acceptance**:
  - GitHub Actions workflow (`hexcore-native-prebuilds.yml`).
  - Builds 5 engines: Capstone, Unicorn, LLVM MC, better-sqlite3, Remill.
  - Creates releases on standalone repos with prebuild tarballs.
  - Preflight validation (`verify-hexcore-preflight.cjs`).
  - `HEXCORE_RELEASE_TOKEN` for cross-repo releases.
- **Target**: v3.3.0

### 19. Pipeline Doctor & Validation
- **Status**: `DONE`
- **Feature**: Diagnostic and validation tooling for automation pipeline.
- **Acceptance**:
  - `hexcore.pipeline.doctor` — checks workspace health, engine status, job validity.
  - `hexcore.pipeline.validateJob` — validates `.hexcore_job.json` against schema.
  - `hexcore.pipeline.validateWorkspace` — validates all jobs in workspace.
  - JSON schema for `.hexcore_job.json` with IntelliSense.
- **Target**: v3.3.0

---

### 20. Remill N-API Bindings (hexcore-remill)
- **Status**: `DONE`
- **Feature**: Lifts machine code to LLVM IR bitcode via Remill (lifting-bits/remill).
- **Acceptance**:
  - Multi-arch lifting: x86, x64, ARM64.
  - Sync and async lifting APIs (64KB threshold).
  - 168 static libs (/MT) — zero runtime DLL dependencies.
  - `liftToIR` command integrated in disassembler.
  - Prebuild pipeline with semantics tarball (win32-x64).
  - Loaded dynamically via `candidatePaths` — disassembler degrades gracefully.
- **Version**: 0.1.2
- **Standalone repo**: [hexcore-remill](https://github.com/LXrdKnowkill/hexcore-remill)
- **Target**: v3.4.0 ✅

---

## Future Engines (Research)

### hexcore-rellic
- LLVM bitcode → goto-free C output (lifting-bits/rellic)
- Depends on Remill (LLVM IR pipeline)
- N-API bindings, Windows build
- **Status**: `NEXT`
- **Target**: v3.6.0

### hexcore-sleigh (Optional / Parked)
- Unofficial CMake build of Ghidra's SLEIGH (lifting-bits/sleigh)
- Machine code → P-Code (semantic IR)
- N-API bindings, Windows build
- **Status**: `PARKED`
- **Note**: not required for the first Remill/Rellic rollout.

### Full Decompilation Pipeline (Planned)
```
Binary → Remill lift stage → LLVM IR → Rellic (C code)
```

## Delivery Gate Before Remill/Rellic Integration
- `DONE`: P0 `#2` (Expression Evaluator)
- `DONE`: P0 `#5` (Run Profile Presets)
- `DONE`: Infra `#12`–`#15` (All 4 native engines with prebuilds)
- `DONE`: Infra `#18` (CI/CD pipeline for prebuilds)
- `DONE`: hexcore-remill v0.1.0 (N-API wrapper + disassembler integration)
- Keep Windows installer/build green for 3 consecutive runs
- Keep pipeline contract stable (`file`, `quiet`, `output`) during native-engine integration

---

## v3.5.0 Audit — New Backlog Items

Items discovered during the comprehensive stress test and audit against an HTB Insane-level ARM64 challenge (2026-02-15).

### 21. Debugger Headless Commands
- **Status**: `DONE` (v3.5.2)
- **Feature**: Expose DebugEngine's programmatic API as headless VS Code commands for pipeline use.
- **Commands needed**: `emulateHeadless`, `stepHeadless`, `continueHeadless`, `readMemoryHeadless`, `setBreakpointHeadless`, `snapshotHeadless`, `restoreSnapshotHeadless`
- **Why**: The engine (`debugEngine.ts`, `unicornWrapper.ts`) is 100% programmatic. All 10 current commands wrap with UI dialogs (`showOpenDialog`, `showInputBox`). AI agents and the pipeline cannot use emulation at all.
- **Priority**: P0 — blocks any pipeline workflow that needs dynamic analysis
- **Target**: v3.6.0

### 22. ARM64 DebugEngine Completion
- **Status**: `DONE` (v3.5.1)
- **Feature**: Complete ARM64 codepaths in DebugEngine for full ELF emulation.
- **Methods needed**:
  - `setupStack()` — configure LR (Link Register) for ARM64
  - `initializeElfProcessStack()` — mount argc/argv/envp in ARM64 layout
  - `installSyscallHandler()` — intercept SVC #0 (ARM64 syscall instruction)
  - `updateEmulationRegisters()` — map ARM64 registers (x0-x30, sp, lr, pc)
  - `popReturnAddress()` — read LR instead of popping from stack
- **Why**: Unicorn wrapper already supports ARM64 fully (init, registers, memory). DebugEngine is the bottleneck.
- **Priority**: P1
- **Target**: v3.6.0

### 23. ELF Analyzer Extension
- **Status**: `DONE` (v3.5.2)
- **Feature**: Create `hexcore-elfanalyzer` with headless commands equivalent to `hexcore-peanalyzer`.
- **Commands**: `elfanalyzer.analyze`, `elfanalyzer.analyzeActive`
- **Output**: sections, segments, symbols, dynamic linking info, RELRO, stack canary, NX, PIE status
- **Why**: PE has full structural analysis via `hexcore-peanalyzer`. ELF has nothing equivalent — the disassembler's internal parser is not exposed as structured analysis.
- **Priority**: P1
- **Target**: v3.6.0+

### 24. Base64 Headless Mode
- **Status**: `DONE` (v3.5.2)
- **Feature**: Add `hexcore.base64.decodeHeadless` that writes decoded output to file instead of opening editor.
- **Why**: Current command always opens a markdown report in the editor, blocking pipeline use.
- **Priority**: P2
- **Target**: v3.6.0

### 25. Multi-byte XOR Deobfuscation
- **Status**: `DONE` (v3.5.2)
- **Feature**: Extend `hexcore.strings.extractAdvanced` to detect multi-byte XOR keys.
- **Key sizes**: 2, 4, 8, 16 bytes + rolling XOR + XOR with increment
- **Why**: Current implementation only brute-forces single-byte keys (0x01-0xFF). Modern malware uses multi-byte XOR extensively.
- **Priority**: P1
- **Target**: v3.6.0

### 26. buildFormula ARM64 Register Support
- **Status**: `DONE` (v3.5.1)
- **Feature**: Expand `hexcore.disasm.buildFormula` register regex to recognize ARM64 registers.
- **Registers to add**: x0-x30, w0-w30, sp, lr, xzr, wzr
- **Why**: Currently only recognizes x86/x64 registers (eax, ebx, rax, rbx, etc.). ARM64 formulas produce empty/incorrect results.
- **Priority**: P2
- **Target**: v3.6.0

### 27. Hex Viewer Headless Commands
- **Status**: `DONE` (v3.5.2)
- **Feature**: Add `hexcore.hexview.dumpHeadless` and `hexcore.hexview.searchHeadless` for pipeline use.
- **Why**: All hex viewer commands require the webview open. No programmatic hex data extraction possible.
- **Priority**: P2
- **Target**: v3.6.0+

---

## v3.5.4 VVM Intelligence Audit — New Backlog Items

Items discovered during the comprehensive stress test and audit against a complex custom VM CTF challenge (2026-02-19). These features were evaluated against the impending v3.6.0 Rellic Integration roadmap.

### 28. Robust Runtime Memory Disassembly (mmap regions)
- **Status**: `PENDING`
- **Feature**: Provide a mechanism in the headless/pipeline debugger to dump an arbitrary region of dynamically allocated (mmap'd) memory and immediately pass it to the Disassembler engine to extract runtime-decrypted opcodes or handlers.
- **Why**: The HexCore emulator executed the handlers flawlessly, but standard static analysis couldn't disassemble them because they only exist in memory after XOR decryption.
- **Priority**: P1 (High Value)
- **Target**: v3.6.1 (Post-Rellic Integration)

### 29. Headless Breakpoint Snapshots & Dumps
- **Status**: `PENDING`
- **Feature**: Expand the `"breakpoints": []` capability in `emulateFullHeadless` so that hitting a breakpoint doesn't just halt, but can automatically trigger a mini-snapshot or a structured dump of registers and stack before continuing.
- **Why**: Currently "roda tudo e vê o resultado" (run and collect at the end). Analysts need to inspect packed values or shift results *during* the execution flow at specific checkpoints.
- **Priority**: P1
- **Target**: v3.6.1 (Post-Rellic Integration)

### 30. Automated VM Pattern Heuristics (Dispatcher/Handler detection)
- **Status**: `PENDING`
- **Feature**: Run basic Graph Theory algorithms on basic blocks to automatically flag large Dispatch Loops, Handler Tables, and Bytecode Arrays.
- **Why**: Reduces human cognitive load when first opening a virtualized binary.
- **Priority**: P2 / P3 (Predictive Analysis)
- **Target**: v3.7.0+

### 31. Zero-Copy IPC Shared Memory (SharedArrayBuffer)
- **Status**: `PENDING`
- **Feature**: Erradicate the N-API context switch overhead during Unicorn Hook callbacks by exposing the C++ CPU state block directly to the Node.js V8 engine via a `BigUint64Array` typed view of an external ArrayBuffer.
- **Why**: To push emulation speeds from 50k inst/sec to 10M+ inst/sec by eliminating JSON-RPC marshalling and N-API transition latencies during heavy API hooking. Also includes Native Hook Filters in C++.
- **Priority**: P3 (Architectural Refactor / Advanced Niche)
- **Target**: v4.0.0

### 32. Basic Symbolic Execution (Constraint Solving)
- **Status**: `PENDING`
- **Feature**: Integrate a lightweight symbolic execution engine (via an SMT solver like Z3) to mark specific inputs as symbolic and track constraints to auto-solve VM bytecode challenges.
- **Why**: Simplifies constraint extraction from complex VM algorithms.
- **Priority**: P4 (Titantic Project)
- **Target**: v4.0.0+

---

## Engineering Notes
- Keep headless contract stable: `file`, `quiet`, `output`.
- Keep pipeline strict on output existence and step timeout.
- Add regression fixtures from real challenges (Wayback, virtually.mad).
- All new features must support headless mode for AI orchestration.
- Native engines follow N-API pattern: prebuildify → fallback chain → zero runtime deps.
- All native wrappers documented via `hexcore-native-engines` power (`.kiro/powers/`).
- Prebuilds currently win32-x64 only — Linux/macOS runners pending.
- `hexcore-ioc` depends on `hexcore-better-sqlite3` — keep API stable.
