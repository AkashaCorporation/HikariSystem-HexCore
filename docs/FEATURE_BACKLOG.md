# HexCore Feature Backlog

> **Date**: 2026-02-08
> **Scope**: Improve reverse workflow quality, reproducibility and teaching value.
> **Source**: Analysis of real CTF usage (Wayback, virtually.mad challenges).

## Status Legend
- `DONE`: implemented and merged
- `IN_PROGRESS`: partially implemented
- `PENDING`: not implemented yet

## Current Snapshot (2026-02-14)
- P0 delivered: **5/5** (`#1`, `#2`, `#3`, `#4`, `#5`)
- P1 delivered: **2/4** (`#7b`, `#8`)
- P2 delivered: **0/2**
- Infrastructure delivered: **7/7** (`#12`, `#13`, `#14`, `#15`, `#16`, `#17`, `#20`)
- Future Engines delivered: **0/2** (hexcore-rellic `NEXT`)
- Pipeline hardening added beyond original backlog:
  - `.hexcore_job.json` schema validation
  - `hexcore.pipeline.validateJob`
  - `hexcore.pipeline.validateWorkspace`
  - `hexcore.pipeline.doctor`
  - step retries (`retryCount`, `retryDelayMs`)

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
- **Status**: `PENDING`
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
- **Status**: `PENDING`
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
- **Version**: 1.2.0
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
  - Builds 4 engines: Capstone, Unicorn, LLVM MC, better-sqlite3.
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
- **Version**: 0.1.1
- **Standalone repo**: [hexcore-remill](https://github.com/LXrdKnowkill/hexcore-remill)
- **Target**: v3.4.0 ✅

---

## Future Engines (Research)

### hexcore-rellic
- LLVM bitcode → goto-free C output (lifting-bits/rellic)
- Depends on Remill (LLVM IR pipeline)
- N-API bindings, Windows build
- **Status**: `NEXT`
- **Target**: v4.0.0

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

## Engineering Notes
- Keep headless contract stable: `file`, `quiet`, `output`.
- Keep pipeline strict on output existence and step timeout.
- Add regression fixtures from real challenges (Wayback, virtually.mad).
- All new features must support headless mode for AI orchestration.
- Native engines follow N-API pattern: prebuildify → fallback chain → zero runtime deps.
- All native wrappers documented via `hexcore-native-engines` power (`.kiro/powers/`).
- Prebuilds currently win32-x64 only — Linux/macOS runners pending.
- `hexcore-ioc` depends on `hexcore-better-sqlite3` — keep API stable.
