# HexCore Feature Backlog

> **Date**: 2026-02-08
> **Scope**: Improve reverse workflow quality, reproducibility and teaching value.
> **Source**: Analysis of real CTF usage (Wayback, virtually.mad challenges).

## Status Legend
- `DONE`: implemented and merged
- `IN_PROGRESS`: partially implemented
- `PENDING`: not implemented yet

## Current Snapshot (2026-02-11)
- P0 delivered: **5/5** (`#1`, `#2`, `#3`, `#4`, `#5`)
- P1 delivered: **1/4** (`#8`)
- P2 delivered: **0/2**
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

### 7. API/Lib Call Trace Snippets in Debugger
- **Status**: `PENDING`
- **Feature**: Optional trace for libc calls (`time`, `localtime`, `srand`, `rand`).
- **Acceptance**:
  - Trace panel with args + return values.
  - Export trace JSON.
- **Target**: v3.3.0

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

## Future Engines (Research)

### hexcore-remill
- Lift semantics into LLVM IR (foundation stage for decompilation)
- N-API bindings, Windows build
- **Status**: `NEXT`
- **Target**: v4.0.0

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
- Keep Windows installer/build green for 3 consecutive runs
- Keep pipeline contract stable (`file`, `quiet`, `output`) during native-engine integration

---

## Engineering Notes
- Keep headless contract stable: `file`, `quiet`, `output`.
- Keep pipeline strict on output existence and step timeout.
- Add regression fixtures from real challenges (Wayback, virtually.mad).
- All new features must support headless mode for AI orchestration.
