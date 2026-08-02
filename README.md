# HikariSystem HexCore

<p align="center">
  <img alt="HikariSystem HexCore" src="BatHexCoreTransparente.png" width="240">
</p>

<p align="center">
  <strong>An open-source workbench for reverse engineering, binary analysis, and controlled emulation</strong>
</p>

<p align="center">
  <a href="#features">Features</a> |
  <a href="#extensions">Extensions</a> |
  <a href="#debugger--emulator">Debugger</a> |
  <a href="#automation-pipeline">Automation</a> |
  <a href="#installation">Installation</a> |
  <a href="#usage">Usage</a> |
  <a href="#license">License</a>
</p>

<p align="center">
  <code>PE/ELF</code> &middot; <code>disassembly</code> &middot; <code>LLVM IR</code> &middot; <code>MLIR decompilation</code> &middot; <code>controlled emulation</code> &middot; <code>automation</code>
</p>

---

## Overview

HikariSystem HexCore is a binary-analysis IDE built on the VS Code workbench. It brings static analysis, IR lifting, MLIR-based decompilation, controlled CPU emulation, semantic queries, and reproducible automation into one workspace.

**Stable release:** `v3.8.2.2`. **Current release candidate:** `v3.8.3` (not yet published). The 3.8.3 work focuses on truthful pipeline outcomes, whole-job engine isolation, artifact provenance, parser format gates, YARA evidence qualification, native-engine refreshes, and the canonical Helix `0.9.3` migration. See the [changelog](CHANGELOG.md) for the release record.

> **Platform status:** the supported packaged application is currently **Windows 10/11 x64**. HexCore analyzes both PE and ELF targets, but that does not imply a supported Linux-host distribution. Linux packaging remains a separate Docker/CI effort and is not part of the 3.8.3 release claim.

**What makes HexCore different:**
- **Agentic-first decompilation** — output designed for both human and LLM consumption; paired with HQL (HikariSystem Query Language) semantic query layer over Helix IR
- **Full PE and ELF emulation** with 70+ API hooks, plus clean-room Project Azoth engine (replaces Qiling)
- **Native Capstone / Unicorn / LLVM MC / Remill / Helix / Souper / Azoth** engines via N-API (no external installs)
- **Decompilation pipeline:** machine code → Pathfinder CFG hints → Remill lift → LLVM IR → Helix MLIR engine (Low/Mid/High lowering) → pseudo-C with debug-info-guided type recovery
- **DWARF + PDB + ET_REL debug-info ingestion** — recovers real parameter names, struct field names, and function signatures on kernel modules and debug-built PE
- **Headless automation pipeline** for batch analysis with `.hexcore_job.json`
- **Vulnerability audit engine** — refcount pattern scanner matched to 4 bounty-confirmed bug shapes
- **Evidence-driven validation** against owned or authorized kernel modules, large PE64 game binaries, CTF challenges, and controlled obfuscated samples

---

## Features

- **Disassembly** — Native multi-architecture disassembler (x86, x64, ARM, ARM64, MIPS, RISC-V)
- **Pathfinder CFG Engine** (v3.8.0) — Pre-lift CFG analysis using `.pdata`/`.symtab` boundaries, recursive descent, jump table resolution, NOP range detection, and gap scanning with prologue heuristics. Feeds Remill via `additionalLeaders` for 2-3× more basic blocks than stock linear sweep
- **IR Lifting** — Machine code → LLVM IR translation via patched Remill fork (FIX-023/024/025: CET preamble handling, XED-ILD exotic-ISA recovery, CALL fall-through wiring)
- **Decompilation** — LLVM IR → pseudo-C via the Helix MLIR engine, with Low/Mid/High dialect lowering, a documented 19-pass pipeline, structured control flow, type recovery, and evidence-gated confidence
- **Helix MLIR Decompiler** — C++23/MLIR pipeline, C AST layer with 16+ optimizer passes, SysV/Win64/Cdecl32 ABI auto-detection, SSA variable splitting via reverse post-order traversal, Ghidra-inspired type recovery with pointer propagation
- **DWARF + BTF + PDB Debug Info Ingestion** (v3.8.0) — Pure-TypeScript DWARF 5 parser with split-form resolution (`DW_FORM_strx*`/`DW_FORM_addrx*`) and in-process ET_REL relocation application for kernel modules. PDB function boundary feeder via `llvm-pdbutil`. End-to-end: `mali_kbase.ko` recovers 792 structs + 3,864 function signatures with real parameter names and types
- **Emulation** — CPU emulation via Unicorn Engine with PE and ELF loading, API hooking, stdin emulation, faithful PRNG (glibc/MSVCRT), side-channel analysis, KUSER_SHARED_DATA + synthetic DLL PE images for hash-resolved imports
- **Project Azoth** — Clean-room Apache-2.0 Rust+C++23 dynamic analysis framework replacing Qiling. Frida-style Interceptor/Stalker. 5/5 parity gates passed on the reference controlled corpus. Standalone repo at `AkashaCorporation/HexCore-Elixir`
- **Perseus Zero-Copy IPC** (v3.8.0) — SPSC `SharedArrayBuffer` ring for Unicorn hook delivery. 1.34× throughput, 100% delivery vs ~35% legacy on heavy hooking workloads
- **Souper Superoptimizer** — Windows N-API integration of Google Souper with Z3 SMT solving for selected LLVM IR
- **Souper Surgical Auto-Activation** — absent/`"auto"` runs Souper only on crypto/MBA-dense IR; `true` forces it on and `false` disables it
- **Vulnerability Audit Engine** — Refcount pattern scanner with four bounty-bug-matching patterns (A: increment-before-error, B: `_force` variant ignoring refcount, C: unconditional operation after failed ref-get, E: reachable `BUG_ON` on allocation failure)
- **Assembly Patching** — Inline patching with LLVM MC backend, NOP sleds, multi-arch support
- **PE/ELF Analysis** — Import/export parsing, section analysis, packer detection, PIE support, CodeView PDB path extraction
- **Anti-Analysis Detection** (v3.8.0) — 8 opcode patterns scanned across executable sections: RDTSC/RDTSCP (timing), CPUID (VM detect), INT 2D (legacy anti-debug), VMCALL, direct PEB access (gs:[0x60] x64, fs:[0x30] x86), LOCK CMPXCHG8B. Density-based suspicious-binary classification separates CRT noise from real anti-analysis
- **API Hash Resolver** (v3.8.0) — 260-entry WinAPI + 32-entry DLL wordlist × 8 hash algorithms (djb2, sdbm, fnv1, fnv1a, ror13, crc32, fnv1_64, fnv1a_64). Resolves hashed imports in shellcode / Cobalt-Strike / Ashaka-class malware
- **Hex Viewer** — Virtual scrolling, data inspector, bookmarks, structure templates
- **Hash Calculator** — MD5, SHA-1, SHA-256, SHA-512 with VirusTotal integration
- **String Extraction** — ASCII/UTF-16, auto-categorization, multi-byte XOR deobfuscation (keys 2/3/4/5/6/7/8/12/16 bytes), stack strings (including disp32 addressing), PE section-aware extraction (`.rdata` prioritized), batch queries
- **Entropy Analysis** — Block-by-block entropy with packer/encryption detection
- **ChaCha20 / Salsa20 Detection** — the entropy analyzer flags the ChaCha20/Salsa20 sigma/tau constants (`expand 32-byte k` / `expand 16-byte k`) via a streaming, boundary-safe byte scan
- **YARA Scanning** — Rule loading, match highlighting, custom rules, **built-in anti-analysis pack** (55 rules: anti-debug, anti-VM, obfuscation, API hashing, Ashaka v3–v5 family, dynamic imports)
- **IOC Extraction** — Binary-aware IOC detection (IPs, URLs, domains, pipes, wallets, registry paths with anti-VM/persistence sub-classification)
- **Minidump Analysis** — Windows crash dump forensics with thread/module/memory parsing
- **Automation** — Headless pipeline system with conditional branching (`onResult`), step output referencing (`$step[N].output`), priority job queue manager (concurrent execution, cancellation, status API)
- **Junk Filtering** — Detect and remove obfuscation junk (callfuscation, nop sleds, identity ops)
- **VM Detection** — Automatic detection of VM-based obfuscation (dispatchers, handler tables, operand stacks)
- **PRNG Detection** — Static detection of srand/rand patterns with seed extraction
- **Callfuscation Detection** (v3.8.2) — Byte-scan detection of call-as-jmp control-flow obfuscation (`call <next>` where the target begins with a `pop` that discards the pushed return address). Independent of function discovery, so it remains reliable even when prologue-based discovery is defeated. `analyzeAll` emits a `callfuscation` field (`detected`, `gadgetCount`, `callCount`, `ratio`, `discardRegisters`). An experimental, opt-in deflattening transform (call→jmp + NOP pop-discards, `liftOptions.deflattenCallfuscation`, default OFF) exists in the lift path; full Remill chain-following is upcoming (see CHANGELOG)
- **Function Boundary Detection** — Native C++ prologue scanner for accurate function start/end identification with auto-backtrack
- **Memory Pattern Search** — AOB byte pattern scan and RTTI class discovery during live emulation (`searchMemoryHeadless`, `searchBytesHeadless`, `rttiScanHeadless`)
- **Trampoline Following** — Automatic detection and follow-through of unconditional JMP trampolines to real function bodies

---

## Extensions

### Analysis Tools

| Extension | Version | Description |
|-----------|---------|-------------|
| **Debugger** | 2.1.9 | PE/ELF emulation with Unicorn Engine, API hooks, stdin emulation, snapshots, traces, and headless lifecycle commands |
| **Disassembler** | 1.4.27 | Multi-arch disassembly, PE/ELF parsing, function discovery, Pathfinder, Remill lifting, Helix integration, and automation |
| **Hex Viewer** | 1.2.3 | Professional binary file viewer with virtual scrolling |
| **PE Analyzer** | 1.1.1 | Comprehensive PE executable analysis with headless mode |
| **Strings Extractor** | 1.2.0 | Memory-efficient string extraction with XOR deobfuscation and stack string detection |
| **Hash Calculator** | 1.1.2 | Fast file hashing with VirusTotal integration |
| **Entropy Analyzer** | 1.1.1 | Streaming entropy analysis with adaptive block sizing and modular report pipeline |
| **File Type Detector** | 1.0.2 | Magic bytes signature detection |
| **Base64 Decoder** | 2.0.2 | Detect and decode Base64 strings |
| **YARA Scanner** | 2.1.3 | YARA scanning with qualified condition/ISA evidence and headless pipeline support |
| **IOC Extractor** | 1.1.2 | Binary-aware IOC extraction with noise reduction, SQLite backend, and threat assessment |
| **Minidump Parser** | 1.0.1 | Windows MDMP forensics with thread injection/RWX detection and threat heuristics |
| **ELF Analyzer** | 1.0.1 | Structural analysis of ELF binaries — sections, segments, symbols, and security mitigations |
| **Report Composer** | 1.0.1 | Aggregates pipeline outputs into unified Markdown reports with TOC and evidence links |

### Native Engines (Standalone N-API Packages)

These engines ship with HexCore and can also be used independently in Node.js projects.

| Package | Version | Description |
|---------|---------|-------------|
| **hexcore-capstone** | 1.3.5 | Capstone v5 N-API binding — async disassembly, detail mode, all architectures |
| **hexcore-unicorn** | 1.3.1 | Unicorn N-API binding — CPU emulation, hooks, breakpoints, snapshots, shared memory, and Perseus SAB delivery |
| **hexcore-llvm-mc** | 1.0.2 | LLVM 18.1.8 MC N-API binding — multi-arch assembly and patching |
| **hexcore-better-sqlite3** | 2.0.3 | SQLite N-API wrapper with safe prepared-statement lifecycle for persistent sessions |
| **hexcore-remill** | 0.5.1 | Patched Remill N-API lifter — machine code to LLVM IR with current call, relocation, preamble, and fallback hardening |
| **hexcore-helix** | 0.9.3 | Canonical Helix MLIR decompiler with structured control flow and debug-info-guided type recovery |
| **hexcore-souper** | 0.2.0 | Google Souper superoptimizer N-API binding with Z3 SMT and density-gated automatic execution |
| **hexcore-elixir** *(Azoth)* | 1.0.0 | Project Azoth clean-room dynamic analysis framework — Apache-2.0 Rust+C++23 replacement for Qiling. Frida-style Interceptor/Stalker, 5/5 Parity Gates passed. Standalone repo at `AkashaCorporation/HexCore-Elixir` |
| **hexcore-keystone** | 1.0.0 | Legacy assembler binding (superseded by LLVM MC) |

> **Note on hexcore-helix:** Depends on LLVM 18.1.8 + MLIR. The `.node` binary is pre-built and ships with HexCore — no compilation needed for end users. Building from source requires VS2022, clang-cl, and `LLVM_BUILD_DIR` pointing to an MLIR-enabled LLVM build (~131 MB deps).

> **Note on hexcore-remill:** This engine depends on LLVM 18, XED, glog, gflags, and Remill. End users receive the pre-built `.node` binary via CI; source builds require the documented native toolchain.

> **Note on hexcore-souper:** Depends on the bundled Z3 runtime. Use `souper: true` to force execution, `souper: false` to disable it, or omit/use `"auto"` for the density gate.

> **Note on hexcore-elixir (Project Azoth):** Apache-2.0 clean-room implementation derived from public specifications (PE/COFF, ELF, MSDN, man pages, Unicorn C API). The wrapper downloads its `.node` at `postinstall`, matching the HexCore-Helix delivery pattern.

---

## Debugger & Emulator

The HexCore Debugger provides controlled CPU emulation for PE and ELF binaries via **Unicorn Engine**. It models selected user-mode APIs and syscalls; it is not a full operating system or a substitute for hardware-backed dynamic analysis.

### Supported Formats
- **PE (x86/x64)** — Automatic section loading, import resolution via IAT, 25+ Windows API hooks
- **ELF (x86_64)** — PIE support, PLT/GOT resolution (`.rela.plt` + `.rela.dyn`), 40+ Linux API hooks
- **Raw binaries** — Direct memory mapping for shellcode and firmware

### Emulation Capabilities
- **Step / Continue / Breakpoints** — Standard debugger controls with register and memory inspection
- **API Hooking** — Transparent interception of library calls (no real DLLs/SOs needed)
- **stdin Emulation** — Configurable input buffer for `scanf`, `read(0)`, `getchar`, `fgets`
- **TLS/FS_BASE** — Automatic Thread Local Storage with stack canary for `-fstack-protector` binaries
- **Syscall Handler** — Linux syscall interception (read, write, mmap, brk, arch_prctl, exit)
- **`__libc_start_main` redirect** — Skip CRT init, jump directly to `main()` with argc/argv/envp
- **Snapshot save/restore** — Save and restore full emulation state

### Linux API Hooks (40+)
I/O, string, memory, heap, conversion, process, time, file stubs, and security functions — all using System V AMD64 ABI argument passing.

### Windows API Hooks (25+)
Kernel32, user32, msvcrt emulation for common PE analysis scenarios.

> Powered by [hexcore-unicorn](extensions/hexcore-unicorn) and [hexcore-capstone](extensions/hexcore-capstone).

### Known Limitations

The HexCore emulator uses **Unicorn Engine** (based on QEMU's TCG backend) for CPU translation. While this covers the vast majority of real-world binaries, there are edge cases where Unicorn's behavior diverges from full QEMU user-mode or real hardware:

- **Instruction fidelity** — Some undocumented or edge-case instructions may behave differently than on real CPUs or full QEMU. Binaries that rely on CPU-specific quirks (e.g., certain CTF challenges) may crash or produce incorrect results.
- **ARM64 specifics** — ARM64 emulation runs in an isolated worker process to bypass Chromium security restrictions (ACG/CFG). This adds IPC overhead but is functionally equivalent.
- **No full system emulation** — Unicorn provides user-mode emulation only. Kernel-level operations, hardware interrupts, and privileged instructions are not supported.

For binaries that require higher fidelity emulation, consider using **QEMU user-mode** (`qemu-aarch64`, `qemu-x86_64`) alongside HexCore's static analysis tools.

---

## Disassembler

Native multi-architecture disassembler powered by **Capstone Engine v5.0** with assembly patching via **LLVM MC** and IR lifting via **Remill**.

- **Architectures**: x86, x64, ARM, ARM64, MIPS, RISC-V
- **IR Lifting** — Lift machine code to LLVM IR via Remill engine (experimental)
- **Inline PE/ELF parsing** — Imports, exports, sections without external dependencies
- **Function detection** — Native C++ prologue scanner with auto-backtrack, call target analysis, up to 1000 functions
- **String cross-references** — Track which instructions reference which strings
- **Graph View** — IDA-style control flow graph visualization
- **Patching** — Assemble, patch instructions, NOP sleds (LLVM MC)
- **Headless mode** — `hexcore.disasm.analyzeAll` for automation with JSON/MD output

> Powered by [hexcore-capstone](extensions/hexcore-capstone), [hexcore-llvm-mc](extensions/hexcore-llvm-mc), and [hexcore-remill](extensions/hexcore-remill).

---

## Helix Decompiler & Pathfinder (v3.8.0)

Full decompilation pipeline from machine code to pseudo-C, with DWARF/PDB-aware type recovery.

### Pipeline stages

```
Binary
  → Pathfinder      (CFG pre-analysis: .pdata/.symtab boundaries, recursive descent,
                     jump table resolution, gap scanning with prologue heuristics)
  → Remill fork     (lift to LLVM IR, patched with FIX-023/024/025 for CET/exotic-ISA/CALL)
  → Helix engine    (MLIR 3-dialect lowering: HelixLow → HelixMid → HelixHigh)
  → C AST layer     (16+ optimizer passes: dead-store elim, copy prop, compound assign,
                     struct field recovery, semantic naming, confidence scoring)
  → pseudo-C output with DWARF/PDB-driven parameter names and struct field names
```

### Pathfinder CFG Engine

- **Binary Context Provider** — Parses PE `.pdata` (RUNTIME_FUNCTION entries) and ELF `.symtab` (STT_FUNC) for exact function boundaries
- **Recursive Descent Scanner** — Worklist-based discovery (x86 via Capstone batch decode, ARM64 linear fixed-width 4-byte). Found 479 insns / 142 leaders on `kbase_jit_allocate` benchmark
- **Jump Table Resolver** — Backward-slice (15 insns) + pattern match for MSVC x64 and GCC/SysV jump table patterns
- **Gap Scanning** — Prologue heuristics (`push rbp; mov rbp, rsp`, `sub rsp, N`, `endbr64 + push`, MSVC fastcall) catch functions only reachable via vtable or indirect call
- **NOP Range Detection** — `endbr64`, `call __fentry__` (ftrace), INT3 padding; ARM64 NOP/BRK/UDF padding
- **Remill Integration** — `additionalLeaders` + `knownFunctionEnds` hints fed to Remill Phase 1

### Helix MLIR Decompiler

- **HelixLow dialect** — machine-level semantics (`reg.read`/`reg.write`, `mem.read`/`mem.write`, flags, control flow)
- **HelixMid dialect** — ISA-agnostic typed SSA (registers → typed variable slots, flags → comparisons, REP MOVS/STOS → memcpy/memset)
- **HelixHigh dialect** — C-level (`var.decl` with storage class, structured control flow, typed expressions)
- **C AST Layer** (default since v0.8.0) — MLIR → C AST → printed C
- **19 ordered pipeline passes** covering normalization, variable recovery, dialect lowering, calling conventions, control-flow structuring, type/struct propagation, cleanup, and confidence scoring

### DWARF + PDB Debug-Info Ingestion

- **DWARF 5 parser** in pure TypeScript — handles split forms (`DW_FORM_strx*`/`DW_FORM_addrx*` via `.debug_str_offsets`/`.debug_addr`)
- **ET_REL relocation application** — applies `.rela.debug_*` entries in-place on debug section buffers before parsing, unlocking DWARF in Linux kernel modules (`.ko`)
- **PDB function boundary feeder** via `llvm-pdbutil` — covers leaf functions `.pdata` misses on PE binaries
- **Results on `mali_kbase.ko`** — 792 structs, 3,864 function signatures with real parameter names/types, 1,633 DWARF boundaries. `kbase_jit_allocate` recovers IDA-exact signature

### Usage

```json
{
  "cmd": "hexcore.helix.decompileIR",
  "args": { "inputFile": "target.ll", "outputFile": "target.c" }
}
```

> Powered by [hexcore-remill](extensions/hexcore-remill), [hexcore-helix](extensions/hexcore-helix), and Pathfinder (embedded in hexcore-disassembler).

---

## Project Azoth — Dynamic Analysis

Clean-room Apache-2.0 Rust+C++23 dynamic analysis framework that replaces Qiling as HexCore's default emulation path. Frida-style Interceptor (API hooking) and Stalker (basic-block tracing) built on HexCore-Unicorn.

### Highlights

- **Clean-room derivation** from public specs (PE/COFF, ELF, MSDN, Unicorn C API) — no GPL contamination
- **5/5 Parity Gates passed** on the reference malware corpus
- **22,921 API calls** captured end-to-end on v3 "Ashaka Shadow" with djb2 hash resolution
- **KUSER_SHARED_DATA page** populated at `0x7FFE0000` for timing-check bypass
- **8 synthetic DLL PE images** at `0x72000000..0x72040000` (ntdll, kernel32, KERNELBASE, ucrtbase, msvcp140, shell32, advapi32, user32) with real export tables for hash-resolved imports
- **PEB_LDR_DATA** populated with circular lists (`InLoadOrder`/`InMemoryOrder`/`InInitializationOrder`)
- **Standalone repo**: [`AkashaCorporation/HexCore-Elixir`](https://github.com/AkashaCorporation/HexCore-Elixir)

### Usage

HexCore currently exposes `azoth`, `debugger`, and `both` modes through `hexcore.emulator`; the default is `both` so the engines remain available side by side during the 3.8.3 validation cycle.

---

## Automation Pipeline

HexCore supports headless batch analysis via `.hexcore_job.json` job files.

```json
{
  "file": "C:\\bin\\sample.exe",
  "outDir": "C:\\reports\\sample",
  "steps": [
    { "cmd": "hexcore.filetype.detect" },
    { "cmd": "hexcore.peanalyzer.analyze" },
    { "cmd": "hexcore.hashcalc.calculate" },
    { "cmd": "hexcore.entropy.analyze" },
    { "cmd": "hexcore.strings.extract", "args": { "minLength": 5 } },
    { "cmd": "hexcore.disasm.analyzeAll" },
    { "cmd": "hexcore.yara.scan" },
    { "cmd": "hexcore.ioc.extract" }
  ]
}
```

- **Auto-trigger** — Workspace watcher detects `.hexcore_job.json` on creation
- **Step controls** — Per-step timeout, error handling, output validation
- **Extension preflight** — Auto-activates required extensions before each step
- **Capability audit** — `hexcore.pipeline.listCapabilities` exports headless/interactive capability map
- **Safety model** — Interactive commands are explicitly blocked in pipeline mode with clear errors
- **Conditional branching** — `onResult` field enables skip/goto/abort/log based on step output (v3.7.1)
- **Step output referencing** — `$step[N].output` interpolation passes prior step results as arguments to later steps (v3.7.3)
- **Output** — JSON/Markdown reports + `hexcore-pipeline.status.json` + `hexcore-pipeline.log`

All analysis extensions support headless execution with `file`, `output`, and `quiet` parameters.

### Selected Headless Commands

| Command | Extension | Description |
|---------|-----------|-------------|
| `hexcore.debug.snapshotHeadless` | hexcore-debugger | Save emulation snapshot |
| `hexcore.debug.restoreSnapshotHeadless` | hexcore-debugger | Restore emulation snapshot |
| `hexcore.debug.exportTraceHeadless` | hexcore-debugger | Export API/libc call trace |
| `hexcore.elfanalyzer.analyze` | hexcore-elfanalyzer | Structural ELF analysis |
| `hexcore.base64.decodeHeadless` | hexcore-base64 | Extract Base64 strings from binary |
| `hexcore.hexview.dumpHeadless` | hexcore-hexviewer | Programmatic hex dump extraction |
| `hexcore.hexview.searchHeadless` | hexcore-hexviewer | Pattern search with streaming |
| `hexcore.pipeline.composeReport` | hexcore-report-composer | Aggregate reports into unified Markdown |

### Memory and Session Commands

| Command | Extension | Description |
|---------|-----------|-------------|
| `hexcore.debug.searchMemoryHeadless` | hexcore-debugger | Search emulator memory for byte/string patterns during live emulation |
| `hexcore.debug.searchBytesHeadless` | hexcore-debugger | AOB (array of bytes) pattern scan across emulated memory |
| `hexcore.debug.rttiScanHeadless` | hexcore-debugger | RTTI class discovery — extract C++ class names from emulated PE memory |
| `hexcore.strings.batchHeadless` | hexcore-strings | Batch string search with a queries array in a single pass |

### Lifting, Decompilation, and Queue Commands

| Command | Extension | Description |
|---------|-----------|-------------|
| `hexcore.disasm.liftToIR` | hexcore-disassembler | Lift function bytes to LLVM IR via Pathfinder + Remill pipeline, with auto-backtrack and trampoline following |
| `hexcore.helix.decompileIR` | hexcore-disassembler | Decompile LLVM IR to pseudo-C via Helix MLIR engine. Auto-extracts struct info from BTF/DWARF/PDB and applies struct field naming |
| `hexcore.audit.refcountScan` | hexcore-disassembler | Scan decompiled `.c` output for 4 refcount bounty-bug patterns (A/B/C/E). Outputs JSON report with confidence scores and bounty-bug attribution |
| `hexcore.souper.optimize` | hexcore-souper | Run Google Souper + Z3 SMT superoptimization on LLVM IR. Opt-in per job |
| `hexcore.pipeline.queueJob` | hexcore-disassembler | Submit a job to the priority queue manager (priority/status/cancellation APIs) |
| `hexcore.pipeline.cancelJob` | hexcore-disassembler | Cancel a queued or running job via AbortController |
| `hexcore.pipeline.jobStatus` | hexcore-disassembler | Query job queue state (queued/running/done/failed/cancelled) |

See [docs/HEXCORE_AUTOMATION.md](docs/HEXCORE_AUTOMATION.md) for full documentation.

---

## Hex Viewer

Professional binary file viewer with virtual scrolling for large files.

- **Virtual Scrolling** — Handles files of any size efficiently
- **Data Inspector** — View bytes as Int8/16/32/64, Float, Unix timestamp
- **Bookmarks** — Save and navigate to important offsets
- **Structure Templates** — Parse common binary structures
- **Search** — Find hex patterns (e.g., `4D 5A` for PE headers)
- **Go to Offset** — Jump directly to any offset
- **Copy Selection** — Export as Hex, C Array, or Python bytes
- **Little/Big Endian** toggle

---

## Installation

### Packaged Application

The supported release artifact is the Windows x64 ZIP/installer produced by
GitHub Actions. Download it from the
[AkashaCorporation releases page](https://github.com/AkashaCorporation/HikariSystem-HexCore/releases).
Native `.node` engines are bundled; end users do not compile LLVM/MLIR locally.

### Development Mode

```powershell
# Clone the repository
git clone https://github.com/AkashaCorporation/HikariSystem-HexCore.git
cd HikariSystem-HexCore

# Install dependencies
npm install

# Run in development mode
$env:VSCODE_SKIP_NODE_VERSION_CHECK="1"
.\scripts\code.bat
```

### Requirements

- Node.js 22.x for the current development tree
- npm 10.x or higher
- Windows 10/11 x64
- Visual Studio Build Tools 2022 (for native modules)
- Python 3.x (for node-gyp)

---

## Project Structure

```
HikariSystem-HexCore/
├── extensions/
│   ├── hexcore-debugger/          # Emulation-based debugger (PE/ELF), Azoth integration
│   ├── hexcore-disassembler/      # Multi-arch disassembler + Pathfinder CFG + Helix client + DWARF/PDB loaders
│   ├── hexcore-hexviewer/         # Binary file viewer
│   ├── hexcore-peanalyzer/        # PE file analyzer (with CodeView PDB path extraction)
│   ├── hexcore-capstone/          # Capstone N-API binding
│   ├── hexcore-llvm-mc/           # LLVM MC N-API binding
│   ├── hexcore-unicorn/           # Unicorn N-API binding + Perseus SAB IPC
│   ├── hexcore-keystone/          # Legacy assembler binding (superseded by LLVM MC)
│   ├── hexcore-remill/            # Remill lifter (machine code → LLVM IR), HikariSystem fork
│   ├── hexcore-helix/             # Helix MLIR decompiler (LLVM IR → pseudo-C)
│   ├── hexcore-souper/            # Google Souper superoptimizer (Windows N-API build)
│   ├── hexcore-elixir/            # Project Azoth clean-room dynamic analysis
│   ├── hexcore-yara/              # YARA scanner + built-in anti-analysis pack (55 rules)
│   ├── hexcore-ioc/               # IOC extractor (with anti-VM/persistence sub-classification)
│   ├── hexcore-hashcalc/          # Hash calculator
│   ├── hexcore-strings/           # Strings extractor (multi-byte XOR, API hash resolver)
│   ├── hexcore-entropy/           # Entropy analyzer
│   ├── hexcore-base64/            # Base64 decoder
│   ├── hexcore-filetype/          # File type detector
│   ├── hexcore-elfanalyzer/       # ELF binary analyzer
│   ├── hexcore-minidump/          # Windows minidump parser
│   └── hexcore-report-composer/   # Pipeline report aggregator
├── .agent/
│   └── skills/hexcore/         # AI skill for agent integration
├── docs/                       # Documentation + v3.8.0 roadmap + Pathfinder DWARF design
├── src/                        # Core IDE source
├── resources/                  # Icons and assets
├── build/                      # Build scripts
└── product.json                # Product configuration
```

---

## AI Agent Integration

HexCore includes an AI skill definition for integration with AI agents (Claude Code, etc.). The skill provides:

- Complete command reference for all HexCore extensions
- Emulator memory layout and API hook documentation
- Typical analysis workflow guides
- Automation pipeline job file generation

See [.agent/skills/hexcore/SKILL.md](.agent/skills/hexcore/SKILL.md) for details.

---

## Usage

### Debugger
- Open any PE or ELF binary
- Run **"HexCore: Start Emulation"** to begin CPU emulation
- Use **Step**, **Continue**, and **Breakpoints** for dynamic analysis
- Set stdin input with **"HexCore: Set Stdin Buffer"** for interactive binaries

### Disassembler
- Right-click any executable file
- Select **"HexCore: Disassemble File"**
- Use function tree, string references, and graph view for navigation

### Hex Viewer
- Right-click any file and select **"HexCore: Open Hex View"**
- Or use **"Open With..." > "HexCore Hex Editor"**

### PE Analyzer
- Right-click any `.exe`, `.dll`, `.sys`, or `.ocx` file
- Select **"HexCore: Analyze PE File"**

### Hash Calculator
- Right-click any file
- Select **"HexCore: Calculate File Hashes"**

### Strings Extractor
- Right-click any file
- Select **"HexCore: Extract Strings"**

### Automation
- Create a `.hexcore_job.json` in your workspace
- HexCore auto-detects and runs it, or run manually via **"Run HexCore Automation Job"**

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add your feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

---

## License

The VS Code-derived workbench and most HexCore extensions use the repository's
[MIT license](LICENSE.txt). Native engines and wrappers retain their own
package licenses: Helix, Revenant, and Elixir/Azoth are Apache-2.0; Unicorn and
the Debugger wrapper are GPL-2.0-only. Consult each package's `package.json`,
license file, and third-party notices before redistribution.

---

<p align="center">
  <strong>HikariSystem</strong> — Security Tools for Professionals
</p>
