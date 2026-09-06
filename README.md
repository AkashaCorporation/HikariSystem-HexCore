# HikariSystem HexCore

<p align="center">
  <img alt="HikariSystem HexCore" src="BatHexCoreTransparente.png" width="240">
</p>

<p align="center">
  <strong>An open-source workbench for reverse engineering, binary analysis, and controlled emulation</strong>
</p>

<p align="center">
  <a href="https://github.com/AkashaCorporation/HikariSystem-HexCore/releases/tag/v3.8.4"><img alt="Stable release v3.8.4" src="https://img.shields.io/badge/stable-v3.8.4-2ea44f"></a>
  <a href="https://github.com/AkashaCorporation/HikariSystem-HexCore/actions/workflows/hexcore-build.yml"><img alt="HexCore build" src="https://github.com/AkashaCorporation/HikariSystem-HexCore/actions/workflows/hexcore-build.yml/badge.svg?branch=main"></a>
  <img alt="Platform Windows x64" src="https://img.shields.io/badge/platform-Windows%20x64-0078d4">
  <a href="LICENSE.txt"><img alt="License MIT" src="https://img.shields.io/badge/workbench%20license-MIT-blue"></a>
</p>

<p align="center">
  <a href="#features">Features</a> |
  <a href="#extensions">Extensions</a> |
  <a href="#disassembler">Disassembler</a> |
  <a href="#semantic-analysis">Semantic Analysis</a> |
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

**Stable release:** [`v3.8.4`](https://github.com/AkashaCorporation/HikariSystem-HexCore/releases/tag/v3.8.4).

This release brings HXDB v2, typed references, bounded whole-program propagation,
Semantic Explorer, HQL `0.3.1`, Function Atlas, and killable native analysis.
Manual and automatic job requests share one queue, while session generations
retain their analysis-universe binding across semantic edits and reloads.
Static signals, candidates and proven evidence remain explicitly distinguished.

See the [changelog](CHANGELOG.md) for the release history and
[known limitations](docs/KNOWN_LIMITATIONS.md) before treating an analysis
result as complete.

> **Platform status:** the supported packaged application is currently
> **Windows 10/11 x64** and is distributed as a portable ZIP. HexCore analyzes
> both PE and ELF targets, but Linux-host packaging remains experimental.

**What makes HexCore different:**
- **Agentic-first decompilation** — output designed for both human and LLM consumption; paired with HQL (Helix Query Language) over typed HAST and HXDB evidence
- **Controlled PE and ELF emulation** with selected API/syscall models plus the clean-room Project Azoth path
- **Native Capstone / Unicorn / LLVM MC / Remill / Helix / Souper / Azoth** engines bundled through the release workflow, so packaged users do not compile the native stack locally
- **Decompilation pipeline:** machine code → Pathfinder CFG hints → Remill lift → LLVM IR → Helix MLIR engine (Low/Mid/High lowering) → pseudo-C with debug-info-guided type recovery
- **DWARF + PDB + ET_REL debug-info ingestion** — recovers real parameter names, struct field names, and function signatures on kernel modules and debug-built PE
- **Headless automation pipeline** for batch analysis with `.hexcore_job.json`
- **Evidence-aware audit tooling** — refcount and semantic scanners emit review observations without promoting text matches directly to vulnerabilities
- **Evidence-driven validation** against owned or authorized kernel modules, large PE64 game binaries, CTF challenges, and controlled obfuscated samples

---

## Features

- **Disassembly** — Native multi-architecture disassembler (x86, x64, ARM, ARM64, MIPS, RISC-V)
- **Pathfinder CFG Engine** (v3.8.0) — Pre-lift CFG analysis using reconciled logical `.pdata` ranges and section-safe `.symtab` boundaries, recursive descent, jump table resolution, NOP range detection, and gap scanning with prologue heuristics. PE ranges are non-overlapping before binary search; ET_REL numeric navigation is canonicalized to `.text`, while other colliding sections use `symbolName`. Feeds Remill through bounded `additionalLeaders`
- **IR Lifting** — Machine code → LLVM IR translation via patched Remill fork (FIX-023/024/025: CET preamble handling, XED-ILD exotic-ISA recovery, CALL fall-through wiring)
- **Decompilation** — LLVM IR → pseudo-C via the Helix MLIR engine, with Low/Mid/High dialect lowering, a documented 19-pass pipeline, structured control flow, type recovery, and evidence-gated confidence
- **Helix MLIR Decompiler** — C++23/MLIR pipeline, C AST layer with 16+ optimizer passes, SysV/Win64/Cdecl32 ABI auto-detection, SSA variable splitting via reverse post-order traversal, Ghidra-inspired type recovery with pointer propagation
- **HXDB Semantic Model** (3.8.4) — Target-bound canonical types, full function prototypes, ABI locations, type bindings, evidence/conflicts, generations, typed references, and propagation summaries persisted in `.hexcore_session.db`
- **Semantic Explorer** (3.8.4) — Evidence-first prototype/type editor with xrefs, conflicts, providers, stale facts, generation diffs, transactional edits, and undo
- **HQL 0.3.1 + Atlas** (3.8.4) — Recursive `all`/`any`/`not`/`count` rules over HAST plus typed HXDB facts, explicit signal/candidate/proven levels, deterministic fixtures, and target-bound semantic hashes
- **Function Atlas** (3.8.4) — Deterministic function-family similarity across compiler, architecture, optimization, and debug variants, evaluated separately from Ghidra BSim
- **DWARF + BTF + PDB Debug Info Ingestion** (v3.8.0) — Pure-TypeScript DWARF 5 parser with split-form resolution (`DW_FORM_strx*`/`DW_FORM_addrx*`) and in-process ET_REL relocation application for kernel modules. PDB function boundary feeder via `llvm-pdbutil`. End-to-end: `mali_kbase.ko` recovers 792 structs + 3,864 function signatures with real parameter names and types
- **Emulation** — CPU emulation via Unicorn Engine with PE and ELF loading, API hooking, stdin emulation, faithful PRNG (glibc/MSVCRT), side-channel analysis, KUSER_SHARED_DATA + synthetic DLL PE images for hash-resolved imports
- **Project Azoth** — Clean-room Apache-2.0 Rust+C++23 dynamic-analysis path with Interceptor/Stalker APIs, shipped through `AkashaCorporation/HexCore-Elixir`
- **Perseus Zero-Copy IPC** (v3.8.0) — SPSC `SharedArrayBuffer` ring for Unicorn hook delivery. 1.34× throughput, 100% delivery vs ~35% legacy on heavy hooking workloads
- **Souper Superoptimizer** — Windows N-API integration of Google Souper with Z3 SMT solving for selected LLVM IR
- **Souper Surgical Auto-Activation** — absent/`"auto"` runs Souper only on crypto/MBA-dense IR; `true` forces it on and `false` disables it
- **Vulnerability Audit Engine** — Refcount-oriented review scanner with explicit partial/not-assessed states. Textual matches and assertion calls remain signals until CFG, aliasing, reachability, and impact are proven
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
- **Callfuscation Detection** — Byte-scan detection of call-as-jump patterns (`call <next>` followed by a return-address discard). `analyzeAll` emits qualified callfuscation evidence; the opt-in lift transform remains experimental and disabled by default
- **Function Boundary Detection** — Native C++ prologue scanner for accurate function start/end identification with auto-backtrack
- **Memory Pattern Search** — AOB byte pattern scan and RTTI class discovery during live emulation (`searchMemoryHeadless`, `searchBytesHeadless`, `rttiScanHeadless`)
- **Trampoline Following** — Automatic detection and follow-through of unconditional JMP trampolines to real function bodies

---

## Extensions

### Analysis Tools

| Extension | Version | Description |
|-----------|---------|-------------|
| **Debugger** | 2.1.22 | PE/ELF execution lab with Unicorn Engine, deterministic inputs, typed stop reasons, live-memory analysis, and binary/input/trace-bound runtime corroboration |
| **Disassembler** | 1.4.68 | Multi-arch disassembly, killable native analysis, HXDB v2, typed references, whole-program propagation, partial-body quarantine, Semantic Explorer, Helix/HQL integration, and automation |
| **Revenant** | 0.4.0 | Portable managed .NET decompilation to C# or IL, including single-file apphost recovery through the bundled ILSpy 10 backend |
| **Hex Viewer** | 1.2.4 | Chunk-backed binary viewer with scaled large-file scrolling, data inspection, editing, templates, and offset sync |
| **PE Analyzer** | 1.1.3 | Comprehensive PE analysis with binary transforms, Windows security summaries, and headless mode |
| **Strings Extractor** | 1.3.3 | Memory-efficient ASCII/UTF-16 extraction, bounded deobfuscation, provenance-bound transform chains, and stack strings |
| **Hash Calculator** | 1.1.2 | Fast file hashing with VirusTotal integration |
| **Entropy Analyzer** | 1.1.2 | Streaming entropy analysis with adaptive block sizing and modular report pipeline |
| **File Type Detector** | 1.0.2 | Magic bytes signature detection |
| **Base64 Decoder** | 2.0.2 | Detect and decode Base64 strings |
| **YARA Scanner** | 2.1.3 | YARA scanning with qualified condition/ISA evidence and headless pipeline support |
| **IOC Extractor** | 1.1.2 | Binary-aware IOC extraction with noise reduction, SQLite backend, and threat assessment |
| **Minidump Parser** | 1.0.1 | Windows MDMP forensics with thread injection/RWX detection and threat heuristics |
| **ELF Analyzer** | 1.0.1 | Structural analysis of ELF binaries — sections, segments, symbols, and security mitigations |
| **HQL** | 0.3.1 | Typed HAST/HXDB rule engine with recursive conditions, Atlas fixtures, provenance, and deterministic semantic cache identities |
| **Report Composer** | 1.0.14 | Aggregates outputs while separating proofs, signals, barriers, semantic providers, and runtime corroboration |

### Native Engines (Standalone N-API Packages)

These engines are maintained as standalone N-API packages and are bundled into
the portable application by the release workflow. Standalone consumer and npm
distribution are qualified separately from the HexCore ZIP.

| Package | Version | Description |
|---------|---------|-------------|
| **hexcore-capstone** | 1.3.6 | Capstone v5 N-API binding — async disassembly, structured detail, half-open function boundaries, all architectures |
| **hexcore-unicorn** | 1.3.2 | Unicorn N-API binding — CPU emulation, hooks, breakpoints, snapshots, shared memory, and Perseus SAB delivery |
| **hexcore-llvm-mc** | 1.0.2 | LLVM 18.1.8 MC N-API binding — multi-arch assembly and patching |
| **hexcore-better-sqlite3** | 2.0.3 | SQLite N-API wrapper with safe prepared-statement lifecycle for persistent sessions |
| **hexcore-remill** | 0.5.4 | Patched Remill N-API lifter — machine code to LLVM IR with logical-entry/reachable-only CFG recovery plus current call, relocation, preamble, and fallback hardening |
| **hexcore-helix** | 0.9.4-rc.1 | Canonical Helix MLIR decompiler candidate with structured control flow, debug-info-guided type recovery, deterministic HAST, and evidence-gated confidence |
| **hexcore-souper** | 0.2.2 | Google Souper superoptimizer N-API binding with Z3 SMT and density-gated automatic execution |
| **hexcore-elixir** *(Azoth)* | 1.0.4 | Project Azoth clean-room dynamic analysis framework for PE32+ x86_64 — Apache-2.0 Rust+C++23 replacement for Qiling. Frida-style Interceptor/Stalker, 5/5 Parity Gates passed. Standalone repo at `AkashaCorporation/HexCore-Elixir` |
| **hexcore-keystone** | 1.0.0 | Legacy assembler binding (superseded by LLVM MC) |

> **Note on hexcore-helix:** Depends on LLVM 18.1.8 + MLIR. The extension/package version (`0.9.4-rc.1`), native engine API, and HAST producer version are separate provenance identities and are reported separately. The `.node` binary is pre-built and ships with HexCore; building from source requires VS2022, clang-cl, and `LLVM_BUILD_DIR` pointing to an MLIR-enabled LLVM build.

> **Note on hexcore-remill:** This engine depends on LLVM 18, XED, glog, gflags, and Remill. End users receive the pre-built `.node` binary via CI; source builds require the documented native toolchain.

> **Note on hexcore-souper:** Depends on the bundled Z3 runtime. Use `souper: true` to force execution, `souper: false` to disable it, or omit/use `"auto"` for the density gate.

> **Note on hexcore-elixir (Project Azoth):** Apache-2.0 clean-room implementation derived from public specifications (PE/COFF, ELF, MSDN, man pages, Unicorn C API). The wrapper downloads its `.node` at `postinstall`, matching the HexCore-Helix delivery pattern.

---

## Semantic Analysis

HexCore's semantic layer is evidence-driven. A successful command means the
operation completed; it does not by itself prove that a behavior, type, or
security finding is correct.

- **HXDB v2** stores canonical types/prototypes, independent evidence,
  conflicts, generations, typed references, propagation summaries, and
  immutable history for one exact binary identity.
- **Typed references** distinguish direct calls, qualified indirect
  candidates, imports, strings, data reads/writes, address-taken facts,
  fields, globals, and unresolved barriers.
- **Whole-program propagation** runs to a bounded fixed point. Cancellation,
  timeout, conflict, and budget exhaustion preserve the prior accepted
  generation.
- **Partial decode honesty** records authoritative and decoded ranges, stop
  reason, byte coverage, and body state. Incomplete bodies remain retryable
  display-only evidence and cannot enter accepted graph/summary inputs.
- **HQL** combines HAST structure with the active SemanticStore. It preserves
  semantic fact counts/hashes, matched-fact provenance, proof status, and
  explicit read failures.
- **capa, FLOSS, and Ghidra BSim are external benchmark tools**, pinned only in
  the development/evaluation lane. They are not bundled HexCore extensions or
  native engines. Benchmark adapters normalize their output for comparison;
  external evidence cannot directly promote a HexCore claim to `proven`.

Current source-known gates cover 16 MSVC/clang-cl PE variants with exact
boundaries and 60/60 calling conventions, equivalent DWARF/BTF layouts, a
202/202 pinned API-callsite reference set, deterministic zlib/libarchive
semantic runs, and byte-identical installed HQL reruns. These are regression
gates, not a claim of parity with IDA, Ghidra, capa, FLOSS, or BSim.

See [HexCore Automation](docs/HEXCORE_AUTOMATION.md), the
[RC checklist](docs/RELEASE_3_8_4_RC_CHECKLIST.md), and the
[known limitations](docs/KNOWN_LIMITATIONS.md).

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

The Disassembler is the static-analysis coordinator for HexCore. It combines
**Capstone Engine v5**, **LLVM MC**, **Remill**, Pathfinder, Helix, HQL, and the
persistent HXDB session model while keeping discovery, materialization, and
semantic proof as distinct states.

- **Architectures**: x86, x64, ARM, ARM64, MIPS, RISC-V
- **Function index and lazy bodies** — Complete discovered indexes stay visible while expensive bodies are materialized on demand; lazy, partial, complete, and decode-empty states are explicit
- **Boundary reconciliation** — Merges PE `.pdata`, ELF symbols, recursive descent, call targets, prologue candidates, and padding roles without counting alignment bytes as semantic instructions
- **Killable native analysis** — Large `analyzeAll` work runs in a child process with external watchdog, heartbeat, terminal error stubs, and snapshot handoff so a timeout does not freeze the Extension Host
- **IR lifting** — Lifts selected machine-code regions to Remill-compatible LLVM IR with Pathfinder leaders, logical entry, reachable-only recovery, auto-backtrack, and trampoline handling
- **Inline PE/ELF parsing** — Imports, exports, sections without external dependencies
- **HXDB v2** — Persists target identity, materialized bodies, prototypes, types, evidence, conflicts, semantic facts, typed references, generations, and canonical provenance
- **Closure and propagation** — Newly investigated bodies can re-enter the accepted analysis universe, rerank candidates, and propagate facts through a bounded, cancellable fixed point
- **Soundness barriers** — Partial decode, unknown calls, writes, dominance failures, stale generations, and resource limits prevent unsupported facts from becoming proofs
- **Evidence levels** — Reports distinguish `signal`, `candidate`, and `proven`; command success is never treated as semantic correctness
- **String and data references** — Tracks calls, imports, strings, reads/writes, address-taken values, fields, globals, and unresolved edges
- **Graph Editor** — Central control-flow workspace with branch labels, routed edges, bounded block previews, pan/zoom, and an optional compact sidebar view
- **Analysis Center** — Session summary, workspace target selection, persistent string/xref investigations, saved findings, engine health, automation jobs, and primary actions without crowding the navigation sidebar
- **Semantic Explorer** — Edits prototypes and types transactionally with provider/conflict visibility, generation diffs, and undo
- **Patching** — Assemble, patch instructions, NOP sleds (LLVM MC)
- **Headless automation** — `hexcore.disasm.analyzeAll`, focused investigation, reference export, propagation, HQL, lifting, and decompilation with JSON/Markdown artifacts plus `.hexcore-meta` provenance

The function tree and Markdown previews are intentionally bounded views. Use
the JSON index and HXDB state for complete enumeration, and consult
[known limitations](docs/KNOWN_LIMITATIONS.md) before interpreting zero xrefs,
high confidence, or a successful job as proof of absence or correctness.

> Powered by [hexcore-capstone](extensions/hexcore-capstone), [hexcore-llvm-mc](extensions/hexcore-llvm-mc), and [hexcore-remill](extensions/hexcore-remill).

---

## Helix Decompiler & Pathfinder

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
- **Qualified kernel benchmark** — the maintained `mali_kbase.ko` fixture recovers 792 structs, 3,864 function signatures, and 1,633 DWARF boundaries. These corpus measurements do not imply universal type or boundary accuracy

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

Clean-room Apache-2.0 Rust+C++23 dynamic-analysis framework with
Interceptor-style API hooking and basic-block tracing built on HexCore-Unicorn.

### Highlights

- **Clean-room implementation** based on public PE/COFF, ELF, Windows API, and Unicorn API specifications
- **5/5 Parity Gates passed** on the reference malware corpus
- **22,921 API calls** captured end-to-end on v3 "Ashaka Shadow" with djb2 hash resolution
- **KUSER_SHARED_DATA page** populated at `0x7FFE0000` for timing-check bypass
- **8 synthetic DLL PE images** at `0x72000000..0x72040000` (ntdll, kernel32, KERNELBASE, ucrtbase, msvcp140, shell32, advapi32, user32) with real export tables for hash-resolved imports
- **PEB_LDR_DATA** populated with circular lists (`InLoadOrder`/`InMemoryOrder`/`InInitializationOrder`)
- **Standalone repo**: [`AkashaCorporation/HexCore-Elixir`](https://github.com/AkashaCorporation/HexCore-Elixir)

### Usage

HexCore exposes `azoth`, `debugger`, and `both` modes through
`hexcore.emulator`; both paths remain available for explicit comparison.

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

Professional raw-byte viewer with chunk-backed, scaled virtual scrolling for large files.

- **Scaled Virtual Scrolling** — Reaches the complete file without exceeding Chromium's element-height limit
- **Data Inspector** — View bytes as Int8/16/32/64, Float, Unix timestamp
- **Bookmarks** — Save and navigate to important offsets
- **Structure Templates** — Parse common binary structures
- **Search** — Find hex patterns (e.g., `4D 5A` for PE headers)
- **Go to Offset** — Jump directly to any offset
- **Copy Selection** — Reads the exact selected range from disk and exports as Hex, C Array, or Python bytes
- **Disassembler Sync** — Maps file offsets to the loaded image's virtual addresses through section metadata
- **Little/Big Endian** toggle

---

## Installation

### Packaged Application

The supported release artifact is the portable Windows x64 ZIP produced by
GitHub Actions. Download it from the
[AkashaCorporation releases page](https://github.com/AkashaCorporation/HikariSystem-HexCore/releases).
Native `.node` engines are bundled; end users do not compile LLVM/MLIR locally.
Updates are manual so analysts can keep reproducible versions side by side; the
application does not replace a working analysis environment automatically. Each
package includes `resources/app/hexcore-engine-manifest.json` with the version,
release tag, size, and SHA-256 of every bundled native engine artifact.

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
│   ├── hexcore-keystone/          # Disabled legacy assembler source; LLVM MC is active
│   ├── hexcore-remill/            # Remill lifter (machine code → LLVM IR), HikariSystem fork
│   ├── hexcore-helix/             # Helix MLIR decompiler (LLVM IR → pseudo-C)
│   ├── hexcore-hql/               # HAST/HXDB semantic query engine + Atlas
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
├── docs/                       # Automation, release, architecture, and engine documentation
├── src/                        # Core IDE source
├── resources/                  # Icons and assets
├── build/                      # Build scripts
└── product.json                # Product configuration
```

---

## AI Agent Integration

HexCore includes an AI skill definition for reproducible agent-driven analysis. The skill provides:

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
