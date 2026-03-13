# HikariSystem HexCore

<p align="center">
  <img alt="HikariSystem HexCore" src="BatHexCore.png" width="200">
</p>

<p align="center">
  <strong>A specialized IDE for malware analysis, reverse engineering, and binary emulation</strong>
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
  <code>binary analysis</code> &middot; <code>reverse engineering</code> &middot; <code>malware analysis</code> &middot; <code>CPU emulation</code> &middot; <code>PE/ELF</code> &middot; <code>CTF tools</code> &middot; <code>disassembler</code> &middot; <code>debugger</code>
</p>

---

## Overview

HikariSystem HexCore is a comprehensive binary analysis IDE built on VS Code. It provides security researchers with a unified environment for malware analysis, reverse engineering, and threat hunting — from static analysis to full CPU emulation.

**Latest release (2026-03-11):** `v3.7.0-beta.1` "Helix MLIR Stability (Beta Part 1)" — Critical crash fixes in the Helix MLIR engine: loop-at-entry functions now decompile successfully, calling convention recovery crash-free on all IR patterns. See [CHANGELOG](CHANGELOG.md) for details.

**What makes HexCore different:**
- Full PE and ELF emulation with 70+ API hooks (Windows + Linux)
- Native Capstone/Unicorn/LLVM MC/Remill/Helix engines via N-API (no external installs)
- Decompilation pipeline: machine code → LLVM IR → pseudo-C via Helix MLIR engine
- Headless automation pipeline for batch analysis
- Tested and verified against real-world obfuscated custom VM CTF binaries

---

## Features

- **Disassembly** — Native multi-architecture disassembler (x86, x64, ARM, ARM64, MIPS, RISC-V)
- **IR Lifting** — Machine code → LLVM IR translation via Remill engine
- **Decompilation** — LLVM IR → pseudo-C via Helix MLIR engine (x86/x64, structured control flow, confidence scoring)
- **Helix MLIR Decompiler** — C++23/MLIR pipeline with 7 analysis passes (v0.5.0: crash-free on loop-at-entry functions)
- **Emulation** — CPU emulation via Unicorn Engine with PE and ELF loading, API hooking, stdin emulation
- **Assembly Patching** — Inline patching with LLVM MC backend, NOP sleds, multi-arch support
- **PE/ELF Analysis** — Import/export parsing, section analysis, packer detection, PIE support
- **Hex Viewer** — Virtual scrolling, data inspector, bookmarks, structure templates
- **Hash Calculator** — MD5, SHA-1, SHA-256, SHA-512 with VirusTotal integration
- **String Extraction** — ASCII/UTF-16, auto-categorization, XOR deobfuscation, stack strings
- **Entropy Analysis** — Block-by-block entropy with packer/encryption detection
- **YARA Scanning** — Rule loading, match highlighting, custom rules
- **IOC Extraction** — Binary-aware IOC detection (IPs, URLs, domains, pipes, wallets)
- **Minidump Analysis** — Windows crash dump forensics with thread/module/memory parsing
- **Automation** — Headless pipeline system for batch binary analysis

---

## Extensions

### Analysis Tools

| Extension | Version | Description |
|-----------|---------|-------------|
| **Debugger** | 2.1.0 | PE/ELF emulation with Unicorn Engine, 70+ API hooks, IPC Smart Sync, stdin emulation |
| **Disassembler** | 1.4.0 | Multi-arch disassembler with inline PE/ELF parsing, function detection, string xrefs, IR lifting |
| **Hex Viewer** | 1.2.1 | Professional binary file viewer with virtual scrolling |
| **PE Analyzer** | 1.1.0 | Comprehensive PE executable analysis with headless mode |
| **Strings Extractor** | 1.2.0 | Memory-efficient string extraction with XOR deobfuscation and stack string detection |
| **Hash Calculator** | 1.1.0 | Fast file hashing with VirusTotal integration |
| **Entropy Analyzer** | 1.1.0 | Streaming entropy analysis with adaptive block sizing and modular report pipeline |
| **File Type Detector** | 1.0.0 | Magic bytes signature detection |
| **Base64 Decoder** | 1.0.0 | Detect and decode Base64 strings |
| **YARA Scanner** | 2.1.0 | YARA scanning with DefenderYara integration and headless pipeline support |
| **IOC Extractor** | 1.1.0 | Binary-aware IOC extraction with noise reduction, SQLite backend, and threat assessment |
| **Minidump Parser** | 1.0.0 | Windows MDMP forensics with thread injection/RWX detection and threat heuristics |
| **ELF Analyzer** | 1.0.0 | Structural analysis of ELF binaries — sections, segments, symbols, security mitigations (NEW) |
| **Report Composer** | 1.0.0 | Aggregates pipeline outputs into unified Markdown reports with TOC and evidence links (NEW) |

### Native Engines (Standalone N-API Packages)

These engines ship with HexCore and can also be used independently in Node.js projects.

| Package | Version | Description |
|---------|---------|-------------|
| **hexcore-capstone** | 1.3.2 | Capstone v5 N-API binding — async disassembly, detail mode, all architectures |
| **hexcore-unicorn** | 1.2.1 | Unicorn N-API binding — CPU emulation, hooks, breakpoints, snapshots, shared memory |
| **hexcore-llvm-mc** | 1.0.0 | LLVM 18.1.8 MC N-API binding — multi-arch assembly and patching |
| **hexcore-better-sqlite3** | 2.0.0 | SQLite N-API wrapper for IOC persistence — prebuild packaging for better-sqlite3 |
| **hexcore-remill** | 0.1.2 | Remill N-API binding — lifts machine code to LLVM IR (experimental, heavy deps) |
| **hexcore-helix** | 0.5.0 | Helix MLIR decompiler N-API binding — LLVM IR → pseudo-C via C++23/MLIR pipeline (7 analysis passes) |
| **hexcore-rellic** | — | *(deprecated)* Rellic-based decompiler — superseded by Helix MLIR engine |
| **hexcore-keystone** | 1.0.0 | Legacy assembler binding (superseded by LLVM MC) |

> **Note on hexcore-helix:** Depends on LLVM 18.1.8 + MLIR. The `.node` binary is pre-built and ships with HexCore — no compilation needed for end users. Building from source requires VS2022, clang-cl, and `LLVM_BUILD_DIR` pointing to an MLIR-enabled LLVM build (~131 MB deps).

> **Note on hexcore-remill:** This engine depends on LLVM 18, XED, glog, gflags, and the Remill library itself (168 static libs, ~131 MB of pre-compiled dependencies). Building from source requires clang-cl, VS2022, and a dedicated build pipeline (`_rebuild_mt.py`). For development, download the pre-compiled deps from the [standalone repo releases](https://github.com/LXrdKnowkill/hexcore-remill/releases). End users receive the pre-built `.node` binary via CI — no compilation needed.

---

## Debugger & Emulator

The HexCore Debugger provides full CPU emulation for PE (Windows) and ELF (Linux) binaries via **Unicorn Engine**. No native debugger or target OS required — everything runs in-process.

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
- **Function detection** — Prolog scanning, call target analysis, up to 1000 functions
- **String cross-references** — Track which instructions reference which strings
- **Graph View** — IDA-style control flow graph visualization
- **Patching** — Assemble, patch instructions, NOP sleds (LLVM MC)
- **Headless mode** — `hexcore.disasm.analyzeAll` for automation with JSON/MD output

> Powered by [hexcore-capstone](extensions/hexcore-capstone), [hexcore-llvm-mc](extensions/hexcore-llvm-mc), and [hexcore-remill](extensions/hexcore-remill).

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
- **Output** — JSON/Markdown reports + `hexcore-pipeline.status.json` + `hexcore-pipeline.log`

All analysis extensions support headless execution with `file`, `output`, and `quiet` parameters.

### v3.5.2 Headless Commands

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

### Development Mode

```powershell
# Clone the repository
git clone https://github.com/LXrdKnowkill/HikariSystem-HexCore.git
cd HikariSystem-HexCore

# Install dependencies
npm install

# Run in development mode
$env:VSCODE_SKIP_NODE_VERSION_CHECK="1"
.\scripts\code.bat
```

### Requirements

- Node.js 18.x or higher
- npm 8.x or higher
- Windows 10/11
- Visual Studio Build Tools 2022 (for native modules)
- Python 3.x (for node-gyp)

---

## Project Structure

```
HikariSystem-HexCore/
├── extensions/
│   ├── hexcore-debugger/       # Emulation-based debugger (PE/ELF)
│   ├── hexcore-disassembler/   # Multi-arch disassembler + patching
│   ├── hexcore-hexviewer/      # Binary file viewer
│   ├── hexcore-peanalyzer/     # PE file analyzer
│   ├── hexcore-capstone/       # Capstone N-API binding
│   ├── hexcore-llvm-mc/        # LLVM MC N-API binding
│   ├── hexcore-unicorn/        # Unicorn N-API binding
│   ├── hexcore-keystone/       # Legacy assembler binding
│   ├── hexcore-remill/         # Remill lifter (machine code → LLVM IR)
│   ├── hexcore-yara/           # YARA scanner
│   ├── hexcore-ioc/            # IOC extractor
│   ├── hexcore-hashcalc/       # Hash calculator
│   ├── hexcore-strings/        # Strings extractor
│   ├── hexcore-entropy/        # Entropy analyzer
│   ├── hexcore-base64/         # Base64 decoder
│   ├── hexcore-filetype/       # File type detector
│   ├── hexcore-elfanalyzer/    # ELF binary analyzer
│   └── hexcore-report-composer/ # Pipeline report aggregator
├── .agent/
│   └── skills/hexcore/         # AI skill for agent integration
├── docs/                       # Documentation
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

This project is licensed under the MIT License. See the [LICENSE.txt](LICENSE.txt) file for details.

---

<p align="center">
  <strong>HikariSystem</strong> — Security Tools for Professionals
</p>
