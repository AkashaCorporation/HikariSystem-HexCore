# Changelog

All notable changes to the HikariSystem HexCore project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- **29/29 tests passing** ✅
- Author: **Bih** [(ThreatBih)](https://github.com/ThreatBiih)

#### hexcore-keystone v1.0.0
- **Automated Keystone assembler** bindings
- Auto-generates architecture definition files (no manual configuration)
- X86/X64 assembly support (Intel, AT&T, NASM syntax)
- Async assembly support (`asmAsync`)
- Automatic build system with CMake
- **Legacy mode**: Based on LLVM 3.8 (stable but dated)
- Note: ARM/MIPS support requires full LLVM rebuild (coming in LLVM MC)

### 🔄 Updated

#### hexcore-capstone v1.3.0
- **Standalone package** with async disassembly (`disasmAsync`)
- Dual module support: ESM (`index.mjs`) + CommonJS (`index.js`)
- Complete TypeScript definitions with JSDoc
- Extended architecture support (Capstone v5)
- Synced with standalone npm package structure
- Support for detail mode across all architectures

#### Extension Infrastructure
- Updated package.json files across multiple extensions
- Standardized build scripts and dependencies

### 📝 Notes

**CTF-Ready Toolkit:**
- **Disassembly**: hexcore-capstone (analyze code)
- **Assembly**: hexcore-keystone (create/modify code)
- **Emulation**: hexcore-unicorn (execute and debug)

Complete binary analysis pipeline for security research and CTF competitions.

### ⚠️ Breaking Changes

- New installation process for native modules (automated scripts)
- Keystone is documented as "legacy" (modern replacement planned)

---

## [2.0.0] - Previous Release

- HexCore UI Overhaul & IDA-Style Graph View (CFG)
- Multi-arch disassembler integration
- Capstone N-API binding
- New analysis tools

[3.1.1]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v3.1.1
[3.1.0]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v3.1.0
[3.0.0]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v3.0.0
[2.0.0]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v2.0.0
