# Changelog

All notable changes to the HikariSystem HexCore project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[3.2.2]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v3.2.2
[3.2.1]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v3.2.1
[3.2.0-preview]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v3.2.0-preview
[3.1.1]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v3.1.1
[3.1.0]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v3.1.0
[3.0.0]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v3.0.0
[2.0.0]: https://github.com/LXrdKnowkill/HikariSystem-HexCore/releases/tag/v2.0.0
