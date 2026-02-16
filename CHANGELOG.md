# Changelog

All notable changes to the HikariSystem HexCore project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
