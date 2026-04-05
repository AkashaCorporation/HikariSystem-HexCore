# HexCore Automation — v3.7.4

HexCore supports running analysis pipelines from a workspace job file named `.hexcore_job.json`.

## How It Works

- If `.hexcore_job.json` exists in the workspace, HexCore watches it and runs it automatically on create/change.
- Auto-run serializes repeated triggers to avoid overlapping runs.
- Manual run: `Run HexCore Automation Job` (`hexcore.pipeline.runJob`).
- Generate from preset: `Create HexCore Job from Preset` (`hexcore.pipeline.createPresetJob`).
  - Built-in presets: **quick triage**, **full static**, **ctf reverse**.
- Save as reusable profile: `Save Current Job as Workspace Profile` (`hexcore.pipeline.saveJobAsProfile`).
  - Stored in `.hexcore_profiles.json` per workspace.
- Validate before running: `Validate HexCore Automation Job` (`hexcore.pipeline.validateJob`).
- Batch validate: `Validate HexCore Jobs in Workspace` (`hexcore.pipeline.validateWorkspace`).
- Diagnose health: `Run HexCore Pipeline Doctor` (`hexcore.pipeline.doctor`).
- Schema validation via `hexcore-disassembler/schemas/hexcore-job.schema.json`.
- Job execution writes `hexcore-pipeline.log` and `hexcore-pipeline.status.json` to `outDir`.

## Example Job

```json
{
  "file": "C:\\samples\\target.exe",
  "outDir": "C:\\reports\\target",
  "quiet": true,
  "steps": [
    { "cmd": "hexcore.filetype.detect" },
    { "cmd": "hexcore.hashcalc.calculate", "args": { "algorithms": "all" } },
    { "cmd": "hexcore.entropy.analyze" },
    { "cmd": "hexcore.strings.extract", "args": { "minLength": 5 } },
    { "cmd": "hexcore.strings.extractAdvanced" },
    { "cmd": "hexcore.disasm.analyzePEHeadless", "continueOnError": true },
    { "cmd": "hexcore.disasm.analyzeELFHeadless", "continueOnError": true },
    { "cmd": "hexcore.disasm.analyzeAll" },
    { "cmd": "hexcore.yara.scan" },
    { "cmd": "hexcore.ioc.extract" }
  ]
}
```

---

## Step Controls

Each step supports optional controls:

```json
{
  "cmd": "hexcore.disasm.analyzeAll",
  "timeoutMs": 300000,
  "retryCount": 2,
  "retryDelayMs": 1500,
  "expectOutput": true,
  "continueOnError": false
}
```

| Control | Default | Description |
|---------|---------|-------------|
| `timeoutMs` | per-command | Override per-step timeout |
| `retryCount` | `0` | Retries after initial failure |
| `retryDelayMs` | `1000` | Delay between retries (ms) |
| `expectOutput` | `true` | Validate output file existence |
| `continueOnError` | `false` | Continue remaining steps after failure |

---

## Conditional Branching (`onResult`) — v3.7.1

Each step supports an optional `onResult` field that evaluates the step's JSON output and controls pipeline flow.

```json
{
  "cmd": "hexcore.entropy.analyze",
  "onResult": {
    "field": "maxEntropy",
    "operator": "gt",
    "value": 7.5,
    "action": "goto",
    "actionValue": 5
  }
}
```

### onResult Schema

| Field | Type | Description |
|-------|------|-------------|
| `field` | `string` | Output JSON field to evaluate (e.g., `"maxEntropy"`, `"matchCount"`, `"stdout"`) |
| `operator` | `string` | One of: `contains`, `equals`, `not`, `gt`, `lt`, `regex` |
| `value` | `string \| number` | Comparison value |
| `action` | `string` | One of: `skip`, `goto`, `abort`, `log` |
| `actionValue` | `string \| number` | Parameter for action (step index for `goto`, count for `skip`, message for `abort`/`log`) |

### Operators

| Operator | Description |
|----------|-------------|
| `contains` | String representation of field contains value |
| `equals` | Field strictly equals value |
| `not` | Field does not equal value |
| `gt` | Numeric field is greater than value |
| `lt` | Numeric field is less than value |
| `regex` | Field matches JavaScript RegExp pattern |

### Actions

| Action | Description |
|--------|-------------|
| `skip` | Skip next N steps (N = `actionValue`, default 1) |
| `goto` | Jump to step index `actionValue` (0-based). Allows loops. |
| `abort` | Stop pipeline with error message `actionValue` |
| `log` | Log message `actionValue` and continue to next step |

### Loop Protection

`goto` actions that target already-executed steps are allowed (enabling loops), but a maximum of **100 iterations** is enforced. Exceeding this limit aborts the pipeline with a descriptive error.

### Example: Adaptive Malware Triage

```json
{
  "file": "C:\\samples\\suspect.exe",
  "outDir": "C:\\reports\\adaptive",
  "quiet": true,
  "steps": [
    {
      "cmd": "hexcore.entropy.analyze",
      "onResult": {
        "field": "maxEntropy",
        "operator": "gt",
        "value": 7.5,
        "action": "goto",
        "actionValue": 3
      }
    },
    { "cmd": "hexcore.strings.extract" },
    { "cmd": "hexcore.disasm.analyzeAll", "args": { "filterJunk": true, "detectVM": true } },
    { "cmd": "hexcore.yara.scan" },
    { "cmd": "hexcore.pipeline.composeReport" }
  ]
}
```

When `maxEntropy > 7.5` (likely packed), the pipeline skips strings and disassembly, jumping directly to YARA scanning.

---

## Pipeline Step Referencing — v3.7.3

Steps can reference outputs from previously-completed steps using `$step[N]` tokens in argument values. This eliminates hardcoded paths and makes multi-step pipelines self-describing.

### Syntax

| Token | Description |
|-------|-------------|
| `$step[N].output` | Output file path produced by step N (0-based index) |
| `$step[N].result.fieldName` | A specific field from the JSON result of step N |
| `$step[prev].output` | Output file path from the immediately preceding step |

**Example — auto-wire liftToIR → decompileIR:**

```json
{
  "steps": [
    {
      "cmd": "hexcore.disasm.liftToIR",
      "args": { "address": "0x140001000", "count": 150 },
      "output": { "path": "function.ll" }
    },
    {
      "cmd": "hexcore.helix.decompile",
      "args": { "irPath": "$step[0].output" }
    }
  ]
}
```

**Example — branch on a result field:**

```json
{
  "steps": [
    { "cmd": "hexcore.disasm.analyzeAll", "args": { "file": "test.exe" } },
    {
      "cmd": "hexcore.helix.decompile",
      "args": { "irPath": "$step[0].result.irOutputPath" }
    }
  ]
}
```

**Rules:**
- Forward references (referencing a step that has not yet run) are a validation error.
- Tokens are resolved immediately before the step executes, using the live result of the referenced step.
- `$step[prev]` is equivalent to `$step[N-1]` where N is the current step index. It is a validation error on step 0.

---

## Headless Commands (Pipeline-Safe)

These commands accept `file`, `quiet`, and `output` options and can run without any UI interaction.

### Static Analysis

| Command | Timeout | Description | Arch |
|---------|---------|-------------|------|
| `hexcore.filetype.detect` | 60s | Magic-byte file type detection (118 signatures) | All |
| `hexcore.hashcalc.calculate` | 90s | MD5, SHA1, SHA256, SHA512 hashes | All |
| `hexcore.entropy.analyze` | 90s | Shannon entropy analysis, packing detection | All |
| `hexcore.strings.extract` | 120s | ASCII/Unicode string extraction with categorization | All |
| `hexcore.strings.extractAdvanced` | 180s | XOR deobfuscation (1-byte + multi-byte keys, rolling, increment) + stack string detection | All |
| `hexcore.peanalyzer.analyze` | 120s | PE header, sections, entropy, packer detection, security mitigations (legacy) | PE only |
| `hexcore.disasm.analyzePEHeadless` | 120s | **Deep PE analysis**: typed imports (180+ API signatures), exports, sections, TLS/Debug/CLR/DelayImport, security indicators, category summary | PE only |
| `hexcore.elfanalyzer.analyze` | 120s | ELF header, sections, segments, symbols, security mitigations (RELRO, NX, PIE, Canary) (legacy) | ELF only |
| `hexcore.disasm.analyzeELFHeadless` | 120s | **Deep ELF analysis**: program headers, full symtab/dynsym, all relocations, dynamic entries, .ko modinfo, symbol stats | ELF only |
| `hexcore.base64.decodeHeadless` | 90s | Detect and decode Base64 strings with **confidence scoring** (entropy, context filters, categories) | All |
| `hexcore.yara.scan` | 180s | YARA rule scanning with threat scoring | All |
| `hexcore.yara.updateRules` | 60s | Reload YARA rule files | N/A |
| `hexcore.ioc.extract` | 120s | IOC extraction (IPs, URLs, hashes, emails, domains) | All |

### Disassembly & Analysis

| Command | Timeout | Description | Arch |
|---------|---------|-------------|------|
| `hexcore.disasm.analyzeAll` | 180s | Deep analysis: prolog scan, function discovery, xrefs | x86, x64, ARM, ARM64, MIPS |
| `hexcore.disasm.buildFormula` | 90s | Symbolic expression extraction from instruction chains | **x86, x64 only** |
| `hexcore.disasm.checkConstants` | 90s | Validate numeric annotations against instruction immediates | All |
| `hexcore.disasm.searchStringHeadless` | 120s | Search string references (headless variant) | All |
| `hexcore.disasm.exportASMHeadless` | 180s | Export disassembly to file (headless variant) | All |
| `hexcore.disasm.disassembleAtHeadless` | 120s | Disassemble N instructions starting at a given address | x86, x64, ARM, ARM64, MIPS |
| `hexcore.disasm.liftToIR` | 120s | Lift machine code to LLVM IR via Remill engine | x86, x64 |
| `hexcore.rellic.decompile` | 180s | ~~Decompile binary to pseudo-C via Rellic~~ **(DEPRECATED — use `hexcore.helix.decompile`)** | x86, x64 |
| `hexcore.rellic.decompileIR` | 120s | ~~Decompile pre-lifted LLVM IR text to pseudo-C via Rellic~~ **(DEPRECATED — use `hexcore.helix.decompileIR`)** | x86, x64 |
| `hexcore.helix.decompile` | 180s | **Decompile binary to pseudo-C via Helix MLIR pipeline** (lift + full pass pipeline in one step) | x86, x64 |
| `hexcore.helix.decompileIR` | 180s | **Decompile pre-lifted .ll file to pseudo-C via Helix MLIR pipeline** — use `irPath` to specify the IR file | x86, x64 |
| `hexcore.disasm.rttiScanHeadless` | 120s | Scan PE binary for MSVC RTTI Type Descriptors, returns class names and offsets **(v3.7.3)** | PE only |
| `hexcore.disasm.searchBytesHeadless` | 120s | AOB scan with wildcard support — finds byte patterns across the entire binary **(v3.7.3)** | All |
| `hexcore.disasm.extractStrings` | 180s | Section-filtered string extraction with PE/ELF section selection **(v3.7.4)** | All |
| `hexcore.disasm.renameFunction` | 10s | Rename a function in the session DB — propagates to all call sites **(v3.7.4)** | All |
| `hexcore.disasm.renameVariable` | 10s | Rename a variable within a function scope in the session DB **(v3.7.4)** | All |
| `hexcore.disasm.retypeVariable` | 10s | Change variable type in the session DB — propagates to Helix output **(v3.7.4)** | All |
| `hexcore.disasm.retypeFunction` | 10s | Change function return type in the session DB **(v3.7.4)** | All |
| `hexcore.disasm.setBookmark` | 10s | Set a named bookmark at an address in the session DB **(v3.7.4)** | All |
| `hexcore.disasm.getSessionDbPath` | 10s | Returns the path to the `.hexcore_session.db` for the current binary **(v3.7.4)** | All |

### Hex Viewer

| Command | Timeout | Description | Arch |
|---------|---------|-------------|------|
| `hexcore.hexview.dumpHeadless` | 60s | Extract hex dump of byte range (offset + size) with base64 raw output | All |
| `hexcore.hexview.searchHeadless` | 120s | Search hex pattern in file with streaming (64KB chunks + overlap) | All |

### Debugger (Headless)

| Command | Timeout | Description | Arch |
|---------|---------|-------------|------|
| `hexcore.debug.emulateHeadless` | 30s | Start emulation session only (load + configure, no automatic run) | x86, x64, ARM64 |
| `hexcore.debug.continueHeadless` | 30s | Continue active emulation session for `maxSteps` instructions | x86, x64, ARM64 |
| `hexcore.debug.stepHeadless` | 30s | Single-step or N-step active session | x86, x64, ARM64 |
| `hexcore.debug.readMemoryHeadless` | 30s | Read arbitrary memory range from active session | x86, x64, ARM64 |
| `hexcore.debug.getRegistersHeadless` | 30s | Export current register set from active session | x86, x64, ARM64 |
| `hexcore.debug.getStateHeadless` | 30s | Export current emulation state, regions, and API call log | x86, x64, ARM64 |
| `hexcore.debug.setBreakpointHeadless` | 30s | Set one or more breakpoints in active session | x86, x64, ARM64 |
| `hexcore.debug.emulateFullHeadless` | 300s | Unified single-shot emulation (load → configure → run → collect → dispose) | x86, x64, ARM64 |
| `hexcore.debug.writeMemoryHeadless` | 30s | Write data to emulation memory (requires active session) | x86, x64, ARM64 |
| `hexcore.debug.setRegisterHeadless` | 30s | Set CPU register value (requires active session) | x86, x64, ARM64 |
| `hexcore.debug.setStdinHeadless` | 30s | Set STDIN buffer for emulation (requires active session) | x86, x64, ARM64 |
| `hexcore.debug.disposeHeadless` | 30s | Dispose emulation session — idempotent, safe to call without active session | x86, x64, ARM64 |
| `hexcore.debug.snapshotHeadless` | 60s | Save emulation snapshot (requires active session) | x86, x64, ARM64 |
| `hexcore.debug.restoreSnapshotHeadless` | 60s | Restore emulation snapshot (requires saved snapshot) | x86, x64, ARM64 |
| `hexcore.debug.exportTraceHeadless` | 60s | Export API/libc call trace as JSON | x86, x64, ARM64 |
| `hexcore.debug.searchMemoryHeadless` | 60s | Pattern search across emulated RAM during keepAlive sessions **(v3.7.3)** | x86, x64, ARM64 |

**Wave 2 runtime note**

- `hexcore.debug.emulateHeadless`, `continueHeadless`, and `getStateHeadless` now expose `executionBackend` in their JSON output.
- `continueHeadless` and `getStateHeadless` may also include `faultInfo` when emulation stops on `UC_ERR_FETCH_UNMAPPED`, `UC_ERR_READ_UNMAPPED`, or `UC_ERR_WRITE_UNMAPPED`.
- `hexcore.debug.emulateHeadless` accepts `permissiveMemoryMapping: true` for PE/ELF worker paths.
- `hexcore.debug.setBreakpointHeadless` now supports `output.path` correctly in pipeline jobs.

### Report Composer

| Command | Timeout | Description |
|---------|---------|-------------|
| `hexcore.pipeline.composeReport` | 60s | Aggregate all reports from `hexcore-reports/` into unified Markdown with TOC and analyst notes |

### Minidump Analysis

| Command | Timeout | Description | Arch |
|---------|---------|-------------|------|
| `hexcore.minidump.parse` | 120s | Full minidump analysis (headers, threads, modules, memory) | x86, x64 |
| `hexcore.minidump.threads` | 60s | Thread context listing | x86, x64 |
| `hexcore.minidump.modules` | 60s | Module enumeration with versions | x86, x64 |
| `hexcore.minidump.memory` | 60s | Memory region listing with RWX detection | x86, x64 |

### Pipeline Administration

| Command | Timeout | Description |
|---------|---------|-------------|
| `hexcore.pipeline.listCapabilities` | 30s | Export capability map (headless/interactive per command) |
| `hexcore.pipeline.validateJob` | 30s | Preflight validation of current job |
| `hexcore.pipeline.validateWorkspace` | 30s | Validate all `.hexcore_job.json` in workspace |
| `hexcore.pipeline.createPresetJob` | 30s | Generate job from built-in preset |
| `hexcore.pipeline.saveJobAsProfile` | 30s | Save current job as workspace profile |
| `hexcore.pipeline.doctor` | 30s | Diagnose command registration and extension health |

---

## Interactive-Only Commands (NOT Pipeline-Safe)

These commands require UI interaction (file pickers, input boxes, webviews) and are blocked in pipeline mode.

| Command | Reason |
|---------|--------|
| `hexcore.disasm.openFile` | Opens file picker dialog |
| `hexcore.disasm.analyzeFile` | Opens editor UI |
| `hexcore.disasm.searchString` | Prompts for input |
| `hexcore.disasm.exportASM` | Opens save dialog |
| `hexcore.yara.quickScan` | Shows notifications and threat report UI |
| `hexcore.yara.scanWorkspace` | Depends on workspace UI flow |
| `hexcore.yara.loadDefender` | Opens folder picker |
| `hexcore.yara.loadCategory` | Prompts with quick-pick UI |
| `hexcore.yara.createRule` | Depends on active selection and editor UI |
| `hexcore.yara.threatReport` | Renders output from prior UI scan context |
| `hexcore.debug.emulate` | Opens file picker and UI |
| `hexcore.debug.emulateWithArch` | Opens prompts and UI |
| `hexcore.rellic.decompileUI` | Opens decompile panel with editor integration **(DEPRECATED)** |
| `hexcore.helix.decompileUI` | Opens Helix decompile panel with editor integration |
| `hexcore.pipeline.runJob` | Recursive pipeline invocation is not supported |

---

## Command Aliases

| Alias | Resolves To |
|-------|-------------|
| `hexcore.hash.file` | `hexcore.hashcalc.calculate` |
| `hexcore.hash.calculate` | `hexcore.hashcalc.calculate` |
| `hexcore.pe.analyze` | `hexcore.peanalyzer.analyze` |
| `hexcore.pe.deep` | `hexcore.disasm.analyzePEHeadless` |
| `hexcore.elf.analyze` | `hexcore.elfanalyzer.analyze` |
| `hexcore.elf.deep` | `hexcore.disasm.analyzeELFHeadless` |
| `hexcore.hex.dump` | `hexcore.hexview.dumpHeadless` |
| `hexcore.hex.search` | `hexcore.hexview.searchHeadless` |
| `hexcore.disasm.open` | `hexcore.disasm.openFile` |
| `hexcore.debug.emulate.full` | `hexcore.debug.emulateFullHeadless` |
| `hexcore.debug.run` | `hexcore.debug.emulateFullHeadless` |
| `hexcore.decompile` | `hexcore.helix.decompile` |
| `hexcore.decompile.ir` | `hexcore.helix.decompileIR` |
| `hexcore.liftir` | `hexcore.disasm.liftToIR` |
| `hexcore.disasm.disassembleAt` | `hexcore.disasm.disassembleAtHeadless` |
| `hexcore.debug.searchMemory` | `hexcore.debug.searchMemoryHeadless` |
| `hexcore.unicorn.searchMemory` | `hexcore.debug.searchMemoryHeadless` |
| `hexcore.unicorn.searchMemoryHeadless` | `hexcore.debug.searchMemoryHeadless` |
| `hexcore.disasm.rttiScan` | `hexcore.disasm.rttiScanHeadless` |
| `hexcore.disasm.scanRtti` | `hexcore.disasm.rttiScanHeadless` |
| `hexcore.disasm.searchBytes` | `hexcore.disasm.searchBytesHeadless` |
| `hexcore.disasm.aobScan` | `hexcore.disasm.searchBytesHeadless` |
| `hexcore.disasm.rename` | `hexcore.disasm.renameFunction` |
| `hexcore.disasm.retype` | `hexcore.disasm.retypeVariable` |
| `hexcore.disasm.bookmark` | `hexcore.disasm.setBookmark` |
| `hexcore.disasm.sessionPath` | `hexcore.disasm.getSessionDbPath` |

---

## Session Persistence — v3.7.4

### Overview

HexCore now persists analyst annotations (renames, retypes, comments, bookmarks) across sessions via `.hexcore_session.db` (SQLite, WAL mode). The session is keyed by SHA-256 of the binary — reopening the same binary restores all data.

### Session Commands

| Command | Args | Description |
|---------|------|-------------|
| `renameFunction` | `{ "address": "0x...", "name": "ValidateFlag" }` | Rename function — propagates to all call sites |
| `renameVariable` | `{ "funcAddress": "0x...", "originalName": "param_1", "newName": "healthPtr" }` | Rename variable within function scope |
| `retypeVariable` | `{ "funcAddress": "0x...", "variableName": "healthPtr", "newType": "HealthComponent*" }` | Change variable type — feeds back into Helix |
| `retypeFunction` | `{ "address": "0x...", "returnType": "int32_t" }` | Change function return type |
| `setBookmark` | `{ "address": "0x...", "label": "damage calc entry" }` | Named bookmark at address |
| `getSessionDbPath` | (none) | Returns `.hexcore_session.db` path |

### Helix Integration

When `helix.decompile` runs, it consults the session DB and applies renames/retypes as a post-processing overlay. The `sessionOverlay` arg can also be passed explicitly:

```json
{
  "cmd": "hexcore.helix.decompile",
  "args": {
    "address": "0x14003EDD0",
    "sessionOverlay": {
      "functions": { "0x14003EDD0": { "name": "ValidateFlag" } },
      "variables": {
        "0x14003EDD0.param_1": { "name": "result", "type": "int32_t" }
      }
    }
  }
}
```

### HQL Integration

The HQL matcher reads the session DB via `SessionDbReader` to apply analyst-defined names/types to the HAST before running pattern queries.

### Schema

```sql
CREATE TABLE session_meta (binary_hash TEXT PRIMARY KEY, version INTEGER, created_at TEXT);
CREATE TABLE functions (address TEXT PRIMARY KEY, name TEXT, return_type TEXT);
CREATE TABLE variables (func_address TEXT, original_name TEXT, new_name TEXT, new_type TEXT);
CREATE TABLE fields (struct_type TEXT, offset INTEGER, name TEXT, type TEXT);
CREATE TABLE comments (address TEXT PRIMARY KEY, comment TEXT);
CREATE TABLE bookmarks (address TEXT PRIMARY KEY, label TEXT);
CREATE TABLE analyze_cache (address TEXT PRIMARY KEY, name TEXT, size INTEGER, instruction_count INTEGER);
```

---

## ELF Relocatable Support — v3.7.4

### ELF ET_REL Processing

For ELF relocatable files (`.ko` kernel modules, `.o` object files), the disassembler processes `.rela.text` relocation entries before lifting. External symbols (kernel APIs) are resolved to named declarations in the IR.

- **Supported relocations**: `R_X86_64_PLT32`, `R_X86_64_PC32`, `R_X86_64_GOTPCREL`
- **Symbol resolution**: via `.symtab` + `.strtab`
- **Effect**: `call sub_0` → `call mutex_lock` in Helix output

### ftrace Preamble Detection

Kernel binaries compiled with `-fpatchable-function-entry=16,16` have NOP padding before each function. HexCore detects this pattern and skips to the real prologue:

```
(90 | 0F 1F XX){8,32}  ← NOP sled (ftrace __pfx_)
F3 0F 1E FA             ← endbr64 (CET)
E8 XX XX XX XX          ← call __fentry__ (tracing)
55                      ← push rbp (REAL FUNCTION START)
```

### ET_REL Warning

When loading an ELF with `e_type == ET_REL`, a warning is emitted in pipeline output:
```
[WARN] Target is a relocatable ELF (ET_REL). External calls are unresolved relocations.
```

---

## Architecture Notes

- **Arch-agnostic commands** (filetype, hash, entropy, strings, YARA, IOC, base64) operate on raw bytes — no architecture dependency.
- **Disassembler** auto-detects architecture from ELF `e_machine` and PE `Machine` headers. Defaults to x64 for raw files.
- **buildFormula** uses x86/x64 register regex — ARM64 registers (x0-x30, sp, lr) are **not recognized**.
- **checkConstants** is architecture-neutral — it only compares numeric literals.
- **PE Analyzer** is PE-format only. Use `hexcore.elfanalyzer.analyze` for ELF binaries.
- **ELF Analyzer** is ELF-format only. TypeScript-pure parser, no native dependencies. Detects RELRO, NX, PIE, Stack Canary.
- **Minidump** supports x86/x64 Windows crash dumps only.
- **Remill IR Lifter** requires x86/x64 machine code. ARM/ARM64 lifting is not yet supported.
- **Rellic Decompiler** **(DEPRECATED — removal in v3.8.0)** — Walks LLVM IR and emits pseudo-C with mnemonic annotations. Superseded by Helix in v3.7.0. Remains functional for backward compatibility. v3.7.1 adds `optimizationPasses` (DCE, ConstFold) and Souper hook for v3.8 preparation.
- **Helix Decompiler** (v0.4+) runs a full MLIR pass pipeline on Remill IR: type propagation, calling convention recovery, structured control flow reconstruction, and PseudoC emission with confidence scoring. Output is substantially higher quality than Rellic. Requires x86/x64 machine code. Use `hexcore.helix.decompile` (one-step) or `liftToIR` + `hexcore.helix.decompileIR` (two-step). Pass `optimizeIR: false` to skip MLIR optimization passes when debugging pass pipeline issues.
- **Auto-backtrack** (v3.7.3+) — `disassembleAtHeadless`, `helix.decompile`, and `liftToIR` auto-detect function boundaries. If the supplied address lands mid-function, the engine backtracks to the real function start. v3.7.4 adds `forceProbe` mode, Capstone backward disassembly, ftrace preamble skip, and `endbr64` recognition. Disable with `autoBacktrack: false`.
- **Section-filtered strings** (v3.7.4) — `hexcore.disasm.extractStrings` accepts `sections: [".rdata", ".data"]` to scan only specific PE/ELF sections. Eliminates noise from `.text`.
- **Session persistence** (v3.7.4) — `.hexcore_session.db` stores function renames, variable retypes, comments, bookmarks, and `analyzeAll` cache across sessions. Keyed by binary SHA-256.
- **ELF ET_REL support** (v3.7.4) — Relocatable ELF files (`.ko`, `.o`) have `.rela.text` processed before lifting. External symbols resolved to named declarations. ftrace preambles auto-skipped.

---

## Step Arguments

### `hexcore.disasm.analyzeAll`
```json
{
  "cmd": "hexcore.disasm.analyzeAll",
  "args": {
    "maxFunctions": 2500,
    "maxFunctionSize": 65536,
    "forceReload": true,
    "filterJunk": true,
    "detectVM": true,
    "detectPRNG": true
  }
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `maxFunctions` | `number` | `1000` | Maximum functions to analyze. |
| `maxFunctionSize` | `number` | `65536` | Maximum function size in bytes. |
| `forceReload` | `boolean` | `false` | Force reload of binary file. |
| `filterJunk` | `boolean` | `false` | Filter junk instructions (callfuscation, nop sleds, identity ops). Reports `junkCount` and `junkRatio`. **(v3.7.1)** |
| `detectVM` | `boolean` | `false` | Run VM obfuscation heuristics (dispatcher, handler tables, operand stacks). Reports `vmDetected`, `vmType`, `dispatcher`, `opcodeCount`. **(v3.7.1)** |
| `detectPRNG` | `boolean` | `false` | Detect PRNG usage patterns (srand/rand call sites, seed extraction). Reports `prngDetected`, `seedSource`, `seedValue`, `randCallCount`. **(v3.7.1)** |

### `hexcore.disasm.buildFormula`
```json
{
  "cmd": "hexcore.disasm.buildFormula",
  "args": {
    "startAddress": "0x401020",
    "endAddress": "0x40103F",
    "targetRegister": "eax"
  }
}
```

### `hexcore.disasm.checkConstants`
```json
{
  "cmd": "hexcore.disasm.checkConstants",
  "args": {
    "notesFile": "ANALYST_NOTES.md",
    "maxFindings": 200
  },
  "output": {
    "path": "constant-sanity-report.md",
    "format": "md"
  }
}
```

### `hexcore.disasm.searchStringHeadless`

Single query mode (unchanged):

```json
{
  "cmd": "hexcore.disasm.searchStringHeadless",
  "args": { "query": "HTB{" }
}
```

Batch mode **(v3.7.3)** — accepts a `queries` array and searches all terms in one call:

```json
{
  "cmd": "hexcore.disasm.searchStringHeadless",
  "args": { "queries": ["health", "ammo", "recoil"] }
}
```

**Batch output:**

```json
{
  "mode": "batch",
  "queriesCount": 3,
  "totalMatches": 12,
  "results": [
    { "query": "health", "totalMatches": 5, "matches": [ ... ] },
    { "query": "ammo",   "totalMatches": 4, "matches": [ ... ] },
    { "query": "recoil", "totalMatches": 3, "matches": [ ... ] }
  ]
}
```

Use `query` (string) for single-term lookups and `queries` (array) for batch lookups. Providing both is an error.

### `hexcore.disasm.rttiScanHeadless` **(v3.7.3)**

Scan a PE binary for MSVC RTTI Type Descriptors and recover class names.

```json
{
  "cmd": "hexcore.disasm.rttiScanHeadless",
  "args": { "file": "sample.exe" }
}
```

**Returns:**

```json
{
  "success": true,
  "classes": [
    { "className": "CPlayer", "offset": 1234, "fullName": ".?AVCPlayer@@" }
  ],
  "totalClasses": 1
}
```

**Aliases:** `hexcore.disasm.rttiScan`, `hexcore.disasm.scanRtti`

### `hexcore.disasm.searchBytesHeadless` **(v3.7.3)**

AOB (array-of-bytes) scan across the entire binary with wildcard support.

```json
{
  "cmd": "hexcore.disasm.searchBytesHeadless",
  "args": {
    "file": "sample.exe",
    "pattern": "48 8B ?? ?? 0F 84",
    "maxResults": 100
  }
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file` | `string` | *(from job)* | Path to binary. Inherited from job-level `file` if omitted. |
| `pattern` | `string` | *(required)* | Byte pattern — space-separated (`"48 8B ?? 00"`) or compact (`"488B??00"`). `??` is a single-byte wildcard. |
| `maxResults` | `number` | `100` | Maximum matches to return. |

**Returns:**

```json
{
  "success": true,
  "pattern": "48 8B ?? ?? 0F 84",
  "matches": [
    { "address": "0x140001234", "offset": 4660 }
  ],
  "totalMatches": 1
}
```

**Aliases:** `hexcore.disasm.searchBytes`, `hexcore.disasm.aobScan`

### `hexcore.disasm.exportASMHeadless`
```json
{
  "cmd": "hexcore.disasm.exportASMHeadless",
  "args": { "functionAddress": "0x401000" }
}
```

### `hexcore.disasm.disassembleAtHeadless`

Disassemble N instructions starting at a given virtual address. Requires prior `analyzeAll` or a loaded binary.

```json
{
  "cmd": "hexcore.disasm.disassembleAtHeadless",
  "args": {
    "address": "0x401000",
    "count": 50,
    "filterJunk": true
  },
  "output": { "path": "disasm-at-result.json" },
  "timeoutMs": 120000
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `address` | `string` | *(required)* | Start virtual address as `0x`-prefixed hex string. |
| `count` | `number` | `20` | Number of instructions to disassemble. |
| `filterJunk` | `boolean` | `false` | Filter junk instructions from output. Reports `junkCount` and `junkRatio`. **(v3.7.1)** |
| `autoBacktrack` | `boolean` | `true` | When `true`, auto-detects function boundaries — if the address lands mid-function, backtracks to the real function start. Set to `false` to disable. **(v3.7.3)** |
| `output` | `{ path? }` | — | JSON output file path. |

### `hexcore.disasm.liftToIR`

Lift machine code to LLVM IR using the Remill engine. Requires a loaded binary with disassembly data.

```json
{
  "cmd": "hexcore.disasm.liftToIR",
  "args": {
    "address": "0x401000",
    "count": 100
  },
  "output": { "path": "lifted-ir.ll" },
  "timeoutMs": 120000
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `address` | `string` | *(required)* | Start virtual address as `0x`-prefixed hex string. |
| `count` | `number` | `50` | Number of instructions to lift. |
| `output` | `{ path? }` | — | Output file path for LLVM IR text. |

### `hexcore.rellic.decompile` *(Deprecated — use `hexcore.helix.decompile`)*

Decompile binary to pseudo-C in one step: lifts machine code via Remill, then decompiles the LLVM IR via Rellic. This is the recommended single-shot decompile command for pipelines.

```json
{
  "cmd": "hexcore.rellic.decompile",
  "args": {
    "address": "0x401000",
    "count": 200,
    "optimizerStep": "llvm-passes",
    "optimizationPasses": ["dce", "constfold"]
  },
  "output": { "path": "decompiled.c" },
  "timeoutMs": 180000
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `address` | `string` | *(required)* | Start virtual address as `0x`-prefixed hex string. |
| `count` | `number` | `100` | Number of instructions to lift before decompiling. |
| `optimizerStep` | `string` | `'llvm-passes'` | Optimizer: `'none'`, `'llvm-passes'` (DCE + ConstFold), `'souper'` (not yet implemented — hook for v3.8). **(v3.7.1)** |
| `optimizationPasses` | `string[]` | — | Specific LLVM passes to run: `'dce'`, `'constfold'`, `'simplifycfg'`. Only used when `optimizerStep` is `'llvm-passes'`. **(v3.7.1)** |
| `output` | `{ path? }` | — | Output file path for pseudo-C code. |

**Returns:**

```json
{
  "success": true,
  "code": "// Pseudo-C generated by HexCore Rellic\nvoid * lifted_...",
  "functionCount": 1,
  "instructionsLifted": 87,
  "generatedAt": "2026-02-21T10:30:00.000Z"
}
```

> **Note:** Rellic is **deprecated** as of v3.7.0. Use `hexcore.helix.decompile` or `hexcore.helix.decompileIR` instead. Rellic remains functional for backward compatibility but produces lower-quality output compared to Helix.

### `hexcore.rellic.decompileIR` *(Deprecated — use `hexcore.helix.decompileIR`)*

Decompile pre-lifted LLVM IR text to pseudo-C. Use this when you already have IR from `liftToIR` and want to decompile it separately.

```json
{
  "cmd": "hexcore.rellic.decompileIR",
  "args": {
    "irText": "; ModuleID = ...\ndefine void @lifted_..."
  },
  "output": { "path": "decompiled-from-ir.c" },
  "timeoutMs": 120000
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `irText` | `string` | *(required)* | LLVM IR text to decompile. |
| `output` | `{ path? }` | — | Output file path for pseudo-C code. |

### `hexcore.helix.decompile`

Decompile binary to high-quality pseudo-C in one step using the **Helix MLIR pipeline**: lifts machine code via Remill, then runs the full MLIR pass pipeline (RemillToHelixLow → HelixLowToHigh → StructureControlFlow → RecoverCallingConvention → PseudoCEmit). Produces significantly better output than Rellic — structured control flow, named parameters, struct field recovery, and a confidence score.

```json
{
  "cmd": "hexcore.helix.decompile",
  "args": {
    "address": "0x14142FE90",
    "count": 150
  },
  "output": { "path": "decompiled.helix.c" },
  "timeoutMs": 180000
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `address` | `string` | *(required)* | Start virtual address as `0x`-prefixed hex string. |
| `count` | `number` | `150` | Number of instructions to lift before decompiling. |
| `optimizeIR` | `boolean` | `true` | When `false`, skips MLIR optimization passes and emits IR as-is. Useful for debugging pass pipeline issues. **(v3.7.3)** |
| `autoBacktrack` | `boolean` | `true` | Auto-detects function boundaries and backtracks to the real function start if the address is mid-function. Set to `false` to disable. **(v3.7.3)** |
| `output` | `{ path? }` | — | Output file path for pseudo-C code. |

**Returns:**

```json
{
  "success": true,
  "code": "// sub_14142fe90 (0x14142fe90)\n// Confidence: 84.0% (High)\nint64_t sub_14142fe90(...) { ... }",
  "confidence": 84.0,
  "functionCount": 1,
  "generatedAt": "2026-03-10T10:58:00.000Z"
}
```

> **Note:** Helix requires LLVM IR from `liftToIR` internally. For large functions, prefer the two-step variant (`liftToIR` + `helix.decompileIR`) so you can inspect the IR separately.

---

### `hexcore.helix.decompileIR`

Decompile a pre-lifted LLVM IR file to pseudo-C via the Helix MLIR pipeline. Use this as the second step of a two-step pipeline where the first step is `hexcore.disasm.liftToIR`. The `irPath` argument must point to the `.ll` file produced by `liftToIR` — use the same path as the `output.path` of that step (resolved from `outDir`).

```json
{
  "cmd": "hexcore.helix.decompileIR",
  "args": {
    "irPath": "hexcore-reports\\my-output\\bone_pos_calc.ll"
  },
  "output": { "path": "bone_pos_calc.helix.c" },
  "timeoutMs": 180000
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `irPath` | `string` | *(required)* | Path to a `.ll` LLVM IR file. Relative paths are resolved from the workspace root. Absolute paths are used as-is. |
| `output` | `{ path? }` | — | Output file path for pseudo-C code. Relative to `outDir`. |

> **Important:** `irPath` must be the **path to the `.ll` file**, not inline IR text. The pipeline runner always sets `options.file` to the binary target, so `irPath` is the dedicated arg for specifying the IR file path.

**Two-step pipeline example (recommended):**

```json
{
  "file": "C:\\samples\\target.exe",
  "outDir": "C:\\reports\\helix",
  "continueOnError": true,
  "steps": [
    {
      "cmd": "hexcore.disasm.liftToIR",
      "args": { "address": "0x14142FE90", "count": 150 },
      "output": { "path": "bone_pos_calc.ll" },
      "timeoutMs": 120000
    },
    {
      "cmd": "hexcore.helix.decompileIR",
      "args": { "irPath": "C:\\reports\\helix\\bone_pos_calc.ll" },
      "output": { "path": "bone_pos_calc.helix.c" },
      "timeoutMs": 180000
    }
  ]
}
```

> **Tip:** Use an absolute path for `irPath` when `outDir` is absolute — this avoids any workspace-root resolution ambiguity.

---

### `hexcore.strings.extract`
```json
{
  "cmd": "hexcore.strings.extract",
  "args": { "minLength": 5, "maxStrings": 50000 }
}
```

### `hexcore.elfanalyzer.analyze`
```json
{
  "cmd": "hexcore.elfanalyzer.analyze",
  "timeoutMs": 120000
}
```

### `hexcore.base64.decodeHeadless`
```json
{
  "cmd": "hexcore.base64.decodeHeadless",
  "timeoutMs": 90000
}
```

### `hexcore.hexview.dumpHeadless`
```json
{
  "cmd": "hexcore.hexview.dumpHeadless",
  "args": { "offset": 0, "size": 512 },
  "output": { "path": "header-dump.json" },
  "timeoutMs": 60000
}
```

### `hexcore.hexview.searchHeadless`
```json
{
  "cmd": "hexcore.hexview.searchHeadless",
  "args": { "pattern": "4D5A", "maxResults": 1000 },
  "output": { "path": "mz-search.json" },
  "timeoutMs": 120000
}
```

### `hexcore.debug.emulateFullHeadless`

Unified single-shot emulation: loads the binary, optionally configures STDIN and breakpoints, runs emulation up to the instruction budget, collects full state, and disposes the session.

> **Note on IPC Smart Sync:** Emulation of x64 and ARM64 ELFs occurs in an isolated Node.js Worker process. To ensure the headless pipeline has perfect visibility of dynamically allocated memory (for `__printf_chk`, `puts`, `getline`), HexCore uses an aggressive Smart Sync strategy that seamlessly mirrors the Worker's stack and heap back to the host engine prior to any API interception. This guarantees flawless automated solving of complex VMs.

```json
{
	"cmd": "hexcore.debug.emulateFullHeadless",
	"args": {
		"arch": "x64",
		"stdin": "flag{test}\\n",
		"maxInstructions": 500000,
		"breakpoints": ["0x401000", "0x401050"],
		"keepAlive": false,
		"permissiveMemoryMapping": false,
		"prngMode": "glibc",
		"prngSeed": 4919,
		"collectSideChannels": true,
		"memoryDumps": [
			{ "address": "0x600000", "size": 4096, "trigger": "end" }
		],
		"breakpointConfigs": [
			{ "address": "0x401000", "autoSnapshot": true, "dumpRanges": [{ "address": "0x600000", "size": 256 }] }
		]
	},
	"output": { "path": "emulation-result.json" },
	"timeoutMs": 300000
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file` | `string` | *(from job)* | Path to binary (PE/ELF/raw). Inherited from job-level `file` if omitted in args. |
| `arch` | `string` | auto-detect | Architecture: `x86`, `x64`, or `arm64`. Auto-detected from PE/ELF headers when omitted. |
| `stdin` | `string` | — | STDIN buffer content. Escape sequences (`\n`, `\t`, `\r`, `\\`) are decoded. |
| `maxInstructions` | `number` | `1000000` | Maximum instructions to execute before stopping. |
| `breakpoints` | `string[]` | — | Array of `0x`-prefixed hex address strings where execution pauses. |
| `keepAlive` | `boolean` | `false` | When `true`, preserves the emulation session after completion for subsequent commands. |
| `permissiveMemoryMapping` | `boolean` | `false` | When `true`, maps all segments with RWX permissions. Required for self-modifying VMs that jump to .rodata/.data. **(v3.7.1)** |
| `prngMode` | `string` | `'stub'` | PRNG implementation: `'glibc'` (344-state TYPE_3), `'msvcrt'` (LCG), `'stub'` (returns 0). **(v3.7.1)** |
| `prngSeed` | `number` | `1` | Initial seed for PRNG. Only used when `prngMode` is `'glibc'` or `'msvcrt'`. **(v3.7.1)** |
| `collectSideChannels` | `boolean` | `false` | When `true`, collects instruction counts per basic block, memory access patterns, and branch statistics. **(v3.7.1)** |
| `memoryDumps` | `array` | — | Array of `{ address, size, trigger }` objects. `trigger` is `'breakpoint'` or `'end'`. **(v3.7.1)** |
| `breakpointConfigs` | `array` | — | Array of `{ address, autoSnapshot?, dumpRanges? }` objects. When `autoSnapshot: true`, captures registers + stack + optional memory ranges at breakpoint, then continues. **(v3.7.1)** |
| `output` | `{ path? }` | — | JSON output file path. Parent directories are created recursively. |
| `quiet` | `boolean` | `false` | Suppress VS Code notification messages. |

**Returns** `FullEmulationResult`:

```json
{
	"file": "C:\\samples\\target.exe",
	"architecture": "x64",
	"fileType": "pe",
	"crashed": false,
	"state": {
		"isRunning": false,
		"isPaused": false,
		"currentAddress": "0x401100",
		"instructionsExecuted": 42350,
		"lastError": null
	},
	"registers": { "rax": "0x0", "rcx": "0x1", "rip": "0x401100" },
	"apiCalls": [
		{ "dll": "kernel32.dll", "name": "GetStdHandle", "returnValue": "0x7" }
	],
	"stdout": "Hello, World!\n",
	"memoryRegions": [
		{ "address": "0x400000", "size": 4096, "permissions": "r-x", "name": ".text" }
	],
	"generatedAt": "2025-01-15T10:30:00.000Z"
}
```

When emulation crashes, `crashed` is `true` and `crashError` contains the error message. All other fields are still populated with the state collected up to the crash point.

**Errors:**
- `emulateFullHeadless requires a "file" argument.` — `file` not provided.
- Propagates `DebugEngine.startEmulation` errors (file not found, unsupported format).

---

### `hexcore.debug.writeMemoryHeadless`

Write data to emulation memory. Requires an active emulation session (use `emulateFullHeadless` with `keepAlive: true` first, or the existing `emulateHeadless`).

```json
{
	"cmd": "hexcore.debug.writeMemoryHeadless",
	"args": {
		"address": "0x401000",
		"data": "SGVsbG8gV29ybGQ="
	},
	"output": { "path": "write-memory-result.json" },
	"timeoutMs": 30000
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `address` | `string` | *(required)* | Target memory address as `0x`-prefixed hex string. |
| `data` | `string` | *(required)* | Data to write — base64-encoded string or `0x`-prefixed hex string. |
| `output` | `{ path? }` | — | JSON output file path. |
| `quiet` | `boolean` | `false` | Suppress VS Code notification messages. |

**Returns:**

```json
{
	"address": "0x401000",
	"bytesWritten": 11,
	"generatedAt": "2025-01-15T10:30:00.000Z"
}
```

**Errors:**
- `No active emulation session.` — no session is active.
- `Invalid data format. Use base64 or 0x-prefixed hex.` — `data` is neither valid base64 nor `0x`-prefixed hex.

---

### `hexcore.debug.setRegisterHeadless`

Set a CPU register value. Requires an active emulation session.

```json
{
	"cmd": "hexcore.debug.setRegisterHeadless",
	"args": {
		"name": "rax",
		"value": "0xDEADBEEF"
	},
	"output": { "path": "set-register-result.json" },
	"timeoutMs": 30000
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `name` | `string` | *(required)* | Register name (e.g., `rax`, `rip`, `eax`, `x0`). |
| `value` | `string \| number` | *(required)* | Register value — `0x`-prefixed hex string or decimal number. |
| `output` | `{ path? }` | — | JSON output file path. |
| `quiet` | `boolean` | `false` | Suppress VS Code notification messages. |

**Returns:**

```json
{
	"register": "rax",
	"value": "0xdeadbeef",
	"architecture": "x64",
	"generatedAt": "2025-01-15T10:30:00.000Z"
}
```

**Errors:**
- `No active emulation session.` — no session is active.
- Propagates `DebugEngine.emulationSetRegister` error if register name is invalid for the current architecture.

---

### `hexcore.debug.setStdinHeadless`

Set the STDIN buffer for emulation. Requires an active emulation session.

```json
{
	"cmd": "hexcore.debug.setStdinHeadless",
	"args": {
		"input": "flag{my_secret}\\n"
	},
	"output": { "path": "set-stdin-result.json" },
	"timeoutMs": 30000
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `input` | `string` | *(required)* | STDIN content. Escape sequences (`\n`, `\t`, `\r`, `\\`) are decoded before setting the buffer. |
| `output` | `{ path? }` | — | JSON output file path. |
| `quiet` | `boolean` | `false` | Suppress VS Code notification messages. |

**Returns:**

```json
{
	"bytesSet": 16,
	"generatedAt": "2025-01-15T10:30:00.000Z"
}
```

**Errors:**
- `No active emulation session.` — no session is active.

---

### `hexcore.debug.disposeHeadless`

Dispose the active emulation session and free Unicorn engine resources. This command is idempotent — calling it without an active session returns success without error.

```json
{
	"cmd": "hexcore.debug.disposeHeadless",
	"output": { "path": "dispose-result.json" },
	"timeoutMs": 30000
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `output` | `{ path? }` | — | JSON output file path. |
| `quiet` | `boolean` | `false` | Suppress VS Code notification messages. |

**Returns:**

```json
{
	"disposed": true,
	"generatedAt": "2025-01-15T10:30:00.000Z"
}
```

---

### `hexcore.debug.searchMemoryHeadless` **(v3.7.3)**

Pattern search across emulated RAM. Requires an active emulation session (call `emulateHeadless` or `emulateFullHeadless` with `keepAlive: true` first).

```json
{
  "cmd": "hexcore.debug.searchMemoryHeadless",
  "args": {
    "pattern": "4D 5A ?? ??",
    "encoding": "hex",
    "regions": "all",
    "maxResults": 100
  },
  "output": { "path": "memory-search.json" },
  "timeoutMs": 60000
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `pattern` | `string` | *(required)* | Search pattern — format depends on `encoding`. |
| `encoding` | `string` | `"hex"` | `"hex"` (space-separated hex bytes, `??` wildcard), `"ascii"`, or `"utf16"`. |
| `regions` | `string` | `"all"` | Memory regions to search: `"all"`, `"heap"`, `"stack"`, or an explicit range `"0xSTART-0xEND"`. |
| `maxResults` | `number` | `100` | Maximum matches to return. |
| `output` | `{ path? }` | — | JSON output file path. |
| `quiet` | `boolean` | `false` | Suppress VS Code notification messages. |

**Returns:**

```json
{
  "success": true,
  "pattern": "4D 5A ?? ??",
  "encoding": "hex",
  "regionsSearched": "all",
  "totalMatches": 2,
  "matches": [
    { "address": "0x400000", "region": ".text", "size": 4 },
    { "address": "0x600000", "region": "heap",  "size": 4 }
  ]
}
```

**Errors:**
- `No active emulation session.` — no session is active.

**Aliases:** `hexcore.debug.searchMemory`, `hexcore.unicorn.searchMemory`, `hexcore.unicorn.searchMemoryHeadless`

---

### `hexcore.pipeline.composeReport`
```json
{
  "cmd": "hexcore.pipeline.composeReport",
  "args": { "notes": "ANALYST_NOTES.md" },
  "output": { "path": "FINAL_REPORT.md", "format": "md" },
  "timeoutMs": 60000
}
```

### Output Override

Any step can specify custom output path and format:
```json
{
  "cmd": "hexcore.filetype.detect",
  "output": {
    "path": "01-filetype.md",
    "format": "md"
  }
}
```
Relative output paths are resolved from `outDir`.

---

## Pipeline Execution Details

- Every step runs in headless mode (`quiet: true`) and receives `file`.
- If a step does not define `output`, HexCore auto-generates output files inside `outDir`.
- Before each step, the runner verifies command registration and attempts to activate the owner extension when needed.
- If command activation fails, `hexcore-pipeline.status.json` includes owner-extension diagnostics.
- `outputPath` is only reported for steps that actually request/provide output.
- Commands marked as interactive are blocked with a clear error.

---

## Troubleshooting

### `Command '...' not found`
- Confirm you are on HexCore v3.5.2+.
- Run `hexcore.pipeline.listCapabilities` and confirm the command appears.
- Reload window after update to refresh extension activation.

### `Command is not declared in pipeline capability map`
- Use the exact command name from capabilities export.
- Check the alias table above.

### `Command is not headless-safe for pipeline`
- Expected for interactive commands (file pickers/prompts/UI-only actions).
- Use the headless variant if one exists (e.g., `searchStringHeadless` instead of `searchString`).
- For the debugger, use headless variants: `snapshotHeadless`, `restoreSnapshotHeadless`, `exportTraceHeadless`.
- For single-shot emulation, use `emulateFullHeadless` (alias: `hexcore.debug.run`).

### `No active emulation session.`
- `writeMemoryHeadless`, `setRegisterHeadless`, `setStdinHeadless`, and `searchMemoryHeadless` require an active session.
- Start a session first with `emulateFullHeadless` (set `keepAlive: true`) or the existing `emulateHeadless`.

### `timed out after ...`
- Increase `timeoutMs` for heavy binaries.
- Lower `maxFunctions` and `maxFunctionSize` on `analyzeAll`.
- Helix decompile can take up to 90s for large functions — use `timeoutMs: 180000` or higher.

### Missing report file
- Check step status in `hexcore-pipeline.status.json`.
- If step failed/timed out, output file will not be created.

### `hexcore.helix.decompileIR` fails with "file not found"
- The `irPath` must point to a `.ll` file that exists **before** this step runs.
- Ensure `liftToIR` ran successfully (check its status in `hexcore-pipeline.status.json`).
- Prefer absolute paths for `irPath` (e.g. `"C:\\reports\\helix\\bone_pos_calc.ll"`) to avoid workspace-root resolution issues.
- Relative `irPath` values are resolved from the workspace root folder, not from `outDir`.

---

## Helix MLIR Decompiler — Common Gotchas

### Correct command names (Helix)

| Task | Correct command | Wrong command |
|------|-----------------|---------------|
| Decompile pre-lifted `.ll` file | `hexcore.helix.decompileIR` | ~~`hexcore.helix.decompile`~~ |
| Lift + decompile in one step | `hexcore.helix.decompile` | — |
| Interactive panel | `hexcore.helix.decompileUI` | — |

### PE32 emulation — session lifecycle

Always call `disposeHeadless` between emulation attempts:

```json
{ "cmd": "hexcore.debug.disposeHeadless" },
{ "cmd": "hexcore.debug.emulateFullHeadless", "args": { ... } }
```

Skipping `disposeHeadless` causes `UC_ERR_MAP (code 11)` — Unicorn rejects re-mapping existing memory regions.

### PE32 stack (`UC_ERR_READ_UNMAPPED`)

`permissiveMemoryMapping: true` controls section R/W/X permissions but does NOT create a stack region. If ESP points to an unmapped address (e.g., `0x800eeffc`), redirect it before emulation:

```json
[
  { "cmd": "hexcore.debug.emulateHeadless", "args": { "file": "target.exe", "arch": "x86" } },
  { "cmd": "hexcore.debug.setRegisterHeadless", "args": { "register": "ESP", "value": "0x5f00000" } }
]
```
