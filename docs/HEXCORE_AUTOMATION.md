# HexCore Automation — v3.5.4

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
    { "cmd": "hexcore.peanalyzer.analyze" },
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
| `hexcore.peanalyzer.analyze` | 120s | PE header, imports, exports, sections, anomalies | PE only |
| `hexcore.elfanalyzer.analyze` | 120s | ELF header, sections, segments, symbols, security mitigations (RELRO, NX, PIE, Canary) | ELF only |
| `hexcore.base64.decodeHeadless` | 90s | Detect and decode Base64 strings in binary files | All |
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

### Hex Viewer

| Command | Timeout | Description | Arch |
|---------|---------|-------------|------|
| `hexcore.hexview.dumpHeadless` | 60s | Extract hex dump of byte range (offset + size) with base64 raw output | All |
| `hexcore.hexview.searchHeadless` | 120s | Search hex pattern in file with streaming (64KB chunks + overlap) | All |

### Debugger (Headless)

| Command | Timeout | Description | Arch |
|---------|---------|-------------|------|
| `hexcore.debug.emulateFullHeadless` | 300s | Unified single-shot emulation (load → configure → run → collect → dispose) | x86, x64, ARM64 |
| `hexcore.debug.writeMemoryHeadless` | 30s | Write data to emulation memory (requires active session) | x86, x64, ARM64 |
| `hexcore.debug.setRegisterHeadless` | 30s | Set CPU register value (requires active session) | x86, x64, ARM64 |
| `hexcore.debug.setStdinHeadless` | 30s | Set STDIN buffer for emulation (requires active session) | x86, x64, ARM64 |
| `hexcore.debug.disposeHeadless` | 30s | Dispose emulation session — idempotent, safe to call without active session | x86, x64, ARM64 |
| `hexcore.debug.snapshotHeadless` | 60s | Save emulation snapshot (requires active session) | x86, x64, ARM64 |
| `hexcore.debug.restoreSnapshotHeadless` | 60s | Restore emulation snapshot (requires saved snapshot) | x86, x64, ARM64 |
| `hexcore.debug.exportTraceHeadless` | 60s | Export API/libc call trace as JSON | x86, x64, ARM64 |

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
| `hexcore.pipeline.runJob` | Recursive pipeline invocation is not supported |

---

## Command Aliases

| Alias | Resolves To |
|-------|-------------|
| `hexcore.hash.file` | `hexcore.hashcalc.calculate` |
| `hexcore.hash.calculate` | `hexcore.hashcalc.calculate` |
| `hexcore.pe.analyze` | `hexcore.peanalyzer.analyze` |
| `hexcore.elf.analyze` | `hexcore.elfanalyzer.analyze` |
| `hexcore.hex.dump` | `hexcore.hexview.dumpHeadless` |
| `hexcore.hex.search` | `hexcore.hexview.searchHeadless` |
| `hexcore.disasm.open` | `hexcore.disasm.openFile` |
| `hexcore.debug.emulate.full` | `hexcore.debug.emulateFullHeadless` |
| `hexcore.debug.run` | `hexcore.debug.emulateFullHeadless` |

---

## Architecture Notes

- **Arch-agnostic commands** (filetype, hash, entropy, strings, YARA, IOC, base64) operate on raw bytes — no architecture dependency.
- **Disassembler** auto-detects architecture from ELF `e_machine` and PE `Machine` headers. Defaults to x64 for raw files.
- **buildFormula** uses x86/x64 register regex — ARM64 registers (x0-x30, sp, lr) are **not recognized**.
- **checkConstants** is architecture-neutral — it only compares numeric literals.
- **PE Analyzer** is PE-format only. Use `hexcore.elfanalyzer.analyze` for ELF binaries.
- **ELF Analyzer** is ELF-format only. TypeScript-pure parser, no native dependencies. Detects RELRO, NX, PIE, Stack Canary.
- **Minidump** supports x86/x64 Windows crash dumps only.

---

## Step Arguments

### `hexcore.disasm.analyzeAll`
```json
{
  "cmd": "hexcore.disasm.analyzeAll",
  "args": {
    "maxFunctions": 2500,
    "maxFunctionSize": 65536,
    "forceReload": true
  }
}
```

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
```json
{
  "cmd": "hexcore.disasm.searchStringHeadless",
  "args": { "query": "HTB{" }
}
```

### `hexcore.disasm.exportASMHeadless`
```json
{
  "cmd": "hexcore.disasm.exportASMHeadless",
  "args": { "functionAddress": "0x401000" }
}
```

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
		"keepAlive": false
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
- `writeMemoryHeadless`, `setRegisterHeadless`, and `setStdinHeadless` require an active session.
- Start a session first with `emulateFullHeadless` (set `keepAlive: true`) or the existing `emulateHeadless`.

### `timed out after ...`
- Increase `timeoutMs` for heavy binaries.
- Lower `maxFunctions` and `maxFunctionSize` on `analyzeAll`.

### Missing report file
- Check step status in `hexcore-pipeline.status.json`.
- If step failed/timed out, output file will not be created.
