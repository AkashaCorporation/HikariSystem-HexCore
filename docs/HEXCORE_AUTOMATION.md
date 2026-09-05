# HexCore Automation - v3.8.4 (Analysis Contract)

HexCore supports running analysis pipelines from workspace job files.

This document describes the `3.8.4` analysis-contract surface. The executable source of truth is `extensions/hexcore-disassembler/src/automationPipelineRunner.ts`; use `hexcore.pipeline.listCapabilities` and `hexcore.pipeline.validateJob` to verify an installed build.

Relevant integrated versions: disassembler `1.4.66`, HQL `0.3.1`, PE Analyzer `1.1.3`, common `1.3.0`, debugger `2.1.22`, Revenant `0.4.0`, Capstone `1.3.6`, Remill `0.5.4`, Unicorn `1.3.2`, Souper `0.2.2`, Strings `1.3.3`, Helix package `0.9.4-rc.1`, Elixir `1.0.4`, and Report Composer `1.0.14`.

For nonstandard LLVM installations, set `HEXCORE_PDBUTIL` to the intended
llvm-pdbutil executable before starting HexCore. PDB discovery no longer searches
a developer's Desktop. Missing tools are not proof that a PDB has no symbols.

### Lazy discovery contract (1.4.65)

`analyzeAll` JSON includes every function in the discovered index, including
`bodyStatus:lazy`; this is not a guarantee that discovery found every real function.
Its Markdown table is only the first 100 entries by address, not a ranking or a
complete index. Prefer JSON for agent enumeration and check the reported counts.

Lazy means a known boundary with deferred body decoding, not an absent function.
Select the indexed address for a bounded `disassembleAtHeadless` investigation,
then inspect `analysisClosure` and body completeness. Do not infer absence from
zero known callers/callees or no matches over unmaterialized bodies. `allowLazy`
and `minMaterializedRatio` are acceptance policy, not switches that force decoding.
Automatic critical-neighborhood materialization remains separate product work.

In 1.4.64, `jobStatus` queue-wide results expose `observationScope:queue-at-query-time`,
`terminalSnapshot:false`, `currentJobId`, `currentExecutionId` and `includesCurrentJob`.
Counts remain inclusive: a running status-query job legitimately contributes one.
Direct queries without pipeline context report `includesCurrentJob:null` (unknown).
Use the terminal `summary.queueSnapshot` for counts excluding the completed job.

### Evidence Interpretation (1.4.62 / Composer 1.0.14)

- `analyzeAll.status` describes completion under the declared policy. Inspect
  `analysisDepth`, `functionsMaterialized`, `partialFunctions`, and
  `materializedFunctionRatio` before using its results. Reconnaissance may be
  operationally `ok`; disassembly is never by itself negative security evidence.
- Security jobs should declare `minMaterializedRatio` for their intended scope
  or materialize a targeted function set and check each body's completeness.
  Do not choose a global ratio as a substitute for caller/consumer coverage.
- `refcountScan.inputQuality` checks the source SHA-256 against the nearest
  `.hexcore-meta/provenance.json` and walks recorded upstream statuses. Missing
  provenance, hash mismatch, incomplete ancestors, zero scanned functions, or
  Helix issue annotations give `status:partial`, `negativeEvidenceUsable:false`,
  and an inconclusive zero-match result. Raw source without provenance is also
  unverified. A qualified negative remains limited to this scanner's patterns.
- Composer parser agreement is `signal`, with `independentCorroboration:false`.
  Rejected IOC assertions remain available in original attachments and in a
  bounded table of rejection reasons. HQL adapter coverage is not correctness.
- Refcount schema v2: `findings` are `evidenceLevel:signal`, `proofStatus:unproven`.
  `confidenceKind:heuristic-pattern-score` and `severityKind:review-priority`
  explicitly qualify the legacy numeric/qualitative fields; neither is a
  vulnerability assessment. `observations` contains assertion/warning/termination
  calls with reachability and vulnerability status `not-assessed`. BUG_ON alone
  is not a finding and does not justify replacing an assertion with a return.
  `scanCoverage.status:partial` blocks qualified negative evidence even when
  upstream provenance is complete. Preprocessor, line-splicing, raw literals,
  unparsed source and line/function limits are not silently treated as complete.
- Session storage currently uses one `.hexcore_session.db` per binary directory.
  Keep independent targets in separate directories to preserve their sessions.

## How It Works

### Job File Naming

HexCore recognizes any file matching the pattern `*.hexcore_job.json`:

| File Name | Example | Use Case |
|-----------|---------|----------|
| `.hexcore_job.json` | `.hexcore_job.json` | **Canonical** — default for `Run Job`, auto-detected first |
| `{name}.hexcore_job.json` | `sotr-triage.hexcore_job.json` | **Named** — auto-detected by watcher + queue picker |

Agents can create multiple named jobs in a workspace. Root-level jobs are discovered at startup; the recursive watcher handles later create/change events anywhere under the workspace:

```
my-project/
├── .hexcore_job.json                  ← canonical (Run Job finds this first)
├── strings-deep.hexcore_job.json      ← named job (auto-detected)
├── disasm-export.hexcore_job.json     ← named job (auto-detected)
└── queue-launcher.hexcore_job.json    ← orchestrator that queues the others
```

### Execution

- **Startup auto-run:** HexCore discovers root-level canonical and named jobs.
- **Watcher auto-run:** HexCore watches `**/*.hexcore_job.json` recursively and runs automatically on later create/change events.
- Watch events use a 350 ms debounce, content deduplication, a 2500 ms content-hash cooldown, and an output-directory loop breaker.
- **Manual run:** `Run HexCore Automation Job` (`hexcore.pipeline.runJob`) — finds canonical `.hexcore_job.json` first, then any named `*.hexcore_job.json`.
- **Queue job:** `Queue Job` (`hexcore.pipeline.queueJob`) — file picker shows ALL `*.hexcore_job.json` files in workspace. **(v3.8.0)**
- **Cancel job:** `Cancel Queued Job` (`hexcore.pipeline.cancelJob`) — cancel by job ID. **(v3.8.0)**
- **Job status:** `Show Job Queue Status` (`hexcore.pipeline.jobStatus`) — view all queued/running/completed jobs. **(v3.8.0)**
- Generate from preset: `Create HexCore Job from Preset` (`hexcore.pipeline.createPresetJob`).
  - Built-in presets: **quick triage**, **full static**, **ctf reverse**.
- Save as reusable profile: `Save Current Job as Workspace Profile` (`hexcore.pipeline.saveJobAsProfile`).
  - Stored in `.hexcore_profiles.json` per workspace.
- Validate before running: `Validate HexCore Automation Job` (`hexcore.pipeline.validateJob`).
- Batch validate: `Validate HexCore Jobs in Workspace` (`hexcore.pipeline.validateWorkspace`) — scans `**/*.hexcore_job.json`.
- Diagnose health: `Run HexCore Pipeline Doctor` (`hexcore.pipeline.doctor`).
- Schema validation via `hexcore-disassembler/schemas/hexcore-job.schema.json`.
- Job execution writes `hexcore-pipeline.log` and `hexcore-pipeline.status.json` to `outDir`.
- Execution has a mandatory preflight. Validation errors write `hexcore-pipeline.validation.json` and a terminal error status; no command is dispatched.

### Analysis Center Investigation Jobs (3.8.4)

The Analysis Center separates three persistence layers:

- `Analyze All` stores the current function index in the binary's
  `.hexcore_session.db`.
- Investigations and starred findings are stored in the same session database.
- The `Jobs` tab converts a starred finding into a shareable
  `hexcore-jobs/<name>.hexcore_job.json` pipeline.

The generated job resolves the finding to an owning function and runs Analyze
All, the evidence search, Remill lifting, and Helix decompilation. Retained
artifacts are written to `hexcore-reports/investigations/<name>/` as:

```text
<name>.references.json
<name>.ll
<name>.helix.c
```

The Analyze All step sets `expectOutput:false`: its function index already
lives in `.hexcore_session.db`, avoiding a duplicate JSON artifact that can be
tens of megabytes. The Helix step sets `allowPartial:true`; low-confidence or
honesty-capped pseudo-C is retained with terminal `partial` status rather than
being mislabeled as `ok` or discarded as a hard failure. Provenance records the
`.ll` content hash as an input of the `.helix.c` artifact and assigns media
types from the actual file extension.

Creating the file triggers the normal recursive watcher and queues one run.
Investigation jobs live in a subfolder, so they are not part of root-only
startup auto-run. Another analyst or agent can rerun one through `Run Job` or
`Queue Job`; the job remains subject to normal validation, target isolation,
output containment, and provenance rules. Targets inside the workspace and the
output directory are stored relative to `hexcore-jobs/` so the definition can
move with the workspace; an external target retains its absolute path.

### Output Directory Security

By default, `outDir` must resolve inside either a workspace folder or the directory containing the job file. Each step's `output.path` must also remain strictly inside `outDir`; absolute step-output paths and `..` escapes are rejected.

Set `hexcore.pipeline.allowExternalOutDir` to `true` only when the user deliberately needs an external destination. Job files can auto-run, so this setting expands their write authority. Windows containment is case-insensitive: drive-letter or segment-case differences do not make an in-workspace path external.

## Example Job

```json
{
  "file": "C:\\samples\\target.exe",
  "outDir": ".\\hexcore-reports\\target",
  "priority": "normal",
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

The top-level `continueOnError` value is inherited by every step that does not set its own value. A step-level value always wins.

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
      "cmd": "hexcore.helix.decompileIR",
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
      "cmd": "hexcore.helix.decompileIR",
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
| `hexcore.filetype.detect` | 60s | Magic-byte file type detection (43 signatures across 11 categories) | All |
| `hexcore.hashcalc.calculate` | 90s | MD5, SHA1, SHA256, SHA512 hashes | All |
| `hexcore.entropy.analyze` | 90s | Shannon entropy analysis, packing detection | All |
| `hexcore.strings.extract` | 120s | ASCII/Unicode string extraction with categorization | All |
| `hexcore.strings.extractAdvanced` | 180s | Confidence-scored, deduplicated and section-attributed deobfuscation with bounded output budgets. Optional evidence chains decode hex to ASCII to Base64 and probe JSON without hiding intermediate transformations. | All |
| `hexcore.peanalyzer.analyze` | 120s | PE headers, sections, embedded execution manifest, DLL-characteristics mitigations, and Windows capability signals | PE only |
| `hexcore.pe.extractSection` | 120s | Extract one named PE section as a bounded binary artifact for later pipeline steps | PE only |
| `hexcore.crypto.rc4` | 120s | Apply bounded passive RC4 to an explicit input artifact; supports UTF-8, hex, Base64, or byte-array keys | All |
| `hexcore.disasm.analyzePEHeadless` | 120s | **Deep PE analysis**: typed imports (180+ API signatures), exports, sections, TLS/Debug/CLR/DelayImport, security indicators, category summary | PE only |
| `hexcore.elfanalyzer.analyze` | 120s | ELF header, sections, segments, symbols, security mitigations (RELRO, NX, PIE, Canary) (legacy) | ELF only |
| `hexcore.disasm.analyzeELFHeadless` | 120s | **Deep ELF analysis**: program headers, full symtab/dynsym, all relocations, dynamic entries, .ko modinfo, symbol stats | ELF only |
| `hexcore.base64.decodeHeadless` | 90s | Detect and decode Base64 strings with **confidence scoring** (entropy, context filters, categories) | All |
| `hexcore.yara.scan` | 180s | YARA rule scanning with threat scoring. Scans the bundled rule set by default (7 built-in + 7 AntiAnalysis `.yar` = ~14 rules). The 76k+ DefenderYara rule set is **not bundled**; supply it (see note below) and pass `categories`/`loadEssentials` to scan against it headlessly. | All |
| `hexcore.yara.updateRules` | 60s | Reload YARA rule files | N/A |
| `hexcore.ioc.extract` | 120s | IOC extraction across 12 categories: URL, email, IPv4, IPv6, domain, registry key, file path, named pipe, mutex/GUID, hash (MD5/SHA1/SHA256), user-agent, crypto wallet. Binary-aware noise reduction, dedup, optional SQLite backend (auto at >=64MB or >=20k matches). | All |

### Disassembly & Analysis

| Command | Timeout | Description | Arch |
|---------|---------|-------------|------|
| `hexcore.disasm.analyzeAll` | 180s | Deep analysis: prolog scan, function discovery, xrefs | x86, x64, ARM, ARM64, MIPS |
| `hexcore.disasm.windowsFilesystemAuditHeadless` | 300s | Evidence-gated PE filesystem boundary chain and owner pivots | x86, x64 PE |
| `hexcore.disasm.detectPacker` | 60s | Detect UPX, Themida, VMProtect, ASPack, Enigma, MPRESS, or unknown packing evidence. Detection only: no unpacking and no external UPX dependency. | All |
| `hexcore.disasm.buildFormula` | 90s | Symbolic expression extraction from instruction chains | x86, x64, ARM, ARM64 |
| `hexcore.disasm.checkConstants` | 90s | Validate numeric annotations against instruction immediates | All |
| `hexcore.disasm.searchStringHeadless` | 120s | Search string references with termination/reference/lookup-table evidence and an optional confidence gate | All |
| `hexcore.disasm.exportASMHeadless` | 180s | Export disassembly to file (headless variant) | All |
| `hexcore.disasm.disassembleAtHeadless` | 120s | Disassemble a paged instruction count or exact `[address,endExclusive)` byte range with reach/crossing evidence | x86, x64, ARM, ARM64, MIPS |
| `hexcore.disasm.liftToIR` | 120s | Lift machine code to LLVM IR via Remill engine | x86, x64 |
| `hexcore.rellic.decompile` | 180s | Legacy compatibility surface. Rellic is disabled for new development; use Helix. | x86, x64 |
| `hexcore.rellic.decompileIR` | 120s | Legacy compatibility surface for pre-lifted IR; use Helix. | x86, x64 |
| `hexcore.helix.decompile` | 180s | Decompile a **native** binary through Remill and the Helix MLIR pipeline. Managed inputs return an honesty marker instead of fake native pseudo-C. | x86, x64; experimental ARM64 route |
| `hexcore.helix.decompileIR` | 180s | Decompile a pre-lifted `.ll` file through Helix; pass the producer path in `irPath`. | IR produced by a supported lift |
| `hexcore.revenant.decompile` | 180s | Recover C# from classic CLR PE or a supported .NET single-file apphost via the bundled ICSharpCode.Decompiler route. | Managed .NET |
| `hexcore.revenant.decompileIL` | 180s | Recover IL from classic CLR PE or a supported .NET single-file apphost. | Managed .NET |
| `hexcore.hql.scanHeadless` | 180s | Decompile one or more functions and evaluate semantic signatures over Helix HAST. | Helix-supported targets / IR |
| `hexcore.souper.optimize` | 60s | Optimize LLVM IR with Souper/Z3. Intended for explicit `.ll` experiments, MBA, crypto, and bitwise-heavy code. | LLVM IR |
| `hexcore.constraints.solveHeadless` | 300s | Solve bounded Int/BitVec constraints with Z3 and return concrete models plus solver provenance. | JSON / SMT-LIB assertions |
| `hexcore.extractStructInfo` | 30s | Export BTF/DWARF struct and function type information from the loaded ELF analysis. | ELF with BTF or DWARF |
| `hexcore.disasm.rttiScanHeadless` | 120s | Scan PE binary for MSVC RTTI Type Descriptors, returns class names and offsets **(v3.7.3)** | PE only |
| `hexcore.disasm.searchBytesHeadless` | 120s | AOB scan with wildcard support — finds byte patterns across the entire binary **(v3.7.3)** | All |
| `hexcore.disasm.extractStrings` | 180s | Section-filtered string extraction with PE/ELF section selection **(v3.7.4)** | All |
| `hexcore.disasm.renameFunction` | 10s | Rename a function in the session DB — propagates to all call sites **(v3.7.4)** | All |
| `hexcore.disasm.renameVariable` | 10s | Rename a variable within a function scope in the session DB **(v3.7.4)** | All |
| `hexcore.disasm.retypeVariable` | 10s | Change variable type in the session DB — propagates to Helix output **(v3.7.4)** | All |
| `hexcore.disasm.retypeFunction` | 10s | Change function return type in the session DB **(v3.7.4)** | All |
| `hexcore.disasm.setBookmark` | 10s | Set a named bookmark at an address in the session DB **(v3.7.4)** | All |
| `hexcore.disasm.getSessionDbPath` | 10s | Returns the path to the `.hexcore_session.db` for the current binary **(v3.7.4)** | All |

`hexcore.hql.scanFunction` and `hexcore.elfanalyzer.analyzeActive` are registered but interactive-only. They are not substitutes for the headless commands in jobs.

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
| `hexcore.debug.disassembleMemoryHeadless` | 120s | Disassemble bytes directly from the active debugger memory map | x86, x64, ARM64 |
| `hexcore.debug.decompileMemoryHeadless` | 300s | Read live memory, lift it with Remill, and decompile it with Helix in a killable child process without a derived executable. Set `retainIr:true` to preserve `<output.path>.ll` before Helix runs; results include the IR byte count and SHA-256. | x86, x64, ARM64 |
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
- `hexcore.debug.continueHeadless` uses `maxSteps`; `maxInstructions` belongs to the single-shot `emulateFullHeadless` command. Optional `terminalAddresses` accepts up to 256 unsigned 64-bit address strings and `terminalKind` labels the expected stop. A deliberate sentinel fetch is returned as `ok`, while the observed backend fault remains under `expectedTerminalFault` for auditability.
- To start at a known function or unpacked payload, create a keep-alive session with `emulateHeadless`, write the architecture's program counter with `setRegisterHeadless` (`rip`, `eip`, or `pc`), then call `continueHeadless`. Program-counter writes update both Unicorn and the logical session address used by continue/step.

### Emulator — Project Azoth / Elixir (v3.8.0) 🜇

Clean-room Rust+C++23 dynamic analysis engine that replaces Qiling as HexCore's default emulation path. Activated via the `hexcore.emulator` setting (`"azoth"`, `"debugger"`, or `"both"` — default `"both"`). Each command runs in a forked system Node.js subprocess (not in-host) to bypass Electron's Arbitrary Code Guard (ACG) — see `docs/ELIXIR_VSCODE_WORKER_PATTERN.md`.

| Command | Timeout | Description | Arch |
|---------|---------|-------------|------|
| `hexcore.elixir.version` | — | Show the native Elixir engine version string (interactive toast). Not pipeline-safe. | n/a |
| `hexcore.elixir.smokeTestHeadless` | 30s | Verify the native `.node` loaded and capability surface is exposed. Returns the legacy native `version` plus explicit `wrapperVersion`, `nativeVersion`, and `versionAligned`; wrapper and native use independent release clocks. | n/a |
| `hexcore.elixir.emulateHeadless` | 600s | Full emulation run: load PE32+ → `run(entry, 0n)` → collect API calls + stop reason. Returns `{file, entry, runStart, stopReason, apiCallCount, apiCalls, apiCallsPath, apiCallsTotal, warning}` — `runStart` is the actual start address used (= `entry` unless `startVa` was set); `warning` is non-null when `AddressOfEntryPoint==0` and no `startVa` was given (packed-PE hint). When the API-call log is large, the full list is spilled to a `<output-base>.apicalls.json` companion (`apiCallsPath` points to it; `apiCalls` then holds a capped preview, `apiCallsTotal` the true count). **Accepts an optional `startVa` (start-address override, see the args table — essential for packed PEs) and an optional `oracle` arg that switches it to AI-driven mode (see "Oracle Hook" below). ELF targets are deliberately gated to HexCore Debugger until the Azoth loader supports them.** | PE32+ x86_64 |
| `hexcore.elixir.stalkerDrcovHeadless` | 600s | Same as emulate but with Stalker basic-block tracing enabled. Writes DRCOV v2 binary (IDA Lighthouse format) to `output.path.drcov`. Returns `{file, entry, stopReason, blockCount, drcovBytes}`. | PE32+ x86_64 |
| `hexcore.elixir.snapshotRoundTripHeadless` | 60s | Load binary, save emulator snapshot via `snapshotSave()`, restore via `snapshotRestore()`. Returns `{file, entry, snapshotBytes, restored}`. Verifies snapshot subsystem end-to-end. **Runs IN-HOST (no worker fork) — it loads + snapshots but never calls `run()`/`uc_emu_start`, so ACG does not apply; uses a fixed 100k cap and ignores the `maxInstructions` arg.** | PE32+ x86_64 |

**Args for emulateHeadless / stalkerDrcovHeadless / snapshotRoundTripHeadless:**

| Arg | Type | Default | Description |
|-----|------|---------|-------------|
| `file` | string | — **required** | Path to PE or ELF binary. `binaryPath` is also accepted as an alias. |
| `maxInstructions` | number | `1_000_000` | Instruction cap for the emulation run. (Not used by snapshot command.) |
| `startVa` | string\|number | — | **(v3.8.x)** *(emulate / stalker)* Override the run **start address** (`"0x…"` hex or decimal). By default the run starts at `load()`'s entry — but on a **packed/protected PE with `AddressOfEntryPoint == 0`** that resolves to `ImageBase` (the non-executable PE header) and the run faults at **0 instructions** (`UC_ERR_FETCH_PROT`). Set `startVa` to the **TLS-callback VA** (the real protector stub, from `IMAGE_DIRECTORY_ENTRY_TLS` / `AddressOfCallBacks`) to start there instead. When `AOE==0` and no `startVa` is given, the result carries a `warning` explaining this. The result also echoes `runStart`. |
| `verbose` | boolean | `false` | Stream additional trace lines to the Elixir output channel. **Only honored by `emulateHeadless`; `stalkerDrcovHeadless` and `snapshotRoundTripHeadless` hardcode it off and ignore the arg.** |
| `output.path` | string | — | Write JSON result to this path. For `stalkerDrcovHeadless`, a `.drcov` variant is written alongside (or replaces `.json` with `.drcov`). For `emulateHeadless`, an `.apicalls.json` companion may be written alongside (see its return). |
| `oracle` | object | — | *(optional, `emulateHeadless` only)* Enables the Project Pythia AI-oracle pause/resume run. See "Oracle Hook" below. |

**stopReason shape:** `{ kind: "Exit" | "InsnLimit" | "Error" | "User", address: string, instructionsExecuted: number, message: string }`. (Under the Oracle Hook, `run()` can also stop with `kind: "breakpoint"`.)

**Oracle Hook (Project Pythia) — the `oracle` arg on `emulateHeadless` (v3.9.0-preview.oracle.azoth):**

This is the path for driving **obfuscated / anti-debug / VM-protected** targets. When `emulateHeadless` is given an `oracle` object, it switches from a straight run to an AI-oracle-driven loop: the worker installs **native breakpoints** (`breakpointAdd`), and each time PC reaches one the engine pauses (`run()` returns `stopReason.kind === "breakpoint"`), asks an external **Pythia** decision process (spawned over stdio) what to do — e.g. patch a register or memory value to defeat an anti-debug / integrity / VM check — applies it (`regWrite`/`memWrite`), single-steps past the breakpoint (`runN(pc, 0n, 1n)`), re-installs it, and resumes. All register/memory access happens in-process inside the worker; the parent only receives the final summary.

| `oracle` field | Type | Description |
|----------------|------|-------------|
| `pythiaRepoPath` | string | Path to the Pythia repo (the decision process spawned over stdio). **Required** to enable the oracle op. |
| `triggers` | array | `{ kind, value, reason? }[]` — the breakpoint triggers Pythia reasons about. **Required and non-empty** to enable. |
| `pythiaNodeBin` | string | *(optional)* Node binary used to spawn Pythia. |
| `pythiaSpawnArgs` | string[] | *(optional)* Extra args for the Pythia process. |
| `pauseTimeoutMs` | number | *(optional)* Max wait for a Pythia decision per pause. |

When the oracle op runs, the result gains an `oracle` block — `{ pauseCount, patchesApplied, totalCostUsd, decisions }` — alongside the usual `{file, entry, stopReason, apiCallCount, apiCalls, apiCallsTotal}`. Wiring lives in `worker/oracleAdapter.js`; the op is selected automatically when `oracle.pythiaRepoPath` + a non-empty `oracle.triggers` are present (otherwise a plain emulate runs).

**Full native instrumentation surface (beyond the 5 wrapped commands):** the `.node` exposes a Frida-style API typed in `extensions/hexcore-elixir/index.d.ts` — `Emulator.{memMap, memRead, memWrite, regRead, regWrite, breakpointAdd/Del/Clear, runN, interceptorAttach/Detach, stalkerFollow/Unfollow/exportDrcov, snapshotSave/Restore}` plus standalone `Interceptor` and `Stalker` classes. **Register access is by NUMERIC Unicorn `UC_X86_REG_*` id, NOT name** (e.g. RIP=41, RAX=35, RSP=44) — Elixir rejects register-name strings. Drive these from a forked worker (never in-host for anything that calls `run()`/`runN()`) to build custom instrumentation or Oracle triggers.

**Worker process behaviour:**

- Commands spawn `worker/emulateWorker.js` via `child_process.fork`. The worker uses the system Node.exe (PATH-resolved or `findSystemNode()` fallback) rather than Electron, because `uc_emu_start` crashes the Extension Host with `STATUS_ACCESS_VIOLATION` under ACG.
- Worker IPC uses `process.send({ok:true/false, kind, ...})`. After sending, the worker waits for the disconnect to drain before exiting (fixes lost messages on large payloads like stalker drcov blobs).
- Worker 10-second IPC handshake timeout. Host-side run timeout is per-command (600s for emulate/stalker, 60s for snapshot).

**Activation gating (pipeline-safe):**

The pipeline runner's emulator-gate check maps each `hexcore.elixir.*` command to the `"azoth"` setting value. If `hexcore.emulator` is `"debugger"`, elixir steps are marked `skipped` (not `error`); if `"both"` or `"azoth"`, they run. See "Pipeline Administration" → `hexcore.emulator.switch` (status-bar QuickPick) for the UX entry point.

### Textual Refcount Review (schema v2)

Reviews textual patterns in decompiled C or raw sources. It does not prove control flow, object identity, reachability, concurrency or vulnerability impact. No emulator is required.

| Command | Timeout | Description |
|---------|---------|-------------|
| `hexcore.audit.refcountScan` | 60s | Return unproven textual signals (A/B/C/F), separate diagnostic observations, input-quality assessment and scanner coverage. |

**Args for `hexcore.audit.refcountScan`:**

| Arg | Type | Default | Description |
|-----|------|---------|-------------|
| `input` | string | — **required** | Absolute `.c` / `.helix.c` path or resolved `$step[N].output`. `file` is an alias. Relative `args.input` is process-cwd-relative, not job-directory-relative. |
| `output.path` | string | — | Write JSON report to this path. |
| `quiet` | boolean | `false` | Suppress the VS Code toast showing finding count + scan time. |

**Textual signals and diagnostic observations:**

| Pattern | What is observed | Evidence status |
|---------|-----------------|-------|
| **A** | Textual get/increment and exit imbalance | signal / unproven; no leak proof |
| **B** | Force-named helper or caller | signal / unproven; naming does not prove bypass |
| **C** | Conditional get with nearby member access | signal / unproven; no failed-get or UAF proof |
| **E (legacy identifier)** | Assertion, warning or termination call, including BUG_ON, WARN_ON and panic | `observations` only; reachability and vulnerability status `not-assessed`; zero Pattern E findings |
| **F** | Lock-name asymmetry between similarly named functions | signal / unproven; shared object, concurrent execution and caller-held locks are not established |

Pattern D remains unimplemented. Comments and literal contents are excluded from matching. Unsupported syntax, skipped lines and incomplete function boundaries produce partial scanner coverage. Do not repair code solely on the basis of these textual signals.

**Output shape (`RefcountAuditReport`):**

```json
{
  "schemaVersion": 2,
  "status": "partial",
  "negativeEvidenceUsable": false,
  "conclusion": "pattern-signals",
  "evidenceLevel": "signal",
  "proofStatus": "unproven",
  "inputFile": "...helix.c",
  "fileSize": 12345,
  "scannedLines": 456,
  "functionsScanned": 12,
  "findings": [
    {
      "pattern": "A",
      "evidenceLevel": "signal",
      "proofStatus": "unproven",
      "severity": "high",
      "severityKind": "review-priority",
      "confidence": 95,
      "confidenceKind": "heuristic-pattern-score",
      "title": "Textual increment/exit imbalance: obj",
      "description": "...",
      "functionName": "sample_get",
      "line": 6,
      "snippet": ">>> 6:    kref_get(&obj->ref);\n    7:    err = ...",
      "affectedSymbol": "obj",
      "suggestion": "Review original source and calling contracts before changing code."
    }
  ],
  "summary": {
    "total": 1,
    "byPattern": { "A": 1, "B": 0, "C": 0, "E": 0, "F": 0 },
    "bySeverity": { "high": 1, "medium": 0, "low": 0 },
    "highestConfidence": 95
  },
  "observations": [],
  "scanTimeMs": 7
}
```

The abbreviated example omits `inputQuality`, `scanCoverage` and `limitations`;
consumers must inspect those fields, not only counts or legacy review scores.
When output is requested, the exact consulted provenance revision is retained
under `.hexcore-meta/inputs/<sha256>.json`. Audit lineage references the source
SHA-256 actually scanned and this snapshot, including inputs from previous jobs.
The snapshot is supporting evidence, not a new successful analysis or an automatic
import of old facts into the current session. Snapshot failure stays partial.

**Typical exploratory usage:** chain after `hexcore.helix.decompile` using `$step[N].output`:

```json
{ "cmd": "hexcore.helix.decompile", "args": { "address": "0x140001000", "count": 300 }, "output": { "path": "func.helix.c" } },
{ "cmd": "hexcore.audit.refcountScan", "args": { "input": "$step[0].output" }, "output": { "path": "audit.json" }, "allowPartial": true }
```

### Report Composer

| Command | Timeout | Description |
|---------|---------|-------------|
| `hexcore.pipeline.composeReport` | 60s | Build a compact Markdown evidence index with analyst notes and links to source attachments; full source inlining is opt-in |

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
| `hexcore.pipeline.validateWorkspace` | 30s | Validate all `*.hexcore_job.json` in workspace |
| `hexcore.pipeline.createPresetJob` | 30s | Generate job from built-in preset |
| `hexcore.pipeline.saveJobAsProfile` | 30s | Save current job as workspace profile |
| `hexcore.pipeline.doctor` | 30s | Diagnose command registration and extension health |
| `hexcore.pipeline.queueJob` | 30s | Queue a `*.hexcore_job.json` file for execution with optional priority **(v3.8.0)** |
| `hexcore.pipeline.cancelJob` | 30s | Cancel a queued or running job by ID **(v3.8.0)** |
| `hexcore.pipeline.jobStatus` | 30s | Get status of a specific job or all jobs **(v3.8.0)** |

### Oracle Preview Commands

| Command | Timeout | Status |
|---------|---------|--------|
| `hexcore.oracle.inspectConfig` | 10s | `v3.9.0-preview.oracle`, gated by `hexcore.oracle.enabled` |
| `hexcore.oracle.listSessions` | 10s | `v3.9.0-preview.oracle`, gated by `hexcore.oracle.enabled` |
| `hexcore.oracle.demoHeadless` | 30s | `v3.9.0-preview.oracle`, gated by `hexcore.oracle.enabled` |

These commands are declared pipeline capabilities so preview work can be validated, but they are not part of the stable `3.8.3` release workflow. Do not make a release-validation job depend on them.

### Pipeline Job Queue — v3.8.0

HexCore v3.8.0 introduces a job queue system for managing multiple automation jobs with priority levels.

**Named job files:** The queue picker and watcher accept any file matching `*.hexcore_job.json`. Agents can create descriptive names like `sotr-strings.hexcore_job.json` and they will be auto-detected without manual intervention.

**Worker pool size (v3.8.3 RC):** `hexcore.pipeline.queue.poolSize` configures logical queue slots (integer, default `2`, range `1`–`16`). The extensions and native wrappers share one Extension Host and active-engine state, so every job containing a stateful command is serialized for its complete lifetime. Only commands on the audited stateless allowlist can use parallel slots. A change applies on the **next window reload**.

**Session affinity (v3.8.2):** a job tagged with a `sessionId` (see `queueJob` below) is pinned to a single worker for the life of that `keepAlive` emulation session, so session state is never split across workers. A session job waits for *its* worker if that worker is busy (it never steals a free one); stateless jobs (no `sessionId`) keep the original any-free-worker behavior.

#### `hexcore.pipeline.queueJob`

Queue a `*.hexcore_job.json` file for execution with optional priority.

```json
{
  "cmd": "hexcore.pipeline.queueJob",
  "args": {
    "file": "path/to/job.json",
    "priority": "high",
    "sessionId": "emu-session-1"
  }
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file` | `string` | *(required)* | Path to the `*.hexcore_job.json` file. Accepts both canonical (`.hexcore_job.json`) and named (`sotr-triage.hexcore_job.json`) formats. |
| `priority` | `string` | `"normal"` | Priority level: `"high"`, `"normal"`, or `"low"`. |
| `sessionId` | `string` | *(optional)* | **(v3.8.2)** Pin this job to the worker that owns the session — for `keepAlive` emulation jobs that share state across steps. Omit for stateless jobs (dispatched to any free worker). |

**Returns:**

```json
{
  "success": true,
  "jobId": "hc-job-550e8400-e29b-41d4-a716-446655440000"
}
```

#### `hexcore.pipeline.cancelJob`

Cancel a queued or running job by ID.

```json
{
  "cmd": "hexcore.pipeline.cancelJob",
  "args": {
    "jobId": "hc-job-550e8400-e29b-41d4-a716-446655440000"
  }
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `jobId` | `string` | *(required)* | The job ID returned by `queueJob`. |

**Returns:**

```json
{
  "success": true,
  "cancelled": true,
  "jobId": "hc-job-550e8400-e29b-41d4-a716-446655440000"
}
```

#### `hexcore.pipeline.jobStatus`

Get status of a specific job or all jobs.

```json
{
  "cmd": "hexcore.pipeline.jobStatus",
  "args": {
    "jobId": "hc-job-550e8400-e29b-41d4-a716-446655440000"
  }
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `jobId` | `string` | — | Specific job ID. If omitted, returns all jobs. |
| `output` | `string \| { path? }` | — | Optional JSON artifact path. Pipeline steps with an `output` now create and validate this file. |

**Returns (single job):**

```json
{
  "success": true,
  "job": {
    "jobId": "hc-job-550e8400-e29b-41d4-a716-446655440000",
    "status": "queued",
    "priority": "high",
    "position": 2,
    "sessionId": "emu-session-1",
    "workerId": null,
    "createdAt": "2026-04-11T10:30:00.000Z",
    "startedAt": null,
    "completedAt": null,
    "error": null
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `position` | `number \| null` | **(v3.8.2)** 1-based index in the dispatch order (priority first, then FIFO within a priority). A number **only while the job is `queued`**; `null` for `running`/`done`/`failed`/`cancelled`. |
| `sessionId` | `string \| null` | **(v3.8.2)** The session this job is pinned to (sticky routing), or `null`/absent if stateless. |
| `workerId` | `number \| null` | **(v3.8.2)** The worker slot the job is bound to once it starts running; `null` while still queued. |

**Returns (all jobs):**

```json
{
  "success": true,
  "jobs": [
    {
      "jobId": "hc-job-550e8400...",
      "status": "done",
      "priority": "normal",
      "createdAt": "2026-04-11T10:30:00.000Z",
      "startedAt": "2026-04-11T10:30:02.000Z",
      "completedAt": "2026-04-11T10:32:15.000Z",
      "error": null
    }
  ]
}
```

**Status values:** `queued`, `running`, `done`, `failed`, `cancelled`

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
| `hexcore.hql.scanFunction` | Scans the function in the active disassembler editor and shows UI notifications |
| `hexcore.elfanalyzer.analyzeActive` | Analyzes the active editor file |
| `hexcore.pipeline.runJob` | Recursive pipeline invocation is not supported |
| `hexcore.elixir.version` | Shows VS Code toast with engine version — use `hexcore.elixir.smokeTestHeadless` for pipelines **(v3.8.0)** |
| `hexcore.emulator.switch` | Opens the QuickPick switcher for `hexcore.emulator` setting — status-bar UX only **(v3.8.0)** |

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
| `hexcore.souper` | `hexcore.souper.optimize` |
| `hexcore.optimize` | `hexcore.souper.optimize` |
| `hexcore.superoptimize` | `hexcore.souper.optimize` |
| `hexcore.dotnet.decompile` | `hexcore.revenant.decompile` |
| `hexcore.decompile.dotnet` | `hexcore.revenant.decompile` |
| `hexcore.revenant.decompileCSharp` | `hexcore.revenant.decompile` |
| `hexcore.dotnet.decompileIL` | `hexcore.revenant.decompileIL` |
| `hexcore.decompile.il` | `hexcore.revenant.decompileIL` |
| `hexcore.disasm.disassembleAt` | `hexcore.disasm.disassembleAtHeadless` |
| `hexcore.hql.scan` | `hexcore.hql.scanHeadless` |
| `hexcore.hql.scanFunctions` | `hexcore.hql.scanHeadless` |
| `hexcore.debug.searchMemory` | `hexcore.debug.searchMemoryHeadless` |
| `hexcore.unicorn.searchMemory` | `hexcore.debug.searchMemoryHeadless` |
| `hexcore.unicorn.searchMemoryHeadless` | `hexcore.debug.searchMemoryHeadless` |
| `hexcore.struct` | `hexcore.extractStructInfo` |
| `hexcore.structInfo` | `hexcore.extractStructInfo` |
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

The HQL matcher reads the session DB via `SessionDbReader` to apply analyst-defined names/types to the HAST before running pattern queries. `hexcore.hql.scanHeadless` evaluates the built-in signature library over Helix HAST, not regex over rendered pseudo-C.

Use one of these input forms:

- Binary target plus `address` or `addresses`.
- `irPath` for one retained Remill-compatible LLVM IR artifact.
- `irText` for one inline Remill-compatible IR target.

Ordinary LLVM IR is not currently part of this command contract. The JSON report includes `targetCount`, `matchedFunctionCount`, `totalFindings`, and every scanned function, including clean negatives. Per-target records carry function/address identity, AST node count, adapter coverage and unsupported-node counts, plus the active `signatureSetSha256`. Findings carry `signatureId`, `structuralCompleteness`, `evidenceLevel`, and `matchCount`; `confidence` exists only for an explicitly corpus-calibrated signature. HQL signature `severity` is presentation priority, not vulnerability severity.

```json
{
  "cmd": "hexcore.hql.scanHeadless",
  "args": {
    "addresses": ["0x140001000", "0x140002000"]
  },
  "output": { "path": "hql-findings.json" },
  "timeoutMs": 180000
}
```

### Schema (current, 3.8.4)

```sql
CREATE TABLE session_meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE functions (address TEXT PRIMARY KEY, name TEXT, return_type TEXT, calling_convention TEXT, updated_at TEXT);
CREATE TABLE variables (id INTEGER PRIMARY KEY AUTOINCREMENT, func_address TEXT, original_name TEXT, new_name TEXT, new_type TEXT, updated_at TEXT, UNIQUE(func_address, original_name));
CREATE TABLE fields (id INTEGER PRIMARY KEY AUTOINCREMENT, struct_type TEXT, offset INTEGER, name TEXT, type TEXT, updated_at TEXT, UNIQUE(struct_type, offset));
CREATE TABLE comments (address TEXT PRIMARY KEY, comment TEXT, updated_at TEXT);
CREATE TABLE bookmarks (address TEXT PRIMARY KEY, label TEXT, updated_at TEXT);
CREATE TABLE analyze_cache (address TEXT PRIMARY KEY, name TEXT, size INTEGER, end_address INTEGER);
CREATE TABLE investigations (id TEXT PRIMARY KEY, title TEXT, kind TEXT, query TEXT, status TEXT, result_count INTEGER, created_at TEXT, updated_at TEXT);
CREATE TABLE investigation_findings (id TEXT PRIMARY KEY, investigation_id TEXT REFERENCES investigations(id) ON DELETE CASCADE, kind TEXT, query TEXT, label TEXT, string_address TEXT, reference_address TEXT, function_address TEXT, function_name TEXT, encoding TEXT, evidence_json TEXT, saved INTEGER, created_at TEXT, updated_at TEXT);

-- HXDB v2 semantic catalog and evidence history
CREATE TABLE hxdb_meta (...);
CREATE TABLE types (...);
CREATE TABLE type_members (...);
CREATE TABLE enum_members (...);
CREATE TABLE type_aliases (...);
CREATE TABLE type_dependencies (...);
CREATE TABLE function_prototypes (...);
CREATE TABLE function_parameters (...);
CREATE TABLE type_bindings (...);
CREATE TABLE fact_conflicts (...);
CREATE TABLE fact_dependencies (...);
CREATE TABLE fact_generations (...);
CREATE TABLE fact_history (...);
CREATE TABLE legacy_migrations (...);

-- R33 typed references and immutable versions
CREATE TABLE reference_edges (...);
CREATE TABLE reference_edge_versions (...);
CREATE TABLE reference_edge_dependencies (...);
CREATE TABLE reference_edge_conflicts (...);

-- R34 accepted propagation state, versions, dependencies, and dirty closure
CREATE TABLE propagation_summaries (...);
CREATE TABLE propagation_summary_versions (...);
CREATE TABLE propagation_dependencies (...);
CREATE TABLE propagation_dirty (...);
CREATE TABLE propagation_runs (...);
```

### Analysis Contract keys in `session_meta` (3.8.4)

Alongside `binary_sha256`, `binary_path`, and `created_at`, the store maintains:

- `hexcore_version` — the real extension version, refreshed on every target bind (no longer hardcoded).
- `analysis_contract_version` — the contract version (`1`).
- `analysis_target_json` — the canonical `AnalysisTarget` (`target:sha256:<digest>` identity).
- `analysis_session_json` — the persisted `AnalysisSession` (ID, generation, parent generation, engines).
- `analysis_generation_counter` — the persisted analysis generation counter. `SessionStore.startReanalysis()` advances it and invalidates derived facts; `invalidateFunction(address)` invalidates only one function's dependents.
- `analysis_engines_json` — the recorded engine manifest (engine IDs, versions, settings snapshot). Drift vs the installed engines is reported as diagnostics via `diffEngineManifest`, never as a restore failure.
- `analysis_universe_manifest_json` — replayable closure manifest binding each incrementally materialized function range to its decoded-body SHA-256 and the aggregate `universeSha256`.
- `analysis_generation_universe_json` — exact generation-to-universe binding. A nonzero legacy generation without this binding is reset to a new baseline generation with explicit `partial/reset` status.
- `analysis_last_incremental_update_json` — latest incremental materialization reason, function address, generation, universe hash, and timestamp.

Native `analyzeAll` snapshots are transient, target/digest/size-verified gzip/V8 artifacts under `.hexcore-meta`; they are deleted after successful parent hydration. Durable analysis JSON retains `nativeExecution` (worker PID/outcome/phase/snapshot sizes/heartbeat), while provenance retains the session generation and universe manifest used by downstream artifacts.

Investigation finding IDs are stable contract IDs when a target is bound (`finding:sha256:<digest>:string-reference:token:...`); rediscovering a finding preserves its saved mark and original discovery timestamp. Legacy 24-hex IDs remain valid for session-less callers, and the Analysis Center accepts both formats. Finding references whose embedded target differs from the active one are rejected as `wrong-target`.

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

## ELF Analysis Features — v3.8.0

### Section-Aware Lifting

The `hexcore.disasm.liftToIR` command now supports `allExecutableSections` option for lifting multiple executable sections in ELF files.

```json
{
  "cmd": "hexcore.disasm.liftToIR",
  "args": {
    "address": "0x0",
    "allExecutableSections": true
  },
  "output": { "path": "kernel-module.ll" }
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `allExecutableSections` | `boolean` | `false` | When `true`, lifts ALL executable sections (`.text`, `.init.text`, `.exit.text`) instead of just `.text`. |

**Output structure:**

```json
{
  "success": true,
  "functions": [...],
  "sections": [
    {
      "name": ".text",
      "purpose": "primary",
      "functions": [...]
    },
    {
      "name": ".init.text",
      "purpose": "init",
      "functions": [...]
    },
    {
      "name": ".exit.text",
      "purpose": "exit",
      "functions": [...]
    }
  ],
  "generatedAt": "2026-04-11T10:30:00.000Z"
}
```

**Purpose classification:**
- `primary` — Main code section (`.text`)
- `init` — Module initialization (`.init.text`)
- `exit` — Module cleanup (`.exit.text`)

> **Backward compatibility:** The flat `functions` array is still present in the output for existing pipelines.

### Confidence Scoring in `hexcore.disasm.analyzeELFHeadless`

ELF `.ko` kernel module analysis now includes automatic confidence scoring.

**Output fields:**

```json
{
  "success": true,
  "confidenceScore": {
    "overall": 0.87,
    "symbolResolution": 0.95,
    "cfgComplexity": 0.82,
    "patternRecognition": 0.90,
    "externalCallCoverage": 0.75,
    "symtabCompleteness": 0.98,
    "detectedPatterns": ["ftrace_preamble", "kernel_api_calls", "module_init_exit"]
  }
}
```

| Field | Range | Description |
|-------|-------|-------------|
| `overall` | 0-1 | Aggregate confidence score. |
| `symbolResolution` | 0-1 | Percentage of symbols successfully resolved. |
| `cfgComplexity` | 0-1 | Inverse of control flow complexity. |
| `patternRecognition` | 0-1 | Confidence in detected patterns. |
| `externalCallCoverage` | 0-1 | Coverage of external call targets. |
| `symtabCompleteness` | 0-1 | Completeness of symbol table parsing. |
| `detectedPatterns` | `string[]` | List of detected patterns (e.g., `ftrace_preamble`, `kernel_api_calls`). |

> **Note:** Confidence scoring is automatically computed; no additional arguments are required.

### BTF Type Loading

When an ELF file contains a `.BTF` (BPF Type Format) section, type data is automatically parsed and made available in analysis results.

**BTF data population:**

```json
{
  "success": true,
  "btfData": {
    "version": 1,
    "types": [...],
    "strings": [...],
    "typeCount": 156,
    "hasBTF": true
  }
}
```

**Benefits:**
- Kernel struct type recovery for decompilation
- Accurate type information for kernel modules
- Enhanced symbol resolution for BPF-related binaries

> **Note:** BTF parsing is automatic when the `.BTF` section is present. No additional arguments are required.

---

## Architecture Notes

- **Arch-agnostic commands** (filetype, hash, entropy, strings, YARA, IOC, base64) operate on raw bytes — no architecture dependency.
- **Disassembler** auto-detects architecture from ELF `e_machine` and PE `Machine` headers. Raw files default to x64, but `analyzeAll` accepts explicit `arch` and `baseAddress`; structured PE/ELF headers remain authoritative.
- **buildFormula** recognizes x86/x64 registers AND ARM64 (`x0`-`x30`, `w0`-`w30`, `sp`, `lr`, `fp`, `xzr`, `wzr`) and ARM32 (`r0`-`r15`) registers, plus ARM mnemonics (`movz`/`movk`/`movn`, 3-operand `add`/`sub`). It is NOT x86/x64-only.
- **checkConstants** is architecture-neutral — it only compares numeric literals.
- **PE Analyzer** is PE-format only. Use `hexcore.elfanalyzer.analyze` for ELF binaries.
- **ELF Analyzer** is ELF-format only. TypeScript-pure parser, no native dependencies. Detects RELRO, NX, PIE, Stack Canary.
- **Minidump** supports x86/x64 Windows crash dumps only.
- **Remill IR Lifter** supports x86, x86-64, and AArch64 in the current `0.5.4` package. ISA-extension coverage is not uniform; low AArch64 coverage is reported rather than hidden.
- **Rellic Decompiler** is a disabled legacy compatibility surface. Its commands remain directly addressable for old jobs, but new work must use Helix. Do not claim a removal date that has not been scheduled.
- **Helix Decompiler** runs the MLIR lowering/pass pipeline on Remill IR: type propagation, calling-convention recovery, structured control-flow reconstruction, and PseudoC emission with confidence scoring. x86/x64 is the qualified route; AArch64 remains experimental and must be judged against retained IR/disassembly. Use `hexcore.helix.decompile` or `liftToIR` + `hexcore.helix.decompileIR`. Pass `optimizeIR: false` only when isolating pass-pipeline behavior.
- **Managed routing** is explicit: classic CLR PE and detected .NET single-file apphosts are not native Helix inputs. Helix emits `managed: true`, `managedFormat`, and `confidence: 0`; use Revenant for C# or IL.
- **Souper** is tri-state on the Helix route in `3.8.3`: omitted or `"auto"` runs only on sufficiently bitwise/rotate-heavy IR, `true` forces it, and `false` disables it. The standalone `hexcore.souper.optimize` command is for explicit IR experiments.
- **Auto-backtrack** (v3.7.3+) — `disassembleAtHeadless`, `helix.decompile`, and `liftToIR` auto-detect function boundaries. If the supplied address lands mid-function, the engine backtracks to the real function start. v3.7.4 adds `forceProbe` mode, Capstone backward disassembly, ftrace preamble skip, and `endbr64` recognition. Disable with `autoBacktrack: false`.
- **Section-filtered strings** (v3.7.4) — `hexcore.disasm.extractStrings` accepts `sections: [".rdata", ".data"]` to scan only specific PE/ELF sections. Eliminates noise from `.text`.
- **Session persistence** (v3.7.4) — `.hexcore_session.db` stores function renames, variable retypes, comments, bookmarks, and `analyzeAll` cache across sessions. Keyed by binary SHA-256.
- **ELF ET_REL support** (v3.7.4) — Relocatable ELF files (`.ko`, `.o`) have `.rela.text` processed before lifting. External symbols resolved to named declarations. ftrace preambles auto-skipped.
- **Section-aware lifting** (v3.8.0) — `liftToIR` with `allExecutableSections: true` lifts all executable sections (`.text`, `.init.text`, `.exit.text`) with per-section function grouping.
- **ELF confidence scoring** (v3.8.0) — `analyzeELFHeadless` automatically computes confidence scores for `.ko` analysis including symbol resolution, CFG complexity, and pattern recognition.
- **BTF type loading** (v3.8.0) — Automatic parsing of `.BTF` sections in ELF files for kernel struct type recovery.
- **Job queue with priority** (v3.8.0) — Pipeline jobs can be queued with `high`/`normal`/`low` priority via `hexcore.pipeline.queueJob`. Commands available in Command Palette: **Queue Job**, **Cancel Queued Job**, **Show Job Queue Status**.
- **Named job files** (v3.8.0) — Job watcher and picker accept any `*.hexcore_job.json` file (not just `.hexcore_job.json`). Agents can create descriptive names like `sotr-strings.hexcore_job.json` and they will be auto-detected without manual intervention.
- **Pathfinder CFG recovery** (v3.8.0) — Pre-lift CFG analysis using `.pdata`/`.symtab` boundaries, Capstone batch decode, and jump table resolution. Produces `additionalLeaders` for Remill. Architecture-aware: x86 batch decode, ARM64 linear decode.

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
    "arch": "x86",
    "baseAddress": "0x400000",
    "filterJunk": true,
    "detectVM": true,
    "detectPRNG": true,
    "allowLazy": true,
    "allowDecodeEmpty": false
  }
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `maxFunctions` | `number` | `1000` | Maximum functions to analyze. |
| `maxFunctionSize` | `number` | `65536` | Maximum function size in bytes. |
| `forceReload` | `boolean` | `false` | Force reload of binary file. |
| `arch` | `string` | `x64` for raw | Architecture override for headerless raw binaries: `x86`, `x64`, `arm`, `arm64`, `mips`, or `mips64`. Ignored for PE/ELF, whose headers are authoritative. |
| `baseAddress` | `string \| number` | `0x400000` for raw | Non-negative virtual load base for a headerless raw binary. |
| `filterJunk` | `boolean` | `false` | Filter junk instructions (callfuscation, nop sleds, identity ops). Reports `junkCount` and `junkRatio`. **(v3.7.1)** |
| `detectVM` | `boolean` | `false` | Run VM obfuscation heuristics (dispatcher, handler tables, operand stacks). Reports `vmDetected`, `vmType`, `dispatcher`, `opcodeCount`. **(v3.7.1)** |
| `detectPRNG` | `boolean` | `false` | Detect PRNG usage patterns (srand/rand call sites, seed extraction). Reports `prngDetected`, `seedSource`, `seedValue`, `randCallCount`. **(v3.7.1)** |
| `allowLazy` | `boolean` | `false` | Explicitly accept discovered functions whose bodies remain lazy. Without this opt-in, any lazy population makes the result `partial`. |
| `allowDecodeEmpty` | `boolean` | `false` | Accept a materialized function whose body decoded empty. Keep `false` for correctness gates. |
| `minMaterializedRatio` | `number` | `1` (`0` with `allowLazy`) | Required materialized/total ratio in the inclusive range 0..1. |

The result exposes `materializedFunctionRatio`, `functionsWithInstructions`,
`lazyFunctions`, `decodeEmptyFunctions`, and the effective
`materializationPolicy`. Reconnaissance jobs may set `allowLazy:true`, but the
report still foregrounds the unanalyzed population.

`analyzeAll` executes native discovery in a child process. The Extension Host
owns the external deadline and can terminate the worker even when native code
is synchronously blocked. Successful runs return a digest-verified gzip/V8
engine snapshot, hydrate the parent without repeating whole-binary analysis,
and delete the transient snapshot. `nativeExecution` records outcome, worker
PID, duration, final phase, heartbeat path, and compressed/raw snapshot sizes.
The heartbeat under `.hexcore-meta` is updated by the supervisor independently
of the worker and remains as terminal evidence for success, timeout, cancel,
or crash. Pipeline timeout automatically invokes
`hexcore.disasm.cancelAnalyzeAll`.

On startup, an unchanged job left `running` by a dead prior host is archived
and marked terminal after `hexcore.pipeline.staleRunningMs` (default 15 min),
then becomes eligible for retry. Recovery never overwrites the archived status.

### `hexcore.disasm.windowsFilesystemAuditHeadless`

Build an evidence-gated Windows filesystem boundary map after `analyzeAll`.
The command is PE-only and requires both the Disassembler and PE Analyzer.

```json
{
  "cmd": "hexcore.disasm.windowsFilesystemAuditHeadless",
  "args": { "maxStringSignals": 250 },
  "output": { "path": "windows-filesystem-audit.json" },
  "allowPartial": true,
  "timeoutMs": 300000
}
```

The result separates `import-signal` from `owned-callsite`, maps referenced
path/archive/security strings to owning functions, and emits consolidated
`candidateFunctions`, direct `candidateEdges`, and eight chain edges:
principal, state location, writer, lifecycle, parser, path property,
`reparse-safety`, and sink.
It returns `partial` while any required edge is missing or blocked. An owned
callsite is still not proof of argument values, handle identity, ordering,
attacker control, or exploitability; the command never assigns severity.

`dataflow.facts` retains bounded pre-call contexts and labelled immediate
candidates for SID, ACL, access-mask, path, handle, and write APIs.
`dataflow.typedPaths` connects compatible facts through a maximum four-hop call
neighborhood; `sameValueProven:false` is mandatory until register/SSA def-use
and aliasing prove identity. `dataflow.handleLifecycles` similarly records
co-located open/write/close sequences with `sameHandleProven:false`.

For Win64, `dataflow.deepValueFlow` performs bounded intra-function def-use for
argument registers and stack arguments. A proof is emitted only when producer
and consumer reduce to the same canonical storage or return token. Only those
specific routes may set `sameValueProven:true` or `sameHandleProven:true`.
For `same-path`, equal storage is only the first gate: an overlapping direct
write or passing the buffer address to a call without a proven read-only
pointer summary invalidates stored-value preservation. Such matches are
retained under `dataflow.deepValueFlow.signals` with `status:"signal"` and an
exact blocker; they do not promote `Path -> open`. Calls that clobber volatile
registers, unresolved aliases, heap/object fields, and interprocedural
transfers remain unproven.

Candidate ranking combines direct evidence, role diversity, graph degree,
typed-path participation, and product/third-party attribution. Use
`topCandidateChains` before isolated `candidateFunctions`; `rankScore` is a
navigation score, never vulnerability severity.
`criticalHelpers` expands product-attributed candidates through bounded
depth-1/depth-2 callees, while `product-candidate-route` and
`product-helper-route` preserve concrete routes without promoting helpers to
semantic findings. Reports render these separately from Boundary API Owners so
SID/ACL functions are not hidden by generic string volume.

Dense enum-to-message tables retain matching path/security text under
`stringPivots` with `evidenceClass:"message-table"`, but those strings do not
create path/archive roles. The chain also includes `reparse-safety`: absence of
component-level reparse evidence is `not-assessed`, never an implicit safe
result. Even a `signal` still requires proof of reparse tags, handle-relative
traversal, and final-path descendant enforcement.

Every filesystem audit also includes `normalization` using
`hexcore-canonical-json-v1`. Reproduce `sha256` by deleting the two top-level
members identified by `excludedJsonPointers` (`/generatedAt` and
`/normalization`, plus process-local `/analysisContext/engineGeneration` and
`/analysisContext/closureRestoration`), recursively sorting object keys,
serializing compact JSON in UTF-8, and hashing those bytes with SHA-256. The
persisted session generation and `universeSha256` remain included.

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

Use `query` (string) for single-term lookups or `queries` (array) for batch
lookups. If both are present, the deduplicated `queries` array takes precedence.
Set `minConfidence` from `0` to `1` to discard weak literal candidates. Each
match reports `literalConfidence`, `evidenceClass`, and `evidenceReasons`; the
result reports `discardedLowConfidence`. Standard CRC32 lookup-table sequences
are classified as low-confidence evidence rather than ordinary text.

### `hexcore.strings.extractAdvanced`

The default remains backward-compatible and returns all scored candidates.
Use explicit budgets for large binaries, and opt in to multi-stage decoding:

```json
{
  "cmd": "hexcore.strings.extractAdvanced",
  "args": {
    "minConfidence": 0.7,
    "maxDeobfuscated": 500,
    "highSignalOnly": true,
    "decodeChains": true,
    "maxTransformChains": 100
  }
}
```

`deobfuscationBudget` records generated, retained, and discarded candidates.
`transformChains` preserves every hex/ASCII/Base64/JSON step with source
offset, bounded previews, SHA-256, confidence, and JSON validity;
`transformChainBudget` records its output gate. A transform chain is evidence,
not automatic proof that the decoded payload is trustworthy or executable.

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

Disassemble either a paged instruction count or an exact half-open byte range.
Requires prior `analyzeAll` or a loaded binary.

```json
{
  "cmd": "hexcore.disasm.disassembleAtHeadless",
  "args": {
    "address": "0x401000",
    "endExclusive": "0x4012A0",
    "stopAtFunctionBoundary": true,
    "filterJunk": true
  },
  "output": { "path": "disasm-at-result.json" },
  "timeoutMs": 120000
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `address` | `string` | *(required)* | Start virtual address as `0x`-prefixed hex string. |
| `count` | `number` | `30` | Number of instructions to disassemble in legacy pagination mode. |
| `endExclusive` | `string` | — | Authoritative first byte after the requested range. Takes precedence over instruction-count scope. |
| `stopAtFunctionBoundary` | `boolean` | `false` | Use the known function extent exactly; fails when no authoritative extent exists. |
| `filterJunk` | `boolean` | `false` | Filter junk instructions from output. Reports `junkCount` and `junkRatio`. **(v3.7.1)** |
| `autoBacktrack` | `boolean` | `true` | When `true`, auto-detects function boundaries — if the address lands mid-function, backtracks to the real function start. Set to `false` to disable. **(v3.7.3)** |
| `output` | `{ path? }` | — | JSON output file path. |

`count` is paged at 10,000 instructions and remains an
`instruction-count` domain. Exact requests use the `byte-range` domain and
report `requestedByteRange`, `functionBoundary`, reach/crossing and byte
coverage. `stopReason` is one of `count-limit`, `requested-end`,
`function-end`, `decode-failure`, or `binary-boundary`. An exact range that is
not reached returns `partial`; a full count page is never proof that the
function ended.

When the range belongs to a known lazy function, the command materializes and
commits that body to the active analysis universe. `analysisClosure` records
whether the result was `committed`, `already-current`, `decode-empty`,
`unknown-function`, or `display-only`, plus semantic instruction count,
engine/session generation transitions, and `auditUniverseChanged`. A decoded
window with zero semantic instructions is `partial` even when byte coverage is
1.0. Downstream shared-analysis commands inherit committed disassembly
artifacts in provenance and consume the new generation.

Committed closures survive process/job boundaries. The session stores a
replayable manifest of exact function ranges and decoded-body hashes; the next
`analyzeAll` restores that set before exposing the persisted generation.
`closureRestoration` reports requested/restored/failed counts and
`universeSha256`. A partial replay advances away from the old generation and
returns `partial` instead of assigning one generation to two universes.
Legacy nonzero generations created before closure manifests are reset to a new
baseline generation with `closureRestoration.status:"reset"`; jobs must opt in
to that `partial` result instead of silently trusting unreplayable state.

### `hexcore.constraints.solveHeadless`

Run the packaged Z3 process with an internal deadline and return concrete models.
Use decimal strings for integer constants larger than JavaScript's safe integer range.

```json
{
  "cmd": "hexcore.constraints.solveHeadless",
  "args": {
    "variables": [
      { "name": "digit", "type": "int", "domain": [0, 9] },
      { "name": "mask", "type": "bv", "bits": 32 }
    ],
    "constraints": [
      { "op": "eq", "args": [
        { "op": "mul", "args": ["digit", 7] },
        42
      ] }
    ],
    "maxModels": 2,
    "timeoutMs": 30000
  },
  "output": { "path": "constraints.json" },
  "timeoutMs": 35000
}
```

Supported structured operations are `add`, `sub`, `mul`, `xor`, `and`, `or`,
`shl`, `lshr`, `ashr`, `concat`, `extract`, `ite`, `not`, `neg`, equality,
signed comparisons, and unsigned bitvector comparisons. A large exact integer
literal uses `{ "type": "int", "value": "847851805715481601" }`; a bitvector
literal uses `{ "bits": 64, "value": "847851805715481601" }`. Controlled
`smt2` assertions over variables declared in `variables` are also accepted, but solver-control commands
are added by HexCore. Results include `sat | unsat | unknown`, models, timeout,
enumeration truncation, call/time metrics, Z3 version, and executable SHA-256.
Models are returned as decimal strings to preserve exact widths. Solver result
`truncated:true` means enumeration stopped at `maxModels`; it is independent
from disassembly truncation. Bounds are 2,048 variables, 10,000 constraints,
4 MiB generated SMT, a 300-second internal timeout, and 100 models.

`unknown` and `timeout:true` are semantic errors by default and therefore make
the pipeline step fail. Set `allowUnknown:true` or `allowTimeout:true` only when
an inconclusive result is expected; the result then has
`semanticStatus:"partial"`, and the step must also set `allowPartial:true`.
Neither option converts an inconclusive solve to `ok`.

### `hexcore.disasm.liftToIR`

Lift machine code to LLVM IR using the Remill engine. Requires a loaded binary with disassembly data.

```json
{
  "cmd": "hexcore.disasm.liftToIR",
  "args": {
    "address": "0x401000",
    "endExclusive": "0x4012A0",
    "stopAtFunctionBoundary": true
  },
  "output": { "path": "lifted-ir.ll" },
  "timeoutMs": 120000
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `address` | `string` | *(required)* | Start virtual address as `0x`-prefixed hex string. |
| `count` | `number` | `50` | Number of instructions to lift. |
| `endExclusive` | `string \| number` | — | Exact half-open function endpoint; preferred whenever known. |
| `stopAtFunctionBoundary` | `boolean` | `false` | Select the known function extent exactly instead of estimating `count * 15`. |
| `allExecutableSections` | `boolean` | `false` | When `true`, lifts ALL executable sections (`.text`, `.init.text`, `.exit.text`) with per-section grouping. **(v3.8.0)** |
| `output` | `{ path? }` | — | Output file path for LLVM IR text. |

The result and generated `LiftDiag` keep requested and effective addresses
separate and list entry transformations as `kind@address+bytes`. CET/ftrace
and the exact nine-byte Linux kernel NOP are skipped only when their format
and byte evidence match. In raw and PE inputs, `E8 00 00 00 00` is preserved
because it may be the observable PIC sequence `call $+5; pop reg`.

### Lift and decompiler honesty

Do not interpret `semanticCoverage` as whole-function correctness. It measures
the fraction of decoded instructions for which Remill supplied semantics.
Therefore it may be 100% for an explicitly scoped fragment while the complete
CFG or function boundary is unknown. Judge completeness using all of:

- `requestedByteRange`, `functionByteRange`, `semanticBodyRange`, and their
  boundary reach/crossing fields;
- `remillDecodedByteSet`/`decodedByteCoverage`, which are union-of-intervals
  coverage metrics and are not linear endpoint cursors;
- `scopeLimited`, unsupported/decode-failure counts, and `LiftDiag`;
- Helix `qualityIssues` and canonical `ok|partial|failed|skipped` status;
- `confidenceAxes.translation`, `confidenceAxes.liftCoverage`, and
  `confidenceAxes.semanticType`.

`semanticType:null` with `semanticTypeStatus:"not-assessed"` means no type
identity conclusion was made. Placeholders, suspicious self-references,
unrecovered control flow, under-lift, unsupported instructions, or a scoped
fragment cap presentation confidence and must remain visible in the artifact.

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
| `optimizerStep` | `string` | `'llvm-passes'` | Optimizer: `'none'`, `'llvm-passes'` (DCE + ConstFold), `'souper'` (**no-op stub on the Rellic path**). Souper is implemented for Helix with the `3.8.3` tri-state gate. **(v3.7.1)** |
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
| `souper` | `boolean \| "auto"` | `"auto"` | Tri-state gate: omitted/`"auto"` runs only when IR signal density justifies solver cost; `true` forces optimization; `false` disables it. |
| `souperTimeout` | `number` | `30000` | Per-candidate Z3 solver timeout (ms) for the Souper pass. **(v3.8.0)** |
| `souperAutoThreshold` | `number` | `0.25` | Minimum bitwise/rotate signal density used by the automatic gate. |
| `souperAutoMinOps` | `number` | `8` | Minimum number of signal operations used by the automatic gate. |
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

For detected managed inputs, a successful command can intentionally return `{ "managed": true, "managedFormat": "dotnet-cil" | "dotnet-single-file", "confidence": 0 }` and write an explanatory marker. This is correct engine routing, not native pseudo-C. Follow with Revenant.

---

### `hexcore.helix.decompileIR`

Decompile a pre-lifted LLVM IR file to pseudo-C via the Helix MLIR pipeline. Use this as the second step of a two-step pipeline where the first step is `hexcore.disasm.liftToIR`. The `irPath` argument must point to the `.ll` file produced by `liftToIR` — **use `"$step[N].output"`** (N = the 0-based index of the `liftToIR` step) so the path resolves to exactly what that step wrote, instead of a hardcoded path that can drift.

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
| `souper` | `boolean \| "auto"` | `"auto"` | Tri-state gate: automatic density-based selection, forced on with `true`, or off with `false`. |
| `souperTimeout` | `number` | `30000` | Per-candidate Z3 solver timeout (ms) for the Souper pass. **(v3.8.0)** |
| `souperAutoThreshold` | `number` | `0.25` | Minimum bitwise/rotate signal density used by the automatic gate. |
| `souperAutoMinOps` | `number` | `8` | Minimum number of signal operations used by the automatic gate. |
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
      "args": { "irPath": "$step[0].output" },
      "output": { "path": "bone_pos_calc.helix.c" },
      "timeoutMs": 180000
    }
  ]
}
```

> **Tip:** Prefer `"irPath": "$step[N].output"` (N = the 0-based index of the `liftToIR` step) over a hardcoded path. The runner resolves it to the exact file the lift step wrote, so it cannot drift if `outDir` or the lift's `output.path` changes. A mismatched hardcoded `irPath` makes `decompileIR` fail with `IR file not found`, which the pipeline surfaces only as the generic `Expected output file was not created` — the real error is in the Extension Host console (Help > Toggle Developer Tools > Console).

---

### `hexcore.disasm.detectPacker`

Detect-only packer triage. It does not unpack a sample and does not call a user-installed UPX executable.

```json
{
  "cmd": "hexcore.disasm.detectPacker",
  "output": { "path": "packer.json" },
  "timeoutMs": 60000
}
```

The result exposes flat `packed`, `family`, and `confidence` fields suitable for `onResult`, plus markers, detected families, recommendation, capability tags, file size, and an optional UPX version hint. Known families are `upx`, `themida`, `vmprotect`, `aspack`, `enigma`, `mpress`, `unknown`, and `none`. Run after `analyzeAll` when richer loaded-section/string evidence is useful; direct raw-file detection also works.

Large high-entropy writable/executable sections are reported as `family: "unknown"` even when no commercial-family marker exists. This means "encrypted payload or unknown packer evidence", not a claim that a named packer was identified.

### `hexcore.pe.extractSection` / `hexcore.crypto.rc4`

These passive transforms materialize a payload without loading or executing it. Binary outputs are provenance-hashed and can be chained with `$step[N].output` through `inputPath`.

```json
{
  "file": "managed-loader.exe",
  "outDir": "./hexcore-reports/materialized",
  "steps": [
    {
      "cmd": "hexcore.pe.extractSection",
      "args": { "section": ".payload", "maxBytes": 268435456 },
      "output": { "path": "stage.encrypted.bin" }
    },
    {
      "cmd": "hexcore.crypto.rc4",
      "args": {
        "inputPath": "$step[0].output",
        "key": [1, 2, 3, 4],
        "drop": 0,
        "maxBytes": 268435456
      },
      "output": { "path": "stage.decoded.bin" }
    }
  ]
}
```

`crypto.rc4` requires exactly one of `key`, `keyHex`, or `keyBase64`. `key` may be a UTF-8 string or an array of byte values. The default input/section limit is 256 MiB and the hard ceiling is 1 GiB; `drop` is bounded to 16 MiB. The commands do not infer a key from decompiler text and do not execute the transformed bytes.

### `hexcore.revenant.decompile` / `hexcore.revenant.decompileIL`

Use Revenant for managed .NET inputs. C# mode optionally accepts `type` to target a specific type. Both commands accept the pipeline-injected `file`, `quiet`, and `output` contract.

```json
{
  "file": ".\\managed-target.exe",
  "outDir": ".\\hexcore-reports\\managed",
  "steps": [
    {
      "cmd": "hexcore.revenant.decompile",
      "output": { "path": "target.cs" },
      "timeoutMs": 180000
    },
    {
      "cmd": "hexcore.revenant.decompileIL",
      "output": { "path": "target.il" },
      "timeoutMs": 180000
    }
  ]
}
```

The bundled self-contained engine is preferred. A system `ilspycmd` fallback can handle classic assemblies, but single-file apphosts require the bundled route. Revenant parses the managed artifact; it does not execute the sample.

### `hexcore.hql.scanHeadless`

Pass binary `address`/`addresses`, or one Remill-compatible `irPath`/`irText` target. Ordinary LLVM IR is not accepted by the current Helix/HQL lane. The output is a semantic HAST-signature report that preserves clean function identity, adapter fidelity, and signature-set identity.

```json
{
  "cmd": "hexcore.hql.scanHeadless",
  "args": { "addresses": ["0x140001000", "0x140002000"] },
  "output": { "path": "hql-findings.json" },
  "timeoutMs": 180000
}
```

The report declares `status: "ok" | "partial" | "failed"`, `completedTargetCount`, and `failedTargetCount`. A partial child result fails the pipeline step by default. Add step-level `"allowPartial": true` only when downstream logic explicitly accepts incomplete semantic coverage; the step and terminal job remain visibly `partial`. Treat `signal` and `candidate` as discovery evidence. A completed HQL job, structural completeness `1`, or a high presentation severity does not prove maliciousness, exploitability, or a vulnerability.

### `hexcore.souper.optimize`

Optimize LLVM IR supplied through `irPath`, `irText`, or the job `file` when that file is itself `.ll`. Options are `maxCandidates`, `timeoutMs`, and `aggressiveMode`.

```json
{
  "file": ".\\function.ll",
  "outDir": ".\\hexcore-reports\\souper",
  "steps": [
    {
      "cmd": "hexcore.souper.optimize",
      "args": { "maxCandidates": 128, "timeoutMs": 30000, "aggressiveMode": false },
      "output": { "path": "function.optimized.ll" },
      "timeoutMs": 60000
    }
  ]
}
```

The result reports `candidatesFound`, `candidatesReplaced`, and `optimizationTimeMs`. Zero replacements is a valid result, especially for ordinary non-MBA code.

### `hexcore.extractStructInfo`

After loading/analyzing an ELF containing BTF or DWARF, this command exports struct/function type data and optionally scopes it with `functionName`. Both direct string outputs and the runner's `{ path, format }` output contract are supported; parent directories are created before writing.

---

### `hexcore.yara.scan`

```json
{
  "cmd": "hexcore.yara.scan",
  "args": { "categories": ["Trojan", "Backdoor"], "loadEssentials": false }
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `categories` | `string[]` | — | DefenderYara categories to load into the active rule set before scanning (e.g. `["Trojan", "Ransom"]`). Effective **only when a DefenderYara catalog is indexed**. |
| `loadEssentials` | `boolean` | `false` | Load the DefenderYara "essentials" bundle (Trojan/Backdoor/Ransom/Exploit/PWS/...) before scanning. Effective **only when a DefenderYara catalog is indexed**. |

**What ships vs. what you must provide:**

- **Bundled (always scanned):** 7 built-in rules (packers, suspicious APIs, shellcode, reverse-shell) + 7 AntiAnalysis `.yar` files (anti-debug, anti-VM, API hashing, obfuscation). ~14 rules total, zero configuration.
- **DefenderYara (76k+ rules) is NOT bundled.** To scan against it, place a `DefenderYara-main` folder in `~/Desktop`, `~/Downloads`, or `C:\` (auto-detected at activation), or set the `hexcore.yara.defenderYaraPath` setting. HexCore *indexes* the catalog on activation; categories are **loaded on demand** when you pass `categories`/`loadEssentials`.

**Honest reporting:** when `categories`/`loadEssentials` is requested, the result JSON includes a `categoryLoad` object:

```json
{
  "categoryLoad": {
    "requested": ["Trojan", "drivers"],
    "loaded": ["Trojan"],
    "unavailable": ["drivers"],
    "rulesLoaded": 482,
    "catalogIndexed": 76219
  }
}
```

If no DefenderYara catalog is indexed, `catalogIndexed` is `0`, every requested category appears in `unavailable`, and the scan runs against the bundled rules only — the command **never silently claims** to have loaded the 76k set. Use `activeRules` + `ruleLoadDiagnostics` in the same output to confirm exactly how many rules were active.

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

> **Note on IPC Smart Sync:** Emulation of x64 and ARM64 ELFs occurs in an isolated Node.js worker process. Smart Sync mirrors relevant worker stack/heap state back to the host before API interception so hooks such as `__printf_chk`, `puts`, and `getline` can inspect dynamic buffers. This improves observability but does not guarantee that an unsupported VM, syscall, or anti-emulation path will execute correctly.

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
		"trace": { "maxEntries": 20000, "sampleEvery": 1, "groupRepeated": true },
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
| `trace` | `object` | bounded/grouped | `{ maxEntries, sampleEvery, groupRepeated }`. Retention and sampling never change the exact observed-call total. **(v3.8.4)** |
| `collectSideChannels` | `boolean` | `false` | When `true`, collects instruction counts per basic block, memory access patterns, and branch statistics. **(v3.7.1)** |
| `memoryDumps` | `array` | — | Array of `{ address, size, trigger }` objects. `trigger` is `'breakpoint'` or `'end'`. **(v3.7.1)** |
| `breakpointConfigs` | `array` | — | Array of `{ address, autoSnapshot?, dumpRanges? }` objects. When `autoSnapshot: true`, captures registers + stack + optional memory ranges when execution stops at that breakpoint. **(v3.8.4)** |
| `output` | `{ path? }` | — | JSON output file path. Parent directories are created recursively. |
| `quiet` | `boolean` | `false` | Suppress VS Code notification messages. |

When a prior `analyzeAll` step reports `prngDetection.prngDetected=true`, the
pipeline runner supplies `glibc` for ELF or `msvcrt` for PE plus the recovered
uint32 seed to a later Debugger emulation step. Explicit job arguments always
win; a seed without a non-`stub` mode is rejected.

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
- A missing or non-string `input` is rejected. The legacy/misspelled `data`
  argument is not silently converted to an empty STDIN buffer.
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

### Live-memory disassembly and decompilation **(v3.8.4)**

Use these commands after a keep-alive emulation reaches an unpacked or transformed
code region. The bytes stay in process: the Debugger reads the live Unicorn memory,
the Disassembler lifts the exact byte buffer, and Helix consumes the resulting IR.
The original binary remains the session target.

```json
{
  "cmd": "hexcore.debug.disassembleMemoryHeadless",
  "args": { "address": "0x500000", "size": 1444 },
  "output": { "path": "live-payload.disasm.json" },
  "timeoutMs": 120000
}
```

```json
{
  "cmd": "hexcore.debug.decompileMemoryHeadless",
  "args": { "address": "0x500000", "size": 1444 },
  "output": { "path": "live-payload.helix.c" },
  "timeoutMs": 300000
}
```

Both results identify `source: "debugger-live-memory"`, the original `targetFile`,
the live address, region size, architecture, execution backend, and SHA-256. The
decompile result additionally reports `bytesConsumed`, confidence, and quality
issues. It also reports `analysisContext`: `matched`, `mismatched`, or `unbound`,
plus `activeEngineEvidenceUsed`. A mismatch is expected when another target is
open in the Disassembler and proves that its renames, symbols, debug types,
function starts, and confidence evidence were not applied. The pipeline log
retains this decision even when the output artifact is plain `.c`.

Live-memory Helix work runs in a fresh worker. Its internal deadline accounts
for time already spent reading and lifting memory and settles five seconds
inside the step timeout. The pipeline then has time to write a terminal status
and release queue/session ownership; the timeout capability can also cancel the
live-worker group explicitly. Sizes are bounded to 4 MiB per command; split
larger regions along verified code boundaries.

The internal `hexcore.disasm.liftMemoryHeadless` command accepts `bytesBase64`,
`address`, and `arch`. Pipeline authors normally use the Debugger commands so the
live-memory provenance is assembled automatically.

---

### `hexcore.pipeline.composeReport`
```json
{
  "cmd": "hexcore.pipeline.composeReport",
  "args": { "notes": "ANALYST_NOTES.md", "includeFullSources": false },
  "output": { "path": "FINAL_REPORT.md", "format": "md" },
  "timeoutMs": 60000
}
```

The default compact report summarizes corroborated findings and links each
attachment; it does not duplicate complete JSON/Markdown bodies. Set
`includeFullSources: true` only when a self-contained, substantially larger
report is required.

When this command is the final pipeline step, the runner persists terminal
status first and automatically recomposes the report. The destination report
is excluded from its own source scan; its finalized hash appears in
`.hexcore-meta/provenance.json`.

The final report provenance inputs are the exact source artifacts returned by
the composer, including terminal status, and never the report itself. Composer
lineage uses target, producer/version, command, configuration hash, and input
artifact IDs. Same-lineage normalized-identical reruns are rendered as
`Replicated Evidence`; they do not increase independent corroboration. Audit
parameter variants are compared once and exact replicas are collapsed.

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
Output paths must be relative to and contained inside `outDir`. Absolute paths, `..` escapes, and paths resolving to the directory itself fail preflight.

---

## Pipeline Execution Details

- Every step runs in headless mode (`quiet: true`) and receives `file`.
- If a step does not define `output`, HexCore auto-generates output files inside `outDir`.
- The complete job is validated before the first command executes. Invalid targets, capabilities, references, or output paths stop the job at preflight.
- Before each step, the runner verifies command registration and attempts to activate the owner extension when needed.
- PE-only, ELF-only, and minidump-only parsers are skipped from header metadata when the target format is incompatible.
- A command that returns transport success but reports semantic failure (`success:false`, `terminatedWithError`, child errors, or `status:failed`) fails the step. Partial results require `allowPartial:true`.
- If command activation fails, `hexcore-pipeline.status.json` includes owner-extension diagnostics.
- `outputPath` is only reported for steps that actually request/provide output.
- Commands marked as interactive are blocked with a clear error.
- Startup/watcher auto-run executes each saved job revision once. On Extension
  Host reload, an existing status whose `startedAt` is newer than the job file's
  mtime suppresses replay and preserves that attempt. Edit/save the job or use
  the manual Run Job command to request a new execution.

### Observability fields (v3.8.0)

`hexcore-pipeline.status.json` exposes extra metrics for dashboards and report
composers (all backward compatible — missing on older runs):

- **Per-step** — `attemptCount`, `outputBytes`, and `artifactProvenancePath`. The path points to the run's consolidated `.hexcore-meta/provenance.json` manifest. Each artifact entry contains its SHA-256, binary identity, command, semantic status, context generation, worker/job identity, owner-extension versions, and input-artifact chain.
- **Run-level `provenanceManifestPath`** — the same hidden manifest path, exposed once for consumers that do not need to walk step status. Normal report directories no longer receive a visible `.provenance.json` beside every artifact.
- **Run-level `provenance`** — `executionId`, optional queue/session IDs, `contextGeneration`, `binaryPath`, `binarySha256`, detected `binaryFormat`, architecture, and PE image base when available.
- **Run-level `summary`** (populated on terminal status — `ok` / `error` /
  `partial`):
  - `totalSteps`, `okCount`, `partialCount`, `errorCount`, `skippedCount`
  - `totalDurationMs` — wall-clock from `startedAt` to `finishedAt`
  - `slowestStepCmd` / `slowestStepMs` — slowest successful step (skip
    budgeting and retries dominate the honest timings)
  - `queueSnapshot` — `{queued, running, done, failed, cancelled, includesCurrentJob:false}` from the `JobQueueManager` singleton if one is active.

The runner writes `status.json` after every step (progressive observability),
so a watcher tailing the file sees each transition live.

---

### Command contract envelopes (3.8.4)

The pipeline administration commands now return contract-decorated responses. Legacy fields are preserved; the contract fields are authoritative on name conflicts:

- `hexcore.pipeline.runJob`, `validateJob`, `listCapabilities`, `queueJob`, and `jobStatus` responses carry `contractVersion: 1`, canonical `status`, typed `diagnostics`, and `artifacts`.
- Canonical status vocabulary in command responses: `ok | partial | failed | skipped`. The file-level `hexcore-pipeline.status.json` keeps its legacy `error` run status; the command response maps it to contract `failed`. A `running` snapshot maps to `partial` with a warning diagnostic, never a fake terminal state.
- Step outcomes become typed diagnostics: `timeout` (retryable) vs `engine-fault`, `partial-result` warnings for retained partial output, and gate classifications (`parse-failed` for format gates, `engine-unavailable` for missing engines). Validation issues map to `output-unsafe` / `not-found` / `invalid-input`, with the original issue code preserved in `details.issueCode`.
- Artifact references are never fabricated: artifact hashes live in the provenance manifest, so decorated responses carry sidecar paths in diagnostic `details` instead of inventing `AnalysisArtifactReference` entries.
- `hexcore.pipeline.cancelJob` still returns a bare boolean this wave; migrating it is a consumer-visible break and is deferred with the analysis-command tail (`searchStringHeadless`, `liftToIR`, `helix.decompileIR`, `hql.scanHeadless`, ...).
- Error codes come from the contract registry (`ANALYSIS_ERROR_CODES` in `hexcore-common`): adding or renaming a code is a contract change.

---

## Troubleshooting

### `Command '...' not found`
- Confirm the installed build matches the HexCore `3.8.3` RC command surface.
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
- For isolated `analyzeAll`, inspect `nativeExecution.lastPhase` and the terminal heartbeat before changing scope or deadline. The external watchdog has already terminated the worker.
- Increase `timeoutMs` only for justified heavy analysis; lower `maxFunctions` and `maxFunctionSize` when the requested scope is excessive.
- Helix decompile can take up to 90s for large functions — use `timeoutMs: 180000` or higher.

### Missing report file
- Check step status in `hexcore-pipeline.status.json`.
- A failed/timed-out step never creates a successful analysis artifact. Commands with validated output contracts may create an explicit error stub at the requested path (`stub:true`, `ok:false`, `status:"error"`); provenance and step status remain `error`.

### `Invalid "outDir"` / output resolves outside the allowed directory
- Keep `outDir` under the workspace or the job-file directory.
- Keep every step `output.path` relative and inside `outDir`; absolute paths and `..` escapes are rejected.
- Only enable `hexcore.pipeline.allowExternalOutDir` for a deliberate external destination. This is a workspace security boundary, not a path-format workaround.

### Helix returns `managed: true` and confidence `0`
- The input is classic CLR or a detected .NET single-file apphost, so native Remill -> Helix is intentionally not applicable.
- Run `hexcore.revenant.decompile` for C# and/or `hexcore.revenant.decompileIL` for IL.
- Do not report the marker as a zero-quality native decompilation; it is routing evidence.

### `hexcore.extractStructInfo` produces no output file
- Confirm an earlier ELF analysis loaded BTF or DWARF and inspect the semantic error in `hexcore-pipeline.status.json`.
- The runner object-output contract is supported in Disassembler 1.4.27; an older installed extension still needs to be upgraded.

### `hexcore.helix.decompileIR` fails / `Expected output file was not created`
- **Use `"irPath": "$step[N].output"`** (N = the 0-based index of the `liftToIR` step) so the IR path always matches what the lift wrote. A hardcoded path can drift from the actual artifact.
- Disassembler 1.4.27 propagates the command's semantic error into `hexcore-pipeline.status.json`; the Extension Host console remains useful for native diagnostics.
- Ensure `liftToIR` ran successfully (check its status in `hexcore-pipeline.status.json`); if it failed, no `.ll` exists for this step.
- A relative `irPath` is resolved from the workspace root folder, not from `outDir` — another reason to prefer `$step[N].output`.

### `hexcore.helix.decompile` / `liftToIR` produces no output for an `address`
- `address` is a **virtual address** (e.g. `0x140001000`) or the literal `"entry"`, NOT a raw file offset. An address with no code at it (e.g. `0x1000` on a binary based at `0x140000000`) decompiles nothing and surfaces only the generic `Expected output file was not created`. Pass `"entry"` or a real function VA from `analyzeAll`.

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

---

## Job File Naming Convention — v3.8.0

### File Name Pattern

HexCore detects any file matching `*.hexcore_job.json`:

```
.hexcore_job.json              ← canonical (backward compatible)
sotr-triage.hexcore_job.json   ← named job
strings-deep.hexcore_job.json  ← named job
queue-launcher.hexcore_job.json ← orchestrator job
```

### Detection Priority

1. **Startup discovery** — auto-runs root-level canonical/named jobs; it does not recursively replay every pre-existing nested job
2. **FileSystemWatcher** — watches `**/*.hexcore_job.json` recursively for later create/change events → auto-runs
3. **Run Job** (`hexcore.pipeline.runJob`) — finds `.hexcore_job.json` first, then first `*.hexcore_job.json`
4. **Queue Job** (`hexcore.pipeline.queueJob`) — file picker shows ALL `*.hexcore_job.json` in workspace
5. **Validate Workspace** — scans ALL `*.hexcore_job.json`

### For Agents

When creating automation jobs from an agent session:

```
workspace/
├── .hexcore_job.json                  ← main triage job (auto-detected first)
├── phase2-strings.hexcore_job.json    ← agent creates this for deep string analysis
├── phase3-decompile.hexcore_job.json  ← agent creates this for batch decompilation
└── hexcore-reports/                   ← output directory
```

New or changed jobs are picked up by the watcher. For a pre-existing nested job after window startup, use Run Job/Queue Job or touch the file deliberately rather than assuming startup discovery executed it.

### Multi-Job Orchestration

A job can enqueue other jobs via `hexcore.pipeline.queueJob`:

```json
{
  "file": "target.exe",
  "outDir": "./reports/orchestrator",
  "steps": [
    {
      "comment": "Enqueue strings job (normal priority)",
      "cmd": "hexcore.pipeline.queueJob",
      "args": {
        "file": "phase2-strings.hexcore_job.json",
        "priority": "normal"
      }
    },
    {
      "comment": "Enqueue decompile job (low priority — runs last)",
      "cmd": "hexcore.pipeline.queueJob",
      "args": {
        "file": "phase3-decompile.hexcore_job.json",
        "priority": "low"
      }
    },
    {
      "comment": "Check queue status",
      "cmd": "hexcore.pipeline.jobStatus",
      "output": { "path": "queue-status.json" }
    }
  ]
}
```

Priority levels: `high` > `normal` > `low`. Default: `normal`. Logical queue slots default to `2` and are configurable from `1`–`16`; stateful jobs still execute under the whole-job isolation gate.

### Built-in Presets

Generate a job from a preset via `Create HexCore Job from Preset` (`hexcore.pipeline.createPresetJob`):

| Preset | Description |
|--------|-------------|
| `quick-triage` | File type + hashes + entropy + PE/ELF headers + strings |
| `full-static` | Everything in quick-triage + YARA + IOC + RTTI + AOB patterns |
| `ctf-reverse` | Focused on CTF challenges: strings + disasm + decompile + emulation |

Presets generate a `.hexcore_job.json` in the workspace root.

## HXDB Semantic Commands (3.8.4 / Disassembler 1.4.61)

The semantic model is target-bound in `.hexcore_session.db`.

| Command family | Purpose |
|----------------|---------|
| `hexcore.types.*` | Apply, edit, explain, import/export, or undo full prototypes |
| `hexcore.references.query/export` | Query/export typed R33 references |
| `hexcore.propagation.solve/status/export` | Run and inspect the bounded R34 fixed point |
| `hexcore.typeManager.*` | Transactional type create/edit/rename/delete/undo/import/export |
| `hexcore.types.ingestDebug` | Normalize BTF/DWARF records into HXDB |
| `hexcore.records.recover` | Infer records only from proven scoped object identities |
| `hexcore.pdb.importSemantics/resolveSymbols` | Validate/import PDB or resolve symbol cache entries |
| `hexcore.signatures.apply` | Apply API/header facts as signature evidence |
| `hexcore.semanticExplorer.open` | Interactive-only prototype/type/xref/history editor |

An edit is `partial` unless caller/consumer closure commits. Cancellation,
timeout, or budget exhaustion preserves the prior accepted generation. An
unresolved direct target remains an `address`; an indirect target remains a
qualified candidate until points-to/runtime evidence resolves it.

`hexcore.propagation.solve` and `hexcore.records.recover` run the fixed point
in a pure TypeScript Worker Thread over a read-only semantic snapshot. Their
artifacts expose `worker.transport:"perseus-sab-v1"`, worker duration,
heartbeat count, last phase/iteration, affected-function count, terminal state,
snapshot hash, `snapshotPreparationMs`, and `hardTerminated`. The sibling
`preparation` block separates reference sync, input collection, and summary
invalidation time. Accepted summaries/type bindings are
committed only in the parent after the live HXDB snapshot is revalidated.
Hard timeout returns a terminal non-committed result immediately and reaps the
worker asynchronously; do not increase the deadline to hide an oversized
closure. Prefer an evidence-backed `changedFunctions` set.

Operational worker/preparation diagnostics are deliberately excluded from the
semantic `outputHash`. Thread ids, heartbeat cadence, and timings may change
between runs without manufacturing a semantic diff.

If a restored analysis generation is older than active reference edges, the
producer preserves those edges and reports
`futureGenerationInvalidationDeferred` with `status:"partial"`. This is a
soundness barrier, not a command failure: consumers may inspect the conservative
model, but must not promote it as a complete proof until a monotonic generation
rebuild removes the barrier.

HQL 0.3.1 reads the active target-bound SemanticStore directly in the IDE;
offline scans use a read-only `SessionDbReader` that verifies `target_identity`.
Both combine HAST structure with typed facts and expose read failures instead
of silently returning zero facts. Preserve
`semanticFactCount`, `semanticFactsSha256`, match provenance, and `proofStatus`.
Runtime observations are binary/input/trace-bound corroboration and cannot by
themselves promote static evidence to `proven`.

Helix version identities are separate: extension/package `0.9.3`, native/JS
engine API `0.1.9`, and HAST producer schema version `0.1.9`. Reports must label
these fields independently instead of comparing them as one version stream.
