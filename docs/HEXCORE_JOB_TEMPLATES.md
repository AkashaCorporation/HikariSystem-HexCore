# HexCore Job Templates — v3.8.0

Safe default job templates for users and AI agents.

## Rules

- Job files must match the pattern `*.hexcore_job.json` to be auto-detected.
  - `.hexcore_job.json` — canonical (backward compatible, detected first by `Run Job`)
  - `{name}.hexcore_job.json` — named jobs (auto-detected by watcher + queue picker)
- Keep job files in the workspace root or subdirectories.
- Prefer absolute paths for `file` in multi-folder workspaces.
- Set `expectOutput: false` when you do not need step artifacts.
- Use explicit `output` only for reports you want to keep.
- Agents can create multiple named jobs — all are auto-detected without manual intervention.
- See `docs/HEXCORE_AUTOMATION.md` for full command reference and naming convention details.

---

## Template: Quick Triage (~30s)

Minimal first-look: identify file type, compute hashes, check entropy, extract strings.

```json
{
  "file": "C:\\path\\to\\target.exe",
  "outDir": "C:\\path\\to\\hexcore-reports\\quick-triage",
  "quiet": true,
  "steps": [
    { "cmd": "hexcore.filetype.detect", "timeoutMs": 60000 },
    { "cmd": "hexcore.hashcalc.calculate", "args": { "algorithms": "all" }, "timeoutMs": 90000 },
    { "cmd": "hexcore.entropy.analyze", "timeoutMs": 90000 },
    { "cmd": "hexcore.strings.extract", "args": { "minLength": 5 }, "timeoutMs": 120000 }
  ]
}
```

---

## Template: Full Static Analysis (~5min)

Comprehensive static analysis with advanced strings, Base64 detection, hex inspection, YARA scanning, IOC extraction, and unified report.

```json
{
  "file": "C:\\path\\to\\target.exe",
  "outDir": "C:\\path\\to\\hexcore-reports\\full-static",
  "quiet": true,
  "steps": [
    { "cmd": "hexcore.filetype.detect", "timeoutMs": 60000 },
    { "cmd": "hexcore.hashcalc.calculate", "args": { "algorithms": "all" }, "timeoutMs": 90000 },
    { "cmd": "hexcore.entropy.analyze", "timeoutMs": 90000 },
    { "cmd": "hexcore.strings.extract", "args": { "minLength": 5, "maxStrings": 50000 }, "timeoutMs": 180000 },
    { "cmd": "hexcore.strings.extractAdvanced", "timeoutMs": 180000 },
    { "cmd": "hexcore.base64.decodeHeadless", "timeoutMs": 90000 },
    { "cmd": "hexcore.hexview.dumpHeadless", "args": { "offset": 0, "size": 512 }, "output": { "path": "header-dump.json" }, "timeoutMs": 60000 },
    { "cmd": "hexcore.disasm.analyzeAll", "args": { "maxFunctions": 3000, "maxFunctionSize": 65536, "forceReload": true }, "timeoutMs": 300000 },
    { "cmd": "hexcore.yara.scan", "timeoutMs": 180000 },
    { "cmd": "hexcore.ioc.extract", "timeoutMs": 120000 },
    { "cmd": "hexcore.helix.decompile", "args": { "address": "entry", "count": 200 }, "output": { "path": "decompiled-entry.helix.c" }, "timeoutMs": 180000, "continueOnError": true },
    { "cmd": "hexcore.pipeline.composeReport", "output": { "path": "FINAL_REPORT.md", "format": "md" }, "timeoutMs": 60000 }
  ]
}
```

---

## Template: CTF Reverse Engineering

Focused on disassembly, formula extraction, constant checking, string references, and Base64 detection. Ideal for crackmes and RE challenges.

```json
{
  "file": "C:\\path\\to\\challenge.bin",
  "outDir": "C:\\path\\to\\hexcore-reports\\ctf-reverse",
  "quiet": true,
  "steps": [
    { "cmd": "hexcore.filetype.detect", "timeoutMs": 60000 },
    {
      "cmd": "hexcore.disasm.analyzeAll",
      "args": { "maxFunctions": 2500, "maxFunctionSize": 65536, "forceReload": true },
      "timeoutMs": 300000
    },
    {
      "cmd": "hexcore.disasm.exportASMHeadless",
      "output": { "path": "02-disassembly.asm" },
      "timeoutMs": 240000
    },
    {
      "cmd": "hexcore.helix.decompile",
      "args": { "address": "entry", "count": 300 },
      "output": { "path": "02b-decompiled.helix.c" },
      "timeoutMs": 180000,
      "continueOnError": true
    },
    {
      "cmd": "hexcore.disasm.searchStringHeadless",
      "args": { "query": "flag" },
      "output": { "path": "03-search-flag.json" },
      "timeoutMs": 120000
    },
    {
      "cmd": "hexcore.disasm.searchStringHeadless",
      "args": { "query": "HTB{" },
      "output": { "path": "04-search-htb.json" },
      "timeoutMs": 120000
    },
    {
      "cmd": "hexcore.strings.extractAdvanced",
      "output": { "path": "05-strings-advanced.json" },
      "timeoutMs": 180000
    },
    {
      "cmd": "hexcore.base64.decodeHeadless",
      "output": { "path": "06-base64.json" },
      "timeoutMs": 90000
    },
    {
      "cmd": "hexcore.hexview.searchHeadless",
      "args": { "pattern": "464C4147" },
      "output": { "path": "07-search-FLAG-bytes.json" },
      "timeoutMs": 120000
    }
  ]
}
```

**Note:** `buildFormula` only works with x86/x64 binaries. For ARM/ARM64/MIPS challenges, omit it or replace with `checkConstants`.

---

## Template: Helix Decompile — Single Step (~2min)

Decompile a single function to pseudo-C using the **Helix MLIR pipeline** in one shot. No prior `analyzeAll` needed. Best output quality: structured control flow, named parameters, struct field recovery, confidence score.

```json
{
  "file": "C:\\path\\to\\target.exe",
  "outDir": "C:\\path\\to\\hexcore-reports\\helix",
  "quiet": false,
  "continueOnError": true,
  "steps": [
    {
      "cmd": "hexcore.helix.decompile",
      "args": {
        "address": "0x14142FE90",
        "count": 150
      },
      "output": { "path": "bone_pos_calc.helix.c" },
      "timeoutMs": 180000
    }
  ]
}
```

**Notes:**
- Replace `address` with the virtual address of the function you want to decompile.
- `count` controls how many instructions are lifted (default `150`). Increase for larger functions.
- Output includes a `// Confidence: XX.X% (High/Medium/Low)` header.
- Only supports x86/x64 binaries.

---

## Template: Helix Decompile — Two-Step (Lift + Decompile) (~2–3min)

Recommended when you want to inspect the raw LLVM IR **and** the final pseudo-C separately. Step 1 lifts machine code to `.ll`, Step 2 runs the Helix MLIR pipeline on it.

```json
{
  "file": "C:\\path\\to\\target.exe",
  "outDir": "C:\\path\\to\\hexcore-reports\\helix",
  "quiet": false,
  "continueOnError": true,
  "steps": [
    {
      "cmd": "hexcore.disasm.liftToIR",
      "args": {
        "address": "0x14142FE90",
        "count": 150
      },
      "output": { "path": "bone_pos_calc.ll" },
      "timeoutMs": 120000
    },
    {
      "cmd": "hexcore.helix.decompileIR",
      "args": {
        "irPath": "C:\\path\\to\\hexcore-reports\\helix\\bone_pos_calc.ll"
      },
      "output": { "path": "bone_pos_calc.helix.c" },
      "timeoutMs": 180000
    }
  ]
}
```

**Notes:**
- `irPath` must be an **absolute path** to the `.ll` file produced by `liftToIR`. Use the same path as `outDir` + `output.path` from step 1.
- If `liftToIR` fails, `decompileIR` will also fail (the `.ll` file won't exist). `continueOnError: true` lets you see both statuses in `hexcore-pipeline.status.json`.
- Only supports x86/x64 binaries.

---

## Template: Deep Reverse Engineering (Decompile)

Full reverse engineering pipeline: disassemble, lift to LLVM IR, decompile to pseudo-C via Helix, extract strings and Base64. Ideal for understanding complex functions in PE/ELF binaries.

```json
{
  "file": "C:\\path\\to\\target.exe",
  "outDir": "C:\\path\\to\\hexcore-reports\\deep-reverse",
  "quiet": true,
  "continueOnError": true,
  "steps": [
    { "cmd": "hexcore.filetype.detect", "timeoutMs": 60000 },
    {
      "cmd": "hexcore.disasm.analyzeAll",
      "args": { "maxFunctions": 2500, "maxFunctionSize": 65536, "forceReload": true },
      "timeoutMs": 300000
    },
    {
      "cmd": "hexcore.disasm.disassembleAtHeadless",
      "args": { "address": "0x401000", "count": 200 },
      "output": { "path": "01-disasm-at.json" },
      "timeoutMs": 120000
    },
    {
      "cmd": "hexcore.disasm.liftToIR",
      "args": { "address": "0x401000", "count": 200 },
      "output": { "path": "02-lifted.ll" },
      "timeoutMs": 120000
    },
    {
      "cmd": "hexcore.helix.decompileIR",
      "args": { "irPath": "C:\\path\\to\\hexcore-reports\\deep-reverse\\02-lifted.ll" },
      "output": { "path": "03-decompiled.helix.c" },
      "timeoutMs": 180000
    },
    {
      "cmd": "hexcore.strings.extractAdvanced",
      "output": { "path": "04-strings-advanced.json" },
      "timeoutMs": 180000
    },
    {
      "cmd": "hexcore.base64.decodeHeadless",
      "output": { "path": "05-base64.json" },
      "timeoutMs": 90000
    },
    {
      "cmd": "hexcore.pipeline.composeReport",
      "output": { "path": "FINAL_REPORT.md", "format": "md" },
      "timeoutMs": 60000
    }
  ]
}
```

**Notes:**
- Replace `0x401000` with the function VA you want to decompile.
- `liftToIR` and `helix.decompileIR` only support x86/x64 binaries.
- Use absolute path for `irPath` (matches `outDir` + step 1 `output.path`).
- For Rellic-style output (mnemonic comments, deprecated), swap `hexcore.helix.decompileIR` with `hexcore.rellic.decompile`.

---

## Template: Malware Analysis

Full malware triage with PE/ELF analysis, Base64 detection, YARA threat detection, IOC extraction, and unified report.

```json
{
  "file": "C:\\path\\to\\suspect.exe",
  "outDir": "C:\\path\\to\\hexcore-reports\\malware-analysis",
  "quiet": true,
  "steps": [
    { "cmd": "hexcore.filetype.detect", "timeoutMs": 60000 },
    { "cmd": "hexcore.hashcalc.calculate", "args": { "algorithms": "all" }, "timeoutMs": 90000 },
    { "cmd": "hexcore.entropy.analyze", "timeoutMs": 90000 },
    { "cmd": "hexcore.disasm.analyzePEHeadless", "timeoutMs": 120000, "continueOnError": true },
    { "cmd": "hexcore.disasm.analyzeELFHeadless", "timeoutMs": 120000, "continueOnError": true },
    { "cmd": "hexcore.strings.extract", "args": { "minLength": 4, "maxStrings": 100000 }, "timeoutMs": 180000 },
    { "cmd": "hexcore.strings.extractAdvanced", "timeoutMs": 180000 },
    { "cmd": "hexcore.base64.decodeHeadless", "args": { "minConfidence": 50 }, "timeoutMs": 90000 },
    { "cmd": "hexcore.hexview.dumpHeadless", "args": { "offset": 0, "size": 512 }, "output": { "path": "header-dump.json" }, "timeoutMs": 60000 },
    { "cmd": "hexcore.hexview.searchHeadless", "args": { "pattern": "4D5A" }, "output": { "path": "mz-search.json" }, "timeoutMs": 120000 },
    { "cmd": "hexcore.yara.scan", "timeoutMs": 180000 },
    { "cmd": "hexcore.ioc.extract", "timeoutMs": 120000 },
    { "cmd": "hexcore.pipeline.composeReport", "output": { "path": "FINAL_REPORT.md", "format": "md" }, "timeoutMs": 60000 }
  ]
}
```

**Note:** Both `analyzePEHeadless` and `analyzeELFHeadless` are included with `continueOnError: true` — the wrong format will fail gracefully and the pipeline continues. These v3.7.5 commands replace the legacy `peanalyzer.analyze` / `elfanalyzer.analyze` with typed imports (180+ Windows API signatures), full symbol tables, relocations, and security indicators.

---

## Template: Minidump Triage

Analyze Windows crash dumps: threads, modules, memory regions.

```json
{
  "file": "C:\\path\\to\\crash.dmp",
  "outDir": "C:\\path\\to\\hexcore-reports\\minidump-triage",
  "quiet": true,
  "steps": [
    { "cmd": "hexcore.minidump.parse", "timeoutMs": 120000 },
    { "cmd": "hexcore.minidump.threads", "timeoutMs": 60000 },
    { "cmd": "hexcore.minidump.modules", "timeoutMs": 60000 },
    { "cmd": "hexcore.minidump.memory", "timeoutMs": 60000 }
  ]
}
```

---

## Template: Constant Sanity Only (Lightweight)

Quick check: validate analyst annotations against instruction immediates.

```json
{
  "file": "C:\\path\\to\\target.exe",
  "outDir": "C:\\path\\to\\hexcore-reports\\constant-sanity",
  "quiet": true,
  "steps": [
    {
      "cmd": "hexcore.disasm.checkConstants",
      "args": {
        "notesFile": "C:\\path\\to\\ANALYST_NOTES.md",
        "maxFindings": 200
      },
      "output": {
        "path": "constant-sanity.md",
        "format": "md"
      },
      "timeoutMs": 300000
    }
  ]
}
```

---

## Template: Lean Two-Step (analyzeAll + checkConstants)

Run deep analysis then validate constants. No large intermediate files.

```json
{
  "file": "C:\\path\\to\\target.exe",
  "outDir": "C:\\path\\to\\hexcore-reports\\lean-two-step",
  "quiet": true,
  "steps": [
    {
      "cmd": "hexcore.disasm.analyzeAll",
      "args": { "maxFunctions": 2500, "maxFunctionSize": 65536, "forceReload": true },
      "timeoutMs": 240000,
      "expectOutput": false
    },
    {
      "cmd": "hexcore.disasm.checkConstants",
      "args": { "maxFindings": 200 },
      "output": { "path": "constant-sanity.md", "format": "md" },
      "timeoutMs": 300000
    }
  ]
}
```

---

## Troubleshooting

- **`No .hexcore_job.json file was found.`** — Ensure the file exists in the workspace root opened in HexCore.
- **`timed out after ...`** — Increase `timeoutMs` for heavy binaries. Lower `maxFunctions`/`maxFunctionSize` on `analyzeAll`.
- **Missing report file** — Confirm step status is `ok` in `hexcore-pipeline.status.json`. Failed/timed-out steps do not produce output.
- **`Command is not headless-safe`** — The command requires UI interaction. Check `docs/HEXCORE_AUTOMATION.md` for headless alternatives.

---

## Template: Helix Decompile — Loop/SIMD Functions (~3min)

For functions with loop-at-entry patterns (backward branches to entry block) or heavy SIMD code that previously crashed the engine. These are now fully supported in v3.7.0-beta.1.

```json
{
  "file": "C:\\path\\to\\target.exe",
  "outDir": "C:\\path\\to\\hexcore-reports\\helix-loop",
  "quiet": false,
  "continueOnError": true,
  "steps": [
    {
      "cmd": "hexcore.debug.disposeHeadless",
      "timeoutMs": 30000
    },
    {
      "cmd": "hexcore.disasm.liftToIR",
      "args": {
        "address": "0x140001728",
        "count": 200
      },
      "output": { "path": "logic_1728.ll" },
      "timeoutMs": 120000
    },
    {
      "cmd": "hexcore.helix.decompileIR",
      "args": {
        "irPath": "C:\\path\\to\\hexcore-reports\\helix-loop\\logic_1728.ll"
      },
      "output": { "path": "logic_1728.helix.c" },
      "timeoutMs": 240000
    }
  ]
}
```

**Notes:**
- `disposeHeadless` at the start prevents `UC_ERR_MAP` if a prior session was left open.
- `irPath` must be an absolute path to the `.ll` file.
- Functions with backward branches to the first block (common in loops at function entry) are now handled via `LLParser(UpgradeDebugInfo=false)` in the Helix engine.
- Increase `count` for larger functions (>3000 bytes: use 300+).

---

## Template: Emulation with PRNG (v3.7.1)

Emulate a crackme that uses glibc `rand()` with a known seed. Permissive memory mapping enabled for self-modifying VMs.

```json
{
  "file": "C:\\path\\to\\crackme.elf",
  "outDir": "C:\\path\\to\\hexcore-reports\\prng-emulation",
  "quiet": true,
  "steps": [
    { "cmd": "hexcore.debug.disposeHeadless", "timeoutMs": 30000 },
    {
      "cmd": "hexcore.debug.emulateFullHeadless",
      "args": {
        "arch": "x64",
        "stdin": "test_input\\n",
        "maxInstructions": 500000,
        "permissiveMemoryMapping": true,
        "prngMode": "glibc",
        "prngSeed": 4919,
        "collectSideChannels": true,
        "memoryDumps": [
          { "address": "0x600000", "size": 4096, "trigger": "end" }
        ],
        "breakpointConfigs": [
          { "address": "0x401200", "autoSnapshot": true }
        ]
      },
      "output": { "path": "emulation-result.json" },
      "timeoutMs": 300000
    }
  ]
}
```

**Notes:**
- `prngMode: "glibc"` provides faithful 344-state TYPE_3 algorithm matching native glibc `rand()`.
- Use `"msvcrt"` for Windows crackmes (LCG: `seed * 214013 + 2531011`).
- `permissiveMemoryMapping: true` maps all segments with RWX — required for VMs that execute from .rodata/.data.
- `collectSideChannels: true` captures instruction counts per basic block and branch statistics.
- `breakpointConfigs` with `autoSnapshot: true` captures registers + stack at breakpoint, then continues.

---

## Template: VM Detection Pipeline (v3.7.1)

Detect VM-based obfuscation, filter junk instructions, and detect PRNG patterns in a single pass.

```json
{
  "file": "C:\\path\\to\\obfuscated.exe",
  "outDir": "C:\\path\\to\\hexcore-reports\\vm-detection",
  "quiet": true,
  "steps": [
    { "cmd": "hexcore.filetype.detect", "timeoutMs": 60000 },
    {
      "cmd": "hexcore.disasm.analyzeAll",
      "args": {
        "maxFunctions": 2500,
        "forceReload": true,
        "filterJunk": true,
        "detectVM": true,
        "detectPRNG": true
      },
      "timeoutMs": 300000
    },
    {
      "cmd": "hexcore.disasm.disassembleAtHeadless",
      "args": { "address": "0x401000", "count": 200, "filterJunk": true },
      "output": { "path": "disasm-filtered.json" },
      "timeoutMs": 120000
    },
    { "cmd": "hexcore.strings.extractAdvanced", "timeoutMs": 180000 },
    {
      "cmd": "hexcore.pipeline.composeReport",
      "output": { "path": "FINAL_REPORT.md", "format": "md" },
      "timeoutMs": 60000
    }
  ]
}
```

**Notes:**
- `filterJunk: true` removes callfuscation, nop sleds, identity ops. Reports `junkCount` and `junkRatio`.
- `detectVM: true` identifies dispatcher patterns, handler tables, and operand stacks.
- `detectPRNG: true` finds srand/rand call sites and extracts seed values.

---

## Template: PE64 Runtime Trace Loop (Wave 2)

Capture the API trace of a stable PE/x64 runtime loop after a long `continueHeadless` window. Useful for identifying repeated WinAPI / CRT contracts once the worker runtime is stable.

```json
{
  "file": "C:\\path\\to\\target.exe",
  "outDir": "C:\\path\\to\\hexcore-reports\\pe64-trace-loop",
  "quiet": true,
  "steps": [
    {
      "cmd": "hexcore.debug.emulateHeadless",
      "args": {
        "arch": "x64",
        "permissiveMemoryMapping": true
      },
      "output": { "path": "01-init.json" },
      "timeoutMs": 30000
    },
    {
      "cmd": "hexcore.debug.continueHeadless",
      "args": { "maxSteps": 50000 },
      "output": { "path": "02-run-50000.json" },
      "timeoutMs": 30000
    },
    {
      "cmd": "hexcore.debug.getStateHeadless",
      "output": { "path": "03-state.json" },
      "timeoutMs": 30000
    },
    {
      "cmd": "hexcore.debug.exportTraceHeadless",
      "output": { "path": "04-trace.json" },
      "timeoutMs": 30000
    },
    {
      "cmd": "hexcore.debug.disposeHeadless",
      "output": { "path": "05-dispose.json" },
      "timeoutMs": 30000
    }
  ]
}
```

**Notes:**
- `executionBackend` in `01-init.json`, `02-run-50000.json`, and `03-state.json` should show which runtime path actually ran.
- `03-state.json` is the easiest place to inspect the loop PC before adding breakpoints.
- `04-trace.json` is the best artifact for comparing repeated API cycles between builds.

---

## Template: PE64 Breakpoint Loop (Wave 2)

Set a breakpoint on a known runtime loop PC and export the trace after the session pauses there. Useful once `trace-loop` identifies a repeated address.

```json
{
  "file": "C:\\path\\to\\target.exe",
  "outDir": "C:\\path\\to\\hexcore-reports\\pe64-break-loop",
  "quiet": true,
  "steps": [
    {
      "cmd": "hexcore.debug.emulateHeadless",
      "args": {
        "arch": "x64",
        "permissiveMemoryMapping": true
      },
      "output": { "path": "01-init.json" },
      "timeoutMs": 30000
    },
    {
      "cmd": "hexcore.debug.setBreakpointHeadless",
      "args": {
        "address": "0x141388c80"
      },
      "output": { "path": "02-breakpoint.json" },
      "timeoutMs": 30000
    },
    {
      "cmd": "hexcore.debug.continueHeadless",
      "args": { "maxSteps": 50000 },
      "output": { "path": "03-run.json" },
      "timeoutMs": 30000
    },
    {
      "cmd": "hexcore.debug.getStateHeadless",
      "output": { "path": "04-state.json" },
      "timeoutMs": 30000
    },
    {
      "cmd": "hexcore.debug.exportTraceHeadless",
      "output": { "path": "05-trace.json" },
      "timeoutMs": 30000
    },
    {
      "cmd": "hexcore.debug.disposeHeadless",
      "output": { "path": "06-dispose.json" },
      "timeoutMs": 30000
    }
  ]
}
```

**Notes:**
- Replace `0x141388c80` with the current loop PC from `getStateHeadless`.
- `setBreakpointHeadless` now writes its output file correctly, so the pipeline can validate `02-breakpoint.json`.

---

## Template: Adaptive Pipeline with onResult Branching (v3.7.1)

Uses `onResult` conditional branching to adapt the pipeline based on intermediate results. If entropy is high (likely packed), skip straight to YARA scanning.

```json
{
  "file": "C:\\path\\to\\suspect.exe",
  "outDir": "C:\\path\\to\\hexcore-reports\\adaptive",
  "quiet": true,
  "steps": [
    {
      "cmd": "hexcore.entropy.analyze",
      "output": { "path": "01-entropy.json" },
      "timeoutMs": 90000,
      "onResult": {
        "field": "maxEntropy",
        "operator": "gt",
        "value": 7.5,
        "action": "goto",
        "actionValue": 4
      }
    },
    { "cmd": "hexcore.strings.extract", "args": { "minLength": 5 }, "timeoutMs": 120000 },
    {
      "cmd": "hexcore.disasm.analyzeAll",
      "args": { "filterJunk": true, "detectVM": true },
      "timeoutMs": 300000
    },
    {
      "cmd": "hexcore.helix.decompile",
      "args": { "address": "entry", "count": 200 },
      "output": { "path": "03-decompiled.helix.c" },
      "timeoutMs": 180000,
      "continueOnError": true
    },
    { "cmd": "hexcore.yara.scan", "timeoutMs": 180000 },
    { "cmd": "hexcore.ioc.extract", "timeoutMs": 120000 },
    {
      "cmd": "hexcore.pipeline.composeReport",
      "output": { "path": "FINAL_REPORT.md", "format": "md" },
      "timeoutMs": 60000
    }
  ]
}
```

**Notes:**
- `onResult` on step 0: if `maxEntropy > 7.5`, jumps to step 4 (YARA scan), skipping strings/disassembly/decompile.
- Operators: `contains`, `equals`, `not`, `gt`, `lt`, `regex`.
- Actions: `skip` (skip N steps), `goto` (jump to step index), `abort` (stop pipeline), `log` (log and continue).
- `goto` allows loops (max 100 iterations enforced).
- See `docs/HEXCORE_AUTOMATION.md` for full `onResult` schema.

---

## v3.7.3 Templates

New templates covering dynamic memory search, RTTI class hierarchy extraction, AOB signature scanning, batch string intelligence, and step-reference pipelines introduced in v3.7.3.

---

## Template: Dynamic Analysis with Memory Search (v3.7.3)

Emulate a PE in headless mode, run it forward, then search RAM for decrypted payload markers (MZ header and ASCII strings) while the session is still alive.

```json
{
  "name": "Dynamic Analysis + Memory Pattern Search",
  "description": "Emulate a PE, search for decrypted payload markers in RAM",
  "file": "${file}",
  "outDir": "./results",
  "steps": [
    { "cmd": "hexcore.debug.emulateHeadless", "args": { "file": "${file}", "arch": "x64", "keepAlive": true }, "timeoutMs": 60000 },
    { "cmd": "hexcore.debug.continueHeadless", "args": { "maxInstructions": 500000 }, "timeoutMs": 120000 },
    { "cmd": "hexcore.debug.searchMemoryHeadless", "args": { "pattern": "4D 5A 90 00", "encoding": "hex", "regions": "heap" }, "timeoutMs": 60000 },
    { "cmd": "hexcore.debug.searchMemoryHeadless", "args": { "pattern": "This program", "encoding": "ascii", "regions": "all" }, "timeoutMs": 60000 },
    { "cmd": "hexcore.debug.disposeHeadless", "timeoutMs": 30000 }
  ]
}
```

**Notes:**
- `keepAlive: true` keeps the emulator session open after `emulateHeadless` so subsequent steps can read its memory.
- `searchMemoryHeadless` with `encoding: "hex"` accepts space-separated byte strings (`4D 5A 90 00` = MZ header).
- `regions: "heap"` narrows the search to heap-allocated memory; use `"all"` to scan every mapped region.
- Always end with `disposeHeadless` to release the Unicorn engine handle.

---

## Template: RTTI Class Hierarchy Analysis (v3.7.3)

Extract C++ class names and inheritance chains from a PE binary via the RTTI scanner. Requires a prior `analyzeAll` pass to populate the function index.

```json
{
  "name": "RTTI Class Discovery",
  "description": "Extract C++ class names from PE binary via RTTI scan",
  "file": "${file}",
  "outDir": "./results",
  "steps": [
    { "cmd": "hexcore.disasm.analyzeAll", "args": { "file": "${file}" }, "timeoutMs": 300000 },
    { "cmd": "hexcore.disasm.rttiScanHeadless", "args": { "file": "${file}" }, "timeoutMs": 120000 }
  ]
}
```

**Notes:**
- `analyzeAll` must run first — `rttiScanHeadless` uses the populated function index to locate vtables.
- Works on MSVC-compiled PE/PE+ binaries; GCC/Clang ELF RTTI support is experimental in v3.7.3.
- Results include class name, vtable address, base-class list, and method count per class.

---

## Template: AOB Signature Scan (v3.7.3)

Search for trainer-style array-of-bytes patterns with wildcard support. Useful for locating game engine functions, cheat-engine style offsets, or stable code signatures across builds.

```json
{
  "name": "AOB Signature Scan",
  "description": "Search for byte patterns (trainer-style AOB scan)",
  "file": "${file}",
  "outDir": "./results",
  "steps": [
    { "cmd": "hexcore.disasm.analyzeAll", "args": { "file": "${file}" }, "timeoutMs": 300000 },
    { "cmd": "hexcore.disasm.searchBytesHeadless", "args": { "pattern": "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20", "maxResults": 50 }, "timeoutMs": 120000 }
  ]
}
```

**Notes:**
- `??` is the wildcard token — matches any single byte at that position.
- `maxResults` caps the hit list; omit or set to `0` for unlimited results (can be slow on large binaries).
- `analyzeAll` is required beforehand so `searchBytesHeadless` operates on the decoded instruction stream rather than raw bytes, which reduces false positives inside data sections.

---

## Template: Batch String Intelligence (v3.7.3)

Submit multiple search terms in a single `searchStringHeadless` call. More efficient than chaining individual queries, and produces a single consolidated result file.

```json
{
  "name": "Batch String Intelligence",
  "description": "Search for multiple suspicious strings in one pass",
  "file": "${file}",
  "outDir": "./results",
  "steps": [
    { "cmd": "hexcore.disasm.analyzeAll", "args": { "file": "${file}" }, "timeoutMs": 300000 },
    {
      "cmd": "hexcore.disasm.searchStringHeadless",
      "args": {
        "queries": ["password", "encrypt", "decrypt", "key", "token", "secret", "admin", "root"]
      },
      "output": { "path": "string-intel.json" },
      "timeoutMs": 120000
    }
  ]
}
```

**Notes:**
- `queries` accepts an array of strings — all terms are searched in one pass against the string index built by `analyzeAll`.
- Results are grouped per query in the output JSON, each with address, section, and surrounding context.
- Case-insensitive by default; add `"caseSensitive": true` to `args` if exact casing matters.

---

## Template: Full Decompilation Pipeline with Step References (v3.7.3)

Lift a code region to LLVM IR, then pass the IR path to the Helix decompiler using a `$step[N].output` reference — no hardcoded absolute paths required.

```json
{
  "name": "Full Decompilation Pipeline with Step References",
  "description": "Lift → Decompile using step output referencing",
  "file": "${file}",
  "outDir": "./results",
  "steps": [
    { "cmd": "hexcore.disasm.analyzeAll", "args": { "file": "${file}" }, "timeoutMs": 300000 },
    {
      "cmd": "hexcore.disasm.liftToIR",
      "args": { "address": "0x140001000", "size": 4096 },
      "output": { "path": "lifted.ll" },
      "timeoutMs": 120000
    },
    {
      "cmd": "hexcore.helix.decompile",
      "args": { "irPath": "$step[1].output" },
      "output": { "path": "decompiled.helix.c" },
      "timeoutMs": 180000,
      "continueOnError": true
    }
  ]
}
```

**Notes:**
- `$step[N].output` resolves to the `output.path` of step N at runtime, relative to `outDir`. Step indices are zero-based.
- This eliminates hardcoded paths and makes the template portable across machines and `outDir` values.
- `size` (bytes) is used instead of `count` (instructions) when the region boundary is known; both are accepted by `liftToIR`.
- `continueOnError: true` on the decompile step ensures `hexcore-pipeline.status.json` is written even if Helix returns a partial result.

---

## v3.7.4 Templates

New templates covering section-filtered strings, session-aware decompilation, ELF kernel module analysis, and rename/retype workflows.

---

## Template: Section-Filtered String Extraction (v3.7.4)

Extract strings only from `.rdata` and `.data` sections — eliminates 99% noise from `.text` on large binaries.

```json
{
  "file": "C:\\path\\to\\target.exe",
  "outDir": "C:\\path\\to\\hexcore-reports\\filtered-strings",
  "quiet": true,
  "steps": [
    {
      "cmd": "hexcore.disasm.extractStrings",
      "args": { "sections": [".rdata", ".data"], "minLength": 5, "maxStrings": 50000 },
      "output": { "path": "strings-rdata.json" },
      "timeoutMs": 180000
    }
  ]
}
```

**Notes:**
- `sections` accepts PE section names (`.rdata`, `.data`, `.rsrc`) or ELF section names (`.rodata`, `.data`).
- Without `sections`, defaults to priority scan: `.rdata` (60%) > `.data` (20%) > `.rsrc` (10%) > `.text` (10%).
- `minLength` default is now 6 (was 4 in v3.7.3).

---

## Template: Session-Aware Decompilation (v3.7.4)

Decompile a function with analyst-defined renames and retypes applied to the output.

```json
{
  "file": "C:\\path\\to\\target.exe",
  "outDir": "C:\\path\\to\\hexcore-reports\\session-decompile",
  "quiet": true,
  "continueOnError": true,
  "steps": [
    {
      "cmd": "hexcore.disasm.analyzeAll",
      "args": { "maxFunctions": 2500, "forceReload": true },
      "timeoutMs": 300000,
      "expectOutput": false
    },
    {
      "cmd": "hexcore.disasm.renameFunction",
      "args": { "address": "0x14003EDD0", "name": "ValidateFlag" },
      "timeoutMs": 10000
    },
    {
      "cmd": "hexcore.disasm.retypeVariable",
      "args": { "funcAddress": "0x14003EDD0", "variableName": "param_1", "newType": "int32_t" },
      "timeoutMs": 10000
    },
    {
      "cmd": "hexcore.helix.decompile",
      "args": { "address": "0x14003EDD0", "count": 500, "autoBacktrack": true },
      "output": { "path": "ValidateFlag.helix.c" },
      "timeoutMs": 300000
    }
  ]
}
```

**Notes:**
- `renameFunction` and `retypeVariable` persist to `.hexcore_session.db` — surviving across sessions.
- `helix.decompile` automatically reads the session DB and applies renames/retypes to the output.
- Renames propagate to all call sites in subsequent decompilations.

---

## Template: ELF Kernel Module Analysis (v3.7.4)

Analyze Linux kernel modules (`.ko`) with ELF relocation processing and ftrace preamble handling.

```json
{
  "file": "C:\\path\\to\\driver.ko",
  "outDir": "C:\\path\\to\\hexcore-reports\\kernel-module",
  "quiet": true,
  "continueOnError": true,
  "steps": [
    { "cmd": "hexcore.filetype.detect", "timeoutMs": 60000 },
    { "cmd": "hexcore.elfanalyzer.analyze", "timeoutMs": 120000 },
    {
      "cmd": "hexcore.disasm.analyzeAll",
      "args": { "maxFunctions": 5000, "maxFunctionSize": 65536, "forceReload": true },
      "timeoutMs": 600000
    },
    {
      "cmd": "hexcore.disasm.rttiScanHeadless",
      "output": { "path": "rtti-scan.json" },
      "timeoutMs": 120000
    },
    {
      "cmd": "hexcore.disasm.extractStrings",
      "args": { "sections": [".rodata"], "minLength": 5, "maxStrings": 50000 },
      "output": { "path": "strings-rodata.json" },
      "timeoutMs": 180000
    },
    {
      "cmd": "hexcore.disasm.searchStringHeadless",
      "args": { "queries": ["ioctl", "copy_from_user", "copy_to_user", "mutex_lock", "kmalloc", "kfree", "printk"] },
      "output": { "path": "kernel-api-xrefs.json" },
      "timeoutMs": 120000
    },
    {
      "cmd": "hexcore.helix.decompile",
      "args": { "address": "entry", "count": 500, "autoBacktrack": true },
      "output": { "path": "entry-decompiled.helix.c" },
      "timeoutMs": 300000
    },
    {
      "cmd": "hexcore.pipeline.composeReport",
      "output": { "path": "KERNEL_MODULE_REPORT.md", "format": "md" },
      "timeoutMs": 60000
    }
  ]
}
```

**Notes:**
- `.ko` files are ELF ET_REL (relocatable). HexCore processes `.rela.text` relocations automatically — external kernel API calls appear with real names in Helix output.
- ftrace preambles (`-fpatchable-function-entry=16,16`) are auto-skipped in `analyzeAll`.
- `extractStrings` with `sections: [".rodata"]` targets the read-only data section (ELF equivalent of PE `.rdata`).
- Batch `queries` in `searchStringHeadless` finds all kernel API cross-references in one pass.
- A `[WARN] Target is a relocatable ELF (ET_REL)` will appear in pipeline log.

---

## Template: Rename/Retype Workflow (v3.7.4)

Batch rename and retype functions and variables via pipeline, then decompile with annotations applied.

```json
{
  "file": "C:\\path\\to\\target.exe",
  "outDir": "C:\\path\\to\\hexcore-reports\\annotated",
  "quiet": true,
  "continueOnError": true,
  "steps": [
    {
      "cmd": "hexcore.disasm.analyzeAll",
      "args": { "maxFunctions": 2500, "forceReload": true },
      "timeoutMs": 300000,
      "expectOutput": false
    },
    { "cmd": "hexcore.disasm.renameFunction", "args": { "address": "0x140229680", "name": "HealthComponent_RPC" }, "timeoutMs": 10000 },
    { "cmd": "hexcore.disasm.renameFunction", "args": { "address": "0x1409BF3E0", "name": "SetHealth" }, "timeoutMs": 10000 },
    { "cmd": "hexcore.disasm.renameFunction", "args": { "address": "0x140859DE8", "name": "PlayerAwareness_UpdatePosition" }, "timeoutMs": 10000 },
    { "cmd": "hexcore.disasm.retypeVariable", "args": { "funcAddress": "0x140859DE8", "variableName": "r14", "newType": "GlobalWorldContext*" }, "timeoutMs": 10000 },
    {
      "cmd": "hexcore.helix.decompile",
      "args": { "address": "0x140859DE8", "count": 500, "autoBacktrack": true },
      "output": { "path": "UpdatePosition-annotated.helix.c" },
      "timeoutMs": 300000
    }
  ]
}
```

**Notes:**
- All renames/retypes persist in `.hexcore_session.db` — no need to re-apply next session.
- `helix.decompile` output reflects annotations: `sub_140859DE8` → `PlayerAwareness_UpdatePosition`, `int64_t r14` → `GlobalWorldContext* r14`.
- Session DB is auto-created next to the binary on first annotation command.

---

## v3.8.0 Templates

New templates covering priority job queuing, section-aware ELF kernel module analysis with confidence scoring, and BTF-enhanced deep kernel analysis.

---

## Template: Priority Job Queue — Batch Analysis (v3.8.0)

Queue multiple analysis jobs with different priorities. High-priority jobs execute first.

```json
{
  "file": "C:\\path\\to\\critical-malware.exe",
  "outDir": "C:\\path\\to\\hexcore-reports\\priority-batch",
  "priority": "high",
  "quiet": true,
  "steps": [
    { "cmd": "hexcore.filetype.detect", "timeoutMs": 60000 },
    { "cmd": "hexcore.hashcalc.calculate", "args": { "algorithms": "all" }, "timeoutMs": 90000 },
    { "cmd": "hexcore.entropy.analyze", "timeoutMs": 90000 },
    { "cmd": "hexcore.disasm.analyzePEHeadless", "timeoutMs": 120000, "continueOnError": true },
    { "cmd": "hexcore.yara.scan", "timeoutMs": 180000 },
    { "cmd": "hexcore.pipeline.composeReport", "output": { "path": "PRIORITY_REPORT.md", "format": "md" }, "timeoutMs": 60000 }
  ]
}
```

**Notes:**
- `priority: "high"` ensures this job runs before `"normal"` and `"low"` priority jobs in the queue.
- Use `hexcore.pipeline.queueJob` to submit: `{ "cmd": "hexcore.pipeline.queueJob", "args": { "file": "path/to/job.json", "priority": "high" } }`
- Monitor with `hexcore.pipeline.jobStatus` — returns `queued`, `running`, `done`, `failed`, or `cancelled`.
- Cancel with `hexcore.pipeline.cancelJob` using the `jobId` returned by `queueJob`.
- Queue supports up to 5 concurrent workers (default: 2). Configure in HexCore settings.

---

## Template: Section-Aware ELF Kernel Module Analysis (v3.8.0)

Analyze Linux kernel modules with section-aware lifting — processes `.text`, `.init.text`, and `.exit.text` separately for complete module coverage.

```json
{
  "file": "C:\\path\\to\\driver.ko",
  "outDir": "C:\\path\\to\\hexcore-reports\\section-aware-ko",
  "quiet": true,
  "continueOnError": true,
  "steps": [
    { "cmd": "hexcore.filetype.detect", "timeoutMs": 60000 },
    { "cmd": "hexcore.elfanalyzer.analyze", "timeoutMs": 120000 },
    {
      "cmd": "hexcore.disasm.analyzeELFHeadless",
      "timeoutMs": 180000
    },
    {
      "cmd": "hexcore.disasm.analyzeAll",
      "args": { "maxFunctions": 5000, "maxFunctionSize": 65536, "forceReload": true },
      "timeoutMs": 600000
    },
    {
      "cmd": "hexcore.disasm.liftToIR",
      "args": { "allExecutableSections": true },
      "output": { "path": "all-sections-lifted.json" },
      "timeoutMs": 300000
    },
    {
      "cmd": "hexcore.disasm.extractStrings",
      "args": { "sections": [".rodata"], "minLength": 5, "maxStrings": 50000 },
      "output": { "path": "strings-rodata.json" },
      "timeoutMs": 180000
    },
    {
      "cmd": "hexcore.disasm.searchStringHeadless",
      "args": { "queries": ["ioctl", "copy_from_user", "copy_to_user", "mutex_lock", "kmalloc", "kfree", "kref_get", "kref_put"] },
      "output": { "path": "kernel-api-xrefs.json" },
      "timeoutMs": 120000
    },
    {
      "cmd": "hexcore.pipeline.composeReport",
      "output": { "path": "KERNEL_MODULE_REPORT.md", "format": "md" },
      "timeoutMs": 60000
    }
  ]
}
```

**Notes:**
- `allExecutableSections: true` in `liftToIR` processes `.text`, `.init.text`, `.exit.text` and any other executable sections.
- Output includes `sections` array with per-section grouping: `{ name: ".init.text", purpose: "module_init", functions: [...] }`.
- Section purposes: `runtime` (.text), `module_init` (.init.text), `module_cleanup` (.exit.text), `trampoline` (.plt).
- `analyzeELFHeadless` now includes `confidenceScore` in output — weighted score (0-1) based on symbol resolution, CFG complexity, kernel pattern recognition, and symtab completeness.
- Confidence score `detectedPatterns` lists recognized kernel APIs (mutex_lock, copy_from_user, kref_get, etc.).

---

## Template: BTF-Enhanced Kernel Module Deep Analysis (v3.8.0)

Full kernel module reverse engineering with BTF type information from vmlinux for struct field naming and parameter typing.

```json
{
  "file": "C:\\path\\to\\driver.ko",
  "outDir": "C:\\path\\to\\hexcore-reports\\btf-enhanced",
  "quiet": true,
  "continueOnError": true,
  "steps": [
    { "cmd": "hexcore.filetype.detect", "timeoutMs": 60000 },
    {
      "cmd": "hexcore.disasm.analyzeELFHeadless",
      "timeoutMs": 180000
    },
    {
      "cmd": "hexcore.disasm.analyzeAll",
      "args": { "maxFunctions": 5000, "maxFunctionSize": 65536, "forceReload": true },
      "timeoutMs": 600000
    },
    {
      "cmd": "hexcore.disasm.liftToIR",
      "args": { "allExecutableSections": true },
      "output": { "path": "all-sections.json" },
      "timeoutMs": 300000
    },
    {
      "cmd": "hexcore.helix.decompile",
      "args": { "address": "entry", "count": 500, "autoBacktrack": true },
      "output": { "path": "entry-decompiled.helix.c" },
      "timeoutMs": 300000
    },
    {
      "cmd": "hexcore.disasm.searchStringHeadless",
      "args": { "queries": ["copy_from_user", "copy_to_user", "kref_get", "kref_put", "mutex_lock", "BUG_ON", "capable"] },
      "output": { "path": "security-api-xrefs.json" },
      "timeoutMs": 120000
    },
    { "cmd": "hexcore.yara.scan", "args": { "categories": ["drivers"] }, "timeoutMs": 180000 },
    {
      "cmd": "hexcore.pipeline.composeReport",
      "output": { "path": "BTF_ENHANCED_REPORT.md", "format": "md" },
      "timeoutMs": 60000
    }
  ]
}
```

**Notes:**
- When the `.ko` file or a linked `vmlinux` contains a `.BTF` section, HexCore automatically parses BTF type data.
- BTF enables: kernel struct layout recovery, function parameter auto-typing (e.g., `kctx` → `struct kbase_context *`), and struct field naming.
- `analyzeELFHeadless` output includes `btfData` when BTF is available, plus `confidenceScore` with bonus for BTF/DWARF presence.
- BTF is standard in modern Linux kernels (5.2+, Ubuntu 20.04+, Fedora 31+). For older kernels, DWARF fallback is planned.
- Combine with section-aware lifting for complete `.init.text`/`.exit.text` coverage.

---

## Template: Named Job — Strings Deep Scan (v3.8.0)

Named job file (`strings-deep.hexcore_job.json`) — auto-detected by watcher alongside the canonical `.hexcore_job.json`.

```json
{
  "file": "C:\\path\\to\\target.exe",
  "outDir": "C:\\path\\to\\hexcore-reports\\strings-deep",
  "quiet": true,
  "steps": [
    { "cmd": "hexcore.strings.extract", "args": { "minLength": 4, "maxStrings": 100000 }, "output": { "path": "strings-all.json" }, "timeoutMs": 180000 },
    { "cmd": "hexcore.strings.extractAdvanced", "output": { "path": "strings-advanced.json" }, "timeoutMs": 300000 },
    { "cmd": "hexcore.base64.decodeHeadless", "output": { "path": "base64-decoded.json" }, "timeoutMs": 90000 },
    {
      "cmd": "hexcore.disasm.searchStringHeadless",
      "args": { "query": "password" },
      "output": { "path": "xref-password.json" },
      "timeoutMs": 120000
    },
    {
      "cmd": "hexcore.disasm.searchStringHeadless",
      "args": { "query": "token" },
      "output": { "path": "xref-token.json" },
      "timeoutMs": 120000
    }
  ]
}
```

**Notes:**
- Save as `strings-deep.hexcore_job.json` (not `.hexcore_job.json`) to run alongside other jobs.
- The watcher auto-detects `*.hexcore_job.json` — no manual "Run Job" needed.

---

## Template: Multi-Job Orchestrator (v3.8.0)

Orchestrator job that enqueues other named jobs with priority levels. Save as `orchestrator.hexcore_job.json`.

```json
{
  "file": "C:\\path\\to\\target.exe",
  "outDir": "C:\\path\\to\\hexcore-reports\\orchestrator",
  "quiet": true,
  "continueOnError": true,
  "steps": [
    {
      "comment": "Phase 1: Quick triage (high priority — runs first)",
      "cmd": "hexcore.pipeline.queueJob",
      "args": {
        "file": "triage.hexcore_job.json",
        "priority": "high"
      },
      "output": { "path": "queue-triage-id.json" },
      "timeoutMs": 30000
    },
    {
      "comment": "Phase 2: Deep strings (normal priority)",
      "cmd": "hexcore.pipeline.queueJob",
      "args": {
        "file": "strings-deep.hexcore_job.json",
        "priority": "normal"
      },
      "output": { "path": "queue-strings-id.json" },
      "timeoutMs": 30000
    },
    {
      "comment": "Phase 3: Batch decompile (low priority — runs last)",
      "cmd": "hexcore.pipeline.queueJob",
      "args": {
        "file": "decompile-batch.hexcore_job.json",
        "priority": "low"
      },
      "output": { "path": "queue-decompile-id.json" },
      "timeoutMs": 30000
    },
    {
      "comment": "Show queue status",
      "cmd": "hexcore.pipeline.jobStatus",
      "output": { "path": "queue-status.json" },
      "timeoutMs": 30000
    }
  ]
}
```

**Notes:**
- Each `queueJob` step returns a `jobId` for tracking.
- Priority order: `high` → `normal` → `low`. Jobs at the same priority level run FIFO.
- The orchestrator itself runs instantly (just enqueues) — the heavy work runs in queued jobs.
- Monitor with `hexcore.pipeline.jobStatus`, cancel with `hexcore.pipeline.cancelJob`.

---

## Emulator Setting — `hexcore.emulator` (v3.8.0)

HexCore ships two emulation engines that can coexist. The `hexcore.emulator` user/workspace setting picks which ones activate:

| Value | What activates | When to use |
|-------|---------------|-------------|
| `"both"` **(default)** | Azoth + legacy TypeScript debugger side-by-side | Pipelines that exercise both engines; side-by-side comparison |
| `"azoth"` | Only Project Azoth (hexcore-elixir) | Lighter activation; Azoth-only analysis |
| `"debugger"` | Only legacy hexcore-debugger | Regression comparison against Azoth |

Each extension has its own native module, so `"both"` does NOT create libuc conflicts — they run independently.

**How to switch (no settings.json editing required):**
- Click the `$(debug-alt) Emulator: Both` indicator in the VS Code status bar (bottom right) — opens a QuickPick with all three options.
- Or open the Command Palette (`Ctrl+Shift+P`) and run **`HexCore: Switch Emulator…`**.
- The switcher writes to workspace settings if a workspace is open (so the choice travels with `.hexcore_job.json`), otherwise to user-global.
- A "Reload Window" prompt appears after the switch.

**Pipeline gating:**
The runner automatically marks `hexcore.debug.*` steps as `skipped` (not `error`) when `hexcore.emulator = "azoth"`, and `hexcore.elixir.*` steps as `skipped` when `hexcore.emulator = "debugger"`. With `"both"`, nothing is gated.

---

## Template: Dual-Emulator Malware Analysis — Ashaka Shadow v3 (v3.8.0)

Full malware test pipeline with BOTH emulators running for side-by-side comparison. Targets v3.0-style anti-analysis malware (multi-byte XOR `"Ashaka"`, djb2 API hashing, dynamic `ShellExecuteW`, registry anti-VM).

Requires `hexcore.emulator: "both"`.

```json
{
  "file": "C:\\path\\to\\suspect.exe",
  "outDir": "C:\\path\\to\\hexcore-reports\\dual-emu",
  "quiet": false,
  "continueOnError": true,
  "steps": [
    { "cmd": "hexcore.filetype.detect", "timeoutMs": 60000 },
    { "cmd": "hexcore.hashcalc.calculate", "args": { "algorithms": "all" }, "timeoutMs": 90000 },
    { "cmd": "hexcore.entropy.analyze", "timeoutMs": 90000 },
    { "cmd": "hexcore.strings.extract", "args": { "minLength": 4, "maxStrings": 10000 }, "timeoutMs": 120000 },
    {
      "cmd": "hexcore.strings.extractAdvanced",
      "timeoutMs": 180000,
      "output": { "path": "05-strings-deobfuscated.json" }
    },
    { "cmd": "hexcore.base64.decodeHeadless", "timeoutMs": 90000 },
    { "cmd": "hexcore.disasm.analyzePEHeadless", "timeoutMs": 120000 },
    {
      "cmd": "hexcore.disasm.analyzeAll",
      "args": { "maxFunctions": 500, "maxFunctionSize": 65536, "forceReload": true },
      "timeoutMs": 300000
    },
    { "cmd": "hexcore.disasm.rttiScanHeadless", "timeoutMs": 120000 },
    { "cmd": "hexcore.yara.scan", "timeoutMs": 180000 },
    { "cmd": "hexcore.ioc.extract", "timeoutMs": 120000 },

    { "cmd": "hexcore.disasm.searchStringHeadless", "args": { "query": "IsDebuggerPresent" }, "output": { "path": "12-search-antidebug.json" }, "timeoutMs": 60000 },
    { "cmd": "hexcore.disasm.searchStringHeadless", "args": { "query": "VMware" }, "output": { "path": "13-search-vmware.json" }, "timeoutMs": 60000 },
    { "cmd": "hexcore.disasm.searchStringHeadless", "args": { "query": "VirtualBox" }, "output": { "path": "14-search-virtualbox.json" }, "timeoutMs": 60000 },
    { "cmd": "hexcore.disasm.searchStringHeadless", "args": { "query": "ShellExecuteW" }, "output": { "path": "15-search-shellexecute.json" }, "timeoutMs": 60000 },
    { "cmd": "hexcore.disasm.searchStringHeadless", "args": { "query": "shell32.dll" }, "output": { "path": "15b-search-shell32.json" }, "timeoutMs": 60000 },
    { "cmd": "hexcore.disasm.searchStringHeadless", "args": { "query": "NtQueryInformationProcess" }, "output": { "path": "15c-search-ntquery.json" }, "timeoutMs": 60000 },

    { "cmd": "hexcore.disasm.searchBytesHeadless", "args": { "pattern": "41 53 68 61 73 6B 61" }, "output": { "path": "16-xor-key-ashaka.json" }, "timeoutMs": 120000 },
    { "cmd": "hexcore.disasm.searchBytesHeadless", "args": { "pattern": "29 27 1C 11 00 51 4E 6E" }, "output": { "path": "16b-c2-url-encoded.json" }, "timeoutMs": 120000 },
    { "cmd": "hexcore.disasm.searchBytesHeadless", "args": { "pattern": "4E 4B 52 E4" }, "output": { "path": "16c-djb2-hash-isdebuggerpresent.json" }, "timeoutMs": 120000 },

    {
      "cmd": "hexcore.disasm.liftToIR",
      "args": { "address": "entry", "count": 300 },
      "output": { "path": "17-main-lifted.ll" },
      "timeoutMs": 180000,
      "continueOnError": true
    },
    {
      "cmd": "hexcore.helix.decompileIR",
      "args": { "irPath": "$step[20].output" },
      "output": { "path": "17b-main-decompiled.helix.c" },
      "timeoutMs": 180000,
      "continueOnError": true
    },

    {
      "cmd": "hexcore.debug.emulateFullHeadless",
      "args": { "address": "entry", "maxSteps": 50000, "permissiveMemoryMapping": true, "traceAPIs": true },
      "output": { "path": "18-emulation-unicorn.json" },
      "timeoutMs": 300000,
      "continueOnError": true
    },
    { "cmd": "hexcore.elixir.smokeTestHeadless", "timeoutMs": 30000 },
    {
      "cmd": "hexcore.elixir.snapshotRoundTripHeadless",
      "output": { "path": "19-elixir-snapshot.json" },
      "timeoutMs": 60000
    },
    {
      "cmd": "hexcore.elixir.emulateHeadless",
      "args": { "maxInstructions": 1000000 },
      "output": { "path": "20-emulation-elixir.json" },
      "timeoutMs": 600000,
      "continueOnError": true
    },
    {
      "cmd": "hexcore.elixir.stalkerDrcovHeadless",
      "args": { "maxInstructions": 1000000 },
      "output": { "path": "21-elixir-stalker.json" },
      "timeoutMs": 600000,
      "continueOnError": true
    },

    {
      "cmd": "hexcore.pipeline.composeReport",
      "output": { "path": "FINAL_REPORT.md", "format": "md" },
      "timeoutMs": 60000
    }
  ]
}
```

**Notes:**
- **Dual emulator**: `18-emulation-unicorn.json` (legacy debugger + hexcore-unicorn) and `20-emulation-elixir.json` (Project Azoth) are produced in the same run so you can diff API traces between the two engines. Requires `hexcore.emulator: "both"` — otherwise one side is skipped.
- **Lift + Decompile split**: Step 20 emits raw LLVM IR (`.ll`), Step 21 runs Helix on it (`.helix.c`). Use `$step[20].output` so the IR path resolves at runtime (zero hardcoded paths). Gives you both the IR for manual inspection and the pseudo-C.
- **v3.0 anti-analysis patterns** baked in:
  - `41 53 68 61 73 6B 61` — ASCII "Ashaka" multi-byte XOR key (in `.rdata`)
  - `29 27 1C 11 00 51 4E 6E` — first 8 bytes of the XOR'd C2 URL
  - `4E 4B 52 E4` — djb2 hash of `"IsDebuggerPresent"` in little-endian (`0xE4524B4E`)
  - Dynamic loading strings: `shell32.dll`, `ShellExecuteW`, `NtQueryInformationProcess`
- **Advanced strings deobfuscation**: `hexcore.strings.extractAdvanced` tests key sizes `[2,3,4,5,6,7,8,12,16]` by default in v3.8.0 — covers the 7-byte `"Ashaka"` key. Kasiski auto-detection is on.
- `continueOnError: true` on all emulation steps so one engine choking doesn't kill the other's output.

---

## Template: Decompile → Audit Chain (v3.8.0 Wave 3.3) — RACE-SAFE

**Problem this solves.** Running phase2 decompile and phase3 audit as two *separate* job files (each triggered by the filesystem watcher) creates a race window: the watcher sees both `.hexcore_job.json` files, fires them in parallel, and the audit step wins the race while the decompile step is still writing. Result: `ENOENT: no such file` on the `.helix.c` that would have existed a second later. Same root cause for any chained pipeline where step B depends on step A's output file.

**Fix: a single job with `$step[N].output` references.** The pipeline runner resolves `$step[N].output` to the exact path step N wrote — no filesystem polling, no race, no watcher coordination needed. Step B runs only after step A has finished.

```json
{
    "file": "target.exe",
    "outDir": "./hexcore-reports/decompile-audit-chain",
    "continueOnError": true,
    "steps": [
        {
            "cmd": "hexcore.helix.decompile",
            "args": {
                "functionAddress": "0x5D010C",
                "autoBacktrack": true
            },
            "output": {
                "path": "./hexcore-reports/decompile-audit-chain/00-helix.helix.c"
            }
        },
        {
            "cmd": "hexcore.audit.refcountScan",
            "args": {
                "input": "$step[0].output"
            },
            "output": {
                "path": "./hexcore-reports/decompile-audit-chain/01-refcount-audit.json"
            }
        }
    ]
}
```

**Why this works.**

- `$step[0].output` resolves at step 1's dispatch time to the literal path step 0 wrote (whether set explicitly in `output.path` or auto-derived by the runner)
- If step 0 errored, Wave 3.3 error-stub writes `{"ok": false, "error": ...}` to that path, and step 1's `audit.refcountScan` fails with a clear "read file JSON parse error" instead of ENOENT — the stub makes failure visible at every link in the chain
- With `continueOnError: true` the job completes to `status: "partial"` when a link fails, so downstream orchestration scripts can branch on partial vs error

**When to use `$step[N].output` vs separate jobs**

- **Chain in a single job** when step B reads a file step A writes
- **Separate jobs** when the consumers are independent (two phase3 jobs scanning the same phase2 output in parallel is fine)
- **Named job + orchestrator** when you want the UX of separate jobs but need ordering — the orchestrator template already does this for strings-deep / decompile-batch

Runnable sample: `extensions/hexcore-disassembler/test/sample_decompile_audit_chain.hexcore_job.json`.

---

## Workspace Layout Example (v3.8.0)

```
my-analysis/
├── target.exe                             ← binary to analyze
├── .hexcore_job.json                      ← canonical job (Run Job finds this first)
├── strings-deep.hexcore_job.json          ← named job (auto-detected by watcher)
├── decompile-batch.hexcore_job.json       ← named job (auto-detected by watcher)
├── orchestrator.hexcore_job.json          ← queues the others with priority
└── hexcore-reports/                       ← all output goes here
    ├── quick-triage/
    ├── strings-deep/
    ├── decompile-batch/
    └── orchestrator/
```

All `*.hexcore_job.json` files are auto-detected — agents create them, the watcher picks them up, zero manual intervention.

---

## Template: Malware Deep-Dive — Azoth + Refcount Audit (v3.8.0)

End-to-end malware triage that exercises the v3.8.0 Wave 2/3 surface:
Azoth (Elixir) emulation, YARA with HQL anti-analysis rules, IOC extraction,
Helix decompile of the entry point, and the new refcount-audit scanner against
the decompiled C. `onResult` gates the deep passes on an entropy signal, so
low-value benign binaries short-circuit after the static phase.

Writes a run-level `summary` (okCount/errorCount/skippedCount/totalDurationMs
/queueSnapshot) and per-step `outputBytes` into `hexcore-pipeline.status.json`
(v3.8.0 observability fields).

```json
{
  "file": "C:\\samples\\suspect.exe",
  "outDir": "C:\\samples\\hexcore-reports\\malware-deep-dive",
  "quiet": true,
  "priority": "high",
  "continueOnError": true,
  "steps": [
    { "cmd": "hexcore.filetype.detect", "timeoutMs": 60000 },
    { "cmd": "hexcore.hashcalc.calculate", "args": { "algorithms": "all" } },
    {
      "cmd": "hexcore.entropy.analyze",
      "onResult": {
        "field": "maxEntropy",
        "operator": "lt",
        "value": 6.5,
        "action": "skip",
        "actionValue": 2
      }
    },
    { "cmd": "hexcore.strings.extractAdvanced", "args": { "minLength": 6 } },
    { "cmd": "hexcore.base64.decodeHeadless" },
    { "cmd": "hexcore.peanalyzer.analyze" },
    { "cmd": "hexcore.yara.scan", "args": { "useDefaultRules": true }, "timeoutMs": 180000 },
    { "cmd": "hexcore.ioc.extract" },
    {
      "cmd": "hexcore.elixir.emulateHeadless",
      "args": { "maxInstructions": 2000000, "stopOnException": false },
      "timeoutMs": 300000,
      "retryCount": 1,
      "retryDelayMs": 2000
    },
    {
      "cmd": "hexcore.elixir.stalkerDrcovHeadless",
      "args": { "maxInstructions": 2000000 },
      "output": { "path": "drcov-trace.json" },
      "timeoutMs": 300000
    },
    {
      "cmd": "hexcore.helix.decompile",
      "args": { "address": "entry", "count": 300 },
      "output": { "path": "decompiled-entry.helix.c" },
      "timeoutMs": 180000
    },
    {
      "cmd": "hexcore.audit.refcountScan",
      "args": { "input": "$step[prev].output" },
      "output": { "path": "refcount-audit.json" }
    },
    {
      "cmd": "hexcore.pipeline.composeReport",
      "output": { "path": "MALWARE_REPORT.md", "format": "md" }
    }
  ]
}
```

Validate in the Command Palette: `HexCore: Validate Job File` → pick this job.
Run: `HexCore: Run Job File`. Inspect progress in `hexcore-pipeline.status.json`
(live-updated per step) and the final `summary` block.

---

## Template: Crypto Hunt — Entropy-Gated (v3.8.0)

Lightweight scanner tuned for packed/encrypted payloads. Entropy gates the
deep work with `onResult goto`: low-entropy binaries skip straight to the
report step, high-entropy binaries trigger Base64/XOR/AOB scanning and YARA
crypto rules. Demonstrates the full `onResult` operator set (gt/regex/goto).

```json
{
  "file": "C:\\samples\\packed-unknown.bin",
  "outDir": "C:\\samples\\hexcore-reports\\crypto-hunt",
  "quiet": true,
  "steps": [
    { "cmd": "hexcore.filetype.detect" },
    {
      "cmd": "hexcore.entropy.analyze",
      "onResult": {
        "field": "maxEntropy",
        "operator": "gt",
        "value": 7.2,
        "action": "goto",
        "actionValue": 3
      }
    },
    {
      "cmd": "hexcore.hashcalc.calculate",
      "onResult": {
        "field": "note",
        "operator": "contains",
        "value": "skipped",
        "action": "goto",
        "actionValue": 8
      }
    },
    { "cmd": "hexcore.strings.extractAdvanced", "args": { "detectXorKeys": true, "minLength": 6 } },
    { "cmd": "hexcore.base64.decodeHeadless" },
    {
      "cmd": "hexcore.disasm.searchBytesHeadless",
      "args": { "pattern": "?? ?? ?? ?? 48 8B ?? ?? ?? ?? ??", "maxMatches": 64 },
      "output": { "path": "aob-crypto-loops.json" },
      "continueOnError": true
    },
    { "cmd": "hexcore.yara.scan", "args": { "category": "crypto", "useDefaultRules": true } },
    { "cmd": "hexcore.ioc.extract" },
    {
      "cmd": "hexcore.pipeline.composeReport",
      "output": { "path": "CRYPTO_REPORT.md", "format": "md" }
    }
  ]
}
```

After the run, `hexcore-pipeline.status.json` → `summary.slowestStepCmd`
immediately points at the dominant cost (usually `hexcore.yara.scan` on big
binaries), and `summary.skippedCount` reports how many steps the entropy gate
bypassed.
