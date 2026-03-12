# HexCore Job Templates — v3.7.0-beta.1

Safe default `.hexcore_job.json` templates for users and AI agents.

## Rules

- Keep `.hexcore_job.json` in the workspace root used by HexCore.
- Prefer absolute paths for `file` in multi-folder workspaces.
- Set `expectOutput: false` when you do not need step artifacts.
- Use explicit `output` only for reports you want to keep.
- See `docs/HEXCORE_AUTOMATION.md` for full command reference.

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
    { "cmd": "hexcore.rellic.decompile", "args": { "address": "entry", "count": 200 }, "output": { "path": "decompiled-entry.c" }, "timeoutMs": 180000, "continueOnError": true },
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
      "cmd": "hexcore.rellic.decompile",
      "args": { "address": "entry", "count": 300 },
      "output": { "path": "02b-decompiled.c" },
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
- For Rellic-style output (mnemonic comments), swap `hexcore.helix.decompileIR` with `hexcore.rellic.decompile`.

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
    { "cmd": "hexcore.peanalyzer.analyze", "timeoutMs": 120000, "continueOnError": true },
    { "cmd": "hexcore.elfanalyzer.analyze", "timeoutMs": 120000, "continueOnError": true },
    { "cmd": "hexcore.strings.extract", "args": { "minLength": 4, "maxStrings": 100000 }, "timeoutMs": 180000 },
    { "cmd": "hexcore.strings.extractAdvanced", "timeoutMs": 180000 },
    { "cmd": "hexcore.base64.decodeHeadless", "timeoutMs": 90000 },
    { "cmd": "hexcore.hexview.dumpHeadless", "args": { "offset": 0, "size": 512 }, "output": { "path": "header-dump.json" }, "timeoutMs": 60000 },
    { "cmd": "hexcore.hexview.searchHeadless", "args": { "pattern": "4D5A" }, "output": { "path": "mz-search.json" }, "timeoutMs": 120000 },
    { "cmd": "hexcore.yara.scan", "timeoutMs": 180000 },
    { "cmd": "hexcore.ioc.extract", "timeoutMs": 120000 },
    { "cmd": "hexcore.pipeline.composeReport", "output": { "path": "FINAL_REPORT.md", "format": "md" }, "timeoutMs": 60000 }
  ]
}
```

**Note:** Both `peanalyzer.analyze` and `elfanalyzer.analyze` are included with `continueOnError: true` — the wrong format will fail gracefully and the pipeline continues.

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
