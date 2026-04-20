# Pathfinder — DWARF & PDB Feeder Design

> **Status:** SHIPPED 2026-04-19 v3.8.1-nightly. All three parts (DWARF, PDB, ET_REL
> relocations) implemented and validated on real corpora. This document is kept as
> the design-intent record; the actual implementation is in
> `extensions/hexcore-disassembler/src/elfDwarfLoader.ts` (DWARF + ET_REL) and
> `extensions/hexcore-disassembler/src/pdbLoader.ts` (PDB).
>
> **Results on `mali_kbase.ko` (ARM Mali kernel module):**
> - 7 structs → **792 structs** (+113×)
> - 1 function signature → **3,864 functions** (+3,864×)
> - 0 DWARF boundaries → **1,633 boundaries** (unblocked by ET_REL relocation)
> - `kbase_jit_allocate` params recovered: `(struct kbase_context *kctx, const struct base_jit_alloc_info *info, bool ignore_pressure_limit)` — matches IDA ground truth exactly.
>
> **Results on PE+PDB:** 55 function boundaries extracted from `Malware HexCore
> Defeat.exe` via `llvm-pdbutil`, including leaf functions that `.pdata` doesn't
> cover (`__security_check_cookie`, `mainCRTStartup`, etc.).

## Problem statement

Today Pathfinder's `extractELFContext` only reads function boundaries from ELF `.symtab` (`STT_FUNC` entries). On stripped `.ko` files with no `.symtab` but WITH DWARF (`.debug_info`, `.debug_abbrev`, `.debug_str`), Pathfinder has no function boundaries at all — falls back to `engine.getFunctions()` heuristics, which are prologue-based and miss unreachable-via-prologue functions (vtable-called, indirect-jumped).

Same on PE side: `extractPE64Context` only reads `.pdata`. For older PE binaries without `.pdata` (legacy x86 `.exe`, some DLLs), or PE+PDB builds where the PDB has richer function-boundary info than `.pdata` does, we're leaving boundaries on the table.

The DWARF loader at `src/elfDwarfLoader.ts` already parses `DW_TAG_subprogram` DIEs (line 667-707) — but ONLY extracts function names, return types, and parameter types for struct-field naming. The low_pc / high_pc attributes are present in every `DW_TAG_subprogram`, the parser's constants list them (`DW_AT_low_pc = 0x11`, `DW_AT_high_pc = 0x12`), but `extractStructsAndFunctions` silently drops them. **The data is already being parsed but never used.**

## Current state (read-only audit)

### Call graph today

```
disassemblerEngine.ts (line 2505-2515)
  └── loadDwarfStructInfo(filePath)           ← elfDwarfLoader.ts
      └── parseDwarfInfo → extractStructsAndFunctions
          └── returns StructInfoJson { structs, functions }

  └── stored on elfAnalysis.dwarfStructInfo

helixWrapper.ts (line 202, 310)
  └── reads dwarfStructInfo for field naming + function signatures
  └── passes to Helix via structInfo option

pathfinder.ts
  └── extractELFContext → reads engine.getELFAnalysis().symbols ONLY
  └── DWARF data is NEVER consumed here
```

### What DWARF already gives us (unused)

Every `DW_TAG_subprogram` DIE has:
- `DW_AT_name` (function name) — already extracted
- `DW_AT_low_pc` (entry address) — parsed but dropped
- `DW_AT_high_pc` (exit address, DWARF4+ can be constant offset from low_pc) — parsed but dropped
- `DW_AT_type` (return type) — already extracted
- Children: `DW_TAG_formal_parameter` — already extracted

### What PE doesn't have loader for

- `pdbLoader.ts` does not exist
- `.pdata` is only source of PE function boundaries
- `engine.getPdataEntries()` returns `PdataEntry[]` from `disassemblerEngine.ts`
- PE+PDB builds: PDB has richer data (inlined-function ranges, per-section function lists including non-`.pdata` functions, COMDAT info) — not consumed

## Proposed changes

### A — DWARF feeder (low risk, high ROI on `.ko`)

#### A.1 — `elfBtfLoader.ts` — schema additions

```ts
// New interface, exported
export interface FunctionBoundaryInfo {
    name: string;
    lowPc: number;      // absolute virtual address of first instruction
    highPc: number;     // absolute virtual address of first byte AFTER function
}

// Extend existing interface (additive, optional)
export interface StructInfoJson {
    structs: Record<string, StructInfo>;
    functions: Record<string, FunctionSignatureInfo>;
    boundaries?: FunctionBoundaryInfo[];   // NEW — DWARF-source function boundaries
}
```

**Rationale:** Adding to `StructInfoJson` keeps one canonical struct-info object flowing through the pipeline. `boundaries` is optional, so existing BTF consumers (which produce no boundaries) are unaffected. `elfBtfLoader.ts` continues returning `{ structs, functions }` with `boundaries: undefined`. DWARF loader populates it.

#### A.2 — `elfDwarfLoader.ts` — extractStructsAndFunctions

Current (line 667):
```ts
if (die.tag === DW_TAG_subprogram) {
    const name = die.attrs.get(DW_AT_name);
    // ... extracts return type + params only
    functions[name] = { returnType, params };
}
```

Proposed:
```ts
if (die.tag === DW_TAG_subprogram) {
    const name = die.attrs.get(DW_AT_name);
    // ... existing return type + params extraction unchanged ...

    // NEW: extract boundaries (additive — existing code path unchanged)
    const lowPc = die.attrs.get(DW_AT_low_pc);
    const highPcRaw = die.attrs.get(DW_AT_high_pc);
    if (typeof lowPc === 'number' && typeof highPcRaw === 'number') {
        // DWARF 4+ quirk: high_pc can be a constant (offset from low_pc)
        // or an absolute address, depending on the form.  We detect by
        // form value recorded during parseAbbrevTable.
        const highPc = isHighPcOffset(die, lowPc, highPcRaw)
            ? lowPc + highPcRaw
            : highPcRaw;
        boundaries.push({ name, lowPc, highPc });
    }
}
```

**Complication:** `DW_AT_high_pc` has two semantics depending on DW_FORM:
- `DW_FORM_addr` → absolute virtual address (DWARF 2/3)
- `DW_FORM_data1/data2/data4/data8/udata` → offset from `low_pc` (DWARF 4+)

Need to record the form alongside the value in `readFormValue`, or inspect `die.attrs`'s underlying form map. Cleanest fix: extend `DIE` struct with `attrForms: Map<number, number>` so attr-to-form is available downstream. ~20 LOC.

#### A.3 — `pathfinder.ts` — extractELFContext

Current (line 163-203):
```ts
function extractELFContext(engine: DisassemblerEngine): BinaryContext {
    // reads engine.getELFAnalysis().symbols — STT_FUNC entries
    for (const sym of elfData.symbols ?? []) {
        if (sym.type === 'FUNC' && sym.size > 0) {
            context.functionBoundaries.push({ start: sym.value, end: sym.value + sym.size });
        }
    }
    // ...
}
```

Proposed — add DWARF merge pass after `.symtab`:
```ts
function extractELFContext(engine: DisassemblerEngine): BinaryContext {
    // ... existing .symtab walk unchanged ...

    // NEW: DWARF boundaries as additional source
    const dwarfInfo = engine.getELFAnalysis()?.dwarfStructInfo;
    if (dwarfInfo?.boundaries) {
        const seen = new Set(context.functionBoundaries.map(fb => fb.start));
        for (const b of dwarfInfo.boundaries) {
            if (!seen.has(b.lowPc)) {
                context.functionBoundaries.push({ start: b.lowPc, end: b.highPc });
                context.entryPoints.push(b.lowPc);
                seen.add(b.lowPc);
            }
        }
    }
    return context;
}
```

**Dedup policy:** `.symtab` entries win (they're authoritative in linked binaries). DWARF fills gaps for stripped binaries. In the common case where both exist, dedup by `start` address — DWARF additions are a no-op.

#### A.4 — Confidence bump in `runPathfinder`

Current `hints.confidence` is 95 for ARM64, 90 for x86 when Phase 2 completes. Stays the same. But we add a small "metadata coverage" boost:

```ts
// After Phase 2 completes, boost if DWARF supplemented .symtab
if (dwarfBoundariesSuppliedTarget) {
    hints.confidence = Math.min(100, hints.confidence + 5);
}
```

Signals to downstream (Helix) that type-recovery has high-quality input — may want to weight DWARF-derived types higher.

### B — PDB feeder (medium risk, moderate ROI on PE)

#### B.1 — `pdbLoader.ts` (new file)

Parse PDB via subprocess `llvm-pdbutil.exe` (comes with LLVM 18 build we already link against). Commands:

```bash
llvm-pdbutil.exe dump --summary   target.pdb  # module list, image base
llvm-pdbutil.exe dump --symbols   target.pdb  # S_GPROC32 / S_LPROC32 symbols with RVA + size
llvm-pdbutil.exe dump --section-contribs target.pdb  # function-to-section mapping
```

Parse text output, extract `{ name, rva, size, section }`. Convert RVA→VA using PE base address from engine.

**Output type:**
```ts
export interface PdbFunctionBoundary {
    name: string;
    va: number;       // absolute virtual address
    size: number;
    section: string;  // .text, .text$mn, etc.
}

export async function loadPdbFunctionBoundaries(
    pePath: string,
    pdbPath: string,
    imageBase: number
): Promise<PdbFunctionBoundary[] | null>
```

**Discovery:** Look for `.pdb` next to the `.exe`/`.dll`, or in `PDB_PATH` env, or via the PE's `CodeView` debug directory entry which embeds the PDB path. Engine already parses CodeView — exposes `fileInfo.codeView?.pdbPath`.

#### B.2 — `pathfinder.ts` — extractPE64Context

Current: reads `.pdata` only. Proposed: after `.pdata` walk, merge PDB boundaries if available. Same dedup policy (`.pdata` wins when addresses match; PDB fills gaps).

**Critical gap PDB closes:** `.pdata` only covers non-leaf functions (those with stack unwinding). Leaf functions (no frame, no exception handler) have NO `.pdata` entry. PDB lists all functions regardless. On `vgk.sys` this is significant — 97% of code is virtualized, but the leaf routines in the small non-`.grfn1` remainder are invisible to `.pdata`-only analysis.

#### B.3 — Graceful degradation

- `llvm-pdbutil.exe` not in PATH → log + skip, no fatal error
- PDB path wrong / mismatched PE → `llvm-pdbutil` returns mismatch error, we log + skip
- PDB missing section-contribs (older builds) → partial data is still better than none

## Risk matrix

| Change | Surface area | Rollback cost | Regression risk |
|---|---|---|---|
| A.1 `StructInfoJson.boundaries?` | +1 optional field | trivial (field stays undef if no DWARF) | zero — additive |
| A.2 `extractStructsAndFunctions` low_pc/high_pc | ~25 LOC in one file | trivial (new branch only) | zero if high_pc form handled correctly |
| A.3 `pathfinder.ts extractELFContext` merge | ~15 LOC | trivial (new block after `.symtab` walk) | zero — dedup preserves `.symtab` priority |
| A.4 confidence +5 boost | ~3 LOC | trivial | zero — monotonic upward |
| B.1 `pdbLoader.ts` new file | ~200-300 LOC new | trivial (file stays unused if PDB missing) | low — subprocess gated |
| B.2 `extractPE64Context` merge | ~15 LOC | trivial | low — dedup preserves `.pdata` priority |

**Net risk: A is trivial (backward compatible on every axis). B is medium because subprocess spawn adds a new failure mode, but the failure mode is "log + skip", never a broken build.**

## Validation plan

### A — DWARF on `.ko`

Corpus:
- `mali_kbase.ko` (Mali ARM64) — has DWARF if compiled with `-g`
- Any `.ko` from `C:\Users\Mazum\Desktop\Intigrity\hexcore-reports\mali-kbase-*` folders

Metric: how many functions does `.symtab` know vs `.symtab + DWARF`? Ideally DWARF adds zero (linked `.ko` has complete `.symtab`). Non-zero addition = `.symtab` was stripped and DWARF filled the gap — exactly the scenario this exists for.

Run before/after benchmark on the 3 Mali functions we tested today (`kbase_jit_allocate`, `kbase_context_mmap`, `kbase_csf_queue_register`). Expected: identical output (both sources have the same boundary). If regresses, `isHighPcOffset` handling is wrong.

### B — PDB on PE

Corpus:
- `SOTR` (has PDB)
- `gta-sa.exe` (user has PDB)
- `ROTTR.exe` (has PDB per 3.8.0 docs)
- Any MSVC-built malware sample

Metric: functions discovered by `.pdata` alone vs `.pdata + PDB`. PDB should add leaf functions. Measure per-function output line counts before/after.

Failure modes to verify graceful handling:
- Missing `llvm-pdbutil.exe` — is `which` working? is it in `caps/llvm-build/build-mlir/bin/`?
- Mismatched PDB version — `llvm-pdbutil` errors verbosely, must parse stderr
- Stripped PE (no CodeView entry) — skip cleanly

## Shape of the work

### Day 2 schedule (if user approves)

**Morning — DWARF feeder (A.1 → A.4):**
- Extend interfaces (15 min)
- DWARF high_pc form handling (45 min — parse tables + test)
- Pathfinder merge (15 min)
- Rebuild `hexcore-disassembler` TS (5 min)
- Smoke test on `mali_kbase.ko` (15 min)
- Validation: re-run benchmark on kernel Mali corpus, compare line counts (15 min)

Total A: ~2h

**Afternoon — PDB feeder (B.1 → B.3) if A is green:**
- `pdbLoader.ts` scaffold + subprocess invocation (1h)
- Symbol parser (`S_GPROC32` output format) (1h)
- Pathfinder merge + dedup (15 min)
- Smoke test on SOTR (15 min)
- Validation: re-run SOTR benchmark (30 min)

Total B: ~3h

### Files that will change (for reference when implementing)

```
MODIFIED:
  extensions/hexcore-disassembler/src/elfBtfLoader.ts         (+10 LOC schema)
  extensions/hexcore-disassembler/src/elfDwarfLoader.ts       (~30 LOC parser)
  extensions/hexcore-disassembler/src/pathfinder.ts           (~30 LOC merge)

NEW (Part B only):
  extensions/hexcore-disassembler/src/pdbLoader.ts            (~300 LOC)
```

### What this DOES NOT include (explicit non-goals)

- No changes to Remill (`remill_wrapper.cpp`)
- No changes to Helix engine C++
- No changes to `disassemblerEngine.ts` beyond what's needed to expose DWARF data to Pathfinder (probably zero changes — data is already exposed via `elfAnalysis.dwarfStructInfo`)
- No changes to `helixWrapper.ts` (struct-info flow is separate from CFG-hint flow)
- No new npm dependencies (subprocess uses Node built-in `child_process`)

## Open questions

1. **`isHighPcOffset` detection:** the DWARF form of `DW_AT_high_pc` determines semantics. Current parser doesn't keep forms around after reading values. Options:
   - Extend `DIE` interface with `attrForms: Map<number, number>`
   - Or read `high_pc` specially during `readFormValue` (case on form → tag result)
   - Or check DWARF version — DWARF 2/3 is always absolute, DWARF 4+ "any constant form" is offset. We have the version in `parseDwarfInfo` already. Simpler. Recommend this path.

2. **PDB path discovery:** engine.getFileInfo() may or may not expose `codeView.pdbPath`. Need to verify before writing B.1, else we rely on user-supplied path via LiftOptions.

3. **DWARF boundaries vs `hasDwarfSections` gating:** `hasDwarfSections()` already exists in `elfDwarfLoader.ts` (line 884) — can early-skip load if absent. No change needed.

## Memory of this design

Saved at: `C:\Users\Mazum\.claude\projects\...\memory\project_pathfinder_feeder_design.md` (stub created alongside this doc so future sessions pick up).
