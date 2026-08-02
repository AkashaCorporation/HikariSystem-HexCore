# HexCore Disassembler

Professional disassembler + headless pipeline host for HexCore (Capstone, Remill lift, Helix decompile, automation jobs).

| Field | Value |
|-------|--------|
| **Package** | `hexcore-disassembler` |
| **Version** | **1.4.23** |
| **Publisher** | hikarisystem |
| **Product train** | HexCore **3.8.3** (Unreleased) |

## 1.4.23 highlights (exact ELF symbol-boundary normalization)

- Treats exact, non-zero ELF `STT_FUNC/st_size` as the authoritative extent for
  functions truncated at an interior `ud2`/`ret` or overrun into neighbours.
- Keeps ET_REL address collisions safe by preferring the matching function name
  and otherwise accepting only `.text`; other sections remain available through
  the existing `symbolName` path.
- Trims instructions and stale xrefs when shrinking, then rebuilds the direct
  call graph; adjacent ftrace `__pfx_` symbols remain separate from their body.
- Fresh Mali validation: `kbase_jit_allocate` is corrected from 997 to 2121
  bytes, while `kbase_regmap_term` is corrected from 7543 to 84 bytes.
- Cross-kernel validation freshly lifts and decompiles 128/128 selected
  functions; focused and neighbouring boundary regressions pass 5/5 and 29/29.

## 1.4.18 highlights (FIX-027c chained `.pdata` lift extent)

- Reconciles MSVC chained-unwind `.pdata` fragments before the hot `liftToIR` path computes the function extent.
- Prevents a raw continuation boundary from entering `knownFunctionEnds` and truncating Remill at the first fragment.
- The reconciliation barrier is one-shot per loaded binary and safe when followed by `analyzeAll`.
- Validated on SOTTR HealthData: **137 -> 701 bytes**, **4 -> 40 blocks**, **19 -> 156 semantic calls**.
- Preserves explicit ET_REL job windows when symbol/analyzeAll extents cover only a hot fragment (FIX-QUALITY-002e).

## 1.4.17 highlights (FIX-QUALITY packaging)

Closes the **IDE job vs engine-direct quality gap** on real PE drivers (validated `mbamchameleon.sys` @ `0x14002641c`):

| Path | Before | After |
|------|--------|-------|
| IDE `helix.decompile` job | ~891 lines / 53% (or fake 95% on 95-line stub) | **1597 lines / 64.2%** |
| Engine-direct harness | 1596 lines / 64.2% | same |

Key fixes:

- **Cast layer ON by default** (legacy PseudoCEmitter is opt-out only)
- **`.pdata` authoritative function size** (prologue-scan 4800 vs pdata 6761)
- **No Pathfinder leader flood** on single-fn lift; under-lift retry
- **Headless Helix `forceSync`** (no Electron worker double-load)
- **`// LiftDiag:`** stamp on decompiled C
- **#52** import/PLT → real names (`ExAllocatePoolWithTag`, `dlopen`, …)
- **#46** width-aware bit-intrinsic cleanup (`ctpop.i64` → `popcountll`)

See product root `CHANGELOG.md` → *Disassembler/Helix packaging (FIX-QUALITY-001/002/002c/002d)*.

## Commands (headless)

Common pipeline steps:

- `hexcore.disasm.analyzePEHeadless` / `hexcore.disasm.analyzeAll`
- `hexcore.disasm.liftToIR`
- `hexcore.helix.decompile` / `hexcore.helix.decompileIR`
- `hexcore.pipeline.runJob` (auto-runs `*.hexcore_job.json`)

Job args of interest for decompile quality:

```json
{
  "cmd": "hexcore.helix.decompile",
  "args": {
    "address": "0x14002641c",
    "size": 65536,
    "souper": false,
    "useCastLayer": true,
    "allowOversizedLift": false,
    "functionStarts": false
  }
}
```

| Arg | Default | Notes |
|-----|---------|--------|
| `useCastLayer` | **true** | Set `false` only to force legacy PseudoCEmitter |
| `functionStarts` | off | Set `true` / `honesty:true` for D2 authoritative registry |
| `allowOversizedLift` | false | Keep multi-fn huge windows |
| `noLiftRetry` | false | Disable under-lift auto-retry |

## Build

```bash
cd extensions/hexcore-disassembler
npm install
npx tsc -p tsconfig.json
```

## Tests

```bash
npx mocha -u tdd --timeout 10000 "out/helixPackaging.quality.test.js"
npx mocha -u tdd --timeout 10000 "out/importSymbolNames.test.js"
npx mocha -u tdd --timeout 30000 "out/helixCleanupPostProcessor.test.js"
```
