# Khimera PE CFG Ownership Qualification

Date: 2026-11-09

Verdict: **SOURCE-PASS / PACKAGE-PENDING** for Disassembler `1.4.78`.

## Frozen Input

- Target: user-owned Khimera PE64 release fixture (not distributed).
- Size: 151,040 bytes.
- SHA-256: `6b988bedcd5bcf07eee19473c13428bad105557d6f0639afc9121bff71b7e511`.
- The retained build output and the benchmark copy are byte-identical.
- Source oracle: the optimized helper at `0x140013C10` is `ct_equal` from
  `util.hpp`, whose zero-length return precedes the forward loop body.

## Reproduced Defects

1. `0x140013C10` was reported complete at `[0x140013C10,0x140013C21)`:
   17 bytes and one early-return path. The forward conditional target at
   `0x140013C30` and seven remaining basic blocks were omitted. IDA owns
   `[0x140013C10,0x140013C77)`, matching the source.
2. Optimized direct-call leaves omitted from `.pdata` depended on recursive
   prologue-scan order. A boundary change could exchange one real leaf for
   another while keeping the same total function count.

## Fix Contract

- Function discovery remains population-only during the prologue scan.
- After starts and unwind ranges are frozen, bounded transient decoding selects
  reachable CFG blocks and updates semantic ownership without adding starts.
- Independently strong branch targets remain separate owners.
- On PE images below 64 MiB of executable bytes, transient decoding of `.pdata`
  ranges collects direct-call targets outside unwind ownership. Caller bodies
  remain lazy; only missing leaf targets are materialized.
- Large images skip that additional scan with the typed diagnostic
  `partial/large-image-budget`.

## Real-Target A/B

| Metric | 1.4.77 baseline | 1.4.78 candidate |
|---|---:|---:|
| HexCore functions | 526 | 533 |
| IDA starts in common | 495 | 502 |
| Exact common ends | 466 | 497 |
| Exact-end rate | 94.1% | 99.0% |
| Materialized immediately | 107 | 114 |
| Existing lazy bodies retained | 419 | 419 |
| Function overlaps | 0 | 0 |

All seven newly indexed starts exist in the IDA database and every one has the
same end. The six challenge-central ranges remain unchanged.

Two independent fresh runs produced 533 functions and the same address/end
table SHA-256:

`156a65ff11d52a9a8ff1cdedf6fb83e7f028cdd85d3e000f98c5d1ac20d87b0b`

Discovery diagnostics for the fixture are complete:

- prolog scan: 316 candidates accepted;
- direct-call leaves: 1,413 call instructions examined, seven functions added,
  86,845 bytes transiently decoded;
- padding leaves: five functions accepted.

## Source Gates

- TypeScript compile: PASS.
- PE leaf ownership/direct-call gates: 6 PASS.
- Pdata, padding, closure, process, ownership and ghost regressions: 70 PASS.
- Pipeline reliability: 29 PASS.
- Real target: deterministic A/B, no added overlap, no removed start.

## Explicit Holds

- `0x140001C10`: transitive noreturn recognition is still absent; HexCore keeps
  an unreachable epilogue that IDA excludes.
- `_NLG_Notify`: IDA merges a one-byte unwind-backed shared return block while
  HexCore preserves it as a separate owner plus tail edge. This is a model
  difference, not adjudicated as corruption.
- Three one-byte end deltas retain raw unwind/alignment boundaries while IDA
  reports the semantic instruction end.
- Twelve IDA starts remain absent, primarily small CRT/library leaves and
  jump thunks requiring separate signature/seed work.
- VM heuristic reachability, SCF/cast/type quality and Helix cleanup remain
  outside this bounded Disassembler ownership fix.
