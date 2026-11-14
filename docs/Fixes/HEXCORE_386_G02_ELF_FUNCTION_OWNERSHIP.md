# HexCore 3.8.6 G02 - ELF Function Ownership Acceptance

Date: 2026-11-13
Decision: PASS

## Frozen source

```text
Product baseline: aafc383 (accepted G01 checkpoint)
Branch: feat/3.8.6-g02-elf-function-ownership
Disassembler: 1.4.79 (unreleased)
Native Capstone: unchanged 1.3.6
```

## Root causes

1. x86/x64 ELF was excluded from reachable-block ownership and strong-seed
   clamping, so linear decode could cross functions and sections.
2. the PLT extent clamp covered only `.plt.sec`, while stripped legacy `.plt`
   and `.plt.got` entries also terminate at their first indirect transfer;
3. the existing PIC jump-table recovery fed Pathfinder/semantic consumers but
   not the Disassembler's function owner CFG;
4. SysV startup did not promote the proven main address passed to
   `__libc_start_main`;
5. full materialization of a wrong/partial index was labeled
   `complete-disassembly` without an explicit discovery basis.

## Implementation

- Apply reachable ownership and strong-start clamping to non-relocatable x86/x64
  ELF functions.
- Clamp every x86/x64 PLT-family entry at its first transfer.
- Recover main only from a strict SysV process-entry preamble plus executable
  RDI assignment and executable call target.
- Feed bounded PIC jump-table hits back into reachable internal blocks and add
  xrefs for accepted case targets.
- Re-run direct-call discovery over recovered handlers.
- Drop nested weak-prologue owners even when internal CFG edges populated a
  caller count; preserve every independently strong entry.
- Rename complete materialization to
  `complete-known-function-disassembly` and publish a
  `known-function-index` basis plus executable ownership metrics.

## Runbook oracle

Target:

```text
SHA-256: 6c6e48564ac88ed1c057f752a25061db39341f94191205d175d813745937254e
```

| Metric | 3.8.5 | G02 |
|---|---:|---:|
| Functions | 653 | 678 |
| Overlapping function pairs | 83 | 0 |
| `main` at `0x401670` | missing | 571 bytes / 143 instructions |
| `.plt` entry `0x401018` | 2,249 bytes | 6 bytes |
| Direct target `0x402520` | missing; prologue at `0x40252C` | 786 bytes; interior prologue removed |
| Dispatcher `0x402930` | 223 bytes / 54 instructions | 4,192 bytes / 902 instructions |
| Dispatcher callees | 2 | 17 |
| Recovered jump-table target xrefs at `0x4029E9` | 0 | 23 unique targets |

All ten missing handler callees listed by the dogfood report are present after
G02, including `0x401A30`, `0x402270`, `0x4023B0`, `0x402440`, `0x4024F0`,
`0x402840`, `0x402890`, `0x40C440`, `0x412EC0`, and `0x415E30`.

Main evidence is retained as:

```text
kind: runtime-start-main
sourceAddress: 0x4018C4
consumerAddress: 0x4018CB
```

## Honest remaining coverage

```text
analysisDepth: complete-known-function-disassembly
analysisDepthBasis: known-function-index
functionDiscoveryCoverage.status: partial
executable bytes: 502,021
owned range bytes: 324,170 (64.57%)
decoded instruction bytes: 303,533 (60.46%)
unowned executable bytes: 177,851
overlapping owned bytes: 0
unresolved indirect transfers: 227
negativeEvidenceUsable: false
```

The pipeline may be operationally `ok`, but these fields explicitly prevent a
claim of complete binary discovery or clean negative evidence.

## Determinism

R3 and R4 canonical function/coverage records are identical:

```text
SHA-256: 973964fde2519ee20b0c18fad03759925cfca54cd7f8a055c82fccc50172cab6
```

## PE negative control

NUCLEO target:

```text
SHA-256: fe8fa1c4553db5435f2d2e21b5d54769d657b57acf59393ac6b385cdf9277e87
functions: 1,155 before / 1,155 after
function starts added/removed: 0 / 0
function sizes changed: 0
function overlaps: 0
.pdata records: 1,837
exact .pdata starts in function index: 884
.pdata records covered by an accepted function: 1,837/1,837
functions without a .pdata start: 271
```

The ten MASM fixture boundaries remain exact.

## Tests

```text
TypeScript compile: PASS
Focused G02/materialization tests: 26/26 PASS
Ownership/discovery regression selection: 129/129 PASS
PLT compatibility regression: 5/5 PASS
Agent Bridge runbook R3: 2/2 PASS
Agent Bridge deterministic R4: 1/1 PASS
Agent Bridge NUCLEO: 1/1 PASS
```

An umbrella run without the repository's full generated HQL/PDB/VS Code test
environment produced 906 passes and 54 failures. One G02 compatibility failure
(`isPltSecAddress`) was fixed and re-qualified 5/5. The remaining failures are
missing HQL corpus/dist, PDB fixtures, incomplete VS Code mocks, or dependent
pipeline environment and are not represented as product regressions.

## Scope statement

No Helix, Debugger, native engine, issue #62/#66/#70, release, tag, installer or
public artifact was changed by G02.
