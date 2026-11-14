# HexCore 3.8.6-rc.1 Candidate Contract

Status: source-qualified; package E2E pending

Date: 2026-11-14

HexCore 3.8.6 is a bounded semantic-soundness release. RC1 integrates the six
accepted implementation goals without absorbing the separately deferred LLVM
22, HAST 1.3/SCFG, strict whole-binary materialization, no-IDE runner, or broad
runtime expansion programs.

## Accepted Source Checkpoints

| Goal | Scope | Checkpoint |
|---|---|---|
| G01 | x64 ELF worker syscall bridge | `aafc383316d16b0b2d613c496a8e982e3de1d113` |
| G02 | stripped ELF ownership and jump tables | `461c08d5bc2c3d0988e9e94685ee089338fecbe0` |
| G03 | x86 flags and subregister semantics | product `8b809dfd7ca7b88ea25ed636503a7a944f236148`; Helix `7316040f31e758eba5d7ae2c093b39e48bbb7897` |
| G04 | authoritative DWARF/BTF/PDB propagation | product `c46daf8c33c1c233aa14723feb610a66cddbf02e`; Helix `626503bea2bb7145cb8b032426aaf5955f18e8d6` |
| G05 | textual HQL 1.0 | `43a203f90d21e68941344365b39a90b4e7716246` |
| G06 | query-scoped materialization | `820c53579bf310d6c5cb0d29eb621a340e9595fb` |

The product history is sequential from released `v3.8.5`. The unrelated local
Helix C2 research line is not merged into this candidate.

## Candidate Identities

| Component | Candidate |
|---|---|
| Product | `3.8.6-rc.1` |
| Debugger | `2.1.24` |
| Disassembler | `1.4.79` |
| HQL | `0.4.0` |
| Helix package/native | `0.9.4-rc.4` |
| Revenant | unchanged `0.5.0` |
| Elixir | unchanged `1.0.4` |
| Report Composer | unchanged `1.0.14` |

Helix RC4 is built from `626503b` plus version reconciliation commit
`516f5706b20c169c25dfe57f4dd3ca0bfb2f0092`. The local preflight node SHA-256
was `cf851aa09f9f639847b649a36ec9859e24b7586ba2c8b9f8ea20abb8e3d63fd8`.
The official Actions prebuild from run `43617794080` is 15,432,192 bytes with
SHA-256 `7a82a1a36a1ecf86cb11e7adfe97ff591cf33fe42bacd68cf50fab44d2c06b61`.
The Code OSS packager adds a deterministic 1,024-byte `.rsrc` section; the
packaged node SHA-256 is
`a4bc81eeda2801dfa737726ec265f83fef86ca40ac9237693f9e6f7abd66e624`.
All executable/data/unwind/relocation sections remain byte-identical.
Both produced identical pseudo-C and HAST hashes. The source passed 419/419
native tests, 192/192 Rust tests, version parity, deterministic pseudo-C, and
deterministic HAST smoke. No other native engine changed.

## Delivery Boundary

RC1 adds:

- worker-consistent x64 Linux syscall dispatch and typed exit evidence;
- non-overlapping stripped ELF ownership, bounded jump-table recovery, SysV
  `main` recovery, and executable-byte discovery coverage;
- corrected x86 RMW width, partial-register preservation, and single decrement
  emission in Helix;
- exact authoritative debug-type evidence through HXDB, Helix, HAST, and HQL;
- textual HQL 1.0 lowering into the existing canonical matcher;
- opt-in `needed` and `bounded` HQL materialization with transactional closure,
  explicit budgets, cancellation, retry, and unknown-state preservation.

RC1 does not claim complete function discovery, complete decompilation, clean
negative evidence for partial scopes, arbitrary LLVM IR compatibility, perfect
pseudo-C, or full Linux libc runtime emulation.

## G07 Package Gate

This file does not make RC1 releasable by itself. Before any tag, release, push,
or publication decision, the exact Windows ZIP must be built from the frozen
candidate commit and pass:

1. manifest/version/commit and native SHA reconciliation;
2. fresh extraction and native presence/load/function checks;
3. G01-G06 focused fixtures plus runbook, NUCLEO, Khimera, Kbase, and filesystem
   audit controls where their immutable corpora are available;
4. Debugger/SAB, Helix, HQL/HXDB, Agent Bridge, Revenant, Elixir, and Composer
   smokes;
5. terminal queue state, zero residual workers, and retained partial/unknown
   semantics.

The G07 exit is `GO-RC`, `FIX-BLOCK`, or `NO-GO`. Stable/latest publication is
a separate explicit decision.
