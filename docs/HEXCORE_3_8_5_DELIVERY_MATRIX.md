# HexCore 3.8.5 Delivery Matrix

Status: PHASE-0 BASELINE FROZEN

Date: 2026-10-30

This matrix is the source of truth for what HexCore 3.8.5 intends to deliver.
Implementation, source qualification, package qualification and release claims
are separate states. A feature is not considered shipped merely because source
code or a command ID exists.

## Release Positioning

HexCore 3.8.5 is:

> Analysis Contract + Agentic Semantic Workbench + Helix Quality Release

It is not a claim that every engine received a major feature generation.

## Baseline Identities

| Identity | Value |
|---|---|
| Released baseline | HexCore 3.8.4 |
| Released source commit | `148e0870267ef6275aa27edf201924d82c38c76c` |
| Closure branch | `release/3.8.5-closure` |
| Closure starting commit | `c5ebc6b6052ef32c9aa4a8fa1fec708bf59e5e56` |
| Accepted baseline workflow | `41015593557` |
| Accepted baseline ZIP SHA-256 | `997f63aaadef214bcc30716792dbaf1b610287e82bc9bc8759b9db2106290c0b` |
| Product identity | `3.8.5-rc.1` |
| Supported packaged host | Windows 10/11 x64 portable ZIP |

The accepted ZIP is evidence for the starting commit only. A later merge/tag
must produce and qualify a new artifact with its own manifest and hash.

## Integrated Extension Versions

| Component | 3.8.5 baseline |
|---|---|
| Disassembler | `1.4.74` |
| Debugger | `2.1.22` |
| HQL | `0.3.1` |
| Common | `1.3.1` |
| PE Analyzer | `1.1.4` |
| File Type | `1.0.3` |
| Revenant | `0.4.0` |
| Elixir | `1.0.4` |
| Strings | `1.3.3` |
| YARA | `2.1.3` |
| IOC | `1.1.2` |
| Report Composer | `1.0.14` |

Unchanged package versions do not imply that every component has no source
changes. They also do not authorize a new release claim without package tests.

## Accepted Native Runtime Baseline

| Runtime | Version | Primary SHA-256 |
|---|---|---|
| Capstone | `1.3.6` | `409cf8a38f99fb78df58c0f49946f3c8eb27449af188dbf4f0df8138a3d0de91` |
| Unicorn | `1.3.2` | `8000559652da2dfd187851f595cc61d78c736f7237241bb17144532abdf86b64` |
| LLVM MC | `1.0.2` | `0b23a3b8c050a7cdd898417d9c237e005458bbb9bae519ca3a390fe282a20e1c` |
| better-sqlite3 | `2.0.3` | `d630b7f07dfb260b9ff312b68e9c536d22a3bca382db649528d88779820d5a54` |
| Remill | `0.5.4` | `0b013bf7e31c4e2e5c1249d2c95fb7657f51f70b812d6faf6a07392d8e22b078` |
| Souper | `0.2.2` | `241a9b5d7a8c7f56c4b443805f52ed7f3e84fbc0bda9c0d4a25bb0265349ec86` |
| Helix | `0.9.4-rc.2` | `567700180e38774bc234d06a8f0f73e6752d9a54a95004040f0ee62a4ad6c011` |
| Elixir | `1.0.4` | `51129cb794b946331eec7d4d4df652bcde26a3610221e282d5e91f607afe9b25` |
| Revenant backend | `0.4.0` | `06b46c0e0ffb2e920d6a90b66ca03bb86900b0dbb8eb3a5311922c92f7bf0bbe` |

Rellic `0.1.0` remains inactive and is not a delivered runtime.

## Delivery States

Definitions:

- `IMPLEMENTED`: source/command exists.
- `SOURCE-PASS`: focused source tests pass.
- `PACKAGE-PASS`: extracted-product behavior passes positive and negative gates.
- `HOLD-COVERAGE`: required packaged or corpus path has not been exercised.
- `GOAL-OPEN`: a bounded implementation goal is required before release.
- `DEFERRED`: explicitly outside 3.8.5.

| Pillar | Implementation | Source | Package | Release claim |
|---|---|---|---|---|
| Agent Bridge v1 | IMPLEMENTED | SOURCE-PASS | PACKAGE-PASS | accepted |
| Workspace trust boundary | IMPLEMENTED | SOURCE-PASS | PACKAGE-PASS | accepted |
| Named job IDs/references/goto | IMPLEMENTED | SOURCE-PASS | HOLD-COVERAGE | pending E06 |
| Native-worker isolation/cancel | IMPLEMENTED | SOURCE-PASS | PACKAGE-PASS | accepted |
| Artifact ancestry/outcome gates | IMPLEMENTED | SOURCE-PASS | HOLD-COVERAGE | pending E07 |
| AnalyzeAll reuse/session closure | IMPLEMENTED | SOURCE-PASS | HOLD-COVERAGE | pending E08/E25 |
| Function ownership/direct range | partial | partial | HOLD-COVERAGE | GOAL-OPEN #30 |
| SCF/goto/confidence honesty | partial | partial | HOLD-COVERAGE | GOAL-OPEN #31 |
| Helix RC.2 quality | IMPLEMENTED | SOURCE-PASS | partial smoke | final identity pending |
| SemanticQueryView | IMPLEMENTED | SOURCE-PASS | HOLD-COVERAGE | pending E14 |
| HQL ad-hoc query | IMPLEMENTED | SOURCE-PASS | HOLD-COVERAGE | pending E12/E13 |
| Semantic explain | IMPLEMENTED | SOURCE-PASS | HOLD-COVERAGE | pending E15 |
| PE overlay/directory coverage | IMPLEMENTED | SOURCE-PASS | HOLD-COVERAGE | pending E16 |
| Exact-range disassembly | IMPLEMENTED | SOURCE-PASS | PACKAGE-PASS | accepted baseline |
| `.pdata` ownership | IMPLEMENTED | SOURCE-PASS | focused regression | pending E09/E16 |
| ELF canonical address model | partial | partial | HOLD-COVERAGE | GOAL-OPEN #61 |
| AArch64 PLT/branch ownership | IMPLEMENTED | SOURCE-PASS | HOLD-COVERAGE | experimental/focused |
| Native PE/ELF/raw routing | IMPLEMENTED | SOURCE-PASS | HOLD-COVERAGE | pending E19 |
| Android-container rejection | IMPLEMENTED | SOURCE-PASS | HOLD-COVERAGE | metadata only |
| YARA advisory scoring | IMPLEMENTED | SOURCE-PASS | HOLD-COVERAGE | pending E20 |
| Debugger | existing | existing tests | smoke required | no major 3.8.5 claim |
| Revenant | existing | existing tests | smoke required | no major 3.8.5 claim |
| Elixir | existing | existing tests | smoke required | no major 3.8.5 claim |

## Helix Delta and Boundary

The official Helix `0.9.4-rc.1 -> 0.9.4-rc.2` comparison contains nine commits,
49 changed files, approximately 6,507 additions and 530 deletions. RC.2 reports
389 native tests and 192 Rust workspace tests.

Accepted RC.2 themes include:

- address/value corrections;
- ABI and calling-convention recovery;
- variable recovery and return binding;
- x86 floating-flag semantics;
- AArch64 arithmetic/bitfield semantics;
- entry identity and HAST quality;
- SCF/honesty corrections and damning-defect accounting;
- GCC/Linux standalone portability gates.

Not included merely by this baseline:

- wholesale C2 research history;
- the local SCF-structurer branch;
- complete issue #31 closure;
- complete issue #62 type propagation;
- LLVM/MLIR 22 migration;
- Linux support for the HexCore IDE.

The final Helix version remains a release decision after the #30/#31 goal.

## Open-Issue Reconciliation

| Issue | Current evidence | 3.8.5 disposition |
|---|---|---|
| #30 direct valid unregistered function | unresolved correctness gap | mandatory goal |
| #31 malformed pseudo-C/high confidence | partially mitigated; not closed | mandatory scoped goal |
| #37 historical Remill lifter failures | not recently reproduced | retest, then supersede or retain |
| #60 AVX-512 fallback | open tracking enhancement | deferred |
| #61 ELF base/ORG/seeds | unresolved P1 bug | mandatory goal |
| #62 authoritative type propagation | partial foundation only | deferred to 3.8.6 |
| #63 native batch decompile | not implemented | deferred |
| #64 no-IDE runner | Agent Bridge intentionally requires IDE | separate architecture |
| #65 SemanticQueryView | implemented | package acceptance then reconcile |
| #66 HQL text syntax | not part of canonical JSON query delivery | deferred |
| #67 `hql.queryHeadless` | implemented | package acceptance then reconcile |
| #68 named job step IDs | implemented | package acceptance then close |
| #69 `semantic.explain` | implemented | package acceptance then reconcile |
| #70 query-scoped materialization | `materialization:"never"` only | deferred to 3.8.6 |
| Helix #15 recurring quality defects | partially addressed by RC.2 | retain residuals |
| Helix #16 SCF tuple state | research remains open | scoped evidence may join #31 |

## Explicitly Deferred Claims

3.8.5 must not claim completion of:

- issue #62;
- AVX-512 execution/semantic parity;
- native batch decompilation;
- no-IDE job execution;
- query-scoped materialization;
- Agent Bridge progress/replay/ACL/multi-instance P2;
- HQL text language;
- C2/SCF research wholesale adoption;
- LLVM/MLIR 22;
- BinDiff;
- commercial VM detection;
- ChaCha/Salsa structural detection;
- Linux-host HexCore packaging.

## Package E2E Matrix Status

| ID | Pillar | Phase-0 state |
|---|---|---|
| E01 | Package identity | PASS on c5ebc6b baseline |
| E02 | Native runtimes | PASS 9/9 on c5ebc6b baseline |
| E03 | Workspace trust | PASS positive/negative |
| E04 | Agent Bridge | PASS |
| E05 | Active cancellation | PASS |
| E06 | Named jobs | pending |
| E07 | Artifact contracts | pending |
| E08 | AnalyzeAll/session | pending |
| E09 | Function ownership | blocked by #30 goal |
| E10 | SCF/goto honesty | blocked by #31 goal |
| E11 | Helix quality | partial; final corpus/identity gate pending |
| E12 | HQL structural | pending |
| E13 | HQL semantic | pending |
| E14 | Semantic view | pending |
| E15 | Semantic explain | pending |
| E16 | PE evidence | pending |
| E17 | ELF mapping | blocked by #61 goal |
| E18 | AArch64 context | pending focused gate |
| E19 | Native routing | pending |
| E20 | YARA advisory | pending |
| E21 | Debugger smoke | pending |
| E22 | Revenant smoke | pending |
| E23 | Elixir smoke | pending |
| E24 | UI smoke | pending |
| E25 | Determinism | pending |
| E26 | Shutdown hygiene | PASS on Agent Bridge baseline; full matrix pending |

## Documentation State

Phase-0 reconciliation updates:

- Automation integrated versions updated to Disassembler 1.4.74, Common 1.3.1
  and PE Analyzer 1.1.4;
- Automation now states the workspace trust boundary;
- Job Templates now document `autoRun:false` and Agent Bridge validation/submit;
- root changelog now includes Agent Bridge and post-RC product gates.

The root README intentionally continues to describe stable 3.8.4 until the
release decision. Its candidate version table and release narrative must be
updated only after the final artifact/Helix identity is frozen.

## Pre-Reconciliation Documentation Hashes

| File | SHA-256 |
|---|---|
| `HEXCORE_AUTOMATION.md` | `828082ad5695252d25926ae3d9e1ee613578ed80efbdd0778d73c56ea2566545` |
| `HEXCORE_JOB_TEMPLATES.md` | `0edf08c0ce94adcd143881206040102b23b84d8243571451011465c8ef0ca0ce` |
| `HEXCORE_AGENT_BRIDGE.md` | `e263b5430e0e93be42a66aa52f91bae30bb001425ea63f3aa40b638f2ad812dc` |
| `CHANGELOG.md` | `eaf29da231be6232bd3ea032a1f2843b0c71731e36ae3ce8d3bb9f053eae6fce` |

Final documentation hashes are recorded in the Phase-0 checksum file.

## Phase-0 Exit Gate

Phase 0 is accepted only when:

- this matrix and reconciled docs parse/read correctly;
- source branch remains based on `c5ebc6b` plus docs-only changes;
- no deferred implementation enters the diff;
- final documentation hashes are recorded;
- the checkpoint receives an allowlisted diff review;
- no push occurs without explicit approval.

Next implementation phase after acceptance: issue #30/#31 ownership and SCF
honesty, using its existing standalone goal document.
