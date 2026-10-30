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
| Revenant | `0.5.0` |
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
| Helix | `0.9.4-rc.3` | `e4cf25f9bd3dc99555fad7abbaa89de03b8de4f7f70d6e0e1058009138053231` (qualified local build; published asset hash gate pending) |
| Elixir | `1.0.4` | `51129cb794b946331eec7d4d4df652bcde26a3610221e282d5e91f607afe9b25` |
| Revenant backend | `0.5.0` / ILSpy `11.1.0.9782` | `f04334feef9b9fa27689d5b30342fe81a3865821cba0f480127a660663cd58a2` |

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
| Named job IDs/references/goto | IMPLEMENTED | SOURCE-PASS | DERIVED-PACKAGE-PASS | final artifact pending |
| Native-worker isolation/cancel | IMPLEMENTED | SOURCE-PASS | PACKAGE-PASS | accepted |
| Artifact ancestry/outcome gates | IMPLEMENTED | SOURCE-PASS | DERIVED-PACKAGE-PASS | final artifact pending |
| AnalyzeAll reuse/session closure | IMPLEMENTED | SOURCE-PASS | DERIVED-PACKAGE-PASS | final artifact pending |
| Function ownership/direct range | IMPLEMENTED | SOURCE-PASS | PACKAGE-PASS (PE); ELF hidden HOLD | accepted scoped #30 |
| SCF/goto/confidence honesty | IMPLEMENTED | SOURCE-PASS | PACKAGE-PASS-WITH-HOLDS | accepted 3.8.5 slice; #31 stays open |
| Helix final-node honesty | IMPLEMENTED | SOURCE-PASS | DERIVED-PACKAGE-PASS-WITH-HOLDS | distinct prerelease identity required |
| SemanticQueryView | IMPLEMENTED | SOURCE-PASS | DERIVED-PACKAGE-PASS | final artifact pending |
| HQL ad-hoc query | IMPLEMENTED | SOURCE-PASS | DERIVED-PACKAGE-PASS | positive witness remains partial/signal; absence unknown |
| Semantic explain | IMPLEMENTED | SOURCE-PASS | DERIVED-PACKAGE-PASS | final artifact pending |
| PE overlay/directory coverage | IMPLEMENTED | SOURCE-PASS | DERIVED-PACKAGE-PASS | final artifact pending |
| Exact-range disassembly | IMPLEMENTED | SOURCE-PASS | PACKAGE-PASS | accepted baseline |
| `.pdata` ownership | IMPLEMENTED | SOURCE-PASS | focused regression | pending E09/E16 |
| ELF canonical address model | original VVV premise refuted | source gaps documented | original corpus PACKAGE-PASS / NO-FIX | future migration requires real red fixtures |
| AArch64 PLT/branch ownership | IMPLEMENTED | SOURCE-PASS | DERIVED-PACKAGE-PASS | experimental/focused |
| Native PE/ELF/raw routing | IMPLEMENTED | SOURCE-PASS | DERIVED-PACKAGE-PARTIAL | raw package lane remains |
| Android-container rejection | IMPLEMENTED | SOURCE-PASS | DERIVED-PACKAGE-PASS | typed DEX rejection |
| YARA advisory scoring | IMPLEMENTED | SOURCE-PASS | DERIVED-PACKAGE-PASS | qualified positive and clean negative |
| Debugger | existing | existing tests | DERIVED-PACKAGE-PASS | no major 3.8.5 claim |
| Revenant 0.5.0 | IMPLEMENTED | 20/20 SOURCE-PASS | DERIVED-PACKAGE-PASS | ILSpy 11.1 and HX-SH-009 fix |
| Elixir | existing | existing tests | DERIVED-PACKAGE-PASS | no major 3.8.5 claim |

## Helix Delta and Boundary

The official-history Helix `0.9.4-rc.3` reconciliation is rooted at RC.2 commit
`585606d0` and imports 41 code/build/schema files through a named allowlist.
RC.3 reports 412 native PASS, one optional SKIP and 192 Rust workspace PASS.
The prepared source-bound dependency bundle has SHA-256
`ec1105a9be36d2945b22586bb72b4f1e529f6691bf5d8315fb15dc27cc5dba6b`.

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
| #30 direct valid unregistered function | PE64 acceptance PASS; hidden ELF fixture HOLD-COVERAGE | close only after explicit approval |
| #31 malformed pseudo-C/high confidence | honesty/SCF slice accepted; matrix holds remain | retain open |
| #37 historical Remill lifter failures | not recently reproduced | retest, then supersede or retain |
| #60 AVX-512 fallback | open tracking enhancement | deferred |
| #61 ELF base/ORG/seeds | original VVV P1 refuted: `.init` is valid RX code at `0x401000` | supersede/close only after explicit approval; future ET_EXEC-zero/ET_DYN/ET_REL work separate |
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
| E06 | Named jobs | PASS on derived package |
| E07 | Artifact contracts | PASS on derived package |
| E08 | AnalyzeAll/session | PASS on derived package |
| E09 | Function ownership | PASS-PE / HOLD-ELF-HIDDEN |
| E10 | SCF/goto honesty | PASS-WITH-HOLDS |
| E11 | Helix quality | PASS-WITH-HOLDS on accepted final node; prerelease identity pending |
| E12 | HQL structural | PASS on derived package |
| E13 | HQL semantic | PASS after bounded positive-witness fix |
| E14 | Semantic view | PASS on derived package |
| E15 | Semantic explain | PASS on derived package |
| E16 | PE evidence | PASS on derived package |
| E17 | ELF mapping | original VVV PASS/NO-FIX; broader canonical model DEFERRED-REAL-RED-FIXTURES |
| E18 | AArch64 context | PASS on derived package |
| E19 | Native routing | PARTIAL; PE/ELF/DEX pass, raw package lane open |
| E20 | YARA advisory | PASS on derived package |
| E21 | Debugger smoke | PASS on derived package |
| E22 | Revenant smoke | PASS on 0.5.0 derived package |
| E23 | Elixir smoke | PASS on derived package |
| E24 | UI smoke | HOLD-COVERAGE; Computer Use native pipe unavailable |
| E25 | Determinism | PASS, issue #30 K=10 |
| E26 | Shutdown hygiene | PASS on derived package |

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

Phase 0 advanced to issue #30/#31 ownership and SCF honesty using its standalone
goal document.

## Phase-1 #30/#31 Checkpoint

Phase 1 completed on 2026-10-30 with `PASS-WITH-HOLDS`.

- deterministic hidden PE64 fixture: 10/10 semantic reruns identical;
- non-executable and mid-instruction controls: typed/partial as required;
- HexCore focused tests: 87 PASS;
- Helix focused tests: 89 PASS;
- Helix broad current suite: 273 PASS, 1 optional SKIP, 0 FAIL;
- fresh Kbase large path: 1,399 decoded instructions, 4.466 seconds,
  intentional partial, no Extension Host hang;
- final candidate Helix node SHA-256:
  `e4cf25f9bd3dc99555fad7abbaa89de03b8de4f7f70d6e0e1058009138053231`
  (local qualification; replace with the published workflow hash if different).

Adjudication and checksums are recorded in:

- `ISSUE_30_DIRECT_OWNERSHIP_ACCEPTANCE.md`;
- `ISSUE_31_SCF_GOTO_POLICY.md`;
- `ISSUES_30_31_FINAL_ADJUDICATION.md`;
- `ISSUES_30_31_ACCEPTANCE_MANIFEST.json`;
- `ISSUES_30_31_SHA256SUMS.txt`.

Phase 1 advanced to issue #61 adjudication. The public #31 issue remains open;
the Phase-1 holds are not release claims.

## Phase-2 #61 Adjudication

Phase 2 completed on 2026-10-30 with `REFUTED-ORIGINAL-CORPUS / NO-FIX`.

The VVV fixture declares:

- minimum `PT_LOAD` at `0x400000`;
- executable `.init` at `0x401000..0x40101B`;
- executable `.text` and entry at `0x31337000`.

The routine at `0x401000` has eight instructions, terminates in `ret`, and is
called from `0x3133BA1C`. Removing it would be a regression. A clean current
package run completed AnalyzeAll, ASM and session export with 3 ok / 0 partial /
0 error in 3.041 seconds.

Independent source gaps remain documented for ET_EXEC mapped at zero, guessed
ET_DYN runtime bias and flat ET_REL section identity. They are not attributed
to VVV and require dedicated red fixtures before a cross-consumer migration.

Evidence:

- `ISSUE_61_CURRENT_CONSUMER_MAP.md`;
- `ELF_ADDRESS_MODEL_SPEC.md`;
- `ISSUE_61_BASELINE_MATRIX.json`;
- `ISSUE_61_ACCEPTANCE_MATRIX.json`;
- `ISSUE_61_FINAL_ADJUDICATION.md`.

The derived-package matrix completed with `FIX-BLOCK`: runtime behavior is
accepted with declared holds, but E01 fails release identity because the
stored manifest/commit predates the accepted Helix, HQL and Revenant overlays.
See `HEXCORE_3_8_5_DERIVED_PACKAGE_CHECKPOINT_2026-10-30.md`. The next block is
allowlisted commits, a distinct Helix prerelease, artifact-only rebuild and
fresh-package E2E.
