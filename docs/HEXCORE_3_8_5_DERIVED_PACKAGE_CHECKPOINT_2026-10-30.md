# HexCore 3.8.5 Derived Package Checkpoint

Date: 2026-10-30

Verdict: **FIX-BLOCK**. The implementation matrix has no unresolved reproduced
P0/P1 behavior after the bounded HQL fix, but this derived package is not release
eligible because its stored source/engine manifest predates the accepted overlays.

## Identity blocker

The extracted package still declares commit `c5ebc6b...` and its original
engine manifest. Actual runtime smoke passes 9/9, but two identities differ:

| Engine | Stored | Actual |
|---|---|---|
| Helix | `0.9.4-rc.2`, `56770018...` | official-history `0.9.4-rc.3`, `E4CF25F9...` |
| Revenant | `0.4.0`, `06B46C0E...` | `0.5.0`, `F04334FE...`, ILSpy `11.1.0.9782` |

The Helix node does not reuse the RC.2 public identity. RC.3 source is committed
locally on the official history and its source-bound dependency bundle is ready
with SHA-256 `BC1B796C...D0D70`. Push, prerelease creation and the Windows
prebuild remain separately permission-gated.

## Official Helix reconciliation

The local Helix development branch and official repository had unrelated Git
histories. A clean worktree was therefore created from official RC.2 commit
`585606d0`, and 41 code/build/schema files were overlaid by a named allowlist.
No force-push, history graft, corpus import or generated-output import occurred.

That official-history candidate passed:

- 112/112 native build targets;
- 412 native tests, zero failures, one optional fresh-producer skip;
- 192 Rust workspace tests, zero failures, two ignored documentation examples;
- direct N-API controls for calculator baseline, calculator obfuscated and the
  clean issue #30 function.

Its RC.3 addon SHA-256 is `E4CF25F9...53231` and reports matching wrapper/native
identity. The result is recorded in
`HELIX_0_9_4_RC3_OFFICIAL_RECONCILIATION.md`.

## Defects closed in this matrix

1. **Helix false-high confidence.** Calculator baseline and obfuscated outputs
   now cap at 50% for final-AST defects instead of reporting 100%. Native gates:
   97 focused PASS; 347 broad-current PASS and one optional SKIP.
2. **HQL positive witness loss.** A definitive persisted prototype was hidden by
   a stale unrelated summary. The product now returns `matched/partial/signal`;
   a missing fact/address remains `unknown`. The fixed package job has revision
   `b5b2dd73...501ab`.
3. **Revenant omission.** The previously accepted 0.5.0 checkpoint was restored
   to the closure worktree. Source suite: 20/20. Package C#/IL with a native
   `System.dll` neighbor: 2/2.

## High-signal package evidence

- Agent Bridge: containment escape and duplicate step ID rejected with no report
  directory.
- Cancellation: job observed running, cancellation requested, native worker PID
  13024 dead before terminal `cancelled`; no snapshot residue.
- HQL/HXDB: structural positive/negative, persistent prototype, pinned reopen,
  semantic explanation and stale-snapshot rejection.
- AArch64: the PIE bias was taken from AnalyzeAll (`0x555555554000`); both PLT
  stubs resolved exactly, while the non-JUMP_SLOT relocation received no stub.
- YARA: 63 active rules, workspace rule loaded, positive 1 qualified match/score
  50, negative 0/score 0.
- Debugger 9/9, Elixir 3/3, Revenant neighbor 2/2.
- Issue #30 final node: 10/10 deterministic, five ok plus one intentional partial.
- Shutdown: final doctor had zero missing/gated commands; after close the bridge
  returned typed `bridge-unavailable` and the discovery file was absent.

## Holds

- E17 broader canonical ELF work remains gated on real red fixtures; the VVV
  claim was refuted on the original corpus.
- E24 is `HOLD-COVERAGE`: Computer Use could not connect to its native pipe, so
  no current-package render/overlap adjudication was possible.
- E19 raw native routing was source-tested but not exercised through this
  package workspace.
- Issue #31 retains semantic/type/SCF output-quality residuals. Honesty caps do
  not mean the malformed operations themselves were repaired.

## Required next block

1. Authorize pushing the accepted Helix and HexCore branches.
2. Create the Helix RC.3 prerelease, upload the prepared dependency bundle and
   run the Windows prebuild workflow.
3. Replace/amend the provisional Function Atlas node hash if the workflow asset
   differs from the locally qualified node.
4. Run the HexCore artifact-only workflow from the final commit.
5. Extract the new ZIP to a fresh E: root, require manifest/runtime identity,
   rerun the internal delta, then hand only the frozen manual/corpus/package to
   the independent evaluator.

Allowlisted local commits were created. No push, tag, GitHub release, ZIP
publication or issue change occurred in this checkpoint.
