# Hogwarts `analyzeAll` P2 Output and Hydration Qualification

Date: 2026-11-08

Verdict: **PASS-WITH-ARCHITECTURAL-RESIDUAL** for Disassembler `1.4.76`.

## Scope

This follow-up addresses the two P2 items retained after the Hogwarts P1 fix:

1. a 98.7 MB primary `analyzeAll` JSON containing every function summary;
2. duplicate snapshot collections during Extension Host hydration.

Target SHA-256:
`9cab3d4214ec292bc7829cb662d25eb8817b9ffc14e33bbb360913f4273b1213`.

## Compact Output Contract

- Primary JSON defaults to an address-ordered preview of 10,000 functions.
- `functionSummary` publishes exact total/returned/limit/truncated counts.
- A complete address-ordered NDJSON index is written incrementally beside the
  primary output when truncation occurs.
- `functionIndex` publishes path, media type, record count, byte count and
  SHA-256.
- Pipeline provenance verifies the sidecar and retains it as an
  `auxiliaryArtifact` distinct from Helix HAST/C pairing artifacts.
- `functionSummaryLimit` and `emitFunctionIndex` are explicit job options.

### Hogwarts Result

| Artifact | Before | After |
| --- | ---: | ---: |
| Primary JSON | 98,725,875 B | 3,568,972 B |
| Functions in primary array | 303,644 | 10,000 |
| Full streamed index | none | 37,877,711 B |
| Full index records | n/a | 303,644 |

Primary JSON reduction: approximately 96.4%.

Full index SHA-256:
`1030160f23863986a6bbf384b639519b7f3f20acb093217a117dfc5595dce167`.

The on-disk hash, returned `functionIndex.sha256`, and provenance hash match.

## Adoptive Hydration

`loadAnalysisSnapshot` now adopts the trusted deserialized collections rather
than cloning every function, instruction, string and xref. The default public
`importAnalysisSnapshot` path still clones, preserving callers that reuse their
snapshot object.

Standalone same-snapshot comparison:

| Metric after import | Clone | Adopt |
| --- | ---: | ---: |
| Heap used | 854,030,240 B | 605,306,872 B |
| RSS | 2,078,347,264 B | 1,835,626,496 B |

The adopted envelope had zero remaining function/string/xref arrays after
transfer. Heap reduction was approximately 29%; RSS reduction was approximately
243 MB in this adversarial retention harness.

## Agent Bridge Final

- Job revision:
  `e309b26ef70b2fdb7efaada91ede28418ed8dfc17410a9ecac902a5fd0f7c560`
- Pipeline: `partial`, 0 errors, queue `0/0`
- Native execution: completed
- Native duration: 139,159 ms
- Native peak heap: 1,002,024,884 bytes
- Extension Host RSS after hydration/output: 1,244,278,784 bytes
- Worker residual: zero
- Provenance owner: `hikarisystem.hexcore-disassembler` `1.4.76`

A forced one-entry preview smoke independently proved primary truncation,
complete NDJSON rows, hash equality and auxiliary provenance on a 2 KiB PE.

## Agent Discoverability

There is one indexing command, not separate lazy/eager variants. Agent Bridge
capabilities and analyzeAll results now publish:

- `analysisMode: "index-all-materialize-on-demand"`;
- `lazySemantics.automatic: true`;
- `allowLazyControlsAcceptanceOnly: true`;
- `materializeCommand: "hexcore.disasm.materializeFunctions"`;
- recommended materialization, exact disassembly, reference and HQL commands.

This makes `allowLazy` an explicit acceptance policy instead of an apparent
mode switch and gives agents the next operation without relying on prose docs.

## Regression Gates

- Canonical: adoption 11/11, pipeline 29/29, isolated process 9/9
- Dev/WIP merge: adoption 11/11, pipeline 38/38, isolated process 9/9
- Disassembler and Debugger compile independently in `vscode-main`
- Debugger: 115/115

## Residual

The Extension Host still owns the 458 MB target bytes plus more than 303,000
function boundary objects, so it stabilizes near 1.24 GB RSS on this corpus.
Eliminating that retained model requires a paged/on-disk function index or a
long-lived analysis service queried across IPC. That is a separate architecture
change; the duplicate-clone and oversized-primary-output defects are closed.

No commit, push, tag or release was performed.
