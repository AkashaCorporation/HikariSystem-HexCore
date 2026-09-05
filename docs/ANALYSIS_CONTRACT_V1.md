# HexCore Analysis Contract v1

**Status:** initial 3.8.4 implementation

**Contract version:** 1

**Last updated:** 2026-08-05

The Analysis Contract is the shared identity and result vocabulary for HexCore
engines, automation, persistence, and UI. It prevents a result produced for one
binary or analysis generation from being presented as if it belonged to
another.

This document describes the implemented first slice. It does not authorize a
release, commit, push, or removal of compatibility fields.

## Canonical model

The runtime and public TypeScript declarations live in `hexcore-common`.

- `AnalysisTarget` identifies binary content as
  `target:sha256:<digest>`. The source path is metadata and does not affect the
  identity.
- `AnalysisSession` binds a session ID and generation to exactly one target.
- `AnalysisAddress` distinguishes file offset, RVA, VA, and runtime VA.
  Addresses are serialized as lowercase hexadecimal strings. Unsafe JavaScript
  numbers are rejected.
- `AnalysisResult<T>` uses `ok | partial | failed | skipped` and carries typed
  diagnostics and artifact references.
- `AnalysisArtifactProvenance` binds an artifact content hash to its target,
  session, producer engines, inputs, status, and generation time.

The constructors enforce the important invariants. Callers should use them
instead of assembling contract objects manually.

## Automation artifacts

Pipeline artifact provenance is consolidated in the run-level
`.hexcore-meta/provenance.json` schema version 1 manifest. Each artifact's canonical
`analysisContract` block contains the target, session, producer, artifact hash,
and terminal semantic status. Existing `execution`, `step`, `artifact`, and
`ownerExtensions` fields remain present for 3.8.3 compatibility.

Artifact persistence fails closed when a canonical target or session is
missing. A child `error` is represented as canonical `failed`; it cannot be
silently promoted to `ok`.

## Persistent sessions

`SessionStore` writes the following additive keys to `session_meta` after the
binary format has been parsed:

```text
analysis_contract_version
analysis_target_json
analysis_session_json
```

No table migration is required for this slice. Existing renames, retypes,
comments, bookmarks, and saved findings retain their schemas.

Reopening identical binary content reuses the persisted session ID. Replacing
the bytes at the same path creates a different target and session. This follows
the existing rule that derived analysis is cleared on a binary hash mismatch
while user-owned annotations are retained.

The Analysis Center exposes the current target identity and session generation
from the same store used by headless analysis.

## Compatibility boundary

The contract is additive in this first release slice:

- legacy pipeline sidecar files from earlier runs remain valid evidence, but new runs emit the consolidated manifest;
- existing numeric engine APIs are not removed;
- existing session tables are not rewritten;
- extensions that do not yet consume the contract continue to operate.

New cross-engine or persisted APIs must use canonical address strings and
target/session identity. Numeric addresses remain an internal compatibility
surface until their consumers are migrated.

## Validation completed

- `hexcore-common`: address, target, session, result, and provenance invariants;
- `SessionStore`: close/reopen identity and same-path binary replacement;
- automation: schema-v2 provenance assertions and 100 concurrent cross-binary
  pairs without target contamination;
- retained IR-to-pseudo-C provenance records the input artifact hash and
  extension-correct media types; low-confidence Helix output remains `partial`;
- disassembler TypeScript compilation;
- existing pipeline summary and step-record regression suites.

## Remaining 3.8.4 work

Status as of 2026-08-06 (waves 1-2, `docs/3.8.4-wave-1.md`,
`docs/3.8.4-wave-2.md`):

1. ~~Define stable IDs~~ — **partially done**: `analysisIds` module shipped in
   `hexcore-common` 1.2.0 with all ten object kinds; adopted for CFG blocks
   and investigation findings (Disassembler 1.4.30). Open: session DB
   `functions` primary-key migration (gated on item 6) and ID adoption in the
   remaining analyzer surfaces.
2. ~~Add explicit reanalysis generations~~ — **done at the store layer**:
   `startReanalysis()` / persisted `analysis_generation_counter` /
   `invalidateFunction()` selective invalidation. Open: `analyzeAll` does not
   call `startReanalysis()` yet (lands with the Workbench reanalysis flow).
3. ~~Record the complete engine manifest~~ — **done**: `analysis_engines_json`
   recorded per session and bound into the persisted session; drift reported
   as diagnostics. Open: structured versions for wrappers that do not expose
   `getVersion()` yet (Capstone, Remill, Souper).
4. Migrate headless command responses — **started**: error-code registry
   (`hexcore-common` 1.3.0) plus contract-decorated responses on `runJob`,
   `validateJob`, `listCapabilities`, `queueJob`, `jobStatus` (Disassembler
   1.4.31). Open: `cancelJob` (boolean break) and the analysis-command tail.
5. Reject stale or wrong-target responses — **started**: typed `wrong-target`
   rejection for cross-target finding references; runner adoption guard
   (persisted state only adopted on digest match). Open: adversarial suite
   extension to command/UI boundaries and engine-wrapper boundary checks.
6. Version the SQLite schema and implement forward migrations with rollback
   and recovery tests — **open** (wave 3).
7. Run K=10 same-process determinism and broken-engine/parser/emulator
   fixtures — **open** (wave 3).

The 3.8.5 Workbench should consume these identities; it must not create a
second target, address, or selection model in the UI layer.
