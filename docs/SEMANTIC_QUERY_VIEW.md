# SemanticQueryView - 3.8.5 Development

`openSemanticQueryView` in `hexcore-disassembler/src/semanticQueryView.ts` captures
the semantic state of an already-bound `SessionStore`. It is an API, not a new
database or a headless CLI. HQL's installed live reader and Semantic Explorer
consume this shared view.

## Identity

Each view exposes target identity, format/architecture, session ID and generation,
replay-universe SHA-256, logical snapshot SHA-256, reference/propagation generation
observations and engine identities. An optional engine-generation observation is
kept separate from the persisted session generation; these counters are not
interchangeable. Unchanged facts can retain older evidence generations.

Expected target/generation/universe/snapshot values can be supplied when opening.
Wrong or stale identities fail explicitly. Pagination accepts `snapshotSha256`
to prevent a cursor from silently continuing against another view.

The logical hash includes the accepted records and retained annotations, not
incidental session paths, capture times or annotation update timestamps. Existing
fact provenance identifiers are preserved, not rewritten. Annotation edits that
do not advance the session counter still produce a different content hash.

## Read Semantics

- Capture runs synchronously inside a SQLite read snapshot with query-only mode.
- Queries on a captured view do not access or mutate the live database.
- Nested records and arrays are frozen. Later edits cannot alter an older view.
- Cache invalidation considers both local changes and external WAL commits.
- Collection/byte budgets are checked before hydration. Unavailable collections
  have explicit diagnostics; guarded getters throw instead of returning clean
  empty results. The default logical budget is 100000 rows / 64 MiB, not a promise
  about total process RSS.
- Dirty summaries cannot be fetched as current propagation summaries. Conflicts
  and barriers remain inspectable without promoting their evidence strength.

Opening/initializing `SessionStore` is a separate mutable lifecycle operation.
The read-only guarantee applies to view capture and querying, not to session
creation, migration or explicitly requested analysis.

## Surface

The view exposes prototype/type/binding lookup, shared typed-reference filtering,
current propagation summaries, type conflicts, reference conflicts, propagation
conflicts, barriers, captured annotations, coverage and bounded collection pages.
Invalidated/historical reference queries are not silently substituted for the
active reference collection; captured version metadata remains available.

`knownFunctions` comes from the persisted index when available.
`universeMaterializations` counts replay-manifest entries, not every body ever
decoded. `negativeEvidenceUsable` is always false at this read-model layer:
query-specific coverage must be established by the consumer.

## HQL Boundary

Live scans validate the HAST producer's target and architecture before attaching
a semantic snapshot. The snapshot hash participates in HQL cache identity and is
reported with the result. Missing/mismatched producer identity is not repaired by
borrowing the active database. Semantic read failures block evaluation rather than
producing absence-based matches.

Legacy offline `SessionDbReader` remains a compatibility path and does not claim
this new generation-pinned contract. No matcher language, taint model or symbolic
execution was added by this change.

Initial capture remains synchronous and can take noticeable time on a large
session; reuse is cached. Large-corpus latency and packaged IDE behavior must be
qualified independently before closing the implementation issue.

## Measured development-runtime capture

The frozen Poly ARM64 session was measured on 2026-09-22 using a copied binary
and copied 3,420,160-byte HXDB. The source database was not opened by the
benchmark.

- captured view: 36 known functions, 267 active references and 267 reference
  versions;
- coverage: `ok`, zero dirty summaries, read errors or unavailable collections;
- initial cold capture: 121.30 ms;
- reopen cold capture: 98.87 ms with identical target/snapshot identity;
- 20 cached captures: 0.029 ms minimum, 0.044 ms median, 0.112 ms maximum;
- process RSS delta across cold, cached and reopen captures: 27,496,448 bytes;
- semantic revision, cache identity and reopen identity remained stable.

Evidence SHA-256:
`B1BA31C669910C41AABF822C053682E2BAFC8568972176F2F7D9A59614CF5F0F`.
This qualifies initial capture and cache reuse for the development runtime at
this corpus size. It does not claim packaged-build performance or complete
Semantic Explorer UI acceptance.

The integrated development contract (QueryView identity/read snapshots, HQL
bridge, semantic explanation and Semantic Explorer rendering) passes 24/24.
One combined run exceeded its 30-second fixture-setup deadline before executing
the write-blocking case; the isolated rerun passed in 69 ms. No semantic
assertion failed. Packaged visual interaction remains a release-candidate gate.
