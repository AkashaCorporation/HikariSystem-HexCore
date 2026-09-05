# Changelog

## [1.4.66] - 2026-09-04

- Remove the developer-specific LLVM path from PDB tool discovery. Use
  HEXCORE_PDBUTIL for a custom install, PATH, or the standard LLVM installation.
- Hide PDB tool probe subprocess windows. No native engine changes.

## [1.4.65] - 2026-09-04

- Keep deferred functions visible in the Functions tree and expose lazy,
  partial, materialized and decode-empty body state. Reference counts are
  explicitly known counts, not an assertion that unseen references do not exist.
- Label Markdown's first-100 function table as an address-ordered preview,
  including the total discovered count and the full JSON-index alternative.
- Do not eagerly decode bodies merely to populate the Functions tree.

## [1.4.64] - 2026-09-04

- Record cross-job refcount source inputs using the SHA-256 of bytes actually
  scanned. Preserve the exact consulted provenance revision as a content-addressed
  `.hexcore-meta/inputs` snapshot and reference it from the audit manifest.
- Label queue status as query-time inclusive counts with observer execution/job
  identity and includesCurrentJob; do not hide a running status-query job.
- Replace legacy Pattern E vulnerability claims and refcount output examples in
  Automation with the schema-v2 signal/observation contract.

## [1.4.63] - 2026-09-04

- Refcount schema v2 separates assertions, warnings and termination calls into
  diagnostic observations. BUG_ON is not a reachable vulnerability by itself.
- Textual refcount and locking matches are explicitly unproven signals; legacy
  confidence/severity are heuristic review priority, not probability/impact.
- Ignore comments and literal contents when matching and delimiting functions.
  Publish skipped lines, incomplete bodies and unsupported syntax as partial
  scanner coverage; propagate those limits to the downstream negative gate.
- Add focused synthetic regression tests without changing native engines.

## [1.4.62] - 2026-09-04

- Bind refcount scan negatives to the exact input SHA-256 and recorded upstream
  statuses. Missing, ambiguous, mismatched, partial, or cyclic provenance keeps
  the result inconclusive. An empty scanner result is never presented as Clean.
- Count complete bodies separately from functions containing decoded instructions.
  Publish analysisDepth, complete/partial counts, and negativeEvidenceUsable:false
  on analysis indexes, including explicitly accepted reconnaissance jobs.

## [1.4.61] - 2026-08-30

- Isolate whole-program propagation and record recovery in a Worker Thread over
  a read-only HXDB snapshot, with the `perseus-sab-v1` heartbeat/cancellation
  channel and parent-only atomic commit after snapshot revalidation.
- Terminalize hard timeout immediately without waiting for worker teardown;
  preserve the last accepted generation and reject late or stale results.
- Index snapshot reference edges and type bindings instead of rescanning the
  complete graph per function.
- Index active reference edges once for propagation input collection, reducing
  the ROTTR collection lane from 44,773 ms to 491 ms and the complete solve
  step from 49,946 ms to 5,802 ms.
- Exclude Worker thread ids, timings, and heartbeat cadence from the semantic
  `outputHash`; the pre/post optimization ROTTR hash remains byte-identical.
- Clamp stale non-`.pdata` function extents at newly materialized adjacent
  function starts and synchronize the in-memory boundary before retrying body
  materialization. The ROTTR PlayerBase helper no longer crosses into the
  prologue at `0x1408359E0`; unknown leaf discovery remains display-only.
- Defer future-generation reference invalidations conservatively and report
  the graph as `partial` instead of either throwing or returning false `ok`.
- Validate the installed ROTTR lane: 16/16 steps terminal, zero errors, HQL
  6/6, propagation 6 functions in 2 iterations, and a responsive Extension
  Host probe during active CPU work.

## [1.4.60] - 2026-08-30

- Bind installed HQL scans to the active target's read-only HXDB and preserve
  semantic fact counts/hashes, matched facts, proof status, and provenance.
- Reconcile equivalent reference edges across generations with one active
  invalidation dependency per `(kind,key)` while retaining version history.
- Model per-function decode completeness and keep partial bodies retryable,
  display-only, and excluded from typed references and propagation summaries.
- Invalidate previously accepted edges/summaries when their source body is
  discovered incomplete; report partial ASM exports honestly.

## [1.4.59] - 2026-08-30

- Add HXDB v2 semantic types/prototypes, typed R33 references, bounded R34
  whole-program propagation, R35 record recovery, and transactional Type Manager.
- Add validated PDB/debug/signature providers, RSDS GUID+age checks, symbol cache
  support, Semantic Explorer, typed HQL facts, and Helix semantic-context propagation.
- Preserve structured Capstone operand access/width in the real engine and recover
  exact data reads/writes, constant function-pointer candidates, and MSVC/PIC jump tables.
- Keep `.pdata` functions lazy before prologue discovery and materialize semantic
  bodies beyond the former 1,000-instruction preview cap.
- Validate 60/60 calling conventions, 202/202 Backblaze API callsites, equivalent
  DWARF/BTF layouts, and deterministic zlib/libarchive semantic artifacts.

## [1.4.58] - 2026-08-28

- Upgrade the HQL integration to the 0.2 evidence contract: preserve clean
  function identity, exact address, AST node count, adapter-loss coverage, and
  active signature-set SHA-256 in every scan result.
- Replace unconditional HQL confidence display with structural completeness,
  explicit signal/candidate/proven level, and optional calibrated confidence.
- Document that the HQL IR lane accepts Remill-compatible IR rather than
  arbitrary LLVM IR.

## [1.4.57] - 2026-08-28

- Make stale-running archives cryptographically self-contained by adding the
  current job-file SHA-256 plus archive reason, age, and timestamp while
  preserving the original status fields.

## [1.4.56] - 2026-08-28

- Execute `analyzeAll` in a killable child process instead of the Extension
  Host thread, with an external deadline, explicit cancel command, supervisor
  heartbeat, last native phase, crash/timeout outcomes, and worker PID.
- Serialize a target-bound full engine snapshot in the child, gzip it, verify
  its digest/size, hydrate the parent without repeating entry/export analysis,
  and delete the transient snapshot after import.
- Preserve per-job analysis limits after child `loadFile`; omit the large
  linear exec scan unless VM/PRNG analysis needs it.
- Archive and terminalize stale `running` watcher statuses before retrying an
  unchanged job revision.
- Format filesystem audit session/universe bindings independently from Helix
  active-engine ownership diagnostics.

## [1.4.54] - 2026-08-27

- Migrate legacy persisted generations that predate replayable universe
  manifests by advancing to a new bound baseline generation and returning an
  explicit `partial/reset` restoration result.

## [1.4.53] - 2026-08-27

- Retain `closureRestoration` in the serialized `analyzeAll` JSON payload, not
  only the in-memory result and downstream audit context.

## [1.4.52] - 2026-08-27

- Define audit normalization as semantic identity across process boundaries by
  excluding process-local `analysisContext.engineGeneration` and
  `analysisContext.closureRestoration` diagnostics in addition to top-level
  timestamp/normalization metadata.

## [1.4.51] - 2026-08-27

- Persist a replayable closure manifest containing every incrementally
  materialized function boundary and body hash, bind it to session generation
  through `universeSha256`, and restore the same function universe on a later
  `analyzeAll` job.
- Require producer dominance, not mere reachability, before path/handle/SID/ACL
  identity promotion; evaluate path mutation/escape barriers over the complete
  feasible producer-to-consumer CFG subgraph, including backedges.
- Keep transient `decode-empty` materializations lazy and retryable.
- Publish `hexcore-canonical-json-v1` identities on filesystem audits with the
  exact exclusions `/generatedAt` and `/normalization`.

## [1.4.50] - 2026-08-27

- Close the lazy-investigation loop: exact on-demand disassembly now commits a
  previously lazy function body into instruction roles, call graph, string/data
  xrefs, IAT names, and a new persisted analysis generation.
- Expose `analysisClosure` on bounded disassembly and return `partial` when
  decoded bytes remain display-only or contain zero semantic instructions.
- Bind downstream shared-analysis artifacts to every committed materialization
  since the latest `analyzeAll`, and refresh provenance to the persisted
  session generation after each refinement.
- Harden stored-value proofs with write widths, register address aliases,
  pointer spill/reload tracking, conservative complex/implicit write barriers,
  and intra-function CFG feasibility for path, handle, SID, and ACL identities.
- Recognize dense enum-to-message construction tables as message-only string
  evidence, and expose reparse/junction safety as `not-assessed` until concrete
  traversal and descendant enforcement evidence exists.

## [1.4.49] - 2026-08-27

- Separate path-buffer storage identity from preservation of the value stored
  there before promoting `same-path` evidence.
- Downgrade a path identity to an explicit signal when an overlapping direct
  write occurs or the buffer address escapes to a call without a proven
  read-only pointer summary.
- Retain exact producer, escape/write barrier, consumer, and blocker evidence
  so aggregate `Path -> open` remains unproven until preservation is shown.

## [1.4.48] - 2026-08-27

- Add bounded Win64 intra-function def-use for RCX/RDX/R8/R9 and stack
  arguments, following move/lea/register aliases, stack loads/stores, call
  return tokens, and out-parameter storage.
- Prove exact same-handle flow from CreateFile/fopen returns into
  WriteFile/CloseHandle/path consumers when canonical identities match.
- Prove same-ACL and same-SID storage between InitializeAcl/SID producers and
  ACE writers; retain all unresolved/interprocedural cases as false.
- Expose callsite argument bindings, canonical identities, definitions, and
  explicit limitations under `dataflow.deepValueFlow`.

## [1.4.47] - 2026-08-27

- Make consolidated provenance acyclic, attach implicit `analyzeAll` ancestry
  to stateful analysis consumers, and bind composed reports to their actual
  scanned source artifacts instead of their own output path.
- Record a stable semantic configuration hash for every retained artifact.
- Add bounded typed SID/ACL/path/handle/sink dataflow facts, call contexts,
  immediate/access-mask candidates, handle lifecycle signals, and
  interprocedural neighborhood paths with explicit same-value blockers.
- Rank filesystem candidates by role diversity, graph connectivity, typed-path
  participation, and product/third-party attribution instead of raw evidence
  count alone; expose top candidate chains and critical helper routes.

## [1.4.46] - 2026-08-27

- Add `hexcore.disasm.windowsFilesystemAuditHeadless`, an evidence-gated PE
  chain builder for principal, state location, writer, lifecycle, parser, path
  property, and sink edges.
- Distinguish imported API signals from materialized IAT callsite owners and
  retain exact caller/callee and string-to-owner pivots.
- Consolidate filesystem-related owners into candidate functions and direct
  candidate call-graph edges without assigning vulnerability severity.

## [1.4.45] - 2026-08-27

- Accept canonical half-open `endExclusive` ranges and
  `stopAtFunctionBoundary` in disassembly and Remill lift jobs, with explicit
  counting domains, boundary reach/crossing, and byte coverage.
- Keep recursive-descent `bytesConsumed` honest as a union-of-intervals
  coverage metric instead of treating it as a linear semantic endpoint.
- Return `partial` plus structured quality issues for Helix placeholders,
  self-references, uninitialized returns, and duplicate locals independently
  of aggregate confidence.
- Expose `materializedFunctionRatio` and an explicit `allowLazy`,
  `allowDecodeEmpty`, and `minMaterializedRatio` policy from `analyzeAll`.
- Recompose the final report after terminal pipeline status persistence and
  retain the report itself only in the post-finalization provenance manifest.

## [1.4.44] - 2026-08-21

- Recover validated x86/x64 leaf callbacks materialized by RIP-relative `LEA`
  and stored as function pointers, retaining both evidence addresses.
- Normalize native function boundaries to `[start, endExclusive)` and accept
  both Capstone 1.3.6 and legacy inclusive-end payloads during migration.
- Use opt-in structured Capstone detail for function-pointer discovery without
  retaining detail for the general disassembly stream.
- Run x86 Pathfinder through bounded recursive descent with separate available
  byte and semantic ownership ends, plus evidence-gated confidence axes.
- Label bounded-disassembly rows as context, semantic body, alignment padding,
  or unclassified, with separate counts and semantic/end-exclusive boundaries.
- Add the authorized `race_worker` release fixture, end-to-end acceptance tool,
  adjacent-function negative controls, and K=10 determinism gate.
- Refuse to assign an address to a nearby predecessor when no detected
  half-open range actually contains it; proximity is no longer ownership.

## [1.4.43] - 2026-08-15

- Treat Z3 `unknown` and timeout as semantic errors by default; explicit
  `allowUnknown`/`allowTimeout` produces `partial` and still requires the
  pipeline step's `allowPartial` opt-in.
- Stop bounded disassembly at a trusted function end before Capstone crosses
  it, with `function-end`, `truncated:false`, and `boundary.crossed:false`.
- Persist Helix translation, lift-coverage, and semantic-type confidence axes
  in durable C artifacts.
- Make `hexcore.pipeline.jobStatus` write the JSON output promised by its
  artifact-validating capability.
- Version session databases with `PRAGMA user_version = 1`; migrate schema 0
  transactionally, preserve legacy analyst data, and back up/rebuild an
  incompatible database instead of leaving the session unusable.

## [1.4.42] - 2026-08-11

- Preserve raw/PE `call $+5` position-independent-code idioms while treating
  the same bytes as an ftrace placeholder only in relocatable ELF objects.
- Skip only the exact nine-byte Linux kernel NOP and report every entry
  transformation with its address and byte length.
- Classify string literals by evidence, including reference, termination, and
  standard CRC32-table overlap, with an optional `minConfidence` result gate.
- Expose translation, lift-coverage, and semantic-type confidence as separate
  axes instead of implying recovered type identity from emitter confidence.
