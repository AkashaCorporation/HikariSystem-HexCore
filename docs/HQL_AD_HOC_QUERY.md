# HQL Ad-Hoc Query Executor

Status: 3.8.5 development implementation for issue #67. The source pipeline
registry exposes `hexcore.hql.queryHeadless`/`hexcore.hql.query`, using the pinned
view, read-only capture, terminable native producer and isolated HAST matcher.
The new Helix addon is installed only in the local development tree after a
verified backup; the development watcher job passes and packaged acceptance is
pending. The bound single-function IR
lane is implemented for runner-minted pipeline artifacts. This is not yet a
shipped feature.

## Canonical JSON IR

```json
{
  "schemaVersion": 1,
  "condition": {
    "all": [
      { "query": { "target": "CCallExpr", "attributes": [{ "field": "callee", "value": "free" }] } },
      { "fact": { "fact": "summary-ownership", "attributes": [{ "field": "ownershipKind", "value": "free" }] } }
    ]
  },
  "addresses": ["0x1000"],
  "select": ["function", "address", "proofStatus", "evidence"],
  "materialization": "never"
}
```

The library exports `normalizeAdHocQuery` and asynchronous `runAdHocQuery`.
Conditions reuse the existing HQL node/fact validators and matcher. They support
mixed `all`, `any`, `not`, and `count` expressions without registering signatures.
No textual parser, taint execution, automatic lifting, or materialization occurs.

Addresses are exact 64-bit hexadecimal values. Name filters are exact and
case-sensitive. When both filters exist, they intersect. Duplicate filter values
and projection order normalize deterministically. Object key order does not
change `querySha256`; boolean children retain declaration order.

Projection controls display columns. Evidence and proof status remain mandatory
on matched rows even when omitted from `select`.

## Bound Inputs

The producer supplies a `QueryInput` with target/session identity, generation,
universe SHA-256, snapshot SHA-256, and per-function records. Every record must
carry the same snapshot hash. Duplicate addresses and mismatched HAST addresses
are errors. This validates binding consistency, not the cryptographic origin of
caller-supplied facts; production inputs must come from the pinned read view and
validated HAST hydration path, not from arbitrary job-provided evidence.

`astAvailable`/`semanticAvailable` mean the evidence is readable and eligible.
`astComplete`/`semanticComplete` additionally mean a closed collection for the
particular function. A successful SQL read does not establish completeness.
Adapter loss, missing bodies and actual unknown/assembly nodes prevent AST
absence claims even if adapter metadata advertises coverage 1. Dirty or failed
semantic reads must not be marked available by the producer.

## Results

Results contain typed matched `rows` and separate per-function `evaluations`:

- `matched`: supplied evidence satisfies the query; not a vulnerability verdict.
- `negative`: the predicate was evaluated false in its stated evidence domain.
- `unknown`: missing, incomplete, unreadable or budget-limited evidence prevents
  deciding the predicate. This is not a clean negative.

Negation of unknown stays unknown. Exact/upper-bound counts cannot establish
absence from incomplete collections. A positive witness can decide an `any`
branch even when another branch is unknown. Structural matches have a `signal`
ceiling; semantic-only witnesses cannot exceed their recorded proof status.
Partial quality or truncated evidence lowers the row to `signal`.
Facts that claim candidate/proven without provenance are retained as `signal`
with an explicit quality reason. Invalid proof-level labels are errors, not an
implicit promotion to proven. Restoring missing producer provenance remains
the responsibility of the bound reader.

Coverage distinguishes requested, evaluated, matched, negative, unknown and
unevaluated functions. Missing explicit selectors and functions omitted by a
budget remain visible. Requested counts include missing explicit address/name
selectors; an unknown name cannot provide a concrete function address.

Evaluations include the HAST/AST hash and semantic-facts hash. Live facts carry
an `origin` with target, snapshot, collection, record identity and canonical
record hash. This identifies the actual persisted record, including legacy
summaries that lack producer provenance; it does not fabricate such provenance.

`resultSha256` hashes the complete logical result excluding that hash field.
No elapsed wall-clock time participates. Repeatability requires the same inputs
and terminal outcome; a timeout is not expected to equal a successful run.

## Isolation and Budgets

The executor validates bounded JSON input, then copies it to a terminable Node
worker. No SQLite handles, native engines or write APIs are passed to the worker.
The host owns cancellation and deadline timers and awaits worker termination
before returning. A blocked regex cannot monopolize the caller's event loop.

Limits cover functions, actual AST nodes, matcher operations, rows, evidence per
row, input/output bytes and timeout. AST depth and worker heap also have ceilings.
The output budget reserves at least 4096 bytes for a terminal envelope. An
oversized result falls back to an explicit partial envelope, not silent clipping.

Timeout/cancellation return partial, truncated, zero committed rows when no
worker result was received. Worker failure returns `success:false,status:error`.
Neither means an evaluated negative. This isolation covers matching and HAST
hydration; native lifting/decompilation and initial snapshot capture have pending latency
and interruption gates. The in-process input-budget walk is bounded but is not
an RSS guarantee or an externally preemptible native operation.

### Native Process Execution

The development-only native producer can now run a prepared descriptor through
Remill and Helix in one child process. It receives bytes/IR, copied data sections
and captured context, not a live DisassemblerEngine or SQLite handle. A host-owned
watchdog covers initialization, lifting and decompilation. Cancellation, timeout,
crash and mismatched responses return `success:false,status:error`; completion
is reported only after the process `close` event. Heartbeats retain PID and phase.

This is operational process isolation, not an OS security sandbox. The child
inherits the user's permissions. The V8 heap setting does not bound C++/LLVM
native allocations; memory and packaged-process behavior still need qualification.

Request/context/input digests and output/HAST bounds are checked. The factory
preserves explicit preparation issues and currently marks the new byte path as
unqualified for full preparation parity. The single-function IDE lift and isolated
producer now share x64 ET_REL relocation byte preparation; prepared IR requires ancestry
validation in command routing. Raw ABI assumptions remain not-assessed.
These gates deliberately prevent the prototype producer from promoting its HAST
to eligible semantic evidence prematurely. The factory/process APIs are not
registered job arguments or a shipped public command yet.

The first native smoke fixture returns constant 7: both addons produced C/HAST in
the child, a short deadline terminated initialization, and the next identical
request reproduced IR/HAST hashes. The accepted engine/database stayed unchanged.
This verifies execution/termination/identity, not general decompilation fidelity.

### Shared Relocation Preparation

`prepareLiftRelocations` is shared by the single-function IDE lift and the
isolated request factory. It copies the source bytes, applies supported x64
ET_REL symbol/data fixups, and returns exact source/prepared hashes, patch records,
external symbol mappings and detached synthetic data sections. Return thunks
remain resolvable; infrastructure not modeled by the helper remains explicit.

Unsupported or deferred relocations, incomplete operand windows, overlapping
writes, missing data and displacement overflow produce diagnostics. The IDE
propagates these into the lift's partial status instead of silently certifying
complete preparation. Large synthetic data sections no longer overlap at fixed
1 MiB spacing. These are byte-fixup claims, not proof that a PC32 relocation is a
call or a particular security-relevant data flow.

Supported-case parity is checked against the exact previous single-function
block, including a real ELF object generated by LLVM. Broader kernel/corpus and
IDE job qualification remains pending. Entry-preamble handling, Pathfinder hints
and post-lift IR symbol/metadata rewriting still need the same shared treatment.
The isolated ET_REL smoke currently retains the global preparation-parity gate;
its recovered string does not mean full native output equivalence is accepted.

### Scoped IR Symbol Resolution

`resolveLiftExternalSymbols` is now shared by the normal single-function lift
and native child. It rewrites target operands in recognized Remill CALLI/JMPI
and call/jump intrinsics, rather than replacing every matching decimal constant.
Existing symbolic operands are idempotent. Quoted symbol names are LLVM-escaped;
declarations are not duplicated, and definitions/conflicts are preserved.

The prior cleanup could corrupt longer integers and remove a definition header
without its body. Frozen-reference tests reproduce both cases; the new helper
preserves those inputs. Comments, string data and return-address arguments are
not rewritten. Unresolved/conflicting mappings are explicit partial-quality
issues. This is a scoped transform over current Remill syntax, not a general
LLVM parser. Other call forms stay unchanged and require qualification.

The real ET_REL control now emits `external_fixture("fixture")` instead of a
synthetic indirect target. This verifies the shared external-name path only:
function-entry naming, preamble address reconciliation, broader IR metadata and
Pathfinder parity still gate public query acceptance. The separate legacy
whole-section lifting path has not been migrated by these single-function changes.

### Pinned Input Bridge

`createHqlQueryInput` and `runHqlSnapshotQuery` in the Disassembler read an
explicit bounded selection from an existing SemanticQueryView. They do not open
a new session, lift, materialize or write. Annotation changes after capture do
not change an old view. `semanticComplete` stays false until a producer proves
closed coverage for the relevant domain. Upstream partial quality is preserved.

The adapter can attach a verified `hastSource` envelope to each selected
function. The envelope contains the exact bytes/hash, pinned identity, expected
target architecture and producer quality. Inside the worker, the existing
`hydrateHAST` implementation applies copied snapshot annotations and checks the
requested function's address and metadata. Hash/identity mismatches fail;
partial/ineligible producers cannot produce structural matches.

Hydration has function and table-visit budgets, plus the worker's external
deadline and heap ceiling. Only selected sources within the function budget are
hydrated. Hydration budget exhaustion is partial and explicitly truncated.
Native lifting/decompilation itself is not covered by this worker.

Do not feed the existing mutable `hexcore.helix.decompile` callback straight into
this read-only contract. Its current lift/context paths can reconcile or heal
function boundaries and materialize lazy instructions. Native producer routing
must preserve the accepted snapshot and avoid those side effects before public
command acceptance.

### Read-Only Native Capture

Preamble decisions now require architecture evidence. Removing an ELF entry call
as ftrace additionally requires the exact `__fentry__` relocation at its operand,
with supported relocation type/addend. An ELF container and `call +0` bytes alone
are insufficient. Missing evidence preserves bytes; x86 patterns do not apply to
AArch64 or a different CET mode.

The isolated producer explicitly uses `entryPreparation.policy:"preserve"`.
It records observed preamble kinds without stripping bytes or shifting entry
addresses. Installed-addon controls for plain/CET/NOP9 entries preserve HAST
address `0x1000` and return the same constant, with full adapter coverage. These
controls do not establish general runtime CFI/ftrace semantics; the producer's
overall preparation qualification remains partial.

Open entry-identity gate: the installed Helix lowering still derives addresses
from names such as `lifted_<decimal>`. Renaming the tested nonzero entry to a
human-readable IR symbol changed its HAST address to `0x0`. A native entry
identity contract or preservation of the encoded identity is required before
accepting named-IR parity. Relabeling HAST afterward would not repair any PC-based
lowering that already used the wrong entry. The public query gate remains open.

The local 0.9.4 native source now supports function attribute
`"hexcore.entry_address"="0x1000"`. The Disassembler stamps it before a
human-readable entry rename, using LLVM-global token handling rather than text
replacement in comments/strings. LLVM import preserves it as typed native
identity before PC substitution. Missing identity is an error, not zero;
explicit zero remains valid. Conflicting encoded-name identities are rejected.
Legacy named IR without this attribute must be regenerated or supplied verified
identity; `bb_N` names cannot provide that evidence because they may be ordinals.

Fresh original/stamped-renamed IR both produce HAST at `0x1000` through the
newly compiled C ABI. The installed addon was not replaced and still reproduces
the old unstamped behavior. Relinking/staging the new addon and testing actual
IDE jobs remain required before this gate can be closed for distribution.

The Disassembler now provides `createReadOnlyHelixAnalysisContext` and the
in-process `captureReadOnlyHelixInput` capability. They reuse the existing context
builder but read semantic types/prototypes/bindings from the pinned view and
accepted instructions directly, never from a materializing accessor.

Capture requires an exact, already complete function, matching recorded extent,
contiguous non-overlapping instruction coverage and matching backing bytes.
Target/session/universe/snapshot and engine generation must agree. Lazy, partial,
missing, stale, patched or oversized inputs are rejected explicitly. The normal
context path retains its existing materialization behavior.

`peekFunctionBodyCompleteness` does not populate the legacy body cache. The
capability stores immutable context and image/body identities, provides detached
byte copies, and rejects revision/model/image changes before further reads. It
cannot be recreated from JSON job input. Current limits are 4 MiB per function
and 250,000 accepted instructions; these are capture limits, not completeness
claims about the rest of the target.

The current image hash is recomputed because legacy byte getters expose mutable
views without a revision event. This is synchronous and must be included in
large-target latency qualification; the small ELF capture result is not proof of
interactive latency on large games. Native lifting/decompilation and command
routing still need to consume this capability without returning to mutable
accessors. This addition alone does not complete the read-only native producer.

## Verification

`npm run test:query` compiles the worker and runs the focused contract suite.
It is also included in the full HQL `npm test` suite. Tests cover matcher parity,
mixed three-state logic, validation, identity rejection, deterministic output,
actual node/loss checks, limits, host heartbeat during blocked regex matching,
external cancellation/timeout and successful work after termination.

Remaining issue #67 gates: UI/headless parity, real IDE corpus jobs, broader
complex-flow qualification, and packaged-worker
deployment verification.

### Bound IR Lane

An ad-hoc structural query may consume `irPath` only through an immutable binding
minted inside the pipeline runner after normal artifact validation. The binding
contains the verified artifact SHA-256, kind/status, producer command, target,
session generation and materialization universe. It is held in a WeakSet and
cannot be reconstructed from JSON job arguments.

The query re-hashes the file immediately before reading and rejects any later
change, target/session/generation/universe drift, non-IR kind or failed producer.
The 3.8.5 contract requires exactly one address to bind the IR's single function
to the active read-only context. Inline `irText` and external unbound files are
rejected. A partial upstream artifact remains partial and requires the pipeline's
normal `allowPartial` opt-in; it cannot become eligible by supplying fields.

Runner cancellation and its step deadline are also minted internally. They are
excluded from configuration hashes and artifact-input discovery. The query uses
an earlier internal deadline to allow the native child to close before the outer
step timeout. Stable query hashes exclude PID and elapsed diagnostics; the output
retains stable exit state while runtime telemetry remains in job status/logs.
