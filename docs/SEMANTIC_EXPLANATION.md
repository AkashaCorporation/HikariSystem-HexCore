# Semantic Explanation Contract

Status: HexCore 3.8.5 development implementation for issue #69. Source command,
shared UI contract, real-HXDB tests and headless IDE watcher acceptance pass.
Interactive human inspection and packaged acceptance remain pending.

## Purpose

`hexcore.semantic.explain` answers why a persisted semantic entity exists. It
does not generate an explanation with AI and does not infer missing relationships.
The same `explainSemanticEntity` function serves the headless command and the
Semantic Explorer.

Supported entity kinds:

- `prototype`: identity is the persisted `prototypeId`.
- `type-binding`: identity is the persisted `bindingId`.
- `typed-reference`: identity is the active `edgeId`.
- `propagation-effect`: identity is the deterministic effect identity rendered
  by Semantic Explorer.
- `semantic-conflict`: identity is a semantic/reference `conflictHash`.
- `hql-semantic-match`: identity is the `explainIdentity` attached to a bound
  HQL semantic fact.

```json
{
  "cmd": "hexcore.semantic.explain",
  "args": {
    "kind": "type-binding",
    "identity": "binding:sha256:...",
    "expected": {
      "snapshotSha256": "..."
    },
    "maxNodes": 256,
    "maxEdges": 512,
    "maxBytes": 4194304
  },
  "output": { "path": "binding-explanation.json" },
  "allowPartial": true
}
```

The command requires the already active target-bound session. It does not load a
target, materialize a function, update HXDB or run native analysis. Optional
expected target/session/generation/universe/snapshot fields fail closed on drift.

## Result

The JSON result contains:

- the complete pinned query identity and deterministic `explanationSha256`;
- a typed `claim` with its evidence ceiling;
- deduplicated `nodes` and typed `edges` whose source is `persisted-field` or
  `record-origin`;
- compact `evidenceChain` entries projected from those exact nodes;
- conflicts, barriers and explicit missing links;
- function/address navigation targets;
- `truncated` and bounded status.

Status meanings:

- `ok`: the requested record and every relationship represented by this bounded
  contract were available; this is not an exploitability or correctness verdict.
- `partial`: the claim exists, but provenance, a related record, conflict/barrier
  resolution or budget is incomplete.
- `unknown`: the requested entity cannot be distinguished from unavailable data.
- `error`: malformed input or identity mismatch. No explanation was fabricated.

The automation runner classifies `unknown` as semantic partial. A job must set
`allowPartial:true` to retain it; otherwise the step fails rather than appearing
green. The accepted explanation artifact records any `$step[id].result.*`
producer artifact in its provenance DAG.

Debug/definitive evidence may support `proven`; signature/derived evidence is at
most `candidate`; missing/guessed evidence is `signal`. Conflicts remain signals.
An explanation being `ok` does not raise its claim above the recorded evidence.

## Persisted Relationships

Prototype explanations connect the record to its function, return/parameter
types and each evidence producer. Binding explanations add scope, type,
function and invalidation dependencies. Reference explanations retain source
function/address, target, decoder provenance, semantic evidence and dependencies.

Propagation-effect identities hash function, generation, category and exact
effect record. Explanations include the owning summary, persisted dependencies,
reference hashes, conflicts and lossy barriers. A summary/effect without direct
producer evidence is partial; its storage location is not relabeled as producer
provenance.

HQL facts expose identities bound to snapshot, source collection and canonical
record SHA-256. Prototype, binding, reference and conflict matches resolve to the
underlying entity explanation. Current summary-backed HQL facts resolve the
summary but stay partial because the exact match-to-effect relation is not yet
persisted. Structural-only HQL nodes have no persisted semantic record identity.

## Determinism and Limits

Nodes/edges/navigation/missing links are canonically ordered. Incidental engine
generation observations are excluded from the logical hash, while target,
session, semantic generation, universe and snapshot remain bound. Reopening an
unchanged database reproduces the hash.

To reproduce `explanationSha256`, canonicalize the result without that field and
without `identity.engineGeneration`, using recursively sorted object keys and
preserved array order, then hash its UTF-8 JSON with SHA-256.

Default limits are 256 nodes, 512 edges and 4 MiB, with ceilings of 4,096 nodes,
8,192 edges and 16 MiB. Byte budgets below 4 KiB are invalid. A single oversized
claim is replaced by a compact record-hash node and explicit partial status; the
command does not emit an oversized supposedly complete result.

## Semantic Explorer

Explain buttons are available for prototypes, bindings, active typed references,
individual propagation effects and conflicts. The dialog renders the exact JSON
returned by the headless command. Function/address navigation posts the recorded
address back to the existing disassembly navigation command. The UI sends its
current snapshot hash, so a stale row cannot silently explain a newer generation.

HQL result consumers can pass a fact's `explainIdentity` to the same headless
command. A future analysis-results view can use this field without implementing
a second explanation engine.

## Remaining Qualification

- Run the command and Explain actions inside the development IDE with a real
  watcher job and retained HXDB.
- Verify package worker/assets and responsive UI in the built archive.
- Add exact persisted match-to-effect identities for summary-derived HQL facts.
- Expand source-address links to retained HAST/IR/disassembly artifacts only when
  their artifact provenance is stored; do not infer those links from filenames.
