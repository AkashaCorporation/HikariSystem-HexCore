# HexCore HQL

Helix Query Language (HQL) matches versioned semantic rules against the typed C AST exported by Helix. It is a discovery and triage layer: a match is evidence that a structure exists, not proof of maliciousness or a vulnerability.

## Input contract

The 3.8.5 development library also exposes a read-only ad-hoc query executor
over bound HAST/HXDB records. It returns typed rows and explicit
`matched/negative/unknown` evaluations, using a terminable worker for matching.
The Disassembler source registers the pinned binary-session headless command and
a runner-bound single-function IR lane; development watcher acceptance passes and
packaged acceptance remains pending. See
[the ad-hoc query contract](../../docs/HQL_AD_HOC_QUERY.md).

HQL consumes a Helix HAST FlatBuffer. In the IDE this is produced by either:

- a binary function lifted through the HexCore/Remill pipeline; or
- pre-lifted **Remill-compatible LLVM IR** accepted by `hexcore.helix.decompileIR`.

Ordinary LLVM IR is not currently a supported HQL input contract.

### Native quality in HAST 1.1 (development)

Semantic scanning requires a negotiated per-function native quality report.
The reader distinguishes `no-known-loss`, `known-loss`, and `unreported`;
this is separate from adapter coverage and is not a correctness probability.
Known barriers or unavailable reports keep results partial and prevent a clean
negative scan. Legacy HAST 1.0 remains readable for structural inspection, but
does not acquire a quality report merely because hydration succeeded.

Deploy the HAST 1.1 producer and this reader together. Older readers ignore the
appended quality fields. Native quality does not replace target identity,
provenance, upstream coverage, or independent validation of a finding.

Tests retain `canonical-hast-v1.fb` unchanged for legacy structure/identity
checks; semantic tests use separately generated HAST 1.1 fixtures. The pinned
x86 producer regression remains a historical shape check, not acceptance of
current native semantics.

Installed scans read the active target-bound HXDB generation through the
Disassembler's live SemanticStore. Offline consumers may use `SessionDbReader`;
it validates `target_identity` and reports semantic read failures explicitly.

The adapter preserves 64-bit integers and addresses exactly. Unsupported expressions, statements, and assembly are represented explicitly and contribute to per-function adapter coverage; they are never fabricated as integer zero.

### 3.8.5 development: upstream quality

`scanHAST` accepts `options.upstream` with producer `architecture`, `status`,
`semanticEligible`, `qualityIssues` and `warning`. The IDE bridge supplies this
from the decompiler response. A partial/unknown producer, architecture mismatch
or declared quality problem returns `partial` with `hast.semanticEligible:false`
and explicit reasons; signatures are not evaluated on that input. Empty findings
in this state are not a negative result.

The serialized HAST architecture is not relabeled to hide mismatches. Adapter
coverage may still be 1: it measures adaptation, not producer correctness.
Upstream context participates in the cache key. Standalone consumers should
supply available producer context; omitting it cannot establish upstream quality.

Bound HXDB facts may include `explainIdentity`. It binds the exact snapshot,
source collection and persisted record hash consumed by the match. Pass it to
`hexcore.semantic.explain`; do not derive an identity from a rendered label.
Summary-backed matches currently explain the containing summary with partial
status until exact match-to-effect identity is persisted.

Installed live HXDB scans now use a generation-pinned SemanticQueryView. The
bridge validates its target/architecture against the HAST producer and includes
the logical snapshot hash in cache identity and per-result metadata. Failed
semantic reads cannot produce absence-based matches. Offline SessionDbReader
remains a compatibility reader, not an implicit substitute for a pinned view.

## Rule model

Every signature uses either legacy `queries` (implicit `all`) or one recursive `condition`:

```json
{
  "id": "anti-analysis.timer",
  "name": "Timer access",
  "description": "Structural timer signal",
  "severity": "info",
  "evidenceLevel": "signal",
  "condition": {
    "any": [
      { "query": { "target": "CCallExpr", "attributes": [{ "field": "callee", "value": "GetTickCount64" }] } },
      { "query": { "target": "CCallExpr", "attributes": [{ "field": "callee", "value": "QueryPerformanceCounter" }] } }
    ]
  }
}
```

Supported combinators:

- `all`: every child condition must match;
- `any`: at least one child condition must match;
- `not`: the child condition must not match;
- `count`: applies `min`, `max`, or `exactly` to one query;
- `query`: matches a typed AST node recursively.

The loader validates every node kind, field, operator, operand index, bound, regex, and combinator recursively. One invalid signature rejects the library instead of becoming a silent dead branch.

## Evidence contract

- `structuralCompleteness` reports whether the declared rule expression was satisfied. It is not probabilistic confidence.
- `evidenceLevel` is `signal`, `candidate`, or `proven`; adapter loss can only downgrade it.
- `confidence` is absent unless a signature includes a corpus-backed calibration record.
- `severity` is presentation priority for a signature. It must not be mapped to vulnerability severity.

Every scanned function is returned, including clean negatives, with its name, exact address, AST node count, adapter coverage, unsupported node counts, active signature-set SHA-256, and findings.

## Development

```powershell
npm install
npm run build
npm test
```

The tests cover matcher primitives, recursive combinators, fail-closed schema validation, all 12 anti-analysis alternative branches with positive and negative fixtures, exact 64-bit hydration, adapter-loss downgrades, clean-scan identity, and deterministic signature-set hashing.

## Atlas and benchmarks

The versioned rule and fixture architecture is specified in [docs/HQL_ATLAS_V1.md](docs/HQL_ATLAS_V1.md). Mandiant capa remains the behavioral-rule benchmark. Function Atlas and Ghidra BSim are measured in a separate function-similarity lane. FLOSS may supply provenance-carrying string facts, but decoded strings do not become behavior or vulnerability claims by themselves.
