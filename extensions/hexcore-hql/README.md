# HexCore HQL

Helix Query Language (HQL) matches versioned semantic rules against the typed C AST exported by Helix. It is a discovery and triage layer: a match is evidence that a structure exists, not proof of maliciousness or a vulnerability.

## Input contract

HQL consumes a Helix HAST FlatBuffer. In the IDE this is produced by either:

- a binary function lifted through the HexCore/Remill pipeline; or
- pre-lifted **Remill-compatible LLVM IR** accepted by `hexcore.helix.decompileIR`.

Ordinary LLVM IR is not currently a supported HQL input contract.

Installed scans read the active target-bound HXDB generation through the
Disassembler's live SemanticStore. Offline consumers may use `SessionDbReader`;
it validates `target_identity` and reports semantic read failures explicitly.

The adapter preserves 64-bit integers and addresses exactly. Unsupported expressions, statements, and assembly are represented explicitly and contribute to per-function adapter coverage; they are never fabricated as integer zero.

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
