# Textual HQL 1.0

Textual HQL is a reviewable frontend for the canonical HQL JSON signature IR.
It is parsed and statically validated, then executed by the existing
`HQLMatcher`. A `.hql` file cannot import modules, execute expressions, define
macros, or call host APIs.

## Versioning

Every file starts with:

```hql
hql 1.0;
```

Grammar version `1.0` and compiler contract `1.0.0` are exported as
`HQL_TEXT_VERSION` and `HQL_TEXT_COMPILER_VERSION`. Unsupported or caller-
requested mismatched versions fail with `HQL1003`.

## Rule Shape

```hql
rule "namespace.rule_id" {
  version "1.0.0";
  namespace "namespace";
  status released;
  author "Author";
  license "MIT";
  provenance {
    kind internal;
    source "Repository rule library";
    modified false;
  }
  compatibility {
    hql ">=0.3.1 <1.0.0";
    helix ">=0.9.4";
    hast 1;
  }
  fixtures "v1/namespace.rule_id.json";
  limitations ["Known limitation."];
  name "Rule name";
  description "Rule description.";
  severity info;
  evidence signal;

  where ast CCallExpr {
    callee == /^(malloc|calloc)$/;
  }
}
```

Atlas-managed `status` rules retain the same required metadata as JSON rules.
`mitre`, `supersedes`, and `limitations` use string arrays. Calibration uses:

```hql
calibration {
  confidence 0.75;
  corpus "corpus-id";
  sha256 "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
}
```

## Conditions

Structural leaves use `ast`; semantic leaves use `fact`:

```hql
ast CCallExpr {
  callee == "malloc";
  operand 0 ast CVarRefExpr { type == "size_t"; };
  contains ast CCastExpr { targetType == "void *"; };
  minDepth 0;
  maxDepth 4;
}

fact summary-ownership {
  ownershipKind == "allocate";
}
```

Conditions compose recursively:

```hql
where all {
  any {
    ast CForStmt {};
    ast CWhileStmt {};
  };
  not ast CUnknownStmt { lossy == true; };
  count min 1 max 3 ast CFieldAccessExpr { arrow == true; };
  fact summary-ownership { ownershipKind == "allocate"; };
  not fact summary-barrier { lossy == true; };
  count exactly 1 fact summary-call { calleeIdentity == /malloc$/; };
}
```

A mixed AST/fact `where all` splits exactly into the canonical structural and
semantic conditions, which the matcher already combines with AND semantics.
Mixed `any`, mixed `not`, and nested mixed boolean expressions are rejected
with `HQL1012`; HQL 0.4.0 has no canonical cross-domain node for them.

Rules may instead use a separate fact-only `semantic` section. Legacy JSON
`queries` round-trip without changing their hash through:

```hql
queries {
  ast CCallExpr { callee == "free"; };
  ast CCallExpr { callee == "refcount_dec_and_test"; };
}
```

## Values

- JSON strings are exact matches; `*` inside a string retains existing glob semantics.
- `/pattern/` is a regex literal and lowers to the canonical `re:pattern` value.
- Regex flags are not supported.
- Integers outside the JavaScript safe range lower to canonical decimal strings.
- Decimal numbers and `true`/`false` are supported.
- Only `==` is a textual comparison operator in v1.

Node kinds, node fields, AST operators, operand positions, semantic fact kinds,
fact fields, regexes, depths, and count bounds are validated against the same
schema used by JSON rules.

## Diagnostics

Compiler errors are `HqlCompileError` values containing typed diagnostics:

```text
rules/timing.hql:8:5
error HQL1007: field 'calleee' does not exist on CCallExpr
8 |     calleee == "VirtualAlloc";
  |     ^^^^^^^
did you mean 'callee'?
```

The source compiler is bounded by byte, token, and nesting-depth limits. It is
fail-fast and never lowers a partially valid rule.

## Public API

```ts
const signature = compileHql(source, { filename: 'rule.hql' });
const result = compileHqlDetailed(source);
const canonicalText = formatHql(source);
const textFromJson = formatHqlSignature(signature);
```

`compileHqlDetailed()` returns canonical JSON and the canonical signature
SHA-256. Formatting is idempotent, and recompiling formatted text must preserve
the signature hash.
