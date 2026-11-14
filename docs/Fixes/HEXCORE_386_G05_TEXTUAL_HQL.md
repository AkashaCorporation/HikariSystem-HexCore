# HexCore 3.8.6 G05 - Textual HQL 1.0 Acceptance

Date: 2026-11-14

Verdict: **PASS**

Issue authority: `#66 - HQL Text Syntax: Compile Human-Readable .hql Queries to the Canonical HQL IR`

## Checkpoint

- Product base: `c46daf8c33c1c233aa14723feb610a66cddbf02e`
- Implementation: `2b86cbe07896dc953fb4ba1d02dd2e9bf912c48a`
- Grammar version: `1.0`
- Compiler contract: `1.0.0`
- HQL runtime/package remains the unreleased `0.3.1` base until package reconciliation.
- Native engines are unchanged; the Function Atlas regression used the accepted G04 Helix node `88aa4912d7f9000398ac8311dceebb2b5d40c57942753c4eb76d41339896fa90`.

No push, release, issue #70 materialization, dataflow/path syntax, second matcher, arbitrary scripting, or native rebuild is part of this checkpoint.

## Implemented Surface

1. Bounded lexer with UTF-8 byte, token, and nesting-depth ceilings.
2. Typed parser with source spans for rule metadata, AST queries, semantic facts, `all`, `any`, `not`, and `count`.
3. Structural node attributes, positional operands, subtree containment, depth bounds, exact/glob/regex values, booleans, and exact large integers.
4. Typed HXDB fact kinds and fields using the existing canonical schema.
5. Rule version, namespace, status, author, license, provenance, compatibility, fixtures, limitations, supersession, MITRE tags, evidence, and calibration.
6. Exact lowering into `HQLSignature`, `HQLCondition`, and `HQLSemanticCondition`; `HQLMatcher` remains the only matcher.
7. Mixed AST/fact top-level `all` lowers to the existing structural-plus-semantic AND contract. Non-representable mixed `any`, `not`, or nested boolean expressions fail as `HQL1012`.
8. Legacy `queries` has a dedicated textual block and round-trips without changing canonical JSON identity.
9. Stable formatter for source and JSON signatures.
10. `.hql` support in the normal signature loader and HQL Atlas canonical package loader, with duplicate IDs rejected across text and JSON.
11. Public APIs: `compileHql`, `compileHqlDetailed`, `parseHql`, `formatHql`, `formatHqlSignature`, `HqlCompileError`, and explicit version constants.

## Diagnostics And Safety

Every diagnostic carries filename, line, column, code, message, source excerpt,
caret, and a suggestion when one is known. The frozen negative fixtures prove:

| Fixture | Expected code |
|---|---|
| arbitrary script/template syntax | `HQL1002` |
| unsupported grammar version | `HQL1003` |
| unknown node kind | `HQL1006` |
| unknown node field | `HQL1007` |
| invalid AST/comparison operator | `HQL1008` |
| unknown fact kind | `HQL1009` |
| unknown fact field | `HQL1010` |
| malformed regex | `HQL1011` |
| non-representable mixed domain | `HQL1012` |

The frontend contains no `eval`, `Function`, VM, module import, shell, macro, or
plugin execution path. A file either compiles completely or produces a typed
error; no partial query reaches the matcher.

## Parity And Determinism

- Text fixture SHA-256: `56977f9bf8d92e6c651a967436d81c555b7db3dc4a327f6fcc7c254bdd68c23c`
- JSON fixture SHA-256: `d8a91315cc6bddaeecda34edb397d6a54efe892c489bf390620154c3d6c057b3`
- Canonical signature SHA-256: `3ced6385bc1ca868d384f01dae74ccba98fe0890db9926bdda0d5aea6f7a93af`
- Canonical formatted text SHA-256: `3e9946869d6b32c8e36b8cb00f0dc4cb402e9ca7ee7fab21e31071cb53ca6a0e`
- Matcher result SHA-256: `f2d3a4b4d9eb9ed72b375b5d8fe0c00be03365b0480658d82edfb0952a89b0ae`
- Text/JSON canonical parity: PASS.
- Text/JSON matcher result hash parity: PASS.
- Formatted round-trip parity: PASS.
- 100 independent compilation repeats: one unique signature hash.
- 256 deterministic source mutations: only success or typed `HqlCompileError`; no raw parser/runtime exception.
- All 12 packaged JSON signatures format to text and compile byte-semantically back to the original canonical signature.

## Regression Gates

- HQL full suite: PASS.
- Matcher smoke: 21/21.
- Anti-analysis fixtures: 36 assertions.
- Atlas fixtures: 12 rules, 60 cases (20 positive, 40 negative).
- Benchmark contracts: 24 assertions.
- Ad-hoc query contracts: 24 assertions.
- Function Atlas: 38 assertions plus the pinned current-producer regression.
- Atlas build: 12 rules, 60 fixtures, logical SHA-256 `e128fb00d15a18ad91cf3d5dd70fc387eae00405984aec85b55f16b56e895f76`.

## Evidence

Evidence root: `E:\HexCore-3.8.6-G05-Acceptance`

- `hql-full-test.log` SHA-256 `ea4acd7a6172d67aa9cfd149e475b82c9f8b01d194bb732c7e3725c4bb1ed9c2`
- `hql-build-atlas.log` SHA-256 `4bcc0a62732645fd04ff2762d7d3d659c6f62124458ad44c1d48eb8cbbb6dd38`
- `textual-hql-parity.json` SHA-256 `d7123cd349b290230fd88f924749cd5093d4659fc2065f81e2c7b6fe2c4c99de`
- `build-textual-hql-evidence.cjs`

## Exit

G05 satisfies the frozen issue #66 acceptance criteria and may close the issue.
G06 query-scoped materialization is the next queued goal.
