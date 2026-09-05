# Helix + HQL Integration Contract

Status: HQL 0.2 / Helix 0.9.3 development line, 2026-08-28.

This file replaces the obsolete 2026-04-01 snapshot note. That snapshot said the HAST serializer, bridge, adapter, and end-to-end path did not exist; those statements are no longer true.

## Current path

1. HexCore lifts a selected binary function to Remill-compatible LLVM IR.
2. Helix runs its MLIR pipeline and emits pseudo-C plus a HAST FlatBuffer.
3. The Disassembler exposes `astBuffer` from the quiet/headless decompile result.
4. HQL validates the HAST file identifier and FlatBuffer table/vector bounds.
5. The HQL adapter hydrates typed `CNode` values while retaining exact 64-bit integers, addresses, unsupported nodes, assembly, and per-function loss coverage.
6. The matcher evaluates the canonical versioned rule library.
7. The headless result preserves every hydrated function, including clean controls, with address, node count, adapter coverage, budget outcome, signature-set hash, cache key, and evidence-level findings.
8. Report Composer renders HQL as structural evidence rather than vulnerability confidence.

The `irPath`/`irText` route accepts Remill-compatible IR. Arbitrary ordinary LLVM IR is not part of the current contract.

## Current boundary

HAST schema v1 carries syntax trees but does not yet carry stable node/value/storage identities, basic-block ownership, dominance, SSA lineage, memory-object identity, or typed HXDB fact references. Therefore HQL 0.2 can express recursive structural `all`, `any`, `not`, and `count` rules, but it cannot honestly prove ordering, same-object dataflow, mutation barriers, dominance, or interprocedural identity from HAST alone.

Absence-sensitive rules over lossy HAST are downgraded. Unsupported or malformed functions remain explicit `partial` records and are never silently removed.

## Sources of truth

- HAST transport schema: `HexCore-Helix-v2/schemas/ast.fbs`.
- HAST serializer: `HexCore-Helix-v2/engine/src/emit/FlatBufSerializer.cpp`.
- HQL adapter: `src/adapter/flatbuf.ts`.
- HQL matcher and rule schema: `src/engine/matcher.ts`, `src/signatures/schema.ts`.
- Canonical rule files: `signatures/**/*.hql.json`.
- Atlas contract: `docs/HQL_ATLAS_V1.md`.

Runtime artifacts and contract fixtures, not source presence, are the acceptance evidence.
