# Named pipeline steps acceptance - issue #68

Date: 2026-09-22

Status: source and development-IDE contract accepted. Public issue/package
closure remains pending until the extracted release candidate is tested.

## Contract

- Step IDs are optional, case-sensitive, unique and validated by one shared
  identity map.
- `$step[id].output` and nested `$step[id].result.field` resolve independently
  of insertion/reordering; numeric and `prev` forms remain compatible.
- Status/provenance distinguish logical step, occurrence and retry attempt.
- A failed latest occurrence cannot resurrect an earlier successful result.
- Replaced/stale artifacts fail hash validation instead of silently rebinding.
- Named goto supports forward and backward routing with bounded execution.
- Jobs without IDs retain the legacy status/provenance shape.

## Acceptance matrix

Focused source validation passes 17/17:

1. insertion/reordering stability;
2. nested result paths and scalar-only interpolation;
3. producer dependency provenance with zero self-loop;
4. invalid/reserved/duplicate/unknown ID rejection before dispatch;
5. forward named goto;
6. unexecuted named-reference rejection;
7. skipped dependency warning;
8. backward goto and occurrence history;
9. retry failure/success attempt history;
10. failed rerun cannot expose prior success;
11. stale replaced output hash rejection;
12. legacy no-ID parity;
13. partial result-field quality inheritance;
14. case-sensitive execution-order-independent lookup;
15. reserved/duplicate grammar negatives;
16. numeric/`prev` and legacy goto compatibility;
17. malformed token rejection.

Development IDE jobs use named steps and named output dependencies in the
accepted calc/Helix/HQL and Poly pipelines. The final Helix runtime job completed
4/4 `ok`; the Poly job completed 3/3 `ok`, both with terminal idle queues.
These runs qualify real watcher/queue dispatch and artifact retention, while the
focused matrix qualifies control-flow/history corner cases deterministically.

## Remaining gate

Run the same named job set from the extracted 3.8.5 release candidate and
verify status/provenance hashes before closing issue #68. No new queue or CLI is
required.
