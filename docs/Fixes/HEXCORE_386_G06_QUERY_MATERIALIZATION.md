# HexCore 3.8.6 G06 - Query-Scoped Materialization Acceptance

Date: 2026-11-14

Verdict: **PASS**

Issue authority: `#70 - Query-Scoped Materialization for Lazy Functions`

## Checkpoint

- Product base: `43a203f90d21e68941344365b39a90b4e7716246`
- Implementation: `83716df7137e012afb7b161b5fedbfb103ca20da`
- Disassembler: unreleased `1.4.79`
- HQL: unreleased `0.3.1`
- Qualified Helix node SHA-256: `88aa4912d7f9000398ac8311dceebb2b5d40c57942753c4eb76d41339896fa90`

No native engine changed in this goal. Strict whole-binary materialization,
proximity scanning, unbounded traversal, release, push, publication, and public
issue mutation are outside this checkpoint.

## Public Contract

`hexcore.hql.queryHeadless` now accepts:

- `materialization:"never"`: unchanged default. No body is decoded and missing
  evidence remains unknown.
- `materialization:{mode:"needed",...}`: explicit functions plus direct proven
  dependencies only. Its depth is fixed to one.
- `materialization:{mode:"bounded",...}`: recursive closure over exact direct
  calls/references, resolved candidates, and persisted propagation dependencies.

Both active modes require normalized ceilings for functions, decoded bytes,
wall time, and dependency depth. The defaults are 32 functions, 4 MiB, 30
seconds, and depth one for `needed` or depth three for `bounded`. Hard ceilings
reject oversized policies instead of silently widening the query.

Address proximity, guessed boundaries, unresolved indirect targets, and
arbitrary neighbors are not dependency evidence. A structural query requires
the selected body; a prototype-only query does not decode an unrelated body.

The capability inventory now publishes `never`, `needed`, and `bounded`, with
`never` explicitly identified as the default.

## Transaction And Isolation

1. The parent creates a target-bound, generation-bound, universe-bound plan.
2. A child process receives a hashed gzip snapshot and materializes only the
   planned addresses.
3. The parent validates the returned snapshot hash, target, ranges,
   completeness states, instruction counts, and per-body SHA-256 values.
4. Only complete bodies enter `commitMaterializationBatch`.
5. One SQL transaction persists all bodies, the new universe, one session
   generation, engine binding, invalidation roots, and dirty consumers.
6. Whole-program propagation runs in its isolated worker.
7. The query opens the new pinned semantic view and reevaluates only after the
   propagation closure is committed.

An injected mid-transaction failure restores every metadata, body, dirty-row,
generation, and universe field. Timeout, cancellation, corrupt output, wrong
target, and time exhaustion before commit retain the previous accepted state.
Temporary snapshots are removed on success and on failure.

`partial` and `decode-empty` bodies remain outside the accepted universe and
retryable. A successful exact rerun requests zero unchanged bodies. Reopening
the target in another process restores the accepted generation, universe, body
hash, and closure manifest without recommit.

## Evidence Honesty

The result publishes:

- initial and final generation;
- initial and final universe SHA-256;
- plan SHA-256 and normalized budgets;
- requested, materialized, partial, decode-empty, and failed counts;
- body ranges, instruction counts, states, and hashes;
- native worker outcome, heartbeat phase, and artifact cleanup state;
- propagation closure state and missing recomputations;
- exact unknown reasons and budget exhaustion.

Only functions that received an accepted complete body, current summary, clean
propagation closure, and no unresolved candidate/barrier/conflict can use
absence as negative evidence. The raw x64 fixture deliberately retains its
`raw target ABI not assessed` barrier even after successful materialization and
HAST production. The qualified PE fixture reaches `matched` only after the body
and propagation closure are accepted.

## Real PE Gate

- Corpus ID: `msvc-x64-O2-debug`
- Target: `semantic_benchmark.dll`
- SHA-256: `556ac8cdc265ee058861b42b7b1a02e1b649924b35535edb191ad73444af5775`
- Size: 35,328 bytes
- Export: `bench_plain_copy`

The gate intentionally replaced the selected function body with a lazy stub.
One `needed` query then materialized exactly one function in the child process,
committed one new generation/universe, completed propagation, produced an `ok`
HAST, and re-evaluated `CReturnStmt` as `matched` in about four seconds.

## Negative And Recovery Gates

- Unscoped and wrong-target requests fail closed.
- An unresolved indirect target remains an explicit unknown.
- Function, byte, and depth exhaustion retain the skipped functions and reason.
- Pre-cancelled work never launches a child.
- Active cancellation and watchdog timeout terminate the child and preserve the
  original generation/universe.
- Corrupt snapshots and foreign target snapshots are rejected before commit.
- Partial decode is retried on a later query and never promoted to complete.
- A transaction trigger that aborts after the first staged function proves full
  rollback for a multi-body batch.
- An exact rerun cannot invoke the staging controller for an already-current
  body.
- Cross-process reopen restores the exact body SHA-256 and records one restored
  closure without advancing generation.

## Regression Gates

- Disassembler compile: **PASS**.
- G06 focused Disassembler matrix: **109/109 PASS**.
- HQL full suite: **PASS**.
- HQL matcher smoke: 21/21.
- Text compiler: parity, 12 corpus round-trips, 100 deterministic repeats, and
  256 deterministic mutations.
- Atlas fixtures: 12 rules and 60 cases.
- Benchmark contracts: 24 assertions.
- Ad-hoc query contracts: 24 assertions.
- Function Atlas current-producer regression: PASS.

## Evidence

Evidence root: `E:\HexCore-3.8.6-G06-Acceptance`

- `disassembler-g06-focused.log` SHA-256 `abb0bbfb655754e96f78fb7767b25a2684b9bc50806eae52eb1077622152d1f3`
- `disassembler-compile.log` SHA-256 `8a7ef8e6e44314c9aa38f15069bbce7f1e77d8b5e9ab581be12e0cb4045b56df`
- `hql-full-test.log` SHA-256 `ea4acd7a6172d67aa9cfd149e475b82c9f8b01d194bb732c7e3725c4bb1ed9c2`
- `G06_ACCEPTANCE_MANIFEST.json` SHA-256 `776ed9ad846d9a9cfc1f6c07bbdf70afb8f1d7688b025b784e4fba7a58231322`
- `SHA256SUMS.txt`

## Scope Boundary

This contract answers an explicit HQL query over a bounded, proven dependency
closure. It does not claim that default lazy `analyzeAll` is strict or complete,
and it does not define the separate whole-binary mode planned after 3.8.6.
Standalone IR has no bound target/session universe and therefore rejects active
materialization.

## Exit

G06 satisfies the frozen issue #70 v1 contract and may close the issue. G07
package E2E is the only remaining goal in the bounded HexCore 3.8.6 sequence.
