# Hogwarts `analyzeAll` P1 Qualification

Date: 2026-11-07

Verdict: **PASS-WITH-BOUNDED-COVERAGE** for Disassembler `1.4.76`.

## Target

- Path: retained local fixture (not distributed)
- Size: 458,466,816 bytes
- SHA-256: `9cab3d4214ec292bc7829cb662d25eb8817b9ffc14e33bbb360913f4273b1213`
- Executable section bytes: 406,089,216
- Largest executable section: `.trace`, 295,285,760 raw bytes

## Before

Disassembler `1.4.70` ran in the isolated child for 1,501,407 ms and died with
exit code 134 during `discover-padding-leaves`.

- V8 heap near failure: approximately 3.9 GB
- Result: `error`
- Snapshot: none
- Extension Host: survived

## Causes

1. Per-job limits were applied only after `loadFile`, so entry/export discovery
   still used the default 5,000-function budget.
2. Large-image load recursively retained eager bodies and scanned strings across
   the complete 458 MB image.
3. Padding-leaf discovery used the 500,000 authoritative-stub ceiling instead of
   a heuristic budget.
4. Every padding candidate performed linear `.pdata` searches plus
   `map/filter/reduce` allocations and populated the global instruction cache.
5. Heartbeats did not expose worker memory, hiding the earlier load-time growth.

## Fix

- Apply requested limits before entry/export discovery.
- Disable recursive eager traversal during large-image load.
- Release heuristic prolog bodies as exact lazy boundaries on images with at
  least 64 MiB of executable bytes.
- Merge and sort `.pdata` ranges once, then use binary search.
- Decode padding candidates without populating the global instruction cache.
- Persist accepted padding leaves as lazy stubs.
- Enforce deterministic function, candidate and decoded-byte budgets.
- Limit large-image Disassembler string extraction to readable,
  non-executable sections and report the missing coverage.
- Persist discovery/string diagnostics through the isolated snapshot.
- Include RSS, heap, external memory and peak heap in worker heartbeats.

## Source Probe

Default limits (`maxFunctions=5000`) completed in 114,954 ms.

- Outcome: `completed`
- Peak heap: 1,613,638,560 bytes
- Snapshot: 20,975,771 bytes compressed / 168,970,398 bytes raw
- Functions: 303,644
- Lazy bodies: 302,678
- Padding candidates examined: 5,000
- Padding leaves accepted: 1,518
- Status: partial (`candidate-limit`)
- String coverage: 52,376,064 / 458,466,816 bytes

## Agent Bridge Probe

The Dev extension was rebuilt in place as `1.4.76` and executed through Agent
Bridge using job revision
`e0ac8ad18b1f94678b701e71d8caf1358765c243e3ff2ce78790806d0b3a7db0`.

- Native execution: 92,686 ms
- Pipeline step: 113,980 ms
- Peak heap: 1,100,837,400 bytes
- Result: `partial`, not `error`
- Warning: padding candidate limit and bounded string coverage
- Queue: `queued=0`, `running=0`
- Residual worker: none
- Provenance owner: `hikarisystem.hexcore-disassembler` `1.4.76`

A subsequent 2 KiB PE smoke proved that `discoveryDiagnostics` and `stringScan`
are present in the written JSON, not only used internally to derive status.

## Regression Gates

- Dev Disassembler focused gates: 84 passing
- Dev Debugger: 115 passing
- Canonical worktree: compile clean; padding 4, process isolation 9, pipeline 28
- Real target: source and Agent Bridge paths both completed

## P2 Follow-up

The oversized primary JSON and duplicate snapshot cloning were addressed on
2026-11-08. The primary output is now a 10,000-entry preview with a complete
streamed NDJSON index, and trusted isolated snapshots are adopted rather than
cloned. See `HOGWARTS_ANALYZEALL_P2_20261108.md`. Retaining the 458 MB image and
303,000 boundary objects still costs approximately 1.24 GB RSS and requires a
future paged/on-disk model to reduce further.

No commit, push, tag or release was performed.
