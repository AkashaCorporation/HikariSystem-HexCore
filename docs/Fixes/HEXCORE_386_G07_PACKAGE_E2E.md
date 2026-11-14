# HexCore 3.8.6 G07 - Package E2E and Release Decision

Date: 2026-11-14

Decision: **GO-RC**

Publication status: **NOT AUTHORIZED / NOT PERFORMED**

`GO-RC` means the accepted source and derived Windows preflight are eligible to
enter the official engine/prebuild/product build sequence. It does not mean a
tag, GitHub release, push, stable promotion, or `latest` publication exists.

## Frozen Source

- Product branch: `release/3.8.6-rc1-e2e`
- Product commit: `7b2cfc943c293bcc8a47855560ce8ba95f8dfae4`
- Helix branch: `release/0.9.4-rc.4-e2e`
- Helix commit: `516f5706b20c169c25dfe57f4dd3ca0bfb2f0092`
- Product lineage: released `v3.8.5` followed sequentially by accepted G01-G06.
- Excluded lineage: the unrelated local Helix C2 research branch was not merged.

Candidate versions:

| Component | Version |
|---|---|
| HexCore | `3.8.6-rc.1` |
| Debugger | `2.1.24` |
| Disassembler | `1.4.79` |
| HQL | `0.4.0` |
| Helix | `0.9.4-rc.4` |
| Revenant | unchanged `0.5.0` / ILSpy `11.1.0.9782` |
| Elixir | unchanged `1.0.4` |
| Report Composer | unchanged `1.0.14` |

## Helix RC4

G03 and G04 changed native Helix source after the public RC3 producer. Shipping
that node as `0.9.4-rc.3` would have made package identity false. G07 therefore
created a new, unpublished RC4 candidate and rebuilt it explicitly with Visual
Studio 2022 `19.40` and LLVM/MLIR `18.1.8`.

- C++: 419/419 PASS; one external fresh-fixture test skipped as declared.
- Rust: 192/192 PASS; two documentation examples ignored.
- N-API: `helix-js=0.9.4-rc.4 native=0.9.4-rc.4`.
- Deterministic pseudo-C and HAST smoke: PASS.
- Node size: 15,420,928 bytes.
- Node SHA-256: `cf851aa09f9f639847b649a36ec9859e24b7586ba2c8b9f8ea20abb8e3d63fd8`.

No other native engine changed. The package reuses the already qualified 3.8.5
Capstone, Unicorn, LLVM MC, SQLite, Remill, Souper, Elixir, and Revenant assets.

## Component Gates

- Debugger `2.1.24`: 119/119 PASS.
- Disassembler `1.4.79`: 128/128 focused release tests PASS, covering G02,
  G04, G06, HXDB generation, rollback, propagation, and pipeline reliability.
- HQL `0.4.0`: full suite PASS, including 21 matcher checks, 36 anti-analysis
  fixtures, 60 Atlas cases, 24 benchmark contracts, 24 ad-hoc checks, textual
  parity, 100 deterministic compiles, and 256 deterministic mutations.
- Function Atlas accepted the RC4 producer hash and retained its honest
  `known-loss` barrier.

## Derived Windows Candidate

The workbench core did not change in G01-G06. To avoid a local full Code OSS
build with known OOM risk, G07 constructed a reproducible derived preflight from
the exact official 3.8.5 ZIP, then overlaid only the changed compiled extensions,
metadata, and RC4 node. The normal manifest/runtime scripts were used.

- Stable baseline ZIP SHA-256:
  `2cde56666350218fd14b2f9a5026ab074d7dfb42b52a1312d8a5e1b170572de7`
- Final derived ZIP: `HexCore-3.8.6-rc.1-derived-v2-win32-x64.zip`
- Size: 427,319,908 bytes.
- SHA-256: `d0842d96c058a7d6fcd40b7a6ffe9d27fcf2c51066fef91db1c49a10c0b057af`.
- Product identity: `3.8.6-rc.1` at exact commit `7b2cfc9...`.
- Manifest: 22 native artifacts, 0 size/hash mismatches.
- Runtime smoke: 9/9 active engines loaded.
- Revenant version probe: backend `0.5.0`, ILSpy `11.1.0.9782`.
- Fresh extraction: `E:\HexCore-3.8.6-G07-Fresh-Extract-v2`.

The first derived ZIP is retained as superseded evidence, SHA-256
`23621c4a3f8fd98235d320f7166a8c168c9cc7e06e2e9823e654960ac2a5e991`.
Its runtime was correct, but packaged HQL `src/test/docs/benchmarks` still came
from the 3.8.5 baseline. V2 updated the complete HQL tree and then repeated
fresh extraction, artifact hashing, runtime loading, and Agent Bridge startup.

## Agent Bridge E2E

The packaged CLI connected to a fresh hidden IDE instance with a new profile:

- protocol v1;
- 134 pipeline capabilities;
- zero missing commands;
- every submitted job reached terminal queue state;
- final queue: zero queued and zero running;
- final cleanup: zero candidate IDE processes and zero analysis workers.

Jobs and verdicts:

| Lane | Result |
|---|---|
| Static PE smoke | expected `partial`; 107/171 bodies materialized, 64 lazy |
| G06 query materialization | one body committed; generation 0 -> 1; HAST matched |
| Exact repeat | zero requested bodies; same generation and universe |
| Cross-process fresh-v2 restore | zero requested bodies; generation 1; same universe |
| Debugger lifecycle | 6/6 ok: load, step, snapshot, step, restore, dispose |
| Revenant | 2/2 ok: C# and IL |
| Elixir | 3/3 ok: native, snapshot, execution |
| Khimera | 3/3 ok: index, exact range, session export |
| Runbook | ok; 678 functions, zero overlaps, recovered main/direct target/dispatcher |
| NUCLEO | expected `partial`; 1,155 functions, zero overlaps, 981 lazy bodies |
| Kbase DWARF | expected `partial`; 792 records, 1,817 ingested types, 1,800 exact prototypes, 2,064 deferred |
| Filesystem negative control | expected `partial`; zero proofs/signals, reparse `not-assessed`, Composer ok |

The first cross-process attempt shared one input directory with several targets,
so the documented one-session-database-per-directory policy archived the earlier
session. That run was not counted as a closure failure. The accepted control used
an isolated target directory; after a real IDE restart it restored the exact
generation/universe and requested zero bodies.

## Honest Holds

1. This is a local derived preflight, not a GitHub Actions artifact from a
   pushed tag/commit.
2. Helix RC4 has not been tagged, released, or uploaded; the product workflow
   therefore cannot yet consume an official RC4 asset.
3. The historical Backblaze corpus was not present. The filesystem lane used a
   controlled negative PE and correctly retained zero proofs/signals plus
   `reparse-safety:not-assessed`.
4. Per-job provenance still records `analysisSession.engines:[]`. The package
   engine manifest is complete and hash-bound, but this diagnostic P2 remains.
5. Strict whole-binary materialization remains a separate post-3.8.6 contract.

None of these holds is represented as a completed feature or a stable release.

## Evidence

Evidence root: `E:\HexCore-3.8.6-G07-Acceptance`

- `G07_ACCEPTANCE_MANIFEST.json`
- `SHA256SUMS.txt`
- `fresh-v2-manifest-verification.json`
- `fresh-v2-runtime-smoke.json`
- `fresh-v2-agent-doctor.json`
- `fresh-v2-agent-closure.json`
- `fresh-v2-closure-summary.json`
- `fresh-v2-process-cleanup.json`
- component logs and retained Agent Bridge job outputs under
  `E:\HexCore-3.8.6-G07-Workspace\reports`.

## Decision

G01-G07 are complete at the source and derived-preflight level. The bounded
3.8.6 implementation sequence has **zero remaining goals**.

The next action, only after explicit authorization, is operational rather than
another implementation goal: publish/build the exact Helix RC4 artifact, run
native prebuilds, produce the official HexCore RC1 ZIP from `7b2cfc9...`, and
repeat the short fresh-ZIP identity/runtime/Agent Bridge gate before any release
is created. Stable/latest remains a separate later decision.
