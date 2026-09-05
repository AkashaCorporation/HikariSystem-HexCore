# Known Limitations - HexCore 3.8.4 RC

This document describes the candidate scope, not a published-release acceptance.
It supersedes the historical 3.5.1 checklist. Release gates are tracked in
[RELEASE_3_8_4_RC_CHECKLIST.md](RELEASE_3_8_4_RC_CHECKLIST.md).

## Platform and distribution

- Windows x64 portable is the release target. Linux packaging remains experimental
  and is not enabled by default; macOS is not qualified by this RC.
- Updates remain manual. npm distribution of standalone libraries is a separate
  packaging effort and is not required to use the portable application.
- Addon presence is not loadability. The installer checks expected runtime paths,
  dependencies and native loading before producing a ZIP; functional acceptance
  and testing a clean extraction remain necessary.
- Elixir's execution worker currently seeks a system Node runtime to avoid Electron
  executable-memory restrictions. Its clean-machine prerequisites must be checked;
  loading its addon does not qualify emulation without a suitable worker runtime.
- Package version, native-reported version and addon hash are different identities.
  Preserve the shipped engine manifest and artifact hashes when reporting a bug.
- PDB boundary extraction requires llvm-pdbutil via `HEXCORE_PDBUTIL`, PATH or
  the standard LLVM installation. A custom development SDK path is not bundled
  or silently searched; qualify tool availability separately from addon loading.

## Discovery and lazy bodies

- A discovered function boundary can remain lazy until its body is requested.
  `analyzeAll` JSON retains all entries in the discovered index; this does not prove
  that all functions in the binary were discovered.
- Markdown is an address-ordered first-100 preview. Use JSON for complete index
  enumeration. The Functions tree exposes body state without eagerly decoding it.
- Zero known callers/callees is not proof of no references. Audits over incomplete
  bodies cannot establish absence of a behavior. Coverage/acceptance thresholds
  do not themselves cause body materialization.
- Automatic critical-neighborhood materialization remains future product work.

## Decompilation and evidence

- Helix can retain SCF temporaries, placeholders and unsupported semantics. These
  are not removed merely to make output shorter or confidence higher.
- Default IR decompilation expects the supported Remill-compatible pipeline shape;
  arbitrary LLVM IR is not a blanket compatibility promise.
- Translation confidence, semantic types and behavioral evidence are distinct.
  A high score is not correctness proof; explicit partial/unknown states prevail.
- The refcount scanner is textual review, not CFG/alias/reachability analysis.
  Assertion/warning/termination calls are observations, not vulnerabilities.
- HQL structural coverage and Function Atlas similarity are not vulnerability
  proof. Atlas false-match calibration and signature coverage remain limitations.
- Composer validation does not rewrite original extractor outputs. Retained raw
  IOC candidates may include entries excluded from the composed assertions.

## Persistence and lineage

- Session storage remains one `.hexcore_session.db` per binary directory. Keep
  independent targets in separate directories and preserve WAL-backed state when
  creating consistent copies.
- Refcount cross-job input lineage retains the scanned source hash and the exact
  consumed provenance snapshot. This is not universal cross-run lineage support
  for every command and does not automatically import old facts into a new session.
- Preserve referenced inputs as well as `.hexcore-meta` when exporting evidence.
- Relative `refcountScan.args.input` is process-cwd-relative. Use absolute paths
  or the resolved `$step[N].output` reference.
- `jobStatus` is an inclusive query-time observation. Its own queued job can be
  running; terminal summaries describe post-job state. Inclusion is unknown for
  direct calls without pipeline context.

## Deferred scope

New automatic containment/reachability models, binary-version rebind, digest-named
session migration, product/library string grouping and richer signer/version
metadata are not promised by 3.8.4. The LLVM/MLIR migration and major Helix semantic
quality work are separately qualified post-3.8.4 changes. Heavy corpus latency and
memory behavior still require bounded execution and explicit resource reporting.
