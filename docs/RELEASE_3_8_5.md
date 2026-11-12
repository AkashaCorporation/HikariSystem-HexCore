# HexCore 3.8.5 - Stable Analysis Contract

HexCore 3.8.5 promotes the accepted RC.2 foundation to stable without changing
the qualified native-engine versions.

## Highlights

- Agent Bridge v1 over the trusted workspace queue, including validate,
  submit, status, events, wait, cancel, schema, capabilities and doctor.
- Disassembler 1.4.78 with deterministic PE leaf/CFG ownership, bounded
  large-image discovery and exact-range semantic-versus-padding roles.
- Helix 0.9.4-rc.3 with evidence-gated confidence, HAST output and final-AST
  honesty checks.
- HQL 0.3.1, target-bound semantic queries, Function Atlas and HXDB views.
- Debugger 2.1.23 with retained typed SharedArrayBuffer hooks, diagnosed PE32
  worker startup and fail-closed partial initialization.
- Revenant 0.5.0 with ILSpy 11.1.0.9782 and native-neighbor collision handling.
- Terminable native analysis workers, bounded snapshots, provenance and stale
  Extension Host recovery.
- Honest lazy discovery: indexing, materialization and negative-evidence
  eligibility remain separate dimensions.

## Accepted Windows package gates

The RC.2 package used as the stable source baseline passed:

- all eight native node load checks;
- Agent Bridge doctor/schema/capabilities with zero missing or gated commands;
- Khimera 1.4.78 index, exact-range and session gates;
- Debugger 9-step lifecycle and 7 native SAB tests;
- Revenant and Elixir package smokes;
- HQL/HXDB with one declared typed-caller propagation partial;
- native release-asset code-section parity.

The stable ZIP is rebuilt from the final `v3.8.5` commit and receives a new
manifest and SHA-256. RC hashes must not be reused as stable identities.

## Known boundaries

- Windows 10/11 x64 portable is the qualified distribution. Linux packaging is
  experimental and macOS is not qualified by this release.
- Agent Bridge requires HexCore to be open on the same trusted workspace.
- Helix SCF temporaries, casts, type recovery and unsupported semantics remain
  explicit quality work; stable does not mean perfect pseudo-C.
- Complete authoritative DWARF/BTF/PDB propagation, query-scoped critical
  materialization, AVX-512 coverage and LLVM/MLIR 22 are post-3.8.5 work.
- Large binaries retain bounded partial analysis instead of silently exhausting
  the Extension Host.
- Job JSON is currently expected as UTF-8 without BOM.

See [Known Limitations](KNOWN_LIMITATIONS.md) and the
[3.8.5 Delivery Matrix](HEXCORE_3_8_5_DELIVERY_MATRIX.md) before treating an
analysis result as complete or negative security evidence.
