# Helix 0.9.4-rc.3 Official Reconciliation

Date: 2026-10-30

Status: SOURCE-QUALIFIED / LOCAL-COMMITS-READY

## Base and method

- Official base and RC.2 tag: `585606d0609062ab705f495e733399c747109551`.
- Qualified engine commit: `0a60fb72140a82fcf666bc79c97e29c3d44ca583`.
- Qualified engine tree: `af0baa87475f492366c41ea135555720defa88a8`.
- Local development history was unrelated to the official Git history, so it
  was not merged or force-pushed.
- Forty-one code/build/schema files were copied by the named
  `RELEASE_0_9_4_RC3_SOURCE_ALLOWLIST.txt` onto a clean worktree created from
  official `main`.
- Workflows, generated corpora, logs, private validation outputs, legacy fixture
  deletions and scratch `build.rs.new` were not imported.
- Official Remill 6/7 fixtures were preserved and executed as regression tests;
  they are compatibility checks, not current semantic authority.

## Qualified source gates

### Native C++

- Configure: LLVM/MLIR `18.1.8`, MSVC `19.40`, C++23, Release.
- Build: 112/112 targets.
- Tests: 413 total, 412 PASS, 0 FAIL, 1 optional fresh-producer SKIP.
- `helix_engine.lib` SHA-256:
  `ef7009c945dd00f5afdd610a323266cb7edf3e43f2c3a1455b9df3258de6d425`.
- `helix_tests.exe` SHA-256:
  `72a601805012c0d0778ccb9535fdd7d368b09aed6f7d9d491e5ca22c5ea1ec7e`.

### Rust/N-API

- Offline release build succeeded against the exact library above.
- Workspace tests: 192 PASS, 0 FAIL; two documentation examples ignored.
- Final RC.3 Windows addon SHA-256:
  `e4cf25f9bd3dc99555fad7abbaa89de03b8de4f7f70d6e0e1058009138053231`.
- Addon size: 15,417,856 bytes.

The addon reports `helix-js=0.9.4-rc.3 native=0.9.4-rc.3`. Its local hash is
qualification evidence; the published workflow asset receives its own recorded
hash before HexCore updates the Function Atlas lock.

## Semantic controls

The official-history candidate reproduced the accepted behavior:

- calculator baseline: 50%, with scalar subscript, ordered null-derived access
  and shift-by-width reasons;
- calculator obfuscated: 50%, with invalid pointer/scalar operations;
- issue #30 hidden function: 100%, non-stub, 2,016-byte HAST.

## Dependency bundle contract

The current RC.2 dependency asset is 239,674,248 bytes with SHA-256
`a579068c95ed68ac9bd202ce3b0be51ddc8f5d23cf371775dd66b804caec221d`.
The RC.3 workflow requires a new asset named
`helix-llvm-mlir-deps-win32-x64.zip` containing:

- the unchanged LLVM/MLIR dependency set;
- the final RC.3 `engine/helix_engine.lib`;
- `engine/build-provenance.json` whose `engineSourceTree` equals
  `git rev-parse HEAD:engine`, whose `packageVersion` is `0.9.4-rc.3`, and whose
  `engineLibrarySha256` matches the contained library.

The dependency ZIP must be uploaded before HexCore's native-prebuild workflow,
because that workflow downloads and authenticates this asset before linking the
Windows N-API binary.

## Remaining authorized sequence

1. After separate push authorization, push the branch and merge/fast-forward
   official main without rewriting history.
2. After separate publication authorization, create the prerelease, upload the
   source-bound dependency ZIP, trigger Windows prebuilds and verify the node.

Local allowlisted commits were created. No push, tag, release or asset upload
was performed by this checkpoint.
