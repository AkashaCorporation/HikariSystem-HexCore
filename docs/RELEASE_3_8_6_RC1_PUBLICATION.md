# HexCore 3.8.6-rc.1 Publication Record

Published: 2026-11-14

Release: https://github.com/AkashaCorporation/HikariSystem-HexCore/releases/tag/v3.8.6-rc.1

## Frozen Identity

- Tag: `v3.8.6-rc.1`
- Commit: `cc9d3eb5a6f91335b7fb785087c4aa6133d9c8a9`
- Windows Actions run: `43627393799`
- Asset: `HexCore-win32-x64.zip`
- Bytes: 432,166,028
- SHA-256: `074b69eab8fd75c94ae4a8cd13edfdf3c99bb451ffeedb39b5f46af42e34f600`
- Release state: prerelease
- Stable/latest promotion: not performed

## Helix Producer

- Release: `v0.9.4-rc.4`
- Source commit: `516f5706b20c169c25dfe57f4dd3ca0bfb2f0092`
- Dependency bundle SHA-256:
  `ce83e2555ac1f69f8f7796461bdce73f1f980daf45e2b843d3a0e80a6ed8db2b`
- Raw Actions node SHA-256:
  `7a82a1a36a1ecf86cb11e7adfe97ff591cf33fe42bacd68cf50fab44d2c06b61`
- Packaged node SHA-256:
  `a4bc81eeda2801dfa737726ec265f83fef86ca40ac9237693f9e6f7abd66e624`

The package adds a deterministic 1,024-byte `.rsrc` section. Every original PE
section remains byte-identical, and both images produce identical pseudo-C and
HAST for the canonical fixture.

## Final Acceptance

- 22/22 manifest artifacts matched size and SHA-256.
- 9/9 active runtimes loaded.
- Packaged Function Atlas producer gate passed.
- Agent Bridge reported 134 capabilities and zero missing commands.
- Query materialization committed exactly one body; repeat requested zero.
- Cross-process restore retained generation/universe and requested zero.
- Debugger lifecycle passed 5/5.
- Final queue had zero queued/running jobs.
- Final cleanup found zero HexCore processes and zero analysis workers.

Run `43618476202` and its ZIP are retained as superseded evidence. That package
exposed a benchmark-only producer-lock mismatch between the raw and
resource-stamped node images. Commit `cc9d3eb5...` fixed the exact allowlist and
run `43627393799` is the qualified publication source.

HexCore `3.8.6-rc.1` remains a prerelease. A stable release requires its own
reconciliation and approval.
