# HexCore 3.8.5 Release Decision

Date: 2026-10-30

Decision: **FIX-BLOCK / BLOCKED-ENVIRONMENT**

## Frozen Candidate

- Product: `3.8.5-rc.1`
- Source commit: `3d217f81dbcdf706d8ace165e7c25ca0d7c726df`
- Artifact-only workflow: `41130405904`
- ZIP SHA-256:
  `b17517296a641e7dbdd352434b8d21654fbeb474ac9adc4c00cc7baae09dcb27`
- HexCore.exe SHA-256:
  `9237350caa1873098a698f9df74ef674573074386cd4e7029b54c4f44960b65a`
- Engine manifest SHA-256:
  `5f206aa779161a15724979a0379d2c4354e3da76b4e761e6b2ec0edd33cc74ff`

The workflow passed release identity, preflight, manifest/runtime tests,
extension compilation, Code-OSS build, packaged theme/Agent Bridge checks,
engine manifest generation, packaged runtime smoke, ZIP creation and artifact
upload. Release upload and stable publication were disabled.

## Engine Closure

- Helix `0.9.4-rc.3` is an official prerelease. Native, Rust, Clippy, rustfmt,
  Linux NAPI and Windows prebuild gates passed.
- The official Helix Windows prebuild is
  `032b54bca161faa757f35776192490fd278445bfe146e20119601995c6ce6d35`.
- The packaged Helix node is
  `96d62b11cce921a64c9d52ecb087c66b36c0bef9cf845925debbb83477e8f12c`
  because the Windows packager adds `.rsrc`; every common code/data section
  hash remains identical.
- Revenant `0.5.0` with ILSpy `11.1.0.9782` was reconciled and tagged. Windows,
  Linux and macOS x64 assets passed. macOS arm64 remains an external runner
  brownout hold and does not affect the Windows candidate.
- The extracted package loaded all nine active runtimes locally and on CI.

## Internal Evaluation

Verdict: `FIX-BLOCK`.

- E01, E02, E11, E12 and E22: PASS.
- E03, E25 and E26: PARTIAL.
- Remaining rows: HOLD-COVERAGE.
- No product P0/P1 was confirmed before the stop boundary.

The packaged Helix produced deterministic pseudo-C/HAST. Packaged Revenant
decompiled the managed fixture identically with and without a native
`System.dll` neighbor.

Internal report hashes:

- Markdown:
  `9aec496fd2a66b5312644564c82d8474056d924b336c6cba30d40ee6b7125a57`;
- JSON:
  `34a694135594abbf533671939cd9506ef345a26d0730305a7272543fd8eceff7`.

Full reports and checksums are retained outside Git under the frozen closure
root on the coordinator machine.

## Independent Evaluation

Verdict: `BLOCKED / BLOCKED-ENVIRONMENT`.

The evaluator did not read the internal verdict. It independently confirmed
the ZIP, source commit, executable, 22 manifest artifacts and all 14 corpus
fixtures. Restricted Mode returned typed `bridge-unavailable`, created no
report/job and left no discovery. The trusted positive path could not proceed:
workspace trust is intentionally human-only and Computer Use could not connect
to its native pipe.

Independent report hashes:

- Markdown:
  `596cc069b97d90ecbde2ccad0e483bd438ddf933744e2d6cb3085d59d164bc04`;
- JSON:
  `5785321175f81d364c0ff6208f1ccfd941aa1477193169414e1727511faf27cc`.

## Required Retest

Use the exact frozen ZIP and corpus. A human must trust each fresh evaluation
workspace, restart HexCore with the same profile/workspace, and then run Phase
2 onward from the frozen manual. Do not rebuild engines merely to repeat this
environment gate.

No HexCore tag, prerelease, stable release or `latest` publication is
authorized by this decision.
