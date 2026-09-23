# HexCore 3.8.5-rc.1 Release Reconciliation

Date: 22 September 2026

## Source Boundary

The release worktree starts from public HexCore 3.8.4 commit
`148e0870267ef6275aa27edf201924d82c38c76c`.

Production changes were copied from the development worktree through an
explicit allowlist. The input manifest is retained outside the repository at
`E:\HexCore-3.8.5-Checks\hexcore-385-rc1-migration-manifest.json`
(SHA-256
`96AB1DAB5966EBB6AC6501CBF1B1B8A7FC637C309B0B71B4D0776F9958CEFF64`).

Excluded from the release boundary:

- HXDB/session databases and temporary workspaces
- compiled extension output and local native prebuilds
- benchmark run/work directories and proprietary corpus binaries
- debugger repro scratch, local agent state, and experimental plugins
- private reports and local test-output directories

## Version and Native Identity

- HexCore product: `3.8.5-rc.1`.
- Helix wrapper/native candidate: `0.9.4-rc.2`.
- Canonical Helix candidate commit:
  `89a4a392d0ce511a694a937240a3045779b0fe41`.
- Windows x64 Helix addon SHA-256:
  `D7023EC230C1ADE03E5E28ECBD3F997B89190F9BE6E8301ACD2EDE6C8B2733AB`.
- Version-matched LLVM/MLIR dependency bundle SHA-256:
  `A579068C95ED68AC9BD202CE3B0BE51DDC8F5D23CF371775DD66B804CAEC221D`.

The prebuild workflow verifies package version, engine source tree and static
library hash, uses a cache key derived from the dependency-bundle hash, and
passes the exact library directory through `HELIX_ENGINE_LIB_DIR`.

## Local Acceptance

- Seven changed extensions compile from the reconciled worktree.
- Disassembler: 45/45 changed or new test files pass in isolated Mocha
  processes. The real AnalyzeAll process test passes 7/7 with its required
  120-second harness timeout.
- Named pipeline steps: 13/13.
- Pipeline reliability: 27/27.
- SemanticQueryView: 13/13, including fail-closed producer identity.
- HQL/Atlas full package suite passes, including 24 benchmark contracts and 24
  ad-hoc query checks.
- Function Atlas current-producer regression retains adapter coverage 1.0 and
  the explicit `known-loss/damning-defect` quality barrier.
- Elixir DRCOV path contract: 3/3.
- Strings transform-chain accounting: 3/3.
- IOC validation: 1/1.
- PE coverage: 3/3.
- YARA focused suite: 19/19 plus regex safety 7/7.
- Release identity, engine-manifest tests and both workflow YAML files pass.

The first aggregate Disassembler invocation was intentionally retained as
negative harness evidence: it used the wrong Mocha UI, then mixed incompatible
global VS Code mocks in one process. Isolated test execution removed that
cross-test contamination. A 30-second external timeout also interrupted one
real AnalyzeAll persistence test; its isolated 120-second rerun completed 7/7.

## Remaining Gates

No branch, tag, dependency asset, or release has been published by this
reconciliation. Remaining work:

1. Review and push the canonical Helix and HexCore release branches.
2. Create the Helix RC.2 prerelease and upload the dependency bundle.
3. Run Helix and HexCore GitHub Actions against the published commits/assets.
4. Download the generated HexCore archive and test that extracted package.
5. Promote stable versions only after extracted-package acceptance.
