# HQL Benchmark Lanes

Upstream repositories are pinned by full commit and ref in `third_party.lock.json`. Windows launchers are pinned by SHA-256 in `runtime.lock.json`. A run fails closed when the ref, commit, clean checkout, executable hash, reported version, input hash, or result identity differs.

Every external process has a 180-second watchdog and produces separate artifacts:

- `*.raw.json` and `*.stderr.txt`: unmodified external output.
- `*.execution.json`: volatile timing, process status, signal, and raw stream hashes.
- `*.status.json`: terminal success/error contract with logical identities only.
- `*.normalized.json` or `*.facts.json`: canonical semantic output.
- `*.failure.json`: typed error detail when a gate fails.

Only fields listed in each lane's `normalization-policy.json` may be removed or logically replaced. Raw output is always retained. Canonical identities include the normalization-policy hash, so changing an exclusion policy invalidates prior identities.

- `capa`: behavioral rule comparison. Rules and capa major versions must match. File/global matches without a function owner are reported as unattributed and never credited to every function. Public malware testfiles are opt-in and never part of ordinary CI.
- `floss`: decoded-string evidence import. FLOSS-only facts remain signals and never become behavior or vulnerability claims.
- `bsim`: Function Atlas similarity comparison. Ghidra database access is serialized and compiler identity is verified before a binary enters the corpus.
- `function-atlas`: real Remill -> Helix -> HAST v1 -> structural-index comparison across all 16 corpus binaries. The runner is fail-closed on incomplete lift, non-MLIR output, non-semantic HAST, adapter loss, engine drift, or a stale BSim corpus.

Atlas benchmark files contain aggregate confusion matrices only. Function names, addresses, binary paths, and raw target evidence stay in ignored per-run directories. `runtimeMs` in an Atlas record is the first measured baseline for a given semantic record identity; reruns retain that baseline while current timing remains in `*.execution.json`.

Run the contract and benign-corpus gates with:

```powershell
npm run benchmark:test
npm run benchmark:capa -- msvc-x64-O2-stripped
npm run benchmark:floss -- msvc-x64-O2-stripped
npm run benchmark:function-atlas
```

The Function Atlas acceptance target is 224/224 functions. The current pinned run intentionally exits non-zero at 104/224: all 112 x86 functions expose the Helix `llvm.add` type-verification family, while eight optimized x64 functions contain one lossy HAST node. These are retained separately in `function-atlas/regressions/`; no successful 16-binary Function Atlas baseline is published until both gates reach zero failures.
