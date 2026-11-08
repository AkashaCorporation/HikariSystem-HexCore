# HexCore 3.8.5 Packaged Debugger Fix Qualification

Date: 2026-11-07

Verdict: **GO-RC for the fix block**. This is not authorization to publish,
tag, push, or promote `latest`.

## Frozen Inputs

- Source base: `38aa859e86698e446bb4086262019b0b86c9dfff`
- Worktree branch: `fix/debugger-sab-pe32`
- Base package ZIP SHA-256:
  `b17517296a641e7dbdd352434b8d21654fbeb474ac9adc4c00cc7baae09dcb27`
- Candidate overlay payload SHA-256:
  `292e7b565b3979854b5f6d056b38ee1540df1a150f14125c411ad2de80ac07b1`
- Candidate versions: Debugger `2.1.23`, Disassembler `1.4.75`
- Overlay: 12 files, each verified after application
- Original packaged files were retained in a local rollback checkpoint and were
  not added to the repository.

## Fixed Causes

1. The SAB hook now receives a retained `Uint8Array` over the
   `SharedArrayBuffer`. The real addon rejects the raw SAB and accepts the typed
   view.
2. PE32 bootstrap records runtime kind, executable, Node version, PID, worker
   path, native addon path, bounded stdout/stderr, exit code and signal. The
   15-second deadline was not increased.
3. Node selection prefers a version-probed standard installation. This avoids
   selecting an NVM runtime that could be spawned by packaged Electron but did
   not reach worker IPC readiness.
4. Startup is now a lifecycle transaction. A loader/worker failure releases all
   resources, sets `failed`, and makes step, snapshot, breakpoint and continue
   return `HEXCORE_DEBUGGER_NOT_READY` instead of touching partial native state.
5. Pipeline status and provenance record the owning Extension Host instance.
   A restarted host archives and terminalizes both stale records immediately.

## Source Gates

- Debugger TypeScript compile: PASS
- Disassembler TypeScript compile: PASS
- Debugger tests: **115 passing**
- Auto-run stale recovery: **5 passing**
- Pipeline reliability: **28 passing**
- Native SAB tests: **7 passing**
- Plain-Node real-addon wrapper smoke: 3 instructions, no error
- Plain-Node PE64 worker smoke: start, snapshot, step, restore and dispose PASS
- Forced missing-worker smoke: typed startup/step failure, null state, inactive
  session and no residual worker

## Packaged Gates

### Internal Nominal Final

- Job revision:
  `cf5bce1e0dd7e5f451ab478f9d29b768698480e18f00939f038d0102b32e0a38`
- Result: **9 ok / 0 partial / 0 error / 0 skipped**
- `emulateHeadless`: 626 ms
- Queue terminal snapshot: `queued=0`, `running=0`
- Worker runtime: version-probed `C:\Program Files\nodejs\node.exe`
- Worker residual after dispose: 0

### Packaged Negative

The packaged worker script was temporarily moved and restored in `finally`.

- Job revision:
  `dfc6fe34a54f2a7c623fd45e7635f522e944820dd35dff297b7610fac8b2acd4`
- Result: expected `partial`
- Startup, step, snapshot, breakpoint and continue: typed not-ready errors
- Dispose: `ok`
- Extension Host remained alive
- Queue terminal snapshot: `queued=0`, `running=0`
- Worker residual: 0
- Restored worker SHA-256:
  `1180fb0af8ed885c9e38f7c32961ef1cb9936afc232a67fb6678c13ba4918536`

### Restart Recovery

- Prior host instance:
  `95019e75-354d-4614-b7ec-1af29ce82f55`
- New host instance:
  `cb79ebde-9843-4ad1-899d-aa276a5d3618`
- Old status and provenance were archived separately with their original
  `running` evidence.
- The log recorded terminal recovery before rerun.
- The unchanged job SHA-256 was preserved.
- Rerun result: `ok`, 1/1 step, queue `0/0`.

### Isolated Repeat

- Separate trusted workspace and user-data profile
- Fixture SHA-256:
  `57f937635a1cce3fe2cf14a7d4f22cee1da80c6ab6fc339eb6db14e0ca33c3f9`
- Job revision:
  `e92f7796fbbad329e4312c8fdf0cd489a418282a75e4d347e3886e113d8811b0`
- Result: **9 ok / 0 partial / 0 error / 0 skipped**
- `emulateHeadless`: 490 ms
- Queue terminal snapshot: `queued=0`, `running=0`
- Worker residual after dispose: 0

## Release Boundary

The conditional packaged P1 is closed. The next release action is to commit the
reviewed source, build a fresh official artifact from that commit, and repeat
the same nominal and negative gates against the produced ZIP. The overlay is
qualification evidence, not a distributable replacement for the CI artifact.

The PE worker still requires a usable external Node executable because the
Electron fallback retains the pre-existing ACG/CFG limitation. The selector now
fails closed and explains the chosen runtime; bundling a dedicated worker
runtime is separate packaging work, not part of this fix block.
