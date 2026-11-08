# Changelog

## 2.1.23 - 2026-11-07

- Pass a retained `Uint8Array` view to the native SAB hook instead of a raw
  `SharedArrayBuffer`, preserving the zero-copy backing store across N-API.
- Report PE32 worker runtime, PID, Node version, native-addon resolution,
  bounded stdout/stderr and exit state without extending the startup timeout.
- Dispose failed worker startups deterministically and reject execution,
  snapshot and breakpoint operations with `HEXCORE_DEBUGGER_NOT_READY` until a
  session reaches the ready lifecycle.

## 2.1.22 - 2026-08-30

- Add deterministic, binary/input/trace-bound runtime semantic observations.
- Preserve runtime evidence as corroboration distinct from static proof.
