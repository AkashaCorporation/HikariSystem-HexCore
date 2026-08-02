# Changelog

## [0.5.1] - 2026-07-30

- Upgrade the embedded engine to upstream Remill 6.0.1 at commit
  `0e324aee8c67a63ec759ef379dcfafa0b3cb1448`, built against LLVM 18.1.8
  with static `/MT` runtime and `LLVM_ENABLE_ABI_BREAKING_CHECKS=0`.
- Lift `POPCNT`, `PEXT`, `PDEP`, `BZHI`, `BEXTR`, `SHLX`, and `CRC32` with
  real semantics instead of the previous `HandleUnsupported` fallback.
- Export separate wrapper and upstream provenance through `version`,
  `upstreamVersion`, and `upstreamCommit`.
- Reject unpackaged SPARC64 before Remill initialization. `ARCH.SPARC64`
  remains exported for compatibility, but no longer permits a native
  `CHECK` failure to terminate the Node.js host.
- Package the Sleigh public/generated headers required by Remill 6.0.1 and
  record dependency provenance in `deps/manifest.json`. Runtime packaging now
  explicitly includes `deps/remill/share`, preventing prebuild-only installs
  from omitting the required semantics bitcode.
- Standalone synchronization restores its release-specific install contract
  and uses `node-gyp` 12.4 instead of the vulnerable 10.x build-tool chain.
  Source builds therefore require Node 20.17+ or 22.9+; the N-API v8 prebuild
  retains the package's existing runtime compatibility contract.
- Standalone sync preserves its independently generated lockfile and excludes
  extracted dependency payloads, release archives, debug dumps, Python cache,
  backup prebuilds, and local POCs from accidental staging.
- Preserve FIX-120 control-flow termination for x86 `ud2`.

Validation: native smoke suite 23/23; all linked static libraries `/MT`;
three fresh NUCLEO x64 functions retained byte-identical Helix C and confidence;
three fresh AArch64 functions retained byte-identical IR/C and deterministic
2/2 output. A fresh ET_REL Mali `kbase_jit_allocate` A/B at its authoritative
2,137-byte extent changed IR by only -5 bytes and retained byte-identical
472-line C at 73.5% confidence.
