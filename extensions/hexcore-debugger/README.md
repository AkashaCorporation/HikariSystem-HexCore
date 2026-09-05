# HexCore Debugger

Emulation-based debugger for PE/ELF binary analysis, part of the **HikariSystem HexCore**
binary analysis IDE. Drives the [Unicorn Engine](https://www.unicorn-engine.org/) (via
`hexcore-unicorn`) to single-step, set breakpoints, inspect registers/memory, and run
headless emulation traces.

## 2.1.22 highlights

- Emit typed runtime-observation envelopes for API arguments/returns, resolved
  module symbols, and memory reads/writes.
- Bind every envelope to the exact binary SHA-256, input configuration, and
  trace configuration; timestamps do not affect normalized identity.
- Keep runtime observations at `runtime-corroboration` so they cannot silently
  replace static HXDB proof.

## 2.1.21 highlights

- Apply signature-backed Win32 `stdcall` cleanup in the PE worker and retain
  calling convention, popped argument bytes, signature source, and hook
  semantic level in API traces.
- Implement stateful BCrypt SHA-256 and AES-CBC handles and side effects.
  Unsupported algorithms return typed NTSTATUS failures instead of false
  `STATUS_SUCCESS`.
- Handle `BCryptDecrypt` output-size probes without prematurely validating
  PKCS#7 padding.
- Synchronize likely register and stack argument buffers from PE32/PE64 workers
  into the host mirror before synchronous WinAPI hooks inspect them.

## 2.1.20 highlights

- `getStateHeadless` now reports Unicorn's authoritative mapped image, stack,
  heap, and auxiliary regions. Memory-manager allocations enrich exact regions
  with names instead of replacing the real map and hiding raw code mappings.

## 2.1.19 highlights

- Treats a configured return sentinel as a successful terminal condition even
  when Unicorn reports the expected unmapped instruction fetch at that address.
  The raw observation remains available as `expectedTerminalFault`.
- `continueHeadless` accepts `terminalAddresses` and `terminalKind` for custom
  harness sentinels, and clears the consumed fault before the next operation.
- Reports PE32+ x86-64 worker execution as `worker-pe64`; `worker-pe32` is now
  reserved for actual 32-bit PE sessions.

## 2.1.18 highlights

- Program-counter writes through `setRegisterHeadless` now update both the live
  Unicorn register and the logical session address consumed by continue/step.
  Direct-entry x64, x86, and ARM64 workflows no longer restart from the loader's
  original entry point after writing `rip`, `eip`, or `pc`.
- The same synchronization is applied after worker writes and after deferred
  in-process register mutations are committed.

## 2.1.17 highlights

- Initializes PE32 protected-mode segmentation with a real GDT: flat code and
  data/stack descriptors plus an `FS` descriptor backed by the synthetic TEB.
  CRT and SEH accesses such as `push dword ptr fs:[0]` now work in the worker.
- Implements ABI-correct `memset`, `memcpy`, `memmove`, and `memcmp` hooks for
  VCRuntime, MSVCRT, UCRT, and API-set imports. Memory operations are bounded,
  copy semantics are preserved, and pointer-returning functions return their
  destination on x86 and x64.
- Requires the `hexcore-unicorn` 1.3.2 `regWriteMmr()` API so descriptor-table
  registers are written using Unicorn's native `uc_x86_mmr` layout.

## 2.1.16 highlights

- Classifies Unicorn `UC_ERR_INSN_INVALID` as `unsupported-instruction`
  instead of a generic fault.
- Captures the live instruction address, mnemonic, operands, and bytes after an
  unsupported stop and infers an AVX-512 requirement from mask/ZMM operands.
- Declares backend support and fallback availability explicitly. The current
  Unicorn path reports `supported:false` and `fallbackAvailable:false`; it does
  not claim successful execution when no AVX-512 interpreter is registered.

## 2.1.15 highlights

- Binds live-memory IR to the original emulation target before handing it to
  Helix, preventing evidence from a different Disassembler target from
  changing confidence or post-processing.
- Runs live-memory Helix decompilation in an isolated OS process whose remaining
  budget accounts for memory read and Remill lift time, then settles before the
  pipeline deadline so the queue and keep-alive session can be released. A
  timeout kills only that process, never the Extension Host executing the job.
- Returns the Helix analysis-context ownership decision with live-memory
  results for direct audit in retained automation artifacts.
- Supports `retainIr:true` for crash/timeout evidence, writing the exact lifted
  IR before Helix starts and returning its byte count and SHA-256 on failures.

## 2.1.14 highlights

- Continue, full-run, and state artifacts now share the same bounded,
  grouped/sampled API trace representation and exact counters.
- Large emulation artifacts include a compact execution summary with instruction,
  trace-retention, memory-region, current-address, and stdout-size metrics.

## 2.1.13 highlights

- Accepts deterministic `prngMode`/`prngSeed` automation input and reports the
  effective configuration in headless results.
- Groups consecutive repeated API calls, supports deterministic sampling, and
  caps retained trace rows while preserving exact total-call counters.
- Caps raw WinAPI/Linux hook logs independently of exported trace retention.

## 2.1.12 highlights

- Clears stale fault metadata before each new continue/step so a reached PE32
  breakpoint is classified as a breakpoint rather than a prior fault.
- Captures configured breakpoint snapshots and breakpoint-triggered memory dumps,
  including the `breakpointConfigs` automation spelling.
- Adds direct live-memory disassembly and Remill-to-Helix decompilation commands;
  no temporary executable copy is required.
- Makes multi-step execution honor the requested count and validates STDIN input
  instead of silently accepting an empty buffer from a misspelled argument.

## License

**GPL-2.0-only** - See [LICENSE](LICENSE) for details.

This component embeds `hexcore-unicorn`, which links the Unicorn Engine (GPL-2.0).
Because it links GPL code, the debugger extension is itself GPL-2.0-only. This does **not**
make the rest of the HexCore IDE GPL: the emulation worker runs out-of-process over IPC,
so the core IDE and the other `hexcore-*` extensions remain MIT. Only this extension and
`hexcore-unicorn` carry GPL-2.0.
