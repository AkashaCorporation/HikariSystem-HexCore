# HexCore Disassembler

Professional disassembler + headless pipeline host for HexCore (Capstone, Remill lift, Helix decompile, automation jobs).

| Field | Value |
|-------|--------|
| **Package** | `hexcore-disassembler` |
| **Version** | **1.4.66** |
| **Publisher** | hikarisystem |
| **Product train** | HexCore **3.8.4 development** |

## 1.4.66 highlights (release candidate integration)

- Shows lazy/partial/materialized/decode-empty state without forcing eager body
  decoding; known reference counts are not absence claims.
- Binds cross-job audit inputs to exact source/provenance hashes and labels queue
  self-observation explicitly.
- Uses portable PDB tool discovery through `HEXCORE_PDBUTIL`, PATH or a standard
  LLVM installation instead of a developer-specific filesystem path.

## 1.4.62 highlights (agent evidence contracts)

- Analysis indexes distinguish reconnaissance, partial disassembly, and complete
  disassembly. Only complete bodies count toward materialized coverage.
- Refcount scans retain exact input hashes and provenance quality. Zero findings
  over partial or unbound pseudo-C are inconclusive; accepted negatives apply
  only to the scanner's patterns in the provided source.

## 1.4.61 highlights (Perseus propagation isolation)

- Runs bounded whole-program propagation and record recovery in a pure
  TypeScript Worker Thread over a read-only snapshot, using the versioned
  `perseus-sab-v1` control channel for heartbeat, phase, iteration, affected
  count, cancellation, and terminal state.
- Commits accepted summaries and bindings only in the parent after the HXDB
  snapshot identity is rechecked. Timeout and cancellation never commit a
  partial generation, and hard timeout terminalizes without waiting for V8
  worker teardown.
- Indexes snapshot edges by source/target and bindings by function. On the
  ROTTR health lane, the worker fixed point completes in about 1.7 seconds
  (2 iterations, 6 functions) while the Extension Host main thread remains
  responsive.
- Indexes active producer edges once during input collection instead of issuing
  per-function SQLite queries. The retained ROTTR timing lane reduces
  collection from 44,773 ms to 491 ms and the full propagation step from
  49,946 ms to 5,802 ms.
- Defers, preserves, and reports reference invalidations when restored analysis
  is older than active edge generations; such a graph is explicitly `partial`.
- Reconciles stale heuristic boundaries with newly materialized adjacent
  functions without truncating authoritative `.pdata` spans.

## 1.4.60 highlights (installed semantic closure)

- Connects HQL 0.3.1 to the target-bound HXDB instead of running structural
  matching with an undefined session.
- Makes reference-edge replacement generation-aware and keeps prior dependency
  records in version history.
- Treats partial decode as retryable display-only evidence and blocks it from
  accepted typed-reference and propagation inputs.

## 1.4.59 highlights (semantic parity foundation)

- Adds the HXDB semantic model, full prototype/ABI commands, typed references,
  bounded whole-program propagation, record recovery, PDB/signature providers,
  and the central `HexCore Types: Open Semantic Explorer` editor.
- HQL rules can combine HAST structure with typed HXDB conditions for prototypes,
  fields, xrefs, indirect targets, summary effects, provenance, and proof status.
- Debugger runtime observations remain separate corroboration bound to binary,
  input, and trace hashes; Report Composer renders semantic coverage and barriers.
- Source-known, Backblaze, zlib/libarchive, DWARF/BTF, IDA, and Ghidra baselines
  are retained under `benchmarks/` with deterministic artifact identities.

## 1.4.41 highlights (Foreigner pipeline hardening)

- VM compare ladders require one stable opcode operand, distinct constants, and
  multiple handler destinations. Anti-sandbox conjunctions that branch to one
  failure block are no longer reported as bytecode dispatchers.
- Unknown high-entropy writable/executable sections are reported as encrypted
  payload or unknown-packer evidence instead of `packed:false` merely because
  no commercial-family marker was found.
- Headerless binaries accept explicit `arch` and `baseAddress` options in
  `analyzeAll`; PE and ELF architecture remains header-authoritative.
- Binary pipeline outputs are captured as bounded metadata rather than decoded
  as UTF-8, preserving `$step[N].output` chaining for extracted payloads.
- Engine disposal closes the per-target session store before releasing native
  decoders, avoiding locked `.hexcore_session.db` handles in short-lived runs.

## 1.4.40 highlights (address, execution, and live-memory truth)

- Adds bounded Z3 constraint solving, precise disassembly/lift coverage, custom
  debugger terminal sentinels, and the Wave 2.1 honesty boundaries documented
  in the root changelog.

## 1.4.39 highlights (bounded target selection)

- Auto-backtrack candidates must remain in the requested executable section;
  an exact section-start request can no longer decode bytes from its predecessor.
- An explicit `count` is a hard instruction scope even when analysis knows a
  much larger function boundary. Scoped lifts are reported as `partial`, retain
  the requested count in diagnostics, and cap whole-function confidence at 50%.
- Callfuscation recovery honors the same explicit byte window instead of
  replacing it with the containing section.

## 1.4.38 highlights (retained-session body honesty)

- Rediscovered cached function boundaries are materialized instead of being
  returned as hollow bodies merely because their address already exists.
- Analysis summaries distinguish `materialized`, `lazy`, and `decode-empty`
  bodies and report body/instruction coverage explicitly.
- Whole-program ASM export streams one function at a time, decodes lazy bodies
  on demand, releases those temporary bodies again, and returns `partial` with
  typed empty-function evidence if decoding produces no instructions.

## 1.4.37 highlights (semantic lift honesty)

- Consumes Remill's pre-optimization semantic metrics and reports decoded,
  lifted, unsupported, decode-failure, coverage, and opcode-histogram evidence.
- Writes that evidence into the retained `.ll` header and preserves the detailed
  semantic warning in pipeline status/logs instead of a generic partial reason.
- Marks a transport-successful lift as `partial` whenever machine instructions
  use `HandleUnsupported`; pipeline status and provenance retain that result.
- Propagates incomplete source-IR evidence into Helix diagnostics and confidence
  gating so generated C cannot remain High solely because LLVM removed the
  unsupported paths from the final textual IR.

## 1.4.36 highlights (target-owned IR context and cancellable live decompile)

- `decompileIR` accepts an explicit producing target and consumes active-engine
  renames, symbols, debug types, function starts, and callfuscation evidence
  only when that target matches the binary loaded by the Disassembler.
- Every direct-IR result reports whether analysis context was `matched`,
  `mismatched`, or `unbound`, and whether active-engine evidence was used.
- Live-memory Helix work runs in a fresh OS process with an internal deadline
  and an explicit cancellation command. A native timeout can therefore kill
  the isolated process without restarting or indefinitely holding the Extension Host.
- Job watcher deduplication uses case-insensitive path identity on Windows,
  preventing `C:\\...` and `c:\\...` from launching the same job concurrently.
  Startup auto-run also preserves an existing attempt for an unchanged job
  revision across Extension Host reloads; edit the job or run it manually to
  request another attempt.

## 1.4.35 highlights (bounded automation and deterministic context)

- Context rows are emitted only when they form a contiguous instruction chain
  ending at the effective target. The result reports complete, partial, or
  unavailable recovery instead of silently joining disjoint ranges.
- Pipeline summaries count failed commands when selecting the slowest executed
  step, so timeouts and expensive failures remain visible.

## 1.4.34 highlights (bounded automation and callfuscation recovery)

- Propagates detected PRNG mode and seed into later Debugger steps unless a
  job explicitly overrides them.
- Exposes disassembly count caps and the exact next-address pagination cursor.
- Detects genuine call boundaries before call-as-jump rewriting, recovers
  logical function entries hidden by callfuscation, and asks Remill to retain
  only CFG-reachable code from the requested entry.

## 1.4.33 highlights (live-memory handoff and confidence honesty)

- Accepts raw bytes from an active Debugger session and lifts them with Remill
  without creating a derived executable on disk.
- Lets the Debugger compose live memory -> Remill IR -> Helix C while preserving
  the original target identity and recording the region address and SHA-256.
- Caps misleading High confidence when whole-binary evidence proves dominant
  call-as-jump callfuscation, even if the emitted helper body looks clean.

## 1.4.32 highlights (truth-boundary hardening)

- Resolves PE virtual addresses through explicit header/section mappings and
  reports RVA, raw offset, section, source, and remaining file-backed bytes.
- Preserves raw-backed section tails beyond `VirtualSize` without allowing a
  disassembly range to bleed into the next physical section.
- Declares Elixir/Azoth's current PE32+ x86_64 capability in pipeline metadata
  and skips unsupported ELF/PE32 targets with an actionable reason.

## 1.4.29 highlights (persistent investigations)

- Adds `Investigate` and `Saved` views to the central Analysis Center while keeping the sidebar compact.
- Exposes `Open Analysis Center` as a full-width sidebar launcher and in the title actions of both Session Overview and the always-visible Functions view.
- Finds binary candidates already present in the workspace and loads a selected target through the existing custom disassembly editor.
- Provides focused string-reference investigations for health/state, anti-debug, network/URL, credentials/secrets, or one custom term.
- Deduplicates string xrefs, maps each code reference to its containing function, and keeps unreferenced strings as explicit evidence instead of inventing a function association.
- Records investigation history and findings in the binary's `.hexcore_session.db`. Findings can be starred into `Saved` without overloading ordinary disassembly bookmarks.
- Opens a finding at its code reference and sends its owning function address through the normal Remill-to-Helix decompile command. Findings with only an xref resolve their function boundary on demand and persist the association before decompiling.
- Bounds custom queries, workspace discovery, history, and result counts; validates every webview request before it reaches the extension host.
- Native SQLite smoke covers record, save, and restore. The investigation model passes 5/5 focused tests, TypeScript compilation is clean, and desktop/720 px webview renders complete with zero page errors.

## 1.4.28 highlights (integrated Analysis Center)

- Adds an always-visible `HexCore Analysis` Activity Bar entry with a live session overview.
- Adds a full editor surface with `Overview`, `Engines`, and `Automation` tabs.
- Keeps the sidebar focused on compact session actions and navigation trees; detailed workspace jobs and target metadata remain in the central Analysis Center.
- Opens CFGs as central editors, keeps existing graph surfaces synchronized with function selection, and handles the initially displayed function consistently.
- Routes long branches around intermediate blocks, separates conditional arrivals, grids disconnected regions, and bounds large basic-block previews to 32 instructions.
- Surfaces active-binary metadata, function/section/import/export/string/bookmark counts, native-engine health, emulator selection, and workspace job files from existing runtime state.
- Routes Open, Analyze, Lift, Decompile, Hex, YARA, Entropy, PE, Job, Doctor, and native-status actions through their owning commands.
- Reports Rellic as disabled compatibility scope and includes active Souper in native health checks.
- Uses a nonce-based CSP and a fixed inbound-action allowlist; runtime Playwright smoke passes with zero console errors.
- Parses large PE64 `.pdata` tables completely (up to an explicit 500,000-entry safety bound), reconciles chained/overlapping records into a non-overlapping logical domain, and feeds those ranges directly to Pathfinder.
- Restores the analysis cache as lazy stubs in one SQLite transaction and keeps authoritative bounds intact when the UI materializes only a 1,000-instruction preview.
- Canonicalizes ET_REL numeric navigation to `.text`; colliding executable sections remain accessible through `symbolName`, which carries the required section identity.
- Uses exact `.text` `STT_FUNC/st_size` stubs to eliminate interior prologue ghosts. On `mali_kbase.ko`, the table now matches `llvm-readobj` at 3,680 functions with zero overlaps and loads in about 1.1 seconds instead of about 72 seconds.
- Real Pathfinder validation on `kbase_jit_allocate` scans the exact 2,121-byte symbol range, decodes 471 instructions, emits 144 in-range leaders, and reports 90% CFG confidence.

## 1.4.23 highlights (exact ELF symbol-boundary normalization)

- Treats exact, non-zero ELF `STT_FUNC/st_size` as the authoritative extent for
  functions truncated at an interior `ud2`/`ret` or overrun into neighbours.
- Keeps ET_REL address collisions safe by preferring the matching function name
  and otherwise accepting only `.text`; other sections remain available through
  the existing `symbolName` path.
- Trims instructions and stale xrefs when shrinking, then rebuilds the direct
  call graph; adjacent ftrace `__pfx_` symbols remain separate from their body.
- Fresh Mali validation: `kbase_jit_allocate` is corrected from 997 to 2121
  bytes, while `kbase_regmap_term` is corrected from 7543 to 84 bytes.
- Cross-kernel validation freshly lifts and decompiles 128/128 selected
  functions; focused and neighbouring boundary regressions pass 5/5 and 29/29.

## 1.4.18 highlights (FIX-027c chained `.pdata` lift extent)

- Reconciles MSVC chained-unwind `.pdata` fragments before the hot `liftToIR` path computes the function extent.
- Prevents a raw continuation boundary from entering `knownFunctionEnds` and truncating Remill at the first fragment.
- The reconciliation barrier is one-shot per loaded binary and safe when followed by `analyzeAll`.
- Validated on SOTTR HealthData: **137 -> 701 bytes**, **4 -> 40 blocks**, **19 -> 156 semantic calls**.
- Preserves explicit ET_REL job windows when symbol/analyzeAll extents cover only a hot fragment (FIX-QUALITY-002e).

## 1.4.17 highlights (FIX-QUALITY packaging)

Closes the **IDE job vs engine-direct quality gap** on real PE drivers (validated `mbamchameleon.sys` @ `0x14002641c`):

| Path | Before | After |
|------|--------|-------|
| IDE `helix.decompile` job | ~891 lines / 53% (or fake 95% on 95-line stub) | **1597 lines / 64.2%** |
| Engine-direct harness | 1596 lines / 64.2% | same |

Key fixes:

- **Cast layer ON by default** (legacy PseudoCEmitter is opt-out only)
- **`.pdata` authoritative function size** (prologue-scan 4800 vs pdata 6761)
- **No Pathfinder leader flood** on single-fn lift; under-lift retry
- **Headless Helix `forceSync`** (no Electron worker double-load)
- **`// LiftDiag:`** stamp on decompiled C
- **#52** import/PLT → real names (`ExAllocatePoolWithTag`, `dlopen`, …)
- **#46** width-aware bit-intrinsic cleanup (`ctpop.i64` → `popcountll`)

See product root `CHANGELOG.md` → *Disassembler/Helix packaging (FIX-QUALITY-001/002/002c/002d)*.

## Commands (headless)

Common pipeline steps:

- `hexcore.disasm.analyzePEHeadless` / `hexcore.disasm.analyzeAll`
- `hexcore.disasm.liftToIR`
- `hexcore.helix.decompile` / `hexcore.helix.decompileIR`
- `hexcore.pipeline.runJob` (auto-runs `*.hexcore_job.json`)

Job args of interest for decompile quality:

```json
{
  "cmd": "hexcore.helix.decompile",
  "args": {
    "address": "0x14002641c",
    "size": 65536,
    "souper": false,
    "useCastLayer": true,
    "allowOversizedLift": false,
    "functionStarts": false
  }
}
```

| Arg | Default | Notes |
|-----|---------|--------|
| `useCastLayer` | **true** | Set `false` only to force legacy PseudoCEmitter |
| `functionStarts` | off | Set `true` / `honesty:true` for D2 authoritative registry |
| `allowOversizedLift` | false | Keep multi-fn huge windows |
| `noLiftRetry` | false | Disable under-lift auto-retry |

## Build

```bash
cd extensions/hexcore-disassembler
npm install
npx tsc -p tsconfig.json
```

## Tests

```bash
npx mocha -u tdd --timeout 10000 "out/helixPackaging.quality.test.js"
npx mocha -u tdd --timeout 10000 "out/importSymbolNames.test.js"
npx mocha -u tdd --timeout 30000 "out/helixCleanupPostProcessor.test.js"
```
