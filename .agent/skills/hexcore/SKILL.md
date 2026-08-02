---
name: HexCore Binary Analysis
description: Analyze authorized binaries with HexCore's static, decompilation, managed, emulation, query, and evidence pipelines.
---

# HexCore Binary Analysis Skill - v3.8.3 RC

## Scope

HexCore is a VS Code-based reverse-engineering environment. Use it only for binaries the user owns or is authorized to analyze, including CTF/HTB challenges, controlled game research, malware triage, and bug-bounty artifacts within scope.

The automation source of truth is `extensions/hexcore-disassembler/src/automationPipelineRunner.ts`. Validate jobs before treating examples in prose as executable contracts.

> Release train: HexCore `3.8.3` RC, "Honest Analysis at Scale".
>
> Important: `hexcore-helix` still reports package version `0.9.2` in the IDE tree while the Helix v2 sandbox is being qualified as the future `0.9.3`. Do not describe the sandbox as a separately shipped product.

## Engine Routing

| Input / goal | Primary route | Notes |
|---|---|---|
| Native PE/ELF machine code | Remill -> Helix | Use `hexcore.helix.decompile` or explicit lift + `decompileIR`. |
| Classic CLR PE or .NET single-file apphost | Revenant | Use `hexcore.revenant.decompile` for C# or `decompileIL` for IL. Helix intentionally returns a managed-input honesty marker with confidence `0`. |
| LLVM IR optimization experiment | Souper | Use explicitly on `.ll`, or Helix `souper: "auto"`. Do not force it on every function. |
| Semantic pattern scan | HQL | Scans Helix HAST, not regex over rendered pseudo-C. |
| ELF `.ko`/`vmlinux` types | BTF/DWARF extraction | Run ELF/deep analysis first, then `hexcore.extractStructInfo`. |
| Broad emulation | Debugger/Unicorn | Stable general route; use the full one-shot command unless session state is required. |
| Isolated native instrumentation | Elixir/Azoth | Worker-isolated alternative; select with `hexcore.emulator`. |
| Legacy Rellic jobs | Rellic, compatibility only | Disabled legacy surface. Do not use in new jobs or claim a scheduled removal version. |

### Current native package versions

`capstone 1.3.5`, `unicorn 1.3.0`, `remill 0.5.1`, `llvm-mc 1.0.1`, `better-sqlite3 2.0.2`, `souper 0.2.0`, `elixir 1.0.0`, `common 1.1.1`.

Current integrated extensions relevant to automation: `hexcore-disassembler 1.4.27`, `hexcore-debugger 2.1.9`, `hexcore-yara 2.1.3`, `hexcore-revenant 0.4.0`, and IDE `hexcore-helix 0.9.2` metadata.

## Job Rules

1. Put the canonical job at `.hexcore_job.json`, or use a descriptive `*.hexcore_job.json` name.
2. Keep `outDir` inside the workspace or the job-file directory. External output is rejected unless the user deliberately enables `hexcore.pipeline.allowExternalOutDir`.
3. Use `hexcore.pipeline.validateJob` or `validateWorkspace` before expensive runs.
4. Prefer a single job plus `$step[N].output` when one step consumes another step's artifact.
5. `$step[prev]` is valid except in step `0`; forward references are invalid. Conditional jumps that may skip a referenced producer are reported by validation.
6. Top-level `continueOnError` is inherited by steps unless a step overrides it.
7. Set realistic timeouts. Static analysis and full emulation of large binaries can legitimately take minutes.
8. Inspect both `hexcore-pipeline.log` and `hexcore-pipeline.status.json`. The status records attempts, output bytes, totals, slowest step, and queue snapshot.
9. A command disabled by `hexcore.emulator` is `skipped`, not a tool failure.
10. Do not invoke `hexcore.pipeline.runJob` from a pipeline step; recursive pipeline execution is blocked.
11. Preflight is mandatory and prevents command dispatch on validation errors. Do not bypass it to obtain a partial artifact.
12. Semantic child failures fail by default. Use `allowPartial: true` only when incomplete coverage is intentional, and preserve the terminal `partial` status.
13. Verify each artifact's `.provenance.json` sidecar before cross-run comparison.

### Watcher and queue behavior

- On startup, root-level canonical/named jobs are auto-discovered.
- The recursive watcher reacts to later create/change events under the workspace.
- Watch events are debounced and content-deduplicated; outputs are protected from re-trigger loops.
- Queue slots are configured by `hexcore.pipeline.queue.poolSize` (default `2`, range `1..16`). Stateful jobs serialize across the shared Extension Host; only audited stateless tools use parallel slots.
- Use `sessionId` for sticky routing when multiple queued jobs share a `keepAlive` emulation session.

## Pipeline-Safe Commands

This list mirrors the v3.8.3 RC capability registry. Aliases are listed separately.

### Static, format, and reporting

- `hexcore.filetype.detect`
- `hexcore.hashcalc.calculate`
- `hexcore.entropy.analyze`
- `hexcore.strings.extract`
- `hexcore.strings.extractAdvanced`
- `hexcore.peanalyzer.analyze`
- `hexcore.disasm.analyzePEHeadless`
- `hexcore.elfanalyzer.analyze`
- `hexcore.disasm.analyzeELFHeadless`
- `hexcore.base64.decodeHeadless`
- `hexcore.yara.scan`
- `hexcore.yara.updateRules`
- `hexcore.ioc.extract`
- `hexcore.hexview.dumpHeadless`
- `hexcore.hexview.searchHeadless`
- `hexcore.minidump.parse`
- `hexcore.minidump.threads`
- `hexcore.minidump.modules`
- `hexcore.minidump.memory`
- `hexcore.pipeline.composeReport`

### Disassembly, decompilation, and semantic analysis

- `hexcore.disasm.analyzeAll`
- `hexcore.disasm.detectPacker` - detection only; no unpacking or external UPX dependency.
- `hexcore.disasm.buildFormula`
- `hexcore.disasm.checkConstants`
- `hexcore.disasm.searchStringHeadless`
- `hexcore.disasm.exportASMHeadless`
- `hexcore.disasm.disassembleAtHeadless`
- `hexcore.disasm.rttiScanHeadless`
- `hexcore.disasm.searchBytesHeadless`
- `hexcore.disasm.extractStrings`
- `hexcore.disasm.liftToIR`
- `hexcore.helix.decompile`
- `hexcore.helix.decompileIR`
- `hexcore.revenant.decompile`
- `hexcore.revenant.decompileIL`
- `hexcore.hql.scanHeadless`
- `hexcore.souper.optimize`
- `hexcore.extractStructInfo`
- `hexcore.audit.refcountScan`
- `hexcore.rellic.decompile` and `hexcore.rellic.decompileIR` - legacy compatibility only.

### Persistent analysis session

- `hexcore.disasm.getSessionDbPath`
- `hexcore.disasm.renameFunction`
- `hexcore.disasm.renameVariable`
- `hexcore.disasm.retypeFunction`
- `hexcore.disasm.retypeVariable`
- `hexcore.disasm.setBookmark`

Annotations are stored in `.hexcore_session.db`, keyed to the binary, and may be applied to later Helix/HQL work.

### Debugger / Unicorn

- `hexcore.debug.emulateFullHeadless`
- `hexcore.debug.emulateHeadless`
- `hexcore.debug.continueHeadless`
- `hexcore.debug.stepHeadless`
- `hexcore.debug.readMemoryHeadless`
- `hexcore.debug.writeMemoryHeadless`
- `hexcore.debug.searchMemoryHeadless`
- `hexcore.debug.getRegistersHeadless`
- `hexcore.debug.setRegisterHeadless`
- `hexcore.debug.setStdinHeadless`
- `hexcore.debug.setBreakpointHeadless`
- `hexcore.debug.getStateHeadless`
- `hexcore.debug.snapshotHeadless`
- `hexcore.debug.restoreSnapshotHeadless`
- `hexcore.debug.exportTraceHeadless`
- `hexcore.debug.disposeHeadless`

Use `emulateFullHeadless` for a one-shot load/run/collect/dispose workflow. Use granular commands only with `keepAlive: true`, explicit cleanup, and session-aware queue routing.

### Elixir / Azoth

- `hexcore.elixir.emulateHeadless`
- `hexcore.elixir.stalkerDrcovHeadless`
- `hexcore.elixir.snapshotRoundTripHeadless`
- `hexcore.elixir.smokeTestHeadless`

Elixir emulation runs in a worker process to isolate native crashes. Set `hexcore.emulator` to `azoth` or `both`; otherwise these steps are skipped.

### Pipeline administration

- `hexcore.pipeline.listCapabilities`
- `hexcore.pipeline.validateJob`
- `hexcore.pipeline.validateWorkspace`
- `hexcore.pipeline.createPresetJob`
- `hexcore.pipeline.saveJobAsProfile`
- `hexcore.pipeline.doctor`
- `hexcore.pipeline.queueJob`
- `hexcore.pipeline.cancelJob`
- `hexcore.pipeline.jobStatus`

### Oracle preview

`hexcore.oracle.inspectConfig`, `hexcore.oracle.listSessions`, and `hexcore.oracle.demoHeadless` are `v3.9.0-preview.oracle`, gated by `hexcore.oracle.enabled`. Do not depend on them for a `3.8.3` release-validation job.

### Interactive-only registry entries

These commands are declared but blocked in pipeline mode because they depend on pickers, active editors, notifications, or report UI:

- `hexcore.disasm.openFile`
- `hexcore.disasm.analyzeFile`
- `hexcore.debug.emulate`
- `hexcore.debug.emulateWithArch`
- `hexcore.elfanalyzer.analyzeActive`
- `hexcore.hql.scanFunction`
- `hexcore.yara.quickScan`
- `hexcore.yara.scanWorkspace`
- `hexcore.yara.loadDefender`
- `hexcore.yara.loadCategory`
- `hexcore.yara.createRule`
- `hexcore.yara.threatReport`
- `hexcore.pipeline.runJob` when attempted recursively from a step

## Important Aliases

| Alias | Resolves to |
|---|---|
| `hexcore.decompile` | `hexcore.helix.decompile` |
| `hexcore.decompile.ir` | `hexcore.helix.decompileIR` |
| `hexcore.liftir` | `hexcore.disasm.liftToIR` |
| `hexcore.souper`, `hexcore.optimize`, `hexcore.superoptimize` | `hexcore.souper.optimize` |
| `hexcore.dotnet.decompile`, `hexcore.decompile.dotnet`, `hexcore.revenant.decompileCSharp` | `hexcore.revenant.decompile` |
| `hexcore.dotnet.decompileIL`, `hexcore.decompile.il` | `hexcore.revenant.decompileIL` |
| `hexcore.hql.scan`, `hexcore.hql.scanFunctions` | `hexcore.hql.scanHeadless` |
| `hexcore.struct`, `hexcore.structInfo` | `hexcore.extractStructInfo` |
| `hexcore.debug.run`, `hexcore.debug.emulate.full` | `hexcore.debug.emulateFullHeadless` |
| `hexcore.disasm.rttiScan`, `hexcore.disasm.scanRtti` | `hexcore.disasm.rttiScanHeadless` |
| `hexcore.disasm.searchBytes`, `hexcore.disasm.aobScan` | `hexcore.disasm.searchBytesHeadless` |

Prefer canonical command names in durable jobs. Aliases are useful interactively but hide less context in a report.

## Recommended Workflows

### Hard / Insane reverse challenge

1. File type, hashes, format-specific deep analysis, entropy, and packer detection.
2. `analyzeAll`, strings, AOB search, assembly export, and candidate-function identification.
3. Decompile only selected functions; retain their `.ll`, pseudo-C, address, and confidence.
4. Use HQL and formula extraction where the architecture supports them.
5. Emulate only after static evidence defines entry, inputs, stop conditions, and expected observations.
6. Record failures as evidence: command, step, address, architecture, error, partial artifact, and comparison target.

Souper is not a default challenge step. Use `souper: "auto"` in Helix or run `hexcore.souper.optimize` against a retained `.ll` when bitwise/rotate-heavy IR justifies solver cost.

### Sherlock / investigation

1. Hash and identify every provided artifact.
2. Use PE/ELF/minidump analyzers according to format.
3. Extract strings, IOCs, YARA evidence, and relevant memory or trace artifacts.
4. Preserve timestamps, source paths, addresses, hashes, and negative findings.
5. Compose a report only after individual JSON artifacts exist; do not treat the composed narrative as primary evidence.

### Managed binary

1. Run format/deep PE analysis.
2. If CLR or .NET single-file is detected, route to Revenant.
3. Produce C# and IL when semantic recovery or compiler transformations need cross-checking.
4. A Helix managed marker is correct routing evidence, not a decompilation regression.

### Kernel ELF

1. Run `hexcore.disasm.analyzeELFHeadless` and `hexcore.disasm.analyzeAll`.
2. Export `hexcore.extractStructInfo`, optionally scoped by `functionName`.
3. Lift/decompile the target function and retain `.ll` plus pseudo-C.
4. Run the refcount audit as triage only. Every finding requires manual control/data-flow verification.

## Failure Discipline

- Distinguish decoder, format parser, function-boundary, Remill lift, Helix lowering, renderer, and pipeline-runner failures.
- Compare the same input, address, architecture, and command arguments before attributing a regression.
- Never compare against stale `.ll` files without provenance.
- Re-run determinism-sensitive targets and compare hashes or normalized output.
- Confidence is evidence metadata, not correctness proof. Validate control flow, calls, memory offsets, types, and side effects against disassembly/IR.
- Do not execute unknown malware natively. Prefer static analysis and isolated emulation; document emulator limitations and anti-debug behavior.

See `docs/HEXCORE_AUTOMATION.md` for the command contract and `docs/HEXCORE_JOB_TEMPLATES.md` for runnable job patterns.
