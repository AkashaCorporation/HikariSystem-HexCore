---
name: HexCore Binary Analysis
description: Analyze authorized binaries with HexCore's static, decompilation, managed, emulation, query, and evidence pipelines.
---

# HexCore Binary Analysis Skill - v3.8.4 (Analysis Contract)

## Scope

HexCore is a VS Code-based reverse-engineering environment. Use it only for binaries the user owns or is authorized to analyze, including CTF/HTB challenges, controlled game research, malware triage, and bug-bounty artifacts within scope.

The automation source of truth is `extensions/hexcore-disassembler/src/automationPipelineRunner.ts`. Validate jobs before treating examples in prose as executable contracts.

> Release train: HexCore `3.8.4` in development, "Analysis Contract".
>
> Contract additions an agent must respect: pipeline admin commands (`runJob`, `validateJob`, `listCapabilities`, `queueJob`, `jobStatus`) return contract-decorated responses (`contractVersion: 1`, canonical `status` (`ok|partial|failed|skipped`), typed `diagnostics`, `artifacts`) with all legacy fields preserved. The file-level `hexcore-pipeline.status.json` keeps the legacy `error` run status; only the command response uses `failed`. Error codes come from the `ANALYSIS_ERROR_CODES` registry in `hexcore-common`. When the target's `.hexcore_session.db` exists, run provenance records the persisted session ID/generation and the session engine manifest instead of a synthetic session; `contextGeneration` remains the runner's execution counter. Finding IDs are stable contract IDs (`finding:sha256:<digest>:...`) that survive re-runs with saved marks intact; cross-target references are rejected as `wrong-target`.

> Wave 2.1 additions: detected PRNG mode/seed are propagated to later Debugger
> emulation unless explicitly overridden; API traces are bounded/grouped with
> exact counters; disassembly pages expose truncation and `nextAddress`; and
> dominant callfuscation uses instruction-aware rewriting plus reachable-only
> Remill lifting from the requested logical entry.
>
> P2 hardening: ASCII line boundaries separate adjacent messages; disassembly
> context is contiguous or carries an explicit recovery reason; failed steps
> participate in slowest-duration accounting; Debugger state/run artifacts use
> the same bounded trace counters and compact execution summary.
>
> FlareAuthenticator closure: `hexcore.constraints.solveHeadless` runs the
> packaged Z3 and returns concrete models; disassembly pages that fill the
> 10,000-instruction cap report `truncated:true`, `stopReason:"count-limit"`,
> and `nextAddress`; Helix output exposes translation, lift-coverage, and
> semantic-type confidence separately. Never treat one 100% coverage field as
> whole-function or type correctness.

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

`capstone 1.3.6`, `unicorn 1.3.2`, `remill 0.5.4`, `llvm-mc 1.0.2`, `better-sqlite3 2.0.3`, `souper 0.2.2`, `elixir 1.0.4`, `common 1.3.0`.

Current integrated extensions relevant to automation: `hexcore-disassembler 1.4.57`, `hexcore-debugger 2.1.21`, `hexcore-strings 1.3.3`, `hexcore-yara 2.1.3`, `hexcore-revenant 0.4.0`, `hexcore-helix 0.9.3`, `hexcore-peanalyzer 1.1.3`, and `hexcore-report-composer 1.0.11`.

## Job Rules

1. Put the canonical job at `.hexcore_job.json`, or use a descriptive `*.hexcore_job.json` name.
2. Keep `outDir` inside the workspace or the job-file directory. External output is rejected unless the user deliberately enables `hexcore.pipeline.allowExternalOutDir`.
3. Use `hexcore.pipeline.validateJob` or `validateWorkspace` before expensive runs.
4. Prefer a single job plus `$step[N].output` when one step consumes another step's artifact.
5. `$step[prev]` is valid except in step `0`; forward references are invalid. Conditional jumps that may skip a referenced producer are reported by validation.
6. Top-level `continueOnError` is inherited by steps unless a step overrides it.
7. Set realistic timeouts. `analyzeAll` runs in a killable child process; inspect `nativeExecution.lastPhase` and the `.hexcore-meta/*.heartbeat.json` before increasing a deadline. A timeout must terminate the worker and reach terminal pipeline status.
8. Inspect both `hexcore-pipeline.log` and `hexcore-pipeline.status.json`. The status records attempts, output bytes, totals, slowest step, and queue snapshot.
9. A command disabled by `hexcore.emulator` is `skipped`, not a tool failure.
10. Do not invoke `hexcore.pipeline.runJob` from a pipeline step; recursive pipeline execution is blocked.
11. Preflight is mandatory and prevents command dispatch on validation errors. Do not bypass it to obtain a partial artifact.
12. Semantic child failures fail by default. Use `allowPartial: true` only when incomplete coverage is intentional, and preserve the terminal `partial` status.
13. Verify each artifact in the consolidated `.hexcore-meta/provenance.json`
    manifest before cross-run comparison. New jobs do not emit visible
    per-artifact provenance sidecars.

### Watcher and queue behavior

- On startup, root-level canonical/named jobs are auto-discovered.
- The recursive watcher reacts to later create/change events under the workspace.
- A stale unchanged `running` status is archived and terminalized after `hexcore.pipeline.staleRunningMs` (15 minutes by default), then the revision may run again.
- Watch events are debounced and content-deduplicated; outputs are protected from re-trigger loops.
- Queue slots are configured by `hexcore.pipeline.queue.poolSize` (default `2`, range `1..16`). Stateful jobs serialize across the shared Extension Host; only audited stateless tools use parallel slots.
- Use `sessionId` for sticky routing when multiple queued jobs share a `keepAlive` emulation session.

## Pipeline-Safe Commands

This list mirrors the v3.8.4 capability registry. Aliases are listed separately.

### Static, format, and reporting

- `hexcore.filetype.detect`
- `hexcore.hashcalc.calculate`
- `hexcore.entropy.analyze`
- `hexcore.strings.extract`
- `hexcore.strings.extractAdvanced` - accepts optional `minConfidence`,
  `maxDeobfuscated`, `highSignalOnly`, `decodeChains`, and
  `maxTransformChains`; budgets and every transform stage remain auditable.
- `hexcore.peanalyzer.analyze`
- `hexcore.pe.extractSection` - bounded passive extraction of one named PE section.
- `hexcore.crypto.rc4` - bounded passive RC4 transform; chain binary input with `inputPath: "$step[N].output"`.
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
- `hexcore.pipeline.composeReport` - compact evidence index by default; use
  `includeFullSources:true` only for a deliberately self-contained report.

### Disassembly, decompilation, and semantic analysis

- `hexcore.disasm.analyzeAll`
- `hexcore.disasm.detectPacker` - detection only; no unpacking or external UPX dependency.
- `hexcore.disasm.buildFormula`
- `hexcore.constraints.solveHeadless`
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

For HQL, binary targets and Remill-compatible LLVM IR are supported. Preserve every clean function record, `signatureSetSha256`, node count, adapter coverage, and unsupported-node counts. Interpret `structuralCompleteness` as rule satisfaction and `evidenceLevel` as `signal`, `candidate`, or `proven`; `confidence` is valid only when the signature names a hashed calibration corpus. Never map HQL presentation severity directly to vulnerability severity.

HQL 0.3 also reads typed HXDB facts. Preserve `semanticFactCount`,
`semanticFactsSha256`, semantic match provenance, and `proofStatus`; do not
flatten prototypes, xrefs, summary effects, conflicts, or barriers into strings.
Runtime observations are corroboration bound to binary/input/trace hashes, not
static proof.

For semantic edits, use `hexcore.types.*`, `hexcore.references.*`,
`hexcore.propagation.*`, `hexcore.typeManager.*`, `hexcore.records.recover`,
`hexcore.pdb.*`, and `hexcore.signatures.apply`. A stored edit is not complete
until typed consumer propagation commits. Never infer one global struct member
from an equal numeric offset without proven object identity.

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
- `hexcore.debug.disassembleMemoryHeadless`
- `hexcore.debug.decompileMemoryHeadless`
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

When unpacked or self-modified code exists only in emulator RAM, prefer
`disassembleMemoryHeadless` or `decompileMemoryHeadless`. They preserve the
original session identity and hash the inspected region without materializing a
derived executable. Treat the live address and byte count as evidence-bound
inputs; do not widen the region merely to increase lift coverage. Live Helix
decompilation is isolated in a killable OS process. Verify the returned/logged
`analysisContext`: evidence from the active Disassembler is valid only when the
producer target is `matched`; `mismatched` and `unbound` must report
`activeEngineEvidenceUsed=false`. For a native crash or timeout investigation,
set `retainIr:true`; the command writes `<output.path>.ll` before invoking Helix
and reports its byte count and SHA-256 even when decompilation fails.

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

`hexcore.oracle.inspectConfig`, `hexcore.oracle.listSessions`, and `hexcore.oracle.demoHeadless` are `v3.9.0-preview.oracle`, gated by `hexcore.oracle.enabled`. Do not depend on them for a `3.8.4` release-validation job.

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
   For headerless blobs, set `arch` and `baseAddress` explicitly on `analyzeAll` instead of relying on the x64 default.
3. Decompile only selected functions; retain their `.ll`, pseudo-C, address, and confidence.
4. Use HQL and formula extraction where the architecture supports them.
5. Emulate only after static evidence defines entry, inputs, stop conditions, and expected observations.
6. When the verification equation is bounded, call
   `hexcore.constraints.solveHeadless` and retain the exact variables,
   constraints, model, Z3 version/hash, and negative `unsat` results.
7. Record failures as evidence: command, step, address, architecture, error, partial artifact, and comparison target.

Souper is not a default challenge step. Use `souper: "auto"` in Helix or run `hexcore.souper.optimize` against a retained `.ll` when bitwise/rotate-heavy IR justifies solver cost.
Souper optimizes IR; it is not the model-producing interface. Use the
constraint command when the goal is a PIN/key/input model.

### Constraint model

```json
{
  "cmd": "hexcore.constraints.solveHeadless",
  "args": {
    "variables": [
      { "name": "digit_0", "type": "int", "domain": [0, 9] },
      { "name": "state", "type": "bv", "bits": 64 }
    ],
    "constraints": [
      { "op": "eq", "args": [
        { "op": "mul", "args": ["digit_0", 7] },
        42
      ] },
      { "op": "eq", "args": [
        "state",
        { "bits": 64, "value": "847851805715481601" }
      ] }
    ],
    "maxModels": 4,
    "timeoutMs": 30000
  },
  "output": { "path": "constraint-models.json" },
  "timeoutMs": 35000
}
```

Models are decimal strings so 64-bit values do not lose precision. Use exact
integer literals as `{ "type":"int", "value":"..." }` and bitvector
literals as `{ "bits":64, "value":"..." }`. The result is
`sat|unsat|unknown`; `truncated:true` on the solver result means more models
may exist beyond `maxModels`, not incomplete disassembly.
`unknown` and timeout are semantic failures by default. Only set
`allowUnknown:true` or `allowTimeout:true` for an expected inconclusive result;
that produces `semanticStatus:"partial"` and also requires the pipeline step's
`allowPartial:true`. Never report that state as a solved constraint.

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
- A disassembly page that fills its effective count before a trusted end must
  be `truncated:true` with `stopReason:"count-limit"`; continue from
  `nextAddress` or narrow the function. Never rewrite this as a complete page.
- `semanticCoverage` covers decoded instructions with Remill semantics only.
  It does not prove complete CFG, boundary, pseudo-C, or type identity. Require
  non-scoped lift evidence, no unsupported/decode failures, no damning
  `qualityIssues`, and inspect `confidenceAxes`. `semanticType:null` /
  `not-assessed` is not permission to infer a type.
- Do not execute unknown malware natively. Prefer static analysis and isolated emulation; document emulator limitations and anti-debug behavior.

See `docs/HEXCORE_AUTOMATION.md` for the command contract and `docs/HEXCORE_JOB_TEMPLATES.md` for runnable job patterns.
