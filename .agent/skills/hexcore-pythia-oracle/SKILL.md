---
name: HexCore Pythia Oracle Analysis
description: Skill to drive Claude-powered emulation intervention (Project Pythia / Oracle Hook / Issue #17). Teaches Claude to write Oracle-enabled HexCore jobs, interpret Pythia decisions, and delegate to specialists.
---

# HexCore Pythia Oracle Analysis — v0.1-hackathon

> **Hackathon context (Apr 21-26 2026):** this skill drives **Project Pythia**, a Claude Agent that intervenes in HexCore's emulation mid-execution. Pythia receives a `DecisionRequest` at every configured trigger (timing check, PEB access, software breakpoint, exception), inspects state, and issues a `DecisionResponse` (continue / patch / skip / abort). HexCore applies the decision and resumes. **This is the first Claude-driven dynamic malware analysis pipeline.**

> **Companion skill:** `.agent/skills/hexcore/SKILL.md` covers baseline static + dynamic analysis. Use that one when a sample can be understood without live intervention. Use *this* skill when the sample uses anti-debug / packing / API-hash resolution that blocks normal emulation.

---

## When to Use This Skill

Prefer this skill over the baseline HexCore skill when any of these is true:

1. Baseline `hexcore.debug.emulateFullHeadless` trips anti-debug and exits silently (empty `apiCalls`, no `stdout`, no behavior observed).
2. The sample has high-entropy sections + `rdtsc` / `QueryPerformanceCounter` / `GetTickCount` / PEB dereferences visible in disassembly (classic timing & environment anti-debug).
3. Imports table is suspiciously small for the binary's size — indicates API hash resolution at runtime.
4. You need to observe the beacon / C2 / URL that only surfaces AFTER the anti-debug gauntlet is cleared.
5. The user explicitly mentions Pythia, Oracle, or Issue #17.

If the sample is trivial (unpacked, normal imports, no timing checks), use the baseline HexCore skill — Pythia is overkill and burns API credits.

---

## Architecture (60-second version)

```
HexCore workspace
  ├── {name}.hexcore_job.json          ← you create this
  └── Project-Pythia/ (external clone) ← user provides path via setting

1. You write a job file with an `oracle` block in an emulation step.
2. HexCore pipeline auto-detects the job file and runs each step.
3. When the step reaches an emulation command tagged `oracle: {...}`:
     a. HexCore spawns Pythia (Node subprocess in Project-Pythia/).
     b. Handshake over NDJSON stdio.
     c. Oracle injects 0xCC (INT3) bytes at every trigger PC.
     d. Emulation starts. On INT3 hit, emu pauses, state is captured,
        a DecisionRequest is sent to Pythia, a DecisionResponse is read.
     e. Byte is restored, RIP rewound, patches applied, emulation resumes.
4. Output files land in outDir: oracle-session.log + oracle-decisions.json.
5. You read those files and report findings.
```

**Transport:** stdio NDJSON today. SharedArrayBuffer (Project Perseus) is planned for v3.9.0.
**Models:** Haiku 4.5 default, Sonnet 4.6 on crypto/unpacking/exception, Opus 4.7 reserved for one `identify_family` call per session. Routing is automatic inside Pythia.
**Budget:** per-session hard cap in `hexcore.oracle.maxBudgetUsd` (default $5). Pythia degrades to deterministic stubs above budget.

---

## Settings the User Must Configure

These must be set in VS Code settings.json before any Oracle step runs:

| Setting | Required | What |
|---|---|---|
| `hexcore.oracle.enabled` | **YES** | Must be `true`. Default `false` guards v3.8.0 behavior bit-identical. |
| `hexcore.oracle.pythiaRepoPath` | **YES** | Absolute path to the Project-Pythia clone. Typical: `C:\\Users\\Mazum\\Desktop\\HexCore-Oracle-Agent`. |
| `hexcore.oracle.maxBudgetUsd` | no | Session hard cap. Default `5.0`. Lower for CI, higher for deep analysis. |
| `hexcore.oracle.pauseTimeoutMs` | no | Max wait per decision before fallback. Default `30000`. |

Pythia also needs `ANTHROPIC_API_KEY` set — it reads from `$PYTHIA_REPO/.env` automatically (gitignored).

---

## Job File Format — Oracle Steps

Oracle is layered ON TOP of the existing `hexcore.debug.emulateFullHeadless` command. You do NOT write a new step kind — you add an `oracle` field to the args of an existing emulation step.

### Minimal Oracle job

```json
{
  "file": "C:\\samples\\malware-v5.exe",
  "outDir": "C:\\reports\\malware-v5-oracle",
  "quiet": true,
  "steps": [
    { "cmd": "hexcore.filetype.detect" },
    { "cmd": "hexcore.peanalyzer.analyze" },
    { "cmd": "hexcore.disasm.analyzeAll" },
    {
      "cmd": "hexcore.debug.emulateFullHeadless",
      "timeoutMs": 300000,
      "args": {
        "arch": "x64",
        "permissiveMemoryMapping": true,
        "maxInstructions": 5000000,
        "oracle": {
          "triggers": [
            { "kind": "instruction", "value": "0x140001a3f", "reason": "QPC timing check at sv_t1" },
            { "kind": "instruction", "value": "0x140001b80", "reason": "PEB BeingDebugged read at sv_t3" },
            { "kind": "exception",   "value": "*",            "reason": "unmapped read fallback" }
          ]
        },
        "output": { "path": "emulation.json", "format": "json" }
      }
    },
    { "cmd": "hexcore.ioc.extract" },
    { "cmd": "hexcore.pipeline.composeReport" }
  ]
}
```

### `oracle` arg schema

```typescript
{
  // Required. Each trigger registers a pause point with Pythia.
  triggers: Array<{
    kind: "instruction" | "api" | "exception" | "timing_check" | "peb_access";
    value: string;   // "0x..." for instruction; API name for api; "*" for exception fallback
    reason: string;  // human-readable — appears in Pythia's context + logs
  }>;

  // Optional — override the default Pythia budget for this one step.
  maxBudgetUsd?: number;

  // Optional — dry-run: write DecisionRequests to outDir but accept automatic
  // "continue" on all of them. Useful for measuring trigger firing rates
  // before spending real credits.
  rehearseOnly?: boolean;
}
```

### Output files (alongside existing emulation output)

Oracle steps write TWO additional files into `outDir`:

- `oracle-session.log` — line-by-line trace of every pause: timestamp, eventId, trigger, action, reasoning, cost. Human-readable.
- `oracle-decisions.json` — structured array of `{ eventId, trigger, request, response, model, costUsd, elapsedMs }`. Machine-readable. Feed this to subsequent analysis steps or to the report composer.

---

## Finding Trigger PCs

You need concrete addresses to register `instruction` triggers. Three ways:

1. **Pre-scan with hexcore pipeline + static analysis.** Chain two steps: `hexcore.disasm.analyzeAll` → a custom filter step (not yet exposed as a headless command in v3.8.0 — for now, use a pre-analysis subagent, see below). Output: list of PCs matching `rdtsc`, `cpuid`, `mov reg, gs:[0x60]`, `QueryPerformanceCounter` IAT call sites.

2. **Delegate to `analysis-specialist` subagent** (for complex samples, recommended). Send the agent a clear brief: *"Use hexcore-strings + hexcore-disasm + hexcore-peanalyzer pipeline steps to identify anti-debug trigger PCs in `{sample}`. Return a list of `{pc, pattern, reason}`. Do not run emulation."* The agent produces a list you paste into the `oracle.triggers` array.

3. **Use documented PCs from prior runs.** If this sample is `Malware HexCore Defeat v5` or `v6.1`, the known trigger PCs are cached in `docs/pythia-oracle-templates/known-samples.md` (TODO by user).

---

## Typical Workflows

### Workflow A — "Analyze this unknown sample with Oracle" (the demo flow)

```
1. Verify user's oracle config is sane (read settings).
2. IF sample is unknown → delegate pre-scan to analysis-specialist to
   identify anti-debug trigger PCs.
3. Write {sample-name}-oracle.hexcore_job.json with:
     - filetype.detect + peanalyzer.analyze (static prep)
     - disasm.analyzeAll (so Helix can decompile later)
     - debug.emulateFullHeadless with oracle.triggers from step 2
     - ioc.extract + pipeline.composeReport (gather findings)
4. Drop the job into the HexCore workspace — pipeline auto-detects.
5. Monitor the job's outDir for oracle-session.log. Parse pauses as
   they appear.
6. When status.json shows all steps completed:
     - Read oracle-decisions.json to see what Pythia did at each pause.
     - Read the composed report for IOCs, beacon URLs, extracted strings.
7. Summarize for the user: how many pauses, total API cost,
   beacon URL (if observed), comparison vs baseline emulation.
```

### Workflow B — "Compare baseline vs Oracle emulation"

Ideal for the hackathon demo video. Run the SAME sample twice:

```
1. Run {sample}-baseline.hexcore_job.json WITHOUT oracle.
2. Observe: no beacon, apiCalls stop early, behavior looks benign.
3. Run {sample}-oracle.hexcore_job.json WITH oracle.
4. Observe: Pythia bypasses anti-debug, beacon surfaces, real behavior
   visible.
5. Compose side-by-side report diffing the two runs.
```

### Workflow C — "Rehearsal mode" (zero API cost)

For iterating on trigger PCs without burning credits:

```
1. Write the job with oracle.rehearseOnly: true.
2. Run — each pause gets an automatic "continue" decision, logged as
   rehearsal in oracle-session.log.
3. Inspect how many pauses fired and at which PCs. Adjust triggers.
4. When satisfied, flip rehearseOnly → false. Budget charge begins.
```

---

## Interpreting Oracle Decisions

Every line in `oracle-session.log` follows this shape:

```
[2026-04-22T14:31:02.143Z] pause#3 trigger=instruction:0x140001b80 (PEB BeingDebugged read)
  → action=patch model=haiku cost=$0.0087 elapsed=6.2s
  → reasoning: "PEB+0x2 byte is 0x01 (debugger present) — patched [rax+0x2]=0 to bypass IsDebuggerPresent"
  → patches: [{target:memory,location:0x7FFE0002,value:0x00,size:1}]
```

**Key fields:**

- **action** — the verdict: `continue`, `patch`, `skip`, `patch_and_skip`, `abort`.
- **model** — which tier Pythia used. `haiku` = mechanical (timing / PEB flip / NQIP class 7). `sonnet` = crypto / unpacking / multiple indirect calls. `opus` = family identification, once per session max.
- **cost** — actual USD burned. Sum these + compare against the session budget.
- **reasoning** — one line. If reasoning is empty or starts with `[fallback]`, that pause got a timeout/error fallback — investigate.

**When to worry:**

- More than 5 `[fallback]` reasonings in a run → transport unhealthy or Pythia timing out. Raise `pauseTimeoutMs`.
- `modelUsed=opus` firing more than once → escalation logic got stuck. Inspect the last few decisions.
- Total cost > budget × 0.8 → pipeline degrading to rehearsal soon. Stop or bump budget.

---

## Delegating to Specialists

Oracle analysis pairs well with subagent delegation when the work is large:

- **`analysis-specialist`** — pre-scan sample to find trigger PCs; parse YARA / IOC output; extract stringy C2 candidates from `oracle-decisions.json`.
- **`disasm-specialist`** — resolve API hash targets: given an `oracle-decisions.json` entry where Pythia asked about a hash, compute the matching WinAPI name.
- **`emulation-engineer`** — debug Unicorn crashes, check memory mapping when an exception trigger fires unexpectedly.
- **`decompiler-specialist`** — run Helix on the specific function Pythia paused in; feed the pseudo-C back into a follow-up Oracle session for semantic context.

**Pattern:** when the user asks a complex question ("why did v6.1 still evade Pythia?"), kick off a parallel delegation — let the specialist dig while you summarize what the current Oracle decisions already tell you.

---

## Current Limitations (v0.1-hackathon)

1. **Emulator wiring is scaffold-only** as of Apr 21 2026. The `oracle` block on `emulateFullHeadless` lands in commit Phase 3.5 (target Apr 22). Until then:
   - `hexcore.oracle.demoHeadless` works as a **handshake probe** — validates Pythia spawns and transport is healthy.
   - Real INT3-driven emulation is NOT yet interceptable.
   - Use rehearsal fixtures in `Project-Pythia/test/fixtures/` for offline iteration.
2. **Tool round-trip** supports `read_memory` and `get_imports` fully; `disassemble`, `query_helix`, `search_hql`, `list_strings_near` return stubs in v0.1.
3. **Trigger kinds supported today:** `instruction`, `api` (if resolved to a PC), `exception`. Heuristic triggers (`timing_check`, `peb_access`, `memory_read/write`) route through `instruction` — caller must provide the exact PC.
4. **Self-modifying code** will break INT3 injection — if the sample rewrites the 0xCC byte, the trigger is lost. For v5/v6.1 this is not an issue.
5. **Single session per workspace.** Multi-agent sessions land post-hackathon.

---

## Command / File Reference

| Command | Kind | Purpose |
|---|---|---|
| `hexcore.oracle.demoHeadless` | VS Code command | Handshake probe — spawns Pythia, does handshake, closes. No emulation. |
| `hexcore.oracle.listSessions` | VS Code command | Enumerate active sessions (always ≤ 1 in v0.1). |
| `hexcore.oracle.inspectConfig` | VS Code command | Dump resolved `hexcore.oracle.*` settings to Output Channel. |
| `hexcore.debug.emulateFullHeadless` | Pipeline step | Standard emulation — adds `oracle: {...}` arg to enable intervention (Phase 3.5). |
| `hexcore.pipeline.runJob` | Pipeline | Runs the canonical `.hexcore_job.json` — includes Oracle steps. |

**Example templates:** `docs/pythia-oracle-templates/*.hexcore_job.json` (created by this skill's author).

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `[oracle-demo] handshake FAILED: handshake timeout` | `pythiaRepoPath` wrong, or Pythia's deps not installed | `cd $PYTHIA_REPO && npm install`; verify path setting |
| Pythia subprocess exits code=1 immediately | Missing `ANTHROPIC_API_KEY` | Create `$PYTHIA_REPO/.env` with the key |
| `pause timeout — falling through to continue` on every pause | Network latency to Anthropic too high, OR Pythia loop stuck | Bump `pauseTimeoutMs`; check Pythia logs in the Output Channel |
| `INT3 at 0xXXXX unmatched — stopping to avoid corruption` | Sample has a native INT3 at that address we didn't inject | Remove that trigger OR investigate whether the sample is probing for self-modifying code |
| Budget exceeded at 80% → forced to Haiku | Normal — routing is cost-aware | Raise `maxBudgetUsd` or let run degrade |

---

*Project Pythia — Oracle Hook for HexCore. Anthropic Claude Developer Hackathon Apr 21-26 2026. Agent SDK + Claude Haiku/Sonnet/Opus + HexCore v3.8.0 + Project Perseus (IPC). Issue #17 implementation — branch `feature/oracle-hook-hackathon`.*
