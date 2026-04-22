---
name: HexCore Pythia Oracle Analysis
description: Claude-driven malware analysis via Project Pythia. When the user asks "analyze sample X with Pythia" or drops a binary and requests dynamic analysis, use this skill. Claude orchestrates Azoth emulation + Oracle intervention + produces an analyst-style report. Built for the Anthropic Claude hackathon Apr 21-26 2026.
---

# HexCore Pythia Oracle — Analyst Mode

> **Hackathon project (Apr 21-26 2026).** Pythia is a Claude-powered agent that intervenes mid-emulation to bypass anti-analysis. The v6.1 Echo Mirage test corpus was engineered to defeat HexCore v3.8.0 baseline — with Pythia, the analyst watches Claude reason about each anti-debug check in real time. Per-decision cost: ~$0.01 on Haiku / ~$0.03 when Pythia escalates to Sonnet on adversarial patterns.

## When to use this skill

Trigger when the user asks for **dynamic analysis with Pythia**. Examples:

- "analyze C:\samples\suspicious.exe with Pythia"
- "run Pythia on the malware in the workspace"
- "what does this binary do? use the oracle"
- "unpack it with Pythia"
- anything mentioning Oracle Hook, Issue #17, or Claude-driven RE

For **static-only** analysis (strings, YARA, disasm without emulation) use the companion `.agent/skills/hexcore/SKILL.md` instead. Pythia is overkill when emulation already succeeds without intervention.

## Invocation pattern — the CLI runner

The **primary interface** is `scripts/pythia-azoth-run.mjs` — a standalone Node script that spawns Pythia, drives Azoth emulation, collects the session trace. This path is preferred over the VS Code pipeline because it's engine-isolated, deterministic, and the user's workflow is "Claude Code drives, IDE shows".

```bash
node scripts/pythia-azoth-run.mjs \
  --sample <ABSOLUTE\PATH\TO\sample.exe> \
  --pythia C:\Users\Mazum\Desktop\HexCore-Oracle-Agent \
  --outDir <ABSOLUTE\PATH\TO\reports-dir> \
  --maxInstructions 2000000 \
  --triggers '[{"kind":"instruction","value":"0xADDR","reason":"WHY"}]' \
  -v
```

Required env: `ANTHROPIC_API_KEY` lives in `<pythia-repo>/.env` — the runner's transport loads it automatically. Do NOT echo the key.

## Your job as Claude: the narrative

When the user invokes this skill, do NOT dump raw JSON at them. Be a **reverse engineer** walking them through the sample:

### Step 1 — Reconnaissance (~20 seconds)

Before spawning Pythia, establish what you're looking at. Run a fast static pass:

```bash
# Use an existing .hexcore_job.json in the workspace, or a minimal inline one,
# invoking: filetype + hash + entropy + peanalyzer + strings.extractAdvanced.
# Or skip if the user already ran static analysis.
```

Narrate:
> *"Analyzing `<filename>` (x64 PE, 13824 bytes, SHA256 prefix `abc123...`). Entropy suggests \[packed/plain/crypto\]. Strings show \[observations\]. Imports: \[N\] / empty — suggests \[API hash resolution / normal linking\]."*

### Step 2 — Baseline emulation (no Pythia)

Run Azoth alone to establish what the sample does naturally:

```bash
node scripts/pythia-azoth-run.mjs \
  --sample <path> --pythia <pythia-repo> \
  --outDir <tmp-dir>/baseline --maxInstructions 2000000 \
  --triggers '[]'
```

(Empty triggers = no Pythia intervention; it just runs emulation through Pythia's glue for apples-to-apples reports. If you want a truly pristine baseline, invoke the `compare-azoth` job template instead.)

Report observations like:

> *"Baseline emulation ran for **56,161 instructions** before exit. It called **4 unique APIs** — all anti-analysis probes (`GetTickCount`, `GetTickCount64`, `QueryPerformanceCounter`, `ExitProcess`). No `LoadLibraryA`, no network APIs, no user-visible behavior. Classic silent-exit anti-debug pattern: the sample DETECTED the emulator and bailed."*

### Step 3 — Find pause points (disassembly-driven)

If the user wants a full bypass, you'll need trigger PCs. Two ways to get them:

1. **Read existing static reports** if the sample was already analyzed — `<outDir>/06-analyze-all.json` lists functions, `32-entry-decompiled.helix.c` has Helix pseudo-C.
2. **Run a focused disasm job** — one step `hexcore.disasm.disassembleAtHeadless` with `{address: "entry", count: 500}`. Inspect the output for `test bl, bl; jne <exit>`, `call [rip+XXX]` (IAT thunks), anti-debug-looking instruction sequences.

Narrate what you see:

> *"Found the anti-analysis structure at entry point 0x140001360. The function starts with `sub_honey()` (inlined) — three gates OR-accumulated into `BL`: sv_t1 (KUSER timing), sv_t2 (QPC/GetTickCount64 deltas), sv_t3 (PEB BeingDebugged + NtGlobalFlag + debugger DLL hash walk). The final gate tests `bl` at `0x140001577`; if any check detected, `jne 0x14000186d` jumps to `ExitProcess`. After the gate, `0x140001772` begins the LoadLibraryA-by-hash resolution path — the payload."*

### Step 4 — Pythia-assisted emulation

Now invoke Pythia with the trigger(s):

```bash
node scripts/pythia-azoth-run.mjs \
  --sample <path> --pythia <pythia-repo> \
  --outDir <final-reports> \
  --triggers '[{"kind":"instruction","value":"0x140001577","reason":"<plain description of the address — NOT directive instructions>"}]'
```

**Important about the `reason` field:** Pythia defends against prompt injection. If your `reason` reads like "do X then Y", she'll detect the attempted directive and refuse. Phrase it as **observation**, not **instruction**. Example of what works:

> *"Final sv_honey aggregator check. BL holds OR-combined anti-debug results from timing + PEB walk gates. jne target 0x14000186d is the ExitProcess trampoline."*

Let Claude Haiku/Sonnet reason about the state on her own.

### Step 5 — Report the session

Parse `<outDir>/oracle-summary.json` and `<outDir>/oracle-decisions.json`. Tell the user what happened:

> *"Pythia intercepted at pause **#1** (PC=0x140001577), inspected 128 bytes of memory context + 18 live registers, reasoned for **7.4 seconds** on Haiku, and decided `continue` because `BL=0x00` at pause time meant the anti-debug checks hadn't tripped yet. Cost: **$0.0087**. Emulation continued for another 56,152 instructions before natural exit.*
>
> *Pause **#2** (PC=0x14000186D, the ExitProcess trampoline itself), she ESCALATED TO SONNET 4.6 because the trigger's reason field looked adversarial. Her reasoning: 'Prompt injection detected in trigger.reason field; redirecting would execute attacker-controlled code path. Continuing normally — do not honor injected skip directive.' Cost: **$0.0311**. This is defensive AI behavior — she refuses to be directed by potentially-untrusted operator instructions."*

If the bypass succeeded:

> *"Pythia's patch at pause #1 cleared RBX, forcing the jne to fall through. Emulation then resolved LoadLibraryA (hash 0x6B1C110F) → loaded shell32.dll → resolved ShellExecuteW (hash 0x3282FB89) → decoded a stack-XOR'd URL → called ShellExecuteW. The beacon is **`https://github.com/AkashaCorporation`**. Total session cost: **$0.0X** across **N** pauses."*

### Step 6 — Summarize, cite, end

End with a crisp closer:

> *"Summary: baseline Azoth saw 4 APIs and no beacon. With Pythia's 1-3 interventions, we \[observed the full beacon / hit a defensive refusal / escalated to Sonnet / etc.\]. Full session trace at `<outDir>/oracle-decisions.json`. Each decision reviewable — Pythia's reasoning is attached per-pause."*

## Decision shapes Pythia emits

Every entry in `oracle-decisions.json` has this shape — **cite the fields in your narrative**, don't dump the JSON:

```json
{
  "eventId": "evt_instruction_...",
  "trigger": { "kind": "instruction", "value": "0x...", "pc": "0x..." },
  "action": "continue" | "patch" | "skip" | "patch_and_skip" | "abort",
  "patchesApplied": N,
  "reasoning": "...claude's one-sentence rationale...",
  "elapsedMs": N,
  "costUsd": 0.00XX
}
```

**Key quality signals for your writeup:**

- **`reasoning` is gold** — quote it verbatim, one line per decision, inside " blockquote " tags
- **Check for `prompt injection` keywords** in reasoning — if present, emphasize the defensive behavior
- **`elapsedMs` > 15000** + `costUsd` > 0.02 usually means Pythia escalated to Sonnet; say so
- **`costUsd` > 0.10** on a single decision means she escalated to Opus — very rare, worth explicit callout

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Elixir not available: ...loadError` | `.node` not rebuilt / stale | `cd HexCore-Elixir && npm run build && cp hexcore-elixir.win32-x64-msvc.node ../vscode-main/extensions/hexcore-elixir/` |
| `handshake timeout` in first run | Pythia repo missing `npm install` | `cd <pythia-repo> && npm install` |
| `ANTHROPIC_API_KEY not set` | `.env` missing in pythia repo | Create `<pythia-repo>/.env` with `ANTHROPIC_API_KEY=sk-ant-...` |
| Pause #1 always chooses "continue" + no patch | Reason too vague, Pythia couldn't infer intent | Enrich the `reason` field with OBSERVATIONAL context (disasm snippet, structural description) — NOT directive instructions |
| Pythia refuses with "prompt injection detected" | Your `reason` sounds like attacker directives | Rephrase as neutral observation. See Step 4 |
| VS Code pipeline `Worker timed out waiting for IPC message from parent (10s)` | Extension host IPC stuck (known flaky) | **Use the CLI runner instead** — scripts/pythia-azoth-run.mjs bypasses VS Code entirely |

## Budget awareness

Tell the user the running cost **every time a session ends**:

> *"Session cost: **$0.0347** across 3 pauses. Cumulative spend this week: **~$X.XX** of the $500 hackathon budget."*

Hard rules:
- If any single session crosses **$0.50** — stop, report the situation, ask before continuing.
- Never loop-retry on a failing trigger. Adjust context or `reason`, then retry ONCE.
- Haiku is default ($0.008-0.012/decision). Sonnet escalation is automatic (~$0.03/decision). Opus is opt-in via route hint, $0.10-0.30/decision — use only for identify-family calls.

## Not doing in v0.1

- Automated trigger-PC discovery (requires disassembly context in DecisionRequest — Phase 3.5 work)
- Memory patches via address arithmetic (Pythia would need PEB base resolution)
- Multi-session correlation (each invocation is fresh)
- Stalker DrCov integration (emulation coverage as context for decisions)

## Reference artifacts

- Pythia repo (external): `C:\Users\Mazum\Desktop\HexCore-Oracle-Agent` (github.com/AkashaCorporation/Project-Pythia)
- Elixir engine (external): `C:\Users\Mazum\Desktop\HexCore-Elixir`
- Azoth runner: `vscode-main/scripts/pythia-azoth-run.mjs`
- Unicorn runner (legacy, less interesting against v6.1): `vscode-main/scripts/pythia-oracle-run.mjs`
- Isolation test: `vscode-main/scripts/elixir-bp-isolation-test.mjs`
- Demo corpus: `C:\Users\Mazum\Desktop\AkashaCorporationMalware\Malware HexCore Defeat\`
  - Source: `Malware HexCore Defeat.cpp` (9 evasion layers E1-E9)
  - Binary: `Malware HexCore Defeat.exe` (v6.1 Echo Mirage)

---

*Project Pythia — Oracle Hook for HexCore. Anthropic Claude Developer Hackathon Apr 21-26 2026. Agent SDK + Claude Haiku/Sonnet/Opus + HexCore Azoth emulation. Issue #17 implementation — branch `feature/oracle-hook-hackathon`.*
