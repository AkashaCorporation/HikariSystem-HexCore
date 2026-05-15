# Pythia Oracle Job Templates

Job templates for driving HexCore's emulation through **Project Pythia** (Oracle Hook, Issue #17). Copy any of these into your workspace as `.hexcore_job.json` (or a named `{name}.hexcore_job.json`) and the pipeline auto-detects + runs.

Requires `hexcore.oracle.enabled = true` and `hexcore.oracle.pythiaRepoPath` pointing at a Project-Pythia clone. See `.agent/skills/hexcore-pythia-oracle/SKILL.md` for the full operating manual.

## Templates

| File | Purpose | API cost | Runtime |
|---|---|---|---|
| `pythia-probe.hexcore_job.json` | Handshake probe — verifies Pythia spawns + transport is healthy. No emulation. | $0.00 | < 3s |
| `pythia-baseline-compare.hexcore_job.json` | Run WITHOUT Oracle — establishes the "no behavior observed" baseline. Compare side-by-side with the full template. | $0.00 | ~60s (exits early on anti-debug) |
| `pythia-full-emulation.hexcore_job.json` | Run WITH Oracle — Pythia intervenes at known anti-debug trigger PCs so emulation reaches the real payload. | ~$0.05–0.30 | ~2–5min (depends on pause count) |

## Hackathon demo flow

1. Copy `pythia-probe.hexcore_job.json` into workspace → run → verify handshake works.
2. Copy `pythia-baseline-compare.hexcore_job.json` → run → capture the empty emulation result.
3. Copy `pythia-full-emulation.hexcore_job.json` → run → capture the full behavior including beacon URL.
4. Diff the two reports. Demo = that diff.

## Editing a template for a new sample

Three things to change:

1. `file` — absolute path to the sample.
2. `outDir` — where status.json + oracle-session.log + composed report go.
3. `oracle.triggers[]` — PCs where Pythia should pause. If you don't know them, delegate to the `analysis-specialist` subagent with the sample path — it pre-scans via disasm + strings + peanalyzer and returns trigger PCs.

Everything else stays the same — these templates have been tuned for PE64 Windows x64 samples. For ELF x64, switch `arch: "x64"` stays but drop `peanalyzer.analyze` in favor of `elfanalyzer.analyze` and expect tool fallbacks (Linux PEB doesn't exist, PEB-access triggers are moot).
