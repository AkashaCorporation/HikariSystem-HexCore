# Changelog

## [1.3.3] - 2026-08-11

- Add bounded deobfuscation result budgets and optional confidence/high-signal
  gates without changing the default extraction behavior.
- Add an opt-in, evidence-preserving hex to ASCII to Base64 to JSON transform
  chain with offsets, previews, SHA-256, JSON validity, and budget accounting.
- Keep scoring properties deterministic at their decimal boundary and ensure
  the backward-compatibility generator excludes intentionally penalized
  low-diversity inputs.
