# Changelog

## 1.0.14 - 2026-09-04

- Present parser agreement as signal-level observations with
  independentCorroboration:false; multiple views of the same binary do not raise
  behavioral confidence. Preserve exact-replica deduplication.
- Prefer producer commands for artifact typing; distinguish file magic matches
  from YARA matches and PE metadata from strings. Never mine valid arbitrary JSON
  as raw IOC text.
- Reject context-identified OID/version fragments, invalid IP literals, bare GUID
  mutex guesses, and invalid/unvalidated wallet candidates from IOC assertions.
  Preserve raw values and rejection reasons; do not guess certificate URL suffixes.
- Lead summaries with analysis coverage and downstream input quality. Show HQL
  evidence levels and semantic fact counts; label empty findings as No-Match Results.

## 1.0.13 - 2026-08-30

- Render type, xref, summary, conflict, barrier, and generation coverage from
  HXDB semantic artifacts.
- List PDB/debug/signature providers and their hashes separately.
- Render binary/input/trace-bound Debugger observations as runtime
  corroboration, never static proof.

## 1.0.12 - 2026-08-28

- Detect HQL artifacts from provenance or their structured command contract.
- Render clean controls, matched functions, adapter loss, signature-set hashes,
  structural completeness, evidence levels, and optional calibrated confidence
  in a dedicated semantic-scan section.
- Keep HQL structural evidence distinct from vulnerability confidence.
