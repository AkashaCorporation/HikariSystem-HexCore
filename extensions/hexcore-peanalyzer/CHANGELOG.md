# Changelog

## [1.1.3] - 2026-08-27

- Extract embedded `requestedExecutionLevel` and `uiAccess` from bounded PE
  resource data with exact offset and encoding provenance.
- Activate DLL-characteristics mitigation reporting and correct
  `FORCE_INTEGRITY` to Code Integrity instead of mislabeling it as `/GS`.
- Add a Windows filesystem/security capability inventory whose imports remain
  explicitly `signals-only` until the Disassembler supplies owner and data-flow
  evidence.
