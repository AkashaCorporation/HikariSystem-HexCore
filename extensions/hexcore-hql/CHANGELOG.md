# Changelog

## 0.3.1 - 2026-08-30

- Expose the exact HXDB target identity so installed scans can fail closed on
  a session/binary mismatch.
- Complete the Disassembler bridge for semantic fact counts, hashes, matched
  facts, proof status, and provenance.
- Use the active target-bound SemanticStore in the IDE and retain the SQLite
  reader for offline scans; fix R33 column names and surface semantic read
  failures instead of silently returning zero facts.

## 0.3.0 - 2026-08-30

- Add recursive typed HXDB conditions for prototypes, type bindings, xrefs,
  indirect targets, summary effects, conflicts, barriers, and provenance.
- Permit semantic-only rules and combine their proof ceiling with HAST adapter
  completeness without converting facts into strings.
- Bind scan cache identity to the exact semantic fact set and generation.
- Complete deterministic Function Atlas versus Ghidra BSim, capa, and FLOSS gates.

## 0.2.0 - 2026-08-28

- Add recursive `all`, `any`, `not`, and `count` conditions while retaining legacy implicit-`all` queries.
- Reject invalid signature kinds, fields, operators, operand indexes, bounds, regexes, and combinator trees.
- Repair the four anti-analysis signatures as alternatives and add branch-level positive/negative fixture gates.
- Replace fabricated confidence with structural completeness, explicit evidence levels, and optional corpus calibration.
- Preserve exact 64-bit HAST integers and addresses; expose unknown, assembly, and adapter-loss metadata.
- Retain clean function scans with identity, node counts, adapter coverage, and signature-set SHA-256.
- Document the Remill-compatible IR contract and the HQL Atlas v1 architecture.
- Pin capa/FLOSS source and executable identities, add watchdog terminal artifacts, and declare normalization policies explicitly.
- Add a deterministic 16-binary corpus contract with exact compiler provenance and byte/semantic repeat gates.
- Add honest capa confusion matrices, FLOSS signal-only evidence import, and canonical rerun verification.
- Add the real Remill-to-HAST Function Atlas gate plus retained x86 verifier and x64 adapter-loss regression artifacts.
