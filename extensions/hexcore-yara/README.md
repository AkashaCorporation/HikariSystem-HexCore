# HexCore YARA Scanner

This extension scans file bytes with the HexCore rule evaluator. It does not
establish malware behavior or vulnerability impact. Full upstream YARA language
compatibility is not implied.

## 3.8.5 Development: Qualified Scoring

`threatScore` retains its compatibility name, but represents the maximum priority
of applicable, non-advisory rule matches. Zero means no scored matches, not clean.

Matches remain in the output when excluded from that score:

- `score`: the rule's original priority;
- `scoreContribution`: zero for advisory matches;
- `advisoryOnly` and `advisoryReason`: the exclusion decision;
- `scoring`: scored/advisory counts, advisory maximum and scoring policy;
- `binaryContext`: detected format, architecture, executable section count and
  byte-scan scope. ZIP/VDEX member semantics remain unassessed.

Optional rule metadata, using string values:

- `advisory_only = "true"` excludes a rule from primary scoring everywhere.
- `advisory_reason = "..."` explains that policy.
- `formats = "pe,elf"` restricts applicable file formats.
- `architecture = "x86"` restricts architecture; unknown does not satisfy it.
  The existing x86 and arm family aliases include their 64-bit counterparts.
- `requires_executable = "true"` requires collected, extent-qualified executable
  evidence to satisfy the supported rule condition. Unknown extents and limited
  cardinality evidence remain advisory; the display preview is not the evidence set.

Bundled hash constants, common encoding alphabets and generic virtualization
strings are advisory observations. They are not promoted to API hashing,
obfuscation or VM-detection behavior merely by their presence.

APK/DEX recognition here only qualifies byte matches. There is no Android
component model, archive-member analysis or JADX integration in this extension.
