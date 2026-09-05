# HexCore 3.8.4 RC release checklist

Updated: 2026-09-05. Candidate: **3.8.4-rc.2**, tag **v3.8.4-rc.2**.
Target: Windows x64 portable. Native engine versions are unchanged from RC.1.

## Promotion policy

Keep candidates as prereleases. Qualify a clean extraction of the generated ZIP
before publishing a deliberately versioned stable 3.8.4 distribution. A source
smoke pass does not qualify a different packaged artifact. Missing or unloadable
required engines block packaging. Updates remain manual; Linux is experimental.

## Completed qualification

- [x] Canonical/standalone source reconciliation and required native releases.
- [x] Native Prebuilds run 33944178833 and RC.1 Installer run 33944520715 succeeded.
- [x] RC.1 extraction: 22 native artifacts across nine engines match the manifest.
- [x] Operational smokes: managed C#/IL, malformed managed rejection, static
  extractors, snapshots, breakpoints, bounded emulation, HQL controls and prototype
  persistence. Doctor reached 128 ready / zero missing after activation.
- [x] Manual/autorun deduplication passed focused and development-UI checks.
- [x] Logical function ownership survives preamble removal; absent semantic
  endpoints remain unknown/partial rather than claiming zero decoded bytes.
- [x] Fresh HXDB binding: 65 focused tests passed. Four separate harness processes
  preserved the session, prototype, generation binding and materialized-body hash.

## Native release matrix

| Engine | Required release |
| --- | --- |
| Capstone | v1.3.6 |
| Unicorn | v1.3.2 |
| LLVM-MC | v1.0.2 |
| Better SQLite | v2.0.3 |
| Remill | v0.5.4 |
| Souper | v0.2.2 |
| Helix | v0.9.4-rc.1 |
| Elixir | v1.0.4 |
| Revenant | v0.4.0 |

These releases supplied the qualified RC.1 extraction. RC.2 still verifies
native loading and records hashes in its own packaged engine manifest.

## RC.2 delivery gates

- [ ] Commit only reviewed source, tests and public documentation; exclude private
  reports, corpora, sessions, generated dumps and local build caches.
- [ ] Confirm source CI on the exact RC.2 commit.
- [ ] Dispatch Build Installer with version=v3.8.4-rc.2 and build_linux=false.
- [ ] Download the resulting ZIP and verify product/native identities, fresh HXDB
  edit/reopen and manual/autorun behavior on that extraction.
- [ ] Publish the candidate artifact and record its SHA-256.
- [ ] Promote stable only after packaged acceptance and explicit stable identity.

## Explicit limitations

Helix's calculator baseline remains semantically partial, including unresolved
flags, SIMD/width expressions and placeholders. This is not claimed fixed by
RC.2. Missing lift endpoints remain unknown. Doctor reports registration, not
universal behavior correctness. A zero-stream minidump smoke does not replace a
realistic crash-dump corpus. Elixir's system-Node worker dependency and PDB tool
availability require qualification on the intended host.

See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) and
[HEXCORE_AUTOMATION.md](HEXCORE_AUTOMATION.md) for contracts and supported scope.

## npm

npm library distribution is independent of the portable release. Qualify tarball
contents, install-time dependencies, native payloads and clean consumer imports
before a separate npm publication. This RC workflow does not publish npm packages.
