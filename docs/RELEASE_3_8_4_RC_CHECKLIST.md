# HexCore 3.8.4 RC release checklist

Date: 2026-09-04. Candidate identity: **3.8.4-rc.1**, tag **v3.8.4-rc.1**.
Status: preparation, not published. Target: Windows x64 portable.

## Version and promotion policy

Publish the candidate as a GitHub prerelease, qualify the downloaded ZIP, then
promote a deliberately versioned stable 3.8.4 build. A metadata/version change
still requires artifact identity checks. If another candidate is needed, increment
rc.N. Four-part product/package tags such as 3.8.4.1 are not npm SemVer. A stable
hotfix increments the patch version; future roadmap labels can move accordingly.

An absent or unloadable required engine blocks the ZIP; it is not an intentionally
accepted defect to repair after calling the build stable.

## Implemented preparation gates

- [x] Product identity and installer input agree on 3.8.4-rc.1.
- [x] CI checks the requested release tag against product metadata before build.
- [x] Native manifest requires supported primary runtime locations, DLLs and
  Remill semantics, rather than accepting an unrelated DLL as an engine.
- [x] Native loading/CLI-version smoke is isolated and bounded; it runs before
  the full build and against the packaged app before ZIP creation.
- [x] Lazy bodies stay visible and are labeled; Markdown states its preview limit.
- [x] Current limitations and agent documentation distinguish unknown from absent.

## Native release metadata checked on 2026-09-04

| Engine | Required tag | Metadata result |
| --- | --- | --- |
| Capstone | v1.3.6 | Missing; latest listed v1.3.5 |
| Unicorn | v1.3.2 | Missing; latest listed v1.3.1 |
| Remill | v0.5.4 | Missing; latest listed v0.5.1 |
| Souper | v0.2.2 | Missing; latest listed v0.2.0 |
| Elixir | v1.0.4 | Missing; latest listed v1.0.3 |
| LLVM-MC | v1.0.2 | Exists; downloaded artifact not qualified by metadata lookup |
| Better SQLite | v2.0.3 | Exists; downloaded artifact not qualified by metadata lookup |
| Helix | v0.9.3 | Exists; source/addon/release identity still needs reconciliation |
| Revenant | v0.4.0 | Exists; downloaded artifact not qualified by metadata lookup |

## Blocking release work

- [ ] Freeze the exact source/runtime matrix and reconcile canonical/standalone
  sources. Do not copy the entire working tree or generated/backup artifacts.
- [ ] Review native version identities before publishing, especially Helix.
  Do not silently clobber an older published asset with a different build.
- [ ] Verify GitHub publishing permissions and pinned dependency bundles.
- [ ] Publish reviewed standalone sources; build native outputs through the
  HexCore native-prebuild workflow and qualify downloaded assets.
- [ ] Recheck unresolved prior compiler/latency regressions on the current matrix;
  distinguish corrected behavior, explicit limitations and remaining blockers.
- [ ] Consolidate final identity, persistence, cancellation, determinism and
  evidence-status acceptance on the same candidate versions.
- [ ] Exercise one agent-only documented workflow and one UI workflow.
- [ ] Select explicit release files, reconcile READMEs/changelogs and commit without
  unrelated documents, caches, databases, dumps, `.node` backups or attribution footers.
- [ ] Run the full Windows build only in GitHub Actions.
- [ ] Download the candidate ZIP and qualify a clean extraction, including native
  dependencies and the Elixir worker prerequisites on a machine without dev paths.
- [ ] Publish/promote only after the above gates pass.

## npm distribution decision

npm is useful for reusable standalone libraries, not for distributing the full
Code-OSS portable application. Keep it independent of the 3.8.4 release gate.
First qualify one small standalone package in a clean consumer project.

Required checks: owned package scope, explicit files allowlist, runtime install
dependencies, no monorepo-relative installers, native/runtime payloads, dependency
notices, clean tarball install/import, and supported-platform errors. For example,
the current standalone Capstone still lists install-time prebuild-install only as
a devDependency and remains at 1.3.5 while the IDE uses 1.3.6. It is not ready for
an unchanged npm upload.

Use a prerelease dist-tag for experimental npm builds; configure trusted publishing
only after package ownership and the publishing workflow are established. No npm
publication or change to the application's dependency source is part of this prep.

References: [npm versioning](https://docs.npmjs.com/about-semantic-versioning/),
[npm trusted publishing](https://docs.npmjs.com/trusted-publishers/).
