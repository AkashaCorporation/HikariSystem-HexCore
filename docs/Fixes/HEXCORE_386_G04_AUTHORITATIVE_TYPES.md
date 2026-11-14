# HexCore 3.8.6 G04 - Authoritative Type Propagation Acceptance

Date: 2026-11-14

Verdict: **PASS**

Issue authority: `#62 - Propagate DWARF/BTF/PDB types into Helix function signatures and C-AST field access`

## Frozen Checkpoints

- Product base: `8b809dfd7ca7b88ea25ed636503a7a944f236148`
- Product implementation: `40743f9f5688424f60dd61b2ba9f0a56500984de`
- Helix base: `7316040f31e758eba5d7ae2c093b39e48bbb7897`
- Helix implementation: `626503bea2bb7145cb8b032426aaf5955f18e8d6`
- Qualified Helix node SHA-256: `88aa4912d7f9000398ac8311dceebb2b5d40c57942753c4eb76d41339896fa90`

No push, release, publication, LLVM/MLIR upgrade, issue #66, or issue #70 is part of this checkpoint.

## Implemented Contract

1. DWARF/BTF function signatures now enter HXDB as canonical prototypes instead of remaining `functionSignaturesDeferred`.
2. Function ownership is exact: one DWARF boundary or one exact function-table name. Ambiguous names and boundary/table disagreement remain unreconciled.
3. DWARF/BTF parsers retain ABI size and value class independently from display spelling. Kernel aliases such as `u64` retain their canonical typedef and machine width.
4. Unknown debug typedef pointees may preserve proven pointer shape while the pointee remains an explicit opaque declaration. This behavior is opt-in for debug providers only.
5. PE uses `win64`; ELF x64 uses `sysv64`; ARM/AArch64 use their AAPCS contracts. LP64/LLP64 `long` width is selected from target format.
6. Prototype mutations batch generation/invalidation and run one isolated caller-propagation closure. Callback or closure failure yields `partial` with diagnostics.
7. PDB imports use the same batched recomputation contract.
8. HXDB type/prototype conflicts are carried into the Helix context and cannot re-enter through the textual debug fallback.
9. Equal-authority conflict remains visible in C-AST/HAST evidence, but C-AST emits a machine type rather than the selected nominal spelling.
10. HQL hydrates HAST 1.2 declaration evidence, validates origins/capabilities/payloads, and makes conflicted or unresolved functions semantically ineligible.
11. Legacy HAST 1.0/1.1 remains readable. Minor/capability mismatch, missing evidence payload, invalid enum/origin, and unbound authoritative evidence fail closed.
12. Function Atlas now pins the exact G04 producer node.

## Corpora

### PE/PDB

- Corpus: `semantic_benchmark.dll` plus matching PDB.
- Exact debug prototype applied to `bench_plain_copy`.
- Caller closure completed once and the prototype used `win64`.
- Validated PDB types/prototypes remained distinct from signature-database evidence.

### Kernel DWARF

- Input: `mali_kbase.ko`
- SHA-256: `05c1d42b702e275af96e992ee384b33bd67511dbf500e00b088a6cca03ac416d`
- Parsed: 792 structs, 3,864 functions, 1,633 exact boundaries.
- `kbase_mem_alloc` retained seven named parameters, DWARF boundary ownership, pointer shapes, `u64` widths, enum width, and debug provenance.

### Kernel-Target BTF

- Base: the stripped exact kbase module below.
- Deterministic BTF payload SHA-256: `70501f865f89dac3c5ab2c992be8e14fb906d663e0a69b7ce023d39962922b61`
- ELF+BTF fixture SHA-256: `b1ed4a4452a07c6800332216db7b194b9e2a468081c780e2c454647c6cf0c9e8`
- The synthetic metadata describes the real `kbase_mem_alloc` symbol in the kernel module and proves seven-parameter BTF ingestion with 64-bit integers and a 32-bit enum.
- This is explicitly a controlled kernel-target BTF fixture, not a claim that the original module shipped BTF.

### Stripped Negative

- SHA-256: `6c8b92e1aa1f5652372b1b42559b92c934d216769a8c54c38fd439154d139c6a`
- `.debug_*` was removed without modifying the original module.
- No BTF or DWARF authority appeared; the ingestion command rejected the missing payload and function/prototype counts remained unchanged.

## Test Evidence

- Helix: **419/419 PASS**, one intentional C-ABI fixture skip.
- Helix type/HAST focused lane: **44/44 PASS**.
- Disassembler G04 focused lane: **82/82 PASS**.
- Authoritative corpus lane: **3/3 PASS**.
- HQL full suite: **PASS**, including 21 matcher checks, 36 anti-analysis fixture assertions, 60 Atlas cases, 24 benchmark contracts, Function Atlas regression, and 24 ad-hoc query checks.
- Helix/HAST determinism: **10/10 byte-identical**.
  - pseudo-C SHA-256: `ae7261b24ce17fecfb31aded6a7570de8efff0085528414eba366a73391cc011`
  - HAST SHA-256: `e4258e187986d694c49ec341e708b4b935b3cd75fa2acaad602e076f5a2a0c2d`
  - provenance identity: stable target, snapshot, generation, producer, source, strength, authority, and origin ID.

The exploratory monolithic Mocha run reported 935 passes and 32 failures because 140 test files replace the process-global `vscode` module with incompatible mocks. The affected named-step and reliability groups passed independently (13/13 and 29/29). `jobQueueManager.test` requires the VS Code extension-test host and is not a standalone Node gate. This harness limitation is not counted as a G04 product failure.

## Evidence Files

Evidence root: `E:\HexCore-3.8.6-G04-Acceptance`

- `authoritative-corpus-test.log`
- `disassembler-g04-focused-test.log`
- `hql-full-test.log`
- `helix-hast-determinism-10x.json`
- `mali_kbase.stripped-debug.ko`
- `mali_kbase.synthetic-btf.ko`
- `kbase-mem-alloc.btf`
- `build-kernel-btf-fixture.cjs`
- `run-helix-hast-determinism.mjs`

## Scope Boundary

- HAST 1.2 carries declaration and return evidence. A new HAST 1.3 struct-field evidence schema remains a later, separately planned change.
- Named field recovery remains gated by proven layout/offset tests; unknown or conflicting offsets retain generic field/pointer representation.
- The original kbase module contains DWARF but no BTF. The BTF gate therefore uses the controlled payload described above.

## Exit

G04 satisfies its frozen acceptance contract and may close issue #62. The next queued goal is G05.
