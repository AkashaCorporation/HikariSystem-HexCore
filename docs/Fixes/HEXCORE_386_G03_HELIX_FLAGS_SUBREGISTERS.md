# HexCore 3.8.6 G03 - Helix Flags and Subregisters Acceptance

Date: 2026-11-14
Decision: PASS

## Frozen source

```text
Helix baseline: v0.9.4-rc.3 @ 89c55b49de51ffdc81dc35d9f59917961cc819e1
Helix branch: feat/0.9.4-g03-flags-subregisters
Helix accepted commit: 7316040
Product baseline: 461c08d (accepted G02 checkpoint)
Product branch: feat/3.8.6-g03-helix-flags-subregisters
Disassembler: 1.4.79 (unreleased)
Final Windows node SHA-256:
51f18f61f36f3f14365b598a0d53d191cf1add6387f0bb1108d26b9af2f142a5
```

LLVM/MLIR remains 18.1.8. No LLVM 22 migration, release, publication, or
legacy Remill 6/7 quality claim is part of this goal.

## Source-known oracle

```text
source root: C:/Users/Mazum/Desktop/c++/NUCLEO/cpp/New-Version/src
ASM: asm/obf.asm
ASM SHA-256: 883b09ddd0bd3eea7104f29793cfa2f36e5c730bc123a9c32b413bae9045a41b
binary: build/NUCLEO.exe
binary SHA-256: fe8fa1c4553db5435f2d2e21b5d54769d657b57acf59393ac6b385cdf9277e87
entry: 0x140022197
endExclusive: 0x1400221DC
instructions: 29 semantic / 0 padding / 69 bytes
frozen IR SHA-256: a0ad485e37833b995698b80e35f6f5d10f3a954a9e0c81ee52a120994efb8822
```

The exact source contains `xor al, dl`, `dec ecx`/`jnz`,
`dec rsi`/`jnz`, and `not eax`.

## Root causes

1. Current Remill uses an i64 carrier and can encode an EAX/ECX destination as
   `RnWIm` because the physical parent storage is 64-bit. The architectural
   RMW width is encoded separately in `2RnI<T>`. Helix treated the carrier or
   storage width as the operation width.
2. `RecoverVariables` Strategy B skipped partial writes inside structured
   regions. `xor al, dl` therefore became a destructive full RAX assignment.
3. The C-AST rebuilt a shared decrement SSA expression after assigning it to
   the recovered register variable. This emitted `v--; if (v - 1)` and applied
   the decrement twice.
4. EAX write-back used an untyped high-level cast. Without an explicit
   `ZeroExtend` kind, `not eax` became a signed 64-bit `return ~result`.
5. The source build path had three independent validation defects: HAST schema
   constants were hidden by the FlatBuffers feature guard, CTest was enabled
   only in the test subdirectory, and napi-rs output was not staged to the
   package root before smoke testing.

## Implementation

- Parse register-source RMW width independently from parent write storage.
- Use the architectural source width for binary and unary RMW operations.
- Preserve AL/AH/AX parent bits inside structured regions and zero-extend EAX.
- Mark integer extension casts with `CastKind::ZeroExtend`.
- Materialize shared arithmetic SSA values through transparent casts before
  later condition users rebuild them.
- Keep call results outside that materialization rule; the stack-backed direct
  call receiver regression remains unchanged.
- Register CTest at the engine build root and stage the napi-rs Windows node
  before package smoke.
- Regenerate the crate-local napi loader/types from the current 0.9.4-rc.3
  package metadata and exported Rust surface.
- Add the exact current-Remill NUCLEO CRC32 fixture with recorded provenance.

## Before and after

Baseline:

```c
result = (uint64_t)(uint8_t)(int8_t)v12 ^
         (uint64_t)(uint8_t)(int8_t)v6;
v7--;
if (v7 - 1) { ... }
return ~result;
```

G03:

```c
result = result & -256 | (...) & 255;
v7 = (uint64_t)(uint32_t)((int32_t)v7 - 1);
if (v7) { ... }
return (uint64_t)(uint32_t)~(int32_t)result;
```

The outer 64-bit `dec rsi` remains a single `v5--; if (v5)`.

## Required gates

```text
AL/AH/AX/EAX/RAX structured parent matrix: PASS
inc/dec/sub/cmp/test branch matrix at 8/16/32/64 bits: PASS
current Remill NUCLEO CRC32 fixture: PASS
legacy stack-backed direct-call receiver control: PASS
direct full native suite: 417 PASS / 1 optional skip / 0 FAIL
CTest: 417 PASS / 1 optional skip / 0 FAIL (418 registered)
N-API package smoke: PASS
N-API deterministic pseudo-C/HAST: PASS/PASS
```

The optional skip is
`EntryIdentity.FreshNamedFixtureExportsHastThroughCAbi`; it requires an
external fresh-producer fixture and is not silently counted as a pass.

## Integrated acceptance

R4 and R5 used Disassembler 1.4.79 and the exact NUCLEO target:

```text
status: ok / ok
steps: 3 ok, 0 partial, 0 error, 0 skipped (each run)
owner: hikarisystem.hexcore-disassembler@1.4.79
target SHA-256: fe8fa1c4553db5435f2d2e21b5d54769d657b57acf59393ac6b385cdf9277e87
C SHA-256: b549a5dd602a7a6580eb4528202b3acdc6d69b2b89e8b9ed3979b28fa140ca08
normalized IR SHA-256: 0d76b07abf9c8ab073e0dc8c2242a13be34e6a34e6e9bcac26723d8dc920fb94
instruction witness: identical, 29/29
```

The C files are byte-identical. The IR files are identical after removing the
documented `; Generated:` timestamp line.

Direct final-node evidence is also deterministic:

```text
pseudo-C SHA-256: eb406ea3b9e20b5594cf10c8c56786719b0301bc7ae90c081ba660fecab02a74
HAST SHA-256: 80abb110b7c74cc212e854259667e0ed645eec875094a2bc6b780c67e05e1491
```

## Kbase regression control

The seven current stored lifts under
`hexcore-reports-3.8.4-rc.1/fresh-helix-souper-2` were each decompiled twice
through the final node:

```text
kbase_context_mmap.ll
kbase_csf_queue_register.ll
kbase_jit_allocate.ll
kbase_mem_alloc.ll
kbase_mem_commit.ll
kbase_mem_free.ll
kbase_mem_import.ll
```

Result: 7/7 non-empty C, 7/7 non-empty HAST, 7/7 deterministic C/HAST,
and zero causal double-decrement witnesses.

The archived modules preserve a symbolic function name and `; Address:` only;
they predate the strict in-module entry-identity contract. The regression
harness therefore renamed the first function in memory to
`lifted_<address-decimal>` using that frozen header. Original IR files were
not modified, and both original and instrumented hashes are recorded in
`09-kbase-regression/kbase-evidence.json`.

These lifts explicitly report `SemanticStatus: partial` and incomplete
function boundaries. They are a non-crash, determinism and G03-causal
regression control only; the historical B outputs are not treated as semantic
oracles and all seven current outputs differ from them.

## Evidence roots

```text
E:/HexCore-3.8.6-G03-Acceptance
E:/HexCore-3.8.6-G03-Acceptance/09-kbase-regression
E:/HexCore-3.8.5-Closure/trust-e2e-20261101/internal-workspace/
  stable-package-smoke-20261112/reports/g03-nucleo-final-1479-r4
E:/HexCore-3.8.5-Closure/trust-e2e-20261101/internal-workspace/
  stable-package-smoke-20261112/reports/g03-nucleo-final-1479-r5
```

## Honest residuals

- R4/R5 provenance identifies the Disassembler owner/version and target, but
  `analysisSession.engines` is still empty. The node hash is externally frozen
  above; self-contained engine inventory remains a product-provenance follow-up.
- The lift header reports `426/69 bytes` while exact disassembly proves a
  69-byte range. This is producer telemetry inconsistency, not accepted as a
  byte-count fact. Exact range, instruction witness, source and binary hashes
  are the authoritative evidence.
- Confidence remains explicitly the translation/structuring axis. G03 does not
  claim whole-binary discovery, recovered source types, or vulnerability proof.

These residuals are retained for G07 package E2E. They do not invalidate the
source-known G03 semantic oracle.

## Scope statement

No live-in recovery, rotate cleanup, broad SCF cleanup, HAST 1.3, issue
#62/#66/#70 implementation, LLVM/MLIR 22 migration, release, tag, push, or
publication was performed.
