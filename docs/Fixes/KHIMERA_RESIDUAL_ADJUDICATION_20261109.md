# Khimera Residual Adjudication

Date: 2026-11-09

Status: **CLOSED-FOR-1.4.78 / EXPLICIT FOLLOW-UPS**

This document prevents the Khimera comparison from turning Disassembler
`1.4.78` into an unbounded attempt to reproduce every IDA/FLIRT decision.

## R1 - Transitive Noreturn and Terminal INT3

Verdict: **HONEST HOLD / 3.8.6 SIGNATURE-DATAFLOW GOAL**.

IDA marks `0x140001C10` noreturn and excludes its unreachable epilogue. HexCore
retains `[0x140001C10,0x140001C24)` and therefore does not have sufficient
authority to remove the terminal INT3 after calls to it.

The call chain reaches CRT security-failure code and ultimately
`TerminateProcess`, but that API can fail and return. A blanket `call + int3 =
padding` rule would erase real trap semantics in unrelated binaries. Closure
requires one of:

- an authoritative signature/prototype declaring noreturn;
- proven all-path no-return dataflow;
- an independently validated CRT function signature.

The existing partial status is conservative and may ship as a known hold.

## R2 - `_NLG_Notify` Shared Return Block

Verdict: **ACCEPTED MODEL DIFFERENCE**.

IDA owns `[0x140002DC0,0x140002DE1)` and includes the one-byte return at
`0x140002DE0` as a second block. The PE exception directory gives that return
its own unwind-backed owner. HexCore preserves two owners plus the tail edge.

Both models preserve reachability. Merging the owners would discard explicit
unwind identity, so no 1.4.78 change is justified.

## R3 - Three One-Byte End Deltas

Verdict: **ACCEPTED RAW/SEMANTIC DUALITY**.

The remaining one-byte differences are raw unwind/alignment ends. IDA reports
the final semantic instruction end; HexCore retains the half-open pdata range
and exposes semantic/padding counts separately. No instruction or branch is
missing.

## R4 - Twelve IDA Starts Still Absent

Verdict: **CAPABILITY BACKLOG, NOT CFG REGRESSION**.

The remaining starts split into:

- five data-offset/address-taken functions requiring relocation/table evidence;
- one jump-only thunk requiring tail-target discovery;
- six functions without incoming code xrefs, primarily CRT/library bodies that
  IDA discovers through FLIRT or library-specific recognition.

They require bounded relocation/signature lanes. Inventing prologues or scanning
every byte as a function would increase false positives and violate the lazy
analysis contract.

## R5 - Application-vs-CRT Classification

Verdict: **REPORT ASSUMPTION REFUTED**.

The source oracle proves `ct_equal` from the application at `0x140013C10`.
Therefore an address cutoff such as `>= 0x140002000 means CRT` is invalid for
MSVC `/O2 /MT`: COMDAT/function-level linking can distribute application helpers
throughout `.text`.

VM/CPUID heuristics must use reachability, signatures and evidence provenance,
not a target-specific address range. This remains a separate 3.8.6 heuristic
quality goal.

## R6 - Helix SCF, Cast and Type Quality

Verdict: **OUTSIDE DISASSEMBLER 1.4.78**.

SCF carriers, cast noise, ABI/type recovery and source naming remain valid
Helix-quality gaps. They do not invalidate the corrected function starts,
boundaries or instruction-role contracts and stay under the Helix 0.9.5 / HexCore
3.8.6 quality program.

## Release Boundary

Disassembler `1.4.78` is eligible for a HexCore `3.8.5-rc.2` package test with:

- the CFG/direct-call fixes from `KHIMERA_PE_CFG_OWNERSHIP_20261109.md`;
- all residuals above disclosed;
- no claim of FLIRT parity, complete noreturn inference or IDA decompiler parity.
