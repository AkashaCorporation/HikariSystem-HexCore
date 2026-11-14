# HexCore 3.8.6 G01 - x64 ELF Syscall Bridge Acceptance

Date: 2026-11-13
Decision: PASS

## Frozen source

```text
Product baseline: 07805c3b63f64f3360ee3100a781ec7225c1d171
Branch: feat/3.8.6-g01-x64-elf-syscall
Debugger: 2.1.24 (unreleased)
Native Unicorn: unchanged 1.3.2
```

## Root cause

The x64 ELF worker stopped before a `syscall`, but the host callback invoked the
synchronous `LinuxApiHooks.handleSyscall()`. That method read registers and
memory from the host Unicorn instance instead of the isolated worker. The host
then wrote the return into worker RAX and derived the diagnostic name from the
already-overwritten value.

This produced address-shaped syscall numbers followed by repeated unsigned
renderings of `-ENOSYS`.

## Implementation

- Capture the complete x64 register snapshot from the worker before dispatch.
- Dispatch through `handleSyscallAsync(snapshot)`.
- Route reads, mappings, FS/GS writes, return values and stop effects to the
  same worker.
- Record the captured syscall number and PC before RAX is overwritten.
- Render negative trace values as 64-bit two's-complement hexadecimal.
- Propagate `exit`/`exit_group` evidence into headless outcome classification,
  including the exit code and source syscall.

The sync/in-process path remains available and native worker isolation is not
weakened.

## Focused fixture

Source:

```text
extensions/hexcore-debugger/tests/fixtures/x64-syscall-bridge.S
```

Generated ELF:

```text
SHA-256: 4f4e589e821e61bf208a8e76725f1aab7c38363fc38ba61b221ab8c7d2ca42f2
Size: 1,032 bytes
Backend: worker-x64-elf
```

Observed sequence:

```text
sys_12  -> 0x06000000
sys_9   -> 0x20000000
sys_158 -> 0
sys_1   -> 2, stdout "OK"
sys_999 -> -38 / 0xffffffffffffffda
sys_60  -> 0, exit code 7
```

Agent Bridge R2:

```text
executionId: aebea5dc-dad2-4304-a770-9b33becb16bd
pipeline: ok
steps: 1 ok, 0 partial, 0 error
artifact SHA-256: 911ad5c83482902eed4882c1e447195e5d40d9d184f021df1d6f280646adaf20
stopReason.kind: exit
stopReason.exitCode: 7
```

## Regressions

```text
TypeScript compile: PASS
Focused syscall tests: 3/3 PASS
Debugger suite: 119/119 PASS
Packaged PE nominal job: 9/9 PASS
Native SAB tests: 7/7 PASS
Residual x64 worker processes: 0
```

## Real target comparison

Target `runbook`:

```text
SHA-256: 6c6e48564ac88ed1c057f752a25061db39341f94191205d175d813745937254e
```

Before:

```text
5,481 instructions
sys_4590320 -> 0x-26
sys_18446744073709552000 -> 0x-26 (repeated)
```

After:

```text
5,591 instructions
sys_12, sys_12, sys_9, sys_158, sys_218, sys_273, sys_334
negative returns: 0xffffffffffffffda
```

The target now reaches the next explicit compatibility boundary. Syscalls 218
(`set_tid_address`), 273 (`set_robust_list`) and 334 (`rseq`) remain unsupported
and correctly return `-ENOSYS`; the later unmapped read remains a failed
emulation result. Adding those libc-startup syscalls belongs to a separate
bounded runtime goal and is not represented as fixed here.

## Scope statement

This goal changes TypeScript only. No native `.node`, engine release, product
package, public tag or installer was published.
