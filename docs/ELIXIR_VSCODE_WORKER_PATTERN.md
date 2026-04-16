# HexCore Elixir — VS Code Worker Pattern (ACG bypass)

## Problem

**HexCore Elixir** (`extensions/hexcore-elixir/`) wraps `unicorn.dll` via a NAPI-RS `.node` (Rust+C++23). The Unicorn emulator's JIT (TCG — QEMU Translation Cache Generator) allocates RWX (Read-Write-Execute) pages at runtime via `VirtualAlloc(PAGE_EXECUTE_READWRITE)` to emit native machine code for guest instruction translation.

The VS Code Extension Host process is an **Electron renderer** process. Electron binaries have **ACG (Arbitrary Code Guard)** — also known as `ProcessDynamicCodePolicy` — enabled in their PE header. ACG prevents the process from allocating new executable memory at runtime. When Unicorn's `uc_emu_start()` tries to allocate an RWX page for its first TCG translation block, Windows denies the request with `STATUS_ACCESS_VIOLATION` (`0xC0000005`).

This crash manifests as:
```
Extension host (LocalProcess pid: XXXXX) terminated unexpectedly. Code: 18446744072635812000, Signal: unknown
```

(`18446744072635812000` = `0xFFFFFFFFC0000005` = access violation exit code, sign-extended to 64-bit)

### Why plain Node.exe works

System Node.js binaries (installed via nvm, nodejs.org, etc.) do NOT have ACG enabled in their PE header. `VirtualAlloc(PAGE_EXECUTE_READWRITE)` succeeds normally, and Unicorn's JIT emulation works.

### What we tried before discovering ACG

1. **C++ exception safety** (`try/catch(...)`, `/EHa` compiler flag) — doesn't catch SEH access violations from the Windows kernel
2. **SEH `__try`/`__except`** — installed correctly (confirmed via `__C_specific_handler` presence in DLL), but VS Code's **Vectored Exception Handlers** (crashpad) intercept the AV before frame-based SEH dispatch runs
3. **TCG cache flush** (`uc_ctl_flush_tb`) — irrelevant; the crash isn't from stale cache, it's from the RWX allocation being denied by ACG
4. **hexcore-debugger toggle** (`hexcore.emulator = "azoth" | "debugger"`) — eliminated hexcore-debugger/unicorn contamination as a variable. The crash still happens with Elixir alone in the process.

### The clue that solved it

`hexcore-debugger/src/pe32WorkerClient.ts` already had this exact problem documented in a code comment:

```typescript
// causing STATUS_ACCESS_VIOLATION (0xC0000005) when Unicorn tries to
// JIT-compile guest code.
// Solution: prefer a system Node.js binary (which does NOT have ACG
// in its PE header) over the Electron binary.
```

The debugger solved it by spawning `pe32Worker` as a child process using a system Node.exe binary.

## Solution

**Run `uc_emu_start()` in a forked child process** using a system Node.exe binary.

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│ VS Code Extension Host (Electron, ACG enabled)          │
│                                                          │
│  extensions/hexcore-elixir/out/extension.js              │
│    ├── hexcore.elixir.version → in-process (no JIT)     │
│    ├── hexcore.elixir.smokeTestHeadless → in-process     │
│    ├── hexcore.elixir.snapshotRoundTripHeadless          │
│    │      → in-process (no emu.run(), no JIT)            │
│    ├── hexcore.elixir.emulateHeadless                    │
│    │      → child_process.fork() ──────────────────┐     │
│    └── hexcore.elixir.stalkerDrcovHeadless          │     │
│           → child_process.fork() ──────────────┐   │     │
└──────────────────────────────────────────────────┼───┼───┘
                                                   │   │
  ┌────────────────────────────────────────────────┼───┼───┐
  │ Worker (system Node.exe, NO ACG)               │   │   │
  │                                                ▼   ▼   │
  │  worker/emulateWorker.js                               │
  │    require('../index.js')  → loads .node + unicorn.dll │
  │    new Emulator() → uc_open (OK, no ACG)               │
  │    emu.load(data) → uc_mem_map + uc_mem_write (OK)     │
  │    emu.run()      → uc_emu_start (OK, RWX alloc works) │
  │    process.send({ result }) → IPC back to parent       │
  └────────────────────────────────────────────────────────┘
```

### Key files

| File | Purpose |
|------|---------|
| `extensions/hexcore-elixir/src/extension.ts` | Extension entry point. Commands that need `emu.run()` delegate to `runInWorker()`. Commands that don't touch JIT (getVersion, smokeTest, snapshotRoundTrip) run in-process. |
| `extensions/hexcore-elixir/worker/emulateWorker.js` | Plain JS worker that runs in the forked Node.exe. Loads `.node`, creates Emulator, runs emulation, sends result via IPC. |
| `extensions/hexcore-elixir/hexcore-elixir.win32-x64-msvc.node` | NAPI-RS native binary containing the Elixir C++23 engine + Rust bridge. |
| `extensions/hexcore-elixir/unicorn.dll` | Unicorn 2.0.1 runtime DLL (34 MB). Must be in the same directory as the `.node`. |

### findSystemNode()

Both `hexcore-elixir/src/extension.ts` and `hexcore-debugger/src/pe32WorkerClient.ts` implement a `findSystemNode()` function that probes for a system Node.exe in this order:

1. `NVM_HOME` — all nvm-windows managed versions
2. `NVM_SYMLINK` — nvm's current active version
3. `C:\Program Files\nodejs\node.exe` — standard installer
4. `C:\Program Files (x86)\nodejs\node.exe`
5. `PATH` directories
6. `/usr/local/bin/node`, `/usr/bin/node` (Linux/macOS)

If no system Node.exe is found, falls back to `process.execPath` with `ELECTRON_RUN_AS_NODE=1` (may still crash on ACG-enabled Electron builds).

### IPC protocol

Parent sends via `worker.send()`:
```json
{
  "op": "emulate" | "stalker",
  "binaryPath": "C:\\path\\to\\binary.exe",
  "maxInstructions": 1000000,
  "verbose": false
}
```

Worker responds via `process.send()`:
```json
{
  "ok": true,
  "kind": "emulate",
  "entry": "0x140002880",
  "stopReason": { "kind": "exit", "address": "0x140002067", "instructionsExecuted": 1000000, "message": "..." },
  "apiCallCount": 22809,
  "apiCalls": [...]
}
```

All `BigInt` values are serialized as `"0x..."` hex strings because `structuredClone` (used by Node IPC) doesn't handle BigInt.

### hexcore.emulator toggle

The setting `hexcore.emulator` (default `"azoth"`) controls which emulation extension activates:

- `"azoth"` → `hexcore-elixir` activates, `hexcore-debugger` returns early from `activate()` without registering commands or loading `hexcore-unicorn`
- `"debugger"` → `hexcore-debugger` activates normally, `hexcore-elixir` returns early

This prevents both extensions from loading `unicorn.dll` simultaneously. While the ACG bypass (worker subprocess) eliminates the crash, the toggle is defense-in-depth and also prevents memory waste from loading two emulation engines.

### For future maintainers / Claude sessions

If you encounter `0xC0000005` crashes in `uc_emu_start` inside the VS Code Extension Host:
1. **Don't try C++ exception handling** — `catch(...)` doesn't catch SEH from ACG denial, even with `/EHa`
2. **Don't try `__try`/`__except`** — VS Code's VEH interceptors run before frame-based SEH
3. **Don't try TCG cache flushing** — the crash is at RWX page allocation, not at TCG cache lookup
4. **DO fork a child process** using a system Node.exe — that's the only path that works

If the crash happens in a NEW extension that uses Unicorn (not Elixir), copy the `findSystemNode()` + worker pattern from `hexcore-elixir/src/extension.ts` or `hexcore-debugger/src/pe32WorkerClient.ts`.
