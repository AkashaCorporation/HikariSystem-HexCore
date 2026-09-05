# hexcore-remill

Modern N-API bindings for [Remill](https://github.com/lifting-bits/remill) — lifts machine code to LLVM IR bitcode.

Part of [HikariSystem HexCore](https://github.com/AkashaCorporation/HikariSystem-HexCore).

## Supported Architectures

| Architecture | Variants |
|---|---|
| x86 (32-bit) | `x86`, `x86_avx`, `x86_avx512` |
| x86-64 | `amd64`, `amd64_avx`, `amd64_avx512` |
| AArch64 | `aarch64` |
| SPARC | `sparc32` |

`ARCH.SPARC64` remains exported for source compatibility, but construction is
rejected because this package does not ship SPARC64 semantics.

## Usage

```javascript
const { RemillLifter, ARCH } = require('hexcore-remill');

const lifter = new RemillLifter(ARCH.AMD64);

// push rbp; mov rbp, rsp; pop rbp; ret
const code = Buffer.from([0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3]);
const result = lifter.liftBytes(code, 0x401000);

if (result.success) {
  console.log(result.ir);           // LLVM IR text
  console.log(result.bytesConsumed); // 6
  console.log(result.semanticCoverage); // 1 for this scalar sample
}

lifter.close();
```

### Async (non-blocking)

```javascript
const result = await lifter.liftBytesAsync(largeBuffer, 0x140001000);
```

### Windows ABI context

```javascript
const lifter = new RemillLifter(ARCH.AMD64, OS.WINDOWS);
```

## API

### `new RemillLifter(arch, os?)`

Create a lifter for the given architecture. Loads the Remill semantics module.

- `arch` — Architecture name (use `ARCH` constants)
- `os` — OS name for ABI context (optional, defaults to `'linux'`)

### `lifter.liftBytes(code, address) → LiftResult`

Synchronous lift. Decodes and lifts instructions from the buffer.

Pass an optional third `options` object to control lift limits and IR shape.
Named semantic helper calls are preserved by default for downstream decompiler
compatibility. Set `inlineSemantics: true` only when you explicitly want the
semantic helper bodies inlined into the lifted function.

### `lifter.liftBytesAsync(code, address) → Promise<LiftResult>`

Async lift in a worker thread. Use for large buffers (>64KB).

### Non-contiguous control flow

`entryAddress` may identify a logical function entry inside a larger buffer.
With `reachableOnly: true`, the lifter decodes the address-preserving window
but emits only instructions reachable from that entry. This is used for
callfuscation, where one function is scattered across an executable section.

### `LiftResult`

```typescript
{
  success: boolean;
  ir: string;           // LLVM IR text
  error: string;        // Error message if !success
  address: number;      // Start address
  bytesConsumed: number; // Bytes consumed from input
  decodedInstructions: number; // Before LLVM optimization
  liftedInstructions: number;  // Concrete Remill semantics
  unsupportedInstructions: number; // HandleUnsupported fallbacks
  decodeFailureInstructions: number; // Decode, ISEL, or semantic-lifter failures
  semanticCoverage: number; // lifted / semantic attempts, range 0..1
  unsupportedOpcodes: Record<string, number>;
}
```

Semantic counts are collected before LLVM optimization. This prevents dead-code
elimination from making an incomplete lift appear complete; consequently, the
unsupported count can be higher than the surviving `HandleUnsupported` calls in
the final textual IR.

### `RemillLifter.getSupportedArchs() → string[]`

Returns list of supported architecture names.

## Building from Source

```bash
# Prerequisites: Node 20.17+ (or 22.9+), LLVM 18, CMake 3.21+,
# Ninja, clang-cl (Windows)

# Build Remill deps first (see deps/README.md)
npm run build
npm test
```

## Dependencies

- [Remill 6.0.1](https://github.com/lifting-bits/remill/releases/tag/v6.0.1)
  (`0e324aee8c67a63ec759ef379dcfafa0b3cb1448`) — static library
- [Sleigh](https://github.com/lifting-bits/sleigh) — static library and public headers
- [LLVM 18](https://llvm.org/) — static libraries (Core, Support, BitReader, BitWriter, IRReader, etc.)
- [Intel XED](https://github.com/intelxed/xed) — x86 instruction decoder (used by Remill)

**Important:** Must use the same LLVM version as `hexcore-llvm-mc` (currently LLVM 18)
to avoid symbol conflicts when both are loaded in the same process.

## License

MIT — Copyright (c) HikariSystem
