# hexcore-remill

Modern N-API bindings for [Remill](https://github.com/lifting-bits/remill) — lifts machine code to LLVM IR bitcode.

Part of [HikariSystem HexCore](https://github.com/LXrdKnowkill/HikariSystem-HexCore).

## Supported Architectures

| Architecture | Variants |
|---|---|
| x86 (32-bit) | `x86`, `x86_avx`, `x86_avx512` |
| x86-64 | `amd64`, `amd64_avx`, `amd64_avx512` |
| AArch64 | `aarch64` |
| SPARC | `sparc32`, `sparc64` |

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

### `lifter.liftBytesAsync(code, address) → Promise<LiftResult>`

Async lift in a worker thread. Use for large buffers (>64KB).

### `LiftResult`

```typescript
{
  success: boolean;
  ir: string;           // LLVM IR text
  error: string;        // Error message if !success
  address: number;      // Start address
  bytesConsumed: number; // Bytes consumed from input
}
```

### `RemillLifter.getSupportedArchs() → string[]`

Returns list of supported architecture names.

## Building from Source

```bash
# Prerequisites: LLVM 15+, CMake 3.21+, Ninja, clang-cl (Windows)

# Build Remill deps first (see deps/README.md)
npm run build
npm test
```

## Dependencies

- [Remill](https://github.com/lifting-bits/remill) — static library
- [LLVM 18](https://llvm.org/) — static libraries (Core, Support, BitReader, BitWriter, IRReader, etc.)
- [Intel XED](https://github.com/intelxed/xed) — x86 instruction decoder (used by Remill)

**Important:** Must use the same LLVM version as `hexcore-llvm-mc` (currently LLVM 18)
to avoid symbol conflicts when both are loaded in the same process.

## License

MIT — Copyright (c) HikariSystem
