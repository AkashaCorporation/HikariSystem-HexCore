# HexCore Unicorn

Modern Node.js bindings for the [Unicorn Engine](https://www.unicorn-engine.org/) CPU emulator using N-API.

Part of the **HikariSystem HexCore** binary analysis IDE.

## Features

- Full Unicorn Engine API support
- Modern N-API bindings (ABI stable)
- Async emulation with Promises
- TypeScript definitions included
- Hook system with ThreadSafeFunction
- Support for all architectures: x86, ARM, ARM64, MIPS, SPARC, PPC, M68K, RISC-V
- Context save/restore
- Memory mapping and protection

## Installation

```bash
npm install hexcore-unicorn
```

**Note:** You need to have the Unicorn library installed on your system or place the library files in the `deps/unicorn/` directory.

### Building from source

```bash
git clone https://github.com/LXrdKnowkill/hexcore-unicorn.git
cd hexcore-unicorn
npm install
npm run build
```

## Quick Start

```javascript
const { Unicorn, ARCH, MODE, PROT, X86_REG } = require('hexcore-unicorn');

// Create x86-64 emulator
const uc = new Unicorn(ARCH.X86, MODE.MODE_64);

// Map memory for code and stack
uc.memMap(0x1000n, 0x1000, PROT.ALL);  // Code
uc.memMap(0x2000n, 0x1000, PROT.ALL);  // Stack

// Write x86-64 code: mov rax, 0x1234; ret
const code = Buffer.from([
    0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00,  // mov rax, 0x1234
    0xC3                                        // ret
]);
uc.memWrite(0x1000n, code);

// Set up stack pointer
uc.regWrite(X86_REG.RSP, 0x2800n);

// Run emulation
uc.emuStart(0x1000n, 0x1008n);

// Read result
const rax = uc.regRead(X86_REG.RAX);
console.log(`RAX = 0x${rax.toString(16)}`);  // RAX = 0x1234

// Clean up
uc.close();
```

## API Reference

### Creating an Emulator

```javascript
const uc = new Unicorn(arch, mode);
```

- `arch`: Architecture constant (e.g., `ARCH.X86`, `ARCH.ARM64`)
- `mode`: Mode constant (e.g., `MODE.MODE_64`, `MODE.UC_MODE_ARM`)

### Memory Operations

```javascript
// Map memory
uc.memMap(address, size, permissions);

// Read memory
const buffer = uc.memRead(address, size);

// Write memory
uc.memWrite(address, buffer);

// Unmap memory
uc.memUnmap(address, size);

// Change permissions
uc.memProtect(address, size, permissions);

// Get mapped regions
const regions = uc.memRegions();
// Returns: [{ begin: bigint, end: bigint, perms: number }, ...]
```

### Register Operations

```javascript
// Read register
const value = uc.regRead(X86_REG.RAX);

// Write register
uc.regWrite(X86_REG.RAX, 0x1234n);

// Batch operations
const values = uc.regReadBatch([X86_REG.RAX, X86_REG.RBX]);
uc.regWriteBatch([X86_REG.RAX, X86_REG.RBX], [0x1111n, 0x2222n]);
```

### Emulation Control

```javascript
// Synchronous emulation
uc.emuStart(begin, until, timeout, count);

// Asynchronous emulation
await uc.emuStartAsync(begin, until, timeout, count);

// Stop emulation (from hook)
uc.emuStop();
```

### Hooks

```javascript
// Code execution hook
const handle = uc.hookAdd(HOOK.CODE, (address, size) => {
    console.log(`Executing: 0x${address.toString(16)}`);
});

// Memory access hook
uc.hookAdd(HOOK.MEM_WRITE, (type, address, size, value) => {
    console.log(`Memory write at 0x${address.toString(16)}`);
});

// Interrupt hook
uc.hookAdd(HOOK.INTR, (intno) => {
    console.log(`Interrupt: ${intno}`);
});

// Remove hook
uc.hookDel(handle);
```

### Context Management

```javascript
// Save context
const ctx = uc.contextSave();

// Restore context
uc.contextRestore(ctx);

// Free context
ctx.free();
```

### Utility Functions

```javascript
// Get version
const ver = version();
console.log(`Unicorn ${ver.string}`);

// Check architecture support
if (archSupported(ARCH.ARM64)) {
    console.log('ARM64 is supported');
}

// Get error message
const msg = strerror(errorCode);
```

## Constants

### Architectures (ARCH)

- `ARCH.X86` - x86/x64
- `ARCH.ARM` - ARM
- `ARCH.ARM64` - ARM64 (AArch64)
- `ARCH.MIPS` - MIPS
- `ARCH.SPARC` - SPARC
- `ARCH.PPC` - PowerPC
- `ARCH.M68K` - Motorola 68K
- `ARCH.RISCV` - RISC-V

### Modes (MODE)

- `MODE.MODE_16` - 16-bit mode
- `MODE.MODE_32` - 32-bit mode
- `MODE.MODE_64` - 64-bit mode
- `MODE.LITTLE_ENDIAN` - Little-endian
- `MODE.BIG_ENDIAN` - Big-endian

### Memory Permissions (PROT)

- `PROT.NONE` - No permissions
- `PROT.READ` - Read permission
- `PROT.WRITE` - Write permission
- `PROT.EXEC` - Execute permission
- `PROT.ALL` - All permissions

### Hook Types (HOOK)

- `HOOK.CODE` - Code execution
- `HOOK.BLOCK` - Basic block
- `HOOK.INTR` - Interrupts
- `HOOK.MEM_READ` - Memory read
- `HOOK.MEM_WRITE` - Memory write
- `HOOK.MEM_FETCH` - Memory fetch

### Registers

- `X86_REG` - x86/x64 registers (RAX, RBX, RCX, etc.)
- `ARM_REG` - ARM registers (R0-R12, SP, LR, PC, etc.)
- `ARM64_REG` - ARM64 registers (X0-X30, SP, PC, etc.)
- `MIPS_REG` - MIPS registers (V0, A0-A3, T0-T9, etc.)

## TypeScript

Full TypeScript definitions are included:

```typescript
import { Unicorn, ARCH, MODE, PROT, X86_REG, version } from 'hexcore-unicorn';

const uc = new Unicorn(ARCH.X86, MODE.MODE_64);
const rax: bigint | number = uc.regRead(X86_REG.RAX);
```

## Requirements

- Node.js >= 18.0.0
- Unicorn Engine library

### Installing Unicorn

**Windows:**
Download from [Unicorn releases](https://github.com/unicorn-engine/unicorn/releases) and place `unicorn.dll` and `unicorn.lib` in `deps/unicorn/`.

**Linux:**
```bash
sudo apt install libunicorn-dev
# Or build from source
```

**macOS:**
```bash
brew install unicorn
```

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Related Projects

- [hexcore-capstone](https://www.npmjs.com/package/hexcore-capstone) - Capstone disassembler bindings
- [hexcore-keystone](https://www.npmjs.com/package/hexcore-keystone) - Keystone assembler bindings
- [Unicorn Engine](https://www.unicorn-engine.org/) - The underlying emulation framework
