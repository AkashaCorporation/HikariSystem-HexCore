# HexCore Keystone

Modern Node.js bindings for [Keystone](https://www.keystone-engine.org/) assembler engine using N-API.

Part of the **HikariSystem HexCore** binary analysis IDE.

## ⚠️ Legacy Mode Notice

This is the **legacy Keystone** (based on LLVM 3.8 from 2016). It is provided for backward compatibility while we develop a modern replacement.

### Current Status:
- ✅ **X86/X64 assembly** - Working
- ⚠️ **ARM/MIPS/etc** - Limited/Not working (requires full LLVM rebuild)
- 🚧 **Modern replacement** - Being developed (LLVM MC Layer)

## Installation

```bash
npm install hexcore-keystone
```

No manual configuration required! The installation script automatically handles build steps.

## Quick Start

```javascript
const { Keystone, ARCH, MODE } = require('hexcore-keystone');

// Create assembler for x86-64 (working)
const ks = new Keystone(ARCH.X86, MODE.MODE_64);

// Assemble code
const result = ks.asm('push rbp; mov rbp, rsp; ret', 0x401000);
console.log('Bytes:', result.bytes);
console.log('Size:', result.size);

ks.close();
```

## API

### `new Keystone(arch, mode)`
Create a new Keystone instance.

- `arch` - Architecture (use `ARCH.*` constants)
- `mode` - Mode (use `MODE.*` constants)

### `ks.asm(code, [address])`
Assemble code synchronously.

### `ks.asmAsync(code, [address])`
Assemble code asynchronously (non-blocking).

### `ks.close()`
Close the handle and free resources.

## Supported Architectures

| Architecture | Status | Notes |
|--------------|--------|-------|
| x86/x64 | ✅ Working | Full support |
| ARM | ⚠️ Limited | Coming in LLVM MC |
| ARM64 | ⚠️ Limited | Coming in LLVM MC |
| MIPS | ❌ Not working | Coming in LLVM MC |
| PowerPC | ❌ Not working | Coming in LLVM MC |

## Future: LLVM MC Layer

A modern replacement using LLVM's MC Layer is being developed by the HexCore team. This will provide:
- Support for all modern architectures
- Up-to-date instruction sets (AVX-512, ARMv9, etc.)
- Better performance and maintainability

## Building from Source

```bash
npm install
npm run build
npm test
```

## Related Projects

- [hexcore-capstone](https://github.com/LXrdKnowkill/hexcore-capstone) - Disassembler (Capstone v5)
- [hexcore-unicorn](https://github.com/LXrdKnowkill/hexcore-unicorn) - CPU Emulator (Unicorn)
- hexcore-llvm-mc (Coming Soon) - Modern assembler

## License

MIT License - Copyright (c) HikariSystem
