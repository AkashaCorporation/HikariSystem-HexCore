# HexCore Capstone

Modern Node.js bindings for [Capstone](https://capstone-engine.org) disassembler engine using N-API.

[![npm version](https://badge.fury.io/js/hexcore-capstone.svg)](https://www.npmjs.com/package/hexcore-capstone)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

-  **Async API**: Non-blocking `disasmAsync()` for large binaries
-  **Modern N-API**: Binary compatible across Node.js 18+
-  **Zero Dependencies**: Capstone is bundled - just `npm install`
-  **Full TypeScript**: Complete type definitions with JSDoc
-  **Multi-Architecture**: x86, ARM, ARM64, MIPS, PPC, SPARC, M68K, and more
-  **Detail Mode**: Access operands, registers, groups, and flags
-  **ESM + CommonJS**: Works with `import` and `require`

## Installation

```bash
npm install hexcore-capstone
```

No system dependencies required! Capstone is compiled from source automatically.

## Quick Start

### Basic Example

```javascript
const { Capstone, ARCH, MODE } = require('hexcore-capstone');

// Create a disassembler for x86-64
const cs = new Capstone(ARCH.X86, MODE.MODE_64);

// Machine code to disassemble
const code = Buffer.from([
    0x55,                         // push rbp
    0x48, 0x89, 0xe5,             // mov rbp, rsp
    0x48, 0x83, 0xec, 0x20,       // sub rsp, 0x20
    0xc3                          // ret
]);

// Disassemble
const instructions = cs.disasm(code, 0x401000);

for (const insn of instructions) {
    console.log(`0x${insn.address.toString(16)}: ${insn.mnemonic} ${insn.opStr}`);
}

// Output:
// 0x401000: push rbp
// 0x401001: mov rbp, rsp
// 0x401004: sub rsp, 0x20
// 0x401008: ret

cs.close();
```

### Async Disassembly (Recommended for large files)

```javascript
const { Capstone, ARCH, MODE } = require('hexcore-capstone');
const fs = require('fs');

const cs = new Capstone(ARCH.X86, MODE.MODE_64);

// Load a large binary
const largeCode = fs.readFileSync('large_binary.bin');

// Disassemble without blocking the event loop
const instructions = await cs.disasmAsync(largeCode, 0x401000);

console.log(`Disassembled ${instructions.length} instructions`);

cs.close();
```

### ESM Import

```javascript
import { Capstone, ARCH, MODE, OPT, OPT_VALUE } from 'hexcore-capstone';

const cs = new Capstone(ARCH.ARM64, MODE.ARM);
// ...
```

### Detail Mode

```javascript
const { Capstone, ARCH, MODE, OPT, OPT_VALUE } = require('hexcore-capstone');

const cs = new Capstone(ARCH.X86, MODE.MODE_64);

// Enable detail mode for operand info
cs.setOption(OPT.DETAIL, OPT_VALUE.ON);

const code = Buffer.from([0x48, 0x89, 0xc3]); // mov rbx, rax
const insns = cs.disasm(code, 0x1000);

for (const insn of insns) {
    console.log(`${insn.mnemonic} ${insn.opStr}`);

    if (insn.detail) {
        console.log('  Registers read:', insn.detail.regsRead.map(r => cs.regName(r)));
        console.log('  Registers written:', insn.detail.regsWrite.map(r => cs.regName(r)));
        console.log('  Groups:', insn.detail.groups.map(g => cs.groupName(g)));
    }
}

cs.close();
```

## Supported Architectures

| Architecture | Constant | Detail Mode |
|--------------|----------|-------------|
| x86/x64 | `ARCH.X86` | ✅ Full |
| ARM | `ARCH.ARM` | ✅ Full |
| ARM64 | `ARCH.ARM64` | ✅ Full |
| MIPS | `ARCH.MIPS` | ✅ Full |
| PowerPC | `ARCH.PPC` | ✅ Full |
| SPARC | `ARCH.SPARC` | ✅ Full |
| SystemZ | `ARCH.SYSZ` | ✅ Full |
| XCore | `ARCH.XCORE` | ✅ Full |
| M68K | `ARCH.M68K` | ✅ Full |

## API Reference

### Class: Capstone

#### `new Capstone(arch, mode)`
Create a new disassembler instance.

#### `cs.disasm(code, address, [count])`
Disassemble code buffer synchronously. Returns `Instruction[]`.

#### `cs.disasmAsync(code, address, [count])`
Disassemble code buffer asynchronously. Returns `Promise<Instruction[]>`.

> ⚡ **Use `disasmAsync()` for buffers >1MB** to avoid blocking the event loop.

#### `cs.setOption(type, value)`
Set a disassembler option (e.g., enable detail mode).

#### `cs.close()`
Close the handle and free resources.

#### `cs.regName(regId)`, `cs.insnName(insnId)`, `cs.groupName(groupId)`
Get human-readable names.

### Helper Functions

```javascript
const { version, support, ARCH } = require('hexcore-capstone');

console.log(`Capstone version: ${version().string}`);  // "5.0"
console.log(`ARM supported: ${support(ARCH.ARM)}`);    // true
```

## Building from Source

```bash
git clone --recursive https://github.com/LXrdKnowkill/hexcore-capstone.git
cd hexcore-capstone
npm install
npm run build
npm test
```

> **Note:** Use `--recursive` to clone the vendored Capstone submodule.

## Changelog

### v1.1.0
-  Add `disasmAsync()` for non-blocking disassembly
-  Add ESM support via `index.mjs`
-  Add detail mode for PPC, SPARC, SYSZ, XCORE, M68K
-  Enhanced TypeScript definitions with JSDoc

### v1.0.0
-  Initial release with sync API

## License

MIT License - Copyright (c) HikariSystem

## Acknowledgments

- [Capstone Engine](https://capstone-engine.org) by Nguyen Anh Quynh
- The Node.js N-API team
