# HexCore Capstone

Modern Node.js bindings for [Capstone](https://capstone-engine.org) disassembler engine using N-API.

[![npm version](https://badge.fury.io/js/hexcore-capstone.svg)](https://www.npmjs.com/package/hexcore-capstone)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Modern N-API**: Uses Node-API for binary compatibility across Node.js versions
- **Full Capstone API**: Complete bindings for all Capstone functions
- **TypeScript Support**: Full TypeScript definitions included
- **Multi-Architecture**: x86, x64, ARM, ARM64, MIPS, RISC-V, and more
- **Detail Mode**: Access to operands, registers, groups, and flags
- **Prebuilt Binaries**: No compilation needed for most platforms

## Installation

```bash
npm install hexcore-capstone
```

### Prerequisites

You need `libcapstone` installed on your system:

**Windows:**
```powershell
# Download from https://capstone-engine.org/download.html
# Or use vcpkg: vcpkg install capstone
```

**macOS:**
```bash
brew install capstone
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt install libcapstone-dev
```

**Linux (Fedora):**
```bash
sudo dnf install capstone-devel
```

## Usage

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

// Clean up
cs.close();
```

### With Detail Mode

```javascript
const { Capstone, ARCH, MODE, OPT, OPT_VALUE } = require('hexcore-capstone');

const cs = new Capstone(ARCH.X86, MODE.MODE_64);

// Enable detail mode
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

### ARM Disassembly

```javascript
const { Capstone, ARCH, MODE } = require('hexcore-capstone');

const cs = new Capstone(ARCH.ARM, MODE.ARM);

const armCode = Buffer.from([
    0x04, 0xe0, 0x2d, 0xe5,  // push {lr}
    0x00, 0x00, 0xa0, 0xe1,  // nop
    0x04, 0xf0, 0x9d, 0xe4   // pop {pc}
]);

const insns = cs.disasm(armCode, 0x1000);
for (const insn of insns) {
    console.log(`${insn.mnemonic} ${insn.opStr}`);
}

cs.close();
```

### Check Capstone Version

```javascript
const { version, support, ARCH } = require('hexcore-capstone');

console.log(`Capstone version: ${version().string}`);
console.log(`x86 supported: ${support(ARCH.X86)}`);
console.log(`RISC-V supported: ${support(ARCH.RISCV)}`);
```

## API Reference

### Class: Capstone

#### `new Capstone(arch, mode)`

Create a new disassembler instance.

- `arch` - Architecture constant (e.g., `ARCH.X86`)
- `mode` - Mode constant (e.g., `MODE.MODE_64`)

#### `cs.disasm(code, address, [count])`

Disassemble code buffer.

- `code` - Buffer or Uint8Array containing machine code
- `address` - Base address of the code
- `count` - (Optional) Maximum instructions to disassemble

Returns an array of instruction objects.

#### `cs.setOption(type, value)`

Set a disassembler option.

#### `cs.close()`

Close the handle and free resources.

#### `cs.regName(regId)`, `cs.insnName(insnId)`, `cs.groupName(groupId)`

Get human-readable names for registers, instructions, and groups.

### Constants

- `ARCH` - Architecture constants
- `MODE` - Mode constants
- `OPT` - Option type constants
- `OPT_VALUE` - Option value constants
- `ERR` - Error code constants

## Building from Source

```bash
git clone https://github.com/hikarisystem/hexcore-capstone.git
cd hexcore-capstone
npm install
npm run build
npm test
```

## License

MIT License - Copyright (c) HikariSystem

## Acknowledgments

- [Capstone Engine](https://capstone-engine.org) by Nguyen Anh Quynh
- The Node.js N-API team
