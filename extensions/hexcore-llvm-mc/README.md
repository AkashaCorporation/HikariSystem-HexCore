# hexcore-llvm-mc

LLVM MC-based assembler bindings for Node.js. Part of **HikariSystem HexCore**.

## Features

- Multi-architecture support (x86, x86-64, ARM, ARM64, MIPS, RISC-V, PowerPC, SPARC, etc.)
- Synchronous and asynchronous assembly
- Intel and AT&T syntax support for x86
- CPU-specific code generation
- TypeScript definitions included
- Modern N-API bindings (ABI stable)

## Installation

### Prerequisites

1. **Node.js** 18.0.0 or later
2. **LLVM libraries** (see below)
3. **Build tools**:
   - Windows: Visual Studio 2019+ with C++ workload
   - Linux: GCC/Clang, make
   - macOS: Xcode Command Line Tools

### Installing LLVM Libraries

Download LLVM from the [official releases](https://github.com/llvm/llvm-project/releases) and copy:

- Headers to `deps/llvm/include/`
- Libraries to `deps/llvm/lib/`

#### Windows

Download the LLVM installer or build from source. Copy the required `.lib` files.

#### Linux/macOS

```bash
# Ubuntu/Debian
sudo apt install llvm-dev

# macOS
brew install llvm
```

### Build

```bash
npm install
npm run build
```

## Usage

### Basic Assembly

```javascript
const { LlvmMc, TRIPLE } = require('hexcore-llvm-mc');

// Create assembler for x86-64
const asm = new LlvmMc(TRIPLE.X86_64);

// Assemble a single instruction
const result = asm.assemble('mov rax, rbx');
console.log(result.bytes); // <Buffer 48 89 d8>
console.log(result.size);  // 3

// Clean up
asm.close();
```

### Multiple Instructions

```javascript
const { LlvmMc, TRIPLE } = require('hexcore-llvm-mc');

const asm = new LlvmMc(TRIPLE.X86_64);

const results = asm.assembleMultiple([
    'push rbp',
    'mov rbp, rsp',
    'sub rsp, 0x20',
    'pop rbp',
    'ret'
]);

results.forEach(r => {
    console.log(`${r.statement}: ${r.bytes.toString('hex')}`);
});

asm.close();
```

### Async Assembly

```javascript
const { LlvmMc, TRIPLE } = require('hexcore-llvm-mc');

async function main() {
    const asm = new LlvmMc(TRIPLE.X86_64);

    const result = await asm.assembleAsync('mov rax, 0x12345678');
    console.log(result.bytes);

    asm.close();
}

main();
```

### ARM64 Assembly

```javascript
const { LlvmMc, TRIPLE } = require('hexcore-llvm-mc');

const asm = new LlvmMc(TRIPLE.ARM64);

const result = asm.assemble('mov x0, x1');
console.log(result.bytes); // ARM64 encoding

asm.close();
```

### Using CPU Features

```javascript
const { LlvmMc, TRIPLE, CPU, FEATURES } = require('hexcore-llvm-mc');

// Target specific CPU with AVX2 support
const asm = new LlvmMc(
    TRIPLE.X86_64,
    CPU.X86.SKYLAKE,
    FEATURES.X86.AVX2
);

const result = asm.assemble('vaddps ymm0, ymm1, ymm2');
console.log(result.bytes);

asm.close();
```

### Available Targets

```javascript
const { getTargets, version } = require('hexcore-llvm-mc');

console.log('LLVM Version:', version());
console.log('Available targets:');
getTargets().forEach(t => {
    console.log(`  ${t.name}: ${t.description}`);
});
```

## API Reference

### `LlvmMc` Class

#### Constructor

```typescript
new LlvmMc(triple: string, cpu?: string, features?: string)
```

- `triple`: Target triple (e.g., `"x86_64-unknown-unknown"`)
- `cpu`: Optional CPU name (e.g., `"skylake"`)
- `features`: Optional CPU features (e.g., `"+avx2,+sse4.2"`)

#### Methods

| Method | Description |
|--------|-------------|
| `assemble(code, address?)` | Assemble code synchronously |
| `assembleAsync(code, address?)` | Assemble code asynchronously |
| `assembleMultiple(instructions, startAddress?)` | Assemble multiple instructions |
| `setOption(option, value)` | Set assembler option |
| `getTriple()` | Get target triple |
| `getCpu()` | Get CPU name |
| `getFeatures()` | Get CPU features |
| `close()` | Release resources |

#### Properties

| Property | Description |
|----------|-------------|
| `isOpen` | Whether instance is still open |
| `handle` | Native handle (advanced use) |

### Constants

#### `TRIPLE`

Pre-defined target triples:

- `X86`, `X86_64`, `I386`, `I686`
- `ARM`, `ARMV7`, `ARMV8`, `THUMB`, `THUMBV7`
- `ARM64`, `AARCH64`
- `MIPS`, `MIPSEL`, `MIPS64`, `MIPS64EL`
- `PPC`, `PPC64`, `PPC64LE`
- `RISCV32`, `RISCV64`
- `SPARC`, `SPARCV9`, `SPARC64`
- `SYSTEMZ`, `S390X`
- `WASM32`, `WASM64`
- And more...

#### `SYNTAX`

- `INTEL`: Intel syntax (default for x86)
- `ATT`: AT&T syntax

#### `OPTION`

- `SYNTAX`: Set assembly syntax

### Functions

| Function | Description |
|----------|-------------|
| `version()` | Get LLVM version string |
| `getTargets()` | Get list of available targets |

## Supported Architectures

| Architecture | Triple Examples |
|-------------|-----------------|
| x86 (32-bit) | `i386-unknown-unknown`, `i686-unknown-unknown` |
| x86-64 | `x86_64-unknown-unknown` |
| ARM (32-bit) | `arm-unknown-unknown`, `armv7-unknown-unknown` |
| ARM64 | `aarch64-unknown-unknown` |
| MIPS | `mips-unknown-unknown`, `mips64el-unknown-unknown` |
| RISC-V | `riscv32-unknown-unknown`, `riscv64-unknown-unknown` |
| PowerPC | `powerpc-unknown-unknown`, `powerpc64le-unknown-unknown` |
| SPARC | `sparc-unknown-unknown`, `sparcv9-unknown-unknown` |
| System Z | `systemz-unknown-unknown` |
| WebAssembly | `wasm32-unknown-unknown` |
| BPF | `bpf-unknown-unknown` |

## License

MIT

## Related Projects

- [hexcore-capstone](https://github.com/hikarisystem/hexcore-capstone) - Disassembler bindings
- [hexcore-unicorn](https://github.com/hikarisystem/hexcore-unicorn) - CPU emulator bindings
