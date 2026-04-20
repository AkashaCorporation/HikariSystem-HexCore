# hexcore-souper

LLVM IR superoptimizer for HexCore — powered by [Google Souper](https://github.com/google/souper) and Z3 SMT solving.

Part of the [HikariSystem HexCore](https://github.com/AkashaCorporation/HikariSystem-HexCore) reverse engineering IDE.

## Pipeline

```
machine code → Remill (lift) → Souper (optimize) → Helix (decompile)
```

Souper takes the LLVM IR produced by Remill's lifter and uses SMT solving (Z3) to find semantically equivalent but simpler instruction sequences, improving the quality of Helix decompiler output.

## API

```javascript
const { SouperOptimizer } = require('hexcore-souper');

const optimizer = new SouperOptimizer();

// Synchronous
const result = optimizer.optimize(llvmIrText, {
    maxCandidates: 1000,
    timeoutMs: 30000,
    aggressiveMode: false,
});

// Asynchronous (for large IR)
const result = await optimizer.optimizeAsync(llvmIrText);

console.log(result.success);            // boolean
console.log(result.ir);                 // optimized LLVM IR text
console.log(result.candidatesFound);    // number
console.log(result.candidatesReplaced); // number
console.log(result.optimizationTimeMs); // number

optimizer.close();
```

## Build

Requires pre-compiled dependencies (LLVM 18, Z3, Souper). See `deps/` structure.

```bash
npm run build        # node-gyp rebuild
npm run build:debug  # node-gyp rebuild --debug
npm test             # smoke tests
```

## License

MIT
