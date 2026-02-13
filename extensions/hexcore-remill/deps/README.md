# hexcore-remill Dependencies

This directory holds pre-built static libraries and headers for Remill, LLVM, and Intel XED.

## Directory Structure

```
deps/
├── remill/
│   ├── include/          # Remill public headers
│   │   └── remill/
│   │       ├── Arch/     # Arch.h, Name.h
│   │       ├── BC/       # IntrinsicTable.h, Lifter.h, Util.h
│   │       └── OS/       # OS.h
│   └── lib/
│       ├── remill.lib    # Windows static lib
│       └── libremill.a   # Linux/macOS static lib
├── llvm/
│   ├── include/          # LLVM public headers
│   │   └── llvm/
│   │       ├── IR/
│   │       ├── Support/
│   │       └── ...
│   └── lib/
│       ├── LLVMCore.lib / libLLVMCore.a
│       ├── LLVMSupport.lib / libLLVMSupport.a
│       ├── LLVMBitReader.lib / libLLVMBitReader.a
│       ├── LLVMBitWriter.lib / libLLVMBitWriter.a
│       ├── LLVMIRReader.lib / libLLVMIRReader.a
│       ├── LLVMIRPrinter.lib / libLLVMIRPrinter.a
│       ├── LLVMAsmParser.lib / libLLVMAsmParser.a
│       ├── LLVMRemarks.lib / libLLVMRemarks.a
│       ├── LLVMBitstreamReader.lib / libLLVMBitstreamReader.a
│       ├── LLVMBinaryFormat.lib / libLLVMBinaryFormat.a
│       ├── LLVMTargetParser.lib / libLLVMTargetParser.a
│       └── LLVMDemangle.lib / libLLVMDemangle.a
└── xed/
    ├── include/          # Intel XED headers
    │   └── xed/
    └── lib/
        ├── xed.lib       # Windows
        └── libxed.a      # Linux/macOS
```

## Building from Source (Windows)

Remill requires `clang-cl` on Windows. Run from a VS Developer Prompt.

**IMPORTANT:** Build Remill against LLVM 18 to match `hexcore-llvm-mc`.
The Remill superbuild can use an external LLVM via `-DUSE_EXTERNAL_LLVM=ON`.

```powershell
# Option A: Use Remill's superbuild (will download its own LLVM)
# NOTE: Ensure the superbuild pulls LLVM 18.x, or use Option B

git clone https://github.com/lifting-bits/remill
cd remill

cmake -G Ninja -S dependencies -B dependencies/build `
  -DCMAKE_C_COMPILER=clang-cl `
  -DCMAKE_CXX_COMPILER=clang-cl
cmake --build dependencies/build

cmake -G Ninja -B build `
  -DCMAKE_PREFIX_PATH:PATH="$PWD/dependencies/install" `
  -DCMAKE_C_COMPILER=clang-cl `
  -DCMAKE_CXX_COMPILER=clang-cl `
  -DCMAKE_BUILD_TYPE=Release `
  -DBUILD_SHARED_LIBS=OFF
cmake --build build

# Option B: Point Remill at the same LLVM 18 used by hexcore-llvm-mc
# This avoids downloading LLVM twice and guarantees version match

cmake -G Ninja -S dependencies -B dependencies/build `
  -DUSE_EXTERNAL_LLVM=ON `
  -DCMAKE_PREFIX_PATH:PATH="<path-to-llvm18-install>" `
  -DCMAKE_C_COMPILER=clang-cl `
  -DCMAKE_CXX_COMPILER=clang-cl
cmake --build dependencies/build

cmake -G Ninja -B build `
  -DCMAKE_PREFIX_PATH:PATH="$PWD/dependencies/install;<path-to-llvm18-install>" `
  -DCMAKE_C_COMPILER=clang-cl `
  -DCMAKE_CXX_COMPILER=clang-cl `
  -DCMAKE_BUILD_TYPE=Release `
  -DBUILD_SHARED_LIBS=OFF
cmake --build build
```

## Building from Source (Linux)

```bash
git clone https://github.com/lifting-bits/remill
cd remill

cmake -G Ninja -S dependencies -B dependencies/build
cmake --build dependencies/build

cmake -G Ninja -B build \
  -DCMAKE_PREFIX_PATH:PATH=$(pwd)/dependencies/install \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF
cmake --build build

# Copy headers and .a files to deps/ following the structure above
```

## Notes

- LLVM version must be 18 (same as hexcore-llvm-mc) to avoid symbol conflicts
- Always build with `BUILD_SHARED_LIBS=OFF` for static linking
- The semantics bitcode files (`*.bc`) must be available at runtime
  (Remill loads them via `LoadArchSemantics`)
- XED is only needed for x86/amd64 architectures
- Total deps size is ~200-400MB (LLVM is large)
- If hexcore-llvm-mc is loaded in the same process, LLVM symbols will
  already be present — the Remill addon must link against the exact same
  LLVM version to avoid ODR violations
