# hexcore-remill Dependencies

This directory holds pre-built static libraries and headers for Remill, LLVM 18, Intel XED, glog, and gflags.

## Directory Structure

```
deps/
├── remill/
│   ├── include/
│   │   ├── remill/
│   │   │   ├── Arch/     # Arch.h, Name.h, Instruction.h, Context.h
│   │   │   ├── BC/       # IntrinsicTable.h, Lifter.h, Util.h, InstructionLifter.h
│   │   │   ├── OS/       # OS.h
│   │   │   └── Version/  # Version.h
│   │   └── sleigh/       # Ghidra Sleigh decompiler headers
│   ├── lib/
│   │   ├── remill_bc.lib
│   │   ├── remill_os.lib
│   │   ├── remill_arch.lib
│   │   ├── remill_arch_x86.lib
│   │   ├── remill_arch_aarch64.lib
│   │   ├── remill_arch_sparc32.lib
│   │   ├── remill_arch_sparc64.lib
│   │   ├── remill_arch_sleigh.lib
│   │   ├── remill_version.lib
│   │   ├── decomp.lib
│   │   ├── sla.lib
│   │   └── slaSupport.lib
│   └── share/remill/18/semantics/  # .bc bitcode files
├── llvm/
│   ├── include/          # LLVM 18 public headers
│   └── lib/              # 78 LLVM static libs
├── xed/
│   ├── include/xed/      # Intel XED headers
│   └── lib/
│       ├── xed.lib
│       └── xed-ild.lib
├── glog/
│   ├── include/glog/     # Google logging headers
│   └── lib/
│       └── glog.lib
└── gflags/
    ├── include/gflags/   # Google flags headers
    └── lib/
        └── gflags_static.lib
```

## Building from Source (Windows)

Remill requires `clang-cl` on Windows. Build environment:
- VS2022 with MSVC 14.44 toolset
- LLVM/Clang 21 as host compiler
- `vcvarsall.bat x64 -vcvars_ver=14.44`
- `set PATH=C:\Program Files\LLVM\bin;%PATH%`

```powershell
# 1. Build dependencies (LLVM 18 + XED + gflags + glog + googletest)
$env:REMILL_BUILD = "C:\remill-build"
git clone https://github.com/lifting-bits/remill "$env:REMILL_BUILD\remill"

cmake -G Ninja -S "$env:REMILL_BUILD\remill\dependencies" `
  -B "$env:REMILL_BUILD\deps-build" `
  -DCMAKE_INSTALL_PREFIX="$env:REMILL_BUILD\deps-install" `
  -DCMAKE_C_COMPILER=clang-cl `
  -DCMAKE_CXX_COMPILER=clang-cl `
  -DUSE_EXTERNAL_LLVM=OFF
cmake --build "$env:REMILL_BUILD\deps-build"

# 2. Build Remill itself
cmake -G Ninja -S "$env:REMILL_BUILD\remill" `
  -B "$env:REMILL_BUILD\remill-build" `
  -DCMAKE_PREFIX_PATH="$env:REMILL_BUILD\deps-install" `
  -DCMAKE_INSTALL_PREFIX="$env:REMILL_BUILD\remill-install" `
  -DCMAKE_C_COMPILER=clang-cl `
  -DCMAKE_CXX_COMPILER=clang-cl `
  -DCMAKE_BUILD_TYPE=Release `
  -DBUILD_SHARED_LIBS=OFF `
  -DREMILL_BUILD_SPARC32_RUNTIME=OFF `
  -DREMILL_BUILD_SPARC64_RUNTIME=OFF `
  -DREMILL_BUILD_PPC64_RUNTIME=OFF
cmake --build "$env:REMILL_BUILD\remill-build"
cmake --install "$env:REMILL_BUILD\remill-build"

# 3. Copy to deps/ following the structure above
```

## Notes

- LLVM version MUST be 18 (same as hexcore-llvm-mc) to avoid symbol conflicts
- Always build with `BUILD_SHARED_LIBS=OFF` for static linking
- The semantics bitcode files (`*.bc`) must be available at runtime
  (Remill loads them via `LoadArchSemantics`)
- XED is only needed for x86/amd64 architectures
- glog and gflags are required by Remill internals
- Total deps size is ~200-400MB (LLVM is large)
- If hexcore-llvm-mc is loaded in the same process, LLVM symbols will
  already be present — the Remill addon must link against the exact same
  LLVM version to avoid ODR violations
