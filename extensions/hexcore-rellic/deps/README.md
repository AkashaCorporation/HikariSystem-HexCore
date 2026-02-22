# hexcore-rellic Dependencies

This directory holds pre-built static libraries and headers for Rellic, LLVM 18, Clang 18, and Z3.

## Directory Structure

```
deps/
├── llvm/
│   ├── include/          # LLVM 18.1.8 public headers (same as hexcore-remill)
│   └── lib/              # LLVM 18.1.8 static libs
├── clang/
│   ├── include/          # Clang 18.1.8 headers
│   │   └── clang/
│   │       ├── AST/      # ASTContext.h, Decl.h, Expr.h, Stmt.h, Type.h, ...
│   │       ├── Basic/    # Diagnostic.h, SourceManager.h, TargetInfo.h, ...
│   │       ├── Frontend/ # CompilerInstance.h, ASTUnit.h, ...
│   │       ├── Lex/      # Preprocessor.h, Token.h, ...
│   │       ├── Parse/    # Parser.h, ...
│   │       ├── Sema/     # Sema.h, ...
│   │       └── ...
│   └── lib/              # Clang 18.1.8 static libs
│       ├── clangAST.lib          (or libclangAST.a on Linux)
│       ├── clangBasic.lib
│       ├── clangLex.lib
│       ├── clangSema.lib
│       ├── clangFrontend.lib
│       ├── clangSerialization.lib
│       ├── clangDriver.lib
│       ├── clangParse.lib
│       ├── clangEdit.lib
│       └── clangAnalysis.lib
├── z3/
│   ├── include/          # Z3 4.12+ headers
│   │   ├── z3.h
│   │   ├── z3++.h
│   │   └── z3_api.h
│   └── lib/
│       └── libz3.lib            (or libz3.a on Linux)
└── rellic/
    ├── include/          # Rellic headers (ported to LLVM 18)
    │   └── rellic/
    │       ├── AST/      # GenerateAST, ASTBuilder, ...
    │       ├── BC/       # Passes, Util, ...
    │       └── ...
    └── lib/
        └── rellic.lib           (or librellic.a on Linux)
```

## Building from Source

### Prerequisites

- VS2022 with MSVC 14.44 toolset (Windows)
- LLVM/Clang 21 as host compiler
- CMake 3.21+
- Ninja build system
- `vcvarsall.bat x64 -vcvars_ver=14.44`
- `set PATH=C:\Program Files\LLVM\bin;%PATH%`

### 1. LLVM 18.1.8 (reuse from hexcore-remill)

The LLVM headers and libs are identical to those used by hexcore-remill.
Copy `deps/llvm/` from the hexcore-remill standalone repo, or build from
the same LLVM 18.1.8 source tree.

### 2. Clang 18.1.8

Clang is built from the same LLVM 18.1.8 source tree. The key is to enable
only the libraries needed by Rellic (AST manipulation, not full compiler).

```powershell
$env:LLVM_SRC = "C:\llvm-project-18.1.8"

cmake -G Ninja -S "$env:LLVM_SRC\clang" `
  -B "C:\clang-build" `
  -DCMAKE_C_COMPILER=clang-cl `
  -DCMAKE_CXX_COMPILER=clang-cl `
  -DCMAKE_BUILD_TYPE=Release `
  -DBUILD_SHARED_LIBS=OFF `
  -DLLVM_DIR="$env:LLVM_SRC\build\lib\cmake\llvm" `
  -DCMAKE_INSTALL_PREFIX="C:\clang-install"

cmake --build "C:\clang-build" --target `
  clangAST clangBasic clangLex clangSema clangFrontend `
  clangSerialization clangDriver clangParse clangEdit clangAnalysis

# Copy headers and libs to deps/clang/
```

### 3. Z3 4.12+

```powershell
git clone https://github.com/Z3Prover/z3.git -b z3-4.12.6
cd z3

cmake -G Ninja -S . -B build `
  -DCMAKE_C_COMPILER=clang-cl `
  -DCMAKE_CXX_COMPILER=clang-cl `
  -DCMAKE_BUILD_TYPE=Release `
  -DBUILD_SHARED_LIBS=OFF `
  -DZ3_BUILD_LIBZ3_SHARED=OFF `
  -DCMAKE_INSTALL_PREFIX="C:\z3-install"

cmake --build build
cmake --install build

# Copy headers and lib to deps/z3/
```

### 4. Rellic (ported to LLVM 18)

The Rellic source is ported from LLVM 16 to LLVM 18.1.8 in the standalone
repo. Key changes:
- Legacy Pass Manager → New Pass Manager (PassBuilder, ModulePassManager)
- Typed Pointers → Opaque Pointers (PointerType::get(context, 0))
- Updated renamed/removed LLVM 16 APIs to LLVM 18 equivalents

```powershell
# Build from the ported source in the standalone repo
cmake -G Ninja -S rellic-src `
  -B rellic-build `
  -DCMAKE_C_COMPILER=clang-cl `
  -DCMAKE_CXX_COMPILER=clang-cl `
  -DCMAKE_BUILD_TYPE=Release `
  -DBUILD_SHARED_LIBS=OFF `
  -DLLVM_DIR="deps/llvm/lib/cmake/llvm" `
  -DClang_DIR="deps/clang/lib/cmake/clang" `
  -DZ3_DIR="deps/z3/lib/cmake/z3"

cmake --build rellic-build
# Copy headers and lib to deps/rellic/
```

## Packing Dependencies

Use `_pack_deps.py` to create a distributable zip:

```powershell
python _pack_deps.py
# Creates: rellic-deps-win32-x64.zip (or rellic-deps-linux-x64.zip)
```

Upload as a release asset to `LXrdKnowkill/hexcore-rellic`.
CI downloads this zip during prebuild generation.

## 5. Building the Rellic Static Library

The ported Rellic passes are built as a static library using the
`CMakeLists.txt` in the extension root. This produces `rellic.lib`
(Windows) or `librellic.a` (Linux) which is then linked into the
N-API module by `binding.gyp`.

### Automated Build (recommended)

```powershell
# Full pipeline: configure → build → install → verify
python _build_rellic.py

# With custom LLVM build dir
python _build_rellic.py --llvm-build C:\llvm-18-build

# Only verify installed library
python _build_rellic.py --verify

# Only write reference IR for manual testing
python _build_rellic.py --validate-ir
```

### Manual Build

```powershell
# Windows (from VS Developer Command Prompt)
cmake -G Ninja -S . -B build-rellic ^
  -DCMAKE_C_COMPILER=clang-cl ^
  -DCMAKE_CXX_COMPILER=clang-cl ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DBUILD_SHARED_LIBS=OFF ^
  -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded ^
  -DLLVM_DIR=deps/llvm/lib/cmake/llvm ^
  -DClang_DIR=deps/clang/lib/cmake/clang ^
  -DZ3_DIR=deps/z3/lib/cmake/z3

cmake --build build-rellic --target rellic

# Copy to deps/rellic/
mkdir deps\rellic\include\rellic
mkdir deps\rellic\lib
copy src\rellic_passes.h deps\rellic\include\rellic\
copy src\rellic_decompile_pipeline.h deps\rellic\include\rellic\
copy src\rellic_opaque_ptr.h deps\rellic\include\rellic\
copy src\rellic_llvm_compat.h deps\rellic\include\rellic\
copy build-rellic\rellic.lib deps\rellic\lib\
```

```bash
# Linux
cmake -G Ninja -S . -B build-rellic \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_C_FLAGS="-fPIC" \
  -DCMAKE_CXX_FLAGS="-fPIC -fexceptions" \
  -DLLVM_DIR=deps/llvm/lib/cmake/llvm \
  -DClang_DIR=deps/clang/lib/cmake/clang \
  -DZ3_DIR=deps/z3/lib/cmake/z3

cmake --build build-rellic --target rellic

# Copy to deps/rellic/
mkdir -p deps/rellic/include/rellic deps/rellic/lib
cp src/rellic_passes.h src/rellic_decompile_pipeline.h \
   src/rellic_opaque_ptr.h src/rellic_llvm_compat.h \
   deps/rellic/include/rellic/
cp build-rellic/librellic.a deps/rellic/lib/
```

### Source Files in the Static Library

| File | Description |
|------|-------------|
| `rellic_passes.cpp` | 9 Rellic passes ported to LLVM 18 new Pass Manager |
| `rellic_decompile_pipeline.cpp` | Pipeline builder wiring all passes |
| `rellic_opaque_ptr.cpp` | Opaque pointer migration utilities |
| `rellic_llvm_compat.cpp` | LLVM 16→18 API compatibility layer |

**NOT included** (N-API specific, built by `binding.gyp`):
- `rellic_wrapper.cpp`
- `main.cpp`

## Build Validation

### CRT Verification (Windows)

After building, verify that the library uses `/MT` (static CRT):

```powershell
python _build_rellic.py --verify

# Or manually:
dumpbin /directives deps\rellic\lib\rellic.lib | findstr DEFAULTLIB
# Expected: /DEFAULTLIB:LIBCMT (NOT MSVCRT)
```

### Symbol Verification

Key symbols that must be present in the built library:

| Symbol | Source |
|--------|--------|
| `GenerateASTPass::run` | `rellic_passes.cpp` |
| `buildRellicPipeline` | `rellic_decompile_pipeline.cpp` |
| `runRellicPipeline` | `rellic_decompile_pipeline.cpp` |
| `getPointeeType` | `rellic_opaque_ptr.cpp` |
| `getOrInsertRellicFunction` | `rellic_llvm_compat.cpp` |
| `createFunctionType` | `rellic_llvm_compat.cpp` |

```powershell
# Windows
dumpbin /symbols deps\rellic\lib\rellic.lib | findstr "buildRellicPipeline"

# Linux
nm --defined-only deps/rellic/lib/librellic.a | grep "buildRellicPipeline"
```

### Reference IR Validation

Once the full N-API module is built, validate decompilation with this
reference IR:

```llvm
define i32 @add(i32 %a, i32 %b) {
entry:
  %sum = add i32 %a, %b
  ret i32 %sum
}

define i32 @sub(i32 %a, i32 %b) {
entry:
  %diff = sub i32 %a, %b
  ret i32 %diff
}
```

Expected pseudo-C output (approximate):

```c
int add(int a, int b) {
    return a + b;
}

int sub(int a, int b) {
    return a - b;
}
```

To run the validation:

```powershell
# Generate reference IR file
python _build_rellic.py --validate-ir

# After building the N-API module:
npx node-gyp rebuild
npm test
```

The smoke tests in `test/test.js` include a reference IR decompilation
test that validates the output contains the expected function names and
basic structure.

## Notes

- LLVM version MUST be 18.1.8 (same as hexcore-remill) to avoid ODR violations
- Clang version MUST match LLVM version exactly (18.1.8)
- Z3 version should be 4.12+ (tested with 4.12.6)
- Always build with `BUILD_SHARED_LIBS=OFF` for static linking
- Total deps size is ~300-500MB (LLVM + Clang + Z3 are large)
- The Rellic static lib is built separately via CMakeLists.txt, then
  linked into the N-API module by binding.gyp
- Use `_build_rellic.py` for automated builds, or CMake directly for
  manual control
