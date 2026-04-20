---
name: "hexcore-how-to-compile"
displayName: "How to Compile HexCore"
description: "Step-by-step compilation guide for all HexCore components: TypeScript extensions, native N-API engines, and Helix. Covers monorepo development flow, native engine rebuild, and deploy-to-prebuild workflow."
keywords: ["hexcore", "compile", "build", "node-gyp", "typescript", "native", "napi", "remill", "capstone", "helix"]
author: "HikariSystem"
---

# How to Compile HexCore

## Overview

HexCore has three types of compilable code:

| Type | Language | Build Tool | Example |
|------|----------|------------|---------|
| **TypeScript extensions** | TypeScript | `npm run compile` | hexcore-disassembler, hexcore-ioc |
| **Native N-API engines** | C++ | `npx node-gyp rebuild` | hexcore-remill, hexcore-capstone, hexcore-unicorn, hexcore-souper, helix-wrapper |
| **Helix decompiler** | C++ (MLIR) + Rust (NAPI-RS) | CMake/Ninja + `npm run build` | HexCore-Helix | this living out of source. if u need working on a Helix Decompiler source talk with me.. and i will dispatch the agent to make diff n etc.

---

## 1. TypeScript Extensions

These are pure TypeScript extensions that compile to JavaScript. No native code involved.

### Extensions

- `extensions/hexcore-disassembler/` — Main disassembler extension (Pathfinder lives here)
- `extensions/hexcore-ioc/` — Indicators of Compromise extraction
- `extensions/hexcore-common/` — Shared utilities (no native code)

### How to compile

```powershell
cd extensions/hexcore-disassembler
npm run compile
```

### When to compile

- After editing any `.ts` file in `src/`
- Changes to `pathfinder.ts`, `extension.ts`, `remillWrapper.ts`, `souperWrapper.ts`, etc.
- **No reload needed** if you only changed TS — the compiled JS is picked up on next VS Code Reload Window

### Output

- `out/` directory with compiled `.js` files
- No binary artifacts — VS Code loads these directly

---

## 2. Native N-API Engines

These are C++ wrappers that compile to `.node` native addons. They bind external libraries (Remill, Capstone, LLVM, XED, Z3, etc.) to Node.js via N-API.

### Engines in the monorepo

| Engine | Path | Key deps |
|--------|------|----------|
| hexcore-remill | `extensions/hexcore-remill/` | Remill, LLVM 18, XED, glog, gflags, Sleigh |
| hexcore-capstone | `extensions/hexcore-capstone/` | Capstone |
| hexcore-unicorn | `extensions/hexcore-unicorn/` | Unicorn + runtime DLLs |
| hexcore-llvm-mc | `extensions/hexcore-llvm-mc/` | LLVM MC |
| hexcore-better-sqlite3 | `extensions/hexcore-better-sqlite3/` | SQLite3 |
| hexcore-souper | `extensions/hexcore-souper/` | Souper, LLVM 18, Z3 |

### How to compile (same for ALL engines)

```powershell
# Step 1: Navigate to the engine in the MONOREPO (not standalone!)
cd extensions/hexcore-remill

# Step 2: Rebuild the native addon
npx node-gyp rebuild

# Step 3: The .node is generated at:
#   build/Release/hexcore_remill.node
```

### Deploy to prebuilds (CRITICAL)

The extension loader checks `prebuilds/win32-x64/` FIRST. If an old prebuild exists there, your fresh `build/Release/` build will be IGNORED.

```powershell
# Step 3: Backup old prebuild
cp prebuilds/win32-x64/hexcore_remill.node prebuilds/win32-x64/hexcore_remill.node.bak

# Step 4: Copy new build over the prebuild
cp build/Release/hexcore_remill.node prebuilds/win32-x64/hexcore_remill.node

# Step 5: Reload VS Code window (Ctrl+Shift+P → "Reload Window")
```

### Loading order (from index.js)

1. `prebuilds/{platform}-{arch}/hexcore_{name}.node` ← **prebuild (checked first!)**
2. `build/Release/hexcore_{name}.node` ← local dev build
3. `build/Debug/hexcore_{name}.node` ← debug build

### Prerequisites

- **Node.js 18+** (production) / **22.x** (prebuilds CI)
- **Python 3.11+** (for node-gyp)
- **Visual Studio Build Tools 2022** with C++ workload (Windows)
- `node-addon-api` installed (already in each engine's `node_modules/` after `npm install --ignore-scripts`)

### When to compile

- After editing `.cpp`, `.h`, or `.gyp` files in the engine
- After changing `binding.gyp` (added libs, includes, defines)
- **Always reload VS Code window** after copying the new `.node`

### Common issues

| Issue | Cause | Fix |
|-------|-------|-----|
| `Cannot find module 'node-addon-api'` | Missing devDeps | `npm install --ignore-scripts` in the engine dir |
| `Cannot open include file: 'remill/Arch/Arch.h'` | deps/ not populated | The `deps/` folder should already exist in the monorepo. If empty, check the `*-deps-win32-x64.zip` — see POWER.md `hexcore-native-engines` |
| Old behavior after rebuild | Prebuild shadows build | Copy `build/Release/*.node` → `prebuilds/win32-x64/` |
| `pragma 'clang' desconhecido` | MSVC warning on Remill headers | Harmless — ignore |

---

## 3. Helix Decompiler

Helix is a two-part build: C++ engine (MLIR-based) + Rust NAPI-RS binding.

### C++ Engine build

```powershell
# Open "x64 Native Tools Command Prompt for VS 2022"
cd C:\Users\Mazum\Desktop\HexCore-Helix-Original\HexCore-Helix\engine\build
cmake ..
ninja
```

- Produces `helix_engine.lib` which is consumed by the NAPI-RS binding
- Requires LLVM/MLIR deps (in `helix-llvm-mlir-deps-win32-x64.zip`)

### NAPI-RS binding build

```powershell
cd C:\Users\Mazum\Desktop\HexCore-Helix-Original\HexCore-Helix
npm run build
```

- Links against `helix_engine.lib` from the deps ZIP
- Produces the `.node` file for the extension

### When to rebuild

- After changing any C++ pass in `engine/src/passes/`
- After modifying the MLIR dialect definitions
- After changing the Rust NAPI bridge code
- **Bih handles Helix rebuilds manually** — it requires specific LLVM/MLIR toolchain setup

---

## 4. Development Flow Summary

### Golden Rule: Monorepo First, Standalone Second

```
1. Edit source in:     extensions/hexcore-{name}/
2. Build there:        npx node-gyp rebuild  (native)  OR  npm run compile  (TS)
3. Deploy:             cp build/Release/*.node → prebuilds/win32-x64/  (native only)
4. Test in HexCore:    Reload Window → run your test case
5. ONLY after it works: sync to StandalonePackagesHexCore/hexcore-{name}/
```

### Quick reference

```powershell
# === TypeScript (disassembler, pathfinder, wrappers) ===
cd extensions/hexcore-disassembler
npm run compile

# === Native C++ (remill, capstone, unicorn, souper, llvm-mc, sqlite3) ===
cd extensions/hexcore-remill
npx node-gyp rebuild
cp build/Release/hexcore_remill.node prebuilds/win32-x64/hexcore_remill.node

# === Check TS types without emitting JS ===
npx tsc --noEmit --project extensions/hexcore-disassembler/tsconfig.json

# === Helix C++ engine ===
# (x64 Native Tools Command Prompt)
cd HexCore-Helix/engine/build && cmake .. && ninja  / talk with me first.

# === Helix NAPI-RS binding ===
cd HexCore-Helix && npm run build / talk with me first.
```

---

## 5. What Lives Where

```
extensions/hexcore-disassembler/
├── src/                      ← TypeScript source
│   ├── extension.ts          ← Main entry, pipeline orchestration
│   ├── pathfinder.ts         ← CFG recovery engine
│   ├── remillWrapper.ts      ← Remill N-API bridge (TypeScript side)
│   ├── souperWrapper.ts      ← Souper N-API bridge (TypeScript side)
│   ├── capstoneWrapper.ts    ← Capstone N-API bridge
│   └── disassemblerEngine.ts ← Binary analysis core
└── out/                      ← Compiled JS (npm run compile)

extensions/hexcore-remill/
├── src/
│   ├── main.cpp              ← N-API entry point
│   └── remill_wrapper.cpp    ← Lift logic, Phase 1-5, FIX-024/025
├── deps/                     ← Headers + static libs (remill, llvm, xed, glog)
├── build/Release/            ← node-gyp output
│   └── hexcore_remill.node   ← Fresh build
└── prebuilds/win32-x64/
    └── hexcore_remill.node   ← Production prebuild (loaded first!)
```

---

## 6. Do NOT

- **Do NOT extract `*-deps-win32-x64.zip`** into `deps/` of standalone repos — those are distribution artifacts, not vendor dumps
- **Do NOT add native engines to `dependencies`** of consuming extensions (hexcore-disassembler) — see `hexcore-native-engines` Power for why
- **Do NOT `npm run build`** in standalone repos and expect it to affect HexCore — always work in the monorepo first
- **Do NOT forget to copy `.node` to prebuilds/** — the old prebuild will shadow your fresh build silently
