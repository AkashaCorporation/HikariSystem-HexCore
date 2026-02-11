# HexCore v3.3.0 - Development Build Report

**Date**: February 11, 2026  
**Tester**: Community Member  
**Platform**: Windows 10 (26200.7840), Node.js 22.22.0  
**Status**: ✅ Successfully Built with Issues

---

## Summary

Successfully built and launched HexCore v3.3.0 development environment from source. All native modules (Capstone, Unicorn, LLVM-MC) loaded correctly. However, the build process is **extremely complex** and requires multiple manual steps that are not documented.

---

## Issues Encountered

### 1. **Interactive Shell During npm install** ⚠️
**Problem**: The `preinstall` script opens an interactive shell that blocks the installation process.

**Location**: `build/npm/preinstall.ts`

**Workaround**: User must manually type `exit` and press Enter when the shell appears.

**Impact**: Makes automated builds impossible and confuses new contributors.

**Suggested Fix**: 
- Remove the interactive shell requirement
- Or add clear instructions in the console output

---

### 2. **Native Module Binary Naming Mismatch** 🐛
**Problem**: Prebuilt binaries use hyphen naming (`hexcore-unicorn.node`) but the runtime code expects underscore naming (`hexcore_unicorn.node`).

**Affected Modules**:
- `hexcore-capstone`
- `hexcore-unicorn`
- `hexcore-llvm-mc`

**Location**: 
- Binaries: `extensions/*/prebuilds/win32-x64/*.node`
- Expected by: `extensions/*/index.js` (loadNativeAddon function)

**Workaround**: Created a PowerShell script to copy and rename binaries:
```powershell
# Copy from: extensions/hexcore-unicorn/prebuilds/win32-x64/hexcore-unicorn.node
# To: extensions/hexcore-unicorn/build/Release/hexcore_unicorn.node
```

**Impact**: Native modules fail to load without manual intervention.

**Suggested Fix**: 
- Standardize naming convention (prefer underscore for consistency with Node.js native modules)
- Or update `index.js` to handle both naming conventions

---

### 3. **Missing Build Directory Structure** 📁
**Problem**: The `index.js` loader expects binaries in `build/Release/` but this directory doesn't exist after `git clone`.

**Workaround**: Script creates the directory structure and copies binaries.

**Suggested Fix**: 
- Include empty `build/Release/` directories in git (with `.gitkeep`)
- Or update the loader to check `prebuilds/` first before `build/`

---

### 4. **Unicorn DLL Dependency Path** 🔗
**Problem**: `unicorn.dll` must be in multiple locations for the module to load correctly:
- `extensions/hexcore-unicorn/deps/unicorn/unicorn.dll` (for PATH setup)
- `extensions/hexcore-unicorn/build/Release/unicorn.dll` (for runtime loading)

**Workaround**: Copy `unicorn.dll` to all required locations.

**Suggested Fix**: 
- Simplify the DLL loading logic to check fewer locations
- Or document the required directory structure

---

### 5. **Missing Documentation** 📚
**Problem**: No documentation exists for building from source for development/testing purposes.

**Impact**: Community members cannot easily test pre-release versions.

**Suggested Fix**: Add `CONTRIBUTING.md` or `DEVELOPMENT.md` with:
- Prerequisites (Node.js version, Python, Visual Studio Build Tools)
- Step-by-step build instructions
- Common issues and solutions

---

## Working Build Process

We created a working build process documented in `BUILD_INSTRUCTIONS.md`. Key steps:

1. **Copy native binaries FIRST** (before npm install)
2. Run `npm install` (type `exit` when prompted)
3. Install extension dependencies
4. Build native core modules (sqlite3, spdlog)
5. Install ripgrep
6. Compile TypeScript
7. Launch with `.\scripts\code.bat`

**Total Time**: ~15-20 minutes (excluding download time)

---

## Test Results

### ✅ Working Features
- HexCore launches successfully
- Hex Viewer extension loads and activates
- Debugger extension loads and activates
- **Unicorn engine loads correctly** (v2.1)
- **Capstone engine loads correctly**
- **LLVM-MC engine loads correctly**
- PE file loading works
- Emulation initialization works

### ⚠️ Issues Found
- Extension host crashes with code `-1073740791` (Access Violation) when clicking "Continue" in debugger
- This appears to be a bug in the debugger extension itself, not the build process

### ℹ️ Expected Warnings (Not Issues)
- `json-language-features` version mismatch (requires VS Code 1.91.0, got 1.0.0)
- `local-network-access` feature warnings (browser security)
- Sandbox warnings (expected for webviews)

---

## Recommendations for v3.3.0 Release

### High Priority
1. **Fix the interactive shell issue** - This blocks automated CI/CD
2. **Standardize binary naming** - Prevents runtime loading failures
3. **Add development build documentation** - Enables community testing

### Medium Priority
4. **Investigate debugger crash** - Access violation when continuing emulation
5. **Simplify native module loading** - Reduce number of paths to check

### Low Priority
6. **Add automated build script** - One command to build everything
7. **Add build verification tests** - Ensure all modules load correctly

---

## Files Created

We created the following helper files that might be useful to include in the repository:

1. **`BUILD_INSTRUCTIONS.md`** - Step-by-step build guide
2. **`scripts/copy-hexcore-binaries.ps1`** - Automates binary copying
3. **`scripts/hexcore-native-install.js`** (modified) - Skips compilation when prebuilds exist

---

## Conclusion

HexCore v3.3.0 is **buildable and functional** but requires significant manual intervention. The native modules work correctly once properly configured. With the suggested fixes, the development build process could be much smoother for future contributors and testers.

**Estimated effort to fix**: 4-8 hours of development time to address the high-priority issues.

---

## Contact

If you need more details or want to discuss these findings, feel free to reach out!

**Build tested by**: Community tester  
**Build date**: February 11, 2026  
**HexCore version**: v3.3.0 (pre-release)
