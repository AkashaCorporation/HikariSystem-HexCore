#!/usr/bin/env python3
"""
Rebuild remill with /MT using clang-cl.

Strategy:
  1. Patch abi-breaking.h in deps-install to ABI_BREAKING_CHECKS=0
     (must match hexcore-llvm-mc LLVM libs)
  2. Rebuild glog + gflags with MSVC cl.exe /MT (not clang-cl)
     to avoid __std_search_1 / __std_remove_8 STL symbol mismatches
  3. cmake configure remill with clang-cl x64
  4. Patch build.ninja /MD → /MT
  5. Build remill libs
  6. Copy to wrapper deps/ and verify CRT

Prerequisites:
  - Run from VS Developer Command Prompt (vcvarsall x64)
  - LLVM libs already copied from hexcore-llvm-mc (already MT)
  - XED already MT

Usage:
  python _rebuild_mt.py              # full pipeline
  python _rebuild_mt.py --verify     # only verify CRT of all libs
  python _rebuild_mt.py --copy       # only copy libs + verify
  python _rebuild_mt.py --patch-only # only patch build.ninja
  python _rebuild_mt.py --deps-only  # only rebuild glog+gflags with cl.exe
"""
import subprocess, sys, os, shutil, argparse, re, stat

DEPS_INSTALL = r"C:\remill-build\deps-install"
REMILL_SRC   = r"C:\remill-build\remill"
REMILL_INSTALL = r"C:\remill-build\remill-install-mt"
BUILD_DIR    = r"C:\remill-build\remill-clangcl-mt"
LLVM_DIR     = os.path.join(DEPS_INSTALL, "lib", "cmake", "llvm")
WRAPPER_DEPS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "deps")

# Use FULL PATH to x64 clang-cl to avoid picking up x86 version
CLANG_CL = r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\Llvm\x64\bin\clang-cl.exe"

CMAKE = "cmake"
JOBS  = str(os.cpu_count() or 4)

# Dirs for rebuilding glog/gflags with cl.exe
GLOG_BUILD   = r"C:\remill-build\glog-mt-cl"
GFLAGS_BUILD = r"C:\remill-build\gflags-mt-cl"
GLOG_SRC     = r"C:\remill-build\glog"
GFLAGS_SRC   = r"C:\remill-build\gflags"


def run(cmd, cwd=None, check=True):
    print(f"\n{'='*60}")
    print(f"CMD: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    print(f"CWD: {cwd or os.getcwd()}")
    print(f"{'='*60}")
    r = subprocess.run(cmd, cwd=cwd)
    if check and r.returncode != 0:
        print(f"FAILED with exit code {r.returncode}")
        sys.exit(r.returncode)
    return r.returncode


def force_rmtree(path):
    """rmtree that handles read-only .git objects on Windows."""
    def on_error(func, fpath, exc_info):
        os.chmod(fpath, stat.S_IWRITE)
        func(fpath)
    if os.path.isdir(path):
        shutil.rmtree(path, onerror=on_error)


# ===================================================================
# STEP 0: Patch abi-breaking.h in deps-install
# ===================================================================
def patch_abi_breaking():
    """
    The LLVM headers in deps-install ship with ABI_BREAKING_CHECKS=1
    (remill's vcpkg default). Our hexcore-llvm-mc libs were built with 0.
    We MUST patch deps-install BEFORE compiling remill so the remill .obj
    files get #pragma detect_mismatch(..., "0") baked in.
    """
    print("\n>>> PATCHING abi-breaking.h in deps-install <<<\n")

    abi_h = os.path.join(DEPS_INSTALL, "include", "llvm", "Config", "abi-breaking.h")
    if not os.path.isfile(abi_h):
        print(f"  WARNING: {abi_h} not found, skipping patch")
        return

    with open(abi_h, "r", encoding="utf-8") as f:
        content = f.read()

    old = "#define LLVM_ENABLE_ABI_BREAKING_CHECKS 1"
    new = "#define LLVM_ENABLE_ABI_BREAKING_CHECKS 0"

    if old in content:
        content = content.replace(old, new)
        with open(abi_h, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  PATCHED: {abi_h}")
        print(f"  {old}  →  {new}")
    elif new in content:
        print(f"  Already patched (value=0), skipping")
    else:
        print(f"  WARNING: Could not find ABI_BREAKING_CHECKS define in {abi_h}")


# ===================================================================
# STEP 1: Rebuild glog + gflags with MSVC cl.exe /MT
# ===================================================================
def rebuild_glog_gflags():
    """
    Rebuild glog and gflags using MSVC cl.exe (NOT clang-cl).
    This avoids __std_search_1 / __std_remove_8 / __std_find_first_of_trivial_pos_1
    symbol mismatches that happen when clang-cl compiled libs link with
    cl.exe compiled code (different MSVC STL internal symbol versions).
    """
    print("\n>>> REBUILDING gflags + glog WITH cl.exe /MT <<<\n")

    # --- gflags ---
    if os.path.isdir(GFLAGS_SRC):
        print("--- Building gflags with cl.exe /MT ---")
        if os.path.isdir(GFLAGS_BUILD):
            force_rmtree(GFLAGS_BUILD)
        os.makedirs(GFLAGS_BUILD, exist_ok=True)

        run([CMAKE, "-G", "Ninja",
             f"-DCMAKE_INSTALL_PREFIX={DEPS_INSTALL}",
             "-DCMAKE_BUILD_TYPE=Release",
             "-DCMAKE_C_COMPILER=cl",
             "-DCMAKE_CXX_COMPILER=cl",
             "-DCMAKE_POLICY_DEFAULT_CMP0091=NEW",
             "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
             "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded",
             "-DCMAKE_C_FLAGS=/MT /EHsc",
             "-DCMAKE_CXX_FLAGS=/MT /EHsc",
             "-DGFLAGS_BUILD_SHARED_LIBS=OFF",
             "-DGFLAGS_BUILD_STATIC_LIBS=ON",
             "-DGFLAGS_BUILD_TESTING=OFF",
             GFLAGS_SRC], cwd=GFLAGS_BUILD)

        run([CMAKE, "--build", ".", "--config", "Release", "-j", JOBS],
            cwd=GFLAGS_BUILD)
        run([CMAKE, "--install", "."], cwd=GFLAGS_BUILD)
        print("  gflags: OK")
    else:
        print(f"  WARNING: gflags source not found at {GFLAGS_SRC}")
        print(f"  Clone it: git clone https://github.com/gflags/gflags.git {GFLAGS_SRC}")

    # --- glog ---
    if os.path.isdir(GLOG_SRC):
        print("\n--- Building glog with cl.exe /MT ---")
        if os.path.isdir(GLOG_BUILD):
            force_rmtree(GLOG_BUILD)
        os.makedirs(GLOG_BUILD, exist_ok=True)

        run([CMAKE, "-G", "Ninja",
             f"-DCMAKE_INSTALL_PREFIX={DEPS_INSTALL}",
             "-DCMAKE_BUILD_TYPE=Release",
             "-DCMAKE_C_COMPILER=cl",
             "-DCMAKE_CXX_COMPILER=cl",
             "-DCMAKE_POLICY_DEFAULT_CMP0091=NEW",
             "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
             "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded",
             "-DCMAKE_C_FLAGS=/MT /EHsc",
             "-DCMAKE_CXX_FLAGS=/MT /EHsc",
             "-DBUILD_SHARED_LIBS=OFF",
             "-DWITH_GFLAGS=ON",
             "-DWITH_GTEST=OFF",
             "-DWITH_UNWIND=OFF",
             f"-Dgflags_DIR={DEPS_INSTALL}/lib/cmake/gflags",
             GLOG_SRC], cwd=GLOG_BUILD)

        run([CMAKE, "--build", ".", "--config", "Release", "-j", JOBS],
            cwd=GLOG_BUILD)
        run([CMAKE, "--install", "."], cwd=GLOG_BUILD)
        print("  glog: OK")
    else:
        print(f"  WARNING: glog source not found at {GLOG_SRC}")
        print(f"  Clone it: git clone https://github.com/google/glog.git {GLOG_SRC}")


# ===================================================================
# STEP 2: Patch build.ninja /MD → /MT
# ===================================================================
def patch_ninja_md_to_mt(build_dir):
    """
    Walk all .ninja files in build_dir and replace /MD with /MT.
    This is the nuclear option — guarantees every .obj is compiled with /MT
    regardless of what CMakeLists.txt says.
    """
    print("\n>>> PATCHING build.ninja: /MD → /MT <<<\n")
    total_replacements = 0

    for root, dirs, files in os.walk(build_dir):
        for fname in files:
            if not fname.endswith(".ninja"):
                continue
            fpath = os.path.join(root, fname)
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            count_md  = content.count("/MD")
            count_dmd = content.count("-MD")

            if count_md == 0 and count_dmd == 0:
                continue

            new_content = content
            new_content = re.sub(r'(?<![/\w])/MDd(?![a-zA-Z])', '/MTd', new_content)
            new_content = re.sub(r'(?<![/\w])/MD(?!d)(?![a-zA-Z])', '/MT', new_content)
            new_content = re.sub(r'(?<![/\w-])-MDd(?![a-zA-Z])', '-MTd', new_content)
            new_content = re.sub(r'(?<![/\w-])-MD(?!d)(?![a-zA-Z])', '-MT', new_content)

            if new_content != content:
                replacements = (count_md + count_dmd)
                total_replacements += replacements
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(new_content)
                relpath = os.path.relpath(fpath, build_dir)
                print(f"  patched: {relpath} ({replacements} replacements)")

    print(f"\n  Total /MD → /MT replacements: {total_replacements}")
    if total_replacements == 0:
        print("  WARNING: No /MD found in ninja files. Check if cmake already uses /MT.")
    return total_replacements


# ===================================================================
# STEP 3: Configure + build remill
# ===================================================================
def rebuild_remill():
    """Full rebuild: patch ABI → configure → patch ninja → build."""
    print("\n>>> REBUILDING REMILL WITH clang-cl /MT <<<\n")

    # Verify x64 clang-cl exists
    if not os.path.isfile(CLANG_CL):
        print(f"ERROR: x64 clang-cl not found at {CLANG_CL}")
        print("Install 'C++ Clang Compiler for Windows' via VS Installer")
        sys.exit(1)
    print(f"Using clang-cl: {CLANG_CL}")

    # 1. Clean build dir
    if os.path.isdir(BUILD_DIR):
        print(f"Cleaning {BUILD_DIR} ...")
        force_rmtree(BUILD_DIR)
    os.makedirs(BUILD_DIR, exist_ok=True)

    if os.path.isdir(REMILL_INSTALL):
        force_rmtree(REMILL_INSTALL)

    # 2. CMake configure with FULL PATH to x64 clang-cl
    run([CMAKE, "-G", "Ninja",
         f"-DCMAKE_INSTALL_PREFIX={REMILL_INSTALL}",
         "-DCMAKE_BUILD_TYPE=Release",

         f"-DCMAKE_C_COMPILER={CLANG_CL}",
         f"-DCMAKE_CXX_COMPILER={CLANG_CL}",

         "-DCMAKE_POLICY_DEFAULT_CMP0091=NEW",
         "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded",

         "-DCMAKE_C_FLAGS=/MT /EHsc",
         "-DCMAKE_CXX_FLAGS=/MT /EHsc",
         "-DCMAKE_C_FLAGS_RELEASE=/MT /EHsc /O2 /DNDEBUG",
         "-DCMAKE_CXX_FLAGS_RELEASE=/MT /EHsc /O2 /DNDEBUG",

         f"-DLLVM_DIR={LLVM_DIR}",
         f"-Dgflags_DIR={DEPS_INSTALL}/lib/cmake/gflags",
         f"-Dglog_DIR={DEPS_INSTALL}/lib/cmake/glog",
         f"-DXED_DIR={DEPS_INSTALL}/lib/cmake/XED",

         "-DREMILL_ENABLE_TESTING=OFF",
         "-DREMILL_BUILD_SPARC32_RUNTIME=ON",
         "-DREMILL_BUILD_SPARC64_RUNTIME=ON",

         REMILL_SRC], cwd=BUILD_DIR)

    # 3. PATCH: replace all /MD with /MT in generated ninja files
    n = patch_ninja_md_to_mt(BUILD_DIR)
    print(f"\n  Ninja patch complete ({n} replacements)")

    # 4. Build library targets
    lib_targets = [
        "remill_bc", "remill_os", "remill_arch",
        "remill_arch_x86", "remill_arch_aarch64",
        "remill_arch_sparc32", "remill_arch_sparc64",
        "remill_arch_sleigh", "remill_version",
    ]

    for t in lib_targets:
        print(f"\n--- Building target: {t} ---")
        r = subprocess.run(
            [CMAKE, "--build", ".", "--config", "Release",
             "--target", t, "-j", JOBS],
            cwd=BUILD_DIR)
        if r.returncode != 0:
            print(f"WARNING: target {t} failed, skipping")

    # Sleigh targets
    sleigh_candidates = [
        "decomp", "sla", "slaSupport",
        "sleigh_decomp", "sleigh_sla", "sleigh_slaSupport",
        "ghidra_decomp", "ghidra_sla",
    ]
    for t in sleigh_candidates:
        r = subprocess.run(
            [CMAKE, "--build", ".", "--config", "Release",
             "--target", t, "-j", JOBS],
            cwd=BUILD_DIR, capture_output=True)
        if r.returncode == 0:
            print(f"  sleigh target OK: {t}")

    print("\n>>> REMILL LIB BUILD COMPLETE <<<")


# ===================================================================
# STEP 4: Copy libs to wrapper deps/
# ===================================================================
def copy_to_wrapper():
    """Copy rebuilt libs to extensions/hexcore-remill/deps/."""
    print("\n>>> COPYING LIBS TO WRAPPER DEPS <<<\n")

    # --- remill libs (from build dir) ---
    remill_lib_dst = os.path.join(WRAPPER_DEPS, "remill", "lib")
    if os.path.isdir(remill_lib_dst):
        shutil.rmtree(remill_lib_dst)
    os.makedirs(remill_lib_dst, exist_ok=True)

    count = 0
    lib_dir = os.path.join(BUILD_DIR, "lib")
    if os.path.isdir(lib_dir):
        for root, dirs, files in os.walk(lib_dir):
            for f in files:
                if f.endswith(".lib"):
                    shutil.copy2(os.path.join(root, f),
                                 os.path.join(remill_lib_dst, f))
                    print(f"  remill: {f}")
                    count += 1

    deps_dir = os.path.join(BUILD_DIR, "_deps")
    if os.path.isdir(deps_dir):
        for root, dirs, files in os.walk(deps_dir):
            for f in files:
                if f.endswith(".lib") and f in [
                    "decomp.lib", "sla.lib", "slaSupport.lib",
                    "sleigh.lib", "sleighSupport.lib"
                ]:
                    shutil.copy2(os.path.join(root, f),
                                 os.path.join(remill_lib_dst, f))
                    print(f"  sleigh: {f}")
                    count += 1
    print(f"  -> {count} remill/sleigh libs copied")

    # --- glog ---
    glog_dst = os.path.join(WRAPPER_DEPS, "glog", "lib", "glog.lib")
    os.makedirs(os.path.dirname(glog_dst), exist_ok=True)
    for v in ["glog.lib", "glogd.lib", "glog_static.lib"]:
        p = os.path.join(DEPS_INSTALL, "lib", v)
        if os.path.isfile(p):
            shutil.copy2(p, glog_dst)
            print(f"  glog: {v}")
            break

    # --- gflags ---
    gflags_dst = os.path.join(WRAPPER_DEPS, "gflags", "lib", "gflags_static.lib")
    os.makedirs(os.path.dirname(gflags_dst), exist_ok=True)
    for v in ["gflags_static.lib", "gflags.lib"]:
        p = os.path.join(DEPS_INSTALL, "lib", v)
        if os.path.isfile(p):
            shutil.copy2(p, gflags_dst)
            print(f"  gflags: {v}")
            break

    print("  xed: already MT, skipping")


# ===================================================================
# STEP 5: Verify CRT
# ===================================================================
def verify():
    """Check CRT of all libs using dumpbin."""
    print("\n>>> VERIFYING CRT OF ALL LIBS <<<\n")
    libs = [
        ("remill_bc",       os.path.join(WRAPPER_DEPS, "remill", "lib", "remill_bc.lib")),
        ("remill_os",       os.path.join(WRAPPER_DEPS, "remill", "lib", "remill_os.lib")),
        ("remill_arch",     os.path.join(WRAPPER_DEPS, "remill", "lib", "remill_arch.lib")),
        ("remill_arch_x86", os.path.join(WRAPPER_DEPS, "remill", "lib", "remill_arch_x86.lib")),
        ("remill_arch_aarch64", os.path.join(WRAPPER_DEPS, "remill", "lib", "remill_arch_aarch64.lib")),
        ("remill_arch_sleigh",  os.path.join(WRAPPER_DEPS, "remill", "lib", "remill_arch_sleigh.lib")),
        ("remill_version",  os.path.join(WRAPPER_DEPS, "remill", "lib", "remill_version.lib")),
        ("decomp",          os.path.join(WRAPPER_DEPS, "remill", "lib", "decomp.lib")),
        ("sla",             os.path.join(WRAPPER_DEPS, "remill", "lib", "sla.lib")),
        ("slaSupport",      os.path.join(WRAPPER_DEPS, "remill", "lib", "slaSupport.lib")),
        ("glog",            os.path.join(WRAPPER_DEPS, "glog", "lib", "glog.lib")),
        ("gflags",          os.path.join(WRAPPER_DEPS, "gflags", "lib", "gflags_static.lib")),
        ("xed",             os.path.join(WRAPPER_DEPS, "xed", "lib", "xed.lib")),
        ("LLVMSupport",     os.path.join(WRAPPER_DEPS, "llvm", "lib", "LLVMSupport.lib")),
        ("LLVMCore",        os.path.join(WRAPPER_DEPS, "llvm", "lib", "LLVMCore.lib")),
    ]
    all_ok = True
    for name, path in libs:
        if not os.path.isfile(path):
            print(f"  {name}: MISSING ({path})")
            all_ok = False
            continue
        r = subprocess.run(["dumpbin", "/directives", path],
                           capture_output=True, text=True)
        defaults = set()
        for line in r.stdout.split("\n"):
            if "/DEFAULTLIB:" in line:
                val = line.strip().split("/DEFAULTLIB:")[1].strip().strip('"')
                defaults.add(val.lower())
        if "libcmt" in defaults or "libcmt.lib" in defaults:
            crt = "MT"
        elif "msvcrt" in defaults or "msvcrt.lib" in defaults:
            crt = "MD"
        else:
            crt = "???"
        status = "OK" if crt == "MT" else "MISMATCH"
        if crt != "MT":
            all_ok = False
        print(f"  {name}: {crt} {status}  ({', '.join(sorted(defaults))})")

    if all_ok:
        print("\n  ALL LIBS ARE /MT — ready for node-gyp rebuild!")
    else:
        print("\n  WARNING: Some libs are NOT /MT — fix before building!")
    return all_ok


# ===================================================================
# STEP 6: Verify ABI consistency
# ===================================================================
def verify_abi():
    """Check that remill libs have ABI_BREAKING_CHECKS=0 (matching LLVM libs)."""
    print("\n>>> VERIFYING ABI_BREAKING_CHECKS CONSISTENCY <<<\n")

    test_lib = os.path.join(WRAPPER_DEPS, "remill", "lib", "remill_bc.lib")
    if not os.path.isfile(test_lib):
        print(f"  remill_bc.lib not found, skipping ABI check")
        return

    r = subprocess.run(["dumpbin", "/directives", test_lib],
                       capture_output=True, text=True)

    for line in r.stdout.split("\n"):
        if "LLVM_ENABLE_ABI_BREAKING_CHECKS" in line:
            print(f"  remill_bc.lib: {line.strip()}")
            if '"0"' in line:
                print("  ABI check: OK (matches LLVM libs)")
            elif '"1"' in line:
                print("  ABI check: MISMATCH! Remill has 1, LLVM has 0")
                print("  Did you run patch_abi_breaking() before building?")
            return

    print("  No ABI_BREAKING_CHECKS pragma found in remill_bc.lib")


# ===================================================================
# Main
# ===================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Rebuild remill + deps with /MT for node-gyp linking")
    parser.add_argument("--verify", action="store_true",
                        help="Only verify CRT of all libs")
    parser.add_argument("--copy", action="store_true",
                        help="Only copy libs to wrapper deps + verify")
    parser.add_argument("--patch-only", action="store_true",
                        help="Only patch build.ninja (configure must be done)")
    parser.add_argument("--deps-only", action="store_true",
                        help="Only rebuild glog+gflags with cl.exe /MT")
    parser.add_argument("--skip-deps", action="store_true",
                        help="Skip glog/gflags rebuild (if already done)")
    args = parser.parse_args()

    if args.verify:
        verify()
        verify_abi()
    elif args.copy:
        copy_to_wrapper()
        verify()
        verify_abi()
    elif args.patch_only:
        patch_ninja_md_to_mt(BUILD_DIR)
    elif args.deps_only:
        rebuild_glog_gflags()
    else:
        # Full pipeline
        print("=" * 60)
        print("  FULL REBUILD PIPELINE")
        print("  1. Patch abi-breaking.h (deps-install)")
        print("  2. Rebuild glog+gflags with cl.exe /MT")
        print("  3. Configure + build remill with clang-cl x64 /MT")
        print("  4. Copy libs to wrapper deps/")
        print("  5. Verify CRT + ABI")
        print("=" * 60)

        # Step 0: Patch ABI header
        patch_abi_breaking()

        # Step 1: Rebuild glog+gflags (skip if --skip-deps)
        if not args.skip_deps:
            rebuild_glog_gflags()

        # Step 2-3: Configure + build remill
        rebuild_remill()

        # Step 4: Copy
        copy_to_wrapper()

        # Step 5: Verify
        ok = verify()
        verify_abi()

        if ok:
            print("\n" + "=" * 60)
            print("  ALL DONE! Next steps:")
            print("  1. python _write_gyp.py")
            print("  2. npx node-gyp rebuild")
            print("  3. npm test")
            print("=" * 60)
        else:
            print("\nSome libs still /MD. Check output above.")
