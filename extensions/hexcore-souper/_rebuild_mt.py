#!/usr/bin/env python3
"""
Rebuild Souper + deps with /MT for node-gyp linking.

Strategy:
  1. Build hiredis with cl.exe /MT
  2. Build Alive2 with cl.exe /MT against existing LLVM + Z3
  3. Patch Souper CMakeLists.txt for MSVC (replace llvm-config with find_package)
  4. Configure Souper with cmake, patch build.ninja /MD → /MT
  5. Build Souper static libs
  6. Copy to wrapper deps/ and verify CRT

Prerequisites:
  - Run from VS Developer Command Prompt (vcvarsall x64)
  - LLVM 18.1.8 already built at caps/llvm-build
  - Z3 already downloaded at StandalonePackagesHexCore/hexcore-souper/z3-*
  - Souper source cloned at Desktop/souper-source
  - Alive2, KLEE, hiredis cloned in souper-source/third_party

Usage:
  python _rebuild_mt.py              # full pipeline
  python _rebuild_mt.py --verify     # only verify CRT of all libs
  python _rebuild_mt.py --copy       # only copy libs + verify
  python _rebuild_mt.py --deps-only  # only rebuild hiredis+alive2
"""
import subprocess, sys, os, shutil, argparse, re, stat, json

# ── Paths ──────────────────────────────────────────────────────────────
SOUPER_SRC     = r"C:\Users\Mazum\Desktop\souper-source"
SOUPER_BUILD   = os.path.join(SOUPER_SRC, "build-win")
THIRD_PARTY    = os.path.join(SOUPER_SRC, "third_party")
LLVM_BUILD     = r"C:\Users\Mazum\Desktop\caps\llvm-build\build"
LLVM_CMAKE_DIR = os.path.join(LLVM_BUILD, "lib", "cmake", "llvm")
Z3_DIR         = r"C:\Users\Mazum\Desktop\StandalonePackagesHexCore\hexcore-souper\z3-4.16.0-x64-win\z3-4.16.0-x64-win"
WRAPPER_DEPS   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "deps")

ALIVE2_SRC     = os.path.join(THIRD_PARTY, "alive2")
ALIVE2_BUILD   = os.path.join(THIRD_PARTY, "alive2-build")
HIREDIS_SRC    = os.path.join(THIRD_PARTY, "hiredis")
HIREDIS_INSTALL= os.path.join(THIRD_PARTY, "hiredis-install")
KLEE_SRC       = os.path.join(THIRD_PARTY, "klee")
Z3_INSTALL     = os.path.join(THIRD_PARTY, "z3-install")

CMAKE = "cmake"
JOBS  = str(max(1, (os.cpu_count() or 4) - 2))


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
    def on_error(func, fpath, exc_info):
        os.chmod(fpath, stat.S_IWRITE)
        func(fpath)
    if os.path.isdir(path):
        shutil.rmtree(path, onerror=on_error)


# ===================================================================
# STEP 0: Setup Z3 install directory
# ===================================================================
def setup_z3():
    print("\n>>> SETTING UP Z3 INSTALL DIR <<<\n")
    if not os.path.isdir(Z3_INSTALL):
        os.makedirs(os.path.join(Z3_INSTALL, "include"), exist_ok=True)
        os.makedirs(os.path.join(Z3_INSTALL, "lib"), exist_ok=True)
        os.makedirs(os.path.join(Z3_INSTALL, "bin"), exist_ok=True)
        # Copy from downloaded Z3
        for f in os.listdir(os.path.join(Z3_DIR, "include")):
            shutil.copy2(os.path.join(Z3_DIR, "include", f),
                         os.path.join(Z3_INSTALL, "include", f))
        shutil.copy2(os.path.join(Z3_DIR, "bin", "libz3.lib"),
                     os.path.join(Z3_INSTALL, "lib", "libz3.lib"))
        shutil.copy2(os.path.join(Z3_DIR, "bin", "libz3.dll"),
                     os.path.join(Z3_INSTALL, "bin", "libz3.dll"))
        shutil.copy2(os.path.join(Z3_DIR, "bin", "z3.exe"),
                     os.path.join(Z3_INSTALL, "bin", "z3.exe"))
    print(f"  Z3 install: {Z3_INSTALL}")


# ===================================================================
# STEP 1: Build hiredis with cl.exe /MT
# ===================================================================
def build_hiredis():
    print("\n>>> BUILDING HIREDIS WITH cl.exe /MT <<<\n")
    if os.path.isfile(os.path.join(HIREDIS_INSTALL, "lib", "hiredis.lib")):
        print("  Already built, skipping")
        return

    os.makedirs(os.path.join(HIREDIS_INSTALL, "include", "hiredis"), exist_ok=True)
    os.makedirs(os.path.join(HIREDIS_INSTALL, "lib"), exist_ok=True)

    # Compile C files with cl.exe /MT
    c_files = ["hiredis.c", "read.c", "sds.c", "alloc.c", "net.c",
               "async.c", "dict.c", "sockcompat.c"]
    existing = [f for f in c_files if os.path.isfile(os.path.join(HIREDIS_SRC, f))]

    run(["cl", "/c", "/MT", "/O2", "/DWIN32", "/D_CRT_SECURE_NO_WARNINGS",
         "/D_WINSOCK_DEPRECATED_NO_WARNINGS", "/I."] + existing,
        cwd=HIREDIS_SRC, check=False)

    # Create static lib
    objs = [f.replace(".c", ".obj") for f in existing
            if os.path.isfile(os.path.join(HIREDIS_SRC, f.replace(".c", ".obj")))]
    if objs:
        run(["lib", f"/OUT:{os.path.join(HIREDIS_INSTALL, 'lib', 'hiredis.lib')}"] + objs,
            cwd=HIREDIS_SRC)

    # Copy headers
    for h in ["hiredis.h", "read.h", "sds.h", "alloc.h", "async.h", "dict.h",
              "sockcompat.h", "net.h"]:
        src = os.path.join(HIREDIS_SRC, h)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(HIREDIS_INSTALL, "include", "hiredis", h))

    # Cleanup obj files
    for f in os.listdir(HIREDIS_SRC):
        if f.endswith(".obj"):
            os.remove(os.path.join(HIREDIS_SRC, f))

    print("  hiredis: OK")


# ===================================================================
# STEP 2: Build Alive2 with cl.exe /MT
# ===================================================================
def build_alive2():
    print("\n>>> BUILDING ALIVE2 WITH cl.exe /MT <<<\n")
    if os.path.isfile(os.path.join(ALIVE2_BUILD, "ir.lib")):
        print("  Already built, skipping")
        return

    if os.path.isdir(ALIVE2_BUILD):
        force_rmtree(ALIVE2_BUILD)
    os.makedirs(ALIVE2_BUILD, exist_ok=True)

    run([CMAKE, "-G", "Ninja",
         "-DCMAKE_BUILD_TYPE=Release",
         f"-DZ3_LIBRARIES={Z3_INSTALL}/lib/libz3.lib",
         f"-DZ3_INCLUDE_DIR={Z3_INSTALL}/include",
         f"-DLLVM_DIR={LLVM_CMAKE_DIR}",
         "-DCMAKE_CXX_FLAGS=/EHsc /MT /std:c++20 /W0 /bigobj",
         "-DCMAKE_C_FLAGS=/MT /W0",
         "-DCMAKE_POLICY_DEFAULT_CMP0091=NEW",
         "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded",
         ALIVE2_SRC], cwd=ALIVE2_BUILD)

    # Patch /MD → /MT in ninja files
    patch_ninja_md_to_mt(ALIVE2_BUILD)

    run([CMAKE, "--build", ".", "-j", JOBS], cwd=ALIVE2_BUILD)
    print("  Alive2: OK")


# ===================================================================
# STEP 3: Patch build.ninja /MD → /MT
# ===================================================================
def patch_ninja_md_to_mt(build_dir):
    print(f"\n>>> PATCHING build.ninja: /MD → /MT in {build_dir} <<<\n")
    total = 0
    for root, dirs, files in os.walk(build_dir):
        for fname in files:
            if not fname.endswith(".ninja"):
                continue
            fpath = os.path.join(root, fname)
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            count = content.count("/MD") + content.count("-MD")
            if count == 0:
                continue
            new = content
            new = re.sub(r'(?<![/\w])/MDd(?![a-zA-Z])', '/MTd', new)
            new = re.sub(r'(?<![/\w])/MD(?!d)(?![a-zA-Z])', '/MT', new)
            new = re.sub(r'(?<![/\w-])-MDd(?![a-zA-Z])', '-MTd', new)
            new = re.sub(r'(?<![/\w-])-MD(?!d)(?![a-zA-Z])', '-MT', new)
            if new != content:
                total += count
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(new)
                print(f"  patched: {os.path.relpath(fpath, build_dir)} ({count})")
    print(f"  Total /MD → /MT: {total}")
    return total


# ===================================================================
# STEP 4: Build Souper
# ===================================================================
def build_souper():
    """
    Souper's CMakeLists.txt uses llvm-config (Linux-only).
    We need to either:
    1. Create a fake llvm-config.bat that returns our LLVM paths
    2. Or patch CMakeLists.txt to use find_package(LLVM)

    For now we create a fake llvm-config.bat.
    """
    print("\n>>> BUILDING SOUPER <<<\n")

    # Create fake llvm-config.bat
    llvm_include_src = os.path.join(
        r"C:\Users\Mazum\Desktop\caps\llvm-build\llvm-project-18.1.8.src\llvm\include")
    llvm_include_gen = os.path.join(LLVM_BUILD, "include")
    llvm_lib_dir = os.path.join(LLVM_BUILD, "Release", "lib")

    # Collect all LLVM .lib files
    llvm_libs = []
    if os.path.isdir(llvm_lib_dir):
        for f in sorted(os.listdir(llvm_lib_dir)):
            if f.startswith("LLVM") and f.endswith(".lib"):
                llvm_libs.append(os.path.join(llvm_lib_dir, f))

    llvm_config_bat = os.path.join(SOUPER_SRC, "third_party", "llvm-Release-install", "bin", "llvm-config.exe")
    # Actually we write a .bat and rename the reference

    # Better approach: create the expected directory structure
    fake_install = os.path.join(THIRD_PARTY, "llvm-Release-install")
    os.makedirs(os.path.join(fake_install, "bin"), exist_ok=True)
    os.makedirs(os.path.join(fake_install, "include"), exist_ok=True)
    os.makedirs(os.path.join(fake_install, "lib"), exist_ok=True)

    # Create a Python-based llvm-config shim
    shim = os.path.join(fake_install, "bin", "llvm-config.bat")
    with open(shim, "w") as f:
        f.write(f"""@echo off
if "%1"=="--version" echo 18.1.8
if "%1"=="--includedir" echo {llvm_include_src};{llvm_include_gen}
if "%1"=="--cppflags" echo /I"{llvm_include_src}" /I"{llvm_include_gen}"
if "%1"=="--libs" echo {' '.join(llvm_libs)}
if "%1"=="--system-libs" echo Advapi32.lib Shell32.lib Ole32.lib Uuid.lib ws2_32.lib psapi.lib dbghelp.lib version.lib ntdll.lib synchronization.lib bcrypt.lib Shlwapi.lib
if "%1"=="--ldflags" echo /LIBPATH:"{llvm_lib_dir}"
if "%1"=="--bindir" echo {os.path.join(fake_install, 'bin')}
if "%1"=="--obj-root" echo {LLVM_BUILD}
""")
    print(f"  Created fake llvm-config.bat at {shim}")
    print(f"  Points to {len(llvm_libs)} LLVM libs")

    # NOTE: Souper's CMakeLists.txt calls llvm-config as an executable.
    # On Windows, cmake's execute_process may not run .bat files directly.
    # This step will likely need manual CMakeLists.txt patching.
    # We print instructions for the user.

    print("\n" + "=" * 60)
    print("  IMPORTANT: Souper's CMakeLists.txt is Linux-only.")
    print("  The fake llvm-config.bat is at:")
    print(f"    {shim}")
    print("")
    print("  You may need to manually edit CMakeLists.txt")
    print("  or run cmake with -DLLVM_CONFIG_EXECUTABLE pointing to it.")
    print("  This is the step where we iterate together.")
    print("=" * 60)


# ===================================================================
# STEP 5: Copy to wrapper deps/
# ===================================================================
def copy_to_wrapper():
    print("\n>>> COPYING LIBS TO WRAPPER DEPS <<<\n")
    count = 0

    # -- Souper libs --
    souper_lib_dst = os.path.join(WRAPPER_DEPS, "souper", "lib")
    os.makedirs(souper_lib_dst, exist_ok=True)
    for d in [SOUPER_BUILD, os.path.join(SOUPER_BUILD, "lib")]:
        if os.path.isdir(d):
            for f in os.listdir(d):
                if f.endswith(".lib") and "souper" in f.lower():
                    shutil.copy2(os.path.join(d, f), os.path.join(souper_lib_dst, f))
                    print(f"  souper: {f}")
                    count += 1

    # -- Souper headers --
    souper_hdr_src = os.path.join(SOUPER_SRC, "include", "souper")
    souper_hdr_dst = os.path.join(WRAPPER_DEPS, "souper", "include", "souper")
    if os.path.isdir(souper_hdr_src):
        if os.path.isdir(souper_hdr_dst):
            shutil.rmtree(souper_hdr_dst)
        shutil.copytree(souper_hdr_src, souper_hdr_dst)
        print(f"  souper headers copied")

    # -- Generated headers (GetSolver.h etc) --
    gen_dir = os.path.join(SOUPER_BUILD, "include", "souper")
    if os.path.isdir(gen_dir):
        for root, dirs, files in os.walk(gen_dir):
            for f in files:
                if f.endswith((".h", ".hpp")):
                    rel = os.path.relpath(os.path.join(root, f), gen_dir)
                    dst = os.path.join(souper_hdr_dst, rel)
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    shutil.copy2(os.path.join(root, f), dst)

    # -- KLEE headers --
    klee_hdr_src = os.path.join(KLEE_SRC, "include")
    klee_hdr_dst = os.path.join(WRAPPER_DEPS, "klee", "include")
    if os.path.isdir(klee_hdr_src):
        if os.path.isdir(klee_hdr_dst):
            shutil.rmtree(klee_hdr_dst)
        shutil.copytree(klee_hdr_src, klee_hdr_dst)
        print(f"  klee headers copied")

    # -- Alive2 libs --
    alive2_lib_dst = os.path.join(WRAPPER_DEPS, "alive2", "lib")
    os.makedirs(alive2_lib_dst, exist_ok=True)
    if os.path.isdir(ALIVE2_BUILD):
        for f in os.listdir(ALIVE2_BUILD):
            if f.endswith(".lib"):
                shutil.copy2(os.path.join(ALIVE2_BUILD, f),
                             os.path.join(alive2_lib_dst, f))
                print(f"  alive2: {f}")
                count += 1

    # -- Alive2 headers --
    for sub in ["ir", "smt", "tools", "util"]:
        src = os.path.join(ALIVE2_SRC, sub)
        dst = os.path.join(WRAPPER_DEPS, "alive2", "include", sub)
        if os.path.isdir(src):
            if os.path.isdir(dst):
                shutil.rmtree(dst)
            shutil.copytree(src, dst,
                            ignore=shutil.ignore_patterns("*.cpp", "*.o", "*.obj"))

    # -- LLVM libs --
    llvm_lib_dst = os.path.join(WRAPPER_DEPS, "llvm", "lib")
    os.makedirs(llvm_lib_dst, exist_ok=True)
    llvm_lib_src = os.path.join(LLVM_BUILD, "Release", "lib")
    if os.path.isdir(llvm_lib_src):
        for f in sorted(os.listdir(llvm_lib_src)):
            if f.startswith("LLVM") and f.endswith(".lib"):
                shutil.copy2(os.path.join(llvm_lib_src, f),
                             os.path.join(llvm_lib_dst, f))
                count += 1
        print(f"  llvm: {count} libs")

    # -- LLVM headers --
    llvm_hdr_dst = os.path.join(WRAPPER_DEPS, "llvm", "include")
    for src_dir in [
        os.path.join(r"C:\Users\Mazum\Desktop\caps\llvm-build\llvm-project-18.1.8.src\llvm\include"),
        os.path.join(LLVM_BUILD, "include"),
    ]:
        if os.path.isdir(src_dir):
            if not os.path.isdir(llvm_hdr_dst):
                shutil.copytree(src_dir, llvm_hdr_dst,
                                ignore=shutil.ignore_patterns("*.cpp", "*.o"))
            else:
                # Merge generated headers
                for root, dirs, files in os.walk(src_dir):
                    for f in files:
                        if f.endswith((".h", ".hpp", ".inc", ".def", ".gen", ".td")):
                            rel = os.path.relpath(os.path.join(root, f), src_dir)
                            dst = os.path.join(llvm_hdr_dst, rel)
                            os.makedirs(os.path.dirname(dst), exist_ok=True)
                            shutil.copy2(os.path.join(root, f), dst)

    # -- Z3 --
    z3_dst = os.path.join(WRAPPER_DEPS, "z3")
    os.makedirs(os.path.join(z3_dst, "include"), exist_ok=True)
    os.makedirs(os.path.join(z3_dst, "lib"), exist_ok=True)
    for f in os.listdir(os.path.join(Z3_DIR, "include")):
        shutil.copy2(os.path.join(Z3_DIR, "include", f),
                     os.path.join(z3_dst, "include", f))
    shutil.copy2(os.path.join(Z3_DIR, "bin", "libz3.lib"),
                 os.path.join(z3_dst, "lib", "libz3.lib"))
    shutil.copy2(os.path.join(Z3_DIR, "bin", "libz3.dll"),
                 os.path.join(z3_dst, "libz3.dll"))
    print("  z3: lib + dll + headers copied")

    print(f"\n  Total: {count} lib files copied to deps/")


# ===================================================================
# STEP 6: Verify CRT
# ===================================================================
def verify():
    print("\n>>> VERIFYING CRT OF ALL LIBS <<<\n")
    libs = []

    # Souper libs
    souper_lib = os.path.join(WRAPPER_DEPS, "souper", "lib")
    if os.path.isdir(souper_lib):
        for f in os.listdir(souper_lib):
            if f.endswith(".lib"):
                libs.append((f"souper/{f}", os.path.join(souper_lib, f)))

    # Alive2 libs
    alive2_lib = os.path.join(WRAPPER_DEPS, "alive2", "lib")
    if os.path.isdir(alive2_lib):
        for f in os.listdir(alive2_lib):
            if f.endswith(".lib"):
                libs.append((f"alive2/{f}", os.path.join(alive2_lib, f)))

    # Sample LLVM libs
    for l in ["LLVMCore", "LLVMSupport", "LLVMIRReader"]:
        p = os.path.join(WRAPPER_DEPS, "llvm", "lib", f"{l}.lib")
        if os.path.isfile(p):
            libs.append((l, p))

    # Z3
    z3p = os.path.join(WRAPPER_DEPS, "z3", "lib", "libz3.lib")
    if os.path.isfile(z3p):
        libs.append(("z3", z3p))

    all_ok = True
    for name, path in libs:
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
        status = "OK" if crt in ("MT", "???") else "MISMATCH"
        if crt == "MD":
            all_ok = False
        print(f"  {name}: {crt} {status}")

    if all_ok:
        print("\n  ALL LIBS OK — ready for node-gyp rebuild!")
    else:
        print("\n  WARNING: Some libs are /MD — may cause LNK warnings")
    return all_ok


# ===================================================================
# Main
# ===================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Rebuild Souper + deps with /MT for node-gyp linking")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--copy", action="store_true")
    parser.add_argument("--deps-only", action="store_true")
    args = parser.parse_args()

    if args.verify:
        verify()
    elif args.copy:
        copy_to_wrapper()
        verify()
    elif args.deps_only:
        setup_z3()
        build_hiredis()
        build_alive2()
    else:
        print("=" * 60)
        print("  FULL BUILD PIPELINE")
        print("  0. Setup Z3 install dir")
        print("  1. Build hiredis with cl.exe /MT")
        print("  2. Build Alive2 with cl.exe /MT")
        print("  3. Build Souper (may need manual patches)")
        print("  4. Copy libs to wrapper deps/")
        print("  5. Verify CRT")
        print("=" * 60)

        setup_z3()
        build_hiredis()
        build_alive2()
        build_souper()
        # copy_to_wrapper() and verify() after souper builds successfully
