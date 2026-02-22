#!/usr/bin/env python3
"""
Master build script for hexcore-rellic — orchestrates the full local build.

This script automates the entire process of building hexcore-rellic locally:
  1. Copy LLVM deps from hexcore-remill (reuse existing /MT libs)
  2. Build Clang 18 static libs (from llvm-project source)
  3. Download + install Z3 pre-built
  4. Build Rellic static lib (stubs)
  5. Run node-gyp rebuild
  6. Run npm test

Usage:
    python _rebuild_all.py                              # full pipeline
    python _rebuild_all.py --remill-deps <path>         # custom remill deps path
    python _rebuild_all.py --llvm-src <path>            # custom llvm-project source
    python _rebuild_all.py --step copy-llvm             # run single step
    python _rebuild_all.py --step build-z3
    python _rebuild_all.py --step build-rellic-lib
    python _rebuild_all.py --step node-gyp
    python _rebuild_all.py --step test
    python _rebuild_all.py --verify                     # verify all deps

Prerequisites:
    - VS2022 Developer Command Prompt (vcvarsall x64)
    - clang-cl in PATH
    - CMake 3.21+ and Ninja in PATH
    - Node.js 18+ with node-gyp
    - hexcore-remill deps already built (for LLVM libs reuse)

Copyright (c) HikariSystem. All rights reserved.
Licensed under MIT License.
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
DEPS_DIR = SCRIPT_DIR / 'deps'
IS_WINDOWS = platform.system() == 'Windows'

# Default paths — adjust for your machine
DEFAULT_REMILL_DEPS = SCRIPT_DIR.parent / 'hexcore-remill' / 'deps'
DEFAULT_LLVM_SRC = Path(r'C:\remill-build\remill\dependencies\llvm-project')
DEFAULT_LLVM_BUILD = Path(r'C:\remill-build\deps-install')

# Alternative LLVM source locations to try
LLVM_SRC_CANDIDATES = [
    Path(r'C:\llvm-project-18.1.8'),
    Path(r'C:\remill-build\remill\dependencies\llvm-project'),
    Path(r'C:\remill-build\deps-build\llvm-project-src'),
    Path(r'C:\remill-build\llvm-project'),
]


def run(cmd, cwd=None, check=True):
    print(f"\n{'=' * 60}")
    print(f"CMD: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    print(f"CWD: {cwd or os.getcwd()}")
    print(f"{'=' * 60}")
    r = subprocess.run(cmd, cwd=cwd)
    if check and r.returncode != 0:
        print(f"FAILED with exit code {r.returncode}")
        sys.exit(r.returncode)
    return r.returncode


def find_llvm_source():
    """Try to find the llvm-project source tree."""
    for candidate in LLVM_SRC_CANDIDATES:
        clang_dir = candidate / 'clang'
        if clang_dir.exists():
            print(f"  Found llvm-project source at: {candidate}")
            return candidate
    return None


# ===================================================================
# STEP 1: Copy LLVM deps from hexcore-remill
# ===================================================================
def copy_llvm_deps(remill_deps_path):
    """Copy LLVM headers and libs from hexcore-remill deps."""
    print("\n>>> STEP 1: COPY LLVM DEPS FROM REMILL <<<\n")

    src_llvm = Path(remill_deps_path) / 'llvm'
    dst_llvm = DEPS_DIR / 'llvm'

    if not src_llvm.exists():
        print(f"  ERROR: Remill LLVM deps not found at {src_llvm}")
        print(f"  Make sure hexcore-remill deps are built.")
        print(f"  Expected path: {remill_deps_path}")
        sys.exit(1)

    src_include = src_llvm / 'include'
    src_lib = src_llvm / 'lib'

    if not src_include.exists() or not src_lib.exists():
        print(f"  ERROR: LLVM include/ or lib/ not found in {src_llvm}")
        sys.exit(1)

    # Count source libs
    src_libs = list(src_lib.glob('*.lib' if IS_WINDOWS else '*.a'))
    print(f"  Source: {src_llvm}")
    print(f"  LLVM libs found: {len(src_libs)}")

    # Copy
    dst_include = dst_llvm / 'include'
    dst_lib = dst_llvm / 'lib'

    if dst_include.exists():
        print(f"  Cleaning existing {dst_include}...")
        shutil.rmtree(dst_include)
    if dst_lib.exists():
        print(f"  Cleaning existing {dst_lib}...")
        shutil.rmtree(dst_lib)

    print(f"  Copying LLVM headers...")
    shutil.copytree(str(src_include), str(dst_include))

    print(f"  Copying LLVM libs...")
    shutil.copytree(str(src_lib), str(dst_lib))

    # Verify key libs
    key_libs = ['LLVMCore', 'LLVMSupport', 'LLVMAsmParser', 'LLVMIRReader']
    for lib in key_libs:
        ext = '.lib' if IS_WINDOWS else '.a'
        lib_path = dst_lib / f'{lib}{ext}'
        if lib_path.exists():
            size_kb = lib_path.stat().st_size / 1024
            print(f"  {lib}{ext}: OK ({size_kb:.0f} KB)")
        else:
            print(f"  {lib}{ext}: MISSING!")

    print(f"\n  LLVM deps copied to {dst_llvm}")


# ===================================================================
# STEP 2: Build Clang 18 static libs
# ===================================================================
def build_clang(llvm_src, llvm_build=None):
    """Build Clang 18 static libs using _build_clang.py."""
    print("\n>>> STEP 2: BUILD CLANG 18 STATIC LIBS <<<\n")

    clang_dir = DEPS_DIR / 'clang'
    clang_lib = clang_dir / 'lib'

    # Check if already built
    if clang_lib.exists():
        libs = list(clang_lib.glob('*.lib' if IS_WINDOWS else '*.a'))
        if len(libs) >= 8:
            print(f"  Clang libs already present ({len(libs)} libs)")
            print(f"  Skipping build. Use --force-clang to rebuild.")
            return

    if not llvm_src:
        llvm_src = find_llvm_source()
        if not llvm_src:
            print("  ERROR: Cannot find llvm-project source tree.")
            print("  Tried:")
            for c in LLVM_SRC_CANDIDATES:
                print(f"    {c}")
            print("  Use --llvm-src to specify the path.")
            sys.exit(1)

    clang_src = Path(llvm_src) / 'clang'
    if not clang_src.exists():
        print(f"  ERROR: Clang source not found at {clang_src}")
        sys.exit(1)

    print(f"  LLVM source: {llvm_src}")
    print(f"  Clang source: {clang_src}")

    cmd = [sys.executable, str(SCRIPT_DIR / '_build_clang.py'),
           '--llvm-src', str(llvm_src)]
    if llvm_build:
        cmd += ['--llvm-build', str(llvm_build)]

    run(cmd, cwd=str(SCRIPT_DIR))


# ===================================================================
# STEP 3: Download + install Z3
# ===================================================================
def install_z3():
    """Download and install Z3 pre-built using _build_z3.py."""
    print("\n>>> STEP 3: INSTALL Z3 <<<\n")

    z3_dir = DEPS_DIR / 'z3'
    z3_lib = z3_dir / 'lib'

    # Check if already installed
    if z3_lib.exists():
        libs = list(z3_lib.glob('*.lib' if IS_WINDOWS else '*.a'))
        if len(libs) >= 1:
            print(f"  Z3 already installed ({len(libs)} libs)")
            print(f"  Skipping. Use --force-z3 to reinstall.")
            return

    run([sys.executable, str(SCRIPT_DIR / '_build_z3.py')],
        cwd=str(SCRIPT_DIR))


# ===================================================================
# STEP 4: Build Rellic static lib
# ===================================================================
def build_rellic_lib(llvm_build=None):
    """Build Rellic static lib using _build_rellic.py."""
    print("\n>>> STEP 4: BUILD RELLIC STATIC LIB <<<\n")

    rellic_dir = DEPS_DIR / 'rellic'
    rellic_lib = rellic_dir / 'lib'

    # Check if already built
    if rellic_lib.exists():
        libs = list(rellic_lib.glob('*.lib' if IS_WINDOWS else '*.a'))
        if len(libs) >= 1:
            print(f"  Rellic lib already present ({len(libs)} libs)")
            print(f"  Skipping. Use --force-rellic to rebuild.")
            return

    cmd = [sys.executable, str(SCRIPT_DIR / '_build_rellic.py')]
    if llvm_build:
        cmd += ['--llvm-build', str(llvm_build)]

    run(cmd, cwd=str(SCRIPT_DIR))


# ===================================================================
# STEP 5: node-gyp rebuild
# ===================================================================
def node_gyp_rebuild():
    """Run node-gyp rebuild to compile the .node addon."""
    print("\n>>> STEP 5: NODE-GYP REBUILD <<<\n")

    # Check node-gyp is available
    try:
        r = subprocess.run(['npx', 'node-gyp', '--version'],
                           capture_output=True, text=True, cwd=str(SCRIPT_DIR))
        print(f"  node-gyp: {r.stdout.strip()}")
    except FileNotFoundError:
        print("  ERROR: npx/node-gyp not found. Install node-gyp globally:")
        print("    npm install -g node-gyp")
        sys.exit(1)

    run(['npx', 'node-gyp', 'rebuild'], cwd=str(SCRIPT_DIR))

    # Verify output
    node_file = SCRIPT_DIR / 'build' / 'Release' / 'hexcore_rellic.node'
    if node_file.exists():
        size_mb = node_file.stat().st_size / (1024 * 1024)
        print(f"\n  Built: {node_file} ({size_mb:.1f} MB)")
    else:
        print(f"\n  ERROR: .node file not found at {node_file}")
        # Try Debug build
        debug_node = SCRIPT_DIR / 'build' / 'Debug' / 'hexcore_rellic.node'
        if debug_node.exists():
            print(f"  Found Debug build: {debug_node}")
        sys.exit(1)


# ===================================================================
# STEP 6: npm test
# ===================================================================
def npm_test():
    """Run smoke tests."""
    print("\n>>> STEP 6: NPM TEST <<<\n")
    run(['node', 'test/test.js'], cwd=str(SCRIPT_DIR))


# ===================================================================
# Verify all deps
# ===================================================================
def verify_all():
    """Verify all dependencies are present and correct."""
    print("\n>>> VERIFYING ALL DEPENDENCIES <<<\n")

    all_ok = True

    # LLVM
    llvm_lib = DEPS_DIR / 'llvm' / 'lib'
    llvm_inc = DEPS_DIR / 'llvm' / 'include'
    if llvm_lib.exists() and llvm_inc.exists():
        libs = list(llvm_lib.glob('*.lib' if IS_WINDOWS else '*.a'))
        print(f"  LLVM: {len(libs)} libs, headers present")
    else:
        print(f"  LLVM: MISSING")
        all_ok = False

    # Clang
    clang_lib = DEPS_DIR / 'clang' / 'lib'
    clang_inc = DEPS_DIR / 'clang' / 'include'
    if clang_lib.exists() and clang_inc.exists():
        libs = list(clang_lib.glob('*.lib' if IS_WINDOWS else '*.a'))
        print(f"  Clang: {len(libs)} libs, headers present")
    else:
        print(f"  Clang: MISSING")
        all_ok = False

    # Z3
    z3_lib = DEPS_DIR / 'z3' / 'lib'
    z3_inc = DEPS_DIR / 'z3' / 'include'
    if z3_lib.exists() and z3_inc.exists():
        libs = list(z3_lib.glob('*.lib' if IS_WINDOWS else '*.a'))
        z3_h = z3_inc / 'z3.h'
        print(f"  Z3: {len(libs)} libs, z3.h {'present' if z3_h.exists() else 'MISSING'}")
    else:
        print(f"  Z3: MISSING")
        all_ok = False

    # Rellic
    rellic_lib = DEPS_DIR / 'rellic' / 'lib'
    rellic_inc = DEPS_DIR / 'rellic' / 'include'
    if rellic_lib.exists():
        libs = list(rellic_lib.glob('*.lib' if IS_WINDOWS else '*.a'))
        print(f"  Rellic: {len(libs)} libs")
    else:
        print(f"  Rellic: MISSING (build with _build_rellic.py)")
        all_ok = False

    # .node file
    node_file = SCRIPT_DIR / 'build' / 'Release' / 'hexcore_rellic.node'
    if node_file.exists():
        size_mb = node_file.stat().st_size / (1024 * 1024)
        print(f"  .node: {node_file.name} ({size_mb:.1f} MB)")
    else:
        print(f"  .node: NOT BUILT YET")

    if all_ok:
        print("\n  All deps present!")
    else:
        print("\n  Some deps missing — run the full pipeline.")

    return all_ok


# ===================================================================
# Main
# ===================================================================
def main():
    parser = argparse.ArgumentParser(
        description='Master build script for hexcore-rellic')
    parser.add_argument('--remill-deps', type=str,
                        default=str(DEFAULT_REMILL_DEPS),
                        help=f'Path to hexcore-remill deps/ (default: {DEFAULT_REMILL_DEPS})')
    parser.add_argument('--llvm-src', type=str,
                        help='Path to llvm-project source (auto-detected if omitted)')
    parser.add_argument('--llvm-build', type=str,
                        default=str(DEFAULT_LLVM_BUILD),
                        help=f'Path to LLVM build/install dir (default: {DEFAULT_LLVM_BUILD})')
    parser.add_argument('--step', type=str, choices=[
        'copy-llvm', 'build-clang', 'build-z3', 'build-rellic-lib',
        'node-gyp', 'test'],
                        help='Run a single step instead of the full pipeline')
    parser.add_argument('--verify', action='store_true',
                        help='Only verify all deps')
    parser.add_argument('--force-clang', action='store_true',
                        help='Force rebuild of Clang libs')
    parser.add_argument('--force-z3', action='store_true',
                        help='Force reinstall of Z3')
    parser.add_argument('--force-rellic', action='store_true',
                        help='Force rebuild of Rellic lib')
    parser.add_argument('--skip-clang', action='store_true',
                        help='Skip Clang build (if you already have it)')
    parser.add_argument('--skip-test', action='store_true',
                        help='Skip npm test after build')
    args = parser.parse_args()

    os.chdir(SCRIPT_DIR)

    if args.verify:
        verify_all()
        return

    if args.step:
        if args.step == 'copy-llvm':
            copy_llvm_deps(args.remill_deps)
        elif args.step == 'build-clang':
            build_clang(args.llvm_src, args.llvm_build)
        elif args.step == 'build-z3':
            install_z3()
        elif args.step == 'build-rellic-lib':
            build_rellic_lib(args.llvm_build)
        elif args.step == 'node-gyp':
            node_gyp_rebuild()
        elif args.step == 'test':
            npm_test()
        return

    # Force flags
    if args.force_clang:
        clang_lib = DEPS_DIR / 'clang' / 'lib'
        if clang_lib.exists():
            shutil.rmtree(clang_lib)
    if args.force_z3:
        z3_lib = DEPS_DIR / 'z3' / 'lib'
        if z3_lib.exists():
            shutil.rmtree(z3_lib)
    if args.force_rellic:
        rellic_lib = DEPS_DIR / 'rellic' / 'lib'
        if rellic_lib.exists():
            shutil.rmtree(rellic_lib)

    # Full pipeline
    print('=' * 60)
    print('  HEXCORE-RELLIC FULL BUILD PIPELINE')
    print('  1. Copy LLVM deps from hexcore-remill')
    print('  2. Build Clang 18 static libs')
    print('  3. Download + install Z3')
    print('  4. Build Rellic static lib (stubs)')
    print('  5. node-gyp rebuild')
    print('  6. npm test')
    print('=' * 60)

    # Step 1: Copy LLVM
    copy_llvm_deps(args.remill_deps)

    # Step 2: Build Clang (skip if --skip-clang)
    if not args.skip_clang:
        build_clang(args.llvm_src, args.llvm_build)
    else:
        print("\n>>> STEP 2: SKIPPED (--skip-clang) <<<")

    # Step 3: Z3
    install_z3()

    # Step 4: Rellic lib
    build_rellic_lib(args.llvm_build)

    # Step 5: node-gyp
    node_gyp_rebuild()

    # Step 6: Test
    if not args.skip_test:
        npm_test()
    else:
        print("\n>>> STEP 6: SKIPPED (--skip-test) <<<")

    # Summary
    print('\n' + '=' * 60)
    print('  BUILD COMPLETE!')
    print('')
    print('  Next steps:')
    print('  1. Test in dev mode: .\\scripts\\code.bat')
    print('  2. Copy to standalone: python _copy_to_standalone.py')
    print('  3. Pack deps: python _pack_deps.py')
    print('  4. Upload deps zip as release asset')
    print('  5. Generate prebuild in standalone repo')
    print('=' * 60)


if __name__ == '__main__':
    main()
