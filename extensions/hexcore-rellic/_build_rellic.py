#!/usr/bin/env python3
"""
Build Rellic ported passes as a static library for hexcore-rellic.

Usage:
    python _build_rellic.py
    python _build_rellic.py --llvm-build C:\\llvm-18-build
    python _build_rellic.py --verify
    python _build_rellic.py --validate-ir

Prerequisites:
    - VS2022 with MSVC 14.44 toolset (Windows)
    - LLVM/Clang 21 as host compiler (clang-cl in PATH) (Windows)
    - GCC or Clang (Linux)
    - CMake 3.21+ and Ninja in PATH
    - LLVM 18.1.8 headers/libs in deps/llvm/
    - Clang 18.1.8 headers/libs in deps/clang/
    - Z3 4.12+ headers/lib in deps/z3/
    - Run from VS Developer Command Prompt (Windows):
      vcvarsall.bat x64 -vcvars_ver=14.44

This script:
    1. Configures CMake for the Rellic static library
    2. Builds rellic.lib (Windows) or librellic.a (Linux)
    3. Copies headers and lib to deps/rellic/include/ and deps/rellic/lib/
    4. Optionally validates with a reference IR snippet

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

# Rellic source files (passes only — no N-API wrapper)
RELLIC_SOURCES = [
    'rellic_passes.cpp',
    'rellic_decompile_pipeline.cpp',
    'rellic_opaque_ptr.cpp',
    'rellic_llvm_compat.cpp',
]

RELLIC_HEADERS = [
    'rellic_passes.h',
    'rellic_decompile_pipeline.h',
    'rellic_opaque_ptr.h',
    'rellic_llvm_compat.h',
]

# Reference IR for validation (simple add function)
REFERENCE_IR = r"""
; ModuleID = 'hexcore_rellic_validation'
source_filename = "validation.c"
target datalayout = "e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-windows-msvc"

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
""".strip()

# Expected pseudo-C output (approximate — actual output depends on Rellic)
EXPECTED_PSEUDO_C = """
int add(int a, int b) {
    return a + b;
}

int sub(int a, int b) {
    return a - b;
}
""".strip()

IS_WINDOWS = platform.system() == 'Windows'
SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = SCRIPT_DIR / 'src'
DEPS_DIR = SCRIPT_DIR / 'deps'
CMAKE = 'cmake'
JOBS = str(os.cpu_count() or 4)


def run(cmd, cwd=None, check=True):
    """Run a command with logging."""
    print(f"\n{'=' * 60}")
    print(f"CMD: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    print(f"CWD: {cwd or os.getcwd()}")
    print(f"{'=' * 60}")
    r = subprocess.run(cmd, cwd=cwd)
    if check and r.returncode != 0:
        print(f"FAILED with exit code {r.returncode}")
        sys.exit(r.returncode)
    return r.returncode


def check_prerequisites():
    """Verify that all required deps are present."""
    print("\n>>> CHECKING PREREQUISITES <<<\n")

    errors = []

    # Check CMake
    try:
        r = subprocess.run([CMAKE, '--version'], capture_output=True, text=True)
        version_line = r.stdout.split('\n')[0]
        print(f"  CMake: {version_line}")
    except FileNotFoundError:
        errors.append("CMake not found in PATH")

    # Check Ninja
    try:
        r = subprocess.run(['ninja', '--version'], capture_output=True, text=True)
        print(f"  Ninja: {r.stdout.strip()}")
    except FileNotFoundError:
        errors.append("Ninja not found in PATH")

    # Check deps directories
    for dep in ['llvm', 'clang', 'z3']:
        dep_dir = DEPS_DIR / dep
        include_dir = dep_dir / 'include'
        lib_dir = dep_dir / 'lib'
        if not include_dir.exists():
            errors.append(f"Missing: {include_dir}")
        else:
            print(f"  {dep}/include: OK")
        if not lib_dir.exists():
            errors.append(f"Missing: {lib_dir}")
        else:
            print(f"  {dep}/lib: OK")

    # Check source files
    for src in RELLIC_SOURCES:
        src_path = SRC_DIR / src
        if not src_path.exists():
            errors.append(f"Missing source: {src_path}")
        else:
            print(f"  src/{src}: OK")

    if errors:
        print(f"\n  ERRORS ({len(errors)}):")
        for e in errors:
            print(f"    - {e}")
        return False

    print("\n  All prerequisites OK")
    return True


def configure(build_dir, llvm_build=None):
    """Configure CMake for the Rellic static library."""
    print("\n>>> CONFIGURING RELLIC BUILD <<<\n")

    build_dir.mkdir(parents=True, exist_ok=True)

    cmake_args = [
        CMAKE, '-G', 'Ninja',
        '-S', str(SCRIPT_DIR),
        '-B', str(build_dir),
        '-DCMAKE_BUILD_TYPE=Release',
        '-DBUILD_SHARED_LIBS=OFF',
    ]

    if IS_WINDOWS:
        cmake_args += [
            '-DCMAKE_C_COMPILER=clang-cl',
            '-DCMAKE_CXX_COMPILER=clang-cl',
            '-DCMAKE_POLICY_DEFAULT_CMP0091=NEW',
            '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded',
            '-DCMAKE_C_FLAGS=/MT /EHsc',
            '-DCMAKE_CXX_FLAGS=/MT /EHsc',
            '-DCMAKE_C_FLAGS_RELEASE=/MT /EHsc /O2 /DNDEBUG',
            '-DCMAKE_CXX_FLAGS_RELEASE=/MT /EHsc /O2 /DNDEBUG',
        ]
    else:
        cmake_args += [
            '-DCMAKE_C_FLAGS=-fPIC',
            '-DCMAKE_CXX_FLAGS=-fPIC -fexceptions',
        ]

    # LLVM/Clang/Z3 paths
    llvm_dir = DEPS_DIR / 'llvm' / 'lib' / 'cmake' / 'llvm'
    clang_dir = DEPS_DIR / 'clang' / 'lib' / 'cmake' / 'clang'
    z3_dir = DEPS_DIR / 'z3' / 'lib' / 'cmake' / 'z3'

    if llvm_build:
        llvm_dir = Path(llvm_build) / 'lib' / 'cmake' / 'llvm'

    if llvm_dir.exists():
        cmake_args.append(f'-DLLVM_DIR={llvm_dir}')
    else:
        print(f"  WARNING: LLVM CMake config not found at {llvm_dir}")
        print(f"  CMake will try to find LLVM via system paths")

    if clang_dir.exists():
        cmake_args.append(f'-DClang_DIR={clang_dir}')
    else:
        print(f"  WARNING: Clang CMake config not found at {clang_dir}")

    if z3_dir.exists():
        cmake_args.append(f'-DZ3_DIR={z3_dir}')
    else:
        # Fall back to manual Z3 paths
        z3_include = DEPS_DIR / 'z3' / 'include'
        z3_lib = DEPS_DIR / 'z3' / 'lib'
        if z3_include.exists():
            cmake_args.append(f'-DZ3_INCLUDE_DIR={z3_include}')
        if z3_lib.exists():
            lib_name = 'libz3.lib' if IS_WINDOWS else 'libz3.a'
            z3_lib_file = z3_lib / lib_name
            if z3_lib_file.exists():
                cmake_args.append(f'-DZ3_LIBRARY={z3_lib_file}')

    run(cmake_args)
    print("\n  Configure: OK")


def build(build_dir):
    """Build the Rellic static library."""
    print("\n>>> BUILDING RELLIC STATIC LIBRARY <<<\n")

    run([CMAKE, '--build', str(build_dir),
         '--target', 'rellic',
         '--config', 'Release',
         '-j', JOBS])

    # Verify output
    if IS_WINDOWS:
        lib_file = build_dir / 'rellic.lib'
    else:
        lib_file = build_dir / 'librellic.a'

    if not lib_file.exists():
        # Try alternative paths (CMake may put it in a subdirectory)
        for candidate in build_dir.rglob('rellic.lib' if IS_WINDOWS else 'librellic.a'):
            lib_file = candidate
            break

    if lib_file.exists():
        size_kb = lib_file.stat().st_size / 1024
        print(f"\n  Built: {lib_file} ({size_kb:.1f} KB)")
    else:
        print(f"\n  ERROR: Library not found after build")
        sys.exit(1)

    return lib_file


def install_to_deps(build_dir, lib_file):
    """Copy headers and lib to deps/rellic/ for binding.gyp consumption."""
    print("\n>>> INSTALLING TO deps/rellic/ <<<\n")

    output_dir = DEPS_DIR / 'rellic'
    include_dst = output_dir / 'include' / 'rellic'
    lib_dst = output_dir / 'lib'

    # Clean previous install
    if include_dst.exists():
        shutil.rmtree(include_dst)
    if lib_dst.exists():
        shutil.rmtree(lib_dst)

    # Copy headers
    include_dst.mkdir(parents=True, exist_ok=True)
    for header in RELLIC_HEADERS:
        src_path = SRC_DIR / header
        if src_path.exists():
            shutil.copy2(src_path, include_dst)
            print(f"  Header: {header}")
        else:
            print(f"  WARNING: Header not found: {header}")

    # Copy library
    lib_dst.mkdir(parents=True, exist_ok=True)
    lib_name = 'rellic.lib' if IS_WINDOWS else 'librellic.a'
    dst_lib = lib_dst / lib_name
    shutil.copy2(lib_file, dst_lib)
    size_kb = dst_lib.stat().st_size / 1024
    print(f"  Library: {lib_name} ({size_kb:.1f} KB)")

    print(f"\n  Installed to {output_dir}")
    return output_dir


def verify_lib(output_dir):
    """Verify the installed library using dumpbin (Windows) or nm (Linux)."""
    print("\n>>> VERIFYING LIBRARY <<<\n")

    if IS_WINDOWS:
        lib_path = output_dir / 'lib' / 'rellic.lib'
        if not lib_path.exists():
            print(f"  ERROR: {lib_path} not found")
            return False

        # Check CRT linkage with dumpbin
        try:
            r = subprocess.run(
                ['dumpbin', '/directives', str(lib_path)],
                capture_output=True, text=True)
            defaults = set()
            for line in r.stdout.split('\n'):
                if '/DEFAULTLIB:' in line:
                    val = line.strip().split('/DEFAULTLIB:')[1].strip().strip('"')
                    defaults.add(val.lower())

            if 'libcmt' in defaults or 'libcmt.lib' in defaults:
                crt = 'MT'
            elif 'msvcrt' in defaults or 'msvcrt.lib' in defaults:
                crt = 'MD'
            else:
                crt = '???'

            status = 'OK' if crt == 'MT' else 'MISMATCH'
            print(f"  CRT: {crt} {status}  ({', '.join(sorted(defaults))})")

            if crt != 'MT':
                print("  WARNING: Library is NOT /MT — must match LLVM/Clang/Z3 libs")
                return False
        except FileNotFoundError:
            print("  WARNING: dumpbin not found, skipping CRT check")
            print("  (Run from VS Developer Command Prompt for CRT verification)")

        # Check symbols with dumpbin
        try:
            r = subprocess.run(
                ['dumpbin', '/symbols', str(lib_path)],
                capture_output=True, text=True)
            # Look for key Rellic symbols
            key_symbols = [
                'GenerateASTPass',
                'buildRellicPipeline',
                'runRellicPipeline',
                'getPointeeType',
                'getOrInsertRellicFunction',
                'createFunctionType',
            ]
            found = []
            for sym in key_symbols:
                if sym in r.stdout:
                    found.append(sym)
                    print(f"  Symbol OK: {sym}")
                else:
                    print(f"  Symbol MISSING: {sym}")

            print(f"\n  Symbols: {len(found)}/{len(key_symbols)} found")
        except FileNotFoundError:
            print("  WARNING: dumpbin not found, skipping symbol check")

    else:
        lib_path = output_dir / 'lib' / 'librellic.a'
        if not lib_path.exists():
            print(f"  ERROR: {lib_path} not found")
            return False

        # Check symbols with nm
        try:
            r = subprocess.run(
                ['nm', '--defined-only', str(lib_path)],
                capture_output=True, text=True)
            key_symbols = [
                'buildRellicPipeline',
                'runRellicPipeline',
                'getPointeeType',
                'getOrInsertRellicFunction',
                'createFunctionType',
            ]
            found = []
            for sym in key_symbols:
                if sym in r.stdout:
                    found.append(sym)
                    print(f"  Symbol OK: {sym}")
                else:
                    print(f"  Symbol MISSING: {sym}")

            print(f"\n  Symbols: {len(found)}/{len(key_symbols)} found")
        except FileNotFoundError:
            print("  WARNING: nm not found, skipping symbol check")

    # Verify headers
    include_dir = output_dir / 'include' / 'rellic'
    header_count = 0
    for header in RELLIC_HEADERS:
        h_path = include_dir / header
        if h_path.exists():
            header_count += 1
        else:
            print(f"  Header MISSING: {header}")
    print(f"  Headers: {header_count}/{len(RELLIC_HEADERS)} installed")

    return True


def validate_ir():
    """
    Write the reference IR to a temp file and print expected pseudo-C.

    This validation step is informational — it documents the expected
    input/output pair for the Rellic decompiler.  Actual decompilation
    validation requires the full N-API module to be built and loaded.
    """
    print("\n>>> REFERENCE IR VALIDATION <<<\n")

    # Write reference IR
    ir_path = SCRIPT_DIR / 'test' / 'reference_validation.ll'
    ir_path.parent.mkdir(parents=True, exist_ok=True)
    ir_path.write_text(REFERENCE_IR, encoding='utf-8')
    print(f"  Reference IR written to: {ir_path}")

    print(f"\n  --- Input LLVM IR ---")
    for line in REFERENCE_IR.split('\n'):
        print(f"  {line}")

    print(f"\n  --- Expected Pseudo-C Output ---")
    for line in EXPECTED_PSEUDO_C.split('\n'):
        print(f"  {line}")

    print(f"\n  NOTE: Actual decompilation validation requires the full")
    print(f"  N-API module (hexcore_rellic.node) to be built and loaded.")
    print(f"  Use 'npm test' after 'npx node-gyp rebuild' to validate.")

    return ir_path


def main():
    parser = argparse.ArgumentParser(
        description='Build Rellic static library for hexcore-rellic')
    parser.add_argument('--llvm-build',
                        help='Path to existing LLVM 18 build dir (for LLVM_DIR)')
    parser.add_argument('--build-dir', default='build-rellic',
                        help='CMake build directory (default: build-rellic)')
    parser.add_argument('--verify', action='store_true',
                        help='Only verify installed library (skip build)')
    parser.add_argument('--validate-ir', action='store_true',
                        help='Only write reference IR and show expected output')
    parser.add_argument('--skip-prereq', action='store_true',
                        help='Skip prerequisite checks')
    args = parser.parse_args()

    os.chdir(SCRIPT_DIR)

    if args.validate_ir:
        validate_ir()
        return

    if args.verify:
        output_dir = DEPS_DIR / 'rellic'
        if not output_dir.exists():
            print(f"ERROR: {output_dir} does not exist. Run build first.")
            sys.exit(1)
        ok = verify_lib(output_dir)
        sys.exit(0 if ok else 1)

    # Full build pipeline
    print('=' * 60)
    print('  RELLIC STATIC LIBRARY BUILD')
    print('  1. Check prerequisites')
    print('  2. Configure CMake (Ninja)')
    print('  3. Build rellic static lib')
    print('  4. Install to deps/rellic/')
    print('  5. Verify library')
    print('  6. Write reference IR')
    print('=' * 60)

    # Step 1: Prerequisites
    if not args.skip_prereq:
        if not check_prerequisites():
            print("\nPrerequisites not met. Fix errors above and retry.")
            print("Use --skip-prereq to skip this check.")
            sys.exit(1)

    # Step 2: Configure
    build_dir = SCRIPT_DIR / args.build_dir
    configure(build_dir, llvm_build=args.llvm_build)

    # Step 3: Build
    lib_file = build(build_dir)

    # Step 4: Install
    output_dir = install_to_deps(build_dir, lib_file)

    # Step 5: Verify
    ok = verify_lib(output_dir)

    # Step 6: Reference IR
    validate_ir()

    # Summary
    print('\n' + '=' * 60)
    if ok:
        print('  BUILD COMPLETE!')
        print('')
        print('  Next steps:')
        print('  1. npx node-gyp rebuild   (build N-API module)')
        print('  2. npm test               (run smoke tests)')
        print('  3. python _pack_deps.py   (pack for CI)')
    else:
        print('  BUILD COMPLETE (with warnings)')
        print('  Check output above for issues.')
    print('=' * 60)


if __name__ == '__main__':
    main()
